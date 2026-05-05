#[cfg(not(target_os = "linux"))]
use std::alloc::{alloc_zeroed, Layout};
use std::cell::UnsafeCell;
use std::mem::MaybeUninit;
use std::ptr::{self, NonNull};
use std::sync::atomic::{AtomicPtr, Ordering};
use std::sync::{Arc, Mutex, Weak};

use quac_socket::{BufferPool, PacketBuf, PacketBufMut};

/// Max UDP payload bytes the non-Linux fallback recv path stages. Linux uses
/// `recvmmsg` directly into caller-supplied buffers (no staging).
#[cfg(not(target_os = "linux"))]
pub(crate) const MAX_DATAGRAM: usize = 65535;

// ── MTU constants (re-exported from quac-socket::net) ────────────────────────

pub use quac_socket::net::{IPV4_MAX_UDP_PAYLOAD, IPV6_MAX_UDP_PAYLOAD};

// ── OsBufNode ────────────────────────────────────────────────────────────────

/// Heap-allocated intrusive node carrying a UDP payload.
///
/// `pool` carries an `Arc<OsPool>` while the node is **live** (held by an
/// `OsBuf` / `OsBufMut`); this strong reference keeps the pool alive for the
/// duration of any in-flight buffer, eliminating the UAF window that a raw
/// back-pointer would expose. When the node is **queued** (waiting in the
/// pool's MPSC list), `pool` is `None` — otherwise nodes in the queue would
/// each contribute a strong ref and the pool could never drop. `from_slice`
/// nodes (pool-less) also use `None` and are freed via `Box::from_raw`.
pub(crate) struct OsBufNode {
    pub(crate) data: Vec<u8>,
    /// Intrusive MPSC link. Written by drop (producers); read by pop_raw (consumer).
    next: AtomicPtr<OsBufNode>,
    /// Strong ref held while the node is live; `None` while queued and for
    /// pool-less nodes.
    pool: Option<Arc<OsPool>>,
}

// ── OsBuf / OsBufMut ─────────────────────────────────────────────────────────

/// Frozen (Tx) buffer. Returned to its owning pool on drop.
pub struct OsBuf {
    node: NonNull<OsBufNode>,
}

/// Mutable (Rx) buffer. Returned to its owning pool on drop.
///
/// Caches `(data_ptr, data_cap, data_len)` from the underlying `Vec<u8>` so
/// the recv hot path can wire the kernel iov and read filled bytes without
/// dereferencing the heap-scattered `OsBufNode`. The cache is set in
/// `OsPool::alloc` and kept in sync by `set_filled`; none of the
/// `PacketBufMut` operations resize the underlying Vec, so `data_ptr` and
/// `data_cap` remain stable for the wrapper's lifetime.
///
/// Size: 32 bytes on 64-bit (one `NonNull<OsBufNode>` + three `usize` cache fields).
pub struct OsBufMut {
    node: NonNull<OsBufNode>,
    /// Cached `data.as_mut_ptr()` — start of the heap slab the kernel
    /// writes into via the iov. Stable for the wrapper's lifetime.
    data_ptr: *mut u8,
    /// Cached `data.capacity()` — the iov_len the kernel respects.
    /// Stable for the wrapper's lifetime.
    data_cap: usize,
    /// Cached `data.len()` — kept in sync by `set_filled`. Used by
    /// `filled()`, `filled_mut()`, and `uninit_mut()` to avoid dereferencing
    /// the heap-scattered `OsBufNode` on the receive hot path.
    data_len: usize,
}

// Safety: nodes are heap-allocated; while the wrapper exists, the node holds
// an `Arc<OsPool>` that keeps the pool alive, so the `push` in drop is always
// valid. The cached `data_ptr` on `OsBufMut` targets the same heap allocation
// the node owns; both move together with the wrapper.
unsafe impl Send for OsBuf {}
unsafe impl Send for OsBufMut {}

fn return_node(node: NonNull<OsBufNode>) {
    // Take the Arc out so the queued node has `pool = None` — otherwise
    // queued nodes would each pin the pool, preventing it from ever dropping.
    let pool = unsafe { (*node.as_ptr()).pool.take() };
    match pool {
        None => {
            // Pool-less (OsBuf::from_slice): reclaim the Box allocation.
            // Slab-allocated pool nodes never reach this branch — they
            // always have `pool = Some(_)` while wrapped, and the queue's
            // pool=None nodes are owned by the Vec inside `consumer_lock`
            // (freed by the Vec<Box<[OsBufNode]>> drop chain when the pool drops).
            unsafe { drop(Box::from_raw(node.as_ptr())) };
        }
        Some(pool) => {
            // Push is lock-free and only requires the pool to be live —
            // guaranteed by the `pool` Arc we still hold here.
            unsafe { pool.push(node) };
            // `pool` drops at end of scope, decrementing the strong count.
        }
    }
}

impl Drop for OsBuf {
    fn drop(&mut self) {
        return_node(self.node);
    }
}

impl Drop for OsBufMut {
    fn drop(&mut self) {
        return_node(self.node);
    }
}

impl AsRef<[u8]> for OsBuf {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        unsafe { &self.node.as_ref().data }
    }
}

impl PacketBuf for OsBuf {}

impl OsBuf {
    /// Create a pool-less buffer from a byte slice (tests / one-off sends).
    /// Freed to the heap on drop; not recycled.
    pub fn from_slice(data: &[u8]) -> Self {
        let node = Box::new(OsBufNode {
            data: data.to_vec(),
            next: AtomicPtr::new(ptr::null_mut()),
            pool: None,
        });
        OsBuf {
            node: NonNull::from(Box::leak(node)),
        }
    }
}

impl OsBufMut {
    /// Cached data pointer — the start of the slab the kernel writes into
    /// via `recvmmsg`'s iov. Used by [`OsSocket::recv`](crate::OsSocket::recv)
    /// to wire iov_base without dereferencing the underlying `OsBufNode`.
    #[inline]
    pub(crate) fn data_ptr(&self) -> *mut u8 {
        self.data_ptr
    }
}

impl PacketBufMut for OsBufMut {
    type Frozen = OsBuf;

    #[inline]
    fn capacity(&self) -> usize {
        // Cached: avoids the per-call deref of the heap-scattered node.
        self.data_cap
    }

    #[inline]
    fn filled(&self) -> &[u8] {
        // Use cached ptr+len to avoid dereferencing the heap-scattered OsBufNode.
        unsafe { std::slice::from_raw_parts(self.data_ptr, self.data_len) }
    }

    #[inline]
    fn filled_mut(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.data_ptr, self.data_len) }
    }

    #[inline]
    fn uninit_mut(&mut self) -> &mut [MaybeUninit<u8>] {
        unsafe {
            std::slice::from_raw_parts_mut(
                self.data_ptr.add(self.data_len) as *mut MaybeUninit<u8>,
                self.data_cap - self.data_len,
            )
        }
    }

    #[inline]
    unsafe fn set_filled(&mut self, new_len: usize) {
        self.data_len = new_len;
        unsafe { self.node.as_mut().data.set_len(new_len) }
    }

    fn freeze(self) -> OsBuf {
        // Transfer node ownership without touching any atomic or pool pointer.
        // Cached `data_ptr` / `data_cap` are simply discarded — `OsBuf` reads
        // through the node's `Vec` for `as_ref()` (post-freeze the slice
        // covers the *filled* prefix, not the full cap, so the cache wouldn't
        // help here).
        let node = self.node;
        std::mem::forget(self);
        OsBuf { node }
    }
}

// ── OsPool — Vyukov intrusive MPSC queue ─────────────────────────────────────

/// Slab size for `OsPool` node growth. Picked to match `OsSocket::MAX_BATCH`
/// so a steady-state recv batch's worth of nodes share cache locality.
const SLAB_SIZE: usize = 64;

/// Maximum buffer capacity the pool will allocate. Requests above this are
/// silently clamped. With `IP_PMTUDISC_DO` (no fragmentation) and an MTU of
/// 1500 the largest UDP payload is ≈ 1472 bytes; 2048 gives comfortable
/// headroom while bounding node inflation: recycled nodes retain their
/// allocation, so without a cap a node that once held a 64 KiB buffer keeps
/// occupying that memory for the pool's lifetime.
pub(crate) const MAX_BUF_SIZE: usize = 2048;

/// Per-socket buffer pool implemented as a Vyukov intrusive MPSC linked list.
///
/// **Producers** (any thread dropping an `OsBuf`/`OsBufMut`): `push()` — one `XCHG`,
/// always lock-free.
/// **Consumers** (any thread calling `BufferPool::alloc`): serialized via
/// [`consumer_lock`] so only one thread at a time runs `pop_raw`. The MPSC
/// algorithm assumes a single consumer; the lock upholds that invariant
/// without forcing the upstream `BufferPool: Sync` contract to change.
///
/// Nodes are **slab-allocated**: the first time `alloc` finds the queue
/// empty, it allocates a contiguous slab of `SLAB_SIZE` `OsBufNode`s and
/// pushes them all onto the queue. Subsequent allocs recycle from the
/// queue. Slabs are heap-stable (`Box<[OsBufNode]>` contents don't move
/// once allocated) and owned by the pool — they drop with the pool, freeing
/// every node at once. The MPSC queue holds raw pointers into slab storage.
///
/// Must live behind `Arc` (use `OsPool::new()`); the stub sentinel's address is
/// baked into `head`/`tail` at construction and must remain stable.
pub struct OsPool {
    /// Consumer-only. Read/written by whichever thread holds `consumer_lock`
    /// (or has `&mut self`, e.g. during `Drop`).
    head: UnsafeCell<*mut OsBufNode>,
    /// Shared tail; written atomically by all producers and by `pop_raw` when
    /// re-injecting the stub.
    tail: AtomicPtr<OsBufNode>,
    /// Sentinel node. Always present in the queue; never returned to callers.
    ///
    /// Wrapped in `UnsafeCell` so that `push` (which takes `&self`) can derive
    /// a `*mut OsBufNode` via `.get()` rather than by casting a shared-reference
    /// pointer. The cast-based route (`&self.stub as *const _ as *mut _`) would
    /// violate Tree Borrows: the shared reference grants only read provenance, so
    /// the subsequent write to `stub.next` inside `push` is formally UB even
    /// though `AtomicPtr` itself wraps its own field in `UnsafeCell`.
    stub: UnsafeCell<OsBufNode>,
    /// Serializes consumer access (`pop_raw`) and owns the slab storage.
    /// Uncontended in the typical single-Rx-thread case; correctly handles
    /// concurrent `alloc` calls against a shared `Arc<OsPool>`.
    ///
    /// Slab storage lives here rather than in a separate `Mutex` because
    /// `grow_slab` is only ever called from `alloc` (under this lock), so a
    /// second mutex would be redundant. The `Vec<Box<[OsBufNode]>>` heap
    /// allocations are stable for the slab's lifetime; the MPSC queue's raw
    /// pointers into them remain valid even as the Vec itself grows.
    consumer_lock: Mutex<Vec<Box<[OsBufNode]>>>,
    /// Self-referential `Weak<Self>` initialised by `Arc::new_cyclic`. Lets
    /// `alloc` obtain an `Arc<Self>` to embed in each freshly-popped node
    /// without changing the `BufferPool` trait signature.
    self_weak: Weak<OsPool>,
    /// Cached result of `BufferPool::max_payload_size`. Set at construction
    /// from the socket's address family; `new()` defaults to
    /// `IPV6_MAX_UDP_PAYLOAD` (1452) — the conservative value that is safe
    /// for any socket family.
    max_payload: usize,
}

// Safety: `head` is accessed only under `consumer_lock` (or `&mut self`);
// `tail` and `stub.next` use atomic ops with documented orderings.
unsafe impl Send for OsPool {}
unsafe impl Sync for OsPool {}

impl OsPool {
    /// Public constructor. Uses `IPV6_MAX_UDP_PAYLOAD` (1452) as the
    /// conservative default — safe for any socket family. `OsSocket`
    /// uses `with_max_payload` internally to set the exact value for the
    /// bound address family.
    pub fn new() -> Arc<Self> {
        Self::with_max_payload(IPV6_MAX_UDP_PAYLOAD)
    }

    /// Construct a pool with an explicit max payload. Used by `OsSocket`
    /// to propagate the address-family-specific value (1472 for IPv4,
    /// 1452 for IPv6).
    pub(crate) fn with_max_payload(max_payload: usize) -> Arc<Self> {
        let pool = Arc::new_cyclic(|weak: &Weak<OsPool>| Self {
            head: UnsafeCell::new(ptr::null_mut()),
            tail: AtomicPtr::new(ptr::null_mut()),
            stub: UnsafeCell::new(OsBufNode {
                data: Vec::new(),
                next: AtomicPtr::new(ptr::null_mut()),
                pool: None,
            }),
            consumer_lock: Mutex::new(Vec::new()),
            self_weak: weak.clone(),
            max_payload,
        });
        // Wire head and tail to the stub. `UnsafeCell::get()` gives a `*mut`
        // with write provenance; the Arc heap allocation is stable.
        let stub_ptr = pool.stub.get();
        unsafe { *pool.head.get() = stub_ptr }
        pool.tail.store(stub_ptr, Ordering::Relaxed);
        pool
    }

    /// Upgrade the self-Weak to an `Arc<Self>`. Always succeeds while `&self`
    /// is held, since the borrow implies a live strong reference.
    fn arc(&self) -> Arc<Self> {
        self.self_weak
            .upgrade()
            .expect("OsPool is alive while &self is held")
    }

    /// Allocate a fresh slab of `SLAB_SIZE` `OsBufNode`s and push every node
    /// onto the MPSC queue. Must be called under `consumer_lock`; `slabs` is
    /// the guard's dereferenced Vec. The queue holds raw pointers into the
    /// slab's stable heap allocation.
    fn grow_slab(&self, slabs: &mut Vec<Box<[OsBufNode]>>) {
        let mut slab: Box<[OsBufNode]> = (0..SLAB_SIZE)
            .map(|_| OsBufNode {
                data: Vec::new(),
                next: AtomicPtr::new(ptr::null_mut()),
                pool: None,
            })
            .collect();

        // Snapshot per-node pointers while we still hold a `&mut` to the
        // slab. After we move it into `slabs`, we no longer have a borrow
        // we could legally re-derive write pointers from — but these we
        // already captured remain valid because the heap allocation owned
        // by the Box doesn't move when the Box itself is moved into the Vec.
        let nodes: Vec<NonNull<OsBufNode>> = slab.iter_mut().map(NonNull::from).collect();

        slabs.push(slab);

        for n in nodes {
            unsafe { self.push(n) };
        }
    }

    /// Push `node` onto the tail of the queue. Called from any thread.
    ///
    /// Safety: `node` must be exclusively owned and heap-allocated (or be the
    /// pool's own stub pointer when called from `pop_raw`).
    pub(crate) unsafe fn push(&self, node: NonNull<OsBufNode>) {
        let ptr = node.as_ptr();
        (*ptr).next.store(ptr::null_mut(), Ordering::Relaxed);
        // Atomically claim the old tail and install ourselves as the new one.
        // A single XCHG — never retries, never fails.
        let prev = self.tail.swap(ptr, Ordering::AcqRel);
        // Make ourselves visible to the consumer by wiring the old tail's next.
        (*prev).next.store(ptr, Ordering::Release);
    }

    /// Pop one real node from the head. Must be called only from the consumer thread.
    ///
    /// Returns `None` if the queue is empty or a concurrent push has not yet
    /// completed wiring its `next` pointer (try again on the next iteration).
    /// Never returns the internal stub node.
    pub(crate) unsafe fn pop_raw(&self) -> Option<NonNull<OsBufNode>> {
        // `UnsafeCell::get()` gives a `*mut` with write provenance — needed
        // because `push` writes to `stub.next` via this pointer.
        let stub_ptr = self.stub.get();
        let mut head_ptr = *self.head.get();
        let mut next = (*head_ptr).next.load(Ordering::Acquire);

        // If head is the stub, skip past it to the first real node.
        if head_ptr == stub_ptr {
            let next_nn = NonNull::new(next)?; // null → queue is empty
            *self.head.get() = next_nn.as_ptr();
            head_ptr = next_nn.as_ptr();
            next = (*head_ptr).next.load(Ordering::Acquire);
        }

        // Fast path: there is a node after head — advance and return.
        if !next.is_null() {
            *self.head.get() = next;
            return Some(NonNull::new_unchecked(head_ptr));
        }

        // Slow path: head might be the last node in the queue.
        // Re-inject the stub so that a concurrent push can complete wiring.
        let tail = self.tail.load(Ordering::Acquire);
        if head_ptr != tail {
            // A producer swapped tail but hasn't stored next yet — try later.
            return None;
        }
        self.push(NonNull::new_unchecked(stub_ptr));
        next = (*head_ptr).next.load(Ordering::Acquire);
        if !next.is_null() {
            *self.head.get() = next;
            return Some(NonNull::new_unchecked(head_ptr));
        }
        None
    }
}

// `OsPool` does not need a custom `Drop`: every pool-allocated node lives
// in the Vec inside `consumer_lock` and is freed by the Vec/Box drop chain. Queued nodes
// (pool=None) have raw pointers into those slabs; no `Box::from_raw` is
// needed for them. Pool-less nodes (`OsBuf::from_slice`) are owned by
// their wrapper, not by us.

impl BufferPool for OsPool {
    type Buf = OsBuf;
    type BufMut = OsBufMut;

    fn max_payload_size(&self) -> usize {
        self.max_payload
    }

    fn alloc(&self, capacity: usize, count: usize, bufs: &mut Vec<OsBufMut>) -> usize {
        // Clamp to MAX_BUF_SIZE: no-fragment policy + 1500 MTU means the
        // largest UDP payload is ≈ 1472 bytes. The cap prevents recycled
        // nodes from accumulating large allocations (M2 inflation).
        let capacity = capacity.min(MAX_BUF_SIZE);
        // Hold the consumer lock for the whole batch — uncontended in the
        // single-Rx-thread case, but correct under concurrent shared-pool use.
        // The guard also gives exclusive access to the slab storage Vec.
        // Mutex poisoning is irrelevant: the only critical section is pure
        // pointer arithmetic that can't panic.
        let mut slabs = self.consumer_lock.lock().unwrap_or_else(|e| e.into_inner());
        bufs.reserve(count);
        // Upgrade the self-Weak once and clone N times into the popped nodes.
        // Each live buffer carries one strong ref so the pool stays alive
        // for the buffer's lifetime.
        let pool_arc = self.arc();
        for _ in 0..count {
            let mut node = match unsafe { self.pop_raw() } {
                Some(n) => n,
                None => {
                    self.grow_slab(&mut slabs);
                    // Spin until visible: the Vyukov MPSC queue can briefly
                    // return None after a producer's first CAS completes but
                    // before the next-pointer store finishes. grow_slab pushes
                    // SLAB_SIZE nodes so this terminates in at most a few spins.
                    loop {
                        if let Some(n) = unsafe { self.pop_raw() } {
                            break n;
                        }
                        std::hint::spin_loop();
                    }
                }
            };
            let node_mut = unsafe { node.as_mut() };
            // Always set: queued nodes had `None` (we took it out at push
            // time); freshly-slabbed nodes were initialised with `None`.
            node_mut.pool = Some(Arc::clone(&pool_arc));
            // Reset fill level so uninit_mut() covers [0..capacity).
            node_mut.data.clear();
            if node_mut.data.capacity() < capacity {
                // reserve(n) with len=0 ensures capacity() >= n.
                node_mut.data.reserve(capacity);
            }
            // Snapshot the post-grow Vec ptr/cap for the recv hot path.
            // data_len starts at 0: alloc calls clear() above so the Vec is empty.
            let data_ptr = node_mut.data.as_mut_ptr();
            let data_cap = node_mut.data.capacity();
            bufs.push(OsBufMut {
                node,
                data_ptr,
                data_cap,
                data_len: 0,
            });
        }
        count
    }

    fn zerocopy_threshold(&self) -> usize {
        // OS sockets pass scatter-gather to the kernel via sendmmsg's iov
        // array — coalescing into a contiguous buffer is never required.
        0
    }
}

// ── RecvBuf ──────────────────────────────────────────────────────────────────

/// Kernel-facing receive buffer aligned to 64 bytes (non-Linux fallback only).
#[cfg(not(target_os = "linux"))]
#[repr(align(64))]
pub(crate) struct RecvBuf(pub(crate) [u8; MAX_DATAGRAM]);

#[cfg(not(target_os = "linux"))]
pub(crate) fn alloc_recv_buf() -> Box<RecvBuf> {
    let layout = Layout::new::<RecvBuf>();
    let ptr = unsafe { alloc_zeroed(layout) as *mut RecvBuf };
    if ptr.is_null() {
        std::alloc::handle_alloc_error(layout);
    }
    unsafe { Box::from_raw(ptr) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quac_socket::{BufferPool, PacketBufMut};
    use std::sync::mpsc;
    use std::thread;

    /// Stable pointer identifying the heap-allocated node inside an `OsBufMut`.
    /// Recycled buffers preserve this address; freshly minted ones don't.
    fn node_id(b: &OsBufMut) -> *const OsBufNode {
        b.node.as_ptr() as *const OsBufNode
    }

    fn frozen_id(b: &OsBuf) -> *const OsBufNode {
        b.node.as_ptr() as *const OsBufNode
    }

    // ── P1: pool ─────────────────────────────────────────────────────────────

    #[test]
    fn pool_alloc_then_drop_recycles() {
        // With slab allocation, the pool grows by `SLAB_SIZE` nodes at a
        // time and `pop_raw` returns them in queue order. Dropping one
        // and allocating one again wouldn't return the *same* slab node
        // (the queue still has unused slab siblings ahead of the dropped
        // one). To observe the recycle property we exhaust the slab and
        // verify the next round returns the same set of node IDs.
        let pool = OsPool::new();

        let mut bufs1 = Vec::new();
        pool.alloc(64, SLAB_SIZE, &mut bufs1);
        let mut ids1: Vec<_> = bufs1.iter().map(node_id).collect();
        bufs1.clear(); // drop returns every node to the pool's queue

        let mut bufs2 = Vec::new();
        pool.alloc(64, SLAB_SIZE, &mut bufs2);
        let mut ids2: Vec<_> = bufs2.iter().map(node_id).collect();

        ids1.sort();
        ids2.sort();
        assert_eq!(
            ids1, ids2,
            "every node should be recycled — no fresh slab grown"
        );
    }

    #[test]
    fn pool_alloc_appends_without_clearing() {
        let pool = OsPool::new();
        let mut bufs = Vec::new();
        pool.alloc(8, 2, &mut bufs);
        assert_eq!(bufs.len(), 2);
        // Second call must extend, not replace.
        pool.alloc(8, 3, &mut bufs);
        assert_eq!(bufs.len(), 5);
    }

    #[test]
    fn pool_alloc_grows_capacity() {
        // The grow-on-demand property holds for whichever node `alloc`
        // returns from the slab/queue. We don't assert "same node" here
        // because slab queue order doesn't preserve original-pop identity
        // across drop/realloc cycles — see `pool_alloc_then_drop_recycles`.
        let pool = OsPool::new();
        let mut bufs = Vec::new();

        pool.alloc(64, 1, &mut bufs);
        assert!(bufs[0].capacity() >= 64);
        bufs.clear();

        // MAX_BUF_SIZE is the ceiling; requests at the ceiling must be
        // honoured exactly, and requests above it are silently clamped.
        pool.alloc(MAX_BUF_SIZE, 1, &mut bufs);
        assert!(
            bufs[0].capacity() >= MAX_BUF_SIZE,
            "alloc at MAX_BUF_SIZE must reserve at least that much"
        );
        assert!(bufs[0].uninit_mut().len() >= MAX_BUF_SIZE);
        bufs.clear();

        // A request above the cap is clamped — the node must still be usable
        // and capacity must not exceed MAX_BUF_SIZE (no inflation beyond cap).
        pool.alloc(MAX_BUF_SIZE * 4, 1, &mut bufs);
        assert!(
            bufs[0].capacity() >= MAX_BUF_SIZE,
            "clamped alloc must still provide MAX_BUF_SIZE capacity"
        );
    }

    #[test]
    fn pool_drop_drains_queued_nodes() {
        // Allocate, drop bufs (queues nodes back into the pool's MPSC queue),
        // then drop the pool. The slab Vec<Box<[OsBufNode]>> default drop
        // frees every node at once; no explicit `impl Drop for OsPool` is
        // needed. Test passes if the process doesn't crash; ASan/Miri catch leaks.
        let pool = OsPool::new();
        let mut bufs = Vec::new();
        pool.alloc(128, 32, &mut bufs);
        bufs.clear();
        drop(pool);
    }

    #[test]
    fn pool_mpsc_stress() {
        // 4 producer threads each alloc-drop a buffer in a tight loop, plus
        // the main thread acting as another producer/consumer. The pool
        // serializes consumers via consumer_lock; producers race on tail
        // CAS-loops. Test passes if no panic, no UAF, and the pool drops
        // cleanly after.
        const PRODUCERS: usize = 4;
        const ITERS: usize = 5_000;

        let pool = OsPool::new();
        let handles: Vec<_> = (0..PRODUCERS)
            .map(|_| {
                let pool = pool.clone();
                thread::spawn(move || {
                    let mut local = Vec::with_capacity(8);
                    for _ in 0..ITERS {
                        pool.alloc(64, 1, &mut local);
                        local.clear();
                    }
                })
            })
            .collect();

        // Main thread also exercises the pool.
        let mut local = Vec::with_capacity(8);
        for _ in 0..ITERS {
            pool.alloc(64, 1, &mut local);
            local.clear();
        }

        for h in handles {
            h.join().expect("producer panicked");
        }

        // Final alloc must still work (queue is consistent).
        let mut last = Vec::new();
        pool.alloc(64, 1, &mut last);
        assert_eq!(last.len(), 1);
    }

    #[test]
    fn pool_cross_thread_return() {
        // Allocate on thread A, ship via channel to thread B, drop on B.
        // After the join, the queue must contain the cross-thread-dropped
        // node. With slab allocation, draining `SLAB_SIZE` nodes back must
        // recover every original node ID — including the one that took the
        // channel-and-drop detour.
        let pool = OsPool::new();
        let (tx, rx) = mpsc::channel::<OsBufMut>();

        let mut all = Vec::new();
        pool.alloc(64, SLAB_SIZE, &mut all);
        let originals: std::collections::HashSet<_> = all.iter().map(node_id).collect();

        // One node ships across threads; the rest drop locally back to pool.
        let buf = all.pop().unwrap();
        let id = node_id(&buf);
        drop(all);

        let dropper = thread::spawn(move || {
            let buf = rx.recv().unwrap();
            drop(buf);
        });
        tx.send(buf).unwrap();
        drop(tx);
        dropper.join().expect("dropper panicked");

        let mut drained = Vec::new();
        pool.alloc(64, SLAB_SIZE, &mut drained);
        let drained_ids: std::collections::HashSet<_> = drained.iter().map(node_id).collect();
        assert_eq!(drained_ids, originals, "all slab nodes recycled");
        assert!(
            drained_ids.contains(&id),
            "cross-thread-dropped node round-trips through the pool"
        );
    }

    // ── Multi-slab growth ────────────────────────────────────────────────────

    #[test]
    fn pool_second_slab_grown_on_exhaustion() {
        // Hold all SLAB_SIZE nodes from the first slab simultaneously, then
        // request one more. `grow_slab` must be called a second time and the
        // new node must come from fresh slab storage (not a recycled first-slab
        // node). This also verifies that the `Vec<Box<[OsBufNode]>>` inside
        // `consumer_lock` can reallocate its pointer array without invalidating
        // the MPSC queue's raw pointers into the first slab's heap allocation.
        let pool = OsPool::new();

        let mut held = Vec::new();
        pool.alloc(64, SLAB_SIZE, &mut held);
        assert_eq!(held.len(), SLAB_SIZE);
        let first_slab_ids: std::collections::HashSet<_> = held.iter().map(node_id).collect();

        // All first-slab nodes are live — next alloc must grow a second slab.
        let mut extra = Vec::new();
        pool.alloc(64, 1, &mut extra);
        assert_eq!(
            extra.len(),
            1,
            "alloc must succeed by growing a second slab"
        );
        assert!(
            !first_slab_ids.contains(&node_id(&extra[0])),
            "node from second slab must not alias any first-slab node"
        );

        // Drop everything; pool drop must not crash.
        drop(extra);
        drop(held);
        drop(pool);
    }

    #[test]
    fn pool_multi_slab_recycles_all_nodes() {
        // Allocate 2×SLAB_SIZE nodes (forcing two slabs to be grown), drop
        // all, then reallocate 2×SLAB_SIZE. The returned node ID set must be
        // identical — every node from both slabs must be recycled.
        let pool = OsPool::new();

        let mut round1 = Vec::new();
        pool.alloc(64, SLAB_SIZE, &mut round1); // first slab
        pool.alloc(64, SLAB_SIZE, &mut round1); // second slab (first still held)
        assert_eq!(round1.len(), 2 * SLAB_SIZE);

        let mut ids1: Vec<_> = round1.iter().map(node_id).collect();
        round1.clear(); // return all 2×SLAB_SIZE nodes to the pool

        let mut round2 = Vec::new();
        pool.alloc(64, 2 * SLAB_SIZE, &mut round2);
        assert_eq!(round2.len(), 2 * SLAB_SIZE);
        let mut ids2: Vec<_> = round2.iter().map(node_id).collect();

        ids1.sort();
        ids2.sort();
        assert_eq!(ids1, ids2, "all nodes from both slabs must be recycled");
    }

    #[test]
    fn pool_multi_slab_drop() {
        // Grow two slabs, return all nodes, then drop the pool. The
        // `Vec<Box<[OsBufNode]>>` must free both slab allocations without
        // crashing. ASan/Miri catch double-frees or leaks.
        let pool = OsPool::new();
        let mut bufs = Vec::new();
        pool.alloc(64, SLAB_SIZE, &mut bufs); // first slab
        pool.alloc(64, SLAB_SIZE, &mut bufs); // second slab (first still held)
        assert_eq!(bufs.len(), 2 * SLAB_SIZE);
        bufs.clear(); // enqueue all 2×SLAB_SIZE nodes back to the pool
        drop(pool);
    }

    // ── max_payload_size ─────────────────────────────────────────────────────

    #[test]
    fn pool_max_payload_size_default_is_ipv6() {
        let pool = OsPool::new();
        assert_eq!(pool.max_payload_size(), IPV6_MAX_UDP_PAYLOAD);
    }

    #[test]
    fn pool_max_payload_size_ipv4() {
        let pool = OsPool::with_max_payload(IPV4_MAX_UDP_PAYLOAD);
        assert_eq!(pool.max_payload_size(), IPV4_MAX_UDP_PAYLOAD);
    }

    // ── P2: buffer trait surface ─────────────────────────────────────────────

    #[test]
    fn osbuf_from_slice_round_trip() {
        let payload = b"hello-pool-less";
        let buf = OsBuf::from_slice(payload);
        assert_eq!(buf.as_ref(), payload);
        // Drop must free the heap allocation; ASan/Miri verify no leak.
        drop(buf);
    }

    #[test]
    fn osbufmut_init_uninit_split() {
        let pool = OsPool::new();
        let mut bufs = Vec::new();
        pool.alloc(256, 1, &mut bufs);
        let b = &mut bufs[0];

        assert!(b.filled().is_empty(), "fresh buffer should have len=0");
        assert!(b.capacity() >= 256, "capacity at least the requested 256");
        assert_eq!(
            b.uninit_mut().len(),
            b.capacity(),
            "uninit covers the full capacity when filled is empty"
        );
    }

    /// Regression for the S2 soundness fix: dropping the last `Arc<OsPool>`
    /// before outstanding buffers must not UAF. Each live buffer holds a
    /// strong ref via `OsBufNode::pool`, so the pool only drops once every
    /// buffer is gone.
    #[test]
    fn arc_in_node_pool_outlives_caller_arc() {
        let pool = OsPool::new();
        let mut bufs = Vec::new();
        pool.alloc(64, 4, &mut bufs);
        // Drop the caller's Arc while bufs still hold strong refs via the
        // node `pool` field — pool must remain alive.
        drop(pool);
        // Now drop the buffers: each push runs against a still-live pool.
        // ASan / Miri would catch a regression here.
        drop(bufs);
    }

    #[test]
    fn osbufmut_set_filled_and_freeze() {
        let pool = OsPool::new();
        let mut bufs = Vec::new();
        pool.alloc(64, 1, &mut bufs);
        let mut b = bufs.pop().unwrap();
        let pre_id = node_id(&b);

        // Write 5 bytes through uninit_mut, then set_filled(5).
        let bytes = b"hello";
        let uninit = b.uninit_mut();
        for (i, &x) in bytes.iter().enumerate() {
            uninit[i] = std::mem::MaybeUninit::new(x);
        }
        unsafe { b.set_filled(5) };
        assert_eq!(b.filled(), bytes);
        assert_eq!(b.uninit_mut().len(), b.capacity() - 5);

        // filled_mut roundtrip
        b.filled_mut()[0] = b'H';
        assert_eq!(b.filled(), b"Hello");

        // freeze keeps node identity (so drop returns it to pool) and bytes.
        let frozen = b.freeze();
        assert_eq!(frozen.as_ref(), b"Hello");
        assert_eq!(
            frozen_id(&frozen),
            pre_id,
            "freeze must preserve node identity for pool return"
        );
    }
}
