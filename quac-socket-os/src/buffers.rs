#[cfg(not(target_os = "linux"))]
use std::alloc::{alloc_zeroed, Layout};
use std::cell::UnsafeCell;
use std::mem::MaybeUninit;
use std::ptr::NonNull;
use std::thread::ThreadId;

use quac_socket::{MpscQueue, PacketBuf, PacketBufMut, RxPool};

/// Max UDP payload bytes the non-Linux fallback recv path stages. Linux uses
/// `recvmmsg` directly into caller-supplied buffers (no staging).
#[cfg(not(target_os = "linux"))]
pub(crate) const MAX_DATAGRAM: usize = 65535;

// ── MTU constants (re-exported from quac-socket::net) ────────────────────────

pub use quac_socket::net::{IPV4_MAX_UDP_PAYLOAD, IPV6_MAX_UDP_PAYLOAD, MAX_BUF_SIZE};

// ── NodePtr ──────────────────────────────────────────────────────────────────

/// Wrapper that makes `NonNull<OsBufNode>` sendable across threads.
///
/// # Safety
/// Callers guarantee that the pointed-to node is not accessed concurrently:
/// - same-thread drops read `pool` then push into the local `Vec` (owner only)
/// - cross-thread drops push the `NodePtr` into the MPSC queue and never touch
///   the node again; the consumer drains the queue on the owner thread
struct NodePtr(NonNull<OsBufNode>);
unsafe impl Send for NodePtr {}

// ── OsBufNode ────────────────────────────────────────────────────────────────

/// Heap-allocated node carrying a UDP payload, owned by an [`OsPool`] slab.
///
/// Pool-less nodes (from [`OsBuf::from_slice`]) use `pool: null()` and are
/// individually heap-allocated via [`Box`]; they are freed on drop.
pub(crate) struct OsBufNode {
    pub(crate) data: Vec<u8>,
    /// Raw pointer to the originating pool. Null for pool-less nodes.
    ///
    /// # Safety
    /// The pool must outlive all `OsBufNode` instances it created.
    pool: *const OsPool,
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

// Safety: `OsBuf`/`OsBufMut` carry a `*const OsPool` raw pointer (inside the
// node) and a `*mut u8` data pointer. The pool outlives all buffers (safety
// contract); the data pointer targets memory owned by the node's Vec, which
// moves with the wrapper. Cross-thread drops push to the pool's MPSC queue.
unsafe impl Send for OsBuf {}
unsafe impl Send for OsBufMut {}

fn return_node(node: NonNull<OsBufNode>) {
    let pool = unsafe { (*node.as_ptr()).pool };
    if pool.is_null() {
        // Pool-less (OsBuf::from_slice): free the Box allocation.
        unsafe { drop(Box::from_raw(node.as_ptr())) };
    } else {
        let pool = unsafe { &*pool };
        if std::thread::current().id() == pool.owner {
            // Same thread as the network tile: push to the local free list
            // (zero atomics).
            unsafe { (*pool.local.get()).push(NodePtr(node)) };
        } else {
            // Cross-thread drop: push to the bounded MPSC queue. If full,
            // the node pointer is dropped — its slab memory remains live
            // until the pool itself is freed, but it is no longer recycled.
            // With a 4096-slot queue this only happens under extreme bursts
            // where the IO tile cannot drain fast enough.
            let _ = pool.remote.push(NodePtr(node));
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
    /// Create a pool-less buffer from a byte slice.
    /// Freed to the heap on drop; not recycled. Test-only.
    #[cfg(test)]
    pub fn from_slice(data: &[u8]) -> Self {
        let node = Box::new(OsBufNode { data: data.to_vec(), pool: std::ptr::null() });
        OsBuf { node: NonNull::from(Box::leak(node)) }
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
        self.data_cap
    }

    #[inline]
    fn filled(&self) -> &[u8] {
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
        let node = self.node;
        std::mem::forget(self);
        OsBuf { node }
    }
}

// ── OsPool ────────────────────────────────────────────────────────────────────

/// Slab size for `OsPool` node growth. Picked to match `OsSocket::MAX_BATCH`
/// so a steady-state recv batch's worth of nodes share cache locality.
const SLAB_SIZE: usize = 64;

/// Per-socket buffer pool for [`OsSocket`](crate::OsSocket).
///
/// Backed by two free lists:
/// - `local`: a `UnsafeCell<Vec<NonNull<OsBufNode>>>` drained and filled only by
///   the network tile thread — zero atomics on the hot alloc path.
/// - `remote`: an MPSC queue fed by app threads dropping [`OsBuf`]s received
///   over an Rx channel. Each cross-thread drop allocates one small wrapper node
///   and performs one `AtomicPtr::swap`; the network thread batch-drains it into
///   `local` at the start of each `alloc` call.
///
/// Nodes are **slab-allocated**: `grow_slab` allocates a contiguous
/// `Box<[OsBufNode]>` of `SLAB_SIZE` nodes and pushes pointers into `local`.
/// Slabs live in `UnsafeCell<Vec<Box<[OsBufNode]>>>` and are freed with the pool.
///
/// **Safety contract**: no [`OsBuf`] or [`OsBufMut`] may outlive the `OsPool`
/// that allocated it. The pool is owned by the socket, which is the
/// longest-lived object on the tile. Violating this contract is undefined
/// behaviour.
///
/// Lives behind `Box` (use [`OsPool::new`] or [`OsPool::with_max_payload`]).
pub struct OsPool {
    max_payload: usize,
    /// Owner thread — the network tile thread. Same-thread drops reclaim directly
    /// into `local`; other threads push into `remote`.
    owner: ThreadId,
    /// Fast free list. Accessed only by the owning thread; no synchronisation needed.
    /// Uses [`NodePtr`] so cross-thread reclaims drained from `remote` can be
    /// appended without per-call allocation or wrapper conversion.
    local: UnsafeCell<Vec<NodePtr>>,
    /// Cross-thread return queue. App threads push here when dropping an [`OsBuf`]
    /// received over an Rx channel.
    remote: MpscQueue<NodePtr>,
    /// Slab storage. Owns the backing memory of every pool-allocated `OsBufNode`.
    /// Accessed only by the owning thread (inside `alloc` → `grow_slab`).
    slabs: UnsafeCell<Vec<Box<[OsBufNode]>>>,
}

// Safety: `local` and `slabs` are accessed only by the owner thread;
// `remote` is `Sync` via `MpscQueue`. The raw `*const OsPool` in each
// `OsBufNode` is only used on drop — same-thread drops use `local`
// (no atomics), cross-thread drops use `remote` (lock-free MPSC).
unsafe impl Send for OsPool {}
unsafe impl Sync for OsPool {}

impl OsPool {
    /// Construct a pool with the IPv6-MTU default payload (1452 bytes).
    pub fn new() -> Box<Self> {
        Self::with_max_payload(IPV6_MAX_UDP_PAYLOAD)
    }

    /// Construct a pool with an explicit max payload. Used by
    /// [`OsSocket::from_udp`] to set the address-family-specific value
    /// (1472 for IPv4, 1452 for IPv6).
    pub(crate) fn with_max_payload(max_payload: usize) -> Box<Self> {
        // Sized for the maximum number of cross-thread node returns that can
        // be in flight between drains: a full `tx_buf_queue` (1024) plus
        // engine-side caches, rx working set, and per-tile in-flight buffers.
        // 4096 leaves >2× headroom; if it ever fills the node is dropped on
        // the engine thread (its slab memory is leaked from the pool's
        // perspective until the pool is freed).
        const REMOTE_CAP: usize = 4096;
        Box::new(Self {
            max_payload,
            owner: std::thread::current().id(),
            local: UnsafeCell::new(Vec::new()),
            remote: MpscQueue::new(REMOTE_CAP),
            slabs: UnsafeCell::new(Vec::new()),
        })
    }

    /// Allocate a fresh slab of `SLAB_SIZE` `OsBufNode`s and push every node
    /// pointer into `local`. Must be called only from the owner thread.
    fn grow_slab(&self) {
        // Safety: called only from the owner thread (inside alloc).
        let local = unsafe { &mut *self.local.get() };
        let slabs = unsafe { &mut *self.slabs.get() };

        let mut slab: Box<[OsBufNode]> = (0..SLAB_SIZE)
            .map(|_| OsBufNode { data: Vec::new(), pool: self as *const OsPool })
            .collect();

        // Snapshot per-node pointers while we still hold `&mut slab`.
        // After `slab` is moved into `slabs`, the heap allocation it owns
        // doesn't move, so these pointers remain valid.
        let nodes: Vec<NodePtr> = slab.iter_mut().map(|n| NodePtr(NonNull::from(n))).collect();
        slabs.push(slab);
        local.extend(nodes);
    }
}

impl RxPool for OsPool {
    type Buf = OsBuf;
    type BufMut = OsBufMut;

    fn max_payload_size(&self) -> usize {
        self.max_payload
    }

    fn alloc(&self, capacity: usize, count: usize, bufs: &mut Vec<OsBufMut>) -> usize {
        let capacity = capacity.min(MAX_BUF_SIZE);
        // Safety: alloc is called only by the owner thread.
        let local = unsafe { &mut *self.local.get() };

        // Batch-drain cross-thread returns directly into the local list.
        unsafe { self.remote.drain_into(local) };

        bufs.reserve(count);
        for _ in 0..count {
            let mut node = match local.pop() {
                Some(NodePtr(n)) => n,
                None => {
                    self.grow_slab();
                    let NodePtr(n) = local.pop().expect("grow_slab must populate local");
                    n
                }
            };
            let node_mut = unsafe { node.as_mut() };
            node_mut.data.clear();
            if node_mut.data.capacity() < capacity {
                node_mut.data.reserve(capacity);
            }
            let data_ptr = node_mut.data.as_mut_ptr();
            let data_cap = node_mut.data.capacity();
            bufs.push(OsBufMut { node, data_ptr, data_cap, data_len: 0 });
        }
        count
    }
}

impl quac_socket::TxPool for OsPool {
    type Buf = OsBuf;
    type BufMut = OsBufMut;
    type RxBufMut = OsBufMut;
    const UNIFIED: bool = true;

    fn max_payload_size(&self) -> usize {
        self.max_payload
    }

    fn alloc(&self, capacity: usize, count: usize, bufs: &mut Vec<OsBufMut>) -> usize {
        <Self as RxPool>::alloc(self, capacity, count, bufs)
    }

    fn zerocopy_threshold(&self) -> usize {
        // OS sockets pass scatter-gather to the kernel via sendmmsg's iov
        // array — coalescing into a contiguous buffer is never required.
        0
    }

    fn available(&self) -> usize {
        // Safety: called only by the owner thread.
        let local = unsafe { &mut *self.local.get() };
        unsafe { self.remote.drain_into(local) };
        local.len()
    }

    fn from_rx(&self, rx: OsBufMut) -> Result<OsBufMut, OsBufMut> {
        Ok(rx)
    }

    fn from_rx_unified(rx: OsBufMut) -> OsBufMut {
        rx
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
    use quac_socket::{PacketBufMut, RxPool};

    /// Stable pointer identifying the heap-allocated node inside an `OsBufMut`.
    fn node_id(b: &OsBufMut) -> *const OsBufNode {
        b.node.as_ptr() as *const OsBufNode
    }

    fn frozen_id(b: &OsBuf) -> *const OsBufNode {
        b.node.as_ptr() as *const OsBufNode
    }

    // ── P1: pool ─────────────────────────────────────────────────────────────

    #[test]
    fn pool_alloc_then_drop_recycles() {
        let pool = OsPool::new();

        let mut bufs1 = Vec::new();
        pool.alloc(64, SLAB_SIZE, &mut bufs1);
        let mut ids1: Vec<_> = bufs1.iter().map(node_id).collect();
        bufs1.clear(); // drop returns every node to the pool's local list

        let mut bufs2 = Vec::new();
        pool.alloc(64, SLAB_SIZE, &mut bufs2);
        let mut ids2: Vec<_> = bufs2.iter().map(node_id).collect();

        ids1.sort();
        ids2.sort();
        assert_eq!(ids1, ids2, "every node should be recycled — no fresh slab grown");
    }

    #[test]
    fn pool_alloc_appends_without_clearing() {
        let pool = OsPool::new();
        let mut bufs = Vec::new();
        pool.alloc(8, 2, &mut bufs);
        assert_eq!(bufs.len(), 2);
        pool.alloc(8, 3, &mut bufs);
        assert_eq!(bufs.len(), 5);
    }

    #[test]
    fn pool_alloc_grows_capacity() {
        let pool = OsPool::new();
        let mut bufs = Vec::new();

        pool.alloc(64, 1, &mut bufs);
        assert!(bufs[0].capacity() >= 64);
        bufs.clear();

        pool.alloc(MAX_BUF_SIZE, 1, &mut bufs);
        assert!(bufs[0].capacity() >= MAX_BUF_SIZE);
        assert!(bufs[0].uninit_mut().len() >= MAX_BUF_SIZE);
        bufs.clear();

        pool.alloc(MAX_BUF_SIZE * 4, 1, &mut bufs);
        assert!(bufs[0].capacity() >= MAX_BUF_SIZE);
    }

    #[test]
    fn pool_drop_drains_queued_nodes() {
        let pool = OsPool::new();
        let mut bufs = Vec::new();
        pool.alloc(128, 32, &mut bufs);
        bufs.clear();
        drop(pool);
    }

    // ── Multi-slab growth ────────────────────────────────────────────────────

    #[test]
    fn pool_second_slab_grown_on_exhaustion() {
        let pool = OsPool::new();

        let mut held = Vec::new();
        pool.alloc(64, SLAB_SIZE, &mut held);
        assert_eq!(held.len(), SLAB_SIZE);
        let first_slab_ids: std::collections::HashSet<_> = held.iter().map(node_id).collect();

        let mut extra = Vec::new();
        pool.alloc(64, 1, &mut extra);
        assert_eq!(extra.len(), 1, "alloc must succeed by growing a second slab");
        assert!(
            !first_slab_ids.contains(&node_id(&extra[0])),
            "node from second slab must not alias any first-slab node"
        );

        drop(extra);
        drop(held);
        drop(pool);
    }

    #[test]
    fn pool_multi_slab_recycles_all_nodes() {
        let pool = OsPool::new();

        let mut round1 = Vec::new();
        pool.alloc(64, SLAB_SIZE, &mut round1);
        pool.alloc(64, SLAB_SIZE, &mut round1);
        assert_eq!(round1.len(), 2 * SLAB_SIZE);

        let mut ids1: Vec<_> = round1.iter().map(node_id).collect();
        round1.clear();

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
        let pool = OsPool::new();
        let mut bufs = Vec::new();
        pool.alloc(64, SLAB_SIZE, &mut bufs);
        pool.alloc(64, SLAB_SIZE, &mut bufs);
        assert_eq!(bufs.len(), 2 * SLAB_SIZE);
        bufs.clear();
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

    // ── Cross-thread drop ─────────────────────────────────────────────────────

    #[test]
    fn cross_thread_drop_recycles_via_remote_queue() {
        use std::sync::Arc;

        // Wrap in Arc for the test (production uses Box exclusively).
        let pool = Arc::new(OsPool::with_max_payload(IPV4_MAX_UDP_PAYLOAD));

        let mut bufs = Vec::new();
        pool.alloc(64, SLAB_SIZE, &mut bufs);
        let originals: std::collections::HashSet<_> = bufs.iter().map(node_id).collect();

        let buf = bufs.pop().unwrap();
        let id = node_id(&buf);
        drop(bufs);

        let frozen = buf.freeze();
        let handle = std::thread::spawn(move || drop(frozen));
        handle.join().unwrap();

        let mut drained = Vec::new();
        pool.alloc(64, SLAB_SIZE, &mut drained);
        let drained_ids: std::collections::HashSet<_> = drained.iter().map(node_id).collect();
        assert_eq!(drained_ids, originals, "all slab nodes recycled");
        assert!(
            drained_ids.contains(&id),
            "cross-thread-dropped node must round-trip through the pool"
        );
    }

    // ── P2: buffer trait surface ─────────────────────────────────────────────

    #[test]
    fn osbuf_from_slice_round_trip() {
        let payload = b"hello-pool-less";
        let buf = OsBuf::from_slice(payload);
        assert_eq!(buf.as_ref(), payload);
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

    #[test]
    fn osbufmut_set_filled_and_freeze() {
        let pool = OsPool::new();
        let mut bufs = Vec::new();
        pool.alloc(64, 1, &mut bufs);
        let mut b = bufs.pop().unwrap();
        let pre_id = node_id(&b);

        let bytes = b"hello";
        let uninit = b.uninit_mut();
        for (i, &x) in bytes.iter().enumerate() {
            uninit[i] = std::mem::MaybeUninit::new(x);
        }
        unsafe { b.set_filled(5) };
        assert_eq!(b.filled(), bytes);
        assert_eq!(b.uninit_mut().len(), b.capacity() - 5);

        b.filled_mut()[0] = b'H';
        assert_eq!(b.filled(), b"Hello");

        let frozen = b.freeze();
        assert_eq!(frozen.as_ref(), b"Hello");
        assert_eq!(
            frozen_id(&frozen),
            pre_id,
            "freeze must preserve node identity for pool return"
        );
    }

    // ── available() ──────────────────────────────────────────────────────────
    //
    // These tests call available() via UFCS (<OsPool as TxPool>::available)
    // rather than importing TxPool, so that pool.alloc() remains unambiguous
    // (resolves to RxPool::alloc, the only alloc in scope).

    #[test]
    fn available_zero_on_fresh_pool() {
        let pool = OsPool::new();
        assert_eq!(
            <OsPool as quac_socket::TxPool>::available(&pool),
            0,
            "fresh pool has no slabs yet"
        );
    }

    #[test]
    fn available_reflects_same_thread_reclaim() {
        let pool = OsPool::new();
        let mut bufs = Vec::new();
        pool.alloc(64, SLAB_SIZE, &mut bufs);
        assert_eq!(<OsPool as quac_socket::TxPool>::available(&pool), 0, "all nodes are live");
        bufs.clear(); // same-thread drop → local free list
        assert_eq!(<OsPool as quac_socket::TxPool>::available(&pool), SLAB_SIZE);
    }

    #[test]
    fn available_does_not_count_live_buffers() {
        let pool = OsPool::new();
        let mut bufs = Vec::new();
        pool.alloc(64, SLAB_SIZE, &mut bufs);
        assert_eq!(<OsPool as quac_socket::TxPool>::available(&pool), 0);
        let _ = &bufs; // keep alive
    }

    #[test]
    fn available_drains_cross_thread_returns() {
        use std::sync::Arc;

        let pool = Arc::new(OsPool::with_max_payload(IPV4_MAX_UDP_PAYLOAD));
        let mut bufs = Vec::new();
        pool.alloc(64, SLAB_SIZE, &mut bufs);
        assert_eq!(<OsPool as quac_socket::TxPool>::available(&pool), 0);

        // Drop half the buffers on a foreign thread — they land in `remote`.
        let half: Vec<_> = bufs.drain(..SLAB_SIZE / 2).collect();
        std::thread::spawn(move || drop(half)).join().unwrap();

        // available() must drain `remote` into `local` before counting.
        assert_eq!(
            <OsPool as quac_socket::TxPool>::available(&pool),
            SLAB_SIZE / 2,
            "cross-thread returns must be visible via available()"
        );
    }
}
