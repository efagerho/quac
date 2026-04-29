use std::alloc::{alloc_zeroed, Layout};
use std::cell::UnsafeCell;
use std::ptr::{self, NonNull};
use std::sync::Arc;
use std::sync::atomic::{AtomicPtr, Ordering};

use quac_socket::{BufferPool, PacketBuf, PacketBufMut};

pub(crate) const MAX_DATAGRAM: usize = 65535;

// ── OsBufNode ────────────────────────────────────────────────────────────────

/// Heap-allocated intrusive node carrying a UDP payload.
///
/// Allocated via `Box::leak`; freed by `Box::from_raw` when `queue` is null
/// (pool-less buffers), or returned to the owning `OsPool` via `push` otherwise.
pub(crate) struct OsBufNode {
    pub(crate) data: Vec<u8>,
    /// Intrusive MPSC link. Written by drop (producers); read by pop_raw (consumer).
    next: AtomicPtr<OsBufNode>,
    /// Back-pointer to the owning pool. Null for stub nodes and pool-less buffers.
    queue: *const OsPool,
}

// ── OsBuf / OsBufMut ─────────────────────────────────────────────────────────

/// Frozen (Tx) buffer. Returned to its owning pool on drop.
pub struct OsBuf(NonNull<OsBufNode>);

/// Mutable (Rx) buffer. Returned to its owning pool on drop.
pub struct OsBufMut(NonNull<OsBufNode>);

// Safety: nodes are heap-allocated; the `queue` raw pointer is valid for the
// lifetime of the Arc<OsPool> that holds the pool (architectural invariant).
unsafe impl Send for OsBuf {}
unsafe impl Send for OsBufMut {}

fn return_node(node: NonNull<OsBufNode>) {
    let queue = unsafe { node.as_ref().queue };
    if queue.is_null() {
        // Pool-less (OsBuf::from_slice): reclaim the Box allocation.
        unsafe { drop(Box::from_raw(node.as_ptr())) };
    } else {
        unsafe { (*queue).push(node) };
    }
}

impl Drop for OsBuf {
    fn drop(&mut self) {
        return_node(self.0);
    }
}

impl Drop for OsBufMut {
    fn drop(&mut self) {
        return_node(self.0);
    }
}

impl AsRef<[u8]> for OsBuf {
    fn as_ref(&self) -> &[u8] {
        unsafe { &self.0.as_ref().data }
    }
}

impl AsRef<[u8]> for OsBufMut {
    fn as_ref(&self) -> &[u8] {
        unsafe { &self.0.as_ref().data }
    }
}

impl AsMut<[u8]> for OsBufMut {
    fn as_mut(&mut self) -> &mut [u8] {
        unsafe { &mut self.0.as_mut().data }
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
            queue: ptr::null(),
        });
        OsBuf(NonNull::from(Box::leak(node)))
    }
}

impl PacketBufMut for OsBufMut {
    type Frozen = OsBuf;

    fn freeze(self) -> OsBuf {
        // Transfer node ownership without touching any atomic or pool pointer.
        let node = self.0;
        std::mem::forget(self);
        OsBuf(node)
    }

    fn resize(&mut self, new_len: usize) {
        let data = self.data_mut();
        if data.capacity() < new_len {
            data.reserve(new_len - data.len());
        }
        // Safety: u8 has no invalid bit patterns; caller writes [0..new_len]
        // before any read (copy_from_slice in enqueue_transmit).
        unsafe { data.set_len(new_len) }
    }
}

impl OsBufMut {
    /// Direct access to the payload `Vec` for the recv path's `extend_from_slice`.
    pub(crate) fn data_mut(&mut self) -> &mut Vec<u8> {
        unsafe { &mut self.0.as_mut().data }
    }
}

// ── OsPool — Vyukov intrusive MPSC queue ─────────────────────────────────────

/// Per-socket buffer pool implemented as a Vyukov intrusive MPSC linked list.
///
/// **Consumer** (Rx thread): `pop_raw()` / `BufferPool::alloc()` — no CAS, just loads.
/// **Producers** (any thread dropping an `OsBuf`/`OsBufMut`): `push()` — one `XCHG`.
///
/// Must live behind `Arc` (use `OsPool::new()`); the stub sentinel's address is
/// baked into `head`/`tail` at construction and must remain stable.
pub struct OsPool {
    /// Consumer-only. Only the owning Rx thread reads or writes this field.
    head: UnsafeCell<*mut OsBufNode>,
    /// Shared tail; written atomically by all producers and by `pop_raw` when
    /// re-injecting the stub.
    tail: AtomicPtr<OsBufNode>,
    /// Sentinel node. Always present in the queue; never returned to callers.
    stub: OsBufNode,
}

// Safety: `head` is accessed only by the consumer thread; `tail` and `stub.next`
// use sequentially-consistent atomic ops; raw pointers satisfy the Arc invariant.
unsafe impl Send for OsPool {}
unsafe impl Sync for OsPool {}

impl OsPool {
    pub fn new() -> Arc<Self> {
        let pool = Arc::new(Self {
            head: UnsafeCell::new(ptr::null_mut()),
            tail: AtomicPtr::new(ptr::null_mut()),
            stub: OsBufNode {
                data: Vec::new(),
                next: AtomicPtr::new(ptr::null_mut()),
                queue: ptr::null(),
            },
        });
        // Wire head and tail to the stub. The Arc heap allocation is stable.
        let stub_ptr = &pool.stub as *const OsBufNode as *mut OsBufNode;
        unsafe { *pool.head.get() = stub_ptr }
        pool.tail.store(stub_ptr, Ordering::Relaxed);
        pool
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
        let stub_ptr = &self.stub as *const OsBufNode as *mut OsBufNode;
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

impl Drop for OsPool {
    fn drop(&mut self) {
        // Drain queued nodes to free their Vec allocations.
        // Safety: refcount is zero — no concurrent producers remain.
        while let Some(node) = unsafe { self.pop_raw() } {
            unsafe { drop(Box::from_raw(node.as_ptr())) };
        }
    }
}

impl BufferPool for OsPool {
    type Buf = OsBuf;
    type BufMut = OsBufMut;

    fn alloc(&self, capacity: usize, count: usize, bufs: &mut Vec<OsBufMut>) -> usize {
        for _ in 0..count {
            let mut node = unsafe { self.pop_raw() }.unwrap_or_else(|| {
                let n = Box::new(OsBufNode {
                    data: Vec::with_capacity(capacity),
                    next: AtomicPtr::new(ptr::null_mut()),
                    queue: self as *const OsPool,
                });
                NonNull::from(Box::leak(n))
            });
            let data = &mut unsafe { node.as_mut() }.data;
            if data.capacity() < capacity {
                data.reserve(capacity - data.len());
            }
            // Safety: u8 has no invalid bit patterns; alloc_tx_bufs callers
            // write [0..size] via copy_from_slice before transmitting.
            unsafe { data.set_len(capacity) };
            bufs.push(OsBufMut(node));
        }
        count
    }

    fn zerocopy_threshold(&self) -> usize {
        usize::MAX
    }
}

/// Pop a buffer from the pool ready for the recv path to fill via `extend_from_slice`.
/// Recycles a queued node when available; otherwise allocates from the heap.
pub(crate) fn pop_recv_buf(len: usize, pool: &Arc<OsPool>) -> OsBufMut {
    let mut node = unsafe { pool.pop_raw() }.unwrap_or_else(|| {
        let n = Box::new(OsBufNode {
            data: Vec::with_capacity(len),
            next: AtomicPtr::new(ptr::null_mut()),
            queue: Arc::as_ptr(pool),
        });
        NonNull::from(Box::leak(n))
    });
    let data = &mut unsafe { node.as_mut() }.data;
    data.clear();
    if data.capacity() < len {
        data.reserve(len - data.capacity());
    }
    OsBufMut(node)
}

// ── RecvBuf ──────────────────────────────────────────────────────────────────

/// Kernel-facing receive buffer aligned to 64 bytes for `recvmmsg`.
#[repr(align(64))]
pub(crate) struct RecvBuf(pub(crate) [u8; MAX_DATAGRAM]);

pub(crate) fn alloc_recv_buf() -> Box<RecvBuf> {
    let layout = Layout::new::<RecvBuf>();
    let ptr = unsafe { alloc_zeroed(layout) as *mut RecvBuf };
    if ptr.is_null() {
        std::alloc::handle_alloc_error(layout);
    }
    unsafe { Box::from_raw(ptr) }
}
