#[cfg(not(target_os = "linux"))]
use std::alloc::{alloc_zeroed, Layout};
use std::cell::UnsafeCell;
use std::mem::MaybeUninit;
use std::ptr::NonNull;
use std::thread::ThreadId;

use quac_socket::{MpscQueue, PacketBuf, PacketBufMut, RxPool};

/// Max UDP payload staged by the non-Linux fallback recv. Linux's recvmmsg
/// writes directly into caller buffers.
#[cfg(not(target_os = "linux"))]
pub(crate) const MAX_DATAGRAM: usize = 65535;

pub use quac_socket::net::{IPV4_MAX_UDP_PAYLOAD, IPV6_MAX_UDP_PAYLOAD, MAX_BUF_SIZE};

/// `Send` wrapper around `NonNull<OsBufNode>`. Safety: same-thread accesses
/// go through `pool.local`; cross-thread drops push into the MPSC and never
/// touch the node again.
struct NodePtr(NonNull<OsBufNode>);
unsafe impl Send for NodePtr {}

/// Heap node owning a UDP payload (slab-allocated, or `Box`'d when pool-less).
pub(crate) struct OsBufNode {
    pub(crate) data: Vec<u8>,
    /// Originating pool. Null for pool-less nodes (freed on drop).
    pool: *const OsPool,
}

/// Frozen (Tx) buffer; returned to the pool on drop.
pub struct OsBuf {
    node: NonNull<OsBufNode>,
}

/// Mutable (Rx) buffer. Caches `(data_ptr, data_cap, data_len)` so the recv
/// hot path doesn't dereference the heap-scattered `OsBufNode`. Cache is set
/// in `OsPool::alloc` and kept in sync by `set_filled` -- no operation resizes
/// the Vec, so `data_ptr`/`data_cap` are stable. Size: 32 B on 64-bit.
pub struct OsBufMut {
    node: NonNull<OsBufNode>,
    data_ptr: *mut u8,
    data_cap: usize,
    data_len: usize,
}

// Safety: pool outlives all buffers (safety contract). Data pointer targets
// the node's Vec, which moves with the wrapper. Cross-thread drops route
// through the pool's MPSC queue.
unsafe impl Send for OsBuf {}
unsafe impl Send for OsBufMut {}

fn return_node(node: NonNull<OsBufNode>) {
    let pool = unsafe { (*node.as_ptr()).pool };
    if pool.is_null() {
        // Pool-less (OsBuf::from_slice): free the Box.
        unsafe { drop(Box::from_raw(node.as_ptr())) };
    } else {
        let pool = unsafe { &*pool };
        if std::thread::current().id() == pool.owner {
            // Same thread: push to local free list (no atomics).
            unsafe { (*pool.local.get()).push(NodePtr(node)) };
        } else {
            // Cross-thread: push to MPSC. If full, slab is leaked from the
            // pool's perspective until the pool drops (4096 slots → only
            // under extreme bursts the IO tile can't drain).
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
    /// Cached iov_base; lets `recv` wire the kernel iov without OsBufNode deref.
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

/// Slab size; matches `OsSocket::MAX_BATCH` so a recv batch fits one slab.
const SLAB_SIZE: usize = 64;

/// Per-socket buffer pool. Two free lists: `local` (owner-thread only,
/// no atomics) and `remote` (MPSC for cross-thread drops). Nodes are
/// slab-allocated in `Box<[OsBufNode]>` chunks of `SLAB_SIZE`. SAFETY:
/// no `OsBuf`/`OsBufMut` may outlive the pool; pool lives behind `Box`.
pub struct OsPool {
    max_payload: usize,
    /// Owner thread (same-thread drops → local; others → remote).
    owner: ThreadId,
    /// Owner-thread-only free list (no atomics).
    local: UnsafeCell<Vec<NodePtr>>,
    /// Cross-thread return queue.
    remote: MpscQueue<NodePtr>,
    /// Slab storage (owner-thread only; in `alloc` → `grow_slab`).
    slabs: UnsafeCell<Vec<Box<[OsBufNode]>>>,
}

// Safety: local/slabs are owner-thread only; remote is `Sync` via MpscQueue.
// `*const OsPool` in each node is read only on drop.
unsafe impl Send for OsPool {}
unsafe impl Sync for OsPool {}

impl OsPool {
    /// Construct with IPv6-MTU default payload (1452 B).
    pub fn new() -> Box<Self> {
        Self::with_max_payload(IPV6_MAX_UDP_PAYLOAD)
    }

    /// Construct with explicit max payload (1472 v4, 1452 v6).
    pub(crate) fn with_max_payload(max_payload: usize) -> Box<Self> {
        // Sized for tx_buf_queue (1024) + engine caches + rx working set +
        // in-flight, with >2× headroom. Overflow drops the node (slab is
        // leaked from the pool's perspective until pool drops).
        const REMOTE_CAP: usize = 4096;
        Box::new(Self {
            max_payload,
            owner: std::thread::current().id(),
            local: UnsafeCell::new(Vec::new()),
            remote: MpscQueue::new(REMOTE_CAP),
            slabs: UnsafeCell::new(Vec::new()),
        })
    }

    /// Allocate a slab and push pointers to local. Owner-thread only.
    fn grow_slab(&self) {
        // SAFETY: owner thread only (inside alloc).
        let local = unsafe { &mut *self.local.get() };
        let slabs = unsafe { &mut *self.slabs.get() };

        let mut slab: Box<[OsBufNode]> = (0..SLAB_SIZE)
            .map(|_| OsBufNode { data: Vec::new(), pool: self as *const OsPool })
            .collect();

        // Snapshot pointers before moving slab; heap addresses stay valid.
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
        // SAFETY: owner thread only.
        let local = unsafe { &mut *self.local.get() };

        // Drain remote into local.
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
        // sendmmsg passes iov directly; coalescing not needed.
        0
    }

    fn available(&self) -> usize {
        // SAFETY: owner thread only.
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
        assert_eq!(ids1, ids2, "every node should be recycled - no fresh slab grown");
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

        // Drop half the buffers on a foreign thread -- they land in `remote`.
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
