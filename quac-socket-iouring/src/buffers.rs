use std::cell::UnsafeCell;
use std::mem::{self, MaybeUninit};
use std::slice;
use std::thread::ThreadId;

use quac_socket::{MpscQueue, PacketBuf, PacketBufMut, RxPool, TxPool};

use crate::socket::RingReclaimer;

// ── MTU constants (re-exported from quac-socket::net) ────────────────────────

pub use quac_socket::net::{IPV4_MAX_UDP_PAYLOAD, IPV6_MAX_UDP_PAYLOAD, MAX_BUF_SIZE};

// ── IoRxPool ──────────────────────────────────────────────────────────────────

/// Marker pool for the receive side.
///
/// Holds no memory of its own — ring slots belong to the provided-buffer ring,
/// supplied by the kernel via recv. [`alloc`](RxPool::alloc) returns zero-cost
/// [`IoRxBufMut::Empty`] placeholders that `recv` swaps for Ring-backed buffers
/// as CQEs arrive.
pub struct IoRxPool {
    pub(crate) max_payload: usize,
}

impl RxPool for IoRxPool {
    type Buf = IoRxBuf;
    type BufMut = IoRxBufMut;

    fn max_payload_size(&self) -> usize {
        self.max_payload
    }

    fn alloc(&self, _capacity: usize, count: usize, bufs: &mut Vec<IoRxBufMut>) -> usize {
        bufs.reserve(count);
        for _ in 0..count {
            bufs.push(IoRxBufMut { repr: IoRxBufMutRepr::Empty });
        }
        count
    }
}

// ── IoTxPool ──────────────────────────────────────────────────────────────────

/// Heap allocator for transmit-side buffers.
///
/// Backed by two free lists:
/// - `local`: a `UnsafeCell<Vec<Vec<u8>>>` drained and filled only by the network
///   tile thread — zero atomics on the hot alloc path.
/// - `remote`: an MPSC queue fed by app threads dropping [`IoTxBuf`]s received
///   over a channel. Each cross-thread drop performs one `AtomicPtr::swap`; the
///   network thread batch-drains it into `local` at the start of each `alloc` call.
///
/// **Safety contract**: no [`IoTxBuf`] or [`IoTxBufMut`] may outlive the
/// `IoTxPool` that allocated it. The pool is owned by the socket, which is the
/// longest-lived object on the tile.
pub struct IoTxPool {
    pub(crate) max_payload: usize,
    owner: ThreadId,
    local: UnsafeCell<Vec<Vec<u8>>>,
    remote: MpscQueue<Vec<u8>>,
}

// Safety: `local` is accessed only by the owner thread; `remote` is `Sync` via
// `MpscQueue`. Raw `*const IoTxPool` pointers in buffers only call back into
// the pool on drop.
unsafe impl Send for IoTxPool {}
unsafe impl Sync for IoTxPool {}

impl IoTxPool {
    pub fn new() -> Box<Self> {
        Self::with_max_payload(IPV6_MAX_UDP_PAYLOAD)
    }

    pub fn with_max_payload(max_payload: usize) -> Box<Self> {
        // Sized for the maximum number of `Vec<u8>` reclamations that can be
        // in flight between drains: a full `tx_buf_queue` (1024) plus engine
        // cache, send slots, and tx_q in-flight. 4096 leaves >2× headroom; if
        // it ever fills the buffer is dropped and the pool grows on next alloc.
        const REMOTE_CAP: usize = 4096;
        Box::new(Self {
            max_payload,
            owner: std::thread::current().id(),
            local: UnsafeCell::new(Vec::new()),
            remote: MpscQueue::new(REMOTE_CAP),
        })
    }

    #[inline]
    fn reclaim_local(&self, v: Vec<u8>) {
        unsafe { (*self.local.get()).push(v) };
    }

    #[inline]
    fn reclaim_remote(&self, v: Vec<u8>) {
        // If the queue overflows, drop `v` — the pool effectively shrinks by
        // one buffer. The `Vec`'s heap memory is still freed by the drop, so
        // there is no leak; just lost recycling.
        let _ = self.remote.push(v);
    }
}

impl TxPool for IoTxPool {
    type Buf = IoTxBuf;
    type BufMut = IoTxBufMut;
    type RxBufMut = IoRxBufMut;
    const UNIFIED: bool = false;

    fn max_payload_size(&self) -> usize {
        self.max_payload
    }

    fn alloc(&self, capacity: usize, count: usize, bufs: &mut Vec<IoTxBufMut>) -> usize {
        let capacity = capacity.min(self.max_payload);
        let local = unsafe { &mut *self.local.get() };

        unsafe { self.remote.drain_into(local) };

        bufs.reserve(count);
        let pool_ptr = self as *const IoTxPool;
        for _ in 0..count {
            let mut v = match local.pop() {
                Some(v) => v,
                None => Vec::with_capacity(capacity),
            };
            v.clear();
            if v.capacity() < capacity {
                v.reserve(capacity - v.capacity());
            }
            bufs.push(IoTxBufMut { data: v, pool: pool_ptr });
        }
        count
    }

    fn zerocopy_threshold(&self) -> usize {
        0
    }

    fn from_rx(&self, rx: IoRxBufMut) -> Result<IoTxBufMut, IoRxBufMut> {
        let mut tmp = Vec::new();
        if self.alloc(self.max_payload, 1, &mut tmp) == 0 {
            return Err(rx);
        }
        let mut tx = tmp.pop().unwrap();
        match &rx.repr {
            IoRxBufMutRepr::Empty => panic!("from_rx called on empty placeholder"),
            IoRxBufMutRepr::Ring { payload, len, .. } => {
                let len = *len;
                // Safety: tx.data was just alloc'd with capacity >= max_payload;
                // `len` was validated against max_payload in drain_cqes_into.
                unsafe {
                    std::ptr::copy_nonoverlapping(*payload, tx.data.as_mut_ptr(), len);
                    tx.data.set_len(len);
                }
                drop(rx);
                Ok(tx)
            }
        }
    }
}

// ── IoRxBufMut ────────────────────────────────────────────────────────────────

pub(crate) enum IoRxBufMutRepr {
    /// Zero-cost placeholder returned by [`IoRxPool::alloc`].
    /// `recv` swaps this for `Ring` when a CQE arrives. Drop is a no-op.
    Empty,
    /// Zero-copy receive buffer wrapping a provided-buffer ring slot.
    Ring {
        payload: *const u8,
        len: usize,
        cap: usize,
        bid: u16,
        reclaimer: *const RingReclaimer,
    },
}

// Safety: cross-thread drop of Ring pushes `bid` to reclaimer.remote (MPSC).
unsafe impl Send for IoRxBufMutRepr {}

/// Mutable receive buffer. Either a zero-cost placeholder (`Empty`) or a
/// kernel-filled ring slot (`Ring`).
pub struct IoRxBufMut {
    pub(crate) repr: IoRxBufMutRepr,
}

unsafe impl Send for IoRxBufMut {}

impl Drop for IoRxBufMut {
    fn drop(&mut self) {
        match &self.repr {
            IoRxBufMutRepr::Empty => {}
            IoRxBufMutRepr::Ring { bid, reclaimer, .. } => {
                let rec = unsafe { &**reclaimer };
                if std::thread::current().id() == rec.owner {
                    unsafe { (*rec.pending.get()).push(*bid) };
                } else {
                    // Queue is sized for >= BUF_RING_COUNT, so this never
                    // overflows in practice. Losing a bid here would leak a
                    // ring slot permanently, so panic if it ever does.
                    rec.remote
                        .push(*bid)
                        .expect("reclaimer.remote queue full — sized < BUF_RING_COUNT");
                }
            }
        }
    }
}

impl PacketBufMut for IoRxBufMut {
    type Frozen = IoRxBuf;

    #[inline]
    fn capacity(&self) -> usize {
        match &self.repr {
            IoRxBufMutRepr::Empty => 0,
            IoRxBufMutRepr::Ring { cap, .. } => *cap,
        }
    }

    #[inline]
    fn filled(&self) -> &[u8] {
        match &self.repr {
            IoRxBufMutRepr::Empty => &[],
            IoRxBufMutRepr::Ring { payload, len, .. } => {
                unsafe { slice::from_raw_parts(*payload, *len) }
            }
        }
    }

    #[inline]
    fn filled_mut(&mut self) -> &mut [u8] {
        match &mut self.repr {
            IoRxBufMutRepr::Empty => &mut [],
            IoRxBufMutRepr::Ring { payload, len, .. } => {
                unsafe { slice::from_raw_parts_mut(*payload as *mut u8, *len) }
            }
        }
    }

    #[inline]
    fn uninit_mut(&mut self) -> &mut [MaybeUninit<u8>] {
        match &mut self.repr {
            IoRxBufMutRepr::Empty => &mut [],
            IoRxBufMutRepr::Ring { payload, len, cap, .. } => unsafe {
                slice::from_raw_parts_mut(
                    (*payload as *mut u8).add(*len) as *mut MaybeUninit<u8>,
                    *cap - *len,
                )
            },
        }
    }

    #[inline]
    unsafe fn set_filled(&mut self, new_len: usize) {
        match &mut self.repr {
            IoRxBufMutRepr::Empty => {}
            IoRxBufMutRepr::Ring { len, cap, .. } => {
                debug_assert!(new_len <= *cap);
                *len = new_len;
            }
        }
    }

    fn freeze(mut self) -> IoRxBuf {
        match mem::replace(&mut self.repr, IoRxBufMutRepr::Empty) {
            IoRxBufMutRepr::Empty => panic!("freeze called on empty IoRxBufMut placeholder"),
            IoRxBufMutRepr::Ring { payload, len, bid, reclaimer, .. } => {
                mem::forget(self);
                IoRxBuf { payload, len, bid, reclaimer }
            }
        }
    }
}

impl IoRxBufMut {
    /// Wrap a provided-buffer ring slot for zero-copy recv.
    ///
    /// # Safety
    /// `payload` must point into the ring slot's payload area and remain valid
    /// until the buffer is dropped. `reclaimer` must outlive this buffer.
    pub(crate) fn from_ring_slot(
        payload: *const u8,
        len: usize,
        cap: usize,
        bid: u16,
        reclaimer: *const RingReclaimer,
    ) -> Self {
        Self { repr: IoRxBufMutRepr::Ring { payload, len, cap, bid, reclaimer } }
    }
}

// ── IoRxBuf ───────────────────────────────────────────────────────────────────

/// Frozen receive buffer wrapping a ring slot. Returned to the ring on drop.
pub struct IoRxBuf {
    payload: *const u8,
    len: usize,
    bid: u16,
    reclaimer: *const RingReclaimer,
}

unsafe impl Send for IoRxBuf {}

impl Drop for IoRxBuf {
    fn drop(&mut self) {
        let rec = unsafe { &*self.reclaimer };
        if std::thread::current().id() == rec.owner {
            unsafe { (*rec.pending.get()).push(self.bid) };
        } else {
            rec.remote
                .push(self.bid)
                .expect("reclaimer.remote queue full — sized < BUF_RING_COUNT");
        }
    }
}

impl AsRef<[u8]> for IoRxBuf {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        unsafe { slice::from_raw_parts(self.payload, self.len) }
    }
}

impl PacketBuf for IoRxBuf {}

// ── IoTxBufMut ────────────────────────────────────────────────────────────────

/// Mutable transmit buffer heap-allocated by [`IoTxPool`].
pub struct IoTxBufMut {
    pub(crate) data: Vec<u8>,
    /// Raw pointer to the originating pool.
    ///
    /// # Safety
    /// The pool must outlive all `IoTxBufMut` instances it created.
    pool: *const IoTxPool,
}

// Safety: cross-thread drop pushes Vec to pool.remote (MPSC).
unsafe impl Send for IoTxBufMut {}

impl Drop for IoTxBufMut {
    fn drop(&mut self) {
        if self.pool.is_null() {
            return;
        }
        let pool = unsafe { &*self.pool };
        let data = mem::take(&mut self.data);
        if std::thread::current().id() == pool.owner {
            pool.reclaim_local(data);
        } else {
            pool.reclaim_remote(data);
        }
    }
}

impl PacketBufMut for IoTxBufMut {
    type Frozen = IoTxBuf;

    #[inline]
    fn capacity(&self) -> usize {
        self.data.capacity()
    }

    #[inline]
    fn filled(&self) -> &[u8] {
        &self.data
    }

    #[inline]
    fn filled_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }

    #[inline]
    fn uninit_mut(&mut self) -> &mut [MaybeUninit<u8>] {
        self.data.spare_capacity_mut()
    }

    #[inline]
    unsafe fn set_filled(&mut self, new_len: usize) {
        unsafe { self.data.set_len(new_len) }
    }

    fn freeze(mut self) -> IoTxBuf {
        let data = mem::take(&mut self.data);
        let pool = self.pool;
        mem::forget(self);
        IoTxBuf { data, pool }
    }
}

// ── IoTxBuf ───────────────────────────────────────────────────────────────────

/// Frozen transmit buffer. Recycled to [`IoTxPool`] on drop.
pub struct IoTxBuf {
    pub(crate) data: Vec<u8>,
    pool: *const IoTxPool,
}

// Safety: cross-thread drop pushes Vec to pool.remote (MPSC).
unsafe impl Send for IoTxBuf {}

impl Drop for IoTxBuf {
    fn drop(&mut self) {
        if self.pool.is_null() {
            return;
        }
        let pool = unsafe { &*self.pool };
        let data = mem::take(&mut self.data);
        if std::thread::current().id() == pool.owner {
            pool.reclaim_local(data);
        } else {
            pool.reclaim_remote(data);
        }
    }
}

impl AsRef<[u8]> for IoTxBuf {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl PacketBuf for IoTxBuf {}

impl IoTxBuf {
    /// Create a pool-less buffer from a byte slice. Test-only.
    #[cfg(test)]
    pub fn from_slice(data: &[u8]) -> Self {
        Self { data: data.to_vec(), pool: std::ptr::null() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── IoTxPool (TxPool contract) ───────────────────────────────────────────

    #[test]
    fn tx_pool_default_max_payload_is_ipv6() {
        let pool = IoTxPool::new();
        assert_eq!(pool.max_payload_size(), IPV6_MAX_UDP_PAYLOAD);
    }

    #[test]
    fn tx_pool_with_max_payload_ipv4() {
        let pool = IoTxPool::with_max_payload(IPV4_MAX_UDP_PAYLOAD);
        assert_eq!(pool.max_payload_size(), IPV4_MAX_UDP_PAYLOAD);
    }

    #[test]
    fn tx_pool_zerocopy_threshold_is_zero() {
        let pool = IoTxPool::new();
        assert_eq!(pool.zerocopy_threshold(), 0);
    }

    #[test]
    fn tx_alloc_returns_count_and_appends_without_clearing() {
        let pool = IoTxPool::new();
        let mut bufs = Vec::new();

        assert_eq!(pool.alloc(64, 4, &mut bufs), 4);
        assert_eq!(bufs.len(), 4);

        assert_eq!(pool.alloc(64, 3, &mut bufs), 3);
        assert_eq!(bufs.len(), 7);
    }

    #[test]
    fn tx_alloc_zero_count_is_noop() {
        let pool = IoTxPool::new();
        let mut bufs = Vec::new();
        let mut tmp = Vec::new();
        pool.alloc(8, 1, &mut tmp);
        bufs.push(tmp.pop().unwrap());
        assert_eq!(pool.alloc(64, 0, &mut bufs), 0);
        assert_eq!(bufs.len(), 1);
    }

    #[test]
    fn tx_alloc_provides_requested_capacity_when_within_max_payload() {
        let pool = IoTxPool::new();
        let max = pool.max_payload_size();
        let mut bufs = Vec::new();
        pool.alloc(max, 1, &mut bufs);
        assert!(bufs[0].capacity() >= max);
        assert!(bufs[0].filled().is_empty());
        assert_eq!(bufs[0].uninit_mut().len(), bufs[0].capacity());
    }

    #[test]
    fn tx_alloc_clamps_request_to_max_payload() {
        let pool = IoTxPool::new();
        let max = pool.max_payload_size();
        let mut bufs = Vec::new();
        pool.alloc(max + 1024, 1, &mut bufs);
        assert_eq!(bufs[0].capacity(), max);
    }

    #[test]
    fn tx_drop_then_alloc_recycles_same_allocation() {
        let pool = IoTxPool::new();
        let mut bufs = Vec::new();
        pool.alloc(64, 1, &mut bufs);
        let original_ptr = bufs[0].data.as_ptr();
        bufs.clear();

        pool.alloc(64, 1, &mut bufs);
        let recycled_ptr = bufs[0].data.as_ptr();
        assert_eq!(original_ptr, recycled_ptr);
    }

    #[test]
    fn tx_freeze_preserves_data_and_recycles_on_drop() {
        let pool = IoTxPool::new();
        let mut bufs = Vec::new();
        pool.alloc(64, 1, &mut bufs);
        let mut buf = bufs.pop().unwrap();

        let payload = b"freeze-test";
        let uninit = buf.uninit_mut();
        for (i, &b) in payload.iter().enumerate() {
            uninit[i] = MaybeUninit::new(b);
        }
        unsafe { buf.set_filled(payload.len()) };

        let original_ptr = buf.data.as_ptr();
        let frozen = buf.freeze();
        assert_eq!(frozen.as_ref(), payload);
        assert_eq!(frozen.data.as_ptr(), original_ptr);
        drop(frozen);

        let mut more = Vec::new();
        pool.alloc(64, 1, &mut more);
        assert_eq!(more[0].data.as_ptr(), original_ptr);
    }

    #[test]
    fn tx_from_slice_is_pool_less() {
        let buf = IoTxBuf::from_slice(b"hello");
        assert_eq!(buf.as_ref(), b"hello");
        assert!(buf.pool.is_null());
        drop(buf);
    }

    #[test]
    fn tx_cross_thread_drop_recycles_via_remote_queue() {
        use std::sync::Arc;

        let pool = Arc::new(IoTxPool::with_max_payload(IPV4_MAX_UDP_PAYLOAD));
        let mut bufs = Vec::new();
        pool.alloc(64, 1, &mut bufs);
        let original_ptr = bufs[0].data.as_ptr();
        let frozen = bufs.pop().unwrap().freeze();

        let handle = std::thread::spawn(move || drop(frozen));
        handle.join().unwrap();

        let mut more = Vec::new();
        pool.alloc(64, 1, &mut more);
        assert_eq!(more[0].data.as_ptr(), original_ptr);
    }

    // ── IoRxPool (RxPool contract) ────────────────────────────────────────────

    #[test]
    fn rx_pool_alloc_returns_empty_placeholders() {
        let pool = IoRxPool { max_payload: IPV4_MAX_UDP_PAYLOAD };
        let mut bufs = Vec::new();
        assert_eq!(pool.alloc(64, 3, &mut bufs), 3);
        for b in &bufs {
            assert!(matches!(b.repr, IoRxBufMutRepr::Empty));
            assert_eq!(b.capacity(), 0);
            assert!(b.filled().is_empty());
        }
    }

    // ── TxPool::from_rx ──────────────────────────────────────────────────────

    #[test]
    fn from_rx_exhausted_pool_returns_err_with_rx() {
        struct EmptyPool;

        impl TxPool for EmptyPool {
            type Buf = IoTxBuf;
            type BufMut = IoTxBufMut;
            type RxBufMut = IoRxBufMut;
            const UNIFIED: bool = false;

            fn max_payload_size(&self) -> usize { 64 }
            fn alloc(&self, _: usize, _: usize, _: &mut Vec<IoTxBufMut>) -> usize { 0 }
            fn zerocopy_threshold(&self) -> usize { 0 }
            fn from_rx(&self, rx: IoRxBufMut) -> Result<IoTxBufMut, IoRxBufMut> { Err(rx) }
        }

        let pool = EmptyPool;
        let rx = IoRxBufMut { repr: IoRxBufMutRepr::Empty };
        match pool.from_rx(rx) {
            Err(rx) => assert!(matches!(rx.repr, IoRxBufMutRepr::Empty)),
            Ok(_) => panic!("expected Err"),
        }
    }

    #[test]
    fn callers_handle_partial_alloc_returns() {
        struct PartialPool {
            inner: Box<IoTxPool>,
            limit: std::sync::atomic::AtomicUsize,
        }

        impl TxPool for PartialPool {
            type Buf = IoTxBuf;
            type BufMut = IoTxBufMut;
            type RxBufMut = IoRxBufMut;
            const UNIFIED: bool = false;

            fn max_payload_size(&self) -> usize { self.inner.max_payload_size() }

            fn alloc(&self, capacity: usize, count: usize, bufs: &mut Vec<IoTxBufMut>) -> usize {
                use std::sync::atomic::Ordering;
                let allowed = self.limit.load(Ordering::Relaxed).min(count);
                if allowed == 0 { return 0; }
                self.inner.alloc(capacity, allowed, bufs);
                self.limit.fetch_sub(allowed, Ordering::Relaxed);
                allowed
            }

            fn zerocopy_threshold(&self) -> usize { 0 }

            fn from_rx(&self, rx: IoRxBufMut) -> Result<IoTxBufMut, IoRxBufMut> {
                self.inner.from_rx(rx)
            }
        }

        let pp = PartialPool {
            inner: IoTxPool::new(),
            limit: std::sync::atomic::AtomicUsize::new(7),
        };

        let want = 10;
        let mut bufs = Vec::new();
        loop {
            let n = pp.alloc(64, want - bufs.len(), &mut bufs);
            if n == 0 || bufs.len() >= want { break; }
        }
        assert_eq!(bufs.len(), 7);
        assert_eq!(pp.alloc(64, 1, &mut bufs), 0);
    }
}
