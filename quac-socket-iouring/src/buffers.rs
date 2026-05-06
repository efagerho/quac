use std::cell::UnsafeCell;
use std::mem::{self, MaybeUninit};
use std::thread::ThreadId;

use quac_socket::{BufferPool, MpscQueue, PacketBuf, PacketBufMut};

// ── MTU constants (re-exported from quac-socket::net) ────────────────────────

pub use quac_socket::net::{IPV4_MAX_UDP_PAYLOAD, IPV6_MAX_UDP_PAYLOAD, MAX_BUF_SIZE};

// ── IoPool ────────────────────────────────────────────────────────────────────

/// Per-socket buffer pool for [`IoUringSocket`](crate::IoUringSocket).
///
/// Backed by two free lists:
/// - `local`: a `UnsafeCell<Vec<Vec<u8>>>` drained and filled only by the network
///   tile thread — zero atomics on the hot alloc path.
/// - `remote`: an MPSC queue fed by app threads dropping [`IoBuf`]s received over
///   a channel. Each cross-thread drop allocates one small wrapper node and performs
///   one `AtomicPtr::swap`; the network thread batch-drains it into `local` at the
///   start of each `alloc` call.
///
/// **Safety contract**: no [`IoBuf`] or [`IoBufMut`] may outlive the `IoPool` that
/// allocated it. The pool is owned by the socket, which is the longest-lived object
/// on the tile. Violating this contract is undefined behaviour.
///
/// Lives behind `Box` (use [`IoPool::new`] or [`IoPool::with_max_payload`]).
pub struct IoPool {
    max_payload: usize,
    /// Owner thread — the network tile thread. Same-thread drops reclaim directly
    /// into `local`; other threads push into `remote`.
    owner: ThreadId,
    /// Fast free list. Accessed only by the owning thread; no synchronisation needed.
    local: UnsafeCell<Vec<Vec<u8>>>,
    /// Cross-thread return queue. App threads push here when dropping an [`IoBuf`]
    /// received over an Rx channel.
    remote: MpscQueue<Vec<u8>>,
}

// Safety: `local` is accessed only by the owner thread; `remote` is `Sync` via
// `MpscQueue`. The raw `*const IoPool` pointers in `IoBuf`/`IoBufMut` are never
// used across threads — they only call back into the pool on drop.
unsafe impl Send for IoPool {}
unsafe impl Sync for IoPool {}

impl IoPool {
    /// Construct a pool with the IPv6-MTU default payload (1452 bytes).
    pub fn new() -> Box<Self> {
        Self::with_max_payload(IPV6_MAX_UDP_PAYLOAD)
    }

    /// Construct a pool with an explicit max payload. Used by
    /// [`IoUringSocket::from_udp`] to set the address-family-specific value
    /// (1472 for IPv4, 1452 for IPv6).
    pub fn with_max_payload(max_payload: usize) -> Box<Self> {
        Box::new(Self {
            max_payload,
            owner: std::thread::current().id(),
            local: UnsafeCell::new(Vec::new()),
            remote: MpscQueue::new(),
        })
    }

    /// Reclaim a buffer on the owning thread (zero atomics).
    #[inline]
    fn reclaim_local(&self, v: Vec<u8>) {
        // Safety: called only from the owner thread.
        unsafe { (*self.local.get()).push(v) };
    }

    /// Reclaim a buffer from any thread (one MPSC push).
    #[inline]
    fn reclaim_remote(&self, v: Vec<u8>) {
        self.remote.push(v);
    }
}

impl BufferPool for IoPool {
    type Buf = IoBuf;
    type BufMut = IoBufMut;

    fn max_payload_size(&self) -> usize {
        self.max_payload
    }

    fn alloc(&self, capacity: usize, count: usize, bufs: &mut Vec<IoBufMut>) -> usize {
        let capacity = capacity.min(MAX_BUF_SIZE);
        // Safety: alloc is only called by the owner thread.
        let local = unsafe { &mut *self.local.get() };

        // Batch-drain cross-thread returns into the local list first.
        unsafe { self.remote.drain_into(local) };

        bufs.reserve(count);
        let pool_ptr = self as *const IoPool;

        for _ in 0..count {
            let mut v = match local.pop() {
                Some(v) => v,
                None => Vec::with_capacity(capacity),
            };
            v.clear();
            if v.capacity() < capacity {
                v.reserve(capacity - v.capacity());
            }
            bufs.push(IoBufMut { data: v, pool: pool_ptr });
        }
        count
    }

    fn zerocopy_threshold(&self) -> usize {
        // io_uring sendmsg supports scatter-gather natively via msghdr.iov;
        // coalescing into one buffer is never required.
        0
    }
}

// ── IoBuf ─────────────────────────────────────────────────────────────────────

/// Frozen (Tx) UDP buffer — the immutable form of [`IoBufMut`] after
/// [`freeze`](PacketBufMut::freeze).
///
/// Drops reclaim the backing allocation back to the originating [`IoPool`]:
/// same-thread drops are atomic-free; cross-thread drops push to the pool's
/// MPSC queue (one `Box` alloc + one `AtomicPtr::swap`).
///
/// Buffers constructed via [`IoBuf::from_slice`] carry no pool reference and
/// free their allocation directly to the heap on drop.
pub struct IoBuf {
    data: Vec<u8>,
    /// Raw pointer to the originating pool. Null for pool-less test buffers.
    ///
    /// # Safety
    /// The pool must outlive all `IoBuf` instances it created.
    pool: *const IoPool,
}

// Safety: the pool pointer is valid for the lifetime of the buffer (safety contract).
// Sending an IoBuf to another thread is safe because the cross-thread drop path
// uses the pool's lock-free MPSC queue.
unsafe impl Send for IoBuf {}

impl Drop for IoBuf {
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

impl AsRef<[u8]> for IoBuf {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl PacketBuf for IoBuf {}

impl IoBuf {
    /// Create a pool-less buffer from a byte slice.
    /// Freed to the heap on drop; not recycled. Test-only.
    #[cfg(test)]
    pub fn from_slice(data: &[u8]) -> Self {
        Self {
            data: data.to_vec(),
            pool: std::ptr::null(),
        }
    }
}

// ── IoBufMut ──────────────────────────────────────────────────────────────────

/// Mutable (Rx / Tx-staging) UDP buffer.
///
/// Receives are filled by [`IoUringSocket::recv`](crate::IoUringSocket) via
/// `uninit_mut()` + `set_filled`. Sends are constructed by writing into
/// `uninit_mut()`, calling `set_filled`, then `freeze`-ing into an [`IoBuf`].
///
/// Drop reclaims the allocation back to the originating [`IoPool`] — same-thread
/// drops are atomic-free, cross-thread drops use the pool's MPSC queue.
pub struct IoBufMut {
    data: Vec<u8>,
    /// Raw pointer to the originating pool.
    ///
    /// # Safety
    /// The pool must outlive all `IoBufMut` instances it created.
    pool: *const IoPool,
}

// Safety: same as IoBuf — cross-thread drop uses MPSC queue; pool outlives buffers.
unsafe impl Send for IoBufMut {}

impl Drop for IoBufMut {
    fn drop(&mut self) {
        // `IoBufMut` is only constructed via `IoPool::alloc` (always non-null)
        // and `freeze()` consumes self before transferring the pointer to
        // `IoBuf`, so this null check should never fire — but mirror the
        // `IoBuf` guard so an accidental future pool-less constructor cannot
        // turn a stray drop into UB.
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

impl PacketBufMut for IoBufMut {
    type Frozen = IoBuf;

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

    fn freeze(mut self) -> IoBuf {
        let data = mem::take(&mut self.data);
        let pool = self.pool;
        // Skip Drop (which would reclaim the now-empty Vec) — the data lives on
        // in the IoBuf and will be reclaimed when that drops.
        mem::forget(self);
        IoBuf { data, pool }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── BufferPool contract ──────────────────────────────────────────────────

    #[test]
    fn pool_default_max_payload_is_ipv6() {
        let pool = IoPool::new();
        assert_eq!(pool.max_payload_size(), IPV6_MAX_UDP_PAYLOAD);
    }

    #[test]
    fn pool_with_max_payload_ipv4() {
        let pool = IoPool::with_max_payload(IPV4_MAX_UDP_PAYLOAD);
        assert_eq!(pool.max_payload_size(), IPV4_MAX_UDP_PAYLOAD);
    }

    #[test]
    fn pool_zerocopy_threshold_is_zero() {
        let pool = IoPool::new();
        assert_eq!(pool.zerocopy_threshold(), 0);
    }

    #[test]
    fn alloc_returns_count_and_appends_without_clearing() {
        let pool = IoPool::new();
        let mut bufs = Vec::new();

        assert_eq!(pool.alloc(64, 4, &mut bufs), 4);
        assert_eq!(bufs.len(), 4);

        // Second call appends, does not replace.
        assert_eq!(pool.alloc(64, 3, &mut bufs), 3);
        assert_eq!(bufs.len(), 7);
    }

    #[test]
    fn alloc_zero_count_is_noop() {
        let pool = IoPool::new();
        let mut bufs = Vec::new();
        let mut tmp = Vec::new();
        pool.alloc(8, 1, &mut tmp);
        bufs.push(tmp.pop().unwrap());
        assert_eq!(pool.alloc(64, 0, &mut bufs), 0);
        assert_eq!(bufs.len(), 1, "zero-count alloc must not clear or shorten");
    }

    #[test]
    fn alloc_provides_at_least_requested_capacity() {
        let pool = IoPool::new();
        let mut bufs = Vec::new();
        pool.alloc(IPV4_MAX_UDP_PAYLOAD, 1, &mut bufs);
        assert!(bufs[0].capacity() >= IPV4_MAX_UDP_PAYLOAD);
        assert!(bufs[0].filled().is_empty(), "fresh buffer has len 0");
        assert_eq!(bufs[0].uninit_mut().len(), bufs[0].capacity());
    }

    #[test]
    fn drop_then_alloc_recycles_same_allocation() {
        let pool = IoPool::new();
        let mut bufs = Vec::new();
        pool.alloc(64, 1, &mut bufs);

        let original_ptr = bufs[0].data.as_ptr();
        bufs.clear(); // returns the Vec to the local free list

        pool.alloc(64, 1, &mut bufs);
        let recycled_ptr = bufs[0].data.as_ptr();
        assert_eq!(
            original_ptr, recycled_ptr,
            "free-listed Vec must be reused on the next alloc"
        );
    }

    #[test]
    fn freeze_preserves_data_and_recycles_on_drop() {
        let pool = IoPool::new();
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

        drop(frozen); // returns to pool

        let mut more = Vec::new();
        pool.alloc(64, 1, &mut more);
        assert_eq!(
            more[0].data.as_ptr(),
            original_ptr,
            "frozen buffer's allocation must round-trip through the pool on drop"
        );
    }

    #[test]
    fn from_slice_is_pool_less() {
        let buf = IoBuf::from_slice(b"hello");
        assert_eq!(buf.as_ref(), b"hello");
        assert!(buf.pool.is_null(), "from_slice buffers carry no pool ref");
        drop(buf);
    }

    #[test]
    fn cross_thread_drop_recycles_via_remote_queue() {
        use std::sync::Arc;

        // Wrap pool in Arc so we can move it to another thread for validation.
        // This is test-only; production code uses Box exclusively.
        let pool = Arc::new(IoPool::with_max_payload(IPV4_MAX_UDP_PAYLOAD));

        let mut bufs = Vec::new();
        pool.alloc(64, 1, &mut bufs);
        let original_ptr = bufs[0].data.as_ptr();
        let buf = bufs.pop().unwrap();
        let frozen = buf.freeze();

        // Ship the frozen buffer to another thread and drop it there.
        let handle = std::thread::spawn(move || {
            drop(frozen);
        });
        handle.join().unwrap();

        // The Vec should have been pushed into the remote MPSC queue.
        // alloc() drains remote into local before serving, so the recycled
        // allocation must come back.
        let mut more = Vec::new();
        pool.alloc(64, 1, &mut more);
        assert_eq!(
            more[0].data.as_ptr(),
            original_ptr,
            "cross-thread drop must recycle through the MPSC queue"
        );
    }

    #[test]
    fn callers_handle_partial_alloc_returns() {
        struct PartialPool {
            inner: Box<IoPool>,
            limit: std::sync::atomic::AtomicUsize,
        }

        impl BufferPool for PartialPool {
            type Buf = IoBuf;
            type BufMut = IoBufMut;

            fn max_payload_size(&self) -> usize {
                self.inner.max_payload_size()
            }

            fn alloc(&self, capacity: usize, count: usize, bufs: &mut Vec<IoBufMut>) -> usize {
                use std::sync::atomic::Ordering;
                let allowed = self.limit.load(Ordering::Relaxed).min(count);
                if allowed == 0 {
                    return 0;
                }
                self.inner.alloc(capacity, allowed, bufs);
                self.limit.fetch_sub(allowed, Ordering::Relaxed);
                allowed
            }

            fn zerocopy_threshold(&self) -> usize {
                self.inner.zerocopy_threshold()
            }
        }

        let pp = PartialPool {
            inner: IoPool::new(),
            limit: std::sync::atomic::AtomicUsize::new(7),
        };

        let want = 10;
        let mut bufs = Vec::new();
        loop {
            let n = pp.alloc(64, want - bufs.len(), &mut bufs);
            if n == 0 || bufs.len() >= want {
                break;
            }
        }
        assert_eq!(bufs.len(), 7);
        assert_eq!(pp.alloc(64, 1, &mut bufs), 0);
    }
}
