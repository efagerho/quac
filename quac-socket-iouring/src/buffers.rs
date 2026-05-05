use std::mem::{self, MaybeUninit};
use std::sync::{Arc, Mutex, Weak};

use quac_socket::{BufferPool, PacketBuf, PacketBufMut};

// ── MTU constants (re-exported from quac-socket::net) ────────────────────────

pub use quac_socket::net::{IPV4_MAX_UDP_PAYLOAD, IPV6_MAX_UDP_PAYLOAD, MAX_BUF_SIZE};

// ── IoPool ────────────────────────────────────────────────────────────────────

/// Per-socket buffer pool for [`IoUringSocket`](crate::IoUringSocket).
///
/// Backs each [`IoBuf`] / [`IoBufMut`] with a `Vec<u8>` and recycles those
/// allocations through a `Mutex`-protected free list. The mutex is uncontended
/// in the typical single-threaded io_uring use case (one ring per thread); it
/// exists to satisfy the [`BufferPool: Send + Sync`] contract for callers that
/// share an `Arc<IoPool>` across threads.
///
/// Heap allocation only happens when the free list is empty — and the
/// allocation runs **outside** the lock so a concurrent dropper isn't blocked
/// by a slow allocator. Lives behind `Arc`; construct via [`IoPool::new`] or
/// [`IoPool::with_max_payload`].
pub struct IoPool {
    max_payload: usize,
    free: Mutex<Vec<Vec<u8>>>,
    /// Self-referential `Weak` initialised by `Arc::new_cyclic`. Lets
    /// [`alloc`](Self::alloc) embed an `Arc<Self>` in each new buffer
    /// without changing the `BufferPool` trait signature. Always upgradable
    /// while `&self` is held (the borrow implies a live strong ref).
    self_weak: Weak<IoPool>,
}

impl IoPool {
    /// Construct a pool with the IPv6-MTU default payload (1452 bytes) — safe
    /// for any socket family. [`IoUringSocket`](crate::IoUringSocket) uses
    /// [`with_max_payload`](Self::with_max_payload) internally to set the
    /// exact value for the bound address family.
    pub fn new() -> Arc<Self> {
        Self::with_max_payload(IPV6_MAX_UDP_PAYLOAD)
    }

    /// Construct a pool with an explicit max payload (1472 for IPv4, 1452 for
    /// IPv6). Used by [`IoUringSocket::from_udp`] to propagate the
    /// address-family-specific value.
    pub fn with_max_payload(max_payload: usize) -> Arc<Self> {
        Arc::new_cyclic(|weak| Self {
            max_payload,
            free: Mutex::new(Vec::new()),
            self_weak: weak.clone(),
        })
    }

    fn arc(&self) -> Arc<Self> {
        self.self_weak
            .upgrade()
            .expect("IoPool is alive while &self is held")
    }

    fn reclaim(&self, v: Vec<u8>) {
        self.free.lock().unwrap_or_else(|e| e.into_inner()).push(v);
    }

}

impl BufferPool for IoPool {
    type Buf = IoBuf;
    type BufMut = IoBufMut;

    fn max_payload_size(&self) -> usize {
        self.max_payload
    }

    fn alloc(&self, capacity: usize, count: usize, bufs: &mut Vec<IoBufMut>) -> usize {
        // Clamp to MAX_BUF_SIZE: same cap as OsPool. Prevents recycled buffers
        // from accumulating large allocations when a caller (or future DPDK
        // backend) passes an inflated capacity.
        let capacity = capacity.min(MAX_BUF_SIZE);
        let pool = self.arc();
        bufs.reserve(count);

        // Drain up to `count` recycled buffers under a single mutex acquisition,
        // pushing directly into `bufs` to avoid a secondary heap allocation.
        // The capacity check/grow is bounded to at most one realloc per recycled
        // buffer (rare at steady state: recycled caps are >= capacity).
        let from_pool = {
            let mut guard = self.free.lock().unwrap_or_else(|e| e.into_inner());
            let take = count.min(guard.len());
            for _ in 0..take {
                let mut v = guard.pop().unwrap();
                v.clear();
                if v.capacity() < capacity {
                    v.reserve(capacity - v.capacity());
                }
                bufs.push(IoBufMut {
                    data: v,
                    pool: Arc::clone(&pool),
                });
            }
            take
        };

        // Fresh allocations happen outside the lock.
        for _ in from_pool..count {
            bufs.push(IoBufMut {
                data: Vec::with_capacity(capacity),
                pool: Arc::clone(&pool),
            });
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
/// Returns its backing `Vec<u8>` allocation to the originating [`IoPool`] on
/// drop, where it gets recycled by the next [`IoPool::alloc`] call. Buffers
/// constructed via [`IoBuf::from_slice`] carry no pool reference and free
/// their allocation directly to the heap on drop (intended for one-off
/// construction in tests).
pub struct IoBuf {
    data: Vec<u8>,
    pool: Option<Arc<IoPool>>,
}

impl Drop for IoBuf {
    fn drop(&mut self) {
        if let Some(pool) = self.pool.take() {
            pool.reclaim(mem::take(&mut self.data));
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
    /// The allocation is freed directly to the heap on drop, not recycled.
    /// Test-only: production code must allocate via [`IoPool::alloc`].
    #[cfg(test)]
    pub fn from_slice(data: &[u8]) -> Self {
        Self {
            data: data.to_vec(),
            pool: None,
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
/// On drop the backing `Vec<u8>` is returned to the originating [`IoPool`]
/// for recycling — the next [`IoPool::alloc`] call reuses the heap allocation
/// rather than asking the global allocator.
pub struct IoBufMut {
    data: Vec<u8>,
    pool: Arc<IoPool>,
}

impl Drop for IoBufMut {
    fn drop(&mut self) {
        self.pool.reclaim(mem::take(&mut self.data));
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
        let pool = Arc::clone(&self.pool);
        // Skip Drop (which would reclaim the now-empty Vec) — the data lives on
        // in the IoBuf and will be reclaimed when that drops.
        mem::forget(self);
        IoBuf {
            data,
            pool: Some(pool),
        }
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
        // Scatter-gather is native to sendmsg; coalescing is never required.
        let pool = IoPool::new();
        assert_eq!(pool.zerocopy_threshold(), 0);
    }

    #[test]
    fn alloc_returns_count_and_appends_without_clearing() {
        // Trait contract: `alloc` appends to `bufs` and returns the count.
        // It must never shorten or clear the input vec.
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
        // Seed `bufs` with one entry so we can detect accidental clearing.
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

    /// Recycling: drop a buffer, alloc again, get the *same* heap allocation.
    /// The allocation address proves the Vec was reused (not re-allocated).
    #[test]
    fn drop_then_alloc_recycles_same_allocation() {
        let pool = IoPool::new();
        let mut bufs = Vec::new();
        pool.alloc(64, 1, &mut bufs);

        let original_ptr = bufs[0].data.as_ptr();
        bufs.clear(); // returns the Vec to the free list

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
        assert_eq!(
            frozen.data.as_ptr(),
            original_ptr,
            "freeze must not re-allocate; it transfers the Vec by move"
        );

        drop(frozen); // returns to pool

        // Recycle: next alloc should get the same allocation back.
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
        // `IoBuf::from_slice` allocates a one-shot Vec with no pool reference.
        // Drop must free directly without panicking; ASan/Miri catch leaks.
        let buf = IoBuf::from_slice(b"hello");
        assert_eq!(buf.as_ref(), b"hello");
        assert!(buf.pool.is_none(), "from_slice buffers carry no pool ref");
        drop(buf);
    }

    /// Verifies the trait contract that callers must handle when a pool returns
    /// **less than `count`** — this `IoPool` always grows on demand, but
    /// kernel-bypass pools (DPDK mempool, AF_XDP UMEM) return partial counts
    /// when exhausted. The test wraps `IoPool` in a partial-returning facade
    /// and exercises the loop pattern callers must use.
    #[test]
    fn callers_handle_partial_alloc_returns() {
        struct PartialPool {
            inner: Arc<IoPool>,
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
                // Cap each call at min(count, limit). Real kernel-bypass pools
                // do this when their fixed-size slab is partially exhausted.
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
            limit: std::sync::atomic::AtomicUsize::new(7), // 7 total bufs available
        };

        // Caller pattern: loop until we have enough, or pool reports 0.
        let want = 10;
        let mut bufs = Vec::new();
        loop {
            let n = pp.alloc(64, want - bufs.len(), &mut bufs);
            if n == 0 || bufs.len() >= want {
                break;
            }
        }
        assert_eq!(bufs.len(), 7, "loop must drain pool to its 7-buf limit");
        // Next alloc returns 0 (pool drained) so the loop exits cleanly.
        assert_eq!(pp.alloc(64, 1, &mut bufs), 0);
    }
}
