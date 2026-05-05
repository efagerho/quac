use std::mem::{self, MaybeUninit};
use std::sync::{Arc, Mutex, Weak};

use quac_socket::{BufferPool, PacketBuf, PacketBufMut};

// ── MTU constants ─────────────────────────────────────────────────────────────

const ETHERNET_MTU: usize = 1500;
const IPV4_HEADER: usize  = 20;
const IPV6_HEADER: usize  = 40;
const UDP_HEADER: usize   = 8;

pub const IPV4_MAX_UDP_PAYLOAD: usize = ETHERNET_MTU - IPV4_HEADER - UDP_HEADER;
pub const IPV6_MAX_UDP_PAYLOAD: usize = ETHERNET_MTU - IPV6_HEADER - UDP_HEADER;

// ── IoPool ────────────────────────────────────────────────────────────────────

/// Buffer pool for [`IoUringSocket`](crate::IoUringSocket).
///
/// Recycles `Vec<u8>` storage via a Mutex-protected free list.
/// The lock is uncontended in the typical single-threaded io_uring case.
/// Must live behind `Arc` — use [`IoPool::new`] or [`IoPool::with_max_payload`].
pub struct IoPool {
    max_payload: usize,
    free:        Mutex<Vec<Vec<u8>>>,
    self_weak:   Weak<IoPool>,
}

impl IoPool {
    pub fn new() -> Arc<Self> {
        Self::with_max_payload(IPV6_MAX_UDP_PAYLOAD)
    }

    pub fn with_max_payload(max_payload: usize) -> Arc<Self> {
        Arc::new_cyclic(|weak| Self {
            max_payload,
            free: Mutex::new(Vec::new()),
            self_weak: weak.clone(),
        })
    }

    fn arc(&self) -> Arc<Self> {
        self.self_weak.upgrade().expect("IoPool is alive while &self is held")
    }

    fn reclaim(&self, v: Vec<u8>) {
        self.free.lock().unwrap_or_else(|e| e.into_inner()).push(v);
    }

    fn take_or_alloc(&self, capacity: usize) -> Vec<u8> {
        let mut free = self.free.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(mut v) = free.pop() {
            v.clear();
            if v.capacity() < capacity {
                v.reserve(capacity - v.capacity());
            }
            v
        } else {
            Vec::with_capacity(capacity)
        }
    }
}

impl BufferPool for IoPool {
    type Buf    = IoBuf;
    type BufMut = IoBufMut;

    fn max_payload_size(&self) -> usize {
        self.max_payload
    }

    fn alloc(&self, capacity: usize, count: usize, bufs: &mut Vec<IoBufMut>) -> usize {
        let pool = self.arc();
        bufs.reserve(count);
        for _ in 0..count {
            let data = self.take_or_alloc(capacity);
            bufs.push(IoBufMut { data, pool: Arc::clone(&pool) });
        }
        count
    }

    fn zerocopy_threshold(&self) -> usize {
        0
    }
}

// ── IoBuf ─────────────────────────────────────────────────────────────────────

/// Frozen (Tx) buffer. Returns its backing storage to the pool on drop
/// (or frees it if constructed via [`IoBuf::from_slice`]).
pub struct IoBuf {
    data: Vec<u8>,
    pool: Option<Arc<IoPool>>,
}

unsafe impl Send for IoBuf {}

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
    /// Create a pool-less buffer from a byte slice (tests / one-off sends).
    /// Freed to the heap on drop; not recycled.
    pub fn from_slice(data: &[u8]) -> Self {
        Self { data: data.to_vec(), pool: None }
    }
}

// ── IoBufMut ──────────────────────────────────────────────────────────────────

/// Mutable (Rx) buffer. Returns its backing storage to the pool on drop.
pub struct IoBufMut {
    data: Vec<u8>,
    pool: Arc<IoPool>,
}

unsafe impl Send for IoBufMut {}

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
        IoBuf { data, pool: Some(pool) }
    }
}
