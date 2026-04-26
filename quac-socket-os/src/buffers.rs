use std::alloc::{alloc_zeroed, Layout};
use std::cell::RefCell;

use quac_socket::{BufferPool, PacketBuf, PacketBufMut};

pub(crate) const MAX_DATAGRAM: usize = 65535;

// Per-engine-thread free-list shared by both the send and receive paths.
// All drops happen on the engine thread, so thread-local storage gives us
// zero-cost recycling with no atomics.
thread_local! {
    static OS_BUF_FREE_LIST: RefCell<Vec<Vec<u8>>> = RefCell::new(Vec::new());
}
const OS_BUF_FREE_LIST_CAP: usize = 256;

/// Immutable heap buffer for outgoing packets. Recycled to [`OS_BUF_FREE_LIST`] on drop.
pub struct OsBuf(pub(crate) Vec<u8>);

impl Drop for OsBuf {
    fn drop(&mut self) {
        let v = std::mem::take(&mut self.0);
        if v.capacity() == 0 {
            return;
        }
        OS_BUF_FREE_LIST.with(|fl| {
            let mut list = fl.borrow_mut();
            if list.len() < OS_BUF_FREE_LIST_CAP {
                list.push(v);
            }
        });
    }
}

impl AsRef<[u8]> for OsBuf {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl PacketBuf for OsBuf {}

impl OsBuf {
    pub fn from_slice(data: &[u8]) -> Self {
        OsBuf(data.to_vec())
    }
}

/// Mutable heap buffer used by the pool for both outgoing and received packets.
/// Recycled to [`OS_BUF_FREE_LIST`] on drop (unless consumed by [`freeze`](PacketBufMut::freeze)).
pub struct OsBufMut(pub(crate) Vec<u8>);

impl Drop for OsBufMut {
    fn drop(&mut self) {
        let v = std::mem::take(&mut self.0);
        if v.capacity() < MAX_DATAGRAM {
            return;
        }
        OS_BUF_FREE_LIST.with(|fl| {
            let mut list = fl.borrow_mut();
            if list.len() < OS_BUF_FREE_LIST_CAP {
                list.push(v);
            }
        });
    }
}

impl AsRef<[u8]> for OsBufMut {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for OsBufMut {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl PacketBufMut for OsBufMut {
    type Frozen = OsBuf;

    fn freeze(mut self) -> OsBuf {
        OsBuf(std::mem::take(&mut self.0))
    }
}

pub struct OsPool;

impl BufferPool for OsPool {
    type Buf = OsBuf;
    type BufMut = OsBufMut;
    fn alloc(&self, capacity: usize, count: usize, bufs: &mut Vec<OsBufMut>) -> usize {
        for _ in 0..count {
            let v = OS_BUF_FREE_LIST.with(|fl| fl.borrow_mut().pop());
            let data = match v {
                Some(mut recycled) => {
                    recycled.resize(capacity, 0);
                    recycled
                }
                None => vec![0u8; capacity],
            };
            bufs.push(OsBufMut(data));
        }
        count
    }

    fn zerocopy_threshold(&self) -> usize {
        usize::MAX
    }
}

/// Pop a recycled buffer from the freelist, ready for the caller to fill via `extend_from_slice`.
/// Falls back to a fresh allocation when the freelist is empty.
pub(crate) fn pop_recv_buf(len: usize) -> OsBufMut {
    let v = OS_BUF_FREE_LIST.with(|fl| fl.borrow_mut().pop());
    let inner = match v {
        Some(mut recycled) => {
            recycled.clear();
            if recycled.capacity() < len {
                recycled.reserve(len - recycled.capacity());
            }
            recycled
        }
        None => Vec::with_capacity(len),
    };
    OsBufMut(inner)
}

/// Kernel-facing receive buffer.  `#[repr(align(64))]` guarantees the inner
/// array starts at a 64-byte boundary, so slices of it passed to
/// `OsBuf::from_aligned_slice` satisfy the src-alignment contract.
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
