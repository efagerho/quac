//! Buffer pools and wrappers for the AF_XDP backend. Layout mirrors
//! `quac-socket-iouring`.
//!
//! - `XdpRxPool` is a marker pool -- `alloc` returns zero-cost `Empty`
//!   placeholders that `recv` swaps for `Ring` variants wrapping a UMEM
//!   frame. Drops route the frame back via [`Reclaimer`].
//! - `XdpTxPool` owns a free list of UMEM frame addresses; `alloc` hands
//!   out an `XdpTxBufMut` with the payload region after `HEADROOM` so
//!   `send` can write ETH/IP/UDP headers in place.
//! - `UNIFIED = false`: `from_rx` copies the Rx payload into a fresh Tx
//!   frame (mirrors `IoTxPool::from_rx`).

#![allow(dead_code)]

use std::cell::UnsafeCell;
use std::marker::PhantomData;
use std::mem::{self, MaybeUninit};
use std::ptr;
use std::slice;
use std::thread::ThreadId;

use quac_socket::{MpscQueue, PacketBuf, PacketBufMut, RxPool, TxPool};

use crate::reclaimer::Reclaimer;

/// Bytes at the start of every TX frame reserved for ETH+IPv4+UDP headers
/// that `send` writes in place. 14 + 20 + 8 = 42.
pub const HEADROOM: u32 = 42;


/// Marker pool. Holds no buffers; `alloc` returns `Empty` placeholders that
/// `recv` swaps for live `Ring` variants pointing into a kernel-filled UMEM
/// frame. `Send + !Sync` (see crate-level docs).
pub struct XdpRxPool {
    pub(crate) max_payload: usize,
    _not_sync: PhantomData<core::cell::Cell<()>>,
}

impl XdpRxPool {
    pub fn new(max_payload: usize) -> Self {
        Self { max_payload, _not_sync: PhantomData }
    }
}

impl RxPool for XdpRxPool {
    type Buf = XdpRxBuf;
    type BufMut = XdpRxBufMut;

    fn max_payload_size(&self) -> usize {
        self.max_payload
    }

    fn alloc(&self, _capacity: usize, count: usize, bufs: &mut Vec<XdpRxBufMut>) -> usize {
        bufs.reserve(count);
        for _ in 0..count {
            bufs.push(XdpRxBufMut { repr: XdpRxBufMutRepr::Empty });
        }
        count
    }
}


/// Two-state Rx buffer. `Empty` is what `XdpRxPool::alloc` produces; `recv`
/// `mem::replace`s the slot with a `Ring` variant that points into the
/// kernel-filled UMEM frame.
pub(crate) enum XdpRxBufMutRepr {
    /// Placeholder; Drop is a no-op.
    Empty,
    /// Live UMEM frame. Drop returns `frame_addr` to FILL via the reclaimer
    /// (owner thread → `pending`, else → `remote` MPSC).
    Ring {
        umem_base: *mut u8,
        frame_addr: u64,
        payload_offset: u32,
        payload_len: u32,
        cap: u32,
        reclaimer: *const Reclaimer,
    },
}

pub struct XdpRxBufMut {
    pub(crate) repr: XdpRxBufMutRepr,
}

// Safety: `Ring` raw pointers point into UMEM and the Reclaimer, both of
// which outlive every buffer (CLAUDE.md invariant). Cross-thread drops
// route through the reclaimer's `Sync` MPSC queue.
unsafe impl Send for XdpRxBufMut {}

impl Drop for XdpRxBufMut {
    fn drop(&mut self) {
        let XdpRxBufMutRepr::Ring { frame_addr, reclaimer, .. } = self.repr else {
            return;
        };
        // SAFETY: reclaimer outlives every buffer (socket-lifetime).
        let rec = unsafe { &*reclaimer };
        if rec.current_thread_owns() {
            unsafe { (*rec.pending.get()).push(frame_addr) };
        } else {
            // Capacity is sized to total frame count, so push can't fail
            // unless an invariant is broken; losing a frame would
            // permanently shrink FILL.
            rec.remote
                .push(frame_addr)
                .expect("Reclaimer.remote queue full - sized < frame count");
        }
    }
}

impl PacketBufMut for XdpRxBufMut {
    type Frozen = XdpRxBuf;

    #[inline]
    fn capacity(&self) -> usize {
        match self.repr {
            XdpRxBufMutRepr::Empty => 0,
            XdpRxBufMutRepr::Ring { cap, .. } => cap as usize,
        }
    }

    #[inline]
    fn filled(&self) -> &[u8] {
        match self.repr {
            XdpRxBufMutRepr::Empty => &[],
            XdpRxBufMutRepr::Ring { umem_base, frame_addr, payload_offset, payload_len, .. } => {
                let start = unsafe { umem_base.add(frame_addr as usize + payload_offset as usize) };
                unsafe { slice::from_raw_parts(start, payload_len as usize) }
            }
        }
    }

    #[inline]
    fn filled_mut(&mut self) -> &mut [u8] {
        match self.repr {
            XdpRxBufMutRepr::Empty => &mut [],
            XdpRxBufMutRepr::Ring { umem_base, frame_addr, payload_offset, payload_len, .. } => {
                let start = unsafe { umem_base.add(frame_addr as usize + payload_offset as usize) };
                unsafe { slice::from_raw_parts_mut(start, payload_len as usize) }
            }
        }
    }

    #[inline]
    fn uninit_mut(&mut self) -> &mut [MaybeUninit<u8>] {
        match self.repr {
            XdpRxBufMutRepr::Empty => &mut [],
            XdpRxBufMutRepr::Ring {
                umem_base, frame_addr, payload_offset, payload_len, cap, ..
            } => {
                // Spare capacity follows the filled bytes within the payload region.
                let start = unsafe {
                    umem_base.add(frame_addr as usize + payload_offset as usize + payload_len as usize)
                };
                let len = (cap.saturating_sub(payload_len)) as usize;
                unsafe { slice::from_raw_parts_mut(start as *mut MaybeUninit<u8>, len) }
            }
        }
    }

    #[inline]
    unsafe fn set_filled(&mut self, new_len: usize) {
        if let XdpRxBufMutRepr::Ring { payload_len, cap, .. } = &mut self.repr {
            debug_assert!(new_len as u32 <= *cap);
            *payload_len = new_len as u32;
        }
    }

    fn freeze(mut self) -> XdpRxBuf {
        match mem::replace(&mut self.repr, XdpRxBufMutRepr::Empty) {
            XdpRxBufMutRepr::Empty => panic!("freeze called on empty XdpRxBufMut placeholder"),
            XdpRxBufMutRepr::Ring { umem_base, frame_addr, payload_offset, payload_len, reclaimer, .. } => {
                // Skip our Drop; ownership of the frame transfers to XdpRxBuf.
                mem::forget(self);
                XdpRxBuf { umem_base, frame_addr, payload_offset, payload_len, reclaimer }
            }
        }
    }
}

impl XdpRxBufMut {
    /// Wrap a kernel-filled UMEM frame as a `Ring` buffer. Called from `recv`.
    ///
    /// # Safety
    /// `umem_base + frame_addr + payload_offset + payload_len` must lie
    /// inside the UMEM region; `reclaimer` must outlive this buffer.
    pub(crate) fn from_ring_frame(
        umem_base: *mut u8,
        frame_addr: u64,
        payload_offset: u32,
        payload_len: u32,
        cap: u32,
        reclaimer: *const Reclaimer,
    ) -> Self {
        Self {
            repr: XdpRxBufMutRepr::Ring {
                umem_base,
                frame_addr,
                payload_offset,
                payload_len,
                cap,
                reclaimer,
            },
        }
    }

    /// Frame address backing this buffer (or `None` for `Empty`).
    pub(crate) fn frame_addr(&self) -> Option<u64> {
        match self.repr {
            XdpRxBufMutRepr::Empty => None,
            XdpRxBufMutRepr::Ring { frame_addr, .. } => Some(frame_addr),
        }
    }
}

/// Frozen Rx buffer. Reclaims its UMEM frame on drop.
pub struct XdpRxBuf {
    umem_base: *const u8,
    frame_addr: u64,
    payload_offset: u32,
    payload_len: u32,
    reclaimer: *const Reclaimer,
}

unsafe impl Send for XdpRxBuf {}

impl AsRef<[u8]> for XdpRxBuf {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        let start = unsafe { self.umem_base.add(self.frame_addr as usize + self.payload_offset as usize) };
        unsafe { slice::from_raw_parts(start, self.payload_len as usize) }
    }
}

impl PacketBuf for XdpRxBuf {}

impl Drop for XdpRxBuf {
    fn drop(&mut self) {
        let rec = unsafe { &*self.reclaimer };
        if rec.current_thread_owns() {
            unsafe { (*rec.pending.get()).push(self.frame_addr) };
        } else {
            rec.remote
                .push(self.frame_addr)
                .expect("Reclaimer.remote queue full - sized < frame count");
        }
    }
}


/// Cross-thread reclaim target for TX frames. Buffers hold a
/// `*const XdpTxReclaim` (not a pointer back to the pool) so that
/// cross-thread Drop doesn't need to construct a `&XdpTxPool` on a
/// non-owner thread -- keeping the pool itself `!Sync` per CLAUDE.md.
pub(crate) struct XdpTxReclaim {
    pub(crate) owner: ThreadId,
    pub(crate) local: UnsafeCell<Vec<u64>>,
    pub(crate) remote: MpscQueue<u64>,
}

// Safety: `local` is mutated only on the owner thread (enforced by the
// `owner == current().id()` check in drop sites); `remote` is `Sync` via
// `MpscQueue`'s `ArrayQueue`.
unsafe impl Send for XdpTxReclaim {}
unsafe impl Sync for XdpTxReclaim {}


/// Free list of UMEM frame addresses for the TX side. `Send + !Sync`
/// (see crate-level docs); cross-thread buffer drops route through
/// [`XdpTxReclaim`], not through the pool.
pub struct XdpTxPool {
    pub(crate) max_payload: usize,
    pub(crate) frame_size: u32,
    pub(crate) headroom: u32,
    pub(crate) umem_base: *mut u8,
    /// `Box` so the pointer in buffer wrappers stays stable.
    pub(crate) reclaim: Box<XdpTxReclaim>,
    _not_sync: PhantomData<core::cell::Cell<()>>,
}

// Safety: `XdpTxPool` is `!Sync` (Cell<()> phantom) -- no two threads ever
// hold `&XdpTxPool` simultaneously. The explicit `Send` is needed only
// because `*mut u8` (umem_base) doesn't auto-derive it; cross-thread
// reclaim accesses go through `XdpTxReclaim`, never the pool.
unsafe impl Send for XdpTxPool {}

impl XdpTxPool {
    /// Build with the initial set of frame addresses (the TX half of the
    /// UMEM split). `remote_capacity` should be ≥ the worst-case number
    /// of buffers in flight (= total frame count).
    pub fn new(
        umem_base: *mut u8,
        frame_size: u32,
        headroom: u32,
        max_payload: usize,
        initial_frames: Vec<u64>,
        remote_capacity: usize,
    ) -> Box<Self> {
        Box::new(Self {
            max_payload,
            frame_size,
            headroom,
            umem_base,
            reclaim: Box::new(XdpTxReclaim {
                owner: std::thread::current().id(),
                local: UnsafeCell::new(initial_frames),
                remote: MpscQueue::new(remote_capacity),
            }),
            _not_sync: PhantomData,
        })
    }

    pub(crate) fn umem_base(&self) -> *mut u8 {
        self.umem_base
    }

    pub(crate) fn reclaim_ptr(&self) -> *const XdpTxReclaim {
        &*self.reclaim as *const XdpTxReclaim
    }
}

impl TxPool for XdpTxPool {
    type Buf = XdpTxBuf;
    type BufMut = XdpTxBufMut;
    type RxBufMut = XdpRxBufMut;

    /// `false`: `from_rx` copies. A unified path (rewrite headers in-place
    /// over a single UMEM) is possible but not implemented.
    const UNIFIED: bool = false;

    fn max_payload_size(&self) -> usize {
        self.max_payload
    }

    fn alloc(&self, _capacity: usize, count: usize, bufs: &mut Vec<XdpTxBufMut>) -> usize {
        // SAFETY: alloc is owner-thread only.
        let local = unsafe { &mut *self.reclaim.local.get() };
        if local.len() < count {
            self.reclaim.remote.drain_into(local);
        }

        bufs.reserve(count);
        let umem_base = self.umem_base;
        let reclaim_ptr = self.reclaim_ptr();
        let mut allocated = 0usize;
        for _ in 0..count {
            let Some(addr) = local.pop() else { break };
            bufs.push(XdpTxBufMut {
                umem_base,
                frame_addr: addr,
                payload_offset: self.headroom,
                payload_len: 0,
                cap: self.frame_size.saturating_sub(self.headroom),
                reclaim: reclaim_ptr,
            });
            allocated += 1;
        }
        allocated
    }

    fn available(&self) -> usize {
        // SAFETY: owner-thread only.
        let local = unsafe { &mut *self.reclaim.local.get() };
        self.reclaim.remote.drain_into(local);
        local.len()
    }

    fn zerocopy_threshold(&self) -> usize {
        // MAX_SEGMENTS=1 -- there's no scatter-gather path to threshold.
        0
    }

    fn owns(&self, buf: &XdpTxBuf) -> bool {
        // The kernel TX ring zero-copies from this socket's UMEM only;
        // a buf carrying a different UMEM base must egress via its own
        // socket. Pointer compare is enough -- each XdpSocket owns a
        // distinct, non-overlapping UMEM mmap.
        buf.umem_base as *const u8 == self.umem_base as *const u8
    }

    fn from_rx(&self, rx: XdpRxBufMut) -> Result<XdpTxBufMut, XdpRxBufMut> {
        // SAFETY: owner-thread only.
        let local = unsafe { &mut *self.reclaim.local.get() };
        if local.is_empty() {
            self.reclaim.remote.drain_into(local);
        }
        let Some(tx_addr) = local.pop() else { return Err(rx) };

        let cap = self.frame_size.saturating_sub(self.headroom);
        let umem_base = self.umem_base;
        let payload_offset = self.headroom;

        match &rx.repr {
            XdpRxBufMutRepr::Empty => panic!("from_rx called on empty placeholder"),
            XdpRxBufMutRepr::Ring {
                umem_base: rx_base,
                frame_addr: rx_addr,
                payload_offset: rx_off,
                payload_len,
                ..
            } => {
                let len = *payload_len as usize;
                debug_assert!(len <= cap as usize);
                let src = unsafe { (*rx_base).add(*rx_addr as usize + *rx_off as usize) };
                let dst = unsafe { umem_base.add(tx_addr as usize + payload_offset as usize) };
                // SAFETY: src and dst are in different UMEM frames (no overlap);
                // `len` ≤ max_payload ≤ cap.
                unsafe { ptr::copy_nonoverlapping(src, dst, len) };
                drop(rx); // Returns the rx frame to FILL.
                Ok(XdpTxBufMut {
                    umem_base,
                    frame_addr: tx_addr,
                    payload_offset,
                    payload_len: len as u32,
                    cap,
                    reclaim: self.reclaim_ptr(),
                })
            }
        }
    }
}


/// Mutable Tx buffer. `[0..payload_offset)` is reserved for ETH/IP/UDP
/// headers (filled by `send`); `[payload_offset..+cap)` is the user's.
pub struct XdpTxBufMut {
    umem_base: *mut u8,
    frame_addr: u64,
    payload_offset: u32,
    payload_len: u32,
    cap: u32,
    /// Pointer to `XdpTxReclaim` (`Sync`), not the pool, so the pool can
    /// stay `!Sync`.
    reclaim: *const XdpTxReclaim,
}

unsafe impl Send for XdpTxBufMut {}

impl Drop for XdpTxBufMut {
    fn drop(&mut self) {
        if self.reclaim.is_null() {
            return;
        }
        // SAFETY: `reclaim` is `Sync` and outlives every buffer.
        reclaim_frame(self.reclaim, self.frame_addr);
    }
}

impl PacketBufMut for XdpTxBufMut {
    type Frozen = XdpTxBuf;

    #[inline]
    fn capacity(&self) -> usize {
        self.cap as usize
    }

    #[inline]
    fn filled(&self) -> &[u8] {
        let start = unsafe { self.umem_base.add(self.frame_addr as usize + self.payload_offset as usize) };
        unsafe { slice::from_raw_parts(start, self.payload_len as usize) }
    }

    #[inline]
    fn filled_mut(&mut self) -> &mut [u8] {
        let start = unsafe { self.umem_base.add(self.frame_addr as usize + self.payload_offset as usize) };
        unsafe { slice::from_raw_parts_mut(start, self.payload_len as usize) }
    }

    #[inline]
    fn uninit_mut(&mut self) -> &mut [MaybeUninit<u8>] {
        let start = unsafe {
            self.umem_base
                .add(self.frame_addr as usize + self.payload_offset as usize + self.payload_len as usize)
        };
        let len = self.cap.saturating_sub(self.payload_len) as usize;
        unsafe { slice::from_raw_parts_mut(start as *mut MaybeUninit<u8>, len) }
    }

    #[inline]
    unsafe fn set_filled(&mut self, new_len: usize) {
        debug_assert!(new_len as u32 <= self.cap);
        self.payload_len = new_len as u32;
    }

    fn freeze(mut self) -> XdpTxBuf {
        let umem_base = self.umem_base;
        let frame_addr = self.frame_addr;
        let payload_offset = self.payload_offset;
        let payload_len = self.payload_len;
        let reclaim = self.reclaim;
        // Skip our Drop; ownership of the frame transfers to XdpTxBuf.
        self.reclaim = ptr::null();
        mem::forget(self);
        XdpTxBuf { umem_base, frame_addr, payload_offset, payload_len, reclaim }
    }
}

impl XdpTxBufMut {
    pub(crate) fn frame_addr(&self) -> u64 {
        self.frame_addr
    }
    pub(crate) fn payload_offset(&self) -> u32 {
        self.payload_offset
    }
}

/// Frozen Tx buffer. Reclaims its UMEM frame on drop.
pub struct XdpTxBuf {
    umem_base: *const u8,
    frame_addr: u64,
    payload_offset: u32,
    payload_len: u32,
    reclaim: *const XdpTxReclaim,
}

unsafe impl Send for XdpTxBuf {}

impl AsRef<[u8]> for XdpTxBuf {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        let start = unsafe { self.umem_base.add(self.frame_addr as usize + self.payload_offset as usize) };
        unsafe { slice::from_raw_parts(start, self.payload_len as usize) }
    }
}

impl PacketBuf for XdpTxBuf {}

impl Drop for XdpTxBuf {
    fn drop(&mut self) {
        if self.reclaim.is_null() {
            return;
        }
        reclaim_frame(self.reclaim, self.frame_addr);
    }
}

impl XdpTxBuf {
    /// Frame address inside the UMEM. Read by `send` when building the descriptor.
    pub(crate) fn frame_addr(&self) -> u64 {
        self.frame_addr
    }
    pub(crate) fn payload_offset(&self) -> u32 {
        self.payload_offset
    }
    pub(crate) fn payload_len(&self) -> u32 {
        self.payload_len
    }
}


/// Push `addr` back to the pool. Same-thread drops bypass the MPSC; other
/// threads push to `remote`.
///
/// # Safety
/// `reclaim` must be non-null and outlive this call (CLAUDE.md
/// pool-outlives-buffer invariant).
#[inline]
fn reclaim_frame(reclaim: *const XdpTxReclaim, addr: u64) {
    let r = unsafe { &*reclaim };
    if quac_socket::cpu::current_thread_id() == r.owner {
        unsafe { (*r.local.get()).push(addr) };
    } else {
        // Sized for total frame count; overflow signals a leak elsewhere.
        let pushed = r.remote.push(addr);
        debug_assert!(pushed.is_ok(), "XdpTxReclaim.remote queue full - sized < frame count");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::umem::Umem;

    /// Returns the pool *and* its backing UMEM. The pool's `*mut u8` has no
    /// lifetime, so the caller must drop both together -- otherwise UMEM is
    /// munmapped while the pool's still live and accesses segfault.
    fn fresh_pool() -> (Umem, Box<XdpTxPool>) {
        let mut umem = Umem::new(2048, 16).expect("UMEM alloc");
        let frames: Vec<u64> = (0..16).map(|i| umem.frame_offset(i)).collect();
        let pool = XdpTxPool::new(
            umem.as_mut_ptr(),
            umem.frame_size(),
            HEADROOM,
            (umem.frame_size() - HEADROOM) as usize,
            frames,
            64,
        );
        (umem, pool)
    }

    /// Compile-time assertion that both pools are `!Sync`. Uses the
    /// `static_assertions` ambiguity trick: two impls of `NegatedSync<A>`
    /// exist for any `T`, but only one when `T: Sync` -- so `T: Sync` causes
    /// trait-resolution ambiguity at the call sites below.
    fn _assert_pools_not_sync() {
        trait NegatedSync<A> {
            fn check() {}
        }
        impl<T: ?Sized> NegatedSync<()> for T {}
        impl<T: ?Sized + Sync> NegatedSync<u8> for T {}

        let _ = <XdpRxPool as NegatedSync<_>>::check;
        let _ = <XdpTxPool as NegatedSync<_>>::check;
    }

    /// Anchors `_assert_pools_not_sync` against accidental deletion.
    #[test]
    fn pools_remain_not_sync() {
        _assert_pools_not_sync();
    }

    #[test]
    fn rx_pool_alloc_returns_empty_placeholders() {
        let pool = XdpRxPool::new(1472);
        let mut bufs = Vec::new();
        assert_eq!(pool.alloc(1472, 4, &mut bufs), 4);
        assert_eq!(bufs.len(), 4);
        for b in &bufs {
            assert_eq!(b.capacity(), 0);
            assert!(matches!(b.repr, XdpRxBufMutRepr::Empty));
        }
    }

    #[test]
    fn tx_pool_alloc_drop_recycles() {
        let (_umem, pool) = fresh_pool();
        assert_eq!(pool.available(), 16);

        let mut bufs = Vec::new();
        assert_eq!(pool.alloc(0, 16, &mut bufs), 16);
        assert_eq!(pool.available(), 0);

        let mut frame_addrs: Vec<u64> = bufs.iter().map(|b| b.frame_addr).collect();
        frame_addrs.sort();
        bufs.clear(); // Drop on owner thread → reclaim_local for each.

        // Round-trips: same set of addresses, same count.
        let mut bufs2 = Vec::new();
        assert_eq!(pool.alloc(0, 16, &mut bufs2), 16);
        let mut frame_addrs2: Vec<u64> = bufs2.iter().map(|b| b.frame_addr).collect();
        frame_addrs2.sort();
        assert_eq!(frame_addrs, frame_addrs2);
    }

    #[test]
    fn tx_pool_alloc_returns_partial_when_exhausted() {
        let (_umem, pool) = fresh_pool();
        let mut bufs = Vec::new();
        assert_eq!(pool.alloc(0, 16, &mut bufs), 16);
        // Pool is empty -- next alloc returns 0.
        let n = pool.alloc(0, 4, &mut bufs);
        assert_eq!(n, 0);
        assert_eq!(bufs.len(), 16);
    }

    #[test]
    fn tx_buf_freeze_round_trip() {
        let (_umem, pool) = fresh_pool();
        let mut bufs = Vec::new();
        pool.alloc(0, 1, &mut bufs);
        let mut buf = bufs.pop().unwrap();
        let frame_addr = buf.frame_addr;

        // Write a payload, freeze, drop the frozen buffer -- frame returns
        // to the pool.
        let payload = b"hello xdp";
        let uninit = buf.uninit_mut();
        for (i, &b) in payload.iter().enumerate() {
            uninit[i] = MaybeUninit::new(b);
        }
        unsafe { buf.set_filled(payload.len()) };

        let frozen = buf.freeze();
        assert_eq!(frozen.frame_addr(), frame_addr);
        assert_eq!(frozen.payload_len(), payload.len() as u32);
        assert_eq!(frozen.as_ref(), payload);
        drop(frozen);

        // Frame returned: pool now has 16 again.
        assert_eq!(pool.available(), 16);
    }

    #[test]
    fn cross_thread_drop_reclaims_via_remote() {
        let (_umem, pool) = fresh_pool();
        let mut bufs = Vec::new();
        pool.alloc(0, 4, &mut bufs);

        let buf = bufs.pop().unwrap();
        let owner_dropped_addr = buf.frame_addr;

        // The pool stays on this thread; only the buffer (which carries a
        // `*const XdpTxReclaim`, not a pool ptr) crosses threads.
        std::thread::spawn(move || drop(buf)).join().unwrap();

        // available() drains remote into local before counting.
        assert_eq!(pool.available(), 16 - 3);
        // Re-alloc: we should get back the address that was returned remotely.
        let mut bufs2 = Vec::new();
        pool.alloc(0, 16 - 3, &mut bufs2);
        let addrs: Vec<u64> = bufs2.iter().map(|b| b.frame_addr).collect();
        assert!(addrs.contains(&owner_dropped_addr));
    }
}
