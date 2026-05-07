//! Buffer pools and buffer wrappers for the AF_XDP backend.
//!
//! Layout choice mirrors `quac-socket-iouring`:
//
// Several constructors / accessors aren't called yet — phased construction.
// `XdpRxBufMut::from_ring_frame` is wired up by `recv` (Phase 6); the
// `Ring` variant is constructed there. `frame_addr` / `payload_offset` /
// `payload_len` accessors are read by `send` (Phase 7).
#![allow(dead_code)]
//!
//! - `XdpRxPool` is a marker pool: `alloc` returns zero-cost
//!   [`XdpRxBufMut::Empty`] placeholders; `recv` swaps them for `Ring` variants
//!   wrapping a UMEM frame. Same/cross-thread drops route the frame address
//!   back via [`Reclaimer`].
//! - `XdpTxPool` owns a free list of UMEM frame addresses. `alloc` pops one
//!   into a [`XdpTxBufMut`]; the caller writes the UDP payload starting at
//!   `HEADROOM` so the socket can fill in ETH/IP/UDP headers in place; on
//!   freeze the buffer becomes [`XdpTxBuf`] which `send` consumes.
//! - `UNIFIED = false`: `XdpTxPool::from_rx` allocates a fresh Tx frame and
//!   memcpy's the Rx payload, then drops the Rx frame back to FILL. Same
//!   pattern as `IoTxPool::from_rx`.

use std::cell::UnsafeCell;
use std::marker::PhantomData;
use std::mem::{self, MaybeUninit};
use std::ptr;
use std::slice;
use std::thread::ThreadId;

use quac_socket::{MpscQueue, PacketBuf, PacketBufMut, RxPool, TxPool};

use crate::reclaimer::Reclaimer;

/// Headroom bytes reserved at the start of every TX frame for the
/// Ethernet+IPv4+UDP headers that `send` fills in place.
///
/// 14 (ETH) + 20 (IPv4, no options) + 8 (UDP) = 42 bytes.
pub const HEADROOM: u32 = 42;

// ── XdpRxPool ────────────────────────────────────────────────────────────────

/// Marker Rx pool. Holds no buffers — UMEM frames flow through the FILL/RX
/// rings; this struct only carries the per-socket configuration that
/// `RxPool::alloc` needs. Allocations return [`XdpRxBufMut::Empty`] which
/// `recv()` later replaces with a `Ring` variant.
///
/// `Send + !Sync`: movable between threads at construction time so a tile
/// factory can hand it off to its worker, but never shared concurrently.
/// Cross-thread buffer reclamation routes through the [`Reclaimer`], not
/// through the pool itself.
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

// ── XdpRxBufMut / XdpRxBuf ───────────────────────────────────────────────────

/// Two-state Rx buffer. `Empty` is what `XdpRxPool::alloc` produces; `recv`
/// `mem::replace`s the slot with a `Ring` variant that points into the
/// kernel-filled UMEM frame.
pub(crate) enum XdpRxBufMutRepr {
    /// Placeholder — not yet associated with any frame. Drop is a no-op.
    Empty,
    /// Live UMEM frame. Drop returns `frame_addr` to the FILL ring via the
    /// reclaimer (same-thread → `pending`; cross-thread → `remote` MPSC).
    Ring {
        umem_base: *mut u8,
        frame_addr: u64,
        payload_offset: u32,
        payload_len: u32,
        cap: u32,
        reclaimer: *const Reclaimer,
    },
}

/// Mutable Rx buffer (passed to `recv` slots).
pub struct XdpRxBufMut {
    pub(crate) repr: XdpRxBufMutRepr,
}

// Safety: `Ring` carries raw pointers into the UMEM (which outlives every
// buffer) and to the reclaimer (also socket-lifetime). All cross-thread
// drops route through the reclaimer's MPSC queue.
unsafe impl Send for XdpRxBufMut {}

impl Drop for XdpRxBufMut {
    fn drop(&mut self) {
        let XdpRxBufMutRepr::Ring { frame_addr, reclaimer, .. } = self.repr else {
            return; // Empty placeholder — nothing to reclaim.
        };
        // Safety: `reclaimer` is a `Box<Reclaimer>` owned by the socket
        // (longest-lived object on the tile). Same lifetime constraint as
        // `IoUringSocket::RingReclaimer`.
        let rec = unsafe { &*reclaimer };
        if rec.current_thread_owns() {
            // Same thread as the socket — push to the local list (no atomics).
            unsafe { (*rec.pending.get()).push(frame_addr) };
        } else {
            // Cross-thread — bounded MPSC queue. Capacity is sized to the
            // number of frames in circulation, so push must always succeed.
            // Losing a frame here would permanently shrink the FILL ring's
            // working set.
            rec.remote
                .push(frame_addr)
                .expect("Reclaimer.remote queue full — sized < frame count");
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
                // Spare capacity sits *after* the filled bytes within the
                // payload region — same shape as `IoRxBufMut::uninit_mut`.
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
                // Don't run our Drop (would push the bid back to the
                // reclaimer); ownership transfers to XdpRxBuf.
                mem::forget(self);
                XdpRxBuf { umem_base, frame_addr, payload_offset, payload_len, reclaimer }
            }
        }
    }
}

impl XdpRxBufMut {
    /// Construct a `Ring` buffer wrapping a kernel-filled UMEM frame.
    /// Called from `recv` once the kernel has produced an RX descriptor.
    ///
    /// # Safety
    /// `umem_base + frame_addr + payload_offset + payload_len` must lie
    /// inside the UMEM region. `reclaimer` must outlive this buffer.
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

/// Frozen Rx buffer. Reclaims its UMEM frame on drop, same as `XdpRxBufMut::Ring`.
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
                .expect("Reclaimer.remote queue full — sized < frame count");
        }
    }
}

// ── XdpTxReclaim ─────────────────────────────────────────────────────────────

/// Cross-thread frame reclamation target for the TX side. Mirrors
/// [`Reclaimer`] on the RX side: the buffers hold a `*const XdpTxReclaim`
/// (not `*const XdpTxPool`) so that the cross-thread Drop never has to
/// fabricate a `&XdpTxPool` on a non-owner thread — that would require
/// `XdpTxPool: Sync`, which CLAUDE.md forbids.
///
/// `local` is owner-thread-only (no atomics); `remote` is a bounded MPSC
/// for cross-thread returns. The owner-thread pop path drains `remote`
/// into `local` then takes from `local`.
pub(crate) struct XdpTxReclaim {
    pub(crate) owner: ThreadId,
    pub(crate) local: UnsafeCell<Vec<u64>>,
    pub(crate) remote: MpscQueue<u64>,
}

// Safety: `local` is only mutated on the owner thread (enforced by the
// `owner == current().id()` check in every drop site); `remote` is `Sync`
// via `MpscQueue`'s internal `ArrayQueue`. Same justification as `Reclaimer`.
unsafe impl Send for XdpTxReclaim {}
unsafe impl Sync for XdpTxReclaim {}

// ── XdpTxPool ────────────────────────────────────────────────────────────────

/// Free list of UMEM frame addresses for the TX side.
///
/// Layout mirrors `IoTxPool`: `local` is owner-thread-only (no atomics),
/// `remote` is a bounded MPSC for cross-thread returns; `alloc()` drains
/// `remote` into `local` then pops. `UNIFIED = false`: `from_rx` allocates
/// a new Tx frame and copies the Rx payload (same as `IoTxPool::from_rx`).
///
/// `Send + !Sync`: movable between threads at construction time so a tile
/// factory can hand it off to its worker, but methods (alloc / available /
/// from_rx) only run on the owner thread. Cross-thread buffer drops route
/// through [`XdpTxReclaim`], which is `Sync`.
pub struct XdpTxPool {
    pub(crate) max_payload: usize,
    pub(crate) frame_size: u32,
    pub(crate) headroom: u32,
    pub(crate) umem_base: *mut u8,
    /// Owns the cross-thread reclaim queue. `Box` so its address is stable
    /// for buffers that hold a `*const XdpTxReclaim`.
    pub(crate) reclaim: Box<XdpTxReclaim>,
    _not_sync: PhantomData<core::cell::Cell<()>>,
}

// Safety: `XdpTxPool` itself is `!Sync` (PhantomData<Cell<()>>), so no two
// threads can hold `&XdpTxPool` simultaneously — this is the actual safety
// invariant. Moving the pool from a tile factory thread to the worker thread
// is sound because `local: UnsafeCell<Vec<u64>>` only has one thread looking
// at it at any moment, and `umem_base: *mut u8` is a stable pointer to UMEM
// that the socket also owns. Cross-thread buffer drops never touch the pool
// itself: they route through `XdpTxReclaim` (a separate `Send + Sync` type),
// which is why the pool can stay `!Sync` even when buffers it allocated are
// being dropped on engine threads. The explicit `unsafe impl Send` is needed
// only because `*mut u8` doesn't auto-derive `Send`.
unsafe impl Send for XdpTxPool {}

impl XdpTxPool {
    /// Construct with the initial set of available frame addresses. The
    /// caller (the AF_XDP socket) carves the UMEM into Rx half / Tx half
    /// and seeds this pool with the Tx-side frames.
    ///
    /// `remote_capacity` should be ≥ the maximum number of frames that can
    /// be in flight outside the pool at any one time (= total frames).
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

    /// `false`: `from_rx` copies the Rx payload into a new Tx frame. AF_XDP
    /// could in principle do this without copying (single UMEM, just rewrite
    /// headers) but that's a future optimisation — see plan §UNIFIED choice.
    const UNIFIED: bool = false;

    fn max_payload_size(&self) -> usize {
        self.max_payload
    }

    fn alloc(&self, _capacity: usize, count: usize, bufs: &mut Vec<XdpTxBufMut>) -> usize {
        // Safety: alloc is owner-thread only (CLAUDE.md invariant); `local`
        // is therefore exclusively ours.
        let local = unsafe { &mut *self.reclaim.local.get() };
        // Drain cross-thread returns into the local list — bounded MPSC pop.
        unsafe { self.reclaim.remote.drain_into(local) };

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
        // Safety: owner-thread-only — same invariant as `alloc`.
        let local = unsafe { &mut *self.reclaim.local.get() };
        unsafe { self.reclaim.remote.drain_into(local) };
        local.len()
    }

    fn zerocopy_threshold(&self) -> usize {
        // AF_XDP send is single-segment (MAX_SEGMENTS=1); we always coalesce
        // into one contiguous frame, so there's no scatter-gather path that
        // would need a "small enough to copy" threshold.
        0
    }

    fn from_rx(&self, rx: XdpRxBufMut) -> Result<XdpTxBufMut, XdpRxBufMut> {
        // SAFETY: from_rx is owner-thread only (CLAUDE.md invariant).
        let local = unsafe { &mut *self.reclaim.local.get() };
        unsafe { self.reclaim.remote.drain_into(local) };
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
                // Safety: src and dst are non-overlapping (rx and tx frames
                // are different UMEM regions); `len` ≤ `max_payload` ≤ cap.
                unsafe { ptr::copy_nonoverlapping(src, dst, len) };
                drop(rx); // Returns the rx frame to the FILL ring.
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

// ── XdpTxBufMut / XdpTxBuf ───────────────────────────────────────────────────

/// Mutable Tx buffer. The `payload_offset..payload_offset+cap` window of
/// the underlying UMEM frame is the user's; `[0..payload_offset)` is
/// reserved for the Ethernet/IP/UDP headers `send()` writes in place.
pub struct XdpTxBufMut {
    umem_base: *mut u8,
    frame_addr: u64,
    payload_offset: u32,
    payload_len: u32,
    cap: u32,
    /// Cross-thread reclamation target. Pointing at `XdpTxReclaim` (which is
    /// `Sync`) rather than `XdpTxPool` lets the pool stay `!Send + !Sync`.
    reclaim: *const XdpTxReclaim,
}

unsafe impl Send for XdpTxBufMut {}

impl Drop for XdpTxBufMut {
    fn drop(&mut self) {
        if self.reclaim.is_null() {
            return;
        }
        // Safety: `reclaim` is `Sync` and lives as long as the pool that
        // allocated this buffer (which outlives every buffer per CLAUDE.md).
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
        // Suppress Drop (would re-claim the frame); ownership transfers to XdpTxBuf.
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

/// Frozen Tx buffer ready for `send()`. Reclaims its UMEM frame on drop.
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
    /// Frame address inside the UMEM. `send()` reads this when building the
    /// XDP descriptor.
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

// ── reclaim helper ───────────────────────────────────────────────────────────

/// Push `addr` back to the pool's free list via the cross-thread-safe
/// `XdpTxReclaim`. Caller-thread aware: same-thread drops bypass the MPSC
/// and append to `local`; other-thread drops push to `remote`.
///
/// # Safety
/// `reclaim` must be non-null and point to a `XdpTxReclaim` that outlives
/// this call (true by CLAUDE.md's pool-outlives-buffer invariant).
#[inline]
fn reclaim_frame(reclaim: *const XdpTxReclaim, addr: u64) {
    let r = unsafe { &*reclaim };
    if std::thread::current().id() == r.owner {
        // Owner thread — `local` is exclusively ours.
        unsafe { (*r.local.get()).push(addr) };
    } else {
        // Cross-thread — bounded MPSC. Sized for the full frame count, so
        // an overflow indicates a leak elsewhere; debug-assert to surface.
        let pushed = r.remote.push(addr);
        debug_assert!(pushed.is_ok(), "XdpTxReclaim.remote queue full — sized < frame count");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::umem::Umem;

    /// Returns both the pool *and* the backing UMEM. The pool stores a raw
    /// `*mut u8` into the UMEM with no lifetime; production code (`XdpSocket`
    /// in Phase 6) owns both and guarantees the UMEM outlives the pool. In
    /// tests we have to do the same: drop the returned tuple as a unit, not
    /// the pool alone — otherwise the UMEM is munmapped while the pool
    /// still believes it's live, and any access through a buffer segfaults.
    fn fresh_pool() -> (Umem, Box<XdpTxPool>) {
        // 16 frames × 2048 bytes = 32 KiB UMEM (no huge pages needed).
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

    /// Pools are `Send + !Sync`: movable between threads at construction time
    /// (so a tile factory can hand a pool off to its worker thread) but never
    /// shared concurrently — `alloc` / `available` etc. are owner-thread-only.
    /// The compile-time check below uses the `static_assertions`-style
    /// ambiguity trick to fail compilation if either pool ever gains `Sync`.
    fn _assert_pools_not_sync() {
        trait NegatedSync<A> {
            fn check() {}
        }
        impl<T: ?Sized> NegatedSync<()> for T {}
        impl<T: ?Sized + Sync> NegatedSync<u8> for T {}

        let _ = <XdpRxPool as NegatedSync<_>>::check;
        let _ = <XdpTxPool as NegatedSync<_>>::check;
    }

    /// Anchors `_assert_pools_not_sync` so removing it from the test build is
    /// noisy — without this `#[test]`, the type-level assertion still fires
    /// during compilation, but a future refactor that deletes the helper
    /// silently loses the check. Calling it from a `#[test]` keeps the
    /// dependency explicit.
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
        // Pool is empty — next alloc returns 0.
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

        // Write a payload, freeze, drop the frozen buffer — frame returns
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

        // Send the buffer to another thread and let its Drop run there.
        // The buffer holds a raw `*const XdpTxReclaim` (Sync), which is the
        // whole reason `XdpTxPool` itself doesn't need to be Send/Sync —
        // the pool stays pinned on this thread for the duration of the
        // test (it isn't moved into the spawn).
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
