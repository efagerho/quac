//! Cross-thread frame reclamation for the AF_XDP RX path.
//!
//! When a `XdpRxBufMut::Ring` is dropped, its UMEM frame address has to flow
//! back to the FILL ring so the kernel can refill it on the next RX. Two
//! drop sites:
//! - **owner thread** (network tile, where `recv` lives): push to `pending`,
//!   a `Vec<u64>` behind `UnsafeCell` — zero atomics.
//! - **other threads** (engine threads holding `XdpRxBufMut` after pop):
//!   push to `remote`, a bounded `MpscQueue<u64>` — one `AtomicPtr` swap.
//!
//! `recv()` calls `drain_pending()` at the top of each batch to move both
//! queues into the FILL ring before reading new RX descriptors. Mirrors
//! `RingReclaimer` in `quac-socket-iouring`.
//
// `Reclaimer::new` is called by the AF_XDP socket constructor (Phase 6).
#![allow(dead_code)]

use std::cell::UnsafeCell;
use std::thread::ThreadId;

use quac_socket::MpscQueue;

/// Frame-address reclaimer for the FILL ring.
pub(crate) struct Reclaimer {
    /// The thread that owns the AF_XDP socket. Same-thread drops route to
    /// `pending`; other-thread drops route to `remote`.
    pub(crate) owner: ThreadId,
    /// Same-thread free frames waiting to be re-submitted to FILL. Drained
    /// on the owner thread inside `recv`/`drain_completions`.
    pub(crate) pending: UnsafeCell<Vec<u64>>,
    /// Cross-thread free frames. Bounded; sized for the maximum number of
    /// in-flight rx buffers (= number of frames in the RX/FILL pipeline).
    pub(crate) remote: MpscQueue<u64>,
}

// Safety: `pending` is only touched on the owner thread (enforced by
// `current_thread_owns()` checks in drop impls); `remote` is `Sync` via
// `MpscQueue`'s internal `ArrayQueue`.
unsafe impl Send for Reclaimer {}
unsafe impl Sync for Reclaimer {}

impl Reclaimer {
    pub fn new(owner: ThreadId, remote_capacity: usize) -> Self {
        Self {
            owner,
            pending: UnsafeCell::new(Vec::with_capacity(remote_capacity)),
            remote: MpscQueue::new(remote_capacity),
        }
    }

    /// `true` if the calling thread is the socket-owning thread.
    #[inline]
    pub fn current_thread_owns(&self) -> bool {
        std::thread::current().id() == self.owner
    }
}
