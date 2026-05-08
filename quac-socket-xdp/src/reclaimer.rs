//! Cross-thread frame reclamation for the RX FILL ring. Owner-thread drops
//! push to `pending` (no atomics); other threads push to `remote` (MPSC).
//! `recv` drains both into FILL at the top of each batch.

#![allow(dead_code)]

use std::cell::UnsafeCell;
use std::thread::ThreadId;

use quac_socket::MpscQueue;

pub(crate) struct Reclaimer {
    pub(crate) owner: ThreadId,
    /// Same-thread frames; drained in `recv` / `drain_completions`.
    pub(crate) pending: UnsafeCell<Vec<u64>>,
    /// Cross-thread frames. Sized to in-flight buffer count.
    pub(crate) remote: MpscQueue<u64>,
}

// Safety: `pending` is owner-thread only (enforced by current_thread_owns
// checks); `remote` is Sync via MpscQueue's ArrayQueue.
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

    #[inline]
    pub fn current_thread_owns(&self) -> bool {
        quac_socket::cpu::current_thread_id() == self.owner
    }
}
