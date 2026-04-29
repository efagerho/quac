use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};

use atomic_waker::AtomicWaker;
use crossbeam_queue::ArrayQueue;

/// A fixed-capacity queue that allows async tasks to await items pushed
/// from a non-async producer (the engine thread).
pub(crate) struct AppQueue<T> {
    queue: ArrayQueue<T>,
    waker: AtomicWaker,
    /// Set to `true` when a push transitions the queue from empty (or
    /// "unobserved") to non-empty; cleared by the consumer just before it
    /// re-registers its waker.  The producer calls `waker.wake()` only on
    /// the `false → true` transition, coalescing back-to-back pushes into
    /// a single cross-thread wakeup.
    needs_wake: AtomicBool,
}

impl<T> AppQueue<T> {
    pub(crate) fn new(cap: usize) -> Self {
        Self {
            queue: ArrayQueue::new(cap),
            waker: AtomicWaker::new(),
            needs_wake: AtomicBool::new(false),
        }
    }

    /// Push an item. Wakes the async consumer only on the false→true
    /// transition of `needs_wake`. Returns `Err(item)` if the queue is full.
    pub(crate) fn push(&self, item: T) -> Result<(), T> {
        let result = self.queue.push(item);
        if result.is_ok() && !self.needs_wake.swap(true, Ordering::AcqRel) {
            self.waker.wake();
        }
        result
    }

    /// Force-push: push and drop the oldest item if the queue is full.
    /// Wakes the async consumer only on the false→true transition.
    pub(crate) fn push_overwrite(&self, item: T) {
        let _ = self.queue.force_push(item);
        if !self.needs_wake.swap(true, Ordering::AcqRel) {
            self.waker.wake();
        }
    }

    /// Non-blocking pop.
    pub(crate) fn pop(&self) -> Option<T> {
        self.queue.pop()
    }

    /// Async-friendly poll. Registers the waker then double-checks the
    /// queue to close the race between registration and a concurrent push.
    pub(crate) fn poll_pop(&self, cx: &mut Context<'_>) -> Poll<T> {
        if let Some(v) = self.queue.pop() {
            return Poll::Ready(v);
        }
        // Clear needs_wake BEFORE registering the waker so any push that
        // arrives after this store sees false and calls wake(). The
        // double-check below catches any push that landed in the window
        // between the pop above and waker registration.
        self.needs_wake.store(false, Ordering::Release);
        self.waker.register(cx.waker());
        match self.queue.pop() {
            Some(v) => Poll::Ready(v),
            None => Poll::Pending,
        }
    }
}
