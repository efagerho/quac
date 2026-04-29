use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;
use std::thread::Thread;

/// Allows the engine thread to be unparked from other threads.
///
/// The OnceLock is written once (by the engine thread at startup) and then
/// read-only forever, so all subsequent accesses are wait-free.
pub(crate) struct EngineWaker {
    sleeping: AtomicBool,
    thread: OnceLock<Thread>,
}

impl EngineWaker {
    pub(crate) fn new() -> Self {
        Self {
            sleeping: AtomicBool::new(false),
            thread: OnceLock::new(),
        }
    }

    /// Called once by the engine thread at startup.
    pub(crate) fn register(&self) {
        let _ = self.thread.set(std::thread::current());
    }

    /// Wake the engine thread if it is sleeping.
    pub(crate) fn wake(&self) {
        if self.sleeping.load(Ordering::Acquire) {
            if let Some(t) = self.thread.get() {
                t.unpark();
            }
        }
    }

    /// Called by the engine thread before parking. Returns false if a wakeup
    /// arrived between the last check and this call (caller should not park).
    pub(crate) fn set_sleeping(&self) -> bool {
        self.sleeping.store(true, Ordering::SeqCst);
        true
    }

    /// Called by the engine thread after waking from park.
    pub(crate) fn clear_sleeping(&self) {
        self.sleeping.store(false, Ordering::Relaxed);
    }
}
