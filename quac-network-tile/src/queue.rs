use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::sync::OnceLock;
use std::thread::{self, Thread};
use std::time::Duration;

use crossbeam_queue::ArrayQueue;

mod sealed {
    pub trait Sealed {}
}

/// Compile-time wait strategy for tile queues.
///
/// Implement this on a zero-size marker type. The compiler monomorphizes and
/// inlines all methods, so the spin variant pays zero overhead: no extra
/// fields, no atomic loads, no branch instructions in `push`.
pub trait WaitStrategy: sealed::Sealed + Send + Sync + 'static {
    /// Per-queue state. `()` for `Spin` (zero size); `ParkState` for `Park`.
    type State: Default + Send + Sync + 'static;

    /// Called by the producer immediately after a successful push.
    fn on_push(s: &Self::State);

    /// Called once by the consumer thread before entering its loop.
    fn register_consumer(s: &Self::State);

    /// Announce that the consumer is about to check emptiness and sleep.
    /// Must be sequentially consistent so producers see it before their push.
    fn set_sleeping(s: &Self::State);

    /// Clear the sleeping flag after waking.
    fn clear_sleeping(s: &Self::State);

    /// Sleep hint for the IO thread. Must return promptly even without a
    /// wakeup so the thread can re-poll the socket. `Spin`: spin_loop().
    /// `Park`: park_timeout(50 µs).
    fn do_wait();

    /// SeqCst fence between `set_sleeping` and the empty re-check; pairs
    /// with `on_push`'s SeqCst load on `sleeping`. No-op for `Spin`.
    fn fence_after_set_sleeping();
}

/// Busy-spin wait strategy. Lowest latency; dedicates a full CPU core.
#[derive(Debug, Clone, Copy, Default)]
pub struct Spin;

impl sealed::Sealed for Spin {}

impl WaitStrategy for Spin {
    type State = ();

    #[inline(always)]
    fn on_push(_: &()) {}
    #[inline(always)]
    fn register_consumer(_: &()) {}
    #[inline(always)]
    fn set_sleeping(_: &()) {}
    #[inline(always)]
    fn clear_sleeping(_: &()) {}
    #[inline(always)]
    fn do_wait() {
        std::hint::spin_loop();
    }
    #[inline(always)]
    fn fence_after_set_sleeping() {}
}

/// Park/unpark wait strategy. Near-zero idle CPU; small wakeup latency added.
#[derive(Debug, Clone, Copy, Default)]
pub struct Park;

impl sealed::Sealed for Park {}

pub struct ParkState {
    sleeping: AtomicBool,
    consumer: OnceLock<Thread>,
}

impl Default for ParkState {
    fn default() -> Self {
        Self {
            sleeping: AtomicBool::new(false),
            consumer: OnceLock::new(),
        }
    }
}

impl WaitStrategy for Park {
    type State = ParkState;

    #[inline(always)]
    fn on_push(s: &ParkState) {
        // SeqCst pairs with set_sleeping's SeqCst store for total order.
        if s.sleeping.load(Ordering::SeqCst) {
            if let Some(t) = s.consumer.get() {
                t.unpark();
            }
        }
    }

    #[inline(always)]
    fn register_consumer(s: &ParkState) {
        let _ = s.consumer.set(thread::current());
    }

    #[inline(always)]
    fn set_sleeping(s: &ParkState) {
        s.sleeping.store(true, Ordering::SeqCst);
    }

    #[inline(always)]
    fn clear_sleeping(s: &ParkState) {
        s.sleeping.store(false, Ordering::Relaxed);
    }

    #[inline(always)]
    fn do_wait() {
        thread::park_timeout(Duration::from_micros(50));
    }

    #[inline(always)]
    fn fence_after_set_sleeping() {
        std::sync::atomic::fence(Ordering::SeqCst);
    }
}

/// A bounded queue with a compile-time wait strategy.
///
/// `Queue<T, Spin>` is identical in size and generated code to a thin
/// `ArrayQueue<T>` wrapper -- the strategy fields are zero-sized and all
/// strategy methods are inlined away.
///
/// `Queue<T, Park>` adds a sleeping flag and thread handle; producers
/// unpark the consumer only when it has announced it is sleeping.
pub struct Queue<T, W: WaitStrategy> {
    inner: ArrayQueue<T>,
    state: W::State,
}

impl<T: Send, W: WaitStrategy> Queue<T, W> {
    pub fn new(capacity: usize) -> Arc<Self> {
        Arc::new(Self {
            inner: ArrayQueue::new(capacity),
            state: W::State::default(),
        })
    }

    /// Push an item. Returns `false` if the queue is full (item dropped).
    #[inline]
    pub fn push(&self, item: T) -> bool {
        if self.inner.push(item).is_err() {
            return false;
        }
        W::on_push(&self.state);
        true
    }

    #[inline]
    pub fn pop(&self) -> Option<T> {
        self.inner.pop()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Register the calling thread as this queue's consumer.
    /// No-op for `Spin`; records the thread handle for `Park`.
    #[inline]
    pub fn register_consumer(&self) {
        W::register_consumer(&self.state);
    }

    /// Wait until the queue is non-empty.
    ///
    /// Double-check pattern: set sleeping, SeqCst fence, re-check empty,
    /// sleep, clear. Compiles to spin_loop / no-ops for `Spin`.
    #[inline]
    pub fn wait_if_empty(&self) {
        W::set_sleeping(&self.state);
        W::fence_after_set_sleeping();
        if self.is_empty() {
            W::do_wait();
        }
        W::clear_sleeping(&self.state);
    }
}

/// Wait until at least one queue in `qs` is non-empty, using `do_wait`
/// so the call returns after a bounded timeout even if all queues stay empty,
/// allowing the caller to re-poll the socket. TX pushes still produce an
/// immediate wakeup via unpark.
pub fn wait_any_non_empty<T: Send, W: WaitStrategy>(qs: &[Arc<Queue<T, W>>]) {
    for q in qs {
        W::set_sleeping(&q.state);
    }
    W::fence_after_set_sleeping();
    if qs.iter().all(|q| q.is_empty()) {
        W::do_wait();
    }
    for q in qs {
        W::clear_sleeping(&q.state);
    }
}
