use std::cell::UnsafeCell;
use std::mem::MaybeUninit;
use std::ptr;
use std::sync::atomic::{AtomicPtr, Ordering};

struct Node<T> {
    value: MaybeUninit<T>,
    next: AtomicPtr<Node<T>>,
}

/// Non-intrusive Vyukov MPSC queue.
///
/// **Producers** (any thread): [`push`](Self::push) — allocates one `Box<Node<T>>` and
/// performs a single `AtomicPtr::swap`. Always lock-free; never retries.
///
/// **Consumer** (single thread): [`drain_into`](Self::drain_into) — moves all currently
/// available values into a caller-supplied `Vec` without any allocation. Must be called
/// from at most one thread at a time; the pool's ownership model enforces this.
///
/// The queue uses a sentinel stub node (stored in a `Box` for a stable heap address) so
/// that `push` never has to check for an empty queue.
pub struct MpscQueue<T: Send> {
    /// Consumer-only. Points to the last-consumed node (or the stub initially).
    head: UnsafeCell<*mut Node<T>>,
    /// Shared tail; producers advance it with `swap`, then wire the previous tail's `next`.
    tail: AtomicPtr<Node<T>>,
    /// Sentinel. Always present in the queue; `pop` skips it, never returns it.
    /// Stored in a `Box` so the pointer remains stable across moves of `MpscQueue`.
    stub: Box<Node<T>>,
}

// Safety: `push` is fully lock-free and only touches `tail` (AtomicPtr) and the
// newly-allocated node's `next` (AtomicPtr). `drain_into`/`pop` are consumer-only —
// the pool's single-network-thread invariant serialises them. The `UnsafeCell<*mut>`
// for `head` is only written under that same consumer serialisation.
unsafe impl<T: Send> Send for MpscQueue<T> {}
unsafe impl<T: Send> Sync for MpscQueue<T> {}

impl<T: Send> MpscQueue<T> {
    pub fn new() -> Self {
        let stub = Box::new(Node {
            value: MaybeUninit::uninit(),
            next: AtomicPtr::new(ptr::null_mut()),
        });
        let stub_ptr = &*stub as *const Node<T> as *mut Node<T>;
        Self {
            head: UnsafeCell::new(stub_ptr),
            tail: AtomicPtr::new(stub_ptr),
            stub,
        }
    }

    /// Push a value from any thread. Allocates one `Box<Node<T>>` and performs one
    /// `AtomicPtr::swap`. Never blocks or retries.
    pub fn push(&self, value: T) {
        let node = Box::into_raw(Box::new(Node {
            value: MaybeUninit::new(value),
            next: AtomicPtr::new(ptr::null_mut()),
        }));
        // Claim the old tail and install ourselves as the new one.
        let prev = self.tail.swap(node, Ordering::AcqRel);
        // Wire the old tail's next so the consumer can follow the chain.
        // Safety: `prev` is either the stub or a previously-allocated node; both
        // are valid for the lifetime of the queue.
        unsafe { (*prev).next.store(node, Ordering::Release) };
    }

    /// Pop one value. Consumer thread only.
    ///
    /// Returns `None` when the queue is empty or when a concurrent producer has
    /// claimed the tail pointer but has not yet stored its `next` pointer —
    /// the value will be available on the next call.
    unsafe fn pop(&self) -> Option<T> {
        let stub_ptr = &*self.stub as *const Node<T> as *mut Node<T>;
        let mut h = *self.head.get();

        // If head is the stub, skip it to the first real node.
        if h == stub_ptr {
            let next = (*h).next.load(Ordering::Acquire);
            if next.is_null() {
                return None; // queue is empty
            }
            *self.head.get() = next;
            h = next;
        }

        // h is a real node. Try the fast path: a next pointer is already wired.
        let next = (*h).next.load(Ordering::Acquire);
        if !next.is_null() {
            *self.head.get() = next;
            let value = (*h).value.assume_init_read();
            drop(Box::from_raw(h));
            return Some(value);
        }

        // h might be the last node in the queue. Check the tail.
        let tail = self.tail.load(Ordering::Acquire);
        if h != tail {
            // A producer swapped tail but hasn't stored its next pointer yet.
            // The value will be visible on the next pop call.
            return None;
        }

        // h is definitely the last node. Re-inject the stub so future pushes
        // can wire their nodes after the stub and keep the queue coherent.
        (*stub_ptr).next.store(ptr::null_mut(), Ordering::Relaxed);
        let prev = self.tail.swap(stub_ptr, Ordering::AcqRel);
        // Wire prev (the old last node, possibly h or a newly-raced node) to stub.
        (*prev).next.store(stub_ptr, Ordering::Release);

        // h.next may now be non-null (either stub, or a concurrently-pushed node
        // whose producer wired h.next during the re-injection window).
        let next = (*h).next.load(Ordering::Acquire);
        if !next.is_null() {
            *self.head.get() = next;
            let value = (*h).value.assume_init_read();
            drop(Box::from_raw(h));
            return Some(value);
        }
        None
    }

    /// Drain all currently-available values into `out`. Consumer thread only.
    ///
    /// Stops as soon as `pop` returns `None`, which happens when the queue is empty
    /// or a producer is mid-push. Values from an in-flight push will appear on the
    /// next `drain_into` call — no values are ever lost.
    ///
    /// # Safety
    /// Must be called only from the single consumer thread.
    pub unsafe fn drain_into(&self, out: &mut Vec<T>) {
        while let Some(v) = self.pop() {
            out.push(v);
        }
    }
}

impl<T: Send> Default for MpscQueue<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Send> Drop for MpscQueue<T> {
    fn drop(&mut self) {
        // Drain any queued-but-not-yet-consumed values so their `T` destructors run
        // and the `Box<Node<T>>` allocations are freed. The stub Box drops after.
        while unsafe { self.pop() }.is_some() {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn single_producer_single_consumer() {
        let q: MpscQueue<u64> = MpscQueue::new();
        assert!(unsafe { q.pop() }.is_none());

        q.push(1);
        q.push(2);
        q.push(3);

        assert_eq!(unsafe { q.pop() }, Some(1));
        assert_eq!(unsafe { q.pop() }, Some(2));
        assert_eq!(unsafe { q.pop() }, Some(3));
        assert!(unsafe { q.pop() }.is_none());
    }

    #[test]
    fn drain_into_collects_all() {
        let q: MpscQueue<u32> = MpscQueue::new();
        for i in 0..64u32 {
            q.push(i);
        }
        let mut out = Vec::new();
        unsafe { q.drain_into(&mut out) };
        assert_eq!(out, (0..64).collect::<Vec<_>>());
        assert!(unsafe { q.pop() }.is_none());
    }

    #[test]
    fn multi_producer_single_consumer() {
        const PRODUCERS: usize = 8;
        const PER_PRODUCER: usize = 1_000;

        let q = Arc::new(MpscQueue::<usize>::new());
        let handles: Vec<_> = (0..PRODUCERS)
            .map(|id| {
                let q = Arc::clone(&q);
                thread::spawn(move || {
                    for _ in 0..PER_PRODUCER {
                        q.push(id);
                    }
                })
            })
            .collect();

        let mut out = Vec::new();
        // Spin until all expected values arrive.
        let expected = PRODUCERS * PER_PRODUCER;
        while out.len() < expected {
            unsafe { q.drain_into(&mut out) };
        }

        for h in handles {
            h.join().unwrap();
        }

        assert_eq!(out.len(), expected);
    }

    #[test]
    fn drop_drains_pending() {
        let q: MpscQueue<String> = MpscQueue::new();
        q.push("hello".into());
        q.push("world".into());
        // Drop without consuming — Drop impl must run String destructors without leaking.
        drop(q);
    }

    #[test]
    fn interleaved_push_and_drain() {
        let q: MpscQueue<u32> = MpscQueue::new();
        let mut out = Vec::new();

        for round in 0..10u32 {
            for i in 0..10u32 {
                q.push(round * 10 + i);
            }
            unsafe { q.drain_into(&mut out) };
        }

        assert_eq!(out, (0..100).collect::<Vec<_>>());
    }
}
