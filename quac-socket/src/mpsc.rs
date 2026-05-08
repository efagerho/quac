use crossbeam_queue::ArrayQueue;

/// Bounded MPSC backed by [`ArrayQueue`]. Push from any thread; `pop` /
/// `drain_into` are single-consumer by convention. Full push returns
/// `Err(value)`; size for worst-case in-flight.
pub struct MpscQueue<T: Send> {
    inner: ArrayQueue<T>,
}

impl<T: Send> MpscQueue<T> {
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: ArrayQueue::new(capacity),
        }
    }

    /// Push from any thread. `Err(value)` if full.
    #[inline]
    pub fn push(&self, value: T) -> Result<(), T> {
        self.inner.push(value)
    }

    /// Pop one value. Single-consumer by convention.
    #[inline]
    pub fn pop(&self) -> Option<T> {
        self.inner.pop()
    }

    /// Drain all available values into `out`. Single-consumer by convention.
    pub fn drain_into(&self, out: &mut Vec<T>) {
        while let Some(v) = self.inner.pop() {
            out.push(v);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn single_producer_single_consumer() {
        let q: MpscQueue<u64> = MpscQueue::new(16);
        assert!(q.pop().is_none());

        q.push(1).unwrap();
        q.push(2).unwrap();
        q.push(3).unwrap();

        assert_eq!(q.pop(), Some(1));
        assert_eq!(q.pop(), Some(2));
        assert_eq!(q.pop(), Some(3));
        assert!(q.pop().is_none());
    }

    #[test]
    fn drain_into_collects_all() {
        let q: MpscQueue<u32> = MpscQueue::new(128);
        for i in 0..64u32 {
            q.push(i).unwrap();
        }
        let mut out = Vec::new();
        q.drain_into(&mut out);
        assert_eq!(out, (0..64).collect::<Vec<_>>());
        assert!(q.pop().is_none());
    }

    #[test]
    fn push_full_returns_value() {
        let q: MpscQueue<u32> = MpscQueue::new(2);
        assert!(q.push(10).is_ok());
        assert!(q.push(20).is_ok());
        assert_eq!(q.push(30), Err(30));
    }

    #[test]
    fn multi_producer_single_consumer() {
        const PRODUCERS: usize = 8;
        const PER_PRODUCER: usize = 1_000;

        let q = Arc::new(MpscQueue::<usize>::new(PRODUCERS * PER_PRODUCER + 64));
        let handles: Vec<_> = (0..PRODUCERS)
            .map(|id| {
                let q = Arc::clone(&q);
                thread::spawn(move || {
                    for _ in 0..PER_PRODUCER {
                        // Spin until push succeeds; with capacity > total pushes
                        // this only matters if test ordering happens to fill ahead.
                        while q.push(id).is_err() {
                            std::hint::spin_loop();
                        }
                    }
                })
            })
            .collect();

        let mut out = Vec::new();
        let expected = PRODUCERS * PER_PRODUCER;
        while out.len() < expected {
            q.drain_into(&mut out);
        }

        for h in handles {
            h.join().unwrap();
        }

        assert_eq!(out.len(), expected);
    }

    #[test]
    fn drop_drains_pending() {
        let q: MpscQueue<String> = MpscQueue::new(8);
        q.push("hello".into()).unwrap();
        q.push("world".into()).unwrap();
        drop(q);
    }

    #[test]
    fn interleaved_push_and_drain() {
        let q: MpscQueue<u32> = MpscQueue::new(32);
        let mut out = Vec::new();

        for round in 0..10u32 {
            for i in 0..10u32 {
                q.push(round * 10 + i).unwrap();
            }
            q.drain_into(&mut out);
        }

        assert_eq!(out, (0..100).collect::<Vec<_>>());
    }
}
