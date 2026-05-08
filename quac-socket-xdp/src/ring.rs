//! AF_XDP ring access (FILL / COMPLETION / RX / TX).

use std::io;
use std::ptr;
use std::sync::atomic::{AtomicU32, Ordering};

use libc::{munmap, xdp_ring_offset};

/// One AF_XDP descriptor (matches the kernel's `struct xdp_desc`).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct XdpDesc {
    pub addr: u64,
    pub len: u32,
    pub options: u32,
}

/// Cached producer/consumer for a kernel-filled ring. Indexes wrap modulo
/// 2^32; capacity math uses `wrapping_sub`. Caller does modulo-size masking.
pub struct RingConsumer {
    producer: *mut AtomicU32,
    cached_producer: u32,
    consumer: *mut AtomicU32,
    cached_consumer: u32,
}

// Safety: only the owning thread (network tile) accesses these atomics.
unsafe impl Send for RingConsumer {}

impl RingConsumer {
    /// Wrap kernel-shared mmap pointers. Producer load is Acquire (see
    /// kernel writes); consumer is Relaxed (we own it).
    pub fn new(producer: *mut AtomicU32, consumer: *mut AtomicU32) -> Self {
        Self {
            producer,
            cached_producer: unsafe { (*producer).load(Ordering::Acquire) },
            consumer,
            cached_consumer: unsafe { (*consumer).load(Ordering::Relaxed) },
        }
    }

    /// Available descriptors (cached). Call [`sync`](Self::sync) to refresh.
    pub fn available(&self) -> u32 {
        self.cached_producer.wrapping_sub(self.cached_consumer)
    }

    /// Consume one descriptor; returns the index (not yet committed).
    pub fn consume(&mut self) -> Option<u32> {
        if self.cached_consumer == self.cached_producer {
            return None;
        }
        let index = self.cached_consumer;
        self.cached_consumer = self.cached_consumer.wrapping_add(1);
        Some(index)
    }

    /// Publish our consumer index to the kernel (Release).
    pub fn commit(&mut self) {
        unsafe { (*self.consumer).store(self.cached_consumer, Ordering::Release) };
    }

    /// Optionally commit, then re-load the kernel's producer index.
    pub fn sync(&mut self, commit: bool) {
        if commit {
            self.commit();
        }
        self.cached_producer = unsafe { (*self.producer).load(Ordering::Acquire) };
    }
}

/// Cached producer/consumer for a userspace-filled ring. Full when
/// `producer - consumer == size`.
pub struct RingProducer {
    producer: *mut AtomicU32,
    cached_producer: u32,
    consumer: *mut AtomicU32,
    cached_consumer: u32,
    size: u32,
}

// Safety: see RingConsumer.
unsafe impl Send for RingProducer {}

impl RingProducer {
    pub fn new(producer: *mut AtomicU32, consumer: *mut AtomicU32, size: u32) -> Self {
        Self {
            producer,
            cached_producer: unsafe { (*producer).load(Ordering::Relaxed) },
            consumer,
            cached_consumer: unsafe { (*consumer).load(Ordering::Acquire) },
            size,
        }
    }

    /// Free slots.
    pub fn available(&self) -> u32 {
        self.size
            .saturating_sub(self.cached_producer.wrapping_sub(self.cached_consumer))
    }

    /// Reserve one slot; returns the index (not yet committed).
    pub fn produce(&mut self) -> Option<u32> {
        if self.available() == 0 {
            return None;
        }
        let index = self.cached_producer;
        self.cached_producer = self.cached_producer.wrapping_add(1);
        Some(index)
    }

    /// Publish our producer index to the kernel (Release).
    pub fn commit(&mut self) {
        unsafe { (*self.producer).store(self.cached_producer, Ordering::Release) };
    }

    /// Optionally commit, then re-load the kernel's consumer index.
    pub fn sync(&mut self, commit: bool) {
        if commit {
            self.commit();
        }
        self.cached_consumer = unsafe { (*self.consumer).load(Ordering::Acquire) };
    }

    /// Ring capacity.
    pub fn size(&self) -> u32 {
        self.size
    }
}

/// mmap'd ring (munmap'd on drop).
pub struct RingMmap<T> {
    pub mmap: *const u8,
    pub mmap_len: usize,
    pub producer: *mut AtomicU32,
    pub consumer: *mut AtomicU32,
    pub desc: *mut T,
    pub flags: *mut AtomicU32,
}

// Safety: only the owning thread accesses the mmap'd memory; the kernel is
// the only other concurrent reader/writer and uses the producer/consumer
// AtomicU32s for synchronisation.
unsafe impl<T> Send for RingMmap<T> {}

impl<T> Drop for RingMmap<T> {
    fn drop(&mut self) {
        // Safety: `mmap` is what `mmap_ring` returned; `mmap_len` is the
        // exact size we passed to `mmap`.
        unsafe { munmap(self.mmap as *mut _, self.mmap_len) };
    }
}

/// `mmap` an AF_XDP ring. `ring_type` is `XDP_PGOFF_*_RING`; `offsets`
/// from `getsockopt(XDP_MMAP_OFFSETS)`. `size = ring_capacity * sizeof::<T>()`.
///
/// # Safety
/// `fd` must be a sized AF_XDP socket; `offsets` must come from the same fd.
pub unsafe fn mmap_ring<T>(
    fd: i32,
    size: usize,
    offsets: &xdp_ring_offset,
    ring_type: u64,
) -> io::Result<RingMmap<T>> {
    // Cover producer, consumer, flags, and the full desc array. Current
    // kernels place flags before desc but the layout is not contractually
    // guaranteed; max() over all four keeps the mapping correct if it changes.
    let u32_sz = std::mem::size_of::<AtomicU32>();
    let map_size = [
        (offsets.producer as usize).saturating_add(u32_sz),
        (offsets.consumer as usize).saturating_add(u32_sz),
        (offsets.flags as usize).saturating_add(u32_sz),
        (offsets.desc as usize).saturating_add(size),
    ]
    .into_iter()
    .max()
    .unwrap();
    let map_addr = unsafe {
        libc::mmap(
            ptr::null_mut(),
            map_size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED | libc::MAP_POPULATE,
            fd,
            ring_type as i64,
        )
    };
    if ptr::eq(map_addr, libc::MAP_FAILED) {
        return Err(io::Error::last_os_error());
    }

    // Safety: the offsets are kernel-supplied and bounded by `map_size`.
    let producer = unsafe { map_addr.add(offsets.producer as usize) as *mut AtomicU32 };
    let consumer = unsafe { map_addr.add(offsets.consumer as usize) as *mut AtomicU32 };
    let desc = unsafe { map_addr.add(offsets.desc as usize) as *mut T };
    let flags = unsafe { map_addr.add(offsets.flags as usize) as *mut AtomicU32 };

    Ok(RingMmap {
        mmap: map_addr as *const u8,
        mmap_len: map_size,
        producer,
        consumer,
        desc,
        flags,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ring_producer_basic() {
        let mut producer = AtomicU32::new(0);
        let mut consumer = AtomicU32::new(0);
        let size = 16;
        let mut ring = RingProducer::new(&mut producer, &mut consumer, size);
        assert_eq!(ring.available(), size);

        for i in 0..size {
            assert_eq!(ring.produce(), Some(i));
            assert_eq!(ring.available(), size - i - 1);
        }
        assert_eq!(ring.produce(), None);

        // Kernel consumes one slot -- we don't see it until sync().
        consumer.store(1, Ordering::Release);
        assert_eq!(ring.produce(), None);
        ring.commit();
        assert_eq!(ring.produce(), None);
        ring.sync(true);
        assert_eq!(ring.produce(), Some(16));
        assert_eq!(ring.produce(), None);

        consumer.store(2, Ordering::Release);
        ring.sync(true);
        assert_eq!(ring.produce(), Some(17));
    }

    #[test]
    fn ring_producer_wrap_around() {
        let size = 16;
        let mut producer = AtomicU32::new(u32::MAX - 1);
        let mut consumer = AtomicU32::new(u32::MAX - size - 1);
        let mut ring = RingProducer::new(&mut producer, &mut consumer, size);
        assert_eq!(ring.available(), 0);

        consumer.fetch_add(1, Ordering::Release);
        ring.sync(true);
        assert_eq!(ring.produce(), Some(u32::MAX - 1));

        consumer.fetch_add(1, Ordering::Release);
        ring.sync(true);
        assert_eq!(ring.produce(), Some(u32::MAX));

        consumer.fetch_add(1, Ordering::Release);
        ring.sync(true);
        assert_eq!(ring.produce(), Some(0));

        consumer.fetch_add(1, Ordering::Release);
        ring.sync(true);
        assert_eq!(ring.produce(), Some(1));
    }

    #[test]
    fn ring_consumer_basic() {
        let mut producer = AtomicU32::new(0);
        let mut consumer = AtomicU32::new(0);
        let size = 16;
        let mut ring = RingConsumer::new(&mut producer, &mut consumer);
        assert_eq!(ring.available(), 0);

        producer.store(1, Ordering::Release);
        assert_eq!(ring.available(), 0);
        ring.sync(true);
        assert_eq!(ring.available(), 1);

        producer.store(size, Ordering::Release);
        ring.sync(true);

        for i in 0..size {
            assert_eq!(ring.consume(), Some(i));
            assert_eq!(ring.available(), size - i - 1);
        }
        assert_eq!(ring.consume(), None);
    }

    #[test]
    fn ring_consumer_wrap_around() {
        let mut producer = AtomicU32::new(u32::MAX - 1);
        let mut consumer = AtomicU32::new(u32::MAX - 1);
        let mut ring = RingConsumer::new(&mut producer, &mut consumer);
        assert_eq!(ring.available(), 0);
        assert_eq!(ring.consume(), None);

        producer.fetch_add(1, Ordering::Release);
        ring.sync(true);
        assert_eq!(ring.consume(), Some(u32::MAX - 1));

        producer.store(0, Ordering::Release);
        ring.sync(true);
        assert_eq!(ring.available(), 1);
        assert_eq!(ring.consume(), Some(u32::MAX));

        producer.fetch_add(1, Ordering::Release);
        ring.sync(true);
        assert_eq!(ring.consume(), Some(0));

        producer.fetch_add(1, Ordering::Release);
        ring.sync(true);
        assert_eq!(ring.consume(), Some(1));
    }
}
