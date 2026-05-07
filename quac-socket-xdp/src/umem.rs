//! UMEM: page-aligned memory the kernel and userspace share via AF_XDP.
//!
//! Adapted from `xdp/src/umem.rs`. Trimmed to a single concrete `Umem` type
//! (the prototype's generic `Umem` / `Frame` traits were over-engineered for
//! our use — we always own the backing memory and the per-frame "filled
//! length" lives in the buffer wrappers, not in a frame descriptor).

#![allow(clippy::arithmetic_side_effects)]

use std::ffi::c_void;
use std::io;
use std::ops::{Deref, DerefMut};
use std::ptr;
use std::slice;

use libc::{_SC_PAGESIZE, munmap, sysconf};

/// Failure to `mmap` the UMEM region. The kernel returns `MAP_FAILED` on
/// errors like missing huge-page reservations — fall back to small pages
/// and retry.
#[derive(Debug)]
pub struct AllocError;

impl std::fmt::Display for AllocError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "mmap failed (UMEM allocation)")
    }
}

impl std::error::Error for AllocError {}

/// Anonymous page-aligned region created with `mmap(MAP_PRIVATE|MAP_ANONYMOUS
/// [|MAP_HUGETLB])`. Released via `munmap` on drop.
pub struct PageAlignedMemory {
    ptr: *mut u8,
    len: usize,
}

// Safety: `PageAlignedMemory` instances must only be resident on one thread
// at a time (the owning network-tile thread). The raw pointer is otherwise
// stable for the lifetime of the allocation.
unsafe impl Send for PageAlignedMemory {}

impl PageAlignedMemory {
    /// Allocate `frame_size * frame_count` bytes aligned to the system page
    /// size. Both arguments must be powers of two.
    pub fn alloc(frame_size: usize, frame_count: usize) -> Result<Self, AllocError> {
        // Safety: `sysconf` is a thread-safe libc query.
        let page_size = unsafe { sysconf(_SC_PAGESIZE) as usize };
        Self::alloc_with_page_size(frame_size, frame_count, page_size, false)
    }

    /// Allocate with an explicit page size, optionally requesting transparent
    /// huge pages (`MAP_HUGETLB`). The caller is responsible for ensuring the
    /// kernel has 2MB huge pages reserved (`/proc/sys/vm/nr_hugepages`) when
    /// `huge` is true; on failure the returned `AllocError` indicates the
    /// caller should retry with `huge=false`.
    pub fn alloc_with_page_size(
        frame_size: usize,
        frame_count: usize,
        page_size: usize,
        huge: bool,
    ) -> Result<Self, AllocError> {
        debug_assert!(frame_size.is_power_of_two());
        debug_assert!(frame_count.is_power_of_two());
        debug_assert!(page_size.is_power_of_two());

        let memory_size = frame_count * frame_size;
        let aligned_size = (memory_size + page_size - 1) & !(page_size - 1);

        // Safety: anonymous mmap; addr=NULL ⇒ kernel chooses; fd ignored.
        let ptr = unsafe {
            libc::mmap(
                ptr::null_mut(),
                aligned_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | if huge { libc::MAP_HUGETLB } else { 0 },
                -1,
                0,
            )
        };

        if std::ptr::eq(ptr, libc::MAP_FAILED) {
            return Err(AllocError);
        }

        // MAP_ANONYMOUS pages are kernel-zeroed but we explicitly clear in
        // case the libc returned recycled memory (some glibc versions do).
        unsafe {
            ptr::write_bytes(ptr as *mut u8, 0, aligned_size);
        }

        Ok(Self {
            ptr: ptr as *mut u8,
            len: aligned_size,
        })
    }
}

impl Drop for PageAlignedMemory {
    fn drop(&mut self) {
        // Safety: `ptr` is the value mmap returned; `len` is what we passed.
        unsafe { munmap(self.ptr as *mut c_void, self.len) };
    }
}

impl Deref for PageAlignedMemory {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        // Safety: ptr is valid for `len` bytes for the lifetime of `self`.
        unsafe { slice::from_raw_parts(self.ptr, self.len) }
    }
}

impl DerefMut for PageAlignedMemory {
    fn deref_mut(&mut self) -> &mut [u8] {
        unsafe { slice::from_raw_parts_mut(self.ptr, self.len) }
    }
}

/// UMEM region carved into fixed-size frames. The XDP socket registers it
/// with `XDP_UMEM_REG`; the kernel and userspace share it for zero-copy DMA.
///
/// Frame allocation is **not** done here — buffer pools (`XdpRxPool` /
/// `XdpTxPool`) maintain their own free lists of frame addresses so the hot
/// path doesn't touch `Umem` state.
pub struct Umem {
    backing: PageAlignedMemory,
    frame_size: u32,
    frame_count: u32,
}

impl Umem {
    /// Try to allocate a UMEM with `frame_count` frames of `frame_size` each.
    /// Attempts huge pages first; falls back to regular pages on failure.
    pub fn new(frame_size: u32, frame_count: u32) -> io::Result<Self> {
        debug_assert!(frame_size.is_power_of_two());
        debug_assert!(frame_count.is_power_of_two());

        let backing = PageAlignedMemory::alloc_with_page_size(
            frame_size as usize,
            frame_count as usize,
            HUGE_PAGE_SIZE,
            true,
        )
        .or_else(|_| PageAlignedMemory::alloc(frame_size as usize, frame_count as usize))
        .map_err(|e| io::Error::other(e.to_string()))?;

        Ok(Self { backing, frame_size, frame_count })
    }

    /// Pointer to the start of the UMEM. Stable for the lifetime of `self`.
    /// Used by `XDP_UMEM_REG` setsockopt and to resolve frame addresses.
    pub fn as_ptr(&self) -> *const u8 {
        self.backing.as_ptr()
    }

    /// Mutable pointer to the start of the UMEM. Required for `XDP_UMEM_REG`
    /// even though we mostly read; the socket holds it as `*mut`.
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.backing.as_mut_ptr()
    }

    /// Total UMEM size in bytes (`frame_size * frame_count`, page-aligned).
    pub fn len(&self) -> usize {
        self.backing.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn frame_size(&self) -> u32 {
        self.frame_size
    }

    pub fn frame_count(&self) -> u32 {
        self.frame_count
    }

    /// Byte offset of frame `index` in the UMEM. The XDP descriptor `addr`
    /// field uses these offsets directly.
    #[inline]
    pub fn frame_offset(&self, index: u32) -> u64 {
        debug_assert!(index < self.frame_count);
        u64::from(index) * u64::from(self.frame_size)
    }

    /// Borrow the bytes of frame `index` as an immutable slice.
    #[inline]
    pub fn frame(&self, index: u32) -> &[u8] {
        let start = (index as usize) * (self.frame_size as usize);
        &self.backing[start..start + self.frame_size as usize]
    }

    /// Borrow the bytes of frame `index` as a mutable slice.
    #[inline]
    pub fn frame_mut(&mut self, index: u32) -> &mut [u8] {
        let start = (index as usize) * (self.frame_size as usize);
        &mut self.backing[start..start + self.frame_size as usize]
    }

    /// Slice the UMEM by raw byte offset (as the kernel reports in RX
    /// descriptors). Bounds-checked in debug; UB if `addr + len` overflows
    /// the UMEM.
    #[inline]
    pub fn slice_at(&self, addr: u64, len: usize) -> &[u8] {
        let start = addr as usize;
        debug_assert!(start + len <= self.len());
        &self.backing[start..start + len]
    }
}

/// Default 2 MiB huge-page size on x86_64 Linux. Used as a hint for the
/// initial UMEM allocation attempt; falls back to normal page size.
const HUGE_PAGE_SIZE: usize = 2 * 1024 * 1024;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn umem_layout() {
        let frame_size = 2048u32;
        let frame_count = 16u32;
        let umem = Umem::new(frame_size, frame_count).expect("UMEM alloc");

        assert_eq!(umem.frame_size(), frame_size);
        assert_eq!(umem.frame_count(), frame_count);
        assert!(umem.len() >= (frame_size * frame_count) as usize);

        // Frame offsets are contiguous and span exactly frame_size each.
        for i in 0..frame_count {
            assert_eq!(umem.frame_offset(i), u64::from(i) * u64::from(frame_size));
            assert_eq!(umem.frame(i).len(), frame_size as usize);
        }
    }

    #[test]
    fn umem_writeable_frame_round_trips() {
        let mut umem = Umem::new(2048, 8).expect("UMEM alloc");
        // Write a sentinel into frame 3.
        let buf = umem.frame_mut(3);
        for (i, b) in buf.iter_mut().enumerate() {
            *b = (i & 0xff) as u8;
        }
        // Read it back via slice_at using the kernel-style offset.
        let addr = umem.frame_offset(3);
        let view = umem.slice_at(addr, 2048);
        for (i, b) in view.iter().enumerate() {
            assert_eq!(*b, (i & 0xff) as u8);
        }
    }
}
