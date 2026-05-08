//! UMEM: page-aligned memory shared with the kernel via AF_XDP.

#![allow(clippy::arithmetic_side_effects)]

use std::ffi::c_void;
use std::io;
use std::ops::{Deref, DerefMut};
use std::ptr;
use std::slice;

use libc::{_SC_PAGESIZE, munmap, sysconf};

/// `mmap` failed (e.g. no huge-page reservation). Caller may retry with
/// regular pages.
#[derive(Debug)]
pub struct AllocError;

impl std::fmt::Display for AllocError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "mmap failed (UMEM allocation)")
    }
}

impl std::error::Error for AllocError {}

/// Page-aligned anonymous mmap (munmap'd on drop).
pub struct PageAlignedMemory {
    ptr: *mut u8,
    len: usize,
}

// Safety: only resident on one thread at a time (the network-tile thread).
unsafe impl Send for PageAlignedMemory {}

impl PageAlignedMemory {
    /// Allocate `frame_size * frame_count` bytes (both must be powers of 2).
    pub fn alloc(frame_size: usize, frame_count: usize) -> Result<Self, AllocError> {
        // Safety: sysconf is thread-safe.
        let page_size = unsafe { sysconf(_SC_PAGESIZE) as usize };
        Self::alloc_with_page_size(frame_size, frame_count, page_size, false)
    }

    /// Allocate with an explicit page size, optionally requesting `MAP_HUGETLB`.
    /// On failure caller may retry with `huge=false`.
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

        // Explicitly zero in case libc returned recycled memory.
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

/// UMEM region carved into fixed-size frames; registered via `XDP_UMEM_REG`
/// for kernel/userspace zero-copy DMA. Frame allocation lives in the buffer
/// pools, not here.
pub struct Umem {
    backing: PageAlignedMemory,
    frame_size: u32,
    frame_count: u32,
}

impl Umem {
    /// Allocate `frame_count` frames of `frame_size`. Tries huge pages first.
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

    /// Base pointer (stable for `self`'s lifetime).
    pub fn as_ptr(&self) -> *const u8 {
        self.backing.as_ptr()
    }

    /// Mutable base pointer (required by `XDP_UMEM_REG`).
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.backing.as_mut_ptr()
    }

    /// Total UMEM size in bytes (page-aligned).
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

    /// Frame byte offset (used directly as the XDP descriptor `addr` field).
    #[inline]
    pub fn frame_offset(&self, index: u32) -> u64 {
        debug_assert!(index < self.frame_count);
        u64::from(index) * u64::from(self.frame_size)
    }

    /// Frame bytes (immutable).
    #[inline]
    pub fn frame(&self, index: u32) -> &[u8] {
        let start = (index as usize) * (self.frame_size as usize);
        &self.backing[start..start + self.frame_size as usize]
    }

    /// Frame bytes (mutable).
    #[inline]
    pub fn frame_mut(&mut self, index: u32) -> &mut [u8] {
        let start = (index as usize) * (self.frame_size as usize);
        &mut self.backing[start..start + self.frame_size as usize]
    }

    /// Slice by raw byte offset (as kernel reports in RX descriptors).
    /// Bounds-checked in debug; UB on overflow.
    #[inline]
    pub fn slice_at(&self, addr: u64, len: usize) -> &[u8] {
        let start = addr as usize;
        debug_assert!(start + len <= self.len());
        &self.backing[start..start + len]
    }
}

/// 2 MiB; the x86_64 Linux huge-page default.
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
