use std::mem::MaybeUninit;

use smallvec::SmallVec;

/// Immutable handle to a pool-owned packet buffer. Drop returns it to the pool.
pub trait PacketBuf: AsRef<[u8]> + Send + 'static {}

/// Mutable buffer split into a filled prefix `[0..len)` and uninitialized
/// spare `[len..capacity)`. Extend the prefix by writing into
/// [`uninit_mut`](Self::uninit_mut) then calling [`set_filled`](Self::set_filled);
/// transition to an immutable [`PacketBuf`] via [`freeze`](Self::freeze).
pub trait PacketBufMut: Send + 'static {
    type Frozen: PacketBuf;

    fn capacity(&self) -> usize;
    fn filled(&self) -> &[u8];
    fn filled_mut(&mut self) -> &mut [u8];
    fn uninit_mut(&mut self) -> &mut [MaybeUninit<u8>];

    /// Mark `[0..new_len)` as initialized.
    ///
    /// # Safety
    /// `new_len <= capacity()` and bytes in `[0..new_len)` are initialized.
    unsafe fn set_filled(&mut self, new_len: usize);

    /// Convert to an immutable buffer carrying the currently filled bytes.
    fn freeze(self) -> Self::Frozen;
}

/// One contiguous piece of a scatter-gather packet. Private fields preserve
/// the `offset + len ≤ buf.len()` invariant so [`as_slice`] elides bounds
/// checks.
pub struct Segment<B> {
    buf: B,
    offset: u32,
    len: u32,
}

impl<B> Segment<B> {
    /// Construct without bounds checking.
    ///
    /// # Safety
    /// `offset + len` must not exceed the bytes readable from `buf` for its
    /// lifetime -- `buf.as_ref().len()` for `AsRef<[u8]>` types or
    /// `buf.filled().len()` for a pre-freeze [`PacketBufMut`].
    #[inline]
    pub unsafe fn new_unchecked(buf: B, offset: u32, len: u32) -> Self {
        Self { buf, offset, len }
    }

    #[inline]
    pub fn buf(&self) -> &B {
        &self.buf
    }

    #[inline]
    pub fn offset(&self) -> u32 {
        self.offset
    }

    #[inline]
    pub fn len(&self) -> u32 {
        self.len
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl<B: AsRef<[u8]>> Segment<B> {
    /// Construct a segment; `None` if `offset + len` exceeds `buf` length.
    #[inline]
    pub fn new(buf: B, offset: u32, len: u32) -> Option<Self> {
        let end = (offset as usize).checked_add(len as usize)?;
        if end > buf.as_ref().len() {
            return None;
        }
        Some(Self { buf, offset, len })
    }

    /// The bytes referenced by this segment.
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        let bytes = self.buf.as_ref();
        let start = self.offset as usize;
        let end = start + self.len as usize;
        // Safety: invariant maintained by all constructors.
        unsafe { bytes.get_unchecked(start..end) }
    }
}

impl<B> std::fmt::Debug for Segment<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Segment")
            .field("offset", &self.offset)
            .field("len", &self.len)
            .finish_non_exhaustive()
    }
}

/// Ordered segments forming one logical packet (up to 4 inline; spills to heap).
pub struct ScatterGather<B> {
    segments: SmallVec<[Segment<B>; 4]>,
}

impl<B> ScatterGather<B> {
    #[inline]
    pub fn new() -> Self {
        Self {
            segments: SmallVec::new(),
        }
    }

    #[inline]
    pub fn single(seg: Segment<B>) -> Self {
        let mut sg = Self::new();
        sg.segments.push(seg);
        sg
    }

    /// Append unconditionally. Use [`try_push`] at backend boundaries to
    /// enforce per-transmit segment limits.
    #[inline]
    pub fn push(&mut self, seg: Segment<B>) {
        self.segments.push(seg);
    }

    #[inline]
    pub fn segments(&self) -> &[Segment<B>] {
        &self.segments
    }

    #[inline]
    pub fn total_len(&self) -> usize {
        self.segments.iter().map(|s| s.len as usize).sum()
    }

    /// Append if `len < max`; otherwise return the rejected segment.
    /// Pass `S::MAX_SEGMENTS` at the backend boundary to enforce the limit
    /// without panicking on caller violations.
    #[inline]
    pub fn try_push(&mut self, seg: Segment<B>, max: usize) -> Result<(), Segment<B>> {
        if self.segments.len() >= max {
            return Err(seg);
        }
        self.segments.push(seg);
        Ok(())
    }
}

impl<B> Default for ScatterGather<B> {
    fn default() -> Self {
        Self::new()
    }
}

impl<B: AsRef<[u8]>> ScatterGather<B> {
    /// Contiguous slice when the list has exactly one segment.
    #[inline]
    pub fn as_contiguous(&self) -> Option<&[u8]> {
        match self.segments.as_slice() {
            [s] => Some(s.as_slice()),
            _ => None,
        }
    }
}

impl<B: PacketBufMut> ScatterGather<B> {
    /// Freeze every segment's buffer.
    pub fn freeze(self) -> ScatterGather<B::Frozen> {
        ScatterGather {
            segments: self
                .segments
                .into_iter()
                .map(|s| {
                    // Safety: source satisfied `offset + len <= buf.filled().len()`;
                    // the frozen buffer's `as_ref()` is exactly those filled bytes.
                    unsafe { Segment::new_unchecked(s.buf.freeze(), s.offset, s.len) }
                })
                .collect(),
        }
    }
}

impl<B> std::fmt::Debug for ScatterGather<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScatterGather")
            .field("segments", &self.segments)
            .finish()
    }
}

/// Receive-side buffer pool. Owned exclusively by the network tile thread;
/// `alloc` is owner-thread-only. Not `Send` or `Sync`.
pub trait RxPool: 'static {
    type Buf: PacketBuf;
    type BufMut: PacketBufMut<Frozen = Self::Buf>;

    /// Maximum UDP payload these buffers can carry.
    fn max_payload_size(&self) -> usize;

    /// Append up to `count` buffers to `bufs`. Never clears `bufs`. Returns
    /// the count appended (0 when the pool is exhausted).
    fn alloc(&self, capacity: usize, count: usize, bufs: &mut Vec<Self::BufMut>) -> usize;
}

/// Transmit-side buffer pool. Owned exclusively by the network tile thread;
/// `alloc` is owner-thread-only. `RxBufMut` is the Rx type this pool can
/// promote via [`from_rx`].
pub trait TxPool: 'static {
    type Buf: PacketBuf;
    type BufMut: PacketBufMut<Frozen = Self::Buf>;
    type RxBufMut;

    /// `true` when Rx and Tx share the same buffer type (zero-copy identity);
    /// `false` when conversion needs a copy into fresh Tx memory.
    const UNIFIED: bool;

    fn max_payload_size(&self) -> usize;

    /// Append up to `count` buffers to `bufs`. Never clears `bufs`. Returns
    /// the count appended (0 when exhausted).
    fn alloc(&self, capacity: usize, count: usize, bufs: &mut Vec<Self::BufMut>) -> usize;

    /// Buffers available without growing. Default `usize::MAX` (unbounded);
    /// unified backends override to cap pre-alloc so Rx isn't starved.
    fn available(&self) -> usize {
        usize::MAX
    }

    /// Payload size below which copying into one buffer beats scatter-gather.
    fn zerocopy_threshold(&self) -> usize;

    /// Promote an Rx buffer to a Tx buffer.
    /// - `UNIFIED=true`: identity (no copy).
    /// - `UNIFIED=false`: alloc + copy filled bytes; `Err(rx)` if exhausted.
    ///
    /// Owner-thread only for separate backends; thread-safe for unified.
    #[allow(clippy::wrong_self_convention)]
    fn from_rx(&self, rx: Self::RxBufMut) -> Result<Self::BufMut, Self::RxBufMut>;

    /// Identity conversion for `UNIFIED=true` backends; callable from any
    /// thread. Panics by default; unified pools override.
    fn from_rx_unified(rx: Self::RxBufMut) -> Self::BufMut {
        let _ = rx;
        panic!("from_rx_unified called on non-unified backend");
    }

    /// `true` if `buf` belongs to (or is otherwise sendable via) this
    /// pool. Default `true` — heap-backed pools (OS, io_uring) are
    /// fungible across siblings, so any pool can send any sibling's
    /// buf. AF_XDP overrides to compare UMEM bases: each socket's TX
    /// ring can only egress frames that live in its own UMEM.
    fn owns(&self, buf: &Self::Buf) -> bool {
        let _ = buf;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn segment_new_bounds() {
        let buf: Vec<u8> = vec![0u8; 10];

        // exact fit at end
        assert!(Segment::new(buf.as_slice(), 0, 10).is_some());
        assert!(Segment::new(buf.as_slice(), 5, 5).is_some());
        assert!(Segment::new(buf.as_slice(), 10, 0).is_some()); // empty at end
        assert!(Segment::new(buf.as_slice(), 0, 0).is_some()); // empty at start

        // overflows
        assert!(Segment::new(buf.as_slice(), 0, 11).is_none());
        assert!(Segment::new(buf.as_slice(), 5, 6).is_none());
        assert!(Segment::new(buf.as_slice(), 11, 0).is_none()); // offset > len
                                                                // u32 wraparound is rejected by checked_add
        assert!(Segment::new(buf.as_slice(), u32::MAX, 1).is_none());
    }

    #[test]
    fn scatter_gather_helpers() {
        // Empty
        let empty: ScatterGather<&[u8]> = ScatterGather::new();
        assert_eq!(empty.total_len(), 0);
        assert!(empty.as_contiguous().is_none());

        // Single segment → as_contiguous returns the slice.
        let one = b"abcdef";
        let sg1 = ScatterGather::single(Segment::new(&one[..], 1, 4).unwrap());
        assert_eq!(sg1.total_len(), 4);
        assert_eq!(sg1.as_contiguous(), Some(&b"bcde"[..]));

        // Multi-segment → as_contiguous is None even if buffers happen to be adjacent.
        let a = b"AB";
        let b = b"CDEF";
        let mut sg_n: ScatterGather<&[u8]> = ScatterGather::new();
        sg_n.push(Segment::new(&a[..], 0, 2).unwrap());
        sg_n.push(Segment::new(&b[..], 0, 4).unwrap());
        assert_eq!(sg_n.total_len(), 6);
        assert!(sg_n.as_contiguous().is_none());
    }
}
