use std::mem::MaybeUninit;

use smallvec::SmallVec;

/// An immutable handle to a packet buffer owned by a [`BufferPool`].
/// Dropping the handle returns the buffer to the pool.
pub trait PacketBuf: AsRef<[u8]> + Send + 'static {}

/// A mutable handle used to fill an outgoing packet or inspect a received one.
///
/// The buffer is split into an initialized **filled** prefix `[0..len)` and an
/// uninitialized **spare** suffix `[len..capacity)`. Reads always go through
/// [`filled`](Self::filled); writes go either through [`filled_mut`](Self::filled_mut)
/// (overwriting the existing prefix) or [`uninit_mut`](Self::uninit_mut) followed
/// by [`set_filled`](Self::set_filled) (extending it).
///
/// Call [`freeze`](Self::freeze) to transition to an immutable [`PacketBuf`]
/// ready for transmission. The frozen buffer's bytes are exactly the filled
/// prefix at the time of the call.
pub trait PacketBufMut: Send + 'static {
    type Frozen: PacketBuf;

    /// Total backing storage in bytes. Independent of how much is currently filled.
    fn capacity(&self) -> usize;

    /// Initialized bytes `[0..len)` of this buffer.
    fn filled(&self) -> &[u8];

    /// Mutable view of the initialized bytes `[0..len)`.
    fn filled_mut(&mut self) -> &mut [u8];

    /// Mutable view of the uninitialized spare capacity `[len..capacity)`.
    fn uninit_mut(&mut self) -> &mut [MaybeUninit<u8>];

    /// Mark `[0..new_len)` as initialized.
    ///
    /// # Safety
    /// - `new_len <= capacity()`.
    /// - All bytes in `[0..new_len)` must have been initialized (e.g. via writes
    ///   into the slice returned by [`uninit_mut`](Self::uninit_mut)).
    unsafe fn set_filled(&mut self, new_len: usize);

    /// Convert into an immutable buffer carrying the currently filled bytes.
    fn freeze(self) -> Self::Frozen;
}

/// One contiguous piece of a scatter-gather packet.
///
/// Fields are private; constructors maintain the invariant
/// `offset as usize + len as usize <= buf.as_ref().len()` (or, when constructed
/// over an unfilled [`PacketBufMut`], the equivalent against `buf.filled().len()`),
/// allowing [`as_slice`](Segment::as_slice) to elide bounds checks.
pub struct Segment<B> {
    buf: B,
    offset: u32,
    len: u32,
}

impl<B> Segment<B> {
    /// Construct without bounds checking.
    ///
    /// # Safety
    /// `offset as usize + len as usize` must not exceed the length of bytes
    /// readable from `buf` (and that remains true for the buffer's lifetime).
    /// For `B: AsRef<[u8]>` that means `<= buf.as_ref().len()`. For a
    /// [`PacketBufMut`] used pre-freeze, that means `<= buf.filled().len()`.
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
    /// Construct a segment, returning `None` if `offset + len` would exceed `buf`'s length.
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

/// A logical packet described as an ordered list of segments. The NIC's DMA
/// engine gathers the segments without an intermediate copy.
///
/// Up to 4 segments fit inline; longer chains spill to the heap.
pub struct ScatterGather<B> {
    segments: SmallVec<[Segment<B>; 4]>,
}

impl<B> ScatterGather<B> {
    /// Construct an empty list.
    #[inline]
    pub fn new() -> Self {
        Self { segments: SmallVec::new() }
    }

    /// Construct a single-segment list.
    #[inline]
    pub fn single(seg: Segment<B>) -> Self {
        let mut sg = Self::new();
        sg.segments.push(seg);
        sg
    }

    /// Append a segment unconditionally.
    ///
    /// Use [`try_push`](Self::try_push) at the backend boundary when you need
    /// to enforce a per-transmit segment limit.
    #[inline]
    pub fn push(&mut self, seg: Segment<B>) {
        self.segments.push(seg);
    }

    /// Read access to the segment list.
    #[inline]
    pub fn segments(&self) -> &[Segment<B>] {
        &self.segments
    }

    /// Total payload length across all segments.
    #[inline]
    pub fn total_len(&self) -> usize {
        self.segments.iter().map(|s| s.len as usize).sum()
    }

    /// Append `seg` if `self.segments.len() < max`, otherwise return it as `Err`.
    ///
    /// Use `max = S::MAX_SEGMENTS` at the backend boundary to enforce the
    /// per-transmit segment limit without panicking on caller violations.
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
    /// Returns a contiguous slice if the list has exactly one segment.
    #[inline]
    pub fn as_contiguous(&self) -> Option<&[u8]> {
        match self.segments.as_slice() {
            [s] => Some(s.as_slice()),
            _ => None,
        }
    }
}

impl<B: PacketBufMut> ScatterGather<B> {
    /// Freeze every segment's buffer, producing a sendable [`ScatterGather`].
    pub fn freeze(self) -> ScatterGather<B::Frozen> {
        ScatterGather {
            segments: self
                .segments
                .into_iter()
                .map(|s| {
                    // Safety: the source segment satisfied
                    // `offset + len <= buf.filled().len()`, and `freeze`
                    // produces a buffer whose `as_ref()` is exactly those
                    // filled bytes, so the invariant holds for the frozen
                    // buffer too.
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

/// Pool for receive-side packet buffers.
///
/// Exclusively owned by the network tile thread; only that thread calls
/// [`alloc`](Self::alloc). Not `Send` or `Sync`.
pub trait RxPool: 'static {
    type Buf: PacketBuf;
    type BufMut: PacketBufMut<Frozen = Self::Buf>;

    /// Maximum UDP payload, in bytes, that this pool's buffers can carry.
    fn max_payload_size(&self) -> usize;

    /// Append up to `count` mutable receive buffers to `bufs`. Returns the
    /// number appended; never clears `bufs`. Returns 0 when exhausted.
    fn alloc(&self, capacity: usize, count: usize, bufs: &mut Vec<Self::BufMut>) -> usize;
}

/// Pool for transmit-side packet buffers.
///
/// Exclusively owned by the network tile thread; only that thread calls
/// [`alloc`](Self::alloc). Not `Send` or `Sync`.
///
/// The associated `RxBufMut` type is the receive buffer type this pool can
/// promote to a transmit buffer via [`from_rx`](Self::from_rx).
pub trait TxPool: 'static {
    type Buf: PacketBuf;
    type BufMut: PacketBufMut<Frozen = Self::Buf>;
    /// The Rx buffer type this pool can promote to a Tx buffer.
    type RxBufMut;

    /// `true` when Rx and Tx share the same buffer type and conversion is a
    /// zero-cost identity. `false` when conversion requires a copy into fresh
    /// Tx memory (e.g. io_uring provided-buffer ring → heap).
    const UNIFIED: bool;

    fn max_payload_size(&self) -> usize;

    /// Append up to `count` mutable transmit buffers to `bufs`. Returns the
    /// number appended; never clears `bufs`. Returns 0 when exhausted.
    fn alloc(&self, capacity: usize, count: usize, bufs: &mut Vec<Self::BufMut>) -> usize;

    /// Payload size, in bytes, below which copying into a single contiguous
    /// buffer is faster than building a scatter-gather descriptor list.
    fn zerocopy_threshold(&self) -> usize;

    /// Promote a received buffer into a Tx buffer suitable for `send`.
    ///
    /// - `UNIFIED=true`: returns `Ok(rx)` (identity, no copy; `&self` unused).
    /// - `UNIFIED=false`: calls `self.alloc()` internally, copies `rx`'s filled
    ///   bytes into the new Tx buffer, drops `rx` (releasing any backend-side
    ///   resource), and returns `Ok(tx)`. Returns `Err(rx)` if the pool is
    ///   exhausted, giving the caller the buffer back.
    ///
    /// **Owner-thread only** for separate backends (alloc uses `UnsafeCell`).
    /// Thread-safe for unified backends (stateless identity).
    fn from_rx(&self, rx: Self::RxBufMut) -> Result<Self::BufMut, Self::RxBufMut>;

    /// Identity conversion for unified backends (`UNIFIED=true`).
    ///
    /// Callable from any thread without a pool reference. The default
    /// implementation panics; each unified pool overrides it.
    fn from_rx_unified(rx: Self::RxBufMut) -> Self::BufMut {
        let _ = rx;
        panic!("from_rx_unified called on non-unified backend");
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
