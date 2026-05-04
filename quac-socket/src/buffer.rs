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
    pub segments: SmallVec<[Segment<B>; 4]>,
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

impl<B> ScatterGather<B> {
    /// Total payload length across all segments.
    #[inline]
    pub fn total_len(&self) -> usize {
        self.segments.iter().map(|s| s.len as usize).sum()
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

/// A pool of fixed-size packet buffers shared across one or more
/// [`PacketSocket`](crate::socket::PacketSocket) instances (e.g. a DPDK mempool
/// backing several TX/RX queues on the same port, or an AF_XDP UMEM backing
/// multiple sockets on the same NIC).
///
/// `Send + Sync`: the pool may be referenced from any thread simultaneously.
pub trait BufferPool: Send + Sync + 'static {
    type Buf: PacketBuf;
    type BufMut: PacketBufMut<Frozen = Self::Buf>;

    /// Append up to `count` mutable buffers of `capacity` bytes each to `bufs`.
    ///
    /// Returns the number appended; never clears or shortens `bufs`. Returns 0
    /// when the pool is exhausted. `count == 0` is a no-op.
    fn alloc(&self, capacity: usize, count: usize, bufs: &mut Vec<Self::BufMut>) -> usize;

    /// Payload size, in bytes, below which copying into a single contiguous
    /// buffer is faster than building a scatter-gather descriptor list.
    /// Hardware-dependent; callers use this to decide whether to coalesce or
    /// scatter-gather.
    fn zerocopy_threshold(&self) -> usize;
}
