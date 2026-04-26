use smallvec::SmallVec;

/// An immutable handle to a packet buffer owned by a [`BufferPool`].
/// Dropping the handle returns the buffer to the pool.
pub trait PacketBuf: AsRef<[u8]> + Send + 'static {}

/// A mutable handle used to fill an outgoing packet or inspect a received one.
/// Call [`freeze`](PacketBufMut::freeze) to transition to an immutable [`PacketBuf`] ready for transmission.
pub trait PacketBufMut: AsRef<[u8]> + AsMut<[u8]> + Send + 'static {
    type Frozen: PacketBuf;
    fn freeze(self) -> Self::Frozen;
}

/// One contiguous piece of a scatter-gather packet.
pub struct Segment<B> {
    pub buf: B,
    pub offset: usize,
    pub len: usize,
}

/// A logical packet described as an ordered list of segments. The NIC's DMA
/// engine gathers the segments without an intermediate copy.
///
/// Up to 4 segments fit inline; longer chains spill to the heap.
pub struct ScatterGather<B> {
    pub segments: SmallVec<[Segment<B>; 4]>,
}

impl<B: AsRef<[u8]>> ScatterGather<B> {
    /// Returns a contiguous slice if the list has exactly one segment covering
    /// its entire buffer. This is the common case for received UDP datagrams.
    pub fn as_contiguous(&self) -> Option<&[u8]> {
        if self.segments.len() == 1 {
            let s = &self.segments[0];
            Some(&s.buf.as_ref()[s.offset..s.offset + s.len])
        } else {
            None
        }
    }

    /// Total payload length across all segments.
    pub fn total_len(&self) -> usize {
        self.segments.iter().map(|s| s.len).sum()
    }
}

impl<B: PacketBufMut> ScatterGather<B> {
    /// Freeze every segment's buffer, producing a sendable [`ScatterGather`].
    pub fn freeze(self) -> ScatterGather<B::Frozen> {
        ScatterGather {
            segments: self.segments.into_iter().map(|s| Segment {
                buf: s.buf.freeze(),
                offset: s.offset,
                len: s.len,
            }).collect(),
        }
    }
}

/// A pool of fixed-size packet buffers shared across one or more [`PacketSocket`]
/// instances (e.g. a DPDK mempool backing several TX/RX queues on the same port,
/// or an AF_XDP UMEM backing multiple sockets on the same NIC).
///
/// `Send + Sync`: the pool may be referenced from any thread simultaneously.
pub trait BufferPool: Send + Sync + 'static {
    type Buf: PacketBuf;
    type BufMut: PacketBufMut<Frozen = Self::Buf>;

    /// Allocate a batch of mutable buffers of at most `capacity` bytes each.
    /// Pushes up to `count` into `bufs` and returns how many were allocated.
    /// Returns 0 when the pool is exhausted.
    fn alloc(&self, capacity: usize, count: usize, bufs: &mut Vec<Self::BufMut>) -> usize;

    /// Payload size below which copying into a single contiguous buffer is
    /// faster than building a scatter-gather descriptor list. Hardware-dependent;
    /// callers use this to decide whether to coalesce or scatter-gather.
    fn zerocopy_threshold(&self) -> usize;
}
