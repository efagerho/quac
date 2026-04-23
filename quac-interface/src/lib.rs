//! Runtime-agnostic packet I/O traits: [`BufferPool`], [`PacketSocket`], and buffer types.
//!
//! This crate is the single source of truth for the abstraction described in the quac book
//! (`book/src/socket.md`). Backends (`quic-socket`, `quic-iouring`, …) implement [`PacketSocket`];
//! The `quic-engine` crate drives QUIC over any [`PacketSocket`].

use std::io;
use std::net::{IpAddr, SocketAddr};

#[cfg(unix)]
use std::os::fd::RawFd;

use smallvec::SmallVec;

// ── ECN ──────────────────────────────────────────────────────────────────────

/// Explicit Congestion Notification codepoint carried in the IP header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcnCodepoint {
    Ect0,
    Ect1,
    Ce,
}

// ── Receive metadata ─────────────────────────────────────────────────────────

/// Metadata associated with a single received UDP datagram.
#[derive(Debug, Clone)]
pub struct RecvMeta {
    pub src: SocketAddr,
    pub dst_ip: Option<IpAddr>,
    pub ecn: Option<EcnCodepoint>,
    /// Total length of the datagram payload in bytes.
    pub len: usize,
    /// GRO segment stride: distance between consecutive datagrams within a
    /// single `recv` batch entry. Equal to `len` when GRO is not in use.
    pub stride: usize,
}

impl Default for RecvMeta {
    fn default() -> Self {
        use std::net::{Ipv4Addr, SocketAddrV4};
        RecvMeta {
            src: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
            dst_ip: None,
            ecn: None,
            len: 0,
            stride: 0,
        }
    }
}

// ── Transmit descriptor ───────────────────────────────────────────────────────

/// A packet to be sent. Generic over the contents type so callers can use
/// either a contiguous buffer or a [`ScatterGather`] list.
#[derive(Debug)]
pub struct Transmit<T> {
    pub destination: SocketAddr,
    pub ecn: Option<EcnCodepoint>,
    pub contents: T,
    /// GSO segment size. `None` means the entire `contents` is one datagram.
    pub segment_size: Option<usize>,
    pub src_ip: Option<IpAddr>,
}

// ── Buffer traits ─────────────────────────────────────────────────────────────

/// An immutable handle to a packet buffer owned by a [`BufferPool`].
/// Dropping the handle returns the buffer to the pool.
pub trait PacketBuf: AsRef<[u8]> + Send + 'static {}

/// A mutable handle used to fill an outgoing packet.
/// Call [`freeze`](PacketBufMut::freeze) to transition to an immutable [`PacketBuf`] ready for transmission.
pub trait PacketBufMut: AsMut<[u8]> + Send + 'static {
    type Frozen: PacketBuf;
    fn freeze(self) -> Self::Frozen;
}

/// Mutable pool buffer for the receive path. Flows through `PartialDecode` → decrypt
/// inside quic-proto. At `process_payload` it is copied once into `BytesMut` then
/// dropped, returning the buffer to the pool (custom `Drop` carries pool-return logic
/// for DPDK mbufs, io_uring fixed buffers, etc.).
pub trait RecvBuf: AsRef<[u8]> + AsMut<[u8]> + Send + 'static {
    fn len(&self) -> usize;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// Return `[..at]`; `self` becomes `[at..]`.
    fn split_to(&mut self, at: usize) -> Self;
    /// Return `[at..]`; `self` becomes `[..at]`.
    fn split_off(&mut self, at: usize) -> Self;
    /// Shrink to the first `len` bytes (used after decrypt to discard the auth tag).
    fn truncate(&mut self, len: usize);
}

// ── Scatter-gather ────────────────────────────────────────────────────────────

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

// ── Buffer pool ───────────────────────────────────────────────────────────────

/// A pool of fixed-size packet buffers shared across one or more [`PacketSocket`]
/// instances (e.g. a DPDK mempool backing several TX/RX queues on the same port,
/// or an AF_XDP UMEM backing multiple sockets on the same NIC).
///
/// `Send + Sync`: the pool may be referenced from any thread simultaneously.
pub trait BufferPool: Send + Sync + 'static {
    type Buf: PacketBuf;
    type BufMut: PacketBufMut<Frozen = Self::Buf>;
    /// Recv-side pool buffer. Flows through parse + decrypt then is dropped at
    /// the assembler boundary in `process_payload`.
    type RecvBuf: RecvBuf;

    /// Allocate a batch of mutable buffers of at most `capacity` bytes each.
    /// Pushes up to `count` into `bufs` and returns how many were allocated.
    /// Returns 0 when the pool is exhausted.
    fn alloc(&self, capacity: usize, count: usize, bufs: &mut Vec<Self::BufMut>) -> usize;

    /// Allocate a batch of recv-side buffers of at most `capacity` bytes each.
    fn alloc_recv(&self, capacity: usize, count: usize, bufs: &mut Vec<Self::RecvBuf>) -> usize;

    /// Payload size below which copying into a single contiguous buffer is
    /// faster than building a scatter-gather descriptor list. Hardware-dependent;
    /// callers use this to decide whether to coalesce or scatter-gather.
    fn zerocopy_threshold(&self) -> usize;
}

// ── Packet socket ─────────────────────────────────────────────────────────────

/// A low-level, runtime-agnostic packet socket bound to one hardware RX/TX
/// queue.
///
/// `Send` but not `Sync`: TX/RX queues have single-threaded ownership
/// invariants (DPDK queue, AF_XDP ring head/tail pointers). `&mut self` on
/// [`send`](PacketSocket::send) and [`recv`](PacketSocket::recv) expresses this without internal locking.
///
/// All operations are **non-blocking**. They return immediately with whatever
/// they could complete; the caller is responsible for readiness polling via
/// [`rx_fd`](PacketSocket::rx_fd) or a busy-poll loop.
pub trait PacketSocket: Send + 'static {
    type Pool: BufferPool;

    /// The buffer pool backing this socket's packet memory.
    fn pool(&self) -> &Self::Pool;

    /// Submit a batch of outgoing packets. Non-blocking.
    ///
    /// Takes ownership of all packets. Accepted packets are held by the socket
    /// until [`drain_completions`](PacketSocket::drain_completions) recycles
    /// them (zerocopy backends) or dropped immediately (copy backends). Returns
    /// the packets that could not be submitted; the caller decides whether to
    /// retry, drop, or log them. On I/O errors the implementation logs
    /// internally and returns all packets as unsent.
    fn send(
        &mut self,
        transmits: Vec<Transmit<ScatterGather<<Self::Pool as BufferPool>::Buf>>>,
    ) -> Vec<Transmit<ScatterGather<<Self::Pool as BufferPool>::Buf>>>;

    /// Drain completed zerocopy sends and drop the corresponding buffers.
    /// Must be called regularly to prevent in-flight buffer accumulation.
    /// A no-op for copy-based backends (plain OS sockets, test socket).
    fn drain_completions(&mut self);

    /// Receive a batch of packets into caller-supplied metadata and buffer slots.
    /// Non-blocking: returns `WouldBlock` immediately when no packets are available.
    ///
    /// Returns the number of datagrams written into `meta[..n]` / `bufs[..n]`.
    /// Buffers are pool-allocated [`RecvBuf`] values that flow through parse +
    /// decrypt and are dropped (pool-returned) at the assembler boundary.
    fn recv(
        &mut self,
        meta: &mut [RecvMeta],
        bufs: &mut Vec<ScatterGather<<Self::Pool as BufferPool>::RecvBuf>>,
    ) -> io::Result<usize>;

    fn local_addr(&self) -> io::Result<SocketAddr>;

    /// Index of the hardware RX queue this socket is bound to. The engine
    /// encodes this value in the connection ID prefix of every new server-side
    /// connection so that subsequent packets are steered back to this queue.
    fn queue_id(&self) -> u32;

    /// File descriptor that becomes readable when packets are available.
    /// Returns `None` for polling-only backends (e.g. DPDK) where the caller
    /// must busy-poll by calling [`recv`](PacketSocket::recv) in a tight loop.
    #[cfg(unix)]
    fn rx_fd(&self) -> Option<RawFd> {
        None
    }

    /// Maximum number of segments per GSO or XDP transmit call.
    fn max_gso_segments(&self) -> usize {
        1
    }

    /// Maximum number of GRO segments returned in a single `recv` call.
    fn max_gro_segments(&self) -> usize {
        1
    }
}

/// Blanket `RecvBuf` implementation for `BytesMut` so quic-proto internals and
/// tests can use `BytesMut` directly where a `RecvBuf` is expected.
impl RecvBuf for bytes::BytesMut {
    fn len(&self) -> usize {
        bytes::BytesMut::len(self)
    }
    fn split_to(&mut self, at: usize) -> Self {
        bytes::BytesMut::split_to(self, at)
    }
    fn split_off(&mut self, at: usize) -> Self {
        bytes::BytesMut::split_off(self, at)
    }
    fn truncate(&mut self, len: usize) {
        bytes::BytesMut::truncate(self, len);
    }
}
