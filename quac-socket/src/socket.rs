use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

#[cfg(unix)]
use std::os::fd::RawFd;

use crate::buffer::{BufferPool, ScatterGather};

/// Explicit Congestion Notification codepoint carried in the IP header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcnCodepoint {
    Ect0,
    Ect1,
    Ce,
}

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

    /// Shared handle to the buffer pool backing this socket's packet memory.
    fn pool(&self) -> Arc<Self::Pool>;

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
    /// Each buffer is mutable: the caller may inspect or modify it, then call
    /// [`ScatterGather::freeze`] to obtain a sendable buffer.
    fn recv(
        &mut self,
        meta: &mut [RecvMeta],
        bufs: &mut Vec<ScatterGather<<Self::Pool as BufferPool>::BufMut>>,
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
