use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;

#[cfg(unix)]
use std::os::fd::BorrowedFd;

use crate::buffer::{BufferPool, ScatterGather};

/// Explicit Congestion Notification codepoint carried in the IP header.
///
/// Discriminants match the on-wire ECN bits, so encoding is `self as u8` and
/// decoding via [`from_bits`](EcnCodepoint::from_bits) is a small bounded
/// table. The non-ECT codepoint (`0b00`) is represented as `None` in
/// `Option<EcnCodepoint>`, which fits in 1 byte via niche optimization.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcnCodepoint {
    Ect1 = 0b01,
    Ect0 = 0b10,
    Ce = 0b11,
}

impl EcnCodepoint {
    /// Decode from the 2-bit ECN field of an IP header. `0b00` (non-ECT)
    /// returns `None`.
    #[inline]
    pub const fn from_bits(bits: u8) -> Option<Self> {
        match bits & 0b11 {
            0b01 => Some(Self::Ect1),
            0b10 => Some(Self::Ect0),
            0b11 => Some(Self::Ce),
            _ => None,
        }
    }

    /// Encode to the 2-bit ECN field of an IP header.
    #[inline]
    pub const fn bits(self) -> u8 {
        self as u8
    }
}

/// Metadata associated with a single received UDP datagram.
///
/// Backends fill these fields after writing the payload into the matching
/// buffer slot. Callers seed the slice via [`RecvMeta::default`] before
/// passing it to [`PacketSocket::recv`].
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct RecvMeta {
    pub src: SocketAddr,
    pub dst_ip: Option<IpAddr>,
    pub ecn: Option<EcnCodepoint>,
    /// Total length of the datagram payload in bytes.
    pub len: u16,
    /// GRO segment stride: distance between consecutive datagrams within a
    /// single batch entry, in bytes. Equal to `len` when GRO is not in use.
    pub stride: u16,
}

impl Default for RecvMeta {
    #[inline]
    fn default() -> Self {
        Self {
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
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct Transmit<T> {
    pub contents: T,
    pub destination: SocketAddr,
    pub src_ip: Option<IpAddr>,
    /// GSO segment size in bytes; `0` means "single datagram, no segmentation".
    pub segment_size: u16,
    pub ecn: Option<EcnCodepoint>,
}

impl<T> Transmit<T> {
    /// Construct a basic transmit with no GSO, no ECN, and no source-IP override.
    #[inline]
    pub fn new(contents: T, destination: SocketAddr) -> Self {
        Self {
            contents,
            destination,
            src_ip: None,
            segment_size: 0,
            ecn: None,
        }
    }
}

/// A low-level, runtime-agnostic packet socket bound to one hardware RX/TX
/// queue.
///
/// `Send` but not `Sync`: TX/RX queues have single-threaded ownership
/// invariants (DPDK queue, AF_XDP ring head/tail pointers). `&mut self` on
/// [`send`](PacketSocket::send) and [`recv`](PacketSocket::recv) expresses
/// this without internal locking.
///
/// All operations are **non-blocking**. They return immediately with whatever
/// they could complete; the caller is responsible for readiness polling via
/// [`rx_fd`](PacketSocket::rx_fd) or a busy-poll loop.
pub trait PacketSocket: Send + 'static {
    type Pool: BufferPool;

    /// Maximum number of segments per GSO transmit call. Defaults to 1 (no GSO).
    const MAX_GSO: u16 = 1;
    /// Maximum number of GRO segments returned in a single `recv` call.
    /// Defaults to 1 (no GRO).
    const MAX_GRO: u16 = 1;
    /// Maximum number of scatter-gather segments per [`Transmit`].
    ///
    /// Callers must ensure `transmit.contents.segments.len() <= Self::MAX_SEGMENTS`
    /// before passing the transmit to [`send`](PacketSocket::send); implementations
    /// panic on violation rather than silently truncating.
    ///
    /// Backends with fixed inline-iovec arrays (io_uring) typically expose a much
    /// smaller value than the kernel's `IOV_MAX` (1024 on Linux). Defaults to 1
    /// (no scatter-gather).
    const MAX_SEGMENTS: usize = 1;

    /// Shared handle to the buffer pool backing this socket's packet memory.
    /// Returns a borrow to avoid an atomic refcount bump on the hot path;
    /// callers who need ownership clone explicitly.
    fn pool(&self) -> &Arc<Self::Pool>;

    /// Submit a batch of outgoing packets. Non-blocking.
    ///
    /// Drains the accepted prefix from `transmits` (taking ownership of the
    /// accepted entries; zerocopy backends hold them until
    /// [`drain_completions`](PacketSocket::drain_completions) recycles them).
    /// Returns the count accepted; rejected entries remain at the front of
    /// `transmits` for the caller to retry, drop, or log.
    ///
    /// `Err` is reserved for hard I/O failures; partial acceptance is `Ok(n)`.
    fn send(
        &mut self,
        transmits: &mut Vec<Transmit<ScatterGather<<Self::Pool as BufferPool>::Buf>>>,
    ) -> io::Result<usize>;

    /// Drain completed zerocopy sends and drop the corresponding buffers.
    /// Must be called regularly to prevent in-flight buffer accumulation.
    /// A no-op for copy-based backends (plain OS sockets, test socket).
    fn drain_completions(&mut self);

    /// Receive a batch of packets into caller-supplied metadata and buffer slots.
    /// Non-blocking; returns `Ok(0)` immediately when no packets are available.
    /// `Err` is reserved for hard I/O failures.
    ///
    /// The effective batch capacity is `min(meta.len(), bufs.len())`. The impl
    /// writes into `meta[..n]` and `bufs[..n]`; the remainder is left
    /// untouched. Each buffer slot is a [`PacketBufMut`](crate::buffer::PacketBufMut)
    /// pre-allocated by the caller from `pool().alloc(...)`; the impl writes
    /// the received bytes into it via `filled_mut`/`uninit_mut` + `set_filled`.
    fn recv(
        &mut self,
        meta: &mut [RecvMeta],
        bufs: &mut [<Self::Pool as BufferPool>::BufMut],
    ) -> io::Result<usize>;

    /// Address this socket is bound to.
    fn local_addr(&self) -> io::Result<SocketAddr>;

    /// Index of the hardware RX queue this socket is bound to. The engine
    /// encodes this value in the connection ID prefix of every new server-side
    /// connection so that subsequent packets are steered back to this queue.
    fn queue_id(&self) -> u16;

    /// Borrowed file descriptor that becomes readable when packets are available.
    /// Returns `None` for polling-only backends (e.g. DPDK) where the caller
    /// must busy-poll by calling [`recv`](PacketSocket::recv) in a tight loop.
    #[cfg(unix)]
    fn rx_fd(&self) -> Option<BorrowedFd<'_>> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ecn_codepoint_round_trip() {
        // 0b00 → None (non-ECT); 01/10/11 → Ect1/Ect0/Ce.
        assert_eq!(EcnCodepoint::from_bits(0b00), None);
        assert_eq!(EcnCodepoint::from_bits(0b01), Some(EcnCodepoint::Ect1));
        assert_eq!(EcnCodepoint::from_bits(0b10), Some(EcnCodepoint::Ect0));
        assert_eq!(EcnCodepoint::from_bits(0b11), Some(EcnCodepoint::Ce));
        // High bits are masked off.
        assert_eq!(EcnCodepoint::from_bits(0xFE), Some(EcnCodepoint::Ect0));

        // bits() then from_bits() is identity for the three encoded variants.
        for v in [EcnCodepoint::Ect0, EcnCodepoint::Ect1, EcnCodepoint::Ce] {
            assert_eq!(EcnCodepoint::from_bits(v.bits()), Some(v));
        }
    }

    #[test]
    fn recv_meta_default() {
        let m = RecvMeta::default();
        assert_eq!(m.src.port(), 0);
        assert!(m.src.ip().is_unspecified());
        assert!(m.src.is_ipv4());
        assert!(m.dst_ip.is_none());
        assert!(m.ecn.is_none());
        assert_eq!(m.len, 0);
        assert_eq!(m.stride, 0);
    }
}
