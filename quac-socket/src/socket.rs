use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};

#[cfg(unix)]
use std::os::fd::BorrowedFd;

use crate::buffer::{RxPool, ScatterGather, TxPool};

/// ECN codepoint carried in the IP header. Discriminants match on-wire bits
/// so encoding is `self as u8`. Non-ECT (`0b00`) is `None` in
/// `Option<EcnCodepoint>` (niche-optimized to 1 byte).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcnCodepoint {
    Ect1 = 0b01,
    Ect0 = 0b10,
    Ce = 0b11,
}

impl EcnCodepoint {
    /// Decode from the 2-bit ECN field; `0b00` → `None`.
    #[inline]
    pub const fn from_bits(bits: u8) -> Option<Self> {
        match bits & 0b11 {
            0b01 => Some(Self::Ect1),
            0b10 => Some(Self::Ect0),
            0b11 => Some(Self::Ce),
            _ => None,
        }
    }

    /// Encode to the 2-bit ECN field.
    #[inline]
    pub const fn bits(self) -> u8 {
        self as u8
    }
}

/// Metadata for a received UDP datagram. Backends fill it after writing the
/// payload; callers seed slices via [`RecvMeta::default`] before passing
/// them to [`PacketSocket::recv`].
#[non_exhaustive]
#[derive(Debug, Clone, Copy)]
pub struct RecvMeta {
    pub src: SocketAddr,
    pub dst_ip: Option<IpAddr>,
    pub ecn: Option<EcnCodepoint>,
    /// Total length of the datagram payload in bytes.
    pub len: u16,
}

impl Default for RecvMeta {
    #[inline]
    fn default() -> Self {
        Self {
            src: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
            dst_ip: None,
            ecn: None,
            len: 0,
        }
    }
}

/// A packet to send. Generic over `contents` so the caller can choose
/// contiguous bytes or a [`ScatterGather`].
#[non_exhaustive]
#[derive(Debug)]
pub struct Transmit<T> {
    pub contents: T,
    pub destination: SocketAddr,
    pub src_ip: Option<IpAddr>,
    /// GSO segment size; `0` = single datagram, no segmentation. Must be `0`
    /// if the backend's [`MAX_GSO`](PacketSocket::MAX_GSO) is 1.
    pub segment_size: u16,
    pub ecn: Option<EcnCodepoint>,
}

impl<T> Transmit<T> {
    /// Construct with no GSO, no ECN, no src-IP override.
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

/// Counts returned by [`PacketSocket::drain_completions`]. `#[non_exhaustive]`
/// so future error-class counters don't break downstream crates.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DrainResult {
    pub completed: usize,
    /// `EMSGSIZE` (path MTU exceeded). QUIC stacks should reduce PMTU.
    pub emsgsize: usize,
    /// Failures other than `EMSGSIZE`.
    pub errors: usize,
}

/// Low-level, runtime-agnostic packet socket bound to one hardware RX/TX
/// queue. `!Send` -- owned exclusively by one tile thread; `&mut self` on
/// [`send`] / [`recv`] is the only synchronization. All operations are
/// non-blocking; callers poll readiness via [`rx_fd`] or busy-loop.
pub trait PacketSocket: 'static {
    type RxPool: RxPool;
    type TxPool: TxPool<RxBufMut = <Self::RxPool as RxPool>::BufMut>;

    /// Max GSO datagrams per kernel send. `Transmit::segment_size > 0`
    /// requires `MAX_GSO > 1`; impls panic otherwise. Defaults to 1.
    const MAX_GSO: u16 = 1;
    /// Max GRO segments per [`recv`]. Defaults to 1.
    const MAX_GRO: u16 = 1;
    /// Max scatter-gather segments per [`Transmit`]. Implementations panic
    /// if a transmit exceeds this. Defaults to 1.
    const MAX_SEGMENTS: usize = 1;
    /// Max packets per [`recv`]. Backends never return more, but may return
    /// fewer; partial batches are not an error. Defaults to 64.
    const MAX_BATCH: usize = 64;

    fn rx_pool(&self) -> &Self::RxPool;
    fn tx_pool(&self) -> &Self::TxPool;

    /// Submit outgoing packets. Returns `Ok(n)` accepted; caller discards
    /// the first `n` entries. Zero-copy backends hold accepted packets
    /// until [`drain_completions`] signals kernel completion. `Err` is
    /// reserved for hard I/O failures (partial acceptance is `Ok(n)`).
    fn send(
        &mut self,
        transmits: &mut [Transmit<ScatterGather<<Self::TxPool as TxPool>::Buf>>],
    ) -> io::Result<usize>;

    /// Drain completed zero-copy sends. Copy-based backends always return
    /// `DrainResult::default()`. Call regularly to prevent in-flight
    /// accumulation.
    fn drain_completions(&mut self) -> DrainResult;

    /// Receive into caller-supplied slots. Returns `Ok(n)` with `meta[..n]`
    /// and `bufs[..n]` filled; the remainder is untouched. Slots must be
    /// pre-allocated via `rx_pool().alloc(...)`.
    fn recv(
        &mut self,
        meta: &mut [RecvMeta],
        bufs: &mut [<Self::RxPool as RxPool>::BufMut],
    ) -> io::Result<usize>;

    fn local_addr(&self) -> io::Result<SocketAddr>;

    /// Hardware RX queue index. The engine encodes this in connection-ID
    /// prefixes so subsequent packets steer back to this queue.
    fn queue_id(&self) -> u16;

    /// FD that becomes readable when packets are available. `None` for
    /// polling-only backends (e.g. DPDK).
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
    }
}
