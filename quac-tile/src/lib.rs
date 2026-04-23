//! Tile-based QUIC dataplane traits and queue packet types.
//!
//! A [`NetworkTile`] is a pair of I/O threads (reader + writer) bound to one
//! `SO_REUSEPORT` socket. It connects to N engine tiles via bounded lock-free
//! SPSC queues. Implementors live in crates like `quac-network-tile-socket`.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use bytes::{Bytes, BytesMut};
use crossbeam_queue::ArrayQueue;
use quac_interface::{EcnCodepoint, RecvMeta};

/// Number of slots in each SPSC queue between a reader/writer and an engine tile.
pub const QUEUE_CAP: usize = 1024;

/// CID length used by the QUIC-LB generator (1 + 4 server-id + 4 nonce bytes).
pub const CID_LEN: usize = 9;

// ── Packet types ──────────────────────────────────────────────────────────────

/// A datagram received from the network, queued for delivery to an engine tile.
pub struct RxPacket {
    pub meta: RecvMeta,
    pub payload: BytesMut,
}

/// A datagram to be transmitted by a network tile writer.
pub struct TxPacket {
    pub destination: SocketAddr,
    pub ecn: Option<EcnCodepoint>,
    pub payload: Bytes,
    pub segment_size: Option<usize>,
    pub src_ip: Option<IpAddr>,
}

// Safety: BytesMut and Bytes are Send; RecvMeta/EcnCodepoint are plain data.
unsafe impl Send for RxPacket {}
unsafe impl Send for TxPacket {}

// ── NetworkTile trait ─────────────────────────────────────────────────────────

/// A pair of I/O threads (reader + writer) bound to one `SO_REUSEPORT` socket
/// and connected to N engine tiles via lock-free SPSC queues.
///
/// Implementors: `quac-network-tile-socket::OsNetworkTile`.
pub trait NetworkTile: Send + Sync + 'static {
    /// Queues from which the engine tiles drain received packets.
    /// `rx_queues()[j]` is the queue from this network tile's reader to engine tile `j`.
    fn rx_queues(&self) -> &[Arc<ArrayQueue<RxPacket>>];

    /// Queues from which this network tile's writer drains outgoing packets.
    /// Each queue belongs to one engine tile assigned to this writer.
    fn tx_queues(&self) -> &[Arc<ArrayQueue<TxPacket>>];

    /// Spawn the reader and writer threads. Must be called once.
    fn start(self: Arc<Self>);
}

// ── Routing helpers ───────────────────────────────────────────────────────────

/// Extract the DCID bytes from the first datagram of a UDP payload.
///
/// Long-header packets carry an explicit DCIL; short-header packets use the
/// fixed [`CID_LEN`] the server chose at connection setup.
pub fn extract_dcid(payload: &[u8]) -> Option<&[u8]> {
    if payload.is_empty() {
        return None;
    }
    if payload[0] & 0x80 != 0 {
        // Long header: byte[5] = DCIL, DCID = [6..6+DCIL]
        if payload.len() < 6 {
            return None;
        }
        let dcil = payload[5] as usize;
        if payload.len() < 6 + dcil {
            return None;
        }
        Some(&payload[6..6 + dcil])
    } else {
        // Short header: DCID at [1..1+CID_LEN]
        if payload.len() < 1 + CID_LEN {
            return None;
        }
        Some(&payload[1..1 + CID_LEN])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_long_header(dcid: &[u8]) -> Vec<u8> {
        let mut pkt = vec![0x80u8];
        pkt.extend_from_slice(&[0, 0, 0, 1]);
        pkt.push(dcid.len() as u8);
        pkt.extend_from_slice(dcid);
        pkt.extend_from_slice(&[0]);
        pkt
    }

    fn make_short_header(dcid: &[u8; CID_LEN]) -> Vec<u8> {
        let mut pkt = vec![0x40u8];
        pkt.extend_from_slice(dcid);
        pkt
    }

    #[test]
    fn extract_dcid_long_header() {
        let dcid = [1u8, 2, 3, 4, 5, 6, 7, 8, 9];
        let pkt = make_long_header(&dcid);
        assert_eq!(extract_dcid(&pkt), Some(dcid.as_slice()));
    }

    #[test]
    fn extract_dcid_short_header() {
        let dcid = [0u8, 0, 0, 0, 7, 0, 0, 0, 0];
        let pkt = make_short_header(&dcid);
        assert_eq!(extract_dcid(&pkt), Some(dcid.as_slice()));
    }

    #[test]
    fn extract_dcid_too_short() {
        assert_eq!(extract_dcid(&[]), None);
        assert_eq!(extract_dcid(&[0x80, 0, 0]), None);
    }

    #[test]
    fn rx_tx_packet_are_send() {
        fn assert_send<T: Send>() {}
        assert_send::<RxPacket>();
        assert_send::<TxPacket>();
    }
}
