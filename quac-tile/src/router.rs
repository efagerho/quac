use std::sync::atomic::{AtomicUsize, Ordering};

use quac_network_tile::PacketRouter;
use quac_socket::RecvMeta;

/// CID length used by the QUIC-LB generator (1 + 4 server-id + 4 nonce bytes).
pub const CID_LEN: usize = 9;

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

/// Routes QUIC packets to engine tiles.
///
/// Initial packets (new connections) are distributed round-robin across engine
/// tiles. All other packets carry a server-assigned DCID whose first byte
/// encodes the owning engine index — see `TileIndexCidGenerator`. Routing by
/// `dcid[0] % engine_count` sends them back to the correct engine without any
/// shared lookup table.
pub struct QuicPacketRouter {
    next_engine: AtomicUsize,
}

impl QuicPacketRouter {
    pub fn new() -> Self {
        Self { next_engine: AtomicUsize::new(0) }
    }
}

impl Default for QuicPacketRouter {
    fn default() -> Self {
        Self::new()
    }
}

impl PacketRouter for QuicPacketRouter {
    fn route(&self, _meta: &RecvMeta, payload: &[u8], engine_count: usize) -> usize {
        if engine_count == 1 || payload.is_empty() {
            return 0;
        }
        let is_long    = payload[0] & 0x80 != 0;
        let is_initial = is_long && (payload[0] & 0x30) == 0x00;
        if is_initial {
            self.next_engine.fetch_add(1, Ordering::Relaxed) % engine_count
        } else if let Some(dcid) = extract_dcid(payload) {
            dcid[0] as usize % engine_count
        } else {
            0
        }
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
}
