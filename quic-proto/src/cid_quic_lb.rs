//! RFC 9386–style connection IDs for QUIC load balancing / local queue steering.
//!
//! Initial profile: fixed total length, plaintext 4-byte server ID carrying `queue_id`
//! (big-endian), first octet uses 3-bit config rotation `0` and 5 random bits, nonce fills remainder.

use std::sync::Arc;

use rand::{Rng, RngCore};

use crate::cid_generator::{ConnectionIdGenerator, InvalidCid};
use crate::shared::ConnectionId;
use crate::{Duration, MAX_CID_SIZE};

/// Three most significant bits of the first CID octet (must not be `0b111`).
const CONFIG_ROTATION: u8 = 0;

/// Server ID field size in octets (stores full `queue_id` in big-endian).
const SERVER_ID_LEN: usize = 4;

/// A connection ID generator embedding a `queue_id` in the server-id field for steering.
#[derive(Debug, Clone)]
pub struct QuicLbConnectionIdGenerator {
    queue_id: u32,
    cid_len: usize,
}

impl QuicLbConnectionIdGenerator {
    /// Create a generator. `cid_len` must satisfy `1 + SERVER_ID_LEN + 4 <= cid_len <= MAX_CID_SIZE`.
    pub fn new(queue_id: u32, cid_len: usize) -> Self {
        assert!(cid_len <= MAX_CID_SIZE);
        assert!(
            cid_len >= 1 + SERVER_ID_LEN + 4,
            "cid_len must fit first octet + server_id + nonce (>=4)"
        );
        Self { queue_id, cid_len }
    }

    fn nonce_len(&self) -> usize {
        self.cid_len - 1 - SERVER_ID_LEN
    }
}

impl ConnectionIdGenerator for QuicLbConnectionIdGenerator {
    fn generate_cid(&mut self) -> ConnectionId {
        debug_assert!(self.nonce_len() >= 4);
        let mut buf = [0u8; MAX_CID_SIZE];
        let mut rng = rand::rng();
        let lower = rng.random::<u8>() & 0x1F;
        buf[0] = (CONFIG_ROTATION << 5) | lower;
        buf[1..1 + SERVER_ID_LEN].copy_from_slice(&self.queue_id.to_be_bytes());
        rng.fill_bytes(&mut buf[1 + SERVER_ID_LEN..self.cid_len]);
        ConnectionId::new(&buf[..self.cid_len])
    }

    fn validate(&self, cid: ConnectionId) -> Result<(), InvalidCid> {
        if cid.len() != self.cid_len {
            return Err(InvalidCid);
        }
        let s: &[u8] = &cid;
        if s[0] >> 5 != CONFIG_ROTATION {
            return Err(InvalidCid);
        }
        if s[1..1 + SERVER_ID_LEN] != self.queue_id.to_be_bytes() {
            return Err(InvalidCid);
        }
        Ok(())
    }

    fn cid_len(&self) -> usize {
        self.cid_len
    }

    fn cid_lifetime(&self) -> Option<Duration> {
        None
    }
}

/// Decode `queue_id` from a CID produced by [`QuicLbConnectionIdGenerator`].
pub fn decode_queue_id_quic_lb(cid: &[u8]) -> Option<u32> {
    if cid.len() < 1 + SERVER_ID_LEN {
        return None;
    }
    if cid[0] >> 5 != CONFIG_ROTATION {
        return None;
    }
    Some(u32::from_be_bytes([
        cid[1],
        cid[2],
        cid[3],
        cid[4],
    ]))
}

/// Factory suitable for [`crate::EndpointConfig::cid_generator`](crate::EndpointConfig::cid_generator).
pub fn quic_lb_cid_generator_factory(
    queue_id: u32,
    cid_len: usize,
) -> Arc<dyn Fn() -> Box<dyn ConnectionIdGenerator> + Send + Sync> {
    Arc::new(move || Box::new(QuicLbConnectionIdGenerator::new(queue_id, cid_len)))
}
