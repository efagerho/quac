//! OS-socket-backed [`NetworkTile`]: one reader thread and one writer thread,
//! connected to N engine tiles via lock-free SPSC queues.

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::thread::Thread;
use std::time::Duration;

use bytes::BytesMut;
use crossbeam_queue::ArrayQueue;
use smallvec::smallvec;

use quac_interface::{PacketSocket, RecvMeta, ScatterGather, Segment, Transmit};
use quac_socket::{OsBuf, OsSocket};
use quac_tile::{NetworkTile, RxPacket, TxPacket, extract_dcid};
use quic_proto::decode_queue_id_quic_lb;

/// OS-socket network tile: one reader, one writer, bound to the same UDP port via `SO_REUSEPORT`.
pub struct OsNetworkTile {
    addr: SocketAddr,
    /// One queue per engine tile; reader pushes, engine drains.
    rx_queues: Vec<Arc<ArrayQueue<RxPacket>>>,
    /// Engine tile tx queues assigned to this writer.
    tx_queues: Vec<Arc<ArrayQueue<TxPacket>>>,
    num_engine_tiles: usize,
    /// Parking state for each engine tile (indexed same as rx_queues).
    engine_is_parked: Vec<Arc<AtomicBool>>,
    /// Thread handles for unparking engine tiles on new RX data.
    engine_threads: Vec<Arc<OnceLock<Thread>>>,
}

impl OsNetworkTile {
    /// Create a new network tile.
    ///
    /// `rx_queues` has one entry per engine tile (reader pushes into these).
    /// `tx_queues` has one entry per engine tile assigned to this writer.
    /// `engine_is_parked` and `engine_threads` are the corresponding engine wake state,
    /// in the same order as `rx_queues`.
    pub fn new(
        addr: SocketAddr,
        rx_queues: Vec<Arc<ArrayQueue<RxPacket>>>,
        tx_queues: Vec<Arc<ArrayQueue<TxPacket>>>,
        engine_is_parked: Vec<Arc<AtomicBool>>,
        engine_threads: Vec<Arc<OnceLock<Thread>>>,
    ) -> Arc<Self> {
        let num_engine_tiles = rx_queues.len();
        Arc::new(Self {
            addr,
            rx_queues,
            tx_queues,
            num_engine_tiles,
            engine_is_parked,
            engine_threads,
        })
    }
}

impl NetworkTile for OsNetworkTile {
    fn rx_queues(&self) -> &[Arc<ArrayQueue<RxPacket>>] {
        &self.rx_queues
    }

    fn tx_queues(&self) -> &[Arc<ArrayQueue<TxPacket>>] {
        &self.tx_queues
    }

    fn start(self: Arc<Self>) {
        let socket = match OsSocket::bind_reuseport(self.addr) {
            Ok(s) => s,
            Err(e) => {
                log::error!("[os_tile] bind_reuseport({}): {e}", self.addr);
                return;
            }
        };
        let writer_socket = match socket.try_clone() {
            Ok(s) => s,
            Err(e) => {
                log::error!("[os_tile] try_clone: {e}");
                return;
            }
        };
        let reader = Arc::clone(&self);
        let writer = Arc::clone(&self);
        std::thread::spawn(move || run_reader(reader, socket));
        std::thread::spawn(move || run_writer(writer, writer_socket));
    }
}

// ── Reader thread ─────────────────────────────────────────────────────────────

fn run_reader(tile: Arc<OsNetworkTile>, mut socket: OsSocket) {
    const BATCH: usize = 64;
    let mut meta = vec![RecvMeta::default(); BATCH];
    let mut bufs: Vec<ScatterGather<BytesMut>> = Vec::new();

    loop {
        match socket.recv(&mut meta, &mut bufs) {
            Ok(n) => {
                for i in 0..n {
                    let m = &meta[i];
                    let sg = bufs.remove(0);
                    let payload = match sg.as_contiguous() {
                        Some(slice) => BytesMut::from(slice),
                        None => {
                            let mut tmp = BytesMut::with_capacity(sg.total_len());
                            for seg in &sg.segments {
                                tmp.extend_from_slice(
                                    &seg.buf.as_ref()[seg.offset..seg.offset + seg.len],
                                );
                            }
                            tmp
                        }
                    };
                    let tile_idx = route_packet(&payload, tile.num_engine_tiles);
                    let pkt = RxPacket { meta: m.clone(), payload };
                    let push_ok = tile.rx_queues[tile_idx].push(pkt).is_ok();
                    if push_ok && tile.engine_is_parked[tile_idx].load(Ordering::Acquire) {
                        if let Some(t) = tile.engine_threads[tile_idx].get() {
                            t.unpark();
                        }
                    }
                }
                bufs.clear();
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_micros(100));
            }
            Err(e) => {
                log::error!("[os_tile reader] recv error: {e}");
                break;
            }
        }
    }
}

/// Choose engine tile index for an incoming datagram.
fn route_packet(payload: &[u8], num_engine_tiles: usize) -> usize {
    if let Some(dcid) = extract_dcid(payload) {
        if let Some(queue_id) = decode_queue_id_quic_lb(dcid) {
            return (queue_id as usize) % num_engine_tiles;
        }
    }
    fastrand::usize(0..num_engine_tiles)
}

// ── Writer thread ─────────────────────────────────────────────────────────────

fn run_writer(tile: Arc<OsNetworkTile>, mut socket: OsSocket) {
    loop {
        let mut sent_any = false;
        for queue in &tile.tx_queues {
            while let Some(pkt) = queue.pop() {
                sent_any = true;
                let len = pkt.payload.len();
                let buf = OsBuf::from_slice(&pkt.payload);
                let transmits = vec![Transmit {
                    destination: pkt.destination,
                    ecn: pkt.ecn,
                    contents: ScatterGather {
                        segments: smallvec![Segment { buf, offset: 0, len }],
                    },
                    segment_size: pkt.segment_size,
                    src_ip: pkt.src_ip,
                }];
                let unsent = socket.send(transmits);
                if !unsent.is_empty() {
                    log::debug!(
                        "[os_tile writer] {} datagram(s) dropped (socket backpressure)",
                        unsent.len()
                    );
                }
            }
        }
        if !sent_any {
            std::thread::sleep(Duration::from_micros(100));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quic_proto::{ConnectionIdGenerator, decode_queue_id_quic_lb, quic_lb_cid_generator_factory};
    use quac_tile::CID_LEN;

    fn gen_cid(queue_id: u32) -> Vec<u8> {
        let factory = quic_lb_cid_generator_factory(queue_id, CID_LEN);
        let mut gen = factory();
        gen.generate_cid().as_ref().to_vec()
    }

    #[test]
    fn route_packet_uses_cid_for_short_header() {
        let cid = gen_cid(3);
        let mut pkt = vec![0x40u8];
        pkt.extend_from_slice(&cid);
        assert_eq!(route_packet(&pkt, 8), 3);
    }

    #[test]
    fn route_packet_uses_cid_for_long_header() {
        let cid = gen_cid(2);
        let mut pkt = vec![0x80u8];
        pkt.extend_from_slice(&[0, 0, 0, 1]);
        pkt.push(cid.len() as u8);
        pkt.extend_from_slice(&cid);
        assert_eq!(route_packet(&pkt, 4), 2);
    }

    #[test]
    fn route_packet_random_for_initial() {
        let random_dcid = [0xFFu8; 9];
        let mut pkt = vec![0x80u8];
        pkt.extend_from_slice(&[0, 0, 0, 1]);
        pkt.push(random_dcid.len() as u8);
        pkt.extend_from_slice(&random_dcid);
        assert!(decode_queue_id_quic_lb(&random_dcid).is_none());
        let idx = route_packet(&pkt, 4);
        assert!(idx < 4);
    }

    #[test]
    fn route_packet_wraps_queue_id_mod_num_tiles() {
        let cid = gen_cid(7);
        let mut pkt = vec![0x40u8];
        pkt.extend_from_slice(&cid);
        assert_eq!(route_packet(&pkt, 4), 3);
    }
}
