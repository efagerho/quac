use std::io;
use std::sync::{Arc, Mutex};
use std::thread;

use crossbeam_queue::ArrayQueue;

use quac_socket::{BufferPool, PacketBufMut, PacketSocket, RecvMeta, ScatterGather, Transmit};

/// Number of slots in each queue between a network tile and an engine tile.
pub const QUEUE_CAP: usize = 1024;

/// CID length used by the QUIC-LB generator (1 + 4 server-id + 4 nonce bytes).
pub const CID_LEN: usize = 9;

/// A datagram received from the network, queued for delivery to an engine tile.
pub struct RxPacket<B: PacketBufMut> {
    pub meta: RecvMeta,
    pub payload: ScatterGather<B>,
}

/// An I/O component bound to one `SO_REUSEPORT` socket and connected to N
/// engine tiles via lock-free queues.
pub trait NetworkTile: Send + Sync + 'static {
    type Pool: BufferPool;

    fn pool(&self) -> Arc<Self::Pool>;
    fn rx_queues(&self) -> &[Arc<ArrayQueue<RxPacket<<Self::Pool as BufferPool>::BufMut>>>];
    fn tx_queues(
        &self,
    ) -> &[Arc<ArrayQueue<Transmit<ScatterGather<<Self::Pool as BufferPool>::Buf>>>>];
    fn start(self: Arc<Self>);
}

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

/// Whether the tile uses one shared thread for Rx+Tx or dedicated threads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreadMode {
    /// One thread handles both receive and transmit.
    Combined,
    /// Separate reader and writer threads.
    Separate,
}

pub struct NetworkTileImpl<S: PacketSocket> {
    pool: Arc<S::Pool>,
    thread_mode: ThreadMode,
    /// Sockets taken out once in `start()`. `None` after `start()`.
    sockets: Mutex<Option<(S, Option<S>)>>,
    rx_queues: Vec<Arc<ArrayQueue<RxPacket<<S::Pool as BufferPool>::BufMut>>>>,
    tx_queues: Vec<Arc<ArrayQueue<Transmit<ScatterGather<<S::Pool as BufferPool>::Buf>>>>>,
}

impl<S: PacketSocket> NetworkTileImpl<S> {
    /// Create a tile that drives both Rx and Tx on a single thread.
    pub fn combined(socket: S, engine_count: usize) -> Self {
        assert!(engine_count > 0);
        let pool = socket.pool();
        Self::build(pool, ThreadMode::Combined, socket, None, engine_count)
    }

    /// Create a tile with dedicated reader and writer threads.
    /// `rx` and `tx` must be clones of the same underlying socket (e.g. via `try_clone`).
    pub fn separate(rx: S, tx: S, engine_count: usize) -> Self {
        assert!(engine_count > 0);
        let pool = rx.pool();
        Self::build(pool, ThreadMode::Separate, rx, Some(tx), engine_count)
    }

    fn build(
        pool: Arc<S::Pool>,
        thread_mode: ThreadMode,
        rx_socket: S,
        tx_socket: Option<S>,
        engine_count: usize,
    ) -> Self {
        let rx_queues = (0..engine_count)
            .map(|_| Arc::new(ArrayQueue::new(QUEUE_CAP)))
            .collect();
        let tx_queues = (0..engine_count)
            .map(|_| Arc::new(ArrayQueue::new(QUEUE_CAP)))
            .collect();
        Self {
            pool,
            thread_mode,
            sockets: Mutex::new(Some((rx_socket, tx_socket))),
            rx_queues,
            tx_queues,
        }
    }
}

impl<S: PacketSocket> NetworkTile for NetworkTileImpl<S> {
    type Pool = S::Pool;

    fn pool(&self) -> Arc<S::Pool> {
        Arc::clone(&self.pool)
    }

    fn rx_queues(&self) -> &[Arc<ArrayQueue<RxPacket<<S::Pool as BufferPool>::BufMut>>>] {
        &self.rx_queues
    }

    fn tx_queues(
        &self,
    ) -> &[Arc<ArrayQueue<Transmit<ScatterGather<<S::Pool as BufferPool>::Buf>>>>] {
        &self.tx_queues
    }

    fn start(self: Arc<Self>) {
        let (rx_socket, tx_socket_opt) = self
            .sockets
            .lock()
            .unwrap()
            .take()
            .expect("NetworkTileImpl::start called more than once");

        match self.thread_mode {
            ThreadMode::Combined => {
                thread::Builder::new()
                    .name("net-io".into())
                    .spawn(move || run_combined(self, rx_socket))
                    .expect("spawn net-io");
            }
            ThreadMode::Separate => {
                let tx_socket = tx_socket_opt.expect("separate mode requires two sockets");
                let reader_tile = Arc::clone(&self);
                thread::Builder::new()
                    .name("net-rx".into())
                    .spawn(move || run_reader(reader_tile, rx_socket))
                    .expect("spawn net-rx");
                thread::Builder::new()
                    .name("net-tx".into())
                    .spawn(move || run_writer(self, tx_socket))
                    .expect("spawn net-tx");
            }
        }
    }
}

fn push_rx<S: PacketSocket>(
    tile: &NetworkTileImpl<S>,
    meta: RecvMeta,
    payload: ScatterGather<<S::Pool as BufferPool>::BufMut>,
) {
    let idx = route(&meta, tile.rx_queues.len());
    let _ = tile.rx_queues[idx].push(RxPacket { meta, payload });
}

fn drain_tx<S: PacketSocket>(
    tile: &NetworkTileImpl<S>,
) -> Vec<Transmit<ScatterGather<<S::Pool as BufferPool>::Buf>>> {
    let mut transmits = Vec::new();
    for queue in &tile.tx_queues {
        while let Some(t) = queue.pop() {
            transmits.push(t);
        }
    }
    transmits
}

fn run_combined<S: PacketSocket>(tile: Arc<NetworkTileImpl<S>>, mut socket: S) {
    let mut meta = vec![RecvMeta::default(); 64];
    let mut bufs: Vec<ScatterGather<<S::Pool as BufferPool>::BufMut>> = Vec::new();

    loop {
        let mut did_work = false;

        match socket.recv(&mut meta, &mut bufs) {
            Ok(n) if n > 0 => {
                did_work = true;
                for (i, payload) in bufs.drain(..n).enumerate() {
                    push_rx(&tile, meta[i].clone(), payload);
                }
            }
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => {
                eprintln!("[net-io] recv: {e}");
                break;
            }
        }

        let transmits = drain_tx(&tile);
        if !transmits.is_empty() {
            did_work = true;
            socket.send(transmits);
            socket.drain_completions();
        }

        if !did_work {
            std::hint::spin_loop();
        }
    }
}

fn run_reader<S: PacketSocket>(tile: Arc<NetworkTileImpl<S>>, mut socket: S) {
    let mut meta = vec![RecvMeta::default(); 64];
    let mut bufs: Vec<ScatterGather<<S::Pool as BufferPool>::BufMut>> = Vec::new();

    loop {
        match socket.recv(&mut meta, &mut bufs) {
            Ok(n) if n > 0 => {
                for (i, payload) in bufs.drain(..n).enumerate() {
                    push_rx(&tile, meta[i].clone(), payload);
                }
            }
            Ok(_) => { std::hint::spin_loop(); }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => { std::hint::spin_loop(); }
            Err(e) => { eprintln!("[net-rx] recv: {e}"); break; }
        }
    }
}

fn run_writer<S: PacketSocket>(tile: Arc<NetworkTileImpl<S>>, mut socket: S) {
    loop {
        let transmits = drain_tx(&tile);
        if transmits.is_empty() {
            std::hint::spin_loop();
            continue;
        }
        socket.send(transmits);
        socket.drain_completions();
    }
}

fn route(meta: &RecvMeta, engine_count: usize) -> usize {
    if engine_count == 1 {
        return 0;
    }
    meta.src.port() as usize % engine_count
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
