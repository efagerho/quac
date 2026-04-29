use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use crossbeam_queue::ArrayQueue;
use quac_socket::{BufferPool, PacketBufMut, PacketSocket, RecvMeta, ScatterGather, Transmit};

const TX_BUF_QUEUE_CAP: usize = 1024;
const TX_BUF_REFILL_WATERMARK: usize = 256;
const TX_BUF_REFILL_BATCH: usize = 64;
const MAX_DATAGRAM: usize = 65535;
/// Pre-fill size for pooled TX buffers. Sized for standard Ethernet MTU; packets
/// larger than this (e.g. GSO batches or jumbo frames) cause a resize-on-demand.
const TX_BUF_SIZE: usize = 2048;

mod queue;
pub use queue::{Park, Queue, Spin, WaitStrategy, wait_any_non_empty, wait_any_non_empty_combined};

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
    type Wait: WaitStrategy;

    /// Pop up to `count` TX buffers sized to `capacity` bytes from the tile's
    /// pre-filled buffer queue. Safe to call from any thread; the queue is
    /// replenished exclusively by the Rx thread via `pool.alloc()`.
    fn alloc_tx_bufs(
        &self,
        capacity: usize,
        count: usize,
        bufs: &mut Vec<<Self::Pool as BufferPool>::BufMut>,
    ) -> usize;
    fn rx_queues(
        &self,
    ) -> &[Arc<Queue<RxPacket<<Self::Pool as BufferPool>::BufMut>, Self::Wait>>];
    fn tx_queues(
        &self,
    ) -> &[Arc<Queue<Transmit<ScatterGather<<Self::Pool as BufferPool>::Buf>>, Self::Wait>>];
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

pub struct NetworkTileImpl<S: PacketSocket, W: WaitStrategy> {
    pool: Arc<S::Pool>,
    thread_mode: ThreadMode,
    /// Sockets taken out once in `start()`. `None` after `start()`.
    sockets: Mutex<Option<(S, Option<S>)>>,
    rx_queues: Vec<Arc<Queue<RxPacket<<S::Pool as BufferPool>::BufMut>, W>>>,
    tx_queues: Vec<Arc<Queue<Transmit<ScatterGather<<S::Pool as BufferPool>::Buf>>, W>>>,
    tx_buf_queue: Arc<ArrayQueue<<S::Pool as BufferPool>::BufMut>>,
    /// Round-robin counter for distributing new (Initial) connections across engine tiles.
    next_engine: AtomicUsize,
}

impl<S: PacketSocket, W: WaitStrategy> NetworkTileImpl<S, W> {
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
        let rx_queues = (0..engine_count).map(|_| Queue::<_, W>::new(QUEUE_CAP)).collect();
        let tx_queues = (0..engine_count).map(|_| Queue::<_, W>::new(QUEUE_CAP)).collect();
        Self {
            pool,
            thread_mode,
            sockets: Mutex::new(Some((rx_socket, tx_socket))),
            rx_queues,
            tx_queues,
            tx_buf_queue: Arc::new(ArrayQueue::new(TX_BUF_QUEUE_CAP)),
            next_engine: AtomicUsize::new(0),
        }
    }
}

impl<S: PacketSocket, W: WaitStrategy> NetworkTile for NetworkTileImpl<S, W> {
    type Pool = S::Pool;
    type Wait = W;

    fn alloc_tx_bufs(
        &self,
        capacity: usize,
        count: usize,
        bufs: &mut Vec<<S::Pool as BufferPool>::BufMut>,
    ) -> usize {
        let mut allocated = 0;
        for _ in 0..count {
            let Some(mut buf) = self.tx_buf_queue.pop() else { break };
            buf.resize(capacity);
            bufs.push(buf);
            allocated += 1;
        }
        allocated
    }

    fn rx_queues(
        &self,
    ) -> &[Arc<Queue<RxPacket<<S::Pool as BufferPool>::BufMut>, W>>] {
        &self.rx_queues
    }

    fn tx_queues(
        &self,
    ) -> &[Arc<Queue<Transmit<ScatterGather<<S::Pool as BufferPool>::Buf>>, W>>] {
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

fn refill_tx_bufs<S: PacketSocket, W: WaitStrategy>(tile: &NetworkTileImpl<S, W>) {
    if tile.tx_buf_queue.len() < TX_BUF_REFILL_WATERMARK {
        let mut tmp = Vec::with_capacity(TX_BUF_REFILL_BATCH);
        tile.pool.alloc(TX_BUF_SIZE, TX_BUF_REFILL_BATCH, &mut tmp);
        for buf in tmp {
            let _ = tile.tx_buf_queue.push(buf);
        }
    }
}

fn push_rx<S: PacketSocket, W: WaitStrategy>(
    tile: &NetworkTileImpl<S, W>,
    meta: RecvMeta,
    payload: ScatterGather<<S::Pool as BufferPool>::BufMut>,
) {
    let idx = route_packet(&payload, tile.rx_queues.len(), &tile.next_engine);
    let _ = tile.rx_queues[idx].push(RxPacket { meta, payload });
}

/// Route a received datagram to an engine tile index.
///
/// Initial packets (new connections) are distributed round-robin so that
/// simultaneous handshakes spread across all engine tiles even when the client
/// uses a single UDP endpoint (one source port for many connections).
///
/// All other packets (Handshake, 0-RTT, 1-RTT) carry a server-assigned DCID
/// whose first byte encodes the owning engine index — see `TileIndexCidGenerator`
/// in `quac-tile`.  Routing by `dcid[0] % engine_count` sends them back to the
/// correct engine without any shared state.
fn route_packet<B: PacketBufMut>(
    payload: &ScatterGather<B>,
    engine_count: usize,
    next_engine: &AtomicUsize,
) -> usize {
    if engine_count == 1 {
        return 0;
    }
    let data: &[u8] = if let Some(s) = payload.as_contiguous() {
        s
    } else if let Some(seg) = payload.segments.first() {
        let buf = seg.buf.as_ref();
        &buf[seg.offset..(seg.offset + seg.len).min(buf.len())]
    } else {
        return 0;
    };
    if data.is_empty() {
        return 0;
    }
    let is_long_header = data[0] & 0x80 != 0;
    let is_initial     = is_long_header && (data[0] & 0x30) == 0x00;
    if is_initial {
        next_engine.fetch_add(1, Ordering::Relaxed) % engine_count
    } else if let Some(dcid) = extract_dcid(data) {
        dcid[0] as usize % engine_count
    } else {
        0
    }
}

fn drain_tx<S: PacketSocket, W: WaitStrategy>(
    tile: &NetworkTileImpl<S, W>,
) -> Vec<Transmit<ScatterGather<<S::Pool as BufferPool>::Buf>>> {
    let mut transmits = Vec::new();
    for queue in &tile.tx_queues {
        while let Some(t) = queue.pop() {
            transmits.push(t);
        }
    }
    transmits
}

fn run_combined<S: PacketSocket, W: WaitStrategy>(
    tile: Arc<NetworkTileImpl<S, W>>,
    mut socket: S,
) {
    for q in &tile.tx_queues {
        q.register_consumer();
    }

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

        refill_tx_bufs(&tile);

        if !did_work {
            wait_any_non_empty_combined(&tile.tx_queues);
        }
    }
}

fn run_reader<S: PacketSocket, W: WaitStrategy>(
    tile: Arc<NetworkTileImpl<S, W>>,
    mut socket: S,
) {
    let mut meta = vec![RecvMeta::default(); 64];
    let mut bufs: Vec<ScatterGather<<S::Pool as BufferPool>::BufMut>> = Vec::new();

    loop {
        match socket.recv(&mut meta, &mut bufs) {
            Ok(n) if n > 0 => {
                for (i, payload) in bufs.drain(..n).enumerate() {
                    push_rx(&tile, meta[i].clone(), payload);
                }
            }
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => { eprintln!("[net-rx] recv: {e}"); break; }
        }

        refill_tx_bufs(&tile);
    }
}

fn run_writer<S: PacketSocket, W: WaitStrategy>(
    tile: Arc<NetworkTileImpl<S, W>>,
    mut socket: S,
) {
    for q in &tile.tx_queues {
        q.register_consumer();
    }
    loop {
        let transmits = drain_tx(&tile);
        if transmits.is_empty() {
            wait_any_non_empty(&tile.tx_queues);
            continue;
        }
        socket.send(transmits);
        socket.drain_completions();
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
