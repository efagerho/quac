use std::hash::{DefaultHasher, Hash, Hasher};
use std::io;
use std::sync::{Arc, Mutex};
use std::thread;

use crossbeam_queue::ArrayQueue;
use quac_socket::{BufferPool, PacketBufMut, PacketSocket, RecvMeta, ScatterGather, Transmit};

/// Routes a received datagram to one of N engine-tile RX queues.
///
/// Both `meta` (source/dest addresses) and `payload` (raw bytes) are available
/// so implementations can use either for routing decisions.
pub trait PacketRouter: Send + Sync + 'static {
    fn route(&self, meta: &RecvMeta, payload: &[u8], engine_count: usize) -> usize;
}

/// Routes packets by hashing the source `SocketAddr` from the UDP metadata.
///
/// All datagrams from the same client endpoint are consistently delivered to
/// the same engine tile, providing connection affinity without any payload
/// inspection.
pub struct FourTupleRouter;

impl PacketRouter for FourTupleRouter {
    fn route(&self, meta: &RecvMeta, _payload: &[u8], engine_count: usize) -> usize {
        let mut h = DefaultHasher::new();
        meta.src.hash(&mut h);
        h.finish() as usize % engine_count
    }
}

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
    fn start(self: Arc<Self>, tile_index: usize);
}

/// Whether the tile uses one shared thread for Rx+Tx or dedicated threads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreadMode {
    /// One thread handles both receive and transmit.
    Combined,
    /// Separate reader and writer threads.
    Separate,
}

pub struct NetworkTileImpl<S: PacketSocket, W: WaitStrategy, R: PacketRouter> {
    pool: Arc<S::Pool>,
    thread_mode: ThreadMode,
    /// Sockets taken out once in `start()`. `None` after `start()`.
    sockets: Mutex<Option<(S, Option<S>)>>,
    rx_queues: Vec<Arc<Queue<RxPacket<<S::Pool as BufferPool>::BufMut>, W>>>,
    tx_queues: Vec<Arc<Queue<Transmit<ScatterGather<<S::Pool as BufferPool>::Buf>>, W>>>,
    tx_buf_queue: Arc<ArrayQueue<<S::Pool as BufferPool>::BufMut>>,
    router: R,
}

impl<S: PacketSocket, W: WaitStrategy, R: PacketRouter> NetworkTileImpl<S, W, R> {
    /// Create a tile that drives both Rx and Tx on a single thread.
    pub fn combined(socket: S, router: R, engine_count: usize) -> Self {
        assert!(engine_count > 0);
        let pool = socket.pool();
        Self::build(pool, ThreadMode::Combined, socket, None, router, engine_count)
    }

    /// Create a tile with dedicated reader and writer threads.
    /// `rx` and `tx` must be clones of the same underlying socket (e.g. via `try_clone`).
    pub fn separate(rx: S, tx: S, router: R, engine_count: usize) -> Self {
        assert!(engine_count > 0);
        let pool = rx.pool();
        Self::build(pool, ThreadMode::Separate, rx, Some(tx), router, engine_count)
    }

    fn build(
        pool: Arc<S::Pool>,
        thread_mode: ThreadMode,
        rx_socket: S,
        tx_socket: Option<S>,
        router: R,
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
            router,
        }
    }
}

impl<S: PacketSocket, W: WaitStrategy, R: PacketRouter> NetworkTile for NetworkTileImpl<S, W, R> {
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

    fn start(self: Arc<Self>, tile_index: usize) {
        let (rx_socket, tx_socket_opt) = self
            .sockets
            .lock()
            .unwrap()
            .take()
            .expect("NetworkTileImpl::start called more than once");

        match self.thread_mode {
            ThreadMode::Combined => {
                thread::Builder::new()
                    .name(format!("net-io-{tile_index}"))
                    .spawn(move || run_combined(self, rx_socket))
                    .expect("spawn net-io");
            }
            ThreadMode::Separate => {
                let tx_socket = tx_socket_opt.expect("separate mode requires two sockets");
                let reader_tile = Arc::clone(&self);
                thread::Builder::new()
                    .name(format!("net-rx-{tile_index}"))
                    .spawn(move || run_reader(reader_tile, rx_socket))
                    .expect("spawn net-rx");
                thread::Builder::new()
                    .name(format!("net-tx-{tile_index}"))
                    .spawn(move || run_writer(self, tx_socket))
                    .expect("spawn net-tx");
            }
        }
    }
}

fn refill_tx_bufs<S: PacketSocket, W: WaitStrategy, R: PacketRouter>(tile: &NetworkTileImpl<S, W, R>) {
    if tile.tx_buf_queue.len() < TX_BUF_REFILL_WATERMARK {
        let mut tmp = Vec::with_capacity(TX_BUF_REFILL_BATCH);
        tile.pool.alloc(TX_BUF_SIZE, TX_BUF_REFILL_BATCH, &mut tmp);
        for buf in tmp {
            let _ = tile.tx_buf_queue.push(buf);
        }
    }
}

fn push_rx<S: PacketSocket, W: WaitStrategy, R: PacketRouter>(
    tile: &NetworkTileImpl<S, W, R>,
    meta: RecvMeta,
    payload: ScatterGather<<S::Pool as BufferPool>::BufMut>,
) {
    let engine_count = tile.rx_queues.len();
    let data: &[u8] = if let Some(s) = payload.as_contiguous() {
        s
    } else if let Some(seg) = payload.segments.first() {
        let buf = seg.buf.as_ref();
        &buf[seg.offset..(seg.offset + seg.len).min(buf.len())]
    } else {
        &[]
    };
    let idx = tile.router.route(&meta, data, engine_count);
    let _ = tile.rx_queues[idx].push(RxPacket { meta, payload });
}

fn drain_tx<S: PacketSocket, W: WaitStrategy, R: PacketRouter>(
    tile: &NetworkTileImpl<S, W, R>,
) -> Vec<Transmit<ScatterGather<<S::Pool as BufferPool>::Buf>>> {
    let mut transmits = Vec::new();
    for queue in &tile.tx_queues {
        while let Some(t) = queue.pop() {
            transmits.push(t);
        }
    }
    transmits
}

fn run_combined<S: PacketSocket, W: WaitStrategy, R: PacketRouter>(
    tile: Arc<NetworkTileImpl<S, W, R>>,
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

fn run_reader<S: PacketSocket, W: WaitStrategy, R: PacketRouter>(
    tile: Arc<NetworkTileImpl<S, W, R>>,
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

fn run_writer<S: PacketSocket, W: WaitStrategy, R: PacketRouter>(
    tile: Arc<NetworkTileImpl<S, W, R>>,
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

