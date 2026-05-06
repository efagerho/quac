use std::hash::{DefaultHasher, Hash, Hasher};
use std::io;
use std::sync::{Arc, Mutex};
use std::thread;

use crossbeam_queue::ArrayQueue;
use quac_socket::{
    PacketBufMut, PacketSocket, RecvMeta, RxPool, ScatterGather, Segment, Transmit, TxPool,
};

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

mod queue;
pub use queue::{Park, Queue, Spin, WaitStrategy, wait_any_non_empty_combined};

/// Number of slots in each queue between a network tile and an engine tile.
pub const QUEUE_CAP: usize = 1024;

/// Shorthand for the RX queue type shared between a network tile and an engine tile.
pub type RxQueue<B, W> = Arc<Queue<RxPacket<B>, W>>;
/// Shorthand for the TX queue type shared between an engine tile and a network tile.
pub type TxQueue<B, W> = Arc<Queue<Transmit<ScatterGather<B>>, W>>;

/// A datagram received from the network, queued for delivery to an engine tile.
pub struct RxPacket<B: PacketBufMut> {
    pub meta: RecvMeta,
    pub payload: ScatterGather<B>,
}

/// An I/O component bound to one `SO_REUSEPORT` socket and connected to N
/// engine tiles via lock-free queues.
pub trait NetworkTile: Send + Sync + 'static {
    type RxPool: RxPool;
    type TxPool: TxPool<RxBufMut = <Self::RxPool as RxPool>::BufMut>;
    type Wait: WaitStrategy;

    /// Pop up to `count` pre-allocated TX buffers from the tile's buffer queue.
    /// Safe to call from any thread; the queue is refilled on the tile thread.
    fn alloc_tx_bufs(
        &self,
        capacity: usize,
        count: usize,
        bufs: &mut Vec<<Self::TxPool as TxPool>::BufMut>,
    ) -> usize;

    /// Convert an Rx buffer into a Tx buffer preserving its contents.
    ///
    /// Compile-time dispatch via `TxPool::UNIFIED`:
    /// - `true` (unified backend, e.g. OS sockets): identity move, no allocation.
    /// - `false` (separate backend, e.g. io_uring): pops a scratch Tx buf from
    ///   the tile's pre-filled queue (same path as `alloc_tx_bufs`), copies Rx
    ///   data into it, drops the Rx buf (releasing any backend resource), and
    ///   returns `Ok` with the populated Tx buf.
    ///
    /// Returns `Err(rx)` when the scratch queue is exhausted (back-pressure),
    /// giving the caller the buffer back to retry or drop explicitly.
    fn convert_rx_to_tx(
        &self,
        rx: <Self::RxPool as RxPool>::BufMut,
    ) -> Result<<Self::TxPool as TxPool>::BufMut, <Self::RxPool as RxPool>::BufMut>;

    fn rx_queues(&self) -> &[RxQueue<<Self::RxPool as RxPool>::BufMut, Self::Wait>];
    fn tx_queues(&self) -> &[TxQueue<<Self::TxPool as TxPool>::Buf, Self::Wait>];
    fn start(self: Arc<Self>, tile_index: usize);
}

pub struct NetworkTileImpl<S: PacketSocket, W: WaitStrategy, R: PacketRouter> {
    /// Socket factory invoked on the IO thread inside `start()`.
    /// `None` after `start()` has consumed it.
    socket_factory: Mutex<Option<Box<dyn FnOnce() -> S + Send>>>,
    rx_queues: Vec<RxQueue<<S::RxPool as RxPool>::BufMut, W>>,
    tx_queues: Vec<TxQueue<<S::TxPool as TxPool>::Buf, W>>,
    tx_buf_queue: Arc<ArrayQueue<<S::TxPool as TxPool>::BufMut>>,
    router: R,
}

impl<S: PacketSocket + Send + 'static, W: WaitStrategy, R: PacketRouter> NetworkTileImpl<S, W, R> {
    /// Create a tile that drives both Rx and Tx on a single combined thread.
    ///
    /// `factory` is called on the IO thread so the socket (and its buffer pool)
    /// is created with the correct thread as owner from the start. Use
    /// `bind_reuseport` inside `factory` to run multiple tiles on the same port.
    pub fn new(factory: impl FnOnce() -> S + Send + 'static, router: R, engine_count: usize) -> Self {
        assert!(engine_count > 0);
        let rx_queues = (0..engine_count).map(|_| Queue::<_, W>::new(QUEUE_CAP)).collect();
        let tx_queues = (0..engine_count).map(|_| Queue::<_, W>::new(QUEUE_CAP)).collect();
        Self {
            socket_factory: Mutex::new(Some(Box::new(factory))),
            rx_queues,
            tx_queues,
            tx_buf_queue: Arc::new(ArrayQueue::new(TX_BUF_QUEUE_CAP)),
            router,
        }
    }
}

impl<S: PacketSocket + Send, W: WaitStrategy, R: PacketRouter> NetworkTile
    for NetworkTileImpl<S, W, R>
{
    type RxPool = S::RxPool;
    type TxPool = S::TxPool;
    type Wait = W;

    fn alloc_tx_bufs(
        &self,
        _capacity: usize,
        count: usize,
        bufs: &mut Vec<<S::TxPool as TxPool>::BufMut>,
    ) -> usize {
        let mut allocated = 0;
        for _ in 0..count {
            let Some(buf) = self.tx_buf_queue.pop() else { break };
            bufs.push(buf);
            allocated += 1;
        }
        allocated
    }

    fn convert_rx_to_tx(
        &self,
        rx: <S::RxPool as RxPool>::BufMut,
    ) -> Result<<S::TxPool as TxPool>::BufMut, <S::RxPool as RxPool>::BufMut> {
        if <S::TxPool as TxPool>::UNIFIED {
            // Compile-time identity: no queue pop, no copy.
            Ok(<S::TxPool as TxPool>::from_rx_unified(rx))
        } else {
            // Pop scratch from the pre-filled queue and copy inline so we avoid
            // calling pool.alloc() from this (possibly cross-thread) context.
            let mut tx = match self.tx_buf_queue.pop() {
                None => return Err(rx),
                Some(t) => t,
            };
            let src = rx.filled();
            let len = src.len();
            unsafe {
                std::ptr::copy_nonoverlapping(
                    src.as_ptr(),
                    tx.uninit_mut().as_mut_ptr() as *mut u8,
                    len,
                );
                tx.set_filled(len);
            }
            drop(rx);
            Ok(tx)
        }
    }

    fn rx_queues(&self) -> &[RxQueue<<S::RxPool as RxPool>::BufMut, W>] {
        &self.rx_queues
    }

    fn tx_queues(&self) -> &[TxQueue<<S::TxPool as TxPool>::Buf, W>] {
        &self.tx_queues
    }

    fn start(self: Arc<Self>, tile_index: usize) {
        let factory = self
            .socket_factory
            .lock()
            .unwrap()
            .take()
            .expect("NetworkTileImpl::start called more than once");

        thread::Builder::new()
            .name(format!("net-io-{tile_index}"))
            .spawn(move || run_combined(self, factory()))
            .expect("spawn net-io");
    }
}

fn refill_tx_bufs<S: PacketSocket, W: WaitStrategy, R: PacketRouter>(
    tile: &NetworkTileImpl<S, W, R>,
    socket: &S,
) {
    if tile.tx_buf_queue.len() < TX_BUF_REFILL_WATERMARK {
        let mut tmp = Vec::with_capacity(TX_BUF_REFILL_BATCH);
        socket.tx_pool().alloc(socket.tx_pool().max_payload_size(), TX_BUF_REFILL_BATCH, &mut tmp);
        for buf in tmp {
            let _ = tile.tx_buf_queue.push(buf);
        }
    }
}

fn push_rx<S: PacketSocket, W: WaitStrategy, R: PacketRouter>(
    tile: &NetworkTileImpl<S, W, R>,
    meta: RecvMeta,
    payload: ScatterGather<<S::RxPool as RxPool>::BufMut>,
) {
    let engine_count = tile.rx_queues.len();
    let data: &[u8] = payload
        .segments()
        .first()
        .map(|s| {
            let filled = s.buf().filled();
            let start = s.offset() as usize;
            let end = (start + s.len() as usize).min(filled.len());
            &filled[start..end]
        })
        .unwrap_or(&[]);
    let idx = tile.router.route(&meta, data, engine_count);
    let _ = tile.rx_queues[idx].push(RxPacket { meta, payload });
}

fn drain_tx<S: PacketSocket, W: WaitStrategy, R: PacketRouter>(
    tile: &NetworkTileImpl<S, W, R>,
) -> Vec<Transmit<ScatterGather<<S::TxPool as TxPool>::Buf>>> {
    let mut transmits = Vec::new();
    for queue in &tile.tx_queues {
        while let Some(t) = queue.pop() {
            transmits.push(t);
        }
    }
    transmits
}

fn run_combined<S: PacketSocket + Send, W: WaitStrategy, R: PacketRouter>(
    tile: Arc<NetworkTileImpl<S, W, R>>,
    mut socket: S,
) {
    for q in &tile.tx_queues {
        q.register_consumer();
    }

    let batch = S::MAX_BATCH.min(64);
    let mut meta = vec![RecvMeta::default(); batch];
    let mut bufs: Vec<<S::RxPool as RxPool>::BufMut> = Vec::with_capacity(batch);

    loop {
        // Keep recv slots filled to a full batch so the kernel always has
        // somewhere to write.
        let needed = batch - bufs.len();
        if needed > 0 {
            socket.rx_pool().alloc(socket.rx_pool().max_payload_size(), needed, &mut bufs);
        }

        let mut did_work = false;

        let n = match socket.recv(&mut meta, &mut bufs) {
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => 0,
            Err(e) => {
                eprintln!("[net-io] recv: {e}");
                break;
            }
        };

        if n > 0 {
            did_work = true;
            for (i, buf) in bufs.drain(..n).enumerate() {
                let len = meta[i].len as u32;
                // Safety: recv set buf.filled().len() == meta[i].len, so
                // offset(0) + len <= buf.filled().len().
                let seg = unsafe { Segment::new_unchecked(buf, 0, len) };
                push_rx(&tile, meta[i], ScatterGather::single(seg));
            }
        }

        let mut transmits = drain_tx(&tile);
        if !transmits.is_empty() {
            did_work = true;
            let _ = socket.send(&mut transmits);
            socket.drain_completions();
        }

        refill_tx_bufs(&tile, &socket);

        if !did_work {
            wait_any_non_empty_combined(&tile.tx_queues);
        }
    }
}

