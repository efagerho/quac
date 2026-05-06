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
pub use queue::{Park, Queue, Spin, WaitStrategy, wait_any_non_empty};

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
            .spawn(move || run_tile(self, factory()))
            .expect("spawn net-io");
    }
}

fn refill_tx_bufs<S: PacketSocket, W: WaitStrategy, R: PacketRouter>(
    tile: &NetworkTileImpl<S, W, R>,
    socket: &S,
) {
    if tile.tx_buf_queue.len() < TX_BUF_REFILL_WATERMARK {
        let avail = socket.tx_pool().available();
        // avail==0 means the pool has no free nodes: allow a full batch so the
        // pool can grow (bootstrap, or unified-backend edge case where the engine
        // is stuck waiting for TX bufs).  avail>0 caps at 50% to leave headroom
        // for the RX path.
        let count = if avail == 0 {
            TX_BUF_REFILL_BATCH
        } else {
            TX_BUF_REFILL_BATCH.min(avail / 2)
        };
        if count == 0 {
            return;
        }
        let mut tmp = Vec::with_capacity(count);
        socket.tx_pool().alloc(socket.tx_pool().max_payload_size(), count, &mut tmp);
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
    out: &mut Vec<Transmit<ScatterGather<<S::TxPool as TxPool>::Buf>>>,
) {
    for queue in &tile.tx_queues {
        while let Some(t) = queue.pop() {
            out.push(t);
        }
    }
}

fn run_tile<S: PacketSocket + Send, W: WaitStrategy, R: PacketRouter>(
    tile: Arc<NetworkTileImpl<S, W, R>>,
    mut socket: S,
) {
    for q in &tile.tx_queues {
        q.register_consumer();
    }

    let batch = S::MAX_BATCH.min(64);
    let mut meta = vec![RecvMeta::default(); batch];
    let mut bufs: Vec<<S::RxPool as RxPool>::BufMut> = Vec::with_capacity(batch);
    // Reused across iterations so `drain_tx` doesn't allocate a fresh Vec per
    // hot-loop turn (visible in profiles as drop_in_place<Vec<Transmit<...>>>).
    let mut transmits: Vec<Transmit<ScatterGather<<S::TxPool as TxPool>::Buf>>> =
        Vec::with_capacity(batch);

    loop {
        let mut did_work = false;

        // Drain TX first so that any response queued by an engine tile from a
        // previously received packet is sent before we block on the next recv.
        // Clearing `transmits` after send drops the OsBufs it held so they
        // return to the pool's local free-list before `refill_tx_bufs` runs
        // and the pool does not grow a new slab.
        drain_tx(&tile, &mut transmits);
        if !transmits.is_empty() {
            did_work = true;
            let _ = socket.send(&mut transmits);
            socket.drain_completions();
            transmits.clear();
        }

        refill_tx_bufs(&tile, &socket);

        // Keep recv slots filled to a full batch so the kernel always has
        // somewhere to write.
        let needed = batch - bufs.len();
        if needed > 0 {
            socket.rx_pool().alloc(socket.rx_pool().max_payload_size(), needed, &mut bufs);
        }

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

        if !did_work {
            wait_any_non_empty(&tile.tx_queues);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quac_socket::{PacketBufMut, RxPool, TxPool};
    use quac_socket_os::{OsBufMut, OsSocket};

    // Build a tile whose factory is never called — used to access tx_buf_queue
    // and call refill_tx_bufs directly alongside a separately-created socket.
    fn make_tile() -> NetworkTileImpl<OsSocket, Spin, FourTupleRouter> {
        NetworkTileImpl::new(
            || unreachable!("factory must not be called in unit tests"),
            FourTupleRouter,
            1,
        )
    }

    fn bind_socket() -> OsSocket {
        OsSocket::bind("127.0.0.1:0".parse().unwrap(), 0)
            .expect("bind loopback socket for test")
    }

    // ── bootstrap ────────────────────────────────────────────────────────────

    #[test]
    fn refill_bootstraps_from_empty_pool() {
        // With available()==0 (fresh pool, no slabs grown), refill_tx_bufs must
        // still populate tx_buf_queue. If it returned early, the engine thread
        // would spin forever in alloc_one() — a bootstrap deadlock.
        let socket = bind_socket();
        let tile = make_tile();

        assert_eq!(socket.tx_pool().available(), 0);
        assert_eq!(tile.tx_buf_queue.len(), 0);

        refill_tx_bufs(&tile, &socket);

        assert!(
            tile.tx_buf_queue.len() > 0,
            "tx_buf_queue must be seeded even when the pool starts empty"
        );
    }

    // ── 50 % cap ─────────────────────────────────────────────────────────────

    #[test]
    fn refill_caps_at_half_of_available() {
        // When the pool has N free buffers, refill must leave at least ⌊N/2⌋
        // behind so the RX path can alloc without triggering slab growth.
        let socket = bind_socket();

        // Warm the pool: alloc a full slab then return all buffers same-thread.
        let mut warmup: Vec<OsBufMut> = Vec::new();
        let cap = RxPool::max_payload_size(socket.rx_pool());
        RxPool::alloc(socket.rx_pool(), cap, 64, &mut warmup);
        drop(warmup); // same-thread return → local

        let avail_before = socket.tx_pool().available();
        assert!(avail_before > 0);

        let tile = make_tile();
        refill_tx_bufs(&tile, &socket);

        let tx_taken = tile.tx_buf_queue.len();
        let avail_after = socket.tx_pool().available();

        assert!(
            tx_taken <= avail_before / 2,
            "TX took {tx_taken}, max allowed is {}/2={}",
            avail_before,
            avail_before / 2
        );
        assert!(
            avail_after >= avail_before / 2,
            "pool must retain ≥ half for RX: before={avail_before} after={avail_after}"
        );
    }

    #[test]
    fn rx_can_alloc_full_batch_after_refill() {
        // After refill_tx_bufs, the pool's free list must still cover a full RX
        // batch (64 buffers) without needing to grow a new slab.
        let socket = bind_socket();
        const BATCH: usize = 64;

        // Two batches worth of free buffers so 50% split leaves one full batch.
        let mut warmup: Vec<OsBufMut> = Vec::new();
        let cap = RxPool::max_payload_size(socket.rx_pool());
        RxPool::alloc(socket.rx_pool(), cap, BATCH * 2, &mut warmup);
        drop(warmup);

        let tile = make_tile();
        refill_tx_bufs(&tile, &socket);

        let avail_after_refill = socket.tx_pool().available();
        assert!(
            avail_after_refill >= BATCH,
            "RX would need a new slab after refill; avail={avail_after_refill} < batch={BATCH}"
        );
    }

    // ── scarce pool ───────────────────────────────────────────────────────────

    #[test]
    fn refill_skips_when_exactly_one_buffer_free() {
        // With a single free buffer, ⌊1/2⌋ = 0, so refill must leave it for RX.
        let socket = bind_socket();

        // Alloc a full slab; keep SLAB-1 alive so only 1 returns to local.
        let mut bufs: Vec<OsBufMut> = Vec::new();
        let cap = RxPool::max_payload_size(socket.rx_pool());
        RxPool::alloc(socket.rx_pool(), cap, 64, &mut bufs);
        let _live = bufs.split_off(1); // _live holds 63 live items
        bufs.clear(); // drops 1 → same-thread → local=1

        assert_eq!(socket.tx_pool().available(), 1, "setup: exactly 1 free buffer");

        let tile = make_tile();
        refill_tx_bufs(&tile, &socket);

        assert_eq!(
            tile.tx_buf_queue.len(),
            0,
            "with 1 free buffer, ⌊1/2⌋=0; TX gets nothing — buffer reserved for RX"
        );
        assert_eq!(socket.tx_pool().available(), 1, "the single buffer must remain in pool");
    }

    #[test]
    fn refill_handles_cross_thread_returns_via_available() {
        // Buffers dropped by engine threads land in `remote`. available() must
        // drain `remote` so refill_tx_bufs sees them and applies the cap correctly
        // rather than treating the pool as empty and growing a slab for TX.
        let socket = bind_socket();

        // Alloc then drop a batch cross-thread → buffers go to `remote`.
        let mut bufs: Vec<OsBufMut> = Vec::new();
        let cap = RxPool::max_payload_size(socket.rx_pool());
        RxPool::alloc(socket.rx_pool(), cap, 64, &mut bufs);
        // Freeze to OsBuf (which is Send) for the cross-thread drop.
        let frozen: Vec<_> = bufs.into_iter().map(|b: OsBufMut| b.freeze()).collect();
        std::thread::spawn(move || drop(frozen)).join().unwrap();

        // Pool looks empty locally but remote has 64 entries.
        // available() must drain remote and expose them.
        let avail = socket.tx_pool().available();
        assert!(avail > 0, "available() must drain remote; got 0");

        let tile = make_tile();
        refill_tx_bufs(&tile, &socket);

        // TX may take at most half; the rest stays available for RX.
        assert!(
            tile.tx_buf_queue.len() <= avail / 2,
            "TX must not exceed 50% of the cross-thread-returned buffers"
        );
    }
}
