use std::io;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
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

/// Routes by splitmix-mixing the source `(IP, port)`. Same client → same
/// engine tile.
pub struct SrcAddrRouter;

/// Deprecated alias; kept for source compatibility.
pub use SrcAddrRouter as FourTupleRouter;

#[inline]
fn mix64(mut x: u64) -> u64 {
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^= x >> 31;
    x
}

impl PacketRouter for SrcAddrRouter {
    fn route(&self, meta: &RecvMeta, _payload: &[u8], engine_count: usize) -> usize {
        let mut h: u64 = match meta.src.ip() {
            IpAddr::V4(v4) => u32::from(v4) as u64,
            IpAddr::V6(v6) => {
                let s = v6.segments();
                ((s[0] as u64) << 48)
                    | ((s[1] as u64) << 32)
                    | ((s[4] as u64) << 16)
                    | (s[5] as u64)
            }
        };
        // Shift port out of the IPv4 bit range to avoid (ip ^ port) collisions.
        h ^= (meta.src.port() as u64) << 32;
        (mix64(h) as usize) % engine_count
    }
}

const TX_BUF_QUEUE_CAP: usize = 1024;
const TX_BUF_REFILL_WATERMARK: usize = 256;
const TX_BUF_REFILL_BATCH: usize = 64;

/// Tile-level toggle for the per-packet `RecvMeta` extras delivered by every
/// backend: `ecn` from `IP_RECVTOS` / `IPV6_RECVTCLASS` (OS, io_uring) or the
/// IPv4 TOS byte (XDP), and `dst_ip` from `IP_PKTINFO` / `IPV6_RECVPKTINFO` /
/// `IP_RECVDSTADDR` (OS, io_uring) or the IPv4 dst-addr field (XDP).
///
/// Defaults to both on so existing callers (QUIC stack driving ECN, multi-
/// homed path selection) keep working unchanged. Production tiles that don't
/// need either field can pass the result of [`RecvMetaConfig::off`] (or only
/// one of `.no_ecn()` / `.no_dst_ip()`) into their socket factory closure to
/// drop the per-packet `put_cmsg` cost on the OS / io_uring backends.
#[derive(Debug, Clone, Copy)]
pub struct RecvMetaConfig {
    pub ecn: bool,
    pub dst_ip: bool,
}

impl Default for RecvMetaConfig {
    fn default() -> Self {
        Self { ecn: true, dst_ip: true }
    }
}

impl RecvMetaConfig {
    /// Both fields populated.
    pub const fn on() -> Self {
        Self { ecn: true, dst_ip: true }
    }

    /// Neither field populated.
    pub const fn off() -> Self {
        Self { ecn: false, dst_ip: false }
    }

    pub fn no_ecn(mut self) -> Self {
        self.ecn = false;
        self
    }

    pub fn no_dst_ip(mut self) -> Self {
        self.dst_ip = false;
        self
    }
}

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
    /// RX packets dropped because the routed engine queue was full.
    rx_drops: AtomicU64,
    router: R,
}

impl<S: PacketSocket + 'static, W: WaitStrategy, R: PacketRouter> NetworkTileImpl<S, W, R> {
    /// Create a tile with the default queue capacity ([`QUEUE_CAP`]).
    ///
    /// `factory` runs on the IO thread so the socket and its pools are
    /// constructed on their owning thread. Multi-tile listeners pass
    /// `cfg.reuseport(true)` inside the factory.
    pub fn new(factory: impl FnOnce() -> S + Send + 'static, router: R, engine_count: usize) -> Self {
        Self::with_queue_cap(factory, router, engine_count, QUEUE_CAP)
    }

    /// Like `new` but with a custom per-engine RX/TX queue capacity.
    pub fn with_queue_cap(
        factory: impl FnOnce() -> S + Send + 'static,
        router: R,
        engine_count: usize,
        queue_cap: usize,
    ) -> Self {
        assert!(engine_count > 0);
        assert!(queue_cap > 0);
        let rx_queues = (0..engine_count).map(|_| Queue::<_, W>::new(queue_cap)).collect();
        let tx_queues = (0..engine_count).map(|_| Queue::<_, W>::new(queue_cap)).collect();
        Self {
            socket_factory: Mutex::new(Some(Box::new(factory))),
            rx_queues,
            tx_queues,
            tx_buf_queue: Arc::new(ArrayQueue::new(TX_BUF_QUEUE_CAP)),
            rx_drops: AtomicU64::new(0),
            router,
        }
    }

    /// Total RX packets dropped due to a full engine queue since construction.
    pub fn rx_drops(&self) -> u64 {
        self.rx_drops.load(Ordering::Relaxed)
    }
}

impl<S: PacketSocket, W: WaitStrategy, R: PacketRouter> NetworkTile
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
            // RX max payload may exceed TX max payload; bail rather than
            // overrun the TX buffer.
            if len > tx.capacity() {
                drop(tx);
                return Err(rx);
            }
            // SAFETY: len <= tx.capacity() (checked above); src and tx do not
            // alias (distinct pool buffers); src is valid for `len` bytes.
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
        // avail==0: only grow if scratch is also empty (bootstrap / stuck);
        // otherwise wait so a TX burst can't trigger unbounded slab growth.
        // avail>0: cap at 50% to leave headroom for RX.
        let count = if avail == 0 {
            if tile.tx_buf_queue.is_empty() {
                TX_BUF_REFILL_BATCH
            } else {
                return;
            }
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
    if !tile.rx_queues[idx].push(RxPacket { meta, payload }) {
        tile.rx_drops.fetch_add(1, Ordering::Relaxed);
    }
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

fn run_tile<S: PacketSocket, W: WaitStrategy, R: PacketRouter>(
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

        // TX before recv. Unsent entries stay at the front for retry; hard
        // I/O errors drop the batch to avoid looping on a broken socket.
        drain_tx(&tile, &mut transmits);
        if !transmits.is_empty() {
            did_work = true;
            let n = match socket.send(&mut transmits) {
                Ok(n) => n,
                Err(e) => {
                    eprintln!("[net-io] send: {e}");
                    transmits.len()
                }
            };
            socket.drain_completions();
            transmits.drain(..n);
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
    use quac_socket_os::{OsBufMut, OsConfig, OsSocket};

    // Build a tile whose factory is never called -- used to access tx_buf_queue
    // and call refill_tx_bufs directly alongside a separately-created socket.
    fn make_tile() -> NetworkTileImpl<OsSocket, Spin, FourTupleRouter> {
        NetworkTileImpl::new(
            || unreachable!("factory must not be called in unit tests"),
            FourTupleRouter,
            1,
        )
    }

    fn bind_socket() -> OsSocket {
        OsSocket::bind("127.0.0.1:0".parse().unwrap(), 0, OsConfig::default())
            .expect("bind loopback socket for test")
    }


    #[test]
    fn refill_bootstraps_from_empty_pool() {
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


    #[test]
    fn refill_caps_at_half_of_available() {
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


    #[test]
    fn refill_skips_when_exactly_one_buffer_free() {
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
            "with 1 free buffer, ⌊1/2⌋=0; TX gets nothing - buffer reserved for RX"
        );
        assert_eq!(socket.tx_pool().available(), 1, "the single buffer must remain in pool");
    }

    #[test]
    fn refill_handles_cross_thread_returns_via_available() {
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
