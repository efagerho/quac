use std::mem::MaybeUninit;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use quac_network_tile::{FourTupleRouter, NetworkTile, NetworkTileImpl, RxPacket, Spin};
use quac_socket::{PacketBufMut, ScatterGather, Segment, Transmit, TxPool};
use quac_socket_iouring::IoUringSocket;
use quac_socket_os::OsSocket;

const BATCH: usize = 64;

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Rate,
    Pingpong,
}

#[derive(Clone, Copy, PartialEq)]
enum Socket {
    Os,
    IoUring,
}

struct Args {
    target: SocketAddr,
    socket: Socket,
    threads: usize,
    mode: Mode,
    rate: u64,
    size: usize,
    window: usize,
    duration: u64,
}

impl Default for Args {
    fn default() -> Self {
        Self {
            target: "127.0.0.1:9999".parse().unwrap(),
            socket: Socket::Os,
            threads: 1,
            mode: Mode::Rate,
            rate: 0,
            size: 64,
            window: 1,
            duration: 10,
        }
    }
}

fn die(msg: &str) -> ! {
    eprintln!("error: {msg}");
    std::process::exit(1);
}

fn parse_args() -> Args {
    let mut a = Args::default();
    let mut it = std::env::args().skip(1);
    while let Some(k) = it.next() {
        let mut v = || it.next().unwrap_or_else(|| die(&format!("{k} needs a value")));
        match k.as_str() {
            "--target" => {
                a.target = v().parse().unwrap_or_else(|_| die("--target needs addr:port"));
            }
            "--socket" => {
                a.socket = match v().as_str() {
                    "os" => Socket::Os,
                    "iouring" => Socket::IoUring,
                    s => die(&format!("unknown socket: {s}")),
                };
            }
            "--threads" => {
                a.threads = v().parse().unwrap_or_else(|_| die("--threads needs a number"));
            }
            "--mode" => {
                a.mode = match v().as_str() {
                    "rate" => Mode::Rate,
                    "pingpong" => Mode::Pingpong,
                    s => die(&format!("unknown mode: {s}")),
                };
            }
            "--rate" => {
                a.rate = v().parse().unwrap_or_else(|_| die("--rate needs a number"));
            }
            "--size" => {
                a.size = v().parse().unwrap_or_else(|_| die("--size needs a number"));
            }
            "--window" => {
                a.window = v().parse().unwrap_or_else(|_| die("--window needs a number"));
            }
            "--duration" => {
                a.duration = v().parse().unwrap_or_else(|_| die("--duration needs a number"));
            }
            "--help" | "-h" => {
                println!(
                    "Usage: tile-bench-sender [--target addr:port] [--socket os|iouring] \
                     [--threads N] [--mode rate|pingpong] [--rate pps] [--size bytes] \
                     [--window N] [--duration secs]"
                );
                std::process::exit(0);
            }
            other => die(&format!("unknown arg: {other}")),
        }
    }
    a
}

static SHUTDOWN: OnceLock<Arc<AtomicBool>> = OnceLock::new();

extern "C" fn sigint_handler(_: libc::c_int) {
    if let Some(flag) = SHUTDOWN.get() {
        flag.store(true, Relaxed);
    }
    unsafe { libc::signal(libc::SIGINT, libc::SIG_DFL) };
}

// Write `size` bytes into `buf` (8-byte LE timestamp, then zeros), freeze it,
// and return the frozen buffer together with its filled length.
fn fill_buf<B: PacketBufMut>(mut buf: B, size: usize, ts_ns: u64) -> (B::Frozen, u32) {
    unsafe { buf.set_filled(0) };
    let uninit = buf.uninit_mut();
    let fill = size.min(uninit.len());
    if fill >= 8 {
        for (i, &b) in ts_ns.to_le_bytes().iter().enumerate() {
            uninit[i] = MaybeUninit::new(b);
        }
        uninit[8..fill].fill(MaybeUninit::new(0));
    } else {
        uninit[..fill].fill(MaybeUninit::new(0));
    }
    unsafe { buf.set_filled(fill) };
    (buf.freeze(), fill as u32)
}

// Extract the LE u64 timestamp from the first segment of an RxPacket and
// record RTT stats. No-op if the payload is too short.
fn record_rtt<B: PacketBufMut>(
    pkt: &RxPacket<B>,
    now_ns: u64,
    rtt_sum: &AtomicU64,
    rtt_n: &AtomicU64,
    rtt_max: &AtomicU64,
) {
    let Some(seg) = pkt.payload.segments().first() else { return };
    let filled = seg.buf().filled();
    let s = seg.offset() as usize;
    let e = (s + seg.len() as usize).min(filled.len());
    let Some(slice) = filled.get(s..e) else { return };
    if slice.len() < 8 {
        return;
    }
    let ts = u64::from_le_bytes(slice[..8].try_into().unwrap());
    if let Some(rtt) = now_ns.checked_sub(ts) {
        rtt_sum.fetch_add(rtt, Relaxed);
        rtt_n.fetch_add(1, Relaxed);
        rtt_max.fetch_max(rtt, Relaxed);
    }
}

fn run_sender<T: NetworkTile>(
    tile: Arc<T>,
    target: SocketAddr,
    mode: Mode,
    rate: u64,
    size: usize,
    window: usize,
    shutdown: Arc<AtomicBool>,
    tx_count: Arc<AtomicU64>,
    rx_count: Arc<AtomicU64>,
    rtt_sum: Arc<AtomicU64>,
    rtt_n: Arc<AtomicU64>,
    rtt_max: Arc<AtomicU64>,
) {
    let tx_q = Arc::clone(&tile.tx_queues()[0]);
    let rx_q = Arc::clone(&tile.rx_queues()[0]);
    rx_q.register_consumer();

    let mut cache: Vec<<T::TxPool as TxPool>::BufMut> = Vec::with_capacity(BATCH);
    let start = Instant::now();

    // Spin until at least one TX buffer is available in the tile's pre-filled queue.
    // Only refill `cache` when it's empty — otherwise we'd siphon buffers out of
    // tx_buf_queue every round trip and force the tile to keep growing the pool.
    let mut alloc_one = || -> <T::TxPool as TxPool>::BufMut {
        loop {
            if cache.is_empty() {
                tile.alloc_tx_bufs(size.max(8), BATCH, &mut cache);
            }
            if let Some(b) = cache.pop() {
                return b;
            }
            std::hint::spin_loop();
        }
    };

    match mode {
        Mode::Rate => {
            let mut total_sent = 0u64;
            let interval_ns = if rate > 0 { 1_000_000_000.0 / rate as f64 } else { 0.0 };

            while !shutdown.load(Relaxed) {
                for _ in 0..BATCH {
                    if rate > 0 {
                        let target_ns = (total_sent as f64 * interval_ns) as u64;
                        let elapsed = start.elapsed().as_nanos() as u64;
                        if elapsed < target_ns {
                            let dt = target_ns - elapsed;
                            if dt > 1_000 {
                                std::thread::sleep(Duration::from_nanos(dt - 500));
                            }
                            while (start.elapsed().as_nanos() as u64) < target_ns {
                                std::hint::spin_loop();
                            }
                        }
                    }

                    let buf = alloc_one();
                    let (frozen, len) = fill_buf(buf, size, 0);
                    let seg = unsafe { Segment::new_unchecked(frozen, 0, len) };
                    let transmit = Transmit::new(ScatterGather::single(seg), target);
                    if tx_q.push(transmit) {
                        total_sent += 1;
                        tx_count.fetch_add(1, Relaxed);
                    }
                }
            }
        }

        Mode::Pingpong => {
            let mut inflight: usize = 0;

            while !shutdown.load(Relaxed) {
                while inflight < window {
                    let ts_ns = start.elapsed().as_nanos() as u64;
                    let buf = alloc_one();
                    let (frozen, len) = fill_buf(buf, size, ts_ns);
                    let seg = unsafe { Segment::new_unchecked(frozen, 0, len) };
                    let transmit = Transmit::new(ScatterGather::single(seg), target);
                    if tx_q.push(transmit) {
                        inflight += 1;
                        tx_count.fetch_add(1, Relaxed);
                    } else {
                        break;
                    }
                }

                while let Some(pkt) = rx_q.pop() {
                    let now_ns = start.elapsed().as_nanos() as u64;
                    record_rtt(&pkt, now_ns, &rtt_sum, &rtt_n, &rtt_max);
                    rx_count.fetch_add(1, Relaxed);
                    inflight = inflight.saturating_sub(1);
                }

                std::hint::spin_loop();
            }
        }
    }
}

fn main() {
    let args = parse_args();

    let shutdown = Arc::new(AtomicBool::new(false));
    SHUTDOWN.set(shutdown.clone()).ok();
    unsafe {
        libc::signal(libc::SIGINT, sigint_handler as *const () as libc::sighandler_t);
    }

    let tx_total: Arc<AtomicU64> = Arc::new(AtomicU64::new(0));
    let rx_total: Arc<AtomicU64> = Arc::new(AtomicU64::new(0));
    let rtt_sum: Arc<AtomicU64> = Arc::new(AtomicU64::new(0));
    let rtt_n: Arc<AtomicU64> = Arc::new(AtomicU64::new(0));
    let rtt_max: Arc<AtomicU64> = Arc::new(AtomicU64::new(0));

    let mut workers = Vec::new();
    for i in 0..args.threads {
        let shutdown = shutdown.clone();
        let tx_count = tx_total.clone();
        let rx_count = rx_total.clone();
        let rtt_sum = rtt_sum.clone();
        let rtt_n = rtt_n.clone();
        let rtt_max = rtt_max.clone();
        let target = args.target;
        let mode = args.mode;
        let rate = args.rate;
        let size = args.size;
        let window = args.window;
        let socket = args.socket;

        workers.push(std::thread::spawn(move || {
            match socket {
                Socket::Os => {
                    let tile = Arc::new(
                        NetworkTileImpl::<_, Spin, _>::new(
                            || OsSocket::bind("0.0.0.0:0".parse().unwrap(), 0)
                                .unwrap_or_else(|e| { eprintln!("bind: {e}"); std::process::exit(1) }),
                            FourTupleRouter, 1,
                        ),
                    );
                    Arc::clone(&tile).start(i);
                    run_sender(tile, target, mode, rate, size, window, shutdown,
                               tx_count, rx_count, rtt_sum, rtt_n, rtt_max);
                }
                Socket::IoUring => {
                    let tile = Arc::new(
                        NetworkTileImpl::<_, Spin, _>::new(
                            || IoUringSocket::bind("0.0.0.0:0".parse().unwrap(), 0)
                                .unwrap_or_else(|e| { eprintln!("bind: {e}"); std::process::exit(1) }),
                            FourTupleRouter, 1,
                        ),
                    );
                    Arc::clone(&tile).start(i);
                    run_sender(tile, target, mode, rate, size, window, shutdown,
                               tx_count, rx_count, rtt_sum, rtt_n, rtt_max);
                }
            }
        }));
    }

    let shutdown_rep = shutdown.clone();
    let tx_rep = tx_total.clone();
    let rx_rep = rx_total.clone();
    let rtt_sum_rep = rtt_sum.clone();
    let rtt_n_rep = rtt_n.clone();
    let rtt_max_rep = rtt_max.clone();
    let mode = args.mode;
    let reporter = std::thread::spawn(move || {
        let mut prev_tx = 0u64;
        let mut prev_rx = 0u64;
        while !shutdown_rep.load(Relaxed) {
            std::thread::sleep(Duration::from_secs(1));
            let tx = tx_rep.load(Relaxed);
            let rx = rx_rep.load(Relaxed);
            let dtx = tx - prev_tx;
            let drx = rx - prev_rx;
            prev_tx = tx;
            prev_rx = rx;
            if mode == Mode::Pingpong {
                let n = rtt_n_rep.load(Relaxed);
                let avg_us = if n > 0 { rtt_sum_rep.load(Relaxed) / n / 1_000 } else { 0 };
                let max_us = rtt_max_rep.load(Relaxed) / 1_000;
                println!(
                    "tx={:.2} Mpps rx={:.2} Mpps avg_rtt={}us max_rtt={}us total_tx={}",
                    dtx as f64 / 1e6, drx as f64 / 1e6, avg_us, max_us, tx,
                );
            } else {
                println!("tx={:.2} Mpps total_tx={}", dtx as f64 / 1e6, tx);
            }
        }
    });

    if args.duration > 0 {
        std::thread::sleep(Duration::from_secs(args.duration));
        shutdown.store(true, Relaxed);
    } else {
        while !shutdown.load(Relaxed) {
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    for w in workers {
        let _ = w.join();
    }
    let _ = reporter.join();

    let tx = tx_total.load(Relaxed);
    let rx = rx_total.load(Relaxed);
    if args.mode == Mode::Pingpong {
        let n = rtt_n.load(Relaxed);
        let avg_us = if n > 0 { rtt_sum.load(Relaxed) / n / 1_000 } else { 0 };
        let max_us = rtt_max.load(Relaxed) / 1_000;
        println!("final: total_tx={tx} total_rx={rx} avg_rtt={avg_us}us max_rtt={max_us}us");
    } else {
        println!("final: total_tx={tx}");
    }
}
