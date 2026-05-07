//! AF_XDP variant of `os-bench-sender`. Same CLI + adds:
//!   --iface NAME    interface to send from (REQUIRED)
//!   --bind addr:port  source IP+port the AF_XDP socket binds to
//!                    (REQUIRED — used as the IP/UDP source on outbound)
//!   --queue ID       first hardware queue; thread N gets ID+N
//!   --xdp-mode zc|copy   default zc
//!   --attach default|skb|drv   default default

use std::ffi::CString;
use std::io;
use std::mem::MaybeUninit;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use quac_socket::{
    PacketBufMut, PacketSocket, RecvMeta, RxPool, ScatterGather, Segment, Transmit, TxPool,
};
use quac_socket_xdp::{
    AttachMode, RingSizes, XdpConfig, XdpMode, XdpRxBufMut, XdpSocket, XdpTxBuf, XdpTxBufMut,
};

const BATCH: usize = XdpSocket::MAX_BATCH;

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Rate,
    Pingpong,
}

struct Args {
    target: SocketAddr,
    bind: SocketAddr,
    iface: String,
    queue: u16,
    threads: usize,
    mode: Mode,
    rate: u64,
    size: usize,
    window: usize,
    duration: u64,
    xdp_mode: XdpMode,
    attach: AttachMode,
}

impl Default for Args {
    fn default() -> Self {
        Self {
            target: "10.99.0.1:9999".parse().unwrap(),
            bind: "10.99.0.2:0".parse().unwrap(),
            iface: String::new(),
            queue: 0,
            threads: 1,
            mode: Mode::Rate,
            rate: 0,
            size: 64,
            window: 1,
            duration: 10,
            xdp_mode: XdpMode::ZeroCopy,
            attach: AttachMode::Default,
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
            "--target" => a.target = v().parse().unwrap_or_else(|_| die("--target needs addr:port")),
            "--bind" => a.bind = v().parse().unwrap_or_else(|_| die("--bind needs addr:port")),
            "--iface" => a.iface = v(),
            "--queue" => a.queue = v().parse().unwrap_or_else(|_| die("--queue needs u16")),
            "--threads" => a.threads = v().parse().unwrap_or_else(|_| die("--threads needs usize")),
            "--mode" => {
                a.mode = match v().as_str() {
                    "rate" => Mode::Rate,
                    "pingpong" => Mode::Pingpong,
                    s => die(&format!("unknown mode: {s}")),
                }
            }
            "--rate" => a.rate = v().parse().unwrap_or_else(|_| die("--rate needs u64")),
            "--size" => a.size = v().parse().unwrap_or_else(|_| die("--size needs usize")),
            "--window" => a.window = v().parse().unwrap_or_else(|_| die("--window needs usize")),
            "--duration" => a.duration = v().parse().unwrap_or_else(|_| die("--duration needs u64")),
            "--xdp-mode" => {
                a.xdp_mode = match v().as_str() {
                    "zc" | "zerocopy" => XdpMode::ZeroCopy,
                    "copy" => XdpMode::Copy,
                    s => die(&format!("unknown xdp-mode: {s}")),
                }
            }
            "--attach" => {
                a.attach = match v().as_str() {
                    "default" => AttachMode::Default,
                    "skb" => AttachMode::Skb,
                    "drv" => AttachMode::Drv,
                    "hw" => AttachMode::Hw,
                    s => die(&format!("unknown attach mode: {s}")),
                }
            }
            "--help" | "-h" => {
                println!(
                    "Usage: xdp-bench-sender --iface NAME [--target addr:port] \
                     [--bind addr:port] [--queue ID] [--threads N] \
                     [--mode rate|pingpong] [--rate pps] [--size bytes] [--window N] \
                     [--duration secs] [--xdp-mode zc|copy] [--attach default|skb|drv|hw]"
                );
                std::process::exit(0);
            }
            other => die(&format!("unknown arg: {other}")),
        }
    }
    if a.iface.is_empty() {
        die("--iface NAME is required");
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

fn if_name_to_index(name: &str) -> io::Result<u32> {
    let c = CString::new(name).map_err(|_| io::Error::other("interface name has NUL"))?;
    let idx = unsafe { libc::if_nametoindex(c.as_ptr()) };
    if idx == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(idx)
    }
}

/// Allocate a Tx buf, fill `size` bytes (8-byte LE timestamp at the start
/// when the buf is large enough; zero-padded otherwise), freeze, and wrap
/// in a `Transmit` ready for `send`.
fn make_packet(
    sock: &XdpSocket,
    cache: &mut Vec<XdpTxBufMut>,
    target: SocketAddr,
    size: usize,
    ts_ns: u64,
) -> Option<Transmit<ScatterGather<XdpTxBuf>>> {
    if cache.is_empty() {
        sock.tx_pool().alloc(size, BATCH, cache);
        if cache.is_empty() {
            return None; // tx pool exhausted; caller should drain completions
        }
    }
    let mut buf = cache.pop().unwrap();
    let uninit = buf.uninit_mut();
    let fill = size.min(uninit.len());
    if fill >= 8 {
        for (i, b) in ts_ns.to_le_bytes().iter().enumerate() {
            uninit[i] = MaybeUninit::new(*b);
        }
        uninit[8..fill].fill(MaybeUninit::new(0));
    } else {
        uninit[..fill].fill(MaybeUninit::new(0));
    }
    unsafe { buf.set_filled(fill) };
    let frozen = buf.freeze();
    let seg = unsafe { Segment::new_unchecked(frozen, 0, fill as u32) };
    Some(Transmit::new(ScatterGather::single(seg), target))
}

fn main() {
    let args = parse_args();
    let if_index = if_name_to_index(&args.iface)
        .unwrap_or_else(|e| die(&format!("if_nametoindex({}): {e}", args.iface)));

    let shutdown = Arc::new(AtomicBool::new(false));
    SHUTDOWN.set(shutdown.clone()).ok();
    unsafe { libc::signal(libc::SIGINT, sigint_handler as *const () as libc::sighandler_t) };

    let tx_total: Arc<AtomicU64> = Arc::new(AtomicU64::new(0));
    let rx_total: Arc<AtomicU64> = Arc::new(AtomicU64::new(0));
    let rtt_sum: Arc<AtomicU64> = Arc::new(AtomicU64::new(0));
    let rtt_n: Arc<AtomicU64> = Arc::new(AtomicU64::new(0));
    let rtt_max: Arc<AtomicU64> = Arc::new(AtomicU64::new(0));

    let cfg = XdpConfig::builder()
        .ring_sizes(RingSizes::default())
        .frame_count(4096)
        .frame_size(2048)
        .mode(args.xdp_mode)
        .attach_mode(args.attach)
        .build();

    let mut workers = Vec::new();
    for t in 0..args.threads {
        let shutdown = shutdown.clone();
        let tx_count = tx_total.clone();
        let rx_count = rx_total.clone();
        let rtt_sum = rtt_sum.clone();
        let rtt_n = rtt_n.clone();
        let rtt_max = rtt_max.clone();
        let target = args.target;
        let bind = args.bind;
        let mode = args.mode;
        let rate = args.rate;
        let size = args.size;
        let window = args.window;
        let queue_id = args.queue + t as u16;

        workers.push(std::thread::spawn(move || {
            let mut sock = XdpSocket::with_interface(if_index, queue_id, bind.ip(), bind.port(), cfg)
                .unwrap_or_else(|e| {
                    eprintln!("[t{t}] XdpSocket::with_interface(if_index={if_index}, queue={queue_id}): {e}");
                    std::process::exit(1);
                });

            let mut tx: Vec<Transmit<ScatterGather<XdpTxBuf>>> = Vec::with_capacity(BATCH);
            let mut cache: Vec<XdpTxBufMut> = Vec::with_capacity(BATCH);

            match mode {
                Mode::Rate => {
                    let start = Instant::now();
                    let mut total_sent = 0u64;
                    let interval_ns = if rate > 0 { 1_000_000_000.0 / rate as f64 } else { 0.0 };

                    while !shutdown.load(Relaxed) {
                        for _ in 0..BATCH {
                            let Some(t) = make_packet(&sock, &mut cache, target, size, 0) else {
                                break;
                            };
                            tx.push(t);
                        }

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

                        let n = sock.send(&mut tx).unwrap_or(0);
                        total_sent += n as u64;
                        tx_count.fetch_add(n as u64, Relaxed);
                        tx.clear();
                        sock.drain_completions();
                    }
                }

                Mode::Pingpong => {
                    let start = Instant::now();
                    let now_ns = || start.elapsed().as_nanos() as u64;
                    let mut inflight: usize = 0;
                    let mut meta = vec![RecvMeta::default(); BATCH];
                    let mut rx_bufs: Vec<XdpRxBufMut> = Vec::with_capacity(BATCH);

                    while !shutdown.load(Relaxed) {
                        while inflight < window {
                            let Some(t) = make_packet(&sock, &mut cache, target, size, now_ns()) else {
                                break;
                            };
                            tx.push(t);
                            inflight += 1;
                        }

                        if !tx.is_empty() {
                            let n = sock.send(&mut tx).unwrap_or(0);
                            tx_count.fetch_add(n as u64, Relaxed);
                            inflight -= tx.len() - n;
                            tx.clear();
                        }

                        if rx_bufs.len() < BATCH {
                            sock.rx_pool().alloc(
                                sock.rx_pool().max_payload_size(),
                                BATCH - rx_bufs.len(),
                                &mut rx_bufs,
                            );
                        }
                        let m = sock.recv(&mut meta[..], &mut rx_bufs[..]).unwrap_or(0);
                        if m > 0 {
                            let now = now_ns();
                            for buf in rx_bufs.iter().take(m) {
                                let bytes = buf.filled();
                                if bytes.len() >= 8 {
                                    let ts = u64::from_le_bytes(bytes[..8].try_into().unwrap());
                                    if let Some(rtt) = now.checked_sub(ts) {
                                        rtt_sum.fetch_add(rtt, Relaxed);
                                        rtt_n.fetch_add(1, Relaxed);
                                        rtt_max.fetch_max(rtt, Relaxed);
                                    }
                                }
                            }
                            rx_count.fetch_add(m as u64, Relaxed);
                            inflight = inflight.saturating_sub(m);
                            rx_bufs.drain(..m);
                        }
                        sock.drain_completions();
                    }
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
