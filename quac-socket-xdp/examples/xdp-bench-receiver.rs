//! AF_XDP variant of `os-bench-receiver`. Same CLI flags + adds:
//!   --iface NAME    interface to bind to (REQUIRED)
//!   --queue ID      first hardware queue to use; thread N gets ID+N
//!   --xdp-mode zc|copy   default zc
//!   --attach default|skb|drv   default default

use std::ffi::CString;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use quac_socket::{
    PacketBufMut, PacketSocket, RecvMeta, RxPool, ScatterGather, Segment, Transmit, TxPool,
};
use quac_socket_xdp::{
    AttachMode, RingSizes, XdpConfig, XdpMode, XdpRxBufMut, XdpSocket, XdpTxBuf,
};

const BATCH: usize = XdpSocket::MAX_BATCH;

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Count,
    Reflect,
}

struct Args {
    bind: SocketAddr,
    iface: String,
    queue: u16,
    threads: usize,
    mode: Mode,
    duration: u64,
    xdp_mode: XdpMode,
    attach: AttachMode,
}

impl Default for Args {
    fn default() -> Self {
        Self {
            bind: "10.99.0.1:9999".parse().unwrap(),
            iface: String::new(),
            queue: 0,
            threads: 1,
            mode: Mode::Count,
            duration: 0,
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
            "--bind" => a.bind = v().parse().unwrap_or_else(|_| die("--bind needs addr:port")),
            "--iface" => a.iface = v(),
            "--queue" => a.queue = v().parse().unwrap_or_else(|_| die("--queue needs u16")),
            "--threads" => a.threads = v().parse().unwrap_or_else(|_| die("--threads needs usize")),
            "--mode" => {
                a.mode = match v().as_str() {
                    "count" => Mode::Count,
                    "reflect" => Mode::Reflect,
                    s => die(&format!("unknown mode: {s}")),
                }
            }
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
                    "Usage: xdp-bench-receiver --iface NAME [--bind addr:port] [--queue ID] \
                     [--threads N] [--mode count|reflect] [--duration secs] \
                     [--xdp-mode zc|copy] [--attach default|skb|drv|hw]"
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

fn main() {
    let args = parse_args();
    let if_index = if_name_to_index(&args.iface)
        .unwrap_or_else(|e| die(&format!("if_nametoindex({}): {e}", args.iface)));

    let shutdown = Arc::new(AtomicBool::new(false));
    SHUTDOWN.set(shutdown.clone()).ok();
    unsafe { libc::signal(libc::SIGINT, sigint_handler as *const () as libc::sighandler_t) };

    let rx_total: Arc<AtomicU64> = Arc::new(AtomicU64::new(0));
    let tx_total: Arc<AtomicU64> = Arc::new(AtomicU64::new(0));
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
        let rx_count = rx_total.clone();
        let tx_count = tx_total.clone();
        let bind = args.bind;
        let mode = args.mode;
        let queue_id = args.queue + t as u16;

        workers.push(std::thread::spawn(move || {
            let mut sock = XdpSocket::with_interface(if_index, queue_id, bind.ip(), bind.port(), cfg)
                .unwrap_or_else(|e| {
                    eprintln!("[t{t}] XdpSocket::with_interface(if_index={if_index}, queue={queue_id}): {e}");
                    std::process::exit(1);
                });

            let mut bufs: Vec<XdpRxBufMut> = Vec::with_capacity(BATCH);
            let mut meta = vec![RecvMeta::default(); BATCH];
            let mut tx: Vec<Transmit<ScatterGather<XdpTxBuf>>> = Vec::with_capacity(BATCH);

            while !shutdown.load(Relaxed) {
                if bufs.len() < BATCH {
                    sock.rx_pool().alloc(
                        sock.rx_pool().max_payload_size(),
                        BATCH - bufs.len(),
                        &mut bufs,
                    );
                }

                let n = match sock.recv(&mut meta[..], &mut bufs[..]) {
                    Ok(n) => n,
                    Err(_) => {
                        std::thread::yield_now();
                        continue;
                    }
                };
                if n == 0 {
                    // Drain any TX completions that piled up while waiting.
                    sock.drain_completions();
                    std::thread::yield_now();
                    continue;
                }
                rx_count.fetch_add(n as u64, Relaxed);

                match mode {
                    Mode::Count => {
                        // Drop the buffers immediately so frames cycle back to
                        // the FILL ring via the reclaimer. Without this the
                        // pool fills up and the kernel starts dropping packets.
                        bufs.drain(..n);
                    }
                    Mode::Reflect => {
                        // Convert each Rx buf to a Tx buf via from_rx() (UNIFIED=false
                        // → copies payload into a fresh Tx frame), then echo back to
                        // the source. Drops the rx buffers on conversion success
                        // (returns frames to FILL).
                        for (i, rx_buf) in bufs.drain(..n).enumerate() {
                            let dst = meta[i].src;
                            let len = meta[i].len as u32;
                            let tx_buf_mut = match sock.tx_pool().from_rx(rx_buf) {
                                Ok(b) => b,
                                Err(_rx) => {
                                    // Tx pool exhausted — drop the rx buffer
                                    // (it's `_rx`, drops here, frame returns to FILL).
                                    continue;
                                }
                            };
                            let frozen = tx_buf_mut.freeze();
                            let seg = unsafe { Segment::new_unchecked(frozen, 0, len) };
                            tx.push(Transmit::new(ScatterGather::single(seg), dst));
                        }
                        let sent = sock.send(&mut tx).unwrap_or(0);
                        tx_count.fetch_add(sent as u64, Relaxed);
                        tx.clear();
                        sock.drain_completions();
                    }
                }
            }
        }));
    }

    let shutdown_rep = shutdown.clone();
    let rx_rep = rx_total.clone();
    let tx_rep = tx_total.clone();
    let reporter = std::thread::spawn(move || {
        let mut prev_rx = 0u64;
        let mut prev_tx = 0u64;
        while !shutdown_rep.load(Relaxed) {
            std::thread::sleep(Duration::from_secs(1));
            let rx = rx_rep.load(Relaxed);
            let tx = tx_rep.load(Relaxed);
            let drx = rx - prev_rx;
            let dtx = tx - prev_tx;
            prev_rx = rx;
            prev_tx = tx;
            println!(
                "rx={:.2} Mpps tx={:.2} Mpps total_rx={} total_tx={}",
                drx as f64 / 1e6,
                dtx as f64 / 1e6,
                rx,
                tx,
            );
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

    let rx = rx_total.load(Relaxed);
    let tx = tx_total.load(Relaxed);
    println!("final: total_rx={rx} total_tx={tx}");
}
