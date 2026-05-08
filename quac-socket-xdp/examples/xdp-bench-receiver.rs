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
    /// Explicit `--threads` override. `None` means "1 by default; or
    /// `nic_queue_count(iface)` if `incoming_cpu` is on".
    threads: Option<usize>,
    mode: Mode,
    duration: u64,
    xdp_mode: XdpMode,
    attach: AttachMode,
    recv_ecn: bool,
    recv_dst_ip: bool,
    /// `--incoming-cpu`: opt in to per-queue NIC alignment. AF_XDP doesn't
    /// have a `SO_INCOMING_CPU` analogue (the kernel UDP stack is
    /// bypassed), but the worker thread is still pinned to the queue's
    /// IRQ CPU, and `--threads` defaults to `nic_queue_count(--iface)`.
    incoming_cpu: bool,
}

impl Default for Args {
    fn default() -> Self {
        Self {
            bind: "10.99.0.1:9999".parse().unwrap(),
            iface: String::new(),
            queue: 0,
            threads: None,
            mode: Mode::Count,
            duration: 0,
            xdp_mode: XdpMode::ZeroCopy,
            attach: AttachMode::Default,
            recv_ecn: true,
            recv_dst_ip: true,
            incoming_cpu: false,
        }
    }
}

fn die(msg: &str) -> ! {
    eprintln!("error: {msg}");
    std::process::exit(1);
}

/// Default `--threads` to the total NIC queue count (across bond slaves
/// for bonded ifaces) when `--incoming-cpu` is set; otherwise 1.
fn resolve_thread_count(requested: Option<usize>, iface: &str, incoming_cpu: bool) -> usize {
    if let Some(n) = requested {
        return n.max(1);
    }
    if incoming_cpu {
        match quac_socket::nic::nic_queue_count(iface) {
            Ok(n) => {
                eprintln!("[bench] auto --threads={n} from NIC queues on {iface}");
                return n as usize;
            }
            Err(e) => {
                eprintln!("[bench] could not auto-detect NIC queue count for {iface}: {e}; defaulting to 1");
            }
        }
    }
    1
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
            "--threads" => {
                let n: usize = v().parse().unwrap_or_else(|_| die("--threads needs usize"));
                a.threads = Some(n);
            }
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
            "--no-recv-ecn" => a.recv_ecn = false,
            "--no-recv-dst-ip" => a.recv_dst_ip = false,
            "--incoming-cpu" => a.incoming_cpu = true,
            "--help" | "-h" => {
                println!(
                    "Usage: xdp-bench-receiver --iface NAME [--bind addr:port] [--queue ID] \
                     [--threads N] [--mode count|reflect] [--duration secs] \
                     [--xdp-mode zc|copy] [--attach default|skb|drv|hw] \
                     [--no-recv-ecn] [--no-recv-dst-ip] [--incoming-cpu]"
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

    // For non-coalesced binds (without --incoming-cpu) we still need a
    // (real-iface, queue_id) slot per thread; AF_XDP can't bind to a
    // bond directly. Build the flat list once at startup -- for non-bonds
    // it's just (args.iface, 0..N).
    let queue_slots: Vec<(String, u16)> =
        match quac_socket::nic::bond_slaves(&args.iface).unwrap_or(None) {
            Some(slaves) => {
                let mut out = Vec::new();
                for slave in &slaves {
                    let n = quac_socket::nic::nic_queue_count(slave)
                        .unwrap_or_else(|e| die(&format!("nic_queue_count({slave}): {e}")));
                    for q in 0..n as u16 {
                        out.push((slave.clone(), q));
                    }
                }
                if out.is_empty() {
                    die(&format!("bond {} has no slave queues", args.iface));
                }
                out
            }
            None => {
                let n = quac_socket::nic::nic_queue_count(&args.iface)
                    .unwrap_or_else(|e| die(&format!("nic_queue_count({}): {e}", args.iface)));
                (0..n as u16).map(|q| (args.iface.clone(), q)).collect()
            }
        };

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
        .recv_ecn(args.recv_ecn)
        .recv_dst_ip(args.recv_dst_ip)
        .build();

    let mut workers = Vec::new();
    {
        let threads = resolve_thread_count(args.threads, &args.iface, args.incoming_cpu);
        let incoming_cpu = args.incoming_cpu;
        for t in 0..threads {
            let shutdown = shutdown.clone();
            let rx_count = rx_total.clone();
            let tx_count = tx_total.clone();
            let bind = args.bind;
            let mode = args.mode;

            let slot = args.queue as usize + t;
            if slot >= queue_slots.len() {
                die(&format!(
                    "--threads ({threads}) + --queue ({}) exceeds {} available NIC queues on {}",
                    args.queue, queue_slots.len(), args.iface,
                ));
            }
            let (slave_iface, queue_id) = queue_slots[slot].clone();
            let slave_idx = if_name_to_index(&slave_iface)
                .unwrap_or_else(|e| die(&format!("if_nametoindex({slave_iface}): {e}")));

            workers.push(std::thread::spawn(move || {
                let mut sock = XdpSocket::with_interface(slave_idx, queue_id, bind.ip(), bind.port(), cfg)
                    .unwrap_or_else(|e| {
                        eprintln!("[t{t}] XdpSocket::with_interface(iface={slave_iface}, queue={queue_id}): {e}");
                        std::process::exit(1);
                    });
                if incoming_cpu {
                    if let Err(e) = sock.pin_current_thread_to_queue_cpu() {
                        eprintln!("[t{t}] pin_current_thread_to_queue_cpu skipped: {e}");
                    }
                }

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
                            bufs.drain(..n);
                        }
                        Mode::Reflect => {
                            for (i, rx_buf) in bufs.drain(..n).enumerate() {
                                let dst = meta[i].src;
                                let len = meta[i].len as u32;
                                let tx_buf_mut = match sock.tx_pool().from_rx(rx_buf) {
                                    Ok(b) => b,
                                    Err(_rx) => continue,
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
