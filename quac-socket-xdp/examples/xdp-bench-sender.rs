//! AF_XDP variant of `os-bench-sender`. Same CLI + adds:
//!   --iface NAME    interface to send from (REQUIRED)
//!   --bind addr:port  source IP; workers use random ephemeral source ports.
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
use rand::seq::SliceRandom;

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
    /// Explicit `--threads` override. `None` means "1 by default; or
    /// `nic_queue_count(iface)` if `incoming_cpu` is on".
    threads: Option<usize>,
    mode: Mode,
    /// `None` blasts at full speed without reading any clocks.
    rate: Option<u64>,
    size: usize,
    window: usize,
    duration: u64,
    xdp_mode: XdpMode,
    attach: AttachMode,
    recv_ecn: bool,
    recv_dst_ip: bool,
    incoming_cpu: bool,
}

impl Default for Args {
    fn default() -> Self {
        Self {
            target: "10.99.0.1:9999".parse().unwrap(),
            bind: "10.99.0.2:0".parse().unwrap(),
            iface: String::new(),
            queue: 0,
            threads: None,
            mode: Mode::Rate,
            rate: None,
            size: 64,
            window: 1,
            duration: 10,
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

/// See identical helper in xdp-bench-receiver.rs. Auto-default only kicks
/// in when `--incoming-cpu` is set.
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
        let mut v = || {
            it.next()
                .unwrap_or_else(|| die(&format!("{k} needs a value")))
        };
        match k.as_str() {
            "--target" => {
                a.target = v()
                    .parse()
                    .unwrap_or_else(|_| die("--target needs addr:port"))
            }
            "--bind" => {
                a.bind = v()
                    .parse()
                    .unwrap_or_else(|_| die("--bind needs addr:port"))
            }
            "--iface" => a.iface = v(),
            "--queue" => a.queue = v().parse().unwrap_or_else(|_| die("--queue needs u16")),
            "--threads" => {
                let n: usize = v().parse().unwrap_or_else(|_| die("--threads needs usize"));
                a.threads = Some(n);
            }
            "--mode" => {
                a.mode = match v().as_str() {
                    "rate" => Mode::Rate,
                    "pingpong" => Mode::Pingpong,
                    s => die(&format!("unknown mode: {s}")),
                }
            }
            "--rate" => {
                let n: u64 = v().parse().unwrap_or_else(|_| die("--rate needs u64"));
                a.rate = Some(n);
            }
            "--size" => a.size = v().parse().unwrap_or_else(|_| die("--size needs usize")),
            "--window" => a.window = v().parse().unwrap_or_else(|_| die("--window needs usize")),
            "--duration" => {
                a.duration = v().parse().unwrap_or_else(|_| die("--duration needs u64"))
            }
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
                    "Usage: xdp-bench-sender --iface NAME [--target addr:port] \
                     [--bind src-ip:ignored-port] [--queue ID] [--threads N] \
                     [--mode rate|pingpong] [--rate pps] [--size bytes] [--window N] \
                     [--duration secs] [--xdp-mode zc|copy] [--attach default|skb|drv|hw] \
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

fn random_ephemeral_source_ports(threads: usize) -> Vec<u16> {
    let mut pool: Vec<u16> = (49152u16..=u16::MAX).collect();
    if threads > pool.len() {
        die(&format!(
            "--threads ({threads}) exceeds available ephemeral source ports ({})",
            pool.len()
        ));
    }

    pool.shuffle(&mut rand::thread_rng());
    pool.truncate(threads);
    pool
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

    // AF_XDP can't bind to a bond device directly; enumerate the slaves
    // (or yield a single (iface, queue) for non-bonds) and bind each
    // worker thread to a real slave's (if_index, queue_id).
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
    unsafe {
        libc::signal(
            libc::SIGINT,
            sigint_handler as *const () as libc::sighandler_t,
        )
    };

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
        .recv_ecn(args.recv_ecn)
        .recv_dst_ip(args.recv_dst_ip)
        .build();

    let threads = resolve_thread_count(args.threads, &args.iface, args.incoming_cpu);
    let incoming_cpu = args.incoming_cpu;
    let source_ports = random_ephemeral_source_ports(threads);

    let mut workers = Vec::new();
    for t in 0..threads {
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

        // Map this thread to a (slave_iface, queue_id) slot. AF_XDP binds
        // are exclusive per (if_index, queue_id), so threads + queue
        // offset must fit within the available slots.
        let slot = args.queue as usize + t;
        if slot >= queue_slots.len() {
            die(&format!(
                "--threads ({threads}) + --queue ({}) exceeds {} available NIC queues on {}",
                args.queue,
                queue_slots.len(),
                args.iface,
            ));
        }
        let (slave_iface, queue_id) = queue_slots[slot].clone();
        let slave_idx = if_name_to_index(&slave_iface)
            .unwrap_or_else(|e| die(&format!("if_nametoindex({slave_iface}): {e}")));

        // Per-thread source port: AF_XDP writes raw UDP headers. Contiguous
        // ports can alias badly under Toeplitz RSS, so workers draw unique
        // random ephemeral source ports at startup.
        let src_port = source_ports[t];

        workers.push(std::thread::spawn(move || {
            let mut sock = XdpSocket::with_interface(slave_idx, queue_id, bind.ip(), src_port, cfg)
                .unwrap_or_else(|e| {
                    eprintln!("[t{t}] XdpSocket::with_interface(iface={slave_iface}, queue={queue_id}): {e}");
                    std::process::exit(1);
                });
            if incoming_cpu {
                if let Err(e) = sock.pin_current_thread_to_queue_cpu() {
                    eprintln!("[t{t}] pin_current_thread_to_queue_cpu skipped: {e}");
                }
            }

            let mut tx: Vec<Transmit<ScatterGather<XdpTxBuf>>> = Vec::with_capacity(BATCH);
            let mut cache: Vec<XdpTxBufMut> = Vec::with_capacity(BATCH);

            match mode {
                Mode::Rate => {
                    // When `rate` is set, pace per-batch (one clock read per
                    // BATCH packets) and `thread::sleep` to the deadline --
                    // no spin tail, so we don't burn CPU on `clock_gettime`
                    // in a tight loop. When `rate` is `None`, no clock reads
                    // at all: just keep the wire saturated.
                    let pacer = rate.map(|r| {
                        let interval_ns = 1_000_000_000.0 / r as f64;
                        (Instant::now(), interval_ns, 0u64) // (start, ns/pkt, total_sent)
                    });
                    let mut pacer = pacer;

                    while !shutdown.load(Relaxed) {
                        for _ in 0..BATCH {
                            let Some(t) = make_packet(&sock, &mut cache, target, size, 0) else {
                                break;
                            };
                            tx.push(t);
                        }

                        if let Some((start, interval_ns, total_sent)) = pacer.as_ref() {
                            let target_ns = (*total_sent as f64 * *interval_ns) as u64;
                            let elapsed = start.elapsed().as_nanos() as u64;
                            if elapsed < target_ns {
                                std::thread::sleep(Duration::from_nanos(target_ns - elapsed));
                            }
                        }

                        let n = sock.send(&mut tx).unwrap_or(0);
                        if let Some((_, _, total_sent)) = pacer.as_mut() {
                            *total_sent += n as u64;
                        }
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
                let avg_us = if n > 0 {
                    rtt_sum_rep.load(Relaxed) / n / 1_000
                } else {
                    0
                };
                let max_us = rtt_max_rep.load(Relaxed) / 1_000;
                println!(
                    "tx={:.2} Mpps rx={:.2} Mpps avg_rtt={}us max_rtt={}us total_tx={}",
                    dtx as f64 / 1e6,
                    drx as f64 / 1e6,
                    avg_us,
                    max_us,
                    tx,
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
        let avg_us = if n > 0 {
            rtt_sum.load(Relaxed) / n / 1_000
        } else {
            0
        };
        let max_us = rtt_max.load(Relaxed) / 1_000;
        println!("final: total_tx={tx} total_rx={rx} avg_rtt={avg_us}us max_rtt={max_us}us");
    } else {
        println!("final: total_tx={tx}");
    }
}
