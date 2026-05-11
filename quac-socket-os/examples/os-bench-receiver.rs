use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use quac_socket::{PacketBufMut, PacketSocket, RecvMeta, RxPool, ScatterGather, Segment, Transmit};
use quac_socket_os::{OsBuf, OsBufMut, OsConfig, OsSocket};

const BATCH: usize = OsSocket::MAX_BATCH;

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Count,
    Reflect,
}

struct Args {
    bind: SocketAddr,
    /// Explicit `--threads` override. `None` means "1 by default; or
    /// `nic_queue_count(bind_ip)` if `incoming_cpu` is on".
    threads: Option<usize>,
    mode: Mode,
    duration: u64,
    recv_ecn: bool,
    recv_dst_ip: bool,
    /// `--incoming-cpu`: opt in to per-queue NIC alignment (sets
    /// `SO_INCOMING_CPU` and pins the worker thread to the queue's CPU).
    /// Also auto-defaults `--threads` to the NIC queue count when unset.
    incoming_cpu: bool,
}

impl Default for Args {
    fn default() -> Self {
        Self {
            bind: "0.0.0.0:9999".parse().unwrap(),
            threads: None,
            mode: Mode::Count,
            duration: 0,
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

/// Group `bind`'s NIC queues by IRQ CPU (recursing through bond slaves).
/// Empty when `--incoming-cpu` is off or the lookup fails; the caller
/// then falls back to the legacy `--threads` path.
fn compute_cpu_groups(
    bind: SocketAddr,
    incoming_cpu: bool,
) -> Vec<(u32, Vec<quac_socket::RxQueue>)> {
    if !incoming_cpu {
        return Vec::new();
    }
    let ip = bind.ip();
    if ip.is_unspecified() {
        eprintln!(
            "[bench] --incoming-cpu requires a non-wildcard --bind; falling back to --threads"
        );
        return Vec::new();
    }
    let iface = match quac_socket::nic::interface_for_addr(ip) {
        Ok(i) => i,
        Err(e) => {
            eprintln!(
                "[bench] could not resolve interface for {ip}: {e}; falling back to --threads"
            );
            return Vec::new();
        }
    };
    let queues = match quac_socket::nic::enumerate_rx_queues(&iface) {
        Ok(q) => q,
        Err(e) => {
            eprintln!("[bench] enumerate_rx_queues({iface}): {e}; falling back to --threads");
            return Vec::new();
        }
    };
    let groups = quac_socket::nic::coalesce_by_cpu(queues);
    eprintln!(
        "[bench] coalescing {} queues on {iface} into {} tiles by CPU",
        groups.iter().map(|(_, g)| g.len()).sum::<usize>(),
        groups.len()
    );
    groups
}

fn run_coalesced_recv_loop(
    socks: &mut [OsSocket],
    mode: Mode,
    shutdown: Arc<AtomicBool>,
    rx_count: Arc<AtomicU64>,
    tx_count: Arc<AtomicU64>,
) {
    let mut bufs: Vec<OsBufMut> = Vec::with_capacity(BATCH);
    let mut meta = vec![RecvMeta::default(); BATCH];
    let mut tx: Vec<Transmit<ScatterGather<OsBuf>>> = Vec::with_capacity(BATCH);

    while !shutdown.load(Relaxed) {
        let mut did_work = false;
        for sock in socks.iter_mut() {
            if bufs.len() < BATCH {
                sock.rx_pool().alloc(
                    sock.rx_pool().max_payload_size(),
                    BATCH - bufs.len(),
                    &mut bufs,
                );
            }
            let n = match sock.recv(&mut meta[..], &mut bufs[..]) {
                Ok(n) => n,
                Err(_) => continue,
            };
            if n == 0 {
                continue;
            }
            did_work = true;
            rx_count.fetch_add(n as u64, Relaxed);
            match mode {
                Mode::Count => { /* leave bufs in place; recv sets filled() per call */ }
                Mode::Reflect => {
                    for (i, buf) in bufs.drain(..n).enumerate() {
                        let len = meta[i].len as u32;
                        let frozen = buf.freeze();
                        let seg = unsafe { Segment::new_unchecked(frozen, 0, len) };
                        tx.push(Transmit::new(ScatterGather::single(seg), meta[i].src));
                    }
                    let sent = sock.send(&mut tx).unwrap_or(0);
                    tx_count.fetch_add(sent as u64, Relaxed);
                    tx.clear();
                    sock.drain_completions();
                }
            }
        }
        if !did_work {
            std::thread::yield_now();
        }
    }
}

/// Decide how many tile threads to spawn:
/// - If `--threads N` was given, honour it.
/// - Else if `--incoming-cpu` is on AND the bind IP is non-wildcard,
///   default to that NIC's RX queue count (one socket per queue, the
///   configuration `SO_INCOMING_CPU` is designed for).
/// - Else fall back to 1.
fn resolve_thread_count(requested: Option<usize>, bind: SocketAddr, incoming_cpu: bool) -> usize {
    if let Some(n) = requested {
        return n.max(1);
    }
    #[cfg(target_os = "linux")]
    if incoming_cpu {
        let ip = bind.ip();
        if !ip.is_unspecified() {
            match quac_socket::nic::interface_for_addr(ip)
                .and_then(|iface| quac_socket::nic::nic_queue_count(&iface))
            {
                Ok(n) => {
                    eprintln!("[bench] auto --threads={n} from NIC for bind {ip}");
                    return n as usize;
                }
                Err(e) => {
                    eprintln!("[bench] could not auto-detect NIC queue count for {ip}: {e}; defaulting to 1");
                }
            }
        }
    }
    let _ = bind;
    let _ = incoming_cpu;
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
            "--bind" => {
                a.bind = v()
                    .parse()
                    .unwrap_or_else(|_| die("--bind needs addr:port"));
            }
            "--threads" => {
                let n: usize = v()
                    .parse()
                    .unwrap_or_else(|_| die("--threads needs a number"));
                a.threads = Some(n);
            }
            "--mode" => {
                a.mode = match v().as_str() {
                    "count" => Mode::Count,
                    "reflect" => Mode::Reflect,
                    s => die(&format!("unknown mode: {s}")),
                };
            }
            "--duration" => {
                a.duration = v()
                    .parse()
                    .unwrap_or_else(|_| die("--duration needs a number"));
            }
            "--no-recv-ecn" => {
                a.recv_ecn = false;
            }
            "--no-recv-dst-ip" => {
                a.recv_dst_ip = false;
            }
            "--incoming-cpu" => {
                a.incoming_cpu = true;
            }
            "--help" | "-h" => {
                println!(
                    "Usage: bench-receiver [--bind addr:port] [--threads N] \
                     [--mode count|reflect] [--duration secs] \
                     [--no-recv-ecn] [--no-recv-dst-ip] [--incoming-cpu]"
                );
                std::process::exit(0);
            }
            other => die(&format!("unknown arg: {other}")),
        }
    }
    a
}

static SHUTDOWN: OnceLock<Arc<AtomicBool>> = OnceLock::new();

#[cfg(unix)]
extern "C" fn sigint_handler(_: libc::c_int) {
    if let Some(flag) = SHUTDOWN.get() {
        flag.store(true, Relaxed);
    }
    unsafe { libc::signal(libc::SIGINT, libc::SIG_DFL) };
}

fn main() {
    let args = parse_args();

    let shutdown = Arc::new(AtomicBool::new(false));
    SHUTDOWN.set(shutdown.clone()).ok();

    #[cfg(unix)]
    unsafe {
        libc::signal(
            libc::SIGINT,
            sigint_handler as *const () as libc::sighandler_t,
        );
    }

    let rx_total: Arc<AtomicU64> = Arc::new(AtomicU64::new(0));
    let tx_total: Arc<AtomicU64> = Arc::new(AtomicU64::new(0));

    // --incoming-cpu path: one worker per CPU group, each owning all
    // sockets whose RX queue maps to that CPU. Otherwise: legacy
    // single-socket-per-thread driven by `--threads`.
    let cpu_groups: Vec<(u32, Vec<quac_socket::RxQueue>)> =
        compute_cpu_groups(args.bind, args.incoming_cpu);

    let mut workers = Vec::new();
    if !cpu_groups.is_empty() {
        for (cpu, group) in cpu_groups {
            let shutdown = shutdown.clone();
            let rx_count = rx_total.clone();
            let tx_count = tx_total.clone();
            let bind = args.bind;
            let mode = args.mode;
            let recv_ecn = args.recv_ecn;
            let recv_dst_ip = args.recv_dst_ip;
            let group_label = format!(
                "cpu{cpu} ({} {})",
                group.len(),
                if group.len() == 1 { "queue" } else { "queues" }
            );
            workers.push(std::thread::spawn(move || {
                eprintln!(
                    "[bench] tile {group_label}: queues={:?}",
                    group
                        .iter()
                        .map(|q| (&q.iface, q.queue_id, q.flat_index))
                        .collect::<Vec<_>>()
                );
                if let Err(e) = quac_socket::cpu::pin_current_thread_to_cpu(cpu) {
                    eprintln!("[bench] pin to cpu {cpu} failed: {e}");
                }
                let mut socks: Vec<OsSocket> = group
                    .iter()
                    .map(|q| {
                        let cfg = OsConfig::builder()
                            .reuseport(true)
                            .recv_ecn(recv_ecn)
                            .recv_dst_ip(recv_dst_ip)
                            .incoming_cpu(true)
                            .build();
                        OsSocket::bind(bind, q.flat_index, cfg).unwrap_or_else(|e| {
                            eprintln!("bind {bind} flat_q={}: {e}", q.flat_index);
                            std::process::exit(1);
                        })
                    })
                    .collect();
                run_coalesced_recv_loop(&mut socks, mode, shutdown, rx_count, tx_count);
            }));
        }
    } else {
        let threads = resolve_thread_count(args.threads, args.bind, args.incoming_cpu);
        for i in 0..threads {
            let shutdown = shutdown.clone();
            let rx_count = rx_total.clone();
            let tx_count = tx_total.clone();
            let bind = args.bind;
            let mode = args.mode;
            let recv_ecn = args.recv_ecn;
            let recv_dst_ip = args.recv_dst_ip;
            let queue_id = i as u16;

            workers.push(std::thread::spawn(move || {
                let cfg = OsConfig::builder()
                    .reuseport(true)
                    .recv_ecn(recv_ecn)
                    .recv_dst_ip(recv_dst_ip)
                    .incoming_cpu(false)
                    .build();
                let mut sock = OsSocket::bind(bind, queue_id, cfg).unwrap_or_else(|e| {
                    eprintln!("bind_reuseport {bind}: {e}");
                    std::process::exit(1);
                });

                let mut bufs: Vec<OsBufMut> = Vec::with_capacity(BATCH);
                let mut meta = vec![RecvMeta::default(); BATCH];
                let mut tx: Vec<Transmit<ScatterGather<OsBuf>>> = Vec::with_capacity(BATCH);

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
                        std::thread::yield_now();
                        continue;
                    }
                    rx_count.fetch_add(n as u64, Relaxed);

                    match mode {
                        Mode::Count => {
                            // Keep the buffers in place. The kernel writes from
                            // iov offset 0 regardless of prior fill length, and
                            // set_filled(msg_len) commits the correct length after
                            // each recv -- no need to clear or re-alloc. Saves
                            // MAX_BATCH MPSC pushes + pops per round.
                        }
                        Mode::Reflect => {
                            for (i, buf) in bufs.drain(..n).enumerate() {
                                let len = meta[i].len as u32;
                                let frozen = buf.freeze();
                                let seg = unsafe { Segment::new_unchecked(frozen, 0, len) };
                                tx.push(Transmit::new(ScatterGather::single(seg), meta[i].src));
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

    // Reporter: wakes every second to print per-interval and cumulative stats.
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
