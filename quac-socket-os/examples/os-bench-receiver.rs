use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use quac_socket::{
    PacketBufMut, PacketSocket, RecvMeta, RxPool, ScatterGather, Segment, Transmit,
};
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

    let threads = resolve_thread_count(args.threads, args.bind, args.incoming_cpu);

    let mut workers = Vec::new();
    for i in 0..threads {
        let shutdown = shutdown.clone();
        let rx_count = rx_total.clone();
        let tx_count = tx_total.clone();
        let bind = args.bind;
        let mode = args.mode;
        let recv_ecn = args.recv_ecn;
        let recv_dst_ip = args.recv_dst_ip;
        let incoming_cpu = args.incoming_cpu;
        let queue_id = i as u16;

        workers.push(std::thread::spawn(move || {
            let cfg = OsConfig::builder()
                .reuseport(true)
                .recv_ecn(recv_ecn)
                .recv_dst_ip(recv_dst_ip)
                .incoming_cpu(incoming_cpu)
                .build();
            let mut sock = OsSocket::bind(bind, queue_id, cfg).unwrap_or_else(|e| {
                eprintln!("bind_reuseport {bind}: {e}");
                std::process::exit(1);
            });
            #[cfg(target_os = "linux")]
            if incoming_cpu {
                if let Err(e) = sock.pin_current_thread_to_queue_cpu() {
                    eprintln!("[t{i}] pin_current_thread_to_queue_cpu skipped: {e}");
                }
            }

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
