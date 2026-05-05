use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use quac_socket::{BufferPool, PacketBufMut, PacketSocket, ScatterGather, Segment, Transmit};
use quac_socket_iouring::{IoBuf, IoBufMut, IoUringSocket};

const BATCH: usize = IoUringSocket::MAX_BATCH;

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Count,
    Reflect,
}

struct Args {
    bind: SocketAddr,
    threads: usize,
    mode: Mode,
    duration: u64,
}

impl Default for Args {
    fn default() -> Self {
        Self {
            bind: "0.0.0.0:9999".parse().unwrap(),
            threads: 1,
            mode: Mode::Count,
            duration: 0,
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
                a.threads = v()
                    .parse()
                    .unwrap_or_else(|_| die("--threads needs a number"));
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
            "--help" | "-h" => {
                println!(
                    "Usage: bench-receiver [--bind addr:port] [--threads N] \
                     [--mode count|reflect] [--duration secs]"
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

fn main() {
    let args = parse_args();

    let shutdown = Arc::new(AtomicBool::new(false));
    SHUTDOWN.set(shutdown.clone()).ok();

    unsafe {
        libc::signal(
            libc::SIGINT,
            sigint_handler as *const () as libc::sighandler_t,
        );
    }

    let rx_total: Arc<AtomicU64> = Arc::new(AtomicU64::new(0));
    let tx_total: Arc<AtomicU64> = Arc::new(AtomicU64::new(0));

    let mut workers = Vec::new();
    for _ in 0..args.threads {
        let shutdown = shutdown.clone();
        let rx_count = rx_total.clone();
        let tx_count = tx_total.clone();
        let bind = args.bind;
        let mode = args.mode;

        workers.push(std::thread::spawn(move || {
            let mut sock = IoUringSocket::bind_reuseport(bind, 0).unwrap_or_else(|e| {
                eprintln!("bind_reuseport {bind}: {e}");
                std::process::exit(1);
            });

            use quac_socket::RecvMeta;

            let mut bufs: Vec<IoBufMut> = Vec::with_capacity(BATCH);
            let mut meta = vec![RecvMeta::default(); BATCH];
            let mut tx: Vec<Transmit<ScatterGather<IoBuf>>> = Vec::with_capacity(BATCH);

            while !shutdown.load(Relaxed) {
                if bufs.len() < BATCH {
                    sock.pool().alloc(
                        sock.pool().max_payload_size(),
                        BATCH - bufs.len(),
                        &mut bufs,
                    );
                }

                let n = sock.recv(&mut meta[..], &mut bufs[..]).unwrap_or(0);
                if n == 0 {
                    std::thread::yield_now();
                    continue;
                }
                rx_count.fetch_add(n as u64, Relaxed);

                match mode {
                    Mode::Count => {
                        // Keep the buffers in place. recv() calls set_filled(0)
                        // on each slot before writing, so no explicit reset is
                        // needed here. Saves MAX_BATCH Arc drops + allocs per round.
                    }
                    Mode::Reflect => {
                        for (i, buf) in bufs.drain(..n).enumerate() {
                            let len = meta[i].len as u32;
                            let frozen = buf.freeze();
                            let seg = unsafe { Segment::new_unchecked(frozen, 0, len) };
                            tx.push(Transmit::new(
                                ScatterGather {
                                    segments: smallvec::smallvec![seg],
                                },
                                meta[i].src,
                            ));
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
