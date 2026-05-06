use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use quac_network_tile::{FourTupleRouter, NetworkTile, NetworkTileImpl, Spin};
use quac_socket::{PacketBufMut, ScatterGather, Segment, Transmit, TxPool};
use quac_socket_iouring::IoUringSocket;
use quac_socket_os::OsSocket;

const BATCH: usize = 64;

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Count,
    Reflect,
}

#[derive(Clone, Copy, PartialEq)]
enum Socket {
    Os,
    IoUring,
}

struct Args {
    bind: SocketAddr,
    socket: Socket,
    threads: usize,
    mode: Mode,
    duration: u64,
}

impl Default for Args {
    fn default() -> Self {
        Self {
            bind: "0.0.0.0:9999".parse().unwrap(),
            socket: Socket::Os,
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
        let mut v = || it.next().unwrap_or_else(|| die(&format!("{k} needs a value")));
        match k.as_str() {
            "--bind" => {
                a.bind = v().parse().unwrap_or_else(|_| die("--bind needs addr:port"));
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
                    "count" => Mode::Count,
                    "reflect" => Mode::Reflect,
                    s => die(&format!("unknown mode: {s}")),
                };
            }
            "--duration" => {
                a.duration = v().parse().unwrap_or_else(|_| die("--duration needs a number"));
            }
            "--help" | "-h" => {
                println!(
                    "Usage: tile-bench-receiver [--bind addr:port] [--socket os|iouring] \
                     [--threads N] [--mode count|reflect] [--duration secs]"
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

fn run_receiver<T: NetworkTile>(
    tile: Arc<T>,
    mode: Mode,
    shutdown: Arc<AtomicBool>,
    rx_count: Arc<AtomicU64>,
    tx_count: Arc<AtomicU64>,
) {
    let rx_q = Arc::clone(&tile.rx_queues()[0]);
    let tx_q = Arc::clone(&tile.tx_queues()[0]);
    rx_q.register_consumer();

    let mut tx_cache: Vec<<T::TxPool as TxPool>::BufMut> = Vec::with_capacity(BATCH);

    while !shutdown.load(Relaxed) {
        let mut did_work = false;

        while let Some(pkt) = rx_q.pop() {
            did_work = true;
            rx_count.fetch_add(1, Relaxed);

            match mode {
                Mode::Count => {
                    // Drop pkt; RxBufMut returns to the pool via Drop.
                }
                Mode::Reflect => {
                    // Read offset/length from the first segment while pkt is live.
                    let (s_off, copy_len, src) = {
                        let Some(seg) = pkt.payload.segments().first() else { continue };
                        let s = seg.offset() as usize;
                        let e = (s + seg.len() as usize).min(seg.buf().filled().len());
                        (s, e - s, pkt.meta.src)
                    };

                    // Alloc a TX buf, spinning if the tile's queue is momentarily empty.
                    while tx_cache.is_empty() {
                        tile.alloc_tx_bufs(copy_len.max(1), BATCH, &mut tx_cache);
                        if tx_cache.is_empty() {
                            std::hint::spin_loop();
                        }
                    }
                    let mut tx_buf = tx_cache.pop().unwrap();

                    // Copy payload while pkt is still live.
                    {
                        let seg = pkt.payload.segments().first().unwrap();
                        let filled = seg.buf().filled();
                        let actual = copy_len.min(tx_buf.uninit_mut().len());
                        unsafe {
                            std::ptr::copy_nonoverlapping(
                                filled[s_off..s_off + actual].as_ptr(),
                                tx_buf.uninit_mut().as_mut_ptr() as *mut u8,
                                actual,
                            );
                            tx_buf.set_filled(actual);
                        }
                    }
                    drop(pkt);

                    let frozen = tx_buf.freeze();
                    let seg = unsafe { Segment::new_unchecked(frozen, 0, copy_len as u32) };
                    if tx_q.push(Transmit::new(ScatterGather::single(seg), src)) {
                        tx_count.fetch_add(1, Relaxed);
                    }
                }
            }
        }

        if !did_work {
            std::hint::spin_loop();
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

    let rx_total: Arc<AtomicU64> = Arc::new(AtomicU64::new(0));
    let tx_total: Arc<AtomicU64> = Arc::new(AtomicU64::new(0));

    let mut workers = Vec::new();
    for i in 0..args.threads {
        let shutdown = shutdown.clone();
        let rx_count = rx_total.clone();
        let tx_count = tx_total.clone();
        let bind = args.bind;
        let mode = args.mode;
        let socket = args.socket;

        workers.push(std::thread::spawn(move || {
            match socket {
                Socket::Os => {
                    let tile = Arc::new(
                        NetworkTileImpl::<_, Spin, _>::new(
                            move || OsSocket::bind_reuseport(bind, 0)
                                .unwrap_or_else(|e| { eprintln!("bind_reuseport {bind}: {e}"); std::process::exit(1) }),
                            FourTupleRouter, 1,
                        ),
                    );
                    Arc::clone(&tile).start(i);
                    run_receiver(tile, mode, shutdown, rx_count, tx_count);
                }
                Socket::IoUring => {
                    let tile = Arc::new(
                        NetworkTileImpl::<_, Spin, _>::new(
                            move || IoUringSocket::bind_reuseport(bind, 0)
                                .unwrap_or_else(|e| { eprintln!("bind_reuseport {bind}: {e}"); std::process::exit(1) }),
                            FourTupleRouter, 1,
                        ),
                    );
                    Arc::clone(&tile).start(i);
                    run_receiver(tile, mode, shutdown, rx_count, tx_count);
                }
            }
        }));
    }

    let shutdown_rep = shutdown.clone();
    let rx_rep = rx_total.clone();
    let tx_rep = tx_total.clone();
    let mode = args.mode;
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
            if mode == Mode::Reflect {
                println!(
                    "rx={:.2} Mpps tx={:.2} Mpps total_rx={} total_tx={}",
                    drx as f64 / 1e6, dtx as f64 / 1e6, rx, tx,
                );
            } else {
                println!("rx={:.2} Mpps total_rx={}", drx as f64 / 1e6, rx);
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

    let rx = rx_total.load(Relaxed);
    let tx = tx_total.load(Relaxed);
    if args.mode == Mode::Reflect {
        println!("final: total_rx={rx} total_tx={tx}");
    } else {
        println!("final: total_rx={rx}");
    }
}
