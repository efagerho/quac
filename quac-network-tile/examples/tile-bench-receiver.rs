use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use quac_network_tile::{FourTupleRouter, NetworkTile, NetworkTileImpl, Spin};
use quac_socket::{PacketBufMut, ScatterGather, Segment, Transmit, TxPool};
use quac_socket_iouring::{IoUringConfig, IoUringSocket};
use quac_socket_os::{OsConfig, OsSocket};

#[cfg(target_os = "linux")]
use quac_socket_xdp::{AttachMode, RingSizes, XdpConfig, XdpMode, XdpSocket};

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
    #[cfg(target_os = "linux")]
    Xdp,
}

struct Args {
    bind: SocketAddr,
    socket: Socket,
    threads: usize,
    mode: Mode,
    duration: u64,
    // XDP-only knobs; ignored unless `--socket xdp`.
    #[cfg(target_os = "linux")]
    iface: String,
    #[cfg(target_os = "linux")]
    queue: u16,
    #[cfg(target_os = "linux")]
    xdp_mode: XdpMode,
    #[cfg(target_os = "linux")]
    attach: AttachMode,
}

impl Default for Args {
    fn default() -> Self {
        Self {
            bind: "0.0.0.0:9999".parse().unwrap(),
            socket: Socket::Os,
            threads: 1,
            mode: Mode::Count,
            duration: 0,
            #[cfg(target_os = "linux")]
            iface: String::new(),
            #[cfg(target_os = "linux")]
            queue: 0,
            #[cfg(target_os = "linux")]
            xdp_mode: XdpMode::ZeroCopy,
            #[cfg(target_os = "linux")]
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
            "--bind" => {
                a.bind = v().parse().unwrap_or_else(|_| die("--bind needs addr:port"));
            }
            "--socket" => {
                a.socket = match v().as_str() {
                    "os" => Socket::Os,
                    "iouring" => Socket::IoUring,
                    #[cfg(target_os = "linux")]
                    "xdp" => Socket::Xdp,
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
            #[cfg(target_os = "linux")]
            "--iface" => a.iface = v(),
            #[cfg(target_os = "linux")]
            "--queue" => a.queue = v().parse().unwrap_or_else(|_| die("--queue needs u16")),
            #[cfg(target_os = "linux")]
            "--xdp-mode" => {
                a.xdp_mode = match v().as_str() {
                    "zc" | "zerocopy" => XdpMode::ZeroCopy,
                    "copy" => XdpMode::Copy,
                    s => die(&format!("unknown xdp-mode: {s}")),
                }
            }
            #[cfg(target_os = "linux")]
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
                #[cfg(target_os = "linux")]
                println!(
                    "Usage: tile-bench-receiver [--bind addr:port] [--socket os|iouring|xdp] \
                     [--threads N] [--mode count|reflect] [--duration secs]\n\
                     XDP-only: --iface NAME [--queue ID] [--xdp-mode zc|copy] \
                     [--attach default|skb|drv|hw]"
                );
                #[cfg(not(target_os = "linux"))]
                println!(
                    "Usage: tile-bench-receiver [--bind addr:port] [--socket os|iouring] \
                     [--threads N] [--mode count|reflect] [--duration secs]"
                );
                std::process::exit(0);
            }
            other => die(&format!("unknown arg: {other}")),
        }
    }
    #[cfg(target_os = "linux")]
    if a.socket == Socket::Xdp && a.iface.is_empty() {
        die("--socket xdp requires --iface NAME");
    }
    a
}

#[cfg(target_os = "linux")]
fn if_name_to_index(name: &str) -> std::io::Result<u32> {
    let c = std::ffi::CString::new(name)
        .map_err(|_| std::io::Error::other("interface name has NUL"))?;
    let idx = unsafe { libc::if_nametoindex(c.as_ptr()) };
    if idx == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(idx)
    }
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

    #[cfg(target_os = "linux")]
    let if_index: u32 = if args.socket == Socket::Xdp {
        if_name_to_index(&args.iface).unwrap_or_else(|e| {
            die(&format!("if_nametoindex({}): {e}", args.iface))
        })
    } else {
        0
    };

    let shutdown = Arc::new(AtomicBool::new(false));
    SHUTDOWN.set(shutdown.clone()).ok();
    unsafe {
        libc::signal(libc::SIGINT, sigint_handler as *const () as libc::sighandler_t);
    }

    let rx_total: Arc<AtomicU64> = Arc::new(AtomicU64::new(0));
    let tx_total: Arc<AtomicU64> = Arc::new(AtomicU64::new(0));

    #[cfg(target_os = "linux")]
    let xdp_cfg = XdpConfig::builder()
        .ring_sizes(RingSizes::default())
        .frame_count(4096)
        .frame_size(2048)
        .mode(args.xdp_mode)
        .attach_mode(args.attach)
        .build();

    let mut workers = Vec::new();
    for i in 0..args.threads {
        let shutdown = shutdown.clone();
        let rx_count = rx_total.clone();
        let tx_count = tx_total.clone();
        let bind = args.bind;
        let mode = args.mode;
        let socket = args.socket;
        #[cfg(target_os = "linux")]
        let queue_id = args.queue + i as u16;

        workers.push(std::thread::spawn(move || {
            match socket {
                Socket::Os => {
                    let tile = Arc::new(
                        NetworkTileImpl::<_, Spin, _>::new(
                            move || OsSocket::bind(bind, 0, OsConfig::builder().reuseport(true).build())
                                .unwrap_or_else(|e| { eprintln!("bind reuseport {bind}: {e}"); std::process::exit(1) }),
                            FourTupleRouter, 1,
                        ),
                    );
                    Arc::clone(&tile).start(i);
                    run_receiver(tile, mode, shutdown, rx_count, tx_count);
                }
                Socket::IoUring => {
                    let tile = Arc::new(
                        NetworkTileImpl::<_, Spin, _>::new(
                            move || IoUringSocket::bind(bind, 0, IoUringConfig::builder().reuseport(true).build())
                                .unwrap_or_else(|e| { eprintln!("bind reuseport {bind}: {e}"); std::process::exit(1) }),
                            FourTupleRouter, 1,
                        ),
                    );
                    Arc::clone(&tile).start(i);
                    run_receiver(tile, mode, shutdown, rx_count, tx_count);
                }
                #[cfg(target_os = "linux")]
                Socket::Xdp => {
                    // AF_XDP doesn't use SO_REUSEPORT — multi-tile is by per-thread
                    // (if_index, queue_id) binding; the kernel's RSS / XDP_REDIRECT
                    // does the load-balancing.
                    let cfg = xdp_cfg;
                    let bind_ip = bind.ip();
                    let bind_port = bind.port();
                    let tile = Arc::new(
                        NetworkTileImpl::<_, Spin, _>::new(
                            move || XdpSocket::with_interface(if_index, queue_id, bind_ip, bind_port, cfg)
                                .unwrap_or_else(|e| {
                                    eprintln!("XdpSocket::with_interface(if={if_index}, queue={queue_id}): {e}");
                                    std::process::exit(1)
                                }),
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
