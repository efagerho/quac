use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use quac_network_tile::{FourTupleRouter, NetworkTile, NetworkTileImpl, RecvMetaConfig, Spin};
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
    /// Explicit `--threads` override. `None` means "1 by default; or
    /// `nic_queue_count` if `incoming_cpu` is on".
    threads: Option<usize>,
    mode: Mode,
    duration: u64,
    recv_meta: RecvMetaConfig,
    incoming_cpu: bool,
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
            threads: None,
            mode: Mode::Count,
            duration: 0,
            recv_meta: RecvMetaConfig::default(),
            incoming_cpu: false,
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

/// Default `--threads` for OS / io_uring backends: auto-detect from the NIC
/// owning the bind IP. Auto-default kicks in only when `--incoming-cpu` is set.
#[cfg(target_os = "linux")]
fn resolve_thread_count_for_bind(requested: Option<usize>, bind: SocketAddr, incoming_cpu: bool) -> usize {
    if let Some(n) = requested {
        return n.max(1);
    }
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
    1
}

#[cfg(not(target_os = "linux"))]
fn resolve_thread_count_for_bind(requested: Option<usize>, _bind: SocketAddr, _incoming_cpu: bool) -> usize {
    requested.unwrap_or(1).max(1)
}

/// Default `--threads` for the XDP backend: auto-detect from `--iface`
/// directly. Auto-default kicks in only when `--incoming-cpu` is set.
#[cfg(target_os = "linux")]
fn resolve_thread_count_for_iface(requested: Option<usize>, iface: &str, incoming_cpu: bool) -> usize {
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
                let n: usize = v().parse().unwrap_or_else(|_| die("--threads needs a number"));
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
                a.duration = v().parse().unwrap_or_else(|_| die("--duration needs a number"));
            }
            "--no-recv-ecn" => a.recv_meta.ecn = false,
            "--no-recv-dst-ip" => a.recv_meta.dst_ip = false,
            "--incoming-cpu" => a.incoming_cpu = true,
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
                     [--threads N] [--mode count|reflect] [--duration secs] \
                     [--no-recv-ecn] [--no-recv-dst-ip] [--incoming-cpu]\n\
                     XDP-only: --iface NAME [--queue ID] [--xdp-mode zc|copy] \
                     [--attach default|skb|drv|hw]"
                );
                #[cfg(not(target_os = "linux"))]
                println!(
                    "Usage: tile-bench-receiver [--bind addr:port] [--socket os|iouring] \
                     [--threads N] [--mode count|reflect] [--duration secs] \
                     [--no-recv-ecn] [--no-recv-dst-ip] [--incoming-cpu]"
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

    // Per-tile counters; the reporter and final summary sum them.
    let mut per_tile_rx: Vec<Arc<AtomicU64>> = Vec::new();
    let mut per_tile_tx: Vec<Arc<AtomicU64>> = Vec::new();

    #[cfg(target_os = "linux")]
    let xdp_cfg = XdpConfig::builder()
        .ring_sizes(RingSizes::default())
        .frame_count(4096)
        .frame_size(2048)
        .mode(args.xdp_mode)
        .attach_mode(args.attach)
        .recv_ecn(args.recv_meta.ecn)
        .recv_dst_ip(args.recv_meta.dst_ip)
        .build();

    let mut workers = Vec::new();

    // --incoming-cpu: build_coalesced_tiles enumerates bond slaves and
    // groups by CPU; tiles validate and pin on their IO threads.
    if args.incoming_cpu {
        match args.socket {
            Socket::Os => {
                let bind = args.bind;
                let recv_meta = args.recv_meta;
                let factory = move |q: &quac_socket::RxQueue| -> std::io::Result<OsSocket> {
                    let cfg = OsConfig::builder()
                        .reuseport(true)
                        .recv_ecn(recv_meta.ecn)
                        .recv_dst_ip(recv_meta.dst_ip)
                        .incoming_cpu(true)
                        .build();
                    OsSocket::bind(bind, q.flat_index, cfg)
                };
                let iface = match quac_socket::nic::interface_for_addr(bind.ip()) {
                    Ok(i) => i,
                    Err(e) => die(&format!(
                        "--incoming-cpu requires a non-wildcard --bind that resolves to a NIC: {e}"
                    )),
                };
                let tiles = quac_network_tile::build_coalesced_tiles::<OsSocket, Spin, _, _>(
                    &iface, factory, FourTupleRouter, 1,
                ).unwrap_or_else(|e| die(&format!("build_coalesced_tiles({iface}): {e}")));
                for (i, tile) in tiles.into_iter().enumerate() {
                    let rx_count = Arc::new(AtomicU64::new(0));
                    let tx_count = Arc::new(AtomicU64::new(0));
                    per_tile_rx.push(rx_count.clone());
                    per_tile_tx.push(tx_count.clone());
                    let shutdown = shutdown.clone();
                    let mode = args.mode;
                    Arc::clone(&tile).start(i);
                    workers.push(std::thread::spawn(move || {
                        run_receiver(tile, mode, shutdown, rx_count, tx_count);
                    }));
                }
            }
            Socket::IoUring => {
                let bind = args.bind;
                let recv_meta = args.recv_meta;
                let factory = move |q: &quac_socket::RxQueue| -> std::io::Result<IoUringSocket> {
                    let cfg = IoUringConfig::builder()
                        .reuseport(true)
                        .recv_ecn(recv_meta.ecn)
                        .recv_dst_ip(recv_meta.dst_ip)
                        .incoming_cpu(true)
                        .build();
                    IoUringSocket::bind(bind, q.flat_index, cfg)
                };
                let iface = match quac_socket::nic::interface_for_addr(bind.ip()) {
                    Ok(i) => i,
                    Err(e) => die(&format!(
                        "--incoming-cpu requires a non-wildcard --bind that resolves to a NIC: {e}"
                    )),
                };
                let tiles = quac_network_tile::build_coalesced_tiles::<IoUringSocket, Spin, _, _>(
                    &iface, factory, FourTupleRouter, 1,
                ).unwrap_or_else(|e| die(&format!("build_coalesced_tiles({iface}): {e}")));
                for (i, tile) in tiles.into_iter().enumerate() {
                    let rx_count = Arc::new(AtomicU64::new(0));
                    let tx_count = Arc::new(AtomicU64::new(0));
                    per_tile_rx.push(rx_count.clone());
                    per_tile_tx.push(tx_count.clone());
                    let shutdown = shutdown.clone();
                    let mode = args.mode;
                    Arc::clone(&tile).start(i);
                    workers.push(std::thread::spawn(move || {
                        run_receiver(tile, mode, shutdown, rx_count, tx_count);
                    }));
                }
            }
            #[cfg(target_os = "linux")]
            Socket::Xdp => {
                let bind = args.bind;
                let cfg = xdp_cfg;
                let factory = move |q: &quac_socket::RxQueue| -> std::io::Result<XdpSocket> {
                    let slave_idx = if_name_to_index(&q.iface)?;
                    XdpSocket::with_interface(slave_idx, q.queue_id, bind.ip(), bind.port(), cfg)
                };
                let tiles = quac_network_tile::build_coalesced_tiles::<XdpSocket, Spin, _, _>(
                    &args.iface, factory, FourTupleRouter, 1,
                ).unwrap_or_else(|e| die(&format!("build_coalesced_tiles({}): {e}", args.iface)));
                for (i, tile) in tiles.into_iter().enumerate() {
                    let rx_count = Arc::new(AtomicU64::new(0));
                    let tx_count = Arc::new(AtomicU64::new(0));
                    per_tile_rx.push(rx_count.clone());
                    per_tile_tx.push(tx_count.clone());
                    let shutdown = shutdown.clone();
                    let mode = args.mode;
                    Arc::clone(&tile).start(i);
                    workers.push(std::thread::spawn(move || {
                        run_receiver(tile, mode, shutdown, rx_count, tx_count);
                    }));
                }
            }
        }
    } else {
        let threads = match args.socket {
            #[cfg(target_os = "linux")]
            Socket::Xdp => resolve_thread_count_for_iface(args.threads, &args.iface, args.incoming_cpu),
            _ => resolve_thread_count_for_bind(args.threads, args.bind, args.incoming_cpu),
        };
        for i in 0..threads {
            let rx_count = Arc::new(AtomicU64::new(0));
            let tx_count = Arc::new(AtomicU64::new(0));
            per_tile_rx.push(rx_count.clone());
            per_tile_tx.push(tx_count.clone());
            let shutdown = shutdown.clone();
            let bind = args.bind;
            let mode = args.mode;
            let socket = args.socket;
            let recv_meta = args.recv_meta;
            let os_queue_id = i as u16;
            #[cfg(target_os = "linux")]
            let queue_id = args.queue + i as u16;

            workers.push(std::thread::spawn(move || {
                match socket {
                    Socket::Os => {
                        let tile = Arc::new(NetworkTileImpl::<_, Spin, _>::new(
                            move || {
                                let cfg = OsConfig::builder()
                                    .reuseport(true)
                                    .recv_ecn(recv_meta.ecn)
                                    .recv_dst_ip(recv_meta.dst_ip)
                                    .incoming_cpu(false)
                                    .build();
                                OsSocket::bind(bind, os_queue_id, cfg)
                                    .unwrap_or_else(|e| { eprintln!("bind reuseport {bind}: {e}"); std::process::exit(1) })
                            },
                            FourTupleRouter, 1,
                        ));
                        Arc::clone(&tile).start(i);
                        run_receiver(tile, mode, shutdown, rx_count, tx_count);
                    }
                    Socket::IoUring => {
                        let tile = Arc::new(NetworkTileImpl::<_, Spin, _>::new(
                            move || {
                                let cfg = IoUringConfig::builder()
                                    .reuseport(true)
                                    .recv_ecn(recv_meta.ecn)
                                    .recv_dst_ip(recv_meta.dst_ip)
                                    .incoming_cpu(false)
                                    .build();
                                IoUringSocket::bind(bind, os_queue_id, cfg)
                                    .unwrap_or_else(|e| { eprintln!("bind reuseport {bind}: {e}"); std::process::exit(1) })
                            },
                            FourTupleRouter, 1,
                        ));
                        Arc::clone(&tile).start(i);
                        run_receiver(tile, mode, shutdown, rx_count, tx_count);
                    }
                    #[cfg(target_os = "linux")]
                    Socket::Xdp => {
                        let cfg = xdp_cfg;
                        let bind_ip = bind.ip();
                        let bind_port = bind.port();
                        let tile = Arc::new(NetworkTileImpl::<_, Spin, _>::new(
                            move || {
                                XdpSocket::with_interface(if_index, queue_id, bind_ip, bind_port, cfg)
                                    .unwrap_or_else(|e| {
                                        eprintln!("XdpSocket::with_interface(if={if_index}, queue={queue_id}): {e}");
                                        std::process::exit(1)
                                    })
                            },
                            FourTupleRouter, 1,
                        ));
                        Arc::clone(&tile).start(i);
                        run_receiver(tile, mode, shutdown, rx_count, tx_count);
                    }
                }
            }));
        }
    }

    let shutdown_rep = shutdown.clone();
    let per_tile_rx_rep = per_tile_rx.clone();
    let per_tile_tx_rep = per_tile_tx.clone();
    let mode = args.mode;
    let reporter = std::thread::spawn(move || {
        let mut prev_rx = 0u64;
        let mut prev_tx = 0u64;
        while !shutdown_rep.load(Relaxed) {
            std::thread::sleep(Duration::from_secs(1));
            let rx: u64 = per_tile_rx_rep.iter().map(|c| c.load(Relaxed)).sum();
            let tx: u64 = per_tile_tx_rep.iter().map(|c| c.load(Relaxed)).sum();
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

    println!("final per-tile counts:");
    for (i, rx_c) in per_tile_rx.iter().enumerate() {
        let rx = rx_c.load(Relaxed);
        if args.mode == Mode::Reflect {
            let tx = per_tile_tx[i].load(Relaxed);
            println!("  tile[{i:>3}] rx={rx} tx={tx}");
        } else {
            println!("  tile[{i:>3}] rx={rx}");
        }
    }
    let rx_sum: u64 = per_tile_rx.iter().map(|c| c.load(Relaxed)).sum();
    let tx_sum: u64 = per_tile_tx.iter().map(|c| c.load(Relaxed)).sum();
    if args.mode == Mode::Reflect {
        println!("final: total_rx={rx_sum} total_tx={tx_sum}");
    } else {
        println!("final: total_rx={rx_sum}");
    }
}
