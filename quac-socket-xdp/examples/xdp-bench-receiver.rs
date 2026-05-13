//! AF_XDP variant of `os-bench-receiver`. Same CLI flags + adds:
//!   --iface NAME    interface to bind to (REQUIRED)
//!   --queue ID      first hardware queue to use
//!   --xdp-mode zc|copy   default zc
//!   --attach default|skb|drv   default default

use std::collections::BTreeMap;
use std::ffi::CString;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

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
    /// Explicit queue/socket count override. `None` means "1 by default; or
    /// all NIC queues if `incoming_cpu` is on".
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
    /// IRQ CPU, and `--threads` defaults to all queues on `--iface`.
    incoming_cpu: bool,
}

#[derive(Clone)]
struct QueueSlot {
    iface: String,
    queue_id: u16,
    cpu: Option<u32>,
}

#[derive(Clone)]
struct QueueGroup {
    cpu: Option<u32>,
    slots: Vec<QueueSlot>,
}

struct QueueStats {
    iface: String,
    queue_id: u16,
    rx: u64,
}

struct WorkerStats {
    thread: usize,
    cpu: Option<u32>,
    queues: Vec<QueueStats>,
    rx: u64,
    elapsed: Duration,
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
                    "count" => Mode::Count,
                    "reflect" => Mode::Reflect,
                    s => die(&format!("unknown mode: {s}")),
                }
            }
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

fn all_queue_slots(iface: &str, incoming_cpu: bool) -> Vec<QueueSlot> {
    if incoming_cpu {
        let queues = quac_socket::nic::enumerate_rx_queues(iface)
            .unwrap_or_else(|e| die(&format!("enumerate_rx_queues({iface}): {e}")));
        if queues.is_empty() {
            die(&format!("{iface} has no RX queues"));
        }
        return queues
            .into_iter()
            .map(|q| QueueSlot {
                iface: q.iface,
                queue_id: q.queue_id,
                cpu: Some(q.cpu),
            })
            .collect();
    }

    match quac_socket::nic::bond_slaves(iface).unwrap_or(None) {
        Some(slaves) => {
            let mut out = Vec::new();
            for slave in &slaves {
                let n = quac_socket::nic::nic_queue_count(slave)
                    .unwrap_or_else(|e| die(&format!("nic_queue_count({slave}): {e}")));
                for q in 0..n as u16 {
                    out.push(QueueSlot {
                        iface: slave.clone(),
                        queue_id: q,
                        cpu: None,
                    });
                }
            }
            if out.is_empty() {
                die(&format!("bond {iface} has no slave queues"));
            }
            out
        }
        None => {
            let n = quac_socket::nic::nic_queue_count(iface)
                .unwrap_or_else(|e| die(&format!("nic_queue_count({iface}): {e}")));
            (0..n as u16)
                .map(|q| QueueSlot {
                    iface: iface.to_string(),
                    queue_id: q,
                    cpu: None,
                })
                .collect()
        }
    }
}

fn select_queue_slots(
    slots: &[QueueSlot],
    first_queue: u16,
    requested: Option<usize>,
    incoming_cpu: bool,
    iface: &str,
) -> Vec<QueueSlot> {
    let start = first_queue as usize;
    if start >= slots.len() {
        die(&format!(
            "--queue ({first_queue}) exceeds {} available NIC queues on {iface}",
            slots.len()
        ));
    }
    let available = slots.len() - start;
    let count =
        requested
            .map(|n| n.max(1))
            .unwrap_or_else(|| if incoming_cpu { available } else { 1 });
    if count > available {
        die(&format!(
            "--threads ({count}) + --queue ({first_queue}) exceeds {} available NIC queues on {iface}",
            slots.len(),
        ));
    }
    slots[start..start + count].to_vec()
}

fn queue_groups(slots: Vec<QueueSlot>, incoming_cpu: bool) -> Vec<QueueGroup> {
    if !incoming_cpu {
        return slots
            .into_iter()
            .map(|slot| QueueGroup {
                cpu: None,
                slots: vec![slot],
            })
            .collect();
    }

    let mut by_cpu: BTreeMap<u32, Vec<QueueSlot>> = BTreeMap::new();
    for slot in slots {
        let cpu = slot
            .cpu
            .expect("incoming-cpu queue slots must carry their CPU");
        by_cpu.entry(cpu).or_default().push(slot);
    }
    by_cpu
        .into_iter()
        .map(|(cpu, slots)| QueueGroup {
            cpu: Some(cpu),
            slots,
        })
        .collect()
}

fn queue_stats_label(queues: &[QueueStats]) -> String {
    let mut label = String::new();
    for (i, q) in queues.iter().enumerate() {
        if i > 0 {
            label.push(',');
        }
        label.push_str(&format!("{}:{}({})", q.iface, q.queue_id, q.rx));
    }
    label
}

fn main() {
    let args = parse_args();

    let queue_slots = all_queue_slots(&args.iface, args.incoming_cpu);
    let selected_slots = select_queue_slots(
        &queue_slots,
        args.queue,
        args.threads,
        args.incoming_cpu,
        &args.iface,
    );
    let groups = queue_groups(selected_slots, args.incoming_cpu);
    let selected_queue_count: usize = groups.iter().map(|group| group.slots.len()).sum();
    if args.incoming_cpu {
        eprintln!(
            "[bench] using {selected_queue_count} queue sockets on {} CPU threads from {}",
            groups.len(),
            args.iface,
        );
    }

    let shutdown = Arc::new(AtomicBool::new(false));
    SHUTDOWN.set(shutdown.clone()).ok();
    unsafe {
        libc::signal(
            libc::SIGINT,
            sigint_handler as *const () as libc::sighandler_t,
        )
    };

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
        .incoming_cpu(args.incoming_cpu)
        .build();

    struct RxSocketState {
        slot: QueueSlot,
        sock: XdpSocket,
        bufs: Vec<XdpRxBufMut>,
        meta: Vec<RecvMeta>,
        tx: Vec<Transmit<ScatterGather<XdpTxBuf>>>,
        rx: u64,
    }

    let mut workers = Vec::new();
    for (t, group) in groups.into_iter().enumerate() {
        let shutdown = shutdown.clone();
        let rx_count = rx_total.clone();
        let tx_count = tx_total.clone();
        let bind = args.bind;
        let mode = args.mode;
        let cpu = group.cpu;
        let slots = group.slots;

        workers.push(std::thread::spawn(move || {
            if let Some(cpu) = cpu {
                if let Err(e) = quac_socket::pin_current_thread_to_cpu(cpu) {
                    eprintln!("[t{t}] pin_current_thread_to_cpu({cpu}) skipped: {e}");
                }
            }

            let mut sockets = Vec::with_capacity(slots.len());
            for slot in slots {
                let if_idx = if_name_to_index(&slot.iface)
                    .unwrap_or_else(|e| die(&format!("if_nametoindex({}): {e}", slot.iface)));
                let sock =
                    XdpSocket::with_interface(if_idx, slot.queue_id, bind.ip(), bind.port(), cfg)
                        .unwrap_or_else(|e| {
                            eprintln!(
                                "[t{t}] XdpSocket::with_interface(iface={}, queue={}): {e}",
                                slot.iface, slot.queue_id
                            );
                            std::process::exit(1);
                        });
                sockets.push(RxSocketState {
                    slot,
                    sock,
                    bufs: Vec::with_capacity(BATCH),
                    meta: vec![RecvMeta::default(); BATCH],
                    tx: Vec::with_capacity(BATCH),
                    rx: 0,
                });
            }

            let start = Instant::now();
            let mut worker_rx = 0u64;

            while !shutdown.load(Relaxed) {
                let mut made_progress = false;
                for state in &mut sockets {
                    if state.bufs.len() < BATCH {
                        state.sock.rx_pool().alloc(
                            state.sock.rx_pool().max_payload_size(),
                            BATCH - state.bufs.len(),
                            &mut state.bufs,
                        );
                    }

                    let n = match state.sock.recv(&mut state.meta[..], &mut state.bufs[..]) {
                        Ok(n) => n,
                        Err(_) => continue,
                    };
                    if n == 0 {
                        if mode == Mode::Reflect {
                            state.sock.drain_completions();
                        }
                        continue;
                    }

                    made_progress = true;
                    state.rx += n as u64;
                    worker_rx += n as u64;
                    rx_count.fetch_add(n as u64, Relaxed);

                    match mode {
                        Mode::Count => {
                            state.bufs.drain(..n);
                        }
                        Mode::Reflect => {
                            for (i, rx_buf) in state.bufs.drain(..n).enumerate() {
                                let dst = state.meta[i].src;
                                let len = state.meta[i].len as u32;
                                let tx_buf_mut = match state.sock.tx_pool().from_rx(rx_buf) {
                                    Ok(b) => b,
                                    Err(_rx) => continue,
                                };
                                let frozen = tx_buf_mut.freeze();
                                let seg = unsafe { Segment::new_unchecked(frozen, 0, len) };
                                state
                                    .tx
                                    .push(Transmit::new(ScatterGather::single(seg), dst));
                            }
                            let sent = state.sock.send(&mut state.tx).unwrap_or(0);
                            tx_count.fetch_add(sent as u64, Relaxed);
                            state.tx.clear();
                            state.sock.drain_completions();
                        }
                    }
                }
                if !made_progress {
                    std::hint::spin_loop();
                }
            }

            let queues = sockets
                .into_iter()
                .map(|state| QueueStats {
                    iface: state.slot.iface,
                    queue_id: state.slot.queue_id,
                    rx: state.rx,
                })
                .collect();
            WorkerStats {
                thread: t,
                cpu,
                queues,
                rx: worker_rx,
                elapsed: start.elapsed(),
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

    let mut worker_stats = Vec::new();
    for w in workers {
        if let Ok(stats) = w.join() {
            worker_stats.push(stats);
        }
    }
    let _ = reporter.join();

    for stats in worker_stats {
        let secs = stats.elapsed.as_secs_f64();
        let avg_pps = if secs > 0.0 {
            stats.rx as f64 / secs
        } else {
            0.0
        };
        let cpu = stats
            .cpu
            .map(|cpu| cpu.to_string())
            .unwrap_or_else(|| "-".to_string());
        let queues = queue_stats_label(&stats.queues);
        println!(
            "[t{}] cpu={} queues={} avg_rx={:.2} Mpps total_rx={} elapsed={:.3}s",
            stats.thread,
            cpu,
            queues,
            avg_pps / 1e6,
            stats.rx,
            secs,
        );
    }

    let rx = rx_total.load(Relaxed);
    let tx = tx_total.load(Relaxed);
    println!("final: total_rx={rx} total_tx={tx}");
}
