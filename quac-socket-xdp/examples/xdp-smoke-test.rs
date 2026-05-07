//! Minimal AF_XDP socket smoke test.
//!
//! Usage:
//!   sudo ip netns exec quac-rx ./xdp-smoke-test recv --iface vqrx --bind 10.99.0.1:9999
//!   sudo ip netns exec quac-tx ./xdp-smoke-test send --iface vqtx --bind 10.99.0.2:0 \
//!                                                    --target 10.99.0.1:9999 --count 5
//!
//! Exits non-zero on any setup failure (UMEM alloc, eBPF load, bind, etc.)
//! so the operator gets a clear signal.

use std::ffi::CString;
use std::io::{self, Write};
use std::mem::MaybeUninit;
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::time::{Duration, Instant};

use quac_socket::{
    PacketBufMut, PacketSocket, RecvMeta, RxPool, ScatterGather, Segment, Transmit, TxPool,
};
use quac_socket_xdp::{
    AttachMode, RingSizes, XdpConfig, XdpMode, XdpRxBufMut, XdpSocket, XdpTxBuf, XdpTxBufMut,
};

#[derive(Clone, Copy)]
enum Mode {
    Send,
    Recv,
}

struct Args {
    mode: Mode,
    iface: String,
    bind: SocketAddr,
    target: Option<SocketAddr>,
    queue: u16,
    count: usize,
    attach: AttachMode,
    xdp_mode: XdpMode,
}

fn die(msg: &str) -> ! {
    eprintln!("error: {msg}");
    std::process::exit(1);
}

fn parse_args() -> Args {
    let mut iter = std::env::args().skip(1);
    let mode_arg = iter.next().unwrap_or_else(|| die("usage: send|recv [flags]"));
    let mode = match mode_arg.as_str() {
        "send" => Mode::Send,
        "recv" => Mode::Recv,
        s => die(&format!("unknown mode '{s}' — expected send|recv")),
    };

    let mut iface = None;
    let mut bind: Option<SocketAddr> = None;
    let mut target: Option<SocketAddr> = None;
    let mut queue: u16 = 0;
    let mut count: usize = 1;
    let mut attach = AttachMode::Default;
    let mut xdp_mode = XdpMode::ZeroCopy;

    while let Some(k) = iter.next() {
        let mut v = || iter.next().unwrap_or_else(|| die(&format!("{k} needs a value")));
        match k.as_str() {
            "--iface" => iface = Some(v()),
            "--bind" => bind = Some(v().parse().unwrap_or_else(|_| die("--bind needs addr:port"))),
            "--target" => {
                target = Some(v().parse().unwrap_or_else(|_| die("--target needs addr:port")))
            }
            "--queue" => queue = v().parse().unwrap_or_else(|_| die("--queue needs u16")),
            "--count" => count = v().parse().unwrap_or_else(|_| die("--count needs usize")),
            "--attach" => {
                attach = match v().as_str() {
                    "default" => AttachMode::Default,
                    "skb" => AttachMode::Skb,
                    "drv" => AttachMode::Drv,
                    s => die(&format!("unknown attach mode '{s}'")),
                }
            }
            "--xdp-mode" => {
                xdp_mode = match v().as_str() {
                    "zc" | "zerocopy" => XdpMode::ZeroCopy,
                    "copy" => XdpMode::Copy,
                    s => die(&format!("unknown xdp mode '{s}'")),
                }
            }
            _ => die(&format!("unknown arg: {k}")),
        }
    }

    Args {
        mode,
        iface: iface.unwrap_or_else(|| die("--iface required")),
        bind: bind.unwrap_or_else(|| die("--bind required")),
        target,
        queue,
        count,
        attach,
        xdp_mode,
    }
}

fn if_name_to_index(name: &str) -> io::Result<u32> {
    let c = CString::new(name).map_err(|_| io::Error::other("interface name has NUL"))?;
    let idx = unsafe { libc::if_nametoindex(c.as_ptr()) };
    if idx == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(idx)
}

fn main() -> io::Result<()> {
    let args = parse_args();
    let if_index = if_name_to_index(&args.iface)?;
    println!("[smoke] interface={} (index={})", args.iface, if_index);

    let cfg = XdpConfig::builder()
        .ring_sizes(RingSizes::default())
        .frame_count(4096)
        .frame_size(2048)
        .mode(args.xdp_mode)
        .attach_mode(args.attach)
        .build();

    print!("[smoke] opening AF_XDP socket on {}:{} (queue={})... ",
           args.bind.ip(), args.bind.port(), args.queue);
    io::stdout().flush().ok();
    let mut sock = XdpSocket::with_interface(if_index, args.queue, args.bind.ip(), args.bind.port(), cfg)
        .map_err(|e| {
            eprintln!("FAILED: {e}");
            e
        })?;
    println!("ok (fd={})", sock.rx_fd().unwrap().as_raw_fd());

    match args.mode {
        Mode::Send => smoke_send(&mut sock, args.target.unwrap_or_else(|| die("send mode needs --target")), args.count),
        Mode::Recv => smoke_recv(&mut sock, args.count),
    }
}

fn smoke_send(sock: &mut XdpSocket, target: SocketAddr, count: usize) -> io::Result<()> {
    let payload = b"hello from quac-socket-xdp\n";
    let mut tx_bufs: Vec<XdpTxBufMut> = Vec::with_capacity(1);
    let mut transmits: Vec<Transmit<ScatterGather<XdpTxBuf>>> = Vec::with_capacity(1);

    for i in 0..count {
        // Allocate one Tx frame.
        tx_bufs.clear();
        let n = sock.tx_pool().alloc(payload.len(), 1, &mut tx_bufs);
        if n == 0 {
            // Pool exhausted — drain completions to recycle frames the kernel sent.
            let dr = sock.drain_completions();
            println!("[smoke] tx pool empty, drained {} completions", dr.completed);
            sock.tx_pool().alloc(payload.len(), 1, &mut tx_bufs);
            if tx_bufs.is_empty() {
                return Err(io::Error::other("tx pool stuck — no frames available"));
            }
        }

        let mut buf = tx_bufs.pop().unwrap();
        let uninit = buf.uninit_mut();
        let to_write = payload.len().min(uninit.len());
        for (j, &b) in payload[..to_write].iter().enumerate() {
            uninit[j] = MaybeUninit::new(b);
        }
        unsafe { buf.set_filled(to_write) };
        let frozen = buf.freeze();
        let seg = unsafe { Segment::new_unchecked(frozen, 0, to_write as u32) };
        let transmit = Transmit::new(ScatterGather::single(seg), target);

        transmits.clear();
        transmits.push(transmit);
        let sent = sock.send(&mut transmits)?;
        println!("[smoke] iteration {}: send returned {}", i + 1, sent);

        // Drain completions so frames cycle back to the TX pool.
        std::thread::sleep(Duration::from_millis(50));
        let dr = sock.drain_completions();
        if dr.completed > 0 {
            println!("[smoke]   drained {} completions ({} errors)", dr.completed, dr.errors);
        }
    }
    Ok(())
}

fn smoke_recv(sock: &mut XdpSocket, count: usize) -> io::Result<()> {
    let mut bufs: Vec<XdpRxBufMut> = Vec::with_capacity(64);
    let mut meta = vec![RecvMeta::default(); 64];
    let mut received = 0usize;

    println!("[smoke] receiver ready, waiting for {} packet(s)...", count);

    let deadline = Instant::now() + Duration::from_secs(30);
    while received < count {
        if Instant::now() > deadline {
            return Err(io::Error::other("timeout waiting for packets"));
        }
        // Refill bufs to capacity before each recv (PacketSocket contract).
        if bufs.len() < 64 {
            sock.rx_pool().alloc(2048, 64 - bufs.len(), &mut bufs);
        }
        let n = sock.recv(&mut meta[..], &mut bufs[..])?;
        if n > 0 {
            for i in 0..n {
                let m = meta[i];
                let payload_preview: String = bufs[i]
                    .filled()
                    .iter()
                    .take(64)
                    .flat_map(|b| std::ascii::escape_default(*b))
                    .map(char::from)
                    .collect();
                println!(
                    "[smoke] rx #{}: {} bytes from {} -> {:?}, payload[0..]={:?}",
                    received + i + 1,
                    m.len,
                    m.src,
                    m.dst_ip,
                    payload_preview,
                );
            }
            received += n;
            // Drop the processed buffers — frames return to FILL via the reclaimer.
            bufs.drain(..n);
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    println!("[smoke] received {} packets", received);
    Ok(())
}
