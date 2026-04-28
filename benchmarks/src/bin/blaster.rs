use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use clap::{Parser, Subcommand};
use socket2::{Domain, Protocol, Socket, Type};

#[derive(Parser)]
struct Args {
    /// Destination address (e.g. 127.0.0.1:4000)
    #[arg(long)]
    address: SocketAddr,

    /// Number of sender threads, each with its own SO_REUSEPORT socket
    #[arg(long, default_value_t = 1)]
    threads: usize,

    /// Packets per sendmmsg call (Linux) or per loop iteration (other platforms)
    #[arg(long, default_value_t = 1)]
    batch_size: usize,

    /// UDP payload size in bytes
    #[arg(long, default_value_t = 64)]
    payload_size: usize,

    /// How long to run in seconds (omit to run forever)
    #[arg(long)]
    duration: Option<u64>,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Send packets as fast as possible
    Blast,
    /// Send a batch and wait for all responses before sending the next
    Ping,
}

fn bind_reuseport(addr: SocketAddr) -> UdpSocket {
    let domain = if addr.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
    let sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP)).expect("socket");
    #[cfg(unix)]
    sock.set_reuse_port(true).expect("SO_REUSEPORT");
    #[cfg(not(unix))]
    sock.set_reuse_address(true).expect("SO_REUSEADDR");
    let local: SocketAddr = if addr.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    sock.bind(&local.into()).expect("bind");
    sock.into()
}

fn maybe_flush(counter: &AtomicU64, local: &mut u64, last: &mut Instant) {
    if last.elapsed() >= Duration::from_secs(1) {
        counter.fetch_add(*local, Ordering::Relaxed);
        *local = 0;
        *last = Instant::now();
    }
}

// ── Linux sendmmsg blast ──────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
fn sockaddr_into_storage(addr: SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let len = match addr {
        SocketAddr::V4(v4) => unsafe {
            let sin = &mut *(&mut storage as *mut _ as *mut libc::sockaddr_in);
            sin.sin_family = libc::AF_INET as _;
            sin.sin_port = v4.port().to_be();
            sin.sin_addr.s_addr = u32::from_ne_bytes(v4.ip().octets());
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t
        },
        SocketAddr::V6(v6) => unsafe {
            let sin6 = &mut *(&mut storage as *mut _ as *mut libc::sockaddr_in6);
            sin6.sin6_family = libc::AF_INET6 as _;
            sin6.sin6_port = v6.port().to_be();
            sin6.sin6_addr.s6_addr = v6.ip().octets();
            std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t
        },
    };
    (storage, len)
}

#[cfg(target_os = "linux")]
fn blast_loop_linux(
    sock: &UdpSocket,
    addr: SocketAddr,
    payload: &[u8],
    batch_size: usize,
    counter: &AtomicU64,
) {
    use std::os::fd::AsRawFd;

    let (mut dest, dest_len) = sockaddr_into_storage(addr);
    // iov and dest live for the entire loop; raw pointers into them are stable.
    let iov = libc::iovec { iov_base: payload.as_ptr() as *mut _, iov_len: payload.len() };
    let mut hdrs: Vec<libc::mmsghdr> = (0..batch_size)
        .map(|_| {
            let mut h: libc::mmsghdr = unsafe { std::mem::zeroed() };
            h.msg_hdr.msg_iov = &iov as *const _ as *mut _;
            h.msg_hdr.msg_iovlen = 1;
            h.msg_hdr.msg_name = &mut dest as *mut _ as *mut libc::c_void;
            h.msg_hdr.msg_namelen = dest_len;
            h
        })
        .collect();
    let fd = sock.as_raw_fd();
    let mut local = 0u64;
    let mut last = Instant::now();
    loop {
        let ret = unsafe {
            libc::sendmmsg(fd, hdrs.as_mut_ptr(), batch_size as _, libc::MSG_DONTWAIT)
        };
        if ret > 0 {
            local += ret as u64;
        }
        maybe_flush(counter, &mut local, &mut last);
    }
}

// ── Thread entry points ───────────────────────────────────────────────────────

fn run_blast_thread(addr: SocketAddr, batch_size: usize, payload_size: usize, counter: Arc<AtomicU64>) {
    let sock = bind_reuseport(addr);
    let payload = vec![0xABu8; payload_size];

    #[cfg(target_os = "linux")]
    blast_loop_linux(&sock, addr, &payload, batch_size, &counter);

    #[cfg(not(target_os = "linux"))]
    {
        let mut local = 0u64;
        let mut last = Instant::now();
        loop {
            for _ in 0..batch_size {
                let _ = sock.send_to(&payload, addr);
            }
            local += batch_size as u64;
            maybe_flush(&counter, &mut local, &mut last);
        }
    }
}

fn run_ping_thread(
    addr: SocketAddr,
    batch_size: usize,
    payload_size: usize,
    rx_counter: Arc<AtomicU64>,
    tx_counter: Arc<AtomicU64>,
) {
    let sock = bind_reuseport(addr);
    sock.set_read_timeout(Some(Duration::from_secs(1))).expect("set_read_timeout");
    let payload = vec![0xABu8; payload_size];
    let mut recv_buf = vec![0u8; 65535];
    let mut local_tx = 0u64;
    let mut local_rx = 0u64;
    let mut last = Instant::now();
    loop {
        for _ in 0..batch_size {
            let _ = sock.send_to(&payload, addr);
        }
        local_tx += batch_size as u64;
        let mut received = 0usize;
        while received < batch_size {
            match sock.recv_from(&mut recv_buf) {
                Ok(_) => received += 1,
                Err(_) => break,
            }
        }
        local_rx += received as u64;
        if last.elapsed() >= Duration::from_secs(1) {
            tx_counter.fetch_add(local_tx, Ordering::Relaxed);
            rx_counter.fetch_add(local_rx, Ordering::Relaxed);
            local_tx = 0;
            local_rx = 0;
            last = Instant::now();
        }
    }
}

// ── Main ─────────────────────────────────────────────────────────────────────

fn main() {
    let args = Args::parse();
    let is_ping = matches!(args.cmd, Cmd::Ping);
    let deadline = args.duration.map(|s| Instant::now() + Duration::from_secs(s));
    let rx_counter = Arc::new(AtomicU64::new(0));
    let tx_counter = Arc::new(AtomicU64::new(0));

    for _ in 0..args.threads {
        let rx_counter = Arc::clone(&rx_counter);
        let tx_counter = Arc::clone(&tx_counter);
        let addr = args.address;
        let batch_size = args.batch_size;
        let payload_size = args.payload_size;
        thread::spawn(move || {
            if is_ping {
                run_ping_thread(addr, batch_size, payload_size, rx_counter, tx_counter);
            } else {
                run_blast_thread(addr, batch_size, payload_size, rx_counter);
            }
        });
    }

    loop {
        thread::sleep(Duration::from_secs(1));
        if is_ping {
            let generated = tx_counter.swap(0, Ordering::Relaxed);
            let received = rx_counter.swap(0, Ordering::Relaxed);
            println!("generated={generated}  pps={received}");
        } else {
            let n = rx_counter.swap(0, Ordering::Relaxed);
            println!("pps={n}");
        }
        if deadline.map_or(false, |d| Instant::now() >= d) {
            break;
        }
    }
}
