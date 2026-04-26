use std::io;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use clap::{Parser, Subcommand};

use quac_socket::{PacketSocket, RecvMeta, ScatterGather, Transmit};
use quac_socket_os::{OsBufMut, OsSocket};

#[derive(Parser)]
struct Args {
    #[command(subcommand)]
    mode: Mode,
}

#[derive(Subcommand)]
enum Mode {
    /// Count received packets and print PPS every second
    Count {
        /// Address to listen on (e.g. 0.0.0.0:4000)
        #[arg(long)]
        address: SocketAddr,
    },
    /// Reflect each received packet back to its sender
    Pong {
        /// Address to listen on (e.g. 0.0.0.0:4000)
        #[arg(long)]
        address: SocketAddr,
    },
}

struct Stats {
    packets: u64,
    batch_sum: u64,
    recv_calls: u64,
    last_print: Instant,
}

impl Stats {
    fn new() -> Self {
        Self { packets: 0, batch_sum: 0, recv_calls: 0, last_print: Instant::now() }
    }

    fn record(&mut self, n: usize) {
        self.packets += n as u64;
        self.batch_sum += n as u64;
        self.recv_calls += 1;
    }

    /// Print and reset if a second has elapsed.
    fn maybe_print(&mut self) {
        let elapsed = self.last_print.elapsed();
        if elapsed < Duration::from_secs(1) {
            return;
        }
        let pps = self.packets as f64 / elapsed.as_secs_f64();
        let avg_batch = if self.recv_calls > 0 {
            self.batch_sum as f64 / self.recv_calls as f64
        } else {
            0.0
        };
        println!("pps={pps:.0}  avg_batch={avg_batch:.2}");
        self.packets = 0;
        self.batch_sum = 0;
        self.recv_calls = 0;
        self.last_print = Instant::now();
    }
}

fn main() {
    let args = Args::parse();
    match args.mode {
        Mode::Count { address } => run_count(address),
        Mode::Pong { address } => run_pong(address),
    }
}

fn run_count(address: SocketAddr) {
    let mut socket = OsSocket::bind(address).expect("bind");
    let mut meta = vec![RecvMeta::default(); 64];
    let mut bufs: Vec<ScatterGather<OsBufMut>> = Vec::new();
    let mut stats = Stats::new();

    loop {
        match socket.recv(&mut meta, &mut bufs) {
            Ok(n) => {
                stats.record(n);
                bufs.clear();
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => {
                eprintln!("recv error: {e}");
                break;
            }
        }
        stats.maybe_print();
    }
}

fn run_pong(address: SocketAddr) {
    let mut socket = OsSocket::bind(address).expect("bind");
    let mut meta = vec![RecvMeta::default(); 64];
    let mut bufs: Vec<ScatterGather<OsBufMut>> = Vec::new();
    let mut stats = Stats::new();

    loop {
        match socket.recv(&mut meta, &mut bufs) {
            Ok(n) => {
                stats.record(n);
                let transmits: Vec<_> = bufs.drain(..n)
                    .zip(meta.iter())
                    .map(|(sg, m)| Transmit {
                        destination: m.src,
                        ecn: None,
                        contents: sg.freeze(),
                        segment_size: None,
                        src_ip: None,
                    })
                    .collect();
                socket.send(transmits);
                socket.drain_completions();
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => {
                eprintln!("recv error: {e}");
                break;
            }
        }
        stats.maybe_print();
    }
}
