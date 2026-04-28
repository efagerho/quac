use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::{Parser, Subcommand, ValueEnum};

use quac_network_tile::{NetworkTile, NetworkTileImpl, RxPacket};
use quac_socket::Transmit;
use quac_socket_os::OsSocket;

#[derive(Parser)]
struct Args {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(ValueEnum, Clone)]
enum ThreadMode {
    Combined,
    Separate,
}

#[derive(Subcommand)]
enum Cmd {
    /// Count received packets and print PPS every second
    Count {
        /// Address to listen on (e.g. 0.0.0.0:4000)
        #[arg(long)]
        address: SocketAddr,
        /// Use one combined Rx+Tx thread or separate threads
        #[arg(long, value_enum, default_value_t = ThreadMode::Combined)]
        mode: ThreadMode,
    },
    /// Reflect each received packet back to its sender
    Pong {
        /// Address to listen on (e.g. 0.0.0.0:4000)
        #[arg(long)]
        address: SocketAddr,
        /// Use one combined Rx+Tx thread or separate threads
        #[arg(long, value_enum, default_value_t = ThreadMode::Combined)]
        mode: ThreadMode,
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

fn make_tile(address: SocketAddr, mode: &ThreadMode) -> Arc<NetworkTileImpl<OsSocket>> {
    match mode {
        ThreadMode::Combined => {
            let socket = OsSocket::bind(address).expect("bind");
            Arc::new(NetworkTileImpl::combined(socket, 1))
        }
        ThreadMode::Separate => {
            let rx = OsSocket::bind(address).expect("bind");
            let tx = rx.try_clone().expect("try_clone");
            Arc::new(NetworkTileImpl::separate(rx, tx, 1))
        }
    }
}

fn main() {
    let args = Args::parse();

    match args.cmd {
        Cmd::Count { address, mode } => {
            let tile = make_tile(address, &mode);
            let rx_queue = Arc::clone(&tile.rx_queues()[0]);
            Arc::clone(&tile).start();

            let mut stats = Stats::new();
            loop {
                let mut n = 0usize;
                while rx_queue.pop().is_some() {
                    n += 1;
                }
                if n > 0 {
                    stats.record(n);
                }
                stats.maybe_print();
                std::hint::spin_loop();
            }
        }
        Cmd::Pong { address, mode } => {
            let tile = make_tile(address, &mode);
            let rx_queue = Arc::clone(&tile.rx_queues()[0]);
            let tx_queue = Arc::clone(&tile.tx_queues()[0]);
            Arc::clone(&tile).start();

            let mut stats = Stats::new();
            loop {
                let mut n = 0usize;
                while let Some(RxPacket { meta, payload }) = rx_queue.pop() {
                    let _ = tx_queue.push(Transmit {
                        destination: meta.src,
                        ecn: meta.ecn,
                        contents: payload.freeze(),
                        segment_size: None,
                        src_ip: None,
                    });
                    n += 1;
                }
                if n > 0 {
                    stats.record(n);
                }
                stats.maybe_print();
                std::hint::spin_loop();
            }
        }
    }
}
