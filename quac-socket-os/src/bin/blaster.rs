use std::net::{SocketAddr, UdpSocket};
use std::thread;
use std::time::{Duration, Instant};

use clap::{Parser, Subcommand};

#[derive(Parser)]
struct Args {
    #[command(subcommand)]
    mode: Mode,
}

#[derive(Subcommand)]
enum Mode {
    /// Send UDP packets as fast as possible
    Bombard {
        /// Destination address (e.g. 127.0.0.1:4000)
        #[arg(long)]
        address: SocketAddr,
        /// Number of sender threads
        #[arg(long)]
        threads: usize,
        /// UDP payload size in bytes
        #[arg(long)]
        payload_size: usize,
        /// Number of packets sent per loop iteration
        #[arg(long, default_value_t = 1)]
        batch_size: usize,
        /// How long to run in seconds
        #[arg(long)]
        duration: u64,
    },
    /// Send one packet and wait for a reply before sending the next
    Ping {
        /// Destination address (e.g. 127.0.0.1:4000)
        #[arg(long)]
        address: SocketAddr,
        /// Number of sender threads
        #[arg(long)]
        threads: usize,
        /// UDP payload size in bytes
        #[arg(long)]
        payload_size: usize,
        /// How long to run in seconds
        #[arg(long)]
        duration: u64,
    },
}

fn main() {
    let args = Args::parse();

    match args.mode {
        Mode::Bombard { address, threads, payload_size, batch_size, duration } => {
            let payload: Vec<u8> = vec![0xAB; payload_size];
            let deadline = Instant::now() + Duration::from_secs(duration);
            let handles: Vec<_> = (0..threads)
                .map(|_| {
                    let buf = payload.clone();
                    thread::spawn(move || {
                        let socket = UdpSocket::bind("0.0.0.0:0").expect("bind");
                        while Instant::now() < deadline {
                            for _ in 0..batch_size {
                                let _ = socket.send_to(&buf, address);
                            }
                        }
                    })
                })
                .collect();
            for h in handles {
                let _ = h.join();
            }
        }
        Mode::Ping { address, threads, payload_size, duration } => {
            let payload: Vec<u8> = vec![0xAB; payload_size];
            let deadline = Instant::now() + Duration::from_secs(duration);
            let handles: Vec<_> = (0..threads)
                .map(|_| {
                    let buf = payload.clone();
                    thread::spawn(move || {
                        let socket = UdpSocket::bind("0.0.0.0:0").expect("bind");
                        let mut recv_buf = vec![0u8; 65535];
                        while Instant::now() < deadline {
                            let _ = socket.send_to(&buf, address);
                            let _ = socket.recv(&mut recv_buf);
                        }
                    })
                })
                .collect();
            for h in handles {
                let _ = h.join();
            }
        }
    }
}
