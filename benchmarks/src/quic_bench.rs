//! Quinn-based QUIC benchmark clients (insecure TLS: for use with local `quic_pong` /
//! `quic_pong_quinn` self-signed servers only). CLI is built with **clap** (`--help` on each binary).
//!
//! When the run ends (duration elapsed, Ctrl-C, or all `stream-ping` tasks finished), a one-line
//! throughput summary is printed (requests/s or connections/s).

use std::net::SocketAddr;
use std::num::NonZeroU64;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use clap::{Args, Parser, Subcommand};
use quinn::VarInt;

#[derive(Parser)]
#[command(
    name = "quic_bench",
    version,
    about = "QUIC load clients (Quinn; skip TLS verification — local benches only)",
    disable_help_subcommand = true
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Open many QUIC connections; each runs a tight write+read ping loop on one bidi stream.
    StreamPing(StreamPingArgs),
    /// Open connections as fast as possible, then close each right after the handshake.
    ConnectChurn(ConnectChurnArgs),
    /// Open N connections, open M bidi streams per connection, ping on all streams concurrently.
    MultiStreamPing(MultiStreamPingArgs),
    /// N connections × M streams pinging, each connection replaced after a fixed lifetime.
    ChurnPing(ChurnPingArgs),
}

#[derive(Args)]
struct StreamPingArgs {
    #[command(flatten)]
    common: BenchCommonArgs,
    #[arg(long, default_value_t = 1024)]
    connections: usize,
}

#[derive(Args)]
struct ConnectChurnArgs {
    #[command(flatten)]
    common: BenchCommonArgs,
}

#[derive(Args)]
struct MultiStreamPingArgs {
    #[command(flatten)]
    common: BenchCommonArgs,
    /// Number of QUIC connections to open.
    #[arg(long, default_value_t = 64)]
    connections: usize,
    /// Number of bidirectional streams to open per connection.
    #[arg(long, default_value_t = 16)]
    streams: usize,
}

#[derive(Args)]
struct ChurnPingArgs {
    #[command(flatten)]
    common: BenchCommonArgs,
    /// Number of stable long-lived connections (each with --streams bidi streams pinging).
    #[arg(long, default_value_t = 64)]
    connections: usize,
    /// Number of bidirectional streams per stable connection.
    #[arg(long, default_value_t = 16)]
    streams: usize,
    /// Rate of connection churn: connections opened (and immediately closed) per second.
    #[arg(long, default_value_t = 100.0)]
    churn_rate: f64,
}

#[derive(Args)]
struct BenchCommonArgs {
    #[arg(long, default_value = "127.0.0.1:4433")]
    addr: SocketAddr,
    /// Tokio worker thread count (default: available parallelism, max 256)
    #[arg(long)]
    threads: Option<usize>,
    /// Stop after this many wall-clock seconds (omit to run until Ctrl-C)
    #[arg(long, value_name = "SECS")]
    duration: Option<NonZeroU64>,
}

impl BenchCommonArgs {
    fn worker_threads(&self) -> usize {
        benchmarks::tokio_worker_threads(self.threads)
    }

    fn duration_secs(&self) -> Option<u64> {
        self.duration.map(NonZeroU64::get)
    }
}

fn main() {
    let cli = Cli::parse();
    if let Err(e) = run(cli) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<(), String> {
    match cli.command {
        Commands::StreamPing(args) => {
            let threads = args.common.worker_threads();
            let addr = args.common.addr;
            let duration_secs = args.common.duration_secs();
            let connections = args.connections.max(1);
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(threads)
                .enable_all()
                .build()
                .map_err(|e| e.to_string())?;
            rt.block_on(async move {
                stream_ping(addr, connections, duration_secs).await;
            });
        }
        Commands::ConnectChurn(args) => {
            let threads = args.common.worker_threads();
            let addr = args.common.addr;
            let duration_secs = args.common.duration_secs();
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(threads)
                .enable_all()
                .build()
                .map_err(|e| e.to_string())?;
            rt.block_on(async move {
                connect_churn(addr, threads, duration_secs).await;
            });
        }
        Commands::MultiStreamPing(args) => {
            let threads = args.common.worker_threads();
            let addr = args.common.addr;
            let duration_secs = args.common.duration_secs();
            let connections = args.connections.max(1);
            let streams = args.streams.max(1);
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(threads)
                .enable_all()
                .build()
                .map_err(|e| e.to_string())?;
            rt.block_on(async move {
                multi_stream_ping(addr, connections, streams, duration_secs).await;
            });
        }
        Commands::ChurnPing(args) => {
            let threads = args.common.worker_threads();
            let addr = args.common.addr;
            let duration_secs = args.common.duration_secs();
            let connections = args.connections.max(1);
            let streams = args.streams.max(1);
            let churn_rate = args.churn_rate.max(0.0);
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(threads)
                .enable_all()
                .build()
                .map_err(|e| e.to_string())?;
            rt.block_on(async move {
                churn_ping(addr, connections, streams, churn_rate, duration_secs).await;
            });
        }
    }
    Ok(())
}

async fn stream_ping(addr: SocketAddr, connections: usize, duration_secs: Option<u64>) {
    let start = Instant::now();
    let requests = Arc::new(AtomicU64::new(0));
    let endpoint = benchmarks::quinn_client::make_insecure_client_endpoint().expect("client endpoint");
    match duration_secs {
        Some(s) => eprintln!(
            "stream-ping: {connections} connections to {addr} (stop after {s}s or Ctrl-C)"
        ),
        None => eprintln!(
            "stream-ping: {connections} connections to {addr} (Ctrl-C to stop)"
        ),
    }

    let mut join = tokio::task::JoinSet::new();
    for _ in 0..connections {
        let ep = endpoint.clone();
        let requests = Arc::clone(&requests);
        join.spawn(async move {
            let conn = ep
                .connect(addr, "localhost")
                .expect("connect")
                .await
                .expect("handshake");
            let (mut send, mut recv) = conn.open_bi().await.expect("open_bi");
            const PING: &[u8] = b"pingping";
            let mut buf = [0u8; 64];
            loop {
                send.write_all(PING).await.expect("write");
                match recv.read(&mut buf).await {
                    Ok(Some(n)) if n < PING.len() => {
                        panic!("short read {n}");
                    }
                    Ok(Some(_)) => {
                        requests.fetch_add(1, Ordering::Relaxed);
                    }
                    Ok(None) => break,
                    Err(e) => panic!("read: {e}"),
                }
            }
        });
    }

    drive_until_stop(&mut join, "stream-ping", duration_secs).await;
    join.abort_all();
    print_request_rate("stream-ping", requests.load(Ordering::Relaxed), start);
    endpoint.close(0u32.into(), &[]);
    let _ = endpoint.wait_idle().await;
}

async fn multi_stream_ping(
    addr: SocketAddr,
    connections: usize,
    streams: usize,
    duration_secs: Option<u64>,
) {
    let start = Instant::now();
    let requests = Arc::new(AtomicU64::new(0));
    let endpoint = benchmarks::quinn_client::make_insecure_client_endpoint().expect("client endpoint");
    let total_streams = connections * streams;
    match duration_secs {
        Some(s) => eprintln!(
            "multi-stream-ping: {connections} connections × {streams} streams \
             = {total_streams} streams to {addr} (stop after {s}s or Ctrl-C)"
        ),
        None => eprintln!(
            "multi-stream-ping: {connections} connections × {streams} streams \
             = {total_streams} streams to {addr} (Ctrl-C to stop)"
        ),
    }

    let mut join = tokio::task::JoinSet::new();
    for _ in 0..connections {
        let ep = endpoint.clone();
        let requests = Arc::clone(&requests);
        join.spawn(async move {
            let conn = ep
                .connect(addr, "localhost")
                .expect("connect")
                .await
                .expect("handshake");
            let conn = Arc::new(conn);

            let mut stream_tasks = tokio::task::JoinSet::new();
            for _ in 0..streams {
                let conn = Arc::clone(&conn);
                let requests = Arc::clone(&requests);
                stream_tasks.spawn(async move {
                    let (mut send, mut recv) = conn.open_bi().await.expect("open_bi");
                    const PING: &[u8] = b"pingping";
                    let mut buf = [0u8; 64];
                    loop {
                        send.write_all(PING).await.expect("write");
                        match recv.read(&mut buf).await {
                            Ok(Some(n)) if n < PING.len() => panic!("short read {n}"),
                            Ok(Some(_)) => {
                                requests.fetch_add(1, Ordering::Relaxed);
                            }
                            Ok(None) => break,
                            Err(e) => panic!("read: {e}"),
                        }
                    }
                });
            }

            while stream_tasks.join_next().await.is_some() {}
        });
    }

    drive_until_stop(&mut join, "multi-stream-ping", duration_secs).await;
    join.abort_all();
    print_request_rate("multi-stream-ping", requests.load(Ordering::Relaxed), start);
    endpoint.close(0u32.into(), &[]);
    let _ = endpoint.wait_idle().await;
}

async fn churn_ping(
    addr: SocketAddr,
    connections: usize,
    streams: usize,
    churn_rate: f64,
    duration_secs: Option<u64>,
) {
    let start = Instant::now();
    let requests = Arc::new(AtomicU64::new(0));
    let churned = Arc::new(AtomicU64::new(0));
    let total_streams = connections * streams;

    let endpoint = benchmarks::quinn_client::make_insecure_client_endpoint().expect("client endpoint");
    // Churn connections skip resumption so every replacement is a full handshake.
    let churn_endpoint =
        benchmarks::quinn_client::make_insecure_client_endpoint_no_resumption()
            .expect("churn endpoint");

    match duration_secs {
        Some(s) => eprintln!(
            "churn-ping: {connections} stable connections × {streams} streams \
             ({total_streams} streams) + {churn_rate:.0} churn conn/s to {addr} \
             (stop after {s}s or Ctrl-C)"
        ),
        None => eprintln!(
            "churn-ping: {connections} stable connections × {streams} streams \
             ({total_streams} streams) + {churn_rate:.0} churn conn/s to {addr} \
             (Ctrl-C to stop)"
        ),
    }

    let mut join = tokio::task::JoinSet::new();

    // Stable pool: long-lived connections, M streams each, tight ping loop.
    for _ in 0..connections {
        let ep = endpoint.clone();
        let requests = Arc::clone(&requests);
        join.spawn(async move {
            let connecting = match ep.connect(addr, "localhost") {
                Ok(c) => c,
                Err(_) => return,
            };
            let conn = match connecting.await {
                Ok(c) => Arc::new(c),
                Err(_) => return,
            };
            let mut stream_tasks = tokio::task::JoinSet::new();
            for _ in 0..streams {
                let conn = Arc::clone(&conn);
                let requests = Arc::clone(&requests);
                stream_tasks.spawn(async move {
                    let (mut send, mut recv) = conn.open_bi().await.ok()?;
                    const PING: &[u8] = b"pingping";
                    let mut buf = [0u8; 64];
                    loop {
                        if send.write_all(PING).await.is_err() {
                            break;
                        }
                        match recv.read(&mut buf).await {
                            Ok(Some(_)) => { requests.fetch_add(1, Ordering::Relaxed); }
                            _ => break,
                        }
                    }
                    Some(())
                });
            }
            while stream_tasks.join_next().await.is_some() {}
        });
    }

    // Churn task: fires one connection attempt per tick, closes immediately after handshake.
    // Spawning each attempt separately lets them complete concurrently without blocking the ticker.
    if churn_rate > 0.0 {
        let churn_endpoint = churn_endpoint.clone();
        let churned = Arc::clone(&churned);
        join.spawn(async move {
            let interval =
                std::time::Duration::from_secs_f64(1.0 / churn_rate);
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                ticker.tick().await;
                let ep = churn_endpoint.clone();
                let churned = Arc::clone(&churned);
                tokio::spawn(async move {
                    if let Ok(connecting) = ep.connect(addr, "localhost") {
                        if let Ok(conn) = connecting.await {
                            churned.fetch_add(1, Ordering::Relaxed);
                            conn.close(VarInt::from_u32(0), &[]);
                        }
                    }
                });
            }
        });
    }

    drive_until_stop(&mut join, "churn-ping", duration_secs).await;
    join.abort_all();

    let elapsed = start.elapsed().as_secs_f64().max(1e-9);
    let total_req = requests.load(Ordering::Relaxed);
    let total_churn = churned.load(Ordering::Relaxed);
    eprintln!(
        "churn-ping: {total_req} stream round-trips in {elapsed:.3}s = {:.2} req/s, \
         {total_churn} churn connections = {:.2} conn/s",
        total_req as f64 / elapsed,
        total_churn as f64 / elapsed,
    );

    endpoint.close(0u32.into(), &[]);
    churn_endpoint.close(0u32.into(), &[]);
    let _ = endpoint.wait_idle().await;
}

async fn connect_churn(addr: SocketAddr, workers: usize, duration_secs: Option<u64>) {
    let start = Instant::now();
    let connections_opened = Arc::new(AtomicU64::new(0));
    let endpoint = benchmarks::quinn_client::make_insecure_client_endpoint_no_resumption()
        .expect("client endpoint");
    match duration_secs {
        Some(s) => eprintln!(
            "connect-churn: {workers} workers hammering {addr} (stop after {s}s or Ctrl-C)"
        ),
        None => eprintln!(
            "connect-churn: {workers} workers hammering {addr} (Ctrl-C to stop)"
        ),
    }

    let mut join = tokio::task::JoinSet::new();
    for _ in 0..workers {
        let ep = endpoint.clone();
        let connections_opened = Arc::clone(&connections_opened);
        join.spawn(async move {
            loop {
                let connecting = match ep.connect(addr, "localhost") {
                    Ok(c) => c,
                    Err(_) => continue,
                };
                if let Ok(conn) = connecting.await {
                    connections_opened.fetch_add(1, Ordering::Relaxed);
                    conn.close(VarInt::from_u32(0), &[]);
                }
            }
        });
    }

    drive_until_stop(&mut join, "connect-churn", duration_secs).await;
    join.abort_all();
    print_connection_rate(
        "connect-churn",
        connections_opened.load(Ordering::Relaxed),
        start,
    );
    endpoint.close(0u32.into(), &[]);
    let _ = endpoint.wait_idle().await;
}

fn print_request_rate(label: &str, total: u64, start: Instant) {
    let elapsed = start.elapsed().as_secs_f64().max(1e-9);
    let rps = total as f64 / elapsed;
    eprintln!(
        "{label}: {total} request round-trips in {elapsed:.3}s = {rps:.2} req/s"
    );
}

fn print_connection_rate(label: &str, total: u64, start: Instant) {
    let elapsed = start.elapsed().as_secs_f64().max(1e-9);
    let cps = total as f64 / elapsed;
    eprintln!(
        "{label}: {total} connections opened in {elapsed:.3}s = {cps:.2} conn/s"
    );
}

async fn drive_until_stop(
    join: &mut tokio::task::JoinSet<()>,
    label: &'static str,
    duration_secs: Option<u64>,
) {
    let deadline = duration_secs
        .map(|s| tokio::time::Instant::now() + std::time::Duration::from_secs(s));
    if let Some(dl) = deadline {
        loop {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    eprintln!("{label}: stopping (interrupt)");
                    break;
                }
                _ = tokio::time::sleep_until(dl) => {
                    eprintln!(
                        "{label}: stopping (after {}s)",
                        duration_secs.expect("deadline set from duration_secs")
                    );
                    break;
                }
                r = join.join_next() => {
                    match r {
                        None => break,
                        Some(Err(e)) => eprintln!("{label} task failed: {e}"),
                        Some(Ok(())) => {}
                    }
                }
            }
        }
    } else {
        loop {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    eprintln!("{label}: stopping (interrupt)");
                    break;
                }
                r = join.join_next() => {
                    match r {
                        None => break,
                        Some(Err(e)) => eprintln!("{label} task failed: {e}"),
                        Some(Ok(())) => {}
                    }
                }
            }
        }
    }
}

