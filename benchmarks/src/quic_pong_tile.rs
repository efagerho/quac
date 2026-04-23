//! QUIC echo server using the tile-based architecture: accepts connections and
//! reflects each received bidirectional stream payload back on the same stream.
//!
//! `--threads N` sets N network tiles and N engine tiles (3N OS I/O threads total:
//! one reader, one writer, and one engine per tile). A separate Tokio thread pool
//! handles the async connection and stream accept loops.
//!
//! Matches the CLI of `quic_pong` and `quic_pong_quinn`. Use `--exit-delay-secs`
//! a few seconds above `quic_bench --duration` so the process outlives the client.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use benchmarks::listen;
use clap::Parser;
use quic_proto::{EndpointConfig, ServerConfig};
use quac::{RecvStream, SendStream, TileSet};
use rustls::pki_types::PrivateKeyDer;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Parser)]
#[command(
    name = "quic_pong_tile",
    version,
    about = "QUIC echo server (tile-based architecture)"
)]
struct Args {
    /// Bind as ADDR:PORT, or PORT only (uses 0.0.0.0:PORT)
    #[arg(long, value_name = "ADDR:PORT")]
    listen: Option<String>,
    /// UDP port only (binds 0.0.0.0:PORT; ignored if `--listen` includes a host)
    #[arg(long)]
    port: Option<u16>,
    /// After Ctrl+C, keep running this many seconds before exiting.
    #[arg(long, default_value_t = 0)]
    exit_delay_secs: u64,
    /// Number of network tiles and engine tiles (default: 1).
    /// Each tile spawns one reader thread, one writer thread, and one engine thread.
    #[arg(long, default_value_t = 1)]
    threads: usize,
    /// Number of Tokio worker threads for the async accept loop (default: number of CPUs).
    #[arg(long)]
    tokio_threads: Option<usize>,
}

fn main() {
    let args = Args::parse();
    let worker_threads = benchmarks::tokio_worker_threads(args.tokio_threads);
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(worker_threads)
        .enable_all()
        .build()
        .unwrap_or_else(|e| {
            eprintln!("error: tokio runtime: {e}");
            std::process::exit(1);
        });
    if let Err(e) = rt.block_on(run(args)) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

async fn run(args: Args) -> Result<(), String> {
    let addr: SocketAddr = listen::bind_addr(args.listen, args.port)?;
    let num_tiles = args.threads.max(1);

    let certified =
        rcgen::generate_simple_self_signed(["localhost".into()]).map_err(|e| e.to_string())?;
    let cert_der = certified.cert.der().clone();
    let key = PrivateKeyDer::Pkcs8(certified.signing_key.serialize_der().into());
    let server_config = Arc::new(
        ServerConfig::with_single_cert(vec![cert_der], key).map_err(|e| e.to_string())?,
    );

    let tileset = TileSet::with_os_sockets(
        addr,
        num_tiles,
        num_tiles,
        EndpointConfig::default(),
        server_config,
    );
    let endpoint = tileset.endpoint();

    eprintln!(
        "QUIC pong (tile) listening on {addr} \
         ({num_tiles} network tile(s), {num_tiles} engine tile(s), self-signed localhost cert)"
    );

    let exit_delay = args.exit_delay_secs;
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                if exit_delay > 0 {
                    eprintln!(
                        "quic_pong_tile: Ctrl-C received, waiting {exit_delay}s before exit"
                    );
                    tokio::time::sleep(Duration::from_secs(exit_delay)).await;
                }
                break;
            }
            conn = endpoint.accept() => {
                let Some(conn) = conn else { break };
                tokio::spawn(async move {
                    loop {
                        match conn.accept_bi().await {
                            Some((send, recv)) => {
                                tokio::spawn(echo_stream(send, recv));
                            }
                            None => break,
                        }
                    }
                });
            }
        }
    }

    Ok(())
}

async fn echo_stream(mut send: SendStream, mut recv: RecvStream) {
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = match recv.read(&mut buf).await {
            Ok(n) => n,
            Err(_) => break,
        };
        if n == 0 {
            break;
        }
        if send.write_all(&buf[..n]).await.is_err() {
            break;
        }
    }
    send.finish();
}
