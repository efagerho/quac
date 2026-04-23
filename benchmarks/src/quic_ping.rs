//! Single-connection Quinn client: one bidirectional stream, one `pingping` write, wait for echo.
//! Intended for smoke tests against `quic_pong_quinn` (same payload as `quic_bench` stream-ping).

use std::net::SocketAddr;

use clap::Parser;
use quinn::VarInt;

#[derive(Parser)]
#[command(name = "quic_ping", version, about = "One-shot QUIC echo ping (Quinn; local self-signed servers only)")]
struct Args {
    /// Server address
    #[arg(long, default_value = "127.0.0.1:4433")]
    addr: SocketAddr,
    /// TLS server name (SNI); must match cert (default `localhost` for rcgen / quic_pong_quinn)
    #[arg(long, default_value = "localhost")]
    server_name: String,
    /// Tokio worker threads (default: same policy as `quic_bench` / `quic_pong_quinn`)
    #[arg(long)]
    threads: Option<usize>,
}

fn main() {
    let args = Args::parse();
    let worker_threads = benchmarks::tokio_worker_threads(args.threads);
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
    const PING: &[u8] = b"pingping";

    let endpoint = benchmarks::quinn_client::make_insecure_client_endpoint().map_err(|e| e.to_string())?;
    eprintln!("quic_ping: connecting to {} (SNI {})", args.addr, args.server_name);

    let conn = endpoint
        .connect(args.addr, &args.server_name)
        .map_err(|e| e.to_string())?
        .await
        .map_err(|e| format!("handshake: {e}"))?;

    let (mut send, mut recv) = conn.open_bi().await.map_err(|e| e.to_string())?;
    send.write_all(PING)
        .await
        .map_err(|e| format!("write: {e}"))?;
    send.finish().map_err(|e| format!("finish: {e}"))?;

    let mut buf = vec![0u8; PING.len().max(64)];
    let n = match recv.read(&mut buf).await {
        Ok(Some(n)) => n,
        Ok(None) => return Err("recv: stream closed before echo".into()),
        Err(e) => return Err(format!("read: {e}")),
    };

    if n < PING.len() {
        return Err(format!("short read: got {n} bytes, expected {}", PING.len()));
    }
    if &buf[..PING.len()] != PING {
        return Err(format!(
            "echo mismatch: expected {:?}, got {:?}",
            PING,
            &buf[..PING.len()]
        ));
    }

    println!(
        "quic_ping: ok — echoed {} bytes (matches `quic_bench` / `quic_pong_quinn` ping payload)",
        PING.len()
    );

    conn.close(VarInt::from_u32(0), &[]);
    endpoint.close(VarInt::from_u32(0), &[]);
    let _ = endpoint.wait_idle().await;
    Ok(())
}
