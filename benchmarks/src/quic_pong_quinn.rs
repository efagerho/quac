//! QUIC echo server using the [Quinn](https://github.com/quinn-rs/quinn) stack: accepts
//! connections and reflects each received bidirectional stream payload back on the same stream.
//!
//! Matches the CLI and behavior of `quic_pong` (self-signed `localhost` cert, default
//! `0.0.0.0:4433`). Client-initiated **uni** streams are disabled at the transport layer so the
//! server only accepts **bidirectional** streams, mirroring the proto-engine pong semantics.
//!
//! Use `--exit-delay-secs` a few seconds above `quic_bench --duration` when automating runs so
//! the process outlives the timed client slightly. For a one-shot echo client, run
//! `cargo run -p benchmarks --bin quic_ping`.

use std::net::SocketAddr;
use std::sync::Arc;

use benchmarks::listen;
use clap::Parser;
use quinn::crypto::rustls::QuicServerConfig;
use rustls::pki_types::PrivateKeyDer;

#[derive(Parser)]
#[command(name = "quic_pong_quinn", version, about = "QUIC echo server (Quinn)")]
struct Args {
    #[arg(long, value_name = "ADDR:PORT")]
    listen: Option<String>,
    #[arg(long)]
    port: Option<u16>,
    /// After Ctrl+C, keep running this many seconds before exiting (set a few seconds above
    /// `quic_bench --duration` so the client can finish cleanly).
    #[arg(long, default_value_t = 0)]
    exit_delay_secs: u64,
    /// Tokio worker thread count (default: available parallelism, max 256), same as `quic_bench`.
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

async fn run(args: Args) -> Result<(), RunError> {
    let addr: SocketAddr = listen::bind_addr(args.listen, args.port)?;

    let certified = rcgen::generate_simple_self_signed(["localhost".into()])?;
    let cert = certified.cert.der().clone();
    let key = PrivateKeyDer::Pkcs8(certified.signing_key.serialize_der().into());

    let mut rustls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .map_err(|e| RunError(format!("rustls: {e}")))?;
    rustls_config.max_early_data_size = u32::MAX;

    let crypto = Arc::new(
        QuicServerConfig::try_from(rustls_config).map_err(|e| RunError(format!("quic tls: {e}")))?,
    );
    let mut server_config = quinn::ServerConfig::with_crypto(crypto);
    let transport = Arc::get_mut(&mut server_config.transport).ok_or_else(|| {
        RunError("server transport config is unexpectedly shared".into())
    })?;
    transport.max_concurrent_uni_streams(0u32.into());

    let endpoint = quinn::Endpoint::server(server_config, addr).map_err(|e| RunError(e.to_string()))?;
    eprintln!(
        "QUIC pong (Quinn) listening on {} (self-signed localhost cert)",
        endpoint.local_addr().map_err(|e| RunError(e.to_string()))?
    );

    let exit_delay = args.exit_delay_secs;
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                if exit_delay > 0 {
                    eprintln!(
                        "quic_pong_quinn: Ctrl-C received, waiting {exit_delay}s before exit"
                    );
                    tokio::time::sleep(std::time::Duration::from_secs(exit_delay)).await;
                }
                break;
            }
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else {
                    break;
                };
                tokio::spawn(async move {
                    let conn = match incoming.await {
                        Ok(c) => c,
                        Err(e) => {
                            eprintln!("handshake failed: {e}");
                            return;
                        }
                    };
                    loop {
                        match conn.accept_bi().await {
                            Ok((mut send, mut recv)) => {
                                tokio::spawn(async move {
                                    let mut buf = vec![0u8; 256 * 1024];
                                    loop {
                                        match recv.read(&mut buf).await {
                                            Ok(None) => break,
                                            Ok(Some(0)) => continue,
                                            Ok(Some(n)) => {
                                                if send.write_all(&buf[..n]).await.is_err() {
                                                    break;
                                                }
                                            }
                                            Err(_) => break,
                                        }
                                    }
                                    let _ = send.finish();
                                });
                            }
                            Err(quinn::ConnectionError::ApplicationClosed(_)) => break,
                            Err(quinn::ConnectionError::LocallyClosed) => break,
                            Err(e) => {
                                eprintln!("accept_bi: {e}");
                                break;
                            }
                        }
                    }
                });
            }
        }
    }

    Ok(())
}

#[derive(Debug)]
struct RunError(String);

impl std::fmt::Display for RunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl std::error::Error for RunError {}

impl From<rcgen::Error> for RunError {
    fn from(e: rcgen::Error) -> Self {
        RunError(e.to_string())
    }
}

impl From<std::net::AddrParseError> for RunError {
    fn from(e: std::net::AddrParseError) -> Self {
        RunError(e.to_string())
    }
}

impl From<String> for RunError {
    fn from(s: String) -> Self {
        RunError(s)
    }
}
