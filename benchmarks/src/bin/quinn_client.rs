use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::Parser;
use rustls::pki_types::ServerName;

const ALPN: &[u8] = b"bench";
const PING_PAYLOAD: &[u8] = &[0u8; 8];

#[derive(Debug, Parser)]
struct Args {
    /// QUIC server address to connect to
    #[clap(long)]
    server: SocketAddr,

    /// Number of QUIC connections to open
    #[clap(long, default_value = "1")]
    connections: usize,

    /// Number of bidirectional streams per connection
    #[clap(long, default_value = "1")]
    streams: usize,

    /// How long to run (seconds)
    #[clap(long, default_value = "10")]
    duration: u64,

    /// Tokio worker threads (default: number of CPU cores)
    #[clap(long)]
    threads: Option<usize>,

    /// TLS server name for SNI
    #[clap(long, default_value = "localhost")]
    server_name: String,
}

fn main() {
    let args = Args::parse();

    let mut builder = tokio::runtime::Builder::new_multi_thread();
    builder.enable_all();
    if let Some(n) = args.threads {
        builder.worker_threads(n);
    }
    let rt = builder.build().expect("tokio runtime");
    rt.block_on(run(args));
}

async fn run(args: Args) {
    let client_config = make_client_config();

    let mut endpoint =
        quinn::Endpoint::client("0.0.0.0:0".parse().unwrap()).expect("client endpoint");
    endpoint.set_default_client_config(client_config);

    let counter = Arc::new(AtomicU64::new(0));
    let stop = Arc::new(AtomicBool::new(false));

    let deadline = Instant::now() + Duration::from_secs(args.duration);

    let mut tasks = Vec::new();
    for _ in 0..args.connections {
        let ep = endpoint.clone();
        let addr = args.server;
        let name = args.server_name.clone();
        let streams = args.streams;
        let counter = Arc::clone(&counter);
        let stop = Arc::clone(&stop);

        tasks.push(tokio::spawn(async move {
            let conn = match ep.connect(addr, &name).expect("connect").await {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("connection failed: {e}");
                    return;
                }
            };

            let mut stream_tasks = Vec::new();
            for _ in 0..streams {
                let conn = conn.clone();
                let counter = Arc::clone(&counter);
                let stop = Arc::clone(&stop);

                stream_tasks.push(tokio::spawn(async move {
                    let (mut send, mut recv) = match conn.open_bi().await {
                        Ok(s) => s,
                        Err(e) => {
                            eprintln!("open_bi failed: {e}");
                            return;
                        }
                    };

                    while !stop.load(Ordering::Relaxed) {
                        if let Err(e) = send.write_all(PING_PAYLOAD).await {
                            eprintln!("write failed: {e}");
                            break;
                        }
                        match recv.read_chunk(PING_PAYLOAD.len(), true).await {
                            Ok(Some(_)) => {
                                counter.fetch_add(1, Ordering::Relaxed);
                            }
                            Ok(None) => break,
                            Err(e) => {
                                eprintln!("read failed: {e}");
                                break;
                            }
                        }
                    }
                }));
            }

            for t in stream_tasks {
                let _ = t.await;
            }
        }));
    }

    // Wait for the measurement window.
    tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)).await;
    stop.store(true, Ordering::Relaxed);

    for t in tasks {
        let _ = t.await;
    }

    let elapsed = deadline.elapsed() + Duration::from_secs(args.duration);
    let total = counter.load(Ordering::Relaxed);
    // elapsed is >= duration; use the requested duration for a clean RPS number
    let secs = args.duration as f64;
    let rps = total as f64 / secs;

    println!("duration:       {secs:.2}s");
    println!("pings received: {total}");
    println!("rps:            {rps:.0}");

    endpoint.close(0u32.into(), b"done");
}

fn make_client_config() -> quinn::ClientConfig {
    let provider = Arc::new(rustls::crypto::ring::default_provider());

    let mut tls = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipVerify(provider)))
        .with_no_client_auth();
    tls.alpn_protocols = vec![ALPN.to_vec()];

    quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls).expect("client TLS"),
    ))
}

#[derive(Debug)]
struct SkipVerify(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for SkipVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}
