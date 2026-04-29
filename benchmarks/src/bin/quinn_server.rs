use std::net::SocketAddr;
use std::sync::Arc;

use clap::Parser;

const ALPN: &[u8] = b"bench";

#[derive(Debug, Parser)]
struct Args {
    /// Address to listen on
    #[clap(long, default_value = "[::]:4433")]
    listen: SocketAddr,

    /// Tokio worker threads (default: number of CPU cores)
    #[clap(long)]
    threads: Option<usize>,
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
    let server_config = make_server_config();
    let endpoint =
        quinn::Endpoint::server(server_config, args.listen).expect("server endpoint");

    println!("listening on {}", args.listen);

    while let Some(incoming) = endpoint.accept().await {
        tokio::spawn(async move {
            let conn = match incoming.await {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("accept failed: {e}");
                    return;
                }
            };
            handle_connection(conn).await;
        });
    }
}

async fn handle_connection(conn: quinn::Connection) {
    loop {
        match conn.accept_bi().await {
            Ok((send, recv)) => {
                tokio::spawn(echo_stream(send, recv));
            }
            Err(quinn::ConnectionError::ApplicationClosed(_)) => break,
            Err(e) => {
                eprintln!("accept_bi: {e}");
                break;
            }
        }
    }
}

async fn echo_stream(mut send: quinn::SendStream, mut recv: quinn::RecvStream) {
    loop {
        match recv.read_chunk(usize::MAX, true).await {
            Ok(Some(chunk)) => {
                if let Err(e) = send.write_all(&chunk.bytes).await {
                    eprintln!("echo write: {e}");
                    break;
                }
            }
            Ok(None) => {
                let _ = send.finish();
                break;
            }
            Err(e) => {
                eprintln!("echo read: {e}");
                break;
            }
        }
    }
}

fn make_server_config() -> quinn::ServerConfig {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])
        .expect("cert generation");
    let cert_der = rustls::pki_types::CertificateDer::from(cert.cert.der().to_vec());
    let priv_key = rustls::pki_types::PrivateKeyDer::try_from(cert.signing_key.serialize_der())
        .expect("private key");

    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], priv_key)
        .expect("server TLS");
    tls.alpn_protocols = vec![ALPN.to_vec()];

    let quic = quinn::crypto::rustls::QuicServerConfig::try_from(tls).expect("quic TLS");
    let mut sc = quinn::ServerConfig::with_crypto(Arc::new(quic));
    let mut tc = quinn::TransportConfig::default();
    tc.initial_mtu(1400).mtu_discovery_config(None);
    sc.transport_config(Arc::new(tc));
    sc
}
