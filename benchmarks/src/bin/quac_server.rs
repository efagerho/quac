/// quac_server — QUIC echo server using the quac-tile engine stack.
///
/// Each tile binds an SO_REUSEPORT socket and drives one engine thread.
/// The application layer runs on a tokio executor.
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use clap::{Parser, ValueEnum};
use quac_network_tile::{NetworkTile, NetworkTileImpl, Park};
use quac_socket_os::OsSocket;
use quac_tile::{Connection, Endpoint, EndpointConfig, QuicPacketRouter, SendStream, ServerConfig, StreamEvent, StreamId, TransportConfig};

const ALPN: &[u8] = b"bench";

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum ThreadMode {
    Combined,
    Separate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum SocketBackend {
    Os,
    #[cfg(target_os = "linux")]
    Iouring,
}

#[derive(Debug, Parser)]
struct Args {
    /// Address to listen on
    #[clap(long, default_value = "[::]:4433")]
    listen: SocketAddr,

    /// Number of SO_REUSEPORT network tiles
    #[clap(long, default_value = "1")]
    tiles: usize,

    /// Number of engine threads per network tile
    #[clap(long, default_value = "1")]
    engine_tiles: usize,

    /// Whether the network tile uses a single combined Rx+Tx thread or
    /// separate reader and writer threads
    #[clap(long, default_value = "combined")]
    mode: ThreadMode,

    /// UDP socket backend to use
    #[clap(long, default_value = "os")]
    socket: SocketBackend,

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
    let ep_config = EndpointConfig::default();

    let mut endpoints: Vec<Endpoint> = Vec::new();

    match args.socket {
        SocketBackend::Os => {
            for i in 0..args.tiles {
                let endpoint = build_os_tile(&args, server_config.clone(), ep_config.clone(), i);
                endpoints.push(endpoint);
            }
        }
        #[cfg(target_os = "linux")]
        SocketBackend::Iouring => {
            for i in 0..args.tiles {
                let endpoint = build_iouring_tile(&args, server_config.clone(), ep_config.clone(), i);
                endpoints.push(endpoint);
            }
        }
    }

    println!("listening on {} ({} net tiles × {} engine tiles, {:?} mode, {:?} socket)",
        args.listen, args.tiles, args.engine_tiles, args.mode, args.socket);

    for endpoint in endpoints {
        tokio::spawn(accept_loop(endpoint));
    }

    tokio::signal::ctrl_c().await.expect("ctrl-c");
    println!("shutting down");
}

fn build_os_tile(args: &Args, server_config: ServerConfig, ep_config: EndpointConfig, tile_index: usize) -> Endpoint {
    let n = args.engine_tiles;
    let tile = match args.mode {
        ThreadMode::Combined => {
            let sock = OsSocket::bind_reuseport(args.listen).expect("bind");
            Arc::new(NetworkTileImpl::<OsSocket, Park, _>::combined(sock, QuicPacketRouter::new(), n))
        }
        ThreadMode::Separate => {
            let rx = OsSocket::bind_reuseport(args.listen).expect("bind rx");
            let tx = rx.try_clone().expect("clone tx");
            Arc::new(NetworkTileImpl::<OsSocket, Park, _>::separate(rx, tx, QuicPacketRouter::new(), n))
        }
    };
    Arc::clone(&tile).start(tile_index);
    Endpoint::server(server_config, ep_config, &tile)
}

#[cfg(target_os = "linux")]
fn build_iouring_tile(
    args: &Args,
    server_config: ServerConfig,
    ep_config: EndpointConfig,
    tile_index: usize,
) -> Endpoint {
    use quac_socket_iouring::IoUringSocket;
    let n = args.engine_tiles;
    let tile = match args.mode {
        ThreadMode::Combined => {
            let sock = IoUringSocket::bind_reuseport(args.listen).expect("bind");
            Arc::new(NetworkTileImpl::<IoUringSocket, Park, _>::combined(sock, QuicPacketRouter::new(), n))
        }
        ThreadMode::Separate => {
            let rx = IoUringSocket::bind_reuseport(args.listen).expect("bind rx");
            let tx = IoUringSocket::bind_reuseport(args.listen).expect("bind tx");
            Arc::new(NetworkTileImpl::<IoUringSocket, Park, _>::separate(rx, tx, QuicPacketRouter::new(), n))
        }
    };
    Arc::clone(&tile).start(tile_index);
    Endpoint::server(server_config, ep_config, &tile)
}

async fn accept_loop(endpoint: Endpoint) {
    loop {
        let Some(incoming) = endpoint.accept().await else { break };
        tokio::spawn(async move {
            match incoming.accept().await {
                Ok(conn) => handle_connection(conn).await,
                Err(e) => eprintln!("TLS accept failed: {e}"),
            }
        });
    }
}

async fn handle_connection(conn: Connection) {
    let mut senders: HashMap<StreamId, SendStream> = HashMap::new();
    loop {
        tokio::select! {
            result = conn.accept_bi() => {
                match result {
                    Ok((id, Some(send))) => { senders.insert(id, send); }
                    Ok((_, None)) => {}
                    Err(e) => { eprintln!("accept_bi: {e}"); break; }
                }
            }
            result = conn.recv_stream_event() => {
                match result {
                    Ok(StreamEvent::Data { id, bytes }) => {
                        if let Some(send) = senders.get(&id) {
                            send.write(bytes);
                        }
                    }
                    Ok(StreamEvent::Finished { id }) | Ok(StreamEvent::Reset { id, .. }) => {
                        senders.remove(&id);
                    }
                    Err(e) => { eprintln!("conn closed: {e}"); break; }
                }
            }
        }
    }
}

fn make_server_config() -> ServerConfig {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])
        .expect("cert generation");
    let cert_der =
        quac_tile::CertificateDer::from(cert.cert.der().to_vec());
    let priv_key =
        quac_tile::PrivateKeyDer::try_from(cert.signing_key.serialize_der()).expect("private key");

    let mut tc = TransportConfig::default();
    // Fix MTU at 1400 bytes — fits comfortably in the 2 KB TX buffer pool.
    // Disable discovery so quinn-proto never probes higher (e.g. on loopback).
    tc.initial_mtu(1400).mtu_discovery_config(None);

    ServerConfig::with_single_cert(vec![cert_der], priv_key, &[ALPN])
        .expect("server TLS config")
        .with_transport_config(tc)
}
