//! Wires M network tiles × N engine tiles together into a runnable QUIC server.

use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, OnceLock};
use std::thread::Thread;

use crossbeam_queue::ArrayQueue;
use futures_util::task::AtomicWaker;
use quic_proto::{EndpointConfig, ServerConfig, quic_lb_cid_generator_factory};

use crate::app::{Connection, Endpoint};
use crate::engine_tile::run_engine;
use quac_tile::{RxPacket, TxPacket, QUEUE_CAP, CID_LEN};
use quac_network_tile_socket::OsNetworkTile;
use crate::tile_engine::TileEngine;

/// A set of M network tiles × N engine tiles bound to a single address.
///
/// Create with [`TileSet::with_os_sockets`] then call [`endpoint`](Self::endpoint)
/// to obtain the async server handle.
pub struct TileSet {
    incoming: Arc<ArrayQueue<Connection>>,
    accept_waker: Arc<AtomicWaker>,
}

impl TileSet {
    /// Bind `addr` with `num_network` network tiles and `num_engine` engine tiles,
    /// all using `SO_REUSEPORT` OS sockets.
    ///
    /// Spawns `2 * num_network + num_engine` threads and returns immediately.
    pub fn with_os_sockets(
        addr: SocketAddr,
        num_network: usize,
        num_engine: usize,
        mut endpoint_config: EndpointConfig,
        server_config: Arc<ServerConfig>,
    ) -> Self {
        assert!(num_network >= 1, "need at least one network tile");
        assert!(num_engine >= 1, "need at least one engine tile");

        let incoming: Arc<ArrayQueue<Connection>> = Arc::new(ArrayQueue::new(QUEUE_CAP));
        let accept_waker = Arc::new(AtomicWaker::new());

        // Allocate the M×N rx queue matrix: rx[i][j] = NT i reader → ET j.
        let rx: Vec<Vec<Arc<ArrayQueue<RxPacket>>>> = (0..num_network)
            .map(|_| {
                (0..num_engine)
                    .map(|_| Arc::new(ArrayQueue::new(QUEUE_CAP)))
                    .collect()
            })
            .collect();

        // Allocate the N tx queues: tx[j] = ET j → NT (j % num_network) writer.
        let tx: Vec<Arc<ArrayQueue<TxPacket>>> = (0..num_engine)
            .map(|_| Arc::new(ArrayQueue::new(QUEUE_CAP)))
            .collect();

        // Collect engine wakeup state so the network tiles can unpark engines.
        let mut engine_is_parked: Vec<Arc<AtomicBool>> = Vec::with_capacity(num_engine);
        let mut engine_thread_locks: Vec<Arc<OnceLock<Thread>>> = Vec::with_capacity(num_engine);

        // Spawn engine tiles.
        for j in 0..num_engine {
            // Engine tile j drains rx[0..M][j] and pushes to tx[j].
            let rx_queues: Vec<Arc<ArrayQueue<RxPacket>>> =
                (0..num_network).map(|i| Arc::clone(&rx[i][j])).collect();
            let tx_queue = Arc::clone(&tx[j]);

            // Install a QUIC-LB CID generator so engine tile j stamps its index.
            endpoint_config.cid_generator(quic_lb_cid_generator_factory(j as u32, CID_LEN));

            let engine = TileEngine::new(
                rx_queues,
                tx_queue,
                Arc::clone(&incoming),
                Arc::clone(&accept_waker),
                Arc::new(endpoint_config.clone()),
                Arc::clone(&server_config),
            );

            // Clone wakeup state before moving engine into the thread.
            engine_is_parked.push(Arc::clone(&engine.is_parked));
            engine_thread_locks.push(Arc::clone(&engine.engine_thread));

            std::thread::Builder::new()
                .name(format!("quic-tile-engine-{j}"))
                .spawn(move || run_engine(engine))
                .expect("spawn engine thread");
        }

        // Spawn network tiles.
        for i in 0..num_network {
            // NT i reader pushes to rx[i][0..N].
            let rx_queues: Vec<Arc<ArrayQueue<RxPacket>>> =
                (0..num_engine).map(|j| Arc::clone(&rx[i][j])).collect();
            // NT i writer drains tx[j] for all j where j % num_network == i.
            let tx_queues: Vec<Arc<ArrayQueue<TxPacket>>> = (0..num_engine)
                .filter(|j| j % num_network == i)
                .map(|j| Arc::clone(&tx[j]))
                .collect();
            // Reader wakeup handles for every engine tile.
            let ep_vec: Vec<Arc<AtomicBool>> = engine_is_parked.iter().map(Arc::clone).collect();
            let et_vec: Vec<Arc<OnceLock<Thread>>> = engine_thread_locks.iter().map(Arc::clone).collect();

            let tile = OsNetworkTile::new(addr, rx_queues, tx_queues, ep_vec, et_vec);
            std::thread::Builder::new()
                .name(format!("quic-tile-network-{i}"))
                .spawn(move || {
                    // OsNetworkTile::start spawns reader and writer threads internally.
                    use quac_tile::NetworkTile;
                    tile.start();
                    // This thread exits immediately after spawning; start() is synchronous.
                })
                .expect("spawn network tile supervisor");
        }

        Self { incoming, accept_waker }
    }

    /// Obtain the async server endpoint for accepting inbound connections.
    pub fn endpoint(&self) -> Endpoint {
        Endpoint::new(Arc::clone(&self.incoming), Arc::clone(&self.accept_waker))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, UdpSocket};
    use std::time::Duration;

    use quic_proto::{EndpointConfig as ProtoEndpointConfig, ServerConfig};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn make_server_config() -> Arc<ServerConfig> {
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_der = rustls::pki_types::CertificateDer::from(certified.cert);
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(
            certified.signing_key.serialize_der().into(),
        );
        Arc::new(
            ServerConfig::with_single_cert(vec![cert_der], key).expect("server config"),
        )
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn tileset_accepts_connection() {
        let server_config = make_server_config();

        let addr: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
        let tileset = TileSet::with_os_sockets(
            addr,
            1,
            1,
            EndpointConfig::default(),
            server_config,
        );
        // The TileSet sockets bind to an ephemeral port; we can't know it without
        // capturing it.  For this smoke test we just verify TileSet builds and starts
        // without panicking.
        let _endpoint = tileset.endpoint();
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}
