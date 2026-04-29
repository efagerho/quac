use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use crossbeam_queue::ArrayQueue;
use quac_network_tile::NetworkTile;
use quinn_proto::ConnectionError;

use crate::app_queue::AppQueue;
use crate::config::{EndpointConfig, ServerConfig};
use crate::connection::Connection;
use crate::engine::EngineCmd;
use crate::incoming::Incoming;
use crate::waker::EngineWaker;

pub(crate) struct EndpointInner {
    /// Engine pushes `Incoming` here; app consumes via `accept()`.
    pub(crate) incoming_queue: Arc<AppQueue<Incoming>>,
    /// App pushes `EngineCmd` here; engine drains on each loop iteration.
    pub(crate) engine_cmds: Arc<ArrayQueue<EngineCmd>>,
    pub(crate) engine_waker: Arc<EngineWaker>,
}

/// A QUIC server/client endpoint.
///
/// Create with [`Endpoint::server`] or [`Endpoint::client`], then call
/// [`accept`][Self::accept] (server) or [`connect`][Self::connect] (client).
#[derive(Clone)]
pub struct Endpoint {
    pub(crate) inner: Arc<EndpointInner>,
}

impl Endpoint {
    pub(crate) fn new(
        incoming_queue: Arc<AppQueue<Incoming>>,
        engine_cmds: Arc<ArrayQueue<EngineCmd>>,
        engine_waker: Arc<EngineWaker>,
    ) -> Self {
        Self {
            inner: Arc::new(EndpointInner {
                incoming_queue,
                engine_cmds,
                engine_waker,
            }),
        }
    }

    /// Start a QUIC server backed by `tile`.
    ///
    /// Spawns engine thread(s) for the tile and returns an `Endpoint` whose
    /// `accept()` future yields each new incoming connection.
    pub fn server<N: NetworkTile>(
        config: ServerConfig,
        ep_config: EndpointConfig,
        tile: &Arc<N>,
    ) -> Self {
        let ep_inner = crate::engine::spawn_engines(tile, ep_config.0, config.0);
        Self { inner: ep_inner }
    }

    /// Accept the next incoming connection.
    pub fn accept(&self) -> Accept<'_> {
        Accept { endpoint: self }
    }

    pub fn close(&self) {
        let _ = self.inner.engine_cmds.push(EngineCmd::CloseEndpoint);
        self.inner.engine_waker.wake();
    }
}

pub struct Accept<'a> {
    endpoint: &'a Endpoint,
}

impl<'a> Future for Accept<'a> {
    type Output = Option<Incoming>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.endpoint.inner.incoming_queue.poll_pop(cx).map(Some)
    }
}
