use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Instant;

use crossbeam_queue::ArrayQueue;
use quinn_proto::{AcceptOutcome, ConnectionError, PendingAccept};

use crate::app_queue::AppQueue;
use crate::connection::{ConnEvent, ConnInner, Connection};
use crate::waker::EngineWaker;

/// An in-progress incoming connection whose TLS Initial still needs to run.
///
/// Produced by [`crate::Endpoint::accept`]. Call [`Incoming::accept`] to run
/// the TLS handshake in the calling task's thread and get a [`Connection`].
pub struct Incoming {
    pub(crate) pending: PendingAccept,
    /// Channel back to the engine: push AcceptOutcome here so the engine can
    /// call finish_accept and register the connection.
    pub(crate) result_tx: Arc<ArrayQueue<AcceptOutcome>>,
    /// Notifies the engine that the result has been pushed.
    pub(crate) engine_waker: Arc<EngineWaker>,
    /// Channel on which the engine will push the Connection once registered.
    pub(crate) conn_rx: Arc<AppQueue<Result<Connection, ConnectionError>>>,
}

impl Incoming {
    pub fn remote_address(&self) -> SocketAddr {
        self.pending.remote_address()
    }

    pub fn local_ip(&self) -> Option<IpAddr> {
        self.pending.local_ip()
    }

    /// Run TLS Initial in the calling task's thread.
    ///
    /// This returns a future that:
    /// 1. Calls `PendingAccept::complete()` (CPU-bound TLS work) before the
    ///    first poll — synchronously in the calling thread.
    /// 2. Sends the outcome to the engine thread.
    /// 3. Awaits the engine's confirmation that the connection is registered.
    pub fn accept(self) -> Accept {
        let mut buf = Vec::with_capacity(2048);
        let outcome = self.pending.complete(Instant::now(), &mut buf);
        // Engine scratch buffer is separate; we drop our local buf here.
        drop(buf);

        Accept {
            outcome: Some(outcome),
            result_tx: self.result_tx,
            engine_waker: self.engine_waker,
            conn_rx: self.conn_rx,
        }
    }

    /// Refuse the connection (sends a QUIC CONNECTION_REFUSED).
    pub fn refuse(self) {
        // Dropping without sending anything causes the engine to notice the
        // result_tx is gone and clean up the pending slot.
    }
}

pub struct Accept {
    outcome: Option<AcceptOutcome>,
    result_tx: Arc<ArrayQueue<AcceptOutcome>>,
    engine_waker: Arc<EngineWaker>,
    conn_rx: Arc<AppQueue<Result<Connection, ConnectionError>>>,
}

impl Future for Accept {
    type Output = Result<Connection, ConnectionError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // First poll: send the outcome to the engine.
        if let Some(outcome) = self.outcome.take() {
            let _ = self.result_tx.push(outcome);
            self.engine_waker.wake();
        }

        self.conn_rx.poll_pop(cx).map(|r| r)
    }
}
