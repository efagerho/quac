use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use crossbeam_queue::ArrayQueue;
use quinn_proto::{ConnectionError, ConnectionHandle, Dir, StreamId, VarInt};

use crate::app_queue::AppQueue;
use crate::streams::SendStream;
use crate::waker::EngineWaker;

// ─── Commands from app → engine ────────────────────────────────────────────

pub(crate) enum AppCmd {
    OpenStream { dir: Dir, result_tx: Arc<AppQueue<OpenStreamResult>> },
    StreamWrite { id: StreamId, data: Bytes },
    StreamFinish { id: StreamId },
    StreamStopSending { id: StreamId, error_code: VarInt },
    StreamReset { id: StreamId, error_code: VarInt },
    SendDatagram(Bytes),
    Close { error_code: VarInt, reason: Bytes },
}

// ─── Per-connection event queue ─────────────────────────────────────────────

/// Internal per-connection event delivered via `AppQueue<ConnData>`.
/// One queue per connection replaces the per-stream `AppQueue` map —
/// a burst of N stream events fires exactly one tokio wakeup.
#[derive(Debug)]
pub(crate) enum ConnData {
    Data { id: StreamId, bytes: Bytes },
    Finished { id: StreamId },
    Reset { id: StreamId, code: VarInt },
    Lost(ConnectionError),
}

/// Public per-connection stream event returned by [`Connection::recv_stream_event`].
#[derive(Debug)]
pub enum StreamEvent {
    Data { id: StreamId, bytes: Bytes },
    Finished { id: StreamId },
    Reset { id: StreamId, code: VarInt },
}

/// Payload on the per-direction accept queues.
pub(crate) enum AcceptEvent {
    Opened { id: StreamId },
    Lost(ConnectionError),
}

/// Result for `open_bi` / `open_uni` — delivered via a one-shot queue.
pub(crate) enum OpenStreamResult {
    Opened { id: StreamId },
    Lost(ConnectionError),
}

/// Connection-level events: `Connected` (client handshake done) and `Lost`.
#[derive(Debug)]
pub(crate) enum ConnEvent {
    Connected,
    Lost(ConnectionError),
}

// ─── Shared inner state ──────────────────────────────────────────────────────

pub(crate) struct ConnInner {
    pub(crate) accept_bi: Arc<AppQueue<AcceptEvent>>,
    pub(crate) accept_uni: Arc<AppQueue<AcceptEvent>>,
    pub(crate) conn_events: Arc<AppQueue<ConnEvent>>,
    /// Single per-connection stream-data queue (engine writes, app reads).
    pub(crate) stream_data: Arc<AppQueue<ConnData>>,
    pub(crate) cmds: Arc<ArrayQueue<AppCmd>>,
    pub(crate) engine_waker: Arc<EngineWaker>,
    pub(crate) remote_address: SocketAddr,
    pub(crate) local_ip: Option<IpAddr>,
    /// This connection's handle — pushed to `dirty_conns` on every `send_cmd`
    /// so the engine only wakes and processes connections that have pending work.
    pub(crate) handle: ConnectionHandle,
    pub(crate) dirty_conns: Arc<ArrayQueue<ConnectionHandle>>,
}

impl ConnInner {
    pub(crate) fn send_cmd(&self, cmd: AppCmd) {
        let _ = self.cmds.push(cmd);
        let _ = self.dirty_conns.push(self.handle);
        self.engine_waker.wake();
    }
}

// ─── Public Connection handle ────────────────────────────────────────────────

/// A QUIC connection. Cheap to clone.
#[derive(Clone)]
pub struct Connection {
    pub(crate) inner: Arc<ConnInner>,
}

impl Connection {
    pub(crate) fn new(inner: Arc<ConnInner>) -> Self {
        Self { inner }
    }

    pub fn remote_address(&self) -> SocketAddr {
        self.inner.remote_address
    }

    pub fn local_ip(&self) -> Option<IpAddr> {
        self.inner.local_ip
    }

    /// Open a bidirectional stream.
    pub fn open_bi(&self) -> OpenStream {
        let result_tx = Arc::new(AppQueue::new(1));
        self.inner.send_cmd(AppCmd::OpenStream {
            dir: Dir::Bi,
            result_tx: Arc::clone(&result_tx),
        });
        OpenStream {
            conn: Arc::clone(&self.inner),
            result_rx: result_tx,
            dir: Dir::Bi,
        }
    }

    /// Open a unidirectional send-only stream.
    pub fn open_uni(&self) -> OpenStream {
        let result_tx = Arc::new(AppQueue::new(1));
        self.inner.send_cmd(AppCmd::OpenStream {
            dir: Dir::Uni,
            result_tx: Arc::clone(&result_tx),
        });
        OpenStream {
            conn: Arc::clone(&self.inner),
            result_rx: result_tx,
            dir: Dir::Uni,
        }
    }

    /// Accept the next inbound bidirectional stream opened by the peer.
    pub fn accept_bi(&self) -> AcceptStream {
        AcceptStream {
            queue: Arc::clone(&self.inner.accept_bi),
            conn: Arc::clone(&self.inner),
            dir: Dir::Bi,
        }
    }

    /// Accept the next inbound unidirectional stream opened by the peer.
    pub fn accept_uni(&self) -> AcceptStream {
        AcceptStream {
            queue: Arc::clone(&self.inner.accept_uni),
            conn: Arc::clone(&self.inner),
            dir: Dir::Uni,
        }
    }

    /// Receive the next stream event (data chunk, EOF, reset, or connection loss).
    ///
    /// All stream events for this connection are multiplexed onto a single queue,
    /// so a burst of N events across N streams fires exactly one tokio wakeup.
    /// Pair with [`accept_bi`](Self::accept_bi) inside `tokio::select!` to handle
    /// both new streams and data from existing ones in one task.
    pub fn recv_stream_event(&self) -> RecvStreamEvent {
        RecvStreamEvent {
            stream_data: Arc::clone(&self.inner.stream_data),
        }
    }

    /// Await connection close.
    pub fn closed(&self) -> ClosedFuture {
        ClosedFuture {
            conn: Arc::clone(&self.inner),
        }
    }

    pub fn close(&self, error_code: VarInt, reason: &[u8]) {
        self.inner.send_cmd(AppCmd::Close {
            error_code,
            reason: Bytes::copy_from_slice(reason),
        });
    }

    pub fn send_datagram(&self, data: Bytes) {
        self.inner.send_cmd(AppCmd::SendDatagram(data));
    }
}

// ─── Futures ────────────────────────────────────────────────────────────────

pub struct OpenStream {
    conn: Arc<ConnInner>,
    result_rx: Arc<AppQueue<OpenStreamResult>>,
    dir: Dir,
}

impl Future for OpenStream {
    type Output = Result<(StreamId, Option<SendStream>), ConnectionError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.result_rx.poll_pop(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(OpenStreamResult::Opened { id }) => {
                let send = if self.dir == Dir::Bi {
                    Some(SendStream::new(Arc::clone(&self.conn), id))
                } else {
                    None
                };
                Poll::Ready(Ok((id, send)))
            }
            Poll::Ready(OpenStreamResult::Lost(e)) => Poll::Ready(Err(e)),
        }
    }
}

pub struct AcceptStream {
    queue: Arc<AppQueue<AcceptEvent>>,
    conn: Arc<ConnInner>,
    dir: Dir,
}

impl Future for AcceptStream {
    type Output = Result<(StreamId, Option<SendStream>), ConnectionError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.queue.poll_pop(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(AcceptEvent::Opened { id }) => {
                let send = if self.dir == Dir::Bi {
                    Some(SendStream::new(Arc::clone(&self.conn), id))
                } else {
                    None
                };
                Poll::Ready(Ok((id, send)))
            }
            Poll::Ready(AcceptEvent::Lost(e)) => Poll::Ready(Err(e)),
        }
    }
}

/// Future produced by [`Connection::recv_stream_event`].
pub struct RecvStreamEvent {
    stream_data: Arc<AppQueue<ConnData>>,
}

impl Future for RecvStreamEvent {
    type Output = Result<StreamEvent, ConnectionError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.stream_data.poll_pop(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(ConnData::Data { id, bytes }) => {
                Poll::Ready(Ok(StreamEvent::Data { id, bytes }))
            }
            Poll::Ready(ConnData::Finished { id }) => {
                Poll::Ready(Ok(StreamEvent::Finished { id }))
            }
            Poll::Ready(ConnData::Reset { id, code }) => {
                Poll::Ready(Ok(StreamEvent::Reset { id, code }))
            }
            Poll::Ready(ConnData::Lost(e)) => Poll::Ready(Err(e)),
        }
    }
}

pub struct ClosedFuture {
    conn: Arc<ConnInner>,
}

impl Future for ClosedFuture {
    type Output = ConnectionError;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            match self.conn.conn_events.poll_pop(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(ConnEvent::Lost(e)) => return Poll::Ready(e),
                Poll::Ready(ConnEvent::Connected) => {}
            }
        }
    }
}
