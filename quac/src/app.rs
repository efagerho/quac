//! Async application interface: `Endpoint`, `Connection`, `SendStream`, `RecvStream`.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use crossbeam_queue::ArrayQueue;
use futures_util::task::AtomicWaker;
use quic_proto::{Dir, StreamId};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::bridge::{ConnEvent, ConnState, StreamCell, TileAppCommand};

// ── Endpoint ──────────────────────────────────────────────────────────────────

/// Top-level handle to a tile-based QUIC server.
///
/// Created by [`crate::tileset::TileSet`]. Application code calls
/// [`accept`](Self::accept) in a loop.
pub struct Endpoint {
    incoming: Arc<ArrayQueue<Connection>>,
    accept_waker: Arc<AtomicWaker>,
}

impl Endpoint {
    pub(crate) fn new(
        incoming: Arc<ArrayQueue<Connection>>,
        accept_waker: Arc<AtomicWaker>,
    ) -> Self {
        Self { incoming, accept_waker }
    }

    /// Wait for the next inbound connection.
    pub async fn accept(&self) -> Option<Connection> {
        std::future::poll_fn(|cx| {
            if let Some(conn) = self.incoming.pop() {
                return Poll::Ready(Some(conn));
            }
            self.accept_waker.register(cx.waker());
            // Re-check after registering the waker (close the race).
            if let Some(conn) = self.incoming.pop() {
                Poll::Ready(Some(conn))
            } else {
                Poll::Pending
            }
        })
        .await
    }
}

// ── Connection ────────────────────────────────────────────────────────────────

/// Handle to an established QUIC connection.
pub struct Connection {
    pub(crate) state: Arc<ConnState>,
    /// Slab index of this connection on the engine tile.
    pub(crate) slot: u32,
}

impl Connection {
    pub(crate) fn new(state: Arc<ConnState>) -> Self {
        // slot is embedded in the ConnState — but for simplicity we pass 0 here
        // and have the TileSet set it properly. For now use a sentinel.
        Self { state, slot: u32::MAX }
    }

    /// Used by TileSet to inject the correct slab slot index after the engine
    /// inserts the connection.
    pub(crate) fn with_slot(mut self, slot: u32) -> Self {
        self.slot = slot;
        self
    }

    /// Wait for a remote peer to open a bidirectional stream.
    pub async fn accept_bi(&self) -> Option<(SendStream, RecvStream)> {
        std::future::poll_fn(|cx| {
            // Drain the event queue for a PeerBiStream event.
            while let Some(ev) = self.state.evt_queue.pop() {
                match ev {
                    ConnEvent::PeerBiStream(id, cell) => {
                        let send = SendStream::new(Arc::clone(&self.state), self.slot, id, Arc::clone(&cell));
                        let recv = RecvStream::new(Arc::clone(&self.state), self.slot, id, cell);
                        return Poll::Ready(Some((send, recv)));
                    }
                    ConnEvent::ConnectionClosed => return Poll::Ready(None),
                    // Other events are pushed back — but ArrayQueue has no push_front.
                    // For correctness, push them back and stop (they'll be re-processed).
                    other => {
                        let _ = self.state.evt_queue.push(other);
                        break;
                    }
                }
            }
            self.state.evt_waker.register(cx.waker());
            // Re-check after registering.
            while let Some(ev) = self.state.evt_queue.pop() {
                match ev {
                    ConnEvent::PeerBiStream(id, cell) => {
                        let send = SendStream::new(Arc::clone(&self.state), self.slot, id, Arc::clone(&cell));
                        let recv = RecvStream::new(Arc::clone(&self.state), self.slot, id, cell);
                        return Poll::Ready(Some((send, recv)));
                    }
                    ConnEvent::ConnectionClosed => return Poll::Ready(None),
                    other => {
                        let _ = self.state.evt_queue.push(other);
                        break;
                    }
                }
            }
            Poll::Pending
        })
        .await
    }

    /// Ask the engine to open a local bidirectional stream.
    pub async fn open_bi(&self) -> Option<(SendStream, RecvStream)> {
        self.state.send_cmd(TileAppCommand::OpenStream {
            conn: self.slot,
            dir: Dir::Bi,
        });
        std::future::poll_fn(|cx| {
            while let Some(ev) = self.state.evt_queue.pop() {
                match ev {
                    ConnEvent::LocalStream(id, cell) if id.dir() == Dir::Bi => {
                        let send = SendStream::new(Arc::clone(&self.state), self.slot, id, Arc::clone(&cell));
                        let recv = RecvStream::new(Arc::clone(&self.state), self.slot, id, cell);
                        return Poll::Ready(Some((send, recv)));
                    }
                    ConnEvent::ConnectionClosed => return Poll::Ready(None),
                    other => {
                        let _ = self.state.evt_queue.push(other);
                        break;
                    }
                }
            }
            self.state.evt_waker.register(cx.waker());
            while let Some(ev) = self.state.evt_queue.pop() {
                match ev {
                    ConnEvent::LocalStream(id, cell) if id.dir() == Dir::Bi => {
                        let send = SendStream::new(Arc::clone(&self.state), self.slot, id, Arc::clone(&cell));
                        let recv = RecvStream::new(Arc::clone(&self.state), self.slot, id, cell);
                        return Poll::Ready(Some((send, recv)));
                    }
                    ConnEvent::ConnectionClosed => return Poll::Ready(None),
                    other => {
                        let _ = self.state.evt_queue.push(other);
                        break;
                    }
                }
            }
            Poll::Pending
        })
        .await
    }
}

// ── SendStream ────────────────────────────────────────────────────────────────

/// Writable half of a QUIC stream.
pub struct SendStream {
    state: Arc<ConnState>,
    slot: u32,
    id: StreamId,
    cell: Arc<StreamCell>,
}

impl SendStream {
    fn new(state: Arc<ConnState>, slot: u32, id: StreamId, cell: Arc<StreamCell>) -> Self {
        Self { state, slot, id, cell }
    }

    pub fn finish(self) {
        self.state.send_cmd(TileAppCommand::Finish { conn: self.slot, stream: self.id });
    }
}

impl AsyncWrite for SendStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        // Push a Write command to the engine.
        let data = Bytes::copy_from_slice(buf);
        let len = data.len();
        let cmd = TileAppCommand::Write {
            conn: self.slot,
            stream: self.id,
            data,
            fin: false,
        };
        match self.state.cmd_queue.push(cmd) {
            Ok(()) => {
                self.state.wake_engine();
                Poll::Ready(Ok(len))
            }
            Err(_) => {
                // Command queue is full; register waker and return Pending.
                self.cell.send_waker.register(cx.waker());
                Poll::Pending
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.state.send_cmd(TileAppCommand::Finish { conn: self.slot, stream: self.id });
        Poll::Ready(Ok(()))
    }
}

// ── RecvStream ────────────────────────────────────────────────────────────────

/// Readable half of a QUIC stream.
pub struct RecvStream {
    #[allow(dead_code)]
    state: Arc<ConnState>,
    #[allow(dead_code)]
    slot: u32,
    #[allow(dead_code)]
    id: StreamId,
    cell: Arc<StreamCell>,
    /// Unconsumed bytes from the last `recv_data` pop.
    leftover: Bytes,
}

impl RecvStream {
    fn new(state: Arc<ConnState>, slot: u32, id: StreamId, cell: Arc<StreamCell>) -> Self {
        Self {
            state,
            slot,
            id,
            cell,
            leftover: Bytes::new(),
        }
    }
}

impl AsyncRead for RecvStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        // Serve from leftover bytes first.
        if !self.leftover.is_empty() {
            let n = self.leftover.len().min(buf.remaining());
            buf.put_slice(&self.leftover[..n]);
            self.leftover = self.leftover.split_off(n);
            return Poll::Ready(Ok(()));
        }

        // Try to pop from the engine-provided queue.
        if let Some(chunk) = self.cell.recv_data.pop() {
            let n = chunk.len().min(buf.remaining());
            buf.put_slice(&chunk[..n]);
            if n < chunk.len() {
                self.leftover = chunk.slice(n..);
            }
            return Poll::Ready(Ok(()));
        }

        // Queue empty: check for FIN.
        if self.cell.recv_fin.load(std::sync::atomic::Ordering::Acquire) {
            return Poll::Ready(Ok(())); // EOF
        }

        // Register waker and re-check (close the race).
        self.cell.recv_waker.register(cx.waker());
        if let Some(chunk) = self.cell.recv_data.pop() {
            let n = chunk.len().min(buf.remaining());
            buf.put_slice(&chunk[..n]);
            if n < chunk.len() {
                self.leftover = chunk.slice(n..);
            }
            return Poll::Ready(Ok(()));
        }

        if self.cell.recv_fin.load(std::sync::atomic::Ordering::Acquire) {
            return Poll::Ready(Ok(())); // EOF
        }

        Poll::Pending
    }
}
