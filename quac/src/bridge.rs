//! Shared state between the engine thread and async application handles.

use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::Thread;

use bytes::Bytes;
use crossbeam_queue::ArrayQueue;
use futures_util::task::AtomicWaker;
use quic_proto::{Dir, StreamId};

/// Number of queued `Bytes` chunks the engine can buffer per stream.
///
/// This is an **admission gate**, not a drop point. When `recv_data` is full
/// the engine withholds `recv_stream.read()` calls for that stream, which
/// fills quinn-proto's receive buffer and closes the QUIC flow-control window.
pub const RECV_DATA_CAP: usize = 16;

/// Maximum pending connection events per connection (opened streams, close notifications).
pub const EVT_QUEUE_CAP: usize = 256;

// ── StreamCell ────────────────────────────────────────────────────────────────

/// Per-stream bridge shared between the engine thread and `RecvStream`/`SendStream`.
pub struct StreamCell {
    /// Receive side: engine pushes, `RecvStream::poll_read` drains.
    pub recv_data: ArrayQueue<Bytes>,
    pub recv_waker: AtomicWaker,
    pub recv_fin: AtomicBool,
    /// Send side: engine wakes this when the stream regains flow-control window.
    pub send_waker: AtomicWaker,
}

impl StreamCell {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            recv_data: ArrayQueue::new(RECV_DATA_CAP),
            recv_waker: AtomicWaker::new(),
            recv_fin: AtomicBool::new(false),
            send_waker: AtomicWaker::new(),
        })
    }
}

// ── Commands (application → engine) ──────────────────────────────────────────

/// Commands from application handles to the engine tile.
pub enum TileAppCommand {
    Write {
        conn: u32,
        stream: StreamId,
        data: Bytes,
        fin: bool,
    },
    OpenStream {
        conn: u32,
        dir: Dir,
    },
    Finish {
        conn: u32,
        stream: StreamId,
    },
    ResetStream {
        conn: u32,
        stream: StreamId,
        code: u64,
    },
    CloseConn {
        conn: u32,
    },
}

// ── Events (engine → application, per-connection) ─────────────────────────────

/// Events pushed by the engine to the per-connection bridge.
pub enum ConnEvent {
    /// A remote peer opened a bidirectional stream.
    PeerBiStream(StreamId, Arc<StreamCell>),
    /// A remote peer opened a unidirectional stream.
    PeerUniStream(StreamId, Arc<StreamCell>),
    /// The engine processed an `OpenStream` command; here is the stream.
    LocalStream(StreamId, Arc<StreamCell>),
    /// The connection closed (error or graceful).
    ConnectionClosed,
}

// ── ConnState ─────────────────────────────────────────────────────────────────

/// Shared state between the engine thread and all async handles for one connection.
pub struct ConnState {
    /// Shared command queue for the whole engine tile (all connections on the tile).
    pub cmd_queue: Arc<ArrayQueue<TileAppCommand>>,
    /// Per-connection event queue (engine → application).
    pub evt_queue: Arc<ArrayQueue<ConnEvent>>,
    /// Woken when `evt_queue` has new entries.
    pub evt_waker: AtomicWaker,
    /// Engine-thread park state: true when the engine is in `thread::park()`/`park_timeout()`.
    pub engine_is_parked: Arc<AtomicBool>,
    /// Handle to the engine thread, set once when the thread starts.
    pub engine_thread: Arc<OnceLock<Thread>>,
}

impl ConnState {
    pub fn new(
        cmd_queue: Arc<ArrayQueue<TileAppCommand>>,
        engine_is_parked: Arc<AtomicBool>,
        engine_thread: Arc<OnceLock<Thread>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            cmd_queue,
            evt_queue: Arc::new(ArrayQueue::new(EVT_QUEUE_CAP)),
            evt_waker: AtomicWaker::new(),
            engine_is_parked,
            engine_thread,
        })
    }

    /// Push a command to the engine and wake it if parked.
    pub fn send_cmd(&self, cmd: TileAppCommand) {
        let _ = self.cmd_queue.push(cmd);
        self.wake_engine();
    }

    /// Wake the engine thread if it is parked.
    pub fn wake_engine(&self) {
        if self.engine_is_parked.load(Ordering::Acquire) {
            if let Some(t) = self.engine_thread.get() {
                t.unpark();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;

    fn make_state() -> Arc<ConnState> {
        let cmd_queue = Arc::new(ArrayQueue::new(64));
        let is_parked = Arc::new(AtomicBool::new(false));
        let engine_thread = Arc::new(OnceLock::new());
        ConnState::new(cmd_queue, is_parked, engine_thread)
    }

    #[test]
    fn stream_cell_recv_data_is_admission_gate() {
        let cell = StreamCell::new();
        // Fill to capacity
        for i in 0..RECV_DATA_CAP {
            let pushed = cell.recv_data.push(Bytes::from(vec![i as u8]));
            assert!(pushed.is_ok(), "push {i} should succeed");
        }
        // One more should fail (gate closed, not drop)
        let overflow = cell.recv_data.push(Bytes::from(vec![99u8]));
        assert!(overflow.is_err(), "push beyond RECV_DATA_CAP should be rejected");
        // Drain one entry; push should succeed again
        let _ = cell.recv_data.pop();
        let retry = cell.recv_data.push(Bytes::from(vec![100u8]));
        assert!(retry.is_ok(), "push after drain should succeed");
    }

    #[test]
    fn conn_state_send_cmd_does_not_panic_when_parked_false() {
        let state = make_state();
        // engine_is_parked = false, engine_thread not set: wake_engine is a no-op
        state.send_cmd(TileAppCommand::CloseConn { conn: 0 });
        assert_eq!(state.cmd_queue.len(), 1);
    }

    #[test]
    fn conn_state_wake_engine_uses_thread_unpark() {
        let cmd_queue = Arc::new(ArrayQueue::new(64));
        let is_parked = Arc::new(AtomicBool::new(true));
        let engine_thread = Arc::new(OnceLock::new());
        // Set the engine thread to the current thread so we can verify unpark is called.
        let _ = engine_thread.set(std::thread::current());
        let state = ConnState::new(cmd_queue, Arc::clone(&is_parked), Arc::clone(&engine_thread));
        // Park the current thread with a 1ms timeout; wake_engine should unpark it immediately.
        state.wake_engine();
        // If park_timeout blocks for the full duration, the test is broken.
        let before = std::time::Instant::now();
        std::thread::park_timeout(std::time::Duration::from_millis(500));
        // The unpark token from wake_engine should cause park_timeout to return immediately.
        assert!(
            before.elapsed() < std::time::Duration::from_millis(100),
            "park_timeout should return immediately after wake_engine unparks the thread"
        );
    }
}
