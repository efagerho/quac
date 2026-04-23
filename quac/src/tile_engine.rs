//! Protocol-level engine tile: drives quic-proto over lock-free queues.

use std::collections::HashMap;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, OnceLock};
use std::thread::Thread;
use std::time::Instant;

use bytes::{Bytes, BytesMut};
use crossbeam_queue::ArrayQueue;
use quic_proto::{
    Connection, ConnectionHandle, DatagramEvent, Dir, Endpoint, EndpointConfig, Event, ReadError,
    ServerConfig, StreamEvent, StreamId,
};
use slab::Slab;

use quac_interface::EcnCodepoint;

use crate::app::Connection as AppConnection;
use crate::bridge::{ConnEvent, ConnState, StreamCell, TileAppCommand, RECV_DATA_CAP};
use quac_tile::{RxPacket, TxPacket};

const MAX_DATAGRAMS: usize = 10;
const CMD_QUEUE_CAP: usize = 4096;

/// One QUIC connection owned by a `TileEngine`.
struct ConnectionSlot {
    handle: ConnectionHandle,
    inner: Connection,
    send_buf: Vec<u8>,
    next_timeout: Option<Instant>,
    has_pending_send: bool,
    /// Per-stream data-delivery cells, keyed by StreamId.
    streams: HashMap<StreamId, Arc<StreamCell>>,
    /// Bridge to the async application side.
    conn_state: Arc<ConnState>,
}

/// QUIC engine that drives connections via lock-free queues instead of a raw PacketSocket.
pub struct TileEngine {
    endpoint: Endpoint<BytesMut>,
    server_config: Arc<ServerConfig>,
    endpoint_scratch: Vec<u8>,
    connections: Slab<ConnectionSlot>,
    ch_to_slot: HashMap<usize, usize>,
    /// Receive queues from every network tile; engine drains all of them.
    rx_queues: Vec<Arc<ArrayQueue<RxPacket>>>,
    /// Single transmit queue for this engine tile's writer.
    pub(crate) tx_queue: Arc<ArrayQueue<TxPacket>>,
    /// Command queue shared by all async handles for connections on this tile.
    pub(crate) cmd_queue: Arc<ArrayQueue<TileAppCommand>>,
    /// Global incoming-connection queue (shared with TileSet / Endpoint).
    incoming: Arc<ArrayQueue<AppConnection>>,
    incoming_waker: Arc<futures_util::task::AtomicWaker>,
    /// Engine sleep state (shared with ConnState / EngineTile runner).
    pub(crate) is_parked: Arc<AtomicBool>,
    /// Set by the engine thread once on startup.
    pub(crate) engine_thread: Arc<OnceLock<Thread>>,
    // Scratch buffers (reused across iterations).
    pending_send: Vec<usize>,
    due_slots: Vec<usize>,
}

impl TileEngine {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        rx_queues: Vec<Arc<ArrayQueue<RxPacket>>>,
        tx_queue: Arc<ArrayQueue<TxPacket>>,
        incoming: Arc<ArrayQueue<AppConnection>>,
        incoming_waker: Arc<futures_util::task::AtomicWaker>,
        endpoint_config: Arc<EndpointConfig>,
        server_config: Arc<ServerConfig>,
    ) -> Self {
        let endpoint = Endpoint::new(endpoint_config, Some(Arc::clone(&server_config)), true);
        let is_parked = Arc::new(AtomicBool::new(false));
        let engine_thread = Arc::new(OnceLock::new());
        let cmd_queue = Arc::new(ArrayQueue::new(CMD_QUEUE_CAP));

        Self {
            endpoint,
            server_config,
            endpoint_scratch: Vec::with_capacity(65536),
            connections: Slab::new(),
            ch_to_slot: HashMap::new(),
            rx_queues,
            tx_queue,
            cmd_queue,
            incoming,
            incoming_waker,
            is_parked,
            engine_thread,
            pending_send: Vec::new(),
            due_slots: Vec::new(),
        }
    }

    /// Run one iteration of the engine loop.
    ///
    /// Returns `(next_deadline, did_work)` where `did_work` is `true` if any
    /// packets were received, commands processed, or timers fired.
    pub fn run_once(&mut self, now: Instant) -> (Option<Instant>, bool) {
        let mut did_work = false;
        did_work |= self.recv_and_dispatch(now);
        did_work |= self.process_app_commands(now);
        did_work |= self.drive_transmit(now);
        did_work |= self.fire_timers(now);
        if did_work {
            self.drive_transmit(now);
        }
        (self.next_deadline(), did_work)
    }

    // ── Receive ───────────────────────────────────────────────────────────────

    fn recv_and_dispatch(&mut self, now: Instant) -> bool {
        let mut did_work = false;
        for i in 0..self.rx_queues.len() {
            while let Some(pkt) = self.rx_queues[i].pop() {
                did_work = true;
                let ecn = pkt.meta.ecn.map(map_ecn_to_proto);
                self.endpoint_scratch.clear();
                let dg = self.endpoint.handle(
                    now,
                    pkt.meta.src,
                    pkt.meta.dst_ip,
                    ecn,
                    pkt.payload,
                    &mut self.endpoint_scratch,
                );
                match dg {
                    Some(DatagramEvent::ForConnection(ch, ev)) => {
                        if let Some(&slot_idx) = self.ch_to_slot.get(&ch.0) {
                            if let Some(slot) = self.connections.get_mut(slot_idx) {
                                slot.inner.handle_datagram(ev);
                                if !slot.has_pending_send {
                                    slot.has_pending_send = true;
                                    self.pending_send.push(slot_idx);
                                }
                            }
                            self.drain_connection_events(slot_idx, now);
                        }
                    }
                    Some(DatagramEvent::NewConnection(incoming)) => {
                        match self.endpoint.accept(
                            incoming,
                            now,
                            &mut self.endpoint_scratch,
                            Some(Arc::clone(&self.server_config)),
                        ) {
                            Ok((ch, conn)) => {
                                let conn_state = ConnState::new(
                                    Arc::clone(&self.cmd_queue),
                                    Arc::clone(&self.is_parked),
                                    Arc::clone(&self.engine_thread),
                                );
                                let slot_idx = self.connections.insert(ConnectionSlot {
                                    handle: ch,
                                    inner: conn,
                                    send_buf: Vec::with_capacity(65536),
                                    next_timeout: None,
                                    has_pending_send: true,
                                    streams: HashMap::new(),
                                    conn_state: Arc::clone(&conn_state),
                                });
                                self.pending_send.push(slot_idx);
                                self.ch_to_slot.insert(ch.0, slot_idx);
                                let app_conn = AppConnection::new(conn_state)
                                    .with_slot(slot_idx as u32);
                                let _ = self.incoming.push(app_conn);
                                self.incoming_waker.wake();
                                self.drain_connection_events(slot_idx, now);
                            }
                            Err(e) => {
                                if let Some(t) = e.response {
                                    self.enqueue_proto_transmit(t);
                                }
                            }
                        }
                    }
                    Some(DatagramEvent::Response(t)) => {
                        self.enqueue_proto_transmit(t);
                    }
                    None => {}
                }
            }
        }
        did_work
    }

    fn enqueue_proto_transmit(&mut self, transmit: quic_proto::Transmit) {
        let size = transmit.size;
        if size == 0 || size > self.endpoint_scratch.len() {
            return;
        }
        let payload = Bytes::copy_from_slice(&self.endpoint_scratch[..size]);
        let _ = self.tx_queue.push(TxPacket {
            destination: transmit.destination,
            ecn: transmit.ecn.and_then(map_ecn_from_proto),
            payload,
            segment_size: transmit.segment_size,
            src_ip: transmit.src_ip,
        });
    }

    // ── Connection events ─────────────────────────────────────────────────────

    fn drain_connection_events(&mut self, slot_idx: usize, now: Instant) {
        let ch = match self.connections.get(slot_idx) {
            Some(s) => s.handle,
            None => return,
        };

        // Drain EndpointEvents.
        loop {
            let ev = {
                let Some(slot) = self.connections.get_mut(slot_idx) else { return };
                slot.inner.poll_endpoint_events()
            };
            let Some(ev) = ev else { break };
            if let Some(reply) = self.endpoint.handle_event(ch, ev) {
                let Some(slot) = self.connections.get_mut(slot_idx) else { return };
                slot.inner.handle_event(reply);
            }
        }

        // Drain application Events.
        loop {
            let ev = {
                let Some(slot) = self.connections.get_mut(slot_idx) else { return };
                slot.inner.poll()
            };
            let Some(ev) = ev else { break };
            match ev {
                Event::Stream(StreamEvent::Opened { dir: Dir::Bi }) => {
                    loop {
                        let id = {
                            let Some(slot) = self.connections.get_mut(slot_idx) else { return };
                            slot.inner.streams().accept(Dir::Bi)
                        };
                        let Some(id) = id else { break };
                        self.open_stream_cell(slot_idx, id, false);
                        self.drain_readable_stream(slot_idx, id, now);
                    }
                }
                Event::Stream(StreamEvent::Opened { dir: Dir::Uni }) => {
                    loop {
                        let id = {
                            let Some(slot) = self.connections.get_mut(slot_idx) else { return };
                            slot.inner.streams().accept(Dir::Uni)
                        };
                        let Some(id) = id else { break };
                        self.open_stream_cell(slot_idx, id, false);
                    }
                }
                Event::Stream(StreamEvent::Readable { id }) => {
                    self.drain_readable_stream(slot_idx, id, now);
                }
                Event::Stream(StreamEvent::Writable { id }) => {
                    if let Some(slot) = self.connections.get(slot_idx) {
                        if let Some(cell) = slot.streams.get(&id) {
                            cell.send_waker.wake();
                        }
                    }
                }
                Event::Stream(StreamEvent::Available { dir }) => {
                    self.retry_pending_opens(slot_idx, dir, now);
                }
                Event::Connected => {
                    // Handshake complete; drive transmit.
                    if let Some(slot) = self.connections.get_mut(slot_idx) {
                        if !slot.has_pending_send {
                            slot.has_pending_send = true;
                            self.pending_send.push(slot_idx);
                        }
                    }
                }
                Event::ConnectionLost { .. } => {
                    // Drain remaining endpoint events to clean up quic-proto's internal state.
                    loop {
                        let ev = {
                            let Some(slot) = self.connections.get_mut(slot_idx) else { break };
                            slot.inner.poll_endpoint_events()
                        };
                        let Some(ev) = ev else { break };
                        let _ = self.endpoint.handle_event(ch, ev);
                    }
                    // Notify all streams and the connection handle.
                    let conn_state = self.connections[slot_idx].conn_state.clone();
                    let _ = conn_state.evt_queue.push(ConnEvent::ConnectionClosed);
                    conn_state.evt_waker.wake();
                    self.connections.remove(slot_idx);
                    self.ch_to_slot.remove(&ch.0);
                    return;
                }
                _ => {}
            }
        }

        if let Some(slot) = self.connections.get_mut(slot_idx) {
            slot.next_timeout = slot.inner.poll_timeout();
        }
    }

    /// Create a `StreamCell` for `id`, insert into `slot.streams`, and push a `ConnEvent`.
    fn open_stream_cell(&mut self, slot_idx: usize, id: StreamId, local: bool) {
        let cell = StreamCell::new();
        let event = if local {
            ConnEvent::LocalStream(id, Arc::clone(&cell))
        } else if id.dir() == Dir::Bi {
            ConnEvent::PeerBiStream(id, Arc::clone(&cell))
        } else {
            ConnEvent::PeerUniStream(id, Arc::clone(&cell))
        };
        let conn_state = {
            let Some(slot) = self.connections.get_mut(slot_idx) else { return };
            slot.streams.insert(id, cell);
            Arc::clone(&slot.conn_state)
        };
        let _ = conn_state.evt_queue.push(event);
        conn_state.evt_waker.wake();
    }

    /// Retry any pending `OpenStream` commands for `dir` now that more streams are available.
    fn retry_pending_opens(&mut self, slot_idx: usize, dir: Dir, now: Instant) {
        // Poll once for the given direction.
        let id = {
            let Some(slot) = self.connections.get_mut(slot_idx) else { return };
            slot.inner.streams().open(dir)
        };
        if let Some(id) = id {
            self.open_stream_cell(slot_idx, id, true);
            // After opening, may need to transmit (STREAMS_BLOCKED ack, etc.)
            if let Some(slot) = self.connections.get_mut(slot_idx) {
                if !slot.has_pending_send {
                    slot.has_pending_send = true;
                    self.pending_send.push(slot_idx);
                }
            }
            self.drain_connection_events(slot_idx, now);
        }
    }

    /// Deliver available stream data to the application via `StreamCell::recv_data`.
    ///
    /// Uses the 3-phase borrow pattern:
    ///   1. Clone the `Arc<StreamCell>` (releases borrow on slot.streams).
    ///   2. Read from quinn-proto into a local `Vec<Bytes>` (borrows slot.inner).
    ///   3. Push into `cell.recv_data` (interior mutability, no borrow conflict).
    fn drain_readable_stream(&mut self, slot_idx: usize, id: StreamId, _now: Instant) {
        // Phase 1: get cell (clone Arc, releasing borrow).
        let cell = {
            let slot = match self.connections.get(slot_idx) {
                Some(s) => s,
                None => return,
            };
            match slot.streams.get(&id) {
                Some(c) => Arc::clone(c),
                None => return,
            }
        };

        // Admission gate: only read if there is room in recv_data.
        let room = RECV_DATA_CAP.saturating_sub(cell.recv_data.len());
        if room == 0 {
            return;
        }

        // Phase 2: read from quinn-proto into a local Vec.
        let mut chunks_local: Vec<Bytes> = Vec::new();
        let mut fin = false;
        {
            let Some(slot) = self.connections.get_mut(slot_idx) else { return };
            let mut recv = slot.inner.recv_stream(id);
            let mut chunks = match recv.read(true) {
                Ok(c) => c,
                Err(_) => return,
            };
            loop {
                match chunks.next(65536) {
                    Ok(Some(chunk)) => {
                        chunks_local.push(Bytes::copy_from_slice(&chunk.bytes));
                        if chunks_local.len() >= room {
                            break;
                        }
                    }
                    Ok(None) => {
                        fin = true;
                        break;
                    }
                    Err(ReadError::Blocked) => break,
                    Err(_) => break,
                }
            }
            let _ = chunks.finalize();
        }

        // Phase 3: push to cell (interior mutability).
        let mut pushed = false;
        for data in chunks_local {
            if cell.recv_data.push(data).is_ok() {
                pushed = true;
            }
        }
        if fin {
            cell.recv_fin.store(true, std::sync::atomic::Ordering::Release);
        }
        if pushed || fin {
            cell.recv_waker.wake();
        }
    }

    // ── Application commands ──────────────────────────────────────────────────

    fn process_app_commands(&mut self, now: Instant) -> bool {
        let mut did_work = false;
        while let Some(cmd) = self.cmd_queue.pop() {
            did_work = true;
            match cmd {
                TileAppCommand::Write { conn, stream, data, fin } => {
                    let slot_idx = conn as usize;
                    if let Some(slot) = self.connections.get_mut(slot_idx) {
                        let mut send = slot.inner.send_stream(stream);
                        let _ = send.write(&data);
                        if fin {
                            let _ = send.finish();
                        }
                        if !slot.has_pending_send {
                            slot.has_pending_send = true;
                            self.pending_send.push(slot_idx);
                        }
                    }
                    self.drain_connection_events(slot_idx as usize, now);
                }
                TileAppCommand::OpenStream { conn, dir } => {
                    let slot_idx = conn as usize;
                    let id = {
                        let Some(slot) = self.connections.get_mut(slot_idx) else { continue };
                        slot.inner.streams().open(dir)
                    };
                    if let Some(id) = id {
                        self.open_stream_cell(slot_idx, id, true);
                        if let Some(slot) = self.connections.get_mut(slot_idx) {
                            if !slot.has_pending_send {
                                slot.has_pending_send = true;
                                self.pending_send.push(slot_idx);
                            }
                        }
                        self.drain_connection_events(slot_idx, now);
                    }
                    // If None: flow-control limit; the engine will retry on `Available` event.
                }
                TileAppCommand::Finish { conn, stream } => {
                    let slot_idx = conn as usize;
                    if let Some(slot) = self.connections.get_mut(slot_idx) {
                        let _ = slot.inner.send_stream(stream).finish();
                        if !slot.has_pending_send {
                            slot.has_pending_send = true;
                            self.pending_send.push(slot_idx);
                        }
                    }
                    self.drain_connection_events(slot_idx as usize, now);
                }
                TileAppCommand::ResetStream { conn, stream, code } => {
                    let slot_idx = conn as usize;
                    if let Some(slot) = self.connections.get_mut(slot_idx) {
                        let _ = slot.inner.send_stream(stream).reset(quic_proto::VarInt::from_u32(code as u32));
                        if !slot.has_pending_send {
                            slot.has_pending_send = true;
                            self.pending_send.push(slot_idx);
                        }
                    }
                    self.drain_connection_events(slot_idx as usize, now);
                }
                TileAppCommand::CloseConn { conn } => {
                    let slot_idx = conn as usize;
                    if let Some(slot) = self.connections.get_mut(slot_idx) {
                        slot.inner.close(
                            Instant::now(),
                            quic_proto::VarInt::from_u32(0),
                            Bytes::new(),
                        );
                        if !slot.has_pending_send {
                            slot.has_pending_send = true;
                            self.pending_send.push(slot_idx);
                        }
                    }
                    self.drain_connection_events(slot_idx as usize, now);
                }
            }
        }
        did_work
    }

    // ── Timers ────────────────────────────────────────────────────────────────

    fn fire_timers(&mut self, now: Instant) -> bool {
        self.due_slots.clear();
        self.due_slots.extend(
            self.connections
                .iter()
                .filter_map(|(i, s)| s.next_timeout.is_some_and(|t| t <= now).then_some(i)),
        );
        let did_work = !self.due_slots.is_empty();
        for idx in 0..self.due_slots.len() {
            let i = self.due_slots[idx];
            if let Some(slot) = self.connections.get_mut(i) {
                slot.inner.handle_timeout(now);
                if !slot.has_pending_send {
                    slot.has_pending_send = true;
                    self.pending_send.push(i);
                }
            }
            self.drain_connection_events(i, now);
        }
        did_work
    }

    // ── Transmit ──────────────────────────────────────────────────────────────

    fn drive_transmit(&mut self, now: Instant) -> bool {
        let mut did_work = false;
        let mut to_process = std::mem::take(&mut self.pending_send);

        for &slot_idx in to_process.iter() {
            {
                let Some(slot) = self.connections.get_mut(slot_idx) else { continue };
                slot.has_pending_send = false;
            }

            let mut first_poll = true;
            loop {
                let transmit = {
                    let Some(slot) = self.connections.get_mut(slot_idx) else { break };
                    match slot.inner.poll_transmit(now, MAX_DATAGRAMS, &mut slot.send_buf) {
                        Some(t) => t,
                        None => {
                            if !first_poll {
                                slot.has_pending_send = true;
                                self.pending_send.push(slot_idx);
                            }
                            break;
                        }
                    }
                };
                first_poll = false;

                let payload = {
                    let Some(slot) = self.connections.get_mut(slot_idx) else { break };
                    let bytes = Bytes::copy_from_slice(&slot.send_buf[..transmit.size]);
                    slot.send_buf.clear();
                    bytes
                };

                did_work = true;
                let _ = self.tx_queue.push(TxPacket {
                    destination: transmit.destination,
                    ecn: transmit.ecn.and_then(map_ecn_from_proto),
                    payload,
                    segment_size: transmit.segment_size,
                    src_ip: transmit.src_ip,
                });

                if let Some(slot) = self.connections.get_mut(slot_idx) {
                    slot.next_timeout = slot.inner.poll_timeout();
                }
            }
        }

        to_process.clear();
        to_process.extend(self.pending_send.drain(..));
        self.pending_send = to_process;
        did_work
    }

    fn next_deadline(&self) -> Option<Instant> {
        self.connections
            .iter()
            .filter_map(|(_, s)| s.next_timeout)
            .min()
    }
}

// ── ECN mapping ───────────────────────────────────────────────────────────────

fn map_ecn_to_proto(e: EcnCodepoint) -> quic_proto::EcnCodepoint {
    match e {
        EcnCodepoint::Ect0 => quic_proto::EcnCodepoint::Ect0,
        EcnCodepoint::Ect1 => quic_proto::EcnCodepoint::Ect1,
        EcnCodepoint::Ce => quic_proto::EcnCodepoint::Ce,
    }
}

fn map_ecn_from_proto(e: quic_proto::EcnCodepoint) -> Option<EcnCodepoint> {
    Some(match e {
        quic_proto::EcnCodepoint::Ect0 => EcnCodepoint::Ect0,
        quic_proto::EcnCodepoint::Ect1 => EcnCodepoint::Ect1,
        quic_proto::EcnCodepoint::Ce => EcnCodepoint::Ce,
    })
}
