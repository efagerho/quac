use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rand::RngCore;

use bytes::BytesMut;
use crossbeam_queue::ArrayQueue;
use quinn_proto::{
    AcceptOutcome, ConnectionHandle, ConnectionId, ConnectionIdGenerator, DatagramEvent, Dir,
    InvalidCid, ServerConfig, StreamEvent as QpStreamEvent,
};
use quac_network_tile::{NetworkTile, Queue, RxPacket, WaitStrategy};

use crate::router::CID_LEN;
use quac_socket::{BufferPool, PacketBufMut, ScatterGather, Segment, Transmit};
use smallvec::SmallVec;

use crate::app_queue::AppQueue;
use crate::connection::{
    AcceptEvent, AppCmd, ConnData, ConnEvent, ConnInner, Connection, OpenStreamResult,
};
use crate::endpoint::EndpointInner;
use crate::incoming::Incoming;
use crate::waker::EngineWaker;

// ─── Engine commands from app ────────────────────────────────────────────────

pub(crate) enum EngineCmd {
    Connect {
        remote: SocketAddr,
        server_name: String,
        config: quinn_proto::ClientConfig,
        conn_tx: Arc<AppQueue<Result<Connection, quinn_proto::ConnectError>>>,
    },
    CloseEndpoint,
}

// ─── Per-connection engine state ─────────────────────────────────────────────

struct EngineConn {
    conn: quinn_proto::Connection,
    conn_events: Arc<AppQueue<ConnEvent>>,
    accept_bi: Arc<AppQueue<AcceptEvent>>,
    accept_uni: Arc<AppQueue<AcceptEvent>>,
    /// Single per-connection queue; all stream events funnel here so a burst
    /// across N streams fires exactly one tokio wakeup instead of N.
    stream_data: Arc<AppQueue<ConnData>>,
    /// open_bi/open_uni calls blocked by flow control — retried on Available.
    pending_opens: Vec<Arc<AppQueue<OpenStreamResult>>>,
    from_app: Arc<ArrayQueue<AppCmd>>,
    remote: SocketAddr,
    local_ip: Option<std::net::IpAddr>,
}

// ─── Pending accept (TLS running on app thread) ───────────────────────────────

struct PendingState {
    result_rx: Arc<ArrayQueue<AcceptOutcome>>,
    conn_tx: Arc<AppQueue<Result<Connection, quinn_proto::ConnectionError>>>,
}

// ─── Engine ──────────────────────────────────────────────────────────────────

struct Engine<N: NetworkTile> {
    qp_endpoint: quinn_proto::Endpoint,
    server_config: Arc<ServerConfig>,
    tile: Arc<N>,
    rx_queue: Arc<Queue<RxPacket<<N::Pool as BufferPool>::BufMut>, N::Wait>>,
    tx_queue: Arc<Queue<Transmit<ScatterGather<<N::Pool as BufferPool>::Buf>>, N::Wait>>,
    conns: HashMap<ConnectionHandle, EngineConn>,
    pending: HashMap<ConnectionHandle, PendingState>,
    engine_cmds: Arc<ArrayQueue<EngineCmd>>,
    waker: Arc<EngineWaker>,
    incoming_queue: Arc<AppQueue<Incoming>>,
    tx_scratch: Vec<u8>,
    rx_buf: BytesMut,
    /// App-side `send_cmd` pushes a connection handle here before waking the engine.
    dirty_conns: Arc<ArrayQueue<ConnectionHandle>>,
    /// Connections known to have pending work this iteration.
    ready: VecDeque<ConnectionHandle>,
    /// Dedup set for `ready` — prevents the same handle appearing twice.
    ready_set: HashSet<ConnectionHandle>,
}

impl<N: NetworkTile> Engine<N> {
    fn run(mut self) {
        self.waker.register();
        self.rx_queue.register_consumer();
        loop {
            let now = Instant::now();
            let mut did_work = false;

            // ── 1. Drain RX ──────────────────────────────────────────────────
            while let Some(RxPacket { meta, payload }) = self.rx_queue.pop() {
                self.rx_buf.clear();
                if let Some(slice) = payload.as_contiguous() {
                    self.rx_buf.extend_from_slice(slice);
                } else {
                    for seg in &payload.segments {
                        self.rx_buf
                            .extend_from_slice(&seg.buf.as_ref()[seg.offset..seg.offset + seg.len]);
                    }
                }
                let data = self.rx_buf.split();

                self.tx_scratch.clear();
                match self.qp_endpoint.handle(
                    now,
                    meta.src,
                    meta.dst_ip,
                    meta.ecn.map(ecn_to_qp),
                    data,
                    &mut self.tx_scratch,
                ) {
                    Some(DatagramEvent::NewConnection(incoming)) => {
                        self.handle_new_connection(incoming, now);
                    }
                    Some(DatagramEvent::ConnectionEvent(ch, ev)) => {
                        if let Some(ec) = self.conns.get_mut(&ch) {
                            ec.conn.handle_event(ev);
                        }
                        if self.ready_set.insert(ch) {
                            self.ready.push_back(ch);
                        }
                    }
                    Some(DatagramEvent::Response(qt)) => {
                        enqueue_transmit(
                            &self.tile,
                            &self.tx_queue,
                            &self.tx_scratch,
                            qt.destination,
                            qt.ecn,
                            qt.size,
                            qt.segment_size,
                            qt.src_ip,
                        );
                    }
                    None => {}
                }
                did_work = true;
            }

            // ── 2. Poll pending accepts ───────────────────────────────────────
            let pending_handles: Vec<ConnectionHandle> = self.pending.keys().copied().collect();
            for ch in pending_handles {
                let accepted = self.pending.get(&ch).and_then(|ps| ps.result_rx.pop());
                if let Some(outcome) = accepted {
                    let ps = self.pending.remove(&ch).unwrap();
                    self.tx_scratch.clear();
                    match self.qp_endpoint.finish_accept(outcome, &mut self.tx_scratch) {
                        Ok((handle, qp_conn)) => {
                            let remote = qp_conn.remote_address();
                            let local_ip = qp_conn.local_ip();
                            let ec = make_engine_conn(qp_conn, remote, local_ip);
                            let inner = make_conn_inner(
                                &self.waker,
                                &self.dirty_conns,
                                handle,
                                &ec,
                            );
                            ps.conn_tx.push_overwrite(Ok(Connection::new(inner)));
                            self.conns.insert(handle, ec);
                            if self.ready_set.insert(handle) {
                                self.ready.push_back(handle);
                            }
                        }
                        Err(e) => {
                            ps.conn_tx.push_overwrite(Err(e.cause));
                            if let Some(qt) = e.response {
                                enqueue_transmit(
                                    &self.tile,
                                    &self.tx_queue,
                                    &self.tx_scratch,
                                    qt.destination,
                                    qt.ecn,
                                    qt.size,
                                    qt.segment_size,
                                    qt.src_ip,
                                );
                            }
                        }
                    }
                    did_work = true;
                }
            }

            // ── 3. Engine commands ─────────────────────────────────────────────
            while let Some(cmd) = self.engine_cmds.pop() {
                match cmd {
                    EngineCmd::Connect {
                        remote,
                        server_name,
                        config,
                        conn_tx,
                    } => {
                        match self.qp_endpoint.connect(now, config, remote, &server_name) {
                            Ok((handle, qp_conn)) => {
                                let local_ip = qp_conn.local_ip();
                                let ec = make_engine_conn(qp_conn, remote, local_ip);
                                let inner = make_conn_inner(
                                    &self.waker,
                                    &self.dirty_conns,
                                    handle,
                                    &ec,
                                );
                                conn_tx.push_overwrite(Ok(Connection::new(inner)));
                                self.conns.insert(handle, ec);
                                if self.ready_set.insert(handle) {
                                    self.ready.push_back(handle);
                                }
                            }
                            Err(e) => {
                                conn_tx.push_overwrite(Err(e));
                            }
                        }
                    }
                    EngineCmd::CloseEndpoint => return,
                }
                did_work = true;
            }

            // ── 4. Drain app-side dirty queue ─────────────────────────────────
            while let Some(ch) = self.dirty_conns.pop() {
                if self.ready_set.insert(ch) {
                    self.ready.push_back(ch);
                }
            }

            // ── 5. Timer scan — O(n) comparison, O(fired) work ────────────────
            // Runs every iteration so timers are never delayed by a busy engine.
            // Uses the same `now` as poll_transmit below to keep quinn-proto's
            // clock consistent: handle_timeout(now) and poll_transmit(now) must
            // agree on the current time or pacing checks will suppress TX.
            {
                let mut timer_fired: Vec<ConnectionHandle> = Vec::new();
                for (&ch, ec) in &mut self.conns {
                    if ec.conn.poll_timeout().map_or(false, |t| t <= now) {
                        ec.conn.handle_timeout(now);
                        timer_fired.push(ch);
                    }
                }
                for ch in timer_fired {
                    if self.ready_set.insert(ch) {
                        self.ready.push_back(ch);
                    }
                    did_work = true;
                }
            }

            // ── 6. Process ready connections (app cmds + timer-fired) ─────────
            let mut to_remove = Vec::new();
            while let Some(ch) = self.ready.pop_front() {
                self.ready_set.remove(&ch);
                if let Some(ec) = self.conns.get_mut(&ch) {
                    // App commands
                    while let Some(cmd) = ec.from_app.pop() {
                        dispatch_cmd(cmd, ec, now);
                        did_work = true;
                    }

                    // TX
                    self.tx_scratch.clear();
                    while let Some(qt) = ec.conn.poll_transmit(now, 16, &mut self.tx_scratch) {
                        enqueue_transmit(
                            &self.tile,
                            &self.tx_queue,
                            &self.tx_scratch,
                            qt.destination,
                            qt.ecn,
                            qt.size,
                            qt.segment_size,
                            qt.src_ip,
                        );
                        self.tx_scratch.clear();
                        did_work = true;
                    }

                    // Endpoint events
                    while let Some(ev) = ec.conn.poll_endpoint_events() {
                        let _ = self.qp_endpoint.handle_event(ch, ev);
                    }

                    // App events
                    let mut lost = false;
                    loop {
                        let Some(ev) = ec.conn.poll() else { break };
                        let closed = dispatch_app_event(ev, ec);
                        if closed {
                            lost = true;
                            break;
                        }
                    }

                    // Drain any pending datagrams (no datagram queue exposed yet)
                    while let Some(_) = ec.conn.datagrams().recv() {}

                    if lost {
                        to_remove.push(ch);
                    }
                }
            }
            for ch in to_remove {
                self.conns.remove(&ch);
            }

            if !did_work {
                let deadline = self
                    .conns
                    .values_mut()
                    .filter_map(|ec| ec.conn.poll_timeout())
                    .min()
                    .unwrap_or_else(|| now + Duration::from_millis(50));
                let timeout = deadline.saturating_duration_since(Instant::now());
                self.rx_queue.set_sleeping();
                self.waker.set_sleeping();
                if self.rx_queue.is_empty() && self.dirty_conns.is_empty() {
                    std::thread::park_timeout(timeout);
                }
                self.waker.clear_sleeping();
                self.rx_queue.clear_sleeping();
            }
        }
    }

    fn handle_new_connection(&mut self, incoming: quinn_proto::Incoming, now: Instant) {
        let result_rx: Arc<ArrayQueue<AcceptOutcome>> = Arc::new(ArrayQueue::new(1));
        let conn_tx: Arc<AppQueue<Result<Connection, quinn_proto::ConnectionError>>> =
            Arc::new(AppQueue::new(1));

        self.tx_scratch.clear();
        match self.qp_endpoint.pre_accept(
            incoming,
            Some(Arc::clone(&self.server_config)),
            now,
            &mut self.tx_scratch,
        ) {
            Ok(pending) => {
                let ch = pending.ch();
                let inc = Incoming {
                    pending,
                    result_tx: Arc::clone(&result_rx),
                    engine_waker: Arc::clone(&self.waker),
                    conn_rx: Arc::clone(&conn_tx),
                };
                self.incoming_queue.push_overwrite(inc);
                self.pending.insert(ch, PendingState { result_rx, conn_tx });
            }
            Err(e) => {
                if let Some(qt) = e.response {
                    enqueue_transmit(
                        &self.tile,
                        &self.tx_queue,
                        &self.tx_scratch,
                        qt.destination,
                        qt.ecn,
                        qt.size,
                        qt.segment_size,
                        qt.src_ip,
                    );
                }
            }
        }
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn enqueue_transmit<N: NetworkTile>(
    tile: &Arc<N>,
    tx_queue: &Arc<Queue<Transmit<ScatterGather<<N::Pool as BufferPool>::Buf>>, N::Wait>>,
    tx_scratch: &[u8],
    destination: std::net::SocketAddr,
    ecn: Option<quinn_proto::EcnCodepoint>,
    size: usize,
    segment_size: Option<usize>,
    src_ip: Option<std::net::IpAddr>,
) {
    let mut tmp = Vec::with_capacity(1);
    if tile.alloc_tx_bufs(size, 1, &mut tmp) == 0 {
        return;
    }
    let mut buf = tmp.remove(0);
    buf.as_mut()[..size].copy_from_slice(&tx_scratch[..size]);
    let frozen = buf.freeze();
    let sg = ScatterGather {
        segments: SmallVec::from_vec(vec![Segment {
            buf: frozen,
            offset: 0,
            len: size,
        }]),
    };
    let _ = tx_queue.push(Transmit {
        destination,
        ecn: ecn.map(ecn_from_qp),
        contents: sg,
        segment_size,
        src_ip,
    });
}

fn make_engine_conn(
    conn: quinn_proto::Connection,
    remote: SocketAddr,
    local_ip: Option<std::net::IpAddr>,
) -> EngineConn {
    EngineConn {
        conn,
        conn_events: Arc::new(AppQueue::new(16)),
        accept_bi: Arc::new(AppQueue::new(64)),
        accept_uni: Arc::new(AppQueue::new(64)),
        stream_data: Arc::new(AppQueue::new(4096)),
        pending_opens: Vec::new(),
        from_app: Arc::new(ArrayQueue::new(256)),
        remote,
        local_ip,
    }
}

fn make_conn_inner(
    waker: &Arc<EngineWaker>,
    dirty_conns: &Arc<ArrayQueue<ConnectionHandle>>,
    handle: ConnectionHandle,
    ec: &EngineConn,
) -> Arc<ConnInner> {
    Arc::new(ConnInner {
        accept_bi: Arc::clone(&ec.accept_bi),
        accept_uni: Arc::clone(&ec.accept_uni),
        conn_events: Arc::clone(&ec.conn_events),
        stream_data: Arc::clone(&ec.stream_data),
        cmds: Arc::clone(&ec.from_app),
        engine_waker: Arc::clone(waker),
        remote_address: ec.remote,
        local_ip: ec.local_ip,
        handle,
        dirty_conns: Arc::clone(dirty_conns),
    })
}

fn dispatch_cmd(cmd: AppCmd, ec: &mut EngineConn, now: Instant) {
    match cmd {
        AppCmd::OpenStream { dir, result_tx } => {
            if let Some(id) = ec.conn.streams().open(dir) {
                result_tx.push_overwrite(OpenStreamResult::Opened { id });
            } else {
                ec.pending_opens.push(result_tx);
            }
        }
        AppCmd::StreamWrite { id, data } => {
            let mut chunks = [data];
            let _ = ec.conn.send_stream(id).write_chunks(&mut chunks);
        }
        AppCmd::StreamFinish { id } => {
            let _ = ec.conn.send_stream(id).finish();
        }
        AppCmd::StreamReset { id, error_code } => {
            let _ = ec.conn.send_stream(id).reset(error_code);
        }
        AppCmd::StreamStopSending { id, error_code } => {
            let _ = ec.conn.recv_stream(id).stop(error_code);
        }
        AppCmd::SendDatagram(data) => {
            let _ = ec.conn.datagrams().send(data, true);
        }
        AppCmd::Close { error_code, reason } => {
            ec.conn.close(now, error_code, reason);
        }
    }
}

/// Returns `true` if the connection has been lost.
fn dispatch_app_event(ev: quinn_proto::Event, ec: &mut EngineConn) -> bool {
    use quinn_proto::Event;
    match ev {
        Event::HandshakeDataReady => false,
        Event::Connected => {
            ec.conn_events.push_overwrite(ConnEvent::Connected);
            false
        }
        Event::ConnectionLost { reason } => {
            ec.accept_bi.push_overwrite(AcceptEvent::Lost(reason.clone()));
            ec.accept_uni.push_overwrite(AcceptEvent::Lost(reason.clone()));
            ec.stream_data.push_overwrite(ConnData::Lost(reason.clone()));
            for tx in &ec.pending_opens {
                tx.push_overwrite(OpenStreamResult::Lost(reason.clone()));
            }
            ec.conn_events.push_overwrite(ConnEvent::Lost(reason));
            true
        }
        Event::Stream(stream_ev) => {
            dispatch_stream_event(stream_ev, ec);
            false
        }
        Event::DatagramReceived | Event::DatagramsUnblocked => false,
    }
}

/// Drain all available data from a receive stream into the connection's stream_data queue.
/// Used both from the `Readable` event handler and from the `Opened` handler
/// (quinn-proto does not emit `Readable` for the initial data on a new stream).
fn drain_recv_into(id: quinn_proto::StreamId, ec: &mut EngineConn) {
    if let Ok(mut chunks) = ec.conn.recv_stream(id).read(true) {
        loop {
            match chunks.next(usize::MAX) {
                Ok(Some(chunk)) => {
                    ec.stream_data.push_overwrite(ConnData::Data { id, bytes: chunk.bytes });
                }
                Ok(None) => {
                    ec.stream_data.push_overwrite(ConnData::Finished { id });
                    break;
                }
                Err(quinn_proto::ReadError::Blocked) => break,
                Err(quinn_proto::ReadError::Reset(code)) => {
                    ec.stream_data.push_overwrite(ConnData::Reset { id, code });
                    break;
                }
            }
        }
    }
}

fn dispatch_stream_event(ev: QpStreamEvent, ec: &mut EngineConn) {
    match ev {
        QpStreamEvent::Opened { dir } => {
            while let Some(id) = ec.conn.streams().accept(dir) {
                let target = if dir == Dir::Bi { &ec.accept_bi } else { &ec.accept_uni };
                target.push_overwrite(AcceptEvent::Opened { id });
                // quinn-proto does not emit Readable for initial data on a new stream.
                drain_recv_into(id, ec);
            }
        }
        QpStreamEvent::Readable { id } => {
            drain_recv_into(id, ec);
        }
        QpStreamEvent::Writable { .. } => {}
        QpStreamEvent::Finished { id } => {
            ec.stream_data.push_overwrite(ConnData::Finished { id });
        }
        QpStreamEvent::Stopped { id, error_code } => {
            ec.stream_data.push_overwrite(ConnData::Reset { id, code: error_code });
        }
        QpStreamEvent::Available { dir } => {
            let mut remaining = Vec::new();
            for result_tx in ec.pending_opens.drain(..) {
                if let Some(id) = ec.conn.streams().open(dir) {
                    result_tx.push_overwrite(OpenStreamResult::Opened { id });
                } else {
                    remaining.push(result_tx);
                }
            }
            ec.pending_opens = remaining;
        }
    }
}

// ─── EcnCodepoint conversions ─────────────────────────────────────────────────

fn ecn_to_qp(e: quac_socket::EcnCodepoint) -> quinn_proto::EcnCodepoint {
    use quac_socket::EcnCodepoint as S;
    use quinn_proto::EcnCodepoint as Q;
    match e {
        S::Ect0 => Q::Ect0,
        S::Ect1 => Q::Ect1,
        S::Ce => Q::Ce,
    }
}

fn ecn_from_qp(e: quinn_proto::EcnCodepoint) -> quac_socket::EcnCodepoint {
    use quinn_proto::EcnCodepoint as Q;
    use quac_socket::EcnCodepoint as S;
    match e {
        Q::Ect0 => S::Ect0,
        Q::Ect1 => S::Ect1,
        Q::Ce => S::Ce,
    }
}

// ─── Startup ──────────────────────────────────────────────────────────────────

// ─── Per-engine CID generator ─────────────────────────────────────────────────

/// Generates connection IDs that encode the owning engine tile index in byte 0.
///
/// The network tile's `route_packet` reads `cid[0] % engine_count` to send
/// post-handshake packets back to the engine that created the connection,
/// without any shared lookup table.
struct TileIndexCidGenerator {
    engine_index: usize,
    engine_count: usize,
}

impl ConnectionIdGenerator for TileIndexCidGenerator {
    fn generate_cid(&mut self) -> ConnectionId {
        let mut bytes = [0u8; CID_LEN];
        rand::rng().fill_bytes(&mut bytes[1..]);
        bytes[0] = self.engine_index as u8;
        ConnectionId::new(&bytes)
    }

    fn validate(&self, cid: &ConnectionId) -> Result<(), InvalidCid> {
        if cid.len() == CID_LEN && (cid[0] as usize % self.engine_count) == self.engine_index {
            Ok(())
        } else {
            Err(InvalidCid)
        }
    }

    fn cid_len(&self) -> usize {
        CID_LEN
    }

    fn cid_lifetime(&self) -> Option<Duration> {
        None
    }
}

/// Spawn one engine thread per rx/tx queue pair on the `NetworkTile`.
///
/// Each engine gets its own `EngineWaker` so app-side commands wake the
/// specific thread that owns the connection, not a shared/wrong thread.
/// The endpoint-level waker (for `CloseEndpoint`) points at engine 0.
pub(crate) fn spawn_engines<N: NetworkTile>(
    tile: &Arc<N>,
    ep_config: Arc<quinn_proto::EndpointConfig>,
    server_config: Arc<ServerConfig>,
) -> Arc<EndpointInner> {
    let engine_count = tile.rx_queues().len();
    assert!(engine_count > 0);

    let incoming_queue: Arc<AppQueue<Incoming>> = Arc::new(AppQueue::new(256));
    let engine_cmds: Arc<ArrayQueue<EngineCmd>> = Arc::new(ArrayQueue::new(64));

    let wakers: Vec<Arc<EngineWaker>> =
        (0..engine_count).map(|_| Arc::new(EngineWaker::new())).collect();

    let dirty_conns_per_engine: Vec<Arc<ArrayQueue<ConnectionHandle>>> =
        (0..engine_count).map(|_| Arc::new(ArrayQueue::new(4096))).collect();

    let ep_inner = Arc::new(EndpointInner {
        incoming_queue: Arc::clone(&incoming_queue),
        engine_cmds: Arc::clone(&engine_cmds),
        engine_waker: Arc::clone(&wakers[0]),
    });

    let rx_queues = tile.rx_queues();
    let tx_queues = tile.tx_queues();

    for i in 0..engine_count {
        // Each engine gets its own EndpointConfig with a CID generator that
        // encodes `i` in byte 0, enabling the network tile to route subsequent
        // packets back to this engine by `cid[0] % engine_count`.
        let mut per_engine_cfg = (*ep_config).clone();
        let n = engine_count;
        per_engine_cfg.cid_generator(move || {
            Box::new(TileIndexCidGenerator { engine_index: i, engine_count: n })
        });
        let qp_endpoint = quinn_proto::Endpoint::new(
            Arc::new(per_engine_cfg),
            Some(Arc::clone(&server_config)),
            true,
            None,
        );

        let engine: Engine<N> = Engine {
            qp_endpoint,
            server_config: Arc::clone(&server_config),
            tile: Arc::clone(tile),
            rx_queue: Arc::clone(&rx_queues[i]),
            tx_queue: Arc::clone(&tx_queues[i]),
            conns: HashMap::new(),
            pending: HashMap::new(),
            engine_cmds: Arc::clone(&engine_cmds),
            waker: Arc::clone(&wakers[i]),
            incoming_queue: Arc::clone(&incoming_queue),
            tx_scratch: Vec::with_capacity(65536),
            rx_buf: BytesMut::with_capacity(65536),
            dirty_conns: Arc::clone(&dirty_conns_per_engine[i]),
            ready: VecDeque::new(),
            ready_set: HashSet::new(),
        };

        std::thread::Builder::new()
            .name(format!("quac-engine-{i}"))
            .spawn(move || engine.run())
            .expect("spawn engine thread");
    }

    ep_inner
}
