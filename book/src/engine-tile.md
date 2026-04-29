# QUIC Engine Tile

The engine tile is a single OS thread that drives the QUIC protocol state
machine for all connections assigned to it. It consumes received datagrams from
an RX queue, advances `quinn_proto` state, serialises outgoing packets into a TX
queue, and delivers events to the async application layer via lock-free queues.

## Crate boundary

Engine tiles live in `quac-tile`. Everything below that boundary —
`PacketSocket`, `NetworkTile`, queues, wait strategies — is protocol-agnostic.
The engine tile is where QUIC happens.

## Per-connection state

Each live connection is represented by an `EngineConn`:

```rust,ignore
struct EngineConn {
    conn: quinn_proto::Connection,  // the protocol state machine
    conn_events: Arc<AppQueue<ConnEvent>>,
    accept_bi:   Arc<AppQueue<AcceptEvent>>,
    accept_uni:  Arc<AppQueue<AcceptEvent>>,
    stream_data: Arc<AppQueue<ConnData>>,
    pending_opens: Vec<Arc<AppQueue<OpenStreamResult>>>,
    from_app: Arc<ArrayQueue<AppCmd>>,
    remote:   SocketAddr,
    local_ip: Option<IpAddr>,
}
```

`conn` is owned exclusively by the engine thread — no other thread ever touches
it. `conn_events`, `accept_bi`, `accept_uni`, `stream_data`, and `from_app` are
the queues shared with the application layer; their `Arc` clones live inside the
`Connection` handle returned to the application.

`stream_data` is a single per-connection queue that carries data chunks, EOF
markers, and reset events for all streams on that connection. Multiplexing all
stream events onto one queue means a burst of N stream events across N streams
fires exactly one tokio wakeup instead of N.

## Engine structure

```rust,ignore
struct Engine<N: NetworkTile> {
    qp_endpoint: quinn_proto::Endpoint,
    server_config: Arc<ServerConfig>,
    tile: Arc<N>,
    rx_queue: Arc<Queue<RxPacket<…>, N::Wait>>,
    tx_queue: Arc<Queue<Transmit<…>, N::Wait>>,
    conns:    HashMap<ConnectionHandle, EngineConn>,
    pending:  HashMap<ConnectionHandle, PendingState>,
    engine_cmds: Arc<ArrayQueue<EngineCmd>>,
    waker:    Arc<EngineWaker>,
    incoming_queue: Arc<AppQueue<Incoming>>,
    tx_scratch: Vec<u8>,
    rx_buf:   BytesMut,
    dirty_conns: Arc<ArrayQueue<ConnectionHandle>>,
    ready:    VecDeque<ConnectionHandle>,
    ready_set: HashSet<ConnectionHandle>,
}
```

`dirty_conns` is the **ready list** input: whenever the application side pushes
a command to a connection, it also pushes the connection handle to `dirty_conns`
and wakes the engine. At the start of each iteration the engine drains
`dirty_conns` into the `ready` deque, deduplicating with `ready_set`. Only
connections in `ready` are processed for app commands and TX; all other
connections are skipped unless a timer fires or a packet arrives.

`tx_scratch` is a reusable `Vec<u8>` that `quinn_proto` serialises outgoing
packets into. The engine immediately copies from `tx_scratch` into a pool buffer
via `enqueue_transmit` and clears the scratch buffer for the next call.

## The run loop

The engine loop runs six steps in order every iteration:

### Step 1 — Drain RX

```rust,ignore
while let Some(RxPacket { meta, payload }) = self.rx_queue.pop() {
    // Assemble scatter-gather into rx_buf (BytesMut)
    self.rx_buf.clear();
    // ... copy segments ...
    let data = self.rx_buf.split();

    match self.qp_endpoint.handle(now, meta.src, meta.dst_ip, ecn, data, &mut self.tx_scratch) {
        Some(DatagramEvent::NewConnection(incoming)) => {
            self.handle_new_connection(incoming, now);
        }
        Some(DatagramEvent::ConnectionEvent(ch, ev)) => {
            ec.conn.handle_event(ev);
            // mark ready for TX
        }
        Some(DatagramEvent::Response(qt)) => {
            enqueue_transmit(/* stateless reply */);
        }
        None => {}
    }
}
```

Each received packet is assembled from its `ScatterGather` segments into a
contiguous `BytesMut` and handed to `qp_endpoint.handle`. The three outcomes
are:

- **NewConnection** — an Initial packet for an unknown connection. The engine
  calls `pre_accept` which validates the packet, optionally sends a
  `RETRY` or `VERSION_NEGOTIATION` response, and wraps the connection in an
  `Incoming`. The `Incoming` is pushed to `incoming_queue` where the async
  `Endpoint::accept()` future will pick it up. TLS processing runs on the
  application's tokio thread when the application calls `incoming.accept()`.

- **ConnectionEvent** — an event for an existing connection (data, ACK, RESET,
  etc.). The engine calls `handle_event` to advance the state machine and marks
  the connection ready for TX processing.

- **Response** — a stateless reply (RETRY, VERSION_NEGOTIATION, or
  STATELESS_RESET) that does not create connection state. Serialised directly
  into `tx_scratch` and forwarded to the TX queue.

### Step 2 — Poll pending accepts

When the application calls `incoming.accept()`, TLS runs asynchronously on a
tokio thread. The result is returned through a one-shot `ArrayQueue`. The engine
polls this queue each iteration; when the result arrives, it calls
`qp_endpoint.finish_accept` and promotes the connection from `pending` to
`conns`.

### Step 3 — Engine commands

The engine drains its `engine_cmds` queue for endpoint-level operations:

- `EngineCmd::Connect` — outbound client connection. Creates the quinn_proto
  state and returns a `Connection` handle to the caller via a one-shot queue.
- `EngineCmd::CloseEndpoint` — shuts down the engine thread.

### Step 4 — Drain dirty connections

```rust,ignore
while let Some(ch) = self.dirty_conns.pop() {
    if self.ready_set.insert(ch) {
        self.ready.push_back(ch);
    }
}
```

Every application-side operation (stream write, finish, reset, open) pushes the
connection handle to `dirty_conns` before waking the engine. This step drains
that queue into the ready list.

### Step 5 — Timer scan

```rust,ignore
for (&ch, ec) in &mut self.conns {
    if ec.conn.poll_timeout().map_or(false, |t| t <= now) {
        ec.conn.handle_timeout(now);
        // add to ready
    }
}
```

The timer scan is O(n) in the number of live connections, but the work per
connection is a single `Instant` comparison. Connections whose timer has fired
are added to the ready list.

**Clock consistency.** `handle_timeout(now)` and `poll_transmit(now, …)` in step
6 use the *same* `now` snapshot taken at the top of the loop iteration. If they
used different timestamps, quinn-proto's internal pacing clock could advance in
`handle_timeout` and then `poll_transmit` would suppress TX because it sees the
provided `now` as being in the past. Sharing `now` across both calls avoids
this.

### Step 6 — Process ready connections

For each connection in the ready list:

1. **App commands** — drain `from_app` and dispatch. Stream writes call
   `send_stream(id).write(data)`; open stream calls
   `streams().open(dir)`.

2. **Transmit** — call `poll_transmit(now, max_datagrams, &mut tx_scratch)` in
   a loop until it returns `None`. Each call produces one QUIC packet serialised
   into `tx_scratch`. `enqueue_transmit` copies it into a pool buffer and pushes
   a `Transmit` to the TX queue.

3. **Endpoint events** — drain `poll_endpoint_events` and pass them back to the
   endpoint so it can update its connection ID mappings.

4. **Application events** — drain `poll()` and dispatch stream-opened, data
   received, stream-reset, connection-closed events to the appropriate `AppQueue`
   for delivery to async tasks.

### Sleep

When no work was done in any step, the engine calculates the earliest timer
deadline across all connections and parks for that duration (capped at 50ms).
Before parking it sets the sleeping flags on both `waker` and `rx_queue` and
re-checks the dirty-connection queue to close the race between the final empty
check and the park call.

## TX buffer allocation

```rust,ignore
fn enqueue_transmit<N: NetworkTile>(
    tile: &Arc<N>,
    tx_queue: &Arc<Queue<Transmit<…>, N::Wait>>,
    tx_scratch: &[u8],
    destination: SocketAddr,
    ecn: Option<…>,
    size: usize,
    segment_size: Option<usize>,
    src_ip: Option<IpAddr>,
) {
    let mut tmp = Vec::with_capacity(1);
    if tile.alloc_tx_bufs(size, 1, &mut tmp) == 0 {
        return; // pool exhausted; drop packet
    }
    let mut buf = tmp.remove(0);
    buf.resize(size);
    buf.as_mut()[..size].copy_from_slice(&tx_scratch[..size]);
    let sg = ScatterGather { segments: smallvec![Segment { buf: buf.freeze(), offset: 0, len: size }] };
    let _ = tx_queue.push(Transmit { destination, ecn, contents: sg, segment_size, src_ip });
}
```

Buffers come from the network tile's pre-filled pool via `alloc_tx_bufs`. If the
pool is momentarily empty the packet is dropped; QUIC loss recovery at the peer
will retransmit. There is no blocking or back-pressure on the transmit path
inside the engine — the engine thread never waits for buffer memory.

## Connection ID generation

Each engine tile configures quinn_proto with a `TileIndexCidGenerator` that
encodes the engine's index in byte zero of every server-generated CID:

```rust,ignore
struct TileIndexCidGenerator {
    engine_index: usize,
    engine_count: usize,
}

impl ConnectionIdGenerator for TileIndexCidGenerator {
    fn generate_cid(&mut self) -> ConnectionId {
        let mut bytes = [0u8; CID_LEN]; // CID_LEN = 9
        rand::rng().fill_bytes(&mut bytes[1..]);
        bytes[0] = self.engine_index as u8;
        ConnectionId::new(&bytes)
    }

    fn validate(&self, cid: &ConnectionId) -> Result<(), InvalidCid> {
        if cid.len() == CID_LEN && cid[0] as usize % self.engine_count == self.engine_index {
            Ok(())
        } else {
            Err(InvalidCid)
        }
    }
}
```

`QuicPacketRouter` reads `dcid[0] % engine_count` to route subsequent packets
back to this engine without any shared lookup table. `validate` rejects CIDs
that belong to a different engine tile, so quinn_proto never accepts a packet
routed to the wrong engine.

## Spawning engines

`spawn_engines` creates one engine thread per queue pair on the network tile:

```rust,ignore
pub(crate) fn spawn_engines<N: NetworkTile>(
    tile: &Arc<N>,
    ep_config: Arc<quinn_proto::EndpointConfig>,
    server_config: Arc<ServerConfig>,
) -> Arc<EndpointInner> {
    let engine_count = tile.rx_queues().len();

    // One dirty-connection queue per engine, shared with ConnInner.
    let dirty_conns_per_engine: Vec<Arc<ArrayQueue<ConnectionHandle>>> =
        (0..engine_count).map(|_| Arc::new(ArrayQueue::new(4096))).collect();

    for i in 0..engine_count {
        // Each engine gets its own EndpointConfig with CIDs that encode index i.
        let mut per_engine_cfg = (*ep_config).clone();
        per_engine_cfg.cid_generator(move || {
            Box::new(TileIndexCidGenerator { engine_index: i, engine_count })
        });
        // Spawn the engine thread.
        thread::Builder::new()
            .name(format!("quac-engine-{i}"))
            .spawn(move || engine.run())
            .expect("spawn engine");
    }
    // ...
}
```

Each engine thread is named `quac-engine-{i}` for visibility in profilers. Each
gets its own `quinn_proto::Endpoint` instance so there is no shared QUIC state
between engine threads.
