# Tile-Based Architecture

The `PacketSocket` trait from the previous chapter provides one socket and one thread — nothing
more. An application that only needs raw throughput on a single core can drive it directly. But
most applications want async/await, need more than one I/O thread, and expect backpressure to
flow from slow consumers back to the NIC. The tile-based architecture bridges that gap.

A **tile** is a logical unit of execution that owns exactly one UDP socket and runs exactly three
OS threads: a reader thread, a writer thread, and an engine thread. The reader pumps packets from
the socket into a set of bounded queues; the engine drains those queues, advances protocol state,
and pushes outgoing packets into a different bounded queue; the writer drains that queue and
submits packets to the socket. The three threads never share mutable state and never acquire a
lock on the data path.

Network tiles (reader + writer) and engine tiles are **independent**. Their counts are separate
runtime parameters. This separation means a deployment can have two network tiles — one per NIC
queue — driving four engine tiles that saturate all available CPU cores, without any structural
coupling between I/O thread count and protocol thread count.

## The Network Tile Trait

Every I/O backend — OS UDP socket, AF_XDP, DPDK, io_uring — implements the `NetworkTile` trait.
The trait exposes the queues that connect the reader and writer threads to the engine tiles.
Because queue types are named explicitly in the trait, the engine tiles can be written once
without caring which backend produced the packets.

```rust,ignore
use crossbeam::queue::ArrayQueue;
use std::sync::Arc;

pub trait NetworkTile: Send + Sync + 'static {
    type Pool: BufferPool;

    fn pool(&self) -> &Arc<Self::Pool>;

    /// M×N RX queues: rx_queues()[j] is the SPSC channel from this network
    /// tile's reader thread to engine tile j.
    fn rx_queues(
        &self,
    ) -> &[Arc<ArrayQueue<RxPacket<<Self::Pool as BufferPool>::RecvBuf>>>];

    /// One TX SPSC queue: engine tile j % M pushes outgoing packets here;
    /// SO_REUSEPORT lets this socket transmit on behalf of any connection.
    fn tx_queue(
        &self,
    ) -> &Arc<ArrayQueue<TxPacket<<Self::Pool as BufferPool>::Buf>>>;

    /// Spawn the reader thread (routing layer included) and the writer thread.
    fn start(self: Arc<Self>);

    fn stop(&self);
}
```

The packet types that cross the queues are plain structs. No routing metadata is needed because
the reader uses the CID prefix to choose which queue to push into, and any network tile can
transmit any packet thanks to `SO_REUSEPORT`.

```rust,ignore
/// One received datagram. The RecvBuf is moved zero-copy from the reader
/// thread into the engine thread; no data is copied across the queue.
pub struct RxPacket<B: RecvBuf> {
    pub meta: RecvMeta,
    pub buf:  ScatterGather<B>,
}

/// One outgoing datagram. Ownership of the pool buffer moves from the engine
/// thread into the writer thread, which hands it to socket.send().
pub struct TxPacket<B: PacketBuf> {
    pub transmit: Transmit<ScatterGather<B>>,
}
```

## Queue Topology

Let M be the number of network tiles and N the number of engine tiles. The wiring is asymmetric.

**RX side — M×N SPSC queues.** Each network tile reader has N queues, one per engine tile. Only
one reader writes to each queue and only one engine reads from it — SPSC (single-producer,
single-consumer). Crossbeam's `ArrayQueue<T>` provides a wait-free push and pop with one
`AtomicUsize` each for the head and tail.

**TX side — N SPSC queues.** Each engine tile has exactly one TX queue. Engine tile j sends its
outgoing packets to network tile `j % M`. Because all network tiles bind the same address with
`SO_REUSEPORT`, this tile can transmit on behalf of any connection regardless of which tile
originally received the connection's Initial packet.

```
                    rx[i][j] — SPSC, Network Tile i reader → Engine Tile j
                    tx[j]    — SPSC, Engine Tile j → Network Tile (j % M) writer

NIC RX                                                              NIC TX
(queue 0) ──▶  NT 0 Reader                        NT 0 Writer ──▶ (SO_REUSEPORT)
               [routing]  ──rx[0][0]──▶ ET 0 ──tx[0]─────────────▶
                           ──rx[0][1]──▶ ET 1 ──tx[1]──▶ NT 1 Writer ──▶ (SO_REUSEPORT)

NIC RX
(queue 1) ──▶  NT 1 Reader
               [routing]  ──rx[1][0]──▶ ET 0
                           ──rx[1][1]──▶ ET 1
```

Engine tile j drains M incoming queues (`rx[0][j]` … `rx[M-1][j]`) each iteration and pushes
outgoing packets to its single `tx[j]` queue. Three threads per tile, zero cross-thread locks on
the data path.

## Reader Routing Layer

The reader thread is not a simple pump. Before pushing a received packet onto a queue it inspects
the first byte of the QUIC connection ID to determine the target engine tile:

```
socket.recv() → for each received datagram:
    if packet carries a known server-assigned CID:
        j = cid[0] % N          // first CID byte encodes engine tile index
        rx_queues[j].push(RxPacket { meta, buf })
    else (Initial packet — no server CID yet):
        j = random() % N
        rx_queues[j].push(RxPacket { meta, buf })
```

This is pure userspace routing: one byte read from the received buffer, one bounded queue push,
no shared data structure. If `rx_queues[j]` is full the reader drops the packet and the QUIC loss
recovery mechanism handles retransmission. The engine tile's response to a new connection always
assigns connection IDs whose first byte encodes the tile's own index, so all subsequent packets
from that peer are routed back to the correct engine tile even if the peer's source address
changes (NAT rebinding, multipath, connection migration).

For backends that do not expose the QUIC payload early enough to inspect the CID (e.g. a raw
DPDK pipeline with hardware offload), the routing can be delegated to an XDP program or a DPDK
`rte_flow` rule that steers packets by CID prefix before they ever reach userspace.

## Engine Thread Integration

The engine tile's inner loop wraps a `run_once` function in a queue adapter that replaces the
direct `PacketSocket::recv` / `PacketSocket::send` calls with queue drains and pushes:

```rust,ignore
pub struct EngineTile<S: PacketSocket> {
    engine:      Engine<S>,
    rx_queues:   Vec<Arc<ArrayQueue<RxPacket<RecvBufOf<S>>>>>,  // one per NT
    tx_queue:    Arc<ArrayQueue<TxPacket<BufOf<S>>>>,
    is_parked:   Arc<AtomicBool>,
}

impl<S: PacketSocket> EngineTile<S> {
    pub fn run(&self) {
        loop {
            let (deadline, did_work) = self.run_once(Instant::now());
            if did_work { continue; }

            // Spin briefly before committing to sleep; avoids a syscall
            // when a burst is arriving but the queue was transiently empty.
            let mut idle = 0usize;
            while idle < SPIN_ITERS {
                hint::spin_loop();
                let (_, did_work) = self.run_once(Instant::now());
                if did_work { idle = 0; continue; }
                idle += 1;
            }

            // Commit to sleep. Set flag BEFORE calling park() so producers
            // see it while the engine is still running.
            self.is_parked.store(true, Ordering::Release);
            // Re-check to close the race with a producer that pushed just
            // before the flag was set (see "Engine Wakeup" below).
            let (deadline, did_work) = self.run_once(Instant::now());
            if !did_work {
                match deadline {
                    Some(t) => thread::park_timeout(
                        t.saturating_duration_since(Instant::now())
                    ),
                    None => thread::park(),
                }
            }
            self.is_parked.store(false, Ordering::Relaxed);
        }
    }
}
```

`run_once` now calls `recv_from_queues` instead of `socket.recv`, and `drive_transmit` pushes
`TxPacket` values into `tx_queue` instead of calling `socket.send` directly.

## Engine Wakeup

The queues are `ArrayQueue` values in heap memory — they have no file descriptor, so `epoll` does
not apply. The naive answer is `thread::unpark()`, which on Linux calls `futex(FUTEX_WAKE)`. A
`futex` system call costs roughly 100–500 ns (hundreds of clock cycles, including KPTI
page-table switching). Calling it on every queue push would dominate the inter-tile cost.

The key observation: **a syscall is only needed when the engine is actually sleeping.** When the
engine is spinning it sees new items on the next iteration without any wakeup signal. The solution
is an `AtomicBool is_parked` flag per engine tile. Producers load the flag before deciding whether
to call `unpark`.

**Producer side — zero syscalls on the hot path:**

```rust,ignore
// Reader thread, after pushing an RxPacket:
rx_queues[j].push(packet);
if engine_is_parked[j].load(Ordering::Acquire) {
    engine_threads[j].unpark();   // futex only when engine is asleep
}

// Async task, after pushing an AppCommand:
cmd_queue.push(cmd);
if engine_is_parked.load(Ordering::Acquire) {
    engine_thread.unpark();
}
```

**Race closure.** There is a window between the engine finding all queues empty and setting
`is_parked = true`. A producer that pushes into that window may see the flag as false and skip
`unpark`, while the engine proceeds to `park`. The re-check after setting the flag closes this:

1. Producer pushes, reads `is_parked = false`, skips `unpark`. Engine's re-check sees the item
   and processes it; `park` is never reached.
2. Producer pushes, reads `is_parked = true`, calls `unpark`. The saved token causes the
   subsequent `park` to return immediately.

No item is ever stranded.

On the hot path — the common case when the engine is spinning — the producer's entire cost is one
CAS on the `ArrayQueue` head plus one L1-cached atomic load. `park_timeout` serves QUIC timer
deadlines (PTO, ACK delay, idle timeout) without any additional timer mechanism. For DPDK
deployments where a core is fully dedicated, `SPIN_ITERS = usize::MAX` and `park` is never
reached, matching the run-to-completion model.

## Shared State

Three threads per tile, N×M tiles — the question of what state is shared and how it is
synchronized determines whether the architecture's lock-free promises hold.

**Per-tile, never shared.** Each `rx_queue[i][j]` and `tx_queue[j]` is shared only between the
one reader and one engine, or the one engine and one writer. `ConnectionSlot` values live in the
engine's `Slab` and are never accessed from any other thread.

**Shared, read-mostly.** The `Arc<ServerConfig>` holding TLS configuration and ticket encryption
keys is cloned into every engine tile at startup. Ticket key rotation is an `Arc` swap on the
slow path; the data path never writes to it.

**Shared, lock-free alloc.** The `BufferPool` is an `Arc`-wrapped lock-free ring of free buffer
pointers. `alloc` and `free` are compare-and-swap operations on the ring's head and tail. Each
tile can maintain a small thread-local slab (e.g. 32 slots) refilled from the shared pool in
batches, so the hot path never touches the shared ring at all.

**No routing table.** `SO_REUSEPORT` and the CID prefix guarantee that packets from a given
connection always arrive at the same engine tile. The engine does not need a shared structure to
find the right `ConnectionSlot`; the CID's first byte is sufficient.

### Session Resumption

A resuming client arrives on a new 5-tuple and may land on any network tile. Resumption state
must therefore be either stateless or shared in a lock-free manner.

**TLS session tickets** are stateless by design. The server encrypts the full TLS session state
into the ticket using a shared symmetric key held in `Arc<ServerConfig>`. Any engine tile can
decrypt and validate a ticket presented on a new connection without touching any shared mutable
state.

**Address validation tokens (`NEW_TOKEN`)** are also stateless. The server HMAC-encrypts the
client address and a timestamp using a per-tile key derived from a shared secret. Any engine tile
can verify the token without shared mutable state.

**0-RTT anti-replay** is the only genuinely shared mutable state required for resumption. Three
options in ascending complexity:

1. Disable 0-RTT. Session resumption still gives fast reconnects via 1-RTT; only early data is
   lost. This is the recommended default.
2. Shared lock-free bloom filter over the replay window (typically a few seconds). Bit-sets are
   updated with atomic OR — no mutex. False positives are safe (they reject a legitimate 0-RTT,
   causing a 1-RTT fallback). The filter rotates on a timer via an `ArcSwap`.
3. Per-tile probabilistic filter, accepting cross-tile replay risk — a known limitation of many
   real-world TLS 1.3 deployments.

## Async Application Interface

The public API mirrors quinn's surface so callers find it familiar:

```rust,ignore
// Server
let endpoint = Endpoint::server(addr, server_config)?;
while let Some(conn) = endpoint.accept().await {
    tokio::spawn(async move {
        while let Ok((send, recv)) = conn.accept_bi().await {
            tokio::spawn(handle(send, recv));
        }
    });
}

// Client
let conn = Endpoint::connect(addr, "hostname", client_config).await?;
let (mut send, mut recv) = conn.open_bi().await?;
send.write_all(b"hello").await?;
send.finish().await?;
```

The tile topology is completely hidden. `Endpoint`, `Connection`, `SendStream`, and `RecvStream`
are the only types the application sees.

### Internal Bridge Types

Each connection has a private `ConnState` shared between the engine thread and all async handles
for that connection:

```rust,ignore
struct ConnState {
    conn_id:   ConnId,                       // slab index on the owning engine tile
    cmd_queue: Arc<ArrayQueue<AppCommand>>,  // application → engine
    evt_queue: Arc<ArrayQueue<ConnEvent>>,   // engine → application (per-connection)
    evt_waker: AtomicWaker,                  // woken when evt_queue has a new entry
}

enum ConnEvent {
    BiStreamOpened  { id: StreamId, cell: Arc<StreamCell> },
    UniStreamOpened { id: StreamId, cell: Arc<StreamCell> },
    ConnectionClosed { error: ConnectionError },
}

enum AppCommand {
    Write       { conn: ConnId, stream: StreamId, data: Bytes, fin: bool },
    OpenStream  { conn: ConnId, dir: Dir },
    Finish      { conn: ConnId, stream: StreamId },
    ResetStream { conn: ConnId, stream: StreamId, code: u64 },
    CloseConn   { conn: ConnId, code: u64, reason: Bytes },
}
```

Each stream has a `StreamCell` shared between the engine thread and the `SendStream`/`RecvStream`
handles:

```rust,ignore
struct StreamCell {
    // Receive side — engine pushes, RecvStream polls.
    recv_waker: AtomicWaker,
    // Bounded but never overflowed: the engine only calls recv_stream.read()
    // when this queue has room, so quinn-proto's receive buffer acts as the
    // overflow and its flow-control window closes before this queue fills.
    recv_data:  ArrayQueue<Bytes>,
    recv_fin:   AtomicBool,

    // Send side — engine wakes task when stream regains flow-control credit.
    send_waker: AtomicWaker,
}
```

`AtomicWaker` is a two-word structure from `futures-util` that stores a `Waker` with two atomic
stores — one to clear the old waker, one to write the new. There is no mutex anywhere in the
wakeup path.

### Accept Path

The `TileSet` owns a global `incoming: Arc<ArrayQueue<Connection>>` and `accept_waker:
AtomicWaker`. When an engine tile completes a TLS handshake it allocates a `ConnState`, wraps it
in a `Connection` handle, and pushes it into `incoming`, then calls `accept_waker.wake()`. The
`endpoint.accept()` future drains `incoming`; if empty it registers with `accept_waker` and
returns `Poll::Pending`.

When a peer opens a new bidi stream the engine allocates a `StreamCell`, wraps it in
`ConnEvent::BiStreamOpened`, pushes it into the connection's `evt_queue`, and calls
`evt_waker.wake()`. `conn.accept_bi()` polls `evt_queue`; if empty it registers with `evt_waker`
and returns `Poll::Pending`.

### Open Path

`conn.open_bi()` pushes `AppCommand::OpenStream { dir: Bi }` to `cmd_queue` then polls
`evt_queue` waiting for the matching `BiStreamOpened` event. The engine processes the command,
calls `connection.streams().open(Dir::Bi)`, creates a `StreamCell`, and pushes the event back.

### Read Path

`RecvStream::poll_read` drains `StreamCell::recv_data`. If empty it registers with `recv_waker`
and returns `Poll::Pending`.

The engine drains from quinn-proto's internal receive buffer into `recv_data` only when
`recv_data` has room:

```rust,ignore
// Inside engine's drain_readable loop, per stream:
if stream_cell.recv_data.len() < RECV_DATA_CAP {
    while let Some(chunk) = slot.inner.recv_stream(id).read(usize::MAX)? {
        let wake = stream_cell.recv_data.push(Bytes::from(chunk.bytes)).is_ok();
        if wake { stream_cell.recv_waker.wake(); }
        if stream_cell.recv_data.len() >= RECV_DATA_CAP { break; }
    }
}
// If recv_data is full the engine skips read() for this stream this iteration.
// quinn-proto's receive buffer fills up and the QUIC flow-control window closes.
```

Once data has been accepted by the QUIC state machine it is never discarded. The bounded
`recv_data` queue is an admission gate on draining from quinn-proto, not a discard point.

### Write Path and Flow Control

`SendStream::poll_write` pushes `AppCommand::Write` to `cmd_queue`. If the queue is full it
registers with a per-tile `cmd_waker` and returns `Poll::Pending`. The engine processes write
commands by calling `send_stream.write(data)`; if quinn-proto's send buffer is full (flow control
window exhausted), the engine stores the unaccepted bytes and wakes `send_waker` when the stream
later emits a `StreamEvent::Writable` event. `poll_write` registers `send_waker` and returns
`Poll::Pending` when it detects that the previous write was not fully consumed.

## Full Packet Path

### Receive — NIC to Application

The receive path has two distinct buffering stages with different drop policies.

**Stage 1 (network → engine): packets may be dropped.** `rx_queue[i][j]` is bounded. If the
engine tile is processing a burst and the queue is full, the reader drops the packet. The QUIC
loss recovery mechanism at the sender retransmits it. Dropping here is safe because the QUIC
state machine has not yet seen the packet.

**Stage 2 (engine → application): no data is ever dropped.** Once `endpoint.handle()` processes
a packet, the data is in quinn-proto's internal receive buffer and an ACK will be sent. The engine
must eventually deliver every byte to the application. The bounded `recv_data` queue is not a
discard point — it is an admission gate that controls when the engine drains from quinn-proto (see
"Read Path" above). If `recv_data` is full the engine leaves the data in quinn-proto's receive
buffer; quinn-proto withholds window credits; the sender's flow-control window closes.

```
NIC RX — RSS hashes 5-tuple → hardware queue → SO_REUSEPORT selects tile's socket
  │
  ▼
Reader Thread
  │  socket.recv() fills RecvBuf (pool buffer, no allocation)
  │  reads CID prefix → selects engine tile index j
  │  pushes RxPacket { meta, buf } onto rx_queues[j]  (SPSC, bounded)
  │  *** if rx_queues[j] full: packet DROPPED; QUIC loss recovery retransmits ***
  ▼
rx_queue[i][j]  ← only drop boundary on the receive path
  │
  ▼
Engine Thread
  │  drains rx_queues[0..M][j] in recv_from_queues
  │  endpoint.handle(meta, buf) — zero-copy through parse + decrypt
  │  data lands in quinn-proto's internal receive buffer
  │  response packets: pushes TxPacket onto tx_queue[j]  (SPSC, bounded)
  │
  │  drain_readable (per readable stream, each iteration):
  │    if recv_data has room → recv_stream.read() → push Bytes into recv_data
  │                             call recv_waker.wake()
  │    if recv_data is full  → skip; quinn-proto holds data, window closes
  │  *** data in quinn-proto's buffer is NEVER discarded ***
  ▼
StreamCell::recv_data  (bounded ArrayQueue — admission gate, not a drop point)
  │
  ▼
Async task  ← RecvStream::poll_read drains recv_data; registers recv_waker if empty
  │
  ▼
Application

tx_queue[j]  (SPSC ArrayQueue)
  │
  ▼
Writer Thread
  │  drains tx_queue[j], calls socket.send(batch)
  │  calls socket.drain_completions() to recycle zerocopy TX bufs
  ▼
NIC TX
```

### Transmit — Application to NIC

```
Async task
  │  SendStream::poll_write
  │  pushes AppCommand::Write { conn, stream, data } to cmd_queue  (MPSC)
  │  if cmd_queue full → register cmd_waker, return Pending
  ▼
cmd_queue  (MPSC ArrayQueue — many tasks push, one engine pops)
  │
  ▼
Engine Thread
  │  process_app_commands drains cmd_queue
  │  slot.inner.send_stream(id).write(data)
  │  marks slot.has_pending_send = true
  │  wakes any pending send-side AtomicWakers
  │
  │  drive_transmit:
  │  slot.inner.poll_transmit() → serialises QUIC packet into pool BufMut
  │  pushes TxPacket onto tx_queue[j]
  ▼
tx_queue[j] → Writer Thread → socket.send() → NIC TX
```

No mutex anywhere on either path. The `ArrayQueue` operations are compare-and-swap on a head/tail
pair. The `AtomicWaker` stores the `Waker` with two atomic stores.

## Backpressure

There is a fundamental asymmetry in the receive path: data may be dropped between the network
tile and the engine tile, but never between the engine tile and the application.

**Between network tile and engine tile (rx_queue).** This is the only legitimate drop point on
the receive path. A full `rx_queue[i][j]` causes the reader to discard the packet. The QUIC
state machine has not seen it; the peer's loss detection will retransmit. QUIC's congestion
controller also observes the loss and reduces the sending rate, propagating backpressure to the
remote sender without any additional signalling.

**Between engine tile and application (quinn-proto buffer → recv_data).** No data is ever
discarded here. The engine uses the bounded `recv_data` queue as an admission gate: it calls
`recv_stream.read()` only when there is room in `recv_data`. When `recv_data` is full the data
remains in quinn-proto's internal receive buffer. quinn-proto tracks how many bytes the
application has consumed and withholds `MAX_STREAM_DATA` credits accordingly; the sender's
flow-control window closes and it stops transmitting for that stream. The backpressure signal
travels over the wire as a deliberate absence of window updates, not as packet loss.

```
Application slow to read
  ──▶ recv_data full
  ──▶ engine skips recv_stream.read() for this stream
  ──▶ quinn-proto receive buffer fills, window credits withheld
  ──▶ peer's send window closes, peer pauses transmission
  ──▶ fewer packets arrive, rx_queue drains naturally
```

**Transmit path.** On the transmit side the invariant runs in the opposite direction: the
application has not committed data to the QUIC state machine until `send_stream.write()` succeeds
inside the engine. Backpressure can therefore be applied at any point before that call.

When `tx_queue[j]` fills the engine stops calling `poll_transmit`. quinn-proto's send buffers
fill. The engine stops accepting `AppCommand::Write`; when `cmd_queue` fills,
`SendStream::poll_write` returns `Poll::Pending`, suspending the Tokio task. The application
stops generating data.

```
Writer slow (NIC back-pressure)
  ──▶ tx_queue[j] full
  ──▶ engine stops poll_transmit; quinn-proto send buffer fills
  ──▶ engine stops draining cmd_queue; cmd_queue fills
  ──▶ SendStream::poll_write returns Pending
  ──▶ application task suspended
```

## TileSet Configuration

A `TileSet` constructs the M×N queue matrix and wires each tile to its slice of queues:

```rust,ignore
pub struct TileSet {
    network_tiles: Vec<Arc<dyn NetworkTile>>,
    engine_tiles:  Vec<Arc<EngineTile>>,
    // Shared across all tiles.
    pool:          Arc<dyn BufferPool>,
    incoming:      Arc<ArrayQueue<Connection>>,
    accept_waker:  Arc<AtomicWaker>,
}

impl TileSet {
    pub fn new(num_network: usize, num_engine: usize, config: TileSetConfig) -> Self {
        // Allocate M×N RX queues, one per (network tile, engine tile) pair.
        let rx: Vec<Vec<Arc<ArrayQueue<_>>>> =
            (0..num_network)
                .map(|_| (0..num_engine)
                    .map(|_| Arc::new(ArrayQueue::new(QUEUE_CAP)))
                    .collect())
                .collect();
        // Allocate N TX queues, one per engine tile.
        let tx: Vec<Arc<ArrayQueue<_>>> =
            (0..num_engine)
                .map(|_| Arc::new(ArrayQueue::new(QUEUE_CAP)))
                .collect();
        // Wire up tiles and start their threads.
        // ...
    }

    /// Returns an endpoint handle for the application layer.
    pub fn endpoint(&self) -> Endpoint { /* ... */ }
}
```

Typical choices for `(num_network, num_engine)`:

| Deployment | Suggested configuration |
|------------|------------------------|
| Low-traffic service sharing cores | (1, 1) |
| One NIC queue per available core | (N, N) |
| Separate NIC and protocol cores | (2, 8) |
| NUMA: one tile per node | (nodes, cores/node) |
