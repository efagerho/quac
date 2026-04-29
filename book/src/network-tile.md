# Network Tile

A network tile is an I/O component that wraps one `PacketSocket` instance,
manages its I/O threads, pre-fills a pool of TX buffers, and exposes the
lock-free queues that connect it to the QUIC engine tiles.

## Structure

```
                     ┌─────────────────────────────────┐
                     │         NetworkTileImpl          │
                     │                                  │
          socket ────┤  ┌──────────┐  ┌─────────────┐  │
                     │  │  net-rx  │  │   net-tx    │  │
                     │  │  thread  │  │   thread    │  │
                     │  └────┬─────┘  └──────▲──────┘  │
                     │       │               │          │
                     │  rx_queues[0..N]  tx_queues[0..N]│
                     └───────┼───────────────┼──────────┘
                             │               │
                         engine         engine tiles
                          tiles          produce TX
                         consume
```

There are N rx_queues and N tx_queues — one pair per engine tile. Each queue is
a bounded `Queue<T, W>` backed by a `crossbeam::ArrayQueue`. The engine tiles
own one rx_queue and one tx_queue each; the network tile owns the other end of
every queue.

## Thread modes

A network tile can run in two thread configurations:

**Combined mode** (`ThreadMode::Combined`) uses one thread, named `net-io-{i}`,
that alternates between draining received packets from the socket and flushing
TX buffers accumulated in the TX queues. This is the default for most
deployments because it keeps the socket's send and receive paths on the same
CPU cache, reduces context-switch overhead, and is simpler to reason about.

**Separate mode** (`ThreadMode::Separate`) uses two threads: `net-rx-{i}` for
receiving and `net-tx-{i}` for sending. This is useful when the TX path is
compute-intensive (e.g. with hardware offload) and cannot share a time slice
with the RX path without introducing latency spikes.

In both modes the thread index `i` comes from the caller so that multiple tiles
running side-by-side produce distinct thread names in profilers and `htop`.

## The NetworkTile trait

```rust,ignore
pub trait NetworkTile: Send + Sync + 'static {
    type Pool: BufferPool;
    type Wait: WaitStrategy;

    fn alloc_tx_bufs(
        &self,
        capacity: usize,
        count: usize,
        bufs: &mut Vec<<Self::Pool as BufferPool>::BufMut>,
    ) -> usize;

    fn rx_queues(
        &self,
    ) -> &[Arc<Queue<RxPacket<<Self::Pool as BufferPool>::BufMut>, Self::Wait>>];

    fn tx_queues(
        &self,
    ) -> &[Arc<Queue<Transmit<ScatterGather<<Self::Pool as BufferPool>::Buf>>, Self::Wait>>];

    fn start(self: Arc<Self>, tile_index: usize);
}
```

`alloc_tx_bufs` vends pre-sized mutable buffers from the tile's internal
`tx_buf_queue`. Engine tiles call this to obtain memory for outgoing packets
without touching the shared `BufferPool` on the hot path. The pre-filled queue
is replenished in batches by the I/O thread via `refill_tx_bufs`.

`rx_queues` and `tx_queues` return slices of `Arc<Queue<…>>`, one entry per
engine tile. The network tile writes to rx queues and reads from tx queues; the
engine tiles do the reverse.

## TX buffer pre-fill

The TX buffer queue (`tx_buf_queue`) decouples buffer allocation from the packet
send path. During each I/O iteration, after draining the socket, the I/O thread
checks whether the pre-fill queue has fallen below a watermark (256 buffers) and
tops it up in batches of 64 from the pool.

Engine tiles call `alloc_tx_bufs` to pop from this queue. If the queue is
momentarily empty they fall back to a zero-allocation path that returns fewer
buffers than requested; the QUIC layer retries on the next engine iteration.
Because the I/O thread is the sole allocator and multiple engine threads are the
sole consumers, no lock is needed on the hot path — the `ArrayQueue` provides
wait-free push and pop.

## Wait strategies

The `Queue` type carries a wait strategy as a type parameter:

```rust,ignore
pub trait WaitStrategy: Send + Sync + 'static {
    type State: Default + Send + Sync + 'static;
    fn on_push(s: &Self::State);
    fn register_consumer(s: &Self::State);
    fn set_sleeping(s: &Self::State);
    fn clear_sleeping(s: &Self::State);
    fn do_wait();
    fn do_wait_combined();
}

pub struct Spin; // busy-spin; zero idle CPU overhead, lowest latency
pub struct Park; // thread::park/unpark; near-zero idle CPU, tiny wakeup cost
```

`Spin` compiles all wait methods to `std::hint::spin_loop()`. It is appropriate
when the CPU core is dedicated to I/O and the workload is continuous.

`Park` records the consumer thread at startup via `OnceLock<Thread>` and uses an
`AtomicBool` to track whether it is sleeping. Producers call `unpark` only when
the flag is true, so the syscall cost is paid only when the thread is genuinely
idle. Combined-mode tiles use `park_timeout(50µs)` to allow the thread to check
for incoming TX work even when no new RX packets arrive.

The double-check pattern in `wait_if_empty` prevents missed wakeups:

```
1. set_sleeping()   — announce intent to sleep
2. is_empty()       — re-check the queue; catches items pushed between
                      the last pop and step 1
3. do_wait()        — park; any push after step 1 will unpark us
4. clear_sleeping() — mark as awake
```

## Packet routing

The network tile does not route packets itself. Instead, it delegates to a
`PacketRouter` — a caller-supplied type that inspects each received datagram and
returns the index of the engine tile that should process it.

```rust,ignore
pub trait PacketRouter: Send + Sync + 'static {
    fn route(&self, meta: &RecvMeta, payload: &[u8], engine_count: usize) -> usize;
}
```

Both the per-datagram metadata (source address, destination IP, ECN codepoint)
and the raw payload bytes are available to the router.

### FourTupleRouter

The built-in `FourTupleRouter` hashes the source `SocketAddr` from `RecvMeta`
using `DefaultHasher` and takes the result modulo `engine_count`:

```rust,ignore
pub struct FourTupleRouter;

impl PacketRouter for FourTupleRouter {
    fn route(&self, meta: &RecvMeta, _payload: &[u8], engine_count: usize) -> usize {
        let mut h = DefaultHasher::new();
        meta.src.hash(&mut h);
        h.finish() as usize % engine_count
    }
}
```

This gives connection-level affinity without any protocol knowledge: all
datagrams from the same client endpoint always land on the same engine tile.
It is the right default for any protocol whose connection identity maps to
a fixed UDP 4-tuple.

### QuicPacketRouter

For QUIC, `quac-tile` provides `QuicPacketRouter`. It distinguishes between
Initial packets (new connections, no server-assigned CID yet) and established
packets:

- **Initial packets** (long-header, packet type bits `0x00`) are distributed
  round-robin using an `AtomicUsize` counter. This spreads simultaneous
  handshakes evenly across engine tiles even when many connections arrive from
  the same source port.

- **All other packets** carry a server-assigned Connection ID whose first byte
  encodes the owning engine tile index. The router reads `dcid[0] % N` to
  find the correct tile, with no shared lookup table.

```rust,ignore
pub struct QuicPacketRouter {
    next_engine: AtomicUsize,
}

impl PacketRouter for QuicPacketRouter {
    fn route(&self, _meta: &RecvMeta, payload: &[u8], engine_count: usize) -> usize {
        if engine_count == 1 || payload.is_empty() { return 0; }
        let is_long    = payload[0] & 0x80 != 0;
        let is_initial = is_long && (payload[0] & 0x30) == 0x00;
        if is_initial {
            self.next_engine.fetch_add(1, Ordering::Relaxed) % engine_count
        } else if let Some(dcid) = extract_dcid(payload) {
            dcid[0] as usize % engine_count
        } else {
            0
        }
    }
}
```

The CID encoding — where byte zero stores the engine index — is produced by
`TileIndexCidGenerator` inside the engine tile (see the next chapter). The
router and generator agree on the encoding implicitly: `cid[0] % engine_count`
maps to the same engine tile that set `cid[0] = engine_index`. This means
routing is correct even after NAT rebinding or connection migration, because the
CID does not change when the client's source address changes.

## Constructors

```rust,ignore
// One thread handles both receive and transmit.
NetworkTileImpl::combined(socket, router, engine_count)

// Dedicated reader and writer threads.
// rx and tx must be clones of the same underlying socket.
NetworkTileImpl::separate(rx_socket, tx_socket, router, engine_count)
```

Both constructors allocate the queue vectors and the TX buffer pre-fill queue.
Threads are not started until `tile.start(tile_index)` is called.

## Uses

The network tile is the component you configure when choosing:

- **How many engine tiles** share one socket (`engine_count`)
- **Which routing policy** maps datagrams to engine tiles (the `PacketRouter`)
- **Whether TX and RX share a thread** (`Combined`) or run independently
  (`Separate`)
- **Which wait strategy** the queues use (`Spin` or `Park`)

Multiple network tiles can bind the same address with `SO_REUSEPORT`. The kernel
distributes packets across the sockets based on a hash of the UDP 4-tuple. Each
tile operates completely independently — there is no shared state or
coordination between tiles on the data path. See the Deployment chapter for
typical multi-tile configurations.
