# Deployment

This chapter covers how to wire together network tiles and engine tiles, the
configuration parameters that matter most, and the topology choices for common
deployment scenarios.

## Basic wiring

A server is built from three pieces:

1. One or more **network tiles** — each binds a UDP socket, starts its I/O
   thread(s), and exposes RX/TX queues.
2. An **Endpoint** — created from a network tile via `Endpoint::server`, which
   spawns the engine threads and returns the async handle.
3. An **accept loop** — a tokio task that calls `endpoint.accept()` and
   dispatches connections to application handlers.

```rust,ignore
let tile = Arc::new(NetworkTileImpl::combined(
    OsSocket::bind_reuseport("0.0.0.0:4433".parse()?)?,
    QuicPacketRouter::new(),
    engine_count,
));
tile.clone().start(0);

let endpoint = Endpoint::server(server_config, EndpointConfig::default(), &tile);

tokio::spawn(async move {
    while let Some(incoming) = endpoint.accept().await {
        tokio::spawn(async move {
            let conn = incoming.accept(server_config).await?;
            // handle conn
        });
    }
});
```

## Configuration axes

### Number of network tiles

Each network tile binds one `SO_REUSEPORT` socket. When there are multiple
tiles, the Linux kernel distributes incoming UDP packets across the sockets
using a hash of the 4-tuple. Each tile runs independently — there is no shared
state or coordination between tiles on the data path.

On real deployments with many client IP addresses, `SO_REUSEPORT` distributes
traffic roughly evenly. On loopback benchmarks with one client host, all packets
may hash to the same socket regardless of how many tiles are configured, because
the source IP entropy is low.

Multiple network tiles are most useful when:
- The server has multiple NIC queues and you want to dedicate one tile per queue.
- You want to saturate the kernel's UDP send path with separate send threads.

### Number of engine tiles

Each engine tile is one OS thread. Connections are pinned to engine tiles via
the CID encoding: once a connection's CID is set, all its packets route to the
same engine tile. Engine tiles share no mutable state — adding more engine tiles
adds more parallelism linearly.

The bottleneck in most deployments is either the network tile (kernel send/recv
throughput) or the application logic. Engine tile count should be set to match
available CPU cores after the network tile(s) have been allocated their threads.

### Thread mode

```rust,ignore
// One thread for both RX and TX. Default for most deployments.
NetworkTileImpl::combined(socket, router, engine_count)

// Separate threads for RX and TX. Useful when TX is slow.
NetworkTileImpl::separate(rx_socket, tx_socket, router, engine_count)
```

In `Separate` mode, the two socket halves must be clones of the same underlying
socket (via `try_clone` for `OsSocket`) or independently bound to the same
`SO_REUSEPORT` address (for `IoUringSocket`).

### Wait strategy

```rust,ignore
// Spin: zero idle CPU cost (always uses the core), lowest latency.
Arc::new(NetworkTileImpl::<OsSocket, Spin, _>::combined(…))

// Park: near-zero idle CPU, small wakeup cost (~200–500 ns on Linux).
Arc::new(NetworkTileImpl::<OsSocket, Park, _>::combined(…))
```

`Spin` is appropriate when the CPU core is fully dedicated to the tile and the
workload is continuous. `Park` is the default: it saves CPU when the tile is
idle and the wakeup cost is negligible compared to network latency.

### Socket backend

```rust,ignore
// OS socket — portable, uses recvmmsg/sendmmsg on Linux.
OsSocket::bind_reuseport(addr)?

// io_uring — Linux only, lower per-datagram syscall overhead.
IoUringSocket::bind_reuseport(addr)?
```

Both backends produce the same throughput on loopback benchmarks after warm-up.
The io_uring backend has a cold-start penalty of ~50–60 ms from ring
initialisation. Its advantage appears on real hardware at sustained high packet
rates where eliminating per-datagram kernel crossings reduces CPU usage.

## Common topologies

### Minimal: 1 network tile, 1 engine tile

```
--tiles 1 --engine-tiles 1
Threads: net-io-0, quac-engine-0, tokio-rt-worker × N
```

Suitable for a low-traffic service or for initial development. All QUIC
processing runs on one thread. There is no parallelism in the engine but there
is also no queue coordination overhead.

### Standard: 1 network tile, N engine tiles

```
--tiles 1 --engine-tiles 4
Threads: net-io-0, quac-engine-0..3, tokio-rt-worker × N
```

The most common production configuration. One I/O thread handles all send/recv
and N engine threads handle QUIC protocol processing. Connections are spread
across engine tiles by the CID. Adding engine tiles scales protocol throughput
linearly until the network tile becomes the bottleneck.

In benchmarks, adding engine tiles beyond the point where the network tile is
saturated shows no improvement. Profile with `pidstat -t` to check whether
engine threads or the net-io thread is CPU-bound.

### Parallel I/O: M network tiles, N engine tiles

```
--tiles 2 --engine-tiles 4
Threads: net-io-0, net-io-1, quac-engine-0..3, tokio-rt-worker × N
```

Two network tiles each drive a separate `SO_REUSEPORT` socket. Each tile has
its own set of RX/TX queues connected to the four engine tiles. New connections
are distributed round-robin by `QuicPacketRouter`; subsequent packets follow
their CID. This topology makes sense when two NIC queues are available or when
the send path is the bottleneck on the single-tile configuration.

On loopback, `SO_REUSEPORT` may not distribute traffic evenly when there is
only one client machine — all connections may hash to the same socket. On real
hardware with diverse client addresses the distribution is much better.

### High-connection: combined mode vs separate mode

For workloads with many short-lived connections where the accept rate is high,
`Combined` mode reduces cache pressure by keeping the RX and TX paths on the
same CPU. For workloads where large streams saturate the TX path, `Separate`
mode prevents TX from blocking RX.

## Packet router choice

`QuicPacketRouter` is the correct choice for any QUIC server. It:
- Routes Initial packets round-robin to spread handshakes.
- Routes all other packets by `dcid[0] % engine_count` for per-connection
  affinity with no shared state.
- Is stateful — it must not be shared between tiles; create one instance per
  tile.

`FourTupleRouter` (the built-in default) is appropriate for non-QUIC protocols
or for testing. It routes by source address hash, giving per-client-IP affinity
but no ability to route connections to their owning engine tile after a handshake.

## Example: quac_server benchmark

The `benchmarks/src/bin/quac_server.rs` binary demonstrates a complete server
with all configuration axes exposed as CLI flags:

```
quac_server --listen 0.0.0.0:4433 \
            --tiles 1 \
            --engine-tiles 4 \
            --mode combined \
            --socket os \
            --threads 4
```

```
listening on 0.0.0.0:4433 (1 net tiles × 4 engine tiles, Combined mode, Os socket)
```

`--threads` controls the number of tokio worker threads. Set it to match the
number of CPU cores not occupied by net and engine tiles. For a 12-core machine
with `--tiles 1 --engine-tiles 4` in combined mode (5 threads total for net+engine),
`--threads 7` leaves 7 cores for the tokio runtime.
