# Network Tile

A **network tile** is the I/O thread that sits between a packet socket and one or more *engine tiles* (the application threads that consume RX packets and produce TX packets). It owns the socket, runs the recv/send/completion loop, and shuttles datagrams to and from the engines through bounded lock-free queues. This document describes how to configure one.

The relevant code lives in [`quac-network-tile`](../quac-network-tile/src/lib.rs); the [tile-bench](../quac-network-tile/examples/tile-bench-receiver.rs) examples are reference setups for all three backends.

## Mental model

```text
          ┌────────────────────────────────────────────────┐
          │                  Network Tile                  │
          │   ┌──────────────┐  recv → router → rx_queues  │
  NIC ──► │   │ Socket(s)    │ ────────────────────────► engine[0..N]
          │   │  (1 per RX   │                             │
  NIC ◄── │   │   queue on   │ ◄── send ─── tx_queues      │
          │   │   this CPU)  │                             │
          │   └──────────────┘                             │
          └────────────────────────────────────────────────┘
```

The default shape is **one tile == one socket == one hardware RX/TX queue**. Multi-tile listeners scale out by spawning N tiles, each binding its own socket with `SO_REUSEPORT` (OS / io_uring) or a per-tile `(if_index, queue_id)` (XDP). Each tile has its own RX/TX buffer pools, so there is zero hot-path synchronization between tiles.

A tile can also own **multiple sockets** when bond devices route multiple slave queues to the same CPU — see [build_coalesced_tiles](#bond-aware-coalesced-tiles) below. In that case the loop iterates over all of the tile's sockets per turn.

The tile thread runs a single loop:

1. **Drain TX** queues from all engines, bucket each `Transmit` into per-source-socket lists via [`TxPool::owns`](../quac-socket/src/buffer.rs), batch-`send()` per bucket, then `drain_completions()` on every socket.
2. **Refill the TX-buf scratch queue** from every socket's pool if it's below the watermark (so engines have buffers to write into; non-UNIFIED multi-socket tiles draw on all TX pools).
3. **Refill the RX slots** to a full batch and `recv()` from each socket in turn, tagging each `RxPacket.source_socket` with the originating socket's index.
4. Route each packet to one engine via `PacketRouter`, push onto that engine's RX queue.
5. If neither side did work this iteration, `wait_any_non_empty(tx_queues)` — the wait strategy decides whether this is a `spin_loop()` or a `park_timeout(50µs)`.

## Constructing a tile

[`NetworkTileImpl::new`](../quac-network-tile/src/lib.rs) takes three arguments for the single-socket case:

```rust
NetworkTileImpl::<S, W, R>::new(factory, router, engine_count)
```

- `factory: FnOnce() -> S` — builds the socket. **Called on the IO thread inside `start()`**, not at construction. This is non-negotiable: pools are `!Send + !Sync` and must be created on the thread that will own them.
- `router: R` — implements [`PacketRouter`](../quac-network-tile/src/lib.rs), decides which engine gets each received datagram.
- `engine_count: usize` — number of engine tiles wired to this network tile. Determines the RX/TX queue array length.

For multi-socket tiles, [`NetworkTileImpl::with_sockets`](../quac-network-tile/src/lib.rs) takes a factory returning `Vec<S>`. The IO thread reads each socket's `incoming_cpu()` flag: all-true validates per-queue CPU agreement and pins the thread to the shared CPU; all-false runs unpinned (existing behaviour); mixed configurations panic — every socket in a tile must share the same alignment policy.

Three type parameters:

- `S: PacketSocket + Send + 'static` — the backend (`OsSocket`, `IoUringSocket`, `XdpSocket`).
- `W: WaitStrategy` — `Spin` or `Park`.
- `R: PacketRouter` — routing policy. `R: Clone` is required for [`build_coalesced_tiles`](#bond-aware-coalesced-tiles).

After construction wrap in `Arc`, then call `Arc::clone(&tile).start(tile_index)` to launch the IO thread.

### Bond-aware coalesced tiles

For bond devices (`bond0` aggregating `eth0` + `eth1`) the right shape is one tile per **distinct IRQ CPU**, owning one socket per RX queue mapped to that CPU. [`build_coalesced_tiles`](../quac-network-tile/src/lib.rs) does the enumeration, grouping, and per-tile construction in one call:

```rust
let tiles = quac_network_tile::build_coalesced_tiles::<OsSocket, Spin, _, _>(
    "bond0",
    |q: &RxQueue| OsSocket::bind(
        bind_addr,
        q.flat_index,
        OsConfig::builder().reuseport(true).incoming_cpu(true).build(),
    ),
    FourTupleRouter,
    /*engine_count=*/ 1,
)?;
for (i, tile) in tiles.into_iter().enumerate() {
    Arc::clone(&tile).start(i);
    // wire engine threads to tile.rx_queues() / tile.tx_queues() ...
}
```

Internally it calls [`enumerate_rx_queues`](../quac-socket/src/nic.rs) (recurses through bond slaves), then [`coalesce_by_cpu`](../quac-socket/src/nic.rs), and produces `tiles.len()` equal to the number of distinct slave-IRQ CPUs. See [SOCKETS.md "Multi-queue setup and CPU alignment"](SOCKETS.md) for the operator-side IRQ pinning prerequisite.

## Backends

The factory closure is what selects the backend. The tile itself is generic; nothing outside the factory has to be backend-specific.

### OS sockets ([`quac-socket-os`](../quac-socket-os/))

Standard UDP: `recvmmsg`/`sendmmsg`, `SO_ZEROCOPY` for TX. Multi-tile via `SO_REUSEPORT`:

```rust
NetworkTileImpl::<_, Spin, _>::new(
    move || OsSocket::bind(bind_addr, queue_id, OsConfig::builder().reuseport(true).build()).unwrap(),
    FourTupleRouter,
    engine_count,
)
```

`UNIFIED = true`: heap-backed Rx and Tx pools share a fungible allocation, so [`convert_rx_to_tx`](../quac-network-tile/src/lib.rs) is an identity move and `TxPool::owns` returns `true` for any sibling's buf. Use OS sockets when you don't have or don't want `CAP_BPF` / a dedicated NIC, or as a baseline.

### io_uring ([`quac-socket-iouring`](../quac-socket-iouring/))

Multishot recvmsg with provided-buffer rings (Linux 6.0+). Same `SO_REUSEPORT` story:

```rust
NetworkTileImpl::<_, Spin, _>::new(
    move || IoUringSocket::bind(bind_addr, queue_id, IoUringConfig::builder().reuseport(true).build()).unwrap(),
    FourTupleRouter,
    engine_count,
)
```

`UNIFIED = false`. The tile is **always busy-polled** (assumed by design); if you pick this backend you are paying for one core per tile and want the lowest possible kernel overhead. Don't combine with `Park`.

Tunables on [`IoUringConfig`](../quac-socket-iouring/src/socket.rs): `ring_entries`, `buf_ring_count`, `send_pool_size`, `reuseport`.

### AF_XDP ([`quac-socket-xdp`](../quac-socket-xdp/), Linux only)

True zero-copy. Multi-tile by per-tile `(if_index, queue_id)` -- no `SO_REUSEPORT`:

```rust
let xdp_cfg = XdpConfig::builder()
    .frame_count(4096)
    .frame_size(2048)
    .mode(XdpMode::ZeroCopy)        // or Copy for veth / generic skb
    .attach_mode(AttachMode::Drv)   // or Skb / Default / Hw
    .build();

NetworkTileImpl::<_, Spin, _>::new(
    move || XdpSocket::with_interface(if_index, queue_id, bind_ip, bind_port, xdp_cfg).unwrap(),
    FourTupleRouter,
    engine_count,
)
```

`UNIFIED = false` today: an Rx UMEM frame is converted into a Tx frame by `from_rx` copy. A true single-UMEM identity path is possible but not yet wired up. `TxPool::owns` is overridden to compare UMEM bases — multi-socket coalesced tiles correctly egress each Tx buf via the socket whose UMEM holds the frame (cross-UMEM sends would be UB). Requires `CAP_BPF` (`CAP_PERFMON` on older kernels) and a NIC driver with AF_XDP support for ZC mode. For veth / non-ZC drivers, use `XdpMode::Copy` + `AttachMode::Skb`.

XDP load-balances across queues via NIC RSS or via a custom XDP program; with the default eBPF program in [`quac-socket-xdp-ebpf`](../quac-socket-xdp-ebpf/), each `(port, queue_id)` binding registers itself in the `XSKMAP` and the kernel steers packets accordingly.

### Picking a backend

| | OS | io_uring | XDP |
|---|---|---|---|
| Permissions | none | none | `CAP_BPF` |
| Multi-tile | `SO_REUSEPORT` | `SO_REUSEPORT` | `(if_index, queue_id)` |
| `UNIFIED` (Rx↔Tx identity) | yes | no (copy) | no (copy; identity path TODO) |
| Bond-aware coalescing | yes (`build_coalesced_tiles`) | yes | yes (factory looks up slave's `if_index`) |
| Linux-only | no | yes (6.0+) | yes |
| When to use | baseline / portable | low-overhead syscall path on standard kernels | maximum throughput, dedicated NIC |

## Wait strategies

The fourth concern is what the IO thread does when there's nothing to do: no TX queued, no RX waiting. [`WaitStrategy`](../quac-network-tile/src/queue.rs#L18) is a compile-time choice (zero-sized marker types, all methods inlined) so picking `Spin` over `Park` doesn't add even an atomic load to the hot path.

### `Spin` ([`Spin`](../quac-network-tile/src/queue.rs#L45))

`do_wait()` is `std::hint::spin_loop()`. The tile thread never sleeps; idle CPU is 100%. Lowest possible TX-engine-to-wire latency because the producer side has no `unpark` to do and the consumer is always responsive.

Use `Spin` when:

- You're running a dedicated server and have CPU cores to spare.
- You're optimizing for tail latency under load.
- You're using io_uring (the design assumes busy polling).

This is what every example uses (`NetworkTileImpl::<_, Spin, _>::new(...)`).

### `Park` ([`Park`](../quac-network-tile/src/queue.rs#L63))

`do_wait()` is `thread::park_timeout(50µs)`. When the IO thread runs out of work it parks; when an engine pushes a transmit, the producer's `on_push` checks a `sleeping` flag and calls `unpark()` only if the consumer is asleep. The 50µs timeout is a safety net so the IO thread re-polls the socket even if no engine pushes.

Use `Park` when:

- The tile is mostly idle and you care about idle CPU (laptops, shared hosts, dev/test).
- You're running over OS sockets and the extra ~µs of wakeup latency is acceptable.

The double-check pattern in [`Queue::wait_if_empty`](../quac-network-tile/src/queue.rs#L174) prevents the lost-wakeup race: the consumer sets `sleeping=true` (SeqCst) before re-checking the queue, and producers store with SeqCst before checking the flag. If a producer pushes between the consumer's last `pop` and the `sleeping=true` store, the consumer sees the queue non-empty and skips the park.

### Picking a strategy

Default: `Spin`. Switch to `Park` only when 100% CPU per tile is unacceptable and you've measured that wakeup latency is tolerable. The two strategies are interchangeable at the type level -- changing the marker doesn't change any other code.

Note: `wait_any_non_empty` is called only on the **TX** queues (the engine→IO direction). Idle on the RX side is handled by the socket's own readiness mechanism (`rx_fd()` + `recv()` returning `WouldBlock`); for AF_XDP and io_uring this is busy-polled regardless of the wait strategy.

## Routing

[`PacketRouter::route`](../quac-network-tile/src/lib.rs#L15) is called once per received datagram. It gets `(meta, payload, engine_count)` and returns the engine index. Both the metadata (4-tuple, ECN, dst-IP) and the first segment of the payload are available -- pick whichever is cheap and gives you the affinity you want.

Built-in: [`FourTupleRouter`](../quac-network-tile/src/lib.rs#L24) hashes the source `SocketAddr`. Fine for a server taking traffic from many independent clients. For QUIC, where you typically want connection-id affinity (the engine that decrypted the handshake should see all subsequent packets), implement a custom router that decodes the CID from the QUIC short-header and indexes by `cid % engine_count`.

The router runs on the IO thread; keep it cheap (no allocation, no hashing larger than necessary).

## Buffer flow

The tile keeps a single pre-filled scratch queue of TX buffers (`tx_buf_queue`, capacity 1024). Engines call `tile.alloc_tx_bufs(...)` to pop from it; the IO thread refills it when it falls below 256 entries, drawing from **every socket's pool** (split evenly per call) so a coalesced multi-socket tile uses all of its TX pools, not just `sockets[0]`'s. The 50% pool-share rule in `refill_tx_bufs` keeps RX from starving.

This indirection exists because pool `alloc()` is owner-thread-only; engines (which run on different threads) cannot call it directly. The scratch queue is the cross-thread bridge.

For zero-copy forwarders, [`convert_rx_to_tx`](../quac-network-tile/src/lib.rs) lets the engine promote an Rx buffer straight into a Tx-shaped handle. On UNIFIED backends (OS) this is an identity move; on non-unified backends (io_uring, XDP) it pops a scratch Tx buf, copies, and drops the Rx buf. Either way the Rx buf returns to its originating socket's pool on drop (per-buf reclaimer for AF_XDP, shared heap otherwise) — `RxPacket.source_socket` is informational and engines that want to tag replies by originating slave can read it.

### Source-aware send dispatch

The IO thread doesn't blindly send every drained `Transmit` via `sockets[0]`. It buckets each `Transmit` by walking sockets and finding the one whose `tx_pool().owns(&buf)` returns true, then sends each bucket separately. For OS / io_uring (heap-backed pools, default `owns = true`) this resolves to `sockets[0]` uniformly with no overhead. For AF_XDP, [`XdpTxPool::owns`](../quac-socket-xdp/src/buffers.rs) compares UMEM bases — every Tx buf egresses via the socket whose UMEM holds it, so coalesced reflect/pingpong over a bond routes replies correctly even when the engine produced them from `alloc_tx_bufs`.

## End-to-end shape

```rust
use std::sync::Arc;
use quac_network_tile::{FourTupleRouter, NetworkTile, NetworkTileImpl, Spin};
use quac_socket_os::{OsConfig, OsSocket};

let tile = Arc::new(NetworkTileImpl::<_, Spin, _>::new(
    move || OsSocket::bind(bind, 0, OsConfig::builder().reuseport(true).build()).unwrap(),
    FourTupleRouter,
    /* engine_count = */ 1,
));

// Spawn the IO thread.
Arc::clone(&tile).start(/* tile_index = */ 0);

// On the engine thread:
let rx = Arc::clone(&tile.rx_queues()[0]);
let tx = Arc::clone(&tile.tx_queues()[0]);
rx.register_consumer();   // park-mode no-op for Spin
loop {
    while let Some(pkt) = rx.pop() { /* handle */ }
    // To reply: alloc_tx_bufs → fill → freeze → push onto tx
}
```

For a full multi-backend, multi-thread setup with shutdown handling, see [tile-bench-receiver.rs](../quac-network-tile/examples/tile-bench-receiver.rs).

## Summary

- One tile per IRQ CPU. Default shape is one socket per tile; coalesced bonded tiles own one socket per RX queue mapped to that CPU.
- `factory` closure runs on the IO thread; never construct sockets/pools elsewhere.
- Three orthogonal choices: backend (`S`), wait strategy (`W`), router (`R`). All compile-time, all monomorphized.
- `Spin` is the default; pick `Park` only when idle CPU matters more than wakeup latency.
- Use OS sockets for `UNIFIED` (truly zero-copy `convert_rx_to_tx`); XDP for kernel bypass with maximum throughput.
- For bonded interfaces use [`build_coalesced_tiles`](#bond-aware-coalesced-tiles); the IO thread validates `incoming_cpu()` agreement and pins itself.
