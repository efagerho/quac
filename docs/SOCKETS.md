# Packet Socket API Design

This document describes the design of the [`PacketSocket`](../quac-socket/src/socket.rs) trait and the buffer-pool traits ([`PacketBuf`](../quac-socket/src/buffer.rs), [`PacketBufMut`](../quac-socket/src/buffer.rs), [`RxPool`](../quac-socket/src/buffer.rs), [`TxPool`](../quac-socket/src/buffer.rs)) that sit beneath it. The traits live in the [`quac-socket`](../quac-socket/) crate and are implemented by three backends today: [`quac-socket-os`](../quac-socket-os/) (UDP via `recvmmsg`/`sendmmsg` with `SO_ZEROCOPY`), [`quac-socket-iouring`](../quac-socket-iouring/) (multishot recvmsg + provided-buffer rings on Linux 6.0+), and [`quac-socket-xdp`](../quac-socket-xdp/) (zero-copy AF_XDP).

## Goals

The API exists to support two related workloads on the same abstraction:

1. **Packet routers / forwarders.** Receive a datagram, decide where it goes, send it out. Ideally without copying the payload between the RX and TX paths.
2. **Packet generators / QUIC servers.** Construct datagrams from application state and send them, possibly receiving cryptographic responses back.

Both workloads share the same hard constraints: no allocation on the hot path, no cross-core synchronization on the hot path, and no payload copies beyond what the underlying transport actually requires. The trait shape is what drops out when these constraints are taken seriously across an OS-sockets backend, an io_uring backend, and a true zero-copy backend (AF_XDP) without any backend leaking into the others.

Other goals that fell out of those constraints:

- **One socket = one hardware queue.** A socket is a [`!Send`](../quac-socket/src/socket.rs) handle bound to one RX/TX queue, owned by one tile thread. `&mut self` on `send`/`recv` is the only synchronization. Multi-queue scaling is done by running N tiles, each with its own socket and pools, bound through `SO_REUSEPORT` (OS / io_uring) or queue-id steering (XDP).
- **Backend-agnostic call sites.** A router or QUIC server written against the trait compiles unchanged on top of a kernel socket, an io_uring ring, or an AF_XDP UMEM. The differences (zero-copy completions, GSO/GRO limits, scatter-gather limits) surface as associated constants and an explicit `drain_completions` step rather than as separate code paths.
- **Compatibility with kernel-bypass.** Buffer ownership semantics are designed for AF_XDP and DPDK first; OS sockets are a special case where the buffers happen to be heap allocations rather than UMEM frames.

## Two-trait split: socket vs. pools

The trait surface is intentionally split:

- [`PacketSocket`](../quac-socket/src/socket.rs) handles I/O: `send`, `recv`, `drain_completions`, `local_addr`, `queue_id`, `rx_fd`.
- [`RxPool`](../quac-socket/src/buffer.rs) and [`TxPool`](../quac-socket/src/buffer.rs) handle buffer lifecycle: `alloc` returns pool-owned buffers, drop returns them.

The split matters because in zero-copy backends the *pool* is the truly scarce resource (UMEM frames are pinned at socket creation; you cannot grow them at runtime), while the *socket* is just a kernel handle. Separating them lets callers reason about backpressure (`tx_pool().available()`, `rx_pool().alloc(...)` returning short) without entangling it with I/O readiness (`rx_fd`).

It also makes the buffer flow explicit at every step. A QUIC server's send loop reads:

```text
let mut tx_bufs = Vec::with_capacity(N);
sock.tx_pool().alloc(payload_size, N, &mut tx_bufs);  // get N writable frames
for buf in &mut tx_bufs { /* write payload via uninit_mut + set_filled */ }
let frozen: ScatterGather<TxBuf> = /* freeze each buf into a Segment */;
let mut transmits = vec![Transmit::new(sg, dst); N];
sock.send(&mut transmits)?;
sock.drain_completions();  // recycle frames the kernel finished with
```

There is no `socket.send(&[u8])` shortcut — that would force the implementation to either allocate or copy on every call. The caller always goes through the pool.

## Buffer state machine

A buffer moves through three states:

```text
   alloc()              freeze()            drop
─────────► PacketBufMut ─────────► PacketBuf ─────► (back to pool)
           (writable,             (immutable,
            len + uninit)          ref-only)
```

[`PacketBufMut`](../quac-socket/src/buffer.rs) splits its capacity into a filled prefix (`filled()`/`filled_mut()`) and an uninitialized suffix (`uninit_mut()` returns `&mut [MaybeUninit<u8>]`). Writers fill into the uninit region and call `set_filled(new_len)` to grow the prefix. This avoids the cost of zeroing buffers up-front and matches what `bytes::BytesMut`-style APIs do, but with the buffer ownership pinned to a pool rather than the global allocator.

[`PacketBuf`](../quac-socket/src/buffer.rs) is the immutable, post-`freeze` form. It implements `AsRef<[u8]> + Send + 'static`. The `Send` bound is deliberate: a frozen buffer can be moved across threads (e.g. handed off to a worker for crypto), but only the frozen form — `PacketBufMut` is `Send` so it can be allocated on the network tile and passed to an application thread for filling, but the pool itself is `!Send + !Sync` so allocation always happens on the owning thread.

Drop returns the buffer to the pool. For multi-threaded fill workflows this needs cross-thread reclamation; the AF_XDP and io_uring backends each carry an MPSC reclaim queue with a same-thread fast path so drops on the owner thread don't pay the synchronized-queue cost.

## Scatter-gather without forced contiguity

[`Segment<B>`](../quac-socket/src/buffer.rs) is a `(buffer, offset, len)` triple, and [`ScatterGather<B>`](../quac-socket/src/buffer.rs) is an ordered list of segments forming one logical packet (4 inline, spilling to heap above that). Every send goes through `ScatterGather`, even single-segment ones (`ScatterGather::single(seg)`).

Why uniform scatter-gather:

- A QUIC packet has a header (often built in a small scratch buffer) and a payload (often a slice of a larger frame already in pool memory). Without scatter-gather these would have to be coalesced into one buffer; with it, the kernel/NIC does the gather via `iovec`.
- Forwarders can construct an outgoing `Segment` that points directly into the *received* buffer, with no copy at all. The `TxPool::UNIFIED` const tells the caller whether this is even legal: when true (zero-copy backends like AF_XDP where RX and TX share the same UMEM), a received `BufMut` can become a TX `BufMut` via `from_rx` as a no-op identity conversion. When false (OS / io_uring), `from_rx` allocates and copies — but the caller knows up-front and can choose to amortize the copy elsewhere.

Backends advertise their per-transmit segment cap as `PacketSocket::MAX_SEGMENTS`; the caller enforces it at construction time via `ScatterGather::try_push(seg, S::MAX_SEGMENTS)`. The socket itself panics on over-cap transmits — that is treated as a programming bug, not a runtime error.

## Send, completion, and the zero-copy distinction

`PacketSocket::send` returns the number of transmits accepted. The caller drops the first `n` and retries the rest later — partial acceptance is normal, not an error. Hard I/O failures use `Err`.

What makes the API work across both copying and zero-copy backends is that **send returning `Ok(n)` does not mean the kernel is done with the buffer.** For OS sockets it does (the kernel copied in). For `SO_ZEROCOPY`, io_uring, and AF_XDP, the kernel still holds the buffer until the NIC's DMA completes. The buffer cannot be returned to the pool until then.

The trait surfaces this with [`drain_completions`](../quac-socket/src/socket.rs):

- Copy-based backends return `DrainResult::default()` and treat the call as a no-op.
- Zero-copy backends drain their completion queue (`MSG_ZEROCOPY` errqueue, io_uring CQEs, AF_XDP COMPLETION ring), reclaim the buffers, and return counts (`completed`, `emsgsize`, `errors`). `EMSGSIZE` is split out because QUIC stacks need it to drive PMTUD.

The contract is: callers must invoke `drain_completions` regularly. The pool will simply return short from `alloc` if the caller falls behind; there is no panic, no silent loss, just visible backpressure. A QUIC server's run-loop typically calls `drain_completions` once per iteration after `send` and once after `recv` to keep the pool fresh.

## Receive batching

`recv` is symmetric to `send`: caller pre-allocates `N` buffers from `rx_pool()` and passes a `&mut [RecvMeta]` of equal length. The backend fills `meta[..n]` and `bufs[..n]`, leaving the rest untouched. `RecvMeta` (source addr, optional dst IP, optional ECN, length) is `#[non_exhaustive]` so backends can grow it without breaking downstream crates.

Batch size is bounded by `PacketSocket::MAX_BATCH` (default 64). Backends never return more than this; they may return fewer. There is no "receive one" specialization — single-packet receives go through the same path with an `N=1` slice. This keeps the call site free of branching between batched and non-batched paths.

For drivers that want event-driven dispatch rather than busy-polling, `rx_fd()` returns the underlying readable FD (or `None` for polling-only backends like DPDK).

## What this enables for routers vs. generators

A **forwarder** sees: `recv` into pool buffers → inspect headers → for each packet either `from_rx` (cheap on UNIFIED backends, copying on OS/io_uring) into a TX buffer, or build a `Segment` pointing into the RX buffer directly (UNIFIED only) → `send`. On AF_XDP this is a true zero-copy forward: the same UMEM frame the NIC DMA'd into goes back out via TX without ever being copied or touched by the kernel network stack.

A **packet generator / QUIC server** sees: `tx_pool().alloc(...)` → write into `uninit_mut` → `set_filled` + `freeze` → `Segment::new_unchecked` + `ScatterGather::single` → `send`. The hot path allocates nothing (the `Vec<Transmit>`/`Vec<TxBufMut>` are owned by the tile and reused), copies the payload exactly once into pool memory, and hands a pointer to the kernel.

Both workloads use the same trait, the same buffer flow, and the same backpressure signal (short `alloc`, `Ok(n < requested)` from `send`). The differences between OS sockets and AF_XDP show up as backend-advertised constants (`MAX_GSO`, `MAX_GRO`, `MAX_SEGMENTS`, `UNIFIED`) and as the meaningfulness of `drain_completions`, but never as branches in caller code.

## Summary of invariants

- One socket per hardware queue; sockets are `!Send`, owned by one tile.
- Pools are `!Send + !Sync`; allocation is single-threaded by construction. Frozen buffers are `Send` and may be handed to worker threads.
- No hot-path allocation: caller-provided `Vec`s are reused; pools never grow at runtime.
- No silent data loss: pool exhaustion shows up as short `alloc`, send backpressure as `Ok(n < len)`, completion stalls as `drain_completions` returning small counts.
- Zero-copy is opt-in but uniform: `TxPool::UNIFIED` and `from_rx` give the caller a single decision point for "is this a real zero-copy backend?" without changing the call shape.
- Per-transmit limits (`MAX_SEGMENTS`, `MAX_GSO`) are advertised as `const` so the caller can enforce them at compile-influenced sites and the backend can `panic!` on violations as programming bugs.
