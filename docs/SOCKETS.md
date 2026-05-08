# Packet Socket API Design

This document describes the design of the [`PacketSocket`](../quac-socket/src/socket.rs) trait and the buffer-pool traits ([`PacketBuf`](../quac-socket/src/buffer.rs), [`PacketBufMut`](../quac-socket/src/buffer.rs), [`RxPool`](../quac-socket/src/buffer.rs), [`TxPool`](../quac-socket/src/buffer.rs)) that sit beneath it. The traits live in the [`quac-socket`](../quac-socket/) crate and are implemented by three backends today: [`quac-socket-os`](../quac-socket-os/) (UDP via `recvmmsg`/`sendmmsg` with `SO_ZEROCOPY`), [`quac-socket-iouring`](../quac-socket-iouring/) (multishot recvmsg + provided-buffer rings on Linux 6.0+), and [`quac-socket-xdp`](../quac-socket-xdp/) (zero-copy AF_XDP).

## Goals

The API exists to support two related workloads on the same abstraction:

1. **Packet routers / forwarders.** Receive a datagram, decide where it goes, send it out. Ideally without copying the payload between the RX and TX paths.
2. **Packet generators / QUIC servers.** Construct datagrams from application state and send them, possibly receiving cryptographic responses back.

Both workloads share the same hard constraints: no allocation on the hot path, no cross-core synchronization on the hot path, and no payload copies beyond what the underlying transport actually requires. The trait shape is what drops out when these constraints are taken seriously across an OS-sockets backend, an io_uring backend, and a true zero-copy backend (AF_XDP) without any backend leaking into the others.

Other goals that fell out of those constraints:

- **One socket = one hardware queue.** A socket is a [`!Send`](../quac-socket/src/socket.rs) handle bound to one RX/TX queue, owned by one tile thread. `&mut self` on `send`/`recv` is the only synchronization. Multi-queue scaling is done by running N tiles, each with its own socket and pools, bound through `SO_REUSEPORT` (OS / io_uring) or queue-id steering (XDP). See **Multi-queue setup and CPU alignment** below for the operational requirements that make this scale.
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

## Multi-queue setup and CPU alignment

The "one socket per hardware queue" rule is what lets each tile own its own receive queue, send pool, and reclamation path without sharing state with the others. For the OS and io_uring backends that rule sits on top of `SO_REUSEPORT`; for AF_XDP it sits on top of explicit `(if_index, queue_id)` binding. Either way the goal is the same: **the tile thread that consumes a packet runs on the same CPU that the NIC's softirq used to enqueue it.**

When that alignment holds, the per-socket receive-queue spinlock (`sk->sk_receive_queue.lock` for OS / io_uring, the AF_XDP RX ring head/tail otherwise) stays cache-warm. When it doesn't — e.g. four `SO_REUSEPORT` siblings, the kernel's default 4-tuple hash, and softirqs landing on whichever CPU `irqbalance` picked this second — every recvmsg pays a cross-CPU cache-line bounce on that lock. At >1 Mpps per tile that bounce is the dominant cost; perf shows it as `native_queued_spin_lock_slowpath` underneath `__udp_enqueue_schedule_skb` and `udp_rmem_release`.

### How each backend expresses the rule

- **OS sockets ([`OsSocket::bind`](../quac-socket-os/src/socket.rs))**: bind a `SO_REUSEPORT` group of N sockets, one per RX queue, passing `queue_id = i` for the i-th socket. The alignment is **opt-in**: build the config with `OsConfig::builder().incoming_cpu(true)` and the backend resolves bind IP → interface → CPU for queue `i` and sets `SO_INCOMING_CPU`. The owner then pins its tile thread to the same CPU after construction:

  ```rust
  let cfg = OsConfig::builder().incoming_cpu(true).build();
  let mut sock = OsSocket::bind(bind, queue_id, cfg)?;
  sock.pin_current_thread_to_queue_cpu()?;
  ```

  Without the `incoming_cpu(true)` flag (or with a wildcard bind), `bind` does no setsockopt and behaves as a plain `SO_REUSEPORT` listener — the kernel falls back to its default 4-tuple hash. `pin_current_thread_to_queue_cpu` is a separate public method the owner can choose to call or skip; it errors on wildcard binds.

- **io_uring sockets ([`IoUringSocket::bind`](../quac-socket-iouring/src/socket.rs))**: identical story, gated by `IoUringConfig::builder().incoming_cpu(true)`. The kernel's multishot recvmsg path goes through the same `udp_recvmsg → __skb_recv_udp → udp_rmem_release` chain as plain UDP, so the same lock is the same hazard, and the same flag + thread-pin pair fixes it.

- **AF_XDP sockets ([`XdpSocket::with_interface`](../quac-socket-xdp/src/socket.rs))**: already takes `(if_index, queue_id)` explicitly — the queue/CPU alignment is the operator's responsibility from day one. The kernel UDP stack is bypassed entirely so there is no `SO_INCOMING_CPU` to set, but the per-queue thread-pinning helper applies for the same reason: the AF_XDP RX ring is a single-producer/single-consumer SPSC, and producer-CPU ≠ consumer-CPU still costs a cache-line bounce on every descriptor.

  ```rust
  let sock = XdpSocket::with_interface(if_index, queue_id, bind_ip, bind_port, cfg)?;
  sock.pin_current_thread_to_queue_cpu()?;
  ```

  AF_XDP doesn't carry a bind IP that maps to an interface (the user named the interface directly), so the pin helper resolves the iface name back from `if_index` via `if_indextoname`. Use [`quac_socket::nic::nic_queue_count`](../quac-socket/src/nic.rs) on the iface to size the tile pool — the [`xdp-bench-receiver`](../quac-socket-xdp/examples/xdp-bench-receiver.rs) example defaults its `--threads` from that lookup when `--threads` is not given.

### Discovery helpers

The `quac_socket::nic` module exposes the same lookups the bench harness uses, so production tiles can size themselves to the available NIC queues without hard-coding:

```rust
let iface = quac_socket::nic::interface_for_addr(bind_ip)?;
let n_tiles = quac_socket::nic::nic_queue_count(&iface)?;
// ... spawn n_tiles tiles, queue_id = i for each ...
```

Each socket then uses its `queue_id` to drive both the kernel-side hint (`SO_INCOMING_CPU`, set inside `bind` only when the config has `incoming_cpu(true)`) and the user-side pin (`pin_current_thread_to_queue_cpu`, called by the tile after `bind` returns).

The bench programs all expose this as a single `--incoming-cpu` switch: passing it sets the config flag, makes the backend's `bind` look up the queue/CPU and call `setsockopt(SO_INCOMING_CPU, ...)`, calls `pin_current_thread_to_queue_cpu()` on each worker, and (for non-wildcard binds) defaults `--threads` to `nic_queue_count(...)`. Without the switch the bench behaves as a plain `SO_REUSEPORT` listener with whatever `--threads` value the user passed (or 1).

### Prerequisite: per-queue single-CPU IRQ pinning

`cpu_for_rx_queue` resolves a queue to a CPU by reading `/proc/irq/<irq>/smp_affinity_list`. **Each NIC RX queue's IRQ must be pinned to exactly one CPU** for the alignment story to hold. If a queue's affinity covers multiple CPUs, `cpu_for_rx_queue` returns an error rather than silently picking the first — the bench's soft-fail path then prints a clear `[quac-socket] SO_INCOMING_CPU skipped: …` warning so the operator notices.

The reason is that `irqbalance` (or any multi-CPU affinity mask) lets the kernel fire softirq for queue N on whichever CPU it likes, while our socket has `SO_INCOMING_CPU = first(mask)` and our tile thread is locked to that one CPU. The cache-line bouncing the feature is supposed to eliminate sneaks back in via the IRQs that drift to the "wrong" CPU.

The required setup, run once per benchmark host:

```bash
# 1. N RX/TX queues to match the tile count.
sudo ethtool -L <iface> combined N

# 2. Spread RSS evenly across them.
sudo ethtool -X <iface> equal N

# 3. Pin each rx queue's IRQ to exactly one CPU.
#    Find the IRQ in /proc/interrupts (driver-specific name; e.g.
#    "<iface>-TxRx-0" for ice/i40e, "mlx5_comp0@<iface>" for mlx5).
for q in $(seq 0 $((N-1))); do
    irq=$(awk -v iface=<iface> -v q=$q '$NF ~ iface && $NF ~ "-"q"$" {print $1}' /proc/interrupts | tr -d ':')
    echo $q | sudo tee /proc/irq/$irq/smp_affinity_list
done

# 4. Stop irqbalance so it doesn't undo step 3 at runtime.
sudo systemctl stop irqbalance
```

If any of those steps is missing or wrong, expect the `SO_INCOMING_CPU skipped` warnings and a partial-to-zero throughput improvement vs. the unaligned baseline. The bench keeps running unpinned in that case — running but slow is preferable to refusing to start.

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
