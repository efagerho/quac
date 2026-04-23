# Socket Abstraction

A high-performance QUIC implementation must be portable across I/O backends. The same QUIC
protocol logic should drive packets from a plain OS UDP socket, an `io_uring`-backed ring, or a
DPDK mempool — without rewriting the protocol state machine for each. The `quac-interface` crate
provides the traits that make this possible.

## Motivation

Every packet I/O backend shares three responsibilities: allocating memory for packet data,
transmitting datagrams, and receiving datagrams. The differences are:

- **Plain OS sockets** copy packet data through the kernel. They work everywhere and require no
  special privileges, but incur a kernel crossing per send and per receive.
- **Zero-copy backends** (io_uring with fixed buffers, DPDK, AF_XDP) keep packet memory in
  userspace-mapped buffers and hand descriptors to the kernel. The kernel DMAs directly to/from
  NIC hardware; no data copy ever reaches kernel space.
- **Test doubles** wire two in-memory queues together. Sending into one end appears as a receive
  on the other, with no networking involved.

The abstraction must accommodate all three without burdening the common case. The key design
choice is to make the buffer lifecycle explicit in the type system: a buffer is allocated from a
pool, filled with data, frozen into an immutable handle, sent, and eventually recycled back to the
pool. Each stage is a distinct type.

## Buffer Types

```rust,ignore
/// An immutable handle to a packet buffer owned by a BufferPool.
/// Dropping the handle returns the buffer to the pool.
pub trait PacketBuf: AsRef<[u8]> + Send + 'static {}

/// A mutable handle used to fill an outgoing packet.
pub trait PacketBufMut: AsMut<[u8]> + Send + 'static {
    type Frozen: PacketBuf;
    fn freeze(self) -> Self::Frozen;
}

/// A mutable pool buffer for the receive path.
/// Flows through PartialDecode → decrypt inside quic-proto.
pub trait RecvBuf: AsRef<[u8]> + AsMut<[u8]> + Send + 'static {
    fn len(&self) -> usize;
    fn split_to(&mut self, at: usize) -> Self;
    fn split_off(&mut self, at: usize) -> Self;
    fn truncate(&mut self, len: usize);
}
```

The separation of `PacketBufMut` and its frozen counterpart `PacketBuf` ensures that a buffer
cannot be mutated after it has been enqueued for transmission. For zero-copy backends this is
critical: the NIC is DMAing from the buffer memory while the CPU might otherwise be writing into
it.

`RecvBuf` tracks split points so the protocol parser can peel off header bytes and pass the
remaining payload to the decryptor, all without copying. `BytesMut` implements `RecvBuf` as a
blanket implementation, allowing quic-proto and test code to use it directly.

## The Buffer Pool

```rust,ignore
pub trait BufferPool: Send + Sync + 'static {
    type Buf: PacketBuf;
    type BufMut: PacketBufMut<Frozen = Self::Buf>;
    type RecvBuf: RecvBuf;

    fn alloc(&self, capacity: usize, count: usize, bufs: &mut Vec<Self::BufMut>) -> usize;
    fn alloc_recv(&self, capacity: usize, count: usize, bufs: &mut Vec<Self::RecvBuf>) -> usize;
    fn zerocopy_threshold(&self) -> usize;
}
```

The pool is `Send + Sync` so it can be shared across threads — multiple tile reader/writer threads
or a shared DPDK mempool. `alloc` and `alloc_recv` push into a caller-supplied `Vec` to allow
batch allocation, amortising the cost of touching shared pool state. `zerocopy_threshold` tells
callers the packet size below which copying into a contiguous buffer is faster than building a
scatter-gather descriptor list — a hardware-dependent hint.

## Scatter-Gather

```rust,ignore
pub struct Segment<B> {
    pub buf: B,
    pub offset: usize,
    pub len: usize,
}

pub struct ScatterGather<B> {
    pub segments: SmallVec<[Segment<B>; 4]>,
}
```

`ScatterGather` describes a logical packet as an ordered list of buffer segments. Up to four
segments fit inline with no heap allocation; longer chains spill to the heap. The NIC's DMA
engine gathers the segments without an intermediate copy — a QUIC header can live in one segment
and the application payload in another, avoiding the copy that a contiguous buffer would require.

`as_contiguous()` provides a fast path: if the list has exactly one segment covering its entire
buffer, a single slice is returned directly with no copying.

## The Packet Socket

```rust,ignore
pub trait PacketSocket: Send + 'static {
    type Pool: BufferPool;

    fn pool(&self) -> &Self::Pool;

    fn send(
        &mut self,
        transmits: Vec<Transmit<ScatterGather<<Self::Pool as BufferPool>::Buf>>>,
    ) -> Vec<Transmit<ScatterGather<<Self::Pool as BufferPool>::Buf>>>;

    fn drain_completions(&mut self);

    fn recv(
        &mut self,
        meta: &mut [RecvMeta],
        bufs: &mut Vec<ScatterGather<<Self::Pool as BufferPool>::RecvBuf>>,
    ) -> io::Result<usize>;

    fn local_addr(&self) -> io::Result<SocketAddr>;
    fn queue_id(&self) -> u32;
}
```

`PacketSocket` is `Send` but not `Sync`. TX/RX queues have single-threaded ownership invariants:
DPDK queue head/tail pointers and AF_XDP ring cursors cannot be accessed concurrently. The
`&mut self` on `send` and `recv` expresses this directly without internal locking.

All operations are **non-blocking** and return immediately with whatever they could complete. The
caller is responsible for readiness polling via `rx_fd()` on Unix, or a busy-poll loop for
backends with no file descriptor.

`send` returns any packets it could not submit — the caller decides whether to retry or drop.
Accepted packets are held by the socket until `drain_completions` recycles their buffers (zero-copy
backends) or dropped immediately (copy backends and the test socket).

`queue_id` identifies which hardware RX queue this socket is bound to. The QUIC engine encodes
this value in the Connection ID prefix of every new server-side connection so that subsequent
packets from the same client are steered back to the same queue by RSS — providing connection-level
affinity with no cross-tile coordination.

## Receive Metadata

```rust,ignore
pub struct RecvMeta {
    pub src: SocketAddr,
    pub dst_ip: Option<IpAddr>,
    pub ecn: Option<EcnCodepoint>,
    pub len: usize,
    pub stride: usize,
}
```

`dst_ip` captures the destination IP from the IP header. QUIC requires this to set the source IP
of reply packets correctly on multi-homed hosts. `ecn` carries the Explicit Congestion Notification
codepoint; congestion controllers use it to reduce the sending rate before packet loss occurs.
`stride` is the GRO (Generic Receive Offload) segment distance when the NIC coalesces multiple
datagrams into a single receive call.

## Implementations

The `quac-socket` crate provides `OsSocket`, a plain UDP socket backend using `recvmsg`/`sendmsg`
on Unix (with `recvmmsg`/`sendmmsg` batch variants on Linux). It uses `BytesMut` as its `RecvBuf`
and heap-allocated `OsBuf` as its `PacketBuf`. Both `OsSocket` and its companion `OsPool`
implement the `quac-interface` traits.

The `quac-test-socket` crate provides `PairSocket`, an in-memory packet queue pair for use in
tests. Sending into one end enqueues datagrams for the other end's `recv` call with no kernel
involvement; tests run in microseconds.

## Relationship to Tiles

`PacketSocket` is the lowest-level abstraction — one socket, one thread. The tile layer
(`quac-tile`) operates one level higher: a `NetworkTile` wraps two threads (reader + writer)
around a pair of socket instances and connects them to the QUIC engine via SPSC queues. The
`quac-network-tile-socket` crate implements `NetworkTile` using `OsSocket` from `quac-socket`.
The full engine (`quac`) then wires together any number of network tiles with any number of engine
tiles.

This layering means a future DPDK or AF_XDP backend needs only to implement `PacketSocket` and
`BufferPool`; the tile wiring, the engine, and the async API all work unchanged.

## References

### Run-to-Completion and Pipeline Models

**Belay et al., "IX: A Protected Dataplane Operating System for High Throughput and Low Latency,"
OSDI 2014.**
The foundational reference for the run-to-completion + bounded batching pattern. Dedicates a
hardware thread per queue, processes a bounded batch to completion, and avoids all shared mutable
state across cores. The tile architecture follows this model directly, and the paper provides the
performance rationale for why it outperforms event-driven alternatives.

**Jeong et al., "mTCP: A Highly Scalable User-level TCP Stack for Multicore Systems," NSDI 2014.**
Replaces expensive per-packet system calls with a shared-memory event batching interface modelled
on epoll. A blueprint for the lock-free command/event queue design between engine tiles and the
async application layer, showing how to amortize wakeup overhead across a batch of I/O operations.

**Menon et al., "Soft-RoCE and VPP: High-Performance Networking for Commodity Hardware,"
(Vector Packet Processing model).**
VPP's pipeline model — fixed-size vector of packets processed by a chain of graph nodes per
iteration — is the direct ancestor of the reader-routing-layer design. Each "graph node" in VPP
corresponds to a phase of the engine's `run_once` loop.

### Lock-Free Queue Design

**Michael and Scott, "Simple, Fast, and Practical Non-Blocking and Blocking Concurrent Queue
Algorithms," PODC 1996.**
The canonical lock-free MPMC queue algorithm. Crossbeam's `ArrayQueue<T>` is a bounded
variant derived from this work, using a fixed-size ring with atomic head/tail indices rather than
pointer-chased nodes, which improves cache behaviour for the bounded case.

**Lameter, "An Overview of Non-Uniform Memory Access," Linux Symposium 2013.**
Explains NUMA topology and why the primary cost of cross-socket communication is cache coherence
traffic, not memory latency alone. The tile's per-tile structure eliminates cross-socket
cache-line bouncing on the data path; the shared `BufferPool` is the only structure that may
generate cross-socket traffic when tiles span NUMA nodes.

### Async Wakeup Without System Calls

**Drepper, "Futexes Are Tricky," 2011.**
The authoritative analysis of futex semantics and the exact race conditions that arise when trying
to park a thread without a missed wakeup. The `is_parked` flag + re-check pattern in the engine
tile run loop is the userspace equivalent of the futex two-step described in this paper.

**Tokio contributors, `futures-util::task::AtomicWaker`.**
The `AtomicWaker` type used in `StreamCell` stores a Tokio `Waker` using two atomic stores with
acquire/release ordering, avoiding a mutex on the wakeup path. The implementation handles the
concurrent-register-and-wake race in the same way the engine tile handles the park/unpark race:
a re-read after an atomic flag transition closes the window.

### QUIC Connection ID Routing

**Duke et al., "QUIC-LB: Generating Predictable Multipath-Robust QUIC Connection IDs,"
RFC 9386, 2022.**
Defines a standard format for embedding routing information in QUIC connection IDs so that
load balancers and NIC steering rules can forward packets without inspecting application state.
The CID-prefix routing used by the reader layer is a simplified instance of this standard: the
first byte encodes the target engine tile index.

**Höchst et al., "Faster Connection Establishment in QUIC by Paralleling Cryptographic
Operations," 2022.**
Examines how connection setup latency is affected by the number of threads sharing cryptographic
work. In the tile model TLS handshakes are pinned to a single engine tile (via the CID after the
first random placement), which matches the paper's finding that intra-connection parallelism
across cores does not pay off compared to per-connection ownership.

### Thread-per-Core I/O

**DataStax, "Glommio: A Thread-per-Core Crate for Rust's Async Ecosystem," 2021.**
Glommio implements a thread-per-core io_uring executor where each core owns its own queue of
tasks and I/O completions with no work stealing. The tile architecture adopts the same
thread-ownership principle but keeps the QUIC protocol logic separate from the I/O threads,
allowing the ratio of I/O threads to protocol threads to be tuned independently.
