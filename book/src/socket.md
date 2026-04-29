# Socket Abstraction

`quac-socket` defines the boundary between I/O backends and the rest of the
engine. Any backend — a plain OS UDP socket, an io_uring ring, a DPDK mempool,
or an in-memory test stub — implements the same two traits: `BufferPool` and
`PacketSocket`. Everything above this layer is backend-agnostic.

## Why an abstraction?

Every UDP backend shares three responsibilities: allocating memory for packet
data, sending datagrams, and receiving datagrams. What differs is *how* memory
is managed:

- **Copy backends** (OS UDP socket) copy packet bytes through the kernel. Every
  send and receive crosses a privilege boundary. Simple, portable, no special
  setup required.
- **Zero-copy backends** (io_uring with registered buffers, AF_XDP, DPDK) keep
  packet memory in userspace-mapped rings. The kernel DMA-copies directly to and
  from NIC hardware; no data is ever duplicated into kernel address space.
- **Test backends** wire two in-memory queues together. Sending into one end
  appears as a receive on the other with no kernel involvement at all.

Making the buffer lifetime explicit in the type system is the key design
decision. A buffer is allocated from a pool, filled by the engine, frozen into
an immutable handle, transmitted, and eventually recycled. Each stage is a
distinct Rust type so the compiler prevents use-after-send and enforces
ownership of NIC-mapped memory.

## Buffer types

```rust,ignore
/// An immutable handle to a packet buffer owned by a BufferPool.
/// Dropping the handle returns the buffer to the pool.
pub trait PacketBuf: AsRef<[u8]> + Send + 'static {}

/// A mutable handle used to fill an outgoing packet or inspect a received one.
pub trait PacketBufMut: AsRef<[u8]> + AsMut<[u8]> + Send + 'static {
    type Frozen: PacketBuf;

    /// Transition to an immutable handle ready for transmission.
    fn freeze(self) -> Self::Frozen;

    /// Set the logical length of this buffer.
    /// Bytes in [old_len..new_len] are unspecified after the call;
    /// callers must initialise them before reading.
    fn resize(&mut self, new_len: usize);
}
```

`PacketBufMut` and its frozen counterpart `PacketBuf` enforce ownership at the
type level: once a buffer is frozen it cannot be mutated. For zero-copy backends
this matters — the NIC may be DMA-reading from the buffer while the CPU is doing
other work, so mutable access must be structurally impossible after the freeze.

`resize` has intentionally relaxed semantics: bytes beyond the old length are
unspecified. Callers that build outgoing packets always write a payload before
transmitting, so the CPU does not waste time zeroing memory it is about to
overwrite.

## Buffer pool

```rust,ignore
pub trait BufferPool: Send + Sync + 'static {
    type Buf: PacketBuf;
    type BufMut: PacketBufMut<Frozen = Self::Buf>;

    /// Allocate up to `count` mutable buffers of at most `capacity` bytes each.
    /// Pushes into `bufs` and returns how many were allocated.
    /// Returns 0 when the pool is exhausted.
    fn alloc(&self, capacity: usize, count: usize, bufs: &mut Vec<Self::BufMut>) -> usize;

    /// Payload size below which copying is faster than scatter-gather.
    /// Hardware-dependent; callers use it to decide whether to coalesce.
    fn zerocopy_threshold(&self) -> usize;
}
```

`Send + Sync` allows the pool to be shared across threads — multiple I/O
threads can allocate from and recycle into the same pool. `alloc` pushes into a
caller-supplied `Vec` for batch allocation, amortising synchronisation overhead
across many buffers.

## Scatter-gather

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

A logical packet is an ordered list of buffer segments. Up to four segments fit
inline in the `SmallVec` with no heap allocation; longer chains spill to the
heap. The NIC gathers the segments at DMA time without an intermediate copy: a
QUIC header can live in one segment and application payload in another.

`as_contiguous()` returns a single `&[u8]` slice when the packet is backed by
exactly one segment covering its full buffer. This is the common case for
received datagrams, and checking it first avoids unnecessary copies when routing
or inspecting packet headers.

## Packet metadata

```rust,ignore
pub struct RecvMeta {
    pub src: SocketAddr,       // Source address of the received datagram
    pub dst_ip: Option<IpAddr>, // Destination IP from the IP header
    pub ecn: Option<EcnCodepoint>, // ECN codepoint from the IP header
    pub len: usize,            // Total datagram length in bytes
    pub stride: usize,         // GRO segment stride (0 if not coalesced)
}

pub enum EcnCodepoint { Ect0, Ect1, Ce }

pub struct Transmit<T> {
    pub destination: SocketAddr,
    pub ecn: Option<EcnCodepoint>,
    pub contents: T,
    pub segment_size: Option<usize>, // GSO segment size; None = single datagram
    pub src_ip: Option<IpAddr>,
}
```

`dst_ip` carries the destination address of each received datagram as reported
by the IP header. QUIC requires this so the engine can set the correct source IP
in reply packets on multi-homed hosts.

`ecn` carries Explicit Congestion Notification codepoints. Congestion
controllers inspect them to reduce sending rate before packet loss occurs.

`stride` is the GRO (Generic Receive Offload) stride: when the NIC coalesces
multiple datagrams into one receive call, `stride` is the distance between
logical datagrams in the combined buffer.

`segment_size` on `Transmit` enables GSO (Generic Segmentation Offload): the
kernel or NIC splits one large buffer into many equal-sized datagrams, saving
one `sendmsg` call per segment.

## The PacketSocket trait

```rust,ignore
pub trait PacketSocket: Send + 'static {
    type Pool: BufferPool;

    fn pool(&self) -> Arc<Self::Pool>;

    fn send(
        &mut self,
        transmits: Vec<Transmit<ScatterGather<<Self::Pool as BufferPool>::Buf>>>,
    ) -> Vec<Transmit<ScatterGather<<Self::Pool as BufferPool>::Buf>>>;

    fn drain_completions(&mut self);

    fn recv(
        &mut self,
        meta: &mut [RecvMeta],
        bufs: &mut Vec<ScatterGather<<Self::Pool as BufferPool>::BufMut>>,
    ) -> io::Result<usize>;

    fn local_addr(&self) -> io::Result<SocketAddr>;
    fn queue_id(&self) -> u32;

    fn max_gso_segments(&self) -> usize { 1 }
    fn max_gro_segments(&self) -> usize { 1 }
}
```

`PacketSocket` is `Send` but not `Sync`. TX and RX queue cursors have
single-threaded ownership invariants — DPDK queue head/tail pointers and AF_XDP
ring cursors cannot be safely accessed from multiple threads simultaneously. The
`&mut self` receiver on `send` and `recv` expresses this directly without any
internal lock.

All operations are **non-blocking** and return immediately with whatever work
could be completed. The network tile's I/O thread is responsible for looping and
for deciding when to park.

`send` returns any packets that could not be submitted. Whether to retry or drop
them is the caller's decision. Submitted packets are held by the socket until
`drain_completions` is called, at which point zero-copy backends recycle their
buffer memory; copy backends drop them immediately.

`queue_id` identifies which hardware RX queue this socket is bound to. The QUIC
engine encodes this value in newly-generated Connection IDs so that the network
steering infrastructure (RSS rules or SO_REUSEPORT) can route subsequent packets
from the same client back to the same socket.
