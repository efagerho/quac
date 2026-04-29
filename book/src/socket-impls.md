# Socket Implementations

Three `PacketSocket` implementations are provided: an OS UDP socket backend, an
io_uring backend, and an in-memory test pair. All three implement the same
`PacketSocket` and `BufferPool` traits from `quac-socket`.

## OsSocket (quac-socket-os)

`OsSocket` is a plain UDP socket backed by the OS network stack. It is the
baseline implementation: portable, requiring no privileges, and working on any
platform that supports POSIX UDP sockets. On Linux it uses batch system calls
for higher throughput; on other platforms it falls back to single-datagram calls.

### Binding

```rust,ignore
// Bind to a specific address. Standard UDP socket.
let socket = OsSocket::bind("0.0.0.0:4433".parse()?)?;

// Bind with SO_REUSEPORT so multiple sockets can share the same port.
// The kernel distributes incoming packets across all SO_REUSEPORT sockets
// on the same address using a hash of the UDP 4-tuple.
let socket = OsSocket::bind_reuseport("0.0.0.0:4433".parse()?)?;

// Clone the socket file descriptor. Both clones share the same underlying
// socket — used in Separate mode to give the reader and writer threads
// independent ownership.
let tx_socket = socket.try_clone()?;
```

### Receive path (Linux)

On Linux, `recv` calls `recvmmsg` with up to 64 pre-allocated `mmsghdr`
structures. Each slot holds a pinned `sockaddr_storage` for the source address
and a pre-allocated `OsBufMut` for the payload. A single syscall fills as many
slots as the kernel has available, amortising the crossing cost across a burst
of datagrams.

If the NIC has GRO enabled, multiple coalesced datagrams may arrive in one
receive slot. The `RecvMeta::stride` field carries the per-segment distance so
the engine can split them apart.

### Transmit path (Linux)

TX calls `sendmmsg` with all pending `Transmit` items batched into one syscall.
GSO (Generic Segmentation Offload) is supported: when `segment_size` is set on
a `Transmit`, the kernel splits the large buffer into equal-sized datagrams
before handing them to the NIC, saving one `sendmsg` per segment.

**Zero-copy transmit (MSG_ZEROCOPY).** When the kernel supports it, `sendmsg`
is called with `MSG_ZEROCOPY`. The kernel DMA-copies directly from the userspace
buffer to the NIC without an intermediate kernel buffer. After the NIC
acknowledges the send, the kernel delivers a completion notification to the
socket error queue. `drain_completions` reads these notifications via
`recvmsg(MSG_ERRQUEUE)` and recycles the corresponding `OsBuf` objects back to
the pool. If the kernel copies the data anyway (reported via
`SO_EE_CODE_ZEROCOPY_COPIED`), the buffer is recycled immediately without
waiting for a completion.

### OsPool

`OsPool` is the `BufferPool` implementation for `OsSocket`. It uses a
**Vyukov MPSC intrusive queue**: each `OsBufNode` contains its data `Vec<u8>`
plus an atomic `next` pointer that threads it into a lock-free list when
recycled. The invariants are:

- **Consumer** (the I/O thread calling `alloc`): reads `head` without a CAS.
- **Producers** (any thread dropping an `OsBuf` or `OsBufMut`): one `XCHG`
  instruction to append to the tail.

This gives O(1) alloc and O(1) recycle with minimal synchronisation. When the
pool is empty `alloc` returns fewer buffers than requested; callers allocate
new nodes from the heap and they are recycled back into the pool on drop.

`zerocopy_threshold` returns `usize::MAX`, meaning callers should never attempt
to coalesce a scatter-gather chain into a contiguous buffer for this backend —
the OS socket accepts scatter-gather transmits directly.

## IoUringSocket (quac-socket-iouring)

`IoUringSocket` uses the Linux io_uring interface for both send and receive.
io_uring submits and completes I/O operations through two shared-memory ring
buffers, eliminating the per-operation `syscall` overhead: a single
`io_uring_enter` syscall submits and reaps many operations at once, and for
workloads with a large inflight count, the kernel can be configured to poll
completions without any syscall at all.

### Receive: multishot + provided buffers

`IoUringSocket` uses **multishot `IORING_OP_RECVMSG`** with a **provided buffer
ring**. A single SQE (submission queue entry) arms the socket for continuous
receive; the kernel fills available buffers from the provided ring and delivers
one CQE (completion queue entry) per datagram without any re-arming. The
provided ring holds 256 pre-registered buffers of 65535+144 bytes each (144
bytes for the `recvmsg_out` header and sockaddr, the rest for payload).

When a CQE arrives:
1. The kernel's `io_uring_recvmsg_out` header at the buffer start gives payload
   length, source address, and ECN flags.
2. The payload bytes follow at a fixed offset.
3. The buffer is handed to the engine as an `OsBufMut`. When recycled, it is
   re-registered into the provided ring for the next receive.

### Transmit: fixed buffer pool

Sends go through a pool of 128 pre-registered fixed buffers. The engine
selects a free slot, copies the payload, and submits a `IORING_OP_SENDMSG` SQE.
Completions are reaped on the next `recv` call, recycling the slot.

### Construction

```rust,ignore
// Bind with SO_REUSEPORT (typical server setup).
let socket = IoUringSocket::bind_reuseport("0.0.0.0:4433".parse()?)?;
```

`IoUringSocket` does not implement `try_clone` — io_uring rings are not
shareable. In `Separate` mode, create two independent sockets bound to the same
address:

```rust,ignore
let rx = IoUringSocket::bind_reuseport(addr)?;
let tx = IoUringSocket::bind_reuseport(addr)?; // separate ring for TX thread
```

### Performance characteristics

On benchmarks with a local loopback workload, `IoUringSocket` and `OsSocket`
produce the same throughput once the io_uring rings are warmed up. The io_uring
backend shows a cold-start penalty of roughly 50–60ms on the first benchmark
run, attributable to ring initialisation and provided-buffer registration. After
warm-up the two backends are within measurement noise of each other.

The io_uring backend's advantage appears at higher packet rates with many
concurrent connections on real hardware, where eliminating per-datagram system
calls reduces kernel-crossing overhead.

## PairSocket (quac-test-socket)

`PairSocket` provides an in-memory socket pair for tests. Two `PairSocket`
instances share an `Arc<Mutex<PairInner>>`. Sending into one end enqueues
datagrams into the peer's receive queue; the peer's `recv` call dequeues them.
No kernel, no network, no timing non-determinism.

```rust,ignore
let (client_socket, server_socket) = PairSocket::pair();
// client_socket.local_addr() == 127.0.0.1:4000
// server_socket.local_addr() == 127.0.0.1:4001
```

`PairSocket` uses `TestPool` and `TestBuf`/`TestBufMut`, which are simple heap
`Vec<u8>` wrappers. `zerocopy_threshold` returns `usize::MAX`.

The test socket is intended to be used directly with the QUIC engine tiles,
allowing full end-to-end QUIC handshakes and data transfers without any network
stack:

```rust,ignore
let (client_sock, server_sock) = PairSocket::pair();
let server_tile = Arc::new(NetworkTileImpl::combined(
    server_sock, QuicPacketRouter::new(), 1,
));
let client_tile = Arc::new(NetworkTileImpl::combined(
    client_sock, QuicPacketRouter::new(), 1,
));
server_tile.clone().start(0);
client_tile.clone().start(1);
```
