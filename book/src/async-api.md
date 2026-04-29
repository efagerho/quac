# Async API

The async API is the interface between application code and the engine tiles.
Application code is tokio-based and uses `async/await`; the engine tiles are
plain OS threads with no tokio dependency. The bridge is a set of lock-free
queues and a lightweight wakeup mechanism that integrates with tokio's task
scheduler without any mutex.

## AppQueue — the bridge primitive

`AppQueue<T>` is the building block for every async operation that crosses the
engine boundary:

```rust,ignore
pub(crate) struct AppQueue<T> {
    queue: ArrayQueue<T>,  // bounded crossbeam MPMC queue
    waker: AtomicWaker,    // tokio Waker stored atomically
    needs_wake: AtomicBool,
}
```

**Push path (engine thread):**

```rust,ignore
pub(crate) fn push(&self, item: T) -> Result<(), T> {
    self.queue.push(item)?;
    // Wake only on the false→true transition to coalesce back-to-back pushes.
    if !self.needs_wake.swap(true, Ordering::AcqRel) {
        self.waker.wake();
    }
    Ok(())
}
```

A single boolean swap coalesces wakeups: if the engine pushes N items before the
tokio task drains the queue, only one `wake()` call is issued. This matters
because `wake()` involves a tokio scheduler operation that is more expensive than
an atomic store.

**Poll path (tokio task):**

```rust,ignore
pub(crate) fn poll_pop(&self, cx: &mut Context<'_>) -> Poll<T> {
    // Clear the needs_wake flag before registering the waker.
    self.needs_wake.store(false, Ordering::Release);
    // Register the waker.
    self.waker.register(cx.waker());
    // Re-check — catches items pushed between the last pop and this point.
    match self.queue.pop() {
        Some(item) => Poll::Ready(item),
        None => Poll::Pending,
    }
}
```

The store-then-register-then-check sequence prevents missed wakeups. If the
engine pushes between the `store(false)` and the `pop()`, either:
- The engine sees `needs_wake = false`, calls `wake()`, and the registered waker
  fires; or
- The `pop()` finds the item and returns `Ready` without parking.

## EngineWaker — waking the engine thread

The engine thread parks via `std::thread::park_timeout` when all queues are
empty. The `EngineWaker` provides a thin wrapper for waking it:

```rust,ignore
pub(crate) struct EngineWaker {
    sleeping: AtomicBool,
    thread: OnceLock<Thread>,
}

impl EngineWaker {
    // Called once by the engine thread at startup.
    pub(crate) fn register(&self) {
        self.thread.set(std::thread::current()).ok();
    }

    // Called by producers. Unparks only when the engine is actually parked.
    pub(crate) fn wake(&self) {
        if self.sleeping.load(Ordering::Acquire) {
            if let Some(t) = self.thread.get() {
                t.unpark();
            }
        }
    }

    pub(crate) fn set_sleeping(&self) { self.sleeping.store(true, Ordering::SeqCst); }
    pub(crate) fn clear_sleeping(&self) { self.sleeping.store(false, Ordering::Relaxed); }
}
```

The engine sets `sleeping = true` before parking and `sleeping = false`
immediately after waking. The `park_timeout → unpark` round-trip costs a futex
syscall (~200–500 ns on Linux), so producers only pay that cost when the engine
is genuinely idle.

**Race closure.** Between the engine finding all queues empty and setting
`sleeping = true`, a producer might push an item and read `sleeping = false`,
skipping the `unpark`. The engine's re-check of `dirty_conns` and `rx_queue`
*after* setting `sleeping = true` catches any item pushed in that window: if the
re-check finds work, the engine processes it without parking; otherwise it parks
knowing that any subsequent push will see `sleeping = true` and call `unpark`.

## Connection

`Connection` is the application's handle to a QUIC connection. It is cheap to
clone — all clones share the same `Arc<ConnInner>`.

```rust,ignore
pub struct Connection {
    inner: Arc<ConnInner>,
}

pub(crate) struct ConnInner {
    accept_bi:    Arc<AppQueue<AcceptEvent>>,
    accept_uni:   Arc<AppQueue<AcceptEvent>>,
    conn_events:  Arc<AppQueue<ConnEvent>>,
    stream_data:  Arc<AppQueue<ConnData>>,
    cmds:         Arc<ArrayQueue<AppCmd>>,
    engine_waker: Arc<EngineWaker>,
    handle:       ConnectionHandle,
    dirty_conns:  Arc<ArrayQueue<ConnectionHandle>>,
    remote_address: SocketAddr,
    local_ip:     Option<IpAddr>,
}
```

`send_cmd` is the one method on `ConnInner` that all application operations go
through:

```rust,ignore
pub(crate) fn send_cmd(&self, cmd: AppCmd) {
    let _ = self.cmds.push(cmd);
    let _ = self.dirty_conns.push(self.handle);
    self.engine_waker.wake();
}
```

It pushes the command, marks the connection as dirty so the engine processes it
promptly, and wakes the engine if it is sleeping.

## Application operations

### Accepting incoming connections

```rust,ignore
// Server receives a connection attempt from a client.
let incoming: Incoming = endpoint.accept().await.unwrap();
// TLS runs here, on the tokio thread.
let conn: Connection = incoming.accept(server_config).await?;
```

`Endpoint::accept()` polls the `incoming_queue` that the engine pushes
`Incoming` values into after `pre_accept`. When the queue is empty it registers
with the queue's `AtomicWaker` and returns `Poll::Pending`.

`incoming.accept()` runs the TLS handshake. The `Incoming` struct carries a
`quinn_proto::Pending` (pre-validated by the engine) plus a one-shot
`ArrayQueue<AcceptOutcome>` that the engine polls in step 2 of its loop. When
the tokio-side TLS completes, the outcome is pushed into that queue and the
engine is woken. The engine calls `qp_endpoint.finish_accept`, creates the
`EngineConn`, and pushes the `Connection` back to the tokio task via another
one-shot queue.

### Accepting streams

```rust,ignore
let (id, send) = conn.accept_bi().await?;  // waits for the peer to open a bidi stream
let (id, _)   = conn.accept_uni().await?;  // waits for the peer to open a uni stream
```

These poll the `accept_bi` / `accept_uni` `AppQueue`s on `ConnInner`. The engine
pushes an `AcceptEvent::Opened { id }` when it dispatches an
`Event::Stream(StreamEvent::Opened { dir, id })` from `quinn_proto`. If the
connection is lost, `AcceptEvent::Lost(e)` is pushed and the future returns
`Err`.

### Receiving stream events

```rust,ignore
match conn.recv_stream_event().await? {
    StreamEvent::Data { id, bytes } => { /* data arrived on stream `id` */ }
    StreamEvent::Finished { id }    => { /* EOF on stream `id` */ }
    StreamEvent::Reset { id, code } => { /* stream reset by peer */ }
}
```

All stream data, EOF, and reset events for every stream on this connection are
multiplexed onto a single `stream_data: AppQueue<ConnData>`. A burst of events
across N streams fires one tokio wakeup. Applications typically select between
`accept_bi()` and `recv_stream_event()` in a loop:

```rust,ignore
loop {
    tokio::select! {
        res = conn.accept_bi()         => { /* new stream */ }
        res = conn.recv_stream_event() => { /* data on existing stream */ }
    }
}
```

### Opening streams

```rust,ignore
let (id, send_opt) = conn.open_bi().await?;
let (id, _)        = conn.open_uni().await?;
```

`open_bi()` sends `AppCmd::OpenStream { dir: Bi, result_tx }` to the engine and
polls a one-shot `AppQueue<OpenStreamResult>`. The engine calls
`conn.streams().open(Dir::Bi)`. If flow-control credits are available the result
arrives immediately; otherwise the engine stores the `result_tx` in
`pending_opens` and pushes the result when a `StreamEvent::Available` event
arrives later.

### Writing and finishing streams

```rust,ignore
let send: SendStream = /* from accept_bi or open_bi */;
send.write(bytes::Bytes::from_static(b"hello"));
send.finish(); // consumes send, signals EOF to the peer
```

`SendStream::write` sends `AppCmd::StreamWrite { id, data }` via `send_cmd`.
`finish` sends `AppCmd::StreamFinish { id }`. Both are fire-and-forget: there is
no async back-pressure at the stream-write call site. Back-pressure from a full
`cmds` queue would be visible if the queue filled up (it is sized at 64), but in
practice the engine drains it faster than any single tokio task can fill it.

### Connection close

```rust,ignore
conn.close(VarInt::from_u32(0), b"bye");
// or await for the peer to close:
let err: ConnectionError = conn.closed().await;
```

`close` sends `AppCmd::Close` via `send_cmd`. `closed()` polls `conn_events`
for a `ConnEvent::Lost`. The engine pushes `ConnEvent::Lost` whenever
quinn_proto reports the connection as terminated.

## Wakeup cost

The critical question for async integration is: how expensive is each wakeup?

- **Engine → tokio** (new data): `AppQueue::push` performs one atomic swap
  (`needs_wake`). On the first push after the queue was empty it calls
  `AtomicWaker::wake()`, which stores the waker pointer and schedules the tokio
  task. Total cost: 2–3 atomic operations plus a tokio scheduler notification.

- **Tokio → engine** (new command): `send_cmd` pushes to a `crossbeam ArrayQueue`
  (one CAS on the tail), pushes to `dirty_conns` (one more CAS), and calls
  `EngineWaker::wake()`. If the engine is spinning, `wake()` is a single atomic
  load that returns immediately. If the engine is parked, it calls
  `thread::unpark()` which is a futex syscall (~200–500 ns on Linux).

The engine's spinning window amortises wakeup cost over many commands. For
continuous high-throughput workloads the engine never parks and all wakeup paths
are pure atomic operations.
