# quac

A tile-based async QUIC engine for Rust. The design is documented in the mdBook at
[`book/src/`](book/src/); build it with `mdbook build` inside the `book/` directory.

## Crate layout

| Crate | Purpose |
|-------|---------|
| `quac-interface` | `PacketSocket`, `BufferPool`, and buffer traits — the low-level I/O abstraction |
| `quac-socket` | OS UDP socket implementation of `quac-interface` (`recvmsg`/`sendmsg`, batched on Linux) |
| `quac-test-socket` | In-memory `PairSocket` for unit tests — no kernel involvement |
| `quac-tile` | `NetworkTile` trait and the SPSC queue packet types (`RxPacket`, `TxPacket`) |
| `quac-network-tile-socket` | `OsNetworkTile`: reader/writer thread pair backed by `quac-socket` |
| `quac` | Full engine and async API — `TileSet`, `Endpoint`, `Connection`, `SendStream`, `RecvStream` |
| `quic-proto` | QUIC protocol state machine (forked from quinn-proto) |
| `benchmarks` | Echo servers and load clients — see below |

## Architecture overview

A **tile** owns one UDP socket and three OS threads: a reader, a writer, and an engine thread.

```
NIC RX → Reader → rx[i][j] (SPSC) → Engine → tx[j] (SPSC) → Writer → NIC TX
```

Network tiles (reader + writer) and engine tiles are independent — their counts are separate
runtime parameters. All network tiles share the same address via `SO_REUSEPORT`, so any writer
can transmit on behalf of any connection. The engine tiles route packets by CID prefix: the first
byte of every server-assigned Connection ID encodes the owning engine tile index, so the reader
can route subsequent packets with a single byte read and no shared state.

## Benchmark programs

All binaries are in the `benchmarks` crate. Build with:

```sh
cargo build --release -p benchmarks
```

### Servers

#### `quic_pong_tile` — tile-based echo server

The primary server under test. Accepts QUIC connections and reflects each bidirectional stream
payload back to the sender.

```
quic_pong_tile [OPTIONS]

  --listen <ADDR:PORT>       Bind address (default: 0.0.0.0:4433)
  --port <PORT>              Port only shorthand (default: 4433)
  --threads <N>              Number of network tiles and engine tiles (default: 1)
                             Each tile spawns one reader, one writer, and one engine thread.
  --tokio-threads <N>        Tokio worker threads for the async accept loop (default: CPU count)
  --exit-delay-secs <SECS>   Stay alive this many seconds after Ctrl-C (default: 0)
```

#### `quic_pong_quinn` — Quinn echo server (baseline)

A plain Quinn server with the same echo behaviour. Used as a comparison baseline.

```
quic_pong_quinn [OPTIONS]

  --listen <ADDR:PORT>       Bind address (default: 0.0.0.0:4433)
  --port <PORT>              Port only shorthand
  --threads <N>              Tokio worker threads (default: CPU count)
  --exit-delay-secs <SECS>   Stay alive this many seconds after Ctrl-C (default: 0)
```

### Clients

#### `quic_bench` — load generator

Multi-mode QUIC load client. All modes skip TLS certificate verification (for use against
local self-signed servers only). Prints a throughput summary when the run ends.

```
quic_bench <SUBCOMMAND> [OPTIONS]

Common options (all subcommands):
  --addr <ADDR:PORT>     Target server (default: 127.0.0.1:4433)
  --threads <N>          Tokio worker threads (default: CPU count)
  --duration <SECS>      Stop after this many seconds (default: run until Ctrl-C)
```

**Subcommands:**

| Subcommand | What it does | Key options |
|------------|-------------|-------------|
| `stream-ping` | Opens N connections; each runs a tight write→read echo loop on one bidi stream. Reports requests/s. | `--connections N` (default 1024) |
| `connect-churn` | Opens connections as fast as possible and closes each immediately after the handshake. Reports connections/s. | — |
| `multi-stream-ping` | Opens N connections, M bidi streams each; pings all streams concurrently. Reports requests/s. | `--connections N` (default 64), `--streams M` (default 16) |
| `churn-ping` | Keeps N×M streams active while concurrently churning connections at a fixed rate. | `--connections N` (default 64), `--streams M` (default 16), `--churn-rate R` (conns/s, default 100) |

#### `quic_ping` — single-shot echo client

Sends one `pingping` payload on a single bidi stream and prints the echo. Useful for smoke
testing a server is up and responding.

```
quic_ping [OPTIONS]

  --addr <ADDR:PORT>     Server address (default: 127.0.0.1:4433)
  --server-name <NAME>   TLS SNI name (default: localhost)
  --threads <N>          Tokio worker threads
```

## Profiling

The `scripts/` directory contains perf-based flamegraph scripts for the tile server:

```sh
# Stream-ping workload
sudo scripts/profile_quic_pong_tile_stream_ping.sh

# Connect-churn workload
sudo scripts/profile_quic_pong_tile_connect_churn.sh
```

Both scripts build the release binaries, start the server, run `quic_bench`, collect a `perf
record` trace, and produce an SVG flamegraph via `inferno`. Requires `perf` and `inferno-*`
tools to be installed.

## Running tests

```sh
cargo test --workspace
```
