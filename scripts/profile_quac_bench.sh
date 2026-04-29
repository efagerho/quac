#!/usr/bin/env bash
# Profile quac_server CPU during a sustained benchmark run.
#
# Mirrors the bench_quac.sh configuration:
#   quac_server:  1 combined tile, 2 tokio threads
#   quinn_client: 16 connections, 64 streams/conn, 4 threads
#
# Usage:
#   ./scripts/profile_quac_bench.sh
#
# Env overrides:
#   ADDR            listen/connect address (default: 127.0.0.1:4433)
#   WARMUP_SECS     seconds of traffic before perf starts (default: 3)
#   PERF_DURATION   seconds perf records (default: 10)
#   PERF_FREQ       sampling frequency in Hz (default: 997)
#   PERF_DATA       output perf.data path
#   SVG             output flamegraph SVG path
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="$REPO_ROOT/scripts"

ADDR="${ADDR:-127.0.0.1:4433}"
WARMUP_SECS="${WARMUP_SECS:-3}"
PERF_DURATION="${PERF_DURATION:-10}"
PERF_FREQ="${PERF_FREQ:-997}"
PERF_DATA="${PERF_DATA:-$OUT_DIR/perf_quac_bench.data}"
SVG="${SVG:-$OUT_DIR/flamegraph_quac_bench.svg}"

if [[ "$(uname -s)" != Linux ]]; then
  echo "error: this script uses perf(1) on Linux only." >&2
  exit 1
fi
if ! command -v perf >/dev/null 2>&1; then
  echo "error: perf(1) not found." >&2
  exit 1
fi

echo "=== quac_server bench profile ===" >&2
echo "addr=$ADDR  conns=16  streams=64  client_threads=4" >&2
echo "server: 1 combined tile, 2 tokio threads" >&2
echo "warmup=${WARMUP_SECS}s  perf=${PERF_DURATION}s  freq=${PERF_FREQ}Hz" >&2
echo "perf_data=$PERF_DATA  svg=$SVG" >&2
echo "" >&2

cd "$REPO_ROOT"

echo "Building with frame pointers…" >&2
RUSTFLAGS="-C force-frame-pointers=yes" \
  cargo build --release -p benchmarks \
    --bin quac_server \
    --bin quinn_client \
  2>&1 | grep -E "^(error|warning: unused|   Compiling|    Finished)" || true

SERVER_BIN="$REPO_ROOT/target/release/quac_server"
CLIENT_BIN="$REPO_ROOT/target/release/quinn_client"

# Start server.
"$SERVER_BIN" --listen "$ADDR" --tiles 1 --mode combined --threads 2 &
SERVER_PID=$!

CLIENT_PID=""
cleanup() {
  [[ -n "$CLIENT_PID" ]] && kill -INT "$CLIENT_PID" 2>/dev/null || true
  [[ -n "$CLIENT_PID" ]] && wait "$CLIENT_PID" 2>/dev/null || true
  kill -INT "$SERVER_PID" 2>/dev/null || true
  wait "$SERVER_PID" 2>/dev/null || true
}
trap cleanup EXIT

# Wait for the server's QUIC listener to be ready (TCP/UDP port check).
PORT="${ADDR##*:}"
deadline=$((SECONDS + 30))
while (( SECONDS < deadline )); do
  if ss -ulnH 2>/dev/null | grep -qE ":${PORT}([^0-9]|$)"; then
    break
  fi
  sleep 0.05
done
echo "Server ready (pid=$SERVER_PID)." >&2

# Start the client in the background; it will run for the full warmup + perf window.
TOTAL_CLIENT_SECS=$(( WARMUP_SECS + PERF_DURATION + 5 ))
"$CLIENT_BIN" \
  --server "$ADDR" \
  --connections 16 \
  --streams 64 \
  --duration "$TOTAL_CLIENT_SECS" \
  --threads 4 &
CLIENT_PID=$!
echo "Client running (pid=$CLIENT_PID). Warming up ${WARMUP_SECS}s…" >&2
sleep "$WARMUP_SECS"

echo "Recording ${PERF_DURATION}s of perf data (server pid=$SERVER_PID)…" >&2
set +e
perf record -F "$PERF_FREQ" -g -p "$SERVER_PID" -o "$PERF_DATA" -- sleep "$PERF_DURATION"
perf_rc=$?
set -e

kill -INT "$CLIENT_PID" 2>/dev/null || true
wait "$CLIENT_PID" 2>/dev/null || true
CLIENT_PID=""

if [[ $perf_rc -ne 0 ]]; then
  echo "error: perf record exited $perf_rc" >&2
  exit "$perf_rc"
fi

cleanup
trap - EXIT

echo "" >&2
echo "=== Top hotspots (quac_server) ===" >&2
# shellcheck source=/dev/null
source "$REPO_ROOT/scripts/_socket_bench_profile_helpers.sh"
socket_bench_perf_report "$PERF_DATA"

echo "" >&2
socket_bench_perf_to_svg "$PERF_DATA" "$SVG" || true
