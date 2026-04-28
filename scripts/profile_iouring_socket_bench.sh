#!/usr/bin/env bash
# Profile CPU of iouring_socket_bench in pong mode while blaster sends ping traffic.
#
# Blaster: 4 threads, 16-byte payload, batch-size 4, ping (send+recv) mode.
# Profiles only the pong server process.
#
# Usage:
#   ./scripts/profile_iouring_socket_bench.sh
#
# Env overrides:
#   PORT            UDP port (default: 4101)
#   WARMUP_SECS     seconds of traffic before perf starts (default: 3)
#   PERF_DURATION   seconds perf records (default: 10)
#   PERF_FREQ       sampling frequency in Hz (default: 997)
#   PERF_DATA       output perf.data path
#   SVG             output flamegraph SVG path
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=/dev/null
source "$REPO_ROOT/scripts/_socket_bench_profile_helpers.sh"

OUT_DIR="$REPO_ROOT/scripts"

PORT="${PORT:-4101}"
ADDR="127.0.0.1:$PORT"
WARMUP_SECS="${WARMUP_SECS:-3}"
PERF_DURATION="${PERF_DURATION:-10}"
PERF_FREQ="${PERF_FREQ:-997}"
PERF_DATA="${PERF_DATA:-$OUT_DIR/perf_iouring_socket_bench.data}"
SVG="${SVG:-$OUT_DIR/flamegraph_iouring_socket_bench.svg}"

BLASTER_THREADS=4
BLASTER_PAYLOAD=16
BLASTER_BATCH=4

socket_bench_require_linux

echo "=== iouring_socket_bench pong profile ===" >&2
echo "addr=$ADDR  blaster: threads=$BLASTER_THREADS payload=${BLASTER_PAYLOAD}B batch=$BLASTER_BATCH" >&2
echo "warmup=${WARMUP_SECS}s  perf=${PERF_DURATION}s  freq=${PERF_FREQ}Hz" >&2
echo "svg=$SVG  perf_data=$PERF_DATA" >&2
echo "" >&2

cd "$REPO_ROOT"
socket_bench_build "$REPO_ROOT"

PONG_BIN="$REPO_ROOT/target/release/iouring_socket_bench"
BLASTER_BIN="$REPO_ROOT/target/release/blaster"

# Start pong server.
"$PONG_BIN" pong --address "$ADDR" &
PONG_PID=$!

BLASTER_PID=""
cleanup() {
  [[ -n "$BLASTER_PID" ]] && kill -INT "$BLASTER_PID" 2>/dev/null || true
  [[ -n "$BLASTER_PID" ]] && wait "$BLASTER_PID" 2>/dev/null || true
  kill -INT "$PONG_PID" 2>/dev/null || true
  wait "$PONG_PID" 2>/dev/null || true
}
trap cleanup EXIT

socket_bench_wait_udp "$PORT"
echo "Pong server ready (pid=$PONG_PID)." >&2

# Start blaster.
"$BLASTER_BIN" \
  --address "$ADDR" \
  --threads "$BLASTER_THREADS" \
  --payload-size "$BLASTER_PAYLOAD" \
  --batch-size "$BLASTER_BATCH" \
  ping &
BLASTER_PID=$!
echo "Blaster running (pid=$BLASTER_PID). Warming up ${WARMUP_SECS}s…" >&2
sleep "$WARMUP_SECS"

echo "Recording ${PERF_DURATION}s of perf data (pid=$PONG_PID)…" >&2
set +e
perf record -F "$PERF_FREQ" -g -p "$PONG_PID" -o "$PERF_DATA" -- sleep "$PERF_DURATION"
perf_rc=$?
set -e

kill -INT "$BLASTER_PID" 2>/dev/null || true
wait "$BLASTER_PID" 2>/dev/null || true
BLASTER_PID=""

if [[ $perf_rc -ne 0 ]]; then
  echo "error: perf record exited $perf_rc" >&2
  exit "$perf_rc"
fi

cleanup
trap - EXIT

echo "" >&2
echo "=== Top hotspots (iouring_socket_bench pong) ===" >&2
socket_bench_perf_report "$PERF_DATA"

echo "" >&2
socket_bench_perf_to_svg "$PERF_DATA" "$SVG" || true
