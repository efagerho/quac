#!/usr/bin/env bash
# Profile CPU of quic_pong_tile while quic_bench runs connect-churn (handshake open/close loop).
#
# Runs WARMUP_ROUNDS complete bench rounds first (same flags as the profiling run) to:
#   - warm up the allocator free-lists, tile queues, and connection state
#   - detect memory leaks via RSS tracking across rounds
# Then runs a final round under perf record to capture the steady-state profile.
#
# Requires: Linux, perf(1), sudo if perf needs it (see kernel.perf_event_paranoid).
# Optional: inferno-collapse-perf + inferno-flamegraph, or FlameGraph stackcollapse-perf.pl + flamegraph.pl
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=/dev/null
source "$REPO_ROOT/scripts/_quic_pong_profile_helpers.sh"

OUT_DIR="$REPO_ROOT/scripts"

SVG="${SVG:-$OUT_DIR/flamegraph_quic_pong_tile_connect_churn.svg}"
PERF_DATA="${PERF_DATA:-$OUT_DIR/perf_quic_pong_tile_connect_churn.data}"

PORT="${PORT:-4433}"
ADDR="${ADDR:-127.0.0.1:$PORT}"
# Number of network+engine tiles (passed as --threads to quic_pong_tile).
TILE_THREADS="${TILE_THREADS:-1}"
# Tokio worker threads for quic_bench.
THREADS="${THREADS:-8}"
DURATION="${DURATION:-30}"
WARMUP_ROUNDS="${WARMUP_ROUNDS:-10}"
DRAIN_SECS="${DRAIN_SECS:-2}"
PERF_FREQ="${PERF_FREQ:-997}"

quic_pong_profile_require_linux

echo "=== quic_pong_tile profile (connect-churn load) ===" >&2
echo "addr=$ADDR tile_threads=$TILE_THREADS bench_threads=$THREADS duration=${DURATION}s port=$PORT" >&2
echo "warmup_rounds=$WARMUP_ROUNDS drain_secs=${DRAIN_SECS}s" >&2
echo "svg=$SVG perf_data=$PERF_DATA" >&2

cd "$REPO_ROOT"
quic_pong_profile_build "$REPO_ROOT"

PONG="$REPO_ROOT/target/release/quic_pong_tile"
BENCH="$REPO_ROOT/target/release/quic_bench"

echo "" >&2
echo "Starting quic_pong_tile (${TILE_THREADS} tile(s))…" >&2
echo "(may need: echo -1 | sudo tee /proc/sys/kernel/perf_event_paranoid)" >&2
echo "" >&2

"$PONG" --port "$PORT" --threads "$TILE_THREADS" --tokio-threads 1 &
PONG_PID=$!

BENCH_PID=""
cleanup() {
  if [[ -n "$BENCH_PID" ]] && kill -0 "$BENCH_PID" 2>/dev/null; then
    kill -INT "$BENCH_PID" 2>/dev/null || true
    wait "$BENCH_PID" 2>/dev/null || true
  fi
  if kill -0 "$PONG_PID" 2>/dev/null; then
    kill -INT "$PONG_PID" 2>/dev/null || true
    wait "$PONG_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

quic_pong_profile_wait_udp "$PORT"

# ── Warmup rounds (same flags as the profiling run) ───────────────────────────
echo "Running $WARMUP_ROUNDS warmup rounds (duration=${DURATION}s each)…" >&2
quic_pong_warmup_rounds "$PONG_PID" "$WARMUP_ROUNDS" "$DRAIN_SECS" \
  "$BENCH" connect-churn \
    --addr "$ADDR" \
    --threads "$THREADS" \
    --duration "$DURATION"

echo "" >&2
echo "Warmup complete. Starting profiling run (duration=${DURATION}s)…" >&2

# ── Profiling run ─────────────────────────────────────────────────────────────
set +e
perf record -F "$PERF_FREQ" -g -p "$PONG_PID" -o "$PERF_DATA" -- \
  "$BENCH" connect-churn \
    --addr "$ADDR" \
    --threads "$THREADS" \
    --duration "$DURATION"
perf_rc=$?
set -e

BENCH_PID=""

if [[ $perf_rc -ne 0 ]]; then
  echo "error: perf record or quic_bench exited with status $perf_rc" >&2
  exit "$perf_rc"
fi

cleanup
trap - EXIT

if quic_pong_profile_perf_to_svg "$PERF_DATA" "$SVG"; then
  echo "" >&2
  echo "Flamegraph written to: $SVG" >&2
else
  exit 1
fi
