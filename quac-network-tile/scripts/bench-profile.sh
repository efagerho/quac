#!/usr/bin/env bash
#
# Build quac-network-tile examples and run four benchmark profiles:
#   1. tile-bench-sender --mode rate      + tile-bench-receiver --mode count   (--socket os)
#   2. tile-bench-sender --mode pingpong  + tile-bench-receiver --mode reflect  (--socket os)
#   3. tile-bench-sender --mode rate      + tile-bench-receiver --mode count   (--socket iouring)
#   4. tile-bench-sender --mode pingpong  + tile-bench-receiver --mode reflect  (--socket iouring)
#
# For each run, perf attaches to the receiver process and writes a call-graph
# profile to OUTDIR/.
#
# Usage:
#   ./bench-profile.sh [--duration N] [--rate PPS] [--size BYTES]
#                      [--threads N] [--window N] [--outdir DIR]
#
# Requires: perf (linux-perf / perf-tools package)
#
# Output (per run): perf-output/tile/perf-{os,iouring}-{count,reflect}.data + .svg flamegraph.
#
# Requires inferno (https://github.com/jonhoo/inferno) for flamegraphs:
#   cargo install inferno
#
# Viewing results:
#   perf report -i perf-output/tile/perf-os-count.data
#   xdg-open perf-output/tile/perf-iouring-reflect.svg

set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────────────────

DURATION=15       # seconds per run (sender runs for DURATION-2, receiver for DURATION)
RATE=1000000      # target PPS for rate mode (per sender thread)
SIZE=64           # UDP payload bytes
THREADS=1         # sender and receiver thread count
WINDOW=4          # in-flight packets for pingpong mode
PERF_FREQ=999     # perf sampling frequency in Hz
PORT_OS_RATE=49994
PORT_OS_PINGPONG=49995
PORT_IOR_RATE=49996
PORT_IOR_PINGPONG=49997
OUTDIR="perf-output/tile"

# ── Argument parsing ───────────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
    case "$1" in
        --duration) DURATION="$2"; shift 2 ;;
        --rate)     RATE="$2";     shift 2 ;;
        --size)     SIZE="$2";     shift 2 ;;
        --threads)  THREADS="$2";  shift 2 ;;
        --window)   WINDOW="$2";   shift 2 ;;
        --outdir)   OUTDIR="$2";   shift 2 ;;
        --help|-h)
            sed -n '2,/^$/p' "$0" | grep '^#' | sed 's/^# \?//'
            exit 0 ;;
        *) echo "unknown arg: $1" >&2; exit 1 ;;
    esac
done

# ── Preflight ─────────────────────────────────────────────────────────────────

if ! command -v perf &>/dev/null; then
    echo "error: 'perf' not found — install linux-perf / perf-tools" >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKSPACE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
mkdir -p "$OUTDIR"
OUTDIR="$(cd "$OUTDIR" && pwd)"

# ── Build ─────────────────────────────────────────────────────────────────────
# Force frame pointers so perf's default fp unwinder produces complete stacks.

echo "==> Building examples (force-frame-pointers, release) …"
RUSTFLAGS="-C force-frame-pointers=yes" \
    cargo build --release --examples -p quac-network-tile \
        --manifest-path "$SCRIPT_DIR/Cargo.toml"

RECEIVER="$WORKSPACE_DIR/target/release/examples/tile-bench-receiver"
SENDER="$WORKSPACE_DIR/target/release/examples/tile-bench-sender"

# ── Helpers ───────────────────────────────────────────────────────────────────

cleanup() {
    jobs -p | xargs -r kill 2>/dev/null || true
}
trap cleanup EXIT

# Wait up to $1 seconds for port $2 to become bound on loopback.
wait_for_port() {
    local timeout="$1" port="$2" i=0
    while (( i < timeout * 10 )); do
        if ss -ulnH "sport = :$port" | grep -q "$port" 2>/dev/null; then
            return 0
        fi
        sleep 0.1
        (( i++ ))
    done
    echo "warning: port $port did not appear bound after ${timeout}s" >&2
    return 1
}

print_section() {
    echo
    echo "══════════════════════════════════════════════════════"
    echo "  $*"
    echo "══════════════════════════════════════════════════════"
}

# Pick the first available flamegraph backend, or print a hint.
flamegraph_cmd() {
    if command -v inferno-collapse-perf &>/dev/null \
            && command -v inferno-flamegraph &>/dev/null; then
        echo "inferno"
    elif command -v stackcollapse-perf.pl &>/dev/null \
            && command -v flamegraph.pl &>/dev/null; then
        echo "flamegraph-pl"
    else
        echo ""
    fi
}

# render_flamegraph <perf.data> <out.svg> <title>
render_flamegraph() {
    local data="$1" svg="$2" title="$3"
    local backend
    backend="$(flamegraph_cmd)"
    if [[ -z "$backend" ]]; then
        echo "  (skipping flamegraph — install 'inferno' or Brendan Gregg's FlameGraph)"
        return
    fi
    case "$backend" in
        inferno)
            perf script -i "$data" 2>/dev/null \
                | inferno-collapse-perf \
                | inferno-flamegraph --title "$title" > "$svg"
            ;;
        flamegraph-pl)
            perf script -i "$data" 2>/dev/null \
                | stackcollapse-perf.pl \
                | flamegraph.pl --title "$title" > "$svg"
            ;;
    esac
    echo "  Flamegraph:    $svg"
}

# ── Run 1: os / rate / count ──────────────────────────────────────────────────

print_section "[1/4] --socket os  sender --mode rate  ×  receiver --mode count"
echo "  duration=${DURATION}s  rate=${RATE} pps  size=${SIZE} B  threads=${THREADS}"

"$RECEIVER" \
    --bind "127.0.0.1:${PORT_OS_RATE}" \
    --socket os \
    --threads "$THREADS" \
    --mode count \
    --duration "$DURATION" &
RX_PID=$!

wait_for_port 5 "$PORT_OS_RATE"

perf record \
    -g -F "$PERF_FREQ" \
    -p "$RX_PID" \
    -o "$OUTDIR/perf-os-count.data" \
    -- sleep "$DURATION" &
PERF_PID=$!

"$SENDER" \
    --target "127.0.0.1:${PORT_OS_RATE}" \
    --socket os \
    --threads "$THREADS" \
    --mode rate \
    --rate "$RATE" \
    --size "$SIZE" \
    --duration $(( DURATION - 2 ))

wait "$RX_PID"  || true
wait "$PERF_PID" || true

echo
echo "  Profile:       $OUTDIR/perf-os-count.data"
render_flamegraph \
    "$OUTDIR/perf-os-count.data" \
    "$OUTDIR/perf-os-count.svg" \
    "tile-bench-receiver --socket os --mode count (rate=${RATE}pps size=${SIZE}B threads=${THREADS})"

# ── Run 2: os / pingpong / reflect ────────────────────────────────────────────

print_section "[2/4] --socket os  sender --mode pingpong  ×  receiver --mode reflect"
echo "  duration=${DURATION}s  window=${WINDOW}  size=${SIZE} B  threads=${THREADS}"

"$RECEIVER" \
    --bind "127.0.0.1:${PORT_OS_PINGPONG}" \
    --socket os \
    --threads "$THREADS" \
    --mode reflect \
    --duration "$DURATION" &
RX_PID=$!

wait_for_port 5 "$PORT_OS_PINGPONG"

perf record \
    -g -F "$PERF_FREQ" \
    -p "$RX_PID" \
    -o "$OUTDIR/perf-os-reflect.data" \
    -- sleep "$DURATION" &
PERF_PID=$!

"$SENDER" \
    --target "127.0.0.1:${PORT_OS_PINGPONG}" \
    --socket os \
    --threads "$THREADS" \
    --mode pingpong \
    --window "$WINDOW" \
    --size "$SIZE" \
    --duration $(( DURATION - 2 ))

wait "$RX_PID"  || true
wait "$PERF_PID" || true

echo
echo "  Profile:       $OUTDIR/perf-os-reflect.data"
render_flamegraph \
    "$OUTDIR/perf-os-reflect.data" \
    "$OUTDIR/perf-os-reflect.svg" \
    "tile-bench-receiver --socket os --mode reflect (window=${WINDOW} size=${SIZE}B threads=${THREADS})"

# ── Run 3: iouring / rate / count ─────────────────────────────────────────────

print_section "[3/4] --socket iouring  sender --mode rate  ×  receiver --mode count"
echo "  duration=${DURATION}s  rate=${RATE} pps  size=${SIZE} B  threads=${THREADS}"

"$RECEIVER" \
    --bind "127.0.0.1:${PORT_IOR_RATE}" \
    --socket iouring \
    --threads "$THREADS" \
    --mode count \
    --duration "$DURATION" &
RX_PID=$!

wait_for_port 5 "$PORT_IOR_RATE"

perf record \
    -g -F "$PERF_FREQ" \
    -p "$RX_PID" \
    -o "$OUTDIR/perf-iouring-count.data" \
    -- sleep "$DURATION" &
PERF_PID=$!

"$SENDER" \
    --target "127.0.0.1:${PORT_IOR_RATE}" \
    --socket iouring \
    --threads "$THREADS" \
    --mode rate \
    --rate "$RATE" \
    --size "$SIZE" \
    --duration $(( DURATION - 2 ))

wait "$RX_PID"  || true
wait "$PERF_PID" || true

echo
echo "  Profile:       $OUTDIR/perf-iouring-count.data"
render_flamegraph \
    "$OUTDIR/perf-iouring-count.data" \
    "$OUTDIR/perf-iouring-count.svg" \
    "tile-bench-receiver --socket iouring --mode count (rate=${RATE}pps size=${SIZE}B threads=${THREADS})"

# ── Run 4: iouring / pingpong / reflect ───────────────────────────────────────

print_section "[4/4] --socket iouring  sender --mode pingpong  ×  receiver --mode reflect"
echo "  duration=${DURATION}s  window=${WINDOW}  size=${SIZE} B  threads=${THREADS}"

"$RECEIVER" \
    --bind "127.0.0.1:${PORT_IOR_PINGPONG}" \
    --socket iouring \
    --threads "$THREADS" \
    --mode reflect \
    --duration "$DURATION" &
RX_PID=$!

wait_for_port 5 "$PORT_IOR_PINGPONG"

perf record \
    -g -F "$PERF_FREQ" \
    -p "$RX_PID" \
    -o "$OUTDIR/perf-iouring-reflect.data" \
    -- sleep "$DURATION" &
PERF_PID=$!

"$SENDER" \
    --target "127.0.0.1:${PORT_IOR_PINGPONG}" \
    --socket iouring \
    --threads "$THREADS" \
    --mode pingpong \
    --window "$WINDOW" \
    --size "$SIZE" \
    --duration $(( DURATION - 2 ))

wait "$RX_PID"  || true
wait "$PERF_PID" || true

echo
echo "  Profile:       $OUTDIR/perf-iouring-reflect.data"
render_flamegraph \
    "$OUTDIR/perf-iouring-reflect.data" \
    "$OUTDIR/perf-iouring-reflect.svg" \
    "tile-bench-receiver --socket iouring --mode reflect (window=${WINDOW} size=${SIZE}B threads=${THREADS})"

# ── Summary ───────────────────────────────────────────────────────────────────

echo
echo "==> Done. Profiles in: $OUTDIR/"
ls -1 "$OUTDIR"/perf-*.{data,svg} 2>/dev/null | sed 's/^/   /' || true
echo
echo "Inspect with:"
echo "   perf report -i $OUTDIR/perf-os-count.data"
echo "   perf report -i $OUTDIR/perf-os-reflect.data"
echo "   perf report -i $OUTDIR/perf-iouring-count.data"
echo "   perf report -i $OUTDIR/perf-iouring-reflect.data"
