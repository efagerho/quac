#!/usr/bin/env bash
#
# Build quac-socket-os and quac-socket-iouring examples and run a head-to-head
# performance comparison across several scenarios.
#
# Usage:
#   ./scripts/compare.sh [--duration N] [--threads N] [--size BYTES] [--outdir DIR]
#
# Requires: ss (iproute2)
# Output: plain-text table printed to stdout; raw logs saved to OUTDIR.

set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────────────────

DURATION=15
THREADS=1
SIZE=64
OUTDIR="/tmp/quac-compare"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --duration) DURATION="$2"; shift 2 ;;
        --threads)  THREADS="$2";  shift 2 ;;
        --size)     SIZE="$2";     shift 2 ;;
        --outdir)   OUTDIR="$2";   shift 2 ;;
        --help|-h)
            sed -n '2,/^$/p' "$0" | grep '^#' | sed 's/^# \?//'; exit 0 ;;
        *) echo "unknown arg: $1" >&2; exit 1 ;;
    esac
done

WORKSPACE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mkdir -p "$OUTDIR"

# ── Build ─────────────────────────────────────────────────────────────────────

echo "==> Building quac-socket-os examples …"
RUSTFLAGS="-C force-frame-pointers=yes" \
    cargo build --release --examples -p quac-socket-os \
        --manifest-path "$WORKSPACE/Cargo.toml" 2>&1 | grep -v "^$"

BIN="$WORKSPACE/target/release/examples"
cp "$BIN/os-bench-receiver" "$OUTDIR/os-receiver"
cp "$BIN/os-bench-sender"   "$OUTDIR/os-sender"

echo "==> Building quac-socket-iouring examples …"
RUSTFLAGS="-C force-frame-pointers=yes" \
    cargo build --release --examples -p quac-socket-iouring \
        --manifest-path "$WORKSPACE/Cargo.toml" 2>&1 | grep -v "^$"

cp "$BIN/iouring-bench-receiver" "$OUTDIR/iouring-receiver"
cp "$BIN/iouring-bench-sender"   "$OUTDIR/iouring-sender"

# ── Helpers ───────────────────────────────────────────────────────────────────

cleanup() { jobs -p | xargs -r kill 2>/dev/null || true; }
trap cleanup EXIT

wait_for_port() {
    local timeout="$1" port="$2" i=0
    while (( i < timeout * 10 )); do
        ss -ulnH "sport = :$port" 2>/dev/null | grep -q "$port" && return 0
        sleep 0.1; (( ++i ))
    done
    echo "warning: port $port not bound after ${timeout}s" >&2
    return 1
}

# run_rate <label> <receiver-bin> <sender-bin> <port> <log-prefix>
# Prints: RX Mpps
run_rate() {
    local label="$1" rx_bin="$2" tx_bin="$3" port="$4" log="$5"
    local rx_dur=$(( DURATION ))
    local tx_dur=$(( DURATION - 2 ))

    "$rx_bin" --bind "127.0.0.1:$port" --threads "$THREADS" \
              --mode count --duration "$rx_dur" \
              > "$log.rx" 2>&1 &
    local rx_pid=$!
    wait_for_port 5 "$port"

    "$tx_bin" --target "127.0.0.1:$port" --threads "$THREADS" \
              --mode rate --rate 0 --size "$SIZE" \
              --duration "$tx_dur" \
              > "$log.tx" 2>&1

    wait "$rx_pid" 2>/dev/null || true

    # Parse "final: total_rx=N" from receiver log
    local total
    total=$(grep "^final:" "$log.rx" | grep -oP 'total_rx=\K[0-9]+' || echo 0)
    local elapsed=$(( rx_dur - 1 ))   # receiver starts ~1s before sender stops
    awk -v n="$total" -v d="$elapsed" 'BEGIN { printf "%.3f", n/d/1e6 }'
}

# run_pingpong <label> <receiver-bin> <sender-bin> <port> <window> <log-prefix>
# Prints: TX Mpps, avg RTT us, max RTT us
run_pingpong() {
    local label="$1" rx_bin="$2" tx_bin="$3" port="$4" win="$5" log="$6"
    local rx_dur=$(( DURATION ))
    local tx_dur=$(( DURATION - 2 ))

    "$rx_bin" --bind "127.0.0.1:$port" --threads "$THREADS" \
              --mode reflect --duration "$rx_dur" \
              > "$log.rx" 2>&1 &
    local rx_pid=$!
    wait_for_port 5 "$port"

    "$tx_bin" --target "127.0.0.1:$port" --threads "$THREADS" \
              --mode pingpong --window "$win" --size "$SIZE" \
              --duration "$tx_dur" \
              > "$log.tx" 2>&1

    wait "$rx_pid" 2>/dev/null || true

    # Parse "final: total_tx=N total_rx=M avg_rtt=Aus max_rtt=Bus"
    local line
    line=$(grep "^final:" "$log.tx" || true)
    local tx avg max
    tx=$(echo "$line"  | grep -oP 'total_tx=\K[0-9]+'  || echo 0)
    avg=$(echo "$line" | grep -oP 'avg_rtt=\K[0-9]+'   || echo 0)
    max=$(echo "$line" | grep -oP 'max_rtt=\K[0-9]+'   || echo 0)
    local elapsed=$(( tx_dur ))
    local mpps
    mpps=$(awk -v n="$tx" -v d="$elapsed" 'BEGIN { printf "%.3f", n/d/1e6 }')
    echo "$mpps $avg $max"
}

# ── Scenarios ─────────────────────────────────────────────────────────────────

PORT=49994   # base port; each scenario uses PORT+n

print_header() {
    echo ""
    printf "%-38s  %s\n" "$1" "$2"
    printf '%0.s─' {1..70}; echo
}

echo ""
echo "════════════════════════════════════════════════════════════════════"
echo "  quac-socket performance comparison"
echo "  size=${SIZE}B  threads=${THREADS}  duration=${DURATION}s"
echo "════════════════════════════════════════════════════════════════════"

# ── 1. Max RX throughput (unlimited sender) ───────────────────────────────────

print_header "Scenario 1 — max RX throughput (sender uncapped)" "RX (Mpps)"

OS_RATE=$(run_rate "os" "$OUTDIR/os-receiver" "$OUTDIR/os-sender" \
          $((PORT+0)) "$OUTDIR/s1-os")
printf "  %-34s  %s\n" "quac-socket-os" "$OS_RATE"

IOR_RATE=$(run_rate "iouring" "$OUTDIR/iouring-receiver" "$OUTDIR/iouring-sender" \
           $((PORT+1)) "$OUTDIR/s1-iouring")
printf "  %-34s  %s\n" "quac-socket-iouring" "$IOR_RATE"

DELTA=$(awk -v a="$IOR_RATE" -v b="$OS_RATE" \
        'BEGIN { printf "%+.1f%%", (a-b)/b*100 }')
printf "  %-34s  %s\n" "delta (iouring vs os)" "$DELTA"

# ── 2. Pingpong window=1 (min latency) ───────────────────────────────────────

print_header "Scenario 2 — pingpong window=1 (min latency)" \
             "TX (Mpps)   avg RTT   max RTT"

read OS_TX  OS_AVG  OS_MAX  <<< $(run_pingpong "os" \
    "$OUTDIR/os-receiver" "$OUTDIR/os-sender" \
    $((PORT+2)) 1 "$OUTDIR/s2-os")
printf "  %-34s  %-10s  %-8s  %s\n" "quac-socket-os" \
    "$OS_TX Mpps" "${OS_AVG}us" "${OS_MAX}us"

read IOR_TX IOR_AVG IOR_MAX <<< $(run_pingpong "iouring" \
    "$OUTDIR/iouring-receiver" "$OUTDIR/iouring-sender" \
    $((PORT+3)) 1 "$OUTDIR/s2-iouring")
printf "  %-34s  %-10s  %-8s  %s\n" "quac-socket-iouring" \
    "$IOR_TX Mpps" "${IOR_AVG}us" "${IOR_MAX}us"

RTT_DELTA=$(awk -v a="$IOR_AVG" -v b="$OS_AVG" \
            'BEGIN { printf "%+.1f%%", (a-b)/b*100 }')
printf "  %-34s  %s avg RTT\n" "delta (iouring vs os)" "$RTT_DELTA"

# ── 3. Pingpong window=4 ──────────────────────────────────────────────────────

print_header "Scenario 3 — pingpong window=4" \
             "TX (Mpps)   avg RTT   max RTT"

read OS_TX  OS_AVG  OS_MAX  <<< $(run_pingpong "os" \
    "$OUTDIR/os-receiver" "$OUTDIR/os-sender" \
    $((PORT+4)) 4 "$OUTDIR/s3-os")
printf "  %-34s  %-10s  %-8s  %s\n" "quac-socket-os" \
    "$OS_TX Mpps" "${OS_AVG}us" "${OS_MAX}us"

read IOR_TX IOR_AVG IOR_MAX <<< $(run_pingpong "iouring" \
    "$OUTDIR/iouring-receiver" "$OUTDIR/iouring-sender" \
    $((PORT+5)) 4 "$OUTDIR/s3-iouring")
printf "  %-34s  %-10s  %-8s  %s\n" "quac-socket-iouring" \
    "$IOR_TX Mpps" "${IOR_AVG}us" "${IOR_MAX}us"

RTT_DELTA=$(awk -v a="$IOR_AVG" -v b="$OS_AVG" \
            'BEGIN { printf "%+.1f%%", (a-b)/b*100 }')
TX_DELTA=$(awk -v a="$IOR_TX" -v b="$OS_TX" \
           'BEGIN { printf "%+.1f%%", (a-b)/b*100 }')
printf "  %-34s  %s TX,  %s avg RTT\n" "delta (iouring vs os)" \
    "$TX_DELTA" "$RTT_DELTA"

# ── 4. Pingpong window=16 ─────────────────────────────────────────────────────

print_header "Scenario 4 — pingpong window=16" \
             "TX (Mpps)   avg RTT   max RTT"

read OS_TX  OS_AVG  OS_MAX  <<< $(run_pingpong "os" \
    "$OUTDIR/os-receiver" "$OUTDIR/os-sender" \
    $((PORT+6)) 16 "$OUTDIR/s4-os")
printf "  %-34s  %-10s  %-8s  %s\n" "quac-socket-os" \
    "$OS_TX Mpps" "${OS_AVG}us" "${OS_MAX}us"

read IOR_TX IOR_AVG IOR_MAX <<< $(run_pingpong "iouring" \
    "$OUTDIR/iouring-receiver" "$OUTDIR/iouring-sender" \
    $((PORT+7)) 16 "$OUTDIR/s4-iouring")
printf "  %-34s  %-10s  %-8s  %s\n" "quac-socket-iouring" \
    "$IOR_TX Mpps" "${IOR_AVG}us" "${IOR_MAX}us"

RTT_DELTA=$(awk -v a="$IOR_AVG" -v b="$OS_AVG" \
            'BEGIN { printf "%+.1f%%", (a-b)/b*100 }')
TX_DELTA=$(awk -v a="$IOR_TX" -v b="$OS_TX" \
           'BEGIN { printf "%+.1f%%", (a-b)/b*100 }')
printf "  %-34s  %s TX,  %s avg RTT\n" "delta (iouring vs os)" \
    "$TX_DELTA" "$RTT_DELTA"

echo ""
echo "Raw logs: $OUTDIR/s*.{rx,tx}"
echo ""
