#!/usr/bin/env bash
#
# veth-based variant of scripts/compare.sh. Builds the quac-socket-os,
# quac-socket-iouring, and quac-network-tile examples and runs a four-way
# matrix across a veth pair living in two separate network namespaces:
#
#   raw os         -- os-bench-{sender,receiver}
#   raw iouring    -- iouring-bench-{sender,receiver}
#   tile os        -- tile-bench-{sender,receiver} --socket os
#   tile iouring   -- tile-bench-{sender,receiver} --socket iouring
#
# Each scenario (max throughput + pingpong window=1/4/16) runs all four
# backends and reports per-backend numbers plus a couple of useful deltas.
# This bypasses the kernel loopback shortcut that scripts/compare.sh
# exercises by default — see scripts/setup-veth.sh.
#
# Usage:
#   sudo ./scripts/compare-veth.sh [--duration N] [--threads N] [--size BYTES] [--outdir DIR]
#
# Prerequisite: scripts/setup-veth.sh --up (must be run first).
# Requires: ss (iproute2), ip (iproute2), root.
# Output: plain-text table printed to stdout; raw logs saved to OUTDIR.

set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────────────────

DURATION=15
THREADS=1
SIZE=64
OUTDIR="/tmp/quac-compare-veth"

NS_RX="${NS_RX:-quac-rx}"
NS_TX="${NS_TX:-quac-tx}"
RX_IP="${RX_IP:-10.99.0.1}"

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

if [[ $EUID -ne 0 ]]; then
    echo "error: must run as root (try: sudo $0 $*)" >&2
    exit 1
fi

# ── Pre-flight: netns must be set up by scripts/setup-veth.sh ─────────────────

if ! ip netns list | awk '{print $1}' | grep -qx "$NS_RX" \
   || ! ip netns list | awk '{print $1}' | grep -qx "$NS_TX"; then
    echo "error: netns ${NS_RX}/${NS_TX} not set up." >&2
    echo "run: sudo scripts/setup-veth.sh --up" >&2
    exit 1
fi

WORKSPACE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mkdir -p "$OUTDIR"

# ── Build ─────────────────────────────────────────────────────────────────────
#
# Cargo lives in the calling user's ~/.cargo/bin and isn't in root's PATH
# under sudo. Run the build as $SUDO_USER through their login shell so PATH
# is set up correctly and target/ stays user-owned. If this script wasn't
# invoked via sudo (e.g. running directly as root or in a container with
# cargo on root's PATH), fall back to running cargo in the current shell.

run_build() {
    local cmd="$1"
    if [[ -n "${SUDO_USER:-}" ]]; then
        sudo -u "$SUDO_USER" -- bash -lc "$cmd" 2>&1 | grep -v "^$"
    else
        bash -c "$cmd" 2>&1 | grep -v "^$"
    fi
}

if ! run_build "command -v cargo" >/dev/null; then
    echo "error: cargo not found." >&2
    if [[ -n "${SUDO_USER:-}" ]]; then
        echo "  Tried to build as user '$SUDO_USER' but cargo is not in their PATH." >&2
    fi
    echo "  Install rustup, or build the examples manually before re-running:" >&2
    echo "    cargo build --release --examples \\" >&2
    echo "      -p quac-socket-os -p quac-socket-iouring -p quac-network-tile" >&2
    exit 1
fi

echo "==> Building quac-socket-os examples …"
run_build "cd '$WORKSPACE' && RUSTFLAGS='-C force-frame-pointers=yes' \
    cargo build --release --examples -p quac-socket-os \
        --manifest-path '$WORKSPACE/Cargo.toml'"

BIN="$WORKSPACE/target/release/examples"
cp "$BIN/os-bench-receiver" "$OUTDIR/os-receiver"
cp "$BIN/os-bench-sender"   "$OUTDIR/os-sender"

echo "==> Building quac-socket-iouring examples …"
run_build "cd '$WORKSPACE' && RUSTFLAGS='-C force-frame-pointers=yes' \
    cargo build --release --examples -p quac-socket-iouring \
        --manifest-path '$WORKSPACE/Cargo.toml'"

cp "$BIN/iouring-bench-receiver" "$OUTDIR/iouring-receiver"
cp "$BIN/iouring-bench-sender"   "$OUTDIR/iouring-sender"

echo "==> Building quac-network-tile examples …"
run_build "cd '$WORKSPACE' && RUSTFLAGS='-C force-frame-pointers=yes' \
    cargo build --release --examples -p quac-network-tile \
        --manifest-path '$WORKSPACE/Cargo.toml'"

cp "$BIN/tile-bench-receiver" "$OUTDIR/tile-receiver"
cp "$BIN/tile-bench-sender"   "$OUTDIR/tile-sender"

# ── Helpers ───────────────────────────────────────────────────────────────────

cleanup() { jobs -p | xargs -r kill 2>/dev/null || true; }
trap cleanup EXIT

# Probes the receiver netns rather than the host because the receiver
# binds inside that netns; the host's `ss` cannot see netns-local sockets.
wait_for_port() {
    local timeout="$1" port="$2" i=0
    while (( i < timeout * 10 )); do
        ip netns exec "$NS_RX" ss -ulnH "sport = :$port" 2>/dev/null \
            | grep -q "$port" && return 0
        sleep 0.1; (( ++i ))
    done
    echo "warning: port $port not bound in netns ${NS_RX} after ${timeout}s" >&2
    return 1
}

# run_rate <label> <rx_bin> <tx_bin> <port> <log_prefix> [<extra_arg>...]
# Extra args are appended to BOTH the receiver and sender invocation —
# used to pass `--socket os` / `--socket iouring` to the tile binaries.
# Prints: RX Mpps
run_rate() {
    local label="$1" rx_bin="$2" tx_bin="$3" port="$4" log="$5"
    shift 5
    local -a extra=("$@")
    local rx_dur=$(( DURATION ))
    local tx_dur=$(( DURATION - 2 ))

    ip netns exec "$NS_RX" \
        "$rx_bin" --bind "$RX_IP:$port" --threads "$THREADS" \
                  --mode count --duration "$rx_dur" \
                  "${extra[@]}" \
                  > "$log.rx" 2>&1 &
    local rx_pid=$!
    wait_for_port 5 "$port"

    ip netns exec "$NS_TX" \
        "$tx_bin" --target "$RX_IP:$port" --threads "$THREADS" \
                  --mode rate --rate 0 --size "$SIZE" \
                  --duration "$tx_dur" \
                  "${extra[@]}" \
                  > "$log.tx" 2>&1

    wait "$rx_pid" 2>/dev/null || true

    local total
    total=$(grep "^final:" "$log.rx" | grep -oP 'total_rx=\K[0-9]+' || echo 0)
    local elapsed=$(( rx_dur - 1 ))
    awk -v n="$total" -v d="$elapsed" 'BEGIN { printf "%.3f", n/d/1e6 }'
}

# run_pingpong <label> <rx_bin> <tx_bin> <port> <window> <log_prefix> [<extra_arg>...]
# Prints: TX Mpps, avg RTT us, max RTT us
run_pingpong() {
    local label="$1" rx_bin="$2" tx_bin="$3" port="$4" win="$5" log="$6"
    shift 6
    local -a extra=("$@")
    local rx_dur=$(( DURATION ))
    local tx_dur=$(( DURATION - 2 ))

    ip netns exec "$NS_RX" \
        "$rx_bin" --bind "$RX_IP:$port" --threads "$THREADS" \
                  --mode reflect --duration "$rx_dur" \
                  "${extra[@]}" \
                  > "$log.rx" 2>&1 &
    local rx_pid=$!
    wait_for_port 5 "$port"

    ip netns exec "$NS_TX" \
        "$tx_bin" --target "$RX_IP:$port" --threads "$THREADS" \
                  --mode pingpong --window "$win" --size "$SIZE" \
                  --duration "$tx_dur" \
                  "${extra[@]}" \
                  > "$log.tx" 2>&1

    wait "$rx_pid" 2>/dev/null || true

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

# ── Output formatting ─────────────────────────────────────────────────────────

# print_header <title> <col1> [<col2> <col3>]
#
# Prints the scenario title, a horizontal rule, and a column-header row
# whose layout matches the data printf below ("  %-34s  %-10s  %-8s  %s"
# for 3-col, "  %-34s  %s" for 1-col). The title is on its own line so its
# variable length never throws off the column alignment.
print_header() {
    local title="$1"; shift
    echo ""
    echo "$title"
    printf '%0.s─' {1..70}; echo
    case $# in
        1) printf "  %-34s  %s\n" "" "$1" ;;
        3) printf "  %-34s  %-10s  %-8s  %s\n" "" "$1" "$2" "$3" ;;
    esac
}

pct_delta() {
    awk -v a="$1" -v b="$2" 'BEGIN {
        if (b+0 == 0) { print "n/a"; exit }
        printf "%+.1f%%", (a-b)/b*100
    }'
}

# ── Scenarios ─────────────────────────────────────────────────────────────────

PORT=49994   # base port; each scenario uses 4 consecutive ports

echo ""
echo "════════════════════════════════════════════════════════════════════"
echo "  quac-socket performance comparison (over veth)"
echo "  size=${SIZE}B  threads=${THREADS}  duration=${DURATION}s"
echo "  rx ns=${NS_RX} tx ns=${NS_TX} target=${RX_IP}"
echo "════════════════════════════════════════════════════════════════════"

# ── 1. Max RX throughput (unlimited sender) ───────────────────────────────────

print_header "Scenario 1 — max RX throughput (sender uncapped)" "RX (Mpps)"

RAW_OS=$(run_rate "raw-os"  \
    "$OUTDIR/os-receiver" "$OUTDIR/os-sender" \
    $((PORT+0)) "$OUTDIR/s1-raw-os")
printf "  %-34s  %s\n" "raw os" "$RAW_OS"

RAW_IOR=$(run_rate "raw-iouring" \
    "$OUTDIR/iouring-receiver" "$OUTDIR/iouring-sender" \
    $((PORT+1)) "$OUTDIR/s1-raw-iouring")
printf "  %-34s  %s\n" "raw iouring" "$RAW_IOR"

TILE_OS=$(run_rate "tile-os" \
    "$OUTDIR/tile-receiver" "$OUTDIR/tile-sender" \
    $((PORT+2)) "$OUTDIR/s1-tile-os" --socket os)
printf "  %-34s  %s\n" "tile os" "$TILE_OS"

TILE_IOR=$(run_rate "tile-iouring" \
    "$OUTDIR/tile-receiver" "$OUTDIR/tile-sender" \
    $((PORT+3)) "$OUTDIR/s1-tile-iouring" --socket iouring)
printf "  %-34s  %s\n" "tile iouring" "$TILE_IOR"

printf "  %-34s  %s\n" "delta (iouring vs os, tile)"   "$(pct_delta "$TILE_IOR" "$TILE_OS")"
printf "  %-34s  %s\n" "delta (tile vs raw, iouring)"  "$(pct_delta "$TILE_IOR" "$RAW_IOR")"

# ── 2. Pingpong window=1 (min latency) ───────────────────────────────────────

print_header "Scenario 2 — pingpong window=1 (min latency)" \
             "TX (Mpps)" "avg RTT" "max RTT"

read RAW_OS_TX  RAW_OS_AVG  RAW_OS_MAX  <<< $(run_pingpong "raw-os" \
    "$OUTDIR/os-receiver" "$OUTDIR/os-sender" \
    $((PORT+4)) 1 "$OUTDIR/s2-raw-os")
printf "  %-34s  %-10s  %-8s  %s\n" "raw os" \
    "$RAW_OS_TX Mpps" "${RAW_OS_AVG}us" "${RAW_OS_MAX}us"

read RAW_IOR_TX RAW_IOR_AVG RAW_IOR_MAX <<< $(run_pingpong "raw-iouring" \
    "$OUTDIR/iouring-receiver" "$OUTDIR/iouring-sender" \
    $((PORT+5)) 1 "$OUTDIR/s2-raw-iouring")
printf "  %-34s  %-10s  %-8s  %s\n" "raw iouring" \
    "$RAW_IOR_TX Mpps" "${RAW_IOR_AVG}us" "${RAW_IOR_MAX}us"

read TILE_OS_TX TILE_OS_AVG TILE_OS_MAX <<< $(run_pingpong "tile-os" \
    "$OUTDIR/tile-receiver" "$OUTDIR/tile-sender" \
    $((PORT+6)) 1 "$OUTDIR/s2-tile-os" --socket os)
printf "  %-34s  %-10s  %-8s  %s\n" "tile os" \
    "$TILE_OS_TX Mpps" "${TILE_OS_AVG}us" "${TILE_OS_MAX}us"

read TILE_IOR_TX TILE_IOR_AVG TILE_IOR_MAX <<< $(run_pingpong "tile-iouring" \
    "$OUTDIR/tile-receiver" "$OUTDIR/tile-sender" \
    $((PORT+7)) 1 "$OUTDIR/s2-tile-iouring" --socket iouring)
printf "  %-34s  %-10s  %-8s  %s\n" "tile iouring" \
    "$TILE_IOR_TX Mpps" "${TILE_IOR_AVG}us" "${TILE_IOR_MAX}us"

# At window=1 the run is RTT-bound, so TX deltas track avg-RTT deltas.
printf "  %-34s  %s avg RTT\n" "delta (iouring vs os, tile)" \
    "$(pct_delta "$TILE_IOR_AVG" "$TILE_OS_AVG")"
printf "  %-34s  %s avg RTT\n" "delta (tile vs raw, iouring)" \
    "$(pct_delta "$TILE_IOR_AVG" "$RAW_IOR_AVG")"

# ── 3. Pingpong window=4 ──────────────────────────────────────────────────────

print_header "Scenario 3 — pingpong window=4" \
             "TX (Mpps)" "avg RTT" "max RTT"

read RAW_OS_TX  RAW_OS_AVG  RAW_OS_MAX  <<< $(run_pingpong "raw-os" \
    "$OUTDIR/os-receiver" "$OUTDIR/os-sender" \
    $((PORT+8)) 4 "$OUTDIR/s3-raw-os")
printf "  %-34s  %-10s  %-8s  %s\n" "raw os" \
    "$RAW_OS_TX Mpps" "${RAW_OS_AVG}us" "${RAW_OS_MAX}us"

read RAW_IOR_TX RAW_IOR_AVG RAW_IOR_MAX <<< $(run_pingpong "raw-iouring" \
    "$OUTDIR/iouring-receiver" "$OUTDIR/iouring-sender" \
    $((PORT+9)) 4 "$OUTDIR/s3-raw-iouring")
printf "  %-34s  %-10s  %-8s  %s\n" "raw iouring" \
    "$RAW_IOR_TX Mpps" "${RAW_IOR_AVG}us" "${RAW_IOR_MAX}us"

read TILE_OS_TX TILE_OS_AVG TILE_OS_MAX <<< $(run_pingpong "tile-os" \
    "$OUTDIR/tile-receiver" "$OUTDIR/tile-sender" \
    $((PORT+10)) 4 "$OUTDIR/s3-tile-os" --socket os)
printf "  %-34s  %-10s  %-8s  %s\n" "tile os" \
    "$TILE_OS_TX Mpps" "${TILE_OS_AVG}us" "${TILE_OS_MAX}us"

read TILE_IOR_TX TILE_IOR_AVG TILE_IOR_MAX <<< $(run_pingpong "tile-iouring" \
    "$OUTDIR/tile-receiver" "$OUTDIR/tile-sender" \
    $((PORT+11)) 4 "$OUTDIR/s3-tile-iouring" --socket iouring)
printf "  %-34s  %-10s  %-8s  %s\n" "tile iouring" \
    "$TILE_IOR_TX Mpps" "${TILE_IOR_AVG}us" "${TILE_IOR_MAX}us"

printf "  %-34s  %s TX,  %s avg RTT\n" "delta (iouring vs os, tile)" \
    "$(pct_delta "$TILE_IOR_TX"  "$TILE_OS_TX")" \
    "$(pct_delta "$TILE_IOR_AVG" "$TILE_OS_AVG")"
printf "  %-34s  %s TX,  %s avg RTT\n" "delta (tile vs raw, iouring)" \
    "$(pct_delta "$TILE_IOR_TX"  "$RAW_IOR_TX")" \
    "$(pct_delta "$TILE_IOR_AVG" "$RAW_IOR_AVG")"

# ── 4. Pingpong window=16 ─────────────────────────────────────────────────────

print_header "Scenario 4 — pingpong window=16" \
             "TX (Mpps)" "avg RTT" "max RTT"

read RAW_OS_TX  RAW_OS_AVG  RAW_OS_MAX  <<< $(run_pingpong "raw-os" \
    "$OUTDIR/os-receiver" "$OUTDIR/os-sender" \
    $((PORT+12)) 16 "$OUTDIR/s4-raw-os")
printf "  %-34s  %-10s  %-8s  %s\n" "raw os" \
    "$RAW_OS_TX Mpps" "${RAW_OS_AVG}us" "${RAW_OS_MAX}us"

read RAW_IOR_TX RAW_IOR_AVG RAW_IOR_MAX <<< $(run_pingpong "raw-iouring" \
    "$OUTDIR/iouring-receiver" "$OUTDIR/iouring-sender" \
    $((PORT+13)) 16 "$OUTDIR/s4-raw-iouring")
printf "  %-34s  %-10s  %-8s  %s\n" "raw iouring" \
    "$RAW_IOR_TX Mpps" "${RAW_IOR_AVG}us" "${RAW_IOR_MAX}us"

read TILE_OS_TX TILE_OS_AVG TILE_OS_MAX <<< $(run_pingpong "tile-os" \
    "$OUTDIR/tile-receiver" "$OUTDIR/tile-sender" \
    $((PORT+14)) 16 "$OUTDIR/s4-tile-os" --socket os)
printf "  %-34s  %-10s  %-8s  %s\n" "tile os" \
    "$TILE_OS_TX Mpps" "${TILE_OS_AVG}us" "${TILE_OS_MAX}us"

read TILE_IOR_TX TILE_IOR_AVG TILE_IOR_MAX <<< $(run_pingpong "tile-iouring" \
    "$OUTDIR/tile-receiver" "$OUTDIR/tile-sender" \
    $((PORT+15)) 16 "$OUTDIR/s4-tile-iouring" --socket iouring)
printf "  %-34s  %-10s  %-8s  %s\n" "tile iouring" \
    "$TILE_IOR_TX Mpps" "${TILE_IOR_AVG}us" "${TILE_IOR_MAX}us"

printf "  %-34s  %s TX,  %s avg RTT\n" "delta (iouring vs os, tile)" \
    "$(pct_delta "$TILE_IOR_TX"  "$TILE_OS_TX")" \
    "$(pct_delta "$TILE_IOR_AVG" "$TILE_OS_AVG")"
printf "  %-34s  %s TX,  %s avg RTT\n" "delta (tile vs raw, iouring)" \
    "$(pct_delta "$TILE_IOR_TX"  "$RAW_IOR_TX")" \
    "$(pct_delta "$TILE_IOR_AVG" "$RAW_IOR_AVG")"

echo ""
echo "Raw logs: $OUTDIR/s*.{rx,tx}"
echo ""
