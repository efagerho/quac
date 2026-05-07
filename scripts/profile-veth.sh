#!/usr/bin/env bash
#
# Profile one side (sender or receiver) of a quac UDP benchmark running
# over the netns pair set up by `setup-veth.sh` or `setup-nic.sh`.
# Parameterised over:
#   --bench    direct | tile        (which binary family)
#   --socket   os | iouring | xdp   (socket backend; xdp requires direct)
#   --side     sender | receiver    (which process perf attaches to)
#
# Plus the usual workload knobs (mode, window, rate, size, threads,
# duration) and XDP-specific overrides.
#
# Usage:
#   sudo scripts/profile-veth.sh --bench direct --socket iouring --side receiver \
#                                --mode rate --duration 20
#
#   sudo scripts/profile-veth.sh --bench tile --socket os --side sender \
#                                --mode pingpong --window 4
#
#   sudo scripts/profile-veth.sh --bench direct --socket xdp --side sender \
#                                --xdp-mode copy --xdp-attach skb
#
# Defaults: --mode rate --window 1 --rate 0 --size 64 --threads 1 --duration 15
#           --xdp-mode copy --xdp-attach skb (veth-safe)
#           --outdir perf-output/<bench>-<socket>-<side>
#
# Output (under OUTDIR):
#   perf.data         — perf record output, view with `perf report -i …`
#   perf.svg          — flamegraph (if `inferno` or Brendan Gregg's tools
#                       are installed; otherwise skipped with a message)
#   <side>.log        — stdout/stderr of the profiled process
#   <other>.log       — stdout/stderr of the traffic-generating peer
#
# Prerequisites:
#   - scripts/setup-veth.sh --up   OR  scripts/setup-nic.sh --up <RX> <TX>
#   - perf (`linux-perf` / `perf-tools` / `linux-tools-generic`)
#   - optional: `cargo install inferno` for flamegraphs

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NS_RX="${NS_RX:-quac-rx}"
NS_TX="${NS_TX:-quac-tx}"
RX_IP="${RX_IP:-10.99.0.1}"
TX_IP="${TX_IP:-10.99.0.2}"

usage() {
    sed -n '2,/^$/p' "$0" | grep '^#' | sed 's/^# \?//'
}

# ── Defaults ────────────────────────────────────────────────────────────────

BENCH=""           # direct | tile
SOCKET=""          # os | iouring | xdp
SIDE=""            # sender | receiver

MODE="rate"        # rate | pingpong
WINDOW=1
RATE=0             # 0 = uncapped
SIZE=64
THREADS=1
DURATION=15
PERF_FREQ=999

# XDP-only knobs; defaults match compare-veth.sh's veth-safe defaults.
XDP_MODE="copy"
XDP_ATTACH="skb"

OUTDIR=""          # set later from BENCH/SOCKET/SIDE if not user-supplied

# ── Argument parsing ────────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
    case "$1" in
        --bench)        BENCH="$2";      shift 2 ;;
        --socket)       SOCKET="$2";     shift 2 ;;
        --side)         SIDE="$2";       shift 2 ;;
        --mode)         MODE="$2";       shift 2 ;;
        --window)       WINDOW="$2";     shift 2 ;;
        --rate)         RATE="$2";       shift 2 ;;
        --size)         SIZE="$2";       shift 2 ;;
        --threads)      THREADS="$2";    shift 2 ;;
        --duration)     DURATION="$2";   shift 2 ;;
        --perf-freq)    PERF_FREQ="$2";  shift 2 ;;
        --xdp-mode)     XDP_MODE="$2";   shift 2 ;;
        --xdp-attach)   XDP_ATTACH="$2"; shift 2 ;;
        --outdir)       OUTDIR="$2";     shift 2 ;;
        -h|--help)      usage; exit 0 ;;
        *)              echo "error: unknown arg: $1" >&2; usage >&2; exit 1 ;;
    esac
done

case "$BENCH" in
    direct|tile) ;;
    *) echo "error: --bench must be 'direct' or 'tile'" >&2; exit 1 ;;
esac
case "$SOCKET" in
    os|iouring) ;;
    xdp)
        if [[ "$BENCH" != "direct" ]]; then
            echo "error: --socket xdp is only valid with --bench direct (no tile-bench-xdp yet)" >&2
            exit 1
        fi
        ;;
    *) echo "error: --socket must be 'os', 'iouring', or 'xdp'" >&2; exit 1 ;;
esac
case "$SIDE" in
    sender|receiver) ;;
    *) echo "error: --side must be 'sender' or 'receiver'" >&2; exit 1 ;;
esac
case "$MODE" in
    rate|pingpong) ;;
    *) echo "error: --mode must be 'rate' or 'pingpong'" >&2; exit 1 ;;
esac

if [[ $EUID -ne 0 ]]; then
    echo "error: must run as root (try: sudo $0 $*)" >&2
    exit 1
fi

if ! command -v perf >/dev/null 2>&1; then
    echo "error: 'perf' not found — install linux-perf / perf-tools" >&2
    exit 1
fi

# ── Pre-flight: netns must be set up ────────────────────────────────────────

if ! ip netns list | awk '{print $1}' | grep -qx "$NS_RX" \
   || ! ip netns list | awk '{print $1}' | grep -qx "$NS_TX"; then
    echo "error: netns ${NS_RX}/${NS_TX} not set up." >&2
    echo "run one of:" >&2
    echo "  sudo scripts/setup-veth.sh --up           # virtual veth pair" >&2
    echo "  sudo scripts/setup-nic.sh  --up RX TX     # real NIC pair" >&2
    exit 1
fi

# Discover the (single) non-lo interface in each netns.
nic_in_ns() {
    ip -n "$1" link show 2>/dev/null \
        | awk -F': ' '/^[0-9]+: / && $2 != "lo" {sub(/@.*/, "", $2); print $2; exit}'
}
RX_IFACE="$(nic_in_ns "$NS_RX")"
TX_IFACE="$(nic_in_ns "$NS_TX")"
if [[ -z "$RX_IFACE" || -z "$TX_IFACE" ]]; then
    echo "error: no non-lo interface found in $NS_RX or $NS_TX" >&2
    exit 1
fi

# ── Build the bench binaries ────────────────────────────────────────────────

run_build() {
    local cmd="$1"
    if [[ -n "${SUDO_USER:-}" ]]; then
        sudo -u "$SUDO_USER" -- bash -lc "$cmd" 2>&1 | grep -v '^$'
    else
        bash -c "$cmd" 2>&1 | grep -v '^$'
    fi
}

# Build the package matching our SOCKET + BENCH selection. `force-frame-pointers`
# is required for accurate stack traces in the perf profile.
case "$SOCKET" in
    os)
        if [[ "$BENCH" == "direct" ]]; then
            PKG="quac-socket-os"
            SENDER_BIN="$REPO/target/release/examples/os-bench-sender"
            RECEIVER_BIN="$REPO/target/release/examples/os-bench-receiver"
        else
            PKG="quac-network-tile"
            SENDER_BIN="$REPO/target/release/examples/tile-bench-sender"
            RECEIVER_BIN="$REPO/target/release/examples/tile-bench-receiver"
        fi
        ;;
    iouring)
        if [[ "$BENCH" == "direct" ]]; then
            PKG="quac-socket-iouring"
            SENDER_BIN="$REPO/target/release/examples/iouring-bench-sender"
            RECEIVER_BIN="$REPO/target/release/examples/iouring-bench-receiver"
        else
            PKG="quac-network-tile"
            SENDER_BIN="$REPO/target/release/examples/tile-bench-sender"
            RECEIVER_BIN="$REPO/target/release/examples/tile-bench-receiver"
        fi
        ;;
    xdp)
        PKG="quac-socket-xdp"
        SENDER_BIN="$REPO/target/release/examples/xdp-bench-sender"
        RECEIVER_BIN="$REPO/target/release/examples/xdp-bench-receiver"
        ;;
esac

echo "[profile] building $PKG examples (frame pointers on for perf stack traces)…"
run_build "cd '$REPO' && RUSTFLAGS='-C force-frame-pointers=yes' \
    cargo build --release --examples -p $PKG \
        --manifest-path '$REPO/Cargo.toml'"

# ── Output directory + log paths ────────────────────────────────────────────

if [[ -z "$OUTDIR" ]]; then
    OUTDIR="$REPO/perf-output/${BENCH}-${SOCKET}-${SIDE}"
fi
mkdir -p "$OUTDIR"
PERF_DATA="$OUTDIR/perf.data"
PERF_SVG="$OUTDIR/perf.svg"
PROFILED_LOG="$OUTDIR/${SIDE}.log"
OTHER_SIDE=$([[ "$SIDE" == sender ]] && echo receiver || echo sender)
OTHER_LOG="$OUTDIR/${OTHER_SIDE}.log"

PORT=49890   # arbitrary; netns isolates from any host conflict

# ── Build the sender / receiver command lines ───────────────────────────────
#
# Each backend has slightly different CLI shape. Build them as bash arrays
# so quoting works for paths containing spaces.

build_receiver_cmd() {
    local recv_mode
    recv_mode=$([[ "$MODE" == rate ]] && echo count || echo reflect)
    case "$SOCKET" in
        os|iouring)
            if [[ "$BENCH" == direct ]]; then
                RECEIVER_CMD=(
                    "$RECEIVER_BIN"
                    --bind "$RX_IP:$PORT"
                    --threads "$THREADS"
                    --mode "$recv_mode"
                    --duration "$DURATION"
                )
            else
                RECEIVER_CMD=(
                    "$RECEIVER_BIN"
                    --socket "$SOCKET"
                    --bind "$RX_IP:$PORT"
                    --threads "$THREADS"
                    --mode "$recv_mode"
                    --duration "$DURATION"
                )
            fi
            ;;
        xdp)
            RECEIVER_CMD=(
                "$RECEIVER_BIN"
                --iface "$RX_IFACE"
                --bind "$RX_IP:$PORT"
                --queue 0
                --threads "$THREADS"
                --mode "$recv_mode"
                --duration "$DURATION"
                --xdp-mode "$XDP_MODE"
                --attach "$XDP_ATTACH"
            )
            ;;
    esac
}

build_sender_cmd() {
    local tx_dur=$(( DURATION - 2 ))
    case "$SOCKET" in
        os|iouring)
            if [[ "$BENCH" == direct ]]; then
                SENDER_CMD=(
                    "$SENDER_BIN"
                    --target "$RX_IP:$PORT"
                    --threads "$THREADS"
                    --mode "$MODE"
                    --rate "$RATE"
                    --size "$SIZE"
                    --window "$WINDOW"
                    --duration "$tx_dur"
                )
            else
                SENDER_CMD=(
                    "$SENDER_BIN"
                    --socket "$SOCKET"
                    --target "$RX_IP:$PORT"
                    --threads "$THREADS"
                    --mode "$MODE"
                    --rate "$RATE"
                    --size "$SIZE"
                    --window "$WINDOW"
                    --duration "$tx_dur"
                )
            fi
            ;;
        xdp)
            SENDER_CMD=(
                "$SENDER_BIN"
                --iface "$TX_IFACE"
                --bind "$TX_IP:0"
                --target "$RX_IP:$PORT"
                --queue 0
                --threads "$THREADS"
                --mode "$MODE"
                --rate "$RATE"
                --size "$SIZE"
                --window "$WINDOW"
                --duration "$tx_dur"
                --xdp-mode "$XDP_MODE"
                --attach "$XDP_ATTACH"
            )
            ;;
    esac
}

build_receiver_cmd
build_sender_cmd

# ── Wait helpers ────────────────────────────────────────────────────────────

# Probes the receiver netns rather than the host (host's `ss` doesn't see
# netns-local sockets). XDP sockets don't show in `ss` though — for XDP we
# fall back to a fixed delay.
wait_for_recv() {
    if [[ "$SOCKET" == xdp ]]; then
        sleep 1
        return
    fi
    local timeout=5 i=0
    while (( i < timeout * 10 )); do
        ip netns exec "$NS_RX" ss -ulnH "sport = :$PORT" 2>/dev/null \
            | grep -q "$PORT" && return 0
        sleep 0.1; (( ++i ))
    done
    echo "warning: port $PORT not bound in $NS_RX after ${timeout}s" >&2
}

# ── Flamegraph helper (matches existing bench-profile.sh idiom) ─────────────

flamegraph_cmd() {
    if command -v inferno-collapse-perf >/dev/null \
            && command -v inferno-flamegraph >/dev/null; then
        echo inferno
    elif command -v stackcollapse-perf.pl >/dev/null \
            && command -v flamegraph.pl >/dev/null; then
        echo flamegraph-pl
    else
        echo ""
    fi
}

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

# ── Run the benchmark with perf attached to the chosen side ─────────────────

cleanup() {
    # Kill any lingering background jobs we own.
    jobs -p | xargs -r kill 2>/dev/null || true
}
trap cleanup EXIT

echo
echo "══════════════════════════════════════════════════════════════"
echo "  bench=${BENCH}  socket=${SOCKET}  side=${SIDE}  mode=${MODE}"
echo "  duration=${DURATION}s  size=${SIZE}B  threads=${THREADS}  window=${WINDOW}  rate=${RATE}pps"
echo "  rx ns=${NS_RX} (iface=${RX_IFACE})  tx ns=${NS_TX} (iface=${TX_IFACE})"
[[ "$SOCKET" == xdp ]] && echo "  xdp: mode=${XDP_MODE}  attach=${XDP_ATTACH}"
echo "  outdir=${OUTDIR}"
echo "══════════════════════════════════════════════════════════════"

if [[ "$SIDE" == receiver ]]; then
    # Profile receiver: start it first, attach perf, then drive with sender.
    ip netns exec "$NS_RX" "${RECEIVER_CMD[@]}" > "$PROFILED_LOG" 2>&1 &
    RECV_PID=$!
    wait_for_recv
    if ! kill -0 "$RECV_PID" 2>/dev/null; then
        echo "error: receiver exited before perf could attach; log:" >&2
        cat "$PROFILED_LOG" >&2
        exit 1
    fi
    perf record -g -F "$PERF_FREQ" -p "$RECV_PID" -o "$PERF_DATA" -- sleep "$DURATION" &
    PERF_PID=$!
    ip netns exec "$NS_TX" "${SENDER_CMD[@]}" > "$OTHER_LOG" 2>&1 || true
    wait "$RECV_PID" 2>/dev/null || true
    wait "$PERF_PID" 2>/dev/null || true
else
    # Profile sender: start receiver first to bind, then perf-record the sender
    # for its full lifetime.
    ip netns exec "$NS_RX" "${RECEIVER_CMD[@]}" > "$OTHER_LOG" 2>&1 &
    RECV_PID=$!
    wait_for_recv
    perf record -g -F "$PERF_FREQ" -o "$PERF_DATA" -- \
        ip netns exec "$NS_TX" "${SENDER_CMD[@]}" > "$PROFILED_LOG" 2>&1
    wait "$RECV_PID" 2>/dev/null || true
fi

echo
echo "  Profile data:  $PERF_DATA"
render_flamegraph "$PERF_DATA" "$PERF_SVG" \
    "${BENCH}-${SOCKET}-${SIDE} (${MODE} window=${WINDOW} size=${SIZE}B threads=${THREADS})"

echo
echo "  Logs:"
echo "    profiled side: $PROFILED_LOG"
echo "    other side:    $OTHER_LOG"
echo
echo "  Inspect:"
echo "    perf report --no-children --stdio -i $PERF_DATA | head -40"
[[ -f "$PERF_SVG" ]] && echo "    xdg-open $PERF_SVG"
echo
