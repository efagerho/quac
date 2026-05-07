#!/usr/bin/env bash
#
# Quick AF_XDP zero-copy smoke test over two physical NICs connected by a
# direct cable. Sets up the netns + interfaces, sends a handful of UDP
# packets in one direction, verifies the receiver gets them, and tears
# down. Intended as the "did everything work" check before running the
# full `compare-nic.sh` matrix (which takes ~6 minutes).
#
# Usage:
#   sudo scripts/smoke-nic.sh <RX_NIC> <TX_NIC> [--count N] [--xdp-mode zc|copy]
#                                                [--xdp-attach default|skb|drv|hw]
#                                                [--no-cleanup]
#
# Defaults:
#   --count 10
#   --xdp-mode zc
#   --xdp-attach drv
#
# Exit codes:
#   0  receiver successfully read the expected packet count
#   1  any setup, send, or recv step failed (error message printed)

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NS_RX="${NS_RX:-quac-rx}"
NS_TX="${NS_TX:-quac-tx}"
RX_IP="${RX_IP:-10.99.0.1}"
TX_IP="${TX_IP:-10.99.0.2}"

usage() {
    sed -n '2,/^$/p' "$0" | grep '^#' | sed 's/^# \?//'
}

# ── Parse args ──────────────────────────────────────────────────────────────

COUNT=10
XDP_MODE="zc"
XDP_ATTACH="drv"
NO_CLEANUP=0
ARGS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)       usage; exit 0 ;;
        --count)         COUNT="$2"; shift 2 ;;
        --xdp-mode)      XDP_MODE="$2"; shift 2 ;;
        --xdp-attach)    XDP_ATTACH="$2"; shift 2 ;;
        --no-cleanup)    NO_CLEANUP=1; shift ;;
        *)               ARGS+=("$1"); shift ;;
    esac
done
set -- "${ARGS[@]+"${ARGS[@]}"}"

if [[ $# -lt 2 ]]; then
    echo "error: needs <RX_NIC> <TX_NIC>" >&2
    echo "" >&2
    usage >&2
    exit 1
fi
RX_NIC="$1"
TX_NIC="$2"

if [[ $EUID -ne 0 ]]; then
    echo "error: must run as root (try: sudo $0 ${RX_NIC} ${TX_NIC})" >&2
    exit 1
fi

# ── Build the smoke-test binary if needed ───────────────────────────────────

SMOKE_BIN="$REPO/target/release/examples/xdp-smoke-test"
if [[ ! -x "$SMOKE_BIN" || "$REPO/quac-socket-xdp/examples/xdp-smoke-test.rs" -nt "$SMOKE_BIN" ]]; then
    echo "[smoke-nic] building xdp-smoke-test…"
    # cargo isn't usually on root's PATH under sudo; fall back to the
    # invoking user's login shell.
    if [[ -n "${SUDO_USER:-}" ]]; then
        sudo -u "$SUDO_USER" -- bash -lc \
            "cd '$REPO' && cargo build --release -p quac-socket-xdp --example xdp-smoke-test"
    else
        bash -c "cd '$REPO' && cargo build --release -p quac-socket-xdp --example xdp-smoke-test"
    fi
fi

# ── Set up + ensure cleanup ─────────────────────────────────────────────────

echo "[smoke-nic] setting up NICs ${RX_NIC} (rx) <-> ${TX_NIC} (tx)…"
"$REPO/scripts/setup-nic.sh" --up "$RX_NIC" "$TX_NIC"

cleanup() {
    if [[ "$NO_CLEANUP" -eq 1 ]]; then
        echo "[smoke-nic] --no-cleanup set; NICs remain in netns"
        return
    fi
    echo "[smoke-nic] cleaning up netns…"
    "$REPO/scripts/setup-nic.sh" --cleanup || \
        echo "[smoke-nic] WARNING: cleanup failed; check with: ip netns list" >&2
}
trap cleanup EXIT

# ── Run receiver in background, sender in foreground ────────────────────────

PORT=39001
RX_LOG="$(mktemp /tmp/smoke-nic-rx.XXXXXX.log)"
TX_LOG="$(mktemp /tmp/smoke-nic-tx.XXXXXX.log)"
trap 'rm -f "$RX_LOG" "$TX_LOG"; cleanup' EXIT

echo "[smoke-nic] starting receiver on ${RX_IP}:${PORT} (queue=0, mode=${XDP_MODE}, attach=${XDP_ATTACH})…"
ip netns exec "$NS_RX" "$SMOKE_BIN" recv \
    --iface "$RX_NIC" --bind "$RX_IP:$PORT" --queue 0 --count "$COUNT" \
    --xdp-mode "$XDP_MODE" --attach "$XDP_ATTACH" \
    > "$RX_LOG" 2>&1 &
RX_PID=$!

# Wait briefly for the receiver to bind. xdp-smoke-test prints "ready" once
# the socket is up; bail if it dies before that.
for _ in $(seq 1 50); do
    grep -q "receiver ready" "$RX_LOG" 2>/dev/null && break
    if ! kill -0 "$RX_PID" 2>/dev/null; then
        echo "[smoke-nic] receiver exited prematurely; logs:" >&2
        cat "$RX_LOG" >&2
        exit 1
    fi
    sleep 0.1
done

echo "[smoke-nic] sending ${COUNT} packets ${TX_IP} -> ${RX_IP}:${PORT}…"
if ! ip netns exec "$NS_TX" "$SMOKE_BIN" send \
        --iface "$TX_NIC" --bind "$TX_IP:0" --target "$RX_IP:$PORT" \
        --queue 0 --count "$COUNT" \
        --xdp-mode "$XDP_MODE" --attach "$XDP_ATTACH" \
        > "$TX_LOG" 2>&1; then
    echo "[smoke-nic] sender failed; logs:" >&2
    cat "$TX_LOG" >&2
    kill "$RX_PID" 2>/dev/null || true
    wait "$RX_PID" 2>/dev/null || true
    exit 1
fi

# Receiver should exit on its own once it's seen $COUNT packets. Give it a
# second to drain; force-kill if it hangs.
for _ in $(seq 1 30); do
    if ! kill -0 "$RX_PID" 2>/dev/null; then break; fi
    sleep 0.1
done
if kill -0 "$RX_PID" 2>/dev/null; then
    echo "[smoke-nic] receiver did not exit after sender finished; killing…" >&2
    kill "$RX_PID" 2>/dev/null || true
fi
wait "$RX_PID" 2>/dev/null || true

# ── Verify ──────────────────────────────────────────────────────────────────

if grep -q "received ${COUNT} packets" "$RX_LOG"; then
    echo "[smoke-nic] OK — receiver got all ${COUNT} packets"
    echo "[smoke-nic]   xdp-mode=${XDP_MODE} attach=${XDP_ATTACH} on ${RX_NIC}/${TX_NIC}"
    echo ""
    echo "Receiver log:"
    sed 's/^/  /' "$RX_LOG"
    exit 0
else
    echo "[smoke-nic] FAILED — receiver did not see all ${COUNT} packets" >&2
    echo "" >&2
    echo "Sender log:" >&2
    sed 's/^/  /' "$TX_LOG" >&2
    echo "" >&2
    echo "Receiver log:" >&2
    sed 's/^/  /' "$RX_LOG" >&2
    exit 1
fi
