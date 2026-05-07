#!/usr/bin/env bash
#
# Profile one side of a quac UDP benchmark over two physical NICs
# connected by a direct cable. Wraps:
#   1. scripts/setup-nic.sh --up   <RX_NIC> <TX_NIC>
#   2. scripts/profile-veth.sh     [--xdp-mode zc --xdp-attach drv] [extras]
#   3. scripts/setup-nic.sh --cleanup   (unless --no-cleanup)
#
# Counterpart to scripts/compare-nic.sh; same NIC-friendly defaults
# (zero-copy + native driver attach for the XDP backend).
#
# Usage:
#   sudo scripts/profile-nic.sh <RX_NIC> <TX_NIC> [profile-veth.sh flags]
#       e.g. sudo scripts/profile-nic.sh enp1s0 enp2s0 \
#                --bench direct --socket xdp --side receiver --mode rate
#
#   profile-nic.sh-specific flags (consumed before forwarding):
#     --no-cleanup    leave the NICs in their netns after the run
#     -h | --help     this help
#
# Forwarded to profile-veth.sh:
#   --bench direct|tile  --socket os|iouring|xdp  --side sender|receiver
#   --mode rate|pingpong --window N --rate PPS --size BYTES --threads N
#   --duration N --perf-freq N --outdir DIR
#   --xdp-mode zc|copy --xdp-attach default|skb|drv|hw  (override)
#
# The XDP defaults (`--xdp-mode zc --xdp-attach drv`) exercise the real
# zero-copy path. Override with `--xdp-mode copy` or `--xdp-attach skb`
# after the NIC arguments — those appear later on the inner command line
# and win.
#
# Prerequisites:
#   - Two physical NICs, neither your primary uplink, connected to each
#     other. Setup will move them into network namespaces.
#   - perf, root, AF_XDP support in the NIC driver (for XDP backend).

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

usage() {
    sed -n '2,/^$/p' "$0" | grep '^#' | sed 's/^# \?//'
}

# ── Parse profile-nic.sh flags before passing the rest to profile-veth.sh ───

NO_CLEANUP=0
ARGS=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)     usage; exit 0 ;;
        --no-cleanup)  NO_CLEANUP=1; shift ;;
        *)             ARGS+=("$1"); shift ;;
    esac
done
set -- "${ARGS[@]+"${ARGS[@]}"}"

if [[ $# -lt 2 ]]; then
    echo "error: needs <RX_NIC> <TX_NIC>" >&2
    echo "" >&2
    usage >&2
    exit 1
fi
RX_NIC="$1"; shift
TX_NIC="$1"; shift

if [[ $EUID -ne 0 ]]; then
    echo "error: must run as root (try: sudo $0 ${RX_NIC} ${TX_NIC} $*)" >&2
    exit 1
fi

# ── Setup ───────────────────────────────────────────────────────────────────

echo "[profile-nic] setting up NICs ${RX_NIC} (rx) <-> ${TX_NIC} (tx)…"
"$REPO/scripts/setup-nic.sh" --up "$RX_NIC" "$TX_NIC"

cleanup() {
    if [[ "$NO_CLEANUP" -eq 1 ]]; then
        echo "[profile-nic] --no-cleanup set; NICs remain in netns"
        echo "[profile-nic]   tear down later with: sudo ${REPO}/scripts/setup-nic.sh --cleanup"
        return
    fi
    echo "[profile-nic] cleaning up netns (returning NICs to default)…"
    "$REPO/scripts/setup-nic.sh" --cleanup || \
        echo "[profile-nic] WARNING: cleanup failed; check with: ip netns list" >&2
}
trap cleanup EXIT

# ── Profile ─────────────────────────────────────────────────────────────────

echo "[profile-nic] running profile-veth.sh with --xdp-mode zc --xdp-attach drv defaults"
"$REPO/scripts/profile-veth.sh" --xdp-mode zc --xdp-attach drv "$@"
