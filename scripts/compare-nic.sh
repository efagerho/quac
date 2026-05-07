#!/usr/bin/env bash
#
# End-to-end performance comparison over two physical NICs connected by a
# direct cable. Wraps:
#   1. scripts/setup-nic.sh --up   <RX_NIC> <TX_NIC>
#   2. scripts/compare-veth.sh     --xdp-mode zc --xdp-attach drv [extras]
#   3. scripts/setup-nic.sh --cleanup   (unless --no-cleanup)
#
# The XDP defaults (`--xdp-mode zc --xdp-attach drv`) exercise the real
# zero-copy path with native driver attach, which is the production
# configuration for AF_XDP. The user can override either by passing
# `--xdp-mode copy` / `--xdp-attach skb` after the NIC arguments — those
# appear later on the inner compare-veth.sh command line and win.
#
# Usage:
#   sudo scripts/compare-nic.sh <RX_NIC> <TX_NIC> [compare-veth.sh flags]
#       e.g. sudo scripts/compare-nic.sh enp1s0 enp2s0 --duration 30
#
#   Flags forwarded to compare-veth.sh include:
#     --duration N --threads N --size BYTES --outdir DIR
#     --xdp-mode zc|copy --xdp-attach default|skb|drv|hw
#
#   compare-nic.sh-specific flags (consumed before forwarding):
#     --no-cleanup   leave the NICs in their netns after the run for
#                    inspection (use `setup-nic.sh --cleanup` later)
#     -h | --help    print this help
#
# Prerequisites:
#   - both NICs are physical, not your primary uplink, and connected to
#     each other (direct cable / patch cable / DAC). Setup will move them
#     into network namespaces; if you put your only NIC into a netns the
#     host loses network access until --cleanup.
#   - kernel with AF_XDP zero-copy support for the NIC's driver
#     (mlx5_core, ice, i40e, ixgbe, etc. all support it on recent kernels).
#   - root privileges (CAP_NET_ADMIN, CAP_NET_RAW, CAP_BPF / CAP_SYS_ADMIN).

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

usage() {
    sed -n '2,/^$/p' "$0" | grep '^#' | sed 's/^# \?//'
}

# ── Parse compare-nic.sh flags before passing the rest to compare-veth.sh ────

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

# ── Setup ────────────────────────────────────────────────────────────────────

echo "[compare-nic] setting up NICs ${RX_NIC} (rx) <-> ${TX_NIC} (tx)…"
"$REPO/scripts/setup-nic.sh" --up "$RX_NIC" "$TX_NIC"

# Always attempt cleanup on exit unless the user opted out, even if the
# benchmark below errors. Without this, the NICs stay in netns and the
# host's view of them looks broken.
cleanup() {
    if [[ "$NO_CLEANUP" -eq 1 ]]; then
        echo "[compare-nic] --no-cleanup set; NICs remain in netns"
        echo "[compare-nic]   tear down later with: sudo ${REPO}/scripts/setup-nic.sh --cleanup"
        return
    fi
    echo "[compare-nic] cleaning up netns (returning NICs to default)…"
    "$REPO/scripts/setup-nic.sh" --cleanup || \
        echo "[compare-nic] WARNING: cleanup failed; check with: ip netns list" >&2
}
trap cleanup EXIT

# ── Benchmark ────────────────────────────────────────────────────────────────

echo "[compare-nic] running compare-veth.sh with --xdp-mode zc --xdp-attach drv"
"$REPO/scripts/compare-veth.sh" --xdp-mode zc --xdp-attach drv "$@"
