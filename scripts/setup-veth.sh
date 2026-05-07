#!/usr/bin/env bash
#
# Set up two Linux network namespaces (quac-rx, quac-tx) joined by a veth
# pair so the quac UDP benchmarks send real packets through a virtual
# network device instead of being short-circuited by the kernel's loopback
# routing optimisation.
#
# Without separate netns, even with a veth pair set up in the default
# namespace, sending UDP to any locally-assigned IP routes via lo because
# the kernel's "local" routing table maps every host-owned address to lo.
# Putting each veth end in its own netns gives each side an independent
# routing table, so the only path between them is the veth.
#
# Usage:
#   sudo scripts/setup-veth.sh           # idempotent setup
#   sudo scripts/setup-veth.sh --up      # same
#   sudo scripts/setup-veth.sh --info    # print ns/iface/IP summary
#   sudo scripts/setup-veth.sh --cleanup # tear down
#
# Requires: ip (iproute2), ethtool, root.

set -euo pipefail

NS_RX="${NS_RX:-quac-rx}"
NS_TX="${NS_TX:-quac-tx}"
VETH_RX="${VETH_RX:-vqrx}"
VETH_TX="${VETH_TX:-vqtx}"
RX_IP="${RX_IP:-10.99.0.1}"
TX_IP="${TX_IP:-10.99.0.2}"
PREFIX="${PREFIX:-24}"
# Number of RX/TX queues per veth end. veth's native XDP (DRV mode) hook
# refuses to attach when the peer has only one RX queue and no XDP program
# attached — `veth_xdp_set` returns -EOPNOTSUPP. AF_XDP zero-copy in turn
# requires DRV mode. 4 queues is plenty for our single-tile benches and
# keeps the kernel happy without forcing peer XDP setup.
NUM_QUEUES="${NUM_QUEUES:-4}"

usage() {
    sed -n '2,/^$/p' "$0" | grep '^#' | sed 's/^# \?//'
}

require_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "error: must run as root (try: sudo $0 $*)" >&2
        exit 1
    fi
}

ns_exists() { ip netns list | awk '{print $1}' | grep -qx "$1"; }

info() {
    cat <<EOF
[veth] netns ${NS_RX} (rx) ↔ ${NS_TX} (tx)
[veth]   ${RX_IP}/${PREFIX}  on ${VETH_RX} (in ${NS_RX})
[veth]   ${TX_IP}/${PREFIX}  on ${VETH_TX} (in ${NS_TX})
[veth] run rx-side: ip netns exec ${NS_RX} <cmd>
[veth] run tx-side: ip netns exec ${NS_TX} <cmd>
EOF
}

cleanup() {
    ip netns del "$NS_RX" 2>/dev/null || true
    ip netns del "$NS_TX" 2>/dev/null || true
    # If a half-created run left the veth in the default ns, drop it.
    ip link del "$VETH_RX" 2>/dev/null || true
    ip link del "$VETH_TX" 2>/dev/null || true
    echo "[veth] cleanup complete"
}

setup() {
    if ns_exists "$NS_RX" && ns_exists "$NS_TX" \
       && ip -n "$NS_RX" link show "$VETH_RX" >/dev/null 2>&1 \
       && ip -n "$NS_TX" link show "$VETH_TX" >/dev/null 2>&1; then
        echo "[veth] already set up"
        info
        return 0
    fi

    # Wipe any half-created leftovers from a prior aborted run.
    cleanup >/dev/null

    ip netns add "$NS_RX"
    ip netns add "$NS_TX"

    # `numrxqueues N numtxqueues N` on BOTH ends so veth's native XDP path
    # accepts AF_XDP zero-copy bind without requiring an XDP program on
    # the peer interface (see comment on $NUM_QUEUES above).
    ip link add "$VETH_RX" numrxqueues "$NUM_QUEUES" numtxqueues "$NUM_QUEUES" \
        type veth peer name "$VETH_TX" \
        numrxqueues "$NUM_QUEUES" numtxqueues "$NUM_QUEUES"
    ip link set "$VETH_RX" netns "$NS_RX"
    ip link set "$VETH_TX" netns "$NS_TX"

    ip -n "$NS_RX" addr add "${RX_IP}/${PREFIX}" dev "$VETH_RX"
    ip -n "$NS_TX" addr add "${TX_IP}/${PREFIX}" dev "$VETH_TX"

    ip -n "$NS_RX" link set "$VETH_RX" up
    ip -n "$NS_TX" link set "$VETH_TX" up
    ip -n "$NS_RX" link set lo up
    ip -n "$NS_TX" link set lo up

    # Disable software offloads so each UDP datagram traverses the veth as
    # its own packet — without this, GSO/GRO/TSO can coalesce traffic and
    # inflate measured PPS in ways that don't translate to a real NIC.
    # Each call is best-effort: not every offload is settable on every
    # kernel/veth combo, and the bench is still correct if a few are no-ops.
    for spec in "$NS_RX:$VETH_RX" "$NS_TX:$VETH_TX"; do
        ns="${spec%%:*}"; ifname="${spec##*:}"
        for off in gso gro tso tx-checksum-ip-generic rx-checksum; do
            ip netns exec "$ns" ethtool -K "$ifname" "$off" off 2>/dev/null || true
        done
    done

    info
}

case "${1:-}" in
    ""|"--up")
        require_root "$@"
        setup
        ;;
    "--cleanup"|"--down")
        require_root "$@"
        cleanup
        ;;
    "--info")
        info
        ;;
    "-h"|"--help")
        usage
        ;;
    *)
        echo "error: unknown arg: $1" >&2
        usage
        exit 1
        ;;
esac
