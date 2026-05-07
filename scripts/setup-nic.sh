#!/usr/bin/env bash
#
# Set up two physical NICs (presumably connected to each other by a direct
# cable) in the same `quac-rx` / `quac-tx` netns topology that
# scripts/setup-veth.sh creates with veth devices. This means
# scripts/compare-veth.sh works unchanged against either backend.
#
# Why netns at all when the NICs are already separate physical devices?
# Same reason as setup-veth.sh: the kernel's `local` routing table maps
# every host-owned IP to lo. Even with two physical NICs on the host,
# UDP from 10.99.0.2 → 10.99.0.1 routes via lo unless the IPs are in
# different netns.
#
# *** WARNING ***
# This MOVES the named NICs into network namespaces. Make sure neither
# NIC is your primary uplink — if you put your only network interface
# into a netns, the host loses connectivity. SSH sessions to the host
# survive (they're on a different fd), but new connections won't work.
# Use `--cleanup` to move the NICs back to the default netns.
#
# Usage:
#   sudo scripts/setup-nic.sh --up <RX_NIC> <TX_NIC>
#       e.g. sudo scripts/setup-nic.sh --up enp1s0 enp2s0
#
#   sudo scripts/setup-nic.sh --info
#   sudo scripts/setup-nic.sh --cleanup
#
# Requires: ip (iproute2), ethtool, root.

set -euo pipefail

NS_RX="${NS_RX:-quac-rx}"
NS_TX="${NS_TX:-quac-tx}"
RX_IP="${RX_IP:-10.99.0.1}"
TX_IP="${TX_IP:-10.99.0.2}"
PREFIX="${PREFIX:-24}"

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

# nic_in_ns NIC NS  → 0 if NIC currently lives in NS, 1 otherwise.
nic_in_ns() {
    local nic="$1" ns="$2"
    ip -n "$ns" link show dev "$nic" >/dev/null 2>&1
}

# nic_in_default NIC  → 0 if NIC is in the default netns, 1 otherwise.
nic_in_default() { ip link show dev "$1" >/dev/null 2>&1; }

# Find the NIC currently inside the named netns (if any). Excludes `lo`.
nic_in() {
    local ns="$1"
    ip -n "$ns" link show 2>/dev/null \
        | awk -F': ' '/^[0-9]+: / && $2 != "lo" {sub(/@.*/, "", $2); print $2; exit}'
}

info() {
    cat <<EOF
[nic] netns ${NS_RX} (rx) ↔ ${NS_TX} (tx)
[nic]   ${RX_IP}/${PREFIX}  on $(nic_in "$NS_RX" || echo "<unset>") (in ${NS_RX})
[nic]   ${TX_IP}/${PREFIX}  on $(nic_in "$NS_TX" || echo "<unset>") (in ${NS_TX})
[nic] run rx-side: ip netns exec ${NS_RX} <cmd>
[nic] run tx-side: ip netns exec ${NS_TX} <cmd>
EOF
}

cleanup() {
    # Move any NICs sitting in our netns back to the default netns before
    # tearing the netns down. `ip link set netns 1` targets PID 1's netns
    # (the default). Without this, deleting the netns can leave the NIC
    # in an awkward state (modern kernels usually re-home physical NICs
    # to default automatically, but this is the explicit, safe path).
    for ns in "$NS_RX" "$NS_TX"; do
        ns_exists "$ns" || continue
        local nic
        nic=$(nic_in "$ns") || true
        if [[ -n "${nic:-}" ]]; then
            echo "[nic] returning ${nic} from ns ${ns} to default netns"
            ip -n "$ns" link set "$nic" netns 1 2>/dev/null \
                || ip -n "$ns" link set "$nic" netns "$$" 2>/dev/null \
                || true
            # Reset name in case it was renamed inside the ns (we don't
            # rename, so this is just defensive).
            true
        fi
        ip netns del "$ns" 2>/dev/null || true
    done
    echo "[nic] cleanup complete"
}

setup() {
    local rx_nic="$1" tx_nic="$2"

    if [[ "$rx_nic" == "$tx_nic" ]]; then
        echo "error: RX_NIC and TX_NIC must be different ($rx_nic == $tx_nic)" >&2
        exit 1
    fi

    # Verify both NICs exist *somewhere* (default ns or an existing
    # quac-* netns from a prior run we'll wipe below).
    for nic in "$rx_nic" "$tx_nic"; do
        if ! ip -all netns exec ip link show dev "$nic" >/dev/null 2>&1 \
           && ! nic_in_default "$nic"; then
            # Fall back: search every netns explicitly. `ip -all netns exec`
            # may not exist on older iproute2.
            local found=""
            for ns in $(ip netns list | awk '{print $1}') ""; do
                if [[ -z "$ns" ]]; then
                    nic_in_default "$nic" && found="default"
                else
                    nic_in_ns "$nic" "$ns" && found="$ns"
                fi
                [[ -n "$found" ]] && break
            done
            if [[ -z "$found" ]]; then
                echo "error: NIC '${nic}' not found in any netns" >&2
                exit 1
            fi
        fi
    done

    # Wipe any prior quac-rx / quac-tx setup so this run is clean.
    cleanup >/dev/null

    ip netns add "$NS_RX"
    ip netns add "$NS_TX"

    # Move the NICs into their target netns. If they're not in the
    # default ns (e.g. left over from an aborted run that survived
    # `cleanup`), find them first and pull them back.
    move_to_ns "$rx_nic" "$NS_RX"
    move_to_ns "$tx_nic" "$NS_TX"

    # Inside each netns: assign IP, bring up, and disable offloads.
    # Disabling offloads matches setup-veth.sh's rationale — we want each
    # UDP datagram to traverse the NIC as one wire packet so per-packet
    # measurements translate to deployment, not be inflated by GSO/GRO.
    ip -n "$NS_RX" addr add "${RX_IP}/${PREFIX}" dev "$rx_nic"
    ip -n "$NS_TX" addr add "${TX_IP}/${PREFIX}" dev "$tx_nic"

    ip -n "$NS_RX" link set "$rx_nic" up
    ip -n "$NS_TX" link set "$tx_nic" up
    ip -n "$NS_RX" link set lo up
    ip -n "$NS_TX" link set lo up

    for spec in "$NS_RX:$rx_nic" "$NS_TX:$tx_nic"; do
        local ns="${spec%%:*}" ifname="${spec##*:}"
        for off in gso gro tso tx-checksum-ip-generic rx-checksum lro; do
            ip netns exec "$ns" ethtool -K "$ifname" "$off" off 2>/dev/null || true
        done
    done

    info
}

# Move NIC to the named netns. Searches for the current location first.
move_to_ns() {
    local nic="$1" target="$2"
    if nic_in_default "$nic"; then
        ip link set "$nic" netns "$target"
        return
    fi
    for ns in $(ip netns list | awk '{print $1}'); do
        if nic_in_ns "$nic" "$ns"; then
            if [[ "$ns" == "$target" ]]; then
                return  # already where we want it
            fi
            ip -n "$ns" link set "$nic" netns "$target"
            return
        fi
    done
    echo "error: NIC '${nic}' disappeared between probe and move" >&2
    exit 1
}

case "${1:-}" in
    "--up")
        require_root "$@"
        if [[ $# -lt 3 ]]; then
            echo "error: --up needs RX_NIC and TX_NIC arguments" >&2
            usage
            exit 1
        fi
        setup "$2" "$3"
        ;;
    "--cleanup"|"--down")
        require_root "$@"
        cleanup
        ;;
    "--info")
        info
        ;;
    "-h"|"--help"|"")
        usage
        ;;
    *)
        echo "error: unknown arg: $1" >&2
        usage
        exit 1
        ;;
esac
