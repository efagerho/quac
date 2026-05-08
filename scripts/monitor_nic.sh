#!/usr/bin/env bash

# pps.sh
# Print RX/TX packets per second for a network interface

IFACE="${1:-eth0}"

if [[ ! -d "/sys/class/net/$IFACE" ]]; then
    echo "Interface '$IFACE' not found"
    exit 1
fi

RX_PREV=$(cat /sys/class/net/$IFACE/statistics/rx_packets)
TX_PREV=$(cat /sys/class/net/$IFACE/statistics/tx_packets)
TIME_PREV=$(date +%s)

while true; do
    sleep 1

    RX_CUR=$(cat /sys/class/net/$IFACE/statistics/rx_packets)
    TX_CUR=$(cat /sys/class/net/$IFACE/statistics/tx_packets)
    TIME_CUR=$(date +%s)

    DT=$((TIME_CUR - TIME_PREV))

    RX_PPS=$(((RX_CUR - RX_PREV) / DT))
    TX_PPS=$(((TX_CUR - TX_PREV) / DT))

    printf "%s  RX: %10d pps  TX: %10d pps\n" \
        "$(date '+%H:%M:%S')" \
        "$RX_PPS" \
        "$TX_PPS"

    RX_PREV=$RX_CUR
    TX_PREV=$TX_CUR
    TIME_PREV=$TIME_CUR
done
