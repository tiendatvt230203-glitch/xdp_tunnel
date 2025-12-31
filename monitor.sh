#!/bin/bash
# XDP Traffic Monitor - Tự động đọc WAN từ config

CONFIG_FILE="${1:-config/server1.conf}"

# Đọc WAN interfaces từ config
IFACES=$(grep "^wan " "$CONFIG_FILE" 2>/dev/null | awk '{print $2}')

if [ -z "$IFACES" ]; then
    echo "Error: Không tìm thấy WAN trong $CONFIG_FILE"
    echo "Usage: $0 [config_file]"
    exit 1
fi

# Lưu giá trị ban đầu
declare -A TX_START RX_START TX_PREV RX_PREV

for iface in $IFACES; do
    TX_START[$iface]=$(cat /sys/class/net/$iface/statistics/tx_packets 2>/dev/null || echo 0)
    RX_START[$iface]=$(cat /sys/class/net/$iface/statistics/rx_packets 2>/dev/null || echo 0)
    TX_PREV[$iface]=${TX_START[$iface]}
    RX_PREV[$iface]=${RX_START[$iface]}
done

clear
echo "=== XDP Traffic Monitor ==="
echo "Config: $CONFIG_FILE"
echo "WANs: $IFACES"
echo "Ctrl+C to stop"
echo ""
printf "%-10s %12s %12s %10s %10s\n" "Interface" "TX_Total" "RX_Total" "TX/s" "RX/s"
echo "--------------------------------------------------------"

while true; do
    # Cursor lên để overwrite
    tput cup 7 0

    for iface in $IFACES; do
        TX_NOW=$(cat /sys/class/net/$iface/statistics/tx_packets 2>/dev/null || echo 0)
        RX_NOW=$(cat /sys/class/net/$iface/statistics/rx_packets 2>/dev/null || echo 0)

        TX_TOTAL=$((TX_NOW - TX_START[$iface]))
        RX_TOTAL=$((RX_NOW - RX_START[$iface]))
        TX_RATE=$((TX_NOW - TX_PREV[$iface]))
        RX_RATE=$((RX_NOW - RX_PREV[$iface]))

        TX_PREV[$iface]=$TX_NOW
        RX_PREV[$iface]=$RX_NOW

        printf "%-10s %12d %12d %10d %10d\n" "$iface" "$TX_TOTAL" "$RX_TOTAL" "$TX_RATE" "$RX_RATE"
    done

    sleep 1
done
