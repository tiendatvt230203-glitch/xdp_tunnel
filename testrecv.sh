#!/bin/bash
# SERVER2 (bên nhận)
# Usage: ./monitor_receiver.sh [wan_interface] [local_interface]

WAN="${1:-ens37}"
LOCAL="${2:-ens33}"
TMP1="/tmp/tcpdump_wan_$$"
TMP2="/tmp/tcpdump_local_$$"

show_result() {
    echo ""
    echo "========== KẾT QUẢ =========="
    echo ""
    echo "--- TỪ WAN ($WAN) ---"
    RECV_WAN=$(grep -c "length [1-9]" $TMP1 2>/dev/null || echo 0)
    DUP_ACK=$(grep -ci "dup ack" $TMP1 2>/dev/null || echo 0)
    OOO=$(grep -ci "out-of-order" $TMP1 2>/dev/null || echo 0)
    echo "Packets nhận: $RECV_WAN"
    echo "Dup ACK:      $DUP_ACK"
    echo "Out-of-order: $OOO"
    echo ""
    echo "--- RA CLIENT ($LOCAL) ---"
    SENT_CLIENT=$(grep -c "length [1-9]" $TMP2 2>/dev/null || echo 0)
    ACK_SENT=$(grep "length 0" $TMP1 | grep -c ", ack" 2>/dev/null || echo 0)
    echo "Packets gửi:  $SENT_CLIENT"
    echo "ACK gửi:      $ACK_SENT"
    echo ""
    echo "=============================="
    rm -f $TMP1 $TMP2
    exit 0
}

trap show_result INT TERM

echo "=== SERVER2 (RECEIVER) ==="
echo "WAN: $WAN | Local: $LOCAL"
echo "Ctrl+C để xem kết quả"
echo ""

tcpdump -i $WAN -nn -l tcp 2>/dev/null > $TMP1 &
tcpdump -i $LOCAL -nn -l tcp 2>/dev/null > $TMP2 &

while true; do sleep 1; done
