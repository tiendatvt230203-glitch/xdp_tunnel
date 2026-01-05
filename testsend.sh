#!/bin/bash
# SERVER1 (bên gửi)
# Usage: ./monitor_sender.sh [wan_interface] [local_interface]

WAN="${1:-ens37}"
LOCAL="${2:-ens33}"
TMP1="/tmp/tcpdump_wan_$$"
TMP2="/tmp/tcpdump_local_$$"

show_result() {
    echo ""
    echo "========== KẾT QUẢ =========="
    echo ""
    echo "--- TỪ CLIENT ($LOCAL) ---"
    RECV_CLIENT=$(grep -c "length [1-9]" $TMP2 2>/dev/null || echo 0)
    echo "Packets nhận: $RECV_CLIENT"
    echo ""
    echo "--- RA WAN ($WAN) ---"
    SENT_WAN=$(grep -c "length [1-9]" $TMP1 2>/dev/null || echo 0)
    ACK_RECV=$(grep "length 0" $TMP1 | grep -c ", ack" 2>/dev/null || echo 0)
    RETRANS=$(grep -ci "retransmission" $TMP1 2>/dev/null || echo 0)
    echo "Packets gửi:  $SENT_WAN"
    echo "ACK nhận:     $ACK_RECV"
    echo "Retrans:      $RETRANS"
    echo ""
    echo "=============================="
    rm -f $TMP1 $TMP2
    exit 0
}

trap show_result INT TERM

echo "=== SERVER1 (SENDER) ==="
echo "Local: $LOCAL | WAN: $WAN"
echo "Ctrl+C để xem kết quả"
echo ""

tcpdump -i $LOCAL -nn -l tcp 2>/dev/null > $TMP2 &
tcpdump -i $WAN -nn -l tcp 2>/dev/null > $TMP1 &

while true; do sleep 1; done
