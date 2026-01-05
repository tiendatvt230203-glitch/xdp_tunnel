#!/bin/bash
# Monitor SENDER - Đếm packets gửi đi và ACK nhận về
# Usage: ./monitor_sender.sh <interface> <remote_ip>

IFACE="${1:-ens37}"
REMOTE_IP="${2:-10.0.0.2}"
TMPFILE="/tmp/tcpdump_sender_$$"

trap "rm -f $TMPFILE; exit" INT TERM

echo "=== SENDER Monitor ==="
echo "Interface: $IFACE"
echo "Remote IP: $REMOTE_IP"
echo "Ctrl+C to stop and show summary"
echo ""

# Start tcpdump in background
tcpdump -i $IFACE -nn -l host $REMOTE_IP 2>/dev/null | tee $TMPFILE &
TCPDUMP_PID=$!

# Wait for Ctrl+C
wait $TCPDUMP_PID 2>/dev/null

echo ""
echo "========== SUMMARY =========="

# Count packets
TOTAL=$(wc -l < $TMPFILE)
SENT=$(grep -c " > $REMOTE_IP" $TMPFILE 2>/dev/null || echo 0)
RECV=$(grep -c " < $REMOTE_IP\|$REMOTE_IP.*>" $TMPFILE 2>/dev/null || echo 0)
RECV=$(grep -E "$REMOTE_IP\.[0-9]+ >" $TMPFILE | wc -l)

# Data packets sent (có length > 0)
DATA_SENT=$(grep " > $REMOTE_IP" $TMPFILE | grep -c "length [1-9]" 2>/dev/null || echo 0)

# ACK received (từ remote về)
ACK_RECV=$(grep -E "$REMOTE_IP\.[0-9]+ >" $TMPFILE | grep -c ", ack" 2>/dev/null || echo 0)

# Retransmissions
RETRANS=$(grep -ci "retransmission\|dup ack" $TMPFILE 2>/dev/null || echo 0)

# SYN/FIN
SYN=$(grep -c "Flags \[S\]" $TMPFILE 2>/dev/null || echo 0)
FIN=$(grep -c "Flags \[F\]" $TMPFILE 2>/dev/null || echo 0)

echo "Total packets captured: $TOTAL"
echo ""
echo "--- SENT (to $REMOTE_IP) ---"
echo "Data packets:    $DATA_SENT"
echo "SYN packets:     $SYN"
echo "FIN packets:     $FIN"
echo ""
echo "--- RECEIVED (from $REMOTE_IP) ---"
echo "ACK packets:     $ACK_RECV"
echo "Retransmissions: $RETRANS"
echo ""
echo "=============================="

rm -f $TMPFILE
