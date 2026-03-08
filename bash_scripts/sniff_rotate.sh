#!/usr/bin/env bash
set -euo pipefail

INTERFACE="eth0"
PCAP_DIR="../data/pcaps"
DURATION=20

# Check tcpdump exists
if ! command -v tcpdump >/dev/null 2>&1; then
    echo "tcpdump not installed."
    exit 1
fi

# Ensure directory exists
if [ ! -d "$PCAP_DIR" ]; then
    echo "Error: $PCAP_DIR does not exist. Run setup_dirs.sh first."
    exit 1
fi

echo "Starting capture on interface: $INTERFACE"
echo "Saving pcaps to: $PCAP_DIR"
echo "Press Ctrl+C to stop."

trap 'echo "Stopping capture..."; exit 0' SIGINT SIGTERM

while true
do
    TIMESTAMP=$(date +""%Y-%m-%d_%H-%M-%S"")
    OUTFILE="$PCAP_DIR/capture-$TIMESTAMP.pcap"

    echo "Capturing -> $OUTFILE"

    tcpdump -i "$INTERFACE" -s 0 -w "$OUTFILE" &
    TCP_PID=$!

    sleep "$DURATION"

    kill "$TCP_PID" 2>/dev/null
    wait "$TCP_PID" 2>/dev/null
done