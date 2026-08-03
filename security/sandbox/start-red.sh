#!/usr/bin/env bash
# Start an isolated VELA server for red-team testing. Writes the PID to a file.
# Usage: start-red.sh <port> <datadir>
set -u
PORT="${1:-8465}"
DATA="${2:-/tmp/opencode/vela-red-current}"
pkill -f "target/debug/vela-server" 2>/dev/null
sleep 1
rm -rf "$DATA"
mkdir -p "$DATA"
setsid env DATA_DIR="$DATA" LISTEN_ADDR="127.0.0.1:${PORT}" RUST_LOG=warn \
    /home/hirew/Projects/VELA/serverVELA/target/debug/vela-server \
    > "$DATA/server.log" 2>&1 < /dev/null &
echo $! > "$DATA/pid"
for _ in $(seq 1 40); do
    if curl -sf -m 2 "http://127.0.0.1:${PORT}/health" >/dev/null 2>&1; then
        echo "READY ${PORT} (pid $(cat "$DATA/pid"))"
        exit 0
    fi
    sleep 0.25
done
echo "FAILED"; tail -20 "$DATA/server.log"; exit 1
