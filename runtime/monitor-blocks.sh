#!/bin/bash
# Real-time block monitor for Synergy Testnet
# Usage: ./monitor-blocks.sh

RPC_URL="${RPC_URL:-http://127.0.0.1:5640/rpc}"

# Allow overriding via CLI argument
if [[ "$1" == "--rpc" && -n "$2" ]]; then
    RPC_URL="$2"
elif [[ "$1" =~ ^https?:// ]]; then
    RPC_URL="$1"
fi
INTERVAL=2  # Check every 2 seconds

echo "🔍 Synergy Testnet Block Monitor"
echo "================================"
echo "RPC: $RPC_URL"
echo "Override: RPC_URL env or './monitor-blocks.sh --rpc http://host:port/rpc'"
echo "Press Ctrl+C to stop"
echo ""

LAST_BLOCK=0

while true; do
    # Get current block number
    RESPONSE=$(curl -s -X POST "$RPC_URL" \
        -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","method":"synergy_blockNumber","params":[],"id":1}')

    BLOCK=$(echo $RESPONSE | jq -r '.result')

    if [ "$BLOCK" != "null" ] && [ "$BLOCK" != "$LAST_BLOCK" ]; then
        TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
        echo "[$TIMESTAMP] 🧱 New Block: #$BLOCK"
        LAST_BLOCK=$BLOCK
    fi

    sleep $INTERVAL
done
