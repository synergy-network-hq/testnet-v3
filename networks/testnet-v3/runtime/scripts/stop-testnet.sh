#!/bin/bash

# Stop the Synergy Testnet Node

echo "🛑 Stopping Synergy Testnet..."

cd "$(dirname "$0")/.."

if [ -f data/synergy-testnet.pid ]; then
    NODE_PID=$(cat data/synergy-testnet.pid)

    if ps -p "$NODE_PID" > /dev/null; then
        kill "$NODE_PID"
        echo "✅ Node process $NODE_PID terminated."
    else
        echo "⚠️ PID $NODE_PID not running. Skipping kill."
    fi

    rm -f data/synergy-testnet.pid
else
    echo "⚠️ No PID file found. Attempting to kill any matching synergy-testnet processes..."
    pkill -f synergy-testnet || echo "No processes matched."
fi

echo "🧹 Synergy Testnet shutdown complete."
