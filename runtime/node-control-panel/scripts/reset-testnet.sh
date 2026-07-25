#!/bin/bash

# Synergy Testnet Reset Script
# This script stops all node processes, resets the blockchain to block 0, and restarts the testnet

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BINARY="$PROJECT_DIR/target/release/synergy-testnet"
DATA_DIR="$PROJECT_DIR/data"
PID_FILE="$DATA_DIR/synergy-testnet.pid"

if [[ -z "${SYNERGY_LEGACY_RESET:-}" && -x "$PROJECT_DIR/scripts/testnet/reset-testnet.sh" ]]; then
    exec "$PROJECT_DIR/scripts/testnet/reset-testnet.sh" "$@"
fi

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

stop_pid() {
    local pid="$1"
    if [ -z "$pid" ]; then
        return
    fi
    if kill -0 "$pid" 2>/dev/null; then
        kill "$pid" 2>/dev/null || true
        for _ in {1..10}; do
            if ! kill -0 "$pid" 2>/dev/null; then
                return
            fi
            sleep 1
        done
        kill -9 "$pid" 2>/dev/null || true
    fi
}

stop_by_pid_file() {
    local pid_file="$1"
    if [ -f "$pid_file" ]; then
        local pid
        pid=$(cat "$pid_file" 2>/dev/null || echo "")
        stop_pid "$pid"
        rm -f "$pid_file"
    fi
}

kill_synergy_processes() {
    local pids
    pids=$(pgrep -f "$BINARY" 2>/dev/null || true)
    for pid in $pids; do
        stop_pid "$pid"
    done

    pids=$(pgrep -x "synergy-testnet" 2>/dev/null || true)
    for pid in $pids; do
        stop_pid "$pid"
    done
}

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  Synergy Testnet Reset Script${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Check if binary exists
if [ ! -f "$BINARY" ]; then
    echo -e "${RED}Error: Binary not found at $BINARY${NC}"
    echo -e "${YELLOW}Please run: cargo build --release${NC}"
    exit 1
fi

# Step 1: Kill all synergy-testnet processes
echo -e "${YELLOW}[1/3] Stopping all synergy-testnet processes...${NC}"

# Stop bootnodes via their script first (avoids killing this script by accident)
if [ -f "$PROJECT_DIR/archive/start-bootnodes.sh" ]; then
    "$PROJECT_DIR/archive/start-bootnodes.sh" stop >/dev/null 2>&1 || true
fi

# Kill by PID file if it exists
stop_by_pid_file "$PID_FILE"

# Kill any bootnode processes
for pid_file in "$DATA_DIR"/bootnode*.pid; do
    stop_by_pid_file "$pid_file"
done

# Kill any remaining synergy-testnet processes (avoid broad pkill that can kill this script)
kill_synergy_processes

sleep 1
echo -e "${GREEN}  ✓ All processes stopped${NC}"

# Step 2: Reset blockchain data
echo -e "${YELLOW}[2/3] Resetting blockchain to block 0...${NC}"

# Remove blockchain state files (validator node)
rm -f "$DATA_DIR/chain.json"
rm -f "$DATA_DIR/token_state.json"
rm -f "$DATA_DIR/validator_registry.json"
rm -f "$DATA_DIR/committed_qcs.json"
rm -f "$DATA_DIR/committed_qcs.json.tmp"
rm -f "$DATA_DIR/canonical_locks.json"
rm -f "$DATA_DIR/canonical_locks.json.tmp"
rm -f "$DATA_DIR/consensus_vote_locks.json"
rm -f "$DATA_DIR/consensus_vote_locks.json.tmp"
rm -f "$DATA_DIR/dag_state.json"
rm -f "$DATA_DIR"/*.pid

# Find and reset bootnode1's chain data if it's running from a different location
# All paths in the code are RELATIVE, so if bootnode1 was started from a different
# working directory, it would have its chain.json in that directory's data/ folder
echo "  Checking for bootnode1 processes running from different locations..."

# Find all synergy-testnet processes that might be bootnode1
# Use timeout to prevent hanging if pgrep has issues
PGREP_OUTPUT=$(timeout 3 pgrep -f "synergy-testnet.*bootnode\|synergy-testnet.*--config.*bootnode1" 2>/dev/null || echo "")
for pid in $PGREP_OUTPUT; do
    # Get the working directory of this process
    if [ -d "/proc/$pid" ] 2>/dev/null; then
        wd=$(readlink -f "/proc/$pid/cwd" 2>/dev/null || echo "")
        if [ -n "$wd" ] && [ "$wd" != "$PROJECT_DIR" ]; then
            echo "  Found bootnode1 process (PID: $pid) running from: $wd"
            # Delete chain.json from that location
            if [ -f "$wd/data/chain.json" ]; then
                rm -f "$wd/data/chain.json"
                echo "    ✓ Deleted chain.json from $wd/data/"
            fi
            rm -f "$wd/data/committed_qcs.json" "$wd/data/committed_qcs.json.tmp"
            rm -f "$wd/data/canonical_locks.json" "$wd/data/canonical_locks.json.tmp"
            rm -f "$wd/data/consensus_vote_locks.json" "$wd/data/consensus_vote_locks.json.tmp"
            rm -f "$wd/data/dag_state.json"
            # Also check for environment variable override
            if [ -f "/proc/$pid/environ" ] 2>/dev/null; then
                data_path=$(timeout 2 cat "/proc/$pid/environ" 2>/dev/null | tr '\0' '\n' | grep "^SYNERGY_DATA_PATH=" | cut -d= -f2 || echo "")
                if [ -n "$data_path" ] && [ -f "$data_path/chain.json" ]; then
                    rm -f "$data_path/chain.json"
                    echo "    ✓ Deleted chain.json from SYNERGY_DATA_PATH: $data_path"
                fi
                if [ -n "$data_path" ]; then
                    rm -f "$data_path/committed_qcs.json" "$data_path/committed_qcs.json.tmp"
                    rm -f "$data_path/canonical_locks.json" "$data_path/canonical_locks.json.tmp"
                    rm -f "$data_path/consensus_vote_locks.json" "$data_path/consensus_vote_locks.json.tmp"
                    rm -f "$data_path/dag_state.json"
                fi
            fi
        fi
    fi
done

# Also check for bootnode1 PID files in the main data directory
if [ -f "$DATA_DIR/bootnode1.pid" ]; then
    echo "  Bootnode1 PID file found in main data directory"
    bootnode_pid=$(cat "$DATA_DIR/bootnode1.pid" 2>/dev/null)
    if [ -n "$bootnode_pid" ] && [ -d "/proc/$bootnode_pid" ]; then
        wd=$(readlink -f "/proc/$bootnode_pid/cwd" 2>/dev/null || echo "")
        if [ -n "$wd" ] && [ "$wd" != "$PROJECT_DIR" ]; then
            echo "    Bootnode1 (PID: $bootnode_pid) running from: $wd"
            if [ -f "$wd/data/chain.json" ]; then
                rm -f "$wd/data/chain.json"
                echo "    ✓ Deleted chain.json from $wd/data/"
            fi
            rm -f "$wd/data/committed_qcs.json" "$wd/data/committed_qcs.json.tmp"
            rm -f "$wd/data/canonical_locks.json" "$wd/data/canonical_locks.json.tmp"
            rm -f "$wd/data/consensus_vote_locks.json" "$wd/data/consensus_vote_locks.json.tmp"
            rm -f "$wd/data/dag_state.json"
        fi
    fi
fi

# Create reset flag to prevent immediate network sync
touch "$DATA_DIR/.reset_flag"

# Clear chain data directory (used by RocksDB storage)
rm -rf "$DATA_DIR/chain"

# Clear logs
rm -rf "$DATA_DIR/logs"

# Ensure directories exist
mkdir -p "$DATA_DIR/chain" "$DATA_DIR/logs"

echo -e "${GREEN}  ✓ Blockchain data cleared (validator + all bootnodes)${NC}"

# Step 3: Start the bootnode
echo -e "${YELLOW}[3/3] Starting bootnode...${NC}"

cd "$PROJECT_DIR"

# Start bootnode using the start-bootnodes.sh script
if [ -f "$PROJECT_DIR/archive/start-bootnodes.sh" ]; then
    echo "  Starting bootnode1..."
    # Start bootnode quietly; logs are in data/logs/bootnode1.out
    if ! "$PROJECT_DIR/archive/start-bootnodes.sh" start >/dev/null 2>&1; then
        echo -e "${RED}  ✗ Bootnode startup failed${NC}"
        echo -e "${YELLOW}  Check logs: tail -f $DATA_DIR/logs/bootnode1.out${NC}"
        exit 1
    fi

    # Verify bootnode is running
    BOOTNODE_PID_FILE="$DATA_DIR/bootnode1.pid"
    if [ -f "$BOOTNODE_PID_FILE" ]; then
        BOOTNODE_PID=$(cat "$BOOTNODE_PID_FILE" 2>/dev/null || echo "")
        if [ -n "$BOOTNODE_PID" ] && kill -0 "$BOOTNODE_PID" 2>/dev/null; then
            echo -e "${GREEN}  ✓ Bootnode started (PID: $BOOTNODE_PID)${NC}"
        else
            echo -e "${RED}  ✗ Failed to start bootnode (PID $BOOTNODE_PID not running)${NC}"
            echo -e "${YELLOW}  Check logs: tail -f $DATA_DIR/logs/bootnode1.out${NC}"
            exit 1
        fi
    else
        echo -e "${RED}  ✗ Bootnode PID file not found${NC}"
        echo -e "${YELLOW}  Check logs: tail -f $DATA_DIR/logs/bootnode1.out${NC}"
        exit 1
    fi
else
    echo -e "${RED}Error: start-bootnodes.sh not found at $PROJECT_DIR/archive/start-bootnodes.sh${NC}"
    exit 1
fi

# Check block height (single probe; RPC may still be warming up)
echo ""
echo -e "${BLUE}Verifying blockchain state...${NC}"
sleep 3
BLOCK_HEIGHT=$(timeout 3 curl -s http://127.0.0.1:5640 -X POST -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"synergy_blockNumber","params":[],"id":1}' 2>/dev/null | \
    grep -o '"result":[0-9]*' | cut -d':' -f2 || true)

if [ -n "$BLOCK_HEIGHT" ]; then
    echo -e "${GREEN}  ✓ Current block height: $BLOCK_HEIGHT${NC}"
else
    echo -e "${YELLOW}  ⚠ Could not verify block height (RPC may still be initializing)${NC}"
    echo -e "${YELLOW}  Check logs: tail -f $DATA_DIR/logs/bootnode1.out${NC}"
fi

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  Testnet reset complete!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo -e "View logs: ${BLUE}tail -f $DATA_DIR/logs/bootnode1.out${NC}"
echo -e "Check status: ${BLUE}$PROJECT_DIR/testnet.sh status${NC}"
