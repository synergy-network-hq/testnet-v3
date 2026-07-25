#!/bin/bash

# Start Synergy Testnet Node with SynQ and PQC Support

echo "🚀 Starting Synergy Network Testnet with SynQ and PQC..."
echo "======================================================="

# Set script path to root of the project
cd "$(dirname "$0")/.."

# Prepare data directory
mkdir -p data/logs

# Kill any existing node processes
pkill -f synergy-testnet || true
sleep 1

# Build the main project
echo "🔨 Building Synergy Network core..."
cargo build --release

if [ $? -ne 0 ]; then
    echo "❌ Core build failed!"
    exit 1
fi

echo "✅ Core build completed successfully"

# Build SynQ components if they exist
if [ -d "SynQ" ]; then
    echo "🔨 Building SynQ programming language..."
    cd SynQ

    # Build SynQ compiler
    if [ -f "compiler/Cargo.toml" ]; then
        cd compiler && cargo build --release && cd ..
        if [ $? -ne 0 ]; then
            echo "⚠️ SynQ compiler build failed, continuing without SynQ..."
        else
            echo "✅ SynQ compiler built successfully"
        fi
    fi

    # Build SynQ VM
    if [ -f "vm/Cargo.toml" ]; then
        cd vm && cargo build --release && cd ..
        if [ $? -ne 0 ]; then
            echo "⚠️ SynQ VM build failed, continuing without SynQ VM..."
        else
            echo "✅ SynQ VM built successfully"
        fi
    fi

    cd ..
fi

# Build Aegis PQVM if available
if [ -d "node_modules/aegis-pqvm" ]; then
    echo "🔨 Building Aegis PQVM..."
    cd node_modules/aegis-pqvm

    # Try to build with available dependencies
    if command -v cargo &> /dev/null; then
        cargo build --release 2>/dev/null || echo "⚠️ Aegis PQVM build failed (missing dependencies)"
    fi

    cd ../..
fi

echo "🎯 Starting Synergy Network node..."
echo "   Features:"
echo "   - Blockchain consensus (Proof of Synergy)"
echo "   - Native SNRG token system"
echo "   - Validator rewards and staking"
echo "   - Transaction processing"
echo "   - Block production"
echo "   - Synergy address formatting"
echo ""
echo "   RPC: http://localhost:8545"
echo "   WebSocket: ws://localhost:8546"
echo ""
echo "Press Ctrl+C to stop the node"

# Start node in background
nohup ./target/release/synergy-testnet start \
  > data/logs/testnet.out 2>&1 &

NODE_PID=$!
echo "✅ Synergy testnet started with PID $NODE_PID"
echo $NODE_PID > data/synergy-testnet.pid
