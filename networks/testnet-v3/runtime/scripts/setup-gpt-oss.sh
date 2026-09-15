#!/bin/bash

# Synergy Network AIVM GPT-OSS Setup Script
# This script sets up the GPT-OSS-20B model for AIVM interactions

echo "🤖 Setting up GPT-OSS-20B for Synergy Network AIVM..."
echo "=================================================="

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is required but not installed."
    echo "Please install Python 3.8+ and try again."
    exit 1
fi

# Check if pip is installed
if ! command -v pip3 &> /dev/null; then
    echo "❌ pip3 is required but not installed."
    echo "Please install pip3 and try again."
    exit 1
fi

echo "✅ Python and pip found"

# Prepare virtual environment to avoid system package conflicts
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/.gpt-oss-env"

create_venv() {
    echo "🧱 Creating virtual environment at $VENV_DIR..."
    rm -rf "$VENV_DIR"
    python3 -m venv "$VENV_DIR" || {
        echo "❌ Failed to create virtual environment"
        exit 1
    }
}

if [ ! -f "$VENV_DIR/bin/activate" ]; then
    create_venv
fi

# shellcheck source=/dev/null
if ! source "$VENV_DIR/bin/activate"; then
    echo "❌ Failed to activate virtual environment"
    exit 1
fi

echo "📦 Installing required Python packages into virtual environment..."
pip install --upgrade pip
pip install "transformers[serving]" torch || {
    echo "❌ Failed to install required packages inside virtual environment"
    echo "Please install manually: $VENV_DIR/bin/pip install transformers torch"
    deactivate
    exit 1
}

echo "✅ Packages installed successfully"

# Start the transformers server
echo "🚀 Starting GPT-OSS model server..."
echo "Note: This will download the GPT-OSS-20B model (~20GB)"
echo "Press Ctrl+C to stop the server"

# Start the server in background
transformers serve &
SERVER_PID=$!

echo "⏳ Waiting for server to start..."
sleep 5

# Test the server
echo "🔍 Testing server connection..."
curl -s http://localhost:8000/health || echo "Server may still be starting..."

echo ""
echo "🎉 GPT-OSS setup complete!"
echo ""
echo "Server Details:"
echo "- URL: http://localhost:8000"
echo "- Model: openai/gpt-oss-20b"
echo "- Status: Running (PID: $SERVER_PID)"
echo ""
echo "To start chatting with the model:"
echo "transformers chat localhost:8000 --model-name-or-path openai/gpt-oss-20b"
echo ""
echo "To stop the server:"
echo "kill $SERVER_PID"
echo ""
echo "The AIVM will now be able to use GPT-OSS for personable interactions!"
echo "You can now use AIVM features in the Synergy Network Testnet."

# Keep the script running to show server status
wait $SERVER_PID
