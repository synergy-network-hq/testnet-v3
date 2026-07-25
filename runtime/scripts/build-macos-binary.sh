#!/bin/bash

# Build script for macOS ARM64 binary
# Run this on a macOS system (M1/M2/M3 Mac)

set -e

echo "🔨 Building Synergy Testnet binary for macOS ARM64..."
echo "===================================================="

# Check if we're on macOS
if [[ "$OSTYPE" != "darwin"* ]]; then
    echo "❌ Error: This script must be run on macOS"
    exit 1
fi

# Check if we're on ARM64
ARCH=$(uname -m)
if [[ "$ARCH" != "arm64" ]]; then
    echo "⚠️  Warning: Not on ARM64 architecture (current: $ARCH)"
    echo "   The binary will be built for the current architecture"
fi

# Check for Rust
if ! command -v cargo &> /dev/null; then
    echo "❌ Error: Rust/Cargo not found"
    echo "   Install with: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
    exit 1
fi

echo "✅ Rust version: $(rustc --version)"
echo "✅ Cargo version: $(cargo --version)"
echo ""

# Get the project directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_DIR="$( cd "$SCRIPT_DIR/.." && pwd )"

cd "$PROJECT_DIR"

echo "📦 Building release binary..."
cargo build --release

if [ $? -ne 0 ]; then
    echo "❌ Build failed!"
    exit 1
fi

# Get version info
VERSION=$(grep '^version' src/Cargo.toml | cut -d'"' -f2 || echo "0.1.0")
COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

echo ""
echo "✅ Build completed successfully!"
echo ""
echo "📊 Build Information:"
echo "   Version: $VERSION"
echo "   Commit: $COMMIT"
echo "   Build Date: $BUILD_DATE"
echo "   Architecture: $ARCH"
echo "   Binary: target/release/synergy-testnet"
echo ""

# Calculate checksum
BINARY_PATH="target/release/synergy-testnet"
if [ -f "$BINARY_PATH" ]; then
    SIZE=$(stat -f%z "$BINARY_PATH")
    SHA256=$(shasum -a 256 "$BINARY_PATH" | cut -d' ' -f1)
    
    echo "📦 Binary Details:"
    echo "   Size: $SIZE bytes ($(echo "scale=2; $SIZE/1024/1024" | bc) MB)"
    echo "   SHA256: $SHA256"
    echo ""
    
    # Create checksum file
    echo "$SHA256  synergy-testnet" > "$BINARY_PATH.sha256"
    echo "✅ Checksum file created: $BINARY_PATH.sha256"
    echo ""
    
    echo "📤 To upload to distribution server:"
    echo "   scp $BINARY_PATH user@server:/var/www/synergy-portal/binaries/macos/synergy-testnet"
    echo "   scp $BINARY_PATH.sha256 user@server:/var/www/synergy-portal/binaries/macos/synergy-testnet.sha256"
    echo ""
    echo "   Then update latest.json with:"
    echo "   - sha256: $SHA256"
    echo "   - size: $SIZE"
    echo "   - commit: $COMMIT"
    echo "   - build_date: $BUILD_DATE"
else
    echo "❌ Binary not found at $BINARY_PATH"
    exit 1
fi


