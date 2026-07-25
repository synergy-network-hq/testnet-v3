#!/bin/bash

# Script to update binary distribution after building
# Run this on the server after building a new binary

set -e

BINARY_DIR="/var/www/synergy-portal/binaries"
PROJECT_DIR="/opt/synergy/synergy-testnet"

echo "🔄 Updating binary distribution..."
echo "===================================="

# Detect platform
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    PLATFORM="linux"
    ARCH="x86_64"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    PLATFORM="macos"
    ARCH=$(uname -m)
else
    echo "❌ Unsupported platform: $OSTYPE"
    exit 1
fi

echo "📦 Platform: $PLATFORM ($ARCH)"
echo ""

# Build the binary
cd "$PROJECT_DIR"
echo "🔨 Building release binary..."
cargo build --release

if [ $? -ne 0 ]; then
    echo "❌ Build failed!"
    exit 1
fi

BINARY_PATH="target/release/synergy-testnet"

if [ ! -f "$BINARY_PATH" ]; then
    echo "❌ Binary not found at $BINARY_PATH"
    exit 1
fi

# Get version info
VERSION=$(grep '^version' src/Cargo.toml | cut -d'"' -f2 || echo "0.1.0")
COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# Calculate checksum and size
if [[ "$PLATFORM" == "linux" ]]; then
    SIZE=$(stat -c%s "$BINARY_PATH")
    SHA256=$(sha256sum "$BINARY_PATH" | cut -d' ' -f1)
else
    SIZE=$(stat -f%z "$BINARY_PATH")
    SHA256=$(shasum -a 256 "$BINARY_PATH" | cut -d' ' -f1)
fi

echo "✅ Build completed!"
echo "   Version: $VERSION"
echo "   Commit: $COMMIT"
echo "   Size: $SIZE bytes"
echo "   SHA256: $SHA256"
echo ""

# Copy binary to distribution directory
mkdir -p "$BINARY_DIR/$PLATFORM"
cp "$BINARY_PATH" "$BINARY_DIR/$PLATFORM/synergy-testnet"
chmod +x "$BINARY_DIR/$PLATFORM/synergy-testnet"

# Create checksum file
if [[ "$PLATFORM" == "linux" ]]; then
    echo "$SHA256  synergy-testnet" > "$BINARY_DIR/$PLATFORM/synergy-testnet.sha256"
else
    echo "$SHA256  synergy-testnet" > "$BINARY_DIR/$PLATFORM/synergy-testnet.sha256"
fi

echo "✅ Binary copied to $BINARY_DIR/$PLATFORM/"
echo ""

# Update latest.json
echo "📝 Updating latest.json..."
python3 << EOF
import json
import os

json_path = "$BINARY_DIR/latest.json"
with open(json_path, 'r') as f:
    data = json.load(f)

# Update version info
data['version'] = "$VERSION"
data['commit'] = "$COMMIT"
data['build_date'] = "$BUILD_DATE"

# Update platform info
platform_key = "$PLATFORM"
if platform_key in data['platforms']:
    data['platforms'][platform_key]['sha256'] = "$SHA256"
    data['platforms'][platform_key]['size'] = $SIZE
    data['platforms'][platform_key]['arch'] = "$ARCH"

# Write back
with open(json_path, 'w') as f:
    json.dump(data, f, indent=2)

print(f"✅ Updated {platform_key} platform info in latest.json")
EOF

echo ""
echo "✅ Distribution updated successfully!"
echo ""
echo "📊 Distribution URLs:"
echo "   Binary: https://testnet.synergy-network.io/binaries/$PLATFORM/synergy-testnet"
echo "   Checksum: https://testnet.synergy-network.io/binaries/$PLATFORM/synergy-testnet.sha256"
echo "   Info: https://testnet.synergy-network.io/binaries/latest.json"
echo ""

