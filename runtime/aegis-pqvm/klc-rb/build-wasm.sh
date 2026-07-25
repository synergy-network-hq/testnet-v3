#!/bin/bash
# Build script for klc-rb WASM module

set -e

echo "🔨 Building klc-rb for WebAssembly..."

# Check if wasm-pack is installed
if ! command -v wasm-pack &> /dev/null; then
    echo "❌ wasm-pack not found. Installing..."
    cargo install wasm-pack
fi

# Build for web target
echo "📦 Building with wasm-pack (web target)..."
wasm-pack build --target web --out-dir pkg --features wasm,mlkem,mldsa,serde

# Build for nodejs target
echo "📦 Building with wasm-pack (nodejs target)..."
wasm-pack build --target nodejs --out-dir pkg-nodejs --features wasm,mlkem,mldsa,serde

# Build for bundler target
echo "📦 Building with wasm-pack (bundler target)..."
wasm-pack build --target bundler --out-dir pkg-bundler --features wasm,mlkem,mldsa,serde

echo "✅ Build complete!"
echo ""
echo "Generated packages:"
echo "  - pkg/          (web target)"
echo "  - pkg-nodejs/   (nodejs target)"
echo "  - pkg-bundler/  (bundler target)"
echo ""
echo "To use in JavaScript:"
echo "  import init from './pkg/aegis_klc_rb.js';"
echo "  const wasm = await init();"
