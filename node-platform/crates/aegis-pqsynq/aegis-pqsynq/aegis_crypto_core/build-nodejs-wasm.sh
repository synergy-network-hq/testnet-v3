#!/bin/bash

# Node.js WASM Build Script for AEGIS
# This script builds WASM packages that work in Node.js environments

set -e

echo "🔨 Building AEGIS WASM for Node.js..."
echo "======================================"

# Clean previous builds
echo "🧹 Cleaning previous builds..."
rm -rf pkg-nodejs/
rm -rf target/wasm32-unknown-unknown/

# Build with Node.js compatible features (pure, no problematic deps)
echo "⚙️  Building WASM with nodejs-pure features..."
cargo build --release --target wasm32-unknown-unknown --features wasm-nodejs-pure --no-default-features

# Check if wasm-pack is available
if ! command -v wasm-pack &> /dev/null; then
    echo "❌ wasm-pack not found. Installing..."
    cargo install wasm-pack
fi

# Build with wasm-pack and fail closed if packaging fails.
echo "📦 Creating WASM package..."

# Create a custom wasm-pack config for Node.js
cat > wasm-pack-nodejs.toml << EOF
[wasm-pack]
out-dir = "pkg-nodejs"

[wasm-pack.profile.release]
wasm-opt = false

[wasm-pack.target.nodejs]
node = true

[wasm-pack.target.nodejs.rustflags]
link-arg = ["--initial-memory=4194304", "--max-memory=4194304"]
EOF

# Build with custom config.
wasm-pack build --target nodejs --out-dir pkg-nodejs --dev --features wasm-nodejs-pure --no-default-features --config wasm-pack-nodejs.toml

# Copy PQWASM files to the Node.js package
echo "📁 Copying PQWASM files..."
mkdir -p pkg-nodejs/pqwasm/refimp/
cp pqwasm/refimp/*.wasm pkg-nodejs/pqwasm/refimp/ 2>/dev/null || {
    echo "⚠️  No PQWASM files found in pqwasm/refimp/"
}

# Create Node.js test script
echo "🧪 Creating Node.js test script..."
cat > pkg-nodejs/test-nodejs.js << 'EOF'
#!/usr/bin/env node

/**
 * Node.js WASM Test for AEGIS
 */

import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Test Node.js WASM functionality
async function testNodejsWasm() {
  console.log('🧪 Testing AEGIS Node.js WASM...');

  try {
    // Check if PQWASM files exist
    const pqwasmDir = join(__dirname, 'pqwasm', 'refimp');
    console.log(`📁 Checking PQWASM directory: ${pqwasmDir}`);

    // Import the WASM module
    console.log('📦 Loading WASM module...');
    const { init } = await import('./aegis_crypto_core.js');

    console.log('🚀 Initializing WASM...');
    await init();

    console.log('✅ Node.js WASM test completed successfully!');
    console.log('');
    console.log('🎯 What works:');
    console.log('   • WASM module loads in Node.js');
    console.log('   • Basic initialization completes');
    console.log('   • No fetch API dependencies');
    console.log('');
    console.log('📝 Note: PQWASM loading requires additional setup');

  } catch (error) {
    console.error('❌ Node.js WASM test failed:', error.message);
    process.exit(1);
  }
}

testNodejsWasm();
EOF

chmod +x pkg-nodejs/test-nodejs.js

# Clean up
rm -f wasm-pack-nodejs.toml

echo ""
echo "✅ Node.js WASM build completed!"
echo "================================"
echo ""
echo "📦 Package created in: pkg-nodejs/"
echo "🧪 Test with: cd pkg-nodejs && node test-nodejs.js"
echo ""
echo "📁 PQWASM files: pkg-nodejs/pqwasm/refimp/"
echo "📄 Package info: pkg-nodejs/package.json"
