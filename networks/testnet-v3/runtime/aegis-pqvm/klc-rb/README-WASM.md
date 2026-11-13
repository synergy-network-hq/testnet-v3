# Building klc-rb for JavaScript/WebAssembly

This guide explains how to build the `klc-rb` (Key Lifecycle Manager and Quantum Randomness Beacon) crate for use in JavaScript/TypeScript environments.

## Prerequisites

- Rust toolchain (latest stable)
- `wasm-pack`: `cargo install wasm-pack`

## Quick Start

```bash
# Build for all targets (web, nodejs, bundler)
./build-wasm.sh

# Or build individually:
npm run build:web      # For browser usage
npm run build:node     # For Node.js usage
npm run build:bundler  # For bundler (webpack, etc.)
```

## Build Output

After building, you'll have:

- `pkg/` - Web target (for direct browser usage)
- `pkg-nodejs/` - Node.js target
- `pkg-bundler/` - Bundler target (webpack, vite, etc.)

Each directory contains:
- `aegis_klc_rb.js` - JavaScript bindings
- `aegis_klc_rb_bg.wasm` - WebAssembly binary
- `aegis_klc_rb.d.ts` - TypeScript definitions

## Usage Examples

### Browser (ES Modules)

```html
<!DOCTYPE html>
<html>
<head>
    <script type="module">
        import init from './pkg/aegis_klc_rb.js';
        
        async function main() {
            // Initialize WASM
            const wasm = await init();
            
            // Create key lifecycle manager
            const klm = new wasm.KeyLifecycleManager();
            
            // Create a rotation policy
            const policy = new wasm.RotationPolicy(
                "my-policy",
                "MLDSA87",
                1000000,
                7776000, // 90 days
                true,
                false,
                0.8
            );
            
            // Register policy
            klm.register_policy_js(policy);
            
            // Generate a key
            const keyId = klm.generate_key_js("my-policy");
            console.log("Generated key ID:", keyId);
            
            // Use the key
            klm.record_usage_js(keyId, "encryption");
            
            // Get statistics
            const stats = klm.get_statistics_js();
            console.log("Total keys:", stats.total_keys_js());
        }
        
        main().catch(console.error);
    </script>
</head>
<body></body>
</html>
```

### Node.js

```javascript
import init from './pkg-nodejs/aegis_klc_rb.js';

async function main() {
    const wasm = await init();
    
    // Create quantum randomness beacon
    const beacon = new wasm.QuantumBeacon();
    
    // Generate beacon output
    const output = beacon.generate("default");
    console.log("Epoch:", output.epoch());
    console.log("Randomness:", output.randomness());
    
    // Verify beacon
    const result = beacon.verify(output);
    console.log("Valid:", result.is_valid());
}

main().catch(console.error);
```

### TypeScript

```typescript
import init, { KeyLifecycleManager, RotationPolicy } from './pkg/aegis_klc_rb';

async function main() {
    const wasm = await init();
    
    const klm = new wasm.KeyLifecycleManager();
    const policy = new wasm.RotationPolicy(
        "policy-1",
        "MLKEM768",
        500000,
        2592000, // 30 days
        true,
        false,
        0.75
    );
    
    klm.register_policy_js(policy);
    const keyId = klm.generate_key_js("policy-1");
    
    console.log(`Generated key: ${keyId}`);
}
```

## Available APIs

### KeyLifecycleManager

- `new KeyLifecycleManager()` - Create new manager
- `register_policy_js(policy)` - Register rotation policy
- `generate_key_js(policy_id)` - Generate new key
- `record_usage_js(key_id, operation_type)` - Record key usage
- `check_rotation_needed_js(key_id)` - Check if rotation needed
- `schedule_rotation_js(key_id, reason)` - Schedule rotation
- `execute_rotation_js(old_key_id)` - Execute rotation
- `retire_key_js(key_id, reason)` - Retire key
- `destroy_key_js(key_id)` - Destroy key with proof
- `get_key_metadata_js(key_id)` - Get key metadata
- `get_audit_trail_js(key_id)` - Get audit trail
- `get_audit_root_js()` - Get Merkle root
- `verify_destruction_proof_js(proof)` - Verify destruction proof
- `get_statistics_js()` - Get statistics

### QuantumBeacon

- `new QuantumBeacon()` - Create new beacon
- `generate(policy_id)` - Generate beacon output
- `verify(output)` - Verify beacon output
- `epoch()` - Get current epoch
- `verification_key()` - Get verification key

### Utility Functions

- `hex_to_bytes(hex_string)` - Decode hex to bytes
- `bytes_to_hex(bytes)` - Encode bytes to hex

## Features

The build includes these features by default:
- `wasm` - WebAssembly bindings
- `mlkem` - ML-KEM support
- `mldsa` - ML-DSA support
- `serde` - Serialization support

## Troubleshooting

### Build Errors

If you get errors about missing dependencies:
```bash
cargo clean
cargo update
./build-wasm.sh
```

### Runtime Errors

Ensure you're using the correct target:
- Browser: Use `pkg/` (web target)
- Node.js: Use `pkg-nodejs/` (nodejs target)
- Bundler: Use `pkg-bundler/` (bundler target)

### Memory Issues

The WASM module manages memory automatically via wasm-bindgen. You don't need to manually allocate/free memory.

## Next Steps

- See `README.md` for more details about the crate
- Check the generated TypeScript definitions for full API documentation
- Run tests: `npm test` or `cargo test --features wasm`
