# Aegis KLC-RB - Key Lifecycle Manager & Randomness Beacon

This package provides a self-contained implementation of the Aegis quantum randomness beacon and key lifecycle manager features. It can be moved completely out of the Aegis-PQC project and used independently.

## Contents

- **Quantum Randomness Beacon** - Verifiable quantum randomness generation
- **Key Lifecycle Manager** - Automated key generation, rotation, retirement, and destruction

## Structure

```markdown
klc-rb/
├── src/
│   ├── lib.rs                    # Main library entry point
│   ├── quantum_randomness_beacon.rs  # Beacon implementation
│   ├── key_lifecycle_manager.rs      # Lifecycle manager implementation
│   ├── algorithms/                   # Algorithm implementations
│   │   ├── mod.rs
│   │   ├── mlkem/                    # ML-KEM (mlkem) implementation
│   │   │   ├── mod.rs
│   │   │   ├── core.rs
│   │   │   ├── traits.rs
│   │   │   ├── utils.rs
│   │   │   └── wasm_bindings.rs
│   │   └── mldsa/                # ML-DSA (mldsa) implementation
│   │       ├── mod.rs
│   │       ├── core.rs
│   │       ├── utils.rs
│   │       └── wasm_bindings.rs
│   ├── hash.rs                       # Cryptographic hash utilities
│   └── utils.rs                      # Utility functions
├── Cargo.toml                        # Cargo configuration with dependencies
└── README.md                         # This file
```

## Dependencies

This package uses the following external crates (all available on crates.io):

- `pqrust-mlkem` - ML-KEM (mlkem) implementation
- `pqrust-mldsa` - ML-DSA (mldsa) implementation
- `pqrust-traits` - Common traits for PQC algorithms
- `sha3` - SHA-3 hash functions
- `blake3` - BLAKE3 hash function
- `zeroize` - Secure memory zeroing
- `getrandom` - Random number generation
- `serde` (optional) - Serialization support
- `wasm-bindgen` (optional) - WebAssembly bindings for JavaScript

All dependencies are standard Rust crates and will be automatically downloaded when building.

## Usage

### Rust

Add this to your `Cargo.toml`:

```toml
[dependencies]
aegis-klc-rb = { path = "./klc-rb" }
```

### JavaScript/TypeScript (WebAssembly)

To build for WebAssembly:

```bash
cd klc-rb
cargo install wasm-pack
wasm-pack build --target web --out-dir pkg
```

Or if using as a standalone crate, simply build it:

```bash
cd klc-rb
cargo build --features wasm
```

## Features

- `mlkem` (default) - Enable ML-KEM support
- `mldsa` (default) - Enable ML-DSA support
- `serde` (default) - Enable serialization support
- `wasm` - Enable WebAssembly bindings for JavaScript
- `hardware-entropy` - Enable hardware entropy sources

## Example Usage

### Rust

```rust
use aegis_klc_rb::{QuantumBeacon, KeyLifecycleManager};

// Create a new beacon
let mut beacon = QuantumBeacon::new();

// Generate a beacon output
let output = beacon.generate_beacon("default").unwrap();

// Create a lifecycle manager
let mut manager = KeyLifecycleManager::new();

// Generate a new key
let key_id = manager.generate_key("default").unwrap();
```

### JavaScript

```javascript
import init, { QuantumBeacon, verify_beacon_standalone_js } from './pkg/aegis_klc_rb.js';

await init();

// Create a new beacon
const beacon = new QuantumBeacon();

// Generate a beacon output
const output = beacon.generate("default");

// Access beacon data
console.log("Epoch:", output.epoch());
console.log("Randomness:", output.randomness());
console.log("Proof:", output.proof());

// Verify beacon standalone
const verificationKey = beacon.verification_key();
const result = verify_beacon_standalone_js(output, verificationKey, null);
console.log("Verification result:", result.as_string());

// Check if valid
if (result.is_valid()) {
    console.log("Beacon is valid!");
}
```

## Standalone Usage

This package is completely self-contained. You can:

1. Copy the entire `klc-rb/` directory to any location
2. Build it independently using `cargo build`
3. Use it as a dependency in other projects
4. Build for WebAssembly with `wasm-pack build --target web`
5. No links to the parent Aegis-PQC project are required

All algorithm implementations are included via external crates from crates.io, so no local dependencies are needed.

## Building for WebAssembly

To build for JavaScript/TypeScript usage:

```bash
# Install wasm-pack if not already installed
cargo install wasm-pack

# Build for web target
cd klc-rb
wasm-pack build --target web --out-dir pkg --features wasm

# The generated files will be in pkg/
# - aegis_klc_rb.js
# - aegis_klc_rb_bg.wasm
# - aegis_klc_rb.d.ts (TypeScript definitions)
```

## License

MIT OR Apache-2.0
