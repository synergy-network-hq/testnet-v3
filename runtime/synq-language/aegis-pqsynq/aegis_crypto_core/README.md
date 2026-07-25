# Aegis Crypto Core

> **The core Rust library for Aegis Post-Quantum Cryptography**
>
> This is the main Rust crate that provides unified access to all NIST PQC algorithms with WebAssembly and Python bindings.

[![CI/CD Pipeline](https://github.com/synergy-network-hq/aegis/workflows/CI/CD%20Pipeline/badge.svg)](https://github.com/synergy-network-hq/aegis/actions)
[![Security Audit](https://github.com/synergy-network-hq/aegis/workflows/Security%20Audit/badge.svg)](https://github.com/synergy-network-hq/aegis/actions)
[![Crates.io](https://img.shields.io/crates/v/aegis_crypto_core.svg)](https://crates.io/crates/aegis_crypto_core)
[![Docs](https://docs.rs/aegis_crypto_core/badge.svg)](https://docs.rs/aegis_crypto_core)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE)

This crate is the core implementation of the Aegis Post-Quantum Cryptography library. It provides a unified Rust API for all NIST-standardized post-quantum cryptographic algorithms, with automatic WebAssembly and Python bindings generation.

## 🚀 Core Features

* **Unified Rust API**: Single crate for all NIST PQC algorithms
* **Memory Safety**: Rust's ownership system prevents common vulnerabilities
* **Constant-Time**: All implementations are constant-time to prevent timing attacks
* **Zeroized Memory**: Sensitive data is securely cleared after use
* **no_std Compatible**: Can be used in embedded and constrained environments
* **WASM Ready**: Automatic WebAssembly bindings generation
* **Python Bindings**: Automatic Python extension module generation
* **Feature Gated**: Optional algorithms can be enabled/disabled as needed

## 📦 Supported Algorithms

| Algorithm | Type | Security Levels | Status | NIST Standard |
|-----------|------|-----------------|--------|---------------|
| **ML-KEM** | KEM | ML-KEM-512, ML-KEM-768, ML-KEM-1024 | ✅ Complete | FIPS 203 |
| **ML-DSA** | Signature | ML-DSA-44, ML-DSA-65, ML-DSA-87 | ✅ Complete | FIPS 204 |
| **FN-DSA** | Signature | FN-DSA-512, FN-DSA-1024 | ✅ Complete | FIPS 206 |
| **SLH-DSA** | Signature | SLH-DSA-SHA2-128f, SLH-DSA-SHA2-192f, SLH-DSA-SHA2-256f, SLH-DSA-SHAKE-128f, SLH-DSA-SHAKE-192f, SLH-DSA-SHAKE-256f | ✅ Complete | FIPS 205 |
| **HQC-KEM** | KEM | HQC-KEM-128, HQC-KEM-192, HQC-KEM-256 | ✅ Complete | FIPS 207 |
| **Classic McEliece** | KEM | 348864, 460896, 6688128 | ⚠️ Experimental | FIPS 208 |

## 🛠️ Installation

### Rust (Cargo)

```toml
[dependencies]
aegis_crypto_core = "0.1.0"

# Optional: Enable Classic McEliece (experimental)
# aegis_crypto_core = { version = "0.1.0", features = ["classicmceliece"] }
```

### WebAssembly (npm)

```bash
npm install aegis-crypto-core
```

### Python (PyPI)

```bash
pip install aegis-crypto-core
```

## 🏗️ Architecture

### Core Components

```
aegis_crypto_core/
├── src/
│   ├── lib.rs              # Main library interface
│   ├── traits.rs           # Common trait definitions
│   ├── utils.rs            # Utility functions
│   ├── performance.rs      # Performance monitoring
│   ├── js_bindings.rs      # WebAssembly bindings
│   ├── wasm_loader.rs      # WASM module loading
│   ├── blockchain.rs       # Blockchain-specific utilities
│   ├── hash.rs             # Cryptographic hashing
│   ├── mlkem/              # ML-KEM implementation
│   ├── mldsa/          # ML-DSA implementation
│   ├── fndsa/             # FN-DSA implementation
│   ├── slhdsa/        # SLH-DSA implementation
│   ├── hqc/                # HQC-KEM implementation
│   ├── classicmceliece/    # Classic McEliece implementation
│   └── bin/                # Example applications
├── benches/                # Performance benchmarks
├── tests/                  # Test suites
└── pkg/                    # Generated WASM package
```

### Algorithm Modules

Each algorithm is implemented as a separate module with:
- **Key Generation**: Secure key pair generation
- **Encryption/Signing**: Core cryptographic operations
- **Decryption/Verification**: Core cryptographic operations
- **Error Handling**: Comprehensive error types
- **Memory Management**: Secure memory handling
- **Performance**: Optimized implementations

## 📚 Quick Start

### Rust Usage

```rust
use aegis_crypto_core::{
    mlkem768_keygen, mlkem768_encapsulate, mlkem768_decapsulate,
    mldsa65_keygen, mldsa65_sign, mldsa65_verify
};

// Key Encapsulation (ML-KEM-768)
let keypair = mlkem768_keygen().expect("Key generation failed");
let public_key = keypair.public_key();
let secret_key = keypair.secret_key();

let encapsulated = mlkem768_encapsulate(&public_key).expect("Encapsulation failed");
let ciphertext = encapsulated.ciphertext();
let shared_secret = encapsulated.shared_secret();

let decapsulated_secret = mlkem768_decapsulate(&secret_key, &ciphertext)
    .expect("Decapsulation failed");

assert_eq!(shared_secret, decapsulated_secret);

// Digital Signatures (ML-DSA-65)
let sig_keypair = mldsa65_keygen().expect("Signature key generation failed");
let message = b"Hello, Post-Quantum World!";

let signature = mldsa65_sign(&sig_keypair.secret_key(), message)
    .expect("Signing failed");

let is_valid = mldsa65_verify(&sig_keypair.public_key(), message, &signature)
    .expect("Verification failed");

assert!(is_valid);
```

### WebAssembly Usage

```javascript
import {
    init,
    mlkem768_keygen,
    mlkem768_encapsulate,
    mlkem768_decapsulate
} from 'aegis-crypto-core';

// Initialize the WASM module
await init();

// Generate key pair (ML-KEM-768)
const keypair = mlkem768_keygen();
const publicKey = keypair.public_key();
const secretKey = keypair.secret_key();

// Encapsulate
const encapsulated = mlkem768_encapsulate(publicKey);
const ciphertext = encapsulated.ciphertext();
const sharedSecret = encapsulated.shared_secret();

// Decapsulate
const decapsulatedSecret = mlkem768_decapsulate(secretKey, ciphertext);

console.log('Shared secrets match:', sharedSecret === decapsulatedSecret);
```

### Python Usage

```python
import aegis_crypto_core as aegis

# Key Encapsulation (ML-KEM-768)
keypair = aegis.mlkem768_keygen()
public_key = keypair.public_key()
secret_key = keypair.secret_key()

encapsulated = aegis.mlkem768_encapsulate(public_key)
ciphertext = encapsulated.ciphertext()
shared_secret = encapsulated.shared_secret()

decapsulated_secret = aegis.mlkem768_decapsulate(secret_key, ciphertext)

assert shared_secret == decapsulated_secret

# Digital Signatures (ML-DSA-65)
sig_keypair = aegis.mldsa65_keygen()
message = b"Hello, Post-Quantum World!"

signature = aegis.mldsa65_sign(sig_keypair.secret_key(), message)
is_valid = aegis.mldsa65_verify(sig_keypair.public_key(), message, signature)

assert is_valid
```

## 🔧 Building from Source

### Prerequisites

* Rust 1.70+
* Node.js 18+ (for WASM builds)
* Python 3.8+ (for Python bindings)
* Clang/LLVM (for C compilation)

### Build Commands

```bash
# Clone the repository
git clone https://github.com/synergy-network-hq/aegis.git
cd aegis/aegis_crypto_core

# Native Rust build
cargo build --release

# Run tests
cargo test --workspace

# WASM build (requires wasm-pack)
npm run build

# Python build (requires maturin)
pip install maturin
maturin develop
```

## 🧪 Testing

```bash
# Run all tests
cargo test --workspace

# Run WASM tests
npm test

# Run benchmarks
cargo bench

# Security audit
cargo audit
```

## 📊 Performance

Performance benchmarks are available for all algorithms:

```bash
cargo bench
```

Typical performance metrics (on modern hardware):
* **ML-KEM-768**: Keygen ~0.5ms, Encaps ~0.3ms, Decaps ~0.4ms
* **ML-DSA-65**: Keygen ~2ms, Sign ~1ms, Verify ~0.5ms
* **WASM Size**: ~2MB (optimized)

## 🔒 Security

* **Security Audited**: Regular security audits with `cargo-audit`
* **Constant-Time**: All implementations are constant-time
* **NIST Compliant**: Follows NIST PQC specifications
* **KAT Validated**: All algorithms validated against NIST test vectors

## ⚠️ Classic McEliece Disclaimer

**IMPORTANT**: Classic McEliece has **not been officially selected by NIST for standardization** and is considered experimental. This algorithm is **disabled by default** in Aegis and is **not recommended for production use**.

### Classic McEliece Status

* **Status**: Experimental algorithm - disabled by default
* **NIST Status**: Not officially selected for standardization
* **Security Assurance**: Uncertain - not recommended for production
* **Use Cases**: Research, testing, and educational purposes only

### Enabling Classic McEliece

If you need to use Classic McEliece for research or testing purposes, you can enable it by:

1. **Building with the feature flag**:

```bash
   cargo build --features classicmceliece
   ```

2. **Adding to Cargo.toml**:

```toml
   [dependencies]
   aegis_crypto_core = { version = "0.1.0", features = ["classicmceliece"] }
   ```

3. **Running tests with Classic McEliece**:

```bash
   cargo test --features classicmceliece
   ```

### Security Warning

**⚠️ WARNING**: Users who choose to enable Classic McEliece do so at their own risk. This algorithm:
* Has not been officially standardized by NIST
* May not provide the same level of security assurance as NIST-standardized algorithms
* Should only be used for research, testing, or educational purposes
* Is not recommended for any production or security-critical applications

For production applications, use NIST-standardized algorithms:
* **ML-KEM** for key encapsulation (FIPS 203)
* **ML-DSA** for digital signatures (FIPS 204)
* **FN-DSA** for digital signatures (FIPS 206)
* **SLH-DSA** for digital signatures (FIPS 205)

## 🔧 Development

### Building from Source

```bash
# Clone the repository
git clone https://github.com/synergy-network-hq/aegis.git
cd aegis/aegis_crypto_core

# Native Rust build
cargo build --release

# Run tests
cargo test --workspace

# Run benchmarks
cargo bench

# Build WASM package
wasm-pack build --target web --out-dir pkg

# Build Python bindings
pip install maturin
maturin develop
```

### Feature Flags

- `classicmceliece`: Enable Classic McEliece (experimental)
- `wasm`: Enable WebAssembly support
- `js-bindings`: Enable JavaScript bindings
- `python-bindings`: Enable Python bindings

### Testing

```bash
# Run all tests
cargo test --workspace

# Run WASM tests
cargo test --target wasm32-unknown-unknown --features wasm,js-bindings

# Run browser tests
cargo test-wasm-browser

# Run security audit
cargo audit
```

## 🚨 Known Issues

### WASM Build Limitations

The current pqrust dependencies have compatibility issues with WASM builds due to WASI API dependencies. This affects:

* WASM compilation with `wasm32-unknown-unknown` target
* Browser deployment via `wasm-pack`

**Workarounds**:
1. Use native Rust builds for server-side applications
2. Use Python bindings for cross-platform deployment
3. Consider alternative WASM-compatible PQC implementations

**Status**: Working on WASM-compatible alternatives and pqrust updates.

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup

```bash
# Install development dependencies
cargo install wasm-pack maturin cargo-audit

# Set up pre-commit hooks
pre-commit install

# Run CI checks locally
./scripts/ci-check.sh
```

## 📄 License

This project is licensed under either of

* Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or https://www.apache.org/licenses/LICENSE-2.0)
* MIT license ([LICENSE-MIT](LICENSE-MIT) or https://opensource.org/licenses/MIT)

at your option.

## 🙏 Acknowledgments

* **PQClean**: For the reference implementations
* **NIST**: For the PQC standardization process
* **Rust Crypto**: For the cryptographic foundations
* **WebAssembly**: For cross-platform deployment

## 📞 Support

* **Issues**: [GitHub Issues](https://github.com/synergy-network-hq/aegis/issues)
* **Discussions**: [GitHub Discussions](https://github.com/synergy-network-hq/aegis/discussions)
* **Email**: justin@synergy-network.io

## 🔗 Links

* [Documentation](https://docs.rs/aegis_crypto_core)
* [API Reference](https://docs.rs/aegis_crypto_core)
* [NIST PQC Project](https://csrc.nist.gov/projects/post-quantum-cryptography)
* [PQClean](https://github.com/PQClean/PQClean)

---

**Aegis**: Protecting the future with post-quantum cryptography. 🛡️
