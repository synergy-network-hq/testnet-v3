# Aegis pqvm — Licensing

Aegis pqvm is commercial software. Runtime access requires a valid license key
installed via `aegis_pqvm::licensing::init(key)` before any VM integration call.

---

## Tier Summary

| Feature | Starter | Pro | Business | Enterprise |
|---|---|---|---|---|
| **Price** | Free (eval) | Commercial | Commercial | Custom SLA |
| **Use case** | Testing / non-commercial | Production | Multi-chain production | Institutional |
| **Ops / session** | 1,000 | 100,000 | 1,000,000 | Unlimited |
| **Expiry** | As issued | As issued | As issued | Negotiable |

### VM Platform Access

| Platform | Starter | Pro | Business | Enterprise |
|---|:---:|:---:|:---:|:---:|
| EVM (Ethereum / EVM-compatible) | ✅ | ✅ | ✅ | ✅ |
| Substrate (Polkadot / Kusama) | ❌ | ✅ | ✅ | ✅ |
| CosmWasm (Cosmos SDK) | ❌ | ❌ | ✅ | ✅ |
| Solana (SVM) | ❌ | ❌ | ✅ | ✅ |
| Move (Aptos / Sui) | ❌ | ❌ | ✅ | ✅ |

### Algorithm Access

| Algorithm | Starter | Pro | Business | Enterprise |
|---|:---:|:---:|:---:|:---:|
| ML-KEM-512 | ✅ | ✅ | ✅ | ✅ |
| ML-KEM-768 | ✅ | ✅ | ✅ | ✅ |
| ML-KEM-1024 | ❌ | ✅ | ✅ | ✅ |
| ML-DSA-44 | ❌ | ✅ | ✅ | ✅ |
| ML-DSA-65 | ❌ | ✅ | ✅ | ✅ |
| ML-DSA-87 | ❌ | ✅ | ✅ | ✅ |
| FN-DSA-512 (FALCON-512) | ❌ | ✅ | ✅ | ✅ |
| FN-DSA-1024 (FALCON-1024) | ❌ | ❌ | ✅ | ✅ |
| SLH-DSA (all parameter sets) | ❌ | ❌ | ✅ | ✅ |
| HQC (all parameter sets) | ❌ | ❌ | ✅ | ✅ |

---

## Key Format

```
AEGIS-V-<BASE32(PAYLOAD || MAC)>
```

| Field | Bytes | Description |
|---|---|---|
| `tier` | 1 | 0=Starter, 1=Pro, 2=Business, 3=Enterprise |
| `expiry` | 4 | Unix timestamp (big-endian u32); 0 = never expires |
| `ops` | 4 | Per-session op override (big-endian u32); 0 = tier default |
| `nonce` | 4 | Subsecond timestamp at generation time |
| `MAC` | 16 | `BLAKE3(SECRET || "pqvm" || PAYLOAD)[0..16]` |

Total: 29 raw bytes → 47 base32 characters.

Example key (Starter, 365 days):
```
AEGIS-V-ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJK
         ↑ 47 base32 characters
```

---

## Integration

### Rust (native / embedded)

```rust
use aegis_pqvm::licensing;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Install license at process startup, before any VM calls
    licensing::init("AEGIS-V-...")?;

    // From here, all integration calls are license-gated automatically
    aegis_pqvm::integrations::evm::EvmIntegration::evm_precompile_call(&payload)?;
    Ok(())
}
```

### Substrate runtime pallet

```rust
// In pallet `on_initialize` or a dedicated `set_license` extrinsic:
aegis_pqvm::licensing::init(license_key_from_storage())?;
```

### CosmWasm contract

```rust
// In contract `instantiate`:
aegis_pqvm::licensing::init(&env.message.license_key)?;
```

### Error handling

`licensing::init` returns `Err(String)` on failure. The message contains the
rejection reason (expired, wrong module, MAC failed, tier insufficient, etc.).
Propagate or `unwrap()` at startup — failure to install a valid license means
all subsequent AEG1 dispatches will return `IntegrationError::Unsupported`.

---

## Enforcement Points

License is enforced at two layers:

1. **Algorithm layer** — `abi::dispatch_deterministic` and `dispatch_offchain`
   call `licensing::check_algorithm(alg_name)` for every AEG1 payload, which
   validates tier access and decrements the session op counter.

2. **Platform layer** — each VM integration module calls
   `licensing::check_platform(VmPlatform::*)` before dispatching, which
   validates tier access without consuming an op credit.

Both checks must pass. A Starter key calling a CosmWasm entry point fails at
the platform check before the algorithm check is reached.

---

## Generating Keys (Operators Only)

Keys are generated with the `generate_license` binary included in the source
tree. It is **never distributed to end users**.

```bash
# Build
cd aegis-pqvm
cargo build --bin generate_license --release

# Generate a Pro key valid for 1 year
./target/release/generate_license --tier pro --days 365

# Generate an Enterprise key (no expiry)
./target/release/generate_license --tier enterprise --days 0

# Generate a Business key with custom op limit
./target/release/generate_license --tier business --days 180 --ops 500000

# Validate / inspect an existing key
./target/release/generate_license --validate "AEGIS-V-..."
```

Sample output:
```
Aegis pqvm License Key
======================
Tier        : Pro (code 1)
Platforms   : EVM, Substrate
Algorithms  : ML-KEM-512/768/1024, ML-DSA-44/65/87, FN-DSA-512
Expiry      : Unix 1775203200 (~365 days)
Ops/session : 100000 (tier default)

AEGIS-V-ABCDE...

Install in Rust:
  aegis_pqvm::licensing::init("AEGIS-V-ABCDE...")?;
```

---

## Pre-Ship Checklist

- [ ] **Replace `LICENSE_SECRET`** in `src/licensing.rs` and `src/bin/generate_license.rs`
      with your production secret (32 bytes). The placeholder ships in source; any
      key generated with it is compromised if the source leaks.
- [ ] **Rotate secret** if the binary ships as open source or in a public crate.
- [ ] **Regenerate all keys** after any secret rotation.
- [ ] Confirm `publish = false` in `Cargo.toml` (already set).

---

## License Diagnostics

```rust
println!("{}", aegis_pqvm::licensing::license_summary());
// Example output:
// Aegis pqvm license: tier=Pro ops_used=42 ops_limit=100000 expiry=1775203200
```
