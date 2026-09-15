# SynQ Language Specification v0.1

---

## 1. Introduction
SynQ is a smart contract language designed for the post-quantum era. It integrates NIST-standardized quantum-safe algorithms—**Dilithium**, **Falcon**, and **Kyber**—as first-class types. The language is defined around cryptographic clarity, safety by design, and explicit resource accounting.

---

## 2. Type System

### 2.1 Primitive Types
- `Bool`
- `Bytes`
- `UInt256`
- `Address`

### 2.2 Post-Quantum Cryptographic Types
```quantumscript
// Parameterized for security level (e.g., 2, 3, 5 for Dilithium)
type DilithiumKeyPair<L>
type DilithiumSignature<L>

type FalconKeyPair<N>
type FalconSignature<N>

type KyberKeyPair<L>
type KyberCiphertext<L>
```

### 2.3 Aliases (for simplicity)
```quantumscript
type DilithiumPublicKey = DilithiumKeyPair<3>
// Add FalconPublicKey, etc., as needed
```

### 2.4 Composite Types
```quantumscript
type PQAuth = {
    dilithium_key: DilithiumKeyPair<3>,
    falcon_key: FalconKeyPair<1024>,
    backup_key: DilithiumKeyPair<2>
}
```

---

## 3. Built-in Functions

### 3.1 Signature Verification
```quantumscript
builtin verify_dilithium<L>(msg: Bytes, sig: DilithiumSignature<L>, key: DilithiumKeyPair<L>) -> Bool
builtin verify_falcon<N>(msg: Bytes, sig: FalconSignature<N>, key: FalconKeyPair<N>) -> Bool
```

### 3.2 Kyber Encapsulation
```quantumscript
builtin kyber_encapsulate<L>(key: KyberKeyPair<L>) -> (KyberCiphertext<L>, Bytes)
builtin kyber_decapsulate<L>(ciphertext: KyberCiphertext<L>, key: KyberKeyPair<L>) -> Bytes
```

### 3.3 Composite Auth Verification
```quantumscript
builtin verify_composite_auth(
  message: Bytes,
  dilithium_sig: DilithiumSignature<3>,
  falcon_sig: FalconSignature<1024>,
  auth: PQAuth
) -> Bool
```

---

## 4. Language Keywords & Decorators

### 4.1 Decorators
```quantumscript
@deploy             // Marks constructor
@public             // Marks public entrypoints
@view               // Marks read-only view
@extensible         // Marks experimental/upgradeable modules
@gas_cost(base, per_item)
@optimize_gas
@gas_limit(value)
```

### 4.2 Modifiers
```quantumscript
modifier authenticated_pqc(auth: PQAuth, msg: Bytes, sig1: DilithiumSignature<3>, sig2: FalconSignature<1024>) {
    require(verify_composite_auth(msg, sig1, sig2, auth), "Bad composite signature");
    _;
}

modifier time_locked_pqc(unlock_time: UInt256, auth: PQAuth) {
    require(block.timestamp >= unlock_time, "Time lock not expired");
    require(verify_dilithium(encode_time(unlock_time), provided_signature, auth.dilithium_key), "Invalid time lock sig");
    _;
}
```

### 4.3 PQC Require Block
```quantumscript
require_pqc {
    verify_dilithium<3>(admin_key, proposal_data, admin_signature);
} or revert("Invalid admin signature");
```

### 4.4 Gas Budget Block
```quantumscript
with_gas_limit(100000) {
    cast_vote(...);
}
```

---

## 5. Imports & Modules
```quantumscript
use pqc::dilithium
use pqc::falcon
use pqc::kyber
```

---

## 6. Message Signing Conventions
- **Prefix all ABI-encoded messages** with a context label: e.g., `"VOTE:", proposalId`
- Required to prevent replay attacks and ensure domain separation

---

## 7. Addressing
SynQ supports advanced address formats (like Synergy’s Bech32m `synq`/`synu`/`synx`) and will accommodate multiple address schemes with cross-chain validation.

---

## 8. Future Extensions
- Support for new PQC algorithms via `@extensible` modules
- Precompiled runtime targets for performance optimization
- Hardware-backed validation (Ledger, TPM, HSM)
- zkPQC support (e.g., zk-Dilithium circuits)

---

End of Specification v0.1
