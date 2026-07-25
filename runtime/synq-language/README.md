# SynQ

SynQ is a domain-specific language (DSL) designed for writing **quantum-resistant smart contracts** using NIST-standardized post-quantum cryptographic (PQC) algorithms such as **ML-DSA** (Module-Lattice-Based Digital Signature Algorithm), **FN-DSA** (FFT over NTRU-Lattice-Based Digital Signature Algorithm), **ML-KEM** (Module-Lattice-Based Key-Encapsulation Mechanism), and **SLH-DSA** (Stateless Hash-Based Digital Signature Algorithm). It is intended to enable secure decentralized applications (dApps) that remain resilient in the face of future quantum computing threats.

---

## AIVM execution tracking

SynQ contracts execute only in the Synergy Network AIVM. A separate SynQ or
QuantumVM runtime is not part of the intended architecture.

The source-derived execution status and remaining production work are maintained
by the AIVM project in
[`../synergy-aivm/docs/readiness/CURRENT_STATUS.md`](../synergy-aivm/docs/readiness/CURRENT_STATUS.md),
with the exact incomplete-code register in
[`../synergy-aivm/docs/readiness/INCOMPLETE_IMPLEMENTATIONS.md`](../synergy-aivm/docs/readiness/INCOMPLETE_IMPLEMENTATIONS.md).


---

## 🔒 Post-Quantum Cryptography Support

SynQ's language design targets these PQC families. Implementation readiness and
the decision to include or remove each family from SynQ 1.0 are tracked only in
the completion checklist.

| Algorithm | Intended purpose | Language type family |
|----------|------------------|----------------------|
| ML-DSA | Digital signatures | `MLDSAKeyPair`, `MLDSASignature` |
| FN-DSA | Compact signatures | `FNDSAKeyPair`, `FNDSASignature` |
| ML-KEM | Key encapsulation | `MLKEMKeyPair`, `MLKEMCiphertext` |
| HQC-KEM | Key encapsulation | Pending a finalized SynQ 1.0 type surface |
| SLH-DSA | Stateless hash signatures | `SLHDSAKeyPair`, `SLHDSASignature` |

> Security levels are specified by variant (e.g., ML-DSA-65 for Level 3, ML-KEM-768 for Level 3).

---

## 📦 Language design goals

The following sections describe the intended language, not completion claims.

### First-Class Cryptographic Types (target)

- Strong type enforcement must prevent security mismatches
- Types must encode security levels explicitly
- Composite authentication is represented through a finalized `PQAuth` model

### Explicit Gas Accounting (target)

- PQC and AIVM host operations have consensus-defined gas schedules
- Costs account for operation, input size, and enabled variant
- Compiler and AIVM enforce the same schedule

### Signature Enforcement (target)

- `require_pqc { ... }` has fail-closed, rollback-safe semantics
- Admission and contract-level domains cannot be replayed across contexts

### AIVM Integration (target)

- AIVM is the only SynQ execution environment
- AIVM tracks PQ-Gas separately from ordinary gas
- Hardware acceleration may be exposed only through deterministic AIVM capabilities

---

## 🧰 Core Syntax

### 🔧 Types

```synq
type MLDSAKeyPair
type FNDSASignature
type MLKEMCiphertext
type SLHDSASignature
```

### 🔑 Composite Authentication

```synq
type PQAuth = {
    mldsa_key: MLDSAKeyPair,
    fndsa_key: FNDSAKeyPair,
    backup_key: MLDSAKeyPair
}
```

### 🧪 Signature Verification

```synq
require_pqc {
    verify_mldsa(admin_key, msg, sig);
} or revert("Invalid sig");
```

### 💸 Gas Budgeting

```synq
@gas_cost(base: 75000, mldsa_verify: 35000)
function submit_proposal(...) { ... }
```

---

## 🏛 Design example: PQC-Verified DAO

SynQ includes a DAO syntax/design example with:

- Admin control via ML-DSA-65 (Level 3)
- Voting via encrypted FN-DSA + ML-KEM
- Proposal submission, encrypted vote casting, batched tally
- Governance key rotation with `verify_mldsa`

This is not executable AIVM proof. Its implementation status is covered by the
completion checklist.

---

## ⚙️ Development Tools

### 🛠 CLI Compiler and artifact tools

```bash
cargo run -p cli -- check contracts/Counter.synq
cargo run -p cli -- build contracts/Counter.synq
cargo run -p cli -- abi contracts/Counter.synq
cargo run -p cli -- manifest contracts/Counter.synq
```

Legacy local `run`/`simulate` paths are not AIVM execution proof and are scheduled
for removal or replacement in the completion checklist.

---

## 🔐 Security model goals

- Critical admission and contract paths are gated by approved post-quantum signatures
- Classical signing is excluded from SynQ admission
- Addresses and contracts use the canonical Synergy encoding
- AIVM traps ordinary-gas and PQ-gas exhaustion deterministically
- Every signed operation uses a versioned, chain-bound domain

---

## 🔮 Future Features

- zk-ML-DSA and zk-ML-KEM proof verification
- Optional PQC signature aggregations
- Module import system (`use pqc::fndsa`)
- Interoperability with classical and quantum-native chains
- Proof-based cold wallet recovery

---

## 📚 Files

| File | Description |
|------|-------------|
| `docs/SynQ-User-Manual.md` | User guide and intended examples |
| `docs/SynQ-Language-Specification.md` | Intended language syntax and types |
| `docs/Gas-Model.md` | Proposed resource and cost model |
| `docs/SynQDAO_Example.md` | DAO design example; not AIVM execution proof |
| `specs/synq-bytecode-spec.md` | SynQ bytecode format |
| `specs/synq-aivm-execution-spec.md` | SynQ execution contract for Synergy AIVM |
| `Version-Pragma.md` | Version pragma documentation |
| `Examples-Index.md` | Index of all example contracts |
| `../synergy-aivm/docs/readiness/CURRENT_STATUS.md` | Source-derived AIVM/SynQ execution status |
| `../synergy-aivm/docs/readiness/INCOMPLETE_IMPLEMENTATIONS.md` | Exact line-addressed incomplete-code inventory |

---

## 🤝 Contributing

To contribute:

1. Fork this repo
2. Clone and run the workspace checks locally
3. Modify one of the source documents
4. Submit a PR with `[SynQ]` prefix

### 📜 Coding Guidelines

- All PQC types follow NIST naming standards (ML-DSA, FN-DSA, ML-KEM, SLH-DSA)
- Signature and encryption messages must be ABI-encoded and prefixed
- All public functions must declare `@gas_cost`

---

## 👨‍🚀 Maintainers

SynQ is maintained by the Synergy Network Core R&D team.

---

## 🧠 License

SynQ is released under the MIT License.
