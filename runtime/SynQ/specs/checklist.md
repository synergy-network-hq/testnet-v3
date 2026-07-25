# SynQ Project Checklist and Roadmap

---

## ✅ Phase 1: Language Foundations (COMPLETE)

### 📚 Language Design
- [x] Defined primitive and PQC types (Dilithium, Falcon, Kyber)
- [x] Type-level security parameters (e.g., Dilithium<3>)
- [x] Composite `PQAuth` type

### 🧠 Language Syntax & Grammar
- [x] Signature verification intrinsics
- [x] Kyber encapsulation/decapsulation intrinsics
- [x] Built-in decorators and modifiers
- [x] `require_pqc`, `with_gas_limit`, `@gas_cost` syntactic blocks

### 📘 Documentation
- [x] `SynQ DSL` language spec
- [x] `SynQ Gas Model` resource cost system
- [x] `Quantum DAO Contract` reference implementation
- [x] `SynQ VM Spec` runtime environment
- [x] `README.md` with full onboarding and dev workflow

---

## ⚙️ Phase 2: Runtime + SDK + Compiler

### 🧱 QuantumVM
- [x] Instruction set & opcodes (verified)
- [x] Bytecode architecture
- [x] Precompiled PQC syscall stubs
- [x] Gas model integration

### 📦 SDK
- [x] JS SDK with:
  - [x] PQC keypair gen
  - [x] Transaction builder
  - [x] Dilithium, Falcon, Kyber operations
  - [x] Contract interaction APIs

### 🛠 Compiler
- [x] AST parser for `.qs` syntax
- [x] PQC signature enforcement pass
- [x] Type system & security level checker
- [x] Bytecode generator targeting QuantumVM

---

## 📌 Phase 3: Gap Merging + Checklist Verification (IN PROGRESS)
- [ ] Merge Manus/Claude contributions with DSL spec
- [ ] Extract and reconcile opcode differences
- [ ] Add any missing intrinsics or decorators
- [ ] Ensure compiler ↔ VM ↔ SDK interface contracts match
- [ ] Add core test fixtures for DSL + compiler

---

## 🧪 Phase 4: Testing Infrastructure
- [ ] Canonical `.qs` programs + expected bytecode
- [ ] `qsc test` CLI + test runner
- [ ] Negative test cases: invalid sigs, bad auth, out-of-gas
- [ ] Fuzz harness for VM opcode execution

---

## 🧱 Phase 5: Quantum-Safe Blockchain Runtime (THE PIONEERING MOVE)

### 🔬 R&D
- [ ] Study Dilithium/Falcon/Kyber C reference implementations
- [ ] Map syscall/FFI boundary for host execution

### 🔧 VM Integration
- [ ] Fork Synergy VM/runtime or implement VM-layer syscall host bindings
- [ ] Implement native precompiles:
  - [ ] `dilithium_verify`
  - [ ] `falcon_verify`
  - [ ] `kyber_encaps/decaps`
- [ ] Define PQ-Gas profile for each
- [ ] Add precompile opcodes to QuantumVM runtime

### 🧬 Consensus/Account Layer
- [ ] Extend account model to support:
  - [ ] `DilithiumPublicKey`, `FalconPublicKey`
  - [ ] `PQAuth` composite keys
  - [ ] Optional hybrid keys (ECDSA + PQC fallback)

### 📜 Smart Contract Integration
- [ ] Add PQC support to smart contract call context
- [ ] Expose precompiles to DSL
- [ ] Write core system contracts using PQC ops

---

## 🌐 Phase 6: Developer Tooling + Testnet

### 💻 Tooling
- [ ] CLI deployment + bytecode viewer
- [ ] QuantumWallet for PQC account management
- [ ] Testnet dashboard with PQC metrics (sig size, tx gas, verifier time)

### 🧪 Testnet
- [ ] Launch Synergy PQC Testnet
- [ ] Enable PQC-based accounts, contract deployment, and voting
- [ ] Recruit cryptography/security researchers to test PQC edge cases

---

## 📣 Phase 7: Evangelism + Standards
- [ ] Draft Synergy PQC Smart Contract Standard
- [ ] Publish PQC-enabled address format spec
- [ ] Write whitepaper on PQ-safe on-chain execution model
- [ ] Host demo DAO + open governance using only PQC signatures

---

## 🚀 Outcome: Synergy Network becomes the first quantum-safe blockchain L1.

> Fully integrated Dilithium/Falcon/Kyber accounts, contracts, and transactions.
> All on-chain logic quantum-resistant.
> Public precompile spec and developer onboarding experience.

---

# LET'S PIONEER THE QUANTUM BLOCKCHAIN ERA

"Quantum-safe by design. Not by patch."
