# SynQ Virtual Machine Specification v0.1

---

## 1. Overview

SynQ requires a virtual machine (VM) capable of executing post-quantum cryptographic (PQC) smart contracts. This includes support for:

- Precompiled PQC operations (Dilithium, Falcon, Kyber)
- Per-operation gas accounting
- Batch signature verification
- On-chain PQC address/key validation
- Hardware acceleration integration (optional)

---

## 2. Required Precompiled Operations

### 2.1 Signature Verification

```vm
precompile.verify_dilithium<L>(msg: Bytes, sig: DilithiumSignature<L>, pubkey: DilithiumKey<L>) -> Bool
precompile.verify_falcon<N>(msg: Bytes, sig: FalconSignature<N>, pubkey: FalconKey<N>) -> Bool
```

### 2.2 Kyber KEM

```vm
precompile.kyber_encapsulate<L>(pubkey: KyberKey<L>) -> (KyberCiphertext<L>, Bytes)
precompile.kyber_decapsulate<L>(ciphertext: KyberCiphertext<L>, privkey: KyberKey<L>) -> Bytes
```

### 2.3 Key Generation

```vm
precompile.dilithium_keygen<L>() -> DilithiumKeyPair<L>
precompile.falcon_keygen<N>() -> FalconKeyPair<N>
precompile.kyber_keygen<L>() -> KyberKeyPair<L>
```

---

## 3. Gas Metering Logic

SynQ VM must:

- Deduct gas per PQC call using `base + size + compute` formula
- Track PQ-Gas separately from base gas
- Enforce:

  ```json
  {
    "max_pqc_gas_per_tx": 300_000,
    "max_pqc_gas_per_block": 2_000_000
  }
  ```

- Reject transactions exceeding per-op or per-block PQC limits

---

## 4. Batch Verification Support

### 4.1 Built-In Batching (Optional)

```vm
precompile.batch_verify_falcon_512(signatures: FalconSignature[512][], pubkeys: FalconKey[512][], messages: Bytes[]) -> Bool[]
```

- Each batch item must match:
  - Signature type & size
  - Message domain prefix (e.g., "VOTE:")

- Gas cost per batch:
  
  ```gas
  base: 75,000 + (30,000 × N members)
  optimized: ~5,000 per verification in batch
  ```

---

## 5. PQC Address and Key Validation

The VM must:

- Reject malformed or mismatched PQC keys
- Hash keys with `SHA3-256` or `BLAKE3` for address derivation
- Support Bech32m format for all wallet and contract addresses

Example:

```text
synq1xya7fpv3sxn3c8uzg7tmh2lgsl57nqxnhn9kwm6
```

---

## 6. Hardware Acceleration Hooks

If node supports HSM, TPM, or custom hardware:

```vm
@hardware_accel
function verify_dilithium(msg, sig, key) -> Bool
```

- VM should route to secure module first
- Fallback to software if HSM not available or disabled

---

## 7. zkPQC Compatibility (Future)

- zkPQC circuits can be introduced for:
  - zk-Dilithium signature proof validation
  - zk-KEM handshake verification
- Proofs verified by:
  
```vm
precompile.zk_verify_proof(bytes proof, bytes circuit_id) -> Bool
```

---

## 8. Cross-Chain Verification

VM must support signature validation across:

- Synergy Network chains
- External chains via message relays

Example (on Solana bridge):

```vm
verify_dilithium<3>(solana_message_hash, bridge_signature, solana_bridge_dilithium_key)
```

---

## 9. Logging & Audit

The VM should log:
- All `require_pqc {}` execution outcomes
- All gas consumed by PQC functions
- Batch verification result arrays
- Any fallback to software from hardware paths

---

## 10. Upgradability & Governance

VM cost parameters must:
- Be defined in genesis block
- Be mutable via on-chain governance proposals
- Enforce versioning compatibility

---

End of SynQ VM Spec v0.1
