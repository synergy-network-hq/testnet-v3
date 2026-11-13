# SynQ Gas & Resource Model v0.1

---

## 1. Design Goals

- Reflect the **computational cost** of PQC operations with high fidelity
- Prevent **denial-of-service** via oversized keys or batching abuse
- Enable **predictable cost estimation** for smart contract developers
- Support **batch optimization**, **gas budgeting**, and **security-level scaling**

---

## 2. Cost Calculation Model

All PQC operations in SynQ follow a 3-part cost formula:

```plaintext
Total Gas = BaseCost + DataCost + ComputeCost
```

| Component         | Description                                               |
|-------------------|-----------------------------------------------------------|
| **BaseCost**      | Fixed overhead for invoking a PQC operation               |
| **DataCost**      | Cost proportional to input sizes (signature, message, key)|
| **ComputeCost**   | CPU/memory cost for the specific PQC algorithm            |

---

## 3. Standard Operation Costs (Benchmark Derived)

| Operation                  | Level           | BaseCost | Est. DataCost | ComputeCost | Total Estimate |
|----------------------------|-----------------|----------|---------------|-------------|----------------|
| `verify_mldsa`             | ML-DSA-44 (L2)  | 5,000    | 6,000         | 14,000      | **25,000**     |
|                            | ML-DSA-65 (L3)  | 6,000    | 9,000         | 20,000      | **35,000**     |
|                            | ML-DSA-87 (L5)  | 7,000    | 13,000        | 30,000      | **50,000**     |
| `verify_fndsa`             | FN-DSA-512 (L1) | 4,000    | 6,000         | 10,000      | **20,000**     |
|                            | FN-DSA-1024 (L5)| 6,000    | 9,000         | 15,000      | **30,000**     |
| `mlkem_encapsulate`        | ML-KEM-768 (L3) | 5,000    | 5,000         | 15,000      | **25,000**     |
| `mlkem_decapsulate`        | ML-KEM-768 (L3) | 5,000    | 6,000         | 14,000      | **25,000**     |
| `mldsa_keygen`             | ML-DSA-65 (L3)  | 5,000    | 0             | 20,000      | **25,000**     |
|----------------------------|-----------------|----------|---------------|-------------|----------------|

---

## 4. Batch Verification Optimization

> **Status:** Batch verification is planned for future implementation. The syntax and gas model below are proposed for the feature.

SynQ will support precompiled batch ops for FN-DSA and ML-DSA:

```synq
// Future syntax (not yet implemented)
@gas_cost(base: 75000, per_member: 30000)
@precompile("fndsa_batch_verify")
function verify_member_batch(members: Address[], signatures: FNDSASignature[]) -> Bool[]
```

**Expected Effect (when implemented):**

- Reduces per-signature cost by up to **40–60%**
- Signature cost drops from 20,000 to **~5,000 gas**

---

## 5. Storage Cost Model

> **Note:** `const` declarations and `macro` definitions are planned for future implementation. Storage costs are currently handled automatically by the VM.

Proposed future syntax:

```synq
// Future syntax (not yet implemented)
const storage_cost_per_kb = 50_000 gas;

macro storage_cost<T>(value: T) -> gas {
    sizeof(T) * storage_cost_per_kb / 1024
}
```

**Current Implementation:**

- Storage costs are automatically calculated by the VM
- Cost is approximately 50,000 gas per KB stored

---

## 6. Gas Control Syntax

### 6.1 Function-Level Cost Annotation

```synq
@gas_cost(base: 45_000, mldsa_verify: 35_000)
function submit_proposal(...) { ... }
```

### 6.2 Gas Limit Enforcement

> **Status:** `@gas_limit` annotation is planned for future implementation.

```synq
// Future syntax (not yet implemented)
@gas_limit(100_000)
function cast_vote(...) { ... }
```

### 6.3 Budgeted Execution Block

> **Status:** `with_gas_limit` blocks are planned for future implementation.

```synq
// Future syntax (not yet implemented)
with_gas_limit(200_000) {
    run_tally();
}
```

**Current Behavior:**

- Gas limits are enforced at the transaction level by the VM
- Each transaction has a maximum gas limit configured at the network level

---

## 7. Genesis File Integration

All base costs and function costs are encoded in the Genesis block for every SynQ-compatible chain.

```json
{
  "pqc_costs": {
    "verify_mldsa_65": 35000,
    "verify_fndsa_512": 20000,
    "mlkem_encapsulate_768": 25000
  },
  "storage_cost_per_kb": 50000,
  "max_pqc_gas_per_tx": 300000,
  "max_pqc_gas_per_block": 2000000
}
```

---

## 8. Runtime Validation

- Each transaction’s PQC gas is tracked separately as **PQ-Gas**
- Exceeding `max_pqc_gas_per_tx` results in an automatic revert
- Developers may estimate PQC gas using `qsc estimate` CLI

---

## 9. Optional Hardware Acceleration

> **Status:** Hardware acceleration annotations are planned for future implementation.

**Proposed Future Syntax:**

```synq
// Future syntax (not yet implemented)
@hardware_accel
function verify_mldsa(msg, sig, key) -> Bool {
    // VM will route to hardware module if available
}
```

**Current Behavior:**

- All PQC operations currently use software implementations
- Hardware acceleration is planned for future VM enhancements
- If implemented, VM will automatically route to hardware when available and fall back to software otherwise
