### SynQ Gas & Resource Model v0.1

---

## 1. Design Goals

- Reflect the **computational cost** of PQC operations with high fidelity
- Prevent **denial-of-service** via oversized keys or batching abuse
- Enable **predictable cost estimation** for smart contract developers
- Support **batch optimization**, **gas budgeting**, and **security-level scaling**

---

## 2. Cost Calculation Model

All PQC operations in SynQ follow a 3-part cost formula:

```
Total Gas = BaseCost + DataCost + ComputeCost
```

| Component         | Description                                              |
|------------------|----------------------------------------------------------|
| **BaseCost**     | Fixed overhead for invoking a PQC operation              |
| **DataCost**     | Cost proportional to input sizes (signature, message, key) |
| **ComputeCost**  | CPU/memory cost for the specific PQC algorithm           |

---

## 3. Standard Operation Costs (Benchmark Derived)

| Operation                   | Level | BaseCost | Est. DataCost | ComputeCost | Total Estimate |
|----------------------------|--------|----------|---------------|--------------|----------------|
| `verify_dilithium`         | 2      | 5,000    | 6,000         | 14,000       | **25,000**     |
|                            | 3      | 6,000    | 9,000         | 20,000       | **35,000**     |
|                            | 5      | 7,000    | 13,000        | 30,000       | **50,000**     |
| `verify_falcon`            | 512    | 4,000    | 6,000         | 10,000       | **20,000**     |
|                            | 1024   | 6,000    | 9,000         | 15,000       | **30,000**     |
| `kyber_encapsulate`        | 768    | 5,000    | 5,000         | 15,000       | **25,000**     |
| `kyber_decapsulate`        | 768    | 5,000    | 6,000         | 14,000       | **25,000**     |
| `dilithium_keygen`         | 3      | 5,000    | 0             | 20,000       | **25,000**     |

---

## 4. Batch Verification Optimization

SynQ supports precompiled batch ops for Falcon and Dilithium:

```quantumscript
@gas_cost(base: 75000, per_member: 30000)
@precompile("falcon_batch_verify")
function verify_member_batch(members: Address[], signatures: FalconSignature<512>[]) -> Bool[]
```

**Effect:**
- Reduces per-signature cost by up to **40–60%**
- Signature cost drops from 20,000 to **~5,000 gas**

---

## 5. Storage Cost Model

```quantumscript
const storage_cost_per_kb = 50_000 gas;
```

Macro:
```quantumscript
macro storage_cost<T>(value: T) -> gas {
    sizeof(T) * storage_cost_per_kb / 1024
}
```

---

## 6. Gas Control Syntax

### 6.1 Function-Level Cost Annotation
```quantumscript
@gas_cost(base: 45_000, dilithium_verify: 35_000)
function submit_proposal(...) { ... }
```

### 6.2 Gas Limit Enforcement
```quantumscript
@gas_limit(100_000)
function cast_vote(...) { ... }
```

### 6.3 Budgeted Execution Block
```quantumscript
with_gas_limit(200_000) {
    run_tally();
}
```

---

## 7. Genesis File Integration

All base costs and function costs are encoded in the Genesis block for every SynQ-compatible chain.

```json
{
  "pqc_costs": {
    "verify_dilithium_3": 35000,
    "verify_falcon_512": 20000,
    "kyber_encapsulate_768": 25000
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

If VM supports it:
- Use `@hardware_accel` tag to signal precompiled path
- Default to software-fallback if unavailable
