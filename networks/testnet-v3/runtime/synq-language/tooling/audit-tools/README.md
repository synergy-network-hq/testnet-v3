# SynQ Audit Tooling

This directory contains tools and utilities used by SynQ auditors to conduct standardized security and correctness reviews.

All tools here are designed to support repeatable, deterministic, and auditable assessments.

---

## 1. Tooling Categories

### 1.1 Static Analysis

- Determinism enforcement checks
- Type safety validation
- Prohibited construct detection
- Dependency integrity scanning

### 1.2 Formal Verification Support

- Verification condition generation
- Specification consistency checks
- Proof artifact validation

### 1.3 Gas & Resource Analysis

- Deterministic gas cost calculation
- Worst-case execution profiling
- Resource bound verification

### 1.4 Cryptographic Validation

- PQC primitive usage checks
- Signature and key lifecycle validation
- Message layout determinism checks

---

## 2. Required Toolchain

Auditors MUST use:

- Official SynQ compiler releases
- SynQ VM reference implementation
- Approved verification backends
- Approved static analysis tools

Tool versions used in an audit MUST be documented.

---

## 3. Custom Scripts

Custom audit scripts MAY be used provided:

- Their behavior is documented
- Outputs are reproducible
- Scripts are archived with audit artifacts

---

## 4. Output Requirements

Audit tooling MUST produce:

- Deterministic results
- Machine-verifiable outputs
- Logs suitable for long-term retention

---

## 5. Integrity Rules

Auditors MUST NOT:

- Modify tools in undocumented ways
- Suppress or ignore tool findings
- Use non-reproducible tooling

Violations invalidate audit results.
