# SynQ Audit Procedure

Version: 1.0  
Status: Active  
Applies to: All SynQ Certification Audits  
Maintained by: SynQ Governance Council  

---

## 1. Purpose

This document defines the standardized procedure for conducting security and correctness audits of smart contracts written in the SynQ programming language.

The objective of the audit procedure is to:

- Establish a repeatable and objective audit methodology
- Ensure consistency across first-party and third-party auditors
- Preserve trust in SynQ Certified designations
- Reduce systemic risk within the SynQ ecosystem

All certification audits MUST follow this procedure without deviation.

---

## 2. Scope of Audits

Audits MAY evaluate:

- Single smart contracts
- Contract systems (multi-contract architectures)
- Upgradeable contract suites
- Cross-chain-enabled contracts

Audits DO NOT evaluate:

- Off-chain infrastructure
- UI or frontend code
- External services not invoked on-chain

---

## 3. Auditor Requirements

Audits may only be conducted by:

- SynQ Core Audit Team, or
- Approved SynQ Audit Partners

Auditors MUST:

- Disclose conflicts of interest
- Use the official SynQ compiler and toolchain
- Maintain confidentiality until publication authorization
- Preserve all audit artifacts and logs

---

## 4. Audit Phases

### Phase 1 — Intake & Scoping

Auditors MUST obtain:

- Exact source code commit hash
- Compiler version and flags
- Target certification level
- Deployment environment assumptions
- Declared dependencies and libraries
- Formal specifications (if provided)

The audit scope MUST be documented before analysis begins.

---

### Phase 2 — Automated Analysis

Mandatory automated checks include:

- Static analysis
- Determinism enforcement validation
- Type and memory safety analysis
- Gas cost predictability analysis
- Cryptographic primitive validation
- Dependency integrity checks

Any Critical or High severity findings MUST halt progression.

---

### Phase 3 — Manual Code Review

Manual review MUST include:

- Line-by-line inspection of business logic
- Validation of state transitions
- Access control correctness
- Invariant enforcement
- Upgradeability and governance logic review
- Cross-contract interaction review

Auditors MUST reason about:

- Worst-case execution paths
- Adversarial inputs
- Unexpected call ordering
- Failure modes

---

### Phase 4 — Formal Verification Review (If Applicable)

If formal verification is required:

- Specifications MUST be reviewed for completeness
- Proofs MUST be reproducible
- Assumptions MUST be explicit
- Unproven properties MUST be disclosed

Auditors MUST NOT accept unverifiable claims.

---

### Phase 5 — Cross-Chain Review (If Applicable)

For contracts using SXCP:

- Validate proof verification logic
- Confirm replay protection
- Review finality assumptions
- Verify timeout and rollback behavior
- Confirm correct UMA handling

---

### Phase 6 — Findings Classification

All findings MUST be classified as:

- **Critical** – Exploitable vulnerability with immediate impact
- **High** – Severe risk requiring remediation
- **Medium** – Risky behavior or poor assumptions
- **Low** – Minor issues or best-practice deviations
- **Informational** – Notes and recommendations

Severity classification MUST be justified.

---

### Phase 7 — Remediation Review

Auditors MUST:

- Review all fixes
- Confirm no regression introduced
- Re-run affected analyses
- Update findings accordingly

Unresolved Critical or High findings invalidate certification.

---

### Phase 8 — Final Determination

Certification approval requires:

- Zero unresolved Critical or High findings
- Documented auditor attestation
- Compliance with certification level requirements

All decisions MUST be recorded.

---

## 5. Audit Integrity Rules

Auditors MUST NOT:

- Modify scope without disclosure
- Accept compensation contingent on certification outcome
- Conceal unresolved issues
- Issue partial certifications

Violations result in auditor disqualification.

---

## 6. Record Keeping

Audit records MUST include:

- Source hashes
- Tool versions
- Logs and outputs
- Reviewer notes
- Final report

Records MUST be retained for a minimum of 24 months.

---

## 7. Disclaimer

Audits reduce risk but do not eliminate it.  
No audit guarantees absolute security.

Users remain responsible for independent risk assessment.
