# SynQ Smart Contract Audit Report

Audit ID: `SYNQ-MULTISIG-2026-02-09`
Project Name: `PQCMultiSigWallet` example contract
Audit Date: 2026-02-09
Auditing Entity: SynQ Internal Engineering Review
Target Certification Level: SynQ Contract Certification Level 1 (example baseline)

---

## 1. Executive Summary

This audit assessed `/Users/devpup/Desktop/Synergy/synergy-components/synq-language/docs/examples/2-MultiSig-Wallet.synq`.

Overall Assessment: **Fail**

The contract is not certifiable. It fails parser intake and has critical authorization design defects that can invalidate multi-signature guarantees under realistic operational mistakes.

---

## 2. Scope

### In-Scope Components

- Contract file: `/Users/devpup/Desktop/Synergy/synergy-components/synq-language/docs/examples/2-MultiSig-Wallet.synq`
- Grammar reference: `/Users/devpup/Desktop/Synergy/synergy-components/synq-language/compiler/src/synq.pest`
- Scope commit hash: `71aab8af592d6a1523679354a0a67db7106655d7`

### Out-of-Scope Components

- Off-chain transaction composer
- External contract call runtime

---

## 3. Methodology

- Official CLI compile attempt
- Manual review of owner management, confirmation model, and governance transitions
- Replay/misuse analysis for ML-DSA signature use

---

## 4. Findings Summary

| Severity | Count |
|---|---:|
| Critical | 1 |
| High | 3 |
| Medium | 2 |
| Low | 0 |
| Informational | 0 |

---

## 5. Detailed Findings

### Finding MSIG-001

Severity: **High**  
Status: Open  
Title: Contract does not compile with official parser

Description: Compile attempt fails at first state declaration.

Evidence:

- Parse failure: `/Users/devpup/Desktop/Synergy/synergy-components/synq-language/docs/examples/2-MultiSig-Wallet.synq:8`
- Grammar expectation: `/Users/devpup/Desktop/Synergy/synergy-components/synq-language/compiler/src/synq.pest:28`

Impact: Not deployable under current toolchain.

Recommendation:

- Migrate syntax to canonical SynQ grammar or update parser support with tests.

---

### Finding MSIG-002

Severity: **Critical**  
Status: Open  
Title: Signature checks are replayable and not transaction-intent bound

Description: Functions verify caller-supplied `messageToSign` without contract-side reconstruction from `txId`, action, contract domain, and nonce. This affects confirmations and governance actions.

Evidence:

- `confirmTransaction`: `/Users/devpup/Desktop/Synergy/synergy-components/synq-language/docs/examples/2-MultiSig-Wallet.synq:99`
- `addOwner`: `/Users/devpup/Desktop/Synergy/synergy-components/synq-language/docs/examples/2-MultiSig-Wallet.synq:158`
- `removeOwner`: `/Users/devpup/Desktop/Synergy/synergy-components/synq-language/docs/examples/2-MultiSig-Wallet.synq:194`
- `replaceOwner`: `/Users/devpup/Desktop/Synergy/synergy-components/synq-language/docs/examples/2-MultiSig-Wallet.synq:236`
- `changeRequiredSignatures`: `/Users/devpup/Desktop/Synergy/synergy-components/synq-language/docs/examples/2-MultiSig-Wallet.synq:282`

Impact: Multi-sig assurance degrades; valid signatures can be replayed in unintended contexts.

Recommendation:

- Build deterministic signed payload in-contract.
- Add per-owner nonce and global action nonce.
- Mark consumed approvals to prevent replay.

---

### Finding MSIG-003

Severity: **High**  
Status: Open  
Title: Owner set integrity not enforced at initialization

Description: Constructor does not reject duplicate owners or zero-address owners.

Evidence:

- `/Users/devpup/Desktop/Synergy/synergy-components/synq-language/docs/examples/2-MultiSig-Wallet.synq:48`

Impact: Duplicate/invalid owners reduce effective threshold security and can lock governance.

Recommendation:

- Enforce uniqueness and non-zero owner address checks before finalizing owner list.

---

### Finding MSIG-004

Severity: **High**  
Status: Open  
Title: Governance signature validation uses index coupling instead of explicit signer set

Description: Governance signature loops bind `signatures[i]` to `owners[i]` by array index, not explicit recovered signer identity. This model is brittle under owner reorder/removal and does not support robust signer set semantics.

Evidence:

- `addOwner`: `/Users/devpup/Desktop/Synergy/synergy-components/synq-language/docs/examples/2-MultiSig-Wallet.synq:171`
- `removeOwner`: `/Users/devpup/Desktop/Synergy/synergy-components/synq-language/docs/examples/2-MultiSig-Wallet.synq:206`
- `replaceOwner`: `/Users/devpup/Desktop/Synergy/synergy-components/synq-language/docs/examples/2-MultiSig-Wallet.synq:251`
- `changeRequiredSignatures`: `/Users/devpup/Desktop/Synergy/synergy-components/synq-language/docs/examples/2-MultiSig-Wallet.synq:294`

Impact: Threshold logic can be operationally fragile and prone to governance deadlocks or incorrect acceptance/rejection behavior.

Recommendation:

- Require explicit signer addresses with dedup check.
- Verify each signature against its declared signer key.
- Enforce signer set cardinality and uniqueness.

---

### Finding MSIG-005

Severity: **Medium**  
Status: Open  
Title: Executed transaction path is placeholder-only

Description: `executeTransaction` sets `executed = true` but does not perform fund transfer or target call.

Evidence:

- `/Users/devpup/Desktop/Synergy/synergy-components/synq-language/docs/examples/2-MultiSig-Wallet.synq:131`

Impact: Contract semantics diverge from wallet expectations; monitoring may record execution without effect.

Recommendation:

- Implement actual call/value transfer path with return handling and revert safety.

---

### Finding MSIG-006

Severity: **Medium**  
Status: Open  
Title: Owner lifecycle cleanup is incomplete

Description: Removed/replaced owner key data and historical confirmations are not fully normalized when owner set changes.

Evidence:

- Owner removal: `/Users/devpup/Desktop/Synergy/synergy-components/synq-language/docs/examples/2-MultiSig-Wallet.synq:222`
- Owner replacement: `/Users/devpup/Desktop/Synergy/synergy-components/synq-language/docs/examples/2-MultiSig-Wallet.synq:267`

Impact: Residual state can cause ambiguity in audits and maintenance operations.

Recommendation:

- Explicitly clear old key mappings and define confirmation invalidation policy on owner-set mutation.

---

## 6. Formal Verification Results (If Applicable)

Not performed; blocked by parser incompatibility.

## 7. Cross-Chain Analysis (If Applicable)

Not applicable.

## 8. Remediation Review

| Finding ID | Status | Notes |
|---|---|---|
| MSIG-001 | Open | Syntax migration required |
| MSIG-002 | Open | Critical authorization redesign required |
| MSIG-003 | Open | Owner invariant checks required |
| MSIG-004 | Open | Signer set model redesign required |
| MSIG-005 | Open | Execution logic implementation required |
| MSIG-006 | Open | State hygiene updates required |

## 9. Certification Decision

Certified: **No**

Certification Level: N/A

## 10. Auditor Attestation

This report is based on reproducible tooling output and line-level review at commit `71aab8af592d6a1523679354a0a67db7106655d7`.

## 11. Disclaimer

Security findings are point-in-time and must be revalidated after remediation.
