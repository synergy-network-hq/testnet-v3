# SynQ Smart Contract Audit Report

Audit ID: `SYNQ-STAKING-2026-02-09`
Project Name: `PQCStaking` example contract
Audit Date: 2026-02-09
Auditing Entity: SynQ Internal Engineering Review
Target Certification Level: SynQ Contract Certification Level 1 (example baseline)

---

## 1. Executive Summary

This audit assessed `/Users/devpup/Desktop/Synergy/synergy-components/synq-language/docs/examples/6-Staking-Contract.synq`.

Overall Assessment: **Fail**

The contract is non-compilable and contains critical economic-model defects: staking and reward accounting are disconnected from real token transfer semantics, so balances can be inflated without custody guarantees.

---

## 2. Scope

### In-Scope Components

- Contract file: `/Users/devpup/Desktop/Synergy/synergy-components/synq-language/docs/examples/6-Staking-Contract.synq`
- Grammar reference: `/Users/devpup/Desktop/Synergy/synergy-components/synq-language/compiler/src/synq.pest`
- Scope commit hash: `71aab8af592d6a1523679354a0a67db7106655d7`

### Out-of-Scope Components

- External token contracts and liquidity sources
- Frontend APY display logic

---

## 3. Methodology

- CLI compile validation
- Manual review of staking/reward/accounting invariants
- ML-DSA authorization misuse-resistance review

---

## 4. Findings Summary

| Severity | Count |
|---|---:|
| Critical | 2 |
| High | 2 |
| Medium | 2 |
| Low | 0 |
| Informational | 0 |

---

## 5. Detailed Findings

### Finding STAKE-001

Severity: **High**  
Status: Open  
Title: Contract does not compile with official parser

Description: Parser fails at first state declaration.

Evidence:

- Parse failure: `/Users/devpup/Desktop/Synergy/synergy-components/synq-language/docs/examples/6-Staking-Contract.synq:8`
- Grammar expectation: `/Users/devpup/Desktop/Synergy/synergy-components/synq-language/compiler/src/synq.pest:28`

Impact: Contract cannot be deployed/tested via canonical toolchain.

Recommendation:

- Align contract syntax with accepted grammar and add compile CI gate.

---

### Finding STAKE-002

Severity: **Critical**  
Status: Open  
Title: Staking and reward accounting are disconnected from actual token transfers

Description: Stake, unstake, and reward paths update internal accounting but transfer calls are placeholders/comments.

Evidence:

- Stake transfer placeholder: `/Users/devpup/Desktop/Synergy/synergy-components/synq-language/docs/examples/6-Staking-Contract.synq:141`
- Unstake transfer placeholder: `/Users/devpup/Desktop/Synergy/synergy-components/synq-language/docs/examples/6-Staking-Contract.synq:176`
- Reward transfer placeholder: `/Users/devpup/Desktop/Synergy/synergy-components/synq-language/docs/examples/6-Staking-Contract.synq:195`

Impact: Economic invariants are not enforceable; internal balances can diverge from real asset custody.

Recommendation:

- Implement mandatory transfer-in/transfer-out checks with revert-on-failure semantics.
- Introduce funded reward-pool accounting invariant.

---

### Finding STAKE-003

Severity: **Critical**  
Status: Open  
Title: Signature-gated admin/emergency functions are replayable and context-ambiguous

Description: `emergencyWithdraw`, `updateRewardRate`, `updateWithdrawalKey`, and `setWithdrawalsEnabled` verify caller-provided message bytes without deterministic payload construction and nonce checks.

Evidence:

- `emergencyWithdraw`: `/Users/devpup/Desktop/Synergy/synergy-components/synq-language/docs/examples/6-Staking-Contract.synq:203`
- `updateRewardRate`: `/Users/devpup/Desktop/Synergy/synergy-components/synq-language/docs/examples/6-Staking-Contract.synq:238`
- `updateWithdrawalKey`: `/Users/devpup/Desktop/Synergy/synergy-components/synq-language/docs/examples/6-Staking-Contract.synq:262`
- `setWithdrawalsEnabled`: `/Users/devpup/Desktop/Synergy/synergy-components/synq-language/docs/examples/6-Staking-Contract.synq:282`

Impact: Governance/emergency controls can be replayed or misapplied.

Recommendation:

- Canonical payload and nonce-based anti-replay per key.

---

### Finding STAKE-004

Severity: **High**  
Status: Open  
Title: Lock-period policy invariants are not validated in constructor

Description: Constructor sets `minLockPeriod` and `maxLockPeriod` without validating `min <= max`.

Evidence:

- `/Users/devpup/Desktop/Synergy/synergy-components/synq-language/docs/examples/6-Staking-Contract.synq:59`

Impact: Misconfiguration can render staking unusable or bypass intended lock policy.

Recommendation:

- Enforce constructor invariant `minLockPeriod <= maxLockPeriod` and sane upper bounds.

---

### Finding STAKE-005

Severity: **Medium**  
Status: Open  
Title: Reward emissions lack explicit funded-cap controls

Description: Reward accounting accrues from `rewardRate` and block delta without contract-side solvency checks against an actual reward reserve.

Evidence:

- Reward accrual formula: `/Users/devpup/Desktop/Synergy/synergy-components/synq-language/docs/examples/6-Staking-Contract.synq:75`

Impact: Accrued obligations can exceed available rewards, causing insolvency at payout.

Recommendation:

- Add reward reserve accounting and cap accrual by available liquidity.

---

### Finding STAKE-006

Severity: **Medium**  
Status: Open  
Title: `stakerList` growth is unbounded with no compaction/removal path

Description: Stakers are appended once and never removed from list, even when inactive.

Evidence:

- Append path: `/Users/devpup/Desktop/Synergy/synergy-components/synq-language/docs/examples/6-Staking-Contract.synq:127`

Impact: Any future list iteration can become vulnerable to gas/DoS pressure.

Recommendation:

- Maintain active-set indexing with removal/swap-pop or pagination.

---

## 6. Formal Verification Results (If Applicable)

Not performed due parser incompatibility.

## 7. Cross-Chain Analysis (If Applicable)

Not applicable.

## 8. Remediation Review

| Finding ID | Status | Notes |
|---|---|---|
| STAKE-001 | Open | Syntax migration required |
| STAKE-002 | Open | Core custody/accounting implementation required |
| STAKE-003 | Open | Critical signature-binding controls required |
| STAKE-004 | Open | Lock policy invariant checks required |
| STAKE-005 | Open | Reward solvency controls required |
| STAKE-006 | Open | State growth management required |

## 9. Certification Decision

Certified: **No**

Certification Level: N/A

## 10. Auditor Attestation

This report is based on reproducible command evidence and manual review at commit `71aab8af592d6a1523679354a0a67db7106655d7`.

## 11. Disclaimer

Re-audit required after remediation and toolchain-compatible syntax convergence.
