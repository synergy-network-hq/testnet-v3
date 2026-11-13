# SynQ Smart Contract Audit Report

Audit ID: `SYNQ-ERC20-2026-02-09`
Project Name: `PQCToken` example contract
Audit Date: 2026-02-09
Auditing Entity: SynQ Internal Engineering Review
Target Certification Level: SynQ Contract Certification Level 1 (example baseline)

---

## 1. Executive Summary

This audit assessed `/Users/devpup/Desktop/Synergy/synergy-components/synq-language/docs/examples/1-ERC20-Token.synq` against the SynQ audit procedure and security manual.

Overall Assessment: **Fail**

The contract is not certifiable for two hard reasons: (1) it does not parse under the official CLI/compiler path, and (2) governance-signature authorization is structurally replayable because the contract verifies an externally supplied byte string without enforcing intent binding or nonce discipline.

---

## 2. Scope

### In-Scope Components

- Contract file: `/Users/devpup/Desktop/Synergy/synergy-components/synq-language/docs/examples/1-ERC20-Token.synq`
- Grammar reference used for semantic compatibility checks: `/Users/devpup/Desktop/Synergy/synergy-components/synq-language/compiler/src/synq.pest`
- Scope commit hash: `71aab8af592d6a1523679354a0a67db7106655d7`

### Out-of-Scope Components

- External bridges/oracles
- Off-chain signing infrastructure
- Wallet UX and key custody

---

## 3. Methodology

The audit was conducted with:

- Automated parser/compiler validation (`cargo run -p cli -- compile --path ...`)
- Manual line-by-line security review
- Access-control and state-transition review
- Cryptographic misuse-resistance review for ML-DSA authorization gates

---

## 4. Findings Summary

| Severity | Count |
|---|---:|
| Critical | 1 |
| High | 2 |
| Medium | 2 |
| Low | 1 |
| Informational | 0 |

---

## 5. Detailed Findings

### Finding ERC20-001

Severity: **High**  
Status: Open  
Title: Contract does not compile with official SynQ parser

Description: The contract fails parser intake at the first state declaration (`String public name;`). Current grammar expects state variables in `name: Type public;` form.

Evidence:

- Parse failure location: `/Users/devpup/Desktop/Synergy/synergy-components/synq-language/docs/examples/1-ERC20-Token.synq:8`
- Grammar expectation: `/Users/devpup/Desktop/Synergy/synergy-components/synq-language/compiler/src/synq.pest:28`

Impact: Non-deployable artifact; no trustworthy codegen/VM validation can proceed.

Recommendation:

- Normalize example syntax to the accepted grammar profile, or
- update parser/codegen intentionally and test it.

---

### Finding ERC20-002

Severity: **Critical**  
Status: Open  
Title: Governance signature checks are replayable and not intent-bound

Description: Privileged functions (`mint`, `pause`, `unpause`, `updateGovernanceKey`) verify `messageToSign` and `signature` provided by caller, but do not build and verify a deterministic in-contract payload containing function name, arguments, chain context, and nonce.

Evidence:

- `mint`: `/Users/devpup/Desktop/Synergy/synergy-components/synq-language/docs/examples/1-ERC20-Token.synq:125`
- `pause`: `/Users/devpup/Desktop/Synergy/synergy-components/synq-language/docs/examples/1-ERC20-Token.synq:181`
- `unpause`: `/Users/devpup/Desktop/Synergy/synergy-components/synq-language/docs/examples/1-ERC20-Token.synq:198`
- `updateGovernanceKey`: `/Users/devpup/Desktop/Synergy/synergy-components/synq-language/docs/examples/1-ERC20-Token.synq:229`

Impact: Any valid signature over arbitrary bytes can potentially be replayed to authorize unintended privileged actions if off-chain signing discipline is imperfect.

Recommendation:

- Build a canonical payload in-contract: `domain || contract || function || args || nonce`.
- Store per-governance nonce and enforce single-use monotonicity.
- Reject if supplied message bytes differ from recomputed payload hash.

---

### Finding ERC20-003

Severity: **High**  
Status: Open  
Title: Pause logic is bypassable/inconsistent

Description: The contract defines transfer logic twice and only one variant checks `paused`. `transferFrom` and `batchTransfer` do not enforce pause status.

Evidence:

- First transfer: `/Users/devpup/Desktop/Synergy/synergy-components/synq-language/docs/examples/1-ERC20-Token.synq:59`
- Second transfer with pause check: `/Users/devpup/Desktop/Synergy/synergy-components/synq-language/docs/examples/1-ERC20-Token.synq:215`
- `transferFrom` lacks pause check: `/Users/devpup/Desktop/Synergy/synergy-components/synq-language/docs/examples/1-ERC20-Token.synq:71`
- `batchTransfer` lacks pause check: `/Users/devpup/Desktop/Synergy/synergy-components/synq-language/docs/examples/1-ERC20-Token.synq:249`

Impact: Emergency pause cannot reliably stop token movement.

Recommendation:

- Centralize transfer preconditions in a shared internal path.
- Enforce `require(!paused)` across all balance-moving entry points.

---

### Finding ERC20-004

Severity: **Medium**  
Status: Open  
Title: Governance key lifecycle validation is incomplete

Description: Constructor and key-rotation path accept key material without explicit invalid-key checks.

Evidence:

- Constructor assignment: `/Users/devpup/Desktop/Synergy/synergy-components/synq-language/docs/examples/1-ERC20-Token.synq:40`
- Update path: `/Users/devpup/Desktop/Synergy/synergy-components/synq-language/docs/examples/1-ERC20-Token.synq:243`

Impact: Misconfiguration can brick privileged operations or produce permanent governance lockout.

Recommendation:

- Add explicit key length/format validation guard.
- Add two-step rotation protocol (propose, activate).

---

### Finding ERC20-005

Severity: **Medium**  
Status: Open  
Title: `approve` uses race-prone allowance overwrite model

Description: Direct overwrite allowance pattern is vulnerable to spender race conditions in common ERC20 semantics.

Evidence:

- `/Users/devpup/Desktop/Synergy/synergy-components/synq-language/docs/examples/1-ERC20-Token.synq:89`

Impact: User-intended allowance changes can be front-run.

Recommendation:

- Require zero-to-nonzero two-step allowance update, or
- recommend only `increaseAllowance`/`decreaseAllowance` flows.

---

### Finding ERC20-006

Severity: **Low**  
Status: Open  
Title: Public API naming collides with state identifiers

Description: Functions share names with state declarations (`totalSupply`, `balanceOf`, `allowance`), creating semantic ambiguity and maintenance risk.

Evidence:

- State names: `/Users/devpup/Desktop/Synergy/synergy-components/synq-language/docs/examples/1-ERC20-Token.synq:11`, `:15`, `:16`
- Function names: `/Users/devpup/Desktop/Synergy/synergy-components/synq-language/docs/examples/1-ERC20-Token.synq:49`, `:54`, `:98`

Impact: Increased parser/codegen fragility and audit ambiguity.

Recommendation:

- Use explicit getter naming (`getTotalSupply`, `getBalance`, `getAllowance`).

---

## 6. Formal Verification Results (If Applicable)

Not performed. Blocked by parser-level non-compilability.

## 7. Cross-Chain Analysis (If Applicable)

Not applicable for this contract.

## 8. Remediation Review

| Finding ID | Status | Notes |
|---|---|---|
| ERC20-001 | Open | Syntax migration required |
| ERC20-002 | Open | Critical cryptographic authorization redesign required |
| ERC20-003 | Open | Pause semantics refactor required |
| ERC20-004 | Open | Key lifecycle hardening required |
| ERC20-005 | Open | Allowance safety patch required |
| ERC20-006 | Open | Naming cleanup required |

## 9. Certification Decision

Certified: **No**

Certification Level: N/A

## 10. Auditor Attestation

This assessment was executed against the repository state at `71aab8af592d6a1523679354a0a67db7106655d7` and reflects independent technical judgment based on reproducible command output and line-level review.

## 11. Disclaimer

This audit is point-in-time. Security posture changes with code, compiler semantics, and deployment assumptions.
