# SynQ Smart Contract Audit Report

Audit ID: `SYNQ-DAO-2026-02-09`
Project Name: `PQCGovernanceDAO` example contract
Audit Date: 2026-02-09
Auditing Entity: SynQ Internal Engineering Review
Target Certification Level: SynQ Contract Certification Level 1 (example baseline)

---

## 1. Executive Summary

This audit assessed `/Users/devpup/Desktop/Synergy/synergy-components/synq-language/docs/examples/3-DAO-Voting.synq`.

Overall Assessment: **Fail**

The example is non-compilable with the official parser and contains critical vote-authentication flaws that can permit forged vote attribution in the signature path.

---

## 2. Scope

### In-Scope Components

- Contract file: `/Users/devpup/Desktop/Synergy/synergy-components/synq-language/docs/examples/3-DAO-Voting.synq`
- Grammar reference: `/Users/devpup/Desktop/Synergy/synergy-components/synq-language/compiler/src/synq.pest`
- Scope commit hash: `71aab8af592d6a1523679354a0a67db7106655d7`

### Out-of-Scope Components

- Off-chain governance UI and vote relayers
- Token contract implementation details

---

## 3. Methodology

- CLI compile validation
- Manual review of proposal lifecycle and vote accounting
- Cryptographic binding analysis for off-chain signature voting and governance updates

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

### Finding DAO-001

Severity: **High**  
Status: Open  
Title: Contract does not compile with official parser

Description: Parser fails at first state declaration.

Evidence:

- Parse failure: `/Users/devpup/Desktop/Synergy/synergy-components/synq-language/docs/examples/3-DAO-Voting.synq:8`
- Grammar expectation: `/Users/devpup/Desktop/Synergy/synergy-components/synq-language/compiler/src/synq.pest:28`

Impact: Non-deployable artifact.

Recommendation:

- Align syntax with canonical grammar and prove compile in CI.

---

### Finding DAO-002

Severity: **Critical**  
Status: Open  
Title: Off-chain vote signature path allows vote attribution forgery

Description: `castVoteWithSignature` accepts `voter` and `voterKey` as caller-controlled inputs and verifies the signature only against `voterKey`, not a registry binding between `voter` address and authorized key.

Evidence:

- `/Users/devpup/Desktop/Synergy/synergy-components/synq-language/docs/examples/3-DAO-Voting.synq:139`

Impact: Attacker can cast a vote on behalf of another address by supplying their own key/signature pair and arbitrary `voter` identity.

Recommendation:

- Maintain on-chain mapping `voterAddress -> authorizedPublicKey`.
- Reject if provided key is not the registered key.
- Include `proposalId`, `support`, and `voter` in signed payload.

---

### Finding DAO-003

Severity: **Critical**  
Status: Open  
Title: Governance signatures are replayable and not nonce-scoped

Description: `executeProposal`, `updateGovernanceKey`, and `updateQuorum` verify caller-supplied message bytes without deterministic in-contract message reconstruction and without anti-replay nonce.

Evidence:

- `executeProposal`: `/Users/devpup/Desktop/Synergy/synergy-components/synq-language/docs/examples/3-DAO-Voting.synq:183`
- `updateGovernanceKey`: `/Users/devpup/Desktop/Synergy/synergy-components/synq-language/docs/examples/3-DAO-Voting.synq:238`
- `updateQuorum`: `/Users/devpup/Desktop/Synergy/synergy-components/synq-language/docs/examples/3-DAO-Voting.synq:258`

Impact: Critical governance actions can be replayed or context-confused.

Recommendation:

- Canonical signed payload + domain separator + per-governance nonce.

---

### Finding DAO-004

Severity: **High**  
Status: Open  
Title: Governance weighting controls are placeholders, enabling Sybil-style influence

Description: Proposal threshold and token-weighted voting are documented but not enforced. `weight` is hardcoded to `1`.

Evidence:

- Threshold bypass note: `/Users/devpup/Desktop/Synergy/synergy-components/synq-language/docs/examples/3-DAO-Voting.synq:77`
- Constant vote weight: `/Users/devpup/Desktop/Synergy/synergy-components/synq-language/docs/examples/3-DAO-Voting.synq:121` and `:165`

Impact: Governance assumptions in docs do not hold; one-address-one-vote can be trivially Sybil-amplified.

Recommendation:

- Integrate actual token snapshot/weighting at proposal start and vote cast.

---

### Finding DAO-005

Severity: **Medium**  
Status: Open  
Title: Governance cancellation path uses impossible authority sentinel

Description: `cancelProposal` allows proposer or `msg.sender == Address(0)` (labeled governance). Zero address sender is not a valid caller identity.

Evidence:

- `/Users/devpup/Desktop/Synergy/synergy-components/synq-language/docs/examples/3-DAO-Voting.synq:228`

Impact: Intended governance cancellation authority is not actually implemented.

Recommendation:

- Replace with explicit governance signature path or role mapping.

---

### Finding DAO-006

Severity: **Medium**  
Status: Open  
Title: Proposal execution is non-functional placeholder

Description: `executeProposal` marks proposal executed but does not call target/calldata.

Evidence:

- `/Users/devpup/Desktop/Synergy/synergy-components/synq-language/docs/examples/3-DAO-Voting.synq:214`

Impact: Execution event can be emitted without state effect on target systems.

Recommendation:

- Implement call execution with strict return/error handling and target allowlist controls.

---

## 6. Formal Verification Results (If Applicable)

Not performed due parser-level compile failure.

## 7. Cross-Chain Analysis (If Applicable)

Not applicable.

## 8. Remediation Review

| Finding ID | Status | Notes |
|---|---|---|
| DAO-001 | Open | Syntax migration required |
| DAO-002 | Open | Vote identity binding redesign required |
| DAO-003 | Open | Governance anti-replay controls required |
| DAO-004 | Open | Token weighting implementation required |
| DAO-005 | Open | Real governance cancel authority required |
| DAO-006 | Open | Real execution path required |

## 9. Certification Decision

Certified: **No**

Certification Level: N/A

## 10. Auditor Attestation

This report is based on reproducible review evidence at commit `71aab8af592d6a1523679354a0a67db7106655d7`.

## 11. Disclaimer

Security posture must be re-audited after remediation and syntax/toolchain alignment.
