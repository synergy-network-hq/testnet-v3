# SynQ Smart Contract Audit Report

Audit ID: `SYNQ-NFT-2026-02-09`
Project Name: `PQCNFT` example contract
Audit Date: 2026-02-09
Auditing Entity: SynQ Internal Engineering Review
Target Certification Level: SynQ Contract Certification Level 1 (example baseline)

---

## 1. Executive Summary

This audit assessed `/Users/devpup/Desktop/Synergy/synergy-components/synq-language/docs/examples/4-NFT-Contract.synq`.

Overall Assessment: **Fail**

The contract is not certifiable. It does not compile in the official toolchain and has critical mint/governance signature misuse risks plus token ID lifecycle defects.

---

## 2. Scope

### In-Scope Components

- Contract file: `/Users/devpup/Desktop/Synergy/synergy-components/synq-language/docs/examples/4-NFT-Contract.synq`
- Grammar reference: `/Users/devpup/Desktop/Synergy/synergy-components/synq-language/compiler/src/synq.pest`
- Scope commit hash: `71aab8af592d6a1523679354a0a67db7106655d7`

### Out-of-Scope Components

- Metadata hosting integrity
- Marketplace integration semantics

---

## 3. Methodology

- CLI compile validation
- Manual review of transfer, mint, burn, and admin controls
- PQ authorization misuse-resistance analysis

---

## 4. Findings Summary

| Severity | Count |
|---|---:|
| Critical | 1 |
| High | 2 |
| Medium | 3 |
| Low | 0 |
| Informational | 0 |

---

## 5. Detailed Findings

### Finding NFT-001

Severity: **High**  
Status: Open  
Title: Contract does not compile with official parser

Description: Parse fails at first contract member declaration.

Evidence:

- Parse failure: `/Users/devpup/Desktop/Synergy/synergy-components/synq-language/docs/examples/4-NFT-Contract.synq:8`
- Grammar expectation: `/Users/devpup/Desktop/Synergy/synergy-components/synq-language/compiler/src/synq.pest:28`

Impact: Artifact cannot be deployed/tested via official path.

Recommendation:

- Normalize syntax or extend parser intentionally with tests.

---

### Finding NFT-002

Severity: **Critical**  
Status: Open  
Title: Mint/admin signatures are not intent-bound and are replayable

Description: `mint`, `batchMint`, `setPublicMinting`, and `updateMintingKey` trust caller-supplied message bytes with no deterministic payload construction and no nonce.

Evidence:

- `mint`: `/Users/devpup/Desktop/Synergy/synergy-components/synq-language/docs/examples/4-NFT-Contract.synq:143`
- `batchMint`: `/Users/devpup/Desktop/Synergy/synergy-components/synq-language/docs/examples/4-NFT-Contract.synq:207`
- `setPublicMinting`: `/Users/devpup/Desktop/Synergy/synergy-components/synq-language/docs/examples/4-NFT-Contract.synq:303`
- `updateMintingKey`: `/Users/devpup/Desktop/Synergy/synergy-components/synq-language/docs/examples/4-NFT-Contract.synq:322`

Impact: Signature replay or context confusion can authorize unintended mint/admin operations.

Recommendation:

- Signed payload must include `function`, `recipient(s)`, metadata hash, contract domain, and nonce.
- Track consumed nonce for minting key.

---

### Finding NFT-003

Severity: **High**  
Status: Open  
Title: Token ID allocation reuses IDs after burn

Description: Mint sets `tokenId = totalSupply`; burn decrements `totalSupply`. This can reassign existing token IDs after burns.

Evidence:

- Mint allocation: `/Users/devpup/Desktop/Synergy/synergy-components/synq-language/docs/examples/4-NFT-Contract.synq:164`
- Burn decrement: `/Users/devpup/Desktop/Synergy/synergy-components/synq-language/docs/examples/4-NFT-Contract.synq:260`

Impact: Token identity collision, ownership corruption risk, and indexer inconsistency.

Recommendation:

- Use monotonic `nextTokenId` counter that never decrements.

---

### Finding NFT-004

Severity: **Medium**  
Status: Open  
Title: `safeTransferFrom` does not perform receiver acceptance checks

Description: Function delegates to `transferFrom` and omits recipient contract callback/validation.

Evidence:

- `/Users/devpup/Desktop/Synergy/synergy-components/synq-language/docs/examples/4-NFT-Contract.synq:131`

Impact: NFTs can be transferred to contracts that cannot handle them, causing permanent lock.

Recommendation:

- Implement receiver interface check before finalizing safe transfer.

---

### Finding NFT-005

Severity: **Medium**  
Status: Open  
Title: Ownership enumeration function is stubbed

Description: `tokensOfOwner` always returns `[]`.

Evidence:

- `/Users/devpup/Desktop/Synergy/synergy-components/synq-language/docs/examples/4-NFT-Contract.synq:346`

Impact: Off-chain consumers receive incorrect ownership state from advertised API.

Recommendation:

- Maintain owner-to-token index or document function as unsupported/removed.

---

### Finding NFT-006

Severity: **Medium**  
Status: Open  
Title: Royalty recipient validation is incomplete

Description: Royalty setup validates percentage but not recipient address validity.

Evidence:

- `/Users/devpup/Desktop/Synergy/synergy-components/synq-language/docs/examples/4-NFT-Contract.synq:273`

Impact: Misconfiguration can silently burn royalties.

Recommendation:

- Reject zero-address recipient for non-zero royalty percentage.

---

## 6. Formal Verification Results (If Applicable)

Not performed due parser incompatibility.

## 7. Cross-Chain Analysis (If Applicable)

Not applicable.

## 8. Remediation Review

| Finding ID | Status | Notes |
|---|---|---|
| NFT-001 | Open | Syntax migration required |
| NFT-002 | Open | Critical signature-binding redesign required |
| NFT-003 | Open | Token ID lifecycle redesign required |
| NFT-004 | Open | Safe transfer receiver checks required |
| NFT-005 | Open | Enumeration state/index implementation required |
| NFT-006 | Open | Royalty validation hardening required |

## 9. Certification Decision

Certified: **No**

Certification Level: N/A

## 10. Auditor Attestation

This report is grounded in reproducible tool evidence and line-level analysis at commit `71aab8af592d6a1523679354a0a67db7106655d7`.

## 11. Disclaimer

Re-audit is mandatory after syntax/toolchain and logic remediation.
