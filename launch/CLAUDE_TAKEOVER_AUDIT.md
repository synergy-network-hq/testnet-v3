# Claude Takeover Audit — Testnet-v3

Date: 2026-07-26. Session scope: verification-first takeover, identity-binding
blocker resolution, and honest launch-gate accounting. Every claim below was
verified against the filesystem this session; nothing was accepted from prior
summaries.

## Git state

- Repository: `network-components/01-Testnetv3` → `github.com/synergy-network-hq/testnet-v3.git`
- Branch `main`, HEAD `3011bfa` ("Verifying alignment with PoSy Specification Docs")
- Worktrees: single. No destructive operations performed; all prior work preserved.
- Working-tree changes (this session + prior validation session, uncommitted):
  launch records, identity-validation artifacts, inherited-binding fixes,
  quarantine moves (git mv), new scripts, TeamVesting.synq draft.
- Version: `3.0.0-prelaunch.1`.

## Contradictions found (source-of-truth table)

| Topic | Governing artifact | Runtime artifact | Current value | Conflicting artifact | Resolution |
|---|---|---|---|---|---|
| Candidate genesis hash | `genesis.testnet-v3.identity-assigned.json` `integrity.genesis_hash` | same | `ac5186cb…008407` | Handover brief claimed `601263ff…b16f` — **appears nowhere in the repo** | On-disk canonical genesis governs; brief value treated as stale/unrecorded. Final hash will be recomputed at binding. |
| Candidate network magic | genesis `network_magic_bytes` | same | `845e8eca` (candidate) | Brief claimed `10583b30` — not in repo | Same resolution; must be recomputed from final canonical genesis. |
| Consensus signature algorithm | Security Spec v7: "ML-DSA-65 exclusively" | `runtime/src/consensus/validator_keys.rs` enforces ML-DSA-65 @1,952 B | ML-DSA-65 | PoSy spec §7/§12/§15/§19.2 + workbook CRYPTO-001 say ML-DSA-87 (workbook lists it as *unresolved decision*) | ML-DSA-65 operative; spec/workbook amendment externally owned. Full evidence: `launch/CRYPTOGRAPHIC_IDENTITY_PROFILE.md`. No identities relabeled or regenerated. |
| Validator cluster schedule | 6–9→1, 10–20→2, floor(N/7) for N≥21 | `runtime/src/synergy_types.rs::testnet_v3_cluster_count` implements exactly this; boundary test covers 6,9,10,20,21,27,28,34,35,41,42,48,49 | consistent | No active occurrence of any obsolete "21–150 = 3 clusters" rule found | PASS (test at `synergy_types.rs::cluster_schedule_matches_every_corrected_boundary`). |
| ETDAG ingress keys | `runtime/src/etdag.rs` `IngressKemPublicKey` requires ML-KEM-1024 (1,568 B) | same | **no ingress records exist** | Validator bundles contain ML-KEM-768 *entropy* keys (1,184 B) — different role | Gate stays BLOCKED; exact external input specified in crypto profile doc. |
| Genesis identity state | Canonical identity-assigned genesis + `identity-registry.public.json` (64 identities) | validated | 54 PASS / 4 BLOCKED / 0 FAIL | Older README text claiming identities "must be generated" | README text stale; validation-and-binding gates govern (launch-readiness `identity_validation`). |
| Retired v2 validator bindings | Genesis assignment record | runtime config/templates/control-panel | **was FAIL** (6 retired addresses across ~60 files) | — | Fixed this session; structural gate `scripts/check-retired-v2-bindings.py` now PASS (0 active violations); runtime compile/test proof still pending. |
| v2 fork recovery | `consensus_fork.rs` fresh-genesis policy (env var always rejected; schema FN-DSA-only) | — | inert | `runtime/config/consensus-fork-migration.json` + control-panel copy | Quarantined to `launch/reference/testnet-v2/`; tombstone notes left. |

## Verified prior-work claims (spot-checked from source/tests, not trusted)

- ML-DSA-65 consensus enforcement with exact 1,952-byte keys and negative
  tests: present (`validator_keys.rs`).
- Strict two-thirds rejection test present (`synergy_types.rs`).
- Typed coordinator exists (`typed_coordinator.rs`, 1,722 lines); parity gate
  confirms it is NOT yet the wired production engine (validator signing
  intentionally unavailable — fail-closed as designed).
- Component-parity gate (`scripts/check-component-parity.py`): all 19
  component groups PASS; 4 operational blockers BLOCKED (typed-engine
  convergence, wallet ETDAG sealing, ingress-key binding, security/perf/
  genesis/soak qualification).
- Structure gate (`scripts/validate-testnet-v3.py --structure`): passes
  content-wise; the TOML failures reported in this sandbox are a Python 3.10
  environment artifact (script requires 3.11 tomllib; topology values verified
  correct with tomli).
- Eight genesis-contract artifact bindings: recomputed SHA-256 of bytecode/
  ABI/manifest all match genesis (identity-validation results).

## Open P0/P1 gates (verified, not inherited labels)

P0 (internal engineering): typed PoSy coordinator as sole production engine
(role-runtime wiring + distributed qualification); deterministic SynQ genesis
deployment producing real receipts and post-deployment AIVM state root, which
must REPRODUCE the ten existing contract addresses; canonical parameter
manifest finalization; wallet-side ETDAG sealing; resource isolation; Security
v7 closure; reproducible release; 10k-block soak.

P0 (external inputs): ML-KEM-1024 ETDAG ingress key records (do not exist);
custody signing ceremony (passphrases); Presale Claim Voucher specification
for `sale_claim`; PoSy-spec/workbook amendment ratifying ML-DSA-65 (or an
explicit contrary ruling); genesis approval signatures; validator machines for
prepare-only deployment and launch.

P1: 90-day consensus-key rotation rule (workbook REM-D-020); regeneration of
control-panel runtime state from v3 genesis (bootstrap gate); topology
validator-address population.

## Environment limits of this session (recorded for honesty)

Sandboxed Linux (aarch64, Python 3.10) with no pre-installed Rust toolchain;
rustup install was still downloading at session close, so `cargo check`/
`cargo test`, SynQ compilation, AIVM deployment execution, distributed
qualification, and any launch-sequence step were not executable here. No
access to validator machines, custody machines, or wallet-platform build
toolchains. Nothing was fabricated to compensate; affected gates remain
BLOCKED/pending with exact next actions in `launch/CLAUDE_HANDOFF.md`.
