# Testnet-v3 launch — handoff to Codex

Written 2026-07-28. Covers sessions 13i–13m. Everything stated here was executed
and verified on the operator's machine, not inferred.

---

## 0. Where this stands in one paragraph

Track G (the atomic genesis deployment mechanism) is **complete and tested**.
The six production custody ceremonies are **done**. The nine production contract
addresses are **derived and reproduced twice**. The only thing left before the
canonical genesis rewrite is the operator running the genesis ceremony
interactively. That ceremony binary is **built and waiting**; its last run
failed on a self-inflicted bug in a pre-signing check, which has been fixed and
rebuilt but **not yet re-run**. See §8 for the exact next action.

---

## 1. Paths

| what | path |
|---|---|
| Testnet-v3 repo | `/Volumes/xcode/Synergy-Network-Projects/network-components/01-Testnetv3` |
| Runtime crate (`synergy-testnet`) | `runtime/src` (crate root **is** `runtime/src`) |
| AIVM core | `runtime/synergy-aivm/runtime/aivm-core` |
| SynQ compiler / pqsynq | `runtime/synq-language` |
| Address Engine (`synergy-keygen`) | `/Volumes/xcode/Synergy-Network-Projects/protocol-components/synergy-address-engine` |
| Staged contract artifacts | `genesis-contracts/staged-governance-v1/` |
| Production custody bundles | `testnet-v3-identity-files/SNRG-TESTNET-V3-*/` |

**The `synergy-address-engine` directory *inside* the Testnet-v3 repo
(`runtime/src/synergy-address-engine`) is a stale v1.0.0 FN-DSA-only copy.
Ignore it.** The canonical engine is the `protocol-components` one (v2.0.0).

---

## 2. Frozen rulings (do not reopen)

* Chain ID `1266`, network `synergy-testnet-v3`, block time `2000 ms`.
* Exactly nine native contracts. SaleClaim excluded, nonce 9 not reserved.
* Nonce order: `0 Identity, 1 ValidatorRegistry, 2 Staking, 3 Governance,
  4 Treasury, 5 Slashing, 6 RewardDistributor, 7 SynergyOracle, 8 TeamVesting`.
* Account/deploy/call domain = **ML-DSA-87**. Consensus = ML-DSA-65.
  P2P = Ed25519. ETDAG ingress = ML-KEM-1024.
* Delegation disabled at genesis (`false / 0 / 0`), one-way `enableDelegation`.
* Treasury contract is a **non-custodial approval/accounting contract**. It is
  **not funded**. TRE-A01 remains the sole holder of the 720M reserve.
  `vault_address` and `initial_balance_nwei` are descriptive mirrors only.
* Governance Authority is **permanent for Testnet-v3** (not retired after
  genesis). Do **not** add governance-key rotation to the other seven contracts
  before launch.
* **Canonical Synergy address model**: `syna…` for accounts/authorities,
  `sync…` for deployed contracts. `tsynq…` is **retired** and must never appear
  as an address, `msg.sender`, authority argument, or derivation input.

---

## 3. Defects found and fixed (all launch-critical)

These were found by tracing, not assumed. Each one would have broken genesis.

### 3.1 AIVM account-domain conflation (session 13i)
Three separate places where the *consensus* algorithm authorized *account*
actions:
1. `stateful_synq.rs::verify_mldsa` hardcoded `AlgorithmId::MlDsa65`. Every
   governance-signed genesis initialization call would have failed.
2. `execution.rs::validate_synq_artifact` demanded `"ML-DSA-65"` manifests and
   would have **rejected all nine ML-DSA-87 artifacts** at deployment.
3. Two `ExecutionContext` builders advertised `required_signature_policy:
   "ml-dsa-65"`.

Fixed by single-sourcing `SYNQ_ACCOUNT_DOMAIN_SIGNATURE_ALGORITHM` /
`_POLICY` in `aivm-core::execution`, and binding the host's verification
algorithm to the compiled manifest.

**Important consequence:** `aivm-core` was **32/42 on arrival**, not the 42/42
recorded in `SYNQ_MLDSA87_MANIFEST_MIGRATION_REPORT.md`. No pre-13i green run
is a valid launch gate.

### 3.2 Governance signatures were replayable (session 13j — P0)
All 24 governed operations verified a caller-supplied `message: Bytes` bound to
nothing else. One signature was replayable across every governed setter on all
eight contracts.

Replaced with a canonical host-constructed envelope
(`verifyGovernanceAuthorization`) binding domain, chain, network, target
contract, resolved method, typed length-prefixed argument hash, a
protocol-owned per-contract nonce, block-height expiry, and the governance key
fingerprint. The eight rebuilt manifests **no longer declare**
`verifyMLDSASignature`, so arbitrary-message verification is not even
reachable.

### 3.3 The runtime library never compiled outside test builds (session 13k)
`posy.rs:76` selected the signing authority with `if cfg!(test)` — a *runtime
boolean* — so both arms compiled in every build and the non-test library had to
resolve `utils::test_temp_root`, which is `#[cfg(test)]`-only.

`cargo test --lib` defines `test`, so every green suite in every prior session
came through the one configuration that happened to work while
`cargo check --lib` (the node binary path) was broken. Fixed with real
conditional compilation.

### 3.4 Genesis determinism leaked hedged signature bytes (session 13k)
ML-DSA signing is randomized. Two values derived from signed bytes fed the state
root: the genesis transaction id, and `SynQDeploymentRecord.deploy_receipt_hash`.
Both now derive from genesis inputs (ordinal, payload hash, artifact triple).
Addresses were never affected.

### 3.5 `tsynq` was a second public address format (session 13m)
`SynQAddress::to_testnet_debug_string()` rendered the internal 41-byte binding
as `tsynq1…`, which leaked into `msg.sender`, receipts, authority manifests and
contract-address derivation. Renamed to `to_execution_signer_id()` →
`synq-signer:<hex>` (deliberately not a Bech32 HRP), and all visible identity
switched to canonical `syna…`.

---

## 4. What exists now

### 4.1 `runtime/src/genesis_deployment.rs` (~1,600 lines)
The Track G mechanism. Entry point:

```rust
execute_genesis_deployment(&mut ExecutionState, &GenesisDeploymentPlan,
                           &GenesisAuthorities, &GenesisParameters)
    -> Result<GenesisDeploymentOutcome, String>
```

* Reuses only canonical paths — `hash_contract_deploy_body`,
  `derive_synq_contract_address_from_deploy`,
  `verify_synq_deploy_for_chain_admission`, `execute_synq_transaction_at`,
  `compute_state_root_after`. **No second deployment algorithm exists.**
* Atomicity is structural: the plan runs against a **clone** of
  `ExecutionState`; the caller's state is overwritten at a single commit point
  after every step succeeds.
* `GenesisDeploymentPlan::validate()` machine-enforces nine entries, unique
  nonces 0..=8, and the dependency graph, before any state is touched.
* Deployer lifecycle persisted under reserved AIVM namespace
  `__synergy_genesis_deployment_v1`; retirement is protocol state, not key
  deletion.
* Also exposes `derive_genesis_addresses(...)` — address derivation from
  **public inputs only**, no private key.

**Test suite: 6/6 green** (`cargo test --lib genesis_deployment::`).

### 4.2 Other binaries
* `runtime/src/bin/derive-genesis-addresses.rs` — public-inputs-only derivation.
* `runtime/src/bin/synergy-genesis-ceremony.rs` — the ceremony driver (§8).
  Behind `--features ceremony`; the feature carries **no dependencies**, so
  `cargo check --lib` and the five-run gate are unaffected.

### 4.3 Address Engine additions
* `generate-authority` — one command produces the whole custody bundle
  (`identity.enc.json`, `identity.pub.json`, `manifest.json`,
  `correspondence.json`, `SHA256SUMS`), `0700`/`0600`, atomic writes, refuses
  overwrite, rejects env passphrases by default.
* `verify-authority-bundle` — validates a bundle with **no passphrase**.
* `decrypt --stdout` — streams the decrypted payload to stdout so a ceremony
  driver can consume it over a pipe with no plaintext keyfile.
* `src/lib.rs` — `[lib]` target added (additive; binaries unchanged).

**Focused tests: 22/22 green.**

---

## 5. Production authorities (ceremonies COMPLETE — do not regenerate)

Frozen: `launch/TESTNET_V3_PRODUCTION_AUTHORITIES.json` (v2, zero `tsynq`).

| role | canonical `syna` address |
|---|---|
| GENESIS-DEPLOYER | `syna197thhzye2pmw6lk3y47nsf6cluqgt07df9t0` |
| GOVERNANCE-AUTHORITY | `syna1adxk7errymz8p8s0k5ysmka9pjv9ntf9jlml` |
| EMERGENCY-SLASHING | `syna1uyct5qxxexzcdqx2wdfd0jfwx5la69ke62yh` |
| VALIDATOR-REGISTRY-AUTHORITY | `syna1rjtgmly6lhtscxaev57hna8p6wwmpq5dle7l` |
| REWARD-DISTRIBUTOR-AUTHORITY | `syna1lqg4qfk2w6esve5h6vgrf9snkl9zce4y6zg2` |
| EMERGENCY-PAUSE-AUTHORITY | `syna12humnsg4tw5agu23z0zlf43jgga732wa06nn` |

All six verify in production mode. No key, address, salt, KEM ciphertext or
nonce is reused between any pair.

**Only three sign anything at genesis:** Genesis Deployer (9 deploys),
Governance Authority (15 governed calls), ValidatorRegistry Authority (12
registry calls). The other three are **address-only constructor inputs** — do
not ask for their passphrases.

---

## 6. Production contract addresses (derived, not yet executed)

Published: `launch/TESTNET_V3_PRODUCTION_CONTRACT_ADDRESSES.json` (v2,
`deployer_address_format: "syna"`, `canonical_synergy_address_model: true`).

| nonce | contract | address |
|---:|---|---|
| 0 | Identity | `sync1tasz8xg3wyvxg8hfujndutgp967ekc25393w` |
| 1 | ValidatorRegistry | `sync1q2s4w0h2q98e2hv9rjycf4th4zwu7r9wxtmz` |
| 2 | Staking | `sync1qqd5u3v4wgqxvfhh49ax08s8pq7uf7kk23l5` |
| 3 | Governance | `sync12j7reatl4p09l4p63kyrxky5t89wp4a8mylg` |
| 4 | Treasury | `sync1puq5nz4wacn25de9suur53esyn99zp9j6jx8` |
| 5 | Slashing | `sync186smh2hyslf7yf5mwa2dq0dt52dpw0eufht3` |
| 6 | RewardDistributor | `sync1gx6zkzqjhfymqz2rz868n8zqf06fe790wued` |
| 7 | SynergyOracle | `sync17yd3kddpn7g9mjeazhnw7ky9pmk5ujjl0rkn` |
| 8 | TeamVesting | `sync14jnyrvt489hz592zc8j5ujptpfxllmy0yu40` |

Nine distinct; two independent runs byte-identical.

Superseded `tsynq`-derived record preserved at
`launch/evidence/SUPERSEDED_TESTNET_V3_CONTRACT_ADDRESSES_TSYNQ.json`
with `do_not_consume: true`. **Nothing may read it.**

---

## 7. Genesis initialization — 27 calls

| # | contract | call | signer |
|---|---|---|---|
| 1–5 | Treasury | `setSigner` ×5 | Governance Authority |
| 6–11 | Identity | `setReservedName` ×6 | Governance Authority |
| 12–17 | ValidatorRegistry | `registerValidator` ×6 | Registry Authority |
| 18–23 | ValidatorRegistry | `activateValidator` ×6 | Registry Authority |
| 24 | SynergyOracle | `setOracle` ×1 | Governance Authority |
| 25–27 | SynergyOracle | `setSourceDomain` ×3 | Governance Authority |

RewardDistributor needs **no** initialization call — `pool_address` is
*distribution authorization only*, proven from source: `distributorAuthority`
appears only in `require(msg.sender == …)`, and `sendNative` debits the
**contract's own** balance. Genesis confirms `initial_pool_balance_nwei: 0`.

Post-initialization state is read back and the deployment **aborts** unless
`signerCount == 5`, `requiredSigners == 4`, `validatorCount == 6`.

---

## 8. THE IMMEDIATE NEXT ACTION

The ceremony was run once and failed on a bug that is now fixed and rebuilt but
**not re-run**.

**What failed:** `signs_correctly()` called
`verify_detached(&sig, probe, public_key)`. The real signature is
`verify_detached(message, signature, public_key)` — arguments swapped. The probe
was wrong; the key material is fine.

**Everything upstream worked:** the child-process pipe rendered the prompt, the
passphrase was accepted, the ML-KEM-1024 + AES-256-GCM envelope decrypted, the
payload parsed, and the key was the correct 4896-byte ML-DSA-87 length.

Fixed at `runtime/src/bin/synergy-genesis-ceremony.rs` and rebuilt
(`cargo build --features ceremony --bin synergy-genesis-ceremony`, EXIT=0).

### Run this

```bash
cd /Volumes/xcode/Synergy-Network-Projects/network-components/01-Testnetv3
unset SYNERGY_PASSPHRASE SYNERGY_DECRYPT_PASSPHRASE

runtime/target/debug/synergy-genesis-ceremony \
  --authorities-file launch/TESTNET_V3_PRODUCTION_AUTHORITIES.json \
  --contracts-file   launch/TESTNET_V3_PRODUCTION_CONTRACT_ADDRESSES.json \
  --output-dir       launch/production-genesis-ceremony \
  --dry-run
```

Three non-echoing prompts, in order: Genesis Deployer, Governance Authority,
ValidatorRegistry Authority. Passphrases are entered **in the Address Engine
child process** and never reach the ceremony process.

**Outcomes:**
* All nine addresses match → `dry-run-status.json` = `DRY_RUN_PASSED`; proceed
  to `--execute` (requires typing `EXECUTE TESTNET-V3 GENESIS` exactly).
* Any mismatch → aborts and names the differing contracts. That would mean the
  constructor inputs the ceremony assembles differ from what
  `derive-genesis-addresses` used. **Diagnose before signing anything.**

---

## 9. Remaining phases after a green dry run

1. `--execute` with the confirmation phrase (writes to a new candidate
   location; never silently overwrites canonical genesis).
2. **Phase 7 — atomic genesis replacement.** One rewrite containing the nine
   real addresses, final artifact bindings, constructor hashes, deployment and
   initialization receipts, final AIVM state root, receipt root, contract root,
   retirement state. Recompute in dependency order: contract records → state
   root → data root → contract root → receipt root → header → genesis hash →
   network magic → release integrity manifest. **Freeze
   `genesis-contracts/staged-governance-v1/` artifacts into
   `genesis-contracts/contracts/` as part of this same atomic step.**
3. **Phase 8 — address migration.** Apply the old→new map atomically workspace
   wide (Track H was never built; the inventory tool still needs writing).
4. **Phase 9 — release tests**, then the five-consecutive-run gate.

---

## 10. Known-red / expected states

`aivm-core::stateful_synq::tests::all_eight_genesis_contracts_deploy_call_restart_and_replay_deterministically`
is **RED and must stay red** until the artifact freeze in Phase 7. It loads the
stale committed artifacts from `genesis-contracts/contracts/` (pre-migration
ML-DSA-65) while the runtime correctly requires ML-DSA-87. **Do not patch around
it** — it is the artifact/runtime coherence gate and turns green exactly when
the freeze lands.

Current: `aivm-core` lib 41/42 + `governance_authorization` 9/9 +
`canonical_address_model` 3/3.

---

## 11. Deferred non-blocking findings

See `launch/DEFERRED_NONBLOCKING_FINDINGS.md`. Summary:

1. Governance-key rotation exists only on ValidatorRegistry (mitigated by the
   permanent-authority ruling).
2. `build_call_admission_envelope_from_pqsynq_bytes_with_args` verifies
   **before** attaching arguments, so its first pass hashes an empty argument
   list — the helper cannot admit any call that has arguments. Worked around in
   `genesis_deployment.rs` by building the envelope directly. **The helper is
   still wrong for any other caller.**
3. SynQ admission requires a non-zero envelope nonce, so deployment ordinals
   0..=8 map to envelope nonces 1..=9.
4. SynergyOracle `quorum_threshold: 1` — a single publisher both proposes and
   finalizes a checkpoint in one call.
5. **Governed setters do not bind the signature to the call** — this was fixed
   by the 13j envelope, but note the *contract sources* still take the
   authorization tail positionally; any new governed function must declare
   `(…, governanceNonce, validUntilBlock, signature)` or it will not compile
   (the compiler now type-checks this).
6. VNS-A01 still holds `validator_registry.authority_address` in the **genesis
   document**. The ceremony overrides it with the dedicated authority, but the
   genesis document itself is corrected only in the Phase 7 rewrite.

---

## 12. Environment notes that will save time

* **Cold `cargo check --lib` on `runtime/src` exceeds 20 minutes** (librocksdb-sys).
  Warm incremental is ~60–90 s. `aivm-core` alone cycles in ~40 s — iterate there.
* Never run two cargo builds in the same target dir concurrently; the second
  blocks on the file lock and looks hung.
* The runtime crate root is `runtime/src`, so `[[bin]]` paths are relative to
  that (`bin/foo.rs`, not `src/bin/foo.rs`).
* The runtime crate **cannot** depend on the Address Engine: both vendor
  `pqrust-internals`, which declares `links = "pqrust_internals"`, and Cargo
  forbids two copies in one graph. This is why the ceremony spawns
  `synergy-keygen` as a child process instead of linking it. **Do not try to
  "fix" this with a feature flag — it is a hard Cargo constraint.**
* SynQ contract rebuild: from `runtime/synq-language`,
  `cargo run -p cli -- build <path>/<Name>.synq` (writes artifacts next to the
  source). `check` validates without emitting.
* ABI method parameters are under `"params"`, not `"inputs"`.
* SynQ constructor arguments are a **JSON array**, not ABI-packed, and the
  encoding is address-determining.

---

## 13. Reading order for context

1. This file.
2. `launch/TRACK_G_COMPLETE.md` — the deployment mechanism.
3. `launch/SESSION_13J_GOVERNANCE_AUTHORIZATION.md` — the P0 fix.
4. `launch/SESSION_13I_ACCOUNT_DOMAIN_VM_FINDINGS.md` — the reuse map and the
   three AIVM defects.
5. `launch/DEFERRED_NONBLOCKING_FINDINGS.md`.
6. `launch/SESSION_13K_TRACK_G_STATE.md` — historical; superseded by
   `TRACK_G_COMPLETE.md`.

Older docs (`CLAUDE_HANDOFF.md`, `PHASE_8_CORRECTED_PLAN.md`,
`CONSTRUCTOR_*.md`) contain useful evidence but **predate** the nonce-order
ruling, the governance-authorization envelope and the canonical address model.
Where they conflict with this document, this document wins.
