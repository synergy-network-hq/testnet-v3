# CLAUDE_HANDOFF — Testnet-v3 (updated 2026-07-27, phase session 6)

## Session-13c (read first) — P0 correction applied, provisional binding REVERTED

The "genesis-installed at pre-assigned identity addresses" ruling is
**withdrawn**. Governing model is now: FN-DSA-derived Synergy addresses are
contract **identity/custody** records; deployed contract **instances** take
addresses from the canonical deterministic deployment derivation; the two are
separate fields and are never conflated.

**Reverted and verified.** Genesis restored from a checksum-validated backup
(`ac5186cb…008407`, magic `845e8eca`, state root `8e9934ab…`, 8 artifacts
bound); `NATIVE_GENESIS_CONTRACTS` 9 → 8; bootstrap test name restored;
TeamVesting artifact files removed from `genesis-contracts/contracts/`.
`git diff` for the genesis document and the bootstrap module is now empty.
`consensus::diagnostics::` is **3/3 green (59/59)** — the causal regression is
gone, and it was not patched around. Both candidate values stay candidates.

**Verified for the corrected model** (read `launch/PHASE_8_DEPLOYMENT_FINDINGS.md`
§7): the deployment address derivation is deterministic and **time-independent**
(`payload_hash` covers only the four hashes plus signer; `not_before_unix` /
`expiration_unix` feed neither the payload hash nor the address). There is **no
`salt`** — `nonce` is the only disambiguator. Deriving addresses does **not**
require custody; only executing a signed deploy does.

**Two hard blockers, neither inventable:**

1. **No genesis deployment signer identity exists.** No `deployer` /
   `deployment_signer` / `deploy_authority` field anywhere in the genesis
   document, and `verifier.rs::expect_address` requires a key-backed SynQ
   address. All ten addresses depend on it. Nothing can be derived until it is
   designated.
2. **No genesis system-deployment mechanism exists.** No
   `system_deploy` / `genesis_deploy` / `deploy_genesis` path in the repository;
   `testnet_v3_execution_bootstrap.rs` only binds and validates artifacts and
   leaves `synq_contracts` empty by design. Correction item 3 is new
   architecture to build, not configuration to change.

SaleClaim also still blocks its own address: its constructor-args hash feeds its
address, and its host capability, attestor set and threshold are unresolved.

---

## Session-13b — Phase 8 advanced, one regression to fix (SUPERSEDED by 13c)

Full detail: **`launch/PHASE_8_DEPLOYMENT_FINDINGS.md`**. Summary:

1. **All eight bound artifacts reproduce bit-for-bit** from source. The SynQ
   compiler is deterministic and the genesis bindings are honest.
2. **Phase 8's acceptance criterion was wrong.** "Deterministic deployment must
   reproduce all ten existing addresses" is unsatisfiable: all ten addresses are
   *identity* addresses — `Bech32m(synq, SHA3-256(FN-DSA-1024 pubkey))`, which I
   reproduced 10/10 from `contract_identities`. The deploy path derives from
   nonce + signer + artifact hashes and would mint ten different addresses.
   Operator ruled: **genesis-installed at pre-assigned addresses**.
3. **TeamVesting compiled and bound** (bytecode hash reproduces session-4's
   value); `NATIVE_GENESIS_CONTRACTS` 8 → 9; all derived roots, the genesis hash
   and the network magic recomputed in dependency order. Ceremony challenges are
   now stale and must be regenerated.
4. **SaleClaim deliberately NOT bound** — its manifest declares no
   `host_functions` despite requiring `hostVerifyThresholdAttestation`, and its
   attestor set and threshold constructor args are an open governance input.
5. **Phase 8 terminates at a custody-gated signature.**
   `testnet_v3_execution_bootstrap.rs` requires a *signed* genesis deployment
   manifest and a post-deployment AIVM state-root binding. Same blocker as
   Phase 9. Not obtainable in-session.

**REGRESSION — fix first.** Binding TeamVesting broke four
`consensus::diagnostics` tests, proven causal by A/B on identical code
(pre-change genesis 3/3 green, post-change 2/3 failed). All fail *closed*.
Likely the diagnostics fixtures stage only the eight contract artifacts into
their temp runtime roots and preparation now needs nine. Treat the binding as
provisional until fixed; reverting is one `cp` from
`/Volumes/xcode/genesis-backup-pre-teamvesting.json` plus
`NATIVE_GENESIS_CONTRACTS` back to 8.

---

## Session-13 — disk unblocked, suite 1104/1104, 4 of 5 runs green

```
cd runtime/src && SYNERGY_GENESIS_FILE=<repo>/genesis.testnet-v3.identity-assigned.json cargo test --lib
=> 1104 passed / 0 failed   (4 of 5 consecutive runs)
```

The suite is **fully green** and no longer has a consistent failure. What
remains is residual order-dependence: 1 run in 5 (the slow one, 38 s vs 29 s)
failed two tests that pass otherwise.

### Disk: root cause found, and it was not what session-12 concluded

Session-12 recorded "the suite does **not** leak temp dirs" and attributed the
11 GB in `/var/folders/.../T` to unrelated WebKit blobs. **That was wrong**, and
the check that produced it was run in a shell where `$TMPDIR` was unset, so the
glob looked in the wrong directory.

The suite leaks **every** scratch root it creates: 67 call sites did
`std::env::temp_dir().join(...)` with no cleanup on any path, success or panic.
Measured: **327 entries per run**; **19,248 had accumulated** (~4.9 GB and, more
damaging, ~60 M inodes). That is what exhausted `/` and produced session-12's
752/351 `StorageFull` collapse.

Fixes:
1. All 67 sites now route through `utils::test_temp_root()`, which on first use
   per process sweeps `synergy-*` entries older than 2 h. The age floor is what
   makes it safe under the test thread pool and against a concurrently running
   suite — nothing the current run created can be reaped.
   Regression test: `utils::tests::stale_test_temp_roots_are_swept_and_fresh_ones_are_kept`.
2. Reclaimed 52 GB of regenerable `target/` dirs outside Testnet-v3
   (`OLD-Testnetv2-…`, `.codex-worktrees/*`, `.codex-build/*`) — operator
   approved. `/Volumes/xcode` went 891 MB → 56 GB free.

### Two real shared-state defects fixed (these were the "flakes")

1. **`SYNERGY_EPOCH_VALIDATOR_SETS_FILE` was guarded by four separate mutexes.**
   `consensus_algorithm`, `dual_quorum`, `validator` and `rpc_server` each held
   their own lock over the same **process-global** env var. Each lock serialized
   one file's writers against themselves and against nothing else, so a test
   that merely expected the default path would intermittently resolve another
   test's temp snapshot and fail with
   `epoch validator set file …/synergy-next-block-epoch-validator-set-… does not exist`.
   All four now take `validator::epoch_validator_sets_env_lock()`. Four reader
   tests that resolve the path were given the lock:
   `finalized_synergy_scores_ignore_noncanonical_qc_vote_subsets`,
   `service_activation_replay_promotes_effective_shadow_without_consensus_duties`,
   `service_replay_reconstructs_sequential_validator_7_through_10_activation`,
   `historical_epoch_cluster_rpc_preserves_ledger_snapshots`.

2. **p2p peer sessions and the service-sync coordinator are one entangled
   global, guarded by two locks.** Ending a peer session releases that peer's
   service-sync reservation, so a peer-session-only test could run alongside a
   service-sync test and knock out its reservation — which is why
   `completed_service_apply_does_not_release_next_batch_slot` failed on its very
   first request while passing 5/5 in isolation. Session-12 attributed this to
   socket `WouldBlock`; that was a symptom, not the cause. `SERVICE_SYNC_TEST_LOCK`
   is deleted; `service_sync_test_guard()` now takes the single
   `PEER_SESSION_TEST_LOCK` and callers no longer take it separately (doing both
   would self-deadlock).

### Remaining — one residual flake, ~1 run in 5

`p2p::networking::tests::completed_service_apply_does_not_release_next_batch_slot`
still fails roughly one full-suite run in five, on its very first
`service_sync_request_from_status` call.

Two more appeared once each, only in the slowest run of a batch (38 s vs 29 s):
`consensus::diagnostics::start_shadow_observe_requires_verified_head_match`,
`consensus::dual_quorum::same_height_same_round_double_vote_rejected`.

**Leading hypothesis, NOT yet confirmed — do not treat as established.**
`service_sync_test_peer` stamps the peer with `canonical_genesis_hash()`, and
peer eligibility re-reads it. `diagnostics::with_runtime_root` does
`std::env::remove_var("SYNERGY_GENESIS_FILE")` and resets `SYNERGY_PROJECT_ROOT`
**process-wide**, so a concurrent reader can observe a different canonical
genesis than the one its fixture was built against and reject the peer. Session-9
made that guard panic-safe but the mutation is still global and is synchronized
only against other diagnostics tests.

Evidence against, so far: the test passes 6/6 alone, and 3/3 when run together
with the entire `consensus::diagnostics::` module — so if `with_runtime_root` is
the writer, the window is narrower than that probe reproduces, or the writer is
in a different module. Next step is to bisect by module rather than guess: run
`p2p::networking::tests::completed_service_apply` against one module at a time,
or run the full suite under `--test-threads=1` to confirm the failure is purely
parallel interference.

The general problem is architectural: runtime-root and genesis resolution is
process-global env state, which is fundamentally unsound under a parallel test
harness. The durable fix is to make that resolution injectable in test builds
(thread-local override or an explicit context) rather than adding another lock.

**`gates.runtime_tests_passed` stays `false`** until five consecutive green runs.
It is not honest to flip it at 4/5.

### Not yet touched

`PoSy_Consensus_Parameter_Control_Workbook_v2.2.xlsx` (uploaded 2026-07-27) is
still not ingested into the Phase-3 parameter manifest. Phase 8 (deterministic
deployment) remains the critical path, and it is unblocked now that the runtime
builds and the suite is green.

**Resume command**
```
cd /Volumes/xcode/Synergy-Network-Projects/network-components/01-Testnetv3/runtime/src && \
for i in 1 2 3 4 5; do \
SYNERGY_GENESIS_FILE=/Volumes/xcode/Synergy-Network-Projects/network-components/01-Testnetv3/genesis.testnet-v3.identity-assigned.json \
cargo test --lib 2>&1 | grep -E "^test result:|^    [a-z0-9_]+::"; done
```

---

## Session-12 — BLOCKED: HOST DISK FULL (superseded by session-13)

**The Mac is out of disk space on both volumes. All test runs are now invalid.**

```
/dev/disk3s3s1   228Gi  12Gi used   116Mi free  100%  /
/dev/disk7s1     237Gi 236Gi used   891Mi free  100%  /Volumes/xcode
```

Symptom: suite collapsed 1102/1 → 752/351 with
`Os { code: 28, kind: StorageFull, message: "No space left on device" }`
at `archive_validator.rs:854`. **This is not a code regression** — the last code
change was verified passing in isolation immediately before.

Checked and ruled out: the suite does **not** leak temp dirs
(`ls -d *synergy* *testnet*` in `$TMPDIR` → 0). The 11 GB in
`/var/folders/.../T` is unrelated system temp (1004 `BlobRegistryFiles-*`
from WebKit, etc.).

### To unblock (operator action)

1. `cargo clean` in `runtime/` frees **14 GB** on `/Volumes/xcode`
   (that volume has only 891 MB free). Costs a full rebuild.
2. Free space on `/` (116 MB free) — this is where tests write temp runtime
   roots, so it is the binding constraint for `archive_validator` tests.
   The 11 GB of WebKit blob temp is the obvious candidate but is **not mine to
   delete** — it is unrelated user/system data.

Re-run the suite only after both volumes have headroom.

### Code state when the disk filled — 1102 pass / 1 fail

Two fixes landed this session, each verified passing in isolation:

1. **`post_fork_snapshot_active_set_uses_consensus_fork_registry`** — the last
   *consistent* failure. It asserted a Testnet-v2 FN-DSA fork registry
   *overrides* the genesis active set above height 204216 — retired v2
   behaviour, and it also assumed a five-validator genesis. Replaced with
   `testnet_v3_ignores_legacy_consensus_fork_registry`, which asserts the
   opposite and correct v3 invariant: the legacy registry is **inert**, the
   active set resolves from canonical genesis at every height, no
   `synv1forktest*` leaks in, and the set is six validators. v2 fork behaviour
   was **not** re-enabled. PASSES.

2. **`configured_validator_dial_is_not_status_ready_until_status_exchange`** —
   failing 3 of 4 runs. This was a direct, correct consequence of the
   peer-identity fix: a bare endpoint no longer identifies a peer, so the dialed
   peer was genuinely "unidentified" and pruned as stale. Gave the test an
   explicit `ValidatorVpnTransportConfig` route → `synv…` binding, matching the
   new identity model. PASSES.

Remaining known flakes (each passes 5/5 in isolation; shared-global-state order
dependence, not defects):
`consensus_algorithm::finalized_synergy_scores_ignore_noncanonical_qc_vote_subsets`,
`recovery::apply_plan_writes_rollback_backup`,
`diagnostics::shadow_status_*` group,
`p2p::completed_service_apply_does_not_release_next_batch_slot` (socket WouldBlock).

**Resume command (after freeing disk)**
```
cd /Volumes/xcode/Synergy-Network-Projects/network-components/01-Testnetv3/runtime && \
cargo clean && cd src && \
SYNERGY_GENESIS_FILE=/Volumes/xcode/Synergy-Network-Projects/network-components/01-Testnetv3/genesis.testnet-v3.identity-assigned.json \
cargo test --lib 2>&1 | tail -5
```

---

## Session-11 — suite 1101/2, ONE consistent failure left

```
cd runtime/src && SYNERGY_GENESIS_FILE=<repo>/genesis.testnet-v3.identity-assigned.json cargo test --lib
=> best run 1101 passed / 2 failed. 0 poison.
```
Three consecutive runs: 2, 3, 3 failures. Only **one** fails every run.

### Two real bugs fixed this session

1. **PRODUCTION BUG — `anti_divergence::precommit_verify_checked`.**
   It compared `qc.block_id` against `block.block_id()` (full header digest),
   but `posy.rs:719` builds votes with `block.candidate_id()` — the stable id
   that deliberately excludes round and proposer so TC-authorized carry-forward
   works. The two digests can never be equal for any block with a non-zero round
   or a set proposer, so **this gate rejected every otherwise-valid QC**.
   Now compares `candidate_id()`. Whole `anti_divergence` module passes.

2. **Test fixture — `p2p::test_quorum_certificate` declared
   `cumulative_weight = votes.len()`** (signer *count*) while production verifies
   it as **summed bonded stake**. Every certified block failed with
   `QC cumulative_weight mismatch: computed bonded weight 250000000000000,
   declared 5`. Now sums each signer's `stake_amount`.
   **This one fix cleared 5 p2p block-apply failures (8 → 3).**

   Found by temporarily instrumenting the `Err` arm of
   `verify_network_commit_certificate` with `#[cfg(test)] eprintln!` — the
   boolean return of `apply_block_if_new` was hiding the reason. Instrumentation
   removed afterwards.

### Remaining

**Consistent (1):** `consensus::diagnostics::post_fork_snapshot_active_set_uses_consensus_fork_registry`
Expects `synv1forktest1..6` from a **Testnet-v2 FN-DSA fork registry**, but gets
the real v3 genesis validators. Testnet-v3 forbids legacy fork migration
(`gates.testnet_v3_legacy_fork_migration_forbidden = true`), and
`with_runtime_root` clears `CONSENSUS_FORK_MIGRATION_ENV`. Decide per the P0
brief: isolate the fork fixture as explicitly non-production, assert the v2 fork
registry is *rejected*, or replace with an ML-DSA-65 v3 registry snapshot test.
Do **not** re-enable v2 fork behaviour.

**Order-dependent flakes (2)** — each passes **5/5 in isolation**, so these are
shared-global-state leaks between tests, not defects:
- `consensus_algorithm::finalized_synergy_scores_ignore_noncanonical_qc_vote_subsets`
- `recovery::apply_plan_writes_rollback_backup`
(`p2p::completed_service_apply_does_not_release_next_batch_slot` also flakes on
socket `WouldBlock`.)

**Resume command**
```
cd /Volumes/xcode/Synergy-Network-Projects/network-components/01-Testnetv3/runtime/src && \
cargo test --lib -- consensus::diagnostics::tests::post_fork_snapshot_active_set_uses_consensus_fork_registry --nocapture
```

---

## Session-10 — suite 1095/8, baseline semantics RESOLVED

```
cd runtime/src && SYNERGY_GENESIS_FILE=<repo>/genesis.testnet-v3.identity-assigned.json cargo test --lib
=> 1095 passed / 8 failed / 0 poison
```

**Baseline resolved by operator ruling: 6 total active validators, 5 required
signers.** The two constants are different concepts; neither was stale. See
`launch/BASELINE_VALIDATOR_COUNT_RESOLUTION.md`.
- `recovery::BASELINE_VALIDATOR_COUNT = 6` → initial ACTIVE SET size
- `self_realign::BASELINE_VALIDATOR_COUNT = 5` → REQUIRED SIGNERS
  (= `required_validator_quorum(6)`, so it is derived, not independent)

Session-9's blanket flip to 6 was wrong in direction — it demanded unanimity.
The correct fix was to leave the signer threshold at 5 and give the **fixtures
six validators**:
1. `diagnostics.rs` registry fixture writes 6 validators (was 5).
2. `diagnostics.rs` committed-QC fixture signs with
   `required_validator_quorum(6)` = 5 supporters (was hardcoded 4);
   `cumulative_weight` and `participant_bitmap` updated to match.

That cleared 12 failures on its own (21 → 8).

**Also tried and reverted:** extending `test_quorum_certificate`'s signer list
from 4 to 6 in `p2p/networking.rs` — regressed 1095/8 → 1083/20. The p2p QC
helper's 4-signer set is load-bearing for its own active-set construction; do
not widen it without tracing `ensure_test_qc_validators`.

### Remaining 8

| Test | Symptom |
|---|---|
| `anti_divergence::precommit_rejects_missing_qc_and_accepts_valid_qc` | `RejectInvalid` vs `AcceptCanonical` |
| `diagnostics::post_fork_snapshot_active_set_uses_consensus_fork_registry` | expects `synv1forktest*`, gets real genesis validators |
| `p2p::apply_block_batch_accepts_qc_less_matching_overlap_before_new_blocks` | 0 vs 1 |
| `p2p::apply_block_batch_rolls_back_to_common_ancestor_before_replaying` | 0 vs 2 |
| `p2p::service_batch_matches_validator_chain_result` | 0 vs 2 |
| `p2p::future_blocks_are_cached_and_applied_when_parent_arrives` | `apply_block_if_new` false |
| `p2p::pending_peer_canonical_lock_conflict_after_tip_apply_does_not_self_quarantine` | `apply_block_if_new` false |
| `p2p::configured_validator_dial_is_not_status_ready_until_status_exchange` | `should_prune_stale_peer` |
| `p2p::completed_service_apply_does_not_release_next_batch_slot` | **flaky**: `WouldBlock` on socket — test infra, not consensus |

Six of these are the p2p block-apply group; they share the QC-helper active-set
construction noted above. Start at `ensure_test_qc_validators` in
`p2p/networking.rs`.

**Resume command**
```
cd /Volumes/xcode/Synergy-Network-Projects/network-components/01-Testnetv3/runtime/src && \
SYNERGY_GENESIS_FILE=/Volumes/xcode/Synergy-Network-Projects/network-components/01-Testnetv3/genesis.testnet-v3.identity-assigned.json \
cargo test --lib -- p2p::networking::tests::future_blocks_are_cached_and_applied_when_parent_arrives --nocapture
```

**New input received:** `PoSy_Consensus_Parameter_Control_Workbook_v2.2.xlsx`
(uploaded 2026-07-27) — authoritative consensus parameters for the Phase-3
parameter manifest. Not yet ingested.

---

## Session-9 — poison cascades ZERO, suite 1082/21

```
cd runtime/src && SYNERGY_GENESIS_FILE=<repo>/genesis.testnet-v3.identity-assigned.json cargo test --lib
=> 1082 passed / 21 failed / 0 poison
```
Session-8 was 1077/25 with 1 poison. **All cascades are now gone.**

### Done this session

1. **Poisoned-lock audit (as requested).** `DIAGNOSTICS_TEST_ENV_LOCK` is a
   `Mutex<()>` — it guards **no data**, so `into_inner()` could not resurrect
   corrupted lock state. The real contamination vector was `with_runtime_root`,
   which restored `SYNERGY_PROJECT_ROOT` / `SYNERGY_CONFIG_PATH` /
   `SYNERGY_GENESIS_FILE` / fork-override **only on the success path** — a
   panicking test leaked its overrides into every later test.
   → Added `DiagnosticsTestEnvironmentGuard`, which restores in `Drop` (runs
   during unwind). `with_runtime_root` now uses it. 49 lock sites route through
   `diagnostics_test_env_lock()`.
   → Regression test `panic_while_holding_diagnostics_lock_does_not_contaminate_later_tests`
   deliberately panics while holding the lock and proves the env is restored and
   the lock still usable. **Passes.**
2. **`synergy-node` binary** no longer references the removed
   `recovery::EXPECTED_GENESIS_HASH` constant; uses the genesis-derived fn.

### OPEN — read before touching validator counts

`launch/evidence/toolchain-and-build/BASELINE_VALIDATOR_COUNT_DISCREPANCY.md`

`recovery.rs::BASELINE_VALIDATOR_COUNT = 6` vs
`self_realign::BASELINE_VALIDATOR_COUNT = 5` (diagnostics imports the 5).
Flipping self_realign to 6 was **tried and reverted**: 1078/24 → 1035/69, with
45 new failures spread across 6 modules — evidence the two denote *different
concepts*. Needs governing intent; do not guess.

### Suite depends on `SYNERGY_GENESIS_FILE`

Without it: 1037/66. `config/genesis.json` is the BLOCKED placeholder, so tests
needing a loadable genesis fail. A `#[cfg(test)]` default pointing at the
fixture was tried and **reverted** (1061/42) — `resolve_data_path` resolves
relative to the per-test temp runtime root, which has no fixture. Correct fix is
the fixture-selection work below, not a path default.

### RESUME HERE

Build the deterministic six-validator fixture + `TestnetV3BlockTestContext`
(see session-8 notes). Blocked on the BASELINE discrepancy above being settled,
because the fixture's validator count must match whichever constant governs.

**Resume command**
```
cd /Volumes/xcode/Synergy-Network-Projects/network-components/01-Testnetv3/runtime/src && \
SYNERGY_GENESIS_FILE=/Volumes/xcode/Synergy-Network-Projects/network-components/01-Testnetv3/genesis.testnet-v3.identity-assigned.json \
cargo test --lib 2>&1 | tail -5
```

---

## Session-8 — poison cascade root cause, suite 1077/25

**Suite: 1077 pass / 25 fail (1 poison, 24 primary)** — was 1041/61 (48 poison,
13 primary). Primary count rose because the cascade was hiding 12 real
diagnostics failures; +36 net passing.

Full detail: `launch/evidence/toolchain-and-build/CURRENT_PRIMARY_FAILURES.md`.

**Done this session**
- SXCP relayer domain **settled**: FN-DSA-1024 retained, documented in
  `CRYPTOGRAPHIC_IDENTITY_PROFILE.md`. No longer an open question.
- Poison root cause: one lock (`DIAGNOSTICS_TEST_ENV_LOCK`) poisoned by a single
  panicking test produced 44 of 45 cascades. 47 sites now recover.
- Diagnostics genesis fixtures moved off the BLOCKED placeholder onto the v3
  test fixture; `expected_genesis_hash()` now reads the runtime root under test
  instead of the process-wide lazy_static (which returned `""`).
- 3 stale quorum expectations corrected to governed `(n*2)/3+1`; one had
  asserted a 6-validator cluster could finalize on 4 signers.
- Diagnostics consensus fixtures → ML-DSA-65.

**RESUME HERE — single highest-value action**

18 of the 24 remaining failures share one cause:
```
active validator registry has 5 canonical validator(s), expected 6
  (recovery.rs:2531, BASELINE_VALIDATOR_COUNT)
```
Fixtures invent `synv11testvalidator{0..4}` — five addresses **not in canonical
genesis** — while `recovery.rs:2525` also requires each active validator's
consensus key to be present in canonical genesis. The tests must *sign* as those
validators, so editing the list alone cannot work.

Build a purpose-built **six-test-validator fixture genesis** whose ML-DSA-65
private keys the harness retains (do not copy the production candidate), then
the `TestnetV3BlockTestContext` builder over it: validator-set root, 1 cluster
with all six, bonded weights, height context, parent state root, QC. Keep it
production-rejected via `genesis.rs::reject_test_fixture_genesis`.

**Resume command**
```
cd /Volumes/xcode/Synergy-Network-Projects/network-components/01-Testnetv3/runtime/src && \
SYNERGY_GENESIS_FILE=/Volumes/xcode/Synergy-Network-Projects/network-components/01-Testnetv3/genesis.testnet-v3.identity-assigned.json \
cargo test --lib 2>&1 | tail -5
```

**Modified, uncommitted:** `runtime/src/{transaction,wallet,broadcast,recovery,role_runtime,genesis,block,consensus_state,dag,token}.rs`,
`runtime/src/consensus/{diagnostics,self_realign,dual_quorum,consensus_algorithm,validator_keys,tests}.rs`,
`runtime/src/p2p/networking.rs`, `runtime/src/rpc/rpc_server.rs`, `runtime/src/sxcp/mod.rs`,
`runtime/config/genesis.testnet-v3.test-fixture.json`, `genesis-contracts/contracts/TeamVesting.synq`,
`scripts/generate-validator-vpn.py`, `scripts/validate-validator-vpn.py`, `launch/*`.

---

## Session-7 — peer identity + v2 chain-hash purge

1. **Positional-zip identity inference REMOVED.**
   `p2p/networking.rs::configured_validator_public_address_map` no longer infers
   a node identity from the *order* of dial targets. An endpoint resolves to a
   `synv…` only through an explicit binding (a `synv…` dial target,
   `network.validator_vpn_transports`, or an authenticated learned transport).
   An endpoint claimed by two identities is **dropped as ambiguous** — the
   Val4 / archive-validator `73.79.66.255:5622` case. New tests:
   `validator_routes_resolve_only_through_explicit_node_identity_bindings`,
   `shared_public_endpoint_cannot_impersonate_another_node_identity`
   (covers route-only, explicit binding, ambiguity, endpoint change, active-set
   scoping, port reuse).

2. **Testnet-v2 genesis hash purged from PRODUCTION code.** It was hardcoded in
   five places, not just tests:
   `consensus_state.rs::TESTNET_RECOVERY_GENESIS_HASH`,
   `self_realign.rs` / `recovery.rs` / `diagnostics.rs::EXPECTED_GENESIS_HASH`,
   and — worst — `rpc_server.rs::current_genesis_hash()` used it as a
   **fallback**, so a v3 node advertised the **v2 chain identity** whenever the
   canonical genesis failed to load (exactly what the BLOCKED placeholder
   causes). All now derive from `canonical_genesis()`; the RPC fallback fails
   closed. The only remaining literal is an `assert_ne!` guard.

3. **Deterministic test-only genesis fixture.**
   `runtime/config/genesis.testnet-v3.test-fixture.json` (chain 1266, 6
   validators), marked `TEST_FIXTURE_NOT_FOR_PRODUCTION`;
   `genesis.rs::reject_test_fixture_genesis` refuses it outside `cfg(test)`.
   Tests no longer depend on the BLOCKED placeholder or the unsigned candidate.

4. **RPC domain separation fixed.** `normalize_signature_algorithm` silently
   mapped FN-DSA labels onto a valid algorithm; it now rejects FN-DSA (address
   domain) and ML-DSA-65 (consensus domain) with distinct errors.

5. **Suite: 1041 pass / 61 fail** (48 poison cascades + 13 primary). Remaining
   primaries are now a *different* set — cluster-count/quorum RPC assertions and
   block-apply tests that need the fixture's 6-validator cluster shape, plus
   `anti_divergence`, `sxcp::duplicate_support_is_rejected`,
   `create_snapshot_requires_majority_branch_proof`. None involve v2 identity.

---

## Session-6

**Correct source paths** (earlier sessions used the wrong ones):
- identities: `01-Testnetv3/testnet-v3-identity-files/` (NOT
  `synergy-testnet-data-files/testnet-keyfiles`, which is v2)
- contracts: `01-Testnetv3/genesis-contracts/` (`.synq`, never `.sol`)
- credentials: workbook sheets `Node Credentials`, `Testnet-v3 Identities`,
  `Testnet-v3 Public Keys` (v3 node addresses use `synv1`/`synv2`/`synv5`)

**DONE — validator VPN package (complete).**
25 X25519 keypairs: 21 validators (`VNS-A02..A22`), 3 relayers
(`NODE-RELAYER-01..03`), 1 coordinator. Governed plan preserved —
`10.70.0.0/16`, coordinator `10.70.0.1`, validators `10.70.10.1-.21`, relayers
`10.70.20.1-.3`. Nothing invented, no retained assignment changed. Full-mesh:
validators 7–21 pre-provisioned with no endpoint (roaming) so later activation
needs **no edit to deployed configs**. Per-node material written into each
identity folder at `…/wireguard/` (`0700` dir, `0600` private key + conf).
Generator `scripts/generate-validator-vpn.py`; validator
`scripts/validate-validator-vpn.py` → **0 failures**, 6 live checks skipped.
Docs: `VALIDATOR_VPN_ARCHITECTURE.md`, `VALIDATOR_VPN_ASSIGNMENT_REPORT.md`,
`VALIDATOR_VPN_SECURITY_REPORT.md`, `validator-vpn-public-registry.json`,
`validator-vpn-checksums.json`.

**DONE — transaction domain → ML-DSA-87.** User/account transactions and
governance now require ML-DSA-87; consensus stays ML-DSA-65. ML-DSA-65 is
admissible on the transaction path **only** for a structurally-identified Aegis
carrier envelope. Migrated `transaction.rs`, `wallet.rs`, `rpc_server.rs`,
`token.rs`, `dag.rs`, `sxcp/mod.rs`, `broadcast.rs`, sts/benchmark bins.
Three cross-domain negative tests added. `cargo test --lib transaction::` = 17/17.
Both crypto docs amended/superseded.

**OPEN — Phase 1 not finished.** Suite is 1031 pass / 70 fail (48 poison
cascades + ~22 primary). Remaining primaries, unchanged in nature:
1. **Peer identity still endpoint-keyed.**
   `p2p/networking.rs::configured_validator_public_address_map` infers identity
   by *positional zip* of dials against validator addresses (~L1596-1676).
   Since Val4 and the Archive Validator share `73.79.66.255:5622`, this is
   ambiguous by construction. Fix: delete positional inference; bind endpoints
   to `synv…` explicitly via `ValidatorVpnTransportConfig` sourced from the
   topology registry — the VPN registry generated this session is the input.
2. **v2 genesis hash `f79011f2…` in `rpc_server.rs:10913`** — needs a
   deterministic test-only v3 fixture (chain 1266, 6 validators, test keys,
   unloadable in production), not the production candidate hash.
3. A handful of cluster/quorum RPC assertions pending that fixture.

## Session-5 correction + launch-critical findings (read first)

1. **RETRACTED: retained IPs are not stale.** Session 4 wrongly classified
   `73.79.66.255` / `194.163.183.166` as inherited v2 bindings. The node
   credentials workbook shows they are current assignments (Val4 + Archive
   Validator share `73.79.66.255`; Val5 = `194.163.183.166`). Retained
   machines/IPs are **not** launch blockers. Corrected evidence:
   `launch/evidence/toolchain-and-build/INHERITED_V2_BINDINGS_IN_RUNTIME_TESTS.md`.
2. **Root defect located (the actual Phase-1 blocker).**
   `p2p/networking.rs::configured_validator_public_address_map` infers node
   identity by **positional zip** of dial endpoints against validator
   addresses (~L1596-1676). Because Val4 and Archive Validator share
   `73.79.66.255:5622`, endpoint-keyed identity is ambiguous **by
   construction** — the failing assertions are the runtime telling the truth.
   Correct fix: delete positional inference; require explicit
   `ValidatorVpnTransportConfig { validator_address, dial_address }` bindings
   sourced from the signed topology registry. Endpoints become route metadata
   only; peers are keyed by authenticated `synv…`.
3. **Only one genuinely stale chain binding remains:** the Testnet-v2 genesis
   hash `f79011f2…` asserted in `rpc_server.rs:10913`. It needs a
   deterministic **test-only** v3 fixture — do not bake the production
   candidate hash into broad unit tests.
4. **VPN scope conflict — needs an operator decision, do not guess.**
   Requested: 21 validators + 3 relayers + 1 coordinator (25 participants).
   Evidence (workbook + deployed `wg0.conf`): **6 validators, 2 relayers, no
   coordinator**, full-mesh WireGuard on `10.69.0.0/24`, DNS endpoints
   `genesisvalN.synergynode.xyz:51820`; **Val6 has no assigned VPN IP**.
   Building the requested set would mean inventing 15 VPN IPs, a third
   relayer, and a coordinator hub that would replace the existing mesh —
   all forbidden by "preserve the existing addressing plan / do not redesign".
5. **Genesis signing is custody-gated.** Keyfiles are
   `ml-kem-1024-hybrid+aes-256-gcm` with `argon2id` KDF — decryption for the
   signing ceremony requires the custody passphrase(s). Not obtainable in-session.

---

# Session 4 and earlier

## Session-4 results (first real test execution; read this first)

Ran on the operator's Mac (rustc/cargo 1.97.1). Everything below is executed,
not inferred; evidence in `launch/evidence/toolchain-and-build/`.

1. **Compiler chain PASS.** `runtime/synq-language` `cli` builds clean (the
   session-3 "1 pre-existing compile error" does not reproduce; it was an
   artifact of the sandbox disk exhaustion). All **8** checked-in genesis
   contracts check PASS with bytecode/abi/manifest hashes
   (`genesis-8-check.txt`). `SaleClaim.synq` PASS.
2. **`TeamVesting.synq` FIXED and PASS.** It failed to parse: `while` loops are
   not in the SynQ grammar. Rewrote the constructor's two accumulation loops as
   `for (i in 0..teamCount)` / `for (j in teamCount..beneficiaryCount)`,
   matching the form already used in `RewardDistributor.synq`. Now compiles —
   `bytecode_hash=6a4bf755a81615aed240c51f6842aa1bdc6ca8ef16ffa75ce7a510453f1b7f4c`.
3. **Deterministic deployment PASS.** `aivm-core` **42/42**, including
   `all_eight_genesis_contracts_deploy_call_restart_and_replay_deterministically`.
4. **`cargo check --workspace` PASS** (0 errors; warnings only) — the check the
   sandbox could never finish.
5. **Full runtime suite executed for the first time: 1039 pass / 59 fail.**
   Of the 59, 45 are `PoisonError` cascades (one panicking test poisons a shared
   test mutex and fails every later test that takes it) — they clear when the
   primaries do. The **14 primary failures share one root cause**, below.
6. **NEW BLOCKER — inherited Testnet-v2 identity is still hardcoded in runtime
   tests.** `rpc_server.rs` asserts the **v2** genesis hash
   `f79011f2aaddd…` (found only under `launch/reference/testnet-v2/`; the v3
   candidate is `ac5186cb4a95…`), and `networking.rs` asserts the **v2** node
   IPs `73.79.66.255` / `194.163.183.166` (zero occurrences in the v3 genesis).
   Session-2's "structural PASS" covered validator *consensus keys* only, so
   the checker never looked for these. **`gates.inherited_identity_bindings_removed`
   stays `false`; `component_focused_tests_passed` downgraded `true → false`.**
   These were deliberately NOT forced green: the v3 genesis hash is not yet
   signed (`integrity.signed_by` empty, `runtime/config/genesis.json` is still
   the BLOCKED placeholder stub), and **the v3 genesis assigns no validator P2P
   endpoints at all**, so there is nothing legitimate to rebind the IPs to.
   Full detail + close-out steps:
   `launch/evidence/toolchain-and-build/INHERITED_V2_BINDINGS_IN_RUNTIME_TESTS.md`.
7. **Legacy v2 test removal (operator-directed).** Removed 10 tests asserting
   v2 behaviour (5 legacy/post-fork QC tests + 1 legacy committed-QC test in
   `recovery.rs`; 4 FN-DSA/checkpoint-fork tests in `validator_keys.rs`).
   Upgraded stale FN-DSA fixtures to ML-DSA-65 across `recovery.rs`,
   `dual_quorum.rs`, `consensus_algorithm.rs`, `networking.rs`, `tests.rs`
   (negative-path FN-DSA fixtures intentionally preserved).
8. **Product fixes made while unblocking the suite** (not test-only):
   - `block.rs` resolved block signature algorithms through the *FN-DSA-only*
     fork-migration parser, so ML-DSA-65 blocks were rejected outright. Now
     routes through `validator_keys::block_signature_algorithm` (ML-DSA first).
   - `recovery.rs::parse_algorithm` had the same defect — ML-DSA-65 labels were
     rejected as "unsupported consensus key algorithm 'mldsa65'".
   - `transaction.rs` accepted **only** `fndsa` for signing/validation, while
     `CRYPTOGRAPHIC_IDENTITY_PROFILE.md` governs transaction signing as
     ML-DSA-65 — the Aegis carrier path was failing on its own profile. Now
     accepts ML-DSA-65 (FN-DSA retained as transitional).
   - `recovery.rs::verify_legacy_qc` enforced `cumulative_weight == unique
     signer count` while live consensus
     (`verify_commit_certificate_for_block_static`) enforces
     `cumulative_weight == summed bonded stake`. Mutually exclusive for any
     stake ≠ 1, and the recovery verifier has no stake data. Removed the stale
     v2 rule; the authoritative bonded-weight check still runs over the same QC.
9. **NEXT SESSION:** finalize+sign the v3 genesis and assign validator P2P
   endpoints, then rebind the 14 tests and re-run; extend
   `scripts/check-retired-v2-bindings.py` to also flag the v2 genesis hash and
   v2 node IPs. Untouched: crypto conformance tests, parameter manifest,
   ingress-keygen tooling fixture.

---

## Session-3 results (toolchain + compiler)

1. **Toolchain root cause RESOLVED.** The prior failures were caused by the
   sandbox reaping background processes the moment the launching shell call
   returns (proven with a persistence probe) — the rustup install kept dying
   mid-download. Foreground re-runs of the installer resume cleanly:
   rustc/cargo **1.97.1 aarch64-unknown-linux-gnu** installed and working.
   No repository-pinned `rust-toolchain(.toml)` exists (checked runtime/);
   stable is the operative toolchain — pin one in-repo if a specific version
   is governed. Constraint: every foreground command is capped at 45 s, so
   any single compilation unit longer than that (librocksdb-sys C++ build)
   cannot complete in this sandbox; full-runtime `cargo check` needs a real
   machine or a sandbox with longer command windows.
2. **Formatting/parse validation PASS** on all four Rust files edited for the
   v2-binding cleanup (`rustfmt --check`, evidence:
   `launch/evidence/toolchain-and-build/rustfmt-*.txt`).
3. **Compiler discovery (important):** `runtime/SynQ` builds clean
   (`cargo check -p synq-compiler` 38 s; `synq-cli` binary works) but its
   grammar REJECTS the checked-in genesis contract sources (fails on
   `field: Type public;` — including the existing `Treasury.synq`). It is NOT
   the toolchain that produced the `synq-stateful-ir-v2` artifacts. The
   canonical toolchain per `genesis-contracts/README.md` is
   **`runtime/synq-language`** (`cargo run -p cli -- check <source>`), and the
   real deployment-evidence test is
   `aivm-core::all_eight_genesis_contracts_deploy_call_restart_and_replay_deterministically`.
   The synq-language `cli` build hit 1 pre-existing compile error (detail not
   captured — the sandbox VM crashed with I/O errors immediately after;
   likely disk exhaustion from /tmp cargo target dirs on a 9.6 GB root).
   NEXT SESSION: clean /tmp targets, rebuild `synq-language` cli, capture the
   error, fix or report it, then `check` all 8 existing sources + compile
   `TeamVesting.synq` and `SaleClaim.synq`, then run the aivm-core
   deterministic deployment test (this is the Phase 6/7/8 critical path).
4. Sandbox VM died before: synq-language cli error capture, cross-domain
   crypto conformance tests, chunked runtime check, ingress-keygen tooling
   fixture. All remain open; nothing was promoted without evidence.

Read `launch/CLAUDE_TAKEOVER_AUDIT.md` first. Canonical genesis:
`genesis.testnet-v3.identity-assigned.json`. CANDIDATE pair (independently
recomputed and proven this session): genesis hash `ac5186cb…008407`, magic
`845e8eca`. Never regenerate existing identities/wallets/addresses.

## Phase status

- **Phase 1 (build validation): PARTIAL.** All Python gates PASS:
  `check-retired-v2-bindings.py` (0 active violations),
  `validate-identity-records.py` (54/4/0), component parity (all groups PASS;
  4 known operational BLOCKED). Rust toolchain download did not complete in
  the sandbox — `cargo fmt/check/test` still outstanding; until they pass,
  `inherited_identity_bindings_removed` stays false. Files needing compile
  proof: `runtime/src/p2p/networking.rs` (v2 shim removed),
  `node-control-panel/control-service/src/{innernet,validator_vpn,testnet}.rs`.
- **Phase 2 (hash provenance): DONE.** `launch/GENESIS_HASH_PROVENANCE_REPORT.md`.
  Recomputed blake3-256 over the canonicalization-spec sections → exact match
  `ac5186cb…`; magic derivation reproduces `845e8eca`. The `601263ff…`/
  `10583b30` pair exists nowhere and is stale summary residue. Both labeled
  CANDIDATE until parameter root, receipts, AIVM root, ingress root bind.
- **Phase 3 (crypto profile): DONE.** `launch/CRYPTOGRAPHIC_PROFILE_RESOLUTION.md`.
  ML-DSA-65 ruled operative (intentional supersession per Security Spec v7);
  PoSy §19 amendment paragraph inserted; workbook SET-0018 updated,
  Unresolved CRYPTO-001 marked resolved, Change Log row appended. Address
  derivation documented exactly: Bech32m(prefix, SHA3-256(FN-DSA-1024 pk)).
  Negative cross-domain tests listed in §7 — add with toolchain.
- **Phase 4 (ETDAG ingress): BLOCKED-external, spec-confirmed.** ML-KEM-1024
  required (`etdag.rs::IngressKemPublicKey`); no records exist; ML-KEM-768
  entropy keys must not be relabeled. Generation must use the identity
  engine + custody workflow (secret-owning machine). Registry binding plan in
  `launch/CRYPTOGRAPHIC_IDENTITY_PROFILE.md`.
- **Phase 5 (540M reconciliation): DONE.**
  `launch/TEAM_SUPPORT_ALLOCATION_RECONCILIATION.md`: TEM-A01 340M (funds the
  vesting contract) + TEM-A02 200M unassigned reserve = 540M; register sums
  to the 12B cap.
- **Phase 6 (TeamVesting): source ready, compile pending.**
  `genesis-contracts/contracts/TeamVesting.synq`. Do not bind hashes until
  compiled + tested + address reproduced.
- **Phase 7 (sale_claim): specification RECOVERED, source drafted.**
  Governing sources found: `synergy-website/docs/token-offering/
  UNIFIED_PRESALE_INFRASTRUCTURE_SPEC.md`, `SNRGClaimVoucherSoulbound.sol`,
  presale backend. Requirements: `launch/SALE_CLAIM_REQUIREMENTS.md`.
  Draft: `genesis-contracts/contracts/SaleClaim.synq` (threshold-attested
  ReceiptRedeemed settlement; fingerprint + tokenId replay protection;
  voucher-vesting claims; refund/settlement modes; no Solidity in package).
  Open input: approved attestor set + threshold (DAO/custody) as constructor
  args. Compile/tests pending toolchain; host capability
  `hostVerifyThresholdAttestation` must be declared in host-capabilities.
- **Phase 8 (deterministic deployment): NOT STARTED** — needs built runtime +
  compiled contracts. Must reproduce all ten existing addresses; stop on any
  mismatch; three-run determinism; then re-bind roots and recompute
  hash/magic.
- **Phase 9 (ceremony): tooling DONE, fixture PASS, operator step BLOCKED**
  (custody passphrases). 16 challenges at `launch/ceremony/challenges.json`.
  NOTE: challenges embed the CANDIDATE genesis hash — regenerate challenges
  after final genesis binding (Phase 8) so signatures bind the final hash.
- **Phase 10: not started** (typed-coordinator wiring, parameter manifest
  finalization, wallet sealing, distributed qualification, Security v7,
  release, soak).

## Repo hygiene note

`runtime/testnet-allocation-manifest.json` was regenerated as a v3 document
from the genesis register (the v2 original is quarantined at
`launch/reference/testnet-v2/`); parity gate depends on this path. All
changes remain uncommitted for review; quarantines used `git mv`.
