# Current primary runtime failures — 2026-07-27 (session 8)

Source of truth: `run-latest.txt` (parallel) and `serial-current.txt` (serial).
Command:
```
cd runtime/src && SYNERGY_GENESIS_FILE=<repo>/genesis.testnet-v3.identity-assigned.json \
  cargo test --lib
```

## Movement this session

| | pass | fail | poison | primary |
|---|---|---|---|---|
| start | 1041 | 61 | 48 | 13 |
| now | **1077** | **25** | **1** | **24** |

Primary count *rose* 9 → 24 because the poison cascade was hiding 12 real
diagnostics failures. The suite now reports honestly; +36 net passing.

## Fixed this session

1. **SXCP relayer domain settled (operator ruling).** FN-DSA-1024 retained as a
   distinct domain. A prior bulk edit had switched relayer keys to ML-DSA-87
   while fixtures still declared `fndsa`. Fixture realigned. 4/4 SXCP pass.
2. **Three stale quorum expectations** corrected to governed
   `(n*2)/3 + 1` over the **frozen eligible set**:
   - 6-validator cluster `4 → 5`, and `can_finalize true → false`,
     `degraded → halted_safely`. The old expectation asserted a 6-validator
     cluster could finalize on 4 signers — a quorum-**lowering** bug.
   - two 5-validator clusters `3 → 4`.
   Production formulas were **not** changed (verified correct).
3. **Poison-cascade root cause.** 44 of 45 cascades came from one lock,
   `DIAGNOSTICS_TEST_ENV_LOCK`, poisoned by a single panicking test. 47 lock
   sites now `unwrap_or_else(|p| p.into_inner())` — failures are still reported,
   they just no longer convert 44 unrelated tests into false failures.
4. **Diagnostics genesis fixture.** `install_test_genesis` /
   `install_mutated_test_genesis` copied the BLOCKED placeholder
   (`config/genesis.json`, no `header.timestamp`, no validators), so every
   snapshot path failed with "genesis unavailable" before reaching the behaviour
   under test. Both now install `config/genesis.testnet-v3.test-fixture.json`.
5. **`diagnostics::expected_genesis_hash()`** read the process-wide
   `canonical_genesis()` lazy_static, which caches whichever genesis the first
   caller in the process loaded — returning `""` and failing every comparison.
   It now reads the runtime root the diagnostic is operating on
   (`load_canonical_genesis_for_runtime()`), falling back to the process
   canonical genesis.
6. **Diagnostics consensus fixtures** moved to ML-DSA-65 (consensus domain):
   1 keypair + 2 `ml-dsa-65:` prefixes.

## Remaining 24 — root cause classification

### A. Missing Testnet-v3 block/validator context (18)

`consensus::diagnostics::*` (12), `p2p::networking::*` (6).

Blocking error, verified:
`active validator registry has 5 canonical validator(s), expected 6`
(`recovery.rs:2531`, `BASELINE_VALIDATOR_COUNT`).

These fixtures invent `synv11testvalidator{0..4}` — five addresses that are
**not in canonical genesis**, while the v3 fixture genesis defines six real
validators. `recovery.rs:2525` additionally requires each active validator's
consensus public key to be present in canonical genesis.

**This cannot be fixed by editing the fixture's validator list alone**: the
tests must *sign* as those validators, and the genesis holds only public keys.

**Correct fix — the canonical builder specified in the P0 brief:** generate a
purpose-built test-fixture genesis containing six *test* validators whose
ML-DSA-65 private keys the harness retains, instead of copying the production
candidate. Then `TestnetV3BlockTestContext` derives validator set root, cluster
map (1 cluster, all six), bonded weights, height context, parent state root and
QC from that fixture. Fixture stays production-rejected via
`genesis.rs::reject_test_fixture_genesis`.

### B. Incorrect test expectation (2)
- `rpc::historical_epoch_cluster_rpc_preserves_ledger_snapshots` — one further
  stale cluster/quorum literal.
- `consensus_algorithm::pre_activation_current_epoch_restart_repairs_the_v19_0_45_cluster_seed`
  — pre-activation v19.0.45 seed expectation.

### C. Not yet diagnosed (4)
- `anti_divergence::precommit_rejects_missing_qc_and_accepts_valid_qc`
  (`RejectInvalid` vs `AcceptCanonical`)
- `role_runtime::active_validator_starts_consensus`
- `rpc::qrpc_status_uses_last_known_good_snapshot_when_consensus_chain_lock_is_busy`
- `validator::service_replay_reconstructs_sequential_validator_7_through_10_activation`

## Next action

Build the six-test-validator fixture genesis + `TestnetV3BlockTestContext`
builder. That single change is expected to clear group A (18 of 24).
