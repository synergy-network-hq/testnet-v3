# BASELINE_VALIDATOR_COUNT — RESOLVED 2026-07-27

Operator ruling: **6 total active validators, 5 required signers.** The two
constants describe *different concepts*; neither was stale.

| Constant | Value | Concept |
|---|---|---|
| `recovery.rs::BASELINE_VALIDATOR_COUNT` | 6 | **initial active validator set size** |
| `self_realign.rs::BASELINE_VALIDATOR_COUNT` | 5 | **required supporters / signers** |

Derivation check: `required_validator_quorum(6) = (6*2)/3 + 1 = 5`. The
self-realignment value therefore equals the strict count quorum over the frozen
six-validator eligible set — it is a *derived* threshold, not an independent
population.

## Why the earlier blanket change was wrong

Setting `self_realign` to 6 (session 9) changed the **signer requirement** from
5 to 6, i.e. demanded unanimity. That regressed the suite 1078/24 → 1035/69.
Reverted. The correct correction was the opposite direction: leave the signer
threshold at 5 and make the **fixtures** carry six validators.

## Fixes applied under this ruling

1. `consensus/diagnostics.rs` validator-registry fixture now writes
   `crate::recovery::BASELINE_VALIDATOR_COUNT` (6) validators instead of 5.
2. The same file's committed-QC fixture now signs with
   `required_validator_quorum(BASELINE_VALIDATOR_COUNT)` = **5** supporters
   (was a hardcoded 4), with `cumulative_weight` and `participant_bitmap`
   updated to match.

Result: **1082 → 1095 passing, 21 → 8 failing.** Twelve failures cleared by the
six-validator / five-signer correction alone.

## Recommended follow-up (not blocking launch)

Rename to remove the ambiguity, without changing values:
- `recovery::BASELINE_VALIDATOR_COUNT` → `INITIAL_ACTIVE_VALIDATOR_COUNT`
- `self_realign::BASELINE_VALIDATOR_COUNT` → `SELF_REALIGNMENT_REQUIRED_SIGNERS`,
  ideally derived via `required_validator_quorum(INITIAL_ACTIVE_VALIDATOR_COUNT)`
  rather than a literal 5.

Deferred deliberately: the rename touches 21 call sites across 4 modules and is
cosmetic relative to launch. The semantics are now documented and correct.
