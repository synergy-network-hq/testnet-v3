# Testnet-v3 consensus parameter governance decision package

Date: 2026-07-28  
Status: **SUPERSEDED — DO NOT USE AS A PARAMETER SOURCE**

This pre-decision package was superseded on 2026-07-28 by the explicit
Testnet-v3 operator approval recorded in
`TESTNET_V3_CONSENSUS_PARAMETER_RELEASE_DECISION.md`, Decision ID
`TV3-POSY-PARAMS-2026-07-28-01`. The approved values are 1,000 epoch slots,
1,500 ms proposal/prevote/precommit timeouts, and a 10,000 ms maximum-round
timeout. The 3,600-slot and 30,000 ms values discussed below are deferred
historical proposals and are not authorized launch values.

This package is derived from the current-code reconciliation of all 844 rows in
`PoSy_Consensus_Parameter_Control_Workbook_v2.2.xlsx`. It does not authorize a
parameter manifest and must not be converted to `status: FINALIZED` without an
explicit approval record.

## Already resolved

| Item | Governing Testnet-v3 value | Evidence |
|---|---|---|
| Chain / network | `1266` / `synergy-testnet-v3` | runtime config and Genesis |
| PoSy protocol | `posy/2.2` | `runtime/src/synergy_types.rs` |
| Validator consensus signature | `mldsa65` | `CRYPTOGRAPHIC_PROFILE_RESOLUTION.md`; Security v7 |
| Account / SynQ signature | `mldsa87` | cryptographic-profile amendment |
| Count quorum | strict `3*s > 2*n`; five of six | typed PoSy and ETDAG tests |
| Weight quorum | strict `3*w_s > 2*w_total` | typed PoSy and ETDAG tests |
| Cluster schedule | `dynamic-v3-floor7` | typed bootstrap and topology tests |
| ETDAG profile | `POSY-ETDAG-v2.2-rc1`; H+3 | `runtime/src/etdag.rs` |
| ETDAG crypto | `mlkem1024` + `aes256gcm` | parameter loader and ETDAG tests |
| Initial ETDAG values | `n=6`, `q=5`, `t_dec=2` | parameter loader and ETDAG tests |
| Quorum reduction | forbidden | parameter loader and typed tests |
| Initial stake floor | `50,000,000,000,000` nwei | Genesis and typed protocol default |
| Target block time | `2,000` ms | Genesis and runtime config |

## Decisions that cannot be inferred

### D1 — Epoch length

- Workbook proposal: **3,600 slots** (approximately two hours at 2 seconds).
- Active configs, validator code, RPC code, and candidate Genesis: **1,000**.
- Parameter-loader test fixture: **7,200**.
- Recommendation: **3,600**, because it is the current workbook proposal and
  removes the known 1,000-block divergence. This requires changing all competing
  constants/configs/Genesis values atomically.

### D2 — Proposal timeout

- Workbook describes a **450 ms cumulative healthy-path proposal deadline**.
- Candidate Genesis: **1,000 ms**.
- Typed `ProtocolConfig` default and parameter-loader fixture: **1,500 ms**.
- Recommendation: **1,500 ms** for the manifest field until the 10,000-block
  production-cryptography soak justifies a lower value. The workbook's 450 ms
  cumulative target should remain a performance target, not be silently mapped
  to a differently scoped timeout field.

### D3 — Prevote and precommit timeouts

- Workbook describes **1,850 ms cumulative** for VC/finality/QC formation.
- Candidate Genesis validation value: **1,000 ms**.
- Typed `ProtocolConfig` defaults: **1,500 ms** each.
- Recommendation: **1,500 ms prevote** and **1,500 ms precommit**, pending soak
  evidence.

### D4 — Maximum round timeout

- Workbook proposal: **30,000 ms**.
- Typed `ProtocolConfig` default and loader fixture: **10,000 ms**.
- Recommendation: **30,000 ms** to match the latest safety workbook, with the
  acknowledgement that it changes current code and must be covered by timing
  tests.

### D5 — Governance approval identifier

No governance approval ID exists. The finalized manifest loader rejects an
empty ID. The approving authority must issue an immutable identifier that
references the exact approved values and this reconciliation evidence.

## Proposed exact manifest values after approval

The following values are ready to encode once D1–D5 are authorized:

| Field | Proposed value |
|---|---|
| `schema_version` | `1` |
| `release_id` | `testnet-v3` |
| `status` | `FINALIZED` only after approval |
| `governance_approval_id` | D5 |
| `chain_id` | `1266` |
| `network_id` | `synergy-testnet-v3` |
| `protocol_version` | `posy/2.2` |
| `epoch_length_slots` | D1 |
| `target_block_time_ms` | `2000` |
| `count_quorum_rule` | `strict_more_than_two_thirds` |
| `weight_quorum_rule` | `strict_more_than_two_thirds` |
| `cluster_schedule_version` | `dynamic-v3-floor7` |
| `consensus_signature_algorithm` | `mldsa65` |
| `ingress_kem_algorithm` | `mlkem1024` |
| `payload_encryption_algorithm` | `aes256gcm` |
| `encrypted_transaction_target_offset` | `3` |
| `initial_cluster_validator_count` | `6` |
| `initial_availability_quorum` | `5` |
| `initial_decryption_threshold` | `2` |
| `shadow_epochs_required` | `1` |
| `activation_delay_epochs` | `1` |
| `minimum_shadow_blocks` | `100` |
| `max_finalized_lag_blocks` | `2` |
| `required_vote_match_rate_ppm` | `995000` |
| `required_validator_stake_nwei` | `50000000000000` |
| `allow_over_staking` | `true` |
| `anti_divergence_enabled` | `true` |
| `auto_reconciliation_enabled` | `true` |
| `self_quarantine_on_local_divergence` | `true` |
| `peer_quarantine_on_invalid_finality_claim` | `true` |
| `require_quorum_peer_confirmation_for_reconciliation` | `true` |
| `min_canonical_sync_peers` | `4` |
| `max_rejoin_lag_blocks` | `0` |
| `rejoin_only_at_round_boundary` | `true` |
| `allow_quorum_reduction` | `false` |
| `proposal_timeout_ms` | D2 |
| `prevote_timeout_ms` | D3 |
| `precommit_timeout_ms` | D3 |
| `max_round_timeout_ms` | D4 |

## Required authorization statement

An approving operator may authorize the proposed values with an explicit record
equivalent to:

> Approve D1=3600, D2=1500, D3=1500/1500, D4=30000 for the Testnet-v3
> consensus parameter manifest, and assign governance approval ID `<ID>`.

After that statement exists, implementation may emit the canonical
deny-unknown-fields JSON, compute its SHA3-512 root, bind both bytes and root
into finalized Genesis, replace competing constants, and enable the typed
coordinator startup path only when all bindings validate.
