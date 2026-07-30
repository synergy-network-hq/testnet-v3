# Typed finality observer defect analysis — 2026-07-30

Resolves Blocker 1 and Blocker 2 of
`launch/CODEX_TO_CLAUDE_TESTNET_V3_HANDOFF_2026-07-30.md` §8.

Both defects were traced from source and confirmed against live node state. No
consensus verification was bypassed or weakened, no identity or genesis artifact
was regenerated, and the healthy six-validator set was not touched.

---

## 1. Live state at diagnosis

Sampled 2026-07-30 12:30 UTC via workbook-backed `ssh synergy-*` aliases.

All six validators had advanced past the 11:53 UTC handoff sample and were
**fully converged**, not merely close:

| Alias | Store version | Records | Height | Block ID |
|---|---:|---:|---:|---|
| `synergy-val1` | 3 | 90 | 90 | `d0191e143cdb6525f6964a27ca62a80ebc2ab6358043c980e2b05f807928dfe0` |
| `synergy-val2` | 3 | 90 | 90 | `d0191e143cdb6525f6964a27ca62a80ebc2ab6358043c980e2b05f807928dfe0` |
| `synergy-val3` | 3 | 90 | 90 | `d0191e143cdb6525f6964a27ca62a80ebc2ab6358043c980e2b05f807928dfe0` |
| `synergy-val4` | 3 | 90 | 90 | `d0191e143cdb6525f6964a27ca62a80ebc2ab6358043c980e2b05f807928dfe0` |
| `synergy-val5` | 3 | 90 | 90 | `d0191e143cdb6525f6964a27ca62a80ebc2ab6358043c980e2b05f807928dfe0` |
| `synergy-val6` | 3 | 90 | 90 | `d0191e143cdb6525f6964a27ca62a80ebc2ab6358043c980e2b05f807928dfe0` |

Downstream, unchanged from the handoff:

- All three relayers: **no** `typed-posy-finality.json` observer store.
- Public RPC `synergy_chainId` = 1266, `synergy_blockNumber` = **0**.
- Atlas summary: `chainId=1266 latestBlock=0 activeValidators=6 peerCount=3`.

Rejection counts over a 30-minute window confirmed both blockers still active
and reproduced identically on all three relayers:

| Alias | `round 1 is not authorized` | `not from a configured public service role` |
|---|---:|---:|
| `synergy-relayer1` | 681 | 88 |
| `synergy-relayer2` | 617 | 88 |
| `synergy-relayer3` | 685 | 88 |

The service-role count is one per ~20 s, consistent with exactly **one**
polling requester being rejected rather than both support roles.

---

## 2. Blocker 1 — observer applies a live round check to a durable record

### Root cause

`runtime/src/consensus/typed_finality_observer.rs::verify_record` called
`ProofOfSynergyBft::validate_core_proposal`, which begins with:

```rust
self.require_authorized_round(&context.height_context, block.header.round)?;
```

`require_authorized_round` (`posy.rs`) reads `self.authorized_rounds`:

```rust
let authorized = self.authorized_rounds.get(&key).copied().unwrap_or(Round(0));
if round != authorized { /* reject */ }
```

`authorized_rounds` is written in **exactly one place** — `advance_round_after_tc`
— and a timeout certificate is an ephemeral liveness artifact that is
deliberately **not** part of a durable `TypedFinalityRecord`.

A non-signing observer therefore constructs a fresh `ProofOfSynergyBft`
(`from_finalized_inputs`), never observes a TC, and `authorized_rounds` stays
empty for the process lifetime. Every record whose round is greater than zero is
rejected as unauthorized regardless of validity.

### Why it blocked the launch completely

Testnet-v3 finalized **height 1 at round 1**, so the rejection hit the very
first record and no observer store was ever created:

```
height  round  qc_phase
1       1      FINALITY
2       0      FINALITY
3       0      FINALITY
4       1      FINALITY
```

Round distribution across the 90 live records: round 0 ×83, round 1 ×5,
round 3 ×1, round 4 ×1. This was never a transient condition.

### Fix

One validation algorithm is retained. `validate_core_proposal` is split into a
shared implementation parameterised by a new `RoundAuthoritySource`:

- `LiveTimeoutCertificate` — unchanged behaviour, used by every signing path.
- `FinalizedQuorumCertificate` — used only by the new
  `validate_finalized_core_record`, which the observer now calls.

The **only** difference is that the live TC lookup is skipped. Every other
check is unchanged.

### Soundness

`candidate_id()` intentionally zeroes `round`, so the QC alone does not bind it.
The relaxed path is safe because `header.round` remains bound by:

1. **Proposer schedule for that exact round** —
   `proposer_for(height_context, block.header.round)` must equal
   `header.proposer_validator_id`.
2. **Proposer signature over the full header** — `SYNERGY_BLOCK_V1` is verified
   over `block.header.canonical_bytes()`, which includes `round`, under the
   `ConsensusProposer` role key. Forging a round requires forging that
   validator's ML-DSA-65 signature.
3. **Supermajority finality QC** — a `VotePhase::Finality` QC exists for the
   candidate, so an honest supermajority each ran the strict
   `LiveTimeoutCertificate` check before voting. The QC is the transitive
   evidence that the round transition was legitimate.
4. **Forward chain linkage** — the successor's `parent_block_hash` commits to
   this header's full hash, so a tampered round breaks the next height.

`require_candidate_carry_forward` is retained on both paths; it is already a
no-op when no carry-forward entry exists.

---

## 3. Blocker 2 — DNS-named allowlist entries were unmatchable inbound

### Root cause

`runtime/src/p2p/networking.rs::connected_endpoint_host_matches_configured_address`
resolved the configured host **after stripping its port**:

```rust
let Some((configured_host, _configured_port)) = endpoint_host_port(configured_address) else { ... };
...
configured_host.to_socket_addrs()   // bare host, no port
```

`str::to_socket_addrs` requires `host:port`. Resolving a bare host always
returns `Err`, so `.unwrap_or(false)` made **every DNS-named allowlist entry
unmatchable on the incoming path**. The port-exact sibling
(`connected_endpoint_matches_configured_address`) already did this correctly
using the tuple form `(host, port).to_socket_addrs()`.

### Why it rejected the RPC gateway specifically

`peer_endpoint_matches_configured_list` requires, for an **incoming** peer, that
a *single* configured entry satisfy both the source-host check and an exact
match against the peer's advertised `public_address`.

The RPC gateway is configured with `public_address = "rpc.synergynode.xyz:5623"`,
and `PUBLIC_HISTORY_GATEWAY_DIAL_ADDRESSES` contains both forms:

| Allowlist entry | Source-host check | Advertised-address check |
|---|---|---|
| `167.86.83.83:5623` | passes (numeric, matches source IP) | **fails** (advertised is the hostname) |
| `rpc.synergynode.xyz:5623` | **fails** (bare-host resolution always errored) | passes |

Neither entry satisfied both, so no entry authorized the peer. The explorer
indexer advertises a numeric `74.208.227.23:5622`, which matches a single entry
on both conditions — which is exactly why only one requester was being rejected.

### Fix

Resolve host and port together, matching the sibling function:

```rust
(configured_host.as_str(), configured_port).to_socket_addrs()
```

The authorization contract is unchanged and was not broadened: a numeric source
host is still mandatory, a self-reported hostname is still never accepted as
transport evidence, and the signed handshake role is still required.

---

## 4. Tests added

`consensus::typed_finality_observer`:

- `imports_a_finalized_record_produced_after_a_round_change` — drives the source
  coordinator through a real TC, produces a genuine round-1 finalized record,
  and asserts an observer imports it. This is the exact live failure.
- `round_change_recovery_does_not_weaken_the_live_signing_path` — a live
  coordinator with no TC must still reject the same block with
  `valid TC is required`, while the recovery path accepts it.
- `round_change_recovery_still_binds_the_round_to_the_proposer_schedule` —
  re-labelling a finalized block's round must fail even though its QC verifies.

`p2p::networking`:

- `incoming_host_match_resolves_dns_named_configured_endpoints` — DNS entries
  resolve; a resolved host that is not the source still fails; numeric entries
  still ignore the ephemeral inbound port; a self-reported hostname is rejected.

### Results

| Suite | Result |
|---|---|
| `consensus::typed_finality_observer::` | **6 passed, 0 failed** (3 new) |
| `consensus::` serialized (`--test-threads=1`) | **358 passed, 0 failed** |
| `role_runtime::` | **48 passed, 0 failed** |
| `p2p::networking::` | 142 passed, 7 failed — see below |

### The seven `p2p::networking` failures are pre-existing

A clean-tree baseline was produced by stashing all three modified files and
re-running the identical command. Baseline: **141 passed, 7 failed**.

Six of the seven failures are identical in both runs:

```
authenticated_support_classification_propagates_without_public_address_trust
completed_service_apply_does_not_release_next_batch_slot
direct_vote_handshake_capability_is_signed_and_verifiable
signed_aegis_pqc_handshake_verifies
status_handler_requests_blocks_from_duty_disabled_support_peer
typed_validator_handshake_requirement_excludes_bootstrap_and_legacy_profiles
```

The seventh differs only between two siblings of the same timing-dependent
`service_sync_*` pair (`service_sync_timeout_releases_and_reassigns_the_source`
on the baseline, `service_sync_response_timeout_allows_qc_warmup_without_source_churn`
with the fix). The count is identical.

Concurrency, not logic, was further confirmed on the consensus suite: parallel
runs failed one **different** test each time
(`pre_activation_leader_seed_repair_is_reported_for_persistence`, then
`stale_conflicting_vote_locks_above_finalized_report_stall`), each passed in
isolation, and the serialized run was fully green at 358/358. These tests share
process-id-keyed temp paths and a process-wide signing authority.

**These failures are not introduced by this change and are not evaluated here as
launch gates.** They are worth a separate pass.

---

## 5. Deployment expectation

Only the relayer, RPC, and indexer roles change behaviour. The durable record
format is unchanged, so per handoff §9.1 step 8 the healthy validators do **not**
require a coordinated cutover for this fix.

Remaining, unchanged from the handoff:

1. Merge, update the Control Panel immutable `TESTNET_SOURCE_REV`, and build one
   v20.0.0 Linux runtime artifact in GitHub Actions. Do not use a locally
   compiled macOS binary on Linux nodes.
2. Verify source revision, `SHA256SUMS`, release-config manifest, ELF
   architecture, and embedded version.
3. Deploy relayers first with timestamped backups, then RPC and indexer.
4. Require all launch gates in handoff §9.1 step 9 before declaring launch —
   in particular an advancing nonzero public RPC height and Atlas `latestBlock`
   across **multiple** samples.
5. `launch/TESTNET_V3_LINUX_RUNTIME_RELEASE.json` is still stale (Incomplete 4).
6. Cloudflare AOP is still disabled while Nginx requires a client certificate
   (Incomplete 6). Independent of this fix.
