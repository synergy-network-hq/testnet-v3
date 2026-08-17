# PoSy v3 five-validator deployment preflight

Status: preparation checklist; all activation/launch controls are open unless backed by linked evidence.

## Immutable inputs

- [ ] Canonical manifest status is `FINALIZED`, not `PROPOSED_NOT_ACTIVATED`.
- [ ] Governance approval ID, activation epoch, and activation height are present and authorized.
- [ ] Exact manifest SHA3-512 root matches every node and the transition certificate.
- [ ] Exactly five approved public validator identities are active in one cluster.
- [ ] Validator, ML-DSA-65 consensus key, frozen-weight, epoch-context, and leader-ring roots match on all five nodes.
- [ ] Each validator has a unique active consensus key with the correct Aegis vote/proposer roles.
- [ ] No boot/seed/relay/archive/RPC/explorer/observer role has implicit vote weight.
- [ ] Chain ID 1266 and network ID `synergy-testnet-v3` match every artifact.

## Quorum and failure model

- [ ] Count quorum derives to four; it is not configured as an override.
- [ ] Exact weight verifier uses checked integer `3*signed_weight > 2*total_frozen_weight`.
- [ ] Every leave-one-out four-validator set retains strict weight quorum.
- [ ] No validator holds one-third or more of total frozen weight.
- [ ] One unavailable validator progresses; two unavailable validators stall safely.
- [ ] Duplicate, revoked, wrong-context, wrong-root, and invalid signers count as zero.

## Safety and persistence

- [ ] Signer journal is readable, canonical, and fsync-before-signature; no reset/delete recovery path exists.
- [ ] Rooted v3 state restores anchor/highest/locked QC, last vote, TC chain, finalized head, and SafetyHalt.
- [ ] Sequential TC verification explains the current takeover owner after restart.
- [ ] State sync reconstructs the same state from certified evidence on all five nodes.
- [ ] Conflicting valid QC evidence enters irreversible SafetyHalt.
- [ ] TC cannot bypass an incompatible lock or authorize a branch.
- [ ] Protected execution and ETDAG boundaries pass their existing gates.

## Network and fault rehearsal

- [ ] Five independent node processes derive identical rings and owners for the tested epoch/height/round space.
- [ ] Divergent wall clocks and peer-health views never change authority.
- [ ] First and second leader failure transfer only the remaining current lease.
- [ ] Predetermined lease boundary resets takeover and permits the scheduled next lease.
- [ ] Delayed, duplicate, stale, skipped, wrong-height, and wrong-round TCs are rejected.
- [ ] Partitions heal without forced leader, journal deletion, height editing, or restart ordering.
- [ ] Long-run repeated leader failures continue when four valid signers remain.

## Release, operations, and launch

- [ ] Signed reproducible binary hash matches the migration record on all five nodes.
- [ ] Full tests, lints, format checks, deterministic vectors, fuzz/property/model tests pass.
- [ ] 10,000-block proposal/vote/QC/finality/takeover/PQC/size/restart evidence meets approved targets.
- [ ] Dashboards and alerts expose every `posy_v3_*` metric and SafetyHalt/root divergence.
- [ ] Migration and fail-closed exercises are witnessed and linked.
- [ ] Existing security, ETDAG, governance, topology, genesis, operations, release, and launch gates pass.
- [ ] Go/no-go record is approved. Until then `launch-readiness.json` remains `blocked_prelaunch`.

## Local preparation commands

```bash
cd runtime
cargo test -p synergy-testnet --lib consensus::simplified_posy::tests --no-fail-fast
cargo test -p synergy-testnet --lib posy_simplified_parameters::tests
scripts/testnet/run-posy-simplified-five-node-harness.sh
```

These commands create local evidence only. They do not deploy, activate, rotate keys, regenerate identities, or modify live infrastructure.

