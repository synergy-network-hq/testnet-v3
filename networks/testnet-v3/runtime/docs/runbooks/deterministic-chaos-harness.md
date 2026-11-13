# Deterministic Chaos Harness Runbook

This runbook covers the offline chaos harness only. It does not deploy binaries,
restart validators, mutate chain state, or re-enable archive services.

## Command

```bash
synergy-node chaos run \
  --input chaos-scenario.json \
  --output chaos-report.json \
  --chain-id 1264 \
  --network-id synergy-testnet-v3
```

The scenario declares the injected fault and the expected safety behavior. The
harness evaluates dynamic cluster quorum, canonical validator head, public
surface fail-closed behavior, archive containment, rejoin gates, and safety
assertions from JSON evidence.

## Covered Behaviors

- Two stopped validators in a six-validator cluster still finalize with the
  four-validator quorum.
- Three stopped validators halt safely without conflicting finality.
- Network partitions cover 2/6 and 3/6 current-fleet cases plus expanded
  dynamic quorum fixtures for 7-validator, 10-validator, and 13-validator
  clusters.
- Two-cluster and three-cluster fixtures report each cluster independently and
  halt safely when any cluster falls below quorum margin.
- Validator crash faults cover mid-block append and crash between committed-QC
  append and canonical-lock write.
- Corruption faults cover canonical lock corruption and
  `committed_qcs.jsonl` corruption.
- Disk-full write failure is handled without quorum lowering.
- Divergent or corrupted validators require quarantine/state sync instead of
  active participation.
- qRPC or metrics failures degrade surfaces without blocking consensus quorum.
- Public RPC or Atlas stale/minority backends are rejected fail-closed.
- Noncanonical or contaminated archive snapshot state remains contained and
  untrusted.
- Rejoin is blocked when checkpoint or delayed-QC evidence is not verified
  against the latest finalized quorum head.
- Community validators can only progress to vote-only when dry-run join gates
  pass.

## Safety Assertions

Every report includes `safety_assertions`:

- `no_unsafe_qc_acceptance`
- `no_quorum_lowering`
- `no_permanent_quarantine_without_persistent_evidence`
- `rejoin_requires_verified_latest_finalized_head`
- `public_surfaces_fail_closed`
- `archive_remains_isolated`

The harness fails closed when a scenario attempts unsafe QC acceptance, tries to
lower dynamic quorum, requests permanent quarantine without persistent fault
evidence, lets a bad-checkpoint or delayed-QC rejoin proceed, trusts unsafe
public surfaces, or lets contaminated archive data enter recovery trust.

## Fail-Closed Conditions

The command exits nonzero if the chain/network IDs are wrong, no validators are
provided, conflicting quorum heads are present, a noncanonical archive is trusted
by recovery, community dry-run join evidence is missing, safety assertions fail,
or the evaluated behavior does not match the expected scenario behavior.

## Scenario Fixtures

Checked-in example inputs live under `fixtures/chaos/`:

- `stop-one-current-six-finalizes.json`
- `network-partition-thirteen-finalizes.json`
- `two-cluster-network-partition-finalizes.json`
- `three-cluster-network-partition-halts.json`
- `atlas-minority-fail-closed.json`

These are offline fixtures for `synergy-node chaos run`; they are not live
validator orchestration scripts.

This remains an offline deterministic evaluator. Real multi-process crash,
partition, and disk-full execution belongs in the future live rollout harness
and is not authorized by this runbook.
