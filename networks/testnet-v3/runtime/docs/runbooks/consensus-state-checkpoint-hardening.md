# Consensus State Checkpoint Hardening Runbook

This runbook covers offline validator state verification. It does not authorize
live chain-data mutation, validator restart, binary deployment, or archive
snapshot use.

## Required Compact Boundary Evidence

When `chain.json` starts above height `0`, the verifier requires:

- a canonical lock at the first retained height;
- a committed QC at the first retained height;
- `state_checkpoint.json` at the first retained height; and
- checkpoint hash agreement with the retained body, canonical lock, and
  committed QC.

`state_checkpoint.json` may include direct SHA-256 fields such as
`chain_sha256`, `canonical_locks_sha256`, and `committed_qcs_sha256`, or nested
entries under `files.<name>.sha256`. When present, those digests must match the
current files.

## Fail-Closed Conditions

`synergy-node validator verify-state` returns `NO_GO` for:

- missing checkpoint on compacted state;
- checkpoint height or hash mismatch at the compact boundary;
- checkpoint and canonical-lock disagreement;
- missing or mismatched committed QC for the checkpoint;
- checkpoint file digest mismatch; and
- unreadable or malformed checkpoint JSON.

## Durable Store Behavior

`synergy-node validator migrate-state` copies `state_checkpoint.json` into
`data/consensus_state_v1` when present and includes it in the durable-store file
summary. The command still refuses migration when state verification fails.
