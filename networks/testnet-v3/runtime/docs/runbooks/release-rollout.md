# Release Rollout Runbook

This runbook defines the future Prompt 2 release gate. It does not authorize a
deployment from the current branch.

## Pre-Release Gates

- `cargo fmt`
- `cargo check -p synergy-testnet`
- `cargo test -p synergy-testnet --lib`
- `cargo check -p synergy-testnet --bin synergy-node`
- `scripts/testnet/validate-testnet.sh`
- `scripts/testnet/check-no-hardcoded-validator-topology.sh`
- `scripts/testnet/check-prompt2-offline-gates.sh`
- Python archive-authority compile and unit tests.
- `bash -n` for changed shell scripts.
- `git diff --check` and staged secret scan.

The branch must contain no secrets, workbooks, private keys, raw SSH configs,
`.env` files, credentials, or production logs containing credentials.

## Hard Stop Conditions

- Any live validator deployment, restart, state mutation, archive re-enable,
  archive snapshot API re-enable, snapshot worker re-enable, or quorum change
  requires explicit authorization.
- Archive services remain disabled until archive canonical reseed passes.
- Archive snapshots are not validator recovery sources before that gate.
- Manual JSON/JSONL consensus repair is forbidden. State-sync repair and
  supervisor transitions are the recovery path.
- Current six-validator references are current-live fixtures only. Validator and
  cluster counts are dynamic.

## Future Rollout Sequence

1. Record commit SHA, release artifact digests, rollback binary digests, config
   digests, validator-set digest, and cluster-map digest.
2. Confirm public RPC and Atlas read-only evidence show advancing canonical data.
3. Confirm every target cluster remains above quorum margin before selecting a
   validator.
4. Upgrade or repair one validator at a time only.
5. Wait for post-action health: local validator health, qRPC, metrics, canonical
   height advancement, public RPC synced status, active validator count, and
   Atlas exact-height hash parity where available.
6. Continue only after health proof is recorded.
7. Stop immediately if any cluster would fall below quorum margin.

## Rollback

Rollback must use the recorded rollback artifact and reviewed config. A rollback
is successful only when health proof is collected after the rollback. If health
proof is missing, keep the validator in the supervisor recovery state indicated
by evidence and do not continue rollout.

## Archive Boundary

The archive validator, archive snapshot API, and archive snapshot worker remain
disabled until `docs/runbooks/archive-canonical-reseed.md` passes and an
operator explicitly authorizes service re-enable. Snapshot publication remains
fail-closed for noncanonical proof.
