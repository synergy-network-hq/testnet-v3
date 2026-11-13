# Validator State Store Migration Runbook

This runbook covers Prompt 2 offline migration from legacy validator state files
into the durable consensus state layout. It does not authorize live validator
state mutation.

## Safety Boundary

- Do not manually repair, truncate, reorder, or synthesize `chain.json`,
  `canonical_locks.json`, `committed_qcs.jsonl`, or `state_checkpoint.json`.
- State migration must be driven by `synergy-node validator migrate-state`,
  `verify-state`, and `rebuild-derived-indexes`; manual JSON/JSONL surgery is
  forbidden.
- State-sync repair and supervisor flow replace ad hoc operator edits during
  recovery.
- Current six-validator state is a live fixture only. Validator and cluster
  counts are dynamic, and migration code must not depend on fixed `Val1-Val6`
  loops.
- No live deploy, restart, migration apply, or rollback is allowed without
  explicit authorization.
- Archive services remain disabled and archive snapshots remain excluded until
  canonical reseed passes.

## Offline Migration Flow

```bash
synergy-node validator inspect-state --state-root <workspace-copy>
synergy-node validator verify-state --state-root <workspace-copy> [--allow-testnet-recovery-checkpoint]
synergy-node validator migrate-state --state-root <workspace-copy> --dry-run [--allow-testnet-recovery-checkpoint]
synergy-node validator rebuild-derived-indexes --state-root <workspace-copy> --dry-run [--allow-testnet-recovery-checkpoint]
```

The state verifier must pass before migration. Commands are strict by default.
The explicit `--allow-testnet-recovery-checkpoint` option may be used only when
the compact append-log or approved testnet recovery evidence passes the same
fail-closed verifier. Corrupt, conflicting, or incomplete QC/lock evidence still
fails even when the option is present.

## Apply Rules

Migration apply is for local/offline fixture workspaces unless a future rollout
explicitly authorizes a live node. A valid apply must:

1. verify source state invariants;
2. create a backup before any write;
3. stage the migrated store in a temporary path;
4. rebuild derived indexes from verified source data;
5. verify the staged store;
6. commit atomically; and
7. emit a migration receipt with source and output digests.

If any step fails, the original workspace remains the authority.

## Future Live Rollout

Live migration must follow the release rollout runbook. Upgrade one validator at
a time, keep the target cluster above quorum margin, record rollback artifacts,
and prove health after rollback or migration before proceeding to another
validator.

## Appliance Layout Closeout Gate

The final active validator appliance root is `/var/lib/synergy/validator`.
Runtime config belongs under `/etc/synergy/validator`, and executable release
artifacts belong under `/opt/synergy`.

The legacy workspace path, usually
`/home/node/.synergy/testnet/nodes/validator-workspace`, must not be used as the
final runtime root and must not be recreated as a symlink to the appliance root.
After a successful migration, archive it with a manifest and checksum, then
remove it or replace it only with an inert README marker that cannot be used as a
workspace.

Before any validator restart, run the read-only closeout verifier on the host:

```bash
python3 scripts/testnet/verify-validator-appliance-layout.py
```

The verifier must return `ok: true`. A `NO_GO` means an active service, env file,
config file, or old workspace still violates the appliance layout gate.
