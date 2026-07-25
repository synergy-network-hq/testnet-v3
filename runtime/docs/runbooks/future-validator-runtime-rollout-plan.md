# Future Validator Runtime Rollout Plan

This plan is for a future rollout only. It does not authorize deployment to the
current live validators from this branch.

## Preconditions

- Public RPC and Atlas show advancing canonical chain data.
- All active validators are healthy, or an incident commander explicitly opens a
  live recovery window.
- Archive validator remains contained unless archive canonical reseed has passed.
- Archive services, snapshot API, and snapshot worker remain disabled until
  archive canonical reseed passes and explicit authorization allows re-enable.
- `scripts/testnet/check-no-hardcoded-validator-topology.sh` passes.
- `scripts/testnet/validate-testnet.sh` passes against generated launch bundles.
- Durable state verification passes on every target before upgrade.
- Rollback binaries, configs, validator-set manifests, and artifact digests are
  recorded before any service mutation.
- Manual JSON/JSONL consensus repair is forbidden; protocol state-sync and
  supervisor transition/write flows replace manual surgery.

## Rollout Order

1. Build release binaries from the reviewed commit.
2. Verify artifact hashes and rollback binary hashes.
3. Run `synergy-node validator inspect-state` and `verify-state` on each target
   state directory. For verified compact append-log state, use the explicit
   `--allow-testnet-recovery-checkpoint` flag.
4. Run `synergy-node validator migrate-state --dry-run` on each target, passing
   the same explicit compact-state flag when required.
5. Run `synergy-node validator rebuild-derived-indexes --dry-run` on each target,
   passing the same explicit compact-state flag when required.
6. Upgrade one non-leader validator candidate only after health gates pass.
7. Wait for post-upgrade height advancement, validator health, qRPC health,
   metrics, and Atlas/RPC parity.
8. Continue one validator at a time. Do not batch validators until chaos and
   rollback tests pass for the exact artifact.
9. Upgrade relayer/RPC/Atlas surfaces only after validator quorum remains stable.
10. Leave archive disabled unless the archive reseed runbook has passed.

## Required Gates Per Node

- Pre-upgrade state verification: `GO`.
- Derived index rebuild dry-run: `GO`.
- Runtime binary digest matches release manifest.
- Config digest matches reviewed config.
- Rollback binary executable and digest recorded.
- Post-start local qRPC responds.
- Public RPC height advances after the validator rejoins.
- Atlas exact-height hash matches RPC for sampled post-upgrade blocks.
- No validator count, cluster count, or quorum assumption is hard-coded to the
  current six-validator fleet.

## Rollback Gate

Rollback is required if any of these occur:

- The upgraded validator stops advancing or diverges from canonical lock.
- Public RPC or Atlas returns mismatched hashes for finalized heights.
- Active validator count drops below the configured BFT safety threshold.
- qRPC, metrics, or indexer reads block consensus progress.
- State verifier reports body-behind-lock, missing compact boundary, malformed
  committed QC JSONL, duplicate/conflicting blocks, or root-owned state files
  that the runtime user cannot read.

## Evidence To Capture

- Commit SHA and artifact SHA256 values.
- Pre-upgrade `inspect-state`, `verify-state`, and migration dry-run reports.
- Service start/stop timestamps and exact command transcript without secrets.
- Post-upgrade RPC block number, latest block hash, health, and validator count.
- Atlas network summary and exact-height block hash match.
- Rollback decision, if any, with trigger and result.
