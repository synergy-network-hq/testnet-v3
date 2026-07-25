# Migration Guide

Migration is one validator at a time.

1. Confirm chain health and redundancy.
2. Run `verify-validator-workspace.sh --legacy-ok` against the current host to record drift.
3. Run `migrate-validator-to-node-user.sh --dry-run --source-workspace <path>`.
4. Review the planned service, key, config, and data movement.
5. Capture a rollback backup.
6. Run the migration with `--apply`.
7. Verify the canonical service, process user, peer count, block height movement, config hashes, genesis hash, and logs.
8. Update the validator inventory repository with the post-migration report.

Do not proceed to the next validator while the current validator is unhealthy, unsynced, quarantined unexpectedly, or running from a non-canonical path.

