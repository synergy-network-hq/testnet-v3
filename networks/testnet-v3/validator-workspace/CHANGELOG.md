# Changelog

## 0.1.1 - 2026-06-16

- Added canonical hot-path retention env settings for `canonical_locks.json` and committed-QC memory retention.
- Documented the block-time impact of unbounded canonical-lock rewrites.
- Updated the node-env schema to require the retention settings.

## 0.1.0 - 2026-06-15

- Added canonical Synergy Testnet validator filesystem template.
- Added safe `.example` config, identity, key, and WireGuard files.
- Added manifest, identity-field allowlist, drift checks, schemas, examples, and validation tests.
- Added dry-run-first install, migration, verification, rollback, drift, hash collection, and block-time diagnostic scripts.
- Added preflight report for validator standardization.
