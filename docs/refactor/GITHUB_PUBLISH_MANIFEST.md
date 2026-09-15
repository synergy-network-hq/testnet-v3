# Core Protocol GitHub Publish Manifest

**Publish date:** 2026-09-15  
**Canonical repository:** `/home/node/Synergy-Network/01-Core-Protocol` on `synergy-val4`  
**Remote:** `https://github.com/synergy-network-hq/testnet-v3.git`  
**Preservation branch:** `reconcile/core-protocol-root-2026-09-15`  
**Starting commit:** `4aa6ae8463b1deababfe6b222dbc9251b1938ba1`

## Intended preservation contents

This branch preserves the complete current Core Protocol root reorganization and the exact dirty production-source state present when implementation was stopped. It also places the five canonical migration ledgers at repository-relative `docs/refactor/` paths, records the organization audit, and removes only reproducible build output and Apple filesystem metadata.

No implementation was repaired, completed, built, tested, deployed, or represented as migration-complete by this preservation pass.

## Staged-tree inventory

The initial exact staged snapshot contains:

- 48,864 changed paths;
- 30,521 detected renames;
- 18,333 additions;
- 4 root-policy/workflow modifications;
- 6 deletions, consisting of four old-root paths whose current files exist beneath `networks/testnet-v3/` and two Python bytecode cache files;
- approximately 4,102,267 inserted lines and 2,306 deleted lines as reported by Git.

All backup-suffixed source/provenance files under the organized roots were force-staged when necessary so ignore rules did not silently discard previously tracked custody. Ignored logs and build artifacts were not added merely because they were present.

## Publishability checks

### Gitleaks

- Tool: Gitleaks v8.30.1, built in `/tmp` on Val4 from the official Go module.
- Scope: exact staged diff (`gitleaks git --staged`).
- Data scanned: approximately 232.64 MB.
- Output handling: 100% redaction; the report remained in `/tmp` and secret values were not printed or copied.
- Raw findings: 36 in six files.
- Reviewed live-secret findings: 0.

Reviewed classifications:

- 2 architecture-checklist prose false positives;
- 1 explicitly test-marked license-secret example absent from active source;
- 30 deterministic pinned PQSynQ test-vector fields across two byte-identical copies;
- 3 vendored NIST FN-DSA/Falcon test constants.

### Targeted checks

- Private-key PEM/OpenSSH headers: none.
- High-confidence GitHub, AWS, Slack, and live Stripe token prefixes: none.
- Staged actual `.env` files: none.
- Staged `.env.example` templates: 3; values structurally reviewed as placeholders, local paths, or non-secret configuration.
- Staged PEM/key containers (`.pem`, `.key`, `.p12`, `.pfx`): none.
- Staged databases (`.db`, `.sqlite`, `.sqlite3`): none.
- Nested Git repositories: none.
- Git submodules: none.
- Reproducible `node-platform/target/` content: removed before staging.
- Apple `.DS_Store`/`._*` metadata: removed before staging.

The unchanged Grafana configuration surfaced sample/default password-shaped assignments during targeted scanning. Git identifies the file as an `R100` move from its already tracked old-root path; it contains no newly introduced configuration bytes.

## Canonical ledger hashes at import

- `IMPLEMENTATION_STATUS.md`: `18546af842b4a4680d8d553d30f52f8842beaea46481fdfffe076e74c6c0e57b`
- `MIGRATION_MAP.md`: `63e7664f4997dc9362423f9ab797840f75b58d5a33a3bcea6ac468351647eeab`
- `NODE_ARCHITECTURE_COMPLETION_CHECKLIST.md`: `650354cfd126f21ea370a5d26e6c743a839b0efd7658bd0a263a648df7da25b4`
- `NODE_ARCHITECTURE_FILE_TREE_CHECKLIST.md`: `37a315020aa32b7b9b412869822feb51e6ea1c4b136153904c1f30b9fd1ae116`
- `NODE_PLATFORM_ACTUAL_FILE_TREE.md`: imported hash `c07b1f6fbd48b4364e72e91345209c901d5ac8f950e4575093908f1b9492bf38`; then intentionally regenerated in place after cleanup to reflect the exact post-cleanup Val4 tree.

## Commit and remote verification

This section is finalized after each preservation push.

- First preservation commit: `PENDING`
- Final manifest/consolidation commit: `PENDING`
- Final local branch HEAD: `PENDING`
- Final remote branch HEAD: `PENDING`
- Equality verification: `PENDING`
- Force push used: **NO**
- Main branch merged or rebased: **NO**
- Production deployment performed: **NO**

## Post-preservation inventory

Cross-repository inventory begins only after the first preservation commit is present on the remote branch. Its findings and AJ-authored commit ledger are recorded in `docs/refactor/REPOSITORY_CONSOLIDATION_PLAN.md`. No repository is consolidated, archived, deleted, or rewritten during that read-only inventory.
