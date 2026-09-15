# Core Protocol Repository Organization Audit

**Audit date:** 2026-09-15  
**Canonical host:** `synergy-val4`  
**Canonical repository:** `/home/node/Synergy-Network/01-Core-Protocol`  
**Preservation branch:** `reconcile/core-protocol-root-2026-09-15`  
**Starting commit:** `4aa6ae8463b1deababfe6b222dbc9251b1938ba1`

## Scope and freeze

This audit records the repository organization and GitHub-preservation pass. The dirty source tree was frozen at the start of this pass. No PoSy, ETDAG, NodeAddress, validator, RPC, updater, GUI, networking, SynQ, AIVM, execution, or other node-platform implementation was changed as part of this work.

The current worktree includes incomplete and unverified production-source work from the interrupted migration. That state is intentionally preserved exactly; this audit does not certify it as built, tested, deployed, or migration-complete.

## Canonical ledger correction

The canonical migration ledgers are repository-relative files, not machine-specific copies:

- `docs/refactor/IMPLEMENTATION_STATUS.md`
- `docs/refactor/MIGRATION_MAP.md`
- `docs/refactor/NODE_ARCHITECTURE_COMPLETION_CHECKLIST.md`
- `docs/refactor/NODE_ARCHITECTURE_FILE_TREE_CHECKLIST.md`
- `docs/refactor/NODE_PLATFORM_ACTUAL_FILE_TREE.md`

The repository-root `AGENTS.md` was corrected to name those paths. The five current ledger contents were imported into the canonical paths and byte-for-byte SHA-256 verified against the latest supplied Mac files before cleanup.

## Repository boundary checks

- One Git worktree exists at the canonical repository root.
- No nested `.git` directories were found beneath the repository.
- No `.gitmodules` file or configured submodule was found.
- The configured origin is `https://github.com/synergy-network-hq/testnet-v3.git`.
- The pre-preservation branch was `codex/node-reorganization-remote`, tracking `origin/main`.
- The preservation branch was created without rebasing, force-updating, or rewriting history.
- `/opt/synergy/chain1266/releases`, validator state, validator keys, databases, NetBird credentials, approved releases, and live service configuration are outside this audit and were not changed.

## Root organization being preserved

The organized repository root contains the primary top-level source areas `.github`, `docs`, `networks`, `node-platform`, `protocol`, and `tooling`, plus repository policy and ignore files. The large dirty change set is primarily the not-yet-committed root reorganization from the former Testnet-v3-root layout into this Core Protocol root, together with the frozen implementation work already present when this audit began.

## Cleanup-candidate audit

### Safe generated material

The following material is deterministic or platform metadata and is eligible for deletion after this record exists:

- `node-platform/target/`: approximately 900 MiB of ignored Rust build output.
- 21 Apple metadata files named `.DS_Store` or `._*`, all ignored by repository policy.

These files do not provide unique source ownership and are reproducible or non-source filesystem metadata. Cleanup removed the complete `node-platform/target/` tree and all 21 Apple metadata files; a post-cleanup search returned zero remaining instances.

### Retained backup-suffixed material

Backup-suffixed files were not bulk-deleted. Comparison against their apparent live counterparts established that many contain different bytes or have no direct counterpart:

- nine `.orig` files under `node-platform` and `networks/testnet-v3`, including frozen pre-edit forms of Cargo manifests and source files;
- two `Cargo.toml.workspace.bak` files in the Aegis PQSynQ import with no direct same-path counterpart;
- `networks/testnet-v3/runtime/scripts/send-tokens.sh.bak`, which differs from the live script;
- NIST `rng.c.backup` files in PQVM source trees, some identical and many different from adjacent `rng.c` files.

The `rng.c.backup` files are part of imported/vendor source history and 37 backup-suffixed files were tracked in the starting repository layout. They are retained pending an explicit consolidation decision. Ignore status is not treated as proof that a file is disposable.

### Retained logs and evidence

Ignored Aegis/PQVM/PQSynQ `.log` files include benchmark and NIST-vector evidence. They are retained during preservation because their evidentiary value and independent upstream custody have not yet been established. They are not staged merely because they are present.

### Databases, snapshots, credentials, and environment files

No live database or validator-state cleanup was authorized. Snapshot-named source modules and test fixtures are source-owned material, not runtime snapshot data, and are retained. `.env.example` templates are treated as publishable templates only after content scanning; actual `.env` files remain ignored. Credential, private-key, and token-like material must pass the publishability gate before any commit is pushed.

## Aegis and vendored-tree custody

The apparent duplicate Aegis trees are materially different and are not safe cleanup aliases:

- `node-platform/crates/aegis-pqvm` versus `networks/testnet-v3/runtime/aegis-pqvm`: 5,634 shared paths, 5,595 identical, 39 different, 11,424 node-platform-only, and 9 runtime-only files, excluding build output.
- `networks/testnet-v3/runtime/aegis-pqvm` versus `networks/testnet-v3/runtime/vendor/aegis-pqvm`: 2,447 shared paths, 1,686 identical, 761 different, 3,196 direct-tree-only, and 3,149 vendor-tree-only files.
- the nested Aegis PQSynQ import shares most of its core files with its parent import but includes different manifests and separately placed fuzz files; it is not deleted during preservation.

The workspace manifest intentionally names the canonical node-platform Aegis crates. `synergy-aegis` is the canonical engine integration boundary and `synergy-crypto` remains a facade over it. This audit records current custody only and does not consolidate these source trees.

## Publishability gate

The preservation branch must not be pushed until all would-be tracked content passes:

1. a secrets scanner over the exact staged tree;
2. targeted filename and content checks for private keys, seed phrases, credentials, tokens, actual environment files, databases, logs, and validator/runtime state;
3. a staged-tree review confirming ignored generated and sensitive material is not accidentally included.

Gitleaks v8.30.1 was built in `/tmp` on Val4 and run against the exact staged diff with full output redaction. It scanned approximately 232.64 MB and produced 36 findings in six files. Every finding was reviewed without exposing its value:

- two were ordinary prose in the canonical architecture checklists;
- one was an explicitly test-marked `AEGIS_LICENSE_SECRET` example in a no-stub audit and was absent from active source;
- 30 were deterministic PQSynQ pinned test-vector secret/shared-secret fields in two byte-identical copies of the same test fixture (SHA-256 `6111d148a96364acc8fa0375e0da67b3c65fd57d0f37be28d6cb58383bafd70e`);
- three were vendored NIST FN-DSA/Falcon test constants referenced by the vendor test program.

No private-key PEM/OpenSSH headers or high-confidence GitHub, AWS, Slack, or live Stripe token prefixes were found. The staged filename scan found only three `.env.example` templates and no actual `.env`, PEM, key-container, SQLite, or database files. Template assignments were structurally reviewed; sensitive-looking values are placeholders/paths, not live credentials. The remaining targeted assignment candidates are source identifiers, test fixtures, or an unchanged `R100` move of an already tracked Grafana sample/default configuration. Tool availability, scan results, exclusions, and final commit verification are recorded in `docs/refactor/GITHUB_PUBLISH_MANIFEST.md`.

## Deletion log

No source or ambiguous artifact was deleted. Cleanup removed only the safe generated material listed above. After cleanup, `node-platform` contains 1,215 directories, 18,534 files, 3 symbolic links, and 19,752 total entries. `docs/refactor/NODE_PLATFORM_ACTUAL_FILE_TREE.md` was regenerated directly from that exact Val4 directory and annotates every entry.

## Preservation status

The first preservation commit is `df17c9264443f9e2e1182bc3e351e69cc8a143d9`. It was pushed to `origin/reconcile/core-protocol-root-2026-09-15`, and the canonical Val4 local HEAD exactly equaled the remote branch HEAD at that checkpoint. The subsequent read-only organization inventory and final manifest are committed on the same branch; final branch equality is verified again after their push.
