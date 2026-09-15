# Synergy Network Repository Consolidation Plan

**Inventory date:** 2026-09-15  
**Organization:** `synergy-network-hq`  
**Mode:** read-only inventory and preservation planning only  
**Consolidation/archive/deletion performed:** **NO**

## Preservation prerequisite

The canonical Core Protocol root was preserved before this inventory at:

- repository: `synergy-network-hq/testnet-v3`
- branch: `reconcile/core-protocol-root-2026-09-15`
- first preservation commit: `df17c9264443f9e2e1182bc3e351e69cc8a143d9`

At the preservation checkpoint, the canonical Val4 local HEAD and GitHub branch HEAD were equal. The branch tree is large enough that GitHub's recursive-tree API reports `truncated: true`; the Git commit itself, not that truncated API response, is the preservation authority.

## Executive conclusion

The organization is not ready for destructive consolidation or archival.

The Core Protocol root, legacy `testnet`, SynQ, AIVM, Aegis PQVM/PQSynQ, and Forge repositories contain divergent or independently unique history and files. Several relationships are explicit submodule pins, while the new Core Protocol root currently contains copied/imported snapshots rather than preserved Git ancestry. Treating similarly named directories as duplicates would lose source, provenance, or unmerged work.

One required AJ-authored implementation commit, abbreviated `b8ec31dd`, is not resolvable from any current repository object exposed by the GitHub API and is not present in any Val4 Git object database searched under `/home/node/Synergy-Network`. This is a **CRITICAL PRESERVATION BLOCKER**. No relevant repository or branch may be archived or consolidated until that object or an independently verified patch is recovered.

## Detailed canonical-family inventory

| Repository | Default HEAD | Branches | Tags | Pull requests | Tree/manifests | Preservation notes |
|---|---:|---:|---:|---:|---:|---|
| `testnet-v3` | `84869dcaa952c5f8c2448338e115794af75d4e4c` | 8 | 4 | 14 total; 2 open; 7 merged | default tree 33,066 entries; 60 manifests | Public repository. The new Core Protocol root is on the separately preserved `reconcile/core-protocol-root-2026-09-15` branch, not default `main`. No submodules in the preserved root. |
| `testnet` | `6c26d376ee2c383542004a3c042291e296c6b1bb` | 35 | 231 | 14 total; 0 open; 13 merged | 13,744 entries; 32 manifests | Private legacy/core repository with extensive release history. It pins `synergy-aivm` and `synq-language` as submodules and must remain preserved. |
| `synq-language` | `01125b6470c6b49c586b7a28fe054a62e1c913c6` | 3 | 0 | 1 merged | 17,443 entries; 17 manifests | Private canonical SynQ repository. Pins `aegis-pqsynq` at the current Aegis PQSynQ main commit. |
| `synq-internal` | `dfb332f8ea69d13599a29883d729f67fee87223e` | 1 | 0 | 0 | 57 entries | Private development reports and the only current documentary evidence for missing commit `b8ec31dd`. |
| `synergy-aivm` | `9debf33e11fdf4c0c20c3a07d4794e3b37751138` | 6 | 0 | 2 total; 1 open; 1 merged | 177 entries; 6 manifests | Private canonical AIVM repository; open PR #2 and multiple fix/recovery branches require disposition. |
| `aegis-pqvm` | `c6631276509fa1f7bf6293e84bd66b42be7d9f65` | 1 | 0 | 0 | 11,992 entries; 13 manifests | Private canonical PQVM repository. Its tree is similar to but not identical with the node-platform import. |
| `aegis-pqsynq` | `eaa01fdf6c9d98694a8fb359cb8348bb53d882ef` | 4 | 0 | 2 total; 1 open; 1 merged | 1,338 entries; 7 manifests | Private canonical PQSynQ repository. Open PR #2 and recovery/archive branches require disposition. |
| `forge-v3` | `bf3226e43341a210abf84e177a518c4e1fa5c06b` | 5 | 0 | 1 open | 262 entries; 2 manifests | Private current Forge. `feature/self-hosted-basepath` is a large divergent AJ-authored branch and open PR #1; it must not be dropped. |
| `synergy-forge` | `8bcfd519bb018e296db9629d325765ffc9bba500` | 3 | 0 | 0 | 77 entries; 1 manifest | Private earlier Forge line with separate history. Preserve until ownership/functionality is reconciled with `forge-v3`. |

### Current open work that blocks consolidation

- `synergy-aivm` PR #2: `fix/aivm-core-quantumvm-compat` → `main`, head `3f3d8b3c5cc841fb4a01349a9cbb4c45d3437bf7`.
- `aegis-pqsynq` PR #2: `agent/fix-deploy-call-verifier-example` → `main`, head `4276b09ddeeac3bb96d531242b5e436b9bde2390`.
- `forge-v3` PR #1: `feature/self-hosted-basepath` → `main`, head `2220da77702bf48a55d77982a616e61533f7f11c`.
- `testnet-v3` Dependabot PRs #9 and #14 remain open on the old-root default branch. They are not automatically applicable to the reorganized preservation branch.

### Active branch-head register

This register records every current branch for the repositories in the detailed inventory. Tags are recorded separately below.

| Repository | Branch | Head SHA |
|---|---|---|
| `testnet-v3` | `archive/justin-codex-reconciled-20260831` | `17a61b395f0f06e10c37d363e781f22de86370ab` |
| `testnet-v3` | `archive/testnet-v2-single-authority-20260823` | `d7f63f1ab5a89a57ea7dcd4e335a551d8532017d` |
| `testnet-v3` | `dependabot/npm_and_yarn/runtime/sxcp/sxcp_external_chains/evm/npm_and_yarn-0ecc17fa51` | `5770407773b1399a56ea952d7005c1bec3c86ee3` |
| `testnet-v3` | `dependabot/npm_and_yarn/runtime/synq-language/sdk/multi-1964815626` | `8a4abd74daf1b0d134915c9f6602b3ae02ae40d3` |
| `testnet-v3` | `main` | `84869dcaa952c5f8c2448338e115794af75d4e4c` |
| `testnet-v3` | `reconcile/core-protocol-root-2026-09-15` | `e923c77bdb254bea7a88505064e7b88bc3df0977` |
| `testnet-v3` | `recovery/ssd-2026-09-03` | `45ab579332be9c7cc05fb3f1429081f99b2c0e69` |
| `testnet-v3` | `release/chain1266-single-authority` | `bc6a7ea3febc4abc63429da9954fb958e53500d7` |
| `testnet` | `archive/testnet-v2-single-authority-20260823` | `bc6a7ea3febc4abc63429da9954fb958e53500d7` |
| `testnet` | `archive-snapshot-publication-hardening` | `f02030d4a2c9dda0b5b8033231fa8cee630ebabf` |
| `testnet` | `codex/authorized-cluster-leader-restoration-19.0.54-restoration.1` | `b02bebbf257d7d44698d285ac5c48cd7d738c174` |
| `testnet` | `codex/epoch-checkpoint-v19.0.21` | `5f7341696a1b9369ea679f4c287c3c28a75ea95a` |
| `testnet` | `codex/fix-qc-exact-round` | `d29f8ab8286720c41c5f7fc2870d24259e6c0b45` |
| `testnet` | `codex/legacy-1151000-recovery-runtime-19.0.49` | `cdfd8814e226218d88791b58ddf70abf38edbc4a` |
| `testnet` | `codex/posy-restoration-v19.1.0-restoration.1` | `e52bb9ac6c9cb35797cb8d355badf22214d06de3` |
| `testnet` | `codex/qc-repair-v19.0.20` | `6d0d3117473424f775dea0ef2fdedb604b37a169` |
| `testnet` | `codex/v19.0.5-runtime` | `9f334e5940d068703ad3792a4040e9c04f84033c` |
| `testnet` | `codex/v19.0.6-runtime` | `85e1ef0b5c3ba9718eb876baa1dac6946849c1af` |
| `testnet` | `codex/v19.0.7-runtime` | `a1736a69c8786f2183b5bdd66caf5162fe945db8` |
| `testnet` | `codex/v19.0.53-rejoin-tail-hotfix` | `182fd84efa8b4225ac72555664e089eaeb0e6f36` |
| `testnet` | `codex/validator-onboarding-v19.0.45` | `374857c7ed530a754b35d151805ebe2d177df6d0` |
| `testnet` | `codex/validator-onboarding-v19.0.46` | `489d76cc0f664557d0a1465f6091b2e5b3468023` |
| `testnet` | `emergency/v19.0.49-dag-tip-persistence` | `84ff77348f826a1549ccc280ffeb1234b4c6e2d0` |
| `testnet` | `feature/native-sts-token-system-testnet` | `26af2bac02a0f42e0755aa544e1cee9c0f1a9b6a` |
| `testnet` | `feature/real-codegen-and-dispatch` | `f7b727f4d8c2bea1ea827abe20c6f25c3073ab38` |
| `testnet` | `feature/validator-rewards-system-audit-rpc` | `a2b4138ebf7a6baafa557f7010ed749ff55e6153` |
| `testnet` | `fix/bump-anyhow-1.0.103` | `337037e959165cebe9b0a6286c3b5f8513ee6a6a` |
| `testnet` | `main` | `6c26d376ee2c383542004a3c042291e296c6b1bb` |
| `testnet` | `phase3-contract-addr-snts01-proto` | `9f2d6e0810a76d26cfb9b60d1339fd2c0b0db2fd` |
| `testnet` | `pr14-resolve` | `401cc15edb577c0b5526b17a397020654ea6ff42` |
| `testnet` | `release/v19.0.14-runtime` | `c195ef97bdb8852e0de57ee25d15b5658665f232` |
| `testnet` | `release/v19.0.15-runtime` | `3cbb0ca1a6ab3c6d690ac753f3c429813c16a7ed` |
| `testnet` | `release/v19.0.16-runtime` | `d9fe92c50471eab2deccddf2c9b4742b72546601` |
| `testnet` | `release/v19.0.17-runtime` | `87f4f10546cac9764beeb6afd08fc6c1c8bb7303` |
| `testnet` | `release/v19.0.18-runtime` | `61ca1960d4355e8b92cdb4d0eb82a5b57a9a4c8d` |
| `testnet` | `release/v19.0.19-runtime` | `0672ae94d358273e3da3b636d98a8a36376aadb3` |
| `testnet` | `release/v19.0.20-runtime` | `6d0d3117473424f775dea0ef2fdedb604b37a169` |
| `testnet` | `release/v19.0.21-runtime` | `5f7341696a1b9369ea679f4c287c3c28a75ea95a` |
| `testnet` | `release/v19.0.22-runtime` | `1c602efbd4774e829a9bdafa1bf193a82dc24e58` |
| `testnet` | `release/v19.0.51-runtime` | `55cf89438b9b304148e547472cdf1b196eaf6710` |
| `testnet` | `release/v19.0.52-runtime` | `3dcbc1b862a9f8df81f23e6231488686bd112534` |
| `testnet` | `release/v19.0.53-runtime` | `b97c645861c64583a5f28329132cc5e95944ccd2` |
| `testnet` | `runtime-fork-recovery-v19.0.49-hotfix` | `9214157a4db2ed1d08c9716c9909139047962a5d` |
| `synq-language` | `archive/justin-codex-reconciled-20260831` | `653d0fa7dedd9ee98ba08ac66b1ba305fcaf918f` |
| `synq-language` | `main` | `01125b6470c6b49c586b7a28fe054a62e1c913c6` |
| `synq-language` | `recovery/ssd-2026-09-03` | `263b0cc508605748bae3450d5270f0f824722ab2` |
| `synq-internal` | `main` | `dfb332f8ea69d13599a29883d729f67fee87223e` |
| `synergy-aivm` | `archive/justin-codex-reconciled-20260831` | `0f5c6711cab4250f24cbc35c1d215ad7112000b9` |
| `synergy-aivm` | `fix/aivm-core-quantumvm-compat` | `3f3d8b3c5cc841fb4a01349a9cbb4c45d3437bf7` |
| `synergy-aivm` | `fix/execution-context-profile-selection` | `b52779f8cf1469c5480e23b70499925ad101ef94` |
| `synergy-aivm` | `fix/v2-artifact-profile-migration` | `ffbe9290b0374a9168ccfef130d06224f0afdcc0` |
| `synergy-aivm` | `main` | `9debf33e11fdf4c0c20c3a07d4794e3b37751138` |
| `synergy-aivm` | `recovery/ssd-2026-09-03` | `dc0d821cc2db6441dedd63fc8249404553a157ea` |
| `aegis-pqvm` | `main` | `c6631276509fa1f7bf6293e84bd66b42be7d9f65` |
| `aegis-pqsynq` | `agent/fix-deploy-call-verifier-example` | `4276b09ddeeac3bb96d531242b5e436b9bde2390` |
| `aegis-pqsynq` | `archive/justin-codex-reconciled-20260831` | `60fb0dc8d4a8b4dc55dcf7c9e4a768ff35ecbd2f` |
| `aegis-pqsynq` | `main` | `eaa01fdf6c9d98694a8fb359cb8348bb53d882ef` |
| `aegis-pqsynq` | `recovery/ssd-2026-09-03/archive-justin-codex-reconciled-20260831` | `708792f93e27e26acb6c0c37e379b99b98450236` |
| `forge-v3` | `archive/justin-codex-reconciled-20260831` | `3020802444f4dd0cc09b1ef6a2c365097ae8be76` |
| `forge-v3` | `feature/self-hosted-basepath` | `2220da77702bf48a55d77982a616e61533f7f11c` |
| `forge-v3` | `feature/synq-v3-compiler-refresh` | `e94ab699a1e66629a56a2b9d642594a8bcc42edd` |
| `forge-v3` | `main` | `bf3226e43341a210abf84e177a518c4e1fa5c06b` |
| `forge-v3` | `recovery/ssd-2026-09-03` | `734a1f5cfad85302496467404b4860343ec50b0e` |
| `synergy-forge` | `archive/justin-codex-reconciled-20260831` | `ff36615eb69f17d8d0c354a5b5bc4941fa704fb8` |
| `synergy-forge` | `main` | `8bcfd519bb018e296db9629d325765ffc9bba500` |
| `synergy-forge` | `recovery/ssd-2026-09-03` | `1c6cc8b80d7921c3f8d6ed1306ffbb4b6cb7abfc` |

Tag inventory: `testnet` has 231 tags and is therefore retained as the historical release authority pending an approved archive plan. `testnet-v3` has four tags: `v20.0.0@c7e098836f368f26703a9c549ef17fc69a3212ee`, `chain1266-v20.0.0-rc.33@ddc3800f6c3546de7859bdf2cbc0906fe883f247`, `chain1266-v20.0.0-rc.32@62b921d09547a245665397f6312008c69553d7e8`, and `chain1266-v20.0.0-rc.31@74b23d3bd63eee41a7a1e9b57e8a32c38f7490f6`. The other detailed-family repositories have no tags.

## Cross-repository dependency and drift findings

### Explicit submodule pins

The private `testnet` default branch records:

- `synergy-aivm@d2d8e67df88145d2262f5997800d6bb2171577ea`; canonical `synergy-aivm/main` is 8 commits ahead.
- `synq-language@04630cfee976018442f4082a23d66e4fbdb01c38`; canonical `synq-language/main` is 12 commits ahead.

The `synq-language` default branch records:

- `aegis-pqsynq@eaa01fdf6c9d98694a8fb359cb8348bb53d882ef`; this is identical to current `aegis-pqsynq/main`.

Those pins are provenance and compatibility boundaries, not redundant copies.

### File-level snapshot comparisons

Git blob comparisons were performed without copying source content from Val4:

- Core Protocol `node-platform/crates/aegis-pqvm` vs `aegis-pqvm/main`: 11,287 shared file paths; 11,284 byte-identical; 3 different; 5,467 node-platform-only; 45 repository-only. Neither side subsumes the other.
- Core Protocol parent `node-platform/crates/aegis-pqsynq` vs `aegis-pqsynq/main`: 121 shared; 119 identical; 2 different; 116 node-platform-only (largely the nested import); 1,126 repository-only. The node-platform directory is not a complete replacement for the canonical repository.
- Nested node-platform PQSynQ import vs `aegis-pqsynq/main`: 113 shared and identical; 1 local-only backup; 1,134 repository-only. The nested import is only a partial snapshot.
- Core Protocol legacy runtime SynQ vs `synq-language/main`: 16,626 shared; 16,607 identical; 19 different; 118 runtime-only; 2 repository-only. Both histories remain necessary until changes are reconciled.
- Core Protocol legacy runtime AIVM vs `synergy-aivm/main`: 107 shared; 100 identical; 7 different; 4 runtime-only; 1 repository-only.

## AJ-authored preservation ledger

### Testnet AIVM chain

These three commits resolve in `synergy-network-hq/testnet`, form a direct parent chain, and are reachable from the current branch `phase3-contract-addr-snts01-proto` (head `9f2d6e0810a76d26cfb9b60d1339fd2c0b0db2fd`). They are preserved but are not on `testnet/main`.

| Commit | Author/date | Parent | Summary | Preservation state |
|---|---|---|---|---|
| `f3857b96e5798bd2880867bec0960b51af9892e2` | Alan Hancock `<alan@synq.dev>`, 2026-09-10 01:23:42Z | `cd9d3445f9d051bb0e12268ec1ecf381e717c553` | Real U256 AIVM support across opcode, arithmetic/comparison widening, ABI, and argument decoding | Reachable from named remote branch; do not archive branch. |
| `7bf7dd65bba48223c862a4656690817f1fb3f1f1` | Alan Hancock `<alan@synq.dev>`, 2026-09-10 01:45:58Z | `f3857b96...` | Widen asset-ledger value to U256 and prevent silent u64 literal wraparound | Reachable from named remote branch; do not archive branch. |
| `8d1479835175d2ab3ae732c097beac0658ff3ba3` | Alan Hancock `<alan@synq.dev>`, 2026-09-10 02:22:35Z | `7bf7dd65...` | Preserve `require()`/revert message text through `TrapMsg` | Reachable from named remote branch; do not archive branch. |

### Missing AIVM bitwise/shift commit

`b8ec31dd` is described by `synq-internal` as the AJ-authored implementation of AIVM bitwise/shift opcodes on branch `fix/synq-admission-chain-migration`. The report identifies changes to instruction opcodes, VM execution, compiler code generation, gas pricing, and tests.

Evidence retained in GitHub:

- `synq-internal` commit `85d2b01940362000252c07af71f7280cbd369837` documents completion.
- `synq-internal` commit `dfb332f8ea69d13599a29883d729f67fee87223e` documents later end-to-end verification.

Preservation result:

- no current organization repository resolves `b8ec31dd` through the commit API;
- no current remote branch named `fix/synq-admission-chain-migration` was found;
- no Val4 Git object database under `/home/node/Synergy-Network` contains that abbreviated commit;
- GitHub commit search finds only the documentary reference, not the implementation object.

**State: CRITICAL PRESERVATION BLOCKER.** Recover the full commit object or a verifiable patch from AJ's clone/reflog, a Git bundle, CI workspace/artifact, deleted-branch recovery, or another clone. Record its full SHA and create a durable protected ref before any consolidation or archival decision.

### Forge `feature/self-hosted-basepath`

The branch exists remotely at `2220da77702bf48a55d77982a616e61533f7f11c` and is the head of open PR #1. Relative to `forge-v3/main`, GitHub reports:

- status: diverged;
- 117 commits ahead;
- 16 commits behind;
- merge base: `9ecb72cd3990927761670069b9c0d02b165c6852`;
- all 117 compare commits attributed to `AlanJHancock`.

The branch includes commit `9c5bda8b251e886f0c783a3767e2aa1a73bcda5d` (opt-in legacy RPC-chain allowance used for isolated loopback verification) and subsequent RPC-console work through the current branch head.

**State: independently preserved, not merged, not safe to archive.** Resolve PR #1 with a reviewed reconciliation against current `main`; do not squash or delete the source branch until an immutable pre-reconciliation tag/bundle and commit crosswalk exist.

### Required-field AJ change records

#### `f3857b96e5798bd2880867bec0960b51af9892e2`

- **SOURCE_REPOSITORY:** `synergy-network-hq/testnet`
- **SOURCE_BRANCH:** `phase3-contract-addr-snts01-proto`
- **FULL_SOURCE_SHA:** `f3857b96e5798bd2880867bec0960b51af9892e2`
- **SUBJECT:** real AIVM U256 support across opcode, arithmetic/comparison, ABI, and argument decoding
- **FILES_CHANGED:** `SynQ/aivm/src/{abi,host,instructions,vm}.rs`, `SynQ/aivm/tests/{execution_test,u256_test}.rs`, `SynQ/compiler/src/aivm_codegen.rs`, `SynQ/compiler/tests/aivm_integration_test.rs`, `SynQ/synq-server/src/aivm_handler.rs`
- **FUNCTIONAL_PURPOSE:** remove the u128 cap and silent truncation/inconsistent decoding from the production AIVM path
- **REACHABLE_FROM_GITHUB_BRANCH:** yes, via `phase3-contract-addr-snts01-proto`
- **PRESENT_IN_OTHER_REPOSITORY:** exact equivalent not proven; current SynQ/AIVM snapshots are divergent
- **TARGET_CANONICAL_REPOSITORY:** `synq-language`
- **TARGET_PATH:** `aivm/`, `compiler/`, and `synq-server/` corresponding paths
- **CONFLICTS:** later compiler/server changes and the separate `synergy-aivm` repository must be reconciled
- **RECOMMENDED_PORT_METHOD:** preserve the three-commit chain and authorship on a dedicated `synq-language` reconciliation branch; use path-aware cherry-pick or `git format-patch`/`git am`, not a manual copy

#### `7bf7dd65bba48223c862a4656690817f1fb3f1f1`

- **SOURCE_REPOSITORY:** `synergy-network-hq/testnet`
- **SOURCE_BRANCH:** `phase3-contract-addr-snts01-proto`
- **FULL_SOURCE_SHA:** `7bf7dd65bba48223c862a4656690817f1fb3f1f1`
- **SUBJECT:** widen AIVM asset-ledger values to U256 and prevent silent u64 literal wraparound
- **FILES_CHANGED:** `SynQ/aivm/src/host.rs`, `SynQ/compiler/src/aivm_codegen.rs`, `SynQ/compiler/tests/aivm_integration_test.rs`, `SynQ/synq-server/src/aivm_handler.rs`
- **FUNCTIONAL_PURPOSE:** make asset/value handling consistent with the preceding U256 implementation
- **REACHABLE_FROM_GITHUB_BRANCH:** yes, via `phase3-contract-addr-snts01-proto`
- **PRESENT_IN_OTHER_REPOSITORY:** exact equivalent not proven
- **TARGET_CANONICAL_REPOSITORY:** `synq-language`
- **TARGET_PATH:** corresponding AIVM/compiler/server paths
- **CONFLICTS:** depends on `f3857b96`; must follow it and reconcile later ledger/schema changes
- **RECOMMENDED_PORT_METHOD:** port immediately after `f3857b96` with original authorship and parent-order recorded

#### `8d1479835175d2ab3ae732c097beac0658ff3ba3`

- **SOURCE_REPOSITORY:** `synergy-network-hq/testnet`
- **SOURCE_BRANCH:** `phase3-contract-addr-snts01-proto`
- **FULL_SOURCE_SHA:** `8d1479835175d2ab3ae732c097beac0658ff3ba3`
- **SUBJECT:** propagate `require()`/revert text through `TrapMsg`
- **FILES_CHANGED:** `SynQ/aivm/src/{instructions,vm}.rs`, `SynQ/compiler/src/aivm_codegen.rs`, `SynQ/synq-server/src/aivm_handler.rs`
- **FUNCTIONAL_PURPOSE:** preserve actionable revert reasons from compiler through VM and server responses
- **REACHABLE_FROM_GITHUB_BRANCH:** yes, via `phase3-contract-addr-snts01-proto`
- **PRESENT_IN_OTHER_REPOSITORY:** exact equivalent not proven; Forge contains downstream display work but not this source implementation
- **TARGET_CANONICAL_REPOSITORY:** `synq-language`
- **TARGET_PATH:** corresponding AIVM/compiler/server paths
- **CONFLICTS:** downstream response schemas and Forge consumers must retain compatible fields
- **RECOMMENDED_PORT_METHOD:** port as the third commit in the source chain, then separately crosswalk downstream Forge changes

#### `b8ec31dd` (unresolved)

- **SOURCE_REPOSITORY:** documentary evidence indicates `synergy-network-hq/testnet`; not cryptographically resolved
- **SOURCE_BRANCH:** reported as `fix/synq-admission-chain-migration`; branch no longer available
- **FULL_SOURCE_SHA:** **UNKNOWN — CRITICAL PRESERVATION BLOCKER**
- **SUBJECT:** AIVM bitwise/shift opcodes and compiler lowering
- **FILES_CHANGED:** reported `aivm/src/{instructions,vm,gas}.rs`, `compiler/src/aivm_codegen.rs`, `aivm/tests/bitwise_test.rs`, and compiler codegen tests
- **FUNCTIONAL_PURPOSE:** add native `AND`, `OR`, `XOR`, `SHL`, `SHR`, and synthesized complement semantics for U256 AIVM execution
- **REACHABLE_FROM_GITHUB_BRANCH:** no current branch/ref found
- **PRESENT_IN_OTHER_REPOSITORY:** not proven; documentation is present, implementation commit is not
- **TARGET_CANONICAL_REPOSITORY:** `synq-language`
- **TARGET_PATH:** AIVM/compiler/test paths above
- **CONFLICTS:** cannot assess accurately without the original object; later code may contain partial/equivalent changes
- **RECOMMENDED_PORT_METHOD:** recover the original full object first; then preserve via branch/tag and apply with authorship. Do not reconstruct from prose unless AJ confirms an independently reviewed patch is equivalent.

#### Forge `feature/self-hosted-basepath` range

- **SOURCE_REPOSITORY:** `synergy-network-hq/forge-v3`
- **SOURCE_BRANCH:** `feature/self-hosted-basepath`
- **FULL_SOURCE_SHA:** head `2220da77702bf48a55d77982a616e61533f7f11c`; merge base `9ecb72cd3990927761670069b9c0d02b165c6852`
- **SUBJECT:** 117 AJ-authored commits covering self-hosted base paths, SynQ compiler refresh, ForgeIDE, wallet/deep-link flows, diagnostics, dry-run/RPC behavior, and UI fixes
- **FILES_CHANGED:** branch-wide compare; preserve GitHub PR #1 as the authoritative file/change list
- **FUNCTIONAL_PURPOSE:** the current AJ Forge development line, including loopback-only legacy RPC allowance `9c5bda8b251e886f0c783a3767e2aa1a73bcda5d`
- **REACHABLE_FROM_GITHUB_BRANCH:** yes
- **PRESENT_IN_OTHER_REPOSITORY:** some older Forge work exists in `synergy-forge`, but branch equivalence is not proven
- **TARGET_CANONICAL_REPOSITORY:** `forge-v3`
- **TARGET_PATH:** existing Forge application paths
- **CONFLICTS:** branch is 16 commits behind and 117 ahead of `main`
- **RECOMMENDED_PORT_METHOD:** create an immutable pre-merge tag/bundle, reconcile `main` into a review branch, preserve individual authorship, and merge through PR #1 without squash; retain the source branch until deployed equivalence is separately proven

## Canonical target repository matrix

| Responsibility | Canonical target | Sources to reconcile | Core Protocol allowance | Retirement candidates after proof |
|---|---|---|---|---|
| Core protocol and networks | rename `testnet-v3` to `core-protocol` after default-branch cutover | preserved Core Protocol branch plus required legacy `testnet` history/artifacts | owns node-platform, network manifests, protocol integration, and thin external-component adapters | `testnet` only after release/tag preservation and history crosswalk; historical archived repos remain immutable |
| SynQ language/compiler/VM including AIVM | `synq-language` | `testnet/SynQ`, Core Protocol `runtime/synq-language`, `synergy-aivm`, `synq-internal` implementation-relevant records, AJ commits | thin `synergy-synq`/execution adapters only; no second compiler or VM | `synergy-aivm` and `synq-internal` after history/docs import and proof; copied runtime implementation becomes reference-only then removed |
| Aegis cryptography engine and modules | rename `aegis-pqvm` to `aegis`, then history-import `aegis-pqsynq` | both Aegis repos plus Core Protocol PQVM/PQSynQ imports and legacy runtime/vendor variants | thin `synergy-aegis` provider adapter and `synergy-crypto` public facade; no independent primitives | `aegis-pqsynq` after history-preserving import; Core/legacy copied engines after dependency cutover |
| Forge | `forge-v3` | `feature/self-hosted-basepath`, `feature/synq-v3-compiler-refresh`, recovery/archive branches, relevant `synergy-forge` history | none | `synergy-forge` after functional/history crosswalk and approved archive |
| Internal development records | canonical product repo `docs/internal/` where access policy permits, otherwise one clearly non-source private records repo | `synq-internal` and similar report-only repos | documentation references only | duplicate records repos after immutable export and approval |

## SynQ consolidation and AIVM ownership decision

**Decision proposed for approval:** AIVM is an intrinsic SynQ execution backend and belongs in the canonical `synq-language` repository. The compiler, ABI, bytecode/opcodes, VM semantics, server handler, and their tests evolve together; separating the authoritative VM from the language/compiler has already produced drift and missing-commit risk.

`synergy-aivm` may contribute runtime-host integration code during reconciliation, but it must not remain a competing implementation repository. Core Protocol retains only protocol/service adapters that invoke versioned SynQ/AIVM APIs. `synq-internal` content should be imported as private engineering records or preserved as a records-only repository until access-policy and history import are approved.

## Aegis/PQVM/PQSynQ consolidation decision

**Decision proposed for approval:** one canonical `aegis` repository owns the Aegis engine, `aegis-pqvm`, `aegis-pqsynq`, their vendored cryptographic dependencies, vectors, conformance evidence, and release provenance. Preserve existing PQVM history by renaming `aegis-pqvm` rather than creating a historyless repository, then import `aegis-pqsynq` with a history-preserving subtree merge.

Core Protocol's `synergy-aegis` remains a thin integration/provider boundary and `synergy-crypto` remains a public facade. Neither may own duplicate PQVM/PQSynQ primitives. Release consumption should use a pinned Cargo Git/release dependency plus checksums/SBOM; generated offline vendor bundles are build artifacts, not a second editable source owner.

## Forge reconciliation decision

`forge-v3` is the sole target. Before PR #1 reconciliation, create an immutable ref/bundle for `feature/self-hosted-basepath`. Reconcile the 16 `main` commits into a review branch, preserve all 117 AJ commits, run the later verification gate, merge without squash, and retain the original branch until deployment equivalence is proven. `synergy-forge` remains preserved until its unique history and functionality are mapped.

## Core Protocol/testnet rename and default-branch strategy

1. Keep `reconcile/core-protocol-root-2026-09-15` as the immutable preservation line during review.
2. Resolve open old-root PRs and identify any remote `main` commits newer than the preservation branch's starting point.
3. After CTO approval, create a reviewed cutover branch whose tree matches the organized Core Protocol root; do not rewrite existing `main` history.
4. Merge by normal reviewed merge commit, change the default branch only after required checks, then rename the GitHub repository from `testnet-v3` to `core-protocol` with redirects retained.
5. Keep `testnet` as the legacy release/history authority until all 231 tags, release branches, submodule pins, AJ work, and operational artifacts have an immutable crosswalk. Archive only after approval; never delete.

## Submodule retirement

The current submodule graph is provenance-bearing and stays untouched during reconciliation. Retirement sequence:

1. advance and verify the existing pins in dedicated branches;
2. port unique work to canonical repositories;
3. replace Core Protocol/testnet submodules with versioned package/Git dependencies or signed release artifacts;
4. record old pin SHA → new canonical release SHA in the crosswalk;
5. remove submodule entries only after reproducible builds and integration tests pass;
6. retain tags/bundles that reproduce the last submodule-based build.

## Source-SHA to canonical-SHA tracking strategy

Create a tracked `docs/repository-consolidation/SOURCE_SHA_CROSSWALK.csv` in each target repository with fields: source repository, source branch, full source SHA, author, subject, source paths, canonical repository, canonical SHA, canonical paths, port method, conflicts, verification evidence, reviewer, and disposition. Every cherry-pick/subtree import must include `-x` or an equivalent `Source-SHA:` trailer. A source change is not “accounted for” until both Git ancestry/patch identity and functional verification are recorded.

## Exact future migration sequence

1. Recover `b8ec31dd` and create durable refs for all AJ source lines.
2. Export signed Git bundles/ref manifests for every branch/tag selected for reconciliation.
3. Reconcile SynQ/AIVM into `synq-language`, preserving commits and adding the SHA crosswalk.
4. Reconcile Aegis PQVM/PQSynQ into the history-preserving `aegis` target.
5. Reconcile Forge PR #1 and `synergy-forge` unique history into `forge-v3`.
6. Cut Core Protocol consumers over to versioned canonical SynQ and Aegis dependencies; remove editable duplicate implementations only after verification.
7. Reconcile `testnet` release/history artifacts and execute the `testnet-v3` → `core-protocol` default-branch/repository rename.
8. Run archive readiness reviews repository by repository; obtain Justin's explicit approval for each archive action.

## Verification tests required before consolidation completion

No tests were run during this preservation task. The future gate requires, at minimum:

- Git patch-ID/tree equivalence checks for every imported commit and path;
- SynQ compiler, AIVM opcode/ABI/U256/revert, server-handler, deterministic bytecode, and signed-carrier integration tests;
- Aegis PQVM/PQSynQ vectors, KAT/ACVP evidence, engine/facade dependency-direction checks, and consumer integration tests;
- Core Protocol builds and focused execution/cryptography integration tests against pinned canonical dependencies;
- Forge build/test suite, base-path deployment, wallet/deep-link, RPC allowlist, compiler bundle hash, and visual/live acceptance checks;
- full secret/license/SBOM scans and reproducible release provenance for each canonical repository.

## Archive sequence and rollback

Archive order, only after explicit approval: records-only duplicates → `synergy-aivm` → `aegis-pqsynq` → `synergy-forge` → legacy `testnet` last. Before each archive: protect tags, publish a signed bundle and SHA manifest, record redirects/consumers, disable writes, and observe a hold period. Rollback is to unarchive the untouched source repository, restore the last dependency pin/default branch from the recorded manifest, and redeploy the last signed release; no source branch is deleted during the hold period.

## Decisions requiring Justin approval

- approve AIVM as intrinsic to `synq-language`;
- approve renaming `aegis-pqvm` to the single canonical `aegis` repository and history-importing PQSynQ;
- approve the Forge PR #1 reconciliation method and no-squash history rule;
- approve the Core Protocol default-branch cutover and repository rename;
- choose private-record placement for `synq-internal`;
- approve each individual repository archive after evidence review;
- decide whether missing `b8ec31dd` can ever be reconstructed if the original object cannot be recovered (current recommendation: no archive until recovered).

## Final expected canonical repository list

The end state retains one source owner per product: `core-protocol`, `synq-language` (including AIVM), `aegis` (including PQVM/PQSynQ), `forge-v3`, and one canonical repository for each independently owned product already in the organization (Wallet, website, control panel, Atlas, design system, contracts, security, and release-only repositories). Historical repositories remain archived/read-only with immutable tags/bundles, not deleted. No Core Protocol subtree may independently evolve another SynQ compiler/VM or Aegis cryptographic engine.

## Organization-wide repository register

This is the complete GitHub organization repository list returned during the inventory. “Active” means GitHub's archive flag is false; it does not assert runtime or product activity.

| Repository | Visibility | GitHub state | Default branch | Last pushed (UTC) |
|---|---|---|---|---|
| `01-testnet` | private | archived | `main` | 2025-10-01 |
| `As-Built-Docs-Checklists` | private | active | `main` | 2026-09-03 |
| `aegis-pqsynq` | private | active | `main` | 2026-09-03 |
| `aegis-pqvm` | private | active | `main` | 2026-08-31 |
| `atlas-v3` | private | active | `main` | 2026-09-03 |
| `contracts_and_programs` | private | active | `main` | 2025-11-20 |
| `devnet-binary` | private | archived | none | 2025-12-13 |
| `devnet-node-config-templates` | private | archived | `main` | 2025-12-27 |
| `forge-v3` | private | active | `main` | 2026-09-15 |
| `node-control-panel` | private | archived | `main` | 2026-03-02 |
| `project-rosetta` | private | active | `main` | 2026-09-03 |
| `protocol-documentation` | private | active | `main` | 2026-09-03 |
| `sam-tool` | private | active | `main` | 2026-06-05 |
| `security` | private | active | `main` | 2026-06-07 |
| `snrg-presale-staking-contracts` | public | active | `main` | 2026-09-03 |
| `synergy-address-engine` | private | active | `main` | 2026-08-31 |
| `synergy-aivm` | private | active | `main` | 2026-09-14 |
| `synergy-atlas` | private | active | `main` | 2026-09-03 |
| `synergy-design-system` | private | active | `main` | 2026-09-03 |
| `synergy-devnet` | private | archived | `main` | 2026-03-11 |
| `synergy-engineering-labs` | private | active | `main` | 2026-07-10 |
| `synergy-forge` | private | active | `main` | 2026-09-03 |
| `synergy-horizon` | private | active | `main` | 2026-09-03 |
| `synergy-keystone` | private | active | `main` | 2026-09-03 |
| `synergy-keystone-native` | private | active | `main` | 2026-09-03 |
| `synergy-learn` | private | active | `main` | 2026-09-03 |
| `synergy-network-old` | private | archived | `main` | 2025-07-17 |
| `synergy-network-testnet` | private | archived | `main` | 2025-10-08 |
| `synergy-node-control-panel` | private | active | `main` | 2026-09-09 |
| `synergy-node-control-panel-releases` | public | active | `main` | 2026-07-29 |
| `synergy-portal` | private | active | `main` | 2026-09-03 |
| `synergy-prism` | private | active | `main` | 2026-09-03 |
| `synergy-project` | private | archived | `main` | 2025-08-22 |
| `synergy-quest` | private | active | `main` | 2026-09-03 |
| `synergy-relay` | private | active | `main` | 2026-09-03 |
| `synergy-spark` | private | active | `main` | 2026-04-26 |
| `synergy-sts-cli-releases` | public | active | `main` | 2026-07-07 |
| `synergy-vault` | private | active | `main` | 2026-09-03 |
| `synergy-wallet` | private | active | `main` | 2026-09-05 |
| `synergy-website-v3` | private | active | `main` | 2026-09-13 |
| `synergy-wts-releases` | public | active | `main` | 2026-04-30 |
| `synq-internal` | private | active | `main` | 2026-09-14 |
| `synq-language` | private | active | `main` | 2026-09-03 |
| `testnet` | private | active | `main` | 2026-09-12 |
| `testnet-beta` | private | archived | `main` | 2026-05-24 |
| `testnet-node` | private | archived | none | 2025-10-05 |
| `testnet-v3` | public | active | `main` | 2026-09-15 |

## Proposed future consolidation sequence

No step below is authorized by this plan; each requires CTO review and a separate execution decision.

1. Recover and durably reference `b8ec31dd`; create a full-SHA evidence record.
2. Create immutable preservation refs/bundles for the AJ Testnet chain and Forge feature branch before any merge or branch deletion.
3. Reconcile open PRs and recovery/archive branches in `synergy-aivm`, `aegis-pqsynq`, and `forge-v3`.
4. Decide authoritative ownership for SynQ, AIVM, PQVM, and PQSynQ at repository and subtree granularity; produce path-level commit/patch crosswalks for every differing file.
5. Decide whether Core Protocol should consume independent repositories through pinned dependencies/submodules, vendored snapshots with provenance manifests, or a true monorepo import preserving history. Do not mix models implicitly.
6. Reconcile the legacy `testnet` submodule pins with current canonical repository heads and prove compatibility before changing pins.
7. Only after equivalence and provenance are proven, mark superseded repositories read-only. Archive later; never delete merely because a copy appears in Core Protocol.
8. Keep release repositories and historical/incident evidence outside source-consolidation decisions unless separately inventoried and approved.

## CTO review gates

- **Approve preservation only:** keep all current repositories/branches unchanged and recover the missing commit.
- **Approve reconciliation design:** choose the canonical dependency/import model for SynQ/AIVM/Aegis and authorize path-level crosswalk work.
- **Do not approve archival yet:** the missing commit, divergent Forge branch, open PRs, lagging submodule pins, and file-level drift are unresolved.
