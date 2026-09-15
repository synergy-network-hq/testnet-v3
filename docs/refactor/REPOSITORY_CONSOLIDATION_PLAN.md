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
