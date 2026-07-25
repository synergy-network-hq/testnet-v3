# Validator Self-Heal And PoSy Cluster Hardening PR Checklist

## Topology And Quorum

- [x] No protocol logic hard-codes six validators, `4-of-6`, `6/6`, or Val1-Val6
      as permanent topology.
- [x] Current six-validator references are limited to current-live fixtures,
      regression tests, or incident runbooks.
- [x] Quorum is derived from active validator count and BFT safety rules.
- [x] Expanded single-cluster, two-cluster, three-cluster, and future cluster
      expansion cases are covered or explicitly tracked.
- [x] `scripts/testnet/check-no-hardcoded-validator-topology.sh` passes.

## State Safety

- [x] `synergy-node validator inspect-state` reports expected files and digests.
- [x] `synergy-node validator verify-state` passes on relevant fixtures.
- [x] Migration dry-run is exercised with
      `synergy-node validator migrate-state --dry-run`.
- [x] Derived-index rebuild dry-run is exercised with
      `synergy-node validator rebuild-derived-indexes --dry-run`.
- [x] `synergy-node validator state-sync repair --dry-run|--apply` is exercised
      only against marker-gated offline fixture workspaces.
- [x] Tests cover missing compact boundary, stale/body-behind locks,
      duplicate/conflicting blocks, corrupted committed QC JSONL, root-owned state
      files, and partial migration.
- [x] Compacted state requires `state_checkpoint.json`, and checkpoint
      height/hash/digests agree with body, canonical lock, and committed QC.
- [x] State-sync repair tests cover receipt writing, backup creation,
      derived-index rebuild, minority/public-RPC/Atlas/archive-contained
      rejection, body-behind-lock repair, 602192/602435 fork fixtures, Val1
      missing-QC fail-closed behavior, and interrupted repair rollback safety.

## Self-Heal And Rejoin

- [x] Quarantine, self-heal, vote-only rejoin, and active promotion transitions
      are deterministic and restart-safe.
- [x] Validator supervisor classification covers divergence, compact-boundary
      gaps, digest mismatch, qRPC/metrics degradation, verified state sync,
      vote-only probation, and fail-closed terminal states.
- [x] `synergy-node validator supervisor-transition` preserves failed-closed
      state and blocks direct recovery-state-to-active promotion without
      vote-only rejoin proof.
- [x] `synergy-node validator supervisor-write --dry-run|--apply` writes only
      marker-gated offline workspace state atomically, backs up previous state,
      and rejects stale evidence, malformed previous state, non-monotonic
      sequence, and unsafe duty gates.
- [x] Vote-only probation writes proposer probation before active promotion, and
      proposer probation cannot propose until promotion proof passes.
- [x] Non-validator roles cannot count toward validator quarantine or rejoin
      quorum.
- [x] Malicious, stale, divergent, or quarantined peers are rejected as repair
      sources.
- [x] State-sync repair refuses missing body/QC/lock proof and never fabricates
      QC evidence.
- [x] Rejoin does not lower quorum or bypass finality proof.

## Community Onboarding

- [x] `synergy-node validator onboarding-preflight` rejects wrong chain/network,
      duplicate identity, insufficient stake, bad key-role proof, NAT/P2P
      failure, missing cluster assignment, and missing rollback plan.
- [x] `synergy-node validator onboarding-bundle` emits only dry-run manifests
      with `.example` operator-editable config paths and no secrets.
- [x] `synergy-node validator onboarding-dry-run-join` rejects finalized-head,
      high-QC, config digest, validator-set digest, and binary digest mismatch
      before vote-only rejoin.
- [x] `synergy-node validator enrollment-token verify` rejects expired, revoked,
      wrong-chain, wrong-network, wrong-scope, or signature-unverified tokens.
- [x] `synergy-node validator package verify` rejects NO-GO artifacts, packages
      with secrets, missing digests, and archive snapshot dependencies.
- [x] `synergy-node validator identity-bundle verify` rejects missing backup
      proof and unverified key-role proofs without creating live keys.
- [x] `synergy-node validator cluster-assignment preview` derives dynamic quorum
      from planned validator count and rejects unsafe assignments without fixed
      six-validator assumptions.
- [x] `synergy-node validator activation-eligibility` blocks observer/vote-only
      proposer duties, requires proposer probation before active, rejects
      archive-contained dependency and missing state proof, and allows activation
      only with a clean proof chain.

## Archive Containment

- [x] Archive validator remains disabled/offline unless canonical reseed gates
      pass.
- [x] Archive snapshots are not used for validator recovery before canonical
      reseed verification.
- [x] Snapshot publication remains fail-closed for noncanonical proof.
- [x] `docs/runbooks/archive-canonical-reseed.md` is followed for any archive
      reseed work.
- [x] `synergy-node archive reseed-plan` remains dry-run-only and rejects
      validator-pruned/support manifests, enabled archive services, and enabled
      archive publication.
- [x] `synergy-node archive status`, `verify-canonical`, `reseed --dry-run`,
      `publish-snapshot --dry-run`, `list-unsafe-snapshots`,
      `mark-unsafe-snapshot`, and `quarantine-snapshot` keep archive services,
      snapshot API, and snapshot worker disabled and mutate no live data.
- [x] Archive safety tests cover h602192 noncanonical containment, h537712
      archive-full mismatch rejection, h601891 validator-pruned support proof,
      noncanonical snapshot-worker refusal, unsafe snapshot API refusal, enabled
      services rejection, and dry-run action output.

## Public RPC And Atlas

- [x] Public RPC never serves synthetic height or unverified backend data.
- [x] Atlas backend handles backend mismatch, lag, and unavailable source data
      fail-closed.
- [x] Exact-height Atlas block hash matches public RPC for sampled finalized
      heights.
- [x] qRPC, metrics, and indexing reads cannot block consensus mutation paths.
- [x] qRPC status/block-number/node-info reads return explicit fail-closed
      metadata when consensus chain state is busy instead of blocking or
      fabricating height.
- [x] `synergy-node fleet status --strict` fails closed on public RPC/Atlas
      mismatch, synthetic height, inactive validators, and dynamic cluster quorum
      failures without assuming six validators.
- [x] `synergy-node fleet status --strict` emits per-backend confidence fields
      for backend id, role, cluster id, finalized/observed head, config digest,
      validator-set digest, binary digest, lifecycle state, qRPC status, lag,
      hash agreement, canonical confidence, read/repair trust, and exclusion
      reasons.
- [x] Stale, minority-fork, quarantined, and archive-contained backends are
      excluded from trust, and public RPC timeouts are recorded as surface jitter
      rather than chain failure.
- [x] Two-cluster and future-cluster public summaries report dynamic cluster
      status independently.

## Tests And CI

- [x] `cargo fmt -p synergy-testnet -- --check`
- [x] `cargo check -p synergy-testnet --bin synergy-node`
- [x] Focused Rust tests for changed consensus/state/validator paths.
- [x] Relevant Python tests or `python3 -m py_compile` for changed Python.
- [x] `bash -n` for changed shell scripts.
- [x] `scripts/testnet/validate-testnet.sh`
- [x] `scripts/testnet/check-no-hardcoded-validator-topology.sh`
- [x] `scripts/testnet/check-prompt2-offline-gates.sh`
- [x] `synergy-node chaos run` scenarios cover stop-one/stop-two/stop-three,
      2/6 and 3/6 network partitions, expanded n=7/n=10/n=13 partition fixtures,
      crash mid-block append, crash between QC append and lock write, corrupt
      canonical lock, corrupt `committed_qcs.jsonl`, disk-full write failure,
      divergence, state corruption, public surface fail-closed, Atlas mismatch,
      archive contamination containment, qRPC/metrics degradation, bad
      checkpoint rejoin, delayed-QC rejoin, unsafe-QC rejection, no quorum
      lowering, and no permanent quarantine without persistent evidence.
- [x] Secret scan confirms no workbooks, passwords, SSH private material, raw SSH
      configs, `.env` files, or production logs are staged.

## Documentation And Architecture

- [x] Runbooks explicitly forbid manual JSON/JSONL consensus repair.
- [x] Runbooks document state-sync repair and supervisor state flow as the
      replacement for manual recovery surgery.
- [x] Archive docs require canonical reseed before archive use and keep archive
      services, snapshot API, and snapshot worker disabled until that gate
      passes.
- [x] Architecture docs state that the current six validators are not final
      topology and validator/cluster counts are dynamic.
- [x] Release docs require explicit authorization before live deploy/restart/
      mutation, one-validator-at-a-time rollout, quorum-margin preservation, and
      health proof for rollback success.
- [x] Required docs exist: emergency recovery, state-store migration,
      state-sync, protocol state-sync repair, supervisor state machine,
      checkpoint hardening, qRPC isolation, strict fleet status, archive reseed,
      community onboarding, public RPC/Atlas backend safety, release rollout,
      dynamic clusters, PoSy lifecycle, validator appliance runtime, and this
      checklist.

## Rollout

- [x] This PR does not deploy to live validators by itself.
- [x] Future live rollout follows
      `docs/runbooks/future-validator-runtime-rollout-plan.md`.
- [x] Rollback path and rollback binary digest are documented before any future
      deployment.
- [x] Final handoff includes commit SHAs, test evidence, live read-only RPC/Atlas
      evidence if sampled, and explicit remaining risks.

## Final Closeout Mapping

Canonical Prompt 2 requirement mapping, verification results, live public-read
evidence, remaining limitations, and Control Panel handoff decision are recorded
in `outputs/prompt2-final-pr-readiness-report.md`.

Final branch-head verification passed with 728 library tests, Prompt 2 offline
gate PASS, topology guard PASS, Testnet validation PASS, archive Python tests
PASS, all changed shell scripts passing `bash -n`, chaos CLI fixtures passing,
and staged secret scans clean before each closeout commit.
