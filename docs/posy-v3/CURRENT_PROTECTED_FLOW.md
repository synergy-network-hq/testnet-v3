# Current protected-flow map and R11 collapse decision

Baseline: `a732bc16ff4c5b23561758dad6f05752bd2576c6`

## Exact Block 1 liveness edge

The fresh protected runtime selects `SimplifiedMaterialMode::Protected` for all
heights. Genesis finality is H0, while the independently scheduled target-
admission producer derives only `finalized + 3`, so startup prepares H3.
The H1 proposer asks `SimplifiedProtectedMaterialAdapter` for a complete H1
`ProtectedBlockInput`; none exists, the adapter returns not-ready, and PoSy
emits no proposal. A timeout changes proposer/round but cannot create protected
material.

The repository has definitions and tests for VAC, cutoff markers, DCC, BVC,
BOC, and reveal shares, but no active runtime producer/gossip chain for those
artifacts. Production re-verifies a complete externally received DCC/BVC/BOC
artifact even though `broadcast_etdag_certified_input` has no caller.

## Component decisions

| Current component | Security purpose | Decision | New owner |
|---|---|---|---|
| Target context | H+3 binding to finalized authority, epoch, cluster, validator set, governed parameters, and KEM registry | Retain deterministic bindings; remove separate vote/certificate/worker/store protocol | PRIMARY types, ProtectedPipeline state |
| VAC | Threshold-authenticated encrypted-data availability and replay/nonce authorization | Retain semantics | ProtectedPipeline evidence |
| Cutoff markers | Authenticated close evidence bound to consensus cutoff | Retain semantics | ProtectedPipeline evidence |
| DCC | Quorum markers, causal closure, and complete eligible cut | Replace voting/certificate with deterministic `ProtectedCutProof` | ProtectedPipeline derivation |
| BVC | Certifies an already deterministic ordering | Remove active dependency | Pure deterministic batch function |
| BOC | Certifies the BVC/batch and gates reveal | Remove active dependency | Parent PoSy commitment plus PoSy VC |
| BTC/batch leader/round/view change | Second coordination/failure system | Remove; already inactive except schema residue | Normal PoSy view change only |
| Reveal/decryption | Prevents early plaintext and binds exact execution | Retain threshold/auth/replay safety; replace BOC gate with exact PoSy VC authorization | ProtectedPipeline plus PoSy adapter |
| Protected material adapter | Independently replays input and binds proposal/execution | Retain as the consensus boundary; consume ProtectedPipeline API | PoSy integration |
| H1/H2 bootstrap | No pre-Genesis protected transaction window exists | Add two Genesis-bound empty batches; reject bootstrap at H3+ | Genesis/bootstrap module |
| Target worker and stores | Admission retry/aggregation and duplicate durable state | Collapse into one level-triggered reconciler and one atomic target-height record | ProtectedPipeline |
| Whole certified-input wire | Carries nested DCC/BVC/BOC/reveal artifact | Replace with bounded semantic evidence propagation and missing-object recovery | ETDAG networking |

## Existing call sites to replace

- Target producer and store: `runtime/src/consensus/simplified_posy/target_admission_producer.rs`.
- Target worker/runtime installation: `runtime/src/role_runtime.rs`.
- DCC/BVC/BOC/reveal composite definitions and verification:
  `runtime/src/etdag.rs`.
- Proposal-time protected material gate:
  `runtime/src/consensus/simplified_posy/protected_material.rs`.
- Normal proposal, reliable delivery, vote, QC, and finality:
  `runtime/src/consensus/simplified_posy/driver.rs` and sibling modules.
- Target/whole-artifact wire carriers: `runtime/src/p2p/messages.rs` and
  `runtime/src/p2p/networking.rs`.

## Before counts

| Category | Before | R11 target |
|---|---:|---:|
| Protected-path logical certificate kinds | 6 (VAC, target admission, DCC, BVC, BOC, BTC) | 1 threshold availability family plus deterministic cut proof and normal PoSy VC/QC |
| Actively required obsolete cut/batch certificates | 3 (DCC, BVC, BOC) | 0 |
| Active protected coordination carrier families | 2 (target admission and whole certified input) | 1 bounded semantic-evidence family |
| Relevant production threads | 2 (PoSy driver and target worker) | 1 PoSy driver plus one logical pipeline owner/reconciler, with no second consensus scheduler |
| Coordination-owned mutable durable boundaries | 4 | 1 ProtectedPipeline record store; consensus safety/material/finality stores remain separate |
| Active batch timeout systems | 0 (one dead BTC schema) | 0 |
| Empty protected bootstrap producers | 0 | Deterministic H1/H2 protocol function, not a worker |

## PoSy VC reconciliation

The active simplified profile previously said it had no ordinary VC. It does,
however, already require each authenticated `ECHO` to follow complete local
proposal/material validation and waits for `n-1` ECHOs before READY. R11 names
that existing `n-1` ECHO proof the proposal validation certificate. This adds
no new network phase or timeout system. The VC semantic identity is the stable
candidate ID; its participant proof remains independently verified. Reveal
cannot use a READY-only proof or the inactive legacy typed VC.
