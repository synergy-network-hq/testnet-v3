# PoSy v3 ProtectedPipeline protocol contract

Status: implementation contract for the Chain 1266 `posy/3.0` R11 migration.

## Ownership boundary

PoSy is the only BFT consensus, view-change, and finality engine. It owns block
proposal validity, validation certificates (VCs), finality votes, quorum
certificates (QCs), view changes, and committed execution state.

ETDAG is a deterministic encrypted-data pipeline. It ingests encrypted
transactions, verifies availability certificates (VACs), accepts authenticated
cutoff markers, derives one semantic cut and deterministic ordering, prepares
reveal material, and supplies the exact protected execution input required by
PoSy. ETDAG does not elect a batch leader, run a batch round, or decide a batch
through a second BFT protocol.

`ProtectedPipeline` is the single per-validator owner of ETDAG progress. Each
target height has one atomic, monotonic durable record and advances through:

`COLLECTING -> CUTOFF_READY -> CUT_READY -> ORDER_READY -> COMMITTED_IN_PARENT -> REVEAL_AUTHORIZED -> REVEALING -> READY_FOR_EXECUTION -> CONSUMED`.

Startup, validated evidence, consensus events, and a bounded reconciliation
tick all invoke the same idempotent transition function. Messages add evidence;
they do not own lifecycle progression.

## Evidence and deterministic derivation

VAC remains threshold-authenticated availability evidence. It is bound to the
chain, technical network `testnet`, incarnation/epoch, target height, target
context, governed parameter root, frozen validator set/cluster, exact encrypted
vertex, and authenticated validator signatures. Insufficient or invalid VAC
evidence fails closed.

Authenticated quorum cutoff markers replace a DCC voting round. Given a valid
target context, certified vertices, and valid quorum marker evidence, every
validator computes the same causal closure, eligible encrypted-envelope set,
semantic `CutRoot`, and `ProtectedCutProof`. The semantic roots exclude
incidental message arrival order and the particular encoding/order of a valid
signer subset; the proof-evidence root may bind the exact canonical evidence
bundle. The causal-closure root contains transaction ancestors, not marker
vertices: authenticated marker digests remain separately bound as cutoff
evidence so different valid 4-of-5 marker subsets cannot change `CutRoot`. A
marker bundle that cannot prove a complete deterministic cut is not ready and
cannot be substituted with an empty batch.

The durable audit record retains the exact marker-evidence proof root. The
PoSy-visible next-batch commitment does not bind that subset-specific root; it
binds the semantic `CutRoot`, eligible-set, order and protected-batch roots so
validators that observed different valid quorum subsets still propose and
validate one identical commitment.

`derive_protected_batch` sorts and deduplicates governed inputs canonically and
uses only the target height, semantic cut, eligible encrypted envelopes,
PoSy-derived ordering seed, gas/byte/capacity policy, protocol parameter root,
chain/network/epoch, cluster, and validator-set context. Wall clock, local RNG,
map iteration order, arrival order, and local cache contents are forbidden
inputs. Its output commits the exact ordered IDs, counts, resource totals, and
all protocol bindings.

The parent PoSy proposal carries `NextProtectedBatchCommitment` for the target
execution height. The proposer has no discretion: every validator derives the
required value independently and rejects a missing or unequal commitment.
The commitment binds target height, `CutRoot`, eligible-set root, order seed and
root, protected-batch root, count/gas/bytes, parameter root,
protocol version, chain/network/epoch, cluster, and validator-set commitment.

## Target admission

`TARGET_ADMISSION: REDUCED`

Reason: the current H+3 context supplies security bindings that VAC, cutoff,
and proposal validation still require, but its independent vote collector,
certificate producer, cache, retry worker, and durable whole-file lifecycle
duplicate quorum evidence supplied by VAC/markers. The governed deterministic
target context remains; separate steady-state target-admission package
consensus does not. If a transition cannot derive that context from finalized
PoSy state and governed roots, protected ingress remains closed.

## Eliminated active stages

DCC proposal/vote/certificate assembly, `BATCH_PROPOSAL`, `BATCH_VALIDATE`, BVC,
`BATCH_FINALITY`, BOC, `BATCH_TIMEOUT`, BTC, batch leaders, batch rounds, and
batch-specific view changes are not production liveness dependencies. Legacy
decoding may remain temporarily during migration, but legacy artifacts neither
authorize reveal nor satisfy proposal validity.

## Height and reveal semantics

The governed ETDAG look-ahead is exactly three heights. Genesis is finalized
height H0 and can derive the first normal target context for H3.

- H1 uses a Genesis-bound, protocol/version/parameter-bound empty protected
  batch. It contains zero ordinary user transactions and proceeds through
  normal PoSy proposal, VC, QC, and finality.
- H2 uses the same bootstrap rule with a distinct height-bound root.
- H3 is the first normal ETDAG target derived from the finalized H0 boundary.
  Its deterministic protected-batch commitment is fixed in the required parent
  PoSy flow before reveal.
- H4 is steady-state normal ETDAG, and H5+ repeats the same pipeline.

Bootstrap is permitted only for the minimal H1-H2 window. A later missing cut,
batch, commitment, or reveal is a hard not-ready condition, never permission to
propose an empty or plaintext block.

The current simplified PoSy profile already signs `ECHO` only after complete
local proposal/material validation and requires `n-1` authenticated ECHOs
before READY. R11 names the canonical `n-1` ECHO proof the PoSy proposal
validation certificate (VC); it does not add another message, leader, vote
round, timeout, or finality system. Proof bundles may contain different valid
signer subsets, while their semantic identity is the stable candidate ID.

Reveal for target H is authorized only after that PoSy VC for the parent
proposal has independently validated the exact `NextProtectedBatchCommitment`
for H. A VC for another proposal, view, parent, target, or commitment does not
authorize reveal. READY delivery without the validating ECHO quorum is not a
reveal certificate. Reveal shares remain authenticated, replay-bound, and
secret until the gate. Decryption and execution are deterministic, and the
resulting execution commitment remains bound into the one ordinary PoSy vote
and QC finality.

## Recovery and diagnostics

Durable state transitions are atomic, monotonic, restart-safe, and idempotent.
Conflicting valid semantic roots, rollback attempts, weakened quorum evidence,
or invalid cryptography fail closed and surface a safety/liveness diagnostic.
Recovery reloads the one target-height record, merges independently verified
evidence, requests missing semantic objects with bounded deduplication, and
reconciles until the next legal phase. It never deletes safety journals, lowers
quorum, exposes plaintext, or makes the control plane an authority.

Every validator exposes a read-only per-height diagnostic containing target
height, pipeline phase, availability and marker counts, cut/order/commitment/
reveal/execution readiness, proposal/VC/QC observation, and finalization. The
Node Control Panel consumes this schema but is not required for consensus.
