# PoSy v3 minimal deterministic state-machine audit

Status: canonical Phase 1 architecture constraint

This audit freezes mechanism expansion. The implementation may retain only a
mechanism listed below, for the stated invariant and failure scenario. Legacy
wire shape or runtime presence is not independent justification. Any future
mechanism requires a governed specification change and a new safety/liveness
argument.

PoSy authority is the epoch-frozen validator registry. Stake, Synergy Score,
NodeID, VPN, transport-registry membership, Sentry membership, and node role do
not create voting or finality authority.

## Retained mechanisms

| Mechanism | Classification | Exact invariant protected | Exact failure scenario | Why a simpler alternative is insufficient |
| --- | --- | --- | --- | --- |
| Consecutive three-QC finality | REQUIRED SAFETY | A block is finalized only when it is the grandparent of a contiguous certified chain whose parent links and execution commitments agree. | Competing proposals or delayed votes create certified descendants on different rounds; finalizing the newest isolated QC could commit a branch before the locking evidence is deep enough. | A single QC proves quorum support for one proposal, not that later quorum movement preserved its branch. Two-QC finality lacks the currently governed third certified link and cannot be substituted without a new safety proof. |
| Independent validator-count and frozen-weight quorum | REQUIRED SAFETY | Every QC, TC, recovery selection, and membership decision independently satisfies both the minimum validator count and the non-uniform epoch-frozen voting-weight threshold. | A small number of high-weight validators or many low-weight validators attempt to satisfy only one dimension. | Count-only ignores governed non-uniform weights; weight-only permits authority concentration. Combining them into one score loses one of the two explicit thresholds. |
| Timeout certificate | REQUIRED LIVENESS | Round/leader takeover occurs only after a dual-quorum proof that the active round failed to progress. | The selected leader is unavailable, partitioned, or withholds a valid proposal. | Local clocks or unilateral timeout observations let different validators advance independently and can split the active round. |
| Highest-QC proof carriage in timeout votes/certificates | REQUIRED SAFETY | A view change carries independently verifiable evidence for every claimed highest certified parent used to select the safe continuation. | Validators time out with different knowledge of the highest QC, including stale or fabricated claims. | Carrying only a QC identifier forces unverifiable external lookup and permits a takeover decision to depend on missing or conflicting data. |
| Deterministic timeout carry-forward | REQUIRED SAFETY | The next round extends the unique highest certified parent selected from the verified TC, with deterministic tie refusal. | A takeover leader proposes below a known QC or chooses one of multiple conflicting equal-ranked candidates. | Ignoring carry can unlock a certified branch; accepting an arbitrary tie makes honest validators choose different parents. |
| Locked-QC state | REQUIRED SAFETY | A validator never votes for a proposal whose certified parent is below its locally established lock unless a governed unlock proof exists. | A stale or Byzantine leader proposes an older branch after a validator has observed a newer QC. | Highest-QC tracking alone describes observed progress but does not encode the local no-conflicting-vote constraint needed across rounds. |
| Prepared consensus state | REQUIRED RECOVERY | Restart reconstructs active height/round, highest parent, lock, takeover TC, sign-once records, and last finalized height before signing resumes. | A process or host restarts after voting/certification but before all in-memory state is reconstructed. | Reloading only the last finalized block loses unfinalized safety state and can permit double-signing or voting below a lock. |
| Peer-quorum reconstruction | REQUIRED RECOVERY | If local prepared state is missing or behind, signing resumes only from one validator-count-and-weight quorum-agreed checkpoint that reconciles with durable local finality. | Local non-finalized state is lost or corrupted while peers retain different checkpoints. | Trusting one peer permits rollback/fabrication; choosing the numerically highest report without quorum can select a minority fork. |
| Two-QC tail carried across an epoch boundary | REQUIRED SAFETY | The successor epoch preserves the two certified descendants needed to continue the existing three-QC finality pipeline from the finalized epoch anchor. | Rolling epoch transition occurs while the first successor blocks still depend on the closing epoch's certified tail. | Resetting the pipeline at the epoch boundary creates an avoidable finality gap or tempts special-case one-QC/two-QC finality. |
| Deterministic epoch-frozen leader ring and bounded lease | REQUIRED LIVENESS | Every validator derives the same proposer order and bounded takeover opportunity from the finalized epoch seed and frozen registry. | Multiple eligible validators propose simultaneously, or one unavailable leader blocks progress indefinitely. | Unranked free-for-all leadership increases equivocation and network contention; a permanent leader has no bounded recovery path. |
| Staged validator synchronization/readiness before future-epoch activation | REQUIRED MEMBERSHIP | A new validator gains authority only in a future frozen registry after authorization, state synchronization, key proof, readiness, and finalized membership transition. | A joining node is configured but stale, lacks the authority-bound key, or has not reconstructed finality state. | Immediate activation from registration, VPN presence, stake, or role would let an unready or unauthorized node vote. A fixed historical 1,000-block duration is not part of this invariant. |
| Finalized membership authority and epoch activation | REQUIRED MEMBERSHIP | Add/remove/jail/expel/slash effects change consensus authority only at a finalized, explicitly authorized epoch boundary. | Operators or local Admin callers attempt to mutate the active validator set mid-epoch or without the closing finality proof. | Editable configuration or immediate local mutation yields different active sets at honest validators. |

## Removed or prohibited derived complexity

| Mechanism | Classification | Decision |
| --- | --- | --- |
| Multiple PoSy consensus clusters, cluster rotation, or Synergy Pods | LEGACY/DERIVED COMPLEXITY | Prohibited. The canonical machine has one consensus cluster containing the exact frozen active registry. Existing cluster-zero types are a compatibility-shaped view and must not grow scheduling or authority behavior. |
| Separate leader score/ranking engines beyond the finalized-seed ring | LEGACY/DERIVED COMPLEXITY | Prohibited. No stake, Synergy Score, performance score, network score, or local heuristic may reorder leaders inside an epoch. |
| Fixed 1,000-block shadow ceremony | LEGACY/DERIVED COMPLEXITY | Not retained as an authority rule. Readiness requires evidence, not an unexplained fixed block count. A governed minimum observation window may exist only when separately specified with its measured invariant. |
| Standalone activation ceremony that can grant authority | LEGACY/DERIVED COMPLEXITY | Prohibited. Genesis binds the initial frozen authority; later activation is the finalized membership/epoch transition. Ceremonial artifacts may document authorization but cannot be a second authority path. |
| Timeout/QC carry variants beyond the single verified TC path | LEGACY/DERIVED COMPLEXITY | Prohibited. No parallel timeout coordinator, local carry cache, QC voting overlay, or legacy recovery coordinator may advance the state machine. |
| Recovery that reconstructs from role, VPN, transport, stake, score, or one peer | LEGACY/DERIVED COMPLEXITY | Prohibited. Only durable verified state or dual-quorum peer reconstruction may reopen signing. |

## Minimal canonical state

The retained consensus state is:

1. frozen epoch authority and deterministic leader ring;
2. last finalized block;
3. contiguous certified tail required by three-QC finality;
4. highest certified parent and locked QC;
5. current height/round and verified takeover TC, when any;
6. durable sign-once proposal/vote records;
7. pending finalized membership transition for the next epoch.

Clustering beyond cluster zero, score-based leader selection, overlapping
coordinators, and ceremony-owned authority are not canonical state.

## Change gate

Removal of a retained safety mechanism requires a written safety proof,
replacement invariants, persisted-state migration, wire/caller migration, and
multi-validator evidence. Addition of a liveness or recovery mechanism requires
an exact failure it solves that the retained machine cannot solve. Legacy parity
alone never satisfies either gate.
