# PoSy v3 canonical consensus object schemas

Status: proposed. These are semantic field lists; the Rust `serde(deny_unknown_fields)` declarations and deterministic vectors define the reviewed JSON transition encoding. A production wire codec requires the same field order, widths, bounds, and rejection behavior.

## Shared context

`ConsensusObjectContext` binds `schema_version`, `chain_id`, `network_id`, `protocol_version`, `epoch`, `height`, `round`, `epoch_context_root`, `consensus_parameter_root`, `active_validator_set_root`, `validator_consensus_key_root`, and `frozen_voting_weight_root`.

No receiver may substitute locally inferred roots or a live-peer set.

## QC reference

Fields: `height`, `block_id`, and stable `qc_id`. The reference deliberately contains no proof round, takeover TC, signer subset, or signature bytes. `qc_id` is the stable certified-candidate ID described below.

## PROPOSAL

Fields: shared context, `proposer_id`, `block_id`, `parent_block_id`, `parent_qc`, optional `takeover_tc_id`, protected-execution root, proposer key ID, and proposer ML-DSA-65 signature.

The proposal transcript includes the exact parent/TC/protected-execution evidence. `block_id` is the canonical block/body commitment. The durable proposal source supplies and independently verifies the corresponding bounded material before reliable delivery or block voting. The implemented core adapter is restricted to deterministic empty blocks while no finalized ETDAG permit exists; the protected ETDAG production adapter remains open and must fail closed when protected execution is active. `takeover_tc_id` is absent only at takeover offset zero.

## VERIFIED_PROPOSAL_MATERIAL

Fields: complete canonical block and body, optional target-admission context, and
optional protected block input. Its stable candidate ID must equal the proposal
subject. Core verification executes the exact empty block. Protected
verification independently checks ETDAG reveal/BOC evidence, reconstructs the
execution manifest and protected commitment, and executes the block. The
protected-execution root is domain separated and normalizes mutable
round/proposer envelope fields so mandatory TC carry can re-envelope the same
stable material without changing its identity.

The durable material store accepts one canonical record per stable candidate,
limits a record to 16 MiB, writes a mode-0600 temporary file, fsyncs it, and
installs it by a non-overwriting atomic link followed by directory fsync.
Identical reinstall is idempotent; conflicting bytes, noncanonical encoding,
wrong epoch/context, or replay failure are rejected.

## MATERIAL_REQUEST and MATERIAL_CHUNK

`MATERIAL_REQUEST` fields bind epoch-context root, stable candidate ID, and a
fresh request ID. `MATERIAL_CHUNK` additionally binds chunk index/count,
predecessor root, record root, and payload. The receiver associates the
authenticated ingress peer with the one outstanding request/session.
Payloads are bounded to 48 KiB, records to 512 chunks, active sessions and
per-peer sessions are capped, request/serve budgets are enforced, and sessions
expire. Only an expected peer's ordered, complete hash chain for an outstanding
request can reach canonical decode, independent verification, and durable
installation. An unsolicited, replayed, cross-peer, oversized, or stale chunk
has no consensus authority.

## PROPOSAL_ECHO and PROPOSAL_READY

Fields: shared proof-slot context, phase, complete stable candidate subject, validator ID, key ID, and ML-DSA-65 signature. The phase-specific signing payload binds the stable candidate ID. Domains are `PoSy/Consensus/v3/ProposalEcho` and `PoSy/Consensus/v3/ProposalReady`.

These are authenticated dissemination statements, not block votes or finality certificates. For `n=5,f=1`, four ECHOs permit READY, two READYs cause relay, and three READYs deliver. Each signer emits at most one ECHO and one READY per round-scoped slot. Retained candidate and evidence maps are bounded.

## VOTE

Fields: shared context, `block_id`, `parent_block_id`, `parent_qc {height,block_id,qc_id}`, optional `takeover_tc_id`, `protected_execution_root`, `validator_id`, `key_id`, and ML-DSA-65 signature.

Signing domain: `PoSy/Consensus/v3/BlockVote`. The signature field is excluded from its own signing payload. The signer journal uses a round-scoped authorization slot while also enforcing height-wide stable-candidate protection. A verified later-round no-carry TC may authorize one conflict unlock; its closure ID is included in the durable authorization. A timeout authorization for the same round prohibits a later block vote.

## QC

Fields: shared context, `block_id`, `parent_block_id`, `parent_qc`, optional `takeover_tc_id`, the exact nonzero `protected_execution_root` certified by every vote, and canonical `participants[] {validator_id,key_id,signature}`.

Participants are strictly increasing by validator ID. The QC ID is the domain-separated hash of `CertifiedCandidateSubject`: context with round canonicalized to zero, block/body commitment, parent block/reference, and protected-execution root. It excludes takeover evidence and the participant proof bundle. Different valid 4-of-5 subsets, nondeterministic signature bytes, and same-candidate proofs in later takeover rounds therefore converge on one QC reference; every proof is still independently verified before the subject ID has authority. The schema deliberately excludes count, signed weight, total weight, threshold, and quorum booleans. Verification recomputes all authority from valid unique frozen-set signers.

## TIMEOUT_VOTE

Fields: shared context, `lease_index`, `timed_out_proposer`, signer-local `highest_qc`, optional `previous_tc_id`, optional complete `last_voted_candidate`, `validator_id`, `key_id`, and ML-DSA-65 signature.

Signing domain: `PoSy/Consensus/v3/TimeoutVote`. Round zero requires no predecessor. Every higher round requires the exact preceding TC ID.

## TC

Fields: shared closure context, `lease_index`, `timed_out_proposer`, optional `previous_tc_id`, canonical signed `reports[]`, and canonical deduplicated `highest_qc_proofs[]` for every reported non-anchor QC.

Reports MAY name different highest QCs and candidates. The deterministic maximum is ordered by `(height,qc_id)`, and every non-anchor reference must be self-contained with a verified QC proof. A candidate reported by at least two distinct signers is the unique mandatory carry candidate; multiple threshold candidates are invalid. With no threshold candidate, the TC proves no hidden QC existed for the abandoned slot and may authorize a fresh proposal extending the verified maximum.

The TC closure ID hashes only context, lease, abandoned proposer, and predecessor. It excludes reports, signature bytes, reported QCs, proofs, and carry result so every valid 4-of-5 subset converges on one sequential predecessor. The certificate proves abandonment of one exact owner/lease/height/round and increments only the current lease takeover offset. It is invalid as a QC, membership change, or finality certificate.

## Persistent safety record

The rooted atomic record contains typed `anchor_parent` and `highest_parent`
values, optional `locked_qc`, optional `last_vote`, authenticated
reliable-delivery evidence for the active slot, optional current `takeover`
with the complete sequential TC chain, `finalized`, indexed certified QCs and
TCs, and optional `safety_halt`. For epoch zero, the two parent values may be
the canonical `GenesisFinalityReference`; Genesis is never encoded as a QC.
Reliable-delivery and participant-proof bytes are local evidence and are
excluded from the stable authority root. The format exposes no
reset/delete/unlock API.

## FINALIZATION_TRANSACTION and finality WAL

The finality environment pins the epoch, exact anchor, and boundary execution
state. A finalization transaction carries a bounded consecutive sequence of
finalized commitments and the exact three-QC witness for the terminal commit.
Every commitment embeds its complete QC; no cached signer count or weight is
trusted. The durable finality sink writes one immutable canonical WAL record per
target height and references proposal material only through its
content-addressed stable candidate ID.

On startup the sink pins epoch metadata, the anchor, and boundary state root;
sorts and canonically decodes every record; independently verifies every QC and
three-chain witness; loads and re-verifies every referenced material record; and
re-executes forward from the boundary. Missing material, anchor substitution,
context drift, invalid signatures, discontinuity, or execution mismatch fails
closed. Repeating the exact transaction returns its prior receipt; different
bytes for an occupied target height are rejected. The production role runtime
now installs this sink as the v3 restart execution authority and publishes
execution snapshots for the Genesis-bound governed-ETDAG path. The autonomous
five-driver harness proves distinct WAL/material durability across restart;
full node-database convergence remains open.

## EPOCH_TRANSITION_PROOF

Format/schema v2 fields: previous epoch context and validator set, complete next
validator set, `authorization`, exactly three previous-epoch QCs ending at the
epoch's last height, and bounded application-owned authority evidence. The
authorization binds its schema, adjacent epoch coordinates, previous-context
root, committing finalized height, next parameter root, and next active-set,
consensus-key, and frozen-weight roots.

The transition-subject ID explicitly excludes finalized block ID and QC ID.
Those identifiers depend on the protected-execution root that contains the
subject, so including either would be circular. Verification separately checks
the exact three-QC tail, derives the finalized seed at `E-2` and certified
parent at `E`, then requires a finalized-execution inclusion/receipt proof for
the subject. Peer state sync cannot supply this membership authority.

## SIMPLIFIED_TARGET_ADMISSION

The H+3 context binds the finalized source height/digest, exact assigned frozen
cluster, dynamic validator count/weight roots, parameter and cryptographic
roots, deterministic height-schedule root, and public ML-KEM registry root.
Vote messages carry that context, the exact public registry, validator/key IDs,
and a journaled ML-DSA signature. A certified package carries the same context
and registry plus the canonical strict count-and-weight vote certificate.

The public registry artifact is canonical JSON bound to one epoch-context root,
epoch, target height, cluster, and registry root. It contains no private KEM
material. Missing, oversized, noncanonical, wrong-target, or substituted
artifacts fail closed. The producer does not derive a target in the next epoch
until that epoch's verified transition exists.

## STATE_SYNC_CHUNK

Fields bind one request/session ID, authenticated peer, epoch/context and anchor roots, chunk index/count, predecessor chunk hash, payload bytes, terminal flag, and terminal reconstructed-bundle root. Production bounds are enforced before staging; only a complete ordered hash chain is decoded and passed to full bundle verification. Stager output alone has no consensus authority.
