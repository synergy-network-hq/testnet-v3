# PoSy v3 canonical consensus object schemas

Status: proposed. These are semantic field lists; the Rust `serde(deny_unknown_fields)` declarations and deterministic vectors define the reviewed JSON transition encoding. A production wire codec requires the same field order, widths, bounds, and rejection behavior.

## Shared context

`ConsensusObjectContext` binds `schema_version`, `chain_id`, `network_id`, `protocol_version`, `epoch`, `height`, `round`, `epoch_context_root`, `consensus_parameter_root`, `active_validator_set_root`, `validator_consensus_key_root`, and `frozen_voting_weight_root`.

No receiver may substitute locally inferred roots or a live-peer set.

## QC reference

Fields: `height`, `block_id`, and stable `qc_id`. The reference deliberately contains no proof round, takeover TC, signer subset, or signature bytes. `qc_id` is the stable certified-candidate ID described below.

## PROPOSAL

Fields: shared context, `proposer_id`, `block_id`, `parent_block_id`, `parent_qc`, optional `takeover_tc_id`, protected-execution root, proposer key ID, and proposer ML-DSA-65 signature.

The proposal transcript includes the exact parent/TC/protected-execution evidence. `block_id` is the canonical block/body commitment. The production proposal source and receiver-side execution adapter MUST supply and independently verify the corresponding bounded body, ETDAG/BOC/reveal evidence, and execution result before reliable delivery or block voting; these adapters are not launch-qualified yet. `takeover_tc_id` is absent only at takeover offset zero.

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

The rooted atomic record contains `anchor_qc`, `highest_qc`, optional `locked_qc`, optional `last_vote`, optional authenticated reliable-delivery evidence for the active slot, optional current `takeover` with the complete sequential TC chain, `finalized`, indexed certified QCs and TCs, and optional `safety_halt`. Reliable-delivery and participant-proof bytes are local evidence and are excluded from the stable authority root. The format exposes no reset/delete/unlock API.

## STATE_SYNC_CHUNK

Fields bind one request/session ID, authenticated peer, epoch/context and anchor roots, chunk index/count, predecessor chunk hash, payload bytes, terminal flag, and terminal reconstructed-bundle root. Production bounds are enforced before staging; only a complete ordered hash chain is decoded and passed to full bundle verification. Stager output alone has no consensus authority.
