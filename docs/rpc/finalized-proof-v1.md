# Finalized proof transport v1

Engineering implementation; this document does not activate a profile or qualify
Wallet/client integration. No new state-root, Merkle-path, or consensus rule.

## Request and exact page response

Public read method: `synergy_getFinalizedProofPageV1`.

```json
{"jsonrpc":"2.0","id":1,"method":"synergy_getFinalizedProofPageV1","params":{"height":1,"kind":"world_state","offset":0,"limit":65536}}
```

`height` is a positive u64. `kind` is `block_commitment`, `world_state`, or
`finality`. `offset` defaults to zero; `limit` defaults to 65536 and must be
1–65536. Reject unknown fields, wrong types, and malformed lowercase-hex pins.
Continuation requests must supply `expected_sha256` from the first response:

```json
{"height":1,"kind":"world_state","offset":65536,"limit":65536,"expected_sha256":"<64 lowercase hex>"}
```

The result contains `version:1`, the requested `height`/`kind`,
`encoding:"base64"`, `bytes_base64`, `sha256`, `total_bytes`, `offset`,
`next_offset` (integer or null), and `authentication` (an advisory instruction).
World/block pages additionally return `block_id`, `state_root`, and
`protected_execution_root`. World pages identify their commitment as:

```json
{"type":"full_canonical_world_preimage","algorithm":"sha3-256","domain_utf8":"SYNERGY_WORLD_STATE_ROOT_V1","framing":"domain || canonical_json_length_be_u64 || canonical_json_bytes"}
```

Concatenate **decoded bytes** at contiguous offsets. Require unchanged kind,
height, digest and total size on every page; check the complete SHA-256. Never
parse and re-encode page fragments or use floating-point JSON numbers to
reconstruct bytes. SHA-256 pins page consistency; it does not authenticate the
block, authority, or network. Normal JSON-RPC errors cover invalid queries and
unavailable/pruned evidence. No partial witness is represented as complete.

A client must fetch each required kind independently. The compact receipt
index and retained finality witness can outlive the canonical block preimage.
Core's certification-only read checks that its verified durable execution
tip covers the requested height. It can return the original finality witness
after the historical execution view is retired, provided the verifier still
has the exact retained quorum and timeout certificates. Any surviving
execution anchor must agree with that witness. The block and World proof
kinds require their original preimages.
For example, the current Canary returned the original finality pages at
height 9,704 on November 21, 2026, while `block_commitment` returned
`requested finalized evidence is not retained`. The compact receipt from
that height cannot establish original receipt inclusion. There is no published
guaranteed retention window for these preimages. Fetch the pages needed for
verification while available and report missing evidence explicitly.

## Original commitments and verification

* World bytes are the complete original canonical `WorldState` JSON, including
  exact protocol byte arrays. The root is
  `SHA3-256("SYNERGY_WORLD_STATE_ROOT_V1" || BE64(byte_length) || bytes)`.
* Block bytes are the canonical JSON tuple
  `[height,parent_block_id,protected_execution_root,state_root,transactions,receipts]`.
  Its block ID is
  `SHA3-256("SYNERGY_BLOCK_ID_V1" || BE64(byte_length) || bytes)`.
* Finality bytes are canonical JSON
  `{"version":1,"finalized":FinalizedBlockRecord,"witness":FinalitySyncWitness}`.
  `finalized` contains `height`, `block_id`, `finality_certificate_id`, and
  `protected_execution_root`. The witness contains exactly three
  `quorum_certificates` and its exact `timeout_certificates` closure. Preserve
  the native serialized fields/signature byte arrays; this is not a new encoding.

Authenticate Genesis, selected network, signed authority origin, and applicable
signed/autonomous successor artifacts independently of the proof producer.
`synergy_getEpochTransitionProofV1` transports existing exact artifacts; its
returned context root is not independently trusted. Validate each successor from
that pinned origin/bootstrap using the native authority verifier. Each QC and
TC is verified under its **original** authenticated epoch and frozen keys, then
the native three-QC finality machine checks ancestry and the returned finalized
record. Reject duplicate/unreferenced timeouts. Match the verified block ID and
protected root with the recomputed block preimage, and match its state root with
the recomputed World preimage. A producer's metadata alone establishes none of
these bindings.

Offline native verifier (immutable public inputs, explicit APQE provider in the
selected configuration; no custody, signing, network access, or storage writer):

```sh
synergy-node finality-proof verify CONFIG REASSEMBLED_PROOF_JSON
synergy-node finality-proof verify CONFIG REASSEMBLED_PROOF_JSON REASSEMBLED_BLOCK_COMMITMENT_JSON
```

It authenticates configuration-selected signed Genesis and retained authority
history, enforces canonical complete proof bytes, verifies native QC/TC evidence,
and emits `version`, `verified:true`, `chain_id`, `network_id`, `genesis_hash`,
and the authenticated `finalized` record. With the optional block commitment
preimage it also checks the exact block-ID hash, height and protected execution
root and emits `state_root`, `epoch`, `epoch_context_root` and
`consensus_timestamp_unix`. The caller checks the intended height and matches
the original World preimage to `state_root`. The CLI does not select trust from
proof-supplied keys or use a gateway-provided clock.

To derive the same clock in a client, verify all three QCs against their
original authenticated epoch contexts. Select the authenticated protected time
policy for the **finalized block's** height, including when the descendants
that finalize it cross an epoch boundary. Evaluate
`(epoch_start_timestamp_ms + (height - epoch_start_height) * target_block_time_ms) / 1000`
with checked integer arithmetic and the height constrained to its authenticated
epoch range. Reject missing policy, overflow or a substituted finalized record
or block preimage. The result is the consensus time used by enrollment
execution, not an observation time. This adds no field to the original v1
proof bytes and no consensus action.

## Finalized governance record inspection

```sh
synergy-node finality-proof verify-activation-record CONFIG FINALITY_JSON BLOCK_COMMITMENT_JSON WORLD_JSON EXPECTATION_JSON
```

For a separately authenticated decision, select the exact record key and
original record SHA-256 independently of the proof source. The expectation
contains `chain_id`, `network_id`, logical `genesis_hash`, `activation_height`,
`finalized_block_id`, `state_root`, `record_key`, and `record_sha256`.
The key names one `governance/<action-kind>/<target>` record. Each path
segment permits ASCII alphanumerics, dots, underscores, and hyphens. The
command has no default key, digest, or activation height.

The reader verifies the original signed Genesis, applicable epoch authority,
three-QC evidence, block commitment, and complete canonical World. At the
exact selected height, it returns `exact_expected_record_finalized` if the
World contains the expected bytes, or `expected_record_absent` if the key is
absent in that authenticated World. A conflicting record, another chain or
Genesis, insufficient evidence, or a height or hash mismatch fails closed.
Use a second command when the release requires evidence that the record was
introduced at the specified boundary.

```sh
synergy-node finality-proof verify-activation-transition CONFIG FINALITY_JSON BLOCK_COMMITMENT_JSON WORLD_JSON EXPECTATION_JSON PREVIOUS_FINALITY_JSON PREVIOUS_BLOCK_JSON PREVIOUS_WORLD_JSON
```

Supply the original finality, block, and World for height H−1 alongside the
evidence and expectation for H. The verifier resolves each QC under its
original authenticated epoch and checks that the QCs and committed block
preimage link H directly to H−1. It verifies both World roots. It returns
`expected_record_introduced_at_finalized_boundary` only if that key was absent
at H−1 and its exact pinned bytes are present at H. The result includes the
certified predecessor height, block ID, finality certificate ID, and state
root. Missing, conflicting, or prematurely present records fail closed.

An absent-to-present transition proves the change between those two states.
Ratification authority, execution eligibility, and exclusion of older uses
require separate evidence. The public World disclosure policy is unchanged.

## Protected candidate state inspection

```sh
synergy-node finality-proof verify-candidate-state CONFIG FINALITY_JSON BLOCK_COMMITMENT_JSON WORLD_JSON QUERY_JSON
```

Supply the complete original World for the same finalized block, obtained from
an authorized evidence source. The local query pins `height`, `block_id` and
`state_root` and selects `ownership_chain_id` as a 32-byte lowercase hexadecimal
integer and one to four distinct `provider_manifests` as 32-byte lowercase
hexadecimal hashes. Select those parameters independently of the proof. Query
up to eight total entries across `addresses`, `commitments`, `settlements`,
`sponsorships` and `transition_settlements`.
Use canonical `synw` addresses and 32-byte lowercase hexadecimal commitment
hashes. A settlement selector has `sender`, `intent_id` and
`signed_intent_digest`. Supply the original 32-byte signed intent ID and
64-byte native intent digest in lowercase hexadecimal.
A sponsorship selector carries a canonical ordinary `syna` payer, the
`nonce_before`, and `signed_sponsor_digest` in lowercase hexadecimal. Compute
the 64-byte digest as SHA3-512 over the ASCII domain `AEGIS/ENROLL-SPONSOR/v1`
followed by the exact canonical sponsor intent bytes.

The normal finality result includes a `candidate_state` projection labeled
`unactivated_candidate`. Enrolled entries include the address, account ID,
registration height, full SEC1 point, exact canonical policy bytes, policy hash
and epoch, D/P/R public roles and keys, decimal nWei balance and next nonce.
An account is `absent` only if the authenticated World lacks both its ledger and
policy entries. A commitment includes its exact hash, inclusion height, recorded
inclusion consensus time and `unconsumed` or `consumed` status. Query the same
hash in the certified Worlds before and after reveal to compare observations.
The consuming action and fees require their own certified receipt evidence.

An enrolled account also returns `pending_transition`. It is `null` only when
that account has no pending transition record in this authenticated World.
Otherwise the closed projection contains `status:"scheduled_candidate"`,
`mode` (`ordinary` or `recovery`), `pending_reference`, `replaced_role` (0 for
D, 1 for P), `old_policy_epoch`, `old_policy_hash`, `new_policy_hash`,
`scheduled_height`, `scheduled_consensus_timestamp_unix`, and
`activation_timestamp_unix`. References and policy hashes are lowercase
32-byte hexadecimal strings; timestamps are consensus seconds, not wall-clock
observations. No additional query selector is required beyond the account
address.

The reader checks the canonical pending record against the same finalized
account, active policy, Genesis and registration height. It validates the exact
proposed canonical replacement and its delay against the recorded scheduling
time, and requires the matching deadline-index entry and reference. A recovery
record requires its nonzero continuity reference; this does not independently
verify an external DKG/share-repair ceremony. Malformed, mismatched or unindexed
pending state refuses the projection. A due `scheduled_candidate` is not proof
that activation executed. `null` is not a terminal cancellation/veto receipt,
proof of earlier activation, or evidence that no transition ever existed.

A `transition_settlements` selector supplies a canonical `synw` `address`,
the original 32-byte `pending_reference` and, for a signed cancellation or
veto, an optional 64-byte `signed_intent_digest`. Both use lowercase
hexadecimal. The output includes this array when requested.
Each result is keyed by the account and exact reference and reports
`canceled_candidate`, `vetoed_candidate`, `activated_candidate`, or
`no_transition_settlement_in_snapshot`. A terminal result binds the mode,
deadline, source and inclusion heights and consensus times, and the old and
resulting policy epochs and hashes. A signed charge gives the action ID,
exact signed intent ID and digest, gas, decimal nWei fee, and before/after
nonce. Automatic activation returns `signed_charge:null`. A different
digest, impossible terminal effect, or matching pending and terminal records
refuses the projection.

The candidate executor inserts that settlement atomically with its policy,
pending, fee and nonce changes. Verification uses the existing block preimage
format and authenticates the record through the original certified World root.
Missing state at the selected snapshot cannot
identify a refusal, lapse, or previously pruned outcome. This candidate
projection does not change public World disclosure or authorize PW13.

The transfer candidate writes its settlement record atomically with debit,
credit, fee and nonce changes. An `applied_candidate` settlement includes the
verified signed-intent digest, exact decrypted content SHA3-256, recipient,
source and inclusion heights, inclusion consensus time, policy epoch, gas,
requested `amount_nwei`, actual `credited_nwei`, fee and before/after nonce.
An ordered, authenticated transfer that was feasible at its finalized source
can settle as `reverted_candidate` when an earlier ordered write leaves
insufficient transfer balance or a recipient credit would overflow. The
candidate reason is `insufficient_transfer_balance` or
`recipient_balance_overflow`. It records `credited_nwei:"0"`, the exact
fee and one nonce advance. Funding the fee, current authority, exact encrypted
content and the original intent remain required. Refusal, replay, invalid
source state, and an atomic fee or settlement failure write no outcome.

SNRG amounts and fees are decimal nWei strings. Authentication comes from the verified World and block supplied to
the command. The record contains no self-referential resulting block or World
hash. A different signed digest for an existing sender/intent ID fails closed.
`no_settlement_in_snapshot` reports missing candidate state at the selected
height. It provides no evidence of rejection, expiry or non-consumption.

The isolated encryption fixture can also record an `engineering_etdag_opening`
with `envelope_id`, `processing_context_root`, `authorization_height`, and
`payload_root`. The payload root uses the existing processing function over the
original context root, envelope ID, and exact opened plaintext. A selector may
supply that object to require an exact match to the settled opening. The
authorization height is the envelope's key-validity anchor. The record separately
reports the source finalized height and the execution height. This evidence
describes local native ETDAG encryption and decryption. The fixture assigns no
public receipt ID and produces no live admission, readiness, or authorized reveal
record.

The sponsored enrollment candidate commits each paid outcome with its
commitment, fee and nonce changes. The result reports
`commit_applied_candidate`, `duplicate_paid_commit_candidate`,
`reveal_applied_candidate` or `reveal_reverted_commit_used_candidate`, with
exact commitment hash, gas, decimal nWei fee,
source finalized height and consensus time, inclusion height and consensus
time, and both nonce values. A fresh sponsor authorization for an existing
commitment can pay a separate fee without rewriting that commitment. An exact
retransmission can be reconciled by the original payer, nonce and digest
without a second charge. A conflicting digest at that payer and nonce fails
closed. A missing sponsorship record only states absence from the selected
World. An ordinary action could have consumed the same payer nonce.

The proposed paid revert covers one exact ordering conflict. The reveal and
sponsor must pass the finalized-parent, proof, expiry, payer, and fee checks.
The working block must already hold the exact consumed commitment and initial
policy written by an earlier reveal at that height. The second action consumes
one sponsor nonce and fee and writes its own outcome. The protected account,
policy, and commitment are untouched. An already-consumed commitment in the
finalized parent, a stale payer nonce, insufficient funds, expiry, and other
failed checks carry no charge.

### Candidate transition execution effects

The isolated ordinary/recovery executors return a typed
`TransitionExecutionOutcome` after a successful atomic write. It is an internal
test-only result, not a serialized public receipt or an independently
authenticated event. Its fields identify the deadline/account/reference/mode,
`kind` (`Canceled`, `Vetoed` or `Activated`), source finalized height, inclusion
height and consensus time, and old/resulting policy epochs and hashes.

`Canceled` and `Vetoed` retain the active policy hash and epoch and carry
`signed_charge`: the exact action, intent ID, native signed digest, gas, nWei
fee and before/after nonce. They remove the exact pending record and index
atomically with one authorized fee and nonce change. `Activated` advances the
policy epoch and installs the proposed policy, with `signed_charge:None`:
there is no submitted activation transaction, second nonce or fee. The bounded
candidate scheduler returns its ordered outcome list only after the complete
selected batch commits. A failed batch returns no successful effects.

These returned effects do not persist a system-event journal, add a terminal
World tombstone, or extend the block/receipt wire format. Existing transaction
receipts remain paired with actual transactions. In particular, a scheduler
activation must not be assigned a fabricated transaction ID or transaction
receipt. Certified terminal evidence requires an approved commitment and its
proof/replay contract; an in-memory outcome or missing pending record cannot
substitute for that evidence. The before/after authenticated Worlds establish
their respective state observations, not an uncommitted event's identity.

Missing or pruned World bytes, malformed entries, scope mismatches and
one-sided account records produce an error without a projection. The local
command leaves the public World disclosure policy unchanged. The projection
omits enrollment bytes, wallet UUIDs and unrelated state. It does not enable
protected enrollment, spending or recovery, or establish external DKG
provenance.

## Disclosure, resources and gateway behavior

World disclosure fails closed if **any** protocol entry lacks an explicitly
qualified public schema. Current schemas are the closed identity binding
commitment table, its authorization-updated height, and ready/group public
metadata. Unknown fields, opaque application records, invalid digests, and
oversized records are refused. The service never redacts bytes and pretends the
redacted World has the same root. Therefore many otherwise valid finalized
Worlds may be unavailable through this endpoint.

Complete documents are limited to 1 MiB, pages to 64 KiB, and each dispatcher
admits at most four proof requests per one-second window. Disclosure scans one
strict borrowed entry at a time. Typed finality responses retain their resource
permit through paging rather than allocating a per-signature-byte JSON tree.
The finality endpoint additionally refuses more than 128 aggregate retained
lease/round timeout-search slots. This is an endpoint work limit, not a quorum,
round, or finality rule. Certificate persistence retains its existing separate
record/decode limits; these tests do not establish a whole-process RSS bound.

The APQE RPC relay preserves original response bytes and adds `chain_context`;
its 1,000,000-byte body bound accommodates a maximum proof page. It does not
turn a page SHA into a trust anchor. Gateway successor verification advances
its authenticated per-worker cursor by at most four proofs per request. If more
behind, that request is unavailable but a later request continues from the
verified intermediate cursor. The shared high-water mark is published only on
an exact advertised epoch/root match. Restart reconstructs from the pinned
origin and repeats bounded batches; there is no durable successor checkpoint or
per-epoch configuration update in this path.

## Focused reproducible qualification

`services::rpc::proofs::tests` covers pinned pagination, integer byte fidelity,
strict disclosure, actual flat-root reconstruction and work limits. The native
ignored test
`native_finality_pages_are_independently_verifiable_and_retain_their_charge`
uses actual APQE signatures from five distinct test-only keys, three QCs, a fresh
verification cache, tamper rejection and permit lifetime checks. It runs no
validator processes or cohort. Optional `SYNERGY_PUBLIC_PROOF_FIXTURES` names a
**new** output directory for four public-only fixtures: positive proof,
substituted record, altered signature, and explicitly test-only public trust.
Those generated test keys are not production authority and cannot replace the
CLI's independently signed configuration inputs.

The existing canonical RPC fixture exercises the actual dispatcher against
joint execution/state/finality storage, exact block and World preimages,
unavailable height, missing authenticated ingress, unknown/oversized/malformed
queries and digest mismatch. A native relay test checks maximum-page transport
without re-encoding. These are offline source tests, not live endpoint or Wallet
qualification.

Committed public test vectors (exact original bytes; independent of the live
network) are in [fixtures/finalized-proof-v1](fixtures/finalized-proof-v1):

* [Positive finality proof](fixtures/finalized-proof-v1/proof-positive.json).
* [Substituted finalized record](fixtures/finalized-proof-v1/proof-negative-record.json), which must fail.
* [Altered QC signature](fixtures/finalized-proof-v1/proof-negative-signature.json), which must fail.
* [Test-only public trust](fixtures/finalized-proof-v1/fixture-public-trust.json): five ML-DSA-65 public keys and their epoch context, **not** an authenticated network enrollment or signed Genesis.
* [SHA256SUMS](fixtures/finalized-proof-v1/SHA256SUMS), covering all four files.

These vectors exercise an ordinary same-epoch, round-zero finality witness. They
do not qualify cross-epoch timeout recovery or substitute for independently
pinned production authority inputs. A Wallet test may supply the explicit test
trust fixture to its native verifier; a production Wallet must never import
that fixture as an approved network. Negative vectors preserve canonical
serialization, so rejection must depend on native finality/signature checking,
not on malformed JSON.

The native offline-successor regression additionally certifies the first slot of
an authenticated successor, with a timeout containing the previous epoch's
terminal QC. Both the proof producer and offline verifier accept it through
`ConsensusSignatureVerifier::verify_timeout_boundary_parent`; they reject a
corrupted predecessor signature (unchanged stable QC ID), substituted boundary
parent, or verifier lacking authenticated predecessor history. The existing
successor fixture's other assertions remain in force. This deterministic test
runs no validator cohort and does not claim a live boundary qualification.
