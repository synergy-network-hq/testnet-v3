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
```

It authenticates configuration-selected signed Genesis and retained authority
history, enforces canonical complete proof bytes, verifies native QC/TC evidence,
and emits `version`, `verified:true`, `chain_id`, `network_id`, `genesis_hash`,
and the authenticated `finalized` record. The caller must perform the block/World
matches above. The CLI does not select trust from proof-supplied keys.

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
