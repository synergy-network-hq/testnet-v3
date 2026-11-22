# PW13 ratification readiness supplement

Review date: 2026-11-21. **DRAFT — no decision recorded, no activation authorized.**
This is an approval instrument to complete, not a second protocol specification or
an executable activation artifact. The original ten hashed files and their
`SHA256SUMS` remain byte-identical. This supplement is outside that historical
manifest; it does not silently replace the packet cited by Wallet.

## Exact review inputs

- [Frozen Core packet at 5dedfb577643a3be6926ea685ec07ba4bbf31110](https://github.com/synergy-network-hq/testnet-v3/tree/5dedfb577643a3be6926ea685ec07ba4bbf31110/docs/protected-accounts-canary-v1).
  Its `SHA256SUMS` SHA-256 is
  `c7cf18bcdfe13eeab2ff23879661599917032518ab3dac9a14c6ae93cb6a0059`.
  All ten entries passed checksum verification on the review date. Its action
  vectors SHA-256 remains
  `4dfd6d62c1745785362ff494ae39f637f6f244aa52df5e3da239b251f387372f`.
  The registry/source assignments agree on ten IDs `0x7001..0x700a`; the corpus
  contains ten positive and eighteen negative payloads and six native-intent
  digests. All 63 decision-register rows still say `unestablished` in the
  ratification-reference column. These checks establish consistency, not consent.
- [APQE enrollment fixture](https://github.com/synergy-network-hq/APQE/blob/8d2d8fb8a86f07a6b7847d7b1ad8e0cec4a74993/synergy-address-engine/tests/fixtures/protected-enrollment-verification.json),
  SHA-256 `458640e58cd23b4abc210adc975a59c2f715d2bb597db71a87053df27f67532c`,
  and [enrollment CDDL](https://github.com/synergy-network-hq/APQE/blob/8d2d8fb8a86f07a6b7847d7b1ad8e0cec4a74993/synergy-address-engine/docs/protected-enrollment-candidate-v1.cddl),
  SHA-256 `e9ddaa1f516fbbf3ff36d9b77c8ca09ef686f9e63fe26b554ae985f5a159fd16`.
  The APQE repository paths include `synergy-address-engine/`; omitting that
  prefix does not identify these immutable blobs.
- [DKLs23 engineering review](https://github.com/synergy-network-hq/APQE/blob/8d2d8fb8a86f07a6b7847d7b1ad8e0cec4a74993/synergy-address-engine/docs/threshold-replacement-candidate-review.md),
  SHA-256 `6a2262f9def22567a017e70272bc226550fd07f22c134f48f7954f092173ee70`,
  and [mobile provider admission review](https://github.com/synergy-network-hq/APQE/blob/8d2d8fb8a86f07a6b7847d7b1ad8e0cec4a74993/synergy-address-engine/docs/mobile-provider-admission-review.md),
  SHA-256 `9b77746dab590440573b553fca7be8dcaa0759b158e1ea8fb126323b55ba9428`.
  These exact Git blobs matched the local reviewed files. They establish
  engineering limits, not a protected-account provider approval.
- [Core issue #24](https://github.com/synergy-network-hq/testnet-v3/issues/24)
  remains open. Its [Wallet acceptance contract](https://github.com/synergy-network-hq/testnet-v3/issues/24#issuecomment-7056019447)
  and [consensus-time requirement](https://github.com/synergy-network-hq/testnet-v3/issues/24#issuecomment-7060242652)
  are outstanding deliverables, not votes over these artifacts.

## Dispositions for an authorized deciding body

Every row below is **UNDECIDED**. Recommended dispositions do not bind any signer,
account, chain, or release. Record the actual governing/delegating instrument,
eligible deciding body, approval procedure, date, signatures and disposition over
the final complete artifact hashes before treating any row as adopted.

Core can check whether independently expected governance record bytes are
present in the verified World at an exact finalized boundary. The paired
proof also checks that the key was absent in its certified direct predecessor,
including when the two heights span authenticated epochs. The original decision,
scope, record key and digest must come from the authorized deciding body.
The proof supplies the finalized transition evidence. In particular,
verifying signatures of the frozen PoSy committee against an execution-supplied
constitution does not establish that committee's authority over this decision.
Wallet must independently verify the original decision and finality evidence.
See [finalized governance record inspection](../rpc/finalized-proof-v1.md#finalized-governance-record-inspection).

| Decision | Recommended disposition | Evidence needed before activation |
| --- | --- | --- |
| Action and admission contract (ACT-01–14, ENR-01–09, TX-01–05) | Retain `SYNW_HEX_EIP55_V1`, independently verified D/P ML-DSA-87 and recovery-only R; review the candidate namespace and canonical bytes. The one-time D+P threshold EIP-712 AccountBinding grants no external ECDSA spending permission. | Complete encrypted multi-role admission/AAD and exact client/gateway codec, sponsored commit/reveal and all action outcomes; independent original-byte positive/negative vectors. |
| DKG/access structure (CRY-05–09) | Keep the DKG profile unapproved and external ECDSA spending disabled. Do not treat an opaque transcript digest as proof. | Qualified initial D+P threshold AccountBinding, authenticated independent D/P/R participants and share-to-policy correspondence, public verification or an explicitly authorized attestation contract, real-device tests and independent security disposition. |
| Provider release (CRY-01–04, CRY-10–11) | Select no replacement merely because a primitive, source revision or simulator test passes. | Exact per-target signed artifact/dependency/ABI manifests, authenticated release roots, protocol-context vectors, negative/interop tests, physical custody and recovery qualification. Historical packet pins are not automatically current distribution pins. |
| Fees and capacity (FEE-01–10) | Paid permissionless commit/reveal sponsorship, separate payer nonce/fees, zero sponsor account-control authority. | Measured per-action gas/bytes/state limits, validity horizon, pruning/scheduler budgets, paid included-revert/duplicate/crash and exhaustion results; do not copy the ordinary transfer's 840,000 nWei fee into PW13. |
| Policy and recovery (REC-01–04) | Preserve the candidate 7,200/172,800 consensus-second minimum delays, current D/P authority while pending, continued nonce and account identity. | Authenticated time at the exact certified height, deterministic bounded scheduling, atomic persistence, veto/cancel/deadline/restart and lost-role tests; separate native-policy and external-share outcomes. |
| Formation and activation (GEN-01–04, GOV-01–06) | Approve no activation coordinate until the complete contract, release and evidence are frozen. | Exact chain/network/Genesis incarnation, registry/profile/provider/vector/fee hashes, signed approval, finalized activation evidence verifiable by Wallet, mixed-version refusal and pre-activation abort/forward-recovery procedure. Treasury custody, fee reserve and disbursement require their own exact authorization. |

## DKG evidence that source does not establish

The pinned review selects only an engineering candidate: DKLs23 v0.6.2,
`beb6d3b066f870421e1707a22bd400b735e300d7`. Its two crate archive hashes remain
in the frozen cryptographic profile. The review records genuine separate-process
DKG and lost-D/lost-P repair, but on one host with synthetic approval and wrapping,
not independent physical custody or a public consensus admission verifier. The
published enrollment fixture's DKG provenance is synthetic.

In symmetric 2-of-3, R plus D or P can mathematically sign externally; disabling a
Wallet button does not remove that capability. Do not relabel this candidate as
recovery-separated. An authorized disposition must either accept and disclose
that access structure for the exact permitted purpose, or retain the block while
a separately reviewed structure is supplied. In both cases native spending
requires D+P, external ECDSA spending stays disabled absent its separate approval,
and the initial AccountBinding still needs genuine DKG admission evidence.

## Qualification and execution boundary

The proposed sponsored enrollment codec assigns the frozen CDDL's three
leading byte-string slots in order to the original sponsor intent, original
action payload and sponsor evidence. The evidence is a deterministic CBOR
array of three byte strings containing the complete canonical native
`IdentityAuthorizationCarrier` JSON, the 2,592-byte ML-DSA-87 public key and
the 4,627-byte pure ML-DSA-87 signature. The carrier uses Core's native JSON
key ordering and shortest integer encoding with no extra whitespace. The
decoder requires the sponsor intent's action to match the content action and
the reveal proof salt to equal the salt in the signed payload. It passes the
original intent and payload bytes to the existing cryptographic and finalized
payer checks. The 128 KiB content limit and 32 KiB slot limit are engineering
ceilings. The frozen CDDL is unchanged. This proposal still requires approval
with the protected ETDAG content profile, AAD and resource policy.

The candidate enrollment profile is `etdag-pw13-sponsored-enrollment-candidate-v1`
with AAD lane `protected-enrollment`. The envelope ID commits the payer and
nonce in the AAD. The outer sponsor proof uses the existing finalized
sponsorship delegation, with pure ML-DSA-87 context
`AEGIS.PW13.SPONSOR.ADMISSION.CANDIDATE.V1`. It signs SHA3-512 over
`AEGIS/PW13-SPONSOR-ADMISSION-CANDIDATE/v1`, a zero byte and compact JSON in
this member order: `genesis`, `action`, `gas_limit`, `maximum_total_fee`,
`valid_until_finalized_height`, `sponsor_intent_digest`, `envelope_id`.
The outer request contains the resource record, complete identity carrier,
ML-DSA-87 public key and signature. The original sponsor intent, enrollment
bytes and D/P/R evidence remain encrypted. Approve the outer disclosure of
payer, nonce, action and resource bounds before any activation.

The local native APQE test authorizes the envelope before decryption, checks
the exact opened sponsor intent and delegated key, and uses the same salted
commitment for a paid commit and valid reveal. Each encrypted settlement
records the original envelope ID, processing context, authorization height and
payload root atomically with the sponsor fee, nonce and enrollment changes.
The reader can require an exact match to that opening after reopening the
state store. Invalid reveal proof or a failed fee credit rolls back sponsor
and enrollment state together. The ordered candidate also records
a paid revert when a second fully authorized reveal for the same finalized
commitment encounters the exact earlier reveal in the same working block.
Only the second sponsor fee, nonce, and outcome change. This is a specific
candidate classification for ACT-12 and FEE-05. The deciding body still must
approve the classification, signed ingress carrier, resource pricing and
production receipt publication.

The isolated funding qualification starts with a separate authenticated
treasury holding the 5,000,000 SNRG fixture allocation. After sponsored reveal,
an ordinary native transfer signed with the pinned APQE provider credits
100 SNRG to the same enrolled account. The scheduler requires matching
canonical policy and ledger records in the finalized and ordered Worlds.
It rejects unfinalized enrollment, missing records and a modified signed
amount. The credit leaves the recipient policy and nonce intact, charges the
treasury 840,000 nWei, and survives reopening the World store. Replaying the
original signed bytes charges zero and leaves the restored state unchanged.
The selected credit policy is test-only. Live Canary funding requires an
approved protected registry, the governed treasury allocation and authority,
and proof of the resulting finalized balance and receipt.

The transfer candidate uses processing profile `etdag-pw13-transfer-candidate-v1`
and AAD lane `protected-transfer`. The original envelope ID commits the AAD,
ciphertext and capsules. D and P independently sign SHA3-512 over
`AEGIS/PW13-TRANSFER-ADMISSION-CANDIDATE/v1`, a zero byte and the compact JSON
resource record. The canonical member order is `genesis`, `account`,
`policy_epoch`, `policy_hash`, `gas_limit`, `maximum_total_fee`,
`valid_until_finalized_height`, `native_intent_digest`, `envelope_id`.
Integers use decimal JSON, binary fields use byte arrays, and the envelope ID
uses its canonical lowercase hexadecimal string. The two proofs are D then P,
each naming its enrolled participant and key version and using pure ML-DSA-87
context `AEGIS.PW13.TRANSFER.ADMISSION.CANDIDATE.V1`. The 663-byte resource test
vector is pinned in `synergy-etdag/src/admission/protected_transfer.rs`.

The candidate verifies finalized source, policy, nonce window, gas limit,
fee affordability and both proofs before opening the ciphertext. It compares
the exact decrypted native intent digest and resource fields with the signed
header, then applies the original native D/P checks again before ledger writes.
The test uses native APQE ML-KEM-1024 and ML-DSA-87 with an isolated state fixture.
The live ordinary ingress rejects this profile. Before ratification, approve
disclosure of payer identity, nonce and resource bounds before reveal, qualify
mobile D/P signing of the separate transcript, and integrate the approved
fee reservation, durable dispatch and recovery rules. Recipient and amount
remain encrypted through the existing reveal path.

Core's native processing pipeline now constructs a budgeted, zeroizing
plaintext owner after checking reveal permission, signed shares and the
original authenticated envelope. The existing ordinary decoder consumes
that owner and verifies the exact admission carrier and signature before
publishing a ready transaction. The compiled PW13 sponsored enrollment and
transfer executors consume the same owner's checked payload against the
original envelope and context. Isolated qualification uses real native
ML-KEM-1024 capsules and APQE ML-DSA-65 signed shares through that owner.
The tests reject insufficient shares, changed signatures, and substituted
envelopes or contexts. The live processing profile still requires ratified
admission, readiness and dispatch rules for PW13.

The canonical pending processing store now accepts typed admission records.
The protected fixtures persist each original encrypted enrollment or transfer
request, reopen the store, and verify the recovered APQE proofs against the
original authorized context and consensus timestamp before reveal. An exact
retry returns the existing envelope identity. Changed request bytes and an
incorrect source timestamp are rejected. The fixture then checks the same
envelope's opening in the resulting settlement. Protected records require
the corrected ML-KEM link. Qualification of live dispatch still requires the
approved activation, fee reservation and certified processing transitions.

The native vertex verifier now accepts a typed admission carrier. The protected
qualification restores the original request from the pending store, binds its
signed gas limit and encrypted envelope to the vertex, and checks the author,
weighted availability quorum and ingress keys. The existing group transition
records the exact member and sender nonce. The fixture opens the payload after
the successor group closes that assignment. Substituted availability proof
bytes are refused. The selected fee class and PoSy parent coordinates are
fixture inputs. Live protected readiness and ordered execution still require
the ratified policy and authenticated parent chain.

Ordinary and protected candidates now share READY record construction and
the parent-derived transitions that publish and consume those records. The
protected fixtures reopen the retained admission, verify the signed opening
and stage the action against a private budgeted World before READY
publication. The next candidate authenticates the same plaintext, applies
the action and its fee, nonce and settlement writes, and consumes the READY
entry and original nonce claim. The fixtures cover sponsored commit and
reveal, an applied D/P transfer and refusal of an altered D proof. Their
ordering and inclusion coordinates are isolated engineering inputs. Live
activation still requires the ratified dispatch and resource contract.

The offline settlement verifier checks the exact encrypted transfer and
sponsored enrollment receipts against adjacent three-QC-certified blocks
and their Worlds. It checks first appearance, the certified inclusion time,
the original opening and per-action nonce effects, and projects actual
account state at each block boundary. The engineering tests cover applied
and reverted transfers and a sponsored reveal after reopening the state
store. The public disclosure and live activation decisions remain pending.

For ACT-12 and TX-04, the ordered transfer candidate now distinguishes an
included transfer failure from pre-inclusion refusal. It proposes paid reverts
when a signed transfer could debit and credit at its finalized source, the
current policy and nonce still authorize it, and ordered execution leaves too
little balance for the full debit or too little capacity for the recipient
credit. The current sender must still cover the authorized fee. The exact
encrypted opening, reason, requested amount, zero credit, charged fee and one
nonce advance are committed atomically. Replay, an infeasible finalized
source, invalid authority or an unpayable fee leave the World unchanged.
Approval must bind these exact classifications, precedence, fee and retention
rules to the real protected admission and execution path.

The recovery fixture exercises the native state machine for replacing either
D or P. R plus the current survivor authorizes scheduling with replacement-key
possession. A finalized pending record survives reopening the state store.
Before the deadline, D and P can cancel or the current replaced role can veto.
Each successful termination consumes one fee and nonce, and its effect takes
precedence over a stale finalized view of the schedule. The isolated activation
advances the policy epoch at the deadline, preserves the address, aggregate
point, balance and continuing nonce, and changes which D/P signatures verify.
These local writes use a synthetic continuity reference. Production scheduling
and activation require an approved continuity verifier, a governed scheduler,
terminal receipt evidence and an independent custody recovery drill.

The isolated scheduler visits a caller-bounded prefix of a finalized deadline
index, ordered by activation consensus time and canonical account ID. Each
entry is tied to the exact pending reference and transition type. Scheduling,
cancellation, veto and activation update the pending record and its index in
the same atomic write. A prior canceled or vetoed entry in the working proposal
cannot be revived from an older finalized snapshot. The scheduler prepares
the entire selected batch before its atomic write and leaves accounts and
nonces untouched at activation. This candidate index has no production
resource limit, migration, or live scheduler binding. Those require a
governed work budget and measured queue behavior.

The proof-bound account reader now projects the exact pending transition as
`pending_transition`: either `null` for no record in that certified World, or
`scheduled_candidate` with ordinary/recovery mode, exact reference, replaced
D/P role, old epoch and old/new policy hashes, scheduling height/time and
activation consensus time. It validates the canonical replacement, selected
account/Genesis, source position and matching deadline index. A recovery
continuity reference is checked for presence, not treated as a qualified
external DKG proof. See the [proof contract](../rpc/finalized-proof-v1.md#protected-candidate-state-inspection)
for exact fields and refusal semantics. A missing record cannot identify an
earlier cancellation, veto or activation.

The candidate writes one terminal settlement per completed schedule, keyed by
account and original pending reference. It inserts that record in the same
atomic World diff as cancellation, veto or activation. A signed terminal action
records its exact intent digest, gas, fee and nonce advance. Automatic
activation records the old and new policy and epoch with no signed charge or
transaction. The verifier can read the record from any retained certified
World containing it, including after a restart, and can require the original
signed digest for a specific cancellation or veto. The verified World root
commits these records without changing the block or receipt encoding. The
candidate retention and write budget, disclosure policy and live executor
binding still require approval. `pending_transition:null` alone cannot identify
a terminal action.

Current Canary qualification concerns Val2/3/4/6 against the authenticated
five-member denominator; it does not redefine quorum or require an invented
fifth current host. The planned fresh PoSy testnet is chain ID 1266 with fresh
Genesis and Val1 freshly provisioned alongside those four, only after current
Canary qualification and separately reviewed retirement/formation. Historical
five-host requirements in the frozen packet are not fresh evidence of either
cohort. Bind client state and pending intents to original Genesis/incarnation,
not chain ID alone. This supplement authorizes no retirement or reprovisioning.

Before proposing activation, supply proof-bound sender/recipient membership and
explicit absence, exact policy/epoch/nonce/balance and receipt/fee evidence, and
the original unconsumed and consumed commitment observations at certified
heights. A finalized record without authenticated time cannot establish the
7,200-second enrollment window. Unavailable/pruned evidence is not absence.
The current time-verifier implementation and its focused tests must be reviewed
at their final source revision; this document does not declare them qualified.

Recommended next action: APQE/security supplies the missing DKG admission and
per-target provider evidence; Core completes the admission, fee, scheduler and
finalized activation contracts; Wallet verifies their independent fixtures and
physical-role outcomes. Then the actually authorized body can decide the final
hash-bound instrument. Until those conditions hold, retain
`UNRATIFIED_DISABLED`; do not schedule an activation or manufacture a signature.
