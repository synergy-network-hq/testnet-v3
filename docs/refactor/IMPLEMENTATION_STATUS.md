<!-- Current fleet replacement authorization: 2026-11-02 -->
Operator explicitly requires replacing obsolete Val2–Val6 applications via the canonical Linux node setup architecture, using actual validator VPN. All5 node services inactive; VPN active, all20 pair reachability checks pass. Canonical package APQE provisioning/commissioning/replacement support is being completed before deployment. Fresh APQE inputs generated; no installed replacement yet. Runtime provider-context regression and strict Clippy pass; actual fleet encrypted execution/recovery remains OPEN. Refer to current fleet section of `../../APQE_COMPLETION_AND_POSY_UNBLOCK_TRACKER.md`; older unchanged-fleet statements below are historical and superseded for this authorized replacement.

<!-- Current continuation: 2026-11-02 -->
APQE secured five-process canary milestone remains OPEN. New uncommitted secure-first NetworkService, signed transport registry/fingerprint pins, opaque consensus+ingress custody, authenticated endpoint discovery and actual session telemetry compile; strict targeted checks pass at integration checkpoints. Actual child-process fixture is running on Linux after correcting its explicit-provider Genesis verification. Finality/ETDAG/restart/resource acceptance has not passed. See the current active section in `../../APQE_COMPLETION_AND_POSY_UNBLOCK_TRACKER.md`; historical assertions below do not establish current transport qualification. Live Testnet-v3 unchanged.

# Production node implementation status

## P0 native PQ-only policy correction — 2026-11-03

This current section supersedes earlier compatibility/transport acceptance claims
below. APQE is mandatory for native cryptographic operations; no historical
classical authority exemption exists. Core currently compiles against APQE
`a0a71c739cd429231c62e3ff19c8397f10ac0a17`. Core remains a pre-existing dirty
integration tree, not a published clean revision or installed fleet candidate.
No deployed configuration, identity, key, Genesis, journal or service changed.

Transport session continuation (source-only; not qualified): the actual handshake
challenge now obtains its 32-byte nonce through APQE entropy. The production
`start_with_services` boundary rejects unqualified transport immediately after
configuration loading, before lifecycle/service effects. Production network
registration, service start and both socket directions independently reject the
unset session profile before network I/O. Only `cfg(test)` offline fixtures retain
the signed plaintext transport for engineering regression; they grant no production
qualification. The always-failing typed profile gate has no configuration waiver.

Current transport authority settles independent ML-DSA-65 transport signatures,
APQE-only native primitives and PQ-only key establishment/record protection. The
older directive's generic ML-KEM-768 establishment reference does not authorize
reusing the distinct entropy role or ETDAG ingress key for transport. No approved
transport KEM identity binding, role-specific key enrollment, transcript, key
schedule, key confirmation, nonce allocation/rekey policy or record serialization
was located; the as-built cryptographic-profile record remains `INCOMPLETE`.
No new record protocol is invented here. Existing APQE AES-256-GCM primitives
remain the single primitive owner; availability is not a session specification.

Current local checks: `synergy-network` 20 library tests, 2 integration tests of
the normally compiled library/profile and production entrypoint gate contracts,
and 7 `synergy-config` tests PASS. The actual production `synergy-node` binary
passes `cargo check`. These prove fail-closed source/configuration and APQE entropy
routing, not an encrypted working session, authenticated record interoperability,
or a successful live node launch. The mounted filesystem reports incremental
hard-link fallback warnings; no cryptographic or compiler failure remains.

Implemented corrections:

- Transport-registry Ed25519 verification/dependency removed. Explicit injected
  APQE ML-DSA-87 verifies the same canonical registry payload. Only canonical
  `ml-dsa-87:` public/signature encodings are accepted. Old no-provider trust
  construction fails closed; classical signatures are never imported as native.
- `NativeTransportPolicyError` rejects NetBird/WireGuard Required/Preferred
  configuration. Read-only preflight rejects raw TCP as missing explicit
  APQE ML-KEM-1024 plus authenticated AES-256 record protection. ML-DSA-65 peer
  authentication alone is not PQ confidential session establishment. No new
  session protocol was invented or qualified to bypass this blocker.
- Normal Genesis CLI sign/verify/binding require authenticated provider flags.
  Keytool authority/release signatures and consensus-65/ingress-1024 generation
  use an explicit authenticated APQE context. Other cryptographic keytool
  commands fail before input access until their role-bound migration exists.
  ML-KEM-768 metadata is rejected as protected ingress; it is entropy-only.
- Production embedded `PqvmVerifier::new`, `PqvmSigner::from_secret_key_bytes`,
  `PqSynqVerifier::for_network` and `PqvmMlKem768` operations fail closed. Explicit
  provider constructors remain functional. Library-only unit fixtures may
  exercise legacy PQ algorithms, but normally built consumer libraries cannot
  use those constructors as an APQE bypass. Identity authorization without an
  injected verifier and ETDAG no-provider KEM encryption/possession/decapsulation
  also reject production calls. Unmigrated consumers lose capability explicitly.
- New `encrypt_protected_payload_with_kem` requires ML-KEM-1024. ETDAG nonce,
  content-key and share-coefficient randomness now delegates to APQE Primitives,
  as does the common entropy provider. Exact AES/hash/KDF wire bytes remain.
  Shamir arithmetic is unchanged and is not an APQE threshold-custody claim.
- Genesis canonical hashing, key fingerprints, identity authorization hashes,
  node PQSynQ artifact hashing and embedded PQSynQ canonical network/address/body
  SHA256 operations delegate to APQE/Labs Primitives without byte changes.

Current focused evidence (not a whole-workspace compliance claim): transport
registry 10/10 including actual native signatures and unconditional classical
rejection; config 7/7 including typed unqualified transport; production-library
mandatory-APQE rejection 1/1; native Genesis V1/V2 CLI 4/4; current APQE v2 opaque
custody plus mandatory journal/restart/conflict native regression passed 6.14s;
real native keytool release/profile rejection and distinct consensus/ingress
key-generation tests 2/2 in 0.07s; canonical PQSynQ integration vectors 23/23.
Owned-native Rust classical implementation/dependency guard passed 2/2. Earlier
broad suites that rely on embedded consumer fixtures are not current passes after
production fail-closed enforcement; those fixtures need explicit APQE injection.

Outstanding blockers/owners:

- Native transport has no qualified PQ-only record/session layer; NetBird,
  WireGuard and any classical TLS/control-plane authentication cannot be counted
  as native PQ security. No end-to-end PQ transport or readiness claim is made.
- Disabled keytool root/node/wallet generation, wallet signing/import/capsule
  utilities need explicit APQE role/context APIs. Preparation and public
  inspection must not grant cryptographic authority. Authority/release helper
  compatibility paths without a context are unavailable in production.
- Core's opt-in consensus custody/journal adapter is not normal runtime custody
  activation; new APQE v2 role bundle must not be relabeled or auto-converted.
- Remaining direct primitive owners include synergy-address registry/address
  hashes, protocol/state/receipt/snapshot hash callers and disabled keytool wallet
  construction. Their canonical bytes must be preserved while delegating owners.
  Neither SHA256 nor SHA3 is classified as classical asymmetric cryptography;
  effective security must be assessed per protocol use, not by renaming hashes.
- Old `networks/testnet-v3/runtime` and `testnet-v3/runtime` still contain Ed25519
  registries. Scoped instructions mark them frozen semantic/release history;
  current node-platform Cargo/build scripts do not include them. They remain
  forbidden/unqualified native migration input, not compliant current owners.
  No historical source or governed artifact was bulk rewritten.
- Pre-P0 Linux async socket failure remains a distinct paused investigation;
  Darwin diagnostic rerun passed 206.40s overall and deleted its disposable log.
  Old socket/resource binaries do not establish post-policy acceptance.


## APQE integration continuation — 2026-11-02

Core remains on the existing dirty integration checkout (HEAD ad615c07); no live
validator was contacted, started, upgraded or reset by this implementation work.
Local socket evidence is not five-host operational acceptance.

The canonical synergy-aegis SHA3 framing delegates to APQE without changing bytes.
Explicit APQE signer/verifier/KEM adapters preserve raw FIPS profiles and canonical
signing preimages. Native adapter/hash tests passed on Darwin and actual Linux
(Labs backend 0.2.3). Node configuration requires an authenticated native report
for migrated production callers; no environment discovery or production embedded
fallback is provided. Dedicated transport workers serialize their engine. Main
consensus, wallet and identity adapters remain nonblocking. Bounded preparation
threads own independent engines, cached once per thread and replaced when the
source authority changes. Immutable authority policy/world and binding bytes are
shared rather than copied. A held-parent-provider native regression verifies
consensus, wallet and root proofs independently, cache reuse and obsolete-context
release; it passed in 0.18 seconds.

APQE-selected funded five-authenticated-socket transfer passed after identity/KEM
migration (77.18 seconds), and asynchronous encrypted pending work, spanning
blocks, restart and actual wallet effects passed (118.46 seconds). Post-worker-isolation Darwin reruns passed: funded 94.71 seconds and async
pending/restart 134.10 seconds. Actual Linux counterparts remain separately
tracked by the parent qualifier. Native KEM
compatibility regression passed (0.43 seconds): FIPS203 decrypt, ordinary rejection
of historical wrapping, historical-pending-only recovery and unchanged serialized
original pending bytes. Bad-capsule pending-preservation/empty-finality restart
passed (123.95 seconds). These test durations are not block-finality SLA results.

Library suites passed: ETDAG 62, execution 44, identity 9, transaction 5, Genesis 2.
Configuration 6, Linux conformance 15 and strict node/Aegis Clippy passed. Physical
Linux synergy-aegis native adapter/hash tests passed 4/4. The new APQE-selected
real-signature storage fixture passed 32 heights locally (28.33 seconds; hot READY
10, archive cache 323072 bytes). It streams 1000-height checkpoints, RSS/HWM when
available and final replay metrics; disposable state is removed on unwind. This
prototype is not the outstanding 10k/100k resource qualification.

### Current Core source dependency ownership

Paths below are relative to `node-platform`; entries describe current source,
not an installed executable or completed deployment.

| Owner | Current constructor/caller | Remaining boundary |
| --- | --- | --- |
| Native provider selection | `bin/synergy-node/src/services/apqe_provider.rs::load/load_selected` | Explicit pinned report/hash and protected immutable native files; no discovery. Loader dependencies remain operator trust responsibility. |
| Consensus/authority/ETDAG signatures | `services/{authority,posy,etdag}.rs` → injected `PqvmVerifier::with_apqe` / `PqvmSigner::with_apqe` | ML-DSA-65 bytes and signing journals unchanged. Legacy constructors in these services are test-only. |
| Transport/snapshot/update | `services/{network,network_session,sync,admin}.rs` | APQE signature providers; transport serialization is confined to blocking I/O workers. |
| Selected signed Genesis | `commands/selected_network.rs` → `synergy_genesis::signing::verify` and `verify_binding_with_verifier` | Injected APQE verifier; no signed format/domain/hash change. Offline CLI sign/verify/verify-binding now require explicit authenticated report flags and inject APQE. Library-only no-provider wrappers now fail closed in production. |
| Native wallet admission and first-use authorization | `services/protected_admission.rs`, `synergy-identity/src/{authorization,registration}.rs`, `synergy-transaction/src/signature.rs`, `synergy-execution/src/scheduler.rs` | Node supplies APQE FN-DSA-1024 root / ML-DSA-65/87 proof owner; unchanged carrier scope, commitment, effective time and first-use rules. Public compatibility wrappers remain for other consumers/tests. |
| Async processing verification | `services/processing_pipeline.rs` → authority-owned wallet/identity verifier and `TransactionPqvmVerifier::from_authority` | Actual inner signature and root proofs use APQE. No reserved FN-DSA-512 or other profile activated. |
| Protected ingress KEM | `services/etdag.rs::load_ingress_custody`, ordinary reveal and `etdag_processing_work.rs` → explicit `ApqeKem::mlkem1024` | APQE possession and FIPS203 decapsulation. Historical KDF recovery stays restricted to authenticated durable version-1 pending records; provider failure is a service error, never a historical fallback or invalid-wallet classification. |
| Canonical SynQ execution authorization | `services/execution.rs::CanonicalSynqRuntime::new` → `synergy-aegis/src/pqsynq.rs::PqSynqVerifier::with_apqe` → embedded policy verifier with injected raw signature callback | Production ML-DSA-87 signature verification is APQE-owned; policy/domain/address/body commitments remain canonical PQSynQ. Compatibility `for_network` remains for other consumers/tests. Existing SHA256 address/body/bytecode construction remains a direct primitive owner; no second runtime introduced. |
| ETDAG symmetric/hash/share constructions | `synergy-etdag/src/crypto/{protected,shamir,...}.rs` | AES-GCM, exact capsule SHA3-512 KDF, historical SHA3-256/SHAKE256 and canonical ETDAG digest framing now delegate to stateless APQE/Labs Primitives. Random generation and Shamir field/share construction remain direct owners; no threshold-custody claim. |
| Runtime custody/signing safety | Existing bounded raw-key loaders plus `DurableSigningAuthority` / `SignOnceJournal` | APQE encrypted custody payload is not the runtime key-file format. Canonical encrypted-custody import, public-binding validation, passphrase handling and existing signing-journal continuity remain required; no plaintext extraction or journal reset was introduced. |

### PQSynQ authorization owner migration — 2026-11-03

The embedded policy verifier now accepts a raw signature callback after its
existing context/domain/algorithm/address/body-commitment validation and exact
`canonicalize_signing_payload` serialization. Canonical execution initialization
injects APQE ML-DSA-87; production never silently selects the compatibility
provider. No serializer, account-domain preimage, FIPS context, raw key/signature
encoding or AIVM execution owner changed. Missing/contended native providers
remain explicit provider errors rather than signature-invalid classification.

Darwin native tests passed 6/6 including deploy/call positives, equality with the
legacy verifier result and wrong domain/chain/network/algorithm/key/signature,
nonce, invocation and bytecode substitution rejections. Held-provider contention
and missing-provider fail-closed behavior are covered. Strict node/Aegis all-target
Clippy passed. Execution passed 44/44; the three compatibility integration suites passed 23/23 under the actual consumer feature set (`--no-default-features --features std,mldsa`). Current funded APQE socket initialization passed in 71.78 seconds. Physical Linux native adapter/PQSynQ tests passed 6/6. Direct PQSynQ SHA256/address/body primitives
remain a separate ownership increment; callback injection does not claim all
cryptographic constructions are APQE-owned.

### Protected-envelope primitive owner migration — 2026-11-03

`synergy-aegis::AegisProtectedPrimitives` explicitly delegates AES-256-GCM and
fixed SHAKE256 output to stateless APQE/Labs `Primitives`; it does not select or
lock the dynamically loaded PQC engine. ETDAG uses this boundary plus the existing
APQE hash boundary for its exact framed SHA3-512 capsule KDF and shared 64-byte
ETDAG digest (including key/share commitments). Nonce, AAD, appended 16-byte tag,
length/domain framing and historical SHA3-256→SHAKE256(32) bytes remain unchanged.
Historical recovery still requires authenticated durable version-1 pending data;
no fallback or Shamir arithmetic change was introduced. AES is now a dev-only
ETDAG dependency for independent old/new parity checks. Derived SHAKE storage and
the temporary capsule digest are wiped after copying their required output.

ETDAG passed 63 tests with one native test ignored (47.74 seconds); the native
FIPS/historical-pending-only/serialized-pending preservation test separately passed
in 0.42 seconds. Final-source parity/tampering test passed, including empty payload,
cross-backend encrypt/decrypt, wrong key/nonce/AAD, tag/ciphertext corruption,
truncation, exact old capsule KDF, historical derivation and commitment bytes.
Strict all-target Clippy for node/Aegis/ETDAG passed. This establishes primitive
ownership and compatibility, not operational fleet readiness.

PQSynQ standalone default-feature compatibility blocker remains explicit:
`cargo test -p aegis-pqsynq --test synq_verifier_tests --test canonical_payload_tests
--test synq_deploy_vector_tests --quiet` fails arm64 linking with unresolved
`_PQCLEAN_randombytes`, referenced by vendored `PQCLEAN_FALCON512_AARCH64` and
`PQCLEAN_FALCON1024_AARCH64` keypair/sign code. Default PQSynQ features enable
legacy `fndsa`; the canonical production consumer in `synergy-aegis/Cargo.toml`
already disables defaults and enables only `std,mldsa`. This callback migration
changes neither those feature declarations nor vendored FN-DSA C linkage.
The 23-test result above is the production feature set, not a default/full-profile
pass. Optional legacy FN-DSA linkage needs its own repair and qualification.

### Offline Genesis signature owner migration — 2026-11-03

The standalone CLI requires trailing `--apqe-report ABSOLUTE_PATH
--apqe-report-sha256 AUTHENTICATED_LOWERHEX` for `sign`, `verify` and
`verify-binding`; `hash` stays provider-free. New signing usage is
`sign UNSIGNED KEY_ID SECRET_KEY TRUST_PUBLIC_KEY OUTPUT` followed by those flags.
The explicit public key is necessary because unsigned Genesis contains the trust
key ID but no authority public key. APQE verifies exact private/public possession
before producing output. Secret material remains a bounded permission-checked
non-symlink file, never an argument value or diagnostic. No discovery/fallback,
Genesis field, serialization, signing domain, hash or authority format changed.

Node and CLI share `synergy-aegis::load_authenticated_native_engine`; the node's
existing absolute-path/bounds/symlink/file-and-directory-permission checks and
five required native artifact checks moved intact. The operator still supplies
the authenticated hash and protects immutable native files/dependencies. Output
uses existing guarded atomic storage with a Missing precondition to prevent a
concurrent writer from replacing an existing Genesis. Cross-network and fleet
qualification wrappers pass explicit pins; the latter reads each node's explicit
provider configuration and includes it in verification cache identity.

Genesis tests passed 4/4 including actual native V1/V2 sign/verify and legacy
verification of the resulting signatures, exact canonical payload preservation,
wrong trust/report/tampering rejection, private file permissions and refusal to
overwrite/create output after failed possession. Native test duration 0.50 seconds.
The valid authority-binding CLI path delegates to the existing injected canonical
library verifier; no new positive full binding fixture was generated in this
increment. Fleet wrapper tests passed 34/34. Strict Genesis/node/Aegis all-target
Clippy passed. This does not alter any existing Genesis or installed validator.

### Current immediate liveness investigation — 2026-11-03

Physical Linux protected primitive/native tests passed 5/5 in 0.79 seconds and
funded socket passed 108.86 seconds on the qualified binary. The async pending/
restart socket then failed after 185.76 seconds with all five at finalized H13,
observed H16 round0. Four peers had valid finalized order-H10 reveal fences;
permission retries on the deliberately held lagging validator are expected.
A failure-only bounded fixture diagnostic now reports elapsed/progress age and
per-node original/availability/reveal/share/completion/build/sync stages. Exact
Darwin rerun is in progress. No timeout, quorum, permission or cryptographic
classification change is justified by the current observation.

### Opt-in consensus custody increment — 2026-11-03

APQE now exposes an opaque, nonserializable `ConsensusCustodyHandle` from the
existing `apqe-validator-bound-private-v1` encrypted bundle. Unlock reuses full
network/enrollment and all-five-key correspondence validation, checks the admitted
consensus public key, and retains zeroizing secret memory without an export API.
The handle signs unchanged raw ML-DSA-65 canonical bytes. Typed transport-ML-DSA-65
and protected-ingress-ML-KEM-1024 requests fail with profile mismatch because v1
actually contains Ed25519 node identity and ML-KEM-768 entropy keys. No key purpose
or algorithm was relabeled. Partial serde failures own zeroizing secret fields;
noncanonical escaped custody JSON is rejected before decoded parser scratch can
copy secret text. Provisioned canonical ASCII/hex v1 remains compatible.

Core `services/custody_signer.rs` is an opt-in API, with no CLI/default runtime
activation. Its private-field `AuthenticatedCustodyNetwork` can be minted only by
verifying exact bounded selected signed-Genesis bytes with the existing pinned
trust root; SHA256 of those same bytes and explicit 32-byte big-endian chain ID
bind the bundle. The token also binds exact immutable authority bytes and network
ID, preventing reuse for another authority incarnation on the same numeric chain.
The adapter checks active frozen ML-DSA-65 membership and exact public key via
`VerifiedAuthority::consensus_binding`, then returns only the existing
`DurableSigningAuthority` around the caller's recovered `SignOnceJournal`.

Validation: APQE 67/67 library tests including native providers passed (13.01s),
check/build/strict all-target Clippy passed. The Core native encrypted-custody
regression passed (6.66s): original journal reopen returns identical signature,
conflicting subject/transcript refuses without altering bytes, wrong passphrase,
unsupported role and mismatched authority token refuse. Core strict all-target
Clippy passed. Actual Linux validation/new sealed artifact rebuild remains required;
older sealed candidates do not contain this increment.

Next activation scope remains bounded passphrase delivery without argv/environment
or logs, explicit custody configuration, proving the selected Genesis digest and
admitted identity for the actual network, and integrating the opaque signer at
`posy::load_local_signer` after complete canonical safety recovery. Preserve the
existing journal path/finalized floor and no duplicate active identity. Runtime
P2P and ingress need separately approved role profiles and compatible bundles;
they cannot consume v1 Ed25519/ML-KEM-768 under ML-DSA-65/ML-KEM-1024 labels.
No plaintext extraction, live conversion, journal reset or validator operation was
performed. A recovered journal argument is still a mandatory adapter precondition;
the opt-in API does not perform fleet recovery on the caller's behalf.

APQE exclusivity for all Core cryptography is not claimed. Linux node qualification,
actual mobile interoperability, 30-second finality-gap, sustained resource bounds,
10k/100k growth and five-host restart/recovery remain release gates.

## Integrated upgrade execution ledger — 2026-10-31

Canonical source: node-platform on branch reconcile/core-protocol-root-2026-09-15,
HEAD ad615c07b3d8ed05c6a6989cdb4dc558ee194fe6, with uncommitted integrated
work; package revision currently running nowhere is
synergy-linux-58db14bdb6534672. A source package was sealed on Oct 31
(manifest SHA-256 cdabe7d41bc9f37b677abb3edc8c00f51b3c29e4ee79db22cfad66de84d1215b)
but is held from deployment because the mobile-to-validator KEM crossprobe
reproduced CapsuleAead failure. A corrected release is not yet sealed.

| Workstream | Current result | Blocker and next dependent action |
| --- | --- | --- |
| Runtime/reveal | Per-item invalid-capsule isolation passed exact crypto tests, five-socket restart regression and strict Clippy; source frozen. Current native backend builds historical Kyber1024 under ML-KEM names. | Prove existing-key compatibility, correct backend and historical pending recovery without bypass; rebuild sealed package before fleet upgrade. |
| Mobile/native crypto | Hermes/JS/ObjC source tests pass. Actual mobile CLEAN C capsule to authenticated Val2 public key fails newly built Rust keytool at CapsuleAead; cross-runtime mismatch reproduced. | Validate corrected native decrypt against original pending mobile capsule, rebuild/install device, then real Send. |
| Wallet authorization | Identity9, execution44, mobile import4 and strict Clippy PASS on reviewed source. | Actual new/imported mobile encrypted Send across all five. |
| Memory/storage | Aggregate 32 MiB retained history and 8 MiB pending handoff source regressions passed, including retirement/reopen and candidate store; no source change. | After safe restoration, verify 1 GiB/swap0 resource and storage growth under real work. |
| Generator/soak | Bounded proof reader and honest first-use/cancellation reporting, adapter28/TPS68/supervisor34/Atlas5 PASS. | Run on recovered fleet after mobile correctness; measure actual finalized TPS then 24h soak. |
| Fleet/Atlas | Val2–Val6 stopped, VPN active, same package/node hashes and 1GiB/swap0; four durable H78310 agree, Val5 one behind. Atlas publishes stopped state. Current all-five stopped recovery archives restore-verified; disposable restore proofs deleted. | Deploy corrected identical sealed release after preflight, then verify advancing common finality and no restart loop. |


## Proven reveal failure substage — 2026-10-31

Read-only native capsule verification on original mobile envelope
4673c833305171d52bb3bb88afe7440dc89e23d3ff513271df3372689cd42a2255cd3e50a836545ec810ad8864d164c0af026f9e370de88b7e0d586460ea01e6
fails CapsuleAead on Val2 AND Val5. Shape/selected registry/secret parsing/key
possession pass; older Val2 nonce14 encrypted-envelope control decrypts. No
secret/share/plaintext exported; temporary diagnostic executable removed. A
fresh mobile CLEAN C encapsulation to the selected authenticated Val2 public key
also fails the newly sealed Rust keytool at CapsuleAead. Current node build.rs
selects historical Kyber1024 KEM sources behind ML-KEM symbol names, whereas
the wallet selects FIPS203 ML-KEM CLEAN sources; their shared-secret derivations
differ. The exact existing-key compatibility and safe historical pending
transition remain under test. No reveal bypass. Original nonce0 pending request
must remain unreplayed. V3/4/6 durable H78310/block989cb62d…/state055ff05b…
match; no current fleet-running claim. Identity9/execution44/mobileimport4 and
strict execution Clippy PASS; source-only acceptance, not mobile/fleet PASS.

## Current incident and staff dashboard — 2026-10-31

Dashboard publisher restored after its previous process exited on destination SSH
publication failure. Existing publisher now retries transient destination failure
using the same SSH owner socket. Current network-bound test plan replaces stale
Oct30 work items; live origin telemetry verified fresh (2.45s old at21:53:58UTC)
and allfive offline/PID0. No browser visual acceptance claimed.

Fresh read-only checks confirm allfive node services inactive/MainPID0 after the
single lifecycle stop; no additional restart or state reset. Native Val2/3/4/6
logs repeat `pending processing verification: UnauthorizedReveal` from ETDAG.
Exact cryptographic failure substage/cause remains unproved; do not weaken reveal
checks. Val5 had remained alive atH78309 before the controlled fleet stop.
No outbound mobile Send submitted. Automatic signed naming intent must be
reconciled before retry. Original custody, history, genesis and VPN preserved.
Wallet native balance/fee correction focused tests and iOS Release build PASS;
live device installation/Send pending runtime recovery. No TPS/soak running.

## Immediate mobile Send correction — 2026-10-31

User supplied existing test-wallet unlock credential; wallet unlocked through normal
UI. Do not repeat/persist credential. Home shows1SNRG, but Send0: SendScreen awaits
all external balance and market requests before publishing native balance. Send also
still displays obsolete hardcoded .000021fee despite runtime40nwei/gas and native
transfer21000gas. No outbound mobile submission. SynIDagent owns minimal mobile-only
selected-native balance independence and runtime fee display correction, focused test
then rebuild/install; no validator changes needed. Fresh allfive exact native common
H78293/block52533d38018370daca41d9362bd0ca9b5094ecac67416f0216e75a8184211eb2,
QC a2ae0844c6f6394158326408f633e0e585ee8cc2d81b69a11c24b52670bb4f8a,
mobilebalance1e9/nonce0/nobinding and NRestarts0. Prior send authorization remains valid.

## Current live wallet acceptance — 2026-10-31 20:08 UTC

Allfive RUNNING on identical universal release synergy-linux-58db14bdb6534672.
Package7e89c7f38044e817c811e1e64c872529cbc1e8e14c98be2626cae35416b64dbe;
node10418aad801e298c3c78be0e9661459e77cdeadb0445b5976388324dde9c324c.
Frozen source inventories/sealed Linux artifact PASS; features[]. Native owner-signed
encrypted wallet SynID registration and selected-runtime fee policy deployed.
StrictClippy PASS; naming8/SDK7/mobile32/init4/Atlas8 focused tests PASS. The
five-socket naming experiment admitted1/ordered0; no live SynID acceptance claimed.
Software-only upgrade preserved protected bytes/inodes/modes/owners1136/885/892/904/874
and each VPN PID. Fullhostconformance PASS allfive; normalized fingerprint unchanged
153a5881458dc517b839dea409beea825a82738434a69b9ad5cec18261855e8e.
Actual5s starts PASS V2=.619093/V3=.599431/V4=.417798/V5=.808036/V6=.435050s.
PIDs2803007/2717706/3399090/2578458/2721195, NRestarts0, original1GiB/swap0.
Exact allfive finalizedH76750 block897d944f637658ecb3ae29393bb9fed25a2ddc850e26f716e8ad959fbee6cccf,
QC88d7fb2431089fb4c8b904daf36e7253c25d8acfc86c803c0914ff202df9758f,
state78081e68dbbd2f397abf4bb573609f341edbbea40846204cb8a8d3bfc08fd8a4;
latest peersH76753, Val5 advancingH76750/healthy SyncPending. Not zero-lag/current
SyncReady claim. Current sampled blockgaps under1s, not continuous qualification.

Actual mobile synw1fx0ng53gvuv0xwtkrxnrw599797r39ysuynh funded1SNRG once from
receiver nonce6 txf6ff67a010a42c734cf53980b5ee548cfbe596dde9b1f7ca9c56932a4d670345:
allfive exactAppliedH76350/block edc4b7e86c885536ce4c3a356c1afca5d38234df15d043c6f16f77fde26bc465.
Exact balance1e9nwei/nonce0/noauthorizationbinding allfive; public gateway agrees.
Sole funding handoff consumed/deleted; never resubmit. Public V5/V6 checkpoint
bundles consumed/deleted after recovered live proof; deployment staging deleted.
iOS Release rebuilt/installed in-place with fee/SynID fixes, user wallet preserved;
now at Unlock Wallet, user asked to unlock when back. User explicitly authorized
prepared0.001SNRG normal encrypted Send when ready; no approval reask, no outbound
mobile intent yet. Keys/password remain on device; do not bypass unlock. SynID
jdh.syn still unregistered until canonical finalized owner proof. Legacy unsigned
registration remains blocked. Gateway23ca08f checked deployment PASS: authenticated public context, native resolve/reverse reads, unsignedregistration/admin reject-32601. Raw public fee_policy40/21000/1098576 verified (SDKnormalizedcontext omits fee fields, mobile consumes raw response).
Follow-up: exact allfive finalizedH76784/block585ac774af75e0e1e0e36b83f6de33b837bd048606fbc3a7a1953eedeca750dc/QCe8ca8df7796134d8b1c0a1a486f933a34b56bc6f8085e1a9bb236ac177d7b07b; advanced from76750, allfive SyncReady sampled, V5oneblockbehindpeers. Allfive originalPIDs/NRestarts0, memory.events max/oom/kill0 and1GiB/swap0. Cgroupcurrent59–69MB sampled. No workload/TPS/soak acceptance; no30s pertransaction deadline. Separate30s block
finality gap and original safety/resource rules remain. All uncertain prior intents
below remain unreplayed. Next: user unlock→normal first-use Send→exactallfive receipt
and balance/nonce proof; native encrypted SynID registration→finalized read verification.

## Active recovery window — 2026-10-31

Release synergy-linux-dcc9268fc57b95fe built/sealed from frozen source; package
4b6817a54276bd94514c591902ba60fc18e8acb9985abaf93c9415b87c1d7951,
node d8e93de8d9aef1bcdaa5ecc4757d512f7b26837706f20bc633c3248aec8ae1aa.
Certified Sync inputs bypass speculative slots into existing authenticated archive;
full speculative staging is retryable. Startup archives/compacts only original
staged inputs with matching verified native QC and durable VC; unmatched preserved.
Authentic encrypted/full32-slot/migration regression PASS32.19s; strictClippy PASS.
Identical package installed allfive after one coherent lifecycle stop. Protected
bytes/inodes/modes/owners unchanged1095/847/859/898/841; VPNPIDs unchanged,
allfive fullhostconformance PASS and normalizedconfiguration fingerprint
153a5881458dc517b839dea409beea825a82738434a69b9ad5cec18261855e8e.
All five services RUNNING after coordinated original5s readiness PASS (Val2=1.252917s, Val3=.963964s, Val4=.565221s, Val5=3.689084s, Val6=.696969s). PIDs2798432/2713246/3393802/2574609/2716597. Allfive exact finalized block/QC/state/protected execution commitment H76312 verified after forward recovery; live Val5 advancing within one block of peers. Native Val5 checkpoint import H70391→76196 completed successfully; durable block3d602e52…/state43c3bd61… and forward signingfloor76196 verified. Wrapper processing-directory equality assertion failed after native success because import adds certified archive/header; no retry. All32 original inputs+VCs remain with pre-import mtimes. Original1GiB/swap0, systemd226.6MiBpeak/4m10s. Next fee/SynID package pending; existing corrected recovery release is running.
Val5 exact anchorH70391/f3a6fdad…; floor70439 ahead of execution must be preserved.
Val6 stopped finalizedH76196/3d602e52…; state43c3bd61… same acrossfleet.
No reset/rollback/cap increase/newtransaction. Parent owns coordinated startup
only after native checkpoint verification; Val5 recovery agent owns V5/V6 until
it returns. User's actual wallet remains unlocked, Send prepared0.001SNRG to
receiver custody address but no funding/submission yet. SynID agent explicitly
requested by user, working signed canonical naming fix; legacy unsigned registry
must not be exposed. No TPS/soak/publicmobileacceptance PASS.

## Active continuation — public wallet acceptance and Val5 recovery, 2026-10-31

Identical release synergy-linux-628f8ad840cfc4b5 installed on Val2–Val6:
package aa29d326fed65090e720b4a3721b6f7b95239ce940266ebfa0a68a37fa0637d0,
running node SHA256 1120c1d41ff4ecabaca2b431a2bf30ace41382c677cc4c12430ad08364550cc2,
features[]. Exact source inventories matched through seal. Protected state/custody/
configuration metadata and VPN PIDs preserved by stopped software-only upgrades.
Recovery fix verifies complete stable VC/QC subject instead of invalid first-input
round ordering; signed regression and strict Clippy PASS. Original H65187 archive
SHA a6868ad4644c987ec1d787eaa2857af95d824c526469efc54729f8b95a61f9c0 unchanged.
Val2 native authenticated checkpoint bridge H65185→68097/292pages PASS, signing=false;
floor advanced only after verified commit, higher reservations preserved. Allfive
exact native commitments advanced H68097→68112 at12:49UTC.

Fresh18:35UTC read-only check supersedes that agreement: Val2/3/4/6 exact common
H75776 and ready, same release/PIDs2681233/2596129/3257901/2599469/NRestarts0.
Val5 now PID2495418/NRestarts1, finalizedH70391, Sync not ready. Val5 original runtime exited13:54:02UTC/status1: processing proposal staging is full.
Restart13:54:19; peers explicitly return candidate-unavailable for requestedH70392.
QC-certified Sync/ancestor inputs currently share32 pre-QC staging slots;
32 empty candidates filled Val5 slots and full was mapped to fatal Invalid.
Correction under test: verified certified archive path plus typed bounded
backpressure for genuinely full pre-QC staging, no eviction/cap increase. Allfive still same executable and
1GiB/swap0. Recorded cadence maxima exceed30s; recovery/maintenance intervals are
not a qualified continuous window. No TPS workload or soak launched, no new intent.

Actual mobile wallet was created by user (requested SynID jdh.syn). SynID verification
failed against older service; wallet persisted. Fixed optional registry failure to
publish usable vault snapshot and allow Continue to Wallet without claiming name
registration.16 focused mobile tests PASS; updated Release build PASS, installed
in-place and relaunched18:34UTC; user unlocked, Home and Receive visually verified.
Actual mobile address synw1fx0ng53gvuv0xwtkrxnrw599797r39ysuynh publicaccountnull;
no funding/submission yet. Eager offline MLDSA87 key
provisioning now precedes backup on create/import unlock;9 SDK/init tests PASS.
Normal Send uses public authenticated profile, lossless integer wire codec, local
keys/carrier and one-submit pending intent. Native finalized receipt observation
replaces false admission-as-confirmed UI; retained compact receipt is functional
wallet state. Actual mobile encrypted Send and imported-wallet acceptance NOT PASS.

Public profile https://testnet-atlas-api.synergy-network.io/posy-network is deployed;
exact authenticated genesis/authority raw hashes verified. RPC /posy-rpc gateway
strict ordinary-method allowlist and CORS verified. Existing index tunnel targeted
historical62.146.182.207, while actualVal2 is62.146.182.208. Dedicated208 tunnel
correction completed through checked repository script commit8a2faee, preserving legacy5640/5660.
Restricted index key enrolled on actualVal2; authenticated208hostkey verified from
existing management master. Public walletSDK authenticated live native processing context PASS; admin/unknown reject-32601.
Keep accepted uncertain intents unreplayed. No native state reset or binding bypass.

## Immediate priority — permissionless public-wallet access, 2026-10-31

User halted throughput/provisioning to correct mandatory sponsored wallet access.
Local commissioner PID16002 stopped with SIGTERM; no generator/soak was launched.
Wallets00–17 have finalized funded bindings;18 funding transaction
c28f770c931bd5df41ce367973339b4fa9da82a1d58548f37af240a23a556a95
sponsor nonce36 was already submitted; retain its sole sender18-transfer handoff
until reconciled, never resubmit. No registration18 or later wallet authoring
is authorized under the stopped provisioning loop. Fleet remains running on
the unchanged release below; no validator restart/config/state mutation this turn.
Current runtime requires finalized bindings at admission, processing and execution;
registration requires an existing authorized sponsor, creating circular self-use.
Existing FN-DSA-root address derivation and root/delegated-key possession proofs
provide the basis for secure atomic first use. Runtime correction, actual mobile
wallet compatibility and public RPC access are now the release-blocking work.
No public-wallet compatibility PASS or first-use deployment is claimed yet.

Generator source corrections completed locally: bounded terminal aggregation,
sequential all-five block decoding, atomic rolling active-intent journal,
independent author workers, configurable async nonce window and rapid capacity
discovery separate from fixed-workload soak. Not deployed or live-qualified.
Interrupted35-intent run reconsumption verifies13 all-five Applied, identifies2
explicit RPC rejections (protected admission queue full), and retains20 exact
outcomes unresolved after historical execution payload retirement. Native local
finalized lifecycle/account nonce advancement is not substituted for all-five
Applied proof. No accepted intent is resubmitted. Its original stream remains
needed for immediate compact reconciliation; old low-rate ladder is superseded.

## Current continuation — corrected fleet and encrypted handoff verified, 2026-10-31

All five run identical universal release synergy-linux-a6dda6cfba67305a,
package61003cc642d2a712ebc3097a6ed3c4cc21d3e9c4944bb60faac431342ff8c09d,
node d6365a0b1421d88375469a9a5b6d5a2650b72fb3816f90dbd8d3ad2c73e7daf3.
Native regression and strict releaseClippy PASS. Exact-pending sender/nonce
filter avoids demanding a retired parent for unrelated authorization-source
pins; matching retirement still requires unchanged native execution/three-QC proof.
Val2 native certified checkpoint H57173→57258 PASS before stopped software-only
upgrade. Protected bytes/inodes/modes/ownership unchanged824/673/685/706/669;
VPN processes unchanged. Original5s readiness PASS Val2=.508193,Val3=.476195,
Val4=.548028,Val5=.700963,Val6=.341690. PIDs2620351/2518830/3172920/2408727/2520904,
NRestarts0, original1GiB/swap0. Native common commitments advanced57259→57264.

Fresh sendernonce15 transaction9480fd3cb2ad24e39c1966ace5c959670af90a560d8a3a7dd40606d5e03d966c
exact native applied receipt matchedallfiveH57294; verifier corrected to accept
native finite fractional-millisecond gap values while preserving30s bound.
Independent pool00nonce3 transaction7486374ca3b3a3d00453ce93e3ff0413834828c16cad9b0054fa87c5ec62f5ae
exact transaction/block/QC/fee/nonce/balance matchedallfiveH57395. Val2 measured
certified1.302801s,reveal-authorized5.973825s,execution-completed6.555236s,
finalized11.134117s; allfive effects verified by14.751054s controllerelapsed.
Canonical once-only tool tools/validator/accept-processing-once.py now atomically
updates its sole handoff with final stage timings before returning; interrupted
consumer/cleanup regression PASS and real handoff reopen equaled direct result.
Both consumed fresh handoffs deleted after exact all-five verification.

Old accepted f0e451042551c6396b6e45f1067a9595836793d7fa6dda798687e4312f8480fe
nonce14 remains locally pending onVal2 across certified import despite matching
fleet account state; never resubmit or retire based on nonce advancement alone.
Its sole original handoff latency-20261031T082005Z remains needed for exact
consumption-proof diagnosis. Public checkpoint bundles are now consumed and
must be deleted after recovered-fleet verification. No TPS/soak PASS claimed.
The first600s observation ended naturally allfive09:09:11–14UTC; observerPIDs
absent. No new finalized transaction activity because TPS preflight authored zero.
Allfive resource-event deltas max/oom/oomkill0 and swap0; cgrouppeaks100–146MiB,
497–498 advancing blocks, largest sampled current gap12.4278s. Not qualification
PASS or contiguous every-block gap proof. Consumed output deleted.

TPS harness corrected initial/live distinction: actualexec launch5s readiness
stays unchanged; later load-stage native health permits only healthy running
Sync Pending with its exact in-progress reason, requires other services Ready,
unchanged process identity, network/epoch, exact common commitments, boundedlag
and30s progression guard. No protocol/runtime/readiness setting changed.
66 focused harness tests PASS including original strict5s startup and unhealthy
live-service rejection. Timing verifier finite fractional-ms correction retained.
Live preflight PASS1.0209286s/block; zero-authoring wallet gate then correctly
rejected pool: allfive exact account readsH62882 establish onlysender00–05
have matching canonical finalized authorization; sender06–31 lack it. No key or
binding rewritten. Explicit --wallet-id selector added to existing harness;
selected wallets still pass all native custody and allfive authorization checks.
66 focused tests PASS. Fresh1TPS/60s unitfleet-tps-20261031-1tps-g now uses6
verified wallets/maxinflight6/perwallet1, original30s blockguard/180s optional
operational drain. No capacity claim; generator maylimit offeredload.
Fresh600s resource/readonlyrelay runfleet-tps-20261031T1040Z actualV2start
2026-10-31T10:37:16.762069UTC; name is NOT actualstart. Otherhosts ownmanifests.
All outputs /var/lib/synergy-qualification/fleet-tps-20261031T1040Z;
consume tps-1.json and tps-1-raw.jsonl before delete; neverresubmit uncertainty.
Previous600s observers ended09:25:55–56 allPIDsabsent/resourceeventdeltas0,
no newtxactivity; consumed/deleted. Setup mistakes consumed/deleted, no nodeaction.
Unitg COMPLETED17submitted/17finalized, allfive exactwallet effects PASS,
rejections0/unresolved0. Offered1TPS/60s was GENERATORLIMITED:43missedslots,
finalizedduringwindow11/60=.183333TPS; includingdrain17/85.995=.197686TPS.
Median/max submission→verifiedfinality23.399/30.219s; contextmax.145s,
signingmax.405s, transportmax.119s. This is not chain capacity. Consumedraw/report
deleted after effects reconciliation. Allfive latest resources originalPIDs,
max/oom/oomkilldelta0/swap0; sampledpeakcurrent118–320MiB, sampledcurrentgap
max5.629s, not every-block coverageproof. Original30s blockbound retained.
Higherconcurrency unitfleet-tps-20261031-1tps-h TERMINAL OOMKILL,
confirmedjournal separate256MiB generatorpeak,97.781s wallclock; no reportwritten.
35authored/submitted,13exact finalized_transfer frames beforekill; remaining
22mustreconcileoriginals; neverresubmit. Sole rawtps-1b-raw.jsonl and surviving
posy-async-authoring-ofigvnwe retainedforimmediate reconciliation/controllerOOMfix.
No nodecapincrease/protocolchange. Runbasefleet-tps-20261031T1040Z unchanged;
resourceobserversfixed600s actual10:37:16UTC end~10:47:17, checknativeendnotclock.
Immediate exact35tx queries dispatchedallfive throughlocalRPC viaexistingSSH,
localexecsession19208 currentlypending; do not duplicate queries whileactive.
Lastallfive resources originalPIDs,resourceevents0; no validatorOOMestablished.
Supervisor livehealth/walletselectorcorrection94testsPASS; notlaunched.
NoTPSuppercapacity/soakclaim. Fix demonstratedgeneratorOOMbeforequalification.
Operator pool registry refreshed from selected signed network context and native
EOF verification passed; no wallet/validator identity or key changed.
Transaction latency may exceed30s; separate block-gap30s/readiness5s/caps remain.

## Governing qualification clarification — 2026-10-30

The user explicitly permits encrypted transaction processing and finalization
latency above 30 seconds. Transaction latency is a measured distribution, not a
30-second acceptance deadline. Measure offered, admitted, processed and verified
finalized throughput separately, together with concurrency and backlog/drain.
PoSy block production and three-QC finality proceed independently of pending
ETDAG processing: blocks include completed results when available and do not wait
for unfinished transactions. The separate maximum block-finality gap remains
30 seconds; signing, cryptographic checks, readiness and resource caps remain
unchanged. Older transaction-30-second requirements below are superseded.

All five were recovered and the first encrypted transaction matched across the
fleet. A second independent-wallet transaction also reconciled APPLIED with
identical effects on all five; its verifier aborted on stale candidate metadata,
so no complete timing result is claimed. Do not resubmit either intent.
The candidate-store correction now refreshes pin descriptors under the same
consistent lock as payload reads; all 16 focused tests and strict Clippy passed.
This correction is local only and has not been deployed. Hercules is aligning
the TPS/soak tools with the clarified transaction-latency policy and preserving
the independent block-gap guard. No TPS or soak is claimed started.

## Current continuation — recovered five-host fleet; encrypted transaction gate passed, 2026-10-30

All5 are running identical release synergy-linux-1d71523b2b371f45/package
 a71a1e02ac0f5c726226ca6821c3351bb70e7f7f9afd82653e9fca1c0a19b382,
node2afdd9da9537039f3f0e14b14c7d5c783d548ea71f5026129aa6c176ef8084e1.
Val5 certified import H5746→29732 completed PASS2400pages, signingfloor5746→29732
only after durable commits, abovefloor reservations preserved, custody/config/
network unchanged. Import peak525062144/max0/oom0/swap0. Original5s readiness
PASS Val5=1.389351s PID2234813, Val6=.511678s PID2313108. Other PIDs Val2=2400784,
Val3=2302997,Val4=2932365. AllNRestarts0 and original1GiB/swap0/TasksMax512.
Exact common block/state/protected/finality commitments advanced H31734→31738.
Initial checker incorrectly demanded instantaneous executionlag0; all5 normal
observed pipeline lag1 with matching same-height commitments, corrected checker
used bounded advancing common commitments. No zero-lag/stability claim.

Fresh once-only encrypted nonce5→6 tx
 e02553056578f82c8853d63b4003140fa62aa45cf2be60498aa52fa10b963dab
finalized H31782, allfive exact transaction/block/fee/nonce/balance/root PASS.
Controller-before-authoring to final verified effects: Val2=22.207983s,
Val3=22.597352s,Val4=22.948556s,Val5=26.650878s,Val6=22.374629s.
Native context=.003262s, signed=.073487s, submitted=.117669s from context start.
State6e802201f3c3670442a4161edc5d294299fd30d86950e5becea8c60d1e0febbf.
Sender nonce6, balance999999999999994959994; receiver nonce0,
balance1000000000000000000006. Do not resubmit any consumed intent.
Consumed handoff/intent and both public checkpoint transfer directories deleted.
No private journal/database copied. Earlier build diagnostics already deleted.

Current expanded goal is emergency realfleet execution per attachment
1facd217-6d3e-430a-ae46-d0fd5d0e4368/goal-objective.md: repeat encrypted tests
from independent authorized wallets, measure real pipeline contributions, actual
ascending finalizedTPS and begin exact86400s supervised soak once functional
and resource/safety conditions pass. No TPS/soak launched yet. Root owns real
fleet/releases; Einstein candidate-store correction; Hercules existing TPS/soak
tooling corrections. Preserve block-gap30s/readiness5s/caps, no uncertain
resubmission/reset/automatic rollback. Use one existing SSH master perhost.

## Current continuation — real-fleet certified checkpoint recovery in progress, 2026-10-30

Allfive installed the same canonical universal package synergy-linux-1d71523b2b371f45,
package SHA256 a71a1e02ac0f5c726226ca6821c3351bb70e7f7f9afd82653e9fca1c0a19b382,
node SHA256 2afdd9da9537039f3f0e14b14c7d5c783d548ea71f5026129aa6c176ef8084e1.
Each stopped upgrade verified every protected member's bytes, inode, mode and
ownership unchanged; VPN PID/executable unchanged and conformance PASS. Val5
684 protected members, Val2 775, Val3/4 617 each, Val6 620. No reset or key copy.
Val2/3/4 normal restarts passed readiness from actual exec in0.481944/0.627021/
0.511659s, actual running /proc executable equals the new SHA, NRestarts0,
1GiB/swap0/TasksMax512/no drop-ins. PIDs2400784/2302997/2932365.

Val5 remains stopped atH5746/block3df321bd04457a12c49393208bc3348a30221a95f656fad3c58bd42935c64bea.
Val6 is deliberately stopped after upgrade atH29732/blockef63222f42f8968d97511b5af493d6f4824ab5341a48b377e2a4f78e16634d1f.
Only three validators run during recovery, so they cannot advance beyond the
checkpoint's retention horizon. Native checkpoint export completed on Val6 under1GiB/swap0, from exact Val5
anchor into /var/lib/synergy-qualification/checkpoint-transfer-1d71523b2b371f45.
Export completed PASS2400 pages,1608814809 prefix bytes. Anonymous process memory
was28MiB at a bounded check; file cache filled the original1GiB cgroup with1497
reclaim max events/oom0/swap0. This is an offline recovery operation, not a
validator stability PASS. Exact four-file public bundle transfer V6→V5 passed full size/hash checks; no
Mac file copy. Val5 importer synergy-checkpoint-import-20261030-2154.service is
in its second commit pass after complete first-pass verification. Last bounded
check162701312 cgroup bytes/max0/oom0/swap0, prefix position398418149 after rewind;
world pointer stillH5746 until all dependencies are durable. Import completion
and starts are not yet verified.
Next import under same caps, start Val5 and Val6 through original5s gates, verify advancing allfive
commitments and fresh once-only encrypted effects under30s. Do not rerun an
uncertain import/start; reconcile its actual outcome first.

Native pruned70-block checkpoint/rejection/interrupted-import/restart test PASS;
strict release Clippy PASS; pure full/bounded/paged R1/R2 replay and byte-level
immutability test PASS after initializing the lazy legacy index before its
snapshot and requiring the exact earlier overlap-conflict rejection. No protocol
rule was weakened. No new transaction, TPS stage or soak during this recovery.
Allfive30s encrypted effects and public-tier lag remain unqualified. Previous
failed allfive latency intent is already resolved; never resubmit it. Consumed
superseded build diagnostics and uninstalled stages were deleted.

## Current continuation — streaming checkpoint recovery under verification, 2026-10-30

Fresh actual fleet check at approximately21:11UTC: Val2/3/4/6 all finalized
H28109, block58e0632e2f571c4edb9556b09d05cd4358f47647c30af1df8f69eddd4e4b0349,
state59e62288ff69520c35d4be7325c458e9f6212789653c1c2942a1ec1ff66a4ce6.
Their PIDs2249812/2155001/2769210/2161954 and restart counters4/4/5/5 were
unchanged from the earlier post-incident readings. Val5 remains deliberately
inactive/PID0, executionH5746/block3df321bd04457a12c49393208bc3348a30221a95f656fad3c58bd42935c64bea,
same state root. No all-five acceptance or uninterrupted-health claim.

Missing/pruned candidate requests now report candidate-unavailable instead of
killing the provider execution owner. Native authenticated-socket regression
passed. The earlier sealed crash-only packagecc44461db8135c24 was staged and
passed all-five native preflight but was not deployed. It is superseded by the
combined recovery build currently in progress; do not confuse staged bytes
with the running/proc executable (old8ef2... on four, stopped5395... on Val5).

Implemented a native stopped-only checkpoint export/import adapter. A single
framed public prefix stream uses bounded complete-lease pages with exact two-QC
preview overlap, original QC/TC ancestry and local supersession checks. First
pass verifies the entire prefix and the checkpoint candidate/native ECHO replay
before canonical commits; second pass rereads the same open inode and checks
per-page hashes before existing native atomic commits. Candidate plus certified
replay lead the forward-only world commit; the original journal's verified floor
then advances through its existing API, preserving authoritative outstanding
reservations. No keys, identities, genesis or consensus rules are reset. Native
Start and offline recovery share an exclusive configuration-inode lock; legacy
running-process/admin-socket checks also reject a live import.

A held-whole-prefix draft was rejected during review because its serialized
capacity did not enforce retained-memory accounting. The final implementation
streams long histories, reserves bounded page allocations before decode, and
leaves the configured World budget and original1GiB/swap0 cap unchanged.
Focused bad-proof/cross-network/interruption/pruned-gap/restart tests and the
Linux seal are underway. Deployment is waiting for those results. No new
transaction, TPS stage or soak has been started; all-five30s effects remain
unqualified. Next: finish focused tests, install one identical combined artifact,
recover Val5 from a certified checkpoint without allowing its new gap to outrun
retention, then reconcile wallets and verify fresh once-only encrypted intents
on the actual five hosts within the unchanged30s requirement.

## Current continuation — dashboard published; Sync recovery blocked, 2026-10-30

This supersedes the earlier all-five-running snapshot below. Atlas staff PoSy
telemetry is publishing the current fresh chain and current five-stage test plan.
The Stability and recovery section is deployed with two cards per desktop row,
active-first yellow pulsing glow, completed-last dim green styling, and stale
telemetry suppressing active glow. Frontend 120 tests, production build, and
backend telemetry checks passed; public page/assets and private origin were
verified. Signed-in visual inspection remains unavailable because local browser
use is disabled. No outdated historical test list is used.

Sync witness/replay byte-vector accounting was corrected in synergy-sync/wire.rs;
all 14 synergy-sync library tests passed. Sealed release
synergy-linux-51515d80e37eb13a has package SHA256
9fde5077223536499c557f2c7e57e31718a9478834183f340f99907d783a2bd6 and
node SHA256 5395a40974b1a2b43fb492ee6f6c96d371b88ada9a5661f740ce6af8afb6d2df.
Only Val5 was upgraded; protected state/custody and VPN were unchanged, conformance
passed, and native readiness passed in 4.088s under the original five-second gate.
Val2/3/4/6 retain release synergy-linux-fa4af603345e200d.

Val5 catch-up then requested already-pruned candidate H5747. All four old peer
providers logged fatal execution-service errors at that exact missing candidate.
Val5 was deliberately stopped through standard lifecycle to stop issuing these
requests; its state was preserved. Other four providers auto-restarted; their
current PIDs/health require fresh verification. Next correction is the provider's
missing/pruned-candidate fatal path in execution.rs serve_sync_requests and the
safe recovery path beyond the 64-height retention window. Do not bypass canonical
prefix verification or reset state. No new transaction, qualification, TPS stage
or soak was launched. Five-wallet effects latency remains unqualified.

## Fresh-chain directive — actual fresh fleet running, 2026-10-30

Operator explicitly ordered old chain files erased and a fresh chain. All five
old active data roots and obsolete private old-chain recovery archives/restore
proofs were removed. Native fresh initialization and exact custody verification
passed; existing validator/wallet private keys, addresses and VPN enrollment
were preserved. Root public network annotation, installation receipt and public
identity export were explicitly rebound to the selected fresh network, with
native possession checks before/after and all other custody bytes unchanged.

All five now run canonical Node-Architecture/Linux/Synergy release
synergy-linux-fa4af603345e200d, package SHA256
8a5f7b660cf41704b5490a7f2944387d5fa1f2e4a4f8f827269d202714206742,
node SHA256
8ef2d886dbabeb59298a2976b2e3c1620d1415a48f7ee031658559abf7fb58ca.
Fresh network synergy-testnet-20261030-7dc4b8b008814f428511001f4a43511f
retains configured numeric chain1266; authenticated Genesis identity
164c4a3cc6aa78c7a57d8c676b5f49a3047d90d2f546be5f298d903fb8e8d2dc,
epoch1/H1. Native Genesis/authority binding, all-five preflight/conformance,
normalized configuration fingerprint
153a5881458dc517b839dea409beea825a82738434a69b9ad5cec18261855e8e
and all20 directed real VPN checks passed before startup.

Actual native starts08:08:08–09UTC: Val2 PID2121157, Val3 2028831,
Val4 2626747, Val5 2130186, Val6 2034589. Original readiness5s passed
in0.415/0.762/0.560/0.635/0.455s respectively from actual exec. Running
/proc/PID/exe hashes match all five, NRestarts0, unchanged1GiB/swap0,
no service drop-ins. Actual common finalized H40 and exact durable
QC40→41→42 ancestry, finality certificate, block/state/protected commitments
match all five using native-produced verified schema2 records. Fresh computed
epoch context root ada128e0062672c703954861d21ea4e207a99cace37464f9ff0a78b8fe54d698.
This is fresh actual distributed consensus, not24h/TPS acceptance.

Native wallet reauthorization preserved existing custody but initially exposed
a serde_json::Value u128-to-float allocation defect before any Genesis signing.
Typed complete-wallet serialization fixed it; exact1000000000000000000000
integer/cross-network/tamper/wrong-secret regression passed. The corrected
utility is uniformly installed and original exact allocation was used for
the fresh signed Genesis. Initial software upgrade was also refused before
mutation due to generated tools/__pycache__; only that attributed disposable
cache was removed. No safety checks bypassed, keys generated or caps increased.
Fresh integration check completed: common finalized H40→H413 and exact
schema2 three-QC/state/protected commitments agreed all five. One genuine
ML-DSA-87 encrypted transfer d1c6d9a0e66a04d61e6aa6f4d0a8b145ea988b96a36195ca403307f79f139a47
finalized H257 with exact all-five sender nonce0→1, amount1 receiver credit and
840000nwei fee in12.713861s under original30s. Never resubmit this intent.
About541–550s actual resource observation advanced397–405 heights: RSS66–75MB
(decimal), PSS61–71MB, sampled cgroup peaks85–114MB, swap0 and zero new max/
OOM/kill events or restarts. Completed paired inventories aroundH86–88→335–338
show stable3 active safety files +1 SQLite index +1 archive segment; Val5 has
one additional legitimate protocol file. Indexed+segment logical growth remains
about42–54KB/finalized block. This is measured current growth, not proof of
long-duration storage adequacy or a24h/TPS PASS.

All old replay/full-migration copied chain roots were then deleted on each host
after verifying their old units inactive and no process references, with fresh
validator PIDs unchanged. Temporary integration observers were intentionally
stopped after this immediate verification; all their raw/result/tool/token outputs
were consumed/deleted, not archived. Fresh chain remains running; no soak or TPS
ladder launched. Required authenticated selected public network inputs now live
in networks/testnet-v3/selected-network for future installs. Existing private
custody is only on its original hosts. Remaining integration work: repeated and
multi-wallet encrypted effects, measured offered/finalized TPS ladder and actual
uninterrupted24h qualification under unchanged original gates.

## Mandatory disposable-evidence lifecycle — 2026-10-30

The user's new evidence lifecycle policy supersedes all older instructions here
to preserve disposable engineering captures, test logs, intermediate reports or
manifests. Retain them only for an immediate active diagnosis, correction or
verification; delete them after use, including redundant remote/local copies.
Do not archive them or create new evidence catalogs. Use bounded streams and
in-memory analysis where possible. Required blockchain/signing/identity state is
protected; upgrade recovery material remains only while its current recovery
purpose exists. Pending fleet tools are being updated for completion, failure and
cancellation cleanup. Historical links below do not require retaining used
disposable output or rerunning completed tests to recreate it.

## Actual-fleet integration directive — 2026-10-30

The user's immediate five-validator integration directive now makes actual Val2–Val6 over their existing VPN the authoritative acceptance environment. Isolated10k/100k synthetic scale runs are explicitly removed as prerequisites; previous incomplete/failed tests remain incomplete/failed, never relabeledPASS. Reuse verified archive crash/signing safety and all-five actual-data migration rehearsals. Essential predeployment checks remain current stopped identities/floors/authenticatedGenesis/membership, recoverable archives matching protected source, capacity/host compatibility, one sealed corrected production package and all-five installation conformance. Authorized work includes non-destructive upgrade, additive storage activation and coordinated actual-fleet start, then genuine authorized encrypted all-five effects<=30s, increasing measured finalizedTPS and actual supervised86400s soak once functional gates pass. No new approval cycle is required. Preserve all keys/identities/Genesis/network/history/signing journals, original quorum/threeQC/signing/authorization protections and1GiB/swap0. No automatic unsafe rollback or synthetic result substituted for real operation. Authority pinned in `target/controlled-network-recovery-20261027T110225Z/real-fleet-integration-directive-authority-20261030.json`; primary owns all SSH/build/deployment; storage, transactions, telemetry and deployment-policy agents have distinct ownership.

## Verified status refresh — 2026-10-30 06:40 UTC

Read-only status refresh `target/controlled-network-recovery-20261027T110225Z/status-refresh-20261030T064015Z.json` verifies all five actual validator services inactive/dead/MainPID0. All five disposable schema-2 full-history import/startup-safety rehearsals have naturally completed with exit0 and successful measurement resource checks: Val2 72,865 source records/830.445s, Val3 71,606/1130.985s, Val4 73,258/785.349s, Val5 72,195/1421.607s, Val6 73,093/855.423s. All 363,017 source paths accounted; each report confirms original source/public inputs unchanged, idempotent import, exact-byte offline reindex and identical closed-handle replay. New OOM/kill events0 and swap0. Four hosts reached the1GiB cgroup cap through reclaim pressure; this is not an OOM finding. This proves copy-only migration and typed native safety-tail replay, not a complete historical signature sweep, full Execution boot or live fleet acceptance. Raw per-path maps/measurement streams still require final collection and release-gate aggregation.

Synthetic Linux VM100k retention run is now terminal FAILED by its original7200s runtime guard, not active: unit Result=timeout/ExecMainStatus15/MainPID0, exit23:09:48UTC Oct29. No final measurement or retention report was produced. Last native sample reachedH94,000 at7198.942s, live tracked heap99,500B/World reservation288,823B/RSS3,403,776B; last cgroup peak173,338,624B, OOM/kill/max events0 and swap0. `retention100k-linux-terminal-status-20261030.json` pins the read-only terminal state and final retained samples. Partial evidence is not a100kPASS, and the timeout alone does not establish a runtime memory defect. No rerun or guard extension occurred.

Encrypted native-background0.2TPS pilot remains FAILED original30s transaction deadline:18accepted/12finalized with exact all-five effects/6pending. First overdue wallet12 completed processing and appears Applied in identicalH34 candidates; saved terminal QC35/finality33 does not establish a missing completion or permanent stall. Linux actual signed32H storage pilotPASS8.228s, but signed10k/100k scale tests remain unlaunched. New test ELF is sealed (SHA256451c7a3634bc36c5601ed1a7aa27d6b8941e3eedf4699510527665e0ae780a91); production installer not yet rebuilt/sealed for this architecture. No new deployment, live restart/load, TPS qualification or soak. Existing three agents have completed their assigned reviews and are idle; no long qualification job is currently active among the inspected units.

## Resume checkpoint — 2026-10-29

User resumed the same research-driven goal; safety gates and non-destructive deployment authority remain unchanged. Existing Hercules/Einstein/transaction agents resumed, separate source ownership preserved. Read root/Core AGENTS and full active objective again; global AOS files still absent, mount currently localExFAT `/dev/disk6s1`. One replacement persistent SSH master per realhost established only after confirming prior masters gone; no duplicate connections.

Fresh read-only all-five evidence `target/controlled-network-recovery-20261027T110225Z/resume-fleet-readonly-20261029T210736Z.json`: every node inactive/dead/MainPID0/NRestarts0, unchanged oldpackagefe6ed3/node9b989c, no overrides,1GiB/swap0; VPNs active, same selected network. No live validator mutation/restart/deployment or new load. Five private recovery archives actually completedOct27 22:46:54–22:49:26UTC: each2.44–2.49GB, complete member sets+all restored bytes/ownership/modes verified in private restore-proof directories, original source unchanged and node stopped/VPNunchanged. Per-host `valN-recoverable-backup-verified.json` receipts preserved; fresh check confirms archives and exact receipt bytes still present. Archive/content rehash and protected-source match remain required just before applying release. Workbook never copied or modified.

Same disposable Linux VM overlay resumed (no real keys or installation). Frozen retention LinuxELF86c214ab7e3330ceee0abedecc99f1344b11128f1fbb65e121d8a7b3dbbf0375 and runnera76b8fb908a277f0f80dc92a4d3a3a8553208b64048cd6dfc90963ca858ff60a. First100k dispatch21:08:25UTC failed closed BEFORE native child because testcgroup io.stat was absent; no workload ran. Second unique dispatch21:09:48UTC enables explicitIO/CPU/MemoryAccounting, original1GiB/swap0,7200s runtimeguard, sample5s,256MiB measurementquota; actual result pending. `retention100k-linux-dispatch2-20261029.json` pins unit/argv/evidencepath. Synthetic touched-state/candidate fixture remains distinct from encrypted ingress. Do not rerun either consumed dispatch or call elapsed time completion. Check exact unit/measurement/report before further action.

Local Linux packaging/conformance/lifecycle/measurement runner32testsPASS; observer+supervisor44testsPASS. Native archive initial suite49PASS/2ignored is prior integration progress, not new archive scale/migration qualification. Hercules continues crash/reindex/import proof, transaction owner actual encrypted block-scale pilot; production source held during timingtest. No newpackage seal or release-gates file until actual safety/migration/scale results exist.

Additional verified Oct29 progress: latest read-only installed-fleet audit21:20:37–48UTC passes allfive against original sealedfe6ed3 package and canonical unit/storage/config policy; normalized fingerprint025941aa67e9cf32e97c6e97e70a18cde2c0949d3e7754bd7909255565d83214 under current normalization. This is stopped-install conformance, not running-executable or advancing-finality proof. `schema-policy-old-fleet-readonly-20261029.json` pins current checker/library hashes. Remote audit now loads local read-only schema helper in memory, avoiding an undeployed-helper dependency without writing host tools. Package ABI checks now verify exact actual native table columns/types/nullability/PK positions and reject generated/default columns/views;44packaging/recovery/runner testsPASS in `linux-packaging-tests-20261029.log`. Builder fixed stalev1 storage metadata: actual Rust format2/segmentSNPARC02, readable1/2 and explicit no-postactivation-downgrade; policyversion2. No sealed newpackage yet.

Disposable Linux observer core probe naturally ended21:18:12.663070UTC after70.314s; separate64MiB/swap0/CPU25% unit inactive/success/PID0 verified. All4endedrawfiles copied and SHA-matched in `linux-observer-probe-ended-20261029/`; independent Einstein auditPASS.15samples,16530B maximum serialized frame; samplegaps4.993–5.004s, actual smapsrefresh~35s/FD~65s (first eligible5ssample, not exact30/60s). Observer cgpeak16,752,640B/processRSSmax23,511,040B (distinct accounting scopes), newOOM0/swap0. RealLinux/proc/cgroup collection, explicit fixtureRPC/inventory/relay counters; projected311,273,474B for87000s at5s fits512MiB, future growth NOT guaranteed. Not chain/relay-concurrency/soak proof. Retention100k still ACTIVE: latest nativeH11000 at657.95s, World288823B stable/liveheap99500B/RSS3.35MB/cgpeak33MB; OOM0/swap0. Filecount566 includes pending analysis of fixture snapshot/checkpoint outputs; no bounded-file or100kPASSclaim yet.

Encrypted native pilot1PASS46.01s:5submissions/5distinctbearingfinalizedheights/allfive effects, max24.065s<=30s, startup1.220s/restart246ms<=5s; raw and hashchain preserved. Recyclepilot failed27.91s on missingRPCreceipt before error payload was logged; exact cause UNPROVED. Test-only error recording and listener distribution corrected (native per-listener pendingcap16 remains unchanged), rerun pending Hercules supported archive fixes/sourcefreeze. Independent review found missingDB with existing singleunsealedarchive could silently lose record indexes and finality legacy-promotion multiappend could exceed boundedtwosegment recovery; Hercules owns failclosed missingindex and oneaggregate<=32MiB append fixes, plus known partialheader/permissions/reindex/hotREADY work. Do not treat initial49PASS as closing new findings. No releasegate file/deployment/live workload/soak authorized by a test result alone.

Latest verified Oct29 continuation: archive current durability suite56PASS/4ignored, direct offline reindex sync regression1PASS/.08s, strict release library ClippyPASS. Complete local append batches now end with a local BATCH_COMMIT footer binding exact record hashes; reindex publishes only complete batches, and every validated scanned segment is fsynced before rebuilt-index publication. Six crash-boundary regressionPASS verifies QC/finality both-or-neither recovery. Missing-index-with-existing-segments fails closed; recovery cannot restore lost hot/v1-only/signing/execution state. Existing backups and typed native startup remain required. Final owned source contract `archive-native-qualification-contract.json` SHA25619be1e354a41364f67bcd02b71d67081ee06d5ea79acb3320f33635c1b10d34d. Full-copy generated rehearsalPASS12.13s proves all-path import, cold reconstruction without legacy fallback, idempotent import/reindex and closed-handle native safety replay; actual all-five full imports still pending.

Real-signature storage32H pilotPASS35.66s on Mac:34QC/32finality,1,045,644unique raw ML-DSA65 signature bytes exactly match persisted unique3309-byte blobs,10hot READY rows,5files/1segment,1,973,342logical/2,445,312allocatedbytes,323,072B SQLite cache; warm native safety replay0.100s. This is actual proof persistence but no encrypted/network/World/TPS proof. Linux32pilot must establish time/free-space before10k/100k. Linux test build attempts1/2 deliberately superseded before sealing/dispatch for supported reindex fsync and lint-only corrections; attempt3 building exact current frozen native sources with before/after inventory binding. No new package, upgrade or validator start.

Corrected native-background encrypted recycle pilot at1TPS failed22.27s because test observer queried candidateH6 before Execution committed it; retained64records show19exact accepted encrypted RPC receipts and only empty finalizedH1–5 observed, no applied result or throughput claim. Exact saved source proves execution world atH5 and active H6 request on affected owner;64-height retention was not the cause. Observer now takes common minimum of native finality and committed execution height, retaining exact3QC/all-five effects and30s deadline. Reservation accounting independently found8pending originals reserving~864MB plus fixed metadata/headroom/temporary owners; Capacity~1.1GB is reservation backpressure, not measuredRSS/OOM. No cap/coefficient change supported. Fresh target33/rate0.2/max240/native-background pilot now compiling; no automatic retry on failure. Packaging46testsPASS, newly guarded test-only modules explicitly classified; runtime chain-literal checks remain enforced. Memory-retention100k still ACTIVE at last21:52UTC check:sampleH38000,~2494s/liveheap99,500B/World288,823B/RSS3.39MB/cgpeak78.5MB, OOM0/swap0. Cgroup includes~62MB reclaimable slab; no100k completion claim.

## Research-driven optimization continuation — 2026-10-27

The latest active objective is attachment `de94947e-01d3-42ca-be75-a8f7d979f2e8/goal-objective.md`, pinned in `target/controlled-network-recovery-20261027T110225Z/research-directive-authority.json`. The user supplied the completed report at `/Volumes/PortableSSD/deep-research-report.md`; all755 lines read, SHA256 `7c373f96497f0f08d7b4faf588e19288dd6a72814c06ec653634c4d01aa7678f`,65,116B. The missing-report request is answered. Treat the report as evidence, not permission to copy its illustrative schemas or alter consensus. `RESEARCH_ARCHITECTURE_EVIDENCE_MAP_20261027.md` maps primary sources, actual code paths, proof obligations and measured versus pending improvements; supplemental Narwhal/Bullshark, Mysticeti, Aptos and Agave sources are explicitly distinguished from the report, which omitted them.

Selected for implementation and measurement: existing durable PoSy signing safety + bounded hot metadata + immutable size-rolled binary history segments with rebuildable SQLite index. DedupSQLite alone and segment-only alternatives are compared. Crucial current-code finding: block-vote QC signatures do NOT subsume VC/ECHO validity/custody facts used by CutRecovery/processing replay, so unique VC proof must remain durable. Only new-format READY may retire below verified finalized floor and outside startup8 horizon after consumer/regression proof; legacy/v1 records remain untouched. Hercules owns archive_segments/evidence_store/delivery/safety and narrow posy finalized maintenance. Additive user_version2 tables preservev1; normal startup bounded active-tail recovery, explicit offline full reindex; archive fsync before index/ack. Schema2 downgrade after new writes is NOT qualified. No source signature/round/quorum change. New architecture crash/migration/10k/100k measurements remain pending; earlier SQLite tests are baseline only.

Fresh read-only fleet proof at22:22:06UTC: Val2–Val6 inactive/dead/MainPID0/NRestarts0, unchanged old package `fe6ed3f0f061e2a272b0b5efca180eaa300ab3b7be5625bb1c4676565be81ae8` and node `9b989c5f39df9fcc05f7f1c57d7b5fd6ec77101558b49322216dddf941d927c4`; original1GiB/swap0/no drop-ins, VPN active, same configured network/genesis domain. Raw `research-directive-readonly-fleet-20261027T222206Z.json` is in the same evidence root. This check did not hash live state or establish a fresh finalized head. No new host mutation, node start, live corrected transaction, TPS result or soak exists.

Supported pin-capacity liveness correction completed: obsolete positively-unreferenced processing pins release BEFORE both pending retry and new source admission, with current/requested/pending references, sole Execution writer, original64examined/4released/4new caps and state-before-candidate crash order preserved. Focused persisted full-capacity regressionPASS1/0 .24s; corrected optimized genuine encrypted five-socket integrationPASS1/0 84.48s, phases19.249/19.913/20.783/19.614s each<=30s, older frozen pending sourceH41 and retained-source restart237ms<=5s. Strict release Clippy3crates/alltargets -DwarningsPASS26.20s, scopedrustfmtPASS. `identity-authorization-integration-pin-reconciled-manifest-20261027.json` SHA256 `5f825a9507e257c5c944356d70e74ababca1b1630de0d15c938875e5ebb238a7` pins16 source/test/log records, rehashed. Both reviewers accept bounded correction. These are offline fixtures, not live effects. Agents resumed successfully after prior provider usage errors; do not treat those earlier errors as current blockers.

Read-only actual-byte baseline `actual-qc-signature-budget-baseline.json`: original Val2H10167 QC has4participants×3309 signaturebytes=13236 rawbytes, but JSON signature arrays alone47140B of49016B total/49152B allocated. Finality416B/4096B allocated. Both hashes match earlier full public-state checkpoint. One-record encoding overhead is not a complete proof budget or fleet mean; uniqueVC/ECHO signatures must also be counted. `POSY_EVIDENCE_LIFECYCLE_PROOF_MATRIX.md` and taxonomy JSON bind actual consumers/facts. Synthetic scale parameter validation and2height smoke pass; actual10k/100k new architecture measurements not yet run.

Einstein owns100k state/candidate retention fixture (synthetic touched transfers, not encrypted ingress) and observer changes:5s memory/native,30s bounded smaps,60s cachedFD, explicit unavailable fields and localOOM/reset;21observer testsPASS. Linux serialized evidence budget and updated collector/supervisor acceptance still required. Network owner is implementing opt-in bounded genuine encrypted >=10k distinct tx-bearing finalized-height fixture with recycled wallets, actual5native owners/ETDAG/PoSy/effects; long Linux result pending, no substitution of10k tx or emptyblocks. Primary owns release/lifecycle/conformance, backups and integration. Additive schema2/strict segment footprint support28packaging testsPASS; native frame/proof checks remain runtime responsibility.

Before host mutation: verify all-five current stopped state/domain/capacity; recoverable verified backups/snapshots; new storage crash/recovery/migration compatibility and scale gates; one frozen Linux package+all-five conformance; then coordinated original5s readiness/30s finality and genuine live authorization/effects gates. `research-driven-release-gates.json` intentionally absent until real prerequisite proof exists; upgrade driver fails closed. Do not fabricate it or consume the older release candidate. No wipes/identity/genesis/signing resets; no automatic rollback after new-format writes. Actual24h and executed/finalized TPS remain the active goal, not satisfied by starting a controller.

## Active controlled recovery — 2026-10-27

Latest verified gates: full actual stopped-state Linux replay PASS on Val2–Val6, exact test ELF SHA256 recorded in `target/controlled-network-recovery-20261027T110225Z/linux-full-replay-test-artifact2.json`; all complete original public consensus trees (71,606–73,258 records,2.25–2.29GB) and six public inputs unchanged. Each disposable copy executes the actual native startup tail twice with closed SQLite handles, preserves signing floors (10167,Val5=10168), verified finality and below-floor protection, and opens no signer/starts no node. Four hosts have a verified cached active-slot vote; Val5 has none at its recovered newactiveH10171, consistent with its empty delivery journal and retained prior signatures, not a failed signature. `actual-state-replay-verified.json` pins scope. Firstattempt helper-path failures are preserved; corrected helper rejects overlap before copying. Transient test cgroup cache reclaim on three sampled EPYC hosts reached1GiB with OOM0/swap0; Val4ZFS≈35MB. These are disposable-copy accounting observations, not live-runtime OOM closure. Only the five attributed failed transient firstattempt unit registrations were released after evidence preservation; all application services remain stopped and VPN untouched.

Durable qualification tooling now passes39tests on the existing disposable Debian12VM:18observer/relay +21supervisor tests. Coverage includes authenticated cached relay, initial and closing freshness, full86400s immutable clock, exception-safe child cancellation, recursive evidence quota, native finality/OOM/restart guards. Controller completion explicitly requires independent retention/end audit and cannot declare overall soak PASS. All prescribed offered targets through10000 are representable; bounded generator concurrency and generator saturation remain separate from finalized network TPS. These are offline/mock tests, not real soak or live transfers.

The optimized native five-socket registration regression passed explicit30s current-nonce phases (19.948/26.689/19.660/21.371s), exact all-five effects and an older-source pending nonce across refresh. That binary precedes the final deterministic last-binding-change-height metadata/cold-start source-publication correction; latest integrated guarded rerun remains required before sealing. No package deployment/start, real corrected-release transaction, TPS number or newsoak exists yet. Same5a9e candidate remains held. The same disposableVM is running and identity-verified for final candidate Linux acceptance; its SSH master is `/tmp/synergy-linux-acceptance-20261027-control`.

The operator's new emergency execution directive at `/Users/jhutzler/.codex/attachments/19d07aa7-d8a3-486d-9962-63d5c0934344/goal-objective.md` explicitly supersedes the historical stop/awaiting-approval boundary below. It authorizes completing corrections, one identical non-destructive Linux upgrade across Val2–Val6, all-five package/state gates before coordinated startup, real encrypted authorization/transfer qualification, then a fresh supervised actual24h soak and ascending finalized-TPS ladder. Preserve genesis/network identity, keys, signing state, history, quorum and finality rules; no wipes or security bypasses. The active goal is incomplete and is not satisfied by offline tests or starting a controller.

Execution evidence: `node-platform/target/controlled-network-recovery-20261027T110225Z`. Fresh stopped preflight11:02:47–48UTC proves all five still inactive/PID0, old node SHA2569b989c5f39df9fcc05f7f1c57d7b5fd6ec77101558b49322216dddf941d927c4, VPN active, original1GiB/swap0/no drop-ins. No new host upgrade/restart or soak has occurred. Preparation identity is not an actual soak start. Incident C1266-2026-10-27-RECOVERY-001 follows full incident-log read.

Hercules has frozen the full stopped-state native startup replay test; focused test and strict test Clippy PASS. Primary is building its exact Linux test ELF on APFS and hashing complete public PoSy state on all five, before disposable-copy safety replay. Original source records stay untouched; no signer or node starts in that test. Prior representative50record rehearsal is not a substitute for this full actual-floor gate.

Transaction integration found no live finalized wallet-registration route; funded wallets are not authorized. Canonical encrypted User native-action registration now verifies an existing authorized sponsor, target root/key possession and selected governed network/time; negative identity and encrypted keytool authoring regressions pass. Real five-socket registration/new-wallet-transfer regression exposed a processing verification scratch reservation failure; exact correction and passing encrypted end-to-end result remain required before release freeze. Prior sealed5a9e candidate is held, not deployed. No authorization exception or cap increase is allowed.

Einstein is finishing durable per-host resource collectors/read-only VPN relays; primary is implementing the remote Val2 supervisor and authenticated harness transport. Controller will own immutable actual86400s start/end; qualification-only observers cannot restart nodes or certify PASS from timers. No real new throughput or stability claim exists yet. NEXT: finish focused transaction fix, full actual-state replay and observer tests; freeze/build/seal one corrected package, upgrade all five with preservation evidence, then coordinated startup and genuine encrypted effects gates before fresh soak/TPS. Earlier stop, failed run and approval-limited diagnostic entries below remain historical evidence.

## Operator stop — 2026-10-26 22:52UTC

**Soak FAILED and STOPPED; CHAIN STOPPED on all five at22:52:10UTC by direct operator instruction after storage qualification FAIL.** Val2–Val6 `synergy-node.service` inactive/dead, MainPID0, stop exit0/Resultsuccess; every previous PID absent. No restart/rearm/load retry is authorized. Chain state, genesis, identities, keys, signing journals and databases preserved; VPN unchanged. `node-platform/target/qualification-20261026T223352Z/OPERATOR-STOP-RESULT.json` pins actual per-host shutdowns. Coordinator/caffeinate process group and exact load continuation stopped; Val2 transient load unit stopped. `TERMINAL.json` records actual observation window 578.023s, not24h. No silent clock restart. Active qualification goal PAUSED at operator request.

Initial0.2TPS/60s stage submitted11 transactions, all11 rejected `invalid_authority`, admitted0/finalized0; one offered slot missed. This is NOT a sustainable TPS ceiling or a PoSy capacity result. Exact report/proof retained. A second0.05TPS transient stage began automatically before the operator stop; it was stopped with the load generator. Preserve and reconcile its partial proof without resubmission. Native32-wallet registry validation and funding do not prove that fresh wallets have current on-chain transaction authority. Earlier “running/pending stage” continuation below is historical. Dashboard restoration investigation is pending; chain must remain stopped during that work.

## Offline engineering recovery — 2026-10-27, ISOLATED ACCEPTANCE COMPLETE

The three explicitly assigned workstreams are integrated into candidate `synergy-linux-3e2ede6cd37aaf44`, package SHA256 `5a9e87db51f431cf7490806ad98e813206a44e2d34fbb08d3b3a25f4f95a91bf`, node SHA256 `a52ae7f2e50445ae2b8141107cb741f071226ffeef833908f9887708a981b366`. Full results and five-column comparison: [integrated report](INTEGRATED_LINUX_RECOVERY_REPORT_20261027.md). Exact [software-only upgrade packet](INTEGRATED_LINUX_UPGRADE_PACKET_20261027.md) is prepared, NOT EXECUTED. All five real installations still carry old package `fe6ed3f0f061e2a272b0b5efca180eaa300ab3b7be5625bb1c4676565be81ae8`; all await explicit deployment approval. PoSy and soak remain stopped. No real keys/genesis/state/journal/VPN or application files changed.

Read-only final conformance08:45:01–04UTC: all five PASS exact old software, closed filesystem/schema inventory, normalized configuration `025941aa67e9cf32e97c6e97e70a18cde2c0949d3e7754bd7909255565d83214`, canonical effective units/no drop-ins, 1GiB/swap0/Tasks512. Independent stopped-state recheck confirms inactive/dead/MainPID0/no active qualification. Exact runtime file counts Val2/3/4/5/6=73667/72249/73893/72843/73733; independent state differences legitimate. Val4 ZFS/Xeon and Val5 lower CPU/RAM remain documented host differences; no causal stall conclusion. `target/engineering-recovery-20261026/existing-release-readonly-conformance-completion.json` and `fleet-stopped-completion.json` are current evidence; prior snapshots below remain historical.

Hercules's exact-byte indexed SQLite archive preserves legacy reads, sign-once safety, original evidence/signatures and paired QC/finality durability. Synthetic8192heights/57344records:2files/267661312B, bounded536320Bcache,0historical fullscansteps. Legacy1024height reference7169files/29360128B. Payloads are synthetic, not a compression claim against failed real220–225KB/block. New Linux PoSy suite45PASS/2ignored; actual process crash recovery separately tested. Native Linux representative50publicrecord/2275946B compatibility rehearsal PASS in1.67s; all exact PQ/QC/threeQC/READY/VC/TC checks and signoncefloor10167 preserved; hashes unchanged. In-process store reopen is not a fresh-process restart. No post-new-write old-binary downgrade is qualified; never delete archive/history or restore old journals.

Einstein's prior-fix inventory and confirmed root-hashing/finalized-read/empty-query repairs are integrated. Linux2048height/1536empty/512transfer/16reopen/16snapshot fixture preserved root/outcomes,269files plateau,heap208988Bflat,peak346233B,drained1712B/Worldreservation0. Cgrouppeak16400384B, sampledswap/events/PSI0 under executed1GiB/swap0guards. Processwrites143593472B; rawcgroupwrites148525056B/read405504B. No matched old/new physical-media I/O improvement claim. Saved fleet memory growth is mostlyfilecache/slab with stableanon; future live OOM closure remains unproven.

Original workload failure remains exact missing canonical finalized authority binding;32fundedwallets still unauthorized. Harness now checks all-five governed binding before authoring and derives explicit selected domain; no registration/bypass/resubmission. Final isolated native encrypted admission/finality/effects/restart regression PASS130.26s. Python70PASS, RPC11PASSserial/parallel and test-only listener readiness regression100/100. Partial stopped-stage proof preserved; unresolved receipts not invented. Live sustainable TPS NOT PROVEN.

Canonical master generated from one package/template implementation; closed file inventory, effective service ownership, storage schema, explicit installation stage, crash-resumable upgrade and SQLite hot-journal recovery tested. Exact source inventories matched before/after/buildpackage/final-codefreeze. Packaging/schema/provenance checkpoint `ad615c07b3d8ed05c6a6989cdb4dc558ee194fe6` commits only18ownedpaths; native runtime remains content-bound working-tree candidate, not a clean published/signed release. Linux Debian12 VM fresh install/native identity/registered and unregistered upgrades/inode preservation/foreign-service refusal/full uninstall PASS;61cross-network checks PASS exact candidate binaries. Strict integrated Clippy/format and32package tests PASS. No PoSy/VPN service started in VM. Evidence index `target/engineering-recovery-20261026/COMPLETION-EVIDENCE-MANIFEST.json` pins raw results and owner reports.

NEXT: operator review of concrete software-only upgrade packet. No automatic staging/application, state import/deletion, VPN or PoSy restart, load, qualification or soak. Legacy compatibility means no mandatory migration of old history. An interrupted software update resumes forward only with exactcandidate/intent. Network restart and governed workload authority remain separate approvals. Original readiness/finality/cadence/caps unchanged. NOT PROVEN:24h stability, live corrected-release OOM/IO/TPS, historical33s/43s rootcause, post-write downgrade, new-release real VPN enrollment/restart, all community environments or signed publication. Dashboard restoration remains pending.

## Active qualification observation — 2026-10-26

Run `qualification-20261026T223352Z` actually began **2026-10-26T22:42:32.411765+00:00**, common finalized H9414, against the five real Linux validators. Evidence/controller directory: `node-platform/target/qualification-20261026T223352Z`. Same running node SHA256 `9b989c5f39df9fcc05f7f1c57d7b5fd6ec77101558b49322216dddf941d927c4`, same fresh network/genesis/authority as completed rebuild below; exact per-host configuration/network hashes frozen in `manifest.json`. No validator restart, replacement, identity/genesis/VPN change or resource-limit increase. Latest operator instruction defers credential rotation; no credential values collected or printed.

The coordinator observation is detached/caffeinated, with a launchd PID guardian that never resets or restarts it (`controller-dispatch.json`, `supervision-audit.json`). A direct launchd attempt was denied external-volume access before actual start; it did not start a prior soak. All-five essential telemetry every15s, common-height commitments, process/cgroup/IO/TCP counters and selected full inventories go to this one run directory. Controller duration86400s from actual start, nominal end2026-10-27T22:42:32Z. Timer alone is not completion proof. Future controller failure or lost coverage must remain explicit. Frozen manifest's supervision phrase is corrected by supervision-audit.json; do not claim launchd directly launched the external-volume Python file.

**Storage qualification FAIL already established.** Measured historical H1079→soak-start H9414–9415 durable PoSy growth7.017–7.205 files and220484–225275 logical bytes/finalized block. Per-height READY/validation/QC/finality and per-slot exact-signature records accumulate without durable retirement; bounded sign-once live reservations do not retire immutable signature files. `INITIAL_STORAGE_QUALIFICATION.md` and `storage-category-verdict.json` classify exact sources, rates and safe correction requirements. This run cannot receive an overall qualified PASS with this implementation. Observation and initial TPS are diagnostic measurements; no safety history was deleted and no segmented-storage correction is implemented.

Actual workload preparation generated32 independent workload wallets on Val2 only, private keys remain there. Native operator registry verification passed. Funding uses sole-attempt genuine encrypted transfers from the two existing funded wallets. Eight funding transactions had immediate all-five finalized-block/effect proofs; two subsequent lookups encountered RPC error `finalized state lacks its canonical execution candidate`. Read-only reconciliation H9708 proved both receiver credits and exact source nonce6/fee effects on all five, executed_total12 including earlier two transactions; no resubmission. Exact historical block/latency for these two is unavailable and must not be invented. Only previously unsubmitted wallet indices10–31 were then funded, with all-five proofs. Full32-wallet pool is ready in `pool-ready.json`; consumed generation/funding scripts must not be rerun. All native transaction intents/receipts and reconciliation files are retained.

Existing asynchronous TPS harness reused on Val2, signing/submission local; all-five proof reads travel through loopback forwarding on existing SSH masters. First explicit early ladder0.2TPS/60s started22:49:13.862820UTC, report pending. New load controller uses bounded transient Linux units256MiB/swap0/CPU400%, no permanent validator service override. Generator limits32 independent senders/one unresolved nonce each and actual missed slots must be reported as generator limits, never consensus capacity. Original30s context-to-finality and30s maximum gap checks remain. No initial TPS number is yet proved. Next read exact stage reports and raw proof copies, stop escalation on failure, refine and repeat highest clean measured stage before representative workload. No estimate or submission-rate-as-finality claim.

Latest sampled all-five H9965 at22:49:33UTC retained original PIDs/NRestarts0, OOM0/swap0; RSS64–74MiB. Cgroup current~772–780MiB on Val2/3/5/6,~127MiB Val4. Pre-run process-lifetime memory.max events1097/1012/0/1386/981 and near1GiB peaks already existed: preserve baselines/deltas, do not claim all lifetime memory events zero. Rolling128-interval gaps reached~7.6s; not full-uptime statistics or a24h PASS. Raw measurement streams preserve unknown/gap observations. Earlier completed rebuild remains true; prior “no24h soak started” sentence is historical as of that report.

## Completed fleet rebuild — 2026-10-26

Working five-validator network objective COMPLETE. Final execution report: `docs/refactor/FIVE_VALIDATOR_REBUILD_EXECUTION_20261026.md`, SHA256 `039b29c29e38cac37230b11e5ee3976a954b7ac262a0d24d8ee10ffc9832503b`. Allfive fresh instances actually running same sealed master package/node hash below, same canonical units/no drop-ins/no diagnostic flags, matching normalized configuration `b724e22b16cf6f6c7e7b5288dd29b356cd66bd3690baa3c7e54c0ecd12caa8bb`, same loaded library hashes. Original readiness5s gate PASS. No automatic deployment/restart/retry/soak is requested by this completion.

Final native same-height proof H1045: allfive block `fcc5d7ed598c05dc06cbdfa162de47bf1630dab6c80c04a39dabe9334b31ff9c`, state `8446cfaa7382cb9e9881171df729443ab1ab9919df1e136bd7fa2ef5e1d743b7`, finality certificate `de6332555e9890723005db08420e7e3cf2e0932110f0e000fc71781485a95d59`; native verified-QC ancestry checked, no independent offline PQ revalidation claimed. Later focused sample allfive H1079. Genuine encrypted transfers initial `ae4e9fe5c60867ef3d9fb183795b706d73ba186bebdeb9a1d737a4e037bebd7b` H33 and reverse `15bd1d6b1965a5bc9fb3f751c7f95673ae0744c80dfab7360279a15de36fb87a` H537 have exact allfive debit/credit/fee840000/nonce effects; first observed finality26.525s/10.541s. Submitted once each; NEVER resubmit.

Five focused resource samples H6→1079: RSS final Val2/3/4/5/6=72.9/67.4/56.7/63.0/60.3MiB, cgroup337.0/337.0/64.5/328.7/329.2MiB; all sampled memory.events high/max/oom/oom_kill0, swap0, NRestarts0. Managed entries8303/8426/8480/8315/8421. Actual working-history retirement:65 finalized-history and66–67 candidate-index records, finalized-world124→100→120 acrossH251/675/1079, final ancestry960–1079. Durable consensus records still grow; measured~255–264KiB/s logical growth, snapshot namespace10–11files. Long-term memory, disk/snapshot bounds and historical33s/43s causes UNPROVEN; no24h soak started. Do not mislabel rolling128sample cadence or sparse resource samples as full qualification.

Original Desktop workbook UPDATED IN PLACE20:48:17UTC:501 public/path/status cells7sheets,4new identity/6publickey rows,20tabs/unrelated cells/styles/ZIP parts preserved; no copy/backup/private-key export. SHA256 `12600078334fed27f75c92a3b81c13a8ad6af871e8381727c73869eb2a3b4d9d`. Credential rotation DEFERRED per operator. Exact attributed old paths absent, fresh keys0600/dirs0700, installation stage empty; only small intent/response receipts retained after completed transfer scratch cleanup. Remaining host differences are documented EXPECTED/JUSTIFIED: Val4 Xeon/ZFS/largerRAM/hostswap but validator swap0, locale; Val2 NetBird OS networkd integration with wt0 unmanaged. No live host-policy homogenization was performed. Raw current evidence/control `node-platform/target/remaining-validator-rebuild-20261026`, pinned by `COMPLETION-EVIDENCE-MANIFEST.json`. Consumed clean-rebuild/enrollment/upgrade/start/transfer scripts MUST NOT be rerun. Earlier active and historical continuations below describe previous stages and are superseded by this completed result.

### Rebuild execution provenance

Operator objective 53131630-0369-4158-be93-684ed629415e authorizes full fresh five-validator network completion. Credential rotation is explicitly deferred. All Val3→4→5→6 sequential removals/replacements PASSED; no old state/key restoration or backups. All five unique fresh native identities/VPN enrollments verified. Twenty directed VPN and TCP mesh paths passed. Fresh signed Testnet chain1266/network synergy-linux-rebuild-20261025-31303316dd024ce685a1dc99 configured allfive; genesis file SHA256a34547918d494bb35b0eca9fc26bacb5ccbaf6bf4f49d58e0154391224bf6a20. Original package61fa failed first launch because legacy route policy hardcoded10.69.10/24 while actual authenticated NetBird allocation uses10.69/16. Allfive failed closed/stopped; preserved fresh state. Minimal verified signed-route correction retains exact authenticated identity/endpoint, private IPv4, canonical TCP5622, signatures/domain/provider-plan/rollback checks;12 focused tests passed. Corrected sealed packagefe6ed3f0f061e2a272b0b5efca180eaa300ab3b7be5625bb1c4676565be81ae8/node9b989c5f39df9fcc05f7f1c57d7b5fd6ec77101558b49322216dddf941d927c4 built from unchanged before/after source inventories and applied same allfive, preserving keys inode metadata and data/config/network hashes during upgrade. Transport generation2 binds corrected release. Allfive second launch PASS original5s gate0.208–0.349s; PIDs Val2=2050439,Val3=1957958,Val4=2387588,Val5=2021073,Val6=1971274. Native finality H13/allfive identical block/state/protected roots and structural three-QC ancestry verified. One genuine encrypted transfer ae4e9fe5c60867ef3d9fb183795b706d73ba186bebdeb9a1d737a4e037bebd7b finalized H33, allfive exact wallet effects amount1e9nwei/fee840000/nonce+1; first finalization observation26.525s after submission intent. NEVER resubmit. First actual resource sample H6/allfive RSS36–38MiB. Canonical evidence/control node-platform/target/remaining-validator-rebuild-20261026; read per-phase receipts before any retry. Those resource, workbook and final-report steps are now complete as recorded above. No24h soak or long-term stability claim. Earlier continuations below are historical and superseded.

## Current continuation — configured network runtime, 2026-10-26 13:33UTC

The operator’s universal-runtime chain-ID audit supersedes the old fixed1266 blocker and the assumption that fresh Genesis needs numeric1185228207. Full implementation/classification/test/execution report: `docs/refactor/CONFIGURED_NETWORK_CHAIN_ID_AUDIT_20261026.md` SHA256540d8b4e51f2828125acf5f4fa037ae8d10e36956a145f3eefe62604ef8884f9. Current reusable runtime/native init/install code accepts explicit authenticated selected chain/network context, including1266. CLI preflight/start/join verifies selected signed Genesis under pinned configured trust and requires configuration/manifest/initial-authority agreement. Numeric chain replacement is not replay isolation: generic transactions bind chain+network, not Genesis hash/incarnation independently; a fresh authenticated network identity is required when reusing the numeric ID. No new numeric assignment was finalized.

Fresh neutral Genesis/manifest format2 and internal SynQ signer format2 are explicit compatibility boundaries. Historical format1 signatures/bytes and frozen deploy vectors remain verifiable offline; runtime format1 startup is refused, not silently migrated. No quorum/round/proposer ownership, readiness/timeout/resource gate changed. Retained344 identifier occurrences in155 files individually classified; zero1264/1266 restrictions in reviewed reusable-source scope. Historical network recipes and unselected nested vendor reference remain outside the universal installation architecture.

Clean Linux x86_64/glibc2.28 build, no diagnostic features, completed with identical full source inventories before/after. Node SHA25665f505fad1d5d3cc0b5322714892364a919f45af61bd3e4e17df4b8ec19fa7dc; keytool74abd0703fbb6c2d4e3f7609ebc8ed6152ac9d971c8402130512f2873ceefa21; Genesis c3f2764e89b282d0048f43ed6c259821d02c6e0f23496fddfb5e6b7d425d1607. Sealed package61faead2376c1257a8efa5fde7ca22098edf57fe5d6389b961ac561add612aa6. Working-tree content-bound build, not published/signed release. Source revision b338dcc223c1ce33599e12c424858cd000772637. Existing nested Git AppleDouble warnings preserved; no unrelated source cleanup.

Tests PASS:166 component,124 bundled Aegis,20 focused SynQ (overlap),3 node-command,4 ingress,7 package;61 native offline checks on Mac and the exact Linux binaries on Val2. Four network fixtures include1266 reused under two distinct identities,9001/9002 test-only networks; real signatures/trust/genesis rejection and disposable storage overwrite refusal. No node start was invoked.

Authorized Val2 sealed application-file upgrade EXECUTED ONCE. Do not rerun `target/configured-chain-domain-20261025/revalidate-val2.py`: its preconditions are consumed. Candidate61 checks passed before upgrade. Combined driver then exited nonzero after upgrade/VPN start without retaining exact postcheck failure. Read-only follow-up established actual completed upgrade; no upgrade retry. Final13:33:22UTC evidence verifies every installed sealed hash/receipt, native custody possession for unchanged address synv11xr6tjlf0gnt7e29lwnzfg823rlujtrwx8nu, unchanged public VPN identity/IP10.69.106.160/16 and four peer pings. Node inactive/MainPID0/no overrides/1GiB/swap0. The failed driver did not retain its inode comparison; do not invent it. No wipe, re-enrollment, key/database copy or rollback. Public-only stage `/opt/Synergy/tmp/configured-chain-20261026` remains with sealed package/public fixtures/disposable offline storage. Real config/node.json, network/genesis.json and config/start-authorized.json remain absent.

Val3–Val6 were NOT modified or erased; no fresh all-five health/equivalence claim. PoSy/performance/qualification/soak remain stopped. The master at Node-Architecture/Linux/Synergy now carries the exact tested sealed package; actual offline acceptance is external to its original build-time unqualified marker. Full real five-identity network configuration, remaining fleet installation, native startup/finality and full install/uninstall acceptance are not implied by this chain-ID fix. Workbook unchanged this task; no identity/key replacement required. Existing authority boundary still prohibits erasing another validator or starting PoSy without the relevant concrete acceptance/authorization.

Evidence `node-platform/target/configured-chain-domain-20261025/EVIDENCE-MANIFEST.json` SHA2569162687126ea9464cf449dabc2071df2a98a1411e37b00e477d2f86b6cfeb630 pins168 files; `val2-acceptance.json` is the final observed result. Source/package/fixture paths are canonical, no source copy. Next work must begin here and in the full report, not the superseded fixed-chain continuation below.

## Current rebuild continuation — 2026-10-25 22:03UTC

Operator-selected Val2 first-machine wipe/install has executed. VPN coordinator remains VPN infrastructure only. Full report: `docs/refactor/VAL2_CLEAN_REBUILD_REPORT_20261025.md`. The previous RUNNING-deletion/preparation-only and live-fleet statements below are historical. Exact 173-path logical removal completed21:41:18.903804UTC; all173 still absent21:57:43. No old backup/archive/relocation. Old Val2 VPN peer and two obsolete setup keys retired. OS/SSH/unrelated applications preserved; no forensic-erasure claim.

Val2 now has fresh `/opt/Synergy` installation, native executable SHA256e847a075491d97898b4cb3754d89c2ee526b8442166764b552f905196b65dc5e, sealed package48c96c9064527a063436e41132edee9f62d462d5563dee9827360031c925cfd0; all installed sealed file hashes match. New address synv11xr6tjlf0gnt7e29lwnzfg823rlujtrwx8nu; locally generated FN-DSA-1024 root, unique ML-DSA-65 P2P/consensus, ML-KEM-1024 ingress; native possession verification passed before/after VPN restart, four local secrets root0600/dirs0700, no private export. Fresh native storage synergy-node-storage:1, safety empty pending actual signer operations. New VPN peer dbf7fiaf611ohpqj0640/IP10.69.106.160/16 connected; actual native VPN PID2043679 at21:57 audit, same public WG identity after restart, all four old peer-IP pings passed. One-off enrollment key dbf7fhif611ohpqj060g deleted; authenticated event63 proves attribution, used_times counter was not retained. PAT stays on VPN host. No repeat enrollment.

PoSy is STOPPED on all five. New Val2 synergy-node.service inactive/MainPID0, disabled/no drop-ins,1GiB/swap0/Tasks512; start-authorized.json, node.json and final genesis absent. Native init initialized storage, not complete launch configuration. Old Val3–6 installation files/keys retained and old unit MainPID0 confirmed21:59:48; Val3 terminal failed/exit1 from stop-time VPN polling error, not repaired. DO NOT erase Val3 or start any PoSy until first-machine/master acceptance passes and exact next destruction authority is settled. Current diagnostic/installation checks are not a new soak, performance experiment or qualified network. Automation remains paused.

BLOCKER: actual native genesis, crypto domain, PoSy membership, ETDAG context/processing, Sync manifest, transport registry, snapshot and DA validation restrict chain1266/testnet. Planned fresh chain1185228207/network synergy-linux-rebuild-20261025-31303316dd024ce685a1dc99 is not yet supported; no fallback to old domain. No native protocol bypass/fix deployed. Final five-key genesis unbuilt. Next local work: implement/review explicit validated fresh domain propagation and replay-denial tests, clean Linux native artifact provenance, effective complete configuration and lifecycle acceptance; no speculative finality fix. Full enrolled-install uninstall and real fresh-chain acceptance remain unpassed.

Installation-tool corrections: API peer name versus OS hostname field fixed; binding verified from authenticated management audit, no re-enrollment. Suppressed Python import bytecode before staged sealed-package verification; first attempt refused before mutation. Tool-only upgrade then completed; its first post-check driver exited1 with exact failing assertion not retained, independent bounded follow-up passed hashes/identity/VPN4pings/node0. Cached build2 target synergy-keytool was non-ELF despite Cargo success; not deployed. Master binaries remain verified build1 binaries; current package is a tool-only reseal, not a clean new native build or signed release. Do not use corrupt cached target as release artifact.

Sole Desktop credentials workbook edited IN PLACE22:01:29UTC,61 cells/seven existing sheets; public identity/key/location/VPN records updated; unrelated cells/styles/ZIP parts verified unchanged, no workbook copy/backup/private-key bytes. Native package README truthfully marks incomplete acceptance. Old NCP authorization revocation remains unverified; obsolete workbook authorization cell cleared without claiming central revocation. Earlier inadvertent workbook credential output acknowledged, no rotation fabricated. Old live kernel sysctl values may remain; no global reload/guessing baseline.

Evidence: `node-platform/target/universal-linux-package-20261025/VAL2-REBUILD-EVIDENCE-MANIFEST.json` SHA256673fdf24aa30d21717a10863f48ab1d8b4d9d9438237be1ab314583d21625eb1 pins24 result files. Do not rerun removal/initialization/enrollment/upgrade scripts: they have consumed their once-only preconditions. Read actual receipts/results first. One persistent SSH master per host remains mandatory.

## Canary critical path — 2026-10-21

### Active continuation — 2026-10-22 async live integration


Execution amendment — 2026-10-25 21:35UTC: authorized Val2 first-machine rebuild is now in progress. Exact manifest `node-platform/target/universal-linux-package-20261025/val2-destruction-manifest.json` SHA25667e186fe98e26177c9e0095d3fec1ba008e4bb6ecfeaf3afe4631b6b8d018aa3 was presented before deletion. Native new Linux executable e847a075491d97898b4cb3754d89c2ee526b8442166764b552f905196b65dc5e ran `version` on Val2 from memfd without starting consensus. Old isolated PoSy units stopped on all five at21:33:06–34UTC; all original validator PIDs absent. Val3 stopped with existing runtime exit1, journal reports VPN polling error during stop; preserved exact result, no restart/reset/repair. Val3–Val6 files/keys are intact, VPN clients retained. Val2 old node/proxy/VPN units stopped/disabled, public SSH preserved. Exact old VPN peer dab92p2f611ghl16e2f0 and its two old setup keys retired via authenticated VPN-host API, absence verified and all other peer/key IDs preserved. Val2 exact logical deletion is RUNNING under target/universal-linux-package-20261025/execute-val2-legacy-removal.py; read its JSONL and actual terminal result before any retry. No old installation backup made. New master build1 succeeded and sealed package SHA2562c7354d7742f3d54b5ec6e8ebb3c9d081dc28de17ab13a793111798d3dde141d; full package acceptance still pending actual Val2 installation/enrollment. New planned chain1185228207/network synergy-linux-rebuild-20261025-31303316dd024ce685a1dc99, final genesis pending actual five fresh public identities. Do not start PoSy, erase another machine, or unpause old automation. Workbook not yet edited. The historical no-mutation statements below predate this amendment.

Current operator direction — 2026-10-25: fleet audit report delivered before correction. The active objective is the complete clean universal-Linux rebuild in attachment `3d38d348-0407-4e1b-8dfd-34b6baecdc06/goal-objective.md`. Operator has now explicitly selected Val2 for the first wipe/fresh-install and native VPN enrollment test, superseding the separate disposable-host prerequisite. The VPN coordinator remains the VPN host, not an application test target. Val2 wipe authorization is explicit; exact path/registration attribution and a concrete destruction manifest must precede deletion. Other machines are not to be erased as part of this first-machine step. Coordinate old isolated-network shutdown before erasing signing safety state; no new PoSy starts until all five fresh installs/public authority/VPN mesh gates pass. No rollback copies or old-install archives. Credentials workbook is exclusively `/Users/jhutzler/Desktop/node-machine-credentials.xlsx`, read/update in place; never copy or back it up. Old preservation-only continuation below is historical and superseded within the approved rebuild scope. Old soak automation remains paused.

Preparation state: canonical native `synergy-node init` now exclusively initializes a fresh schema-1 storage root and refuses existing state/symlink ancestry; it never starts consensus. Focused initializer test passed. Seven native fresh-identity/possession/refusal tests passed. Six offline package-boundary refusal tests passed (not Linux/VPN acceptance). Master generation/lifecycle/VPN tooling under node-platform/tools/linux-node is IN DEVELOPMENT; no native test installation, VPN enrollment, wipe, or workbook edit has occurred. Exact Val2 read-only path/unit/process inventory saved at node-platform/target/universal-linux-package-20261025/val2-removal-inventory-20261025.json, actual collection21:19:09UTC. Current node PID1609905; old installation/history/archives remain. Next: seal/build and verify the real Linux package, complete exact ownership/SSH/VPN retirement checks and manifest, then execute only the authorized Val2 step. Do not infer any rebuild acceptance from source tests.

IMMEDIATE USER PRIORITY — 2026-10-25: perform read-only Val2–Val6 configuration/filesystem/host consistency audit before any further diagnosis, modification, qualification, deployment, performance work or soak. No running validator shutdown/restart/reconfiguration or state mutation. Compare actual /proc executable, effective systemd/environment/config, structural storage compatibility and host environment; classify every meaningful discrepancy with evidence and minimal correction. Reuse existing SSH masters, preserve independent signing/database state. Existing automation is PAUSED; preserve pause. Current diagnostic lifecycle and historical findings below remain evidence, not authority to resume work.

Fleet consistency audit report — 2026-10-25, collection19:43:32–19:49:04UTC; final storage-marker reads19:56:26UTC. Full report: docs/refactor/VALIDATOR_FLEET_CONSISTENCY_AUDIT_20261025.md SHA256cc0b044e6b8137159d6517a5eb819ea8f9134890903599df1bbb2c91828d281d. Evidence E/fleet-consistency-20261025T194328Z/comparison.json and SHA256-MANIFEST.json preserve actual process/config/unit/filesystem/host reads. All5 actual /proc executable hashes equal approved r8 45c4d52bd3013b93b9fbbf484619ee1436366fb50cae98a96629c44feb1e3c9e, selected signed sequence13 verified; normalized node configuration and active data-directory schema identical; actual storage marker synergy-node-storage:1 identical. Operational equivalence NOT certified: diagnostic process flags remain different (Val3 sync-poll;Val4/6 sync-poll+transport flags), accumulated overrides, host task limits, ZFS vs ext4/cgroup accounting, unequal CPUs/RAM/storage/network/firewall/co-resident-service profiles, common missing embedded source-revision telemetry. Report has five-column comparison,16 classified findings,exact sources/minimal safe proposals and coverage limits. No correction or deployment-tooling change implemented; user explicitly requires full report BEFORE any changes. Hold remains; automation PAUSED; no new qualification/release/deploy/performance/soak or live change authorized.

NEW material runtime finding: Val5 previous PID1583633 failed closed16:59:13.281285UTC with "service posy failed during polling: processing proposal staging is full"; existing systemd Restart=on-failure automatically restarted16:59:28.318310UTC. Current audited PID1920264,NRestarts1, same exact r8; audit did not trigger this restart. Staging occupancy cause UNPROVED; peak1G is not OOM proof, current-lifetime OOM0 cannot reconstruct prior lifetime. Other audited PIDs Val2=1609905,Val3=1539009,Val4=2163528,Val6=1801096. No clear/reset/cap increase/restart or speculative fix. Report review and bounded read-only investigation only, subject to user's audit priority.

Diagnostic lifecycle amendment: Val4/6 passive/resource units now inactive/success MainPID0; native transport-window-end and resource end records verified in final-checks evidence. Resource ends Val6 14:23:14.670109UTC elapsed3600.049s,Val4 14:23:16.050088UTC elapsed3600.0226s. Prior statements calling these active/not-ended are historical. No rearm/extension/new capture; native sparse omissions/caps and earlier packet-drop limitations remain, no full-coverage/stability/historical-cause claim. Both diagnostic restart permissions consumed. Audit did not perform a new performance experiment or re-audit old qualification windows.

Current diagnostic freeze amendment — 2026-10-25T13:49:46.964612+00:00. Both passive rings naturally froze on FIRST armed stagnation at finalizedH239858: Val6 end13:36:14.604141UTC/elapsed780.398804s; Val4 end13:36:15.504247UTC/779.889583s. Both passive units inactive/success and original PIDs absent at13:40:22–23 read-only check. Resource PIDs1801613/2163807 still live then; native/resource3600s windows NOT yet verified ended. No rearm/restart/extension. Val6 tcpdump reports163741 kernel drops; Val4 reports0, but retained rings cover only13:36:04.135680–14.240597 and13:36:02.699840–14.254715 respectively, before round1 recovery. All8 PCAP files copied read-only to canonicalSSD with matching source hashes. Structural parsing is NOT independent signature verification or proof of application receipt/completeness.

New H239861 round0 selected proposer Val3; retained allfive signed-slot history has no r0proposal/ECHO and no Val3r0timeout. Other4 timeout votes formedTC0; Val6 signedr1proposal13:36:14.403937, followed by allfive votes/QC. Durable native finality file intervals H239858→239859 are5.086163sVal3 and6.277889–6.295900sothers; this new~6.3s event is NOT the historical33s/43s failure. Frozen wire shows byte-identical ProposalDelivery/QC payloads repeatedly sent towardVal3 at distinct authenticated-frame sequence numbers (e.g. Val6 H239858 delivery28copies70202B/QC27copies48756B). This establishes repeated wire work, NOT why Val3 lacked proposal authorization or a historical root cause. Val3 processing input/parent/proposal gating remains unproved; no speculative fix. Review E/r8-handoff-diagnostic1-20261025T000754Z-h239861-freeze-review-20261025.json SHA2564fa6c1bdeec38dac640bbdd19a5c5cfa639f3676d7c543f955a8b668a47298e0 pins source streams, native history, signing slots and structural analysis. NEXT after14:23:20UTC one bounded actual native transport-window-end +resource end+all4 recorded observerPIDs absent audit; before then offline frozen/source analysis only, no unchanged active polling. Both restart permissions consumed, no workload/qualification retry/soak/binary change/rollback. Earlier active-passive statements are historical snapshots superseded by this amendment.

Current diagnostic evidence amendment — 2026-10-25T13:29:23.282956+00:00. Bounded read-only new-window audit13:27:49 (E/r8-handoff-diagnostic1-20261025T000754Z-readonly-audit-20261025T132749Z.json, SHA2566f990bc4df2f31c4005e2dfa548d9f64099b003f79e922165c5c1603887ba70b) verifies all4 new observer processes still active, resource/native windows not ended, both PCAPs not yet frozen. Val4 sparse transport reached8192 retained completions within43.777345s of first retained completion;8126 failed records,8116 transport-dispatch records. This retention cap means later native completions will be omitted/dropped; do NOT claim complete-hour per-frame coverage. Failed dispatch means nonblocking queue admission rejection, NOT TCP packet loss. Full drop/open/expired/collector totals remain pending native3600s end snapshot. Val6 retained183 records at audit. Both sampled validator memory.events max/oom/kill0 and swap0; Val6 passive observer memory.events max7520/oom0 with hard64MiB cap at audit, preserve reclaim-pressure/completeness caveat. No cap change, rearm, restart or extension. Read-only audit helper target/r8-two-host-diagnostic-readonly-audit-20261025.py now prepared/validated and first bounded execution succeeded. NEXT avoid unchanged active polling, audit actual native/resource/passive end+recorded observerPIDs absent after14:23:20UTC; analyze frozen evidence only. No causal pause diagnosis or repair/newsoak claim.

Current continuation — 2026-10-25T13:26:27.136351+00:00. APPROVED two-host diagnostic execution COMPLETE; captures RUNNING at13:24 initial audit. Val6 restarted exactly once13:22:33.137809UTC, newPID1801096, Sync ready0.530366s from actual ExecMainStartTimestampMonotonic; Val4 exactly once13:22:54.233270UTC, newPID2163528, Sync ready0.432972s. Same sequence13/r8 SHA25645c4d52bd3013b93b9fbbf484619ee1436366fb50cae98a96629c44feb1e3c9e, actual/proc diagnostic env verified, original config/custody/all old units unchanged. Other PIDs Val2=1609905/Val3=1539009/Val5=1583633 unchanged. After each restart native durable advancement and allfive advancing identical block/QC/state/protected commitments PASS. Last pre-arm commonH238894 at13:23:13, allSyncready. Two new restart permissions now CONSUMED; no further restart authorized.

Passive TCP/detectors armed Val6 13:23:14.210640UTC, Val4 13:23:15.622024UTC; exact resource streams started13:23:14.621139/13:23:16.027573UTC. Four standalone observer units posy-r8-handoff-diag1-val{6,4}-{passive,resources}-20261025.service,64MiB/swap0/CPU25%, active at initial audit; PIDs Val6 passive1801603/resources1801613, Val4 passive2163802/resources2163807. Private directory both /var/lib/synergy/posy-async-canary-20261022-rc1/diagnostics/r8-handoff-diagnostic1-20261025T000754Z. Native sparse transport files0600 active,8192+1 completions/64MiB/fixed3600s from firstoperation (firstoperationstart not explicitly serialized; do not substitute preparation timestamp). Both passive rings freeze at first armed native stagnation>=5s OR3600s/cap/failure, no rearm. Resources fixed3600s, due end around14:23:14–16UTC; audit after14:23:20 using native end records, not elapsed timer alone. Val6 passive memory.max reached with1212 max events initially, oom/kill0 and active; retain observer pressure/capture-loss caveat, no cap increase/restart.

E/r8-handoff-diagnostic1-20261025T000754Z-launch-review.json pins authority, fresh preflight, execution/launch/initialaudit. NO NEW LOAD, qualification retry, signing/binary replacement, rollback or SOAK. Historical r8 qualification remains FAILED; new diagnostic is not stability repair/qualified soak. NEXT only bounded read-only new diagnostic stream/end/counter and frozen-PCAP analysis; preserve all previous failed/raw/ended20 qualification windows, no generic health loops, no old-window re-audit. At native3600 end audit totals/drop/cap/open/clock anchors and resource/passive actual terminal state. All observer/capture extensions and automatic return restarts prohibited.

Current continuation — 2026-10-25T13:22:21.769576+00:00. Human explicitly answered APPROVE TWO-HOST R8 DIAGNOSTIC CAPTURE. This supersedes pending-approval entries below. Create-only authority E/r8-handoff-diagnostic1-20261025T000754Z-human-authority.json pins reviewed packet fe918f2da910fd24131dd5630efa9d402b6c51d065f5bfa006a826ab650e54c7. Fresh exact allfive original r8/PIDs/seq13/native release/config/custody/units/NRestarts0/1GiB/swap0/OOM0 preflight PASS, matching advancing common commitment H238609. Execution owner is target/r8-two-host-diagnostic-execution-20261025.py, about to execute once; do not launch a duplicate or repeat old preflight/qualification. Exactly one same-binary restart each Val6 then Val4, original5s readiness and30s advancing agreement; fail stops without retry/rollback. Only after both pass arm two bounded passive captures and two3600s resource streams. Native transport remains fixed3600s from first operation,8192+1/64MiB, no extension. New identity retains preparation timestamp; actual starts must be taken from native records. No workload, resubmission, qualification retry, new binary/signing, production action or soak. Old20 observer windows ended and preserved. NEXT read execution JSONL E/r8-handoff-diagnostic1-20261025T000754Z-execution.jsonl for actual results; do not infer success or authorize further restarts.

Current continuation — 2026-10-25T00:42:58.383730+00:00. Read-only audit now verifies all twenty existing qualification observers ENDED naturally, not merely timer-expired: all recorded observer PIDs absent; five resource streams have native end records observation_period_complete=true at00:36:20.309559–00:36:20.611063UTC, elapsed3600.020–3600.028s, telemetry_errors0/service_observation_errors0. Five block streams have native end records elapsed3600.000–3600.004s, all last finalized184278/certified184280; metadata/host streams' final samples reach their unchanged3600s bounds. No observer extension/replacement or new capture/load/restart occurred. All twenty raw stream paths, byte counts and SHA256 pins retained in E/sync-known-head1-r8-qualification-observer-end-audit-20261025.json SHA256efac74f9d691fe7b89f30925d71a39cf1c9223487967d33dc4549cd3c1e7599a. Across recorded contiguous native finality/QC intervals, the only >30s gaps are the already reported H180871→180872 finality and H180873→180874 QC pause; this is saved-window analysis, NOT current fleet health or renewed qualification. Prior FAILED qualification remains terminal; NO NEW SOAK. Two-host same-r8 diagnostic approval remains pending; do not repeat approval/failure notifications. NEXT preserve ended streams and continue read-only causal analysis/preparation; activation only after specific fresh Val6/Val4 authorization. Original five restart permissions remain consumed; no automatic retry/rollback/new load.

Current continuation — 2026-10-25T00:08:31.539861+00:00. NO NEW SOAK. Original r8 rolling transition completed, but sustained qualification FAILED; all five one-restart permissions consumed. Further exact native history now establishes: Val6 signed H180874r0 proposal4.819918s before its own timeout. Val2/3/5 signed r0ECHO0.831–1.231s AFTER their own timeout; no r0READY retained. Val4 has no retained r0ECHO or r1proposal signature. In r2 only Val3/5/6 have block-vote signatures (3<required4); Val2/4 r2ECHOs arrived5.627924/4.587945s after their own timeout signatures. Val2/4 stored TC1 around23:47:00.742/02.332; Val5 stored it23:47:11.181 then signed proposal23:47:11.236. Cross-host timestamps have no reconstructed historical offset bound; causal order conclusions rely on SAME-HOST intervals and exact signed-slot hashes. Full timeline E/sync-known-head1-r8-height180874-handoff-timeline-review-20261024.json. Val3 retained PoSy193 polls max463541us, Execution176 max550060us, Sync218 max84772us/outbox0/errors0 during23:46:35–23:47:25. Sparse logs are not full all-host scheduling proof. Actual writer/read/processing-input blocking operation and historical43s cause still UNPROVED.

Concrete next diagnostic packet E/sync-known-head1-r8-two-host-handoff-diagnostic-review-20261025.json SHA256fe918f2da910fd24131dd5630efa9d402b6c51d065f5bfa006a826ab650e54c7 prepared, NOT staged or authorized. Proposes exactly one diagnostic restart each Val6 then Val4 of SAME existing r8/sequence13 (no new binary or signing), fixed3600s native sparse trace plus existing bounded owner timings, two bounded private TCP captures freezing on first armed>=5s native stagnation, two exact resource streams. No new workload/qualification retry/resubmission/soak. Goal Section2 explicit live restart approval required; original five restart permissions consumed. Approval request pending; do not repeat it or notify unchanged pending. Fresh allfive exact preflight required AFTER specific approval; no automatic staging/restart/rollback/capture extension. Read-only00:06:32 capability review verified Val6/4 same approved PIDs/exactr8/NRestarts0/caps1GiB/swap0 and tcpdump/wt0 available; not a fresh allfive health claim. Existing twenty qualification observer windows expire naturally around00:36:20Oct25, preserve without extension. NEXT only already-authorized read-only evidence/analysis while awaiting explicit two-host diagnostic authority. Earlier failed qualification/current state below remains applicable.

Current continuation — 2026-10-24T23:55:05.711838+00:00. R8 sequence13 rolling4/6/2/3/5 completed one restart each; all original5s Sync readiness bounds passed. Original memory30 and64height retirement PASS. The subsequent original600s0.1TPS qualification FAILED23:46:49.941981UTC:32 submitted/admitted,31 observed finalized,1 in flight; synergy_chainTelemetry timed out after5.00851s through Val4 relay127.0.0.1:28547. NO NEW SOAK started; qualification driver exited1. No further restart, rollback, staging or load retry has occurred. All five one-restart approvals consumed.

Independent saved native records confirm an all-five finality gap33.089601–33.292433s between H180871 and180872, exceeding unchanged30s. Next QC H180874 round3 follows verified TCround0/1/2 for Val6/4/5. Saved TCP during this same gap shows multi-MB queues toward Val4 and Val4 retransmission backoff; Val4→Val3 SendQ3779996B at23:46:49.660995 and Val4→Val2 backoff6/rto29888ms at23:47:20.454960. Correlation is NOT proof of exact causal blocking/loss. On-host Val4 telemetry continued during the relayed timeout. R8 removes a demonstrated redundant-proof mechanism but is NOT distributed qualified and does not resolve the historical43s cause. Review E/sync-known-head1-r8-distributed-qualification-failed-review-20261024.json pins reports/raws/native boundaries.

Single exact read of the NEW32 cohort pending transfer784d4f1a45447b9d84a51f488a0a1fbfbf5fda5a46dfc60b4c5590aee5ae99f4 returned null on allfive at23:51; do not infer effects/finality or resubmit. Old130/new261 reconciliation remains unchanged (259 exact allfive receipts,2 unrecovered). Last exact postfailure capture23:48:45: all5 approvedr8/PIDs Val2=1609905,Val3=1539009,Val4=1856184,Val5=1583633,Val6=1528981; NRestarts0/1GiB/swap0/OOM0, recovered advancing naturally. Not current health after that capture. Twenty qualification observers started23:36:20 for3600s, expire naturally around00:36:20Oct25; preserve streams, no extension or duplicate observer/load. NEXT read bounded Val3 native owner diagnostics and immutable H180874 proposal/timeout/outbox records to locate the missing publish/delivery handoff, correlate exact peers with savedTCP, then prepare only a supported minimal correction. No speculative protocol change/new owners/phases/certificates/deadline relaxation/automatic deployment or restart. Previous running-stage continuation below is superseded.

Current continuation — 2026-10-24T23:46:14.892991+00:00. R8 memory30 PASS23:39:33,30/30/30 all-five effects, max context-to-finality23.0418161s, mean native QC/finality0.982–0.986s, max observed native interval2.716956598s, zero memory.events deltas/swap. Allfive coherent64height retirement PASS23:40:41 (4–5 samples each, unavailable/incoherent0). Original600s0.1TPS/60tx sustained stage dispatched23:40:41, running without restart. Driver target/posy-sync-known-head1-r8-qualify-distributed-20261024.py remains active; do not duplicate stages. Await terminal report/audit/resource/postfinality gates, then exact manifest+20new observer preflight+newsoak under existing direct approval. No newsoak yet. No further validator restart authorized.

Earlier Current qualification — 2026-10-24T23:40:32.702242+00:00. New r8 memory30 completed: submitted/admitted/finalized30/30/30, all-five wallet effects true, remaining0, original30s maximum context-to-finality PASS, allfive mean native QC/finality .5–1.5s and OOMdelta0/swap0 audit PASS. E/sync-known-head1-r8-distributed-memory30-20261024.json and -audit.json. Existing64height retirement in progress;600s0.1TPS stage follows. No newsoak yet. Allfive exactr8 sequence13/no further restart authorized.

Current continuation — 2026-10-24T23:36:19.744829+00:00. APPROVED rolling r8 sequence13 completed in order4,6,2,3,5, one explicit restart each, every original5s Sync bound PASS, all-five matching advancing commitments after each. PIDs {'4': 1856184, '6': 1528981, '2': 1609905, '3': 1539009, '5': 1583633}. Exact SHA25645c4d52bd3013b93b9fbbf484619ee1436366fb50cae98a96629c44feb1e3c9e, allNRestarts0/caps1GiB/swap0/OOM0, guarded state/custody/config/oldunits unchanged. E/sync-known-head1-r8-rolling-transition-terminal-20261024.json. Original new30 memory and600s0.1TPS qualification next; no new soak yet. No further restart authorized.

Earlier Current continuation — 2026-10-24T23:32:10.824544+00:00. Human explicitly APPROVED r8 rolling transition, qualification and conditional new soak. Authority E/sync-known-head1-r8-human-authority-20261024.json pins exact review/plan and fresh23:31:49 inventory. Approved sequence13/order4,6,2,3,5 maximum one restart each; original gates unchanged. Rolling activation is next, no r8 restart or new soak yet. Prior pending-approval statements below are superseded.

Earlier continuation — 2026-10-24 22:44 UTC. All authorized local preparation
for r8 is complete. Exact Linux standalone component27/27 PASS under256MiB cap,
peak25055232B,swap0,all cgroup memory.events0. Mac native controlled queue,
loss/reconnect/takeover, historical restart/reordering and encrypted/both-restart
results above remain PASS with original assertions/deadlines. Candidate is not
distributed-qualified yet; original43s causal operation remains UNPROVED.

Original r7 native transport-window-end observed22:40:37UTC, audited22:40:46.
8192 completions+1 native snapshot,8144226B; no open operations, lock skips or
collector failures at end. Totals: attempts by stage227269/178148/178148/169243/
169243/169243;1040666 intentionally omitted fast completions,487 slow,49121 failed,
42436 DROPPED at retention cap. Therefore capture coverage is INCOMPLETE, not a
successful complete-hour sequence audit. Failed transport-dispatch is nonblocking
queue admission rejection, not proof of TCP packet loss. Retained maxima writer
queue/sign1462.538146ms,write545.254930ms,bodyread1855.014359ms,verify9.989599ms;
no all-traffic quantiles or old43s explanation. Fixed resource observer ended
naturally22:40:37.204834UTC after3600.020754s,41034382B. Preserve both streams and
expired monitor; no automatic extension/restart/rollback. End audit:
E/transport-sparse1-r7-env1-native-window-end-audit-20261024T224046Z.json.

22:41:32–34 exact fleet remains original PIDs/hashes on other4 and Val4r7/PID1806268,
NRestarts0/1GiB/swap0/OOM0. Four original hosts retain memory reclaim pressure;
Val4 current~94MB/max0. All-five common H176168 identical at subsequent check;
this is transition preflight, not30s transaction qualification. Raw r7 observer
streams preserved; do not call ended exactr7 resource monitor currently active.

Final review E/sync-known-head1-r8-five-validator-transition-review-20261024.json,
SHA256ad0799241f821ad36bf38608f18ab1fe2135b76c9e188c7de1d8098c8c61a2f8,
references exact candidate SHA25645c4d52bd3013b93b9fbbf484619ee1436366fb50cae98a96629c44feb1e3c9e,
plan078bc3b0065990330c1504b359224047f913503e23714b783b748e8ba60614f6,
all positive and original failed test evidence, cap coverage limitation and current
common-finality preflight. Explicit human authorization request now PENDING for
standard signed sequence13, isolated rolling4,6,2,3,5 maximum one restart each,
original qualification and conditional new24h soak. Goal Section2 requires it;
old two approvals consumed. Do not repeat approval request/notify unchanged pending.
No new signing/staging/deployment/restart/soak has occurred. Continue preparing
exact safe execution while pending; immediately refresh live preflight after any
specific approval. No automatic recovery/rollback, deadline changes, state reset,
old receipt/account reconciliation, resubmission or post-soakTPS.

Earlier continuation — 2026-10-24 22:40 UTC. Human priority is to qualify the
minimal supported correction and get a new truthful24h soak started. No new soak
is running. Both prior Val4 r7 restart approvals are consumed; no further live
transition has been authorized. The original43s causal operation remains UNPROVED.

Undeployed sync-known-head1-r8 eliminates independently demonstrated redundant
current-session verified-head proof work and serializes one unchanged head once.
The exact16-frame controlled peer-writer regression shows584600 synthetic proof
bytes occupying the last writer slot before correction; after suppression0 such
bytes and the same waiting PoSy frame is dispatched. This is an equivalent causal
queue regression, not a reproduction/explanation of the historical43s pause.
Unknown/lagging/reconnected peers retain full unchanged proof bytes and accepted
unsent proofs remain retained under actual Sync queue backpressure. No wire,
signature, PoSy owner, phase, timeout, readiness or resource-cap change.

27 focused native tests PASS. Native genuine dropped-timeout retry, idle-expiry/
lease-change reconnect and reversed TC/QC arrival tests PASS. The original
outstanding-request/reordered-prefetch fixture FAILED its complete-two-response
assertion; preserve E/sync-known-head1-r8-native-4-20261024.json. Its test-only
harness prematurely released partial genuine responses after1s. Narrow cfg(test)
correction starts that fallback after a complete response and releases only
complete heights, preserving partial chunks, original90s reorder deadline and all
assertions. Corrected test PASS169.988496s,22:31:53.913941→22:34:43.903578UTC.
E/sync-known-head1-r8-reorder-fixture-fixed-result-20261024.json and exact test-only
patch SHA256702363040d218f6b7832777d6b0b097c5e3f581745c1b9f6dd139a77b9330cb5.
The separate genuine five-native encrypted pending fixture PASS176.931986s,
22:28:11.524340→22:31:08.457503UTC: all-five wallet effects and both restart/rejoin
paths pass. Its intentional pre-reveal hold is not steady30s finality qualification.

Exact sealed Linux runtime candidate11841672B SHA256
45c4d52bd3013b93b9fbbf484619ee1436366fb50cae98a96629c44feb1e3c9e,
SHA3-256f05d70d5773cc9e31dbe532c7a56a8c8c907bde62ba14321a6c124cd9bd8f5f0.
E/sync-known-head1-r8-linux-candidate-review-20261024.json records49169 full inputs
matching before/after, inventory SHA2567dd0e12c4b8fd5f14b3ee0b493cc05a00439949d99a0fa85938d54b14e4426d7.
Production runtime build predates the subsequent cfg(test)-only fixture correction;
services/mod.rs excludes that module from production. Both runtime input file
hashes remain exact. Linux test artifact built22:33:26.808910→22:37:19.354010UTC,
17724968B SHA3-2562a6a624d15489da9953360d5fa33834dee6daf930959a598ce86b754b674c62e;
its full49169-input pre/post inventory SHA2562e7b4cca878ed18efba6166538940725598b69eb19b3f6467f3879650ae0bc62 MATCH.
Next run the27 exact focused Linux tests in a standalone256MiB/swap0/CPU1 component
cgroup after the existing capture naturally ends. No live validator mutation.

Existing r7 fixed3600s capture ends approximately22:40:37UTC; native window-end
record and totals are required. At22:39:13 retained completions reached8192;
most are transport-dispatch failure records. Preserve any cap-exhaustion/drop
counts and do not call the full-hour sparse stream complete. Existing short
Execution-pointer pauses with newer durable QCs remain distinct from the old
43s proposer stall. No additional capture or extension is authorized/planned.

Concrete PROPOSED transition is E/sync-known-head1-r8-controlled-transition-plan-
20261024.json SHA256078bc3b0065990330c1504b359224047f913503e23714b783b748e8ba60614f6:
existing standard release sequence13 after12; exact r8; rolling order4,6,2,3,5,
maximum one explicit restart each; new lexical-last zz dropin clears retired trace
variables. Preserve all old binaries/units/custody/config/state and failed evidence.
Original5s Sync bound measured from actual process start, all-five common finalized
commitments after each restart; no automatic rollback/retry. After authorization
and transition run original new30 encrypted-memory cohort plus600s0.1TPS/60tx,
all-five effects, retirement,0.5–1.5s mean blocks/30s finality/maxgap,1GiB/swap0/OOM0.
Only all original gates passing permits a new identity and actual24h start. NEXT
finish native capture audit and Linux component verification, finalize review,
then request exact live-transition authorization required by human goal Section2.
No repeated old-account reconciliation/resubmission;259 exact old receipts,2
unrecovered exact proofs remains the historical status.

Earlier continuation — 2026-10-24 22:18 UTC. Human approved the original one-Val4
r7 diagnostic restart, then separately approved one corrected capture restart.
Both approvals have been consumed exactly once; no further restart is authorized.
The instrument-only r7 binary is now running on isolated Val4 PID1806268,
SHA2564f8bb35fabc3aa29a02b736ab887bf443ee15e8730f982077f1eebe93f3e9cf5,
with an ACTIVE fixed3600s sparse transport capture. No workload or new soak began.
Other four validators retain exact signedseq12 and their original PIDs.

Execution evidence preserves two preparation/check failures. First staging stopped
before any service change because the host diagnostics parent did not exist;
only the proven empty new binary directory was reused after creating the private
parent. The first authorized restart at21:35:22UTC ran exactr7/PID1803733, but the
old96 dropin's UnsetEnvironment removed SYNERGY_POSY_QUALIFICATION_TIMING_CONFIG
from the final process environment. Therefore no transport collector started.
The initial immediate /proc exe assertion also raced systemd's Type=simple child
exec; independent inspection verified exactr7 without another restart. All failed
records remain unchanged. This is a diagnostic activation configuration defect,
NOT a cause of the historical43s stall. The original reviewed packet missed that
inherited setting; systemctl Environment alone did not prove actual process env.

Human explicitly approved the concrete correction packet
E/transport-sparse1-r7-val4-environment-correction-review-20261024.json,
SHA256916096619edc9860edf77cc96fd7a606dbb045c9b5a9fb8b0b4c9cd962c4b044.
Only diagnostic99 dropin gained an empty UnsetEnvironment= reset and a fresh
private capture config path; original96, all earlier units, config/custody/state
and binary stayed preserved. Second restart requested21:40:36.823938UTC;
actual new PID1806268, NRestarts0, original1GiB/swap0. Actual /proc environment
and exact executable verified, Sync-ready observed0.443057534s after process
start within unchanged5s bound. Native finality H171778 before→H171780 at capture
verification; no transaction traffic was submitted. This is diagnostic activation
and restart/recovery observation, not distributed transaction qualification.

Capture identity transport-sparse1-r7-val4-env1-20261024T214035Z names preparation
time, NOT the true transport start. First retained operation observed around
21:40:37.47UTC, first checked21:40:37.601493UTC. Fixed window ends approximately
22:40:37UTC; require its native transport-window-end record/totals rather than
claiming completion from a timer. Remote private directory:
/var/lib/synergy/posy-async-canary-20261022-rc1/diagnostics/transport-sparse1-r7-val4-env1-20261024T214035Z
contains new0600 transport.jsonl/config.json/resources.jsonl. Exact r7 resource
observer PID1806279 began21:40:37.098575UTC for3600s, monitor SHA256
bdba91df9648c139de2fd1e31566d3461d721927651120606c3c60abe8029556.
Original Val4 seq12 resource observer exited as expected on hash change; preserve
its stream. Nineteen other original streams remain active. Earlier exactr7
resource observer PID1804155 also continues independently until its own3600s end;
do not confuse that earlier resource-only window with the active transport window.

21:41:26 exact5-host inventory: other4 signedseq12/originalPIDs; Val4r7/PID1806268;
all NRestarts0, original config/older unit hashes unchanged,1GiB caps,OOM/swap0.
All19 original plus current new resource streams fresh; earlier r7 resource also
preserved. Cgroup memory Val2/3/4/5/6=1023512576/987787264/48488448/1008574464/
1021607936 bytes. Reclaim pressure remains preserved, not success evidence.
At21:42:21 allfive Sync-ready with advancing non-simultaneousH171894–171896;
exact common H171893 block d20d0fbce990ee4da9f6f2b10e5e7f7365d1f79e46cf9e9db435af0fbb26fea3,
QC id e66cac75c2b1b5bcf5eb2724bb01276b463610ed036326d335790942f228b81c,
state/protected roots all identical. No account reconciliation was repeated.

Early retained trace at21:41:50 contains160 rows over all6 stages, including a
441382-byte write348.278ms and writer queue428.203ms to10.69.10.5:5622, plus a
668318-byte read569.786ms. These are early/startup retained samples, NOT the
historical43s failure, all-traffic quantiles or its causal explanation. Capture
omits fast operations by design; continue exact peer/session/sequence correlation.
Evidence: E/transport-sparse1-r7-val4-env1-activation-summary-20261024.json,
E/transport-sparse1-r7-val4-observation-20261024T214043Z.json,
E/transport-sparse1-r7-val4-observation-20261024T214150Z.json,
E/transport-sparse1-r7-post-activation-inventory-20261024T214126Z.json,
E/transport-sparse1-r7-env1-finality-check-20261024T214221Z.json.
Historical43s root cause remains UNPROVED; no protocol/wire fix is justified yet.

21:47:21 bounded retained-sequence analysis advances the current measurement:
263 complete sparse records were snapshotted to compressed externalSSD evidence,
with remote complete-byte length/hash and exact collector identity. On Val4's
outgoing10.69.10.5:5622 session10, Sync(protocol3) sequence1 occupied write_all/
flush348.277752ms. Same-session subsequent PoSy(protocol4) sequence3's measured
writer queue316.658192ms overlaps that earlier write for approximately193.637ms;
sequence12 waited428.202882ms. One ETDAG(protocol5) and eleven PoSy sign records
have queue age>=250ms. The source uses one ordered per-session writer, so this
demonstrates a Sync write contributing to subsequent PoSy queue residence in
the CURRENT STARTUP stream. It does not establish network delivery time, fully
account for omitted fast writes, or reproduce/explain the historical43s stall.
Inferred interval endpoints include small diagnostic emission/setup overhead.
Incoming read-body spans start after header receipt; ingress success means router
queue admission, not application validation completion. These coverage boundaries
must remain explicit in later TC/QC correlation. E/transport-sparse1-r7-env1-
retained-sequence-analysis-20261024T214721Z.json pins the263-row gzip snapshot,
source hashes and all12 joins. Capture remains within its original3600s window;
no new capture, validator change, workload or protocol correction was made.

22:05UTC focused causal continuation: existing capture recorded finalH172108→
172109 gap5.957932356s. Allfive native records show nextQC172111round1 and the
same round0 TC naming Val3 as timed-out proposer. On Val4 durable QC172110 mtime
21:45:07.482176→TC21:45:12.688117→QC172111round1 21:45:13.440108UTC. These are file
observations, not exact certificate formation times or synchronized clock proof.
Four TC reports (Val4/2/6/5) all have last_voted_candidate=null/highestparent172110;
this proves no last vote reported by that quorum, not that no proposal was built.
Val3 sampled cgroup max/pressure totals did not increase over21:45:05–16. Current
Val4 sparse coverage contains a286ms Sync body read from Val3 overlapping the
gap, with no measured multi-second Val4 write. Header wait remains unmeasured;
Val3 has no r7 instrumentation. This does NOT prove a transport-only explanation.

Correction to an intermediate update: existing processing-metadata observers
cover pending transaction records, NOT proposal handoffs, so they cannot resolve
candidate-publication timing. A targeted passive stall-boundary reader was
launched22:03UTC on eachhost over the existing SSH masters; it reads exact native
signing/candidate metadata, thread wait states and TCP only after finalized height
is unchanged>=2s. It writes only new private evidence below diagnostics/
transport-r7-passive-stall-boundary-20261024T220300Z/boundary.jsonl. Exact nodePIDs/
hashes are checked; no node restart, state/config change, load or source fix.
Bounds correction: the counter limits three COMPLETED two-snapshot episodes;
isolated first triggers reset on height change and do not count toward that limit.
Actual hard bounds remain8MiB perhost and hard end22:40:30UTC
BEFORE the original r7 window ends. First verification22:03:30 confirmed allfive
readerPIDs live; Val2/5/6 already captured finalH173361 boundaries. ReaderPIDs
Val2/3/4/5/6=1578819/1509114/1817720/1552375/1497941. These are passive readers,
not additional consensus owners; stop on nodePID change and preserve their files.
E/transport-sparse1-r7-env1-native-gap-and-passive-boundary-review-20261024.json
pins exact allfive proof/resource/TC reports and launch/status. NEXT consume the
already triggered boundaries to distinguish pre-publication delay, writer/kernel
wait and delayed receipt against TC/QC. Do not substitute another generic health
loop. Historical43s root cause remains unproved; corrected qualification and the
new soak still have not started. Fixed r7 window/limits and both consumed restart
approvals remain unchanged.

22:18UTC source candidate prepared in the canonical checkout, not deployed:
Sync head delivery now consults existing PoSy-verified progress from the current
authenticated peer session. Peers already proving the same/higher finalized
height do not receive another full witness. Unknown/lagging peers retain the full
existing proof bytes; a reconnect invalidates both verified-progress and sent-tip
hints using exact SessionId. One unchanged head payload is serialized once for
all recipients, and large witness cloning/encoding is skipped if none need it.
Only services/sync.rs and services/ingress.rs runtime source changed in this step;
no wire format, signature, certificate, timeout, resource limit or native owner
changed. This removes demonstrated unnecessary work and prepares an equivalent
writer-queue regression; it is NOT proof of the historical43s root cause or
qualification of a corrected distributed network. Two targeted tests cover a
16-frame peer writer held by earlier traffic (legacy redundant head versus
verified suppression), next-height full proofs, unknown/lagging/ahead peers,
exact unchanged wire bytes, immediate session replacement, stale-session claims,
and retained exact unsent proof bytes under congestion. The first test-build
attempt used generic BudgetedWorld decoding and failed at compile time; fixed
by decoding the existing HeadClaim body. First backpressure test run exposed a
test setup error: Discovery has its own4-frame reservation, so it did not fill
the Sync8-frame budget. Corrected to actually saturate Sync, without changing
runtime quotas. Logs are preserved. Final native test build is currently in
progress; no test/build/deployment success is claimed yet.

New passive boundary summary at22:14:16 confirms short Execution pointer pauses
with three newer native round0QCs already durable on several hosts. At22:03:04
Val2 Execution waited in folio_wait_bit_common; Val5 PoSy was observed in
jbd2_log_wait_commit. At22:04:04 Val3 Execution waited in jbd2_log_wait_commit.
These are instantaneous thread observations during approximately2s boundaries,
not proven full-duration waits or explanations of the old43s proposer stall.
The six-second TC/QC event remains distinct. E/transport-r7-passive-boundary-
causal-summary-20261024T221416Z.json preserves public summaries and explicitly
records the passive-reader counter limitation. Original r7 capture continues
only to its existing native end; no window extension, validator restart or
additional approval is consumed. NEXT run the focused new regressions, then
genuine native loss/reconnect/takeover and encrypted pending/restart fixtures
against the exact candidate, while the existing bounded capture completes.
Do not start a soak or assert the old blocker resolved from local tests alone.

Historical failure diagnosis — 2026-10-24 20:40 UTC. sync-prune1-24h-soak-20261024
remains TERMINAL FAILED; no replacement soak or workload has started. The exact
terminal report gives start 11:23:54.486722UTC and abort 12:07:23.760130UTC,
43m29.263s, 261 submitted/260 observed admitted/259 observed finalized. Native
all-five evidence now localizes the shared finality pause: final H131034 to
H131035 took about43s; the next QC H131037 was round2. Authenticated native timeout
records name Val4 as round0 proposer and Val5 as round1 proposer, mapped through
the preserved public transport registry. These same two hosts had port5622 TCP
egress retransmission/backoff during the pause: Val4 send queues up to2.66MB,
RTO7.808s/backoff5/cwnd1; Val5 up to8.90MB, RTO5.12s/backoff4/cwnd1 on another
peer. Val2/3/6 paths remained much faster. Allfive native Sync remained ready and
on-host RPC observations responsive. This is evidence of a native proposer
dissemination/receipt failure, not merely a Mac RPC relay timeout; the precise
packet-loss/blocking operation is NOT yet proven. Local benchmark ended12:04:44,
next build began12:08:29, both outside the observed12:07 failure window.

Bounded passive observations at15:47, without transaction traffic or validator
changes, captured existing port5622 wire streams on Val2 and Val4 (raw pcap stays
on those remote disks). Complete parsed frames: Val2 28.79MB/310frames,32 Sync
head frames=14.22MB; Val4 16.57MB/186frames,16 Sync heads=7.11MB. There were123/75
repeated payload frames after TCP overlap deduplication. These short unloaded
samples identify existing traffic costs, not sustainable TPS or proof that this
traffic caused the earlier failure. Source: sync.rs2553–2579 sends the complete
native finality witness per newly advertised height; posy.rs1185–1285 retries
signed events every250ms; network_session.rs372–401 signs/writes the single
ordered peer stream. No safety, wire or scheduling correction has been made.
E/sync-prune1-stall-proposer-egress-diagnosis-20261024.json pins evidence/hashes.

Saved-capture subtype/height analysis now isolates a concrete encoding cost,
without another health-only loop or new capture. Sync heads account for49.38%
of complete frame bytes on Val2 and42.92% on Val4. One existing146079-byte native
three-QC witness becomes440278 bytes when the outer JSON serializes Vec<u8> as
decimal integers (3.014x), before outer authentication/framing. Existing unloaded
ProcessingProposalInputsV1 frames also contain no publications and null ordered
group: an example215220-byte inner JSON has214027 bytes of certified-ancestor
material; wrapping its bytes again yields655323 bytes, with667371-byte signed
payload/670710-byte frame. This is measured wire amplification, NOT proof it
caused the earlier43s stall. Repeated Ready payloads after TCP overlap dedup:
Val2 54 of93; Val4 29 of54. Echo repeats33 of72/25 of49; QC repeats24 of56/9 of26.
All counts are per directional flow; captured frames have not been independently
signature-reverified. E/sync-prune1-saved-wire-subtype-cost-analysis-20261024.json
pins both detailed saved catalogs, exact public heights and byte counts.

Pre-activation local diagnostic result at20:40UTC: transport-sparse1-r7 was sealed
and ready for review of ONE bounded Val4 activation, then pending authorization.
It is instrumentation, NOT a repair of the historical43s stall. Deployed signedseq12
is untouched. Reading retained stopped native journals found the local r5 active/
control discrepancy depended on random governed leader rings: active[4,0,2,3,1]
placed intentionally held node0 on H11–20's ten-block proposer lease, while the
control[0,4,2,1,3] placed completed node4 there. Active nodes1–4 had completions
aroundH9 but held proposer0 could not publish its missing completion; control
publishedH12/executedH13. Original H10 preparation time was not retained. This
is a concrete fixture role/schedule collision, not proof of the distributed stall
or a paired instrumentation timing experiment. The smallest TEST-ONLY correction
chooses the deliberately held worker from the last existing governed lease before
admission; actual keys, leader ring, native protocol and all deadlines/assertions
remain unchanged. No consensus scheduling rule changed.

That r6 active test completed both restarts and all-five wallet assertions but
FAILED the unchanged diagnostic completeness assertion:779 dropped observations,
all779 due to the diagnostic global handle's exclusive try_lock contention; no
writer/queue loss. Exact operation: concurrent producers only cloned an immutable
handle but excluded each other. r7 changes that diagnostic handle to shared
RwLock try_read; registration/clear remain exclusive and transport producers
never wait. A cross-thread shared-reader regression and existing writer-held
skip/count regression retain the completeness requirement. No protocol owner,
certificate, wire semantics, readiness, deadline or resource limit changed.

r7:15 collector tests and3 existing session tests PASS. Genuine encrypted native
pending/restart fixture PASS178.940s with diagnostics active: all-five effects at
H14, both pre-reveal/post-finality restarts, duplicate prevention, reveal fence
preserved; second restart/rejoin H15→17 in13.342s. Its intentional holds and
original180s/60s local assertions do not establish distributed30s transaction
qualification or mean block cadence. Collector retained477 rows,0 lock skips,
0 drops/failures/open operations;98551 fast operations intentionally omitted.
Maximum RETAINED setup0.232416ms, writer queue1.609292ms; not all-traffic overhead
or quantiles. All prior failures remain preserved. E/transport-sparse1-r7-local-
diagnostic-validation-review-20261024.json pins exact logs/artifacts/hardware.

Single-job Linux r7 build completed1m51s; complete before/after source inventories
MATCH. ELF length11824968, SHA256
4f8bb35fabc3aa29a02b736ab887bf443ee15e8730f982077f1eebe93f3e9cf5,
SHA3-25620764446bb2ff8d16780680bcefd8d8f3b7c1003b4cf79bd5adf5d3b04018c3f,
target/posy-async-linux-transport-sparse1-r7-sealed-20261024/synergy-node.
E/transport-sparse1-r7-linux-diagnostic-candidate-review-20261024.json binds build,
1472 direct-source comparisons and exact local validation; only three runtime
feature diagnostic files and two cfg(test) files differ from acceptedseq12.

Read-only activation preflight17:08:59 used existing single SSH masters: allfive
exact signedseq12, originalPIDs/NRestarts0/1GiBcaps/swap0/OOM0;20 CURRENT sync-prune1
observers alive with matching commands/fresh streams. Non-simultaneous heads
H152880–152882 advanced; no common-height state comparison was repeated. Val2/3/5/6
near1.061GB cgroup memory with max reclaim counts11569/15898/16946/10327; Val4~204MB,
max0. This remains pressure evidence. Initial preflight missing io.stat and old
seq11 stream paths are preserved helper limitations, not current monitoring loss.
No live files/processes were changed. These17:08 facts are not current20:40 health.

The concrete packet E/transport-sparse1-r7-val4-diagnostic-activation-review-
20261024.json proposes exactly one Val4 restart with the pinned instrument-only
ELF, fixed3600s sparse capture in a new private host directory, new exact-hash
resource observer, old streams/hash pins retained, no workload/soak restart or
state reset. Other four remain frozen. After window expiry fixed diagnostic
checks remain; no automatic rollback/restart. The current human goal Section2
explicitly requires authorization before replacing/restarting live validators;
at20:40 this exact Val4 action had not been authorized. Superseded by the two
explicit approvals and bounded execution recorded above. Historical43s loss/blocking cause
remains unproved; no speculative wire/protocol fix or new soak is permitted.

Historical local feature-only transport-sparse1-r5 instrumentation is built/sealed,
but was NOT activation-ready; deployed signedseq12 is untouched. It replaces r4's
first60s slice with a fixed3600s window: retain failed/early-return operations,
operation or writer-queue age>=250ms, and one baseline per1024 operations of each
stage. Limit8192 retained completions plus one window-end snapshot; the existing
256-event queue/64MiB file limit remain. Explicit opt-in transport-only mode uses
the existing exact-artifact/isolation guards and excludes unrelated diagnostic
phases from that budget. Queue age and diagnostic setup cost are separate. It is
an end-only sparse trace, not complete packet coverage or a latency/TPS sample;
unsampled errors join by peer/session/sequence rather than hashing every frame.
Window-end totals expose omitted/expired/in-flight/drop/lock-skip/error counts.

Fourteen focused collector tests and three existing network-session tests PASS.
The additional five-native genuine encrypted pending/restart fixture FAILED its
unchanged180s assertion with diagnostics active; same exact sealed test artifact
with diagnostics disabled PASS, including both restarts and exact all-five wallet
effects. These independent fresh local fixture identities do not prove the trace
caused the timing difference. They also do NOT establish active non-interference
or recovery qualification. No deadline/assertion was extended and no failed
evidence discarded. Active retained state: node0 remained intentionally held before
reveal, nodes1–4 had completions but no finalized processing slot. Disabled control
reached four finalized, released node0, then preserved all-five effects after the
second restart. This is a local candidate-validation discrepancy, not a diagnosed
cause of the old five-host stall or a new distributed throughput result.

The failed local trace retained394 rows/371437bytes. Maximum retained setup0.691ms,
operation1.727ms, writer queue2.017ms; no complete-coverage/zero-overhead claim is
valid because the assertion unwound before terminal totals. The261 failed dispatch
records have session0 (no active sender), not measured slow writes. Raw journals
and trace remain on external APFS. Two initial compile errors (missing mode
argument/import) and both fixture outcomes are preserved with the fixes and exact
artifact. Linux single-job build completed1m51s, full pre/post source inventories
MATCH; ELF SHA256e122896958c3aa43a911be9374c4a1dd9d0857da37b4405ae5f2b3d291fd5647,
SHA3-256f03eedbd0b846a9b4b5d6f440693e4af73b73cb2b985d37bab88ae9de7414418,
target/posy-async-linux-transport-sparse1-r5-sealed-20261024/synergy-node.
E/transport-trace1-sparse-r5-linux-diagnostic-candidate-review-20261024.json pins
build, tests, source drift, sparse limits and the explicit NOT activation-ready
decision. No remote connection, staging, signing, deployment, restart or load.

Historical r4 diagnostic artifact (superseded, retained): it measured dispatch,
writer queue residence, sign/encode, write/flush,
read-body, verify and ingress outcome, with session/sequence/public fingerprints
and setup overhead, no raw payload or keys. Seven collector tests and three
existing queue/blocked-writer cleanup tests PASS; these are local diagnostics,
not five-host or soak qualification. Linux ELF sealed at
target/posy-async-linux-transport-trace1-sealed-20261024/synergy-node,
SHA2562b381985fd9df9049ef0be210d23c7b4d9e93bdbf616011cf7a758b17e2c1397,
SHA3-2562a49380c33f499e2647b1d79fcd74299f4b05af08fb65f6d172eef9042812ac0.
Single-job build completed1m51s; complete before/after source inventories MATCH.
Direct source drift from acceptedseq12: network/network_session are exactly the
feature-only patch; prior qualification collector extensions remain feature-only;
two other changed files are cfg(test) TPS fixtures absent from the runtime node.
Earlier syntax-only drafts remain preserved; r2's undefined ingress outcome local
was caught in review and never applied/compiled. No signing/deployment/restart.
E/transport-trace1-linux-diagnostic-candidate-review-20261024.json pins all results.

The r4 artifact was NOT activation-ready: its first60seconds/8192-operation slice
cannot prove observation of naturally recurring late stalls, and unrelated
qualification hooks shared the collector byte budget. The r5 preparation above
addresses those retention limitations; its unresolved native fixture discrepancy
prevents activation readiness. These checks assess diagnostic behavior, not a new
protocol/release gate. Do not optimize wire format or weaken/reorder safety work
from a cost correlation alone.

New-run wallet effects reviewed ONCE: all33 accounts exactly equal across allfive
at commonH147116/blockb2f38f270063ff55577d7ad9a2e80c586fb57dc6aef9acdec832c0c632d8ce28,
statec6a55e61d513a99c7ff66284f8e9f177f8e6f3a88821e1590c3adbde191ab14e.
Balances/nonces match all261 expected effects; receiver684→945. The259 already
captured all-five receipt proofs were hash-rechecked. TWO exact per-transaction
receipt proofs remain unrecovered; do not label all261 exact receipt reconciliation
complete. Historical RPC reads H131026–131070 returned null after retirement;
direct candidate131035/131036 files are absent. The two missing-receipt expected
wallet comparison uses21000gas, explicitly preserved as that assumption, not a
recovered receipt. E/sync-prune1-abort-new261-wallet-effects-review-20261024.json
and current-account-proofs contain the precise limitation. Earlier helper errors
(RPC client table full from rapid distinct connections; old common height outside
retained history) are preserved; paced public reads succeeded without gate changes.
Original130 reconciliation stays closed. No resubmission.

Latest ordinary health15:44:52: allfive matchingH147119, original PIDs, NRestarts0,
20 observers alive. Post-abort cgroup max reclaim remains pressure evidence;
original five-second readiness/30s finality/.5–1.5s mean blocks/1GiB/swap0 unchanged.
The already completed qualification-timing test artifact is sealed at
target/posy-tps-processing-stage-profile-sealed-20261024/synergy-node-tests,
SHA256731695dc994cbcca6cebf9e40d5fa44bdc85c5e7d4861eb11b7fc70e7236b66d.
NEXT: consume the ALREADY RUNNING exact Val4r7 env1 sparse capture, with one
existing SSH master per host. Use target/transport-sparse1-r7-val4-read-diagnostic-
20261024.py --env1 and target/transport-sparse1-r7-post-activation-inventory-
20261024.py --env1 for explicitly pinned read-only evidence; neither restarts a
validator. Analyse retained queue/sign/write/read/verify peer/session/sequence
against native TC/QC/finality and TCP resources; do not substitute generic health
loops. At approximately22:40:37UTC inspect native transport-window-end totals,
8192 completion+1 snapshot cap, drops/lock skips/writer failures/in-flight and
resource end records. Preserve raw streams on Val4/externalSSD. Never extend the
window, reinstall, restart or automatically roll back. Diagnostic constant checks
remain after expiry. Both specific restart approvals are consumed; any further
live transition needs its own concrete review/authorization. No running/new soak;
historical43s cause and distributed repair qualification remain open. Do not repeat
old failure/approval notifications. No heavy Mac TPS runs, new release
qualification, deadline extension or readiness bypass while this blocker remains
unresolved. No source/wire/protocol correction for the old43s stall is yet justified.

Historical failure notification — 2026-10-24 12:11 UTC. The NEW sync-prune1-24h-soak-20261024
is TERMINAL FAILED; it is no longer running. Failure first captured in
E/sync-prune1-soak-health-20261024T120953476511Z.json. Workload PID1339777 exited1,
report failure "synergy_getProtectedAdmissionStats RPC failed: TimeoutError";
261 submitted,260 observed admitted,259 observed finalized,2 unresolved at abort.
Do not resubmit or restart this run; do not claim a 24h pass. All five validators
remain active with original PIDs/NRestarts0 and advancing finality. At12:09:53
cgroup memory.max reclaim counts are Val2=154/Val3=10/Val4=0/Val5=18/Val6=37;
OOM/oom_kill/swap remain0. These are resource-pressure events, not an OOM-free
stability pass. Failed evidence retained; user notified once at12:11UTC.
The timeout's exact endpoint, remaining native5s budget and correlation with
readiness/resource pressure are being collected read-only; no transport-only
or sole-root-cause claim. Current capture session72410 must be consumed, then
correlate the final RPC trace with existing resource/native observer rows around
12:07UTC. No live source/config/state changes, no automatic restart.
Independent local performance profile build session51810 COMPLETE successfully,
--features qualification-timing. Do not rebuild or run a new TPS workload while
this failure is under diagnosis. Seal its exact artifact before future builds.
Local TPS 1TPS/30 submitted saturated (27 finalized,3 queue-full, p9577.49s);
0.25TPS/120s drained30/30 but2 over30s, p9533.206s; both localmeanblocks~2.32s.
These do not prove a distributed throughput ceiling. The original reveal-fence1
failed soak and all130 prior reconciled transfers remain separate and closed.

Historical start record (superseded by terminal failure above):
Current exact continuation (2026-10-24 11:26UTC): NEW24H SOAK RUNNING,
identity sync-prune1-24h-soak-20261024, offeredwindowstartapproximately
2026-10-24T11:23:54.487UTC. Earliest86400send2026-10-25T11:23:54.487UTC PLUS
drainandterminalreview. Start reconstructedfirstscheduledmonotonic+samehostUTC;
terminalreport'sstartUTCwillbeauthoritative. Neverclaimsuccessbeforefullperiod.
Allfive exactcorrective signedseq12 ACTIVE, nodeSHA256
e8d0fd40058bd0fc561da5eb0e96e06022d2dbdf859db1fda80a5b1043be0d57.
PIDs2=1326171/3=1278849/4=1560859/5=1329254/6=1271292, noautorestarts,
state/config/custodypreserved, productionexcluded. At11:24allfive commonH128243
block59853e9fe2e7f54481e7e2b94b4ec23eb8e92a90082777d84b438a4088c1e06b,
statee1ce40ea1a64f21fc648a3fa0cc25196f1c828e4b329fbb19e5bbb61758de0f5.
20newobservers alive/identitymatching/fresh(<1.87s), remote soak-sync-prune1-20261024;
loadPID1339777 alive; first6newencryptedtransfersfinalizedby11:25:09UTC.
Cgroupmemoryevents0/swap0/hostOOMswapIO0. DiskfreeVal2~176GB/3~364GB/4~1.84TB/
5~155GB/6~359GB. Exacthealth/startacceptance evidenceinE.
FinalaffectedqualificationPASS: localoptimizedproof/recovery/encryptedrestart,
actualVal4 256MiBcomponent,1800sVal3boundedobservation, allfive serialrestart/catchup,
new30encrypted-memorycohort+64heightretirement,600s0.1TPS fixedresourcewindows.
600srun60submitted/60admitted/60finalizedwithallfivewalletverification/drained,
offered/submitted/admitted.1TPS; withinwindowfinalized.098333TPS (59, lastdrained).
Latencycontextfinalityp50=13.252364s/p95=16.341963s/p99max=19.266234s;
mean nativecertified/finalizedintervalsallfive~.8890–.8891s; individualtail4.43s
preserved, targetismean. Resourceblockersnone, fixedmemory/IOcomparisonsPASS,
OOM/swap0; finiteobservedqualificationnotindefiniteboundormaxTPScapacity.
Originalmemory30Val6ONEunavailablereadmetadata_lock_timeoutretained, zero
returnedincoherent; coherent64heightretirement3–4samples/allfive. Newauditadapter
appliesexistingexplicitunavailable-vs-incoherentrule withrawhash/recomputedcounts.
No timeout/consensus/readiness policychanged. Val3 originalboundedtracecaps and
restartbudgetlimitationsremaininfinalreview. Demonstratedno-oparchivefsync/lock
writeamplificationcorrected; notprovenSOLEoriginal26sSyncpendingcause.
Freeze: revisionb338dcc223c1ce33599e12c424858cd000772637,16,875compilerinputsMATCH,
explicitdirtyinventorySHA2565b261afa0ac42283a4bb26ed286d0e36b834e10f2118ed32ad44ffb9c34857b8.
E/sync-prune1-accepted-isolated-canary-manifest-20261024.json pinsqualifiedevidence.
No extraindividuallyreviewedhumaninventoryclaim; broadhumanisolatedauthorization
recordedexactly. OriginalsoakFAILED/all130closed, neverrepeat/resubmit.
Existingheartbeatposy-isolated-canary-soak nowACTIVE5minutes,newidentity/newhealth
script target/posy-sync-prune1-soak-health-20261024.py. Stayquietonunchanged;
notifymeaningfulfailure/missingmonitor/operatoraction/completiononly. Formatter
nulltailTypeErrorpreserved,savedrawhealthunaffected; minimalread-onlyhelperfix.
Independent LOCAL TPS continuation (11:34UTC): first optimized native8wallet burst
at1TPS is TERMINAL, all8wallet effects correct/8admitted,7of8over30s latency.
Offeredwindow8s: submitted1TPS/admitted.25TPS/finalized0; full143.315sdrain
finalized.055821TPS, p50finality70.15853s/p95136.296209s, peakreservation981044119B,
peakRSS145424384B. This is a shared1GiB-FIVE-validator fixture limitation, NOT a
networkcapacityceiling or releasepass. Originalreport native statuspassed means
correctdrain only; additive first-probe-interpretation JSON explicitlyfailslatency.
Oldnativebinary cd4822... sealed target/posy-async-native-sync-prune1-sealed-20261024/
synergy-node-tests beforeincrementalrebuild. No soakhosttraffic/change.
Narrow LOCAL test-only accounting correction: socket_qualification_tps.rs opt-in
POSY_TPS_PER_VALIDATOR_BUDGETS=1 retains1GiBcapEACHvalidator(defaultsharedunchanged),
records per-validatorreservations andfirstsamplednativecompletion timestamps.
Pythonfixture --fixture-per-validator-budgets requiresconfirmedactivatedtopology,
records preparedmetrics separatelyandexplicit30squalificationflag. Production
validator/sourceprotocolpathsunchanged. Nativeoptimizedbuild session45057 RUNNING,
CARGO_TARGET_DIR=/Volumes/SynergyBuilds/posy-resource-local-v43-target,
log target/posy-tps-native-independent-pools-build-r2-20261024.log/jsonl.
Firstcompile Display errorE0599 retainedinoriginalbuild jsonl/log; corrected
EtdagDigest access .0.clone(), no runtime failure. Do notduplicatebuild.
NEXT LOCAL: consume buildterminal then SAME8wallet1TPS/8s burst withconfirmed
independentpools, newidentityandrawtimestamps/blocktimings/resources; compare
fixtureconstraintwithoutclaimingproductionoptimization or sustainablemax.
Stop escalation on correctness/resource/unstablebacklog; .1TPSsoaknotceiling.

Latest LOCAL TPS (11:38UTC): independent1GiBpervalidator8wallet1TPSburst
COMPLETE:8/8allfivewalletsverified, no30sviolations, finalityp5023.0635s/p95max26.0745s,
drain33.08947s versusold143.315s. Wholeload+drainfinalized.241769TPS; offeredwindow8s
submitted1/admitted.75/finalized0TPS; notsustainable1TPS. Eachpoolpeak<937MB,
actualprocessRSSpeak139558912B. Nativeblockmeans~2.04s FAIL .5–1.5s; exploratory,
notreleasequalification. Oldreport release_timing_qualified=true onlychecked30s;
additivecomparisonpreservesfileandexplicitlycorrectslabel. Helpernowseparates
transactiontimingvsblockcadenceandmarksalllocalfixture release_qualified=false.
Measuredpreparedtimestampspervalidator(firstsampledcompletion, not5xTPS), certified
transactioncountsandnativefinalityblocktimesallpreserved. Rawcomparison
E/tps-local-independent-pools-comparison-20261024.json. Perpoolfixturebinary
SHA2568569587952847c5c46472c84ba091b29251c1b348fde157d5022e4a0dd0facdc sealed.
Onlytest-harness source changed; exactseq12soakbinary/configremainuntouched.
NEXT LOCAL:64walletboundedfixturebuild(session98969)RUNNING; test-onlymax64count/
1000offeredcapunderpernodeopt-in, historicalshareddefaults8/2unchanged.
Buildlogs target/posy-tps-native-64-wallets-build-20261024.log/jsonl. Consume terminal,
sealartifact+hashes, run60newwallets at1TPS/60s with TMPDIRexternalAPFS
/Volumes/SynergyBuilds/posy-runtime-tmp-20261020. No concurrentcompileandmeasurement.
Do notduplicatebuild/load. At11:35:53soakhealthyall5matchingH128977,20freshobservers,
workloadalive/proofage4.96s, OOM/swap0. Nextsoakcheckfromexistingmonitor~11:40UTC.

Latest execution (2026-10-24 11:51UTC):64walletoptimizedbuild COMPLETE, sealed
localtest SHA256047c7ebb1f25233be3759e2e2408feec9a674b79f9e4c45aaa44c14fc338ef1f.
60wallet1TPS/60s externalAPFSprobe TERMINALFAILED:60submitted,17admitted,
10allfivewalletverifiedfinalized,7admittedunfinished,36queuefullRPCresponses.
240.516s load+boundeddrain finalizes.041577TPS; p50130.272s/p95max230.482s
for10completed, unfinishedcensored. Meanblocks~11.64–11.74s FAIL. Poolspeak
943–947MB each/1GiBcap, RSS287916032B. E/tps-local-60tx-terminal-interpretation-
20261024.json preservesclassification/confounders. No sustainableTPS orcapacityceiling
claim; no escalation. Separate8wallet externalAPFS diagnosticcontrol session21876
RUNNING(samebinary, existingSYNERGY_SYNC_POLL_DIAGNOSTIC=1); do notduplicate.
Ownerobservednetwork-intakemax5.408823s/executionprocessing4.104713s; staticfixture
uses synchronousPoSy testadapter(posy.rs83–90), production start.rs460 uses
preparation-awareowner. Correct measurementtopologybeforeproductionoptimization.
Currentcontrolmustfinish beforeRustsourcechanges(sourceinventorycheck). Allraw
controlfiles E/tps-local-external-apfs-control-8tx-20261024.*. Next narrowfixture
opt-in actualproduction sharedpernode preparation handle forPoSy+Sync, no protocol
change; preservehistoricaladapter/default andallfailedprobes. Soakat11:48:58 allfive
matchingH129871,20aliveidentitymatching, proofage2.66s/workloadalive, noautorestarts,
cgroupmemoryevents0/swap0. Nextread-onlyhealth~11:54UTC. Newsoakunchanged.

Current isolatedTPS continuation (2026-10-24 11:53UTC): externalAPFS8walletcontrol
session21876 COMPLETE,8/8allfivewalletcorrect/145.3086sdrain, p50122.2525s/
p95max138.2898s; timing/cadenceFAIL despite nativeworkloaddrainpass. Coarseowner
stages network-intakemax5.408823s, processing-execution4.286139s, apply-finality
2.113407s; sampledconcurrentcosts notelapsedcriticalpath. Detailedadditiveanalysis
E/tps-local-storage-and-preparation-diagnosis-20261024.json. No sourceoptimization
claim. Fixture-only optinPOSY_TPS_NATIVE_PREPARATION now connects existing production
preparationPoolpernode toPoSy+Sync; productionruntimeunchanged/defaultfixtureskeep
historicalsyncadapter. Adds boundedexistingpoolobservations. Pythonflag
--fixture-native-preparation requires nativeconfigurationactivation. Optimized
incrementalbuild session22790 RUNNING; logs target/posy-tps-native-preparation-build-
20261024.jsonl/.log. Pythonpy_compilePASS. Do notduplicatebuild. NEXTsealexactbinary
and run nativepreparation8wallet1TPS on internalAPFS(tempstateonly; rawexternal) to
compareexistinginternal8topology; sourcehash/finality/blocktiming/resourcespinned.
Do notbenchmarkwhilebuilding. Soak11:53:07 allfivecommonH130131/20observersalive/
workloadalive/noexitreport/NRestarts0. Nexthealth~11:58UTC. NevertouchsoakforTPS.

Latest TPS (2026-10-24 12:00UTC): test-only production-preparationbuild COMPLETE,
sealedSHA256e0647e34639271191a4931a7980d313c0a0e5d9f5f97cf80c5b00c30c15d5ae6.
Sameartifact/8newwallets/1TPS/1GiBpernode/ownerdiagnostics storagecontrol COMPLETE:
internalAPFS34.193208sdrain,.233965load+drainTPS,p9529.164120s,meanblocks~2.32sFAIL;
externalAPFS142.739042sdrain,p95135.713185s, all8walletverified. External4.1745x
slower withsimilarphysicalwrites154MBinternal/149MBexternal. /Volumes/SynergyBuilds
isAPFSsparsebundle /Volumes/PortableSSD/SynergyBuilds.sparsebundle onexternalExFAT,
notbareAPFSdevice. Evidence E/tps-local-native-preparation-storage-control-20261024.json
and tps-local-external-storage-identity-20261024.json. No productionoptimization or
networkcapacityclaim. Productionpreparationalone didnotremoveslowdiskbehavior.
NEXT measurement ALREADYRUNNING session36407:30independentwallets,1TPS/30soffered,
internalAPFStempstateonly/rawexternal, nativepreparationandindependentpools; bounded
210sload+drain; noescalationifunstablebacklog/correctness/resourcefailure. Name
E/tps-local-native-preparation-internal-1tps-30tx-20261024.*. Do notduplicate.
At44s16admitted/8finalized/H18; pools923–933MB each, stillpending. No terminalpassyet.
Soakat11:57:28allfivecommonH130422/20identitymatchingstreams<3.13s/workloadalive,
noautorestarts/cgroupmemoryevents/swap. Nexthealth~12:02UTC. Frozenartifactuntouched.

Current continuation — 2026-10-24 12:08 UTC. The new sync-prune1 soak remains
running; no soak binaries, configuration, workload or state have changed for TPS.
At 12:04:35 all five matched H130855, all observer streams were under 4.54 seconds
old, workload alive, no restarts or recorded OOM/swap events.
Local native-preparation 30-wallet results are terminal. At 1 TPS offered for
30 seconds: 27 admitted/finalized, 3 queue-full rejections, full drain 104.5368s,
0.258282 TPS including drain, p95/p99 77.4867/77.5026s, 19 over 30s. At 0.25 TPS
for 120 seconds: 30 admitted/finalized, zero rejections, full drain 137.7064s,
0.217855 TPS including drain, p95/p99 33.2061/33.2247s, TWO over 30s. Both runs
mean native blocks approximately 2.30–2.32s. Neither meets original release timing;
no load escalation or sustainable qualified capacity claim. Raw reports and all
five wallet checks preserved under E/tps-local-native-preparation-internal-*.json.
Both used Apple M4 Mac16,10 / 10 logical CPUs / 16GiB, one process and internal
APFS, independent 1GiB pools and genuine encrypted production owners.
The next step is a bounded operation profile, not a protocol change. Existing
qualification-timing hooks now have a test-only initializer, pinned executable
SHA3 and original bounded writer; deployed builds cannot call it. Native fixture
reads optional POSY_TPS_TIMING_CONFIG and records dropped/failed diagnostic counts.
Build session51810 RUNNING with --features qualification-timing; logs target/
posy-tps-processing-stage-profile-build-20261024.log/.jsonl. Do not duplicate build.
Once complete, seal exact artifact and run eight-wallet internal APFS native-path
profile with public timing stream in a private external APFS directory. No new
release gate. Identify exact measured stage before any production optimization.
Next read-only soak health check approximately 12:10 UTC.

NEXT: protectsoak, monitoradvancingmatchingfinality/streams/resources/IO/retirement/
workload; neverrestart/reset/changegates. MaxTPSengineeringisnowauthorizedONLY
separateLOCAL/nativefixtures, neverheavybenchmarkoron-soakhostload. Distinguish
localfixturefromdistributedTPS, offeredfromprepared/finalized; no.1TPSceilingclaim.
Criticalpathcontroller53789 COMPLETEsuccess,no driverleft toduplicate. Allmandatory
results/rawpinsunderE=target/posy-async-conformance-audit-20261021. Preserveallfailures.

Historical immediately preceding execution (11:17UTC):
Current exact continuation (2026-10-24 11:17UTC): SAME critical-path controller
localexecsession53789 RUNNING; do not launch another controller/load. Allfive
signedsequence12 exact sync-prune1 correctedcandidate active, originalstate/config
preserved, productionexcluded. NodeSHA256e8d0fd40058bd0fc561da5eb0e96e06022d2dbdf859db1fda80a5b1043be0d57.
New memory30 PASS30submitted/30admitted/30finalized, exactallfivewallet effects,
maxcontextfinality18.49515s; mean nativecertified/finalizedintervals~.970–.971s.
Original64heightretirement observedallfive; allOOMevents/swap0. Val6 ONE unavailable
metadataread at11:09:02.424521UTC reasonmetadata_lock_timeout, NOT a returned snapshot.
Original combinedunavailable_or_incoherent1 andraw arepreserved; additive classification
E/sync-prune1-memory30-metadata-availability-classification-20261024.json pinsallraw,
zero returnedincoherent,3–4 coherentfullyretiredsamplesafter64heights onallfive.
Newcandidateauditadapter now applies originalreview's explicit unavailable-vs-incoherent
rule, verifiesrawhashes/recomputesretirement; no criterion/source/runtimechange.
NEW600s0.1TPS sustainedarrival DISPATCHED11:11:08.550UTC, currentlyNONTERMINAL;
expect offeredwindowend~11:21:45UTC plusdrain/review. Do notinferpass or duplicate.
Sourcefreeze16,875compilerfilesMATCH, sourceinventorySHA256
5b261afa0ac42283a4bb26ed286d0e36b834e10f2118ed32ad44ffb9c34857b8,
revisionb338dcc223c1ce33599e12c424858cd000772637, dirtyinventoryexplicit.
Val3 boundedobservation terminal1800.039s/1713resourcesamples/errors0/onePID;
nativeSync7200rows1461.523319s steadymaxpending2.027454s, unrecordedtail338.48s.
Fullperiod sampledservicereadinessmaxpending2.566310s; initialrestart11.374142s
pending and16.294656s firstverifiedtargetComplete areseparate120srecoveryevidence,
not5ssteadypass. Concrete no-opprune fsync/writeamplificationfixed, notprovenSOLE
original26sreadinesscause. Native/provenance/actualVal4 256MiB passesapplicable.
AllfivecurrentPIDs2=1326171,3=1278849,4=1560859,5=1329254,6=1271292/NRestarts0.
20freshqualificationobserversroot distributed-sync-prune1-qualification-20261024.
Native5sreadiness/30stxfinality/.5–1.5smeanblocks/1GiBswap0 unchanged.
NEXT: consumeTHIS600s terminal, auditexactallfivewallets/nativeblocks/fixedresource
windows/hostswapIO/metadata, thenfreezeandstartNEWsync-prune1-24h-soak-20261024
ONLYifallestablishedgatesPASS. Existingcontroller haspreparedmanifest/newobserver/
dispatch/healthstages; NOTSTARTED. ExistingheartbeatPAUSEDuntilactualnewstart.
OldsoakremainsFAILED/all130closedalready, neverrepeat/resubmit. MaxTPSstartsWHEN
newsoakstarts, independentenvironment. Console target/posy-sync-prune1-complete-
critical-path-console-20261024.log; child target/sync-prune1-critical-distributed-
qualification-20261024.log. Preserveallfailures; resumeonlyuncompletedstages.

Historical continuation (2026-10-24 10:41UTC): Human broadly approved focused
remediation and progress to a NEW isolated soak; MaxTPS work starts WHEN that
newsoak starts. Original failedsoak/all130-transfer reconciliation remain closed;
no resubmission/workload/newsoak restart. Exact sync-prune1 correction ACTIVE ONLY
onVal3 after one authorized controlled restart at10:36:18.461376UTC, PID1278849,
NRestarts0. NodeSHA256e8d0fd40058bd0fc561da5eb0e96e06022d2dbdf859db1fda80a5b1043be0d57,
SHA3-256 2aec27af8e5fa56b1dae4174a3564c0ee5581beb97618cf016ee08bc734f4db3.
Canonical source includes previously focused-tested ack2r1 plus narrow prune1:
validated caught-up archive cursor/no released pins returns without empty guarded
metadata transaction, preserving actual proof verification/retirement/recovery.
Original config/custody/units/immutable timeout retained. No production changes.
Native focused proof/retirement/reopen regression PASS2.49s; live five-validator
encrypted hold/takeover/threeQC/wallet/restart/noDuplicate PASS94.152s. ExactLinux
optimized bins/tests built; complete before/after source inventories MATCH. Actual
Val4 exactLinux focused ordering/reveal/proof/recovery tests PASS under256MiB,
peak24481792B, all cgroup events0/swap0; not a throughput result. Linux testSHA256
e4c072ceadf6ca71c1c740d7268fad74acf7d8396fc2d5d892281a7e43656e7d.
Concrete defect/evidence: original cleanup commits even unchanged cursor/pins on
everyExecutionpoll while holding proposal-store mutex. Before30.104s:641 journal
generations/32 cursorheights; after30.135s:155 generations/31 cursorheights. Those
headers also include legitimate proposal transitions, not exact redundant-write
counts. Sourceguard regression proves unchanged cleanup no longer rewrites header.
Trace2 baseline completed1807.027s, raw19021661B SHA256c102f0cd2c49c473662835abc3dcd95536ad7b8a19c88633299c9bbe46aa8210;
Sync7200rowcap reached1447.832s, maxpending4.529588s; cannot claim continuous native
trace for unrecorded tail. Resource observer complete1800.034s/1719samples/errors0.
Trace2 did NOT reproduce original>5s loss, so write defect is not yet proven SOLE
originalcause. Exact final frontier/operation correlation and raw data saved inE.
New prune1 bounded trace/resource observer RUNNING until~11:06:18UTC; remote root
/var/lib/synergy/posy-async-canary-20261022-rc1/diagnostics/sync-prune1-val3-20261024T103520Z;
collector1278769, activationdriver1278770, resourceobserver1278860. Do not duplicate,
restart or abandon this run. Initial restart catch-up has11.374142s pending, verified
peer-targetComplete at16.294656s; preserve this, not a5s steady pass. At10:40 after
verifiedcatchup maximum recurringpending.444769s across~218s. Five-second steady
readiness qualification remains INPROGRESS. Otherfour signedseq11 nodes unchanged.
First uncompressed upload timedout120s BEFORE any staging; direct preflight proved
Val3 PID1240555 unchanged/newdirectoryabsent. Exact compressed transfer succeeded;
transport failure logs retained, no protocol deadline changed. Component helper
first had stale imported-name/socket failures BEFORE remote mutation; corrected to
reuse existingVal4 master, successful terminal result retained.
Continuation preparation10:57UTC: exact corrective release signedsequence12 and
natively verified onallfive; signedJSONSHA256c506984e5dce2f7ce567b4fa061ea1962951d13dd92438c65e790caef88cdd40.
Otherfour artifacts staged only; originalPIDs unchanged. Read-only mixed exact-release
check PASS advancing allfive matching commonfinality. Signing verification initially
used candidate12 as previoussequence and refused NonMonotonicSequence; existing
signature adopted and independently verified with previous11, never re-signed.
Runtime adapter first compared Val3 diagnostic drop-in against the nondiagnostic
text; failures retained, exact diagnostic text validated, PASS. No runtime failure
in either helper mistake. At10:54 recurringpendingmax2.027454s afterverifiedcatchup;
no observed OOM/swap. Bounded run still ends~11:06:18UTC, mustconsume terminal.
NEXT: target/posy-sync-prune1-finish-observation-20261024.py consumes THIS existing
run, then posy-sync-prune1-qualify-distributed-20261024.py serially activates other4
(oneatatime, allfive commonfinality betweenrestarts), launches exact new observers,
runs established new30-transfer memory/64height-retirement and600s0.1TPS resource
checks. Existing5s/30s/.5–1.5s limits unchanged. No old130 reconciliation/resubmission,
newsoak or maxTPS work. Native Synctrace7200rowcap coverage willbeexplicit; never
claim continuous observation in unrecordedtail. Existingresource requirements reused.
No releasequalification or soak success claimed from these preparation scripts.

At11:01UTC nativeSync trace reached its7200rowcap at1461.523319s (24m21.5s),
steadymaxpending2.027454s; originalrestart11.374142s remainsglobalmax. Do notclaim
nativephasecoverage afterrowcap. Existing1s fullresource observer ALSO records
native service readiness through chainTelemetry; finalreview willreport its exact
sampled pending windows separately. Current1GiB cgroup all events0/swap0, PID1278849,
continuousfinalityadvancing; previousworldroot remainsunchanged withno newload.
One critical-path driver RUNNING as localexecsession53789, waitingforTHIS collector
terminal~11:06:23 then collecting rawstreams/hashreview, serialpeerqualification,
newcohort/600sresourcechecks andnewsoak ONLY ifeveryestablishedgatepasses. Do not
start another driver or duplicate any load. Console target/posy-sync-prune1-complete-
critical-path-console-20261024.log; child qualification logs target/sync-prune1-critical-
distributed-qualification-20261024.log. Existingsoakautomation staysPAUSED until
actualnewsoak starts. Newidentity prepared sync-prune1-24h-soak-20261024; notstarted.


Historical continuation (2026-10-24 08:53UTC): Human approved the concrete
trace2 activation and necessary focused remediation toward a NEW isolated soak.
ONE trace2 Val3 activation occurred08:44:21.172754UTC, PID1240555/NRestarts0,
nodeSHA256b0b2776eac2a820413c723543fd99c2dc12fd29069ae442a4dc68afc14028f78.
Existing state/config/custody and immutable timeout hashes preserved. Otherfour
validators unchanged; production excluded. No transaction/workload/soak restart.
Trace2 native capture RUNNING until~09:14:21UTC, do not duplicate or restart it.
Remote diagnostics/sync-trace2-val3-20261024T084413Z; collector1240479 and separate
resource observer1240566. E/sync-trace2-val3-activation-authority-20261024.json,
activation-before and latest preserve authorization/artifact/runtime evidence.
At08:49 maximum continuous per-poll pending3.321297s, NOT yet a5s reproduction.
Measured PoSy completion stage1.773232s, Execution processing1.479875s and proof
cleanup1.018110s; Sync acknowledgement stage max.002255s, no retained outbox.
Longest current pending window shows durable ack118651 stalling while PoSy and
verified target advance, then snapshots/native execution catch up to118655.
Specific storage defect found: ProcessingProposalStore::prune_archive always
commits a new generation even when caught-up cursor/pin ledger do not change,
on each Execution cleanup poll under shared proposal-store lock. Narrow isolated
candidate adds a no-transition return ONLY after original pin-ledger validation,
with regressions for retained proof availability, actual release, unchanged
metadata on retry and reopen. This is a demonstrated write-amplification repair,
NOT yet proven sole cause of original readiness failure. Native optimized build
RUNNING; no corrected artifact activated. Canonical ack2r1 remains present and
separate from trace2 deployed original Sync behavior. Next: correlate final trace2
frontiers/owner timings/resources, finish focused prune regression, qualify smallest
supported integrated correction. No new soak/max-TPS job exists; original soak
remains failed and all130 transfers already reconciled, do not repeat/resubmit.

Historical continuation (superseded operator boundary, 2026-10-24 06:51UTC): The ONE approved Val3 trace1
activation/30min native capture is COMPLETE; do not repeat it. Native collector
7056rows/7820685B, terminal1807.77s including collector grace, native emission
stopped at its original1800s cap. Exact raw SHA256f8998bffb80e38620357ab15fb72d9653b9d010c67e8c15c804b0333fa519d85.
Longest SAMPLED pending interval5.957928s at06:32:59.990279–06:33:05.948207;
ack110967→110970, selectedtarget110968→110972, retainedoutbox0 throughout;
localPoSy also lagged verified peers. No queued-ack starvation is demonstrated.
Do not call this continuous5s failure proof: trace1 samples phases every250ms.
NEW CONFOUNDING EVIDENCE: apt-daily-upgrade requested systemd reexecution at
06:33:00.945737, reexecuting06:33:00.959795; host networking/services restarted
through06:33:06.803336, apt finished06:33:12.853928 (21.649sCPU/35.081swall).
Original21:44:40–21:45:25 failure window has no matchingPID1 events. Hence this
recurrence does NOT prove the original rootcause or justify speculative repair.
E/sync-trace1-system-window-review-20261024.json preserves exact journal windows.
The separate Val3 resource observer FAILED at06:33:01.242605 when systemctl-show
returned1 during reexecution:1030attempts/1029samples,1081.225s, periodcompletefalse.
No automatic observer restart. Its raw10322488B SHA2561696e25a609a9d085b53d6971c4d68d9e21ac18057db93af1fa47c0fdfac3798
and exception are retained. Val5 original resource observer also exited on
systemctl-show; only18original observers nowrunning. Do not claim continuous
30min resource coverage or20healthyobservers. Current06:50 direct Val3 check
PID1191132/NRestarts0, exact trace1hash, config/custody/originalunits and immutable
timeout unchanged, H111938; RSS69132KiB, cgroup616767488B, all memory.events0/swap0.
Allfive exactcommonfinalityH111656 matches at06:45; otherPIDs unchanged. Evidence
E/sync-trace1-val3-final-review-20261024.json and health064521970915Z.

Prepared separate INSTRUMENT-ONLY sync-trace2, NOT staged/deployed. Adds bounded
operation costs around existing PoSy/Execution and Sync stages, exact per-poll
pending-duration/phase-change trace, native replay deferral cursor/age. Original
pre-ack2r1 Sync order/target/recovery behavior preserved in sealedcandidate;
canonical source ack2r1 ordering restored after exact build inventory. Removing
added timing statements byte-matches original trace1 PoSy/Execution source hashes.
Linux nodeSHA256b0b2776eac2a820413c723543fd99c2dc12fd29069ae442a4dc68afc14028f78,
full compiler/source inventory matched. LocalnativeM4 optimized encrypted
hold/takeover/threeQC/wallet-effects/restart/noDuplicate fixture PASS97.387s;
not distributed qualification/TPS/steady5s proof. Intentionalrestartednode has
maximumPending8.684659s, honestly retained. Cargo check with existing diagnostic
feature passed; optimized native/Linux bins+tests compiled. No protocol correction
or deadline change claimed from instrumentation. A separate read-only monitor
preparation records transient systemctl failures instead of terminating; no host
monitor source or OS policy was changed. Both resource gaps remain explicit.
Concrete activation review E/sync-trace2-val3-diagnostic-activation-review-
20261024.json SHA256d7ed7ba793627bebdc9eca88ca2b78f3bffc44d2ba45210553e7ba2db862c8af.
NEXT ACTION / REAL OPERATOR BOUNDARY: request ONE controlled isolatedVal3 restart
with this exact trace2 candidate for<=1800s, retaining existingstate/config/custody,
no transfers/load/soak restart. Further deployed binary changes were expressly
reserved by the operator; prior approval covered ONLY trace1. Until newapproval,
do not stage/activate/restart/rollback or repeat generic monitors/qualifications.
Original rootcause still unproven; ack2r1 remains separate, not promoted. Original
soak remains terminalfailed; TPS directive applies WHEN nextsoak starts, perhuman
clarification. No newsoak or maximum-TPS job exists. All runs/builds thisturn terminal.

Operator clarification (2026-10-24): The later ETDAG throughput/scalability
directive is for WHEN THE NEXT24h soak starts; it does not replace the current
approved Sync diagnosis. No new soak exists in current evidence. No benchmark,
source optimization or resource-intensive job was launched on local or validator
hosts in response; only fixture/environment reads. Continue the already-running
bounded Val3 diagnostic, then the smallest proven correction and established gates.

Current authorized diagnostic (2026-10-24 06:15UTC): Human explicitly approved
ONE bounded Val3 trace1 activation. Activated06:14:59.894527UTC, PID1191132,
exact node SHA2560cee5f44801b7381333c427fb20f24de181e237d3dd95593137b9ccce81f6e97.
Original Sync behavior, no ack2r1 repair deployed. Existing state/config/custody,
sequence11 artifacts, original unit files and immutable timeout hashes preserved.
No transfers/load/soak restarted. Evidence E/sync-trace1-val3-activation-before-
20261024.json and sync-trace1-val3-latest-20261024.json. Remote bounded trace root
/var/lib/synergy/posy-async-canary-20261022-rc1/diagnostics/sync-trace1-val3-20261024T061340Z;
collector1191037, separate native resource observer1191143, original binary-hash
observer ended honestly on authorized identity change; its evidence is preserved.
Other19 original observers remain running. Allfive finality advancedH110002/3
at06:15:25UTC. Trace caps1800s/7200rows. Next collect target/cursor/outbox/poll
correlation from THIS existing observation; do not relaunch it or repeat isolated
tests. No additional validator restart/rollback authorized. Original failedsoak
remainsfailed. The prior pending diagnostic activation request below is superseded.

Latest critical update (2026-10-24 00:30 UTC): SOAK ABORTED, NOT SUCCESSFUL.
No workload or validator restart, no source/config/timing changes. Isolated
Val2–Val6 continue finalizing; production untouched. Keep all observers running.
Actual terminal failure occurred2026-10-23 21:45:14.537901UTC, ~1297.299451s
after21:23:37.238450UTC workload start (~21m37s). Driver1034987 exited1.
130submitted,129observed admitted,128all-five verified before abort,2unresolved
in terminal report. These partial counts are NOT a successful86400s soak.
Exact error synergy_nodeStatus RPC failed: TimeoutError atVal3 RPCforward28546.
Trace shows14 earlier successful Val3 nodeStatus requests in the same5s
native-readiness operation; final request had .300561719s remaining and timed
out after .302555117s. Do not describe this as a full5s individual RPC stall,
nor assume a transport-only fault. Native Val3 resource telemetry confirms
Sync readiness pending (verified synchronization remains in progress), while
finality advancedH82477→82495 and execution lag1/5/5/3/3 in the failure window.
Other services remained ready. Primary observed blocker is sustained native
readiness loss during verifiedSync; why Sync stayedpending still needs diagnosis.
Do not bypass readiness or extend its5s budget/30s transaction budget.
At00:26 allfive sameprocesses/no auto restarts, matching common finalizedH91430;
20observers fresh, host+cgroupOOM/swap0, RSS~75–84MB, reservations~51–60MB,
all processing namespaces coherently retired to400logicalB. Cgroup max-limit
reclaim counters later nonzero on2/3/5/6, retained as pressure evidence; absence
ofOOM does not erase this or prove full24h load stability.
E=target/posy-async-conformance-audit-20261021. Preserved terminal report,
command, exit and fullRPCtrace under reveal-fence1-24h-soak-20261023.*.
Raw93,507,761B proof retained onVal2, SHA256
843207bb40150eb580f1845f2af34e6814746cc8d9038672df914a8ae4554848;
reportSHA256 cb339b8559fc93c5e6eb5e68212a8e0d46837c1719646106bb9fe5149f5a08fc.
Initial diagnostic reveal-fence1-soak-abort-initial-diagnostic-20261024.json;
Val3 native window reveal-fence1-soak-val3-failure-window-20261024.json;
current allfive health reveal-fence1-soak-health-20261024T002649185523Z.json.
Update00:35UTC: all130 submitted transfers EVENTUALLY reconciled onallfive at
common finalizedH91737, identical block/state, exact33wallet balances+nonces,
receiver594. This closes the2unresolved effects, not the failedsoak/timing.
Evidence reveal-fence1-soak-abort-wallet-reconciliation-20261024.jsonl and
reveal-fence1-soak-abort-expected-wallets-20261024.json; no resubmission.
Cross-host native passive evidence reveal-fence1-soak-sync-readiness-cross-host-
20261024.json confirms Val3 Syncpending over sampled26.171540s in thefailure
window while durableheight82477→82502; theotherfour areSync-ready in thatwindow.
Val3 also has a sampled30.591374s Syncpending run afterloadaborted, advancing
H91125→91152. Therefore the demonstrated readiness defect also reproduces
without offered transactionload; do not call it a proven TPS capacity ceiling.
Five-second samples bound observedspans, not exact transitionduration.
Source trace: Sync poll selects newest verifiedpeer PoSy head as target while
local cursor advances only on durable Execution acknowledgements; Complete is
required for Sync readiness. Outbox pending canreturn before acknowledgements
are consumed. These are candidate mechanisms, not a measured final rootcause.
Update00:40UTC read-only diagnosis: bounded60s simultaneous localhost observations
onVal2/3 captured120samples/host without source/config/load changes. Native
durable execution advanced92012→92072/92071. Syncpending was only2/6samples,
maximum executionlag2, persisted candidate-request null throughout; thelong
failure interval did not recur. Do not extrapolate this minute into a fix.
Evidence reveal-fence1-sync-readiness-local-frontier-observation-20261024.json
and its summary. CPUquota is unlimited/no throttling allfive; failure-window
background queue waitmax1.972537s, no sampled queuedjobs, maximum recentworker
time83.339671ms, no hostmemorypressure. These exclude a demonstrated persistent
background queue saturation claim; source-level outbox hypothesis remainsunproven.
Val3 persisted snapshot inventory shows actual acquisitionsH91650/91652/91671/
91741 around00:31–00:33UTC, despite ongoing native progression. Source snapshot
acquisition begins when selected peer target exceeds local durable cursor by>1;
candidate fetching separately honors the bounded locally-replayed prefix wait.
The snapshot path is the next narrow diagnostic boundary; inventory alone does
not establish that snapshots caused the earlierfailure. Evidence
reveal-fence1-sync-readiness-snapshot-inventory-val3-20261024.json and
reveal-fence1-sync-readiness-preparation-failure-window-val3-20261024.json.
Update00:49UTC: health snapshot reveal-fence1-soak-health-20261024T004528449530Z.json
shows allfive original PIDs active/no restarts, advancing durableH92449/92450;
20observers fresh (<4.4s), OOM/swap still0. Snapshot-correlation90s observation
reveal-fence1-sync-snapshot-correlation-val3-20261024T004742Z.json captured180
Val3 samples,10 isolated Syncpending samples, lag<=2, no active snapshot and
zero RPCerrors. The long readiness failure did NOT recur; this neither proves
snapshot causation nor resolves the blocker. Do not repeat short random sampling
as if it qualified a repair.
Read-only contract audit: native_endpoint_state in run-posy-tps-baseline.py
requires global ready before each fleet sample within a shared5s budget. Accepted
manifest constraints and async conformance release table explicitly record30s
transaction finality, .5–1.5s mean blocks and bounded resources; these reviewed
records do not separately specify continuous5s global readiness. RPC protected
submission/context handlers do not themselves test snapshot.ready(). This is a
measurement-contract distinction requiring resolution, NOT authorization to
bypass readiness or reclassify the failed soak as successful. Preserve current
5s behavior and all failure evidence while establishing the runtime cause.
To capture a recurring LONG pending interval without extra RPC polling, launched
one bounded passive diagnostic onVal3 at00:48:28UTC: PID1082988,900s/2s samples,
4MiB cap, reads existing resource telemetry plus active snapshot/candidate and
current durable pointer. It performs no RPC or validator/state mutation. Exact
launch record reveal-fence1-passive-sync-correlation-launch-20261024T004828Z.json;
remote evidence /var/tmp/posy-async-canary-20261022-rc1-sync-correlation-20261024T004828Z.jsonl.
Launch verified alive and writing; preserve evidence even if no long recurrence.
Update00:50UTC: latest health reveal-fence1-soak-health-20261024T004927213944Z.json
has identical allfive durable finalized state atH92673; all20observers fresh,
no restarts/OOM/swap, retirement remains coherent400logicalB. The bounded passive
Val3 diagnostic is alive; first30samples contain no active snapshot or new long
readiness event. Partial review reveal-fence1-passive-sync-correlation-review-
20261024T004928Z.json is retained. IMPORTANT for later correlation: diagnostic
samples repeat the latest5s resource row every2s. Deduplicate resource_sequence
and measure readiness spans with resource_utc; do not count repeated cached
telemetry as independent readiness observations. Snapshot/durable file reads use
the diagnostic row's own UTC, not the older resource timestamp; preserve this
sampling offset before claiming causation. No new runtime diagnosis established.
Update00:55UTC: health reveal-fence1-soak-health-20261024T005425762206Z.json
shows advancingH92945–92946 and EXACT matching allfive finality records atcommon
H92945 (unequal independently observed tips are not a fork). All originalPIDs,
20observers fresh, zeroOOM/swap; max-reclaim counters unchanged since00:49.
Passive review reveal-fence1-passive-sync-correlation-review-20261024T005426Z.json
covers179 diagnostic rows /71 distinct resource samples,7 isolated pending
samples and no multi-sample pending run. It captured one actual verifiedVal2
snapshot at00:53:04.864UTC: targetH92869, received1/1chunk; contemporaneous durable
pointerH92868, resource sample0.486s older reportsH92867/Syncpending/lag1. This
establishes snapshot activity during short readiness loss, NOT the cause of a
long pending interval. No repair justified from this observation alone. Sampler
PID1082988 remains running until~01:03:29UTC; do not duplicate or extend it.
Sync metrics/status are private to the native owner; current public service status
reports generic readiness, not selected peer target/outbox/ack queue depth. No
existing exported internal measurement was found; do not label outbox starvation
measured from RPC lag alone. Preserve the current read-only diagnostic boundary.
Update01:00UTC: health reveal-fence1-soak-health-20261024T005935879102Z.json
has matching allfive finalized state/evidence atH93237, originalPIDs and20fresh
observers, zeroOOM/swap; reclaim counters unchanged. Passive partial review
reveal-fence1-passive-sync-correlation-review-20261024T005936Z.json covers334rows /
133distinct resource samples,13isolated Syncpending samples, no multi-sample
pending run and the same one short snapshot observation. PID1082988 still alive;
keep its original~01:03:29UTC termination. Rootcause remains unproven; no repair,
restart, gate change or post-soak comparison is justified from these samples.
Update01:06UTC: the bounded passive diagnostic completed normally at
01:03:29.320818UTC after900.592803s,450rows/179distinct resource samples. Its
680386B raw stream is retained remotely and copied byte-for-byte to externalSSD:
reveal-fence1-passive-sync-correlation-val3-20261024T004828Z.jsonl, SHA256
ab8c1d52f59a41316b9bb9dfccc71f4324d1fe7b4f0a7dda6c95447657d2c3e2.
Final review reveal-fence1-passive-sync-correlation-final-review-20261024.json.
There were16distinct pending samples. At01:01:04.266731 and01:01:09.492041UTC,
Syncpending samples are5.225310s apart, executionlag1 atboth, Execution advanced
H93296→93298; separately sampled durable pointerH93297→93300. All2s file reads
in this interval have no active snapshot/candidate request. These are sampled
observations, NOT proof that readiness stayed continuously false between them.
Cross-host correlation reveal-fence1-passive-sync-recurrence-cross-frontier-
20261024.json shows the other validators advancing at similar heights/lag1;
no unique sustained Val3 execution backlog is demonstrated in this recurrence.
This narrows the hypothesis: a visible active snapshot/candidate import is not
required for sampled readiness loss. It does NOT establish the internal target,
Sync durable-ack cursor or outbox return reason, and does not settle original
26s failure causation. Do not claim a proven snapshot or transport rootcause.
Current health reveal-fence1-soak-health-20261024T010435673429Z.json has matching
allfive finality atH93475, originalPIDs,20fresh observers and zeroOOM/swap. Val2/6
max-reclaim counters increased to1587/1781; retain aspressure evidence, notOOM.
Latest read-only monitor checkpoint05:29:25UTC: evidence
reveal-fence1-soak-health-20261024T052921959774Z.json shows common finalityH107534,
matching allfive finality evidence, originalPIDs/no restarts and20fresh observers.
Allfive advanced since prior snapshot. Host+cgroup OOM0/swap0; retirement metadata
remains coherent400logicalB. Reclaim maxcounters2/3/4/5/6=9118/10009/0/10321/7943;
pressure evidence retained. Minimum available host disk160251727872B.
Workload remains terminalfailed; no restart/resubmission. Diagnostic instrumentation
scope decision requested once at01:06UTC remains pending; heartbeat is not approval.
No instrumented build, extra sampler or validator/workload restart performed.
NEXT / AUTHORIZED DIAGNOSIS (operator directive 2026-10-24): The operator
has now authorized narrowly scoped instrumentation and the smallest measured repair
in a separate isolated candidate. The prior pending-authorization boundary is
superseded. Deployed signedseq11 binaries and all existing validator state remain
unchanged; no failed-soak restart or transfer resubmission. Diagnose Sync selected
verified peer frontier, durable Execution acknowledgement cursor, outbox state and
owner scheduling. Build separate exact diagnostic artifacts from canonical source,
reproduce the operation, preserve before/after evidence, then verify the original
5s readiness and restart/catch-up contracts. No new gates or deadline changes.
Update (operator-authorized isolated diagnosis, 2026-10-24): unmodified trace1
candidate reproduced a concrete Sync acknowledgement-starvation defect. With eight
outbound frames, one retained unsent frame, and durable Execution acknowledgement
H1 already queued, poll returned with cursorH0 / SchedulingBlocks. Noncontiguous
acknowledgement rejection still passed. Evidence E/sync-sync-trace1-durable-ack-
20261024.log and sync-sync-trace1-host-result-20261024.json. The unchanged traced
live encrypted hold/takeover/restart fixture passed in99.62s under1GiB/zero swap,
peak232398848B/no cgroup events. Separate120s sparse encrypted native-owner probe
also passed; allfive traces show only isolated pending samples, no retained outbox,
no queued acknowledgements. This did NOT reproduce Val3 long readiness loss and
must not be called its proven cause. Raw evidence E/sync-sync-trace1-steady-*
retains target/cursor/frontier/scheduling samples and genuine transaction timing.
Small isolated ack1 repair moves the unchanged bounded contiguous durable-ack
consumption loop ahead of Sync network output/maintenance. Unsent bytes and skipped
height rejection remain unchanged. Exact build source inventory and compiler inputs
matched; sealed node SHA3=3d2b48e7d97e9134f9ea6048049a7992303ad3fda3e06f6cda54281b84e9b7da.
Acknowledgement regressions now both pass, including5.1s retained-outbox readiness;
live encrypted restart fixture is running, not yet accepted. These are diagnostic
artifacts only, not release qualification or an explanation proven for original
Val3. Current action: collect ack1 integrated result, inspect moving-target evidence,
and close the production-preparation-path diagnostic gap. Existing deployed signed
binaries and all validator state remain unchanged. Original failedsoak staysfailed.
Further isolated result: ack1 encrypted hold/takeover/restart fixture PASSED82.17s,
peak215994368B/no OOM or swap. Superseded isolated ack2r1 adds the necessary target
preservation: durable H1 must remain pending when verified target isH2. Its three
acknowledgement regressions passed onVal3 in6.24s. Exact node SHA256
80e4129fe7c2162d09190f5729d2dde5a85c801b8bf191b2dddb579769f33e7d;
SHA3 bb1c208b016161ab5ba4948c1f29c2e9fa756929e8e90da4d1eefe2b8592a016;
full source and compiler-input inventories matched. Earlier ack2 build failed on
an incorrect test enum pattern; failed log retained; corrected once as ack2r1.
Review packet E/sync-ack2r1-candidate-review-20261024.json records applicability.
The test fixture now optionally uses actual Sync background preparation, controlled
by SYNERGY_SYNC_DIAGNOSTIC_NATIVE_PREPARATION=1; production owner/pool behavior is
unchanged. Existing certified-gap/prefetch and live encrypted restart tests are
running, not passes. Do not launch an overlapping Val3 fixture or duplicate runs.
One90s read-only49Hz Sync-thread profile of the UNCHANGED deployedVal3 completed:
510samples/no lost samples; all recorded bytes pinned in E/val3-sync-profile-*.
Nineteen distinct native resource rows coverH108691→108779, two isolated pending
samples, no sustained recurrence. Binary symbols are stripped; the profile cannot
name the private poll boundary and is NOT root-cause proof. No repeated sampler.
The diagnostic70-block legacy certified-gap case reachedH57 but its240s wrapper
budget expired before reaching the gap/rejoin phase; preserve as INCOMPLETE, not
pass and not a new canary gate. Original timing/consensus limits were not changed.
The focused8-block outstanding-request case is still running; live encrypted
restart follows in the same already-running driver. An unchanged trace1 control
of the two legacy cases is running onVal4; do not duplicate it.
Current action: collect these already-running results, then one bounded steady
readiness probe with native Sync preparation onVal3. Original Val3 cause remains unproven. Activating diagnostic
artifacts on an existing deployed validator requires further operator authorization.
Operator approval requested once for a concrete instrument-only trace1 activation
on existing isolatedVal3 (bounded30min, no repaired behavior, no load/resubmission,
retain durable state). Packet E/sync-trace1-val3-diagnostic-activation-review-
20261024.json; nodeSHA2560cee5f44801b7381333c427fb20f24de181e237d3dd95593137b9ccce81f6e97.
This is a real explicit operator boundary, not permission inferred from a heartbeat.
Do NOT stage/start/restart deployed services before the human answers. Continue
already-running isolated tests meanwhile. No failedsoak continuation or success.
Integrated ack2r1 results now collected, E/sync-sync-ack2r1-host-result-20261024.json:
three acknowledgement regressions PASS6.24s; outstanding request/reordered prefetch
restart/catch-up PASS84.31s; genuine encrypted hold/takeover/finality/restart/rejoin/
no-duplicate fixture PASS92.61s. All use native Sync background preparation onVal3.
Group peak435449856B/1GiB, memory.events all0, swap0. Intentional held/restarted
transaction test is fault/recovery coverage, not original30s steady timing proof.
70-block certified-gap INCOMPLETE at240s before its recovery phase; unchanged
trace1 control onVal4 also INCOMPLETE240s (not a paired timing comparison). Both
raw failures preserved, no budget extension. The unchanged focused prefetch test
PASS118.67s. No 70-block recovery or distributed qualification is inferred.
The single ack2r1 steady readiness/native encrypted probe is currently running
onVal3, root/var/tmp/posy-sync-sync-ack2r1-steady-20261024, PID1186456. It offers two
fresh synthetic transfers at0.1TPS with120s observation, not capacity work. Do not
start a duplicate or overlap a Val3 workload. Collect via existing
 target/posy-sync-native-preparation-steady-collect-20261024.py sync-ack2r1.
After collection the next deployment step remains pending explicit diagnostic
activation approval; do not continue the old read-only sampling/build loop.
FINAL ISOLATED RESULT / EXACT RESUME (2026-10-24T06:05:25.210801+00:00): ack2r1 native Sync
preparation steady probe COMPLETED normally122.765s (120s observation). Allfive
per-poll measured maximum pending durations .675740/.276462/.849950/.893328/
.779736s, all below original5s requirement. Two FRESH synthetic encrypted transfers
finalized with exact allfive wallet effects in14.050935/17.127426s, both below30s;
receiver14, rejected0. Group peak402915328B/1GiB, no cgroup events/OOM/swap.
Evidence E/sync-sync-ack2r1-steady-result-20261024.json, exact raw native input/log,
and sync-ack2r1-steady-measurement-summary-20261024.json. Original130 transfers
were not repeated. No capacity ceiling or distributed/24h qualification inferred.
All isolated runs are now terminal and their logs collected. Do NOT rerun them.
Post-test allfive health at06:03:51UTC retained in
reveal-fence1-soak-health-20261024T060351051228Z.json: originalPIDs/NRestarts0,
20observers, ongoing native finality, no OOM/swap. Reclaim max counters2/3/4/5/6
9383/10293/0/10709/8161 retained as pressure evidence, not dismissed by no OOM.
EXACT NEXT ACTION: await the already-present human approval request for the
instrument-only trace1 Val3 activation packet (SHA2560cee5f44...81f6e97). Only after
explicit approval, stage/verify that exact diagnostic candidate separately, perform
the authorized controlled isolatedVal3 restart retaining durable state, and capture
target/cursor/outbox/poll evidence during recurring readiness loss. No automatic
restart, no source expansion, no additional generic monitoring/qualification loop.
If authorization is absent, deployment is genuinely blocked; native observers stay
running. Separate ack2r1 repair remains unpromoted pending original-cause diagnosis
and existing release checks. Failed originalsoak remainsfailed; newsoak must receive
its own identity/start only after corrected exact distributed candidate qualifies.
Maximum TPS work remains separate and 0.1TPS is not a throughput ceiling.

Previous critical update (2026-10-23 21:28 UTC): ISOLATED CANARY RUNNING,
OFFICIAL INITIAL BASELINE RECORDED, 24-HOUR SOAK STARTED. Production untouched.
The human explicitly approved this exact frozen candidate and dirty inventory;
approval record is reveal-fence1-operator-exact-input-acceptance-20261023.json.
Accepted manifest reveal-fence1-accepted-isolated-canary-manifest-20261023.json
SHA256 d954a17265d772c8b35523f9e60572e3c1fecc8ca76bf1633b62b22bdb0c301a.
Scope is exact signed sequence11 reveal-fence1 on isolated Val2–Val6 only;
generic clean-source promotion remains ineligible. No compiler/config change.
Node SHA256 b05c5e60c090e0d9d377dc2caa99e47068dd6ca0330c57cd6fb139b78e5ef149.

Official reveal-fence1-official-arrival010-20261023 COMPLETE: 12/12 genuinely
encrypted transfers admitted/finalized, independently verified all-five wallets,
receiver452→464, zero rejection/pending/generator limitation. Offered/submitted/
admitted .100TPS; 10 finalized in120s=.083333TPS; all12 eventually finalized.
Context→all-five finality/wallet p50=17.810340s, p95/p99/max=20.114219s.
Actual transaction drain11.362682s after offered window; report completion
24.806463s includes full-wallet reconciliation and is not queue-drain time.
Native certified/finalized mean intervals1.396924–1.405401s, ~.712–.716blocks/s;
all p50/p95/p99, inclusion, CPU/RSS/network/IO/raw data remain in report/audit.
All-five resource windows: zero cgroupOOM/swap; RSS peaks~76.7–88.1MB.
Earlier sustained .1/600 bounded-resource and timing qualification remains valid.
This is a finite qualified operating load, NOT a verified network maximum.
Sustained .2TPS failed30s, .5TPS failed timing/native cadence; failures preserved.

Soak reveal-fence1-24h-soak-20261023 actually running, driverPID1034987 onVal2.
Offered window approximately2026-10-23 21:23:37.238UTC through2026-10-24
21:23:37.238UTC (4:23:37p.m. Central). Estimated start maps first offered
scheduled_mono379218.870164003 to Val2 adjacent realtime/monotonic anchor;
raw-proof birth21:23:37.237904258UTC corroborates it. Final terminal start_utc
and internal86400s duration are authoritative; drain/review follow the window.
Rate.1TPS/max8640,32wallet/inflight bounds, RPC5s/finality30s unchanged.
Verified launch record: reveal-fence1-24h-soak-start-verified-20261023.json.
At21:27 allfive services active/no auto restarts, identical common finalized
H81585/block6a5922520e1bc44ec8a9cfe1b7fe33823ff88a0a0f73551f81ea96b4d01daf29,
20/20 observers healthy/fresh, hostOOM delta0/swap0; RSS~75–87MB and shared
reservations~168–175MB. At21:28:25UTC the bounded early raw stream records29
submissions and27 all-five finalized transfers, with the remaining work pending;
this is partial progress, not terminal success. Evidence:
reveal-fence1-soak-early-stream-20261023.json. Full24h stability is NOT yet proven.
Allfive passiveOS/cgroup, coherent metadata, nativeQC/finality and hostdevice
observers run90000s under /var/lib/synergy/posy-async-canary-20261022-rc1/
soak-reveal-fence1-20261023. Val2 measurements are under the sibling measurements/
directory. Keep large raw streams there or onexternalSSD, not internal drive.
Read-only health helper target/posy-async-reveal-fence1-soak-health-20261023.py
creates uniquely named health evidence in E=target/posy-async-conformance-audit-20261021.
Heartbeat automation posy-isolated-canary-soak checks every5min and stays quiet
unless meaningful failure/completion/operator action. Mac caffeinatePID40403
keeps RPCtunnels awake90000s. Preserve existing single SSHmasters perhost.
NEXT: monitor this single run; do not redispatch/restart/change source/config
or silently recover failures. At terminal collect/review actual fullperiod,
allfive wallet correctness/matching finality, original timing/native means,
memory/reservations/IO/retirement/OOM/swap. Only after fullsoakPASS repeat the
already requested controlled TPS comparison with simultaneous blocktimes.

Previous critical update (2026-10-23 20:48UTC): approved isolated Val2-Val6,
one validator/host; production untouched. Internalcleanup DONE: removedonly2.2GB
regenerable npm cache;13GiB internalfree, all source/state/evidence preserved.
Overallgoal unchanged: finish safe async nativecanary, actualTPS+blocktime baseline,
thenSTART24hsoak; no componentcheckpoint is taskcompletion.
CURRENT running signedseq11/previous10 reveal-fence1 optimized node SHA256
b05c5e60c090e0d9d377dc2caa99e47068dd6ca0330c57cd6fb139b78e5ef149,
SHA3f7714d9c070f25f6b1fbdc65763cb497dda845d116aec40ad6cdf32005a9a4f2,
11757288B. No compiler changes sincebuild. HEADb338dcc223c1ce33599e12c424858cd000772637,
full frozen before/after inventory identical SHA256
0967d1fab2144ce2426f54b62b95b6acebf2d02372b3adec2c1d94f00e0cf530;
clean=false records substantial pre-existing migration. Laterledger+ignoredhelper
edits are noncompiler deltas, never claim whole currentcheckout stillmatchesfreeze.
Small measured repair: filter indexed certifiedproposal proofs above locally
verified finality BEFORE decode; exact native height/block/protectedroot reveal
fence and eligibleproof authentication remain; unbounded Sync/retention lookup
unchanged. No policy/quorum/signatures/rounds/formats/reservation changes.
Exact-byte actualhost native/order/reveal/recovery +live5 pending/takeover/restart
PASS65.532s, shared1GiB peak236699648B, events0/swap0. Affected native2checks also
256MiB PASS peak24604672B. All5 signed/state-preserving rollout and original
memory30 PASS30/30, max24.0936s, native means1.3908-1.3935s, allOOM/events0/swap0.
Required distributed quorum loss/rejoin +each5individual restarts PASS. Exact
64-height retirement:126-127 fullyretired samples/host, all4 namespaces25nullslots,
400logicalB total,0incoherence; sharedreservations fall afterretirement. Reusevalid
unchanged-boundary evidence; do not rerun wholehost/componentcampaign.
TPSfailures preserved: initial.2test failed5s getBlock observerRPCtimeout after1tx,
all1laterall5wallet224; notcapacityfailure. Measurement-only wrapper observes
RPCendpoint/timing/error, retains5s/no retries/nativepipeline unchanged.
Observed .2/120 COMPLETE24/24,.2offered/admitted,.175finalizedinwindow,
max22.0164s, native means1.307-1.314s. Observed .5 FAILED30s andnative mean~1.70s,
25submitted17observedadmitted11verified,14pending; all25later exactall5effects.
STOPPED upwardladder. Then .2/600 FAILED596.499s:119admitted114verified,
max31.455116s,5pending; all119eventualwallets/nonce PASSreceiver392.
.2native means1.429-1.435s, resource-only comparisons all5PASS, noOOM/swap;
failedworkload is NOT sustainablecapacity/clean600s. Every failure remainsraw.
LATEST .1/600 COMPLETE60submitted/admitted/finalized, all5wallet receiver452,
0reject/missedslots/generatorlimit,peak3pending,drained0. Submitted/admitted.1TPS,
59finalizedinside600s=.098333TPS; finaltransactionverified4.502945s afterwindow.
Terminalreportcompletion18.126055s afterwindow includes fullwalletreconciliation,
NOT transactionqueuedrain. Independentreview originalmisstatement retainedwith
reveal-fence1-final-independent-review-drain-correction-20261023.json addendum.
Context->all5finality/wallet p5015.842371,p9520.419570,p99max22.235232s.
Native all5 certified/finalized means1.18986-1.18998s, tails4.62-6.14s preserved.
All5 preregistered fixed RSS/anon/I/O comparisons PASS, host+cgroupOOM/swap0,
shared/cgroup1GiB caps/sameprocess PASS. Coherent lockedmetadata fixedwindows
adequate;1/2/0/1/0 boundedlocktimeouts recorded as observationlimitations,
no returnedincoherent snapshot; no newzeromissing gate inferred. Priorcohort
retirement0unavailable remainsseparateproven evidence. Honestrootfiniteworkload
qualification only, no arbitraryWorld/nonrootDAG/universalmaximum/24hstability claim.
FINAL READONLY FLEET PASS20:46UTC: all5 exactsamebytes/config/nativeverifiedseq11,
noautomaticrestarts, matchingfinalityH79350 block01fdc5524ca8e1ffd2ff9c217392d1a5c07c5ff0fc0f4ad76c8a5fb5b1bc9bac,
stateb8d1d71cd5f72d4129db5b79c200d5a2891332edfb99e890eebebc83a284d177,
all33walletmatches. No active transactiongenerator/controller remains.
Einstein independentfinalreview CLEAR: exactpacketall20pins,6buildpins,28resource
inputs+binary verified; no demonstratedtechnicalblocker fordeclared.1canary.
BLOCKED ON SPECIFIC OPERATOR DECISION, notanotherimplementationcampaign:
exact dirty frozeninventory acceptance for isolatedcandidate required before
existingclean-source guard exception/officialrelease label/soak. Asyncquestion
sent20:45UTC with concretepacket; NO ANSWER YET. Do not inferapproval fromelapsed
 time orolder generaldeploymentapproval. tools/release/provenance.py:157 requires
clean unchangedreviewedsource; priorcanonicalcheckpoint permits explicitoperator
acceptance exactinventory for isolatedcanary. No falsecleanflag/dirtysweepcommit/
reset/sourcecopy orproductionchanges. Genericclean-source promotion remainsfalse.
E=target/posy-async-conformance-audit-20261021:
reveal-fence1-final-exact-input-acceptance-packet-20261023.json SHA256
 df12de18387d91194e9425e94cf9bd0e05f7f921683e5668f665882b1e4edf5c;
reveal-fence1-final-independent-review-20261023.json;
reveal-fence1-sustained-arrival010-20261023{.json,-audit.json,-sustained-resource-review.json};
reveal-fence1-final-qualification-fleet-20261023.jsonl;
reveal-fence1-release-candidate-pending-acceptance-20261023.json is FALSE/unapproved
preview; dormant soakguard correctly rejects it beforeanydispatch.
EXACT RESUME afteractualapproval: recordtrustedhumanacceptance againstpacket hash;
run official120s offered.1 nativeencrypted stage named
reveal-fence1-official-arrival010-20261023 using existing bounded dispatcher and
reveal-fence1-baseline-observed-command-review-20261023.json; collect+audit actual
30s/cadence/all5wallets/resources. Existing1hOS/metadata monitors end~20:54UTC;
ifoperatorreturnslater renew read-only/versionedobserveroutputs before official
stage (notrepeatqualification), reusing existingSSHmasters. Preservealloldstreams.
Onceofficialpasses, freeze acceptedmanifest with exactsource/config/node/approval
andbaselinepins; adapt preview fields honestly. Thenexecute prepared guarded
posy-async-launch-reveal-fence1-soak-observers-20261023.py followedby
posy-async-start-qualified-reveal-fence1-soak-20261023.py, both--accepted-manifest
and--execute, .1TPS86400s. All5 90000s resource/metadata/nativeblock/hostOOM-device
monitors prepared, 1GiBRPCtrace budget for24h (measurement-only); original16GiB
rawproofbudget+1GiBdiskreserve andRPC5s/finality30s unchanged. RecordactualUTCstart,
launchreceipts/monitorhealth, keepMacforwardsawake90kseconds, quietmeaningful-only
heartbeatmonitor after actualstart. No soakstarted/successclaimed. Existing
caffeinatePID29048 only1800s to~21:10; extendforactualsoak afterapproval.
Keep originalSSHmastersVal2/3/4/6 /tmp/posy-memory-valN-20261022-control,
Val5 /tmp/posy-memory-val5-20261021-audit-control; nosecondconnection/custodyexports.

Previous critical update (2026-10-23 16:40UTC): isolated one-validator/host
Val2-Val6, production untouched. Overall objective remains qualified async native
ETDAG/PoSy, actual-host memory/timing/recovery, measured TPS+block times, then START
24h soak. No release-qualified manifest or soak start; original30s/1.5s gates remain.
Seq8 input-retry1 exploratory .1TPS120 COMPLETE12submitted/admitted/finalized,
11 in offered window=.091667 finalizedTPS, all5wallets, p50=17.235s,
p95/p99/max=22.342s, native means1.338-1.341s, pending0/drained. Seq8 .2TPS
FAILED12submitted/admitted/7verified before30s failure, native means1.629-1.632s,
worst8.225s; all12 later independently wallet/nonce reconciled all5 receiver170.
No maximum-capacity claim. Preserved prefixes input-retry1-exploratory-arrival010-
20261023 and arrival020; original memory30 earlier also FAILED. OOM/swap0 in
observed windows does not close memory plateau/IO/recovery gates.
Seq9 phase-trace1 optimized node SHA256 ed1a546b6613858867f851835351a61a9e269853a7575ccdf28f0757ae9b451b,
SHA3 6d79d81c8e3ac668c9384d464a5df4b0c90243490744f9bb2b0d887c11a4094d;
full before/after inventories equal, focused guard+bounded tracing+live5 encrypted
restart PASS69.042s, shared1GiB peak239988736B/allmemoryevents0/swap0.
Native signed9/previous8 all5, state-preserving rollout and33wallet170 PASS.
Diagnostic activation helper initially caught startup executable race; original
failure and recovery-helper polling failure preserved. Recovery3 validated all5
tracing with advancing finality and zero automatic restarts at activation.
BEFORE transaction workload dispatch, Val2-5 failed closed atH66988/R1: same
TC closure24241f48f91d31a6128aba9b2b60b26a966ac0fefe4593665858e08ad8e14c9c,
first4-of5 subset has1candidate report=>no carry, Val6 subset has2=>carryA.
Overlapping signed reports identical. All5 finalized66985/statec0dea739...;
QCs through66987, noQC66988. Val2-5 trace finish dropped0/failures0; Val6 still
active below quorum (its saved trace is an explicitly incomplete fixed prefix).
Auto-restarts then refused existing create-only diagnostic output. No journals
or records deleted. E phase-trace1-valN-{incident.json,events-20261023.jsonl,
signing-boundary-20261023.json}, incident-critical-path-analysis retained.
Signing snapshot: Val2/3/4 noR1 reservations; Val5 R1proposal/ECHO exactA;
Val6 R1ECHO exactA + R1timeout, whose prohibition on R1blockvote MUST survive.
NoR1 TC, no conflicting R1 blockvote observed. Native A=a7a82eb691d33cc3121a5b7b5f946f9b29f74205acc338d9345f1dbef1227483.
USER EXPLICITLY APPROVED narrow repair2026-10-23: fully verified same-parent,
noncontradictory live None->Some duplicate is Invalid/nonfatal rejection ONLY.
FirstTC/carry/round/signatures/locks/finality remain unchanged; conflictingSome,
parent or same-signer contradiction stays fatal. No T1 union/upgrade approved.
Root implemented minimal state_machine branch; Einstein independent review CLEAR.
Genuine signed test covers both orders, all25 pairs of4-of5 subsets, unchanged
projection/original authority, existing historicalQC and signer-contradiction cases.
Next exact action: frozen optimized live-variant1 build + actual-host focused tests;
if pass, native signed isolated seq10 recovery preserving all existing records,
disable create-only diagnostics by new systemd env dropin before service restart,
verify common advancing3QC finality/all33wallet170 and preserved timeout prohibition.
Then original memory30 uninstrumented, measured affected timing/resource/recovery
boundaries and controlled ascending TPS; never infer pass from dispatch. Keep
failed phase-trace1 diagnostic workload UNDISPATCHED. No production modifications.

Previous critical update: vertex-retry1 original distributed memory30 FAILED,
5submitted/4admitted/4verified, fourth context-to-all5wallet30.195882s >30s.
Full native means1.613-1.651s >1.5s; first3latencies26.879/28.781/29.157s.
Full terminal raw/resource/native/retirement collected and audited with prefix
vertex-retry1-distributed-memory30-20261023. No new TPS or soak claim.
Input retry source has another partial-enqueue pacing defect: retry timestamp
was set only when every peer accepted. Earlier captured same-input repeats to
Val5 arrive as often as170-176ms apart; arrival compression is a limitation,
not proof of enqueue timing. Concrete code path allows poll-rate retries after
partially successful publication. Small input-retry1 correction timestamps every
attempt before the peer loop, retaining existing250ms, exact-ECHO suppression,
unknownpeer retries and all original pending/proof state. No queue/thread changes.
Only etdag_processing.rs changed after vertex-retry1. Next optimized input-retry1
build + affected paced/native/live checks, exact signed seq8 isolated update,
original memory30 and full native gate; do not waive30s or1.5s requirements.
Expected eventual5transfer wallet map receiver140 (pending independent all5 audit):
vertex-retry1-post-failed-memory5-expected-wallets-20261023.json. Vertex node
cea4b5... still runs all5 until qualified update. Prior .1TPS/12tx exploratory
results remain exact seq6 only. No active workload or capture. All failed evidence
preserved. Scope frozen to demonstrated retry defects; no broad refactor.

Current resume (2026-10-23 07:36UTC): vertex-retry1 sequence7 is running one
validator/host all5 isolated Val2-Val6. Production untouched. Node SHA256
cea4b5338697d35077c559e244b1e8999ee19962a8b372e3f45b1c6574977e4f,
SHA3 00ed1c694fce8ced4cb9584fb0122012e652cb8d3dfe6cbc983059e78fda857b,
length11742952. Release SHA256 ee0396a4f45d1a3797e7dd3106fe140669e673a0ca728532b3be7538a7d3039e.
Build/sealed target/posy-async-linux-vertex-retry1-attempt2-{build,sealed}-20261022:
complete before/after input inventories identical; runtime byte-identical to first
vertex build. First new session test used invalid dummy node address and failed
before exercising repair; only test input corrected, failure preserved. Final
focused3batches/6tests PASS: paced session/backpressure4, native order/reveal/
recovery1, live5 encrypted delayed-reveal+wallet+restart1 (76.559s). Shared1GiB
peak236617728B, swap0/allmemoryevents0. New4checks also PASS under256MiB,
peak8089600B,0events/swap. Native sign/all5verify, serial state-preserving rolling
rejoin, advancing matching finality/state/all33wallets receiver135 PASS.
Repair touches only etdag_processing_work.rs + its etdag.rs caller: authenticated
native availability vote for the exact durable vertex records a bounded current-
session transport receipt; skips only that exact original's borrowed frame to
that voter. Frozen-members bound, existing item reservation, no durable format,
new message/certificate/vote, policy/quorum/finality/deadline changes. Restart,
reconnect/unknownpeer and every vote/certificate/share retain existing retries.
All5 new OS/locked metadata observers under distributed-vertex-retry1-qualification-
20261023. Old reveal observers stopped only via exact recorded PID+argv after
binary superseded; evidence retained. No active packet capture. Original unchanged
memory30 workload RUNNING Val2 driver736667, exact prefix
vertex-retry1-distributed-memory30-20261023 (30encrypted/4inflight/300s,30s/tx).
Do not infer pass or duplicate. Controller vertex-retry1-attempt2-critical-path
completed rollout/readonly/monitor steps, then STOPPED on exclusive generic log
collision before workload dispatch. Direct unique-log dispatch above succeeded;
DO NOT rerun controller. New collectors/auditor target/posy-async-{collect,audit}-
vertex-retry1-stage-20261023.py accept terminal name. Component256 was executed
independently; the already-running controller did not load later script edits.
Exact next: collect terminal memory30 and full native cadence/resource/retirement;
if original gates pass, derive33wallet map from report final_by_validator (next
nonce, not signed tx nonce), required distributed quorum+individual restart via
vertex-retry1-runtime-checks, controlled offered .1 then ascending until first
real timing/resource/backlog failure, preserving block distributions and exact
wallet effects. Freeze accepted manifest, guarded vertex soak tools, START24h.
No soak started. Tools prepared only, not acceptance or start evidence.
Previous reveal-replay1 seq6 memory30 FAILED after4admitted/1verified31.8395s,
unchanged30s gate, mean2.227-2.230s FAIL1.5s,0OOMswap. All4 later exact wallet/
nonce effects verified all5 receiver123; adapter initial expected nonce mistake
and optional legacy tx lookup-null preserved, neither native-correctness failure
nor a pass. Seq6 exploratory .1TPS/120s COMPLETE12/12,0reject,peak3/drained0,
all5wallets receiver135; submitted/admitted.1, finalized.083333TPS within offered
window; p5016.738s,p95/p99/max23.329s. Native mean1.326-1.347s, max6.941s.
Diagnostic only, not current vertex binary's TPS or sustainable maximum. Capture
Val2/3 capped128MiB/~9s confirms no Sync chunks but 340KB original vertex repeats
19-24/peer despite availability votes; this is measured cause targeted above.
Earlier reveal-replay1 recovery repair retained (live passed91.190s, shared1GiB
peak245288960B/0events): read-only charged retained public-share replay restores
lagger after others finalize/quiesce. Native Sync hint bounded by existing5s
fallback retained. Earlier genuine failures preserved. Independent general DAG
review limits below remain: canary evidence is honest root cohort; no full
nonroot recovery/adversarial graph qualification claim. No speculative refactor.

Current resume (2026-10-23 06:27UTC): echo-retry1 sequence5 exact optimized
candidate runs all5 isolated hosts. Native focused hint2/finality-fence1/
order-reveal-recovery1/live5-pending-takeover-restart1 tests PASS on Val4
1GiB/swap0, peak238301184B; affected hints also PASS under256MiB. Initial
wrong test selector matched0 and was correctly rejected; failed evidence kept.
Signed node SHA256104d52022c40d38d7d5ec624272574320fb2a05d845430dfcd910578627aad8b,
SHA3 84abd54c589404f9abc8d6e4a87e1f836f6cfbdf698394ec2db796407fccd6b9.
Distributed original30tx/4inflight/300s COMPLETE30/30, all5 wallet effects,
receiver119, max end-to-end27.868979s, p5023.581314/p9526.999579s,0OOM/swap/
memory-limit events during workload. Raw collected/audited evidence prefix
echo-retry1-distributed-memory30-20261023; expected33wallet map
 echo-retry1-post-memory30-expected-wallets-20261023.json. Full-workload native
QC/finality mean1.715-1.721s FAILS1.5s cadence, despite .978s preflight.
No soak started. Duplicate Sync candidate fetch traffic measured in earlier
full frames; checking current exact binary before minimal duplicate-fetch
suppression using locally QC-verified async prefix, with existing5s recovery
fallback. No new vote/QC/wire/policy or timer changes authorized/needed.
Exact next: confirm current duplicate Sync traffic, narrow correction only if
confirmed, focused native + missing-candidate/restart fallback checks, exact
signed isolated artifact update, affected cadence/resource + TPS measurements,
then freeze/rejoin and24h soak START. Passive monitors live; no active load.

Current resume (2026-10-23 06:05UTC): native order-finality2 quorum+individual
restart/rejoin qualification PASSED. Finality halts below4/5, resumes4/5;
all5 individual restarts restore advancing identical blocks/state/33wallets,
receiver89. Raw order-finality2-distributed-quorum-restart-wallets-20261022.jsonl
ends FRESH_RUNTIME_QUALIFICATION_PASS. Four-hour-later read-only exact artifact/
config/common-finality/33wallet check also PASS (idle, not a declared soak).
Memory30 timing failure isolated: H16625 round0 has only3 ECHOs, noquorum4;
timeout+22.55s, takeoverproposal+22.85s, quorumECHOs~27s, QC+27.62..28.05s.
READY→QC<1s; delay is before ECHO (proposal/material/candidate), not wallet
observer or OOM. Full passive packet captures now classify977/950/1071 actual
complete nativeframes onVal2/3/6, cap128MiB reached~14s; caps/incomplete tail
preserved. Old arrival4 diagnostic submitted0: invalid closed-loop4tx command
rejected because established contract is exactly30tx/300s; no validator changed.
Measured native input retransmission continues2–4 copies AFTER peer ECHO,
1.3–2.7MB/peer/block. Minimal echo-retry1 correction implemented: after native
PoSy verifies/persists exact ECHO, a bounded ephemeral current-session hint
suppresses only that peer's same height/round/block processing-input retries.
No new wire/proofs/votes, signing, quorum, timers, retirement or pending changes;
unknown/lagging/different candidate/takeover/reconnected peers keep retries.
Two focused tests cover exact identity, takeover, stale progress, disconnect,
reconnection and bounded fallback. Optimized Linux echo-retry1 build COMPLETE,
before/after full source inventories identical. Artifacts/build evidence under
target/posy-async-linux-echo-retry1-{sealed,build}-20261022. Focused actual-host
native checks DISPATCHED Val4 /var/tmp/posy-async-echo-retry1-focused-20261022,
one1GiB/zeroswap job, selector2tests + prior3native/live encrypted/recovery checks.
Do not infer pass from dispatch. Exact next: collect terminal focus result,
native sign sequence5 and serial isolated upgrade using prepared
target/posy-async-echo-retry1-isolated-rollout-20261023.py, exact all5 wallet/
resource/timing original30tx gate and affected restart tests, controlled TPS,
then frozen24h soak START. No soak running. Subagents credit-limited; root
continues independently. No production state touched, no evidence deleted.

Current resume (2026-10-23 01:22UTC): exact order-finality2 sequence4 runs
one validator per host on Val2–Val6. Parallel-wallet1 observer focused57+9
tests pass without moving the after-wallet-proof timestamp or changing30s.
Exploratory .05TPS/120s completed6/6, .041667 finalized TPS during window,
latency p50=17.422s/p95=p99=22.393s; .1TPS/120s completed12/12,
.091667 finalized TPS during window, p50=18.258s/p95=p99=22.159s.
Native QC/finality interval means .05=1.313–1.323s, .1=1.466–1.474s;
occasional individual intervals exceed1.5s. These finite short stages are
exploratory measurements, not a sustainable maximum or release closure.
.2TPS stage FAILED30s after13 admitted/8 verified finalizations; one verified
latency31.342s,5 outstanding at abort. Escalation stopped. All13 subsequently
finalized exactly once with native all5 matching blocks/state/33wallets PASS
at advancing commonH16565, receiver85. No OOM/swap; measured reservations
peak~707–725MB, RSSpeak~90–97MB. Raw .2 failure SHA3
9a8e216e3480fa823a13dc899bb4b5b3f0b369acbf0d15cd9c3df4b43665c714.
Prospective original30tx/4inflight/300s observercheck also FAILED30s after
4 admitted/0 verified finalized, despite .997930s preflight. Native RPC gaps
up to10.9s during load. All4 later show exact final wallet effects, receiver89;
current expected map order-finality2-post-memory30-observercheck-expected-wallets-20261022.json.
Raw failure SHA3 74993626c9eb60bf7559cb7d056fb2d266c3aaef9243ea17f67bd5702e5bdeb7.
Five-host resource/locked journal/phase diagnostics preserved for this failure.
Existing isolated quorum+individual restart/rejoin qualification is RUNNING,
log order-finality2-distributed-quorum-restart-wallets-20261022.jsonl.
Do not duplicate or restart that operation. Exact next: collect its terminal
result, diagnose measured load delivery/certification delay, smallest justified
repair only if necessary, affected resource/timing gate, qualified baseline
and24h soak START. Mandatory timing/resource gate remains OPEN; no soak started.

Current resume (2026-10-23 01:04UTC): order-finality2 sequence4 signed exact
node is RUNNING all5 one validator/host, focused fence/native/recovery/live5
tests PASS. Postupgrade and postfailed-workload all5 advancing identical
finality/wallet effects PASS. The affected distributed30/300 timing/resource
run FAILED: preflight1.237541s; wallet02 all5 block proof at29.363671s,
then sequential account reconciliation1.006815s gave30.370486s. Old failure
and raw proof SHA3 f76b88bfc553a1e6622ee183f155d43159f190f46ef036f577a8fa9f5b24b5c8
preserved. All6 submitted transactions subsequently finalized with exact wallet
effects (receiver54); postfailed expected map and native checks are in evidence.
Bounded5-way account RPC reads now replace serial reads, retaining all5 equality,
wallet validation, timestamp placement and30s gate. Focused57+9 tests PASS.
New immutable measurement tools parallel-wallet1, no validator artifact change.
Next memory30 attempt FAILED BEFORE submission: preflight1.739497s (0tx), so
the independent cadence blocker remains. Do not rerun preflight until lucky or
claim timing closure. A bounded .05TPS/120s diagnostic is being dispatched
with explicit outside-cadence label to obtain actual throughput while diagnosing
the measured cadence defect; it cannot satisfy the failed release cadence gate.
Exact resume: collect its terminal report/proof and native block interval/OS
observations, preserve all failed preflight files, diagnose idle/load cadence
against exact artifacts, smallest measured repair, affected timing gate,
distributed recovery, qualified TPS ladder and start24h soak. Soak NOT started.

Checkpoint (2026-10-23 00:47UTC): distributed qc-tail1 30/30 encrypted funded
transfers PASS, all-five exact wallet effects, 161.588s within300s /4inflight,
max context-to-finality24.228641s, p50=18.269964/p95=24.039543/p99=24.228641s.
Preflight average1.123678s; native QC/finality persistence intervals duringwork
mean1.475–1.4764s, p95~2.3–2.5s / max4.19s (not every interval below1.5s).
All5 memory events/swap0, observed RSSpeak~71–88MiB. Raw proof19,404,298B,
SHA3 69b936a2cbf5fc25ee7f4d3641720df2e12c09fb8f357ad2b55762310aaed4bf.
Postworkload locked metadata all5 fully retired: all25slots/namespace null,
0 live records /400 logical bytes total, preserved283–285 snapshots over~570s.
This is finite declared-workload qualification, not TPS maximum/24h success.

Small approved-lifecycle repair implemented: exact ingress.finalized_record
height/block/protected-root fence before storing fresh reveal authorization,
before recovered share/completion processing, and before incoming share accept.
Uses existing ordinary three-QC evidence; no new certificate/vote/signing round,
wire/durable format, quorum or timer. Existing shared WorldResourceBudget atomic
limit/used counters now exposed read-only by native RPC provider, with unknown
providers remaining null, for required baseline reservation measurements.
First telemetry compile failed due opaque provider field access; failed build
preserved, corrected through optional provider observation method. Revealfence-only
order-finality1 build passed but was never deployed. Integrated optimized build
order-finality2-attempt2 COMPLETE PASS with identical before/after inventories;
node SHA3 5618fca08d73e7b96316ee14035090b854fdf4543f07855f358827c5b9babfc8,
test SHA3 059a0ee098730b3f9121ece3f8acb35dee134e3c9cf84027c82bcc3c16d57d44.
Focused exact-artifact native finality fence / native order-reveal-recovery /
live five-validator encrypted pending+restart checks are DISPATCHING on Val4
in1GiB/swap0; do not infer a pass until result.json has all3 terminal tests.
Remote root /var/tmp/posy-async-order-finality2-focused-20261022.
Exact next: collect focused result, signed sequence4 isolated rolling activation
preserving state, native all5 finality+updated wallet map, affected timing/resource
gate and distributed recovery, then controlled offered TPS with block intervals.

Read-only independent DAG review confirms root-only local authoring does not
invalidate the current honest root-cohort evidence. General graph conformance
is incomplete: correctly signed nonroot peer vertices can be accepted but their
pending recovery needs native parent capabilities before store authentication;
startup currently has an empty member map. This is fail-closed recovery/liveness,
not demonstrated invalid execution, and must not be represented as general DAG
recovery support. No speculative graph refactor is underway. Review remains
bounded to the explicit canary workload; do not claim full adversarial/nonroot
qualification from these root-only results. Production untouched, no soak started.

Live checkpoint (2026-10-23 00:34UTC): qc-tail1 is running one validator per
host on Val2–Val6. Node SHA256
e5de94c756d1932c741d57222dac2de09fb41622afafb981120732ae451f7639;
SHA3 6def6cbdb53061b8d876abb61893b83dda57b903d55125e1eb1bd8efb9723d0a.
Focused native 7 checks / 10 tests PASS on Val4, 256MiB / swap0,
peak38219776B / all memory events0. Existing verified peer finality H binds
QC(H+2) and its contiguous parents; retry suppression now covers precisely
that checked tail for READY/QC only. Proof retention, unknown/lagging/reconnected
peer retries, blocked cursor, TC behavior, signed bytes and consensus timers
remain unchanged. Exact before/after build inventory matches. Native sequence3
signing and verification all5, serial rolling activation and postupgrade
advancing common finality H14597 with all33 wallet effects PASS. Old artifacts,
state and failures preserved. Initial coordinator failed before signing with
NameError; bounded resume completed only the remaining steps, no reset.

Exact active workload: qc-tail1-distributed-memory30-20261022, driver583131 on
Val2, unchanged 30 transfers / 4 in-flight / 300s resource workload and 30s
transaction budget / 0.5–1.5s preflight cadence. New exact-artifact independent
OS and locked metadata observers running all5. Do not duplicate the workload
or claim a pass from dispatch. Read its terminal report/proof/exit first.
Evidence root: node-platform/target/posy-async-conformance-audit-20261021.
No official TPS or 24h soak started. Production untouched.

Narrow architecture review also found a concrete discrepancy against the active
goal's required order-finality-before-reveal lifecycle: advance_processing_reveal
currently authorizes shares using the closing candidate's native ECHO VC without
requiring that candidate's existing three-QC finality. The intended narrow repair
is to reuse ingress.finalized_record(height) and match the exact closing block
before any fresh or recovered reveal/share/completion path, without adding any
certificate/vote/round. Not implemented or qualified yet. Locally authored
processing vertices currently have empty parent lists/round0; native DAG edge
validation and deterministic graph ordering exist, but live nontrivial graph
construction/recovery is not demonstrated. Independent root vertices are valid;
do not call the missing live-edge demonstration a FIFO proof or claim full DAG
conformance. Keep this review narrow and preserve the running measurement.

Next: collect active distributed timing/resource result and independent
observations, make only measured necessary corrections, close the exact reveal
authorization discrepancy, then affected-boundary checks, required recovery,
controlled TPS stages with native block intervals and bounded backlog, official
provenance gate and start the 24h soak. Prior18 genuine encrypted transfers and
retirement/no-OOM evidence remain valid for their exact earlier bytes; neither
proves the newly required order-finality-before-reveal guard. Subagents exhausted
workspace credits after saving captures; root continues independently.

Live correction checkpoint (2026-10-22 19:09UTC): peer-finality1 is RUNNING
one validator/host on all Val2–Val6, source/binary frozen unchanged during rollout.
Node SHA256 e9a67fb4424b8cfe5bc63f3c77b4b0bcccae40e33d309252df6967a5a70f91ba;
SHA3 cf9164d8dae5591dca22e457f4619c1a7853cb702b0ffc39c842b7eb3f03658d.
Native candidate sequence2 signed/verifiedall5, release SHA256
663bcde7590855e8e10511bcf31baf4916f9baab7edddb1a6d8932e3a1480c4a.
Versioned executable/drop-in only; original binaries/releases/unit and all state
preserved, signed config/quorum/timers/resources unchanged. Ten focused native
tests in7checks PASS Val4 under256MiB/swap0, peak36200448B/events0: per-peer
filter/cursor, session reset, native three-QC dropped-vote restart, historicalREADY
recovery and partition/rejoin. Initial build failed only missing test type import;
fixed to fully qualified synergy_posy::FinalizedBlockRecord, failedbuild preserved.
Attempt2 fullbefore/aftersourceinventory matched and artifactsealed.

Initial rolling coordinator failed its premature Type=simple executable assertion
onVal2 (originalstderr discarded by owner helper, failure preserved). Read-only
native exactbyte/signature checks provedVal2 advancing without automatic restart;
resumed coordinator captured the actual systemd-executor-before-exec condition
onVal3/5/6, waitedfornativeexe, preservedmonotonicstatechecks and rolled3–6once.
This was coordinator observation, no runtime/state repair. Other hosts each
rejoined and advanced durablefinality; all5postupgrade finality/wallet checker
and onehour bounded independentOS/lockedmetadata observers started. No new load
while rollout was occurring. Exact next: finishnativeall5wallet/finalitycheck,
run unchanged30transfer/4inflight/300s distributedmemory/timing gate and required
recovery, then controlledTPSstages. Originalpaced1measurements preserved:
.05TPS6/6 final/max22.8269s, .1TPS12/12final/max29.2525s; bothcadencefailed.
.1offeredwindowfinalized11/120=.0916667TPS, finalworkdrain11.9144s;
all-walletreconciliationreportoverhead47.809s is notqueue drain.
Independentpinnedresource review confirms fullretirementbothcohorts(all12slots
reused,nulltombstones192B/store onall5), noOOM/swap/restarts, no demonstrated
journalcoherence defect. Finite18txevidence is not30/300qualificationclosure.
Generic clean-source promotion notclaimed. Continueauthorizedisolatedcandidate
qualification; beforeofficialrelease label, satisfyexistingprovenanceverifier or
obtainexplicitoperator acceptanceofreviewedexactinputinventory forisolatedcanary.
No24hoursoakstarted. No production state changed.

Current measured checkpoint (2026-10-22 18:55 UTC): original paced1 remains
running one validator per host. Distributed closed-loop qualification aborted
before transactions: unchanged 1.5s cadence gate failed at 2.035351601s average.
First diagnostic offered-load stage COMPLETED: 0.05TPS/120s, 6 submitted/admitted/
finalized, 5 finalized inside offered window (0.0416667TPS), all-five exact wallet
effects, 0 rejects, peak2 pending, final work drained2.5402s after window. Context
to all-five finality p50=17.5465s,p95/p99/max=22.8269s. Final wallet reconciliation
adds time: report completion36.4597s after window is NOT queue-drain time.
Preflight cadence1.876188s failed; diagnostic explicitly preserves this failure
and is not release/resource qualification. Source/raw/proof/OS windows + immutable
QC/finality mtime intervals and metadata are preserved under
`node-platform/target/posy-async-conformance-audit-20261021/`
`exploratory-distributed-005tps-20261022*`; proof SHA3
ac28fffec8b945f6fb3cecfae5ac65c4880b281a0344e19882f3ec995af09926.
Second diagnostic stage0.1TPS/120s is ACTIVE on unchanged running bytes; do not
restart it or change candidate midmeasurement. Both retain30s finality limit.

Measured excessive peer traffic is approximately66-114Mbps outgoing/node even
at low load. Existing retry_delivery sends 70KB historical READY proofs every
250ms to every peer, including current sessions already supplying native verified
finality at those heights. Narrow source correction being implemented: suppress
only READY/QC retransmission to a current-session peer finalized at/above message
height; preserve originals, Sync, unknown/behind/reconnected retries, exact blocked
cursor, timeout policy, cryptography, state formats, quorum and consensus timers.
Einstein read-only safety review supports equality; verified PoSy finality does
not imply durable peer execution. Real bounded-publisher/reconnect regression in
progress, root owns production loop. Not built/deployed/qualified yet.
Next: finish active0.1TPS measurement and preserve failure/success honestly; focused
retry regression and one reproducible optimized build, then candidate-only isolated
rollout without deleting state and repeat failed distributed timing/resource gate.
No official TPS or24h soak started. No production mutation. Existing originals and
all failed evidence retained. Do not infer closure from no OOM kills or exit0.

Current critical path (2026-10-22, distributed paced1 candidate RUNNING): user
explicitly approved the intended one-validator-per-host qualification after the
five-process colocated timing failures. Exact optimized node SHA3-256
`56a36b6a92380fcda1ddc4a9740a844a387ae22ecaed7cfb0d402b30d55cf61d`,
SHA256 `a3c04daac01e199a3ee52730ea587aa0ed0d505b5da95f2047401d94a11e718e`.
All Val2–Val6 staged with native signed candidate verification and started in
fresh `posy-async-canary-20261022-rc1` paths at approximately2026-10-22 18:29:37UTC;
one process/host, physical1GiB, swap0, original signed v2 ProcessingGroupsV1
authority, retention64, unchanged timing and consensus rules. Signature binds
candidate bytes; **not** provenance promotion or resource qualification closure.
Native read-only probes prove all-five matching finalized block/state/finality
commitments advanceH22→25; all services healthy, zero automatic restarts.
Evidence: `node-platform/target/posy-async-conformance-audit-20261021/`
`paced1-distributed-{candidate-native-signing,stage-input-pins}-20261022.json`,
`paced1-distributed-{stage-receipts,start-receipts,first-native-finality}-20261022.jsonl`.
Build source inventory still matches runtime; only this status ledger changed.

Completed colocated paced1 results remain preserved, not reinterpreted: Val4
30/30 encrypted transactions, max21.2399s, all-five wallet effects, restart/rejoin
through matchingH388; cgrouppeak568287232B/events0/swap0. Late locked async
metadata shows all5 coherent30null tombstones/namespace stable199.135s; it does
not prove the earlier transition or a post-restart memory plateau. Val2/5 miss30s
despite all4 durable completions by23.001/20.551s on every replica; Val6 gets13/16
before30.164s; Val3 empty cadence1.60048s fails. Passing Val4 uses8.09cores average
in the comparable window, versus6/8vCPU on smaller hosts. CPU colocation is
implicated, not exclusively proven; no further source repair is demonstrated.

Exact next action: start bounded independent OS/network and shared-writer-lock
async metadata observers, run genuine funded four-in-flight30-transfer workload
on the running distributed network under unchanged30s and1.5s targets, verify
retirement/restart/rejoin and bounded resources, then controlled sustainable
offered-rate TPS stages starting0.05TPS, with certified/finalized block intervals,
wallet effects, backlog/drain, CPU/RSS/I/O and actual peer behavior. Latest user
instruction supplements the100TPS stress probe with increasing sustainable-load
measurements. Preserve generator limitations; no maximum claim from offered load.
Production state untouched. No24-hour soak started. Clean reviewed-source
promotion remains separately unproven; do not bypass it or claim clean checkout.

Previous checkpoint (2026-10-22, retained1 build sealed): exact Linux node
SHA3-256 `9555182f533b0fc5a0db4e84504433024c406869328ef8ef212c0f62da59667b`,
node-test `b8c61581d5519fa4142ca81267c206c5dc9b5f1044295e6d56bc3d674cae4133`;
complete before/after source inventory matched. No consensus, quorum, signed-byte,
state format, timing or resource-limit changes. Exact retry shortcut is after
finalized nonce fence; compares complete native vertex ID and separate author
signature using prepaid scratch. Private immutable live verifier now reuses
previous authentication only after trusted original/progress length/hash checks;
generic mutable authenticators still reverify. New intake/progress/completion and
open/recovery remain fully authenticated; CAS/monotonic evidence checks unchanged.

Prior RC1 eight focused256MiB zero-swap cases passed each Val2–Val6 (40 results).
Original integrated Val3–Val6 campaigns failed (Val3/4/5 concurrent30s finality,
Val6 preflight1.515206573s); all failures preserved, zero OOM is not closure.
Instrumented diag1 reproduced4 admitted/0 finalized30s: retained duplicate native
vertices cost1.90–2.99s/node, progress writes4.98–5.45s/node; candidate replay tiny.
Retry1 reduced duplicate cost to0.126–0.216s/node but still4/0 within30s; progress
writes5.034–5.486s/node, nested nativeprogress verification3.329–3.648s. Retry1
peak647426048B/events0/swap0. Evidence in target/posy-async-conformance-audit-20261021.
First extended retry fixture failed only its round-zero+parent test setup; source
fixture corrected to round1, failed evidence retained. Retry2 live fixture PASSED
on Val4 at1GiB/swap0, peak407900160B/events0: held encrypted work spans finalized
blocks, changed retries reject, journal unchanged, pending restart/rejoin and
finalized wallet effects exactly once. This is not concurrent30s or OOM closure.

retained1 focused mutable-auth/pending recovery and native order/reveal/archive/
retirement cases PASS Val4 under256MiB/swap0. Full live fixture also PASS83.124s,
including pending restart and correct finalized wallet effects. Unchanged loaded
four-wallet stage FAILED:4 admitted/0 finalized within30s; steady1/1 took9.502s.
Public raw SHA256 a1aa22a2d1526229863ed9a31249fb6b22c3c71664e4219f04681406184e9379.
No OOM closure. No duplicate run remains active.

Next measured root cause: existing async retry clock advanced only when a bounded
slice returnedtrue. With more than16pairs and ETDAG queuecap16, partial successful
slices returnedfalse, leaving clockunchanged and resending at ownerpollrate.
57,098-sample Val4 CPU profile:76.0% networkthreads,44.35% PQVM signing,
27.01% verification. Corrected symbol report is
node-platform/target/posy-async-conformance-audit-20261021/retained1perf-symbolized-corrected-20261022.json;
it supersedes incorrect zero-file-offset symbol attribution. Executable mmap
fileoffset→ELFvirtualaddress delta4096, exact.text/.rodata companion hash match.
Raw IPs only, no secret-bearing DWARF stack or memory export.

paced1 changes ONLY async retry attempt pacing: recordtime before bounded delivery
whether full/partial/success; preserve exact cursor/error propagation/all frames.
No queue redesign, permanent sent suppression, signedbyte or protocol change.
Einstein/Hercules independently reviewed safe. Two real boundedpublisher tests
cover80pairs/cap16 at0,250,500,750,1000ms, exact coverage/fullqueue/error resume.
Optimized Linux sealed with matching source inventories; node SHA3-256
56a36b6a92380fcda1ddc4a9740a844a387ae22ecaed7cfb0d402b30d55cf61d,
node-test d422facb9eb989f55aa6e063b8df97949b9c4121bc9ade07f8bb6d509215cb68.
The paced+bounded and affected retained-auth/native-progress regressions passed
on every actual host under256MiB/swap0. All five colocated campaigns finished;
their exact outcomes and current distributed continuation are recorded above.

Earlier preparation checkpoint (superseded operationally by the running distributed
qualification above): fresh isolated posy-async-canary-20261022-rc1 custody generated on all5hosts;
32 funded wallets plus independent receiver native-generated on Val2. Secrets
never exported. Fresh signed Genesis/authority, public configs, actual provider
Ed25519-signed isolated transport snapshot and native-validated operator wallet
registry are READY; no canary service started and no node artifact deployed there.
Provider pin ed25519:1z43udbXvnrwKF0sGk4toqi/pD27ZM3eve7J9uVHrpU= independently
verified. Original/shared provider records unchanged. release.json not signed
until resource/timing gates pass. Fresh stage is import-only stage_fresh; running
stage-stability-release.py directly would invoke LEGACY staging and is prohibited
for this canary. Next: demonstrated timing pass, affected actualhost resource/
retirement/restart gates, freeze/sign exact qualified artifacts, stage/start fresh
isolated distributed canary, matching finality/state/wallet/restart, initial TPS
with block times, then24h soak start. Production state untouched.

User TPS sequence is100,1000,10000,100000,500000,1000000,1250000,1500000,
1750000,2000000, ascending; stop at first failed or unmeasurable step. Highest
fully passed target only; generator exhaustion is not a network capacity result.
Record submitted/admitted/finalized TPS, latency, block times and resources.
Repeat identical TPS parameters after successful24h soak. Preliminary macOS
release6 .1TPS four-wallet sample drained4/4 with p9525.118s submission-to-finality;
.2TPS drained4/4 but p9550.122s failed timing. These finite local observations
are neither official distributed maximum nor full context-to-finality qualification.


Latest continuation (2026-10-22, resumed agents after usage reset):0.2TPS run5
`exploratory-async-tps-020-20261022-run5-awaiting-vc.*` FAILED drain:4 admitted,
1 finalized,3 unfinished after200s while all five finalizedH85. Its original
report erroneously said passed because the fixture required only one finality;
immutable `.audit.json` supersedes that status, originals preserved. Future
fixture/runner now require every offered item to finalize or be explicitly
rejected. Three unfinished transactions violate30s; no capacity/OOM pass inferred.
Root cause under declared shared1GiB geometry: each pending replica retains
~108MB prepaid worker capacity, permitting partial cohorts to exhaust capacity
before availability quorum. Root added local RPC backpressure until existing
unfinished originals have native availability certificates; network intake,
workers and block production remain active, with no finality wait. Hercules
removed unnecessary predecode worst-case duplication using exact streamed
PendingWrite byte counting, retaining identical128x+completion accounting.
Release6 build/focused regressions and identical0.2TPS rerun are the next action.
This pacing does not prove arbitrary simultaneous multi-origin shared-pool
liveness; actual distributed1GiB-per-validator multi-origin pressure remains a
required operational boundary. No memory limit/quorum/crypto/timing relaxation.

Einstein completed actual-host `--async-processing` TPS adapter:62 offline tests
pass; genuine native encrypted RPC authoring, bounded concurrent offered slots,
all-five exact finality/wallet evidence and strict30s checks, raw block/protocol
and observation timestamps retained. This is tooling evidence, not an actual
network result. Hercules completed v2 ProcessingGroupsV1 authority preparation
(9 native+2 Python tests), now parameterizes fresh isolated canary stage-only
paths. Fresh host-generated validator keys and signed transport mapping required;
retired stability identities remain prohibited. Exporter now supports explicit
fresh `SYNERGY_POSY_ISOLATED_PROCESSING_PROFILE=etdag-async-processing-v1`;
default historical export unchanged. Nothing deployed; soak not started.


Current checkpoint (2026-10-22): second completed exploratory baseline
`exploratory-async-tps-005-20261022-run2.json` uses optimized binary SHA256
`1628199f91d362345faf659aa9be8beade1ccf1014428ff19a9dd1c249b6753a`.
Four independently scheduled encrypted wallets over80s:4/4 submitted/admitted/
finalized at0.05TPS, zero rejects; all-five finality latency14.028s p50,
16.150s p95/p99. Certified intervals average1.584–1.586s, finalized1.588–1.591s;
raw certified/finalized observations, protocol timestamps and inclusion counts
are recorded alongside TPS as explicitly required by the operator. All five
advance through finalizedH48, crossing32 proposal slots; receiver28nwei and
sendernonce1 verified from durable state. Accounting255.4MB initial,
881.5MB peak,312.3MB last, member/completion backlog zero; peakRSS145,080,320B.
This is exploratory low-load local evidence, not official distributed capacity,
full30s timing qualification, actual-host OOM closure, or soak success.

Higher-load0.2TPS run3 retained as failed:7.92s PoSy VC persistence Capacity
(requested1073931365,limit1073741824). New intake consumed control-plane
transient capacity. Small correction now integrated: atomic new-intake floor
67,256,320B derived from existing frame workspace bounds; accepted originals
reuse prepaid child capacity; typed VC capacity defers before READY/voting and
retries retained ECHO statements. No pool/quorum/signature/timing-policy change.
Focused atomic2/2, native2/2 (32.68s), pending/recovery/rollback1/1 (10.13s) pass;
first missing-test-initializer compile failure preserved separately. Release4
optimized build underway; exact next action is repeat the same0.2TPS pressure
measurement, preserving block times and raw failed evidence. Then current
restart/rejoin and actual-host resource gates, frozen signed isolated canary,
official TPS/ETDAG verification and24h soak start. All five hosts reachable;
Val4 has cgroupv2 memory controller (absence of root memory.events is normal),
hostswap8GiB used0; qualification groups must enforce swap0.

Latest operator priority: obtain genuine exploratory TPS immediately after the two
retention repairs, then close actual-host gates and launch the isolated canary.
First completed exploratory result: `exploratory-async-tps-005-20261022-run1.json`
(and raw `.transactions.jsonl`, `.resources.jsonl`, `.runtime.log`, `.source.json`
in `node-platform/target/posy-async-conformance-audit-20261021`). Optimized exact
binary SHA256 `26259997f802f662bce26bbaa92e0fa959cb018ee232057662a1059892953ae7`;
source inventory unchanged during measurement. Five production owner-thread nodes,
authenticated loopback, genuine encrypted native async pipeline, two independent
funded wallets submitted on a fixed 20-second schedule without finality gating.
40-second window: submitted/admitted/finalized 0.05TPS, 2/2 finalized, zero rejects,
14.085s p50 and 15.032s p95/p99 observed all-five finality latency, durable receiver
14nwei and each sender nonce1 verified independently on all five. Certified block
interval average1.693–1.697s across validators; raw per-validator QC and three-QC
finality timestamps, protocol timestamps and transaction inclusion counts retained.
Shared process averageCPU180.61%, peak270.75% (one core100%); peakRSS114,638,848B;
disk writes174,453,248B. Accounting first255,315,680B, peak1,042,937,172B,
last668,130,016B. This short low-load sample is not network capacity, sustained
bounded-memory proof, actual-host OOM closure, or release qualification.

Known demonstrated pressure blocker: fixed0.2TPS/4-wallet run1 failed13.62s at
ETDAG advisory namespace allocation escaping Capacity; typed optional namespace
allocation now defers and preserves references. Run2 failed8.68s at an execution
allocation (`requested=1075915692 limit=1073741824`), two admitted, first completion
allfive, no finalized transfer. Both failed evidence sets retained. Hercules owns
narrow proposal-store typed Capacity propagation and execution retry guards; root
owns ETDAG/fixture/measurement integration. Do not raise the shared1GiB pool, change
quorum/timing, discard accepted transactions, or hide corruption. Next: finish this
observed pressure repair, focused regressions, repeat controlled concurrent offered
load with blocktimes. No performance tuning before the recorded baseline.

Retention focused evidence now passes: native terminal marker/archive/recovery/
full-pool retirement256MiB component30.60s; sparse state commitment pin0.66s;
exclusive prepaid child quiescence0.00s; candidate pin14 tests24.43s and maximum
index exact/one-byte-short checks0.13s; native Sync predecode pressure0.13s.
Keytool native `prepare-wallet-processing-admission` is implemented;27 tests pass,
including genuine crypto roundtrip. Live low-load run confirms finalized members/
completion backlog drains to zero. Higher-load safe backpressure remains open.


Objective remains live integration → actual-host resource/safety gates → isolated
canary → initial TPS baseline → genuine encrypted ETDAG validation → soak start.
Nothing deployed; no actual-host OOM or soak pass is claimed. The completed
exploratory TPS evidence and current pressure repair are recorded above.

Accepted live evidence: `processing-live-encrypted-native-dedup-repair.log`
passed five production owner-thread validators over authenticated sockets,
RPC encrypted intake, unfinished work through finalized H2, then native
availability/reveal/completion/ready inclusion and verified wallet effects on
all five through H11 (157.38s test; 151.797s measured; 809,767,072 reserved bytes
of shared 1GiB). This predates the newest restart/fault changes; it is not a
30-second timing pass or actual-host memory qualification. Immutable native
retry-frame deduplication eliminated repeated verification of accepted originals;
missing-prerequisite frames remain retryable, never cached as accepted.

Live pending intake, native availability/member publication, canonical closure
lookup, durable partial reveal recovery, completion publication, and authenticated
wire handlers are now connected. Finalized retirement/storage pins/stage cleanup
and complete native Sync/rejoin remain open. Pending restart paths compile but
have not passed the expanded live fault test yet.

Current live fault findings: lease-wide takeover/current carry adapter repaired;
`...repair2.log` passed H2 takeover and reopened pending journals, then failed
because Sync still used the legacy processing rejection. Native Sync now carries
bounded exact replay inputs plus original ECHO VC in an optional transport
sideband (legacy bytes omit it); PoSy independently verifies exact QC/VC binding
and execution regenerates transitions rather than trusting an incoming World.
The first compile error in `...repair3.log` is fixed; `...repair4.log` exposed an
obsolete speculative candidate being proposed in the new round before its fresh
handoff, causing a correct sign-once refusal. Exact-round handoff checks now
protect proposal admission, delivery/voting and proposal emission. Safety journal
and consensus rules are unchanged. `...repair5.log` avoided that conflict but
failed after 117.21s: restarted node stayed H2 while peers finalized H12–H13.
Its durable Sync request awaited already committed H2; the processing replay
branch now re-acknowledges exact verified durable state without re-execution.
Fixture reconnect retries now match the existing socket restart procedure.
All failed logs and journals remain preserved. No fault-test success is inferred.

Latest integrated recovery evidence: `...repair6.log` recovered all five through
H7 after pending restart but failed at 178.96s with all five at H10/r2. Node0
lacked certified H8–H9 stage inputs/closure VC; four peers had completed witnesses
but node0 could not reconstruct the native reveal World. Current proposal
transport now includes at most two exact certified predecessors; each is matched
to locally admitted native QC history and verified ECHO authority before staging,
then fully replayed by the execution owner. No incoming World grants authority.
The two records bridge the existing three-QC finalized/live frontier only.

`...repair7.log` failed 46.14s because nested proof byte arrays expanded beyond
the unchanged 1MiB native frame. New sideband uses exact UTF8 JSON strings to
avoid the second numeric expansion; measured empty H3 frame ~674KiB, no increased
frame limit. `...repair8.log` failed 96.32s on ETDAG's unchanged 10s owner shutdown
deadline under large retries. The processing receive quantum is now four frames
(previously64), preserving owner threads, queues and timing policy. Test cleanup
now records failed stop errors during unwinding without obscuring the primary
failure with a destructor abort. All failed evidence remains intact.

Latest live milestone accepted: `processing-live-encrypted-takeover-restart-release1.log`
passed in 131.04s using the optimized build, unchanged fixture deadlines and
unchanged governed native rules. Unfinished work survived finalized H2, takeover
and admitting-node restart; after release all five finalized correct wallet
nonce/balance effects at H11 (113.202s from submission fixture clock; 60.781s
from worker release). A second restart/rejoin advanced all five H11→H13 in
11.914s without duplicate execution. Shared reservations peaked at the observed
wallet checkpoint 797,770,710 bytes; this is accounting, not RSS/OOM evidence.
The debug repair9 run failed its unchanged 180s deadline; preserve that failure.
No 30-second contract pass is inferred from the optimized live success.

Focused native Sync proof/idempotence/corruption regression also passed against
this source in the release build: `processing-native-sync-proof-release1.log`,
1 test / 5.41s. Sideband legacy encoding/accounting regression passed separately:
`processing-sync-sideband-focused-exact-20261022.log`, 1 test / 0.04s.

Exact next action: close the existing bounded finalized-retirement/reservation
handoff and speculative-stage cleanup gaps, then qualify the integrated exact
artifacts. Native retirement verifier exists but is not yet wired; the fixed
32-slot proposal stage cannot support a sustained chain without safe reclamation.
Keep canonical recovery/Sync inputs and pending reveal proofs available across
reclamation, restart and configured history pruning. Helper agents resumed after
their reset for narrow read-only design and focused evidence review.
Current retention implementation (2026-10-22 continuation, qualification pending):
- QC-selected exact inputs/VC now archive before bounded speculative slots migrate;
  historical Sync/reveal lookup falls back to that archive. Sparse archive pruning
  respects exact proof pins and revisits released pins in bounded quanta.
- CandidateStore has bounded sparse immutable proof checkpoints; 14 candidate-store
  regressions passed, including prune/restart/corruption/full-pool unpin. The derived
  maximum 12,304 descriptors serialize to 2,377,101 bytes and precharge 19,082,344
  bytes; exact-bound success and one-byte-short rollback pass separately.
- Native consumed selection/three-QC/durable-state verification now authorizes a
  terminal pending marker. Terminal recovery preserves and hashes original
  sidebands, authenticates native finalized consumption, and skips plaintext
  reconstruction. Retained original records obey the configured retention fence.
- Live ETDAG drops finalized worker frames/member/completion ownership and attempts
  exclusive child-pool shrinking; Execution keeps sparse closure/consumption/parent
  dependencies until positively reconciled references permit cleanup. Certified
  parent changes invalidate the reference snapshot. No production records changed.
The integrated all-target check and focused native marker/archive/pressure
regressions pass. The fresh low-load live measurement above passes; saturated
backpressure still requires the exact corrected live run. The native async wallet
authoring adapter is implemented and its 27 keytool tests pass.
Remaining gates: current integrated safety/resource/journal/OOM qualification,
exact frozen signed artifacts/configuration, isolated distributed finality and
wallet/rejoin checks, TPS raw metrics, genuine ETDAG gate, and 24h soak start.

### Asynchronous architecture clarification — latest checkpoint

**Approval received:** the operator explicitly approved implementing the
versioned asynchronous profile for the isolated canary on 2026-10-21. The
approval wait is closed. Implementation is underway; no new profile is activated
and no production deployment, signing-key use or state migration is implied.
The first source boundary separates immutable processing authorization/encryption
from eventual inclusion, reusing the existing cryptographic primitives. Full
runtime conformance, actual-host resource qualification and release gates remain
unproven until integration and their required checks complete.

**Implemented and locally checked:** versioned immutable processing context,
envelope/AAD and outer signature; native ML-KEM/AES processing encryption and
canonical wallet identity verification; bounded deterministic dependency/capacity
selection; per-entry parent-World ready records; actual-parent candidate assembly
and complete candidate replay. Legacy material retains its wire bytes and legacy
native recovery still rejects processing material without explicit activation.

The native ordering/reveal/readiness boundary now validates original wallet and
DAG-author signatures, availability count and strict weight quorum, authenticated
DAG parents and frozen ingress keys. The new vertex ID commits the original
wallet authorization as well as the envelope reference. Ordinary candidate state
commits sequential encrypted groups, successor closure, global sender/nonce
claims and a per-group next-position cursor. Group state and ready-registry diffs
are committed together by the candidate lifecycle root. New assignment/closure
cannot authorize plaintext in the same block. Missing earlier ready members defer
their own certified group instead of allowing later members to skip its prefix.

Existing PoSy n-1 ECHO certificates authenticate the exact reveal parent World.
Native signed shares bind that parent, the original context/envelope and governed
capsule/key; existing threshold decryption reconstructs the genuine ciphertext.
Verified completions publish only for descendants, and execution/replay consumes
only the actual-parent ready prefix. Identity eligibility uses canonical binding
and governed inclusion time. No new QC, finality rule or consensus coordinator was
introduced. Native frozen-source authentication (Genesis or existing three-QC
finality) now also implements pending-store recovery authentication.

The native pending component preserves encrypted request bytes in reusable slots,
uses per-slot writes plus a small durable generation, and enforces cross-context
nonce claims. A native cryptographic boundary regression now demonstrates
4/5 availability, rejection of early reveal, genuine 2-share reconstruction,
ready publication at H4, wallet effects at H5, and unchanged three-QC finality of
H5 at H7. It rejects corrupt availability/ECHO/share signatures, duplicate shares,
rewritten groups and foreign candidate proofs. Original pending requests recover
and authenticate with the pool otherwise full. This is a local proof/execution
fixture using native primitives, not a running distributed processing profile.

Current focused checks pass 15 ETDAG processing tests, 14 execution processing
tests and 5 native processing tests. The maximum 4,096-member group reserves
108,246,032 bytes within a 268,435,456-byte component pool; low-capacity rejection
releases all tentative reservations before graph work. Empty groups retain only
small current metadata; consumed groups and nonce claims retire from candidate
state. These are accounting measurements, not RSS or actual-host OOM evidence.
The adjacent full-library run passed 62 ETDAG and 36 execution tests. The final
ETDAG/native checks and all-target Clippy ran against an unchanged hashed source
set. Earlier unaffected evidence includes 13 Sync tests, the legacy H1-H6 cycle
and the genuine five-signer legacy restart/finality regression. Failed compiler,
fixture and test logs remain preserved alongside their corrected results.

The earlier current-nonce rejection implementation is superseded: terminal state
rejection consumes only the authenticated current nonce, with zero gas/fee and
no action effects; stale requests cannot change it again and future nonces defer.

**Durable worker continuation — 2026-10-22 03:54 UTC:** the assignment remains
active through live integration, final qualification, isolated deployment, initial
TPS baseline and soak start. Do not stop at this component checkpoint.

The pending owner now prepays a bounded child worker pool from the shared World
budget. Detached results keep the original parent charge through ownership
handoff and slot retirement. Completion writes use a separate fixed slot and the
existing generation CAS; original admission bytes are preserved. Native recovery
rechecks wallet/author/availability, exact candidate/VC, successor closure,
signed shares and reconstructed ready metadata; plaintext is reconstructed rather
than repeatedly persisted. Equivalent valid share subsets preserve the first
witness. Native completions retain only charged payload and original authorization
metadata, without borrowing a historical World or worker decode stack.

The native regression passed with the global pool otherwise full, persisted and
recovered a genuine encrypted completion, rejected tampered completion bytes with
reservation rollback, and preserved original journals. Physical retirement passed
only after the exact parent selection, durable candidate/execution commitment,
three-QC finality and retention fence. It rejects an uncommitted execution and a
premature retention boundary. Atomic retirement clears request and witness
slots together, and a detached cache keeps its reservation until dropped.

A separate signed policy version 2 marker (`processing_groups_v1`) and domain
now select the approved profile explicitly; legacy signed policy bytes remain
unchanged. The native lifecycle test passes using a genuinely signed new-profile
fixture. This does not activate any validator deployment. The frozen durable
checks recorded three passes and a Clippy failure for the then-unwired activation
method; that failure remains preserved. Subsequent focused processing runs pass
six tests, and the PoSy library passes all 36 tests after the delivery changes.
Started checks are never accepted as completed evidence.

**Live-owner continuation — 2026-10-21 23:50 CDT:** Hercules completed the bounded
versioned RPC/intake carriers and four native transport variants before both
helpers reached an external usage limit. The primary agent continues independently.
The native Genesis parent now authenticates H1 directly and cannot permit reveal.
The RPC regression proves newer context publication does not expire an original
prepared envelope; duplicate intake and return/rejection preserve byte accounting.

The native runtime seam previously pinned the first candidate and first VC at a
height despite PoSy allowing another candidate after a verified takeover. The
processing branch now has typed, prepaid native slot/parent/proposer instructions,
a bounded candidate handoff, rejection of obsolete results, same-round conflict
rejection and mandatory-carry checks. Default legacy candidate behavior remains
immutable. VCs may be replaced only using a sealed, PoSy-admitted timeout summary;
failed replacements and stale-owner CAS conflicts preserve durable bytes.

A separate fixed-slot pre-QC store preserves replay inputs and per-candidate native
VCs without copying Worlds or rewriting canonical height candidates. Its private
durable token is required for the processing candidate handoff. Tests preserve
both same-height branches and their VCs across restart, using actual native
signatures. Existing whole-height VC history is not the sole reveal-proof source.
Compact native member capabilities now allow owner handoff without borrowing the
original ciphertext decode or source World. Focused staged replay/retirement checks
are underway; see `processing-native-stage-replay-regression.log` for completion.
These remain native component/service-boundary tests, not a live five-node result.

**Exact next action:** wire these durable, owned native results into the existing
live ETDAG/execution owners and authenticated transport/RPC. Preserve a single
PoSy driver and verify the actual proposer material before ECHO/voting. Live
material must be replayed against its exact canonical parent, rather than chosen
independently from each validator's local completion arrival order. Finish source/
DAG/reveal-proof retention, native finalized retirement calls and explicit signed
activation in that live path. Existing failed evidence remains preserved.

**Mandatory remaining gates:** integrated native asynchronous operation with
transaction-free block/finality progress; actual-host resource/journal coherence,
bounded memory/I/O and OOM qualification; applicable admission and separate
30-second finality contracts; exact artifact/config freeze; authorized isolated
five-host deployment with matching finalized roots, genuine encrypted wallet
effects and required restart/rejoin; initial TPS baseline; encrypted ETDAG
qualification; start of the 24-hour soak. No production state change, deployment,
TPS measurement, soak start or actual-host OOM pass is claimed.
Evidence: `node-platform/target/posy-async-conformance-audit-20261021/`.

The operator requires ETDAG processing to span block intervals while PoSy
continues normal proposal/QC/finality, including valid empty blocks. The completed
[conformance audit](POSY_ETDAG_ASYNC_CONFORMANCE_AUDIT.md) confirms the current
signed profile and maintained specifications bind authorization, reveal and
inclusion to an exact target. Asynchronous workers do not remove that coupling;
normal missing ETDAG material blocks proposal construction after H2.

The final instrumented Val5 diagnostic completed FAILED with cleanup complete;
it is no longer underway. Target63 enqueued634.358ms into a974.891ms window,
leaving340.533ms, and admission durably rejected `closed_target`. No timing pass
or transaction finality is claimed. Stop old-profile timing campaigns: the
smallest coherent proposed correction is a versioned processing identity,
authenticated cross-height eligibility and actual-parent execution, with pending
ETDAG work optional for block creation. The audit identifies the exact signed
format, reveal, proposal and journal seams covered by the operator's explicit
implementation approval. Its earlier approval-pending passages are historical.

No production state was changed. Protocol implementation has now begun. Final
integrated memory/OOM and coherent journal qualification remain OPEN. No canary
deployment, TPS baseline or soak has begun. Existing failed evidence remains
unchanged. The prior checkpoint below is historical where it describes a live
diagnostic or timing-only next action; the linked audit now defines the critical
path and evidence reuse boundaries.

### Previous diagnostic checkpoint (historical)

Architectural scope is frozen by the operator's critical-path directive. Repair
only reproduced canary blockers; preserve all failed evidence. This checkpoint
supersedes earlier current-state summaries below, which remain historical.
No designated canary service was deployed and no production state was changed.
Only a fresh isolated Val5 diagnostic may run while its current attempt finishes;
TPS and the24-hour soak have not started.

**Proven:** v43's five affected libraries recorded80 passing tests and strict
all-target Clippy passed. Focused current-source checks now pass the listener
handoff, four-signer finality through H20 with later rejoin, authenticated
snapshot serving/restart under injected World pressure,16 Sync congestion tests,
and a snapshot-store pressure/rollback/retry regression. The full node suite
was interrupted with failures; those two failures were reproduced and repaired
in fixture code. A full-suite pass is not claimed. Recheck exact release bytes,
not just these local macOS tests. The Linux v43 diagnostic candidate was sealed
with identical complete pre/post source inventories: runtime SHA3-256
`0a24cef1239873d0d2e69af24e44422f255792b9f5b3f9de86c669c39321f1b0`.
Its genuine encrypted default5 transfer failed durably with `closed_target`:
target40 opened for732.719ms; RPC enqueued589.538ms after opening, leaving
143.181ms before cutoff. Cleanup completed, all cgroup OOM counters and swap
use were zero. This54-second failure is no sustained resource qualification.
The exact owner/worker boundary was not instrumented and cannot be inferred.
The subsequent bounded qualification-only phase hooks pass4 timing tests and
strict Clippy; the instrumented Linux diagnostic has matching pre/post inventories
and runtime hash `845076fd14452d22f1a0421473aac164c44c9333180e542d8e591d1d2cf29efa`.
Keytool, Genesis and ETDAG-test hashes are unchanged. Neither candidate is an
approved release. Evidence: `node-platform/target/canary-critical-path-default5-v43-failure-analysis-20261021.json`.

V42 remains independently FAILED. All140 actual-host component records passed.
Val2/3/5 completed31 funded transfers each and restart/rejoin under the1GiB,
zero-swap profile. Separate extraction confirms their four prescribed anonymous
memory/RSS plateau comparisons pass. Their journal audit rejected bounded
metadata-lock timeouts (15/13/11 respectively), not demonstrated journal
corruption. Val4/6 mixed runs failed fixture port collisions. All five report
zero cgroup OOM events and zero host swap, including the incomplete runs; absence
of OOM does not close those incomplete qualifications. Original audit results
and exports are unchanged. Evidence: `node-platform/target/canary-critical-path-v42-reusable-evidence-20261021.json`.

| Classification | Remaining issue and evidence | Smallest required action |
|---|---|---|
| BLOCKER | v43 final integration/resource qualification:29 pre-existing Rust/Cargo inputs differ from frozen v42, plus the new World budget module; v42 cannot qualify the integrated current runtime. Temporary World pressure was reproduced as a fatal snapshot-serving error. | The serving repair passes; staging now retains durable acquisition on capacity pressure and Execution retains one pending verified snapshot for retry. Finish focused verification, freeze exact inputs/binaries/config, and qualify changed boundaries on the five actual hosts. Reuse only evidence whose unchanged source/artifact/config scope is established. |
| BLOCKER | Journal retirement evidence: v42 rejected contended metadata observations, with no all-five resource-profile pass. | Repair the observer's bounded capture method prospectively, retaining raw failed attempts and existing file/byte, retirement, memory and I/O thresholds. Collect adequate coherent evidence with the final candidate; do not refactor journals to repair an observer. |
| BLOCKER | Governed default5 admission: Current sealed v43 target40 rejected `closed_target` despite RPC enqueue143.181ms before cutoff; the owner/worker phase is unmeasured. v22 remains earlier failed evidence. | Run one identical genuine funded default5 transfer with bounded owner-dispatch, worker-state/verification and completion/authoring timings. Repair only the demonstrated causal boundary. Any concrete admission-policy amendment requires separate explicit authorization. |
| BLOCKER | Admission/finality timing: v42 offset16 Val5 target153 took31.616540479s, exceeding the separate30s contract. All current native proposal timings are conservatively recovered, so required healthy-cohort headroom remains unqualified. | Establish verifiable uninterrupted timing cohort provenance; preserve recovered observations. Qualify existing positive-window/eligible-p99 headroom and30s finality independently of the60s resource proof wait. |
| BLOCKER | Release provenance and distributed operation: v43 Linux diagnostic bytes are sealed, but no clean reviewed/signed v43 release exists; matching five-host finality/wallet effects or current distributed restart/quorum-recovery evidence. Existing release verification requires clean reviewed source. | Use canonical build/release guards, reconcile task-owned source without sweeping unrelated edits, then exact-artifact isolated and distributed qualification with existing keys/durable records preserved. No production-state mutation is authorized. |
| BLOCKER before baseline | Baseline recorder currently reports p95 and says OS resources unavailable. | Capture external CPU/memory/disk/network raw samples and preserve transaction timestamps; derive p50/p95/p99, submitted/admitted/finalized TPS, rejections and backlog. Measurement tooling only. |
| POST-BASELINE | Throughput tuning, broader admission queue alternatives, additional caches and I/O optimization after the qualified initial measurement. | Keep candidate bytes/config unchanged while capturing the first baseline; optimize only against preserved results. |
| POST-SOAK | Universal arbitrary-World capacity claims beyond the declared canary workload, API hardening for oversized internal commitment identifiers, unexercised role migration, multisig/protected-wallet expansion, new system contracts, archive/Val1 expansion and larger historical experiment matrix. | Do not make these prerequisites to the declared canary. A demonstrated supported-workload safety/recovery defect remains a blocker regardless of this deferral. |

Existing acceptance contracts remain authoritative: the signed five-height
policy, quorum/signatures/three-QC finality and persistent formats are unchanged.
The historical Gate A–H checkboxes below are not newly satisfied or erased;
coverage reuse requires an explicit source/artifact/condition mapping. A resource
proof timeout extension never qualifies admission timing. No new release gates
or retrospective waivers are introduced by this assessment.

The completed10,000-seed abstract campaign is reusable: its frozen source hash
matches the current model exactly. It does not qualify native cryptography or
close Gate C; no repeat of unchanged abstract seeds or10,000 native-run gate is
required. Existing native coverage must be mapped to its actual scope.

**Next action:** complete the single instrumented default5 transfer and locate
the first causal owner/worker boundary. Do not repeat sustained host campaigns
or change policy before this result. Final changed-runtime resource evidence,
coherent journal retirement, signed distributed operation, initial TPS, genuine
encrypted ETDAG and the24-hour soak remain sequenced prerequisites.

## Resource qualification checkpoint — account World lifetime, 2026-10-21

The memory/OOM gate remains **OPEN**. The sealed v41 runtime passed all28
component cases on each of five actual hosts (140 independently audited
records), under256MiB with zero swap and unchanged OOM counters. Val2/3/5
shared1GiB runs failed the unchanged30-second funded context-to-proof budget.
Val4/6 completed31 funded encrypted transfers and restart/rejoin, with no OOM
or swap; both pass the fixed anonymous/RSS and normalized I/O comparisons.
Their overall journal qualification fails because a few bounded metadata scans
could not obtain coherent snapshots during live writes. These failed records
and the original schema-error audit are preserved; no v41 overall pass is claimed.

The account-read repair releases the fully verified candidate World before
reconstructing the separately archived finalized World. Both archives retain
full validation; only verified scalar block/root commitments survive between
reads. This reduces simultaneous decoded residency, without a historical cache
or any consensus, signature, quorum or admission-policy change. Eight focused
RPC tests pass, including pinned/latest account values and missing candidate
World rejection. Encoded record limits are not a proven universal decoded-heap
bound; the actual-host qualification is explicitly scoped to its declared workload.

The next resource profile will use the canonical storage writer lock in shared
mode for bounded metadata-only observations. It will preregister a60-second
resource proof wait, retain the900-second funded cohort bound and separately
report every transaction exceeding30seconds as an admission timing failure.
This prospective measurement profile does not qualify default5 admission or
waive the canary admission gate. Full source/artifact freezing, all-five component
and shared-runtime requalification remain required. No deployment, initial TPS
baseline, canary launch or24-hour soak has started.


## Current resource qualification checkpoint — telemetry commitment reads, 2026-10-21

The memory/OOM gate remains **OPEN**. The v40 candidate lifetime repair passed
all27 component cases on all five actual hosts (135 independently audited
records), under256MiB with zero swap and unchanged OOM counters. Shared1GiB
runs completed on Val2/4/6; Val3 exceeded its30-second context-to-proof budget
at30.341s and Val5 exceeded native finality timing. All failure evidence is
preserved. No production deployment, TPS baseline or canary soak has started.

The independent v40 audit remains incomplete/failed: the last common native
observations preceded the scheduled1281-second shutdown, while the audit
required an observation at or after it. Val2/4 passed quantitative memory,
journal and I/O checks; Val6 failed the journal mean-count growth threshold
(post-restart34 to39 files during32-height retirement cycles). No v40 overall
qualification is claimed and no acceptance threshold is changed retroactively.

The next source repair exposes a bounded canonical candidate commitment read
for telemetry. It validates protected material, canonical block identity and
transaction/receipt correspondence and binds the result to durable finalized
state and PoSy finality, without reconstructing/hash-checking the archived
account world for every status poll. A telemetry commitment attests finalized
identity, not archived world readability. Block/account/execution/import and
recovery paths retain full world validation. No strong historical-world cache,
consensus owner, quorum, signature or governed admission policy is changed.

The final revised runtime requires focused regressions, a complete source freeze,
sealed artifacts and all-five actual-host qualification. The next measurement
harness parallelizes exactly five independent pinned account-proof reads while
preserving all proof checks and the30-second budget; explicit stage timings
are retained. Startup/end sampling and journal retirement observations must be
qualified before the memory gate can close. Default governed admission/finality,
initial TPS baseline, encrypted ETDAG canary and24-hour soak remain subsequent gates.


## Current memory qualification checkpoint — candidate lifetime repair, 2026-10-21

The memory/OOM gate remains **OPEN**. All26 v35 component cases passed on each
of the five actual hosts under256MiB with zero swap and no OOM. This does not
qualify the final integrated runtime. The v37 four-inflight mixed runs failed
on durable admission rejection; v38 serial runs on Val2/3 failed their300-second
count deadline despite verified wallet effects for19/12 cohort transfers.
Two Val3 transfers also exceeded the30-second context-to-proof budget.

Further source review found that PoSy retained executed candidates indefinitely
by height, pinning historical `Arc<WorldState>` values. Candidate payloads must
retire only after verified finality is durable; delayed finalized handoffs must
not repin them. Current/unfinalized candidates and durable safety commitments
remain required. The v39 successor campaigns were explicitly interrupted on
all five hosts after this defect was found; none is a qualification pass.

The revised candidate requires a new source freeze, sealed artifacts, focused
lifetime regressions and repeated actual-host qualification. Sustained memory,
I/O and protected-journal stabilization, restart/rejoin and funded encrypted
wallet effects remain mandatory. No production deployment, active admission
amendment, canary, TPS baseline or24-hour soak has started. Establish the initial
TPS baseline after the resource and admission gates pass, before stabilization
tuning, then repeat the controlled comparison after the canary soak.

## Current memory qualification checkpoint — v35 test correction, 2026-10-20

The memory/OOM gate remains **OPEN**. The v32 actual-host component campaign
passed single-owner4096-generation maximum-proof recovery but failed the
new three-owner4096 test: the test round-robinned three partial indexes in a
pool sized for two complete owners, then incorrectly assumed an owner had
installed before pressure. The production runtime already drives the earliest
pending recovery to completion before decoding the next owner. Its scheduler,
32MiB aggregate pool,40MiB scratch cap and consensus rules are unchanged.

The v35 test correction follows that runtime scheduling, asserts waiting
owners retain zero decoded history, requires two installed owners before
third-owner pressure, and checks retirement/resume with original journal
hashes unchanged. Local and actual-host qualification of the corrected test
and final sealed candidate remain required. v32 failures remain evidence;
they are not passes. Shared-process v33/v34 packages were staged but never
launched. The next mixed-memory package is v36, including bounded sampled
process I/O and per-device host counters for ZFS hosts whose cgroupio.stat
is empty; empty counters mean unavailable, never zero disk activity.

No deployment, active admission amendment, canary, TPS baseline or24-hour
soak has started. Those remain gated on memory/resource and admission closure.


## Remaining memory allocation audit — 2026-10-20

Overall memory qualification remains OPEN. The v27 Linux candidate is sealed
with matching complete source inventories before and after compilation. Runtime
SHA3-256: `8d1ad0f869f0ae60f0a8b49718907b91369f9d1e317075c3dbc9424b6208f168`.
The previous v22/v24 passes remain limited to their declared workload.

The repaired retry iterator selects at most64 payload/peer pairs before cloning.
Authenticated v3 collecting journal actions append/fsync before memory mutation,
preserve original native signatures and proofs, and replace whole-graph intake
rewrites. Cut/prepare/recovery phase frames retain their required full state;
this does not claim all persistence writes are constant-size.

Aggregate intake reserves completion across live targets, including native quorum
votes/certificates, runtime mirrors and all16 ETDAG outbound queue slots. The
collecting reservation pool is32MiB; transition/recovery scratch is40MiB.
Admission checks prospective per-target phase copies before accepting work.
Rejected, nondurable work restores its exact prior reservation; safety/storage
ambiguity retains reservations. Legacy recovery that cannot fit stops further
decoding with an explicit capacity diagnostic and preserves originals. Other
transport queues, finalized worlds and historical proof caches keep their
separate existing bounds; these two pools are not a whole-process memory bound.

Strict node/ETDAG Clippy passes. All46 ETDAG tests and seven focused collecting
regressions pass. Four resource regressions cover native quorum completion after
same-target saturation, many-target pressure, spare allocation capacities and
64 rejected speculative reservations. The real65536-byte encrypted wallet
carrier completes reveal/execution/finality on all five validators. A131072-byte
wallet carrier exceeds the existing1MiB authenticated-frame bound and is rejected
before durable vertex admission; that bound is preserved. Separate twelve-vertex
maximum131072-byte native collecting/restart tests preserve exact originals.

All23 new-artifact component qualification records pass on each actual Val2–Val6
under256MiB/Swap0: collecting/retries/resource pressure, both wallet cases,
all46 ETDAG tests,96/1024/4096 history and4096 maximum-proof recovery, ten native
runtime/restart cases and live-source proof validation. Final exported evidence
and independent audits remain pending.

V28 combined actual-host qualification FAILED on all five hosts. The isolated
signed-offset16 fleets each finalized the initial transfer, then lost readiness
during the first four concurrent funded submissions; zero of the required30
workload transfers finalized. All five1GiB/Swap0 monitors recorded zero OOM,
OOM-kill and MemoryMax events, with validated cleanup. The runs ended before
the scheduled restart and full native-pressure campaign. Fixed public exports
are preserved under node-platform/target/resource-repair-memory-host-evidence-v28-20261020.
The service-health/resource-pressure cause is under investigation using an
isolated diagnostic repeat; component passes do not close this failure.
No deployment, active policy change, TPS baseline, canary launch or24-hour soak
is qualified by these tests.

The isolated v29 diagnostic repeat captured a prospective intake request for
55,047,536 transition bytes against40MiB, degrading the whole-node readiness
while other validators remained healthy. The v30 source correction counts the
exact cut reference instead of a second full encrypted wallet vertex, separates
ordinary queued intake pressure from durable-phase health failures, and checks
closed queued targets before retrying capacity.32MiB/40MiB limits and exact
pipeline allocation guards remain unchanged. The phase bound also uses the
maximum of collecting and prepared serialization, reserves the one parent proof
actually present in runtime preparation, and separately counts canonical native
share wire instead of treating padded heap charges as JSON. Five resource
regressions and strict node/ETDAG Clippy pass on this candidate. The sealed v30
release four-wallet regression passes on every actual Val2-Val6 under256MiB/Swap0,
verifying all four transfers and all five account states. Peak process RSS is
142,958,592-151,822,336 bytes. The local debug build reached all-four certification
but hit its60-second no-finality-progress guard; that failure is retained. Full
24-case v30 host component qualification is still running.

The aggregate retained-history accounting repair is implemented in the v32 source:
both installed and in-progress owners charge indexes, proof locations, allocation
capacity and their latest proof to the same32MiB retained pool. Replay scratch
also includes resident history before decoding another frame. Prospective live
generation charges precede append; typed pressure preserves journal originals.
Each owner excludes its own existing reservation on retry. Finalization releases
only retired heights and re-enables capacity-blocked recovery when space changes.
The pending PoSy-to-ETDAG generation handoff now has an8MiB shared deep-byte
budget as well as entry caps; normal pressure retries from durable PoSy authority.
Each installed generation acknowledges its exact durable prefix immediately.

All47 ETDAG tests, six runtime resource tests and the shared proof-handoff test
pass locally. Genuine R3 timeout recovery, native empty/nonempty close and restart
also pass. The new three-owner regression verifies shared pressure, maximum1MiB
latest proofs, unchanged original journal hashes, retirement/retry without
self-reservation deadlock, and live append rollback. Fresh final source sealing,
all-five-host qualification and sustained memory/I/O stabilization remain OPEN.
V31 is HELD and will not qualify this revised source. V30 component results are
24/24 on Val3-Val6; Val2's measurement stopped on a disappearing cgroup pseudo-file
(ENODEV) after14 successful records, not a qualified all-host pass. Its failure
evidence and four complete public component exports are preserved under
node-platform/target/resource-repair-component-only-host-evidence-v30-20261020.
No canary or deployment starts before the memory gate closes.

## Live admission proof checkpoint — 2026-10-20 (v21–v24)

Fresh default5 reproduction v21 on actual Val5 uses the sealed v17 runtime and
native signed Genesis verification. It fails with a durable `closed_target`
receipt, not OOM: the target opens at0ms, RPC enqueue occurs at396.44ms and
verified cutoff closes at495.48ms on one native monotonic clock. The complete
failed public export and analysis are retained in
`node-platform/target/resource-repair-default5-host-evidence-v21-20261020/`.

The current v22 source candidate snapshots PoSy's bounded, already committed
live source record/witness instead of reopening the record and three QC files
and repeating the ingress-history QC verification. Publication still verifies
all three QCs against the active signed authority, exact ancestry, finalized
record and governed target context; historical sources keep the authenticated
durable reader. A malformed live witness fails closed without fallback. No
new retained cache, cutoff, quorum or signed lookahead policy is introduced.
A genuine five-validator regression passes locally with and without timing:
no-history live proof succeeds, historical proof remains readable, malformed,
truncated, forged and conflicting proofs fail. Targeted Clippy and format pass.
Complete pre/post Linux build source inventories match. Standalone v22 SHA3-256:
`c927a76e559bf4c6b7984a8732594338f429b817c171a80a5280583184b3e129`.
ETDAG, signing and Genesis artifacts remain byte-identical to v17.

V22 now passes all55 actual-host native/component measurement records across
Val2–Val6 under256MiB MemoryMax, zero swap and zero host/cgroup OOM deltas,
with validated cleanup. Peak native RSS is136.84MiB. Public exports and the
independent audit are retained in
`node-platform/target/resource-repair-node-host-evidence-v22-20261020/`.
The fresh v22 default5 retest fails admission: cutoff closes at330.93ms and
server enqueue-shape processing starts at534.49ms. Its complete failure export
is preserved; the cached source proof optimization does not fix default5.

The separately signed isolated six-height comparison v23 reaches durable
admission but its first transfer does not finalize within30seconds. It is a
failed comparison, not a pass or policy amendment. Its verified public export
is retained in
`node-platform/target/resource-repair-lookahead6-host-evidence-v23-20261020/`.
V24 full-process resource qualification of the current sealed v22 runtime
PASSES on all five actual hosts, using the maximum supported experimental
offset16, the same1GiB/zero-swap five-validator group cap, transfer counts,
deadlines and restart schedule. Each host finalizes1 initial plus30 workload
transfers with all-five effects verified (155 total). The30-transfer workloads
finish in98.68–217.35seconds against the unchanged300-second limit. Independent
public-evidence auditing verifies exact runtime/exporter identity, signed-profile
attestations, native observation and transaction proof streams, zero host/cgroup
OOM deltas, zero swap use, signer death before replacement, continued matching
finality after restart and validated cleanup. Final common heights are1140,659,
1277,578,1267 on Val2–Val6. Anonymous memory peaks are605.84–633.02MiB per
five-validator group. Four groups reach the cap and reclaim file cache; this
is survival under pressure, not spare headroom. Retained protected journals are
contiguous recent tails of25–51 records rather than all finalized heights.
Val4 ZFS ARC is accounted separately (peak8.49GiB; host available minimum108.93GiB).
The complete exports, independent audit and post-cleanup file metadata are in
`node-platform/target/resource-repair-memory-host-evidence-v24-20261020/`.

The declared current-runtime memory gate is now passed, together with the
supported-bound protected-history evidence on unchanged ETDAG artifacts below.
This closes the previously open protected-recovery growth and actual-host OOM
qualification for the declared profiles. It does not prove arbitrary-history
support,24-hour stability, default5 admission or distributed canary readiness.
The default5 and experimental6 failures remain open canary blockers. No
production/canary deployment or TPS/24-hour soak has started. Capture the initial
TPS baseline immediately after canary startup and before performance tuning.

## Admission comparison continuation — 2026-10-20 (v25–v26)

With the declared memory gate passed, the existing architecture comparison
continues using the same sealed v22 runtime and unchanged genuine workloads.
Fresh signed experimental offset7 (v25) fails on all five hosts: Val2 receives
a durable `closed_target` rejection; Val3/Val4/Val5/Val6 exceed the unchanged
30-second per-transaction finality budget during the30-transfer workload.
Initial single transfers pass on all five; none of these failed campaigns has
OOM or swap use. Public archives and envelope-correlated native availability
timings are retained in
`node-platform/target/resource-repair-lookahead7-host-evidence-v25-20261020/`.
The completed offset8 comparison (v26) fails the unchanged30-second loaded
transaction finality budget on all five hosts. Initial single transfers pass;
loaded finalized counts are19,6,0,2,9 on Val2 through Val6. Public manifests,
zero host/cgroup OOM deltas, zero swap and cleanup are independently checked in
`node-platform/target/resource-repair-lookahead8-host-evidence-v26-20261020/ANALYSIS.json`.
These diagnostic failures do not qualify healthy timing or activate a policy.
Further admission-window comparisons are paused for the remaining memory repair.

Native proposal timing hooks conservatively label all current observations
`recovered`; their source explicitly lacks healthy-cohort provenance. The
comparison reports observed latency only and cannot supply the required
healthy/worst-eligible p99 or50-percent admission headroom qualification by
relabeling those observations. This diagnostic limitation remains explicit.

## Memory qualification checkpoint — 2026-10-19 (v17–v20)

The final sealed v17 native candidate removes the consumed-state proof rewrite:
a small hash-chained durable transition replaces cloning and serializing the
full prepared record for a boolean change. Legacy frames, native verification,
original-byte indexes, atomic persistence and torn-tail recovery remain intact.
All39 ETDAG tests and strict targeted Clippy/format checks pass locally. Sealed
standalone SHA3-256:
`0613144c8d997965770e024297976e041fc9e6e1fe18d023d7dc63bcd700b565`.
Complete pre/post build source inventories match. Signing/Genesis companions
are byte-identical to v11. Other phase transitions still persist their bounded
current state; this repair does not remove every persistence write.

Actual Val2–Val6 hardware passes55 final-artifact component/native cases under
256MiB MemoryMax and zero swap (one39-test ETDAG suite plus ten native cases
per host); peak native RSS is131.61MiB. All25 final-artifact recovery/history
cases also pass. Each host verifies96,1024 and4096 generations with256KiB
authorizations,4096 generations with1MiB authorizations, and timeout-prefix
recovery. The maximum journal is8,891,619,937 bytes; peak native history RSS is
25.07MiB, with zero pending historical proof payloads and verified original
reads. Metadata is capped at4096 generation/marker entries; authorization size
is capped at1MiB. Cleanup is validated, every host/cgroup OOM delta is zero,
and swap remains unused. Val4 ZFS ARC is separately accounted (peak7.44GiB,
minimum available host memory110.04GiB); device io.stat cannot attribute ZFS
physical I/O. Four unchanged, exactly pinned libraries retain20 earlier passes;
old ETDAG artifacts receive no final-candidate qualification credit.

Final native full-process memory qualification passes on all five actual hosts
for the declared mixed campaigns. Val2/4/6 completed v18 with concurrent,
separately capped256MiB history pressure; Val3 completed fresh v19 against the
original ongoing history jobs. Val5 completed isolated v20 after validated
history cleanup. Each process unit runs five real validators at1GiB MemoryMax,
zero swap, signed experimental16 lookahead, four wallets, initial transfer plus
30 exact proof-verified transfers and all-five wallet effects within300s, then
stop531s/restart561s and681s total validator lifetime. The complete independent
public evidence audit passes all five, including original-signer stop before
replacement and matching advancing all-five commitments after restart.
Anonymous memory peaks are616.37–630.23MiB per five-validator unit. Four hosts
reach the1GiB cgroup cap and reclaim cache; every cgroup/host OOM delta is zero.
This demonstrates survival under the cap, not unused memory headroom or24-hour
stability. All five also pass the two native R4 exact retirement safety tests
under256MiB/zero swap. Six snapshot-cache pressure, reservation, active-custody,
lease/restart, incremental-cleanup and corrupt-input tests also pass on every
host under the same cap, with at most8MiB native RSS. Post-cleanup metadata confirms contiguous recent tails
of protected journals after hundreds of finalized heights; it does not claim
constant total chain storage or arbitrary-history support.

Failed campaigns remain failed: v18 Val3 stopped before initial transfer on a
bundled native telemetry identity/epoch/height check; source permits a null
finalized height before the first finalized state, but the original report
does not prove the exact invalid field. External v19 tooling adds only a
bounded wait for this valid null startup state, with strict immutable identity,
schema, five-validator finality and deadline checks retained (53 baseline tests
and23 runner tests pass). v18 Val5 finalized12 of16 submitted transfers before
its unchanged30s unresolved-finality budget expired; native finality continued
advancing together, with zero process-cap/OOM events. CPU/I/O contention was
observed, not proven causal. The separately declared v20 Val5 run starts only
after all original history jobs complete and their cgroups are proven empty;
it preserves the same artifact, caps, count, deadlines and restart schedule.
No all-five concurrent-pressure success is claimed.

Public archives, exact proof streams, sampled resource counters and independent
complete auditing are retained under
`node-platform/target/resource-repair-final-host-evidence-v18-20261019/`,
`node-platform/target/resource-repair-final-host-evidence-v19-20261019/` and
`node-platform/target/resource-repair-final-host-evidence-v20-20261019/`.
The complete mixed audit is `independent-audit-final.json` in the v20 directory;
R4 supplemental artifacts are in
`node-platform/target/resource-repair-final-host-r4-v17-20261019/`; snapshot-cache
artifacts are in `node-platform/target/resource-repair-final-host-cache-v17-20261019/`.

Default-lookahead5 funded ingress remains blocked by the reproduced admission
window failure. The experimental16 memory profile does not qualify default5,
production deployment, distributed canary, TPS/capacity or release Gate D/E.
No deployment, initial canary TPS baseline, ETDAG canary test or24-hour soak has
started. Capture the initial canary TPS baseline before tuning, then repeat the
same workload after stability. Earlier checkpoints below remain historical.

## Final memory candidate checkpoint — 2026-10-19 (v11)

Actual Val2–Val6 hardware passes75/75 capped component/native cases:25 cases
reuse the five unchanged, exactly pinned library artifacts;50 cases run the
final node test artifact SHA256
`25c0081f609f4dd8509f30802baef9002b4ca2c0eac1e7df037abef89cc495e1`.
All use256MiB MemoryMax and zero swap, with positive native test counts and
zero cgroup/host OOM events. Maximum native-test RSS is136.875MiB. Both stale
verified-head regressions pass on every host; strict same-height conflict
rejection remains intact. Complete build inventories match before/after;
standalone runtime SHA3-256 is
`2336bf66586f7786557049f086753dd7a9d4e92d38616832df1bae60088a0b02`.
Public archives and independently checked logs/hashes are retained under
`node-platform/target/resource-repair-final-host-evidence-v11-20261019/`,
including `summary-2-3-4-5-6.json`. Earlier checkpoints below remain historical.

The separate-process gate remains OPEN. All five v11 campaigns stopped at
funded-workload observation boundaries despite advancing native finality:
four report admission-context readiness unavailable; Val4 reports an ambiguous
admission response with receipt lookup unavailable. No OOM was observed;
aggregate cgroup peaks were487.32–576.13MiB under the declared1GiB cap. These
short failed runs do not qualify sustained load or restart/rejoin. The workload
harness is being corrected and ambiguous submission must be reconciled without
resubmission. Protected-growth and actual-host memory completion boxes remain
unchecked pending successful integrated qualification. No deployment, initial
canary TPS baseline, ETDAG canary test or24-hour soak has started.


## Five-host resource checkpoint — 2026-10-19

VERIFIED_ISOLATED on actual Val2–Val6 hardware:75/75 capped component/native
fixture cases passed (15 per host). Every case used256MiB MemoryMax with zero
swap; recorded cgroup OOM, OOM-kill and group-OOM counters are zero. This is
actual-hardware component evidence, not full-process production-chain closure.

The4096-generation/1MiB-authorization payload fixture wrote and recovered the
same8,891,619,937-byte append journal on each host. It preserves original bytes,
checks first/middle/latest indexed proofs, authenticates each generation exactly
once with the explicit fixture verifier and drains pending payloads. Peak process
RSS: Val2 24.61MiB, Val3 25.09MiB, Val4 21.26MiB, Val5 25.14MiB, Val6 24.86MiB.
Elapsed time448.4–608.2s includes generation, durable writes and recovery; no test
temporary payload remains. Linux page cache reached the256MiB cgroup cap on four
hosts and was reclaimed without OOM; process RSS is separately measured.
Val4's qualification filesystem is ZFS: its global ARC is outside process RSS
and may be outside cgroup file-cache accounting. Its successful unit cap is not
a whole-host cache bound. Final measurement tooling also records host available
RAM, swap, filesystem and ZFS ARC before/after/peak; no host ARC/VPN setting was
changed. The final Val4 ZFS repeat also passed:560.50s,20.77MiB process RSS,
minimum113.19GiB host available RAM, peak4.18GiB ARC, zero host/cgroup OOM,
no swap use and zero remaining temporary payload bytes. Its unchanged test
artifact recovered the same8,891,619,937-byte journal. This separately measures
whole-host cache behavior for this workload; the actual-process memory gate
remains open.
These padded-payload tests use a mock recovery verifier; native cryptography is
independently covered by the genuine signed R3 and socket fixtures.

The marker-cache node artifact
`991c72e6f3740efa9da9ee070846a5a1ac566d4c65ab1a340da0129cdf749189`
passed six cases per host:4097-context marker-cache bound/equivocation, genuine
signed R3, snapshot pressure/rebuild/restart, H16 restart/rejoin, outstanding Sync
restart/reordered prefetch and funded finality. Across all75 cases the maximum
process RSS was135.17MiB. Exact artifact pins, logs, RSS/cgroup memory, disk I/O,
remaining disk bytes and zero-OOM checks are retained under
`node-platform/target/resource-repair-protected-host-evidence-v6-20261019/summary.json`.

The compact PoSy timeout repair now passes70/70 final capped component/native
fixture cases on Val2–Val6 (five library suites and nine node cases per host).
All use256MiB MemoryMax, zero swap and zero cgroup/host OOM-kill counters.
Exact native-original retries,4096 compact references,15000-slot pagination,
historical recovery, R3, snapshot/rejoin/prefetch and funded finality pass.
Node test artifact SHA256:
`e52d50334a884b20c5d8e0d2eefcf7f03573a894feab6bf863fa8bc33f8b8736`.
The separate-process campaign has not qualified: native progression exposed a
false-fatal delayed verified-head notification in Sync (`current:13,received:12`;
another host observed18/17). The strict collector remains monotonic, but runtime
must ignore an already-native-verified stale observation without weakening
same-height conflict rejection. Final repair/requalification remains open.
No production deployment, canary TPS baseline or24-hour soak has started.

Operator direction: preserve an initial canary TPS baseline before tuning and
repeat the same workload after stabilization. The canonical completion checklist
records the comparable artifact/config/workload and acceptance/finality/resource
metrics; memory qualification remains first.

## Compact protected-recovery history — 2026-10-19

IMPLEMENTED / VALIDATED_LOCAL; ACTUAL_HOST_QUALIFICATION_IN_PROGRESS.
`ProtectedPipeline` now retains compact authenticated history identities and
journal byte locations rather than all original authorizations and signed
markers. Only the latest authorization remains resident per live target;
authenticated incremental recovery drains each frame before loading the next.
Required original evidence remains unchanged on disk. Selected-proof APIs use
bounded exact-frame seeks and digest/record checks; the bulk audit export refuses
more than16MiB. ETDAG marker admission and recovery acknowledgement consume
compact metadata. Source compatibility changes are internal; no wire proof,
quorum, signature, finality or governed cutoff relation changes.

`CutRecoveryVerifier` retains one authenticated round-zero ID ancestry per lease,
reuses a matching verified prefix and checks only new predecessor suffixes. It
publishes cache changes only after the exact signed V1 path-root match. The
existing native certificate summary cache remains bounded. Exact canonical V1
prefix hashing remains; an incremental hash would change signed bytes.

A final caller audit also found full peer cutoff-marker payloads retained across
obsolete generations in `EtdagService`. `CutMarkerCache` now retains only active
payloads plus compact authenticated historical signing-byte fingerprints. Frozen
membership/signature checks and historical equivocation rejection are preserved.
A4097-generation/five-signer regression passes with only five retained payloads;
the genuine signed R3 split/restart test and strict node/ETDAG Clippy pass after
this repair. Earlier node artifact results are not final qualification for this
additional change; the final node is being rebuilt and requalified.

Local evidence: the35-test ETDAG suite passed before the final additional indexed
corruption regression; that regression independently passes. The7 protected
recovery regressions include a near16MiB legacy snapshot with1136 generations,
96 appended256KiB authorization payloads/full16KiB signatures, bounded staged
recovery, unchanged originals, old-proof indexed retrieval and capped diagnostic
exports. Three timeout cache/prefix regressions pass, including all4096 original
summaries within the8MiB charged cache budget and exact identity/height/lease
matching. Native genuine-signature R3 split/restart passes in5.12s with direct
maximum RSS26,394,624 bytes after prefix reuse. Strict targeted Clippy passes.
These are scoped tests, not full production OOM closure.

An initial isolated Linux Val2 run passed all35 ETDAG tests under256MiB cgroup
memory with swap disabled, maximum process RSS106,404KiB. This predates the final
prefix/cache corruption additions and is preliminary evidence only. Exact final
Linux artifacts are being qualified through
`tools/validator/measure-posy-memory.py`: source/binary pins, cgroup memory caps,
RSS, anonymous/file memory, OOM counters, disk I/O and test logs are retained.
Val4 returned online after operator intervention and is now reached through
the validator VPN using the existing Val2 SSH master as a transport. All five
hosts are participating in isolated qualification. No validator service, production state,
keys, network configuration, release or canary chain has been changed.

Evidence prefix: `node-platform/target/resource-repair-protected-*20261019*`.
Protected memory source and actual-host qualification remain unchecked until the
exact integrated resource measurements and required recovery checks complete.

## Bounded snapshot cache — 2026-10-19

IMPLEMENTED / VALIDATED_LOCAL (scoped repair): Sync now owns
`services/sync_snapshot_cache.rs`, a disposable indexed cache limited to four
snapshot contexts and514MiB of conservative encoded-payload reservations. The
budget includes metadata and worst-case JSON byte encoding for two64MiB worlds;
it does not describe peak physical filesystem allocation or RSS. Local restore
accepts at most64 chunks and64MiB of world bytes. The existing1MiB producer fits
this profile. Unsupported authenticated peer snapshots fall back to canonical
candidate replay after unchanged signature/context checks; no consensus validity
rule, QC, finality, signer or governed parameter changes.

The durable active incoming transfer is pinned. Successful outgoing reads renew
a10-second inactivity lease, and indexed snapshots receive the same restart
grace. Full pinned capacity causes retryable backpressure; it cannot evict the
active incoming transfer or advance its received cursor. Cache lookup checks the
reserved content, canonical request binding and existing proof shape. Primary
proofs survive independently signed equivalent manifests. Eviction removes cache
records only; rebuilt snapshots require retained exact state and verified PoSy
finality. Outside retained history, old snapshots may be unavailable.

Legacy active custody is indexed before cleanup. Old/orphan payloads drain in
batches of at most64 removals per cache directory per poll; retained paths are
bounded by the index. Admission eviction handles at most260 exact paths. The old
backlog can temporarily exceed the new reservation budget while it drains.
Metadata/active records are capped at1MiB before decoding, each chunk read is
bounded by the manifest and remaining world budget, and restore collects at most
64 chunks. Cache index growth and decoded snapshots no longer scale with the
number of historical requested heights.

Local validation:19 Sync-owner tests (including six cache regressions),12
Storage tests and10 Sync-library tests pass; the Snapshot library compiles with
zero unit tests, so its functional evidence is the native snapshot qualification.
Strict targeted all-target Clippy passes. The cache tests cover
40 successive heights, eviction/rebuild/restart, failed-admission atomicity, byte pressure independently of
entry count, active incoming pinning, lease pressure/restart grace, incremental
legacy cleanup and corrupt/oversized data rejection. A native five-validator
snapshot-after-restart test passed in55.65s, including four live leased contexts,
backpressure on a fifth, lease expiry, verified eviction/rebuild and exact chunk/
root equality. Its direct maximum RSS was81,936,384 bytes; the test includes an
11-second wait to exercise the10-second cache lease, without changing product
timeouts. This short fixture is not production resource qualification.

A quota regression caught a transient refactor error that measured the original
entry list instead of the planned survivors. The failure is retained in
`resource-repair-snapshot-cache-sync-final-20261019.log`; the corrected selector
passes19 tests in `resource-repair-snapshot-cache-sync-qualified-20261019.log`.
Insufficient capacity now leaves all candidate victims and the index unchanged.

Evidence: `node-platform/target/resource-repair-snapshot-cache-{unit,sync,sync-final,sync-qualified,storage,libraries,clippy,clippy-qualified,native,native-qualified,rejoin,wallet}-20261019.log`.
H16 restart/rejoin passes in131.48s (direct maximum RSS98,418,688 bytes).
Native funded transfer passes in73.23s with all-five finalized balance/nonce/
transaction checks (direct maximum RSS99,844,096 bytes). Final native cache
pressure qualification after the selector correction passes in51.07s, with
matching rebuilt bytes/roots and direct maximum RSS84,180,992 bytes. These
short fixture observations do not establish production RSS or I/O scaling.
Aggregate protected
recovery and actual-host allocation/RSS/I/O/disk/fairness/soak gates remain open.
No source freeze, release, deployment or production OOM closure is claimed.


## Incremental candidate persistence — 2026-10-19

IMPLEMENTED / VALIDATED_LOCAL (scoped repair): shared
`synergy-execution::CandidateStore` atomically persists `SNCDV001` candidate
metadata and checkpoint/delta worlds using the finalized-world codec. Sequential
verified parent tips avoid repeated checkpoint traversal, and weak world
references do not retain extra allocations. Cold writers, legacy parents and
snapshot jumps seed independent checkpoints. Canonical wire candidates, block
commitments, protected-material validation and PoSy authority remain unchanged.
Execution, Sync, ETDAG retirement, RPC and R3 recovery use the shared reader.
Legacy inline files remain readable and identical replay preserves their bytes.
The64MiB full-candidate bound and R3's8MiB bound apply to reconstructed wire size;
consistent readers also cap metadata/legacy record allocations before decoding,
without shrinking the transaction recovery limit. World dependencies retain the
codec's64MiB record cap: a current world may fit the R3 limit after deleting
entries from a larger checkpoint. The reconstructed current wire limit is checked
again after replay.

Candidate retirement follows Execution's existing configured durable-finality
horizon. Dependency pruning advances only behind the actual metadata cleanup
cursor, preserving a checkpoint while a multi-batch backlog still has surviving
dependent records. Finalized history uses the same correction. Each namespace
still examines at most256 exact heights per call. No new retention horizon,
consensus owner, certificate, quorum or finality rule is introduced.

The70-height fixture retains213,854 candidate metadata/world payload bytes versus
4,657,660 bytes for its full inline candidates (about21.8x fewer). This is a
small retained-payload comparison, not physical filesystem I/O or a validator
RSS bound. Nine candidate-store regressions cover legacy/restart/wire identity,
checkpoint crossing, weak cache lifetime, caller wire limits, guarded concurrent
writers, corruption/missing dependencies, partial atomic transaction recovery
and pruning backlog safety. State adds canonical size/root compatibility and
verified cached-parent replay coverage.

Current library evidence: Execution16 (15-suite plus the shrinking-world regression), State16 and Storage11 pass; PoSy30 and
Sync-library10 also pass. Migrated ETDAG-owner8 and RPC7 pass. Native R3 recovery
passes for legacy and split retained candidates (4.13s; final reader-cap rerun4.54s). Native five-validator
restart/rejoin reaches matching H16 in106.13s with unchanged deadlines; the
direct process maximum RSS was93,896,704 bytes. Native funded transfer passed
in78.97s with all-five finalized balance/nonce/transaction checks; its direct
process maximum RSS was93,519,872 bytes. Missing-payload/outstanding-request restart and
reordered prefetch pass in199.89s (direct maximum RSS108,888,064 bytes), preserving
retained signing/certificate state and genuine socket-delivered candidate binding.
On-demand snapshot after restart also passes in40.64s
(direct maximum RSS81,149,952 bytes). These short fixture measurements
cannot establish comparative memory scaling or production OOM closure.

The first native candidate-delta run failed because ETDAG still decoded the new
metadata as full candidate JSON. That failed evidence is retained; all raw
runtime candidate readers were then migrated to the shared store. The restarted
missing-payload fixture now models absence of both atomic record parts.

Evidence under `node-platform/target/`:
`resource-repair-candidate-delta-{libraries,posy-sync,rejoin}-20261019.log` and
`resource-repair-candidate-readers-{library,bounded,shrinking-world,etdag-owner,rpc,r3,r3-final,rejoin,wallet,gap,snapshot,build,build-final,clippy}-20261019.log`.
All listed native checks passed against the integrated readers. At this candidate-
storage checkpoint, snapshot-cache bounds were still open; the subsequent section
above records that repair. Aggregate protected recovery and actual-host
RSS/I/O/disk/funded/soak gates remain open.
Older binaries cannot read new split candidate or world-delta records. No release,
deployment or production OOM fix is claimed.


## Resource amplification repairs — 2026-10-18

IMPLEMENTED / VALIDATED_LOCAL (scoped repairs): transaction diffs stage only touched
accounts and validate all protocol preconditions before mutation. Finalized
Execution-to-Sync acknowledgements retain compact commitments instead of up to64
full worlds; Execution yields before commit when that acknowledgement queue is
full. Sync materializes snapshots only for authenticated exact requests using
verified durable world bytes and PoSy finality, at most one request per poll.
Immutable storage writes borrow payloads; world compare-and-commit guards refer
to their same-path write instead of cloning its serialized world.

The next repair removes two additional full-world copies per block: the
speculative overlay borrows the existing immutable parent and transfers its
successful state into the outcome. Candidate handoffs share `Arc<WorldState>`;
canonical JSON, account roots and block commitments remain unchanged. Execution
keeps the finalized authorization world separately and advances it only after
durable finalized/snapshot commit, eliminating its per-candidate disk reload.

Configured history retirement now examines at most256 exact paths per namespace
per call and resumes with a durable cursor after restart. Cursor advancement
follows directory-synced deletion. Corrupt cursors/symlinks and ahead-of-durable
finality requests fail closed. The existing configured retention horizon applies.
Finalized state now has one64MiB storage owner; startup can recover world
transactions above the former4MiB metadata limit. An interrupted6MiB serialized
world transaction is replayed and verified by a new restart regression.

Validation:67 library tests passed (Storage10, State10, Execution7, PoSy30,
Sync10);13 Sync-owner and2 Execution-owner tests passed. Native on-demand snapshot
after restart passed at matching H6 without steady-state snapshot files, and the
five-validator restart/rejoin test passed through common H16 (128.68s). Total84
distinct scoped tests passed. Targeted all-target Clippy with `-D warnings`,
scoped rustfmt and diff whitespace checks passed. ExFAT emitted incremental-cache
hard-link fallback warnings, with no lint failures.

The additional native funded-wallet test initially FAILED the unchanged60s
no-matching-finality-progress assertion twice (88.15s/73.26s elapsed). The sampled
control run passed in134.57s, establishing a performance-sensitive boundary rather
than a deterministic transaction rejection. Stack samples located repeated
ETDAG encrypted-envelope serialization, identity verification and persistence
under retry traffic, plus cut construction during active owner reconciliation.

ETDAG now retains at most512 successfully processed announcement fingerprints,
bound to authenticated peer, session and exact payload digest. It retains no
payload bytes. Failed inputs are never cached. Artifact requests and custody
messages retain their full response/current-height path. The cache resets at
owner stop; cache misses, changed payloads, different peers and replacement
sessions still take full native authentication. Exact already-admitted remote
vertices and exact durable vertex replays also avoid redundant validation and
graph copying. New local admission retains its VC/closure linearization.

Validation after this change: all34 ETDAG library and8 ETDAG owner tests pass,
including fingerprint eviction/exactness/session bounds. Strict node/ETDAG
all-target Clippy passed. Native funded transfer passed in72.88s with the
unchanged deadline and all-five matching finalized balances/nonce/transaction
results. The first new run reached QC(H3) at22.3s versus waiting for QC(H3) at55.2s
in the isolated failure. These are small-fixture observations, not a production
latency guarantee. A second funded run passed in76.61s with the same deadline;
restart/rejoin then passed through matching H16 in100.91s. There are127 distinct
passing scoped tests across the resource-repair work (the prior84, ETDAG34,
ETDAG-owner8 and funded-transfer1); repeats are not counted again.

The failed local process peaked at81,592,320/80,494,592 RSS bytes; the successful
new runs peaked at94,388,224/94,552,064 bytes while reaching H6. The restart/rejoin
process peaked at96,206,848 bytes. These short runs at different
completion heights do not establish comparative memory scaling, a production RSS
bound, I/O scaling, throughput or soak completion.

Evidence under `node-platform/target/`:
`resource-repair-shared-state-{libraries,posy-sync,execution,sync,snapshot,rejoin,clippy}-20261018.log`,
`resource-repair-unified-state-recovery-20261018.log`,
`resource-repair-retention-20261018.log`, and
`resource-repair-funded-wallet-resource-20261018.log` and
`resource-repair-funded-wallet-isolated-20261018.log`.
New evidence: `resource-repair-funded-profile-{run,sample,advance-sample}-20261018.*`,
`resource-repair-etdag-dedupe-{unit,library,owner,clippy}-20261018.log`,
`resource-repair-funded-wallet-dedupe-20261018.log`,
`resource-repair-funded-wallet-dedupe-repeat-20261018.log` and
`resource-repair-etdag-dedupe-rejoin-20261018.log`. Earlier repair evidence
remains under the original `resource-repair-*-20261018.log` names.

Sequential finalized worlds now use `SNWDV001` checkpoint/delta records. Full
checkpoints retain legacy world JSON; deltas encode only changed/deleted accounts
and protocol entries. A fixed checkpoint every64 heights or an earlier8MiB
cumulative patch boundary caps replay at63 deltas and8MiB of encoded changes.
Serialization streams borrowed changes into the remaining budget without cloning
large payloads. Execution supplies its existing finalized parent; pointer, history
and world representation still commit atomically through the same storage owner.

Consistent dependent reads hold one writer lock across commitment/checkpoint/
deltas. Reconstruction verifies height/root links and the exact canonical world
root. Restart derives the delta budget from verified records. Snapshot consumers
receive canonical full-world JSON. Identical replay through the full-world API
preserves an existing delta. Retention keeps the fixed checkpoint interval needed
by surviving deltas, at most63 additional world records beyond the configured
boundary; history commitments keep the configured horizon. Snapshot jumps seed
new full checkpoints. Older binaries cannot read new delta records; rollback
against this data requires the updated reader.

The70-height regression stores152,132 world-record payload bytes compared with
4,596,478 bytes for serializing every corresponding full world (about30.2x fewer
payload bytes). This measures retained record payloads in a small fixture, not
physical filesystem writes, production I/O or comparative RSS. New regressions
cover checkpoint crossing, restart without preloading the world, byte-budget
rollover, legacy-parent/partially installed delta transaction recovery, snapshot
jump, identical replay, account/protocol deletion, missing/tampered dependencies,
wrong-parent rejection and pruning with retained dependencies. A storage concurrency
regression proves dependent reads retain their writer view.

Current validation:14 State and11 Storage tests pass, plus7 Execution,30 PoSy,
10 Sync-library,13 Sync-owner and2 Execution-owner tests. Native on-demand snapshot
after restart passed in40.65s; five-validator restart/rejoin reached matching H16
in102.13s, peaking at96,796,672 RSS bytes for that direct test process. The snapshot
command included compilation, so its aggregate maximum RSS is not a validator
measurement. Strict targeted all-target Clippy, scoped rustfmt and diff checks
pass. The native funded-wallet transfer also passed in72.49s with all-five
matching finalized balance/nonce/transaction checks and unchanged deadlines; its
direct process peaked at95,649,792 RSS bytes. These short small-fixture process
measurements do not establish production memory scaling or OOM closure. The
cumulative distinct scoped resource-repair test set is132; repeated runs are not
additional tests. Incremental candidate storage was still open at this2026-10-18 checkpoint; the2026-10-19 section records the subsequent repair.

New evidence: `resource-repair-world-delta-{libraries,execution,posy-sync,sync-owner,snapshot,rejoin,wallet,clippy,node-build}-20261018.log`.

No source revision freeze, commit/push, production release, deployment or actual-host
OOM closure is claimed; pre-existing source changes remain preserved. Remaining
accumulation paths and repair contracts are in `protocol/posy-v3/ARCHITECTURE.md`.


## Coordinated implementation checkpoint — 2026-10-13

IMPLEMENTED SOURCE / UNVERIFIED: the integrated source now contains independent
supervised owners for PoSy, ETDAG, Execution, Network, Sync and RPC; three reserved
preparation lanes with count/byte limits and live-pressure background suspension;
worker generation/authority/session fencing; confirmed worker shutdown before
epoch replacement; durable admission receipts and post-ack VC cutoff checks;
closed staged-journal reconstruction guards; native V2 source-finality evidence;
a persistent native signer and independent-wallet qualification client; native
accepted/ordered/executed/finalized throughput and bounded preparation latency/
queue observations; and Atlas publisher bindings to incarnation/process/commitment.

The isolated exporter now signs and natively verifies actual Genesis, binds its
initial world, validators, parameter/KEM policy and authority to the actual hash,
and retains synthetic fixture status. Native Genesis CLI verify-binding checks
both signatures and the exact initial-state/Genesis relationship. This source is
not a verified generated artifact yet. Experimental bootstrap schedules derive
from signed lookahead; legacy offset5 serialized schedule remains unchanged.

Release source records complete Git-visible build inputs and exact node/keytool/
Genesis binaries and blocks promotion without native qualification evidence.
Isolated quorum-fault source now requires three-validator halt, fourth-validator
restoration and fifth-validator later common commitments. Aggregate qualification,
canonical isolated setup and the reproducible seeded campaign are being completed.

Per operator instruction, no tests or builds of this integrated change set have
run. Source review identified and corrected stale peer-session completion and
admission/cutoff races; these corrections still require consolidated regression
and actual process evidence. No production artifact/configuration/state changed,
no measured production parameters selected, and TPS baseline/24-hour soak have
not started. The next boundary is completed source integration and freeze, then
consolidated checks, exact Linux bytes, genuine funded/fault/timing qualification,
explicit concrete parameter approval, five-host qualification and TPS.

## Operator scope refinement — 2026-10-13

PLANNED / IMPLEMENTATION IN PROGRESS / UNVERIFIED: the canonical architecture
and completion checklist now include the shared address, signed-domain,
authorization, nonce/fee/revert, custody and profile-version requirements from
the three supplied architecture blueprints. The operator confirmed the immediate
objective is chain stability, validator recovery and encrypted ETDAG processing;
new system-contract deployment and new protected-wallet/multisig profiles are
not soak prerequisites. Confirm actual Genesis dependencies before freezing.

Tests/builds remain paused until coordinated source changes are complete.
Baseline and24-hour soak remain unstarted; this plan update is not evidence of
implementation completion, passing qualification or live activation. Deferred
features may be developed in isolation after the soak starts, without changing
the soaking artifact/configuration or claiming its results qualify those features.

## Independent scheduling review and funded diagnostics — 2026-10-12

**Gate A OPEN.** The operator requested a comparative asynchronous transaction scheduling design. The canonical architecture and execution checklist now compare F+5, measured larger lookahead and durable encrypted ingress/eligible-batch queues. This adds a design decision and executable scheduling contracts; it does not activate new authorization or eligibility semantics.

Two retained-state diagnostic runs completed with matching all-five finalized H249 and H412. Both genuine native-signed transfer attempts were rejected at submission because their target closed. First target window300.661ms; optimized same-namespace client at target278 had context65.920ms, signing18.211ms, full rejected response526.156ms versus338.685ms open window. No transaction was durably admitted or finalized. Evidence: `dev:/tmp/posy-isolated-measurements-20261012/process-observations-{6,7}.json`, `transfer-run-{6,7}/result.json` or `client-result.json`, and node `timing-transfer{1,2}.jsonl`. Only client keytool selection changed: transaction authority is selected by verified role/key semantics rather than principal label; three regression tests, strict Clippy and Linux keytool build passed. Consensus node artifact remained unchanged.

An initial executable scheduling contract model and seven deterministic regressions now cover both cutoff/admission event orders, target immutability, retained closed state across restart, duplicate/nonce replay, expiry/backpressure, below-quorum availability, delayed reveal, three-QC finality and rejection of uncertified empty fallback. This is a Gate A abstract model with verified authorization/evidence as explicit assumptions, not genuine-crypto protocol qualification; fairness/retention and full fault coverage remain open. Files: `node-platform/tools/validator/model-posy-admission-scheduling.py` and `test_model_posy_admission_scheduling.py`. Original remediation DOCX updated in place with the independent scheduling adjustment; rendered29pages, revised pages visually checked, no alternate DOCX created.

Further independent subagent work stopped when the collaboration service returned “Your workspace is out of credits.” Root completed the scoped plan/model checkpoints above; no additional qualification or approval is implied.

TPS baseline and24-hour loaded soak have not started. Remaining entry work is measured scheduling design, concrete amendment review where required, integrated implementation, model/exact-byte and five-host funded recovery qualification, and baseline.

## Isolated Linux measurement checkpoint — 2026-10-12

**VERIFIED_DIAGNOSTIC / Gate A OPEN.** Direct key-only SSH to `dev` and privileged isolated namespaces are working. The Desktop credentials workbook was updated in place; no workbook copy was made. A diagnostic Linux native node artifact (`SHA3-256 c9aba7ec9a2ecad00130989827ca783ab647afa96d63289db37b77526b3444db`) executed with genuine synthetic consensus/transport keys and retained signing journals.

The original shared-namespace fixture selected one validator's IP for all outbound TCP connections, violating authenticated peer-route bindings. Replacing that fixture topology with five distinct namespaces/IPs preserved the native authentication checks and existing journals. A bounded 60-second resume completed with all five at finalized H93 and identical block ID `b5972115f5c1782269fef915cfc74013753df2691fd0d07a483adb575c57ab34` and state root `474a6990c692579c0345e463ade0a1faba469cbe9af6c9405fd9e04dc3b77eaf`. The owned processes were stopped after the measurement interval. This is a fixture correction, not a production-chain diagnosis or deployed recovery fix.

Evidence: `dev:/tmp/posy-isolated-measurements-20261012/process-observations-5.json`, `process-run-5.log`, and per-node `timing-resume1.jsonl`; local generated reducer report `node-platform/target/posy-isolated-control-20261012/linux-resume-measurements.json`. The reducer retains recovered/observed classifications and reports insufficient healthy/client-origin coverage. No production timing profile is selected. The fixture uses simulated VPN-provider status and placeholder Genesis anchors, so this run does not close exact-artifact or five-host qualification gates. Funded transfer, native client-path measurements, reviewed amendment, TPS and loaded soak remain pending.

## Approved architecture plan checkpoint — 2026-10-11

**PLANNED / Gate A OPEN.** The operator approved plan implementation, beginning with design measurements, dependency/ownership graph, executable contracts and a reviewed concrete amendment proposal. Current authorized work is canonical document/checklist updates and Gate A measurements. No new architecture implementation, protocol activation, Linux artifact qualification, live deployment or TPS qualification is claimed by this checkpoint.

Historical seq19 rolling deployment passed; the subsequent baseline rejected the first transaction at admission cutoff. A successful loaded baseline and sustained stability remain unproved. Historical seq18 live below-quorum recovery passed, separately from new-architecture qualification.

The exact pending A–H execution sequence and owners are maintained in [NODE_ARCHITECTURE_COMPLETION_CHECKLIST.md](NODE_ARCHITECTURE_COMPLETION_CHECKLIST.md): A design; B integrated implementation; C executable model and deterministic faults with 10,000 seeds; D pinned Rust 1.97 locked Linux build and exact-byte full-process qualification; E five-host funded-transfer/recovery qualification; F first transfer, 1 TPS short/10-minute baseline, doubling two-minute capacity rungs and highest-clean 10-minute validation; G 24-hour loaded fault soak, review, then seven days if clean; H separately approved Val1 cutover. All gates remain unchecked until recorded evidence satisfies them.

Protocol semantic amendments require explicit concrete approval before activation. Cadence and capacity budgets follow measured evidence; no fixed cadence target or generator cap is treated as proof of architecture completion. Existing sections below are historical evidence and retain their original scope.


## Protected crypto and custody checkpoint — 2026-10-09 UTC

IMPLEMENTED / VALIDATED_LOCAL: governed ML-KEM-1024 + AES-256-GCM + Shamir consumer, separate consensus/ingress key roles, exact target/registry/membership verification, AES tag-aware canonical padding, optional absolute custody path schema, explicit generate-etdag-1024 command, and signed-policy key coverage checks. Scoped package tests passed: ETDAG18, client1, config4, keytool7, Genesis1. Durable nonempty preparation/recovery hooks are implemented; runtime share delivery and its new integration regression remain in progress. No fresh signed artifacts, deployment, live finality, or Val1 conversion is claimed. The prior Linux binary predates these crypto changes and is not the current deployable candidate. The operator approved the cutoff clarification on2026-10-08; signed policy activation and runtime integration remain in progress.

## Parallel fresh-chain implementation checkpoint — 2026-10-08

IMPLEMENTED / VALIDATED_LOCAL: governed ECHO/READY validation; immutable historical VC delivery; exact signature replay, height-wide vote guards and finalized-floor journal compaction; signed protected epoch policy; verified durable finality lookup; durable ETDAG collecting/VAC/cutoff integration; typed authority/release signing. Combined53tests passed, then five additional distinct restart/queue/Sync regressions passed. Four existing bounded-router tests passed. Strict Clippy passed for PoSy/ETDAG/Genesis/keytool/updater; node all-target Clippy passed with only the two intentionally unwired protected-material methods warning. Linux x86-64 release build passed; current SHA256 f83774e08d38634919d13d80ae392c79de68156a2c3ade792f6c938b8be4c9e6. No deployment or complete protected socket qualification is claimed. Cutoff clarification remains pending explicit approval; H/H+1/H+2 material integration and nonempty threshold reveal remain open.

## Verified continuation — 2026-10-08

PoSy service delivery now retains signed retries, treats queue saturation as backpressure, fairly resumes queued peer delivery, and rejects invalid/stale peer traffic without failing the service. Sync follows takeover certificate chains across leader leases. Real ML-DSA service qualification covers loss, reordering, one validator offline, catch-up and durable restart. These tests use deterministic execution fixtures; protected ETDAG production and real socket/deployment qualification remain OPEN.

Launch-critical migration gap: replace obsolete batch-certificate handoff dependence with governed cutoff evidence, deterministic cut/order and exact PoSy parent reveal authorization; bind H/H+1/H+2 commitments into proposal/material verification. Do not add a batch-vote engine or relax protected execution.

Source repair and selected tests are verified; source-ownership completion is not launch completion. Missing protected-material production, signed fresh-network artifacts, Linux deployment, and five-node finality qualification remain OPEN.

Evidence and diagnostic corrections: `networks/testnet-v3/CHAIN_1266_STALL_LOG.md`, incident C1266-2026-10-08-002. The operator confirmed a completely fresh replacement chain. Older entries below are historical.


> **Canonical repository ledger:** `docs/refactor/IMPLEMENTATION_STATUS.md` is
> the one canonical version. Every canonical clone contains this same tracked
> file. Update it in place and never create alternate, renamed, or divergent
> copies. An absolute checkout path never defines canonical file identity.

Updated: 2026-09-15. `COMPLETE` means the production responsibility is
implemented. It does not mean tested, integrated, network-verified, or release
qualified. Those states are intentionally tracked separately after migration.
The implementation phase remains incomplete while required production files,
callers, or legacy ownership remain open.

## Migration-phase governing state

Core Protocol root migration (2026-09-15): the canonical workspace was moved
in place on Val4 from `01-Core-Protocol/testnet-v3/node-platform/` to
`01-Core-Protocol/node-platform/`. The former Testnet-v3 repository is now
`01-Core-Protocol/networks/testnet-v3/`, Git ownership is rooted at
`01-Core-Protocol/`, and sibling `networks/`, `protocol/`, and `tooling/`
directories exist. There is one node-platform tree. Path-consumer repair,
network/protocol/tooling redistribution, generated-artifact cleanup, and Git
tracking reconciliation remain in progress.

Runtime completion sprint (2026-09-12): the universal service graph now connects governed Aegis Network -> verified Sync -> ETDAG H+5 certification -> deterministic Execution -> the single PoSy proposal/vote/QC/TC/finality owner. Source was formatted; build, tests, and live qualification remain Phase 2 and were not run in this sprint.

Current reconciliation (2026-09-15): the persistent production-source queue is
100% implemented. The latest direct Val4 source also wires the concrete
SynQ/PQSynQ/AIVM, SXCP/UMA, governance, and supported system-action execution
providers; trust-root-signed cross-epoch Sync handoff; and authenticated ETDAG
shard request/response serving with durable custody. This is source evidence,
not build, test, deployment, or production-readiness evidence. The canonical
completion checklist currently contains 125 complete, 30 partial, and 159 open
items, for **44.6% weighted overall completion** (`complete = 1`, `partial =
0.5`). The target file-tree ledger is **68.4% weighted complete** (984 complete,
66 partial, 436 open); it measures file-level ownership and must not be used as
a substitute for caller migration or legacy retirement.

Active correction wave (2026-09-15): the canonical PoSy simplification audit
now exists at `protocol/posy-v3/PO_SY_SIMPLIFICATION_AUDIT.md`. The public
validator Admin/CLI boundary is being migrated from the ambiguous
`validator_id`/`--validator-id` name to a validated canonical `NodeAddress` and
`--node-address`; internal PoSy `ValidatorId` values remain canonical
NodeAddress aliases, not a second identity. The ordinary-wallet ETDAG admission
wire contract is also being corrected to carry and sign chain/network context,
wallet address, nonce, algorithm, presented public key, and the complete
encrypted-envelope commitment. These newest edits are in progress and have not
yet passed a focused build/test gate, so they are not recorded as complete.


| Gate | Status | Current implementation boundary |
| --- | --- | --- |
| Canonical Core Protocol root | MOVED; RECONCILING | The only runtime tree is `/home/node/Synergy-Network/01-Core-Protocol/node-platform`; the Git root is `/home/node/Synergy-Network/01-Core-Protocol`. Network/protocol/tooling redistribution and path-consumer repair remain. |
| Canonical runtime | IMPLEMENTED (source), CALLERS MIGRATING | `node-platform/bin/synergy-node` loads canonical configuration and authority, registers the complete configured identity/storage/network/sync/Admin/ETDAG/execution/PoSy/RPC/WS/VPN/Sentry/telemetry/health graph, supervises it, and shuts it down in reverse order. Legacy runtime retirement remains separate. |
| Node Address terminology | PARTIAL; ACTIVE CUTOVER | The typed validator Admin operation and CLI are being changed to validated `NodeAddress`/`--node-address`; `--validator-id` is no longer the intended public node-identity option. Remaining production `NodeId`, ambiguous validator/peer fields, persistence, networking, telemetry, GUI, and legacy callers still require classification and migration. `NodeID` remains reserved for a human-readable `.node` alias. |
| Synergy Naming System NodeID | IMPLEMENTED, CALLERS MIGRATING | `synergy-naming` owns normalized `.node` aliases and no ownership state. The production native dispatcher applies register/rename to canonical `WorldState.protocol`, which becomes authoritative only through PoSy finality; Admin/CLI read finalized state or prepare the same wallet-signed action. GUI/RPC/WS/protected-submission and legacy callers remain. |
| Node owner wallet | IMPLEMENTED, CALLERS MIGRATING | `synergy-node-ownership` owns NodeAddress→wallet state. Production execution enforces transaction sender/public-key binding, detached Aegis node possession, and replacement-owner acceptance; Admin/CLI cannot establish ownership locally. Onboarding/GUI/protected-submission and legacy callers remain. |
| Reward withdrawal authorization | IMPLEMENTED, CALLERS MIGRATING | `synergy-rewards` owns NodeAddress-keyed accounting. Production execution authorizes withdrawal against canonical current ownership and commits only through PoSy finality; Admin/CLI inspect or prepare but do not mutate. Reward producers, GUI/protected-submission, audit, and legacy callers remain. |
| Exact CLI/GUI capability parity | PARTIAL | A shared typed Admin foundation exists, but the machine-readable registry and full CLI/Control Panel operation equality are incomplete. |
| Automatic signed updater | OPEN | Signed discovery/staging/verification/drain/restart/health/rollback/activation-aware ownership is not implemented. |
| PoSy simplification | PARTIAL | One new driver exists and the canonical audit now classifies retained mechanisms by safety/liveness/membership/recovery invariant and prohibits derived legacy complexity. The retained-mechanism dependency map, caller/state/wire proof, and evidence-backed removals remain. |
| Legacy artifact compatibility | NOT REQUIRED | Old Genesis, wire bytes, validator-set schema, persistence layout, configuration layout, and release layout are not migration blockers. Preserve semantics and security invariants only. |
| Existing validator deployment | DEFERRED | The failed old-network deployment is not the migration target and must remain untouched during software migration. |
| Build/test/debug/hardening | REQUIRED AFTER SOURCE MIGRATION | Run only after source/path/caller/legacy reconciliation, then record exact static, unit, integration, restart, upgrade, and acceptance evidence. |
| Network artifacts | RECONCILING | Move only existing governed network-specific artifacts under `networks/<network>`; do not fabricate mainnet/mainnet-beta values or alter live deployment state. |

| Launch class | Area | Status | Evidence / remaining boundary |
| --- | --- | --- | --- |
| POST-LAUNCH | Architecture inventory | COMPLETE | Current/target/migration/audit documents in `docs/refactor/`. |
| P0-LAUNCH | Common protocol/config types | IN PROGRESS | Shared node-core/Admin types and complete canonical config schema/validation exist; manifest, identity, and broader protocol callers remain. |
| P0-LAUNCH | Aegis cryptography engine and shared facade | IMPLEMENTED (source), CALLERS MIGRATING | `synergy-aegis` is the single engine/provider owner over required Aegis modules. `synergy-crypto` is protocol-neutral facade only and has no raw PQVM dependency. Network, ETDAG/DA, PoSy, SynQ/PQSynQ, SXCP, UMA, snapshot, and governance production paths now use the Aegis engine/provider boundary; remaining legacy hash and utility callers still require targeted retirement. |
| P0-LAUNCH | Canonical Synergy address engine | IMPLEMENTED, CALLERS_MIGRATED | `synergy-address` owns SNTS-01/Address Engine v1 derivation and Bech32m validation, and `synergy-transaction` delegates sender/receiver admission to that owner. Validator identity and transport route identifiers are governed identifiers, not Synergy payment addresses, and therefore are not address-engine caller gaps. Legacy address ownership still requires retirement. |
| P1-LAUNCH | Naming, node ownership, and rewards | IMPLEMENTED, CALLERS MIGRATING | The three owners run through the canonical native execution overlay and PoSy-finalized world-state commit. Shared Admin/CLI callers inspect finalized state or prepare exact wallet-signed actions without local mutation. Ten focused crate tests and a focused `synergy-node` check pass; protected submission, reward producers, GUI/RPC/WS, legacy retirement, and Phase 2 acceptance remain. |
| P0-LAUNCH | Genesis utility | IMPLEMENTED (source) | Canonical Chain 1266 network/validator/ETDAG/state/authority bindings, deterministic hashing, governed ML-DSA-65 signing, and PQVM verification are implemented; schemas, ceremony artifacts, and Phase 2 qualification remain. |
| P0-LAUNCH | Offline key lifecycle | IMPLEMENTED (source) | synergy-keytool generates non-overwriting ML-DSA-65 node/consensus and ML-KEM-768 ETDAG bundles with 0600 secret custody, validates public metadata, and emits rotation plans without changing membership authority; provider/recovery tests remain Phase 2. |
| P0-LAUNCH | Network manifest CLI | IMPLEMENTED (source) | Strict canonical Chain 1266 bindings, deterministic hashing, governed ML-DSA-65 signing/PQVM verification, safe inspection, and bounded diff tooling are implemented; full library/schema/runtime caller migration and Phase 2 artifacts remain. |
| P0-LAUNCH | Unified node core | IMPLEMENTED (runtime batch), CALLERS MIGRATING | `synergy-node-core` owns lifecycle/management types, dependency-ordered supervision, bounded restart, health/fail-closed inspection, cancellation, and reverse shutdown; `synergy-node` is a real caller. Legacy runtime retirement remains. |
| P0-LAUNCH | Supervisor/lifecycle | IMPLEMENTED (runtime batch), CALLERS MIGRATING | Canonical dependency supervision, lifecycle/evidence transitions, complete configured service registration, retained run loop, and reverse shutdown are wired into `synergy-node`; remaining work is legacy caller retirement and Phase 2 qualification. |
| POST-LAUNCH | Governance library | IMPLEMENTED, CALLERS_MIGRATED | Constitutional rules, proposals, independently verified frozen-authority Aegis approvals, threshold authorization, delayed activation, exact payload/action binding, bounded emergency authority, and audit contracts are populated. The execution dispatcher now has a concrete governance provider and a narrow governance-delegating system provider; legacy retirement remains. |
| POST-LAUNCH | Data availability library | IMPLEMENTED, CALLERS_MIGRATED | Bounded Aegis-facade shard commitments, governed proof verification, serving, audit, and retention ownership are populated. The node ETDAG service now owns authenticated custody admission, finalized-height retention, authenticated bounded shard requests, durable lookup, signed response serving, receiver re-verification, and conflict-safe re-admission. Legacy ownership retirement remains. |
| POST-LAUNCH | AIVM sandbox | IMPLEMENTED, CALLERS_MIGRATED FOR SYNQ | Deterministic sandbox policy, resource budgets, bounded module/input validation, output commitments, runtime engine boundary, and metrics are populated. `CanonicalSynqRuntime` executes the supported deterministic QVM instruction set with bounded gas; unsupported cryptographic/KEM opcodes fail closed pending an injected Aegis provider. Other standalone AIVM role callers and Phase 2 qualification remain. |
| POST-LAUNCH | AI workload contracts | IMPLEMENTED (source) | Authority-neutral capability, job/policy/provider admission, bounded compute, deterministic coordination, data provenance, receipts, metrics, and independent assurance owners are populated; runtime providers and qualification remain. |
| POST-LAUNCH | Role/capability architecture | IMPLEMENTED (source), CALLERS MIGRATING | Typed role/capability/service-graph ownership exists and `synergy-node` validates its configured service declaration through `synergy-roles`; role-specific runtime providers and legacy caller retirement remain. |
| P1-LAUNCH | Admin API | IMPLEMENTED (read, validator lifecycle, node-state query/preparation), CALLERS MIGRATING | The owner-local dispatcher reads canonical finalized ownership/naming/reward state and prepares the exact native actions accepted by execution. It explicitly reports that it did not mutate state and requires wallet-signed protected ETDAG submission. Audit persistence, submission, remaining operation groups, and remaining clients are separate. |
| P0-LAUNCH | CLI | IN PROGRESS | First-class `synergy-node` exposes ownership inspect/claim/transfer preparation, naming resolve/reverse/availability/register/rename preparation, and reward account/withdrawal inspection/preparation through the shared Admin operation enum. Protected submission, broader mutation/audit, and remaining subsystem handlers remain. |
| POST-LAUNCH | Node Control Panel | IN PROGRESS | Uses the shared local Admin API for read operations; operation parity incomplete. |
| P0-LAUNCH | P2P transport | IMPLEMENTED (runtime batch) | Governed PQVM mutual handshake, exact sessions, authenticated frames, replay refusal, listener/dialer shutdown, bounded fair routing, and protocol egress are owned by the universal node. |
| P0-LAUNCH | Handshake | IMPLEMENTED (runtime batch) | Inbound/outbound challenge transcripts, chain identity, governed key bindings, PQVM signing/verification, peer admission, and exact session establishment are wired. |
| P0-LAUNCH | Peer lifecycle | SOURCE IMPLEMENTED | Exact-session manager, legal states, health, score, limits, quarantine/ban, duplicate resolution, persistence boundary, and bounded retry are implemented; runtime socket callers and jitter remain. |
| P0-LAUNCH | Discovery | SOURCE IMPLEMENTED | Prioritized bootseeds, DNS candidates, validated peer exchange, signed-registry boundary, and bounded expiring cache are implemented; resolver/runtime callers remain. |
| P0-LAUNCH | Message routing | SOURCE IMPLEMENTED | Bounded fair per-peer routing, watermarked backpressure, protocol handlers, and attempt/capacity-bounded retransmission are implemented; runtime dispatch callers remain. |
| P0-LAUNCH | VPN routing | IMPLEMENTED, CALLERS MIGRATING | Validator/Sentry route scopes, signed leases, exact peer binding, NetBird control/readiness, and metrics are implemented. The universal node verifies pinned signed registry state, observes NetBird, and schedules bounded authenticated dials; enrollment/lease publication and deployment bindings remain. |
| P0-LAUNCH | VPN enrollment | SOURCE IMPLEMENTED | Challenge/proof/eligibility/authorization/response/resume/revocation owners exist with redacted credential diagnostics; broker endpoint, zeroization, and runtime orchestration remain. |
| P0-LAUNCH | Transport registry | IMPLEMENTED, CALLERS MIGRATING | Signed verification, atomic cache, generation/equivocation/rollback control, leases, revocation, reconciliation, custody boundary, and registry state are implemented. Universal-node callers now pin trust, verify local snapshots, require active-authority coverage, persist accepted generations, and enforce signed routes during authentication; remote fetch, deployment bindings, and legacy retirement remain. |
| P0-LAUNCH | Block/head/state sync | IMPLEMENTED, CALLERS_MIGRATED | Authenticated verified heads select sources; sequential parent-anchored responses carry complete candidate transactions, receipts, and account state with bounded verified-source failover. PoSy verifies/replays the three-QC and required timeout evidence through its one driver, Execution recomputes the transition before finality-gated persistence, and a trust-root-signed successor authority binding is admitted only after the exact epoch-end three-QC witness and anchor are verified and durably committed. Legacy ownership retirement remains. |
| P0-LAUNCH | Snapshot sync | IMPLEMENTED, CALLERS_MIGRATED | Finality-bound manifest/chunk build and Aegis verification are wired through Sync; chunk requests/responses persist conflict-safely with resumable acquisition, verified restore handoff, execution snapshot commit/receipt, finalized publication, and successor-epoch graph reconstruction. Configured external object-store publication is still open; deployment qualification is Phase 2. |
| P0-LAUNCH | PoSy isolation | IMPLEMENTED (runtime batch), CALLERS_MIGRATED, LEGACY REMAINS | The new-platform `PosyService` owns governed authority binding, proposal/vote/QC/TC/three-QC-finality progression, authenticated ingress/egress, verified QC/TC persistence before broadcast, three-QC Sync witness verification, and execution-candidate handoff through one driver. A validator cannot vote until the signed proposal matches locally executed ETDAG material; early valid proposals wait for the candidate. Verified restart replay and successor-epoch two-QC-tail continuity are wired; legacy retirement remains. |
| P0-LAUNCH | PoSy persistence | IMPLEMENTED (runtime batch), CALLERS MIGRATING | Proposal/vote/prepared/QC/TC/finality and durable sign-once ownership are wired into `PosyService`; exact-slot TCs and per-height QCs are independently reverified during startup. Cross-process writer ownership and multi-record crash atomicity remain. |
| P0-LAUNCH | PoSy recovery | IMPLEMENTED, CALLERS_MIGRATED | Checkpoint validation, authenticated peer reports, strict count+non-uniform-weight recovery quorum, fail-closed reconciliation, runtime signing-gate ownership, verified QC/TC replay, exact committed three-QC finality, and successor-epoch transition recovery are wired. Cross-process writer ownership, multi-record crash atomicity, legacy retirement, and Phase 2 qualification remain. |
| P0-LAUNCH | Validator membership/epochs | IMPLEMENTED, CALLERS_MIGRATED, LEGACY REMAINS | Admin and CLI lifecycle mutations, durable reload, activation/deactivation, jailing, expulsion, removal, slashing, frozen-authority reconciliation, future-epoch registry construction, and trust-root-signed epoch activation route through `synergy-validator-management`/PoSy authority ownership. The authoritative numeric shadow-duration requirement and legacy retirement remain separately open. |
| P0-LAUNCH | ETDAG extraction | IMPLEMENTED (runtime batch) | Authenticated validator messages, DAG/availability/order certificates, reveal/batch validation, current-finality H+5 context, and execution handoff are wired through the PQ authority owner. |
| P0-LAUNCH | ETDAG persistence | SOURCE IMPLEMENTED | Atomic admission, encrypted-input, DAG, certificate, sign-once safety, and no-plaintext reveal stores plus bounded reconciliation/replay are implemented; multi-record transactions, live callers, and crash verification remain. |
| P0-LAUNCH | Transaction/block/execution | IMPLEMENTED, CALLERS_MIGRATED | Certified ETDAG batches decode bounded signed transactions, verify them through the Aegis/PQVM boundary, route every supported action through concrete native, SynQ/PQSynQ/AIVM, SXCP/UMA, governance, or supported system providers, produce receipts/state/block candidates, feed PoSy, and commit only matching finality. Candidates persist before PoSy publication and QC-bound candidates are re-executed on restart. Native external-chain proof adapters, ordinary-user transaction ingress, state proofs, cross-process safety, and legacy retirement remain. |
| P0-LAUNCH | Storage hardening | IN PROGRESS | Atomic bounded-file and integrity-bound WAL paths plus the configured critical `StorageService` caller exist; multi-file transactions, remaining safety-store cutover, injected fsync/disk failures, and pruning/migrations remain. |
| P1-LAUNCH | Telemetry | IMPLEMENTED (runtime batch), CALLERS MIGRATING | A configured supervised telemetry service and canonical subsystem metric owners exist; exporter/provider completeness and legacy caller retirement remain. |
| P0-LAUNCH | Readiness/health | IMPLEMENTED (runtime batch), CALLERS MIGRATING | Typed readiness evidence, supervised health observations, runtime snapshot publication, and role/service gates are wired; Phase 2 release criteria and legacy caller retirement remain. |
| P0-LAUNCH | Doctor diagnostics | IN PROGRESS | Typed diagnostic report exists; live network/storage diagnostics remain. |
| POST-LAUNCH | All supported node roles | NOT STARTED | Per-role completion remains. |
| POST-LAUNCH | Community validator onboarding | NOT STARTED | Required zero-touch acceptance scenario remains. |
| P0-LAUNCH | Crash/recovery tests | UNVERIFIED | Test-only stripped/non-incremental Cargo profile now permits focused runtime tests; crash/recovery suite has not yet executed. |
| P0-LAUNCH | Partition tests | NOT STARTED | Deterministic network simulation remains. |
| P1-LAUNCH | Upgrade tests | NOT STARTED | Mixed-version/upgrade coverage remains. |
| POST-LAUNCH | Soak tests | NOT STARTED | Multi-node stability validation remains. |

## EXPEDITED CRITICAL PATH

| # | Dependency | Status | Blocker | Next action | Tests | Dependent phases |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | Common types/config/manifest/identity | CALLERS MIGRATING | Canonical config, manifest, identity, and protocol-type source owners exist; `synergy-node start` loads config and public identity. Broader subsystem callers and legacy aggregate retirement remain. | Migrate the remaining subsystem callers without reintroducing runtime-local types. | Phase 2. | 2–15 |
| 2 | Node supervisor/lifecycle | IMPLEMENTED (runtime batch) | The canonical supervisor and retained process loop register every configured production service and fail closed on incomplete coverage. | Retire legacy startup ownership only after caller migration is proven. | Phase 2 verification deferred. | 3–15 |
| 3 | P2P decomposition | IMPLEMENTED (runtime batch) | TCP listener/dialer, governed PQVM handshake/framing, exact sessions/replay refusal, peer admission, bounded routing, protocol adapters, and new-node `NetworkService` wiring exist. | Continue discovery/registry/VPN caller completion and retire legacy networking ownership only after proof. | Phase 2 verification deferred. | 4–15 |
| 4 | Sentry/VPN/transport registry | CALLERS MIGRATING | Source owners and conditional runtime registration exist. Pinned signed-registry verification/install, rollback-resistant cache, authority coverage, authenticated route admission, and bounded dial scheduling are wired; remote fetch, lease publication, enrollment broker, deployment bindings, and legacy retirement remain. | Connect enrollment/lease publication and deployment inputs without generating Phase 2 artifacts. | New caller verification deferred to Phase 2. | 5, 6, 14, 15 |
| 5 | Verified sync | IMPLEMENTED, CALLERS_MIGRATED | Authenticated heads, source selection, finality advertisement, bounded verified-source failover, sequential finalized candidate/state transport, snapshot chunk/resume, durable request recovery, and trust-root-signed epoch crossing are wired. PoSy verifies and replays QC/TC evidence; Execution validates commitments, re-executes transactions, persists candidates, and commits matching state. | Retire legacy Sync ownership; configured external archive/object-store integration is separate. | New caller verification deferred to Phase 2. | 6, 7, 14, 15 |
| 6 | PoSy isolation | IMPLEMENTED (runtime batch), CALLERS_MIGRATED, LEGACY REMAINS | Governed authority, authenticated transport, durable signing, proposal/vote/QC/TC/three-QC-finality, execution handoff, and verified successor-epoch reconstruction are wired through one `PosyService` driver. | Retire legacy ownership and close the remaining cross-process persistence boundaries. | Historical focused coverage exists; no current migration gate. | 7–15 |
| 7 | PoSy persistence/recovery | CALLERS MIGRATING | Canonical stores, sign-once authority, checkpoints, quorum reconciliation, verified QC/TC replay, exact durable-finality matching, and runtime signing gate are wired; cross-process writer ownership, speculative execution recovery, and multi-record crash atomicity remain. | Complete the remaining durable recovery callers before legacy retirement. | Phase 2 verification deferred. | 8, 14, 15 |
| 8 | Validator membership/epochs | IMPLEMENTED, CALLERS_MIGRATED, LEGACY REMAINS | Durable Admin/CLI lifecycle transitions, frozen-authority reconciliation, future-epoch registry assembly, and governed successor-epoch activation are wired. | Resolve the authoritative shadow-duration constant and retire legacy lifecycle ownership. | Phase 2 verification deferred. | 14, 15 |
| 9 | ETDAG extraction | IMPLEMENTED (runtime batch), CALLERS_MIGRATING | The production tree and supervised `EtdagService` own authenticated H+5 ingress, certification/order/reveal, execution handoff, governance, durable-store boundaries, recovery, metrics, durable shard custody, retention, and authenticated outbound shard serving. Ordinary-user client submission and legacy retirement remain. | Complete ordinary-user protected submission transport and retire the monolithic legacy owner. | Verification intentionally deferred for this bulk migration pass. | 10, 14, 15 |
| 10 | Transaction/execution/block/state | IMPLEMENTED, CALLERS_MIGRATED | Certified ETDAG batches decode and Aegis/PQVM-verify canonical transactions; every supported action routes through concrete native, SynQ/PQSynQ/AIVM, SXCP/UMA, governance, or supported system providers. Candidates persist before PoSy publication, restart recovery re-executes only QC-bound candidates, and finalized account bytes precede their matching commitment. | Finish ordinary-user ingress, native external-chain proof adapters, state proofs, cross-process safety, and legacy retirement. | New recovery/account-state/provider paths not tested. | 11, 14, 15 |
| 11 | Storage durability | IN PROGRESS | No runtime caller cutover or multi-record crash transaction. | Add injected failure coverage and migrate one safety journal at a time. | 5 focused storage tests pass. | 14, 15 |
| 12 | Admin API/CLI/Control Panel parity | IN PROGRESS | Mutating typed operations remain gated. | Expand shared safe operation model. | Read-path tests only. | 13–15 |
| 13 | Canonical role implementation | IN PROGRESS | Most profiles lack independent runtime completion. | Continue capability-based role migration after foundations. | Partial profile checks. | 14, 15 |
| 14 | Full integration/adversarial testing | PHASE 2 | Intentionally deferred until implementation coverage and caller migration are complete. | Do not execute during the migration phase. | Deferred. | 15 |
| 15 | New-network initialization and launch | PHASE 2 | New Genesis, validator set, manifests, transport state, release artifacts, and deployment configuration are intentionally not generated yet. | Build them from the completed architecture, then qualify and launch. | Deferred. | — |

## Phase 2 live deployment gate — intentionally deferred

The table below is retained as historical old-network operational context only.
It is not a blocker for the canonical `node-platform/` software migration and
must not drive compatibility work or mutation of the approved installation.

| Gate | Status | Deterministic material / action |
| --- | --- | --- |
| Transport snapshot | REQUIRED — BLOCKED | The external release-bound transport-attestation signer must publish a signed `synergy-testnet-v3-validator-transport-snapshot-v1` covering the authoritative active identities `validator-02` through `validator-06`, their canonical `synv` addresses, and provider-authorized `10.69.10.N:5622` routes. It must bind the provider-plan SHA-256 and configured release-bound public verification key. No static route fallback is permitted. |
| Snapshot inputs | READY | `scripts/generate-fresh-posy-v3-validator-vpn-provider.py` deterministically produces the public provider plan and offline proof from the canonical validator inputs and authority freeze; it deliberately does not sign or handle provider credentials. |
| Snapshot verification | READY at runtime; standalone current-schema CLI is NOT STARTED | `P2PNetwork::start` fetches, signature-verifies, binds, and coverage-checks the configured snapshot before opening production networking. On each validator, after the signer publishes the snapshot, run `set -a; . /etc/synergy/chain1266/validator-NN.env; set +a; "$CHAIN1266_ROLE_BINARY" preflight-release --config "$CHAIN1266_ROLE_CONFIG"`; then the approved service restart executes the transport verification fail-closed. The existing Python offline checker is legacy-schema and must not be substituted for this current runtime gate. |
| New binary | NOT REQUIRED for snapshot-only recovery | The deployed approved r11 binary already fetched a signed snapshot, bound its listener, and failed only at peer readiness because the live mapping was incomplete. A correct signed snapshot may therefore be consumed without replacing the binary. Current source router/registry changes require a new immutable binary only if they are to be deployed. |
| Release approval | NOT REQUIRED for snapshot-only recovery; REQUIRED for a replacement binary | A replacement package must be bound by the V4 Governance Authority approval over its exact Genesis, desired-state, binary, and configuration hashes. Do not self-approve or substitute a prior approval. |
| Post-approval deployment | BLOCKED on external signer/approval | After a valid snapshot is available and release preflight succeeds, the next approved existing-binary command is `sudo systemctl restart synergy-chain1266-role@validator-NN.service` on each governed host. Observe identity-complete authenticated peers and advancing finalized height before any further rollout. |


## Canonical node-platform transition - 2026-09-11

The legacy runtime tree is frozen as a behavioral reference only. New
production ownership is being implemented under `node-platform/`; scaffolded
files are not evidence of implemented behavior, and legacy artifact compatibility
is not required.

| Boundary | Launch class | New-platform status | Evidence | Legacy status |
| --- | --- | --- | --- | --- |
| Workspace root and target tree | POST-LAUNCH | SCAFFOLDED | 216 directories / 1,138 target files created without overwriting existing content | Runtime remains reference only |
| Shared protocol types | P0-LAUNCH | VERIFIED (foundation) | 4 unit tests pass; canonical 20-role taxonomy is authority-neutral | MIGRATING |
| Node core and Admin API | P0-LAUNCH | VERIFIED (foundation) | 5 unit tests pass; shared typed contract only | MIGRATING |
| Transport parser | P0-LAUNCH | VERIFIED (foundation) | 2 direct behavior-port tests pass | MIGRATING |
| Peer manager | P0-LAUNCH | VERIFIED (foundation) | 4 tests: exact-session cleanup, duplicate dials, quarantine/ban, stale detection | MIGRATING |
| Bounded router | P0-LAUNCH | VERIFIED (foundation) | 4 tests: total/per-peer bounds, fairness, exact cleanup, opaque protocol categories | MIGRATING |
| PoSy / ETDAG / Sync adapters | P0-LAUNCH | VERIFIED (boundary only) | 2 tests; adapters reject wrong route and cannot determine finality | MIGRATING |
| Handshake compatibility and dnsaddr candidate parsing | P0-LAUNCH | VERIFIED (foundation) | 3 tests: accepted algorithms, chain compatibility, TCP-only candidates | MIGRATING |
| VPN route policy and initial registry coverage | P0-LAUNCH | VERIFIED (foundation) | 4 tests: Validator/Sentry scopes, route validation, duplicate and active-set coverage | MIGRATING |
| Sentry perimeter policy and bounded forwarding | P0-LAUNCH | VERIFIED (foundation) | 3 tests: no-authority capability, allowed opaque forwarding, overload containment | MIGRATING |
| Signed provider snapshot verifier and overlay admission | P0-LAUNCH | VERIFIED (foundation) | 7 tests: Ed25519 signature, tampering, plan binding, rollback/equivocation, exact-route fail-closed handoff | MIGRATING |
| Verified sync | P0-LAUNCH | VERIFIED (foundation) | 4 tests: evidence-gated head selection, bounded failover, and no signing while behind | MIGRATING |

Historical verification before the strategy correction: 101 workspace tests
passed on synergy-val4. No further compile/test/validation gate is being run
during implementation migration. Testing, integration, and live validation are
separate Phase 2 states.

| Verified source selection and signing readiness | runtime sync and P2P source selection | node-platform/crates/synergy-sync | MIGRATING | 4 unit tests pass | Runtime synchronization callers | Only authenticated, compatible, evidence-backed sources may contribute; advertised height is never authoritative. |
| PoSy proposal/vote/QC/TC/finality and sign-once safety journal | runtime consensus safety state and simplified driver | node-platform/crates/synergy-posy | BEHAVIOR_MIGRATING | 8 focused tests pass; legacy runtime callers remain. | Runtime PoSy callers | One driver pipelines certified heights, applies three-QC finality, verifies strict independent validator-count and frozen-weight QC/TC quorum, retains lease takeover, and keeps stake/score/VPN/role outside authority. |
| ETDAG protected admission and deterministic ordering | runtime ETDAG pipeline | node-platform/crates/synergy-etdag | BEHAVIOR_MIGRATING | Final ownership is now split across admission, ingress, and persistence; legacy pipeline callers remain. | Runtime ETDAG callers | H+5 context-bound ciphertext ingress; names preserve frozen v3 commitments without interpreting them as stake. |
| Authorized deterministic execution input | runtime protected execution path | node-platform/crates/synergy-execution | MIGRATING | 3 unit tests pass | Runtime execution callers | Accepts only already-authorized, strictly ETDAG-ordered reveals; permits explicit empty input and cannot determine finality. |
| Atomic bounded-file persistence | Dispersed runtime file writes | node-platform/crates/synergy-storage | BEHAVIOR_MIGRATING | Final ownership is now database plus fsync; no runtime safety-journal cutover yet. | Runtime persistence callers | Atomic temp write, file fsync, rename, parent-directory fsync, bounded reads, and traversal rejection are executable. |
| Finalized state commit | Runtime state persistence | node-platform/crates/synergy-state | BEHAVIOR_MIGRATING | Final ownership is now state model plus transition store; runtime callers remain. | Runtime state callers | Persists only caller-supplied PoSy-verified finalization records, enforces contiguous history and idempotent replay, and cannot determine finality. |
| PoSy prepared/proposal/vote/certificate/finality recovery journal | Runtime PoSy persistence | node-platform/crates/synergy-posy | MIGRATING | 4 unit tests pass | Runtime PoSy callers | Shared atomic storage persists opaque validated safety records, survives restart, rejects conflicts and duplicate recovery slots; it does not calculate quorum or finality. |
| Failed durable PoSy write regression | Runtime safety journal semantics | node-platform/crates/synergy-posy | MIGRATING | Focused regression included in current 101-test workspace pass | Runtime PoSy callers | A failed atomic write leaves in-memory sign-once authorization unchanged, preventing false durable-state acknowledgement. |
| ETDAG durable admission recovery | Runtime ETDAG persistence | node-platform/crates/synergy-etdag | BEHAVIOR_MIGRATING | Final persistence owner is persistence/admission_store.rs; runtime callers remain. | Runtime ETDAG callers | Atomic storage restores only matching H+5 admission context, ciphertext envelopes, deterministic order, and closed state; mismatched context fails closed. |
| Deterministic execution transition sequencing | Runtime execution path | node-platform/crates/synergy-execution | MIGRATING | Focused transitions included in current 101-test workspace pass | Runtime execution callers | Applies only ETDAG-established authorized order through a state/VM adapter, returns state-root receipt, permits empty input, and cannot determine finality. |

## Implementation-first migration wave - 2026-09-11

| Component | Classification | Final owner now populated | Remaining migration |
| --- | --- | --- | --- |
| Role, snapshot, SXCP, UMA, and validator-management source owners | IMPLEMENTED; CALLERS_MIGRATING | synergy-roles, synergy-snapshot, synergy-sxcp, synergy-uma, synergy-validator-management | Snapshot, SXCP/UMA execution, and validator lifecycle callers are wired. Role-specific service providers, native external-chain proof adapters, and legacy retirement remain. |
| Storage columns/transactions and Sync/SynQ support owners | IMPLEMENTED; CALLERS_MIGRATING | synergy-storage, synergy-sync, synergy-synq | Verified Sync/snapshot/epoch and concrete SynQ execution callers are wired. Full storage keyspace/runtime schema migration, pruning, disk guards, and legacy retirement remain. |
| PoSy protocol support ownership batch | IMPLEMENTED (source), CALLERS MIGRATING | synergy-posy clustering verification, lifecycle scheduling, domains, metrics, durability/signing boundaries, proposal recovery, replay, and versioning | Source ownership exists without a second consensus driver; frozen-epoch authority remains immutable and legacy caller retirement remains. |
| PoSy proposal/vote/QC/TC/finality driver | BEHAVIOR_MIGRATING | synergy-posy/src/{engine,proposal,voting,quorum,finality,timeout} plus new-node single driver | Epoch-transition recovery, remaining live callers, and legacy retirement remain. |
| PoSy persistence and recovery | IMPLEMENTED, CALLERS_MIGRATED | synergy-posy/src/persistence and recovery canonical stores/checkpoints/reports/reconciliation plus new-node QC/TC and epoch-transition replay | Cross-process writer ownership, multi-record crash atomicity, and legacy retirement remain. |
| ETDAG production subsystem | IMPLEMENTED; CALLERS_MIGRATING | synergy-etdag crypto/admission/ingress/DAG/availability/ordering/certificates/reveal/execution/governance/persistence/network/recovery/metrics plus supervised EtdagService | Governed PQ providers, validator runtime, durable DA custody/retention, and authenticated artifact serving are wired. Ordinary-user protected submission transport, multi-record persistence consolidation, legacy retirement, and Phase 2 verification remain. |
| ETDAG protected client ingress | PARTIAL; SECURITY CORRECTION IN PROGRESS | synergy-etdag admission/ingress plus synergy-etdag-client/src/{target_context,ingress_keys,encrypt,padding,envelope,submit,receipt} | The server request is being changed from governed-validator sender IDs to a wallet-presented signed request bound to chain, network, target context/height, nonce, algorithm, public key, and encrypted envelope. Client construction, RPC/transport submission, final Aegis provider wiring, negative tests, and end-to-end finality evidence remain. |
| ETDAG protected look-ahead | FOUNDATION_VERIFIED | New-platform admission parameter/context now require governed H+5. | Legacy H+3 reference must be reconciled during its governed driver migration; no runtime behavior changed by this source-only boundary. |
| Atomic storage | BEHAVIOR_MIGRATING | synergy-storage/src/database.rs, fsync.rs | WAL, integrity, recovery, pruning, disk guard, and runtime callers remain. |
| Finalized state | BEHAVIOR_MIGRATING | synergy-state/src/state.rs, transition.rs plus new-node ExecutionService | Root-checked account bytes and QC-bound speculative candidates now reload for runtime execution; Sync state import, proofs, pruning, cross-process safety, and legacy caller cutover remain. |
| Deterministic execution | IMPLEMENTED; CALLERS_MIGRATED | synergy-execution/src/{context,executor,receipts,transition,dispatcher}.rs plus synergy-node ExecutionService | Runtime protected execution and concrete native, SynQ/PQSynQ/AIVM, SXCP/UMA, governance, and supported system action providers are wired; ordinary-user ingress, native external-chain proof adapters, state proofs, cross-process safety, and legacy retirement remain. |
| Canonical transaction and block | IMPLEMENTED; CALLERS_MIGRATED | synergy-transaction and synergy-block canonical action/nonce/receipt/block/codec/validation files plus Execution/PoSy/Sync callers | Canonical execution dispatch, state, SynQ/AIVM, PoSy proposal/import, Aegis verification, and universal-node callers are wired. Ordinary-user ingress, state proofs, and legacy retirement remain. |
| Canonical shared protocol types | IMPLEMENTED | synergy-protocol-types complete focused type set | Subsystem caller migration and legacy synergy_types retirement remain. |
| Independent version domains | IMPLEMENTED | synergy-version release/protocol/database/config compatibility and activation modules | Manifest/runtime callers remain. |
| Universal node start boundary | IMPLEMENTED (runtime batch), LEGACY REMAINS | synergy-node absolute-path config/authority load, complete required-service coverage gate, retained poll/shutdown loop, runtime snapshot, and all configured production services | Legacy startup ownership remains until caller migration and retirement are proven. |
| ETDAG verified reveal and persistence | SOURCE IMPLEMENTED | finality-bound reveal verification/decrypt plus atomic admission/encrypted-input/DAG/certificate/safety/reveal stores and bounded recovery | Concrete PQC reconstruction, runtime callers, multi-record transactions, and verification remain. |
| Canonical block execution | IMPLEMENTED, CALLERS_MIGRATED | execution validation/scheduler/fees/receipts/dispatcher plus `ExecutionService` ETDAG conversion, concrete native/SynQ/PQSynQ/AIVM/SXCP/UMA/governance/system action routing, block/state candidate, PoSy handoff, and finality-gated commit | Ordinary-user ingress, native external-chain proof adapters, state proofs, cross-process safety, and legacy retirement remain. |
| Node-facing Aegis policy/provider boundary | IMPLEMENTED, CALLERS_MIGRATED | synergy-aegis signer/verifier/custody/policy/attestation/lifecycle/audit plus PQVM/PQSynQ provider modules | Remaining established legacy hash/utility callers and legacy retirement remain; synergy-crypto remains a facade, not a second engine. |
| Canonical base runtime services | IMPLEMENTED (runtime batch), LEGACY REMAINS | synergy-node real identity/storage/network/sync/Admin/ETDAG/execution/PoSy/RPC/WS/VPN/Sentry/telemetry/health ManagedService adapters and retained supervised process | Legacy runtime remains the frozen semantic reference until explicit caller-retirement proof. |

Narrow cargo check completed after each moved crate group on synergy-val4.
Comprehensive test, simulation, and fleet verification are intentionally deferred
until behavior and callers are substantially migrated.

| Node core lifecycle/readiness/supervision | IMPLEMENTED (runtime batch) | synergy-node-core lifecycle, readiness, and supervisor modules plus complete `synergy-node` service registration/transition ownership | Legacy startup caller retirement remains. |
| Canonical configuration | IMPLEMENTED, CALLERS MIGRATING | synergy-config complete schema-v1 model, bounded loader, cross-field validation, and `synergy-node start` caller | Broader manifest/subsystem callers remain. |
| Canonical network handshake/framing | IMPLEMENTED (runtime batch) | synergy-network plus `NetworkService` governed Aegis/PQVM handshake, authenticated framing, exact sessions, replay refusal, listener/dialer, PeerManager, routing, and protocol adapters | Discovery/registry/VPN extensions and legacy retirement remain. |
| Canonical verified sync | IMPLEMENTED, CALLERS_MIGRATED | synergy-sync plus `SyncService` authenticated heads and sequential full-candidate transport; PoSy QC/TC replay; Execution commitment validation, deterministic re-execution, candidate persistence, finality-gated state commit, bounded failover, durable active-request resume, finality-bound snapshot transport/restore, and trust-root-signed cross-epoch authority transition with full builtin service-graph reconstruction | Legacy retirement and configured external archive/object-store integration remain. |
| Typed config / public identity / manifest composition | IMPLEMENTED, CALLERS MIGRATING | synergy-config/src/{node,role,validation}, synergy-identity/src/{public_identity,key_binding,synv}, synergy-manifest/src/{network_manifest,hash,verifier} | Canonical source owners and bounded validation are populated; full configuration domains, cryptographic proof verification, signatures, and runtime caller migration remain. |
| Verified sync head selection / readiness | IMPLEMENTED, CALLERS_MIGRATED | synergy-sync/src/head/{candidate,quorum_view,selection}.rs, wire.rs, and runtime Sync/PoSy/Execution callers | Finalized candidate/state transfer, bounded failover, durable request resume, manifest/state-root anchored snapshot transport/storage, verified restore handoff, durable execution commit/receipt, and exact trust-root-signed epoch transition are wired; Phase 2 verification and legacy retirement remain. |

## Historical scheduled migration work session - 2026-09-12 01:15 UTC

The counts and "does not start a node" statements in this dated section are
historical observations, not current migration state. The current state is the
governing table above: `synergy-node` now starts and supervises the configured
service graph, while caller migration and legacy retirement remain incomplete.

This run corrected the first broken boundary in the new PoSy owner: the state
machine previously waited for finality before advancing height, so QC(H1)
could never be followed by QC(H2). It now advances after every accepted QC,
retains lease takeover state across heights, and finalizes H only after the
consecutive QC(H), QC(H+1), QC(H+2) witness. Timeout votes and timeout
certificates now flow through the same driver instead of being ignored.

Production files (audited `node-platform/crates/synergy-posy` scope, 85 files):

- IMPLEMENTED: 37
- PARTIAL: 25
- PLACEHOLDER: 23
- DECLARATION_ONLY: 0

The broader `node-platform` filesystem inventory (excluding build `target/`)
currently contains 1,146 files: 298 are non-empty and 848 remain zero-byte.
This inventory includes planned tests/tools/configuration paths; its per-file
semantic audit is not complete, so non-empty files are not automatically
labeled implemented.

Responsibilities (canonical migration-map rows):

- BEHAVIOR_MIGRATING: 9
- BEHAVIOR_VERIFIED: 0
- CALLERS_MIGRATED: 0
- LEGACY_REMOVED: 0

Can `node-platform/bin/synergy-node` operate entirely without legacy production
runtime? **NO.** It is now a functional read-only local Admin API client, but
does not start a node or own runtime services. Remaining legacy dependencies
include runtime startup/lifecycle and mutating/subsystem CLI wiring, P2P socket
and protocol adapters, PoSy durable-state/live-driver callers, ETDAG, verified
sync transfer, execution/state integration, configuration/identity/manifest
consumers, RPC/WS, storage migration, and role implementations.

CURRENT SUBSYSTEM: PoSy engine / proposal / voting / quorum / finality / timeout

CURRENT FILES: `node-platform/crates/synergy-posy/src/{engine,proposal,voting,quorum,finality,timeout}`

LAST COMPLETED RESPONSIBILITY: One driver now accepts proposals, block votes,
QCs, timeout votes, and TCs; QC identity is proof-round/signer-subset
independent; strict count+frozen-weight quorum produces QCs/TCs; each QC
advances the certified height; a consecutive three-QC chain finalizes its
grandparent; timeout takeover persists within the governed leader lease.

CURRENT INCOMPLETE RESPONSIBILITY: Define the clean canonical PoSy protocol and
membership representations; persist typed proposal, vote, QC, TC, finality, and
prepared-state records; reconstruct the highest-parent, lock, takeover, and
three-QC tail before enabling signing after restart.

NEXT FILE / CALLER: Populate
`node-platform/crates/synergy-posy/src/persistence/{proposal_store,vote_store,certificate_store,finality_store,prepared_state}.rs`
and `recovery/{replay,prepared_state,reconciliation}.rs`, then connect the new
runtime driver adapter. Legacy bytes are not a prerequisite.

BLOCKER, IF ANY: No external blocker for source migration. Live validator/fleet
validation remains separately blocked by the missing identity-complete signed
transport snapshot and is not part of this source-only work session.

## Historical direct six-agent migration wave - 2026-09-12 04:26 UTC

This dated verification and caller state is historical; current source and
caller state is recorded in the governing tables above.

The recurring `Migrate Files` automation was deleted before this direct run so
it could not overlap edits. Six subagents were launched in two concurrency
waves with non-overlapping ownership; the configuration/identity foundation
agent exhausted the account usage window before making changes. The other five
agents and the coordinator completed these source-only boundaries:

- PoSy: frozen BLAKE3 domain framing/raw leader-seed handling, pre-mutation
  three-QC witness validation, and verified per-height QC persistence.
- ETDAG: frozen content-blind dependency ordering, order-seed derivation,
  duplicate/cycle refusal, and gas/byte prefix selection.
- Execution/state: decoded-input revalidation, rollback-safe cloned execution,
  immutable finalized per-height history, and conflict-safe pointer retry.
- Network/VPN/registry: exact canonical Validator/Sentry route shapes, signed
  snapshot/coverage/generation handling, and verified route admission.
- Sync: request-anchor/range enforcement, no partial importer advance, and
  bounded failover over a frozen verified support-source set.
- Storage: bounded reads remain bounded after open, WAL sequence/integrity
  replay fails closed on truncation, and first-file directory durability is
  explicit.

Verification on `synergy-val4`:

- `cargo fmt --check`: pass for the full `node-platform` workspace.
- `cargo test --workspace -- --test-threads=1`: 101 passed, 0 failed.
- Focused totals: PoSy 11, ETDAG 10, execution 6, state 4, storage 5,
  sync 8, network 17, transport registry 7, VPN 2.

No deployment or live-validator change was made. The universal node now owns
canonical execution and local management callers for ownership, naming, and
reward withdrawal, but protected ordinary-user transaction submission and
remaining legacy caller retirement are still open.

CURRENT SUBSYSTEM: Canonical NodeAddress terminology and ordinary-wallet protected ETDAG ingress

CURRENT FILES: `node-platform/crates/{synergy-admin-api,synergy-rpc,synergy-etdag,synergy-etdag-client}` and `node-platform/bin/synergy-node`

LAST COMPLETED RESPONSIBILITY: Canonical ownership, NodeID, and reward-withdrawal actions execute against the PoSy-finalized world-state path; the canonical PoSy simplification classification audit was added without changing consensus behavior.

CURRENT INCOMPLETE RESPONSIBILITY: Finish and validate the NodeAddress public-boundary rename, complete signed wallet admission construction and Aegis verification, and wire the request through the public RPC/transport path into ETDAG without bypassing protection.

NEXT FILE / CALLER: `node-platform/crates/synergy-etdag-client/src/{request,submit}.rs`, then the `synergy-rpc` submission method and universal-node ETDAG ingress owner.

BLOCKER, IF ANY: No source-edit blocker. The newest NodeAddress and ETDAG request edits are incomplete and unverified; live Chain 1266 state remains untouched.


### 2026-10-08 protected-pipeline verification checkpoint (C1266-2026-10-08-002)

IMPLEMENTED / VALIDATED_LOCAL: authenticated count-and-weight cutoff verification,
complete certified ancestor closure, deterministic protected batch commitments,
parent-PoSy-proof reveal authorization, and bounded atomic per-target recovery.
Recovery now requires the caller's expected cutoff commitment rather than trusting
the stored record to choose its own authority. Execution additionally waits for the
matching parent QC in the local verified PoSy store; an unrelated parent is rejected.

Validation: node 16/16 and ETDAG 12/12 tests passed. The four real-ML-DSA protected
qualification tests passed again after the recovery and local-parent corrections.
Node/ETDAG all-target Clippy with `-D warnings` passed (the filesystem emitted
incremental-cache hard-link fallback warnings). These are local service/crypto
checks, not live network qualification.

CALLERS_MIGRATED: PARTIAL. The ETDAG runtime still uses its old ordering/batch
certificate handoff. The new durable pipeline is not yet registered as the runtime
owner. Missing production boundaries include governed target-context creation,
durable cutoff signing and gossip, H/H+1/H+2 candidate commitments, parent-proof
handoff, and nonempty reveal preparation. Different cutoff-frontier subsets also
require qualification against the protocol's single semantic-cut requirement.
Do not infer that identical empty-frontier test results prove that property for
heterogeneous frontiers. Fresh signed network artifacts, Linux release, deployment,
sustained matching finalized tips, restart/rejoin, public tiers and Val1 conversion
remain unverified. No live service, key, chain database or workbook changed here.

Release check: `CARGO_INCREMENTAL=0 cargo build --locked --release -p synergy-node` passed on the backing macOS host in 41.05 seconds. Changed Rust-file whitespace checks passed. The broader log diff reports four existing Markdown hard-break whitespace lines at 4247-4250; append-only incident history was preserved. This build is not a Linux release or deployment.

## Gate A tooling checkpoint 2026-10-11

IMPLEMENTED / VALIDATED_LOCAL only: original remediation DOCX revised in place,
27-page repaired visual QA passed; canonical A–H gates and current dependency
contract updated. Native standalone preflight validates configuration/public
authority/startup-plan structure without starting services or opening custody.
Supervisor timing2 tests passed on the canonical backing host; bounded collector
phase2 tests and CLI preflight test passed; strict node/node-core Clippy passed
with only existing filesystem incremental-cache fallback warnings. Timing reducer
and process guards have scoped offline tests; their fixture/schema work continues.

No live rollout, TPS retry, reset, key rotation or protocol activation occurred.
Native synthetic fixture issuance, diagnostic phase hooks, actual Linux process
measurements, parameter report and Gate A review remain pending. Test-only
collector evidence cannot substitute for diagnostic-feature Linux execution.
The archive alias resolves to Darwin/arm64, not a Linux namespace host.
The operator selected their Linux machine via `ssh dev`. Verified on 2026-10-11:
the alias exists on other-mini and resolves to devpup@192.168.1.161; access reuses
the Thunderbolt SSH connection to other-mini and `/tmp/posy-dev-control` there.
The host is Linux x86-64, with 12 logical CPUs, approximately 6.6 GiB RAM and
147 GiB available on its home filesystem. `ip`, Python and `unshare` are present.
Passwordless sudo is unavailable; unprivileged user/network namespace creation
fails with `uid_map: Operation not permitted` and the AppArmor user-namespace
restriction is enabled. Privileged namespace setup remains pending; no host
security setting was changed and no qualification processes were started.

Additional local verification: measurement reducer 10 tests and process launcher
12 tests pass. The launcher now supplies per-node diagnostic configuration and
retains bounded private failure logs. PoSy diagnostic hooks observe owner-poll
start, durable QC acknowledgement and consecutive durable finality commits.
They conservatively exclude observations from healthy-cadence selection until
the isolated runner establishes a healthy cohort; round zero alone is not proof.
Portable source provenance, full admission tracing and sudo-backed isolated
network setup remain open prerequisites to the Linux measurement run.
Diagnostic-feature strict Clippy passes for all synergy-node targets after
test-module placement and test-only helper corrections; evidence:
`node-platform/target/posy-gate-a-feature-clippy.log`. This is local validation,
not Linux runtime qualification.

## Isolated Linux access checkpoint — 2026-10-12

VERIFIED_TARGET: the operator-provided Desktop machine details were used to add
`Host dev` directly to this Mac's SSH configuration. Dedicated local Ed25519
authentication and the server key obtained through the trusted other-mini
connection were verified with strict host-key checking and BatchMode login.
Direct access is devpup@192.168.1.161; the temporary other-mini→dev SSH master was
closed and the direct master at `~/.ssh/posy-dev-control` is reused.

Sudo was verified using the credential supplied in the saved Desktop details
file. A bounded root network namespace check created only loopback and dummy
`wt0`, with isolated addresses 10.69.10.2–.6 and no external route. Its namespace
inode differed from the host; it disappeared on exit and no host `wt0` remained.
No host security policy or production networking was changed. The earlier
sudo/namespace setup blocker is resolved. Actual fleet processes, funded
transactions and timing measurements remain pending.

The original Desktop credentials workbook received one `dev` row in place.
Existing rows and unrelated OOXML parts were verified unchanged. No workbook
copy or secret-bearing evidence log was created. Portable provenance guard
tests pass (13); independently pinned build provenance remains a prerequisite
to transmitting a diagnostic artifact without a second source checkout.

VALIDATED_LOCAL / VERIFIED_TARGET for execution only: the diagnostic-feature
Linux node and keytool build completed from the canonical checkout using locked
dependencies and the pinned toolchain. Build evidence:
`node-platform/target/posy-gate-a-linux-build.log`. The build emitted existing
Zig target-version and deprecated-linker-option warnings; exit status was zero.
Node SHA3-256:
`dfd1a214343db7d51090a1135f22de9778dd53567ace3db61abd9f9f63486e9f`.
That node artifact was transferred to
`dev:/tmp/posy-isolated-measurements-20261012/synergy-node`; digest equality and
native `--help` execution passed. The directory is private and contains the
diagnostic executable only. No validator process was launched. This diagnostic
artifact has not passed Gate D and must not be promoted to the live fleet.

## Gate A HTTP intake measurement — 2026-10-12

Usage availability restored; independent scoped reviews resumed. Feature-only
HTTP and admission-enqueue phase instrumentation passed four collector tests,
the partial-HTTP fairness regression, two live-cutoff regressions, strict Clippy,
and a locked Linux diagnostic build. Exact node SHA3-256:
`8c47bfa7bb7bb88328981d6d8a78ee0c1f1372b2bb8a9df5ab42aef9c6916c25`.
Independent diagnostic provenance pin:
`b6e575b3f205c233126887c2b1f76a7e0e2920a8f3102a4b0a381839c54cbea7`.
This supersedes earlier diagnostic artifact identities for the latest run;
it is not a complete source inventory or Gate D release provenance.

Run9 resumed retained isolated journals to matching finalized H728 on all five.
Its funded transaction was rejected at submission: target596 had224.383ms
between opening and cutoff, versus274.791ms of measured HTTP intake alone.
Native signing took15.480ms, RPC dispatch7.178ms, and complete context-to-rejected
response418.430ms. The316029byte compact body needs at least five64KiB reads;
the shared supervisor sleeps impose at least200ms between those passes.
Canonical design and exact evidence pointers are in `protocol/posy-v3/ARCHITECTURE.md`.

Independent review specified bounded RPC-owned intake, authoritative ETDAG
admission/cutoff serialization, stale completion rejection and a versioned
context envelope that preserves signing bytes while carrying source evidence.
The current baseline client compares source commitments but lacks recomputation
of the source-finality context root; close that verification gap before full
qualification. No integrated architecture change, live deployment, successful
funded finality, TPS baseline, lookahead activation or soak is claimed.

Run10 then applied100ms egress-only delay inside each isolated validator
namespace, retaining the same signed authority, artifact and journals. A genuine
native transfer for target744 was queued and locally durably admitted before
cutoff, but arrived remotely after cutoff. No availability certificate formed;
all five committed empty cuts and finalized identical H744 block/state with
unchanged funded wallet nonce/balance. The observer reached common H809 before
controlled shutdown. This isolates availability-window failure beyond HTTP
intake; it is not a successful TPS or soak entry test.

Bounded public evidence summary and digests are recorded at
`node-platform/target/posy-isolated-control-20261012/linux-admission-boundary-measurements.json`.
The Gate A abstract model gained retained pre-cutoff vote requirements and two
counterexample regressions; all nine tests pass. Integrated owner/worker design
and signed-offset change inventory were independently reviewed. Production
cadence/lookahead remain unselected because complete healthy admission-to-VAC
coverage is absent. No repeated live patch/deploy or manual capacity rescue.

## Approved isolated A1 funded-transfer checkpoint — 2026-10-12

The operator explicitly approved only the isolated A1 lookahead experiment
(D=6–16), not live activation or production parameter selection. Centralized
source/target derivation now binds experimental offsets through parameters,
contexts, authoring, verification, persistence, recovery and runtime bootstrap.
Legacy F+5 context serialization remains unchanged; frozen activation policy
remains unchanged. Configuration alone cannot override signed authority.

VALIDATED_LOCAL: core ETDAG 31, configuration 5, client 1, execution 6, keytool
20, baseline harness 11, and focused native bootstrap tests pass. Native node
test compilation and strict all-target Clippy pass. The locked Linux diagnostic
build completed with source hashes unchanged before/after build. Exact node
SHA3-256: `90d8bc4360adeaab374b739119f27d7085f63b410ff69aa7fe1a746783e59236`.
The public source inventory remains incomplete; this is not Gate D provenance.

VERIFIED_ISOLATED: separate fresh D=6 and D=7 five-process networks each
finalized one genuine steady-state native protected transfer at H28 with
identical receipts, block/state/certificate commitments and exactly-once wallet
effects across all five. Context-to-observed-finality was 4.491s and 4.977s
respectively. Minimum observed availability-to-cutoff margins were 3.606ms and
460.869ms. Neither sample satisfies the plan's 50% admission-window headroom
on every validator; neither establishes a healthy percentile cohort. D=8
measurement is the next candidate using the same exact Linux bytes.

Evidence: `node-platform/target/posy-isolated-control-20261012/a1-lookahead-measurements.json`.
Fixtures retain genuine native cryptography but simulated provider status and
placeholder Genesis anchors; full signed Genesis, persistent signer, independent
funded wallet pool and full-process qualification remain open. No TPS capacity,
production deployment, production timing choice or 24-hour soak is claimed.

A bounded single-validator restart schedule is implemented in the isolated
launcher; 20 offline tests pass. It preserves native journals and authority,
requires termination of the exact old owned process before replacement, and
uses new admin/timing paths. It does not assert recovery merely from restart.
New fixtures may use guarded `/var/tmp/posy-isolated-*` disk storage after
RAM-backed `/tmp` hit its user quota; historical experiment journals are retained.

### 2026-10-12 A1 D=8 and retained-state restart result

VERIFIED_ISOLATED: the D=8 no-fault run finalized the protected transfer at H28
on all five with matching commitments and exactly-once effects. Observed
context-to-finality was6.378s. Per-node open-window/context-to-availability
ratios were2.19–2.34, exceeding1.5 for this single sample; this is not a p99
profile, load qualification or approval of production D=8. All five reached H76.

The same D=8 authority and native journals then resumed without reset. A
declared validator stop occurred at15.032s; old signer termination was confirmed
at15.039s; replacement started at25.062s using the same storage/custody and
fresh admin/timing paths. The other four continued from H98 to H109 during
the outage while the stopped validator stayed at H96. All five subsequently
matched block/state/certificate commitments at pinned H108,H150,H172,H186.
A second funded transfer finalized identically with exactly-once wallet effects,
and all five ended at H196. No manual chain rescue or journal restoration occurred.

Public evidence: `node-platform/target/posy-isolated-control-20261012/a1-retained-state-recovery.json`
and `a1-lookahead-measurements.json`. This verifies the declared isolated restart
scenario only. Actual VPN provider, genuine signed Genesis, complete healthy
percentiles, integrated service scheduling and five-host gates remain open.


## Integrated qualification checkpoint — 2026-10-13 13:18 UTC

IMPLEMENTED, not runtime-qualified: service-owned work, bounded preparation,
durable admission receipts, V2 native signing, independent funded wallet pool,
operator custody mode, cancellation/reconciliation, streaming proof evidence,
common-height telemetry, genuine Genesis/authority binding, and candidate
provenance/qualification controls are written. Independent source review found
and corrected protocol-version agreement and admission-independent telemetry
identity. Existing native fault scenarios and the abstract 10,000-seed campaign
are orchestrated; missing full-process fault instrumentation remains explicit.

Consolidated validation began only after integrated source freeze. Initial build
preflight failed before compilation on deleted tracked inputs, then a source
symlink. Inventory handling is being corrected without restoring or deleting
user files. Python validation ran 59 tests with seven fixture/import errors;
fixture corrections and Python-version compatibility are written but unverified.
The isolated runner is being corrected to consume a pinned Linux fixture-exporter
binary rather than requiring a second source checkout on `dev`.

Evidence directory:
`node-platform/target/posy-integrated-20261013T131800Z`.
No new Linux candidate, successful current TPS baseline, live release, parameter
activation, or soak is claimed. Next: complete tooling corrections, refreeze,
build with before/after provenance, run consolidated checks, then qualify those
same bytes with funded transactions and retained-journal recovery. Production
parameter review and the remaining protocol/fault gates precede live activation.

### Consolidated validation follow-up — 2026-10-13 13:55 UTC

VALIDATED_LOCAL: 80 Python checks passed; strict integrated Clippy passed;
ETDAG31, client1, execution6, Genesis2 and keytool23 passed. The remaining
PoSy26/state4/storage5/sync10 checks passed, as did RPC backpressure.
The abstract campaign completed 10,000 seeds and 3,018,364 events; it does
not close native protocol qualification. Node checks initially had88 passes,
11 failures and1 ignored fixture export. Fixture path canonicalization and
RPC scheduling corrections exposed ten socket cases sharing one actual defect:
unsigned consensus observations incorrectly required128hex characters instead
of PoSy's canonical64hex epoch root. Validation now reuses the native hash
predicate; its regression passes, and the affected socket suite is in progress.

The Linux build completed, but its fixture-exporter artifact is ineligible:
initial bytes contained a zero header and were recorded/transferred with
SHA3-256 2e7a63db2c43e2f222a93051643dd92cc44e2442a84f937f4816fb4e1fd049db.
Subsequent reads on the authoritative ExFAT SSD, without another Linux build,
showed a valid ELF with identical inode/size/mtime and SHA3-256
30d0bd6dd8bd7bdb9aa970c0b8bebe80280901a41b56c0fca2c7797021a1e522.
The underlying storage cause is unproven; the recorded bundle cannot qualify
those changed bytes. The dev copy retains the original invalid bytes as
evidence. The isolated runner rejected execution before starting a fleet.
ELF structural checks and durable stable-byte sealing are being completed
before a new provenance-bound candidate. No live release, current TPS baseline
or soak started. Native fault coverage, measured parameter approval and the
five-host qualification gates remain open.

Artifact guard follow-up: four sealing regressions passed, including byte
instability with unchanged metadata. Full filesystem flush and repeated
structure/hash verification succeeded on the previously changing exporter.
The corrected native epoch-root regression passes. Below-quorum socket halt
and recovery now passes; dropped-timeout convergence failed and is being
isolated while the remaining consolidated suite runs. A newly sealed candidate
may be used for isolated diagnosis; none of these results authorizes promotion.

### Build-storage and fixture follow-up — 2026-10-13 14:05 UTC

The sealed build rejected its fixture exporter during assembly after selection
had read a valid ELF. Device flush and matching reads alone did not eliminate
the observed ExFAT instability. Compiler outputs now move to the backing Mac's
internal APFS build cache only:
`/Users/jhutzler/Library/Caches/Synergy-PoSy-qualification-target`.
Source stays in the single canonical SSD checkout. Previous invalid bundles
and logs remain evidence, never eligible deployment artifacts.

The focused dropped-timeout failure was outbound admission in the test
fixture; it was not a timeout/QC convergence assertion. Its retry polled
Network then PoSy before attempting admission again, allowing retries to
refill bounded slots. The fixture now drains its real sender Network service
immediately before the next admission attempt, preserving quotas, exact
frames, authentication and its deadline. Added failure context identifies the
event and recipient. This correction remains unverified until the scenario
passes. Other completed socket checks include focused restart and genuine
nonempty admission/execution/closed-cutoff. Qualification gates remain open.

### Actual-host and admission scheduling findings — 2026-10-13
Read-only direct host verification: Val2,Val4,Val6 process/service active;
Val3,Val5 failed and no loopback RPC listener. Three active processes cannot
meet four-of-five quorum; active alone does not prove advancing finality.
Val3 journal: timeout proof variant changes accepted parent or carry, four
restart attempts. Val5 journal: persist protected admission close before
broadcast: InvalidCapacity, six restart attempts. No restart, reset, journal
deletion or deployment was performed.

The APFS Linux candidate passed genuine native Genesis/binding validation and
the wrapper was corrected to its native nested anchor. In isolated run
d8-funded-restart, the first funded RPC enqueue preceded target159 cutoff
by1.556seconds but no durable preparation/admission followed before closure.
Source inspection establishes shared-lane starvation: an8MiB context occupies
the full8MiB admission lane and eager replacement precedes wallet dispatch;
older open contexts were also repeatedly regenerated then evicted by a
two-response cache. The integrated correction drains both completion owners,
holds dispatch priority until real dispatch, and limits context candidates to
cache-retainable targets. Causal regressions are added; validation pending.
No increased lookahead is justified by this failed transfer alone.

Single-host Linux five-process runs remain functional/fault evidence only.
Representative timing, production parameter selection, TPS and the loaded
soak require the independent Val2–Val6 topology. Current host errors are being
matched against the integrated source; all qualification/activation gates
remain open and the soak has not started.

## Compact PoSy timeout history — 2026-10-19 final source checkpoint

IMPLEMENTED / VALIDATED_LOCAL; final Linux actual-host qualification pending.
Accepted timeout certificates retain sealed authenticated summaries, bounded to
4096 entries and64MiB conservative metadata; obsolete timeout-vote signatures
are released. Exact native originals remain immutable on disk. Retry frames hold
compact references and load one original at a time; active retry work reads at
most four originals per poll and historical work reads at most one. Historical
scans inspect at most64 directory entries per poll and paginate4096 slot locators
for one historical lease, without omitting larger retained histories. Alternating
current/history priority preserves progress with a one-frame outbound queue.
Startup replay and cold recovery suffix verification no longer retain full proof
bundles. Typed resource pressure preserves valid QC processing. Canonical signed
V1 roots, native signatures, quorum, carry, contradiction checks and exact retry
bytes remain unchanged.

Validation:36 PoSy tests,10 native runtime qualification tests, genuine signed
R3/restart,4096-reference exact-original variant/contradiction regression and
15000-slot/three-lease pagination pass. Independent Einstein review cleared the
Hercules runtime integration; strict targeted Clippy and formatting pass.
These are local results, not final actual-host OOM closure. Nothing deployed.
