# PoSy v3 simplified consensus architecture

PoSy v3 is an epoch-gated candidate engine. For the Genesis-bound initial
epoch, the validator role runtime constructs and spawns the authenticated
simplified driver after replaying the exact v2 boundary and opening the durable
safety, proposal-material, signer-journal, and finality-WAL authorities. A
deferred ETDAG decision selects the deterministic core adapter; a finalized
permit selects the protected adapter, durable WAL/material authority, and
authenticated schedule-neutral ETDAG ingress. Ingress installation and cleanup
are transactional with the execution snapshot and simplified driver lifecycle.
The applied Genesis currently defers ETDAG. An unverified later-epoch transition
still fails closed. The inherited legacy engine remains disabled, and the v2.2
canonical parameter record remains authoritative until a separately finalized
schema-4 manifest and transition activate v3.

The runtime implementation is split into:

- `schedule.rs`: dynamic frozen-epoch validator context (five for the initial activation), full SHA3-512 ring, lease ownership, and one-failure weight preflight;
- `certificates.rs`: one ordinary block vote/QC, timeout vote/TC, canonical participant order, Aegis verification, and recomputed exact quorums;
- `state.rs`: safe proposal, highest/locked QC, three-chain commit, sequential lease takeover, rooted atomic restart state, signer-journal integration, and conflicting-QC SafetyHalt;
- `reliable_delivery.rs`: authenticated ECHO/READY delivery that prevents a
  Byzantine proposer from splitting the one ordinary block vote;
- `material.rs` and `material_sync.rs`: immutable full proposal material,
  independent replay, and bounded peer/request-correlated recovery;
- `protected_material.rs`: schedule-neutral certified ETDAG material,
  deterministic execution/replay, and durable authority reconstructed from the
  finality WAL plus bounded certified tail;
- `target_admission_producer.rs`: dynamic H+3 target assignment, exact public
  ML-KEM registry loading, journaled ML-DSA votes, strict count-and-weight
  certificates, and authenticated process-wide ingress;
- `finality.rs`: immutable finality WAL with complete QC witnesses and startup
  re-execution, including verified-transition previous-tail replay;
- `transition.rs`: exact previous-epoch three-QC tail and dynamic next-set
  proof boundary, still fail-closed until executed state proves authorization;
- `activation.rs`: Genesis-bound, finalized-boundary profile selection with no
  environment/configuration activation fallback;
- `driver.rs`: authenticated peer envelopes, bounded ingress, proposal/vote/TC
  collection, reliable delivery, material/state recovery, and injected
  protected-execution/finalization boundaries; `role_runtime` spawns it for
  either finalized initial-epoch material mode;
- `p2p/messages.rs` and `p2p/networking.rs`: a distinct bounded simplified
  consensus wire family and frozen-validator fanout/ingress;
- `metrics.rs`: bounded non-consensus proposal/vote/QC/finality/TC/takeover/PQC/size/rejoin samples;
- `posy_simplified_parameters.rs`: canonical schema-4 proposal loader that refuses activation while approval/epoch/height are absent.

The normal data flow is proposal validation → durable vote authorization → ML-DSA-65 vote → independently verified QC → lock/highest-QC advancement → three-chain ancestor commit. The failure flow is local timer → durable timeout vote → independently verified sequential TC → current-lease takeover. No local observation is an authority input.

## Qualification boundary

Two five-process harnesses are retained with deliberately different scopes.
The state-machine harness exercises direct consensus objects and long takeover
sequences. The autonomous-driver harness starts five independent OS processes;
each child owns the production `SimplifiedPosyDriver`, real timers, ephemeral
ML-DSA-65 authority, and distinct durable safety, signer-journal, proposal
material, and finality-WAL stores. Its parent is only a bounded authenticated
router and fault injector: it does not construct proposals, votes, QCs, TCs, or
state-sync evidence. The passing run proves 4/5 progress, 3/5 fail-closed,
three-chain finality, real-timer takeover, proposal-material recovery,
future-QC state-sync healing, and exact durable restart authority. Private
harness keys are removed before success is reported.

This satisfies the specifically named five-process harness gate, but it is not
five complete `synergy-node` deployments using the production role-runtime and
socket stack. Full qualification remains open for protected ETDAG/BOC/reveal
execution with provisioned public KEM registries, production identity and
deployment bundles, real socket churn/backpressure, node-database convergence,
Byzantine/model review, and performance/soak evidence.

For a finalized protected profile, role-runtime now constructs the dynamic H+3
target-admission producer, requires the exact externally provisioned public
ML-KEM registry before activation, broadcasts its journaled vote/certificate
traffic only to the frozen validator set, and tears the auxiliary worker down
with the consensus lifecycle. It never derives next-epoch H+3 inputs before a
verified transition. Future v3 startup still stops at the production
finalized-execution transition-authority proof boundary.

See `docs/posy-v3/ARCHITECTURE.md` for diagrams and POSY-00E for normative rules.
