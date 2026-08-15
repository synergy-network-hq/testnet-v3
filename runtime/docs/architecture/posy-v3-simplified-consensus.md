# PoSy v3 simplified consensus architecture

PoSy v3 is an epoch-gated candidate engine. Activation selection and an
authenticated P2P wire/ingress family exist, but the autonomous simplified
validator driver is not installed in the role runtime; selecting v3 therefore
fails closed. The inherited legacy engine remains disabled. The existing v2.2
canonical parameter record remains authoritative until a separately finalized
schema-4 manifest and transition activate v3.

The runtime implementation is split into:

- `schedule.rs`: dynamic frozen-epoch validator context (five for the initial activation), full SHA3-512 ring, lease ownership, and one-failure weight preflight;
- `certificates.rs`: one ordinary block vote/QC, timeout vote/TC, canonical participant order, Aegis verification, and recomputed exact quorums;
- `state.rs`: safe proposal, highest/locked QC, three-chain commit, sequential lease takeover, rooted atomic restart state, signer-journal integration, and conflicting-QC SafetyHalt;
- `activation.rs`: Genesis-bound, finalized-boundary profile selection with no
  environment/configuration activation fallback;
- `driver.rs`: authenticated peer envelopes, bounded ingress, proposal/vote/TC
  collection, and an injected protected-execution/finalization boundary; the
  module exists but is not spawned by `role_runtime`;
- `p2p/messages.rs` and `p2p/networking.rs`: a distinct bounded simplified
  consensus wire family and frozen-validator fanout/ingress;
- `metrics.rs`: bounded non-consensus proposal/vote/QC/finality/TC/takeover/PQC/size/rejoin samples;
- `posy_simplified_parameters.rs`: canonical schema-4 proposal loader that refuses activation while approval/epoch/height are absent.

The normal data flow is proposal validation → durable vote authorization → ML-DSA-65 vote → independently verified QC → lock/highest-QC advancement → three-chain ancestor commit. The failure flow is local timer → durable timeout vote → independently verified sequential TC → current-lease takeover. No local observation is an authority input.

## Qualification boundary

The checked-in five-process harness is a consensus state-machine qualification,
not an autonomous node-network test. It starts five independent OS workers,
each with its own real ephemeral ML-DSA-65 key, durable signer journal, rooted
safety state, Aegis verifier, and `SimplifiedConsensusStateMachine`. It proves
production proposal/vote/timeout signing, exact QC/TC validation, one-worker
loss tolerance, two-worker fail-closed behavior, sequential takeover,
signer-independent authority convergence, verified state-sync reconstruction,
restart preservation, lease reset, and three-chain finality. Private harness
keys exist only in its temporary directory and are removed before success is
reported.

The harness parent remains the deterministic driver: it supplies proposal work,
requests worker signatures, assembles QC/TC objects, relays artifacts over
standard input/output, and controls simulated partitions/healing. Consequently
the passing result does not prove:

- an autonomous simplified driver in `role_runtime`;
- authenticated P2P proposal/vote/QC/timeout/state-sync exchange under socket
  loss, duplication, reordering, backpressure, or peer churn;
- ETDAG/BOC/reveal-derived protected execution rather than the harness's
  deterministic synthetic protected-execution root;
- block execution, receipt/state-root validation, or durable finalized block
  application by five node databases;
- production identities, topology, deployment bundles, performance/soak, or
  release/launch readiness.

The launch-readiness harness gate therefore remains false until an autonomous
five-node driver/P2P/execution/commit qualification supplies that broader
evidence.

See `docs/posy-v3/ARCHITECTURE.md` for diagrams and POSY-00E for normative rules.
