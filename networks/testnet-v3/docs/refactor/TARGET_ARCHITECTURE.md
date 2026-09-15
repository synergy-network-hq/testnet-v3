# Target architecture

## Canonical Core Protocol root

The Core Protocol repository, not an individual network directory, owns the
universal node implementation:

```text
01-Core-Protocol/
├── node-platform/          # One reusable Synergy node implementation.
├── networks/               # Governed network-specific artifacts only.
│   ├── devnet/
│   ├── testnet-v3/
│   ├── mainnet-beta/
│   └── mainnet/
├── protocol/               # Normative protocol specifications and schemas.
└── tooling/                # Operator, release, Genesis, DB, and key tooling.
```

`01-Core-Protocol/testnet-v3/node-platform/` is transitional and is not a
permitted final source location. A network configures and deploys the universal
node; it never owns the node implementation. Unknown mainnet values remain
absent or explicitly blocked and must not be fabricated.

## Universal node and authority boundaries

One `synergy-node` distribution composes the canonical 20 roles from explicit
capabilities. Optional AI, indexing, analytics, oracle, and cross-chain roles
must not become base-chain liveness dependencies.

Authority remains singular:

- PoSy alone owns validator authority, agreement, QCs, and finality.
- ETDAG owns H+5 protected user ingress, availability, deterministic ordering,
  reveal authorization consumption, and verified execution input.
- P2P transports authenticated messages and never grants authority.
- Sync verifies and restores state but never determines finality.
- Execution computes deterministic transitions but never determines finality.
- VPN/NetBird supplies transport connectivity only.
- Storage owns durable, bounded, crash-safe persistence.
- Lifecycle/supervision owns service readiness and process orchestration.

Stake is economic participation and accountability, not Proof-of-Stake voting
power. Synergy Score never determines finality. Approved frozen validator
weights and the independent validator-count and voting-weight quorum checks are
preserved unless a governed protocol amendment replaces them.

## Identity, naming, ownership, and rewards

Every node has one canonical protocol identity:

```text
Node Address = synv<class>... canonical protocol identity
NodeID       = normalized <name>.node Synergy Naming System alias
```

Consensus, authorization, persistence, rewards, slashing, telemetry, sync, and
transport bindings use the Node Address. Hostnames, IP addresses, VPN peer IDs,
TLS sessions, signing keys, and NodeIDs are subordinate locators, credentials,
or aliases. Security-sensitive code resolves a NodeID to a Node Address before
use and never authorizes a NodeID string directly.

A first-class naming owner provides NodeID normalization, availability,
registration, owner-authorized update/rename, forward resolution, and reverse
resolution. Renaming a NodeID changes no cryptographic identity, consensus
authority, ownership, reward state, transport identity, or sync state.

Node ownership is a durable, cryptographically proven binding from Node Address
to a Synergy Wallet. Node software never stores the owner wallet private key.
Server access, node keys, VPN credentials, and local Admin access cannot
withdraw rewards. Rewards are attributed to the Node Address; withdrawal
requires an explicit owner-wallet authorization. Economic formulas are outside
this migration unless already governed.

## Shared management and exact interface parity

All management decisions live behind one typed management dispatcher and Admin
API:

```text
shared node services
        |
management dispatcher
        |
typed Admin API + machine-readable capability registry
       / \
     CLI  Node Control Panel
```

The CLI and Node Control Panel expose exactly the same declared capabilities.
The GUI does not shell out to or scrape the CLI, and neither interface owns
protocol, lifecycle, validator, naming, ownership, reward, or upgrade policy.
Parity covers lifecycle, roles, identity, Node Address, NodeID, owner binding,
rewards, peers, transport/VPN, PoSy, ETDAG, sync, snapshots, storage,
telemetry, diagnostics, recovery, validator operations, and updates.

## Software updates and protocol activation

Software installation and protocol activation are independent state machines.
The automatic updater owns signed release discovery, channel and policy
selection, staged download, Aegis verification, compatibility checks,
disk-space preflight, controlled drain/restart, health validation, rollback,
audit/telemetry, and activation awareness. Installing compatible future
software never activates future protocol behavior before its governed boundary.

P2P, PoSy, ETDAG, sync, snapshot, Admin API, database schema, configuration
schema, and software release retain independent version domains.

## Operator lifecycle and zero-touch onboarding

The operator-visible lifecycle is:

```text
Create -> Join -> Sync -> Ready -> Active
```

Internal safety states may remain, but ordinary progression is automatic.
Jailing, removal, and expulsion remain exceptional governed states. A new node
or validator discovers and authenticates existing infrastructure without
requiring edits or restarts on existing validators. `synergy-node init` and
`synergy-node join --role <role>` and their GUI equivalents use the same typed
operations.

The historical 1,000-block shadow rule remains unresolved until its governing
source classifies it as a protocol rule or operational qualification. It is not
silently retained or removed.

## PO_SY_SIMPLIFICATION_DECISIONS

The target is the smallest deterministic Proof-of-Synergy implementation that
preserves governed safety, liveness, membership, recovery, and finality.

Retained now:

- One driver owns height/round, proposer duty, proposal, validation, vote,
  count-and-weight quorum, QC, three-QC finality, durable commit, and advance.
- Three-QC finality is a governed safety rule and remains until an approved,
  versioned replacement proves equivalent safety.
- Timeout evidence remains only as the bounded liveness mechanism needed to
  leave a stalled round; it cannot outrun valid voting or invent authority.
- Durable-before-send sign-once state, immutable QCs/finality, and restart
  recovery remain because losing them can permit contradictory signing or
  unsafe replay.
- Epoch transitions preserve finalized authority and the required QC tail.
- ETDAG H+5 protected material remains an authenticated supporting input, not a
  second agreement or finality engine.

Removed from the target control plane:

- Proof-of-Stake, Synergy-Score finality, VPN-derived authority, and
  transport-derived authority.
- Independent ETDAG batch consensus, finality, or view-change ownership.
- Duplicate PoSy coordinators, competing finality stores, and overlapping
  startup/recovery drivers.
- Manual lifecycle ceremonies that can be derived safely from governed state.
- Optional service gates on validator block production.

Still requiring source/caller/persistence proof before removal:

- timeout carry-forward details;
- prepared-state layers beyond durable-before-send requirements;
- peer-quorum reconstruction;
- cluster scheduling and leader-ranking mechanics;
- shadow-state and activation-ceremony residue;
- overlapping legacy authority records.

Every removal requires caller, persisted-state, wire, and test migration. This
section records architecture decisions; it does not itself claim implementation
or validation.

## Protocol, network, and tooling ownership

`protocol/` contains normative PoSy, ETDAG, SXCP, UMA, Aegis integration,
transaction, block/state, Node Address, NodeID, ownership/reward, manifest,
versioning, lifecycle, and wire/schema definitions. It contains no duplicate
Rust engine.

`networks/<network>/` contains only governed network artifacts such as manifest,
Genesis, bootseeds, protocol versions, role assignments, and ETDAG parameters,
fees, ingress keys, and activation data.

Reusable libraries stay in `node-platform/crates`. Operational executables may
remain Rust workspace members while `tooling/` owns their operator-facing
entrypoints, policy, and documentation. There is exactly one implementation of
each command.

## Migration and evidence states

The ledgers keep these claims separate:

- `IMPLEMENTED`: canonical production source exists.
- `CALLERS_MIGRATED`: real production callers use that owner.
- `LEGACY_REMOVED`: the legacy owner is unreachable as active production code.
- `VERIFIED`: the required static, build, test, integration, and live evidence
  for the claimed boundary has passed.

No populated file, scaffold, build, or single-node process status proves the
architecture migration complete.
