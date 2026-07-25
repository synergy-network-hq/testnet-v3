# Node Role Functions

This guide is the bundled Node Control Panel role reference for Synergy Testnet
operators. It describes what each role may do, what it must not do, and which
control-panel surfaces are allowed to manage that role.

Current runtime note: Synergy Testnet uses chain id `1264` and network id
`synergy-testnet-v3`. Validator, archive, relayer, observer, RPC gateway, and
Atlas/indexer responsibilities remain separated so the control panel can block
unsafe actions instead of hiding role drift.

## Control Panel Role Boundaries

- `/#/validator/detail` is the validator appliance surface for lifecycle,
  package, identity, state, and activation evidence.
- `/#/clusters` is the dynamic validator-cluster and assignment surface.
- `/#/state-sync` is the validator-pruned recovery and state-sync surface.
- `/#/archive` is the archive canonicality, reseed, and snapshot safety surface.
- `/#/incidents` is the evidence surface for quarantine, rollback, and operator
  handoff records.

The control panel must not turn a support node into a validator, must not use
archive state as canonical unless archive verification has passed, and must not
expose signing actions on read-only service nodes.

### Validator Node

Function: participates directly in PoSy consensus by proposing, voting, and
finalizing blocks with its assigned validator identity.

Boundary: validator signing keys and consensus state are local to the appliance.
State-sync and package updates must prove chain id, network id, snapshot class,
quorum evidence, and validator identity before any start or rejoin action.

Current runtime note: validator actions are managed through
`/#/validator/detail`, `/#/clusters`, and `/#/state-sync`; unsafe package,
identity, archive, or quorum evidence blocks activation.

### Committee Node

Function: handles committee rotation, assigned coordination, and policy-bound
consensus support duties.

Boundary: committee authority is limited to the active assignment window. The
node must reject actions outside its role certificate and recorded assignment.

Current runtime note: committee work follows the same dynamic topology rules as
validators but does not bypass validator identity or cluster safety checks.

### Archive Validator Node

Function: stores complete chain history and provides the trusted source for
archive validation, replay, proofs, and snapshot generation after canonical
reseed gates pass.

Boundary: archive history is not trusted merely because it exists. Archive
validator, snapshot worker, and snapshot API actions stay blocked until
canonical chain id, network id, hash, quorum proof, and source validation pass.

Current runtime note: archive controls belong under `/#/archive`; old or
noncanonical archive state must be cataloged and quarantined before publication
or reseed actions proceed.

### Audit Validator Node

Function: observes consensus behavior independently and emits audit evidence for
validator drift, correlated failure, and policy violations.

Boundary: audit duties are observational and evidentiary. Audit findings can
block operator workflows but must not directly mutate validator identity or
chain state.

Current runtime note: audit evidence is recorded with incident records under
`/#/incidents` and validator status records under `/#/validator/detail`.

### Relayer Node

Function: transports cross-chain, SXCP, and relay work queues while preserving
ordering and finality assumptions.

Boundary: relayers do not vote in consensus and do not serve as canonical chain
state for validator recovery. Queue health, peer health, and upstream chain
evidence must be checked before restart or rollback.

Current runtime note: relayer health may affect launch readiness, but relayer
repair must not mutate validator state unless a public-chain emergency is proven.

### Witness Node

Function: provides independent witness observations, receipts, and availability
signals for network events.

Boundary: witness records are support evidence. They do not grant signing
authority and must be correlated with canonical RPC or validator evidence before
blocking or recovery decisions.

Current runtime note: witness evidence belongs in incident and audit records,
not validator activation records by itself.

### Oracle Node

Function: supplies external data attestations to approved runtime consumers.

Boundary: oracle data must be signed, attributable, and policy-scoped. Oracle
availability must not be confused with consensus finality or archive canonicality.

Current runtime note: oracle failures can degrade dependent features but must not
trigger validator state repair unless consensus evidence also fails.

### UMA Coordinator Node

Function: coordinates UMA-style dispute, assertion, or attestation workflows
when those workflows are enabled for a role.

Boundary: coordinator actions are workflow orchestration, not chain authority.
The coordinator must preserve source evidence and authorization records.

Current runtime note: UMA coordination is tracked as a support role and remains
outside validator signing and archive snapshot publishing surfaces.

### Cross-Chain Verifier Node

Function: verifies cross-chain proofs, remote finality claims, and bridge-related
evidence before relayer or application consumption.

Boundary: verification failure must fail closed. The verifier does not become a
canonical source for Synergy Testnet height or validator-set truth.

Current runtime note: verifier outputs can block relayer workflows but do not
replace public RPC, validator quorum evidence, or archive canonical checks.

### SynQ Execution Node

Function: executes SynQ workloads against the approved runtime and records
deterministic execution evidence.

Boundary: SynQ execution is application execution. It must not mutate consensus
configuration, validator membership, or archive snapshot catalogs.

Current runtime note: SynQ health is reported separately from validator active
count and public RPC canonicality.

### Analytics & Simulation Node

Function: runs replay, analytics, simulation, and planning jobs against exported
or read-only data.

Boundary: analytics outputs are advisory unless promoted through an explicit
operator-approved workflow. Simulation results must not be treated as live chain
state.

Current runtime note: analytics and simulation failures can create readiness
warnings but should not block validator rejoin unless they expose a real runtime
or evidence inconsistency.

### Aegis Cryptography Node

Function: performs cryptographic verification, signing-policy evaluation, and
post-quantum evidence checks where configured.

Boundary: cryptography services validate inputs and policies; they do not own
validator private keys unless the role certificate explicitly allows it.

Current runtime note: failed verification is a blocker for package, snapshot,
and identity workflows, but the fix must be at the bad artifact or policy source.

### Data-Availability Node

Function: serves data-availability checks and proof material for approved
workloads.

Boundary: data availability is not consensus finality. Missing availability data
must be reported without inventing canonical block or snapshot evidence.

Current runtime note: availability health is support infrastructure evidence and
must be compared with canonical RPC or validator evidence when used in rollout
decisions.

### Governance Auditor Node

Function: records and audits governance actions, policy changes, and operator
approvals.

Boundary: governance audit records document authority; they do not themselves
grant validator, archive, or relayer permissions.

Current runtime note: governance audit output can be attached to `/#/incidents`
or activation evidence when operator approval is required.

### Treasury Controller Node

Function: manages treasury policy workflows and financial-operation approvals.

Boundary: treasury control is isolated from validator signing, consensus state,
archive snapshot generation, and public RPC routing.

Current runtime note: treasury activity is not part of validator recovery unless
an approved runtime or staking workflow explicitly references it.

### Security Council Node

Function: reviews critical safety incidents, emergency stop conditions, and
high-impact operator decisions.

Boundary: security council approval may authorize a workflow, but the workflow
still must pass technical validation gates in the control panel.

Current runtime note: security council records belong in incident evidence and
do not replace snapshot, package, chain, quorum, or identity validation.

### RPC Gateway Node

Function: exposes public and operator RPC access while routing only to trusted,
healthy, canonical backends.

Boundary: the gateway is a read path and must not hold signing authority. It
must reject stale, minority, wrong-chain, wrong-network, or ambiguous backend
evidence.

Current runtime note: RPC gateway rollout belongs after validators and direct
backend health are stable. Gateway health is compared against direct validator
qRPC before public RPC is treated as canonical.

### Indexer & Explorer Node

Function: indexes chain data for Atlas/explorer APIs, search, block pages,
transaction pages, validator views, and user-facing chain history.

Boundary: indexer data is derived and rebuildable. Atlas must show canonical
public chain data and must not display stale archive or minority backend state
as authoritative.

Current runtime note: Atlas/indexer recovery follows RPC gateway stability and
checks exact-height hash parity against public RPC and direct canonical sources.

### Observer / Light Node

Function: verifies headers and proofs with a minimal read-only state footprint.

Boundary: observer nodes do not vote, propose, publish archive snapshots, or
serve as canonical recovery sources for validators.

Current runtime note: observer health helps monitoring and support-node rollout,
but validator active count and public RPC advancement remain separate gates.
