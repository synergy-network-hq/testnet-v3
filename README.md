# Synergy Testnet-v3

Synergy Testnet-v3 is the operating Synergy Network testnet on **Chain 1266**.
It has been running for several months. This repository contains its testnet
runtime source, network artifacts, operational tooling, and technical
documentation.

Development continues alongside network operations. Historical launch
checklists and qualification work for new releases describe particular
artifacts or candidate deployments; they do not mean the testnet is awaiting
its initial launch.

## Network identity

| Setting | Value |
| --- | --- |
| Network | Synergy Testnet-v3 |
| Release ID | `testnet-v3` |
| Runtime network ID | `synergy-testnet-v3` |
| Chain ID | `1266` |
| Numeric network ID | `1266` |
| Native token | `SNRG` |
| Consensus | Proof of Synergy (PoSy) |

Use the runtime network ID as well as the chain ID when selecting configuration,
transactions, snapshots, or recovery material. A matching numeric chain ID alone
does not establish compatibility with an approved chain incarnation.

## Start here

- **Explore the repository:** use the directory guide below to find runtime
  source, contract artifacts, network tooling, and monitoring configuration.
- **Work on the protocol:** start with the
  [PoSy architecture](docs/posy-v3/ARCHITECTURE.md) and
  [protected-pipeline protocol](docs/posy-v3/PROTECTED_PIPELINE_PROTOCOL.md).
  Read each document's profile and qualification scope before applying it.
- **Operate or monitor nodes:** use the
  [observability guide](observability/OBSERVABILITY.md),
  [target inventory](observability/TARGET_INVENTORY.md), and
  [validation procedure](observability/VALIDATION.md).
- **Investigate an incident:** read the
  [Chain 1266 stall log](CHAIN_1266_STALL_LOG.md) and the repository's
  [operating instructions](AGENTS.md) before changing a node.

For current endpoints, node configuration, and approved releases, use the
operator-maintained configuration and release instructions for the intended
network. Repository examples and archived launch bundles require validation
against that deployment.

## Protocol and execution

**Proof of Synergy** coordinates proposals, validator votes, quorum
certificates, and finality. PoSy uses pipelined three-QC finality: a quorum
certificate establishes certification, while finality requires the governed
certified-chain relationship. Stake and Synergy Score do not determine
finality.

**ETDAG and the protected pipeline** supply authenticated, verified proposal
material to PoSy. Networking transports that material and consensus messages;
persistence preserves signing safety and finalized history. These supporting
systems remain subject to the network's governed cryptographic and protocol
checks.

**AIVM** is the Synergy Network smart-contract runtime. **SynQ** is the contract
language and compiler targeting AIVM. This repository includes native SynQ
genesis-contract sources and their associated compiled artifacts and manifests.
The presence of a contract artifact or an implemented component does not by
itself establish activation on the running network.

## Repository guide

| Path | Contents |
| --- | --- |
| [`runtime/`](runtime/) | Testnet runtime source, role binaries, configuration, and supporting components |
| [`docs/posy-v3/`](docs/posy-v3/) | Consensus architecture, protected-pipeline specifications, schemas, and engineering notes |
| [`genesis-contracts/`](genesis-contracts/) | Native SynQ genesis contracts, compiled bytecode, ABIs, manifests, and deployment inputs |
| [`validator-workspace/`](validator-workspace/) | Secret-free validator filesystem templates |
| [`observability/`](observability/) | Prometheus/Grafana configuration, target inventories, and validation tools |
| [`scripts/`](scripts/) | Artifact validation, release preparation, configuration generation, and operational tools |
| [`launch/`](launch/) | Launch history, governed artifact inputs, release-candidate material, and qualification records |
| [`artifacts/`](artifacts/) | Release-artifact directory; generated binaries and bundles depend on the release process |
| [`atlas/`](atlas/) | Explorer-related resources |
| [`research/`](research/) | Research and benchmark tooling |

Active universal-node development is owned by the canonical Core Protocol
`node-platform/` implementation. This Testnet-v3 repository also preserves
existing testnet release history and network-specific material. Coordinate
runtime changes with that canonical implementation and the applicable source
ownership rules.

## Development and validation

Read [AGENTS.md](AGENTS.md) and applicable workspace instructions first. The
runtime is a Rust Cargo workspace; validation and release tooling also use
Python. Some Cargo dependencies resolve to sibling source checkouts, so use
the dependency setup and pinned revisions required by the relevant workflow
rather than assuming a standalone clone contains every dependency.

Review the checked-in
[verification workflow](.github/workflows/posy-v3-pr-verification.yml) for its
current dependency and test setup.

The repository provides several checks with different purposes:

```bash
# Validate repository structure and network metadata.
python3 scripts/validate-testnet-v3.py --structure

# Validate the component packaging and contract-artifact parity manifest.
python3 scripts/check-component-parity.py

# Evaluate the launch/release artifact controls represented in this checkout.
python3 scripts/validate-testnet-v3.py
```

These checks evaluate files and recorded controls in the checkout. They are
not live network-health probes. A failure can identify missing artifacts,
stale metadata, or an unqualified candidate; interpret it against the exact
release and chain incarnation under review.

Changes to genesis, validator membership, identities, governed parameters, or
signed releases require their applicable approval and qualification process.
An operating testnet does not automatically qualify every subsequent release
candidate.

## Operations and network health

Assess current health from advancing finalized chain data. Operators should
verify agreement on finalized block IDs across the validator set, sustained
progression, consensus/signing errors, and observer and public-service lag.
An active process, reachable peer, or successful repository check alone is
insufficient to establish healthy finality.

Use the [observability documentation](observability/OBSERVABILITY.md) for the
monitoring configuration and [Chain 1266 stall log](CHAIN_1266_STALL_LOG.md) for
recorded incidents and recovery work. Historical observations describe their
recorded interval and must be rechecked before an operational decision.

## Reading historical material

The [changelog](CHANGELOG.md), `VERSION`, older nested documentation, and
`launch/` include records from the original preparation period. Labels such
as `prelaunch`, unsigned inputs, and incomplete launch checklists belong to
those artifacts or candidate profiles. They should not be read as a statement
that Synergy Testnet-v3 has never launched.

For a specific deployment, identify its approved release, governed genesis,
chain incarnation, and configuration. Preserve authenticated chain history and
signing-safety state when performing upgrades or recovery.

## Repository security

Keep private keys, decrypted key files, passwords, credentials, `.env` files,
and live chain state out of this repository. Use the approved provisioning and
custody procedures for operational material.
