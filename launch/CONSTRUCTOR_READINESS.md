# Constructor readiness — nine Testnet-v3 native contracts

Session 13e, 2026-07-28. Read from the actual `.synq` constructor signatures and
the genesis `init_params`, not from documentation.

**No constructor is final. No constructor hash can be computed yet, and
therefore no contract address can be derived.** Three independent problems.

## Blocker A — the canonical deployment order is not a valid topological order

The earlier "no ordering constraints" finding was wrong. It was based on genesis
`init_params`, which contain no contract addresses. The **constructors** do:

| contract | constructor address parameters | resolves to |
|---|---|---|
| Identity | `initialFeeCollector` | fee-collector wallet — not a contract |
| ValidatorRegistry | `initialAuthority` | `synl1g8hg…` (VNS-A01) — not a contract |
| Treasury | `initialGovernanceContract` | **Governance** |
| Governance | `stakingVotesProvider` | **Staking** |
| Staking | `registry` | **ValidatorRegistry** |
| Slashing | `registry`, `staking` | **ValidatorRegistry**, **Staking** |
| RewardDistributor | `initialDistributorAuthority` | `synl1g8hg…` — not a contract |
| SynergyOracle | — | — |
| TeamVesting | admin authority | `synu18tmd…` — not a contract |

Required precedence: `ValidatorRegistry → Staking → Governance → Treasury`, and
`Staking → Slashing`.

The proposed order deploys **Treasury (2) before Governance (3) before Staking
(4)** — backwards on both edges. Under deployment-derived addressing a
contract's address depends on its constructor-args hash, so those addresses are
not merely mis-ordered, they are **uncomputable** in that order.

No cycle exists, because `ValidatorRegistry.initialAuthority` is a wallet rather
than the Governance contract. A valid order is available:

| nonce | contract | change |
|---:|---|---|
| 0 | Identity | — |
| 1 | ValidatorRegistry | — |
| 2 | **Staking** | was 4 |
| 3 | Governance | — |
| 4 | **Treasury** | was 2 |
| 5 | Slashing | — |
| 6 | RewardDistributor | — |
| 7 | SynergyOracle | — |
| 8 | TeamVesting | — |

This needs an operator ruling because the order is a frozen, signed input.

## Blocker B — `initialGovernanceKey` does not exist

**Eight of the nine constructors take `initialGovernanceKey: MLDSAPublicKey` as
their first parameter.** (Corrected: TeamVesting does **not** — it takes
`initialAdmin: Address` only. See `CONSTRUCTOR_DEPENDENCY_GRAPH.md`.) There is
no value for it anywhere in the genesis document: `governance_key`,
`governanceKey`, `initialGovernanceKey` and `governance_public_key` all return
**zero occurrences**.

Operator ruling 2026-07-28: generate a dedicated **Testnet-v3 Initial Governance
Authority** (`SNRG-TESTNET-V3-INITIAL-GOVERNANCE`), ML-DSA-87, through the
custody ceremony — distinct from the Genesis Deployer, no deployment authority,
retired after the post-deployment governance handoff.

`governance.execution_authority` is the string `"governance_contract"`, not a
key. The emergency block lists two guardian *addresses*, not a public key.

This single missing input blocks all nine constructor hashes, and therefore all
nine addresses. It cannot be invented — it is the key that will authorize
governance operations on every native contract.

## Blocker C — `init_params` are not constructor arguments

The genesis `init_params` are configuration records, not typed constructor
inputs. They do not map 1:1 and several need unit conversion:

| contract | genesis value | constructor parameter | conversion |
|---|---|---|---|
| Governance | `quorum_pct: 0.6` | `quorumBps: UInt256` | → `6000` |
| Governance | `approval_pct: 0.5` | `approvalBps` | → `5000` |
| Governance | `veto_pct: 0.33` | `vetoBps` | → `3300` |
| Governance | `voting_duration_seconds: 604800` | `votingBlocks` | ÷ 2 s → `302400` |
| Governance | `timelock_delay_seconds: 86400` | `timelockBlocks` | ÷ 2 s → `43200` |
| Staking | `unbonding_period_seconds: 604800` | `unbondingBlocks` | ÷ 2 s → `302400` |
| Staking | — | `minimumDelegation`, `maximumDelegation` | **absent** |
| Slashing | `double_sign_slash_pct: 5` | `initialDoubleSignSlashBps` | → `500` |
| Slashing | `downtime_slash_pct: 1` | `initialDowntimeSlashBps` | → `100` |
| Slashing | `invalid_block_slash_pct: 5` | `initialInvalidBlockSlashBps` | → `500` |
| Slashing | `jail_duration_seconds: 86400` | `jailBlocks` | ÷ 2 s → `43200` |
| Slashing | — | `initialSlashingAuthority` | **absent** |
| Treasury | `required_signers: 4` | `initialRequiredSigners` | direct |
| Treasury | `signers`, `vault_address`, `initial_balance_nwei` | — | **no constructor parameter** |
| Identity | `registration_fee_nwei: 1000000` | `initialRegistrationFee` | direct |
| Identity | `reserved_names` | — | **no constructor parameter** |
| SynergyOracle | `quorum_threshold: 1` | `initialQuorumThreshold` | direct |
| SynergyOracle | `replay_protection_enabled: true` | `enableReplayProtection` | direct |
| ValidatorRegistry | `max/min_validator_count`, `min_self_stake_nwei` | direct | direct |

The seconds→blocks divisor comes from `consensus.target_block_time_ms = 2000`.
That derivation is arithmetically obvious but is still a governed parameter
choice and should be confirmed rather than assumed, because it sets real
governance timelocks.

Percentages given as floats (`0.6`, `0.33`) must become integer basis points.
`0.33 → 3300` is exact; confirm no rounding intent was lost.

Two parameters have **no source value at all**: Staking's
`minimumDelegation` / `maximumDelegation`, and Slashing's
`initialSlashingAuthority`.

## Status

| contract | constructor status | hash | unresolved |
|---|---|---|---|
| Identity | BLOCKED | — | governance key |
| ValidatorRegistry | BLOCKED | — | governance key |
| Staking | BLOCKED | — | governance key; min/max delegation; unbonding blocks |
| Governance | BLOCKED | — | governance key; bps conversions; voting/timelock blocks; Staking address |
| Treasury | BLOCKED | — | governance key; Governance address; unused init_params |
| Slashing | BLOCKED | — | governance key; slashing authority; bps; jail blocks; Staking address |
| RewardDistributor | BLOCKED | — | governance key |
| SynergyOracle | BLOCKED | — | governance key |
| TeamVesting | BLOCKED | — | governance key |

Artifacts remain staged at `/Volumes/xcode/phase8-rebuild-1` and are **not
frozen**: freezing is defined to include constructor inputs, and none are final.
