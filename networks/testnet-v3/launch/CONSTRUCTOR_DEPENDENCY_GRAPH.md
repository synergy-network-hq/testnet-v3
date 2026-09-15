# Constructor dependency graph — nine Testnet-v3 native contracts

Session 13e, 2026-07-28. Read from the `.synq` constructor signatures directly.
Supersedes the earlier "no ordering constraints" finding, which was wrong: it
inspected genesis `init_params`, which carry no contract addresses, rather than
the constructors, which do.

**No production address is derived in this document.** Order and nonces are
proposed for approval only.

## Every constructor argument

`A` marks an `Address`-typed argument; **bold** marks one that resolves to
another native contract.

| contract | arguments |
|---|---|
| Identity | `initialGovernanceKey: MLDSAPublicKey`, `initialFeeCollector: Address` ᴬ, `initialRegistrationFee: UInt256` |
| ValidatorRegistry | `initialGovernanceKey`, `initialAuthority: Address` ᴬ, `maximumValidators`, `minimumValidators`, `minimumSelfStake` |
| Treasury | `initialGovernanceKey`, **`initialGovernanceContract: Address`** ᴬ, `initialRequiredSigners` |
| Governance | `initialGovernanceKey`, **`stakingVotesProvider: Address`** ᴬ, `quorumBps`, `approvalBps`, `vetoBps`, `minimumDeposit`, `votingBlocks`, `timelockBlocks` |
| Staking | `initialGovernanceKey`, **`registry: Address`** ᴬ, `minimumStake`, `maximumStake`, `minimumDelegation`, `maximumDelegation`, `unbondingBlocks` |
| Slashing | `initialGovernanceKey`, **`registry: Address`** ᴬ, **`staking: Address`** ᴬ, `initialSlashingAuthority: Address` ᴬ, `initialDoubleSignSlashBps`, `initialDowntimeSlashBps`, `initialInvalidBlockSlashBps`, `missedBlocksThreshold`, `jailBlocks` |
| RewardDistributor | `initialGovernanceKey`, `initialDistributorAuthority: Address` ᴬ |
| SynergyOracle | `initialGovernanceKey`, `initialQuorumThreshold`, `enableReplayProtection: Bool` |
| TeamVesting | `initialAdmin: Address` ᴬ, `vestingStartTime`, `teamAllocationNwei`, `supportAllocationNwei`, `teamCount`, `supportCount` |

**Correction to `CONSTRUCTOR_READINESS.md`:** `initialGovernanceKey` is taken by
**eight** of the nine, not all nine. **TeamVesting does not take it** — it takes
`initialAdmin` only. The Initial Governance Authority public key must be frozen
before eight constructor hashes, not nine.

## Address arguments classified

| contract | argument | resolves to | contract dep? |
|---|---|---|---|
| Identity | `initialFeeCollector` | fee-collector wallet (`synf1…`) | no |
| ValidatorRegistry | `initialAuthority` | `synl1g8hg…` (VNS-A01 security reserve) | no |
| Treasury | `initialGovernanceContract` | **Governance** | **yes** |
| Governance | `stakingVotesProvider` | **Staking** | **yes** |
| Staking | `registry` | **ValidatorRegistry** | **yes** |
| Slashing | `registry` | **ValidatorRegistry** | **yes** |
| Slashing | `staking` | **Staking** | **yes** |
| Slashing | `initialSlashingAuthority` | unresolved — no source value | no (but blocking) |
| RewardDistributor | `initialDistributorAuthority` | `synl1g8hg…` (pool address) | no |
| TeamVesting | `initialAdmin` | `synu18tmd…` (DAO reserve) | no |

## Graph

```
Treasury   → Governance
Governance → Staking
Staking    → ValidatorRegistry
Slashing   → ValidatorRegistry
Slashing   → Staking
```

`A → B` = A requires B's deployed address before A's constructor hash can be
finalized.

No inbound edges: Identity, RewardDistributor, SynergyOracle, TeamVesting.

**The graph is acyclic.** The near-cycle risk was `ValidatorRegistry.initialAuthority`;
it resolves to the VNS-A01 wallet, not the Governance contract, so
`ValidatorRegistry → Governance` does **not** exist and the chain terminates.

### Required at address-derivation time

All five contract edges are required at derivation time. `constructor_args_hash`
is an input to `derive_synq_contract_address_from_deploy`, so a dependency's
address must be final before the dependent's address can be computed. There is
no ordering in which a dependent precedes its dependency.

### Could any be initialized after deployment?

Technically yes for all five — each could take a zero/placeholder address in the
constructor and be wired by a genesis initialization call. It is **not
recommended** and is not necessary here:

- the placeholder value, not the real address, would be what is hashed into the
  contract's own address, so the address would permanently attest to a value the
  contract never actually used;
- each contract would start in a partially-initialized state and must fail
  closed until wired, which is new behaviour none of the nine implements today;
- it changes the security and initialization model for no benefit, since the
  graph is acyclic.

Per the operator instruction, two-phase initialization is reserved for a genuine
cycle. There is none.

### Effect of post-deployment change on the constructor hash

A post-deployment setter does **not** retroactively alter an already-derived
address — the hash was fixed at derivation. The consequence runs the other way:
choosing to pass a placeholder instead of the real address changes
`constructor_args_hash` **at derivation**, and therefore yields a different
contract address than passing the real value. Placeholder-then-wire and
real-value-at-construction are not interchangeable; they produce different
addresses.

## Proposed deterministic order

Constraints: `ValidatorRegistry < Staking < Governance < Treasury`,
`ValidatorRegistry < Slashing`, `Staking < Slashing`.

Four contracts are unconstrained (Identity, RewardDistributor, SynergyOracle,
TeamVesting), so the order is **not unique**. The order below is the one that
deviates least from the previously proposed canonical order — a single swap of
Staking and Treasury:

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

Verification: Staking(2) > ValidatorRegistry(1) ✓ · Governance(3) > Staking(2) ✓ ·
Treasury(4) > Governance(3) ✓ · Slashing(5) > ValidatorRegistry(1), Staking(2) ✓.

SaleClaim excluded. Nonce 9 not reserved.

## Still blocking (unchanged)

1. **Initial Governance Authority public key** — custody ceremony pending;
   feeds eight of nine constructor hashes.
2. **Genesis Deployer address** — custody ceremony pending; feeds all nine
   addresses.
3. **`Slashing.initialSlashingAuthority`** — no source value anywhere.
4. **`Staking.minimumDelegation` / `maximumDelegation`** — no source values.
5. **Unit conversions** — pct→bps and seconds→blocks
   (`consensus.target_block_time_ms = 2000`); see `CONSTRUCTOR_READINESS.md`.
