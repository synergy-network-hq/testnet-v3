# Constructor resolution findings

Session 13f, 2026-07-28. Read from the `.synq` sources directly.

## Canonical order — APPROVED, all edges satisfied

| nonce | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 |
|---|---|---|---|---|---|---|---|---|---|
| | Identity | ValidatorRegistry | Staking | Governance | Treasury | Slashing | RewardDistributor | SynergyOracle | TeamVesting |

With `Slashing.initialSlashingAuthority = Governance` the graph is:

```
Treasury   → Governance      4 > 3  ✓
Governance → Staking         3 > 2  ✓
Staking    → ValidatorRegistry 2 > 1 ✓
Slashing   → ValidatorRegistry 5 > 1 ✓
Slashing   → Staking         5 > 2  ✓
Slashing   → Governance      5 > 3  ✓
```

Acyclic; every edge satisfied. SaleClaim excluded; nonce 9 not reserved.

**Slashing authority check verified.** `Slashing.synq:75` enforces
`require(msg.sender == slashingAuthority, "Unauthorized")`. With that set to the
Governance contract address, slashing can only be invoked by a call whose
`msg.sender` is Governance — i.e. through the governed proposal → timelock →
execution path, using Governance's `callContract` host capability. There is no
direct-operator slashing path. Confirm that is intended: an incident response
cannot slash faster than the timelock.

## BLOCKER — Staking cannot express disabled delegation

The preferred launch policy (delegation disabled at genesis) **cannot be
represented by the contract as written**.

```
Staking.synq:46   require(minimumDelegation > 0, "Minimum delegation is zero");
Staking.synq:47   require(maximumDelegation >= minimumDelegation, "Invalid delegation limits");
```

`minimumDelegation = 0` is **rejected at construction**. `0 / 0` is not a legal
argument set.

Answering the specific questions asked:

| question | finding |
|---|---|
| Delegation intended active on Testnet-v3? | The contract implements it fully — `delegate`, `beginUndelegate`, `delegationOf`, `delegatedStakeOf`, `totalDelegatedStake`, `Delegated` event. Nothing marks it inactive. |
| Do zero values disable it? | **No.** Zero is rejected by a `require`. |
| Can governance update the limits after genesis? | **No.** The only governance setters are `setSlashingContract` (line 151) and `setPaused` (line 166). `minDelegation` / `maxDelegation` are **constructor-only and immutable**. |
| Is `minimumDelegation <= maximumDelegation` enforced? | Yes, line 47. |
| Per delegator, per validator, or system-wide? | **Per (validator, delegator) pair**: line 76 checks `delegationOf[validator][msg.sender] + msg.value <= maxDelegation`. Not a system-wide cap. |
| Does delegation affect quorum weight? | **Yes.** `votingPower = selfStakeOf[a] + delegatedStakeOf[a]` (line 142). |
| Included in bonded voting weight? | **Yes.** `totalVotingPower = totalSelfStake + totalDelegatedStake` (line 147). |
| Is there a delegation-only disable? | **No.** `paused` is global — it gates `selfStake`, `delegate`, `beginUnstake` and `beginUndelegate` alike, so pausing delegation also stops self-staking. |

**Therefore: no safe disable state and no governed update path.** This is the
constructor-design blocker, reported before freezing Staking as instructed. No
arbitrary values were invented.

Three ways forward, for operator decision:

1. **Amend `Staking.synq`** — add a `delegationEnabled: Bool` constructor
   argument plus a governance-signed setter, and relax the `> 0` requires when
   disabled. Changes Staking's bytecode, ABI and manifest hashes. This is the
   cheapest possible moment to do it, because artifacts are not frozen and no
   address has been derived. Delivers the stated policy exactly.
2. **Launch with delegation live** — approve real economic limits now. Requires
   deciding the per-pair minimum and maximum and accepting that delegated stake
   counts toward quorum from block 1.
3. **Construct with limits but keep `paused = true`** until limits are governed.
   Rejected on inspection: `paused` also disables self-staking, so validators
   could not bond. Not viable.

## Non-constructor `init_params` — traced

### Treasury

| genesis value | destination | path |
|---|---|---|
| `signers` (5 entries) | `signers[]`, `isSigner` mapping | **Post-deployment call.** Constructor sets `signerCount = 0` and leaves `signers` empty (lines 41–42). |
| `required_signers: 4` | `requiredSigners` | Constructor argument `initialRequiredSigners`. |
| `vault_address: synu134gwnz…` | — | **No constructor parameter and no matching storage field.** Unresolved. |
| `initial_balance_nwei: 720000000000000000` | — | Not a contract field. This is a genesis **balance allocation** to the Treasury address. |

**Two consequences that must not be missed.**

First, Treasury is constructed with `requiredSigners = 4` and `signerCount = 0`.
It is **inert on deployment** — four approvals required, zero signers able to
give them. The five signers must be added by a genesis initialization call
inside the same atomic deployment, before the final AIVM state root. If that
call is omitted, Treasury is permanently unusable without a governance action.

Second, the 720,000,000 SNRG allocation must be re-pointed at the **new
deployment-derived** Treasury address. Left as-is it funds the superseded
manually generated address, i.e. funds nothing.

### Identity

| genesis value | destination | path |
|---|---|---|
| `reserved_names` (6 entries) | `reservedNameHash` mapping | **Post-deployment calls.** `setReservedName(name, …, reserved, message, signature)` at line 105, governance-signed. Six calls, one per name. |
| `registration_fee_nwei` | `registrationFee` | Constructor argument. |

Reserved names are enforced at registration (`require(!reservedNameHash[canonicalHash], "Reserved name")`,
line 41), so any name not seeded before the network opens is claimable by the
first registrant. These calls are launch-critical and must be inside the atomic
genesis initialization.

### Summary of required genesis initialization calls

| # | contract | call | authorization | why atomic |
|---|---|---|---|---|
| 1–5 | Treasury | add signer ×5 | governance-signed | Treasury inert until done |
| 6 | Treasury | *(vault_address — unresolved)* | — | needs a ruling |
| 7–12 | Identity | `setReservedName` ×6 | governance-signed | names claimable until done |

All must execute before the post-deployment AIVM state root is computed, or the
root will attest to an unusable Treasury and an unprotected name space.

## Approved unit conversions — recorded

| contract | source | value | constructor argument | converted |
|---|---|---|---|---|
| Governance | `quorum_pct` | 0.60 | `quorumBps` | 6000 |
| Governance | `approval_pct` | 0.50 | `approvalBps` | 5000 |
| Governance | `veto_pct` | 0.33 | `vetoBps` | 3300 |
| Governance | `voting_duration_seconds` | 604800 | `votingBlocks` | 302400 |
| Governance | `timelock_delay_seconds` | 86400 | `timelockBlocks` | 43200 |
| Staking | `unbonding_period_seconds` | 604800 | `unbondingBlocks` | 302400 |
| Slashing | `double_sign_slash_pct` | 5 | `initialDoubleSignSlashBps` | 500 |
| Slashing | `downtime_slash_pct` | 1 | `initialDowntimeSlashBps` | 100 |
| Slashing | `invalid_block_slash_pct` | 5 | `initialInvalidBlockSlashBps` | 500 |
| Slashing | `jail_duration_seconds` | 86400 | `jailBlocks` | 43200 |

Divisor: `consensus.target_block_time_ms = 2000` → exact integer division by 2 s.
`0.33 → 3300` recorded as 33.00%, not one third. Conversion tests to be added
with the constructor canonicalization tooling.

## Constructor status

| nonce | contract | status | remaining |
|---:|---|---|---|
| 0 | Identity | blocked | governance key |
| 1 | ValidatorRegistry | blocked | governance key |
| 2 | Staking | **design blocker** | delegation semantics; governance key |
| 3 | Governance | blocked | governance key; Staking address |
| 4 | Treasury | blocked | governance key; Governance address; `vault_address` ruling |
| 5 | Slashing | blocked | governance key; Staking + Governance addresses |
| 6 | RewardDistributor | blocked | governance key |
| 7 | SynergyOracle | blocked | governance key |
| 8 | TeamVesting | blocked | verify `initialAdmin` source record; `vestingStartTime` = 1775044800 from `vesting[0].start_time` |

No constructor hash computed. No production address derived. Artifacts remain
staged and unfrozen at `/Volumes/xcode/phase8-rebuild-1`.
