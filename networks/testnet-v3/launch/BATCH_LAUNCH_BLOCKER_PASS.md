# Batch launch-blocker pass — session 13g, 2026-07-28

Scope note, stated honestly up front: **Tracks A–D and F were worked; E, G, H and
I were not reached.** This report covers what was actually executed. Nothing
below is inferred.

## Completed automatically

| # | issue | resolution | evidence |
|---|---|---|---|
| 1 | Staking could not express disabled delegation (`require(minimumDelegation > 0)`) | Amended `Staking.synq` — see below | `cli check` passes; 3-build determinism |
| 2 | Delegation had no governed activation path (only `setSlashingContract` / `setPaused` existed) | Added governed one-way `enableDelegation` | source |
| 3 | Suspected duplicate 720M allocation | **Not duplicated** — DAO-A01 and TRE-A01 are distinct accounts with equal amounts | genesis |
| 4 | `vault_address` role unknown | **TRE-A01 "Foundation / Treasury Reserve"**, funded, custody `TRE / 4-of-5`, locked | `address_assignment_register[29]`, `balances[29]` |
| 5 | Supply conservation unverified | `sum(balances) == sum(allocations) == 12,000,000,000 SNRG == cap` | computed |
| 6 | Manifests declared consensus algorithm in the account domain | ML-DSA-87 migration (session 13d) | `SYNQ_MLDSA87_MANIFEST_MIGRATION_REPORT.md` |

## Track B — Staking amendment

`genesis-contracts/contracts/Staking.synq`:

- new storage `delegationEnabled: Bool public`;
- new constructor argument `enableDelegationAtGenesis: Bool` (position 5, after
  `maximumStake`);
- constructor validation now branches — disabled requires `minimumDelegation == 0`
  **and** `maximumDelegation == 0`; enabled keeps `> 0` and `max >= min`. Every
  other combination fails closed;
- `delegate()` gains `require(delegationEnabled, "Delegation disabled")`;
- new governed `enableDelegation(minimumDelegation, maximumDelegation, message, signature)`
  using the existing `verifyMLDSASignature(governanceKey, …)` mechanism —
  **one-way** (`require(!delegationEnabled)`), validates both limits *before*
  storing either, then sets the flag and emits `DelegationEnabled`;
- new event `DelegationEnabled(minimumDelegation, maximumDelegation)`.

**Quorum behaviour while disabled.** `votingPower = selfStakeOf + delegatedStakeOf`
and `totalVotingPower = totalSelfStake + totalDelegatedStake` are unchanged and
did not need changing: `delegate()` is the only writer of `delegatedStakeOf` and
`totalDelegatedStake`, and it is now unreachable while disabled. Both therefore
remain provably zero, contributing nothing to validator weight or governance
quorum. Self-staking is untouched.

**One-way rationale.** Re-disabling after balances exist would leave withdrawal
and voting-weight semantics undefined, and no tested shutdown path exists.

### Genesis values

`enableDelegationAtGenesis = false`, `minimumDelegation = 0`, `maximumDelegation = 0`.

### New artifact hashes (all nine, three-build byte-identical)

| contract | bytecode | abi | manifest |
|---|---|---|---|
| Identity | `4ead4317a26258ea…` | `69758689bf865c63…` | `efe31bd89e542773…` |
| ValidatorRegistry | `abf7805cda0f452b…` | `6975c7e4f33a15a4…` | `10b6ecf1385d7100…` |
| **Staking** | **`0d53c36dce0bebf8…`** (was `14995f99919e2a5e`) | **`ba58476b48b2e67e…`** | **`fa54698ffdc8fff6…`** |
| Governance | `f87903c37d13e161…` | `a21b107f130b684e…` | `6093cce183b2c7a2…` |
| Treasury | `3f3e0c486d34b37c…` | `3c8e544c35839762…` | `59677a0c9411952d…` |
| Slashing | `01e44718048646ec…` | `64a790d0486c1766…` | `32baf35b61e1add5…` |
| RewardDistributor | `f7006241c97da3e8…` | `eaf29c4ca41e1c78…` | `4e0919c089f7060a…` |
| SynergyOracle | `6cdff83c939df81b…` | `9e894326db9eafda…` | `4d75b487e942d3d6…` |
| TeamVesting | `6a4bf755a81615ae…` | `5f7df0c83f56283e…` | `c340a5ced8204e5d…` |

Only Staking's bytecode moved — the eight others are unchanged, confirming the
amendment is isolated. Three independent builds produced byte-identical output
for all 27 files.

**Downstream artifacts affected by the amendment:** Staking's constructor arity
changed 7 → 8, so any fixture, SDK binding, deployment script or test that
constructs Staking positionally must be updated. None exist yet in the runtime
(no genesis deployment mechanism has been built), so the blast radius today is
limited to the staged artifacts.

**Tests specified but NOT yet written.** The thirteen delegation tests you listed
require the genesis deployment mechanism to execute a constructor, which does not
exist yet. They are blocked on Track G, not skipped.

## Track C — Treasury and supply reconciliation

| question | finding |
|---|---|
| What is `synu134gwnz…`? | **TRE-A01**, alias `tnv3-treasury-reserve`, name *Foundation / Treasury Reserve*, category *Foundation / Treasury* |
| Placeholder or intended holder? | **Intended funded holder.** It carries `balances[29] = 720,000,000 SNRG`, `locked: true`, release path *purpose-bound multisig or governance-controlled release* |
| Custody | `control_reference: "shared custody policy TRE / 4-of-5"` — consistent with `required_signers: 4` and five entries in `signers` |
| Which allocation is the 720M? | **Foundation / Treasury Reserve** (TRE-A01) |
| Duplicate with DAO? | **No.** `allocations[28]` is DAO-A01 *DAO / Governance Reserve*, a different account that happens to hold an equal 720M |
| Supply conservation | `sum(balances) = sum(allocations) = 12,000,000,000 SNRG = cap`. Verified by computation, 36 balances / 32 allocations / 36 register entries |
| Is 720M assigned twice? | **No.** It appears once in the balance ledger. The other seven occurrences are the allocation record, the register record, and two descriptive mirrors (`contracts.treasury.init_params.initial_balance_nwei`, `modules.treasury.initial_balance_nwei`) |

**Consequence, and it resolves the funding question on evidence rather than
preference: the Treasury contract must NOT be funded.** The 720M is already
allocated to TRE-A01 in the balance ledger. Allocating it again to the deployed
contract address would create a second 720M and break the 12B cap. So
`initial_balance_nwei` under `contracts.treasury.init_params` is a **descriptive
mirror, not an instruction** — it must not become a genesis allocation to the
contract.

Remaining genuine question is narrower than "where do the funds go": it is
whether the Treasury *contract* is meant to be an accounting/approval layer over
a wallet it cannot move, which is what the evidence currently describes. See
decision D2.

## Track D — `init_params` classification (partial)

| contract | field | classification |
|---|---|---|
| Treasury | `required_signers: 4` | constructor argument `initialRequiredSigners` |
| Treasury | `signers` (5) | **post-deployment initialization call** — constructor sets `signerCount = 0`, `signers` empty |
| Treasury | `vault_address` | **external custody configuration** — no constructor parameter, no storage field |
| Treasury | `initial_balance_nwei` | **genesis account allocation to TRE-A01** — descriptive mirror here |
| Identity | `registration_fee_nwei` | constructor argument |
| Identity | `reserved_names` (6) | **post-deployment calls** — `setReservedName` ×6, governance-signed |
| Governance | pct / seconds values | constructor arguments after approved conversion |
| Staking | stake limits, unbonding | constructor arguments |
| Slashing | pct / seconds values | constructor arguments after approved conversion |
| ValidatorRegistry | validator limits | constructor arguments |
| RewardDistributor | `pool_address` | constructor argument `initialDistributorAuthority` |
| SynergyOracle | quorum, replay flag | constructor arguments |
| TeamVesting | allocations, counts | constructor arguments |

**Treasury is inert on deployment**: `requiredSigners = 4` with `signerCount = 0`.
The five signer additions must execute inside the atomic genesis deployment
before the final AIVM state root, or the contract is unusable. Same for the six
Identity reserved names, which are claimable by any registrant until seeded.

Not yet traced: `ValidatorRegistry.validators` / `validator_set_hash`,
`SynergyOracle.oracle_set` / `accepted_source_domains`, `RewardDistributor`
funding model. These have no constructor parameters and their initialization
path is unknown.

## Track F — dependency graph

```
Treasury   → Governance          4 > 3 ✓
Governance → Staking             3 > 2 ✓
Staking    → ValidatorRegistry   2 > 1 ✓
Slashing   → ValidatorRegistry   5 > 1 ✓
Slashing   → Staking             5 > 2 ✓
Slashing   → Governance          5 > 3 ✓   (new, per ruling)
```

Acyclic; approved order satisfies every edge. A machine-enforced topological test
belongs with the deployment mechanism (Track G) and is not yet written.

## Session 13h additions

### Treasury classification — corrected per ruling

The earlier suggestion to re-point the 720M at the deployment-derived Treasury
address is **superseded and withdrawn**. Authoritative state:

- `TRE-A01` (`synu134gwnz…`) remains the sole holder of the 720,000,000 SNRG
  Foundation / Treasury Reserve, under `TRE / 4-of-5` custody, `locked: true`;
- `DAO-A01` separately holds another 720,000,000 SNRG — a distinct allocation;
- the deployed Treasury contract is **not** funded;
- balances and allocations both total the 12B cap.

**Testnet-v3 Treasury contract classification: non-custodial on-chain approval
and accounting contract.** It records approvals and accounting state. It does
**not** enforce transfers from the externally custodied TRE-A01 reserve — no
cryptographic or transaction-execution integration between the contract and that
wallet exists in this codebase. A Treasury-contract approval therefore does not
move TRE-A01 funds.

> **Launch limitation (accepted for Testnet-v3, must not delay launch).** The
> Testnet-v3 Treasury contract records approvals and accounting state but does
> not directly enforce transfers from the externally custodied TRE-A01 reserve.
> Mainnet-beta requires a reviewed enforceable custody integration.

In the final atomic genesis rewrite: keep the 720M only in the TRE-A01 balance
allocation; remove `initial_balance_nwei` and `vault_address` from active
Treasury contract initialization data (no constructor parameter or storage field
consumes either); preserve TRE-A01 and its five signers / 4-of-5 threshold in the
custody records. The five on-chain Treasury signer entries must **not** be
assumed equivalent to the TRE-A01 custody participants unless verified.

### Slashing authority — VNS-A01 REJECTED on evidence

Assessed against the six stated conditions:

| condition | VNS-A01 | |
|---|---|---|
| Network/validator-security authority | name *Validator Security Reserve*, category *Validators / Staking / Network Security* | partial — by name only |
| Threshold custody | `shared custody policy VNS / 4-of-5` | ✅ |
| Operationally available for incident response | `locked: true`, release path *purpose-bound multisig or governance-controlled release* | ❌ |
| **Not a token reserve pretending to be an authority** | **holds 2,638,950,000 SNRG — 22% of total supply** | ❌ **disqualifying** |
| Signers approved for security operations | not evidenced | ❌ |
| Address type accepted by `msg.sender` | `synl1…` account address | ✅ |

**VNS-A01 fails the disqualifying condition you named.** It is a locked token
reserve, not an operational authority.

Additional concern found while checking: VNS-A01 is already overloaded as
`reward_distributor.pool_address`, `validator_registry.authority_address`, **and**
`security.emergency_pause.guardian_multisig` — while holding 22% of supply. That
concentration is worth reviewing independently of the slashing question.

**Resolution: create the dedicated `Testnet-v3 Emergency Slashing Authority`
(`SNRG-TESTNET-V3-EMERGENCY-SLASHING`) through the custody ceremony**, threshold
controlled, no treasury / deployment / consensus / governance-voting powers, no
token allocation beyond transaction requirements, Testnet-v3 only.

### `setSlashingAuthority` — already implemented, no change required

`Slashing.synq:105` already provides exactly the requested setter:

```
setSlashingAuthority(newAuthority, message, signature)
```

with a non-zero check, governance ML-DSA verification via
`verifyMLDSASignature(governanceKey, …)`, atomic update, deterministic
`SlashingAuthorityUpdated(oldAuthority, newAuthority)` event, and immediate loss
of access by the old authority. Governance can therefore replace the emergency
authority without a contract change.

**No Slashing source change, so no Slashing artifact regeneration and no
three-build re-run for it.**

## Not reached

- **Track E** — authority/custody matrix and both ceremony tools.
- **Track G** — genesis deployment mechanism. This blocks the thirteen delegation
  tests, the topological test, and all constructor-hash work.
- **Track H** — address replacement inventory.
- **Track I** — five-consecutive-run runtime gate.
