# Phase 8 — deterministic SynQ genesis deployment: findings

Session 13, 2026-07-27. Everything below is executed and reproducible, not inferred.

> ## P0 CORRECTION (operator, 2026-07-27) — read before anything else
>
> **The "genesis-installed at pre-assigned identity addresses" ruling in §5 is
> WITHDRAWN.** The ten FN-DSA-derived addresses are Synergy *identity* addresses
> and are **not** valid contract-instance addresses. The governing model is now:
>
> - contract **identity** records may keep their FN-DSA-derived Synergy addresses
>   where an identity, administrator, signer, or custody role is required;
> - deployed SynQ contract **instances** must take addresses produced by the
>   canonical deterministic deployment derivation;
> - the two must be **separate fields** and must never be conflated.
>
> The provisional TeamVesting binding has been reverted (§6). Sections 3–5 below
> are retained as the evidence trail for *how* the identity-address model was
> detected and disproven — the derivation facts in §3 remain correct and are the
> reason the correction was needed. Do not act on §5's ruling.

## 1. All eight bound artifacts reproduce bit-for-bit — PASS

Rebuilt every `.synq` source in a scratch directory with
`runtime/synq-language/target/release/cli build`, then compared the regenerated
`.compiled.synq` / `.abi.json` / `.manifest.json` against the hashes bound in
`genesis.testnet-v3.identity-assigned.json`:

| contract | bytecode | abi | manifest |
|---|---|---|---|
| governance | MATCH | MATCH | MATCH |
| identity | MATCH | MATCH | MATCH |
| reward_distributor | MATCH | MATCH | MATCH |
| slashing | MATCH | MATCH | MATCH |
| staking | MATCH | MATCH | MATCH |
| synergy_oracle | MATCH | MATCH | MATCH |
| treasury | MATCH | MATCH | MATCH |
| validator_registry | MATCH | MATCH | MATCH |

The SynQ compiler is deterministic and the genesis artifact bindings are honest.
All ten sources also pass `cli check`.

## 2. The two unbound contracts now compile — artifacts ready, NOT bound

`sale_claim` and `team_vesting` had addresses assigned but empty `artifact` objects.
Both now build:

| | SaleClaim | TeamVesting |
|---|---|---|
| source | `22093775e5dc26f10484c571719a5d434413f4f75576288557bfe592ab2b1265` | `7a0bc49290db88fb4efa587499d4a0b407295384be1a1d6946da40c7e3436fe9` |
| bytecode | `ea9a9ccce90588add7da4cd68d21c3554efa9ae345d956ebdf236de19c7b0ead` | `6a4bf755a81615aed240c51f6842aa1bdc6ca8ef16ffa75ce7a510453f1b7f4c` |
| abi | `fb241a607deb59137cf46316c651879a274b539cb11c7aac5a63a934fe9f53a1` | `784bd58d35099f21d0670b0e15477bbe7ea3baf4be3244460b2c3f963347446c` |
| manifest | `8c8bd8c38330026a1c2b0182f13834f3f59522de0e0d3936d1ef7c84ed27a2ec` | `14a9ede87baa0b06d1d2a09f8535886cd29182f9f3dfab9be57425ebc9f59f39` |

TeamVesting's bytecode hash reproduces session-4's recorded value exactly.

Artifacts are staged at `/Volumes/xcode/phase8-build/` and have **not** been
copied into `genesis-contracts/contracts/` or bound into genesis — binding
changes the genesis document and therefore the genesis hash and magic, which is
a governance-weight action.

**Open defect:** `SaleClaim.manifest.json` declares `"host_functions": []` and
`"permissions": []`, but `launch/SALE_CLAIM_REQUIREMENTS.md` requires the host
capability `hostVerifyThresholdAttestation`. The contract also still needs its
approved attestor set and threshold as constructor arguments — an unresolved
DAO/custody input. SaleClaim must not be bound until both are settled.

## 3. The Phase 8 acceptance criterion as written is unsatisfiable — STOP

The checklist says deterministic deployment "must reproduce all ten existing
addresses". It cannot, because the ten addresses were never deployment-derived.

**Proven, 10 of 10.** Every genesis contract address is an *identity* address:

```
address = Bech32m("synq", first N 5-bit groups of SHA3-256(FN-DSA-1024 public key))
```

Recomputed independently from the `public_key` field of each entry in
`genesis.contract_identities` — all ten reproduce exactly, including
`sale_claim` and `team_vesting`. This matches
`address::derive_address_from_bytes` and the derivation documented in
`CRYPTOGRAPHIC_PROFILE_RESOLUTION.md`.

Deployment-derived addresses use a completely different input set
(`synq_execution::derive_synq_contract_address_from_deploy`): chain id, network
id, protocol version, algorithm id, **nonce**, **signer address**, payload hash,
bytecode hash, manifest hash, abi hash, constructor-args hash. That function
cannot produce an address derived from an FN-DSA-1024 public key, so running the
deploy path will mint ten *different* addresses.

Corroborating evidence that the contracts are **genesis-installed at
pre-assigned addresses**, not deployed by transaction:

- each entry carries `"address_type": "ContractSystem"` and its own FN-DSA-1024
  keypair — these are identities, not deployment outputs;
- `genesis.system_reserved_addresses.policy.contract_deployable = false`;
- `testnet_v3_execution_bootstrap.rs` binds artifacts to the genesis-declared
  addresses and never derives one.

## 4. Where Phase 8 actually terminates

`testnet_v3_execution_bootstrap.rs` is explicit, and it is the authority here:

> Testnet-v3 SynQ artifacts are prepared but not deployed: a signed Genesis
> deployment manifest and post-deployment AIVM state-root binding are required

It deliberately leaves `synq_contracts` empty and its `pre_deployment_state_root`
cannot be used as the genesis block state root. It also enumerates only the
**eight** native contracts — `NATIVE_GENESIS_CONTRACTS` must grow to ten once
sale_claim and team_vesting are bound.

So the remaining Phase 8 work is:

1. **Operator decision** on the address model (§3) — this determines whether
   Phase 8 means "install at pre-assigned addresses" or "deploy and re-derive".
2. Settle SaleClaim's host capability and constructor inputs (§2).
3. Bind both artifacts into genesis; extend `NATIVE_GENESIS_CONTRACTS` to ten.
4. Produce and **sign** the genesis deployment manifest — custody-gated, the
   same blocker as Phase 9. Not obtainable in-session.
5. Bind the post-deployment AIVM state root, then recompute the genesis hash and
   magic and regenerate the Phase-9 ceremony challenges against the final hash.

Nothing was forced green. `gates.synq_genesis_contracts_deployed_and_verified`
stays `false`.

---

## 5. Applied per operator decision (2026-07-27)

Address model ruled **genesis-installed at pre-assigned addresses**; artifacts
ruled **bind TeamVesting only**. Both applied:

- `TeamVesting.{compiled.synq,abi.json,manifest.json}` copied into
  `genesis-contracts/contracts/`;
- `contracts.team_vesting.artifact` bound, `status` →
  `address_assigned_artifact_bound_pending_genesis_approval`;
- `NATIVE_GENESIS_CONTRACTS` extended 8 → 9;
  `identity_assigned_genesis_prepares_every_bound_native_synq_artifact` now
  asserts `team_vesting` present and `sale_claim` absent.

### Derived values recomputed, in dependency order

The recomputation method was validated against the pre-change file first — it
reproduces every derived value exactly, so these are trustworthy:

| field | before | after |
|---|---|---|
| `header.state_root` / `integrity.state_root` | `8e9934ab…4776d4` | `f560cffb…da071d` |
| `header.data_root` | `61280f6b…5bcdee` | `f711f687…3a4ad4` |
| `integrity.contract_hash` | `f8f512af…0a3099` | `e5a99ccd…2d9c5b` |
| `integrity.genesis_hash` | `ac5186cb…008407` | `9f3658d9…0a1c1f` |
| `network_magic_bytes.value` | `845e8eca` | `2ffb1569` |

Order matters: `contracts` feeds `state_root` and `data_root`, `header` feeds
the genesis hash, and the genesis hash feeds the magic. The new state root
`f560cffb…` is exactly the value `genesis.rs` independently expected, which
confirms the computation.

Backups: `/Volumes/xcode/genesis-backup-pre-teamvesting.json` (pre-change),
`/Volumes/xcode/genesis-with-teamvesting.json` (post-change).

**The Phase-9 ceremony challenges at `launch/ceremony/challenges.json` now embed
a stale genesis hash and must be regenerated.**

### REGRESSION CAUSED BY THIS BINDING — fix before moving any gate

Binding TeamVesting made four `consensus::diagnostics` tests fail, and this is
**causal, not flake**. A/B on identical code, `cargo test --lib -- consensus::diagnostics::`:

- pre-change genesis: **3 of 3 runs green** (59/59)
- post-change genesis: **2 of 3 runs failed** (55–56 pass, 3–4 fail)

Failing: `shadow_status_requires_full_epoch_before_rejoin_boundary`
(`QUARANTINED` vs `SHADOW_PASSED`),
`request_rejoin_allows_vote_only_before_full_shadow_epoch_with_exact_proof`,
`request_rejoin_allows_operator_approved_emergency_leader_stall_recovery`
(both `false` vs `true`),
`emergency_leader_stall_promotion_requires_exact_finalized_vote_only_proof`
(`FAILED_CLOSED` vs `VOTE_ONLY`). Each passes in isolation.

All four fail *closed*, which is the correct direction for a safety check — the
runtime is refusing something it can no longer verify. Ruled out: every
`with_runtime_root` call site does hold `DIAGNOSTICS_TEST_ENV_LOCK`, so this is
not the env-restoration race session-9 fixed.

**Leading hypothesis:** the diagnostics fixtures stage a runtime root containing
the eight contract artifacts. Now that preparation requires nine, `TeamVesting`'s
artifact files are missing from those staged roots, artifact loading fails, and
the affected paths fail closed. Check what the diagnostics fixtures copy into
their temp runtime roots before looking anywhere else.

Until this is resolved, treat the binding as **provisional**. Reverting is one
`cp` from the pre-change backup plus reverting `NATIVE_GENESIS_CONTRACTS` to 8.

---

## 6. REVERTED per the P0 correction (2026-07-27)

The provisional binding is fully reverted. The regression is gone — it was
caused by the binding, exactly as §5 concluded, and was **not** patched around.

Backup validated before restore (sha256
`1f0d6ba21147ef3088353870eae750fd6df65fa731f0978392d42d990d951fb6`): every
derived value self-consistent, ten contracts present, eight artifacts bound,
`team_vesting` and `sale_claim` unbound.

| | restored |
|---|---|
| `integrity.genesis_hash` | `ac5186cb4a95130d22986c73c20d0eedd73821a735d944184c94691860008407` |
| `network_magic_bytes.value` | `845e8eca` |
| `header.state_root` | `8e9934abc1fc5e02b2b32b426c45a7c4159342600807c295da5a2bebbc4776d4` |
| artifacts bound | 8 |

Also reverted: `NATIVE_GENESIS_CONTRACTS` 9 → 8, the bootstrap test back to
`identity_assigned_genesis_prepares_all_eight_native_synq_artifacts`, and the
three `TeamVesting.{compiled.synq,abi.json,manifest.json}` files removed from
`genesis-contracts/contracts/`. `git diff` for the genesis document and the
bootstrap module is now **empty** — both are byte-identical to the committed
baseline.

Verification after revert: `consensus::diagnostics::` **3 of 3 runs green
(59/59)**; `testnet_v3_execution_bootstrap` 2/2 green.

Both candidate values remain **candidates** and will change again after the real
ten-contract deployment. Neither is promoted.

## 7. Facts established for the corrected model

**The deployment address derivation is fully deterministic and time-independent.**
Verified by reading the code, not assumed:

`payload_hash = hash_contract_deploy_body(bytecode_hash, manifest_hash, abi_hash, signer_address, constructor_args_hash)`

— no timestamps. And `derive_synq_contract_address_from_deploy` consumes only
chain id, network id, protocol version, algorithm id, nonce, signer address,
payload hash, and the four artifact/constructor hashes. `not_before_unix` and
`expiration_unix` exist on the signing payload but feed **neither** the payload
hash nor the address, so wall-clock time cannot leak into an address.

**There is no `salt`.** `SynQSigningPayload` has `nonce` and no salt field. The
nonce is the only disambiguator; the deployment manifest must therefore fix a
deterministic nonce per contract.

**Address derivation does not require custody.** It needs the signer *address*
and the payload — all public and computable. Only *executing* a signed deploy
needs the private key. Final addresses can therefore be derived and reviewed
before the custody ceremony.

**Two hard inputs do not exist in the repository and cannot be invented:**

1. **No genesis deployment signer identity.** The genesis document contains no
   `deployer`, `deployment_signer`, `deploy_authority` or equivalent field.
   `verifier.rs::expect_address` requires the signer address to be derivable
   from the deployer's public key under the SynQ address scheme, so this must be
   a real key-backed identity. Every one of the ten addresses depends on it —
   nothing can be derived until it is designated.
2. **No genesis system-deployment mechanism.** A repository-wide search found no
   `system_deploy` / `genesis_deploy` / `deploy_genesis` path.
   `testnet_v3_execution_bootstrap.rs` only *binds and validates artifacts* and
   deliberately leaves `synq_contracts` empty. Item 3 of the correction is
   therefore new architecture to be built, not configuration to be changed.

**SaleClaim remains under-specified** (see §2): manifest declares no
`host_functions` despite requiring `hostVerifyThresholdAttestation`, and its
attestor set, threshold and remaining state semantics are unresolved. Its
constructor-args hash feeds its address, so no SaleClaim address can be derived
until those are frozen.
