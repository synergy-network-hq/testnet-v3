# Session 13i — account-domain conflation in the AIVM, and the Track G map

Everything below was traced from source and executed. Nothing is inferred.

## Headline

Track G was **not** completed. Before any genesis deployment mechanism could
execute a single governed initialization call, three further instances of the
ML-DSA-65 / ML-DSA-87 domain conflation had to be removed from the **AIVM**,
two of which are launch-critical and none of which were known. They are fixed
and tested here. The remaining Track G work is scoped at the bottom.

## Three defects found and fixed

Session 13d migrated the SynQ *admission* policy, `signature.rs` and the
compiler to ML-DSA-87 and reported green. That migration stopped at the VM
boundary. Inside `aivm-core` the consensus algorithm was still authorizing
account-domain actions.

### 1. `stateful_synq.rs::verify_mldsa` hardcoded ML-DSA-65 — LAUNCH-CRITICAL

```rust
verify_signature(AlgorithmId::MlDsa65, &message, &signature, &public_key)
```

This is the host behind `verifyMLDSASignature`, which is the **only**
authorization mechanism for every governance-signed entry point on eight of the
nine native contracts: `Treasury.setSigner`, `Identity.setReservedName`,
`SynergyOracle.setOracle` / `setSourceDomain`, `ValidatorRegistry.setAuthority`,
`Staking.enableDelegation`, `Slashing.setSlashingAuthority`, every `setPaused`,
every `updateGovernanceKey`.

The ruled Initial Governance Authority is **ML-DSA-87**. An ML-DSA-87 governance
signature over an ML-DSA-87 public key was being handed to an ML-DSA-65 verifier,
which rejects on length before it ever checks the signature. **Every
governance-signed genesis initialization call would have failed**, which means
the Treasury five-signer seeding and the six Identity reserved names — both
declared launch-critical and both required inside the atomic overlay — were
unreachable.

Fixed by binding the algorithm to the compiled manifest's
`required_signature_algorithm` rather than to a constant, so the VM and the
artifact cannot disagree — the same property `SYNQ_TESTNET_SIGNATURE_ALGORITHM`
gives the compiler. Unknown labels fail closed.

### 2. `execution.rs::validate_synq_artifact` hardcoded ML-DSA-65 — LAUNCH-CRITICAL

```rust
if manifest.required_signature_algorithm != "ML-DSA-65"
    || request.context.security_policy.required_signature_policy != "ml-dsa-65"
```

AIVM artifact validation **rejected every ML-DSA-87 manifest**. All nine staged
Testnet-v3 manifests declare ML-DSA-87. This gate would have rejected all nine
at deployment, after artifact freeze, with no prior warning — the failure is
invisible today only because genesis still binds the pre-migration ML-DSA-65
manifests.

Fixed by introducing two single-source constants in `aivm-core::execution` —
`SYNQ_ACCOUNT_DOMAIN_SIGNATURE_ALGORITHM` (`"ML-DSA-87"`) and
`SYNQ_ACCOUNT_DOMAIN_SIGNATURE_POLICY` (`"ml-dsa-87"`) — and gating on those.
The gate stays strict: ML-DSA-65 is still refused in the account domain. It was
deliberately **not** relaxed to accept either algorithm, which would have
reintroduced the conflation the correction exists to remove.

### 3. Two execution contexts advertised the consensus policy

`aivm-core::execution::ExecutionContext::testnet_1266_for_contract` and
`runtime/src/synq_execution.rs::aivm_context` both hardcoded
`required_signature_policy: "ml-dsa-65"`. Both now use the shared constant.

## Track I consequence — the prior green runs do not hold

`aivm-core` on the working tree as received was **32 passed / 10 failed**, not
the 42/42 recorded in `SYNQ_MLDSA87_MANIFEST_MIGRATION_REPORT.md`. The ten
failures are all defect 2 and pre-date this session: the checked-in `Counter`
fixture manifest was migrated to ML-DSA-87 while `validate_synq_artifact` still
demanded ML-DSA-65. Verified as pre-existing — `git diff` for `execution.rs` was
empty at the time the failures were observed, and the only file this session had
touched was `stateful_synq.rs`.

**Do not treat any pre-13i green run as a launch gate.** Track I restarts from
here.

After the three fixes: **41 passed / 1 failed**.

## The one remaining red is correct and must not be patched

`stateful_synq::tests::all_eight_genesis_contracts_deploy_call_restart_and_replay_deterministically`

```
SynQ signature policy mismatch: manifest ML-DSA-65 context ml-dsa-87
```

It loads the **checked-in** artifacts from `genesis-contracts/contracts/`, which
are still the pre-migration ML-DSA-65 build. The ML-DSA-87 artifacts are staged
at `/Volumes/xcode/phase8-rebuild-1` and are deliberately not frozen, per the
ruling that the canonical candidate is rewritten once, atomically.

This test is now the honest artifact/runtime coherence gate: it goes green when
the staged artifacts are frozen, and only then. The mismatch is confined to the
manifest label — all nine staged manifests already declare ML-DSA-87.

## Canonical deployment path — reuse map for Track G

No second deployment algorithm is needed. The production path is already
callable without going through RPC or the mempool.

| step | canonical function |
|---|---|
| deploy payload hash | `pqsynq::serialization::hash_contract_deploy_body` |
| call payload hash | `pqsynq::serialization::hash_contract_call_body` |
| signer address | `pqsynq::address::derive_synq_address` |
| ML-DSA-87 verify | `pqsynq::signature::verify_signature` |
| envelope + policy + address + payload-hash checks | `AegisSynQVerifier::verify_contract_deploy` / `verify_contract_call` |
| manifest / ABI / STS-9 security policy | `synq_admission::verify_synq_deploy_for_chain_admission` |
| carrier construction | `synq_admission::build_deploy_admission_carrier_from_pqsynq_bytes_with_artifacts_and_constructor_args` |
| **contract address derivation** | `synq_execution::derive_synq_contract_address_from_deploy` |
| artifact hash verification | `synq_execution::register_synq_artifact` → `aivm_core::execution::validate_synq_artifact` |
| constructor decode | `stateful_synq::decode_arguments` (JSON array; see below) |
| constructor execution | `aivm_core::synq_runtime::deploy_synq_contract` |
| call execution | `aivm_core::synq_runtime::call_synq_contract` |
| host-capability enforcement | `stateful_synq::Interpreter::require_host` (manifest `host_functions`) |
| AIVM state mutation | `aivm_core::state::StateOverlay` → `ContractState` |
| receipts | `SynQRuntimeReceipt::canonical_hash` |
| storage root | `ContractState::state_root` |
| state root | `execution::compute_state_root_after` |
| receipt root | `execution::compute_receipt_root` |
| single reusable entry point | `synq_execution::execute_synq_transaction_at` |

`execute_synq_transaction_at` takes `&mut ContractState`, the artifact map and
the deployment map directly. **No refactor out of an RPC or transaction wrapper
is required.**

### Atomicity primitive already exists

`aivm_core::state::StateOverlay` has `commit(self, base)` and `rollback(self)`.
For whole-genesis atomicity the overlay alone is insufficient — `ExecutionState`
also carries `balances_nwei`, `synq_artifacts`, `synq_contracts`,
`synq_verifications`, `synq_errors` and `sts_state`. Clone `ExecutionState`,
execute the entire plan against the clone, and assign back only on total
success; drop the clone otherwise. That leaves the original byte-identical,
which is exactly the required guarantee and is cheaply provable by comparing
`compute_state_root_after` before and after a forced failure.

### Constructor argument encoding — resolved

Constructor arguments are a **JSON array**, not ABI-packed
(`stateful_synq::decode_arguments`, `value_from_json`):

- `UInt*` → JSON number or decimal string
- `Bool` → JSON bool
- `Address` → JSON string
- `MLDSAPublicKey` / `MLDSASignature` / `Bytes` → hex string (`0x` optional) or byte array
- arity must match exactly

`constructor_args_hash = SHA-256(those JSON bytes)` and feeds both the deploy
payload hash and the contract address, so the encoding is address-determining
and must be byte-canonical. Emit with a fixed serializer and no incidental
whitespace.

## Initialization paths — the three previously untraced contracts

All three resolve to existing governed calls. **No direct storage mutation and
no new genesis-only capability is required.**

### ValidatorRegistry — traced, complete

Two governed calls per validator, `msg.sender` must equal the constructor's
`initialAuthority`:

- `registerValidator(idHash, validator, rewardAddress, votingPower, selfStake, metadataHash, keyBundleHash)` — selector `0x26d190af`
- `activateValidator(validator, activationHeight)` — selector `0x4ea663c5`

Genesis supplies all seven arguments per validator from
`contracts.validator_registry.init_params.validators[]` — six validators, each
`status: active_at_genesis`, `activation_height: 0`, `voting_power: 100`,
`stake_nwei: 50000000000000` (equal to `min_self_stake_nwei`, so the
`selfStake >= minSelfStake` require passes exactly), with `validator_id_hash`,
`metadata_hash` and `key_bundle_hash` present per validator.

`validator_set_hash` is a **genesis-document** field with no contract storage
counterpart; there is no membership-epoch state. Activation height is the only
epoch-like field and it is per validator. Nothing else to initialize.

### SynergyOracle — traced, complete

- `setOracle(oracle, true, message, signature)` — selector `0xc9a2eaee` — ×1, governance-signed
- `setSourceDomain(domain, true, message, signature)` — selector `0xb2a5d731` — ×3, governance-signed

Genesis: `oracle_set` has one entry (`synu18tmdavp9ysk…`), `accepted_source_domains`
has three, `quorum_threshold: 1`, `replay_protection_enabled: true` (the last two
are constructor arguments).

Fails closed before initialization: `proposeCheckpoint` requires
`isOracle[msg.sender]` **and** `acceptedSourceDomain[sourceDomain]`, so an
un-initialized oracle accepts nothing from anyone. Confirmed by reading the
guards, and worth an explicit negative test.

Note for the operator, not a blocker: `quorum_threshold = 1` means a single
oracle both proposes and finalizes a checkpoint in one call
(`if (quorumThreshold <= 1) { checkpointFinalized = true }`).

### RewardDistributor — `pool_address` question answered on evidence

**`pool_address` is distribution authorization only. It is not custody, not an
accounting source, and not a funding reference.**

Proof from `RewardDistributor.synq`: `distributorAuthority` appears in exactly
two places, both `require(msg.sender == distributorAuthority)` on `distribute`
and `distributeBatch`. The tokens move via `sendNative(recipient, amount)`,
which debits **the contract's own native balance** — never the authority's.
Genesis corroborates: `initial_pool_balance_nwei: "0"` and
`funding_model: "approved release from VNS-A01"`, a descriptive external
process with no on-chain enforcement.

There is no epoch state, no pending-reward state and no funding reference in the
contract. `totalDistributed` and `distributionCount` are counters initialized to
zero by the constructor. **RewardDistributor needs no initialization call** —
constructor only.

Consequence: VNS-A01 as `pool_address` grants only "may call distribute". It
does **not** grant reward custody. The concentration concern is real but narrower
than feared — see the authority note below.

## VNS-A01 concentration — interim finding

`synl1g8hgegyaezgqwq755zjrglwr7wrvz3jj6dvr` (VNS-A01, 2,638,950,000 SNRG = 22% of
supply, `locked: true`) currently holds three distinct operational roles:

| role | actual power | granted by |
|---|---|---|
| `reward_distributor.pool_address` | may call `distribute` / `distributeBatch` | constructor arg |
| `validator_registry.authority_address` | register, activate, exit, **jail**, unjail, tombstone, `updateVotingPower`, `updateSelfStake`, **`reduceSelfStake`** | constructor arg |
| `security.emergency_pause.guardian_multisig` | pause | genesis config |

These are three separate `require(msg.sender == …)` checks, not one shared
authorization — but they resolve to **one key**. That single key can jail a
validator, cut its self-stake, and pause the network. That is an operational
incident-response capability sitting on a locked 22%-of-supply token reserve
whose release path is "purpose-bound multisig or governance-controlled release" —
i.e. not operationally available when an incident needs it.

Recommendation carried forward: separate `validator_registry.authority_address`
from the reserve **before** Testnet-v3 launch, because it carries `reduceSelfStake`
and `jailValidator`; `pool_address` and the pause guardian can follow at
Mainnet-beta. Both `setAuthority` and `setDistributorAuthority` already exist and
are governance-signed, so separation needs no contract change.

## Additional finding — governance signatures are not bound to the call

Every governed setter has the shape:

```
setX(newValue, message: Bytes, signature: MLDSASignature)
  require_pqc { verifyMLDSASignature(governanceKey, message, signature) }
```

`message` is an **arbitrary caller-supplied byte string**. It is never bound to
the function being called, to its arguments, to the contract address, to a
nonce, or to the chain. One valid governance signature over any message is
therefore replayable to authorize *any* governed setter on *any* of the eight
contracts that share that governance key — `setSigner`, `setAuthority`,
`setSlashingAuthority`, `enableDelegation`, `updateGovernanceKey`.

This is not a Track G blocker and is reported rather than fixed: correcting it
changes eight contract sources and therefore every artifact hash and every
derived address. Operator ruling required on whether Testnet-v3 launches with it.

## Deterministic test authorities — mechanism decided

`Sign::keygen()` wraps PQClean `crypto_sign_keypair`, which draws from the system
RNG. No seeded or derandomized keygen is exposed anywhere in `pqrust-mldsa`
(checked `mldsa87.rs` and `ffi.rs`). Deterministic test authorities therefore
cannot be *derived*; they must be **generated once and frozen as a checked-in
test fixture**, following the existing precedent of
`runtime/config/genesis.testnet-v3.test-fixture.json` and its
`genesis.rs::reject_test_fixture_genesis` production guard.

Required fixture: test Genesis Deployer, test Initial Governance Authority, test
Emergency Slashing Authority — ML-DSA-87, marked
`TEST_FIXTURE_NOT_FOR_PRODUCTION`, refused outside `cfg(test)`.

## Track G — remaining scope

Not started beyond the map above. Ordered:

1. Frozen test-authority fixture (above).
2. `runtime/src/genesis_deployment.rs`: lifecycle state machine
   (`UNINITIALIZED → AUTHORIZED_FOR_GENESIS → EXECUTING → COMPLETED →
   PERMANENTLY_RETIRED`) persisted under a reserved AIVM namespace so retirement
   is enforced in protocol state and survives into the state root.
3. Fixed nine-entry plan; machine-enforced topological check over
   `ValidatorRegistry < Staking < Governance < Treasury`,
   `ValidatorRegistry < Slashing`, `Staking < Slashing`. Note the approved nonce
   order (Identity 0, ValidatorRegistry 1, Staking 2, Governance 3, Treasury 4,
   Slashing 5, RewardDistributor 6, SynergyOracle 7, TeamVesting 8) satisfies all
   five edges. `Slashing.initialSlashingAuthority` is an **account** authority per
   ruling, so it contributes no edge — this supersedes the
   `Slashing → Governance` edge in `CONSTRUCTOR_RESOLUTION_FINDINGS.md`.
4. Canonical typed constructor-argument generation, dependency-first, using the
   JSON encoding above and the recorded conversions.
5. Initialization sequence inside the same overlay: Treasury `setSigner` ×5,
   Identity `setReservedName` ×6, ValidatorRegistry `registerValidator` +
   `activateValidator` ×6, SynergyOracle `setOracle` ×1 + `setSourceDomain` ×3.
6. Test matrix as specified.

### Environmental note for planning

Cold `cargo check` on `runtime/src` exceeded 20 minutes on this host
(librocksdb-sys). `aivm-core` alone cycles in roughly 40 seconds once warm.
Budget Track G iteration against `aivm-core` and the targeted runtime modules,
and reserve the five-run full-suite gate for a single uninterrupted block.

## Files changed this session

- `runtime/synergy-aivm/runtime/aivm-core/src/stateful_synq.rs` — manifest-bound
  governance signature algorithm; `Interpreter::new` now fallible.
- `runtime/synergy-aivm/runtime/aivm-core/src/execution.rs` — account-domain
  constants; artifact-validation gate; context default; fixture labels.
- `runtime/synergy-aivm/runtime/aivm-core/src/synq_runtime.rs` — STS-9 test
  manifest fixture migrated to ML-DSA-87.
- `runtime/src/synq_execution.rs` — execution context uses the shared constant.

No genesis document, no contract source and no staged artifact was modified.
