# Track G — complete

`runtime/src/genesis_deployment.rs`, 1,4xx lines. `cargo check --lib` exits 0.
`cargo test --lib genesis_deployment::` — **6 passed / 0 failed**.

## Entry point

```rust
execute_genesis_deployment(
    state: &mut ExecutionState,
    plan: &GenesisDeploymentPlan,
    authorities: &GenesisAuthorities,
    parameters: &GenesisParameters,
) -> Result<GenesisDeploymentOutcome, String>
```

## Canonical runtime functions reused

No second deployment algorithm exists. Deploy: `hash_contract_deploy_body` →
ML-DSA-87 `detached_sign` → `derive_synq_contract_address_from_deploy` /
`derive_synergy_contract_address_from_deploy` →
`build_deploy_admission_envelope_..._with_constructor_args` →
`verify_synq_deploy_for_chain_admission` → `encode_synq_admission_carrier` →
`execute_synq_transaction_at` → `deploy_synq_contract`. Calls follow the same
path through `hash_contract_call_body` and `verify_synq_call_for_chain_admission`.
Roots come from `compute_state_root_after`. Host capability enforcement,
constructor decoding and AIVM state mutation are untouched production code.

## Atomicity

The plan runs against a **clone** of `ExecutionState`; the caller's state is
overwritten at a single commit point after every step has succeeded. Any error
returns early and drops the clone.

## Nine test-derived addresses

| nonce | contract | address |
|---:|---|---|
| 0 | Identity | `sync1ulk8zl35wmudx2l9fpntyewr4werzuveymjs` |
| 1 | ValidatorRegistry | `sync1h829yavpa8fz50kx59x4eacrkrnsg8pajuld` |
| 2 | Staking | `sync188rp3fag928zhvkt49rtgz5aj3tkunce9yc3` |
| 3 | Governance | `sync149m5ac88djhpz88xa8d4czv4tfgqqs6gkwfr` |
| 4 | Treasury | `sync189e9cma7htdwzzrtcga3w8junrjzg8p8cdrl` |
| 5 | Slashing | `sync1qgq5myp3jz7seflq4vc7fd0v62uarcvzmn6r` |
| 6 | RewardDistributor | `sync10xz5zjttsza3ufwrlnedvhds0ddgsx7ryn38` |
| 7 | SynergyOracle | `sync1uzn220qaudv0g5hzlrzj7r6ec3r39h54ffgt` |
| 8 | TeamVesting | `sync1p4hs2y4nw6x7cd3vpgk2qdg2kgye7yv4ndam` |

All nine distinct. Derived from the frozen test authorities in
`runtime/fixtures/genesis-deployment-test-authorities.json`; they change when
production public identities are substituted, which is expected and correct.

## Roots

| value | test-fixture result |
|---|---|
| post-deployment AIVM state root | `085241bed2ac0de1020ce4e63c5c51b7ac09af3cd6ba7948f457281001c3a878` |
| genesis receipt root | `1582128251cfb25de4ce0cbf44551f24da1e4ed7f673474b3e47083d54a8f275` |
| deployment manifest hash | `eb717ea11800232a3cf258e78b5d8d2d5ab29afdf8f20c885b48cbe12dfe6cfa` |

9 deployment receipts, 27 initialization receipts, lifecycle
`PermanentlyRetired`.

## Initialization sequence — 27 calls

| # | contract | call | signer |
|---|---|---|---|
| 1–5 | Treasury | `setSigner` ×5 | governance authority |
| 6–11 | Identity | `setReservedName` ×6 | governance authority |
| 12–17 | ValidatorRegistry | `registerValidator` ×6 | registry authority |
| 18–23 | ValidatorRegistry | `activateValidator` ×6 | registry authority |
| 24 | SynergyOracle | `setOracle` ×1 | governance authority |
| 25–27 | SynergyOracle | `setSourceDomain` ×3 | governance authority |

Governed calls carry the Session-13J authorization envelope with a per-contract
governance nonce sequence. RewardDistributor needs no initialization call.
Treasury is **not** funded. Post-initialization state is read back from AIVM
storage and the deployment aborts unless `signerCount == 5`,
`requiredSigners == 4` and `validatorCount == 6`.

## Retirement

Lifecycle is persisted under the reserved AIVM namespace
`__synergy_genesis_deployment_v1` and moves
`Uninitialized → AuthorizedForGenesis → Executing → Completed →
PermanentlyRetired` inside the transaction. The executed manifest hash is
recorded alongside it. A second `execute_genesis_deployment` is refused by
protocol state, not by key custody. A tenth entry is refused structurally by
`GenesisDeploymentPlan::validate`.

## Tests — 6/6

| test | result |
|---|---|
| `approved_nonce_order_satisfies_the_dependency_graph` | ok |
| `a_plan_that_violates_the_dependency_graph_is_rejected_before_execution` | ok |
| `genesis_deployment_succeeds_and_reproduces_addresses_and_state_root` | ok |
| `a_failure_rolls_back_every_deployment_and_initialization` | ok |
| `the_genesis_deployer_is_retired_and_cannot_deploy_again` | ok |
| `print_genesis_deployment_evidence` | ok |

The rollback test forces a failure at Treasury signer validation — after all
nine contracts have deployed — and asserts `synq_contracts` empty,
`synq_artifacts` empty, `synq_verifications` empty, lifecycle `Uninitialized`,
and the state root byte-identical to the untouched baseline.

## Determinism notes (resolved during implementation)

ML-DSA signing is hedged, so signature bytes differ every run. Two values
derived from signed bytes leaked into the state root and were made deterministic
from genesis inputs instead:

- genesis transaction ids now derive from operation + label + ordinal + payload
  hash rather than the signed transaction bytes;
- `SynQDeploymentRecord.deploy_receipt_hash` is normalized to a hash over the
  deployed address, artifact triple and deployment ordinal.

Addresses were already signature-independent. With these two changes the full
deployment reproduces addresses, state root, receipt root and manifest hash
across independent runs.
