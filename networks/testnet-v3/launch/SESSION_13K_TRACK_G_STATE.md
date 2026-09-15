# Session 13k — Track G in progress (NOT complete)

## Honest status

Track G is **partially implemented and compiling**, not finished. What exists is
real, compiles into the runtime library, and uses only canonical paths. What is
missing is the top-level atomic driver and every test.

## Landed and compiling

`runtime/src/genesis_deployment.rs` (~740 lines), registered in `lib.rs`.
`cargo check --lib` on `runtime/src` exits 0.

- `GenesisContract` — the nine contracts and the approved nonce order.
- `contract_dependencies()` — deployed-contract edges only. `Slashing`'s
  emergency authority is an account authority per ruling and is deliberately
  not an edge.
- `GenesisDeploymentPlan::validate()` — machine-enforced: exactly nine entries,
  no repeated nonce, no repeated contract, no gap in 0..8, and every dependency
  strictly earlier. Runs before any state is touched.
- `GenesisDeployerLifecycle` — five states, persisted under the reserved AIVM
  namespace `__synergy_genesis_deployment_v1`, so retirement is protocol state
  covered by the state root rather than key deletion.
- `deployment_manifest_hash()` — binds deployer, every nonce, and every artifact
  triple.
- `constructor_arguments()` — canonical typed arguments for all nine, resolved
  dependency-first from already-deployed addresses. Staking is wired
  `false / 0 / 0`. No placeholder addresses anywhere.
- `deploy_one()` — full canonical path: `hash_contract_deploy_body` →
  ML-DSA-87 sign → `derive_synergy_contract_address_from_deploy` →
  `build_deploy_admission_envelope_..._with_constructor_args` →
  `verify_synq_deploy_for_chain_admission` → `execute_synq_transaction_at`.
  Asserts the executed address equals the independently derived address.
- `call_one()` — same shape for the call domain.
- `governance_tail()` — builds the Session-13J authorization envelope over the
  real contract, method, arguments and nonce. No arbitrary message anywhere.

## Not yet written

1. `execute_genesis_deployment()` — the atomic driver (clone `ExecutionState`,
   run the plan, commit only on total success).
2. The initialization sequence wiring: Treasury `setSigner` ×5, Identity
   `setReservedName` ×6, ValidatorRegistry `registerValidator` +
   `activateValidator` ×6, SynergyOracle `setOracle` + `setSourceDomain` ×3.
3. Retirement enforcement and the tenth-deployment / replay rejections.
4. Every test: success path, six rollback cases, thirteen Staking delegation
   tests, governance-envelope integration, retirement.
5. The frozen test-authority fixture. The generator
   (`aivm-core/examples/gen_test_authorities.rs`) is written but its first run
   had not completed.

## Defect found and fixed (exposed by the Track G compile)

`runtime/src/consensus/posy.rs:76` selected the signing authority with
`if cfg!(test)`, a **runtime boolean**, so both arms compiled in every build and
the non-test library had to resolve `utils::test_temp_root`, which is
`#[cfg(test)]`-only.

**The runtime library did not compile outside test builds.** `cargo test --lib`
defines `test` and therefore always passed, which is why every previous session
saw green suites while `cargo check --lib` — the node binary path — was broken.
Replaced with `#[cfg(test)]` / `#[cfg(not(test))]` conditional compilation.

This is the first time `cargo check --lib` has exited 0 on this tree.

## Next session — start here

Append `execute_genesis_deployment()` to `genesis_deployment.rs`, then the
initialization sequence, then tests. Do not re-derive the map; it is above.
Run the authority-fixture generator once and freeze its output.
