# Node Control Panel v2 PR Readiness

Date: 2026-06-26
Branch: `engineering/node-control-panel-v2-overhaul`

## Scope Completed

- Added the v2 control-service command envelope and command registry for validator appliance onboarding, lifecycle, state-sync, archive, cluster, fleet, package, identity, stake, activation, and incident workflows.
- Added fail-closed blockers for missing confirmation, closed P2P, wrong network, wrong chain, noncanonical archive, low snapshot quorum, verifier crash, missing snapshot hash, stale package, hash mismatch, incompatible schemas, missing binary digest, unsigned package, NO-GO packages, missing identity backup proof, missing state-sync quorum proof, and unsafe cluster assignment.
- Added dynamic cluster registry fixtures for six-validator, seven-validator, two-cluster, three-cluster, pending-assignment, quarantined, vote-only, and proposer-probation states.
- Added Validator Appliance filesystem model with `state/store/consensus.db` as primary consensus truth and derived state marked rebuildable.
- Added v2 React routes: `/validator/onboarding`, `/validator/detail`, `/validator`, `/node`, `/clusters`, `/state-sync`, `/archive`, `/storage`, `/alerts`, and `/incidents`.
- Added v2 pages for Validator Onboarding, Validator Detail, Cluster Manager, State Sync, Archive Manager, and Incidents/Evidence.
- Updated operator docs and architecture docs for dynamic cluster registry, appliance runtime, archive safety, state-sync repair, onboarding v2, and incident evidence.

## V2 Commands

`validator.machine.preflight`, `validator.package.verify`, `validator.identity.create`, `validator.identity.backup.verify`, `validator.cluster.previewAssignment`, `validator.cluster.assign`, `validator.config.render`, `validator.state.inspect`, `validator.state.verify`, `validator.stateSync.plan`, `validator.stateSync.dryRun`, `validator.stateSync.repair`, `validator.onboarding.verify`, `validator.onboarding.run`, `validator.lifecycle.status`, `validator.lifecycle.requestVoteOnly`, `validator.lifecycle.promoteProbation`, `validator.stake.preflight`, `validator.stake.submit`, `validator.activation.preflight`, `validator.activation.submit`, `validator.doctor.run`, `fleet.status.strict`, `archive.status`, `archive.verifyCanonical`, `archive.reseed.plan`, `archive.snapshot.listUnsafe`, and `archive.snapshot.quarantine`.

## Validation

| Check | Result |
| --- | --- |
| `cargo fmt --manifest-path control-service/Cargo.toml -- --check` | Pass |
| `cargo check --manifest-path control-service/Cargo.toml --bin control-service --no-default-features` | Pass |
| `cargo test --manifest-path control-service/Cargo.toml control_v2 --no-default-features` | Pass, 17 v2 tests |
| `cargo test --manifest-path control-service/Cargo.toml --no-default-features -- --test-threads=1` | Pass, 106 tests |
| `cargo test --manifest-path control-service/Cargo.toml --no-default-features` | Pass, 106 tests |
| `npm run test:uiux-revamp` | Pass |
| `npm run build` | Pass, existing Vite chunk-size warning |
| `git diff --check` | Pass |
| Browser smoke, desktop routes | Pass for `/validator/onboarding`, `/validator/detail`, `/clusters`, `/state-sync`, `/archive`, `/incidents` |
| Browser smoke, mobile viewport | Pass for `/state-sync`, no horizontal overflow at 390x844 |
| Browser console | Pass for runtime errors; only React Router v7 future warnings remain |

## Full Rust Suite Status

Before cleanup, `cargo test --manifest-path control-service/Cargo.toml --no-default-features -- --test-threads=1` was not clean in this repo baseline: 78 passed and 24 failed.

Observed root causes:

- `monitor::terminal_command_tests::binding_targets_follow_current_topology` cannot resolve `GenVal-01` from inventory and reports `None` instead of `Some("genval-01")`.
- `monitor::terminal_command_tests::logical_nodes_follow_current_topology` cannot resolve `node-inventory.csv` without `SYNERGY_MONITOR_INVENTORY`.
- `testnet::tests::ceremony_import_applies_assigned_validator_ports` fails because the legacy genesis setup-package import test embeds an operational manifest with `network_id` `1266` where strict package validation expects `synergy-testnet-v3`.
- `testnet::tests::role_functions_document_current_runtime_state_for_all_roles` fails because the bundled control-panel role reference is missing.
- The remaining `testnet::tests::*` failures are follow-on `env lock poisoned` failures after the legacy genesis setup-package import panic.

After cleanup, both full control-service suites are clean:

- Serial: `cargo test --manifest-path control-service/Cargo.toml --no-default-features -- --test-threads=1` passed, 106 tests.
- Normal: `cargo test --manifest-path control-service/Cargo.toml --no-default-features` passed, 106 tests.

Fixed legacy test classes:

- Monitor inventory topology tests now use a repo-owned `control-service/fixtures/monitor/node-inventory.test.csv` fixture with documentation-only addresses instead of production workbook data.
- Monitor inventory coverage now proves missing inventory fails clearly, fixture inventory passes, and invalid inventory reports the missing required column.
- Legacy genesis setup-package import tests now normalize only the test package fixture metadata to `synergy-testnet-v3`; production network-id validation remains strict.
- Wrong-network operational manifest regression coverage now proves the legacy genesis setup-package import path rejects a mismatched embedded manifest.
- Environment-variable test isolation now recovers the shared test lock after panics instead of cascading `PoisonError` failures.
- Role-function documentation now lives inside the control-panel repo at `docs/node-role-functions.md`; the test no longer depends on a parent repo doc.

Remaining caveats:

- The Rust code still contains historical `ceremony_*` names for the one-time genesis setup-package import path. This cleanup treats that as legacy naming only and does not promote it as an active operator lifecycle.
- `npm run build` still emits the existing Vite chunk-size warning.

## Public Read-Only Network Check

- `https://testnet-core-rpc.synergy-network.io` returned `synergy_getBlockNumber = 647415`.
- `https://testnet-atlas-api.synergy-network.io/api/v1/network/summary` returned `latestBlock = 647414`, `activeValidators = 6`, `totalValidators = 6`, `chainId = 1266`, and `indexedAt = 2026-06-26T06:13:04.586Z`.

## Live-Safety Statement

No validators were deployed, restarted, or mutated during this work. Archive validator services, APIs, and workers were not re-enabled. Browser validation used the local Vite dev server and local browser session state only.
