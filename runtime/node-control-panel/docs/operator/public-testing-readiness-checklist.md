# Synergy Control Panel Public Testing Readiness Checklist

## Purpose

- This checklist covers the work required before the Synergy node control panel should be distributed to outside testers.
- The goal is not mainnet launch. The goal is a stable, supportable public test build that lets remote operators install the app, provision nodes, join the network, and report problems without needing developer intervention.

## Release-Blocking Summary

- [ ] Finish the remaining role-local subsystem implementations for the roles that are still represented mostly as bounded runtime surfaces rather than fully hardened local services.
- [ ] Remove or refactor the remaining generic-node assumptions in older control-panel paths so every supported setup flow resolves the correct specialized binary.
- [ ] Publish and validate multi-platform release artifacts for the control panel and all role-specific node binaries.
- [ ] Prove that a clean Windows, macOS, and Linux install can provision a node from scratch and join the live test network from an external location.

## 1. Role-Bound Runtime Completion

- [ ] Confirm the final list of supported public-test roles.
- [x] For each public-test role, document whether it is fully implemented, partially implemented, or intentionally deferred. Verified in `synergy-testnet/docs/node-role-functions.md`, which now carries per-role current-runtime notes.
- [ ] Complete the deeper role-local services for roles that still rely on placeholder or bounded-surface behavior.
- [x] Verify that every specialized binary refuses mismatched `identity.role` and `role.compiled_profile` values. Reconfirmed on March 15, 2026 by `cargo test --manifest-path /Users/devpup/Desktop/Testnet/synergy-testnet/Cargo.toml role_runtime -- --nocapture`.
- [ ] Verify that every specialized binary only starts the surfaces it is supposed to run.
- [ ] Verify that non-validator roles cannot accidentally start validator-only consensus behavior.
- [ ] Verify that service-only roles cannot accidentally inherit governance, treasury, or emergency authority.
- [ ] Freeze the public-test config schema for `node.toml`, `peers.toml`, and related generated files.

## 2. Bootstrap and Network Discovery

- [ ] Finalize the public bootnode topology and the public seed-service topology.
- [ ] Confirm that bootnodes run in true `bootstrap_only` mode when they are intended to act only as bootnodes.
- [ ] Verify DNS records for all public bootnodes.
- [ ] Verify `_dnsaddr.bootstrap` TXT records and confirm that fresh nodes can resolve them from outside the local development environment.
- [ ] Verify seed-service HTTP responses and any SRV records used for discovery.
- [ ] Confirm that newly provisioned nodes can bootstrap from hardcoded bootnodes, DNS bootstrap records, and seed-service fallbacks.
- [ ] Test bootstrap from at least three remote networks in different geographies.
- [ ] Confirm that firewall rules, NAT, and public-port exposure match the published bootstrap design.

## 3. Control Panel Provisioning Flows

- [ ] Verify that every supported `NodeType` maps to the correct specialized binary on Windows, macOS, and Linux.
- [ ] Remove or fully migrate any legacy setup path that still assumes one generic node executable.
- [x] Verify that the Testnet setup flow writes correct role metadata into generated configs. Reconfirmed on March 15, 2026 by `cargo test --manifest-path /Users/devpup/Desktop/Testnet/synergy-testnet/tools/testnet-control-panel/control-service/Cargo.toml setup_node_writes_role_metadata_and_bootstrap_inputs -- --nocapture`.
- [ ] Verify that the generic node-manager flow also writes correct role metadata when it is used.
- [x] Verify that the control panel writes valid bootstrap inputs into generated config files. Reconfirmed on March 15, 2026 by `cargo test --manifest-path /Users/devpup/Desktop/Testnet/synergy-testnet/tools/testnet-control-panel/control-service/Cargo.toml setup_node_writes_role_metadata_and_bootstrap_inputs -- --nocapture`.
- [ ] Verify that setup, install, start, stop, restart, logs, status, and uninstall all work for every public-test role.
- [ ] Verify that the control panel can recover cleanly from partial installs, interrupted downloads, or corrupted config files.
- [ ] Verify that the control panel shows clear user-facing errors when a role cannot be installed or started.

## 4. Build, Packaging, and Distribution

- [ ] Run the updated GitHub Actions workflow and confirm that all role-specific binaries build successfully for Linux, Windows, and macOS.
- [ ] Publish a manifest that maps each compiled profile to the correct artifact URL and checksum.
- [ ] Verify that the desktop app can consume the published manifest and download the correct binary for each role.
- [ ] Verify that bundled local binaries and downloaded binaries follow the same naming and checksum rules.
- [ ] Verify that the Electron bundle includes all required helper binaries, agents, and support files.
- [ ] Sign, checksum, and archive every distributed artifact.
- [ ] Verify platform-specific packaging requirements such as macOS notarization and Windows code-signing.
- [ ] Confirm that upgrade bundles preserve user data, keys, and config files correctly.

## 5. Installer, Updates, and Recovery

- [ ] Test first-run installation on clean machines with no existing Synergy files.
- [ ] Test upgrades from at least one earlier internal build.
- [ ] Test uninstall and reinstall without leaving behind broken state that blocks reinstallation.
- [ ] Verify that failed installs can roll back cleanly.
- [ ] Verify that the app can restart helper services and node processes after a reboot.
- [ ] Verify that privilege-escalation prompts are minimal, correct, and clearly explained.
- [ ] Verify that auto-update or update-check behavior does not overwrite a running node unsafely.
- [ ] Verify that recovery instructions exist for operators whose installation fails mid-process.

## 6. Security and Supply Chain Hardening

- [ ] Audit which actions require elevated privileges and reduce that list to the minimum necessary set.
- [ ] Verify checksum validation before any downloaded binary is executed.
- [ ] Verify TLS and certificate behavior for update and artifact-download endpoints.
- [ ] Verify that secrets, keys, and seed material are never written to logs or crash reports.
- [ ] Review local file permissions for wallets, private keys, and node identity files.
- [ ] Verify rate limits, authentication, and abuse controls for any public-facing RPC or gateway services used during testing.
- [ ] Review dependency and build-chain security for both the desktop app and the node runtime.
- [ ] Define emergency disable or kill-switch procedures for a bad public build.

## 7. Testing and Quality Gates

- [ ] Build an automated smoke-test matrix covering every public-test role on every supported OS.
- [ ] Add end-to-end tests that provision a node from the control panel and confirm it reaches the network.
- [ ] Add negative tests for wrong-role configs, corrupt downloads, missing DNS, and unreachable bootnodes.
- [ ] Add regression tests for the role-to-binary mapping in the control panel.
- [ ] Add tests for upgrade, restart, crash recovery, and log collection.
- [ ] Add performance tests for the control panel when multiple managed nodes are running.
- [ ] Add long-running soak tests for at least the bootnodes, validator path, RPC path, and one interoperability role.
- [ ] Define pass/fail criteria for public-test signoff and record the results for each release candidate.

## 8. Observability and Supportability

- [ ] Ensure that every node role produces usable logs with enough detail for support triage.
- [ ] Ensure that the control panel can surface role, binary name, version, sync state, peer count, and recent errors.
- [ ] Ensure that crash logs and diagnostic bundles can be collected without exposing private key material.
- [ ] Stand up basic dashboards or operator reports for bootstrap health, seed-service health, and node installation success rate.
- [ ] Define alerting for bootnode loss, seed-service loss, release-download failures, and repeated install failures.
- [ ] Create a support playbook for the most likely operator failures.

## 9. Operator Documentation and UX

- [x] Publish an operator-facing explanation of each supported node role. Published in `synergy-testnet/docs/node-role-functions-operator.md`.
- [ ] Publish a public setup guide for clean installs on Windows, macOS, and Linux.
- [ ] Publish a bootstrap and firewall guide that matches the real public-test network topology.
- [ ] Publish troubleshooting steps for install failures, peer-discovery failures, and role-mismatch failures.
- [ ] Publish an upgrade guide and rollback instructions.
- [ ] Review the UI wording for role selection so public operators are not asked to choose roles they should not run.
- [ ] Verify that the UI clearly labels experimental, internal-only, or not-yet-supported roles.

## 10. Public-Test Operations

- [ ] Stand up a release-candidate environment that mirrors the public-test topology.
- [ ] Run a full rehearsal in which a brand-new operator installs the app and joins the network without developer help.
- [ ] Create a public issue-intake path for bug reports and operator feedback.
- [ ] Define who owns triage, release hotfixes, docs updates, and bootstrap-node operations during the public test.
- [ ] Define public-test success metrics such as install success rate, node-join success rate, crash rate, and time-to-first-peer.
- [ ] Define rollback criteria for pausing the public test if the build proves unstable.

## 11. Current High-Priority Gaps to Close

- [ ] Finish the roles that are still mostly profile-bounded wrappers rather than fully hardened role-local service implementations.
- [ ] Unify or retire the older generic control-panel node-management paths so there is no generic fallback where a specialized binary is required.
- [ ] Produce and validate real multi-platform release artifacts from GitHub Actions instead of relying only on local builds.
- [ ] Prove that remote operators on clean machines can bootstrap successfully using the public bootnodes and seed services.
- [ ] Prove that the control panel surfaces enough diagnostics for support without requiring local source-code knowledge.

## Exit Criteria for Public Testing

- [ ] A new operator on Windows can install the control panel, provision a supported node role, and join the network without manual developer intervention.
- [ ] A new operator on macOS can do the same.
- [ ] A new operator on Linux can do the same.
- [ ] At least one external-network test from a remote geography succeeds using the published bootstrap and seed infrastructure.
- [ ] Support staff can diagnose a failed install or failed bootstrap attempt using the logs and UI provided by the app.
- [ ] The published documentation matches the actual app behavior and artifact names.
- [ ] A release candidate passes the agreed smoke, regression, and recovery test suites.
