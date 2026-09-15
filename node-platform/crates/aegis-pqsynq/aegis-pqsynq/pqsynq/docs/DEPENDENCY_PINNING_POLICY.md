# Dependency Pinning Policy

## Objective

Ensure deterministic, auditable, and secure dependency management for `aegis-pqsynq` release candidates.

## Baseline Rules

1. All CI and release-path cargo commands must run with `--locked`.
2. `Cargo.lock` is treated as a controlled artifact and must be committed with any dependency change.
3. Dependency update PRs must include:
   - reason for update (security, compatibility, or planned maintenance),
   - scope (direct and notable transitive impact),
   - validation evidence (`fmt`, `clippy`, tests, wasm checks, NIST replay tests).
4. Security scanning uses `cargo-audit` in CI; high-severity findings block release until remediated or explicitly risk-accepted.

## Update Cadence

1. Scheduled maintenance window: at least once per calendar month.
2. Emergency security updates: begin remediation within 48 hours for high-severity advisories affecting shipped paths.
3. Release freeze: no dependency updates inside release-candidate freeze unless security-critical.

## Versioning Guidance

1. Prefer stable semver constraints for direct dependencies.
2. Avoid broad/unbounded constraints that make lockfile drift unpredictable.
3. When upgrading major versions, document compatibility testing scope and migration risks in the PR.

## Verification Gates

Dependency update PRs are not complete until all checks pass:

1. `cargo clippy --all-targets --all-features --no-deps --locked -- -D warnings`
2. `cargo test --all-targets --all-features --locked`
3. `cargo check --target wasm32-unknown-unknown --no-default-features --locked`
4. `cargo check --target wasm32-wasip1 --no-default-features --features "mlkem,mldsa,fndsa,hqckem" --locked`
5. `cargo test --all-features --test nist_vector_replay_tests --locked`
6. `cargo audit`

## Release Evidence

Each CI run generates a compliance artifact (`artifacts/pqsynq-compliance-report.md`) and associated logs.  
Release candidates must retain these artifacts for traceability.
