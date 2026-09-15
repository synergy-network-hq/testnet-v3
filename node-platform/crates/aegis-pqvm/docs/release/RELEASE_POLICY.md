# Release and Distribution Policy - Aegis PQVM

## Distribution policy
`aegis-pqvm` is distributed through licensed customer channels only.

## Explicit restrictions
- no public package-manager publishing workflow is authorized for this module
- release requires complete security/compliance evidence set

## Mandatory gate checklist
- `cargo fmt --all -- --check`
- `cargo check --all-targets --all-features --locked`
- `cargo test --all-targets --all-features --locked`
- `cargo clippy --all-targets --all-features --locked -- -D warnings`
- `cargo audit`
- naming, ignored-test, and absolute-path policy scripts
- deterministic KAT replay evidence
- side-channel boundary review (`scripts/run_side_channel_review.sh`)
- fuzz + fault-injection campaign (`scripts/run_fuzz_fault_campaign.sh`)
- traceability matrix check (`scripts/check_traceability_matrix.sh`)
- independent security sign-off check (`scripts/check_independent_security_signoff.sh`)
- SBOM/checksum/provenance artifact generation
