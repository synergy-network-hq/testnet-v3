# Security Case Bundle - Aegis PQVM

## Objective
Demonstrate that `aegis-pqvm` is release-ready for regulated review with auditable, reproducible security evidence.

## Evidence inventory
- gate logs: `fmt/check/test/clippy/audit` outcomes
- deterministic KAT replay logs and result corpus under `artifacts/acvp/`
- side-channel boundary review logs/reports under `artifacts/security/side_channel_review_*.{log,md}`
- fuzz/fault campaign logs and summary JSON under `artifacts/security/`
- threat model and compliance narratives under `docs/security/` and `docs/compliance/`
- checksum and manifest outputs under `artifacts/checksums/`
- SBOM output under `artifacts/sbom/`
- customer package checksum under `artifacts/package/`
- traceability matrix under `docs/security/TRACEABILITY_MATRIX.md`
- independent review sign-off under `docs/security/INDEPENDENT_SECURITY_SIGNOFF.md`

## Claims
1. Deterministic parsing and cryptographic verification flows fail closed on malformed input.
2. Legacy naming/alias drift is blocked by policy gate.
3. KAT bypass via ignored test attributes is blocked by policy gate.
4. Release artifacts can be independently integrity-validated.
5. Deterministic boundary controls block secret-key-bearing operations from on-chain interfaces.
6. Fuzzing and deterministic fault-injection campaigns execute with reproducible settings.

## Residual risk register
- third-party dependency vulnerability churn between releases
- host-chain integration misuse outside documented constraints
- platform-specific microarchitectural behavior in vendored C implementations requiring dedicated hardware/runtime validation

## Acceptance criteria
- all module security baseline workflow checks pass
- cross-platform deterministic KAT workflow passes
- side-channel boundary review workflow passes
- fuzz and fault-injection campaign workflow passes
- traceability matrix check passes
- independent security/code review sign-off check passes
- release evidence artifacts are present and checksummed
