# Security Policy - Aegis PQVM

## Supported branch
`main` is the supported security branch for `aegis-pqvm`.

## Reporting
Report vulnerabilities through your licensed support channel and include:
- affected commit hash
- reproduction steps
- impact assessment
- proof-of-concept inputs (if available)

## Security controls
- deterministic parsing and bounded payload handling in integration ABI
- constant-time comparison utilities and volatile-memory zeroization helpers
- deterministic KAT replay evidence and strict no-ignored-test policy checks
- CI security baseline with dependency audit and policy-gate enforcement
- release evidence generation (SBOM + checksums + provenance + package manifest)

## Out-of-scope disclosures
Issues solely inside third-party vendored cryptographic source trees should also be reported upstream to the original maintainers.
