# Aegis PQVM Threat Model

## Scope
- Module: `aegis-pqvm`
- Security boundary: Rust crate API surface, deterministic integration ABI, build/release evidence toolchain
- Runtime environments: blockchain virtual machines integrating AEG1 payload dispatch

## Assets
- ML-KEM shared secrets and decapsulation correctness
- ML-DSA and FN-DSA verification correctness
- key lifecycle metadata and audit records
- build and release artifacts consumed by customer environments

## Trust boundaries
1. Host blockchain runtime -> PQVM deterministic dispatch interface
2. PQVM Rust boundary -> vendored C cryptographic implementations
3. CI/build environment -> published customer release bundle
4. Customer deployment environment -> supplied manifests/SBOM/provenance evidence

## Abuse paths
1. Malicious oversized payloads aimed at exhausting decoder memory.
2. Invalid byte sequences probing parser edge-cases for panics or undefined behavior.
3. Silent policy drift introducing legacy alias names or bypassed KAT checks.
4. Supply-chain tampering between build outputs and customer delivery.
5. Key lifecycle state corruption leading to use of retired/destroyed key identifiers.

## Controls
- bounded payload and argument limits in `src/integrations/abi.rs`
- strict deterministic dispatch rules with explicit unsupported-operation responses
- lifecycle state machine validation and append-only audit event recording
- strict CI baseline (`fmt`, `check`, `test`, `clippy -D warnings`, `cargo audit`)
- deterministic KAT replay logs and no-ignored-test policy gate
- side-channel boundary review workflow (`scripts/run_side_channel_review.sh`)
- fuzz + fault-injection workflow (`scripts/run_fuzz_fault_campaign.sh`)
- requirement-to-evidence mapping via `docs/security/TRACEABILITY_MATRIX.md`
- independent security/code review sign-off gate (`scripts/check_independent_security_signoff.sh`)
- SBOM, checksum manifests, release bundling, and provenance attestation workflow

## Residual risk
- transitive dependency CVEs discovered between release windows
- runtime misuse by host chains that bypass documented operational controls
- side-channel risk in third-party vendored C implementations outside this wrapper layer

## Review cadence
- refresh threat model on every release candidate and whenever integration ABI semantics change
