# Aegis PQVM

`aegis-pqvm` is the blockchain-focused Aegis post-quantum module for deterministic virtual-machine integrations.

## Scope
- ML-KEM decapsulation only for trusted off-chain workflows (never deterministic/on-chain calldata).
- ML-DSA and FN-DSA detached-signature verification paths for deterministic VM execution.
- Integration shims for EVM, Substrate, CosmWasm, Solana, and Move runtimes through a compact AEG1 byte ABI.
- Security primitives, key lifecycle tracking, and runtime self-test helpers.

## Security posture
- Fail-closed ABI parsing with payload-size and argument-count limits.
- Deterministic source-root pinning for cryptographic C inputs (`pqcore` by default).
- Strict Rust quality gates (`fmt`, `check`, `test`, `clippy -D warnings`).
- Deterministic KAT replay script and cross-platform KAT CI workflow.
- Naming-policy and ignored-test policy gates.
- SBOM, checksums, and provenance workflow support for release evidence.

## Quick start
```bash
cd aegis-pqvm
cargo build --all-features
cargo test --all-features
./scripts/run_quality_gates.sh
```

`build.rs` consumes `pqcore` by default. To override explicitly for trusted build setups:
```bash
AEGIS_PQ_SOURCE_ROOT=/absolute/path/to/pqclean-compatible-tree cargo build --all-features
```

## Documentation index
- Developer guide: `docs/developer/DEVELOPER_GUIDE.md`
- Technical specification: `docs/specification/TECHNICAL_SPECIFICATION.md`
- User manual: `docs/manual/USER_MANUAL.md`
- Threat model: `docs/security/THREAT_MODEL.md`
- Security case bundle: `docs/security/SECURITY_CASE_BUNDLE.md`
- ACVP plan: `docs/compliance/ACVP_HARNESS.md`
- CMVP boundary: `docs/compliance/CMVP_BOUNDARY_AND_SELFTEST.md`
- Release policy: `docs/release/RELEASE_POLICY.md`
