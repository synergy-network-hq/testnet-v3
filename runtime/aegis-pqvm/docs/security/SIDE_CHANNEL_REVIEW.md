# Side-Channel and Constant-Time Review

## Objective
Provide reproducible evidence that `aegis-pqvm` enforces deterministic boundary controls that prevent secret-key exposure in on-chain interfaces, and track residual side-channel risk requiring platform-lab validation.

## Review Method
1. Execute deterministic-boundary tests in `tests/side_channel_review.rs`.
2. Validate deterministic adapters do not call off-chain dispatchers (`scripts/run_side_channel_review.sh` static checks).
3. Validate deterministic encoder/dispatcher explicitly reject ML-KEM decapsulation with secret-key payloads.
4. Validate Move and CosmWasm routing/binding controls are enforced.

## Evidence Artifacts
- Latest generated review report: `artifacts/security/side_channel_review_*.md`
- Latest generated review log: `artifacts/security/side_channel_review_*.log`
- Deterministic-boundary tests: `tests/side_channel_review.rs`
- Deterministic ABI controls: `src/integrations/abi.rs`

## Result Interpretation
- `PASS`: wrapper-layer controls are in place and verified for deterministic interfaces.
- `FAIL`: boundary controls regressed and release must be blocked.

## Residual Risk
- Microarchitectural timing/cache/branch-leak behavior inside vendored C cryptographic implementations remains a platform-specific validation item and must be assessed in dedicated hardware/runtime evaluation.
