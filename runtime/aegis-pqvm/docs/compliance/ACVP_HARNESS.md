# ACVP Harness Plan - Aegis PQVM

## Goal
Provide repeatable ACVP-oriented evidence collection for PQVM algorithm implementations and deterministic replay behavior.

## Inputs
- KAT corpora under `tests/kats/`
- deterministic replay runner `scripts/run_deterministic_kat.sh`

## Outputs
- replay logs: `artifacts/acvp/replay_logs/`
- result corpus metadata: `artifacts/acvp/result_corpus/`
- ACVP manifest: `artifacts/acvp/manifest.json`

## Procedure
1. Pin repository commit and runtime environment metadata.
2. Export deterministic replay controls (`AEGIS_KAT_SEED`, `AEGIS_KAT_MAX_CASES`).
3. Execute `./scripts/run_deterministic_kat.sh`.
4. Archive generated logs, corpus metadata, and manifest in release evidence.
5. Verify replay integrity hashes before customer bundle packaging.
