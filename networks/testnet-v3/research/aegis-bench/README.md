# Synergy Aegis post-quantum benchmark

This directory is the reproducible evidence package for the post-quantum implementations and Aegis protocol paths selected by Synergy Testnet-v3 at commit `9d3ab807a08ef4cf1077dbc23213e2314ce37c87`.

Every result is classified as `MEASURED`, `DERIVED`, `EXISTING_TELEMETRY`, or `NOT_MEASURED`. Controlled cryptographic throughput is never labeled transaction TPS, source-derived validator scaling is never labeled live behavior, and missing values remain null rather than zero.

The publication dataset contains 204,230 raw rows: one complete safe local run plus two additional independent controlled-load runs. Fifty rows deliberately retain the HQC-256 malformed-ciphertext `panic_caught` finding; all other 204,180 rows satisfy their integrity expectations.

## Reproduce measurements

From the repository root:

```bash
research/aegis-bench/run.sh micro
research/aegis-bench/run.sh protocol
research/aegis-bench/run.sh load-local
research/aegis-bench/run.sh all-safe
```

`micro` is the safe default when no mode is supplied. It does not contact a remote network. `protocol` exercises local production types and validators. `load-local` uses only the local bounded verification pool. `all-safe` combines those modes. `live-observation` is a separate, passive one-session SSH workflow and must be invoked deliberately.

Default publication settings are 30 key-generation samples, 500 operation samples, 10 warmups, and 30 fresh processes. Slow-path caps are disclosed in `METHODOLOGY.md`. Override counts without editing source:

```bash
AEGIS_BENCH_RUN_ID=my-replication \
AEGIS_BENCH_KEYGEN_ITERATIONS=30 \
AEGIS_BENCH_OPERATION_ITERATIONS=500 \
AEGIS_BENCH_WARMUP_ITERATIONS=10 \
AEGIS_BENCH_COLD_PROCESSES=30 \
research/aegis-bench/run.sh all-safe
```

The runner verifies the canonical Genesis hash, builds locked release binaries, captures pre-build/pre-measurement/post-measurement environments, writes timestamped raw rows under `results/runs/<run-id>/raw/`, derives summaries and plots, and writes `SHA256SUMS`.

## Rebuild publication outputs

The checked-in publication results are regenerated without rerunning measurements:

```bash
research/aegis-bench/scripts/rebuild-publication.sh
```

The script combines the primary run `publication-m2-20260815-v1` with independent load runs `publication-load-m2-20260815-v2` and `v3`, then runs `analyze.py` and `report.py`. `results/publication/derivation.json` records every authoritative raw input and SHA-256 digest.

## Evidence map

- `SOURCE_RECONNAISSANCE.md`: production call paths and current consensus boundary.
- `ALGORITHM_MATRIX.md` and `algorithm-inventory.csv`: source, exposure, Aegis, deployment, and benchmark status.
- `BENCHMARK_PLAN.md` and `measurement-matrix.csv`: execution record and coverage.
- `ENVIRONMENT.md` and `environment.json`: frozen source, build, host, and Genesis identity.
- `METHODOLOGY.md`: timing boundaries, repetitions, statistics, noise, and integrity rules.
- `RESULTS.md` and `PAPER_TABLES.md`: cautious narrative and publication tables.
- `EXECUTIVE_SUMMARY.md`: concise implementation, environment, results, impact, gaps, and publication assessment.
- `PROVENANCE.md`: table-to-raw traceability.
- `REQUIREMENTS_AUDIT.md`: section-by-section disposition of the 43-part benchmark brief.
- `LIMITATIONS.md`, `NOT_MEASURED.md`, and `EXISTING_TELEMETRY.md`: exclusions and evidence boundaries.
- `src/`: release-mode measurement harnesses.
- `analyze.py` and `report.py`: deterministic summaries, plots, tables, and source-derived models.
- `results/runs/`: authoritative run packages; `results/publication/`: consolidated outputs.

Diagnostic/smoke files prove harness behavior only and must not be cited as headline performance results.
