# Provenance

## Frozen identity

- Source commit: `9d3ab807a08ef4cf1077dbc23213e2314ce37c87`
- Environment: `macmini-m2-macos26.5.2-rust1.97.1-aarch64-20260814`
- Genesis SHA-256: `ee554c197a878cbfdaf7d470a0274ab2859a7a0c14c87e425908a69c6fbb51cf`
- Primary run: `results/runs/publication-m2-20260815-v1/`
- Independent load runs: `results/runs/publication-load-m2-20260815-v2/` and `v3/`
- Consolidated analyzer input count: 204,230 rows
- Statistic implementation: `analyze.py`; table/model implementation: `report.py`

Each run’s `SHA256SUMS` binds the release binaries, harness sources, lockfile, Genesis, raw rows, summaries, plots, manifest, and environment snapshots. `results/publication/derivation.json` independently lists the raw inputs and digests used by publication derivations.

## Table traceability

| Table/metric | Authoritative raw input and row selector | Calculation | Generated evidence | Classification |
|---|---|---|---|---|
| Table 1 artifact sizes | Primary primitive CSV; `suite=primitive`, `valid=true`, group by algorithm | Maximum nonzero key/ciphertext/shared-secret length; min/max valid signature length | `cryptographic-artifact-sizes.csv` | Measured |
| Table 2 primitive latency | Primary primitive CSV; `layer=runtime_pqc_manager`; keygen, 512-byte sign/verify, KEM operations | Median/mean/p95/p99 over `wall_ns`; ops/s = total work/total wall | `primitive-latency.csv` | Measured/derived statistics |
| Table 3 Aegis paths | Primary Aegis and protocol CSVs; selectors encoded in `publication_table_rows` | Direct operation distributions; separately labeled component medians | `aegis-production-latency.csv`, `summary.csv` | Measured/derived statistics |
| Table 4 transaction bytes | Primary protocol CSV; public build, envelope serialize, carrier serialize; group by payload | Median actual serialized bytes; percent formulas shown in table | `transaction-overhead.csv` | Derived from measured bytes |
| Table 5 block/frame | Primary protocol CSV; committed package build and frame guard, iterations 0–9 | Median/min/max actual framed JSON and authentication delta | `block-overhead.csv` | Measured/derived statistics |
| Table 6 load | Three workers4 raw CSVs; group by run/concurrency | Per-run median accepted work/wall; pooled burst tails, CPU/wall, RSS; run CV | `load-independent-runs.csv`, `load-run-variability.csv`, `summary.csv` | Measured/derived statistics |
| Table 7 validator scaling | Primary protocol exact assignment/proposal/committed frames; primary Aegis 512-byte cache hit/miss; audited production call paths | Explicit formulas in `derivation.json` | `validator-scaling.csv` | Derived |

## Headline metric records

### Primitive and Aegis timing

The primary primitive raw file is `publication-m2-20260815-v1-primitive.csv`, SHA-256 `6f17313973f1d37a46fb2bc87f7c073a8964162bcc99bc7e7338654c6bcea91e`. Table 2 groups are selected by exact algorithm/operation/workload. The Aegis raw file is `publication-m2-20260815-v1-aegis.csv`, SHA-256 `e9ece79a0e4c24b99991fe8134dbaf0c3d57f969fe56e7b0bcd14e9580b5eca4`. The 288.792, 126.000, and 7.333 µs medians use the ML-DSA-65 transaction wrapper `sign_domain`, `verify_cache_miss`, and `verify_cache_hit` groups, each `n=500`.

### Transaction and frame values

The primary protocol raw file is `publication-m2-20260815-v1-protocol.csv`, SHA-256 `c8dd7ef155701e10933f95eb1f29e6fd5ae613d809a9162502b0afec0ca41841`. The 512-byte transaction values select `payload_profile=transaction512`. The frame boundary selects `coordinated_p2p_frame_guard`, `item_count=233` or `234`, iterations 0–9. At 233 the measured range is 8,353,512–8,353,733 bytes and every result is `accepted_within_8mib_limit`; at 234 the range is 8,388,982–8,389,482 and every result is `rejected_above_8mib_limit`.

### Lifecycle and cold start

The lifecycle file SHA-256 is `8e85adf1997e1ba8b675ba03cfcba1678347ffa8f0782771531695c6a6278587`; lifecycle-root medians group by registry size with 100 rows each. The combined cold-start file SHA-256 is `e555a7b5eb53622caba87d364c1b4c0ff5a63e2384f0398df177e2f81de8f9cd`; its seven operations have 30 fresh-process rows each, backed by individually retained process CSVs.

### Independent load runs

Workers4 raw-file hashes are `44240134d96148fe3003408d73423ed355c64ffa373c5262251a70e31ae39d7a`, `d947520cf8ebf9749051353422be041f22270729758b84769ba60930935bfdaa`, and `76963da1ba6d2ce1ee679759c91ece1202d295c7ee9c92fea511fe1e6de4a7a6`. Each concurrency group contributes 100 bursts per run. The 3,930.4 verification/s headline is the median of the three per-run medians at workers4/concurrency64; the 1.15% CV is the sample standard deviation of those three medians divided by their mean.

### HQC negative path

The HQC finding selects the primary primitive CSV rows `suite=negative`, `algorithm=HQC-256`, `operation=decapsulate_tampered_ciphertext`. All 50 rows record `valid=false`, `result=panic_caught`. The panic is caught only by the benchmark negative-test boundary.

### Live observation

The sanitized passive record `results/live-observation-20260814.json` has SHA-256 `2a44781f4f1851ba2b08cf5d9654d6e93d52b1df2c47a0c577c9cf71017b0659`. It supports only the inactive-service/artifact-inventory statements in `EXISTING_TELEMETRY.md`; it provides no live performance value.
