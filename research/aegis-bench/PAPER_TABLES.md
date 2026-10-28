# Publication tables

All latency values are controlled Apple M2 measurements in microseconds unless stated otherwise. `Ops/s` is total work divided by total measured wall time, not the reciprocal of the median. Blank or “not measured” values are not zero. More digits remain in the machine-readable tables under `results/publication/`.

## Table 1 — Cryptographic artifact sizes

| Algorithm | Security/use role | Public key (B) | Secret key (B) | Signature/ciphertext (B) | Shared secret (B) | Classification |
|---|---|---:|---:|---:|---:|---|
| ML-DSA-65 | Current coordinated consensus, validator P2P, typed transaction option | 1,952 | 4,032 | 3,309 signature | — | Measured |
| ML-DSA-87 | Current public account transaction admission | 2,592 | 4,896 | 4,627 signature | — | Measured |
| FN-DSA-1024 | Current support-node P2P identity | 1,793 | 2,305 | 1,259–1,278 signature | — | Measured |
| SLH-DSA SHAKE-128f-simple | Runtime capability; not a current Aegis role | 32 | 64 | 17,088 signature | — | Measured |
| ML-KEM-1024 | Runtime KEM capability | 1,568 | 3,168 | 1,568 ciphertext | 32 | Measured |
| HQC-256 | Runtime/AIVM KEM capability | 7,245 | 7,317 | 14,421 ciphertext | 64 | Measured |

Source: `results/publication/cryptographic-artifact-sizes.csv`.

## Table 2 — Primitive/runtime-abstraction latency

| Algorithm | Operation/workload | Median (µs) | Mean (µs) | p95 (µs) | p99 (µs) | Ops/s | n |
|---|---|---:|---:|---:|---:|---:|---:|
| ML-DSA-65 | Key generation | 99.459 | 105.350 | 120.308 | 142.735 | 9,492.2 | 30 |
| ML-DSA-65 | Sign, 512 B | 277.229 | 359.447 | 867.731 | 1,314.935 | 2,782.1 | 500 |
| ML-DSA-65 | Verify, 512 B | 93.875 | 95.835 | 110.590 | 132.371 | 10,434.6 | 500 |
| ML-DSA-87 | Key generation | 152.500 | 159.542 | 180.306 | 231.555 | 6,268.0 | 30 |
| ML-DSA-87 | Sign, 512 B | 360.437 | 434.510 | 890.659 | 1,430.712 | 2,301.4 | 500 |
| ML-DSA-87 | Verify, 512 B | 154.917 | 157.543 | 175.591 | 187.138 | 6,347.5 | 500 |
| FN-DSA-1024 | Key generation | 24,530.855 | 26,627.194 | 39,729.381 | 48,688.517 | 37.6 | 30 |
| FN-DSA-1024 | Sign, 512 B | 6,055.854 | 6,241.728 | 6,193.598 | 12,004.022 | 160.2 | 500 |
| FN-DSA-1024 | Verify, 512 B | 51.792 | 53.159 | 61.853 | 69.265 | 18,811.6 | 500 |
| SLH-DSA SHAKE-128f-simple | Key generation | 1,012.895 | 1,023.871 | 1,084.196 | 1,106.024 | 976.7 | 30 |
| SLH-DSA SHAKE-128f-simple | Sign, 512 B | 24,058.563 | 24,164.203 | 24,606.942 | 25,182.736 | 41.4 | 30 |
| SLH-DSA SHAKE-128f-simple | Verify, 512 B | 1,458.938 | 1,462.054 | 1,563.358 | 1,603.013 | 684.0 | 30 |
| ML-KEM-1024 | Key generation | 10.750 | 10.928 | 11.231 | 13.616 | 91,510.8 | 30 |
| ML-KEM-1024 | Encapsulate | 11.459 | 12.017 | 15.186 | 17.762 | 83,218.3 | 500 |
| ML-KEM-1024 | Decapsulate | 14.417 | 14.599 | 15.586 | 20.587 | 68,496.1 | 500 |
| HQC-256 | Key generation | 2,534.854 | 2,549.368 | 2,641.354 | 2,648.258 | 392.3 | 30 |
| HQC-256 | Encapsulate | 5,258.145 | 5,426.984 | 6,266.454 | 6,564.340 | 184.3 | 50 |
| HQC-256 | Decapsulate | 7,882.188 | 7,982.099 | 8,491.221 | 9,053.973 | 125.3 | 50 |

These are `runtime_pqc_manager` results. Direct primitive rows are retained separately for Aegis-layer comparisons.

## Table 3 — Aegis production-path latency, 512-byte workload

| Protocol object/operation | Hash/serialization component | Key/lifecycle processing | Sign/verify component | Total median (µs) | n |
|---|---|---|---|---:|---:|
| Aegis ML-DSA-65 domain sign | Transcript/policy included, not isolated | Registry/domain checks included | Signing path | 288.792 | 500 |
| Aegis ML-DSA-65 verify, cache miss | Transcript hash included | Lifecycle/role/key checks included | Bounded worker + primitive verify | 126.000 | 500 |
| Aegis ML-DSA-65 verify, cache hit | Transcript hash included | Lifecycle/role/key checks included | Positive-cache lookup | 7.333 | 500 |
| Public ML-DSA-87 transaction construction | Raw hash 1.042; signed JSON serialization 37.916 | Not applicable | Signing included in total | 562.833 | 500 |
| Public transaction admission | JSON deserialization 82.375 | Public-key/algorithm checks included | Embedded verify 160.375 | 235.417 | 500 |
| Typed submission envelope verification | Canonical hash/serialization included | Fresh verifier + lifecycle witness | ML-DSA-65 verification | 149.229 | 500 |
| Aegis legacy carrier validation | Carrier serialization component 45.708 | Envelope/key checks included | Envelope verification included | 265.604 | 500 |
| Typed build/sign/verify/admit/carrier | Multiple canonical/JSON boundaries included | Fresh key and lifecycle path included | Sign and duplicate validation included | 1,082.625 | 30 |

Component medians come from separate component groups and do not sum exactly to the end-to-end distribution. The total column is directly measured.

Direct-to-Aegis median differences for sign/cache-miss verify were: ML-DSA-65 −0.750/+32.625 µs (−0.26%/+34.94%), ML-DSA-87 +11.771/+35.250 µs (+3.35%/+22.85%), and FN-DSA-1024 +2.500/+44.209 µs (+0.04%/+85.29%). These are full-path differences between semantically different operations, not isolated instruction overhead. The negative ML-DSA-65 sign difference is randomized-sampling variation.

## Table 4 — Transaction byte overhead

`Aegis bytes` is the actual JSON legacy-carrier representation used to transport the typed envelope. Overhead is `(carrier - unsigned legacy)/unsigned legacy`.

| Payload (B) | Unsigned legacy JSON (B) | Signed legacy JSON (B) | Aegis envelope JSON (B) | Aegis carrier JSON (B) | Aegis overhead |
|---:|---:|---:|---:|---:|---:|
| 32 | 352 | 26,129 | 19,689 | 45,319 | 12,774.7% |
| 64 | 384 | 26,159 | 19,808 | 45,505 | 11,750.3% |
| 128 | 448 | 26,226 | 19,998 | 45,754 | 10,112.9% |
| 192 | 512 | 26,288.5 | 20,265 | 46,125 | 8,908.8% |
| 256 | 576 | 26,351 | 20,512 | 46,446 | 7,963.5% |
| 512 | 832 | 26,607 | 21,398 | 47,600 | 5,621.2% |
| 1,024 | 1,344 | 27,126.5 | 23,281 | 50,166 | 3,632.6% |
| 4,096 | 4,416 | 30,193 | 34,162 | 64,586 | 1,362.5% |
| 16,384 | 16,704 | 42,487 | 78,058 | 123,139 | 637.2% |

The large percentages reflect fixed post-quantum witnesses plus current JSON decimal-byte-array and nested carrier encoding. They are not the ratio of signature lengths alone.

## Table 5 — Coordinated block/frame overhead

| Transactions/block | Exact committed frame median (B) | Authentication-delta median (B) | Authentication | Frame guard | n |
|---:|---:|---:|---:|---|---:|
| 1 | 89,445 | 77,829.5 | 87.01% | Accepted | 10 |
| 10 | 410,001 | 353,763 | 86.28% | Accepted | 10 |
| 100 | 3,614,611 | 3,112,967.5 | 86.12% | Accepted | 10 |
| 200 | 7,176,949 | 6,179,914 | 86.11% | Accepted | 10 |
| 225 | 8,068,146 | 6,947,281.5 | 86.11% | Accepted | 10 |
| 230 | 8,246,536 | 7,100,866.5 | 86.11% | Accepted | 10 |
| 231 | 8,282,218.5 | 7,131,546.5 | 86.11% | Accepted | 10 |
| 232 | 8,317,930.5 | 7,162,328.5 | 86.11% | Accepted | 10 |
| 233 | 8,353,615.5 | 7,193,027.5 | 86.11% | Accepted | 10 |
| 234 | 8,389,231 | 7,223,683 | 86.11% | Rejected (>8 MiB) | 10 |

All ten independently signed 233-transaction frames passed; all ten 234-transaction frames failed the exact current guard.

## Table 6 — Controlled local verification load

The offered quantity is concurrency, not offered tx/s. Tail latency is whole-burst wall time. Accepted/committed/finalized tx/s and network bytes are not measured.

| Workers | Offered concurrency | Median of run-median accepted verification/s | p50 burst (ms) | p95 burst (ms) | p99 burst (ms) | Process CPU/wall | Peak RSS (MB) | Saturation/error | Independent runs |
|---:|---:|---:|---:|---:|---:|---:|---:|---|---:|
| 4 | 1 | 6,450.8 | 0.158 | 0.259 | 0.357 | 103.5% | 8.19 | 0 / 0 | 3 |
| 4 | 4 | 14,171.9 | 0.283 | 0.350 | 0.419 | 258.0% | 8.44 | 0 / 0 | 3 |
| 4 | 16 | 6,521.3 | 2.476 | 3.314 | 3.775 | 191.4% | 9.44 | 0 / 0 | 3 |
| 4 | 64 | 3,930.4 | 16.267 | 17.293 | 17.991 | 160.7% | 11.71 | 0 / 0 | 3 |
| 4 | 128 | 3,563.7 | 18.230 | 21.576 | 26.230 | 165.8% | 13.93 | 60–64 saturated / 0 unexpected per burst | 3 |

At concurrency 64 the three run medians were 3,870.6–3,958.7 verification/s (CV 1.15%). The nonmonotonic result includes thread-creation and scheduling overhead and should not be treated as a worker-scaling law.

## Table 7 — Derived consensus authentication cost at 100 transactions/block

| Validators | Consensus auth verify calls | Transaction verify calls | Total Aegis verify calls | Aggregate authentication-delta bytes | Modeled Aegis verify wall time (ms) | Finality/round latency | Classification |
|---:|---:|---:|---:|---:|---:|---|---|
| 4 | 22 | 500 | 522 | 12,475,401.5 | 52.600 | Not measured | Derived |
| 6 | 32 | 700 | 732 | 18,724,898.5 | 78.585 | Not measured | Derived; current configured count |
| 7 | 37 | 800 | 837 | 21,849,647 | 91.578 | Not measured | Derived |
| 10 | 52 | 1,100 | 1,152 | 31,223,892.5 | 130.556 | Not measured | Derived |
| 16 | 82 | 1,700 | 1,782 | 49,972,383.5 | 208.512 | Not measured | Derived |
| 25 | 127 | 2,600 | 2,727 | 78,095,120 | 325.446 | Not measured | Derived |
| 50 | 252 | 5,100 | 5,352 | 156,213,832.5 | 650.263 | Not measured | Derived |

The modeled time uses the measured generic ML-DSA-65 Aegis medians of 126.000 µs per cache miss and 7.333 µs per hit. It is a sensitivity model, not measured consensus CPU, block latency, or finality. Formulas and assumptions are in `results/publication/derivation.json`.
