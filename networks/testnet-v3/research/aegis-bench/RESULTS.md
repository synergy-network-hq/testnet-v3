# Results

## Evidence scope

We measured 204,230 controlled raw observations on the frozen Apple M2 environment. The primary run contains primitive, Aegis, lifecycle, protocol, cold-start, and controlled-load suites; two additional processes repeat the complete load matrix. All artifacts are commit- and Genesis-bound and checksummed.

Of 9,520 primary negative-path rows, 9,470 satisfied their expected fail-closed behavior. The remaining 50 are all malformed HQC-256 ciphertext cases that triggered a dependency panic caught by the harness boundary. This is reported as a robustness failure, not a successful rejection. All positive signature and KEM integrity samples passed.

## Primitive behavior

Under the tested portable implementation, ML-DSA-65 provided a 277.229 µs median 512-byte sign and 93.875 µs verify; ML-DSA-87 measured 360.437 and 154.917 µs. Randomized signing had substantially wider upper tails than verification, so medians and p95/p99 should be cited together.

FN-DSA-1024 was asymmetric: its median verify was 51.792 µs, the fastest measured signature verification, while signing required 6.056 ms and key generation 24.531 ms. SLH-DSA SHAKE-128f-simple had the largest signature (17,088 bytes) and the slowest sign (24.059 ms). These comparisons characterize the selected implementations on one host; they do not rank cryptographic security.

ML-KEM-1024 encapsulation and decapsulation measured 11.459 and 14.417 µs. HQC-256 required 5.258 and 7.882 ms and produced a 14,421-byte ciphertext, versus 1,568 bytes for ML-KEM-1024. Neither timing proves which KEM is deployed by a current coordinated node role.

## Aegis abstraction

Aegis ML-DSA-65 transaction-domain signing measured 288.792 µs. A verification cache miss measured 126.000 µs and includes lifecycle/role/key/algorithm checks, transcript hashing, bounded worker dispatch, and primitive verification. An exact-replay cache hit measured 7.333 µs while retaining policy and transcript work. The observed cache-hit speedup is therefore a semantic reuse optimization, not a faster primitive implementation.

The direct ML-DSA-65 primitive verify median was 93.375 µs; PQCManager measured 93.875 µs; Aegis cache miss measured 126.000 µs. The additional 32–33 µs reflects the measured full-path difference, but it cannot be assigned solely to “wrapper code” because the paths perform different checks and worker dispatch.

Using independently sampled direct and Aegis medians, the explicit production-minus-direct differences were: ML-DSA-65 sign −0.750 µs (−0.26%) and cache-miss verify +32.625 µs (+34.94%); ML-DSA-87 sign +11.771 µs (+3.35%) and cache-miss verify +35.250 µs (+22.85%); FN-DSA-1024 sign +2.500 µs (+0.04%) and cache-miss verify +44.209 µs (+85.29%). The slightly negative ML-DSA-65 sign difference is sampling variation in randomized signing, not negative software cost. Cache-hit differences are not called overhead because the primitive is intentionally not re-executed.

Sequential batch verification preserved approximately linear scaling. ML-DSA-65 batches of 10, 100, and 1,000 sustained 10,492, 10,479, and 10,473 verifications/s; ML-DSA-87 sustained approximately 6,361, 6,342, and 6,336/s. FN-DSA-1024 reached 16,721–16,807/s for batches of 100–1,000. These batch loops are local primitive/runtime work, not consensus throughput.

## Lifecycle and initialization

Registry lookups and individual role/active/revocation checks were sub-microsecond at a one-key registry. The deterministic lifecycle root scaled from 0.667 µs for one key to 383.542 µs for 1,000 and 3.933 ms for 10,000 keys (100 samples per size), consistent with traversal/serialization work rather than constant-time lookup.

Across 30 fresh processes, signer initialization had a 544.854 µs median. First and second domain verification medians were 141.062 and 135.188 µs. The wide cold-start tails and interactive host limit stronger initialization claims.

## Transaction and consensus paths

For a 512-byte representative payload, public ML-DSA-87 transaction construction measured 562.833 µs and admission validation 235.417 µs. The typed Aegis submission envelope verify measured 149.229 µs, carrier validation 265.604 µs, and the broader fresh-key build/sign/verify/admit/carrier path 1.083 ms.

Current coordinated consensus creates three ML-DSA-65 authentication subjects per successful block: assignment, producer block, and coordinator commit. Assignment and commit hash/sign/serialize medians were 311.167 and 310.063 µs; their crypto verification medians were 161.437 and 165.875 µs. An empty three-authentication committed package measured 1.205 ms to build/sign/serialize and 786.750 µs to verify. These are local component costs, not finality latency.

## Serialization and frame limit

The current JSON representations amplify post-quantum material. A 512-byte unsigned legacy transaction was 832 bytes at the measurement boundary, the signed public representation was 26,607 bytes, the typed submission envelope was 21,398 bytes, and the transport carrier was 47,600 bytes. The carrier was 5,621% larger than the unsigned legacy form and 78.9% larger than the signed public form. This includes current decimal byte-array and nested carrier structure, not only signature bytes.

For independently signed 512-byte transaction fixtures, the committed frame median grew from 89,445 bytes at one transaction to 8,353,615.5 bytes at 233. Every 233-transaction sample remained below the exact 8 MiB guard; every 234-transaction sample exceeded it, with a median 8,389,231 bytes. The boundary is workload- and encoding-specific rather than a universal transactions-per-block limit.

## Controlled load

Three independent load runs exercised unique-signature Aegis verification bursts with one, two, and four configured workers. With four workers and concurrency 64, run-median throughput ranged from 3,870.6 to 3,958.7 accepted verifications/s (CV 1.15%). At concurrency 128, the bounded pool accepted approximately 64–68 attempts and rejected the remainder as saturated with no unexpected errors.

Throughput peaked at lower concurrency and then declined because the timed boundary includes OS thread creation, queueing, scheduling, Aegis policy work, primitive verification, and joins. These values demonstrate bounded backpressure and local crypto-pool behavior; they do not establish RPC, block, committed, or finalized TPS.

## Validator scaling

Source-derived steady-round formulas give `2N-1` coordinated transmissions, `5N+2` consensus-signature verification calls, and `(N+1)T` transaction-signature verification calls for `N` validators and `T` transactions. For the configured six-validator count and `T=100`, the model yields 32 consensus-signature calls, 700 transaction-signature calls, and 18.725 MB of aggregate authentication-delta bytes across transmissions.

That six-validator row remains derived: no six-node local round, CPU trace, propagation measurement, or finality measurement was instantiated. Time estimates multiply measured generic cache-hit/miss costs and should not be quoted as block latency.

## Live observation and publication assessment

The authorized passive RPC-gateway snapshot found no running Synergy service or listener. Consequently this study has no live block interval, TPS, finality, CPU, memory, network, or transaction-latency result. Historical incident data are retained only as existing telemetry and are not merged into controlled distributions.

The primitive/runtime, Aegis cache, lifecycle, protocol-component, serialized-size, frame-boundary, negative-path, cold-start, and controlled verification-pool results are reproducible enough for a paper as a clearly labeled Apple M2 portable-path controlled study. Validator scaling can be published only as a formula-based sensitivity analysis. Claims about network throughput, live overhead, production finality, validator resource use, geographic scaling, cross-platform performance, classical superiority, or cryptographic security are not supported by the collected evidence.
