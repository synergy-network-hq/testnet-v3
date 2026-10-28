# Methodology

## Software and environment

Measurements use Synergy Testnet-v3 commit `9d3ab807a08ef4cf1077dbc23213e2314ce37c87`, branch `release/chain1266-consensus-invariants`, and the Chain 1266 incarnation-4 RC30 Genesis whose SHA-256 is `ee554c197a878cbfdaf7d470a0274ab2859a7a0c14c87e425908a69c6fbb51cf`. The harness builds the locked dependency graph with Rust/Cargo 1.97.1 in an `opt-level=3` release profile.

The controlled host is a non-virtualized Apple M2 Mac mini with four performance and four efficiency cores, 8 GiB RAM, and macOS 26.5.2. The target is `aarch64-apple-darwin`. Although the CPU provides NEON, the production Aegis dependency does not enable its optional `neon` feature; the portable native paths are measured. The testnet topology is six validators by configuration, but no six-node local topology was instantiated. Validator-count aggregates are therefore derived, not measured node results.

## Raw observations and timing

Each executed operation produces one CSV row containing a run identifier, privacy-preserving environment identifier, commit, classification, sample timestamp in Unix nanoseconds, suite, implementation layer, exact algorithm, operation, payload profile, iteration, actual warmup count, wall nanoseconds, process CPU nanoseconds, process high-water RSS, validity/result, work units, object sizes, and timing-boundary notes.

Monotonic wall time uses `std::time::Instant`. CPU and peak RSS use `getrusage(RUSAGE_SELF)`. CPU time can include Aegis worker threads; RSS is a process high-water mark, not an allocation delta. `black_box` prevents elimination, while valid signatures are verified, KEM secrets are compared, and negative inputs are required to reject or are recorded as explicit failures. No cryptographic bytes or secrets are persisted.

## Implementations and layers

The direct layer invokes the exact ML-DSA-65, ML-DSA-87, and FN-DSA-1024 portable primitive modules used beneath Aegis. The `runtime_pqc_manager` layer additionally includes production key parsing, record allocation, timestamps, and internal registries. The Aegis layer additionally enforces domain/algorithm, lifecycle, owner, role, public-key, epoch, and revocation bindings, constructs the domain transcript, and uses a bounded worker pool on cache misses. Cache-hit measurements retain policy/transcript work and bypass only an already verified primitive call.

Protocol measurements use current public and typed transaction types, canonical serializers, validators, coordinated-round-robin types, and exact public `NetworkMessage` framing. The private P2P handshake signing helper cannot be called externally; its field-for-field payload is mirrored at the frozen source SHA, while the signed public `NetworkMessage::Handshake` representation is serialized and deserialized exactly. This component is labeled source-equivalent rather than an end-to-end socket handshake.

## Workloads

Deterministic payload sizes are 32, 64, 128, 192, 256, 512, 1,024, 4,096, and 16,384 bytes. Labels such as `vote192` and `transaction512` denote representative input sizes, not exact production wire lengths.

All six runtime algorithms receive key-generation measurements. Signature algorithms receive sign, valid verify, corrupted-signature rejection, and message-scaling samples. ML-KEM-1024 and HQC-256 receive encapsulation, valid decapsulation, and corrupted-ciphertext tests. Protocol suites separately time transaction hashing, serialization, deserialization, signing, envelope/carrier validation, coordinated assignment/block/commit operations, and exact framed bytes.

The block suite generates actual signed Aegis transaction/envelope pairs and constructs current three-authentication committed packages. Counts span 1 through 1,000 transactions, with dense sampling around the 8 MiB frame boundary. Authentication bytes are the exact JSON-size delta after clearing key IDs, signatures, public-key witnesses, lifecycle identities/roles, and the three consensus signatures while retaining structural field names.

## Warmup and repetitions

The publication run requests 30 key-generation and 500 operation samples after 10 warmups. SLH-DSA operation groups cap at 30 and HQC groups at 50 because of their cost. Block/frame groups use 10 independently signed packages per transaction count. Fresh-process operations use 30 independent processes. Typed end-to-end transaction construction uses 30 fresh-key samples; read-only transaction component groups use 500.

Warmups execute the same read-only operation before recorded steady-state samples. Mutating/fresh operations—new keys, unique cache misses, construction, rotation, and concurrent bursts—record zero warmups rather than claiming an operation that was not performed. Cache-hit samples explicitly prepopulate and warm the exact replay. Warmups are never emitted as raw measurement rows.

Controlled load uses unique 512-byte messages/signatures at concurrency 1, 2, 4, 8, 16, 64, 65, and 128 with worker configurations 1, 2, and 4. Each group has 100 bursts per independent run and three independent runs. Wall time includes scoped-thread creation, pool admission, Aegis processing, primitive verification, and joins. Accepted verifications are work units; saturation is expected bounded-pool backpressure. No value is transaction or finalized throughput.

## Statistics

For every exact classification/environment/commit/suite/layer/algorithm/operation/workload group, `analyze.py` reports `n`, valid count/fraction, mean, median, standard deviation, coefficient of variation, minimum, p50, p90, p95, p99, maximum, mean CPU time, operations per second, process RSS, and byte fields. Percentiles use linear interpolation at `(n-1)p`.

A deterministic 95% percentile-bootstrap interval for the median uses 2,000 resamples with a SHA-256-derived grouping seed. Intervals for small groups are retained but interpreted cautiously. MAD outlier flags use `0.6745|x-median|/MAD > 3.5`; all samples remain in the distribution. When MAD is zero, every nonmedian value is flagged. Null represents an unmeasured value in JSON and blank in CSV; zero is not substituted.

## Environment noise

The publication run was made on an interactive desktop. Its one-minute load averages were 2.55 before build, 4.16 immediately after build/before measurement, and 2.89 after measurement on eight logical cores. Codex/UI/background services remained active. CPU frequency, temperature, energy, and PMU counters were unavailable. This is a reproducible development-host baseline, not a quiet bare-metal cycle benchmark. Raw distributions, p95/p99, confidence intervals, load snapshots, and three independent load runs expose rather than hide this noise.

## Validator scaling

For a steady successful `coordinated_round_robin_v1` block with `N` connected validators and `T` transactions, source auditing gives `2N-1` network transmissions, three created consensus signatures, `5N+2` consensus-signature Aegis verification calls, and `(N+1)T` transaction-signature verification calls. Under the documented positive-cache assumptions, modeled primitive misses are `3N-1+NT` and hits are `2N+3+T`.

Aggregate bytes use measured median exact frames: `(N-1)A + P + (N-1)C` for assignment `A`, direct proposal `P`, and committed package `C`. Modeled verification wall time multiplies measured generic 512-byte ML-DSA-65 Aegis cache-miss/hit medians by those counts. It is a derived sensitivity model, not measured CPU, block latency, or finality.

## Integrity, ordering, and provenance

Corrupted signatures, wrong domains/roles/keys/lifecycle states, malformed JSON, changed transaction payloads, and frame limits are tested. Malformed HQC ciphertext panics in the dependency; the harness catches it only at the negative-test boundary and records `valid=false, result=panic_caught`.

Run order is fixed, which can correlate late groups with thermal/background drift. A future randomized-order replication must record its seed and remain a separate result set. Every run contains executable, source, Genesis, raw, derived, manifest, and environment hashes. `report.py` emits input hashes and formulas for consolidated tables and derived scaling.
