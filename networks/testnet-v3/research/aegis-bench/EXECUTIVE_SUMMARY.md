# Executive summary

This evidence package supports a presentable controlled-performance result set for the frozen Synergy Aegis implementation. It does not yet support claims about live testnet TPS, finality, node resource use, or geographic-network behavior. Every quantity is labeled `MEASURED`, `DERIVED`, `EXISTING_TELEMETRY`, or `NOT_MEASURED`.

## A. Implementation discovered

The current Chain 1266 release mode is `coordinated_round_robin_v1`. ML-DSA-65 authenticates coordinated assignment, producer-block, coordinator-commit, validator-P2P, and optional typed-transaction paths. Public account transactions use ML-DSA-87. Support-node P2P identity uses the FN-DSA-1024 API over the in-tree Falcon-1024 compatibility implementation. The runtime also exposes SLH-DSA SPHINCS+-SHAKE-128f-simple, ML-KEM-1024, and HQC-256, but the source audit did not establish all of them as active coordinated-node roles.

Aegis adds explicit domain transcripts, algorithm dispatch, key identifiers, registry/lifecycle state, owner and role authorization, epoch/revocation checks, protocol envelopes, and a bounded verification-worker pool with positive-result caching. The current coordinated mode has no vote, quorum certificate (QC), view certificate (VC), or timeout certificate (TC); disabled typed-PoSy objects are not represented as current behavior.

## B. Experimental environment

The controlled results bind Synergy Testnet-v3 commit `9d3ab807a08ef4cf1077dbc23213e2314ce37c87`, branch `release/chain1266-consensus-invariants`, and Chain 1266 incarnation-4 RC30 Genesis SHA-256 `ee554c197a878cbfdaf7d470a0274ab2859a7a0c14c87e425908a69c6fbb51cf`.

Measurements ran on a non-virtualized Apple M2 Mac mini (`Mac14,3`), four performance plus four efficiency cores, 8 GiB RAM, macOS 26.5.2, and Rust/Cargo 1.97.1 targeting `aarch64-apple-darwin`. The locked release profile uses optimization level 3. Although the CPU exposes NEON, the production Aegis dependency did not enable its optional `neon` feature, so the results characterize the portable native path. This was an interactive development host; background load is disclosed and the results are not quiet bare-metal cycle measurements.

The publication dataset contains 204,230 raw timestamped observations: one full controlled run and two additional independent load processes. Of these, 204,180 satisfy their expected integrity condition; the other 50 deliberately retain the HQC-256 malformed-ciphertext dependency panic as `panic_caught`, not as a valid rejection.

## C. Strongest measured results

At a 512-byte workload, the runtime-abstraction medians were:

| Algorithm | Sign or encapsulate | Verify or decapsulate | n |
|---|---:|---:|---:|
| ML-DSA-65 | 277.229 us | 93.875 us | 500 |
| ML-DSA-87 | 360.437 us | 154.917 us | 500 |
| FN-DSA-1024 | 6.056 ms | 51.792 us | 500 |
| SLH-DSA SHAKE-128f-simple | 24.059 ms | 1.459 ms | 30 |
| ML-KEM-1024 | 11.459 us | 14.417 us | 500 |
| HQC-256 | 5.258 ms | 7.882 ms | 50 |

For Aegis ML-DSA-65 transaction-domain work, signing measured 288.792 us, a unique-signature cache miss 126.000 us, and an exact-replay cache hit 7.333 us (`n=500` each). The direct-to-Aegis cache-miss verification difference was +32.625 us (+34.94%), but the Aegis path performs additional policy, transcript, lifecycle, and worker-dispatch work; it is not an isolated wrapper instruction count.

The controlled four-worker pool reached a median of independent-run medians of 3,930.4 accepted unique-signature verifications/s at concurrency 64. The three run medians ranged from 3,870.6 to 3,958.7/s (CV 1.15%). This is local verification-pool throughput, not transaction TPS.

## D. System-level impact

For a 512-byte payload, the measured unsigned legacy JSON was 832 bytes, signed public transaction JSON 26,607 bytes, typed Aegis envelope 21,398 bytes, and transport carrier 47,600 bytes. The large carrier expansion includes current JSON decimal-byte arrays and nested envelope structure, not only mathematical signature material.

With independently signed 512-byte transaction fixtures, all ten 233-transaction committed frames passed the exact 8 MiB guard at a median of 8,353,615.5 bytes; all ten 234-transaction frames exceeded it at a median of 8,389,231 bytes. This is a workload- and encoding-specific boundary, not a universal transactions-per-block limit.

Current coordinated consensus creates three ML-DSA-65 authentication subjects per successful block. An empty assignment/proposal/commit package measured 1.205 ms to build/sign/serialize and 786.750 us to verify locally. For six validators and 100 transactions, source formulas produce 732 Aegis verification calls and 18.725 MB of aggregate authentication-delta bytes across transmissions. Those two totals are `DERIVED`; they are not measured six-node CPU, block latency, or finality.

## E. Bottlenecks

The dominant cost depends on the path. FN-DSA and SLH-DSA signing are much slower than their verification paths. HQC-256 is materially slower and larger than ML-KEM-1024 in the selected implementations. In transaction and block representations, current JSON encoding and repeated nested witness material dominate byte overhead. Under concurrent local verification, bounded-pool admission, thread creation, scheduling, policy work, and primitive verification jointly determine throughput; increasing offered concurrency beyond the useful range does not increase accepted work.

## F. Live-testnet evidence

The only live evidence is a sanitized, passive RPC-gateway snapshot collected through one authorized session on 2026-08-14. The service was enabled but inactive, with no Synergy process or listener and a last filtered journal height of zero. Therefore no live block interval, TPS, finality, CPU, memory, network, transaction latency, or active software-commit value was obtained. Historical incident material remains separate `EXISTING_TELEMETRY` and is excluded from controlled distributions.

## G. Missing evidence

A faithful disposable six-validator topology was unavailable. The package therefore lacks submit-to-inclusion/finality latency, accepted/committed/finalized TPS, node CPU and memory, storage and bandwidth, geographic propagation, fault/recovery behavior, and instantiated validator-count scaling. It also lacks x86-64/AVX2 and optional AArch64/NEON comparisons, energy and PMU data, a current equivalent classical production baseline, and a randomized-order quiet-host replication. Current-mode vote/QC/VC/TC measurements do not exist because those objects are absent from the selected consensus mode.

## H. Publication assessment

The primitive/runtime, Aegis cache, lifecycle, protocol-component, serialized-size, exact frame-boundary, negative-path, cold-start, and controlled verification-pool results are sufficiently reproducible for inclusion in an IACR ePrint paper if explicitly framed as a single-host portable-path controlled study. Validator scaling is suitable only as a formula-based sensitivity analysis. The HQC panic is publishable as a robustness finding with its exact boundary disclosed.

Live-network throughput, finality, production resource use, multi-node scaling, classical-comparison, optimized-hardware, and security claims are not supported and should not be published as established results. A paper should cite medians together with p95/p99, raw distributions, environment noise, evidence classifications, and the limitations in this package.
