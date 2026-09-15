# Source reconnaissance

## Current deployment boundary

The checked-out Chain 1266 release explicitly requires `coordinated_round_robin_v1`; typed PoSy is present in source but disabled for this release. The current coordinated path has no validator vote, QC, VC, or TC. A normal committed block package authenticates three subjects with ML-DSA-65 through Aegis:

1. the Val1 producer assignment;
2. the assigned producer's block header;
3. the Val1 coordinator commit.

The package verifier checks the assignment while verifying the producer block and then checks the coordinator commit. Those signatures are not a quorum certificate. Measurements of typed-PoSy vote/QC/VC/TC code must be labeled controlled implemented-but-disabled evidence, never current deployed consensus behavior.

## Transaction paths

Two transaction representations coexist.

The public `synergy_sendTransaction` RPC uses `transaction::Transaction`. Public account transactions require ML-DSA-87, include the signer public key and signature, validate the embedded signature before mempool admission, then pass `ProofOfSynergy::validate_transaction_for_mempool` and P2P broadcast.

The typed `synergy_types::Transaction` uses an Aegis key ID and signature. `AegisTxSubmissionEnvelope` adds the public key and lifecycle record; the RPC helper verifies that envelope, converts it to a legacy carrier, validates the carrier, queues it, and broadcasts it. This path includes canonical serialization, domain separation, key lifecycle checks, signature verification, envelope JSON/base64 overhead, and duplicate validation boundaries that primitive benchmarks do not include.

The pre-existing `pqc-benchmark` binary is not reused as primary evidence: it describes FN-DSA transaction signing even though current public user admission requires ML-DSA-87, emits summary-only data, and does not benchmark Aegis policy/cache boundaries.

## Peer identity

The active P2P handshake is Aegis-signed. Configured validators use their Genesis-assigned ML-DSA-65 consensus key with peer and consensus roles. Non-consensus support nodes generate an FN-DSA-1024 Aegis peer identity. Validator handshakes additionally bind the key to the canonical active validator record. A stale comment referring to Ed25519 P2P identity is not treated as execution evidence.

## Runtime primitive abstraction

`runtime/src/crypto/pqc.rs` exposes exactly six variants:

- ML-DSA-65 and ML-DSA-87 from the in-tree Aegis native bindings;
- FN-DSA-1024 from Aegis's `fndsa1024` binding, backed by Falcon-1024 compatibility C symbols;
- SLH-DSA as SPHINCS+-SHAKE-128f-simple from `pqcrypto-sphincsplus 0.7.2`;
- ML-KEM-1024 from `pqcrypto-mlkem 0.1.1`;
- HQC-256 from `pqcrypto-hqc 0.2.2`.

`PQCManager` parses keys on each sign/verify, timestamps results, allocates owned output vectors, and inserts generated signatures/ciphertexts/shared secrets into internal registries. Measurements at this layer are therefore labeled `runtime_pqc_manager`, not bare primitive FFI timings.

One source anomaly is retained for interpretation: ML-DSA-65 key generation returns the keypair but does not insert it into the manager's keypair registry, whereas the other generator paths do. Direct-key APIs work; ID-based lookup behavior is not equivalent across variants.

## Aegis wrapper boundary

Signing performs registry lookup, domain-policy enforcement, length-prefixed domain/chain binding, primitive signing, and wrapper allocation.

Verification always performs presence, lifecycle, role, public-key, algorithm, and consensus-domain checks. It then hashes a cache key over the complete transcript. A cache miss submits the primitive verification to a process-wide bounded pool: capacity 64, default two workers, maximum four. A cache hit bypasses only the primitive; policy and transcript work still runs. The positive cache has 4,096 entries and a two-height scoped pruning window for height-scoped consensus calls.

That distinction is operationally material: the incident ledger records an older typed-PoSy deployment repeatedly verifying equivalent ML-DSA-65 votes during certificate formation, consuming the healthy-path deadline and approximately one CPU core per validator. Those historical values are `EXISTING_TELEMETRY`; the local cache-hit/miss measurements are new `MEASURED` results.

## Dependency and deployment mismatches preserved in the matrix

The identity workbook provisions ML-KEM-768 entropy-contribution keys, while the runtime `PQCManager` exposes ML-KEM-1024. They are separate rows. The library also contains ML-DSA-44, ML-KEM-512/768, and FN-DSA-512 code without a current runtime call path. No result for one variant is substituted for another.

## Protocol-object investigation

| Object requested | Current finding | Measurement disposition |
|---|---|---|
| Public transaction | ML-DSA-87 signed legacy/public transaction | Full component and admission measurements |
| Typed Aegis transaction | ML-DSA-65 typed transaction plus submission envelope and legacy carrier | Full component, envelope, carrier, and end-to-end local measurements |
| Block/header | Assigned producer signs the canonical block header with ML-DSA-65 | Assignment, block, commit, package, and frame measurements |
| Validator vote | No vote in current `coordinated_round_robin_v1` | `NOT_MEASURED`; current object absent |
| QC/VC/TC | No certificate in current coordinated mode | `NOT_MEASURED`; current object absent |
| Epoch transition | No separate Aegis-signed epoch-transition wire object was established in the current coordinated path | Lifecycle-root and epoch policy checks measured; no invented object timing |
| Validator registration/readiness | Genesis/finalized validator records and authenticated P2P identity bind readiness | Handshake authentication and registry policy components measured; full node readiness startup not measured |
| P2P handshake | Validators use ML-DSA-65; support nodes use FN-DSA-1024 | Source-equivalent private signing payload and exact public wire representation measured |
| DAG object | Transaction/block structures bind DAG roots, but no separate current Aegis-signed DAG wire object was established | Covered inside actual typed transaction/block structures only |
| Archive object | No separate current Aegis-signed archive object was established | Not benchmarked |

The absence of a separate object is an implementation finding, not a zero-cost measurement.
