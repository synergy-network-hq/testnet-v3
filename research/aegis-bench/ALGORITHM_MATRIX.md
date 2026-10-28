# Algorithm and deployment matrix

This matrix distinguishes source availability from a demonstrated current call path. “Deployed” means that the checked-out Chain 1266 runtime selects the algorithm for the stated role; it does not mean that the passive snapshot proved the service was running.

| Algorithm | Parameter set | Source location | Compiles? | Runtime exposed? | Used in Aegis? | Current testnet call path? | Protocol role | Benchmark status |
|---|---|---|---:|---:|---:|---:|---|---|
| ML-DSA | ML-DSA-65 | `runtime/aegis-pqvm/src/mldsa65.rs` and native clean C | Yes | Yes | Yes | Yes | Coordinated assignment, producer block, coordinator commit, validator P2P, typed transaction option | Measured direct, PQCManager, Aegis, and protocol paths |
| ML-DSA | ML-DSA-87 | `runtime/aegis-pqvm/src/mldsa87.rs` and native clean C | Yes | Yes | Yes | Yes | Public account transaction admission and account/authority identities | Measured direct, PQCManager, Aegis, and public transaction paths |
| FN-DSA | FN-DSA-1024 | `runtime/aegis-pqvm/src/fndsa1024.rs`; Falcon-1024 compatibility C symbols | Yes | Yes | Yes | Yes | Non-validator support-node P2P identity and provisioned primary identities | Measured direct, PQCManager, Aegis, and source-equivalent handshake paths |
| SLH-DSA | SPHINCS+-SHAKE-128f-simple | `pqcrypto-sphincsplus 0.7.2` | Yes | Yes | No current Aegis parser variant | No demonstrated current role | PQCManager capability | Measured PQCManager primitive only |
| ML-KEM | ML-KEM-1024 | `pqcrypto-mlkem 0.1.1` | Yes | Yes | KEM abstraction | Architecturally relevant; active coordinated use not proven | PQCManager, wallet sealed material, ETDAG protected-input source | Measured PQCManager primitive only |
| HQC | HQC-256 | `pqcrypto-hqc 0.2.2` | Yes | Yes | KEM abstraction | No demonstrated current role | PQCManager and AIVM interoperability surface | Measured; malformed-ciphertext panic retained |
| ML-KEM | ML-KEM-768 | Identity workbook policy | N/A policy row | Not by current `PQCManager` enum | No current runtime mapping | Provisioned policy only | Entropy-contribution identity | Not measured; no substitution from ML-KEM-1024 |
| ML-DSA | ML-DSA-44 | Aegis library source | Yes as library source | No | No reachable current wrapper path | No | None established | Not measured |
| ML-KEM | ML-KEM-512/768 | Aegis library source | Yes as library source | No | No reachable current wrapper path | No | None established | Not measured |
| FN-DSA | FN-DSA-512 | Aegis library source | Yes as library source | No | No reachable current wrapper path | No | None established | Not measured |

## FN-DSA naming

The runtime enum and Aegis API call the deployed support-node algorithm `FNDSA`/`FN-DSA-1024`. Its binding is `fndsa1024`, while the in-tree native compatibility symbols and source lineage use Falcon-1024 terminology. This report therefore uses **FN-DSA-1024 API over Falcon-1024 compatibility implementation**. It is not ML-DSA and no ML-DSA timing is substituted for it.

## Agility mechanism

Algorithm identifiers are explicit enum/string values carried in key and signature records. Aegis selection is not an unauthenticated per-message negotiation: each domain admits a configured algorithm, while registry records bind algorithm, key ID, owner, roles, activation epoch, revocation state, and public key. Verification checks those bindings before primitive dispatch. Multiple algorithms coexist across roles, but a message cannot select an unsupported identifier and reach a weaker fallback; unknown and mismatched identifiers were measured as rejection paths.

These implementation observations are not a proof of downgrade resistance. Protocol governance, upgrade authorization, threat modeling, and cryptographic security arguments are outside performance measurement.
