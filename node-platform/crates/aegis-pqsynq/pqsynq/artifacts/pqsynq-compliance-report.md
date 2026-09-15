# Aegis-PQSynQ Compliance Report

- Generated (UTC): 2026-02-09T23:27:01Z
- Commit: 835dea2
- NIST replay vectors per algorithm: 10

## Test Results

| Check | Status | Log |
|---|---|---|
| Official NIST replay (nist_vector_replay_tests) | PASS | artifacts/nist_vector_replay.log |
| Pinned fixture manifest integrity (vector_manifest_tests) | PASS | artifacts/pinned_vector_manifest.log |

## Official Source Files (SHA-256)

| Algorithm | File | SHA-256 |
|---|---|---|
| ML-KEM-512 | NIST-ml-kem/reference/ml-kem-512/PQCkemKAT_1632.rsp | a30184edee53b3b009356e1e31d7f9e93ce82550e3c622d7192e387b0cc84f2e |
| ML-KEM-768 | NIST-ml-kem/reference/ml-kem-768/PQCkemKAT_2400.rsp | 729367b590637f4a93c68d5e4a4d2e2b4454842a52c9eec503e3a0d24cb66471 |
| ML-KEM-1024 | NIST-ml-kem/reference/ml-kem-1024/PQCkemKAT_3168.rsp | 3fba7327d0320cb6134badf2a1bcb963a5b3c0026c7dece8f00d6a6155e47b33 |
| ML-DSA-44 | NIST-ml-dsa/reference/ml-dsa-44/PQCsignKAT_Dilithium2.rsp | 1d29c3b4ec68e3455f87f49b3386a2a6fc5e167c76e476c4770317ffbb97d242 |
| ML-DSA-65 | NIST-ml-dsa/reference/ml-dsa-65/PQCsignKAT_Dilithium3.rsp | 3c9427c9939788031cbaf2cdfa3e49c1e69ead5584516ad513567a4880fa64b6 |
| ML-DSA-87 | NIST-ml-dsa/reference/ml-dsa-87/PQCsignKAT_Dilithium5.rsp | 8f35a98d3672e89fe8b4d461ff62a145edfe972e515a9bccec248b7899b718ec |
| FN-DSA-512 | NIST-fn-dsa/reference/falcon512-KAT.rsp | dd75c946fdedef4ec46a2bee7e10c65c9126f1a839b9ced6921fd45f7354b5cd |
| FN-DSA-1024 | NIST-fn-dsa/reference/falcon1024-KAT.rsp | 036a0bf5260573cec44977284dfef756cd1143db9961b981bd1fb55828acb20d |
| HQC-KEM-128 | NIST-hqc-kem/reference/hqc-kem-128/hqc-128_kat.rsp | 82763f89381fec398b1b3c33062f552c9adfcf30d37c6117d0bfeae771176f93 |
| HQC-KEM-192 | NIST-hqc-kem/reference/hqc-kem-192/hqc-192_kat.rsp | 3ca9ae7c1127016f4c85ceaf1aa485b42522ee05606567af9c9438e6eaf9035f |
| HQC-KEM-256 | NIST-hqc-kem/reference/hqc-kem-256/hqc-256_kat.rsp | 301614fce342b69df765998f2ab640e4a38b803f9fc3bab487691f37ce64b8c2 |

## Notes

- Report generation exits non-zero if any mandatory replay check fails.
- Full logs are available in `/Users/devpup/Desktop/Synergy/synergy-components/synq-language/aegis-pqsynq/pqsynq/artifacts`.
