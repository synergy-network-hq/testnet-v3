# SynQ Security Policy Spec

Spec version: 0.1

`aegis-pqsynq` is the only owner of SynQ-specific post-quantum policy.

## Launch Policy

| Field | Value |
|---|---|
| `chain_id` | `1264` |
| `network_id` | `synergy-testnet` |
| transaction signatures | `ML-DSA-65` |
| deployment signatures | `ML-DSA-65` |
| call signatures | `ML-DSA-65` |
| chain ID binding | required |
| domain separation | required |
| nonce | required |
| expiration | required |

## Algorithm IDs

| ID | Name | Launch use |
|---:|---|---|
| 0x0101 | `ML-DSA-44` | disallowed for tx/deploy/call |
| 0x0102 | `ML-DSA-65` | allowed |
| 0x0103 | `ML-DSA-87` | disallowed by default |
| 0x0201 | `FN-DSA-512` | disallowed by default |
| 0x0202 | `FN-DSA-1024` | disallowed by default |
| 0x0301 | `SLH-DSA-SHA2-128s` | disallowed |
| 0x0302 | `SLH-DSA-SHA2-192s` | disallowed |
| 0x0303 | `SLH-DSA-SHA2-256s` | disallowed |
| 0x0401 | `HQC-128` | KEM only |
| 0x0402 | `HQC-192` | KEM only |
| 0x0403 | `HQC-256` | KEM only |
| 0x0501 | `Classic-McEliece-348864` | disallowed |

## Error Families

| Code | Meaning |
|---|---|
| `AEGIS-ALG` | unsupported or disallowed algorithm |
| `AEGIS-CHAIN` | wrong chain ID |
| `AEGIS-NETWORK` | wrong network ID |
| `AEGIS-DOMAIN` | wrong domain tag |
| `AEGIS-NONCE` | nonce missing or replayed |
| `AEGIS-EXPIRY` | expired payload |
| `AEGIS-CANON` | non-canonical payload |
| `AEGIS-KEY` | malformed or oversized public key |
| `AEGIS-SIG` | malformed, oversized, or invalid signature |
| `AEGIS-ADDRESS` | signer/address mismatch |
