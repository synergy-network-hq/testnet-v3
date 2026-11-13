# SynQ PQ-Gas Spec

Spec version: 0.1

PQ-Gas meters post-quantum verification and large-key/signature work separately
from ordinary execution gas.

## Launch Costs

| Operation | PQ-Gas |
|---|---:|
| parse ML-DSA-65 public key | 1,000 |
| parse ML-DSA-65 signature | 1,500 |
| SHA-256 canonical payload hash | 500 |
| derive SynQ address | 800 |
| verify ML-DSA-65 signature | 50,000 |
| validate deploy manifest/security policy | 5,000 |
| authorize contract deploy | 60,000 |
| authorize contract call | 55,000 |

## Failure Semantics

- Malformed keys/signatures are charged parse costs before failure.
- Wrong chain/domain/algorithm failures are charged policy validation costs.
- Signature verification failure is charged full verification cost.
- PQ-Gas exhaustion fails before executing contract bytecode.

## Limits

Initial local defaults:

- deploy PQ-Gas limit: `300_000`
- call PQ-Gas limit: `200_000`
- block PQ-Gas limit: pending node/runtime confirmation
