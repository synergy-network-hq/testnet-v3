# SynQ Receipt Spec

Spec version: 0.1

Receipts are canonical binary records for hashing and canonical JSON records for
RPC/debug rendering. The receipt hash is SHA-256 over canonical binary bytes.

## Fields

| Field | Type |
|---|---|
| `receipt_version` | `u16`, `1` |
| `chain_id` | `u64`, `1264` for testnet |
| `network_id` | string, `synergy-testnet` |
| `block_height` | `u64` |
| `tx_hash` | 32 bytes |
| `contract_address` | SynQ address bytes |
| `caller` | SynQ address bytes |
| `status` | `u8`: `0` success, `1` reverted, `2` failed |
| `gas_used` | `u64` |
| `pq_gas_used` | `u64` |
| `state_root_before` | 32 bytes |
| `state_root_after` | 32 bytes |
| `events` | ordered event records |
| `return_data` | length-prefixed bytes |
| `trap_code` | optional `u16` |
| `execution_trace_hash` | 32 bytes |
| `aegis_verification_summary` | canonical summary bytes |

## Event Record

| Size | Field |
|---:|---|
| 4 | event index |
| 32 | event topic hash |
| 4 | data length |
| N | event data |

## Rejection Rules

Receipts MUST NOT include machine-local logs, wall-clock timestamps, non-canonical
debug strings, unordered maps, or floating point values.
