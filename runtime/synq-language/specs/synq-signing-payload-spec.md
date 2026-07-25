# SynQ Signing Payload Spec

Spec version: 0.1

Signing payloads use a custom binary layout. JSON MUST NOT be used for
consensus-critical signing bytes.

All integers are unsigned big-endian.

## Domain IDs

| ID | Tag |
|---:|---|
| 0x0001 | `SYNQ_TX_V1` |
| 0x0002 | `SYNQ_CONTRACT_DEPLOY_V1` |
| 0x0003 | `SYNQ_CONTRACT_CALL_V1` |
| 0x0004 | `SYNQ_VALIDATOR_MESSAGE_V1` |
| 0x0005 | `SYNQ_AIVM_RECEIPT_V1` |
| 0x0006 | `SYNQ_STATE_COMMITMENT_V1` |
| 0x0007 | `SYNQ_WALLET_AUTH_V1` |
| 0x0008 | `SYNQ_CROSS_CHAIN_MESSAGE_V1` |

## Payload Layout

| Size | Field |
|---:|---|
| 4 | magic ASCII `SQSP` |
| 2 | payload version, `0x0001` |
| 2 | domain ID |
| 8 | chain ID |
| 2 | network ID length |
| N | network ID UTF-8 bytes, e.g. `synergy-testnet` |
| 2 | protocol version |
| 2 | algorithm ID |
| 2 | signature purpose |
| 8 | nonce |
| 8 | not-before unix seconds, `0` if unused |
| 8 | expiration unix seconds |
| 2 | signer address length |
| N | canonical signer address bytes |
| 32 | payload hash |

`payload_hash` is SHA-256 over the artifact-specific payload body, not over this
signing wrapper.

## Deploy Payload Body Hash Input

The deploy body hash covers:

- bytecode hash
- manifest hash
- ABI hash
- deployer address
- constructor args hash

## Call Payload Body Hash Input

The call body hash covers:

- contract address
- method selector
- encoded args hash
- caller address

## Reuse Rules

A signature over one domain ID MUST NOT verify under another. A testnet payload
MUST NOT verify on mainnet or any other chain. A deploy payload MUST NOT verify
as a call payload.
