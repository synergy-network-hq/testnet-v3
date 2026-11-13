# SynQ Chain 1264 Integration Spec

Spec version: 0.1

## Network Constants

| Field | Value |
|---|---|
| `chain_id` | `1264` |
| `network_name` | `synergy-testnet` |
| `address_hrp` | `tsynq` |
| `default_signature_algorithm` | `ML-DSA-65` |
| `aivm_version` | `0.1` |
| `synq_bytecode_version` | `0.1` |

## Deployment Transaction

Required fields:

- transaction type: `contract_deploy`
- chain ID
- network ID
- nonce
- expiration
- gas limit
- PQ-Gas limit
- bytecode hash
- manifest hash
- ABI hash
- deployer address
- constructor args hash
- domain `SYNQ_CONTRACT_DEPLOY_V1`
- algorithm `ML-DSA-65`
- signature

## Contract Call Transaction

Required fields:

- transaction type: `contract_call`
- chain ID
- network ID
- nonce
- expiration
- gas limit
- PQ-Gas limit
- contract address
- method selector
- encoded args hash
- caller address
- domain `SYNQ_CONTRACT_CALL_V1`
- algorithm `ML-DSA-65`
- signature

## RPC Requirements

Required before developer preview:

- `synq_estimateGas`
- `synq_estimatePqGas`
- `synq_deployContract`
- `synq_callContract`
- `synq_getContract`
- `synq_getReceipt`
- `synq_getEvents`
- `synq_verifyPayload`
- `synq_getSecurityPolicy`

`synq_compile` is allowed only if the node intentionally embeds the compiler.

## Current Local TESTNET Implementation Evidence

Inspected source:
`/Users/devpup/Desktop/Testnet-Beta/synergy-testnet`.

The current node source defines `SYNERGY_TESTNET_V3_CHAIN_ID = 1264` and
`SYNERGY_TESTNET_V3_NETWORK_ID = "synergy-testnet-v3"` in
`src/synergy_types.rs`. It exposes a `synergy_*` JSON-RPC surface today, not
the future `synq_*` surface above.

Current source-backed RPCs include:

- `synergy_chainId`
- `synergy_networkId`
- `synergy_getAegisStatus`
- `synergy_verifyAegisTransaction`
- `synergy_sendTransaction`
- `synergy_submitAegisTransaction`
- `synergy_submitAegisDagTransaction`
- `synergy_simulateTransaction`
- `synergy_estimateGas`
- `synergy_getReceipt`
- `synergy_getTransactionReceipt`
- `synergy_getBlockReceipts`

Current transaction admission uses `transaction::Transaction` and
`aegis_tx_tool::AegisTxSubmissionEnvelope` with Aegis PQVM verification. It is
not yet wired to the canonical `aegis-pqsynq` SynQ deploy/call adapter.

Current receipt fields are source-backed in `src/rpc/rpc_server.rs`:

- `synergy_getReceipt`: `transactionHash`, `transactionIndex`, `blockHash`,
  `blockNumber`, `from`, `to`, `cumulativeGasUsed`, `gasUsed`,
  `effectiveGasPrice`, `feeCharged`, `feeCollector`, `status`, `logs`, `chain`.
- `synergy_getTransactionReceipt`: `transactionHash`, `transactionIndex`,
  `blockHash`, `blockNumber`, `from`, `to`, `cumulativeGasUsed`, `gasUsed`,
  `effectiveGasPrice`, `status`, `logs`, `logsBloom`, `contractAddress`.

The AIVM runtime scaffolding exists under `src/aivm/runtime.rs`, but the
corresponding AIVM deployment/execution RPC handlers are currently commented out
as temporarily disabled in `src/rpc/rpc_server.rs`.

## Replay Requirement

The same block replayed on another validator MUST produce identical:

- state root
- receipt hash
- event list
- gas used
- PQ-Gas used
- trap/status
