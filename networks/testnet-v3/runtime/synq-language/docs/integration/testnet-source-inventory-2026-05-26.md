# Local TESTNET Source Inventory

Status date: 2026-05-26

Source root inspected: `/Users/devpup/Desktop/Testnet-Beta`

This document records current local implementation evidence. It is not a claim
that the SynQ deploy/call flow is end-to-end complete.

## Repository Inventory

Git roots found under `/Users/devpup/Desktop/Testnet-Beta`:

- `synergy-testnet`
- `synergy-testnet/node-control-panel`
- `synq-language`
- `explorer-app`
- `synergy-prism`
- `synergy-horizon`
- `synergy-address-engine`
- `synergy-learn`
- `synergy-vault`
- `meme-launchpad`
- `synergy-quest`
- `synergy-forge`

The active node/runtime/RPC implementation inspected here is
`/Users/devpup/Desktop/Testnet-Beta/synergy-testnet`.

## Chain 1264 Constants

Source: `/Users/devpup/Desktop/Testnet-Beta/synergy-testnet/src/synergy_types.rs`

- `SYNERGY_TESTNET_V3_CHAIN_ID = 1264`
- `SYNERGY_TESTNET_V3_NETWORK_ID = "synergy-testnet-v3"`
- `ChainId::synergy_testnet_v3()` binds chain `1264`.
- `NetworkId::synergy_testnet_v3()` binds network `synergy-testnet-v3`.

Additional chain-1264 references exist in:

- `config/node.toml`
- `config/node_config.toml`
- `config/bootnode3.toml`
- `config/genesis.testnet.json`
- `config/operational-manifest.json`

## RPC Method Matrix

Source: `/Users/devpup/Desktop/Testnet-Beta/synergy-testnet/src/rpc/rpc_server.rs`

The live local implementation exposes a `synergy_*` JSON-RPC surface, not the
future `synq_*` surface from the SynQ chain-1264 spec.

Public read examples:

- `synergy_chainId`
- `synergy_networkId`
- `synergy_genesisHash`
- `synergy_protocolVersion`
- `synergy_syncing`
- `synergy_getHealth`
- `synergy_getReadiness`
- `synergy_getPeers`
- `synergy_getAegisStatus`
- `synergy_getAegisCapabilities`
- `synergy_verifyAegisTransaction`
- `synergy_getDagStatus`
- `synergy_getDagFrontier`
- `synergy_getDagGraph`
- `synergy_getDagDependencies`
- `synergy_getDagTxOrderRoot`
- `synergy_getTransactionReceipt`
- `synergy_getReceipt`
- `synergy_getBlockReceipts`
- `synergy_getLogs`
- `synergy_getCode`
- `synergy_getStorageAt`

Public client examples:

- `synergy_simulateTransaction`
- `synergy_sendTransaction`
- `synergy_submitAegisTransaction`
- `synergy_submitAegisTransactionBatch`
- `synergy_submitAegisDagTransaction`
- `synergy_submitAegisDagTransactionBatch`
- `synergy_call`
- `synergy_estimateGas`
- `synergy_registerSynID`

Authority-plane, non-public write, and operator methods are present and guarded
by `rpc_method_exposure`.

## Transaction Envelope Formats

Sources:

- `/Users/devpup/Desktop/Testnet-Beta/synergy-testnet/src/transaction.rs`
- `/Users/devpup/Desktop/Testnet-Beta/synergy-testnet/src/rpc/rpc_server.rs`
- `/Users/devpup/Desktop/Testnet-Beta/synergy-testnet/src/aegis_tx_tool.rs`
- `/Users/devpup/Desktop/Testnet-Beta/synergy-testnet/src/synergy_types.rs`

Legacy RPC transaction fields:

- `chain_id`
- `network_id`
- `sender`
- `receiver`
- `amount`
- `nonce`
- `signature`
- `signer_public_key`
- `timestamp`
- `gas_price`
- `gas_limit`
- `data`
- `signature_algorithm`

JSON-RPC compatibility envelope accepts aliases:

- `from`/`sender`
- `to`/`receiver`
- `value`/`amount`
- `signature`
- `signerPublicKey`/`signer_public_key`/`publicKey`
- `gasPrice`/`gas_price`/`maxFee`
- `gasLimit`/`gas_limit`
- `chainId`
- `networkId`/`network_id`
- `signatureAlgorithm`/`signature_algorithm`
- `data`

Aegis typed transaction path:

- `AegisTxSubmissionEnvelope`
- `synergy_types::Transaction`
- `AegisPqPublicKey`
- lifecycle record

Current TESTNET verification is implemented through `aegis-pqvm` in
`aegis_tx_tool.rs`. It is not wired to the standalone `aegis-pqsynq` adapter.

## Validation Flow

`synergy_sendTransaction` flow:

1. Normalize JSON into `transaction::Transaction`.
2. Reject wrong `chainId` against local chain `1264`.
3. Require `validate_for_admission()`.
4. Verify embedded PQC signature or legacy Aegis carrier.
5. Queue transaction in `TX_POOL`.
6. Broadcast through P2P if the P2P network is active.

`synergy_submitAegisTransaction` and `synergy_submitAegisDagTransaction` flow:

1. Deserialize `AegisTxSubmissionEnvelope`.
2. Convert through `legacy_transaction_from_aegis_envelope`.
3. Reject wrong chain.
4. Canonicalize `synergy_types::Transaction`.
5. Hash with Aegis PQVM domain `SYNERGY_TX_V1`.
6. Queue transaction in `TX_POOL`.
7. Return `tx_id`, `tx_hash`, `dag_node_id`, mempool/DAG statuses, and
   `aegis_pqvm_verification = "verified"`.

## Receipt Shapes

`synergy_getTransactionReceipt` returns EVM-style fields:

- `transactionHash`
- `transactionIndex`
- `blockHash`
- `blockNumber`
- `from`
- `to`
- `cumulativeGasUsed`
- `gasUsed`
- `effectiveGasPrice`
- `status`
- `logs`
- `logsBloom`
- `contractAddress`

`synergy_getReceipt` returns the local Synergy receipt shape:

- `transactionHash`
- `transactionIndex`
- `blockHash`
- `blockNumber`
- `from`
- `to`
- `cumulativeGasUsed`
- `gasUsed`
- `effectiveGasPrice`
- `feeCharged`
- `feeCollector`
- `status`
- `logs`
- `chain`

`chain` contains `name`, `chain_id`, `chain_id_hex`, `network_id`, and
`genesis_hash`.

`src/execution.rs` also defines deterministic execution receipts:

- `TransactionReceipt { tx_id, status, gas_used, error, state_root_after }`
- `ExecutionResult { receipts, state_root_after, receipt_root }`

## AIVM and SynQ Integration Points

`src/aivm/runtime.rs` defines:

- `AIVMExecutionContext`
- `AIVMExecutionResult`
- `AIVMContract`
- `AIVMRuntime::deploy_contract`
- `AIVMRuntime::execute_contract`
- `AIVMRuntime::process_transaction`

The RPC handlers for `synergy_deployAIVMContract`,
`synergy_executeAIVMContract`, and related AIVM methods are present in
`rpc_server.rs` but are commented out as `TEMPORARILY DISABLED`.

`src/transaction.rs` meters `data` values beginning with `deploy:` as
`SynqContractDeployment`; other non-empty `data` values are treated as
`SynqContractCall` for gas classification. This is not the same as a complete
SynQ bytecode deployment/call execution path.

`src/synq/compiler.rs` and `src/synq/interpreter.rs` are local simplified SynQ
components and do not prove the canonical SynQ compiler or `aegis-pqsynq`
deploy/call path.

## Current Conclusions

- NET-001 is source-backed for the local TESTNET chain ID and network ID.
- NET-002 is source-backed for existing Synergy transaction and Aegis envelope
  formats, but not for the future `synq_*` deploy/call envelope names.
- NET-003 through NET-006 remain partial for canonical SynQ because the real
  node path currently uses `aegis-pqvm` and `synergy_*` methods, while AIVM RPC
  deployment/execution is disabled.
- NET-007 has a source-backed method matrix; live request/response proof still
  requires running or querying an actual endpoint.
- ROSETTA-008, ROSETTA-009, ROSETTA-011, and ROSETTA-012 can use the real
  receipt shape above without adding live transaction submission.

## Model B Update - 2026-06-01

The earlier `NET-003` through `NET-006` partial conclusion was superseded by
the implemented node adapter:

- `/Users/devpup/Desktop/Testnet-Beta/synergy-testnet/src/synq_admission.rs`
  defines the `synq-admission-v1:` carrier, chain-1264-only network alias
  normalization, pqsynq deploy/call verification, structured error
  preservation, and verification summaries.
- `/Users/devpup/Desktop/Testnet-Beta/synergy-testnet/src/aegis_tx_tool.rs`
  invokes SynQ verification before the existing pqvm outer admission path.
- `/Users/devpup/Desktop/Testnet-Beta/synergy-testnet/src/execution.rs`
  carries internal `synq_verification`, `synq_error_code`, and
  `synq_error_message` receipt fields.
- `src/synq_admission.rs::tests::counter_artifacts_pass_pqsynq_then_existing_pqvm_admission`
  reads generated `contracts/Counter.*` artifacts, signs their actual hashes
  with pqsynq, and proves the existing pqvm outer admission path accepts the
  carrier.

Public RPC exposure of the SynQ receipt summary and enabled AIVM RPC handlers
remain pending. `NET-007` remains unchecked because no local listener
request/response capture was run in this pass.
