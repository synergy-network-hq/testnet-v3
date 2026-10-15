# Synergy Testnet v3 (chain 1266): RPC and API catalog

Updated 2026-10-15 UTC. This is a developer-facing inventory of the current public endpoints and the methods/routes registered in the running Testnet v3 stack. The chain identity is `synergy-testnet-v3`, chain ID `1266` (`0x4f2`). Check the chain identity in every integration response before acting on it.

## Public endpoints

| Endpoint | Interface | Current use |
| --- | --- | --- |
| `https://rpc.synergy-network.io/` | Native JSON-RPC 2.0 over HTTPS | Primary read and signed-transaction endpoint. Two Cloudflare-proxied gateway origins serve this hostname. |
| `https://testnet-core-rpc.synergy-network.io/` | JSON-RPC 2.0 over HTTPS | Public read-only Worker forwarding its allowlisted methods to the live native RPC gateway after verifying chain 1266. It rejects transaction writes. |
| `https://testnet-rpc.synergy-network.io/` | Native JSON-RPC 2.0 over HTTPS | Existing native RPC alias. |
| `wss://testnet-core-ws.synergy-network.io/` | Native WebSocket | Core subscription transport. Requires a WebSocket upgrade. |
| `wss://testnet-ws.synergy-network.io/` | Native WebSocket | Alias of the core WebSocket endpoint. |
| `https://testnet-evm-rpc.synergy-network.io/` | JSON-RPC 2.0 over HTTPS | Currently answers Synergy RPC. `eth_chainId` returned method-not-found during this audit; do not assume Ethereum JSON-RPC compatibility from the hostname. |
| `https://testnet-atlas-api.synergy-network.io/api/v1/` | REST/JSON | Atlas indexed network, block, transaction, account, validator, token, SynID, and contract data. |
| `https://testnet-atlas-api.synergy-network.io/api/v1/openapi.json` | OpenAPI JSON | Live Atlas route schema. Route registration does not imply anonymous access or active chain capability. |
| `https://forge.synergy-network.io/api/rpc` | HTTP POST JSON | Forge read-only RPC adapter with its own method allowlist and Atlas fallback. |
| `https://forge.synergy-network.io/api/network-snapshot` | HTTP GET JSON | Forge network summary assembled from RPC and Atlas. |
| `https://forge.synergy-network.io/api/faucet` | HTTP GET/POST JSON | Live Forge faucet view and request proxy. POST accepts `recipient` or `address` and verifies chain 1266 before forwarding. |
| `https://testnet-faucet.synergy-network.io/api/faucet/info` | HTTP GET JSON | Live v3 faucet identity, 10 SNRG amount, balance, and 24-hour cooldown. |
| `https://testnet-faucet.synergy-network.io/api/faucet/stats` | HTTP GET JSON | Faucet request statistics. |
| `https://testnet-faucet.synergy-network.io/api/faucet/request` | HTTP POST JSON | Live direct faucet request (`recipient` or `address`). Repeat requests for the same wallet are subject to the 24-hour cooldown. |
| `https://forge.synergy-network.io/api/wallet-pairing/healthz` | HTTP GET JSON | Synergy Wallet pairing relay health. |
| `https://forge.synergy-network.io/api/wallet-pairing/sessions` | HTTP POST JSON | Start a wallet pairing session; related session/request endpoints are listed in the Atlas OpenAPI inventory below. |

The previous observer host now serves as a second RPC Gateway behind the existing `rpc`, `testnet-core-rpc`, and `testnet-core-ws` DNS names. Their aliases retain their existing URLs. Both origins tunnel to the same live chain; the second gateway is not a separate validator or independent state source. The `testnet-core-rpc` Worker routes allowed reads to the native `rpc` hostname; the `testnet-rpc` alias reaches the native gateway directly.

## Native JSON-RPC request

Send `POST` with `Content-Type: application/json` to the endpoint. For example:

```sh
curl -fsS https://rpc.synergy-network.io/ \
  -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"synergy_networkId","params":[]}'
```

The response includes chain context and a method-specific `result` or `error`. A successful HTTP status does not guarantee that the JSON-RPC call succeeded; inspect `error`. Useful current reads include `synergy_networkId`, `synergy_chainId`, `synergy_getFinalizedHead`, `synergy_getBlockNumber`, `synergy_getBlockByNumber`, `synergy_getAccountNonce`, and `synergy_getTokenBalance` (address and token symbol). The native signed-transfer submission method `synergy_submitAegisTransaction` accepts one Aegis envelope in `params[0]`; a live faucet payout finalized through it. Plain `synergy_sendTransaction` and DAG/batch submission methods remain gated. Do not use the read-only core facade for writes.

**Receipt compatibility note:** the current authority returns a finalized `synergy_getTransactionReceipt` payload inside JSON-RPC `error.data` because its generic wrapper mistakes an empty execution-error field for an RPC error. The faucet accepts only a hash-matched finalized receipt from that field. Other clients should use this field only after checking the chain context, transaction hash, finalized flag, and status. A runtime fix is prepared; the public RPC response is not yet in its intended `result` shape.

The following inventory distinguishes **registered exposure** from a proven active feature. Some registered methods require parameters, an initialized subsystem, an authorization context, or data that the current deployment does not have. Readiness, finality, and receipts from the live network remain the authority for a specific call. No method in this catalog implies that PoSy or ETDAG is active on this chain.

## Public-read RPC method inventory

These names are classified as public-read in the runtime exposure policy. Feature-specific methods may return a structured unavailable/error response on the current deployment.

### Network, status, Aegis, other (40)

`synergy_blockNumber`, `synergy_chainId`, `synergy_genesisHash`, `synergy_getAccount`, `synergy_getAegisCapabilities`, `synergy_getAegisKeyStatus`, `synergy_getAegisStatus`, `synergy_getBurnLedger`, `synergy_getCanonicalLock`, `synergy_getChainId`, `synergy_getCommittedQC`, `synergy_getDelegators`, `synergy_getDeterminismDigest`, `synergy_getDivergenceStatus`, `synergy_getFinalizedHead`, `synergy_getHealth`, `synergy_getNetworkStats`, `synergy_getNodeStatus`, `synergy_getPeerInfo`, `synergy_getPeers`, `synergy_getProtocolConfig`, `synergy_getReadiness`, `synergy_getRejoinEligibility`, `synergy_getShadowStatus`, `synergy_getStakingAPY`, `synergy_getStakingInfo`, `synergy_getSyncStatus`, `synergy_getSynergyScoreBreakdown`, `synergy_getTransferHistory`, `synergy_getTreasuryRecovery`, `synergy_getUnstakingPeriod`, `synergy_networkId`, `synergy_nodeInfo`, `synergy_protocolVersion`, `synergy_status`, `synergy_subscribe`, `synergy_syncing`, `synergy_unsubscribe`, `synergy_verifyAegisQC`, `synergy_verifyAegisSignature`

### Blocks, transactions, logs, DAG diagnostics (40)

`synergy_getAccountAuthNonce`, `synergy_getAccountNonce`, `synergy_getBlockByHash`, `synergy_getBlockByNumber`, `synergy_getBlockNumber`, `synergy_getBlockRange`, `synergy_getBlockReceipts`, `synergy_getBlockTransactionCount`, `synergy_getBlockValidationStatus`, `synergy_getCode`, `synergy_getDagDependencies`, `synergy_getDagFrontier`, `synergy_getDagGraph`, `synergy_getDagNode`, `synergy_getDagStatus`, `synergy_getDagTopology`, `synergy_getDagTransactionStatus`, `synergy_getDagTxOrderRoot`, `synergy_getDagVertex`, `synergy_getDagVertices`, `synergy_getEtdagAdmissionPackage`, `synergy_getEtdagStatus`, `synergy_getLatestBlock`, `synergy_getLogs`, `synergy_getNonce`, `synergy_getPendingTransaction`, `synergy_getPendingTransactions`, `synergy_getReceipt`, `synergy_getStorageAt`, `synergy_getTransaction`, `synergy_getTransactionByBlockHashAndIndex`, `synergy_getTransactionByBlockNumberAndIndex`, `synergy_getTransactionByHash`, `synergy_getTransactionCount`, `synergy_getTransactionPool`, `synergy_getTransactionReceipt`, `synergy_getTransactionStatus`, `synergy_getTransactionsInBlock`, `synergy_getValidatorPendingRewards`, `synergy_verifyAegisTransaction`

### Assets, STS, balances, fees (69)

`sts_getBalance`, `sts_getBalances`, `sts_getCredential`, `sts_getCredentialSchema`, `sts_getCredentialStatus`, `sts_getCredentialsBySubject`, `sts_getEvents`, `sts_getMultiAssetBalance`, `sts_getMultiAssetBalances`, `sts_getMultiAssetCollection`, `sts_getMultiAssetItem`, `sts_getNativeAsset`, `sts_getNft`, `sts_getNftCollection`, `sts_getNftsByCollection`, `sts_getNftsByOwner`, `sts_getToken`, `sts_getTokens`, `sts_get_credential`, `sts_get_credential_schema`, `sts_get_credential_status`, `sts_get_credentials_by_subject`, `sts_get_multi_asset_balance`, `sts_get_multi_asset_balances`, `sts_get_multi_asset_collection`, `sts_get_multi_asset_item`, `sts_get_nft`, `sts_get_nft_collection`, `sts_get_nfts_by_collection`, `sts_get_nfts_by_owner`, `sts_verifyCredential`, `sts_verify_credential`, `synergy_estimateFee`, `synergy_gasPrice`, `synergy_getAllBalances`, `synergy_getBalance`, `synergy_getEpochFeeDistribution`, `synergy_getFeeCollector`, `synergy_getFeeCollectorBalance`, `synergy_getFeeCollectorDeposits`, `synergy_getFeeHistory`, `synergy_getFeeSchedule`, `synergy_getStakedBalance`, `synergy_getTokenBalance`, `synergy_getTokenStats`, `synergy_getTokens`, `synergy_getTransactionFees`, `synergy_listSnapshots`, `synergy_maxFeePerGas`, `synergy_maxPriorityFeePerGas`, `synergy_stsGetBalance`, `synergy_stsGetBalances`, `synergy_stsGetCredential`, `synergy_stsGetCredentialSchema`, `synergy_stsGetCredentialStatus`, `synergy_stsGetCredentialsBySubject`, `synergy_stsGetEvents`, `synergy_stsGetMultiAssetBalance`, `synergy_stsGetMultiAssetBalances`, `synergy_stsGetMultiAssetCollection`, `synergy_stsGetMultiAssetItem`, `synergy_stsGetNativeAsset`, `synergy_stsGetNft`, `synergy_stsGetNftCollection`, `synergy_stsGetNftsByCollection`, `synergy_stsGetNftsByOwner`, `synergy_stsGetToken`, `synergy_stsGetTokens`, `synergy_stsVerifyCredential`

### Validators, finality, operations, cross-chain (42)

`synergy_checkRewardInvariants`, `synergy_diagnoseConsensusStall`, `synergy_diagnoseVoteLocks`, `synergy_getActiveApprovals`, `synergy_getApprovalHistory`, `synergy_getAttestations`, `synergy_getClusterInfo`, `synergy_getClusterRewardEscrow`, `synergy_getClusterRewards`, `synergy_getClusterStatus`, `synergy_getConsensusForkStatus`, `synergy_getConsensusSafetyHalt`, `synergy_getDelegatedStakes`, `synergy_getEpochClusterAssignments`, `synergy_getEpochRewardAudit`, `synergy_getEventAttestation`, `synergy_getQuarantineStatus`, `synergy_getReconciliationPlan`, `synergy_getRelayerHealth`, `synergy_getRelayerSet`, `synergy_getRewardsProjection`, `synergy_getSelfHealStatus`, `synergy_getSnapshotCatalog`, `synergy_getStakingRewards`, `synergy_getSxcpStatus`, `synergy_getTopValidators`, `synergy_getValidator`, `synergy_getValidatorActivity`, `synergy_getValidatorByCluster`, `synergy_getValidatorClusterHistory`, `synergy_getValidatorPerformance`, `synergy_getValidatorQueue`, `synergy_getValidatorRewardStatus`, `synergy_getValidatorRewards`, `synergy_getValidatorSet`, `synergy_getValidatorSetSnapshot`, `synergy_getValidatorSlashingHistory`, `synergy_getValidatorStats`, `synergy_getValidators`, `synergy_verifyAegisSnapshotCatalog`, `synergy_verifyAegisSnapshotManifest`, `synergy_verifySnapshot`

### SynID (3)

`synergy_getAddressBook`, `synergy_resolveSynID`, `synergy_reverseResolveSynID`

## Public-client RPC method inventory

These methods are classified for public-client exposure, but classification alone does not mean that the current deployment admits the operation. In particular, only the signed Aegis submission path is being enabled for native chain transfers; the plaintext and DAG/batch variants stay gated.

`synergy_call`, `synergy_createApproval`, `synergy_estimateGas`, `synergy_registerSynID`, `synergy_revokeAllApprovals`, `synergy_sendTransaction`, `synergy_simulateTransaction`, `synergy_submitAegisDagTransaction`, `synergy_submitAegisDagTransactionBatch`, `synergy_submitAegisTransaction`, `synergy_submitAegisTransactionBatch`, `synergy_submitEncryptedTransaction`, `synergy_submitEtdagTransaction`

## Atlas REST route inventory

The following registered routes came from the live `/api/v1/openapi.json` schema on 2026-10-14. Paths are relative to `https://testnet-atlas-api.synergy-network.io`. Some write, admin, profile, assertion, and pairing routes require authentication or signed requests; this list is an interface catalog, not permission to call them anonymously.

- `GET /healthz`
- `GET /readyz`
- `GET /version`
- `POST /v1/admin/reindex-from-genesis`
- `GET /api/v1/wallet-pairing/healthz`
- `GET /api/v1/wallet-pairing`
- `POST /api/v1/wallet-pairing/sessions`
- `GET /api/v1/wallet-pairing/sessions/{sessionId}`
- `POST /api/v1/wallet-pairing/sessions/{sessionId}/reject`
- `POST /api/v1/wallet-pairing/sessions/{sessionId}/approve`
- `POST /api/v1/wallet/assertions/challenge`
- `POST /api/v1/wallet/assertions`
- `GET, DELETE /api/v1/wallet/assertions/session`
- `GET, PUT /api/v1/entities/{entityType}/{entityId}/tags`
- `POST /api/v1/entities/{entityType}/{entityId}/tags/session`
- `POST /api/v1/admin/reindex-from-genesis`
- `GET /api/v1/network/summary`
- `GET /api/v1/network/accounts`
- `GET /api/v1/clusters`
- `GET /api/v1/clusters/{id}/history`
- `GET /api/v1/clusters/{id}`
- `GET /api/v1/epochs`
- `GET /api/v1/epochs/{number}/history`
- `GET /api/v1/epochs/{number}`
- `GET /api/v1/dag/status`
- `GET /api/v1/dag/frontier`
- `GET /api/v1/dag/vertices`
- `GET /api/v1/dag/vertices/{vertexId}`
- `GET /api/v1/dag/topology`
- `GET /api/v1/blocks`
- `GET /api/v1/blocks/{id}`
- `GET /api/v1/txs`
- `GET /api/v1/txs/{hash}`
- `GET /api/v1/synids/{synId}`
- `GET /api/v1/synids`
- `GET /api/v1/address/{address}`
- `GET /api/v1/validators`
- `GET, PUT /api/v1/validators/{address}/profile`
- `POST /api/v1/validators/{address}/control-panel-profile`
- `GET /api/v1/validators/{address}/synergy-score`
- `GET /api/v1/validators/{address}/score-history`
- `GET /api/v1/validators/{address}/history`
- `GET /api/v1/validators/{address}/events`
- `GET /api/v1/epochs/{epoch}/validator-scorecards`
- `GET /api/v1/validators/{address}/rewards`
- `GET /api/v1/validators/{address}/reward-settlements`
- `GET /api/v1/validators/{address}`
- `GET /api/v1/token/SNRG/holders`
- `GET /api/v1/tokens`
- `GET /api/v1/tokens/{id}/holders`
- `GET /api/v1/tokens/{id}/transfers`
- `GET /api/v1/tokens/{id}/history`
- `GET /api/v1/tokens/{id}/transactions`
- `POST /api/v1/tokens/{tokenAddress}/image`
- `GET /api/v1/wallets/{address}/token-balances`
- `GET /api/v1/openapi.json`
- `GET /api/v1/status/components`
- `GET /api/v1/status/incidents`
- `GET /api/v1/search`
- `GET /api/v1/metrics/{metric}`
- `GET /api/v1/metrics/contracts/{address}`
- `GET /api/v1/accounts/{address}/balance-history`
- `GET /api/v1/contracts`
- `GET /api/v1/contracts/{address}/activity`
- `GET /api/v1/contracts/{address}/capabilities`
- `POST /api/v1/contracts/{address}/call-data`
- `POST /api/v1/contracts/{address}/read`
- `POST /api/v1/contracts/{address}/write`
- `GET /api/v1/contracts/{address}`

## Sources and verification

- Runtime exposure policy and handler: `runtime/src/rpc/rpc_server.rs`.
- Forge adapter and faucet gates: `14-Forge/forge-v3/app/api/rpc/route.ts`, `app/api/faucet/route.ts`, `app/api/network-snapshot/route.ts` in the Forge repository.
- Atlas route catalog: [live OpenAPI schema](https://testnet-atlas-api.synergy-network.io/api/v1/openapi.json).
- Live checks on 2026-10-14/15 UTC: native `rpc`, read-only `testnet-core-rpc`, and native `testnet-rpc` all returned chain 1266 and advancing finalized heads (3,255,810–3,255,812 after the Worker update); a write to the core read facade returned JSON-RPC `-32601`. Both gateway origins returned HTTP 200 on observed proxied requests. Atlas `/api/v1/network/summary` returned chain 1266 but its indexed head lagged live finality during this audit; use the native RPC for current chain state. `eth_chainId` on the EVM-named host returned JSON-RPC method-not-found. A 10 SNRG faucet payout finalized as transaction `syntxn-441013965ff89449f66d0d62b0f3efacb42d595f23ff13ddddd74efa7fe3241a`; direct and Forge faucet GET returned chain 1266, and repeat POST returned HTTP 429 cooldown on both routes.
