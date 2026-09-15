# STS RPC API

The STS read API exposes finalized Synergy Token System state for wallets, SDKs, Atlas, and operator checks. It is read-only. STS writes must be submitted as signed Synergy transactions carrying a `synergy-sts-v1:` payload.

All methods are testnet-only in this implementation and report chain ID `1264`. Native SNRG has `token_address: null`; the 41-zero placeholder is returned only as `compatibility_placeholder_address` for legacy string-only consumers.

## Common Response Shape

Successful item responses return:

```json
{
  "success": true,
  "chain": {
    "chain_id": 1264,
    "chain_id_hex": "0x4f0"
  },
  "item": {}
}
```

List responses return `items`. Missing items return `success: false` with an `error` string and the requested reference.

## Native And Fungible

- `sts_getNativeAsset` / `synergy_stsGetNativeAsset`
- `sts_getTokens` / `synergy_stsGetTokens`
- `sts_getToken` / `synergy_stsGetToken`
- `sts_getBalance` / `synergy_stsGetBalance`
- `sts_getBalances` / `synergy_stsGetBalances`
- `sts_getEvents` / `synergy_stsGetEvents`

Examples:

```bash
curl -fsS "$SYNERGY_RPC_URL" -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"sts_getNativeAsset","params":[]}'

curl -fsS "$SYNERGY_RPC_URL" -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":2,"method":"sts_getToken","params":["synb1..."]}'

curl -fsS "$SYNERGY_RPC_URL" -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":3,"method":"sts_getBalance","params":[{"owner":"synw1owner...","token":"synb1..."}]}'
```

Fungible token items include `token_id`, `token_address`, `class`, `creator`, `name`, `symbol`, `decimals`, `total_supply`, `max_supply`, `metadata_uri`, `metadata_hash`, `image_uri`, `image_hash`, `image_locked`, `flags`, `policies`, `paused`, and `verified`.

## NFTs

- `sts_getNftCollection` / `synergy_stsGetNftCollection`
- `sts_getNft` / `synergy_stsGetNft`
- `sts_getNftsByOwner` / `synergy_stsGetNftsByOwner`
- `sts_getNftsByCollection` / `synergy_stsGetNftsByCollection`
- Snake-case aliases: `sts_get_nft_collection`, `sts_get_nft`, `sts_get_nfts_by_owner`, `sts_get_nfts_by_collection`

Examples:

```bash
curl -fsS "$SYNERGY_RPC_URL" -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":4,"method":"sts_getNftCollection","params":["synn1..."]}'

curl -fsS "$SYNERGY_RPC_URL" -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":5,"method":"sts_getNft","params":[{"nft":"synn1..."}]}'

curl -fsS "$SYNERGY_RPC_URL" -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":6,"method":"sts_getNftsByOwner","params":[{"owner":"synw1owner..."}]}'
```

NFT collection items include `collection_id`, `collection_address`, `class`, `creator`, `name`, `symbol`, metadata and image fields, authorities, royalty fields, verification state, transfer policy, `requires_issuer_approval`, and `next_serial_number`.

NFT instance items include `nft_id`, `nft_address`, `collection_id`, `serial_number`, `owner`, metadata fields, `burned`, `frozen`, `transferable`, `requires_issuer_approval`, `expires_at`, `revoked`, `used`, authorities, and timestamps.

## Multi-Asset

- `sts_getMultiAssetCollection` / `synergy_stsGetMultiAssetCollection`
- `sts_getMultiAssetItem` / `synergy_stsGetMultiAssetItem`
- `sts_getMultiAssetBalance` / `synergy_stsGetMultiAssetBalance`
- `sts_getMultiAssetBalances` / `synergy_stsGetMultiAssetBalances`
- Snake-case aliases: `sts_get_multi_asset_collection`, `sts_get_multi_asset_item`, `sts_get_multi_asset_balance`, `sts_get_multi_asset_balances`

Examples:

```bash
curl -fsS "$SYNERGY_RPC_URL" -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":7,"method":"sts_getMultiAssetCollection","params":["synj..."]}'

curl -fsS "$SYNERGY_RPC_URL" -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":8,"method":"sts_getMultiAssetItem","params":[{"collection":"synj...","item_id":1}]}'

curl -fsS "$SYNERGY_RPC_URL" -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":9,"method":"sts_getMultiAssetBalances","params":[{"owner":"synw1owner...","collection":"synj..."}]}'
```

Multi-asset collection items include `collection_id`, `collection_address`, creator, metadata, image, authorities, and timestamps. Multi-asset item rows include `item_id`, `item_type`, `name`, `symbol`, `decimals`, `max_supply`, `total_supply`, authorities, and `transfer_policy`. Balance rows include owner, collection, item, amount, and timestamps.

## Credentials

- `sts_getCredentialSchema` / `synergy_stsGetCredentialSchema`
- `sts_getCredential` / `synergy_stsGetCredential`
- `sts_getCredentialsBySubject` / `synergy_stsGetCredentialsBySubject`
- `sts_verifyCredential` / `synergy_stsVerifyCredential`
- `sts_getCredentialStatus` / `synergy_stsGetCredentialStatus`
- Snake-case aliases: `sts_get_credential_schema`, `sts_get_credential`, `sts_get_credentials_by_subject`, `sts_verify_credential`, `sts_get_credential_status`

Examples:

```bash
curl -fsS "$SYNERGY_RPC_URL" -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":10,"method":"sts_getCredentialSchema","params":[{"issuer":"synw1issuer...","schema_id":"kyc-basic-v1"}]}'

curl -fsS "$SYNERGY_RPC_URL" -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":11,"method":"sts_getCredential","params":["synk..."]}'

curl -fsS "$SYNERGY_RPC_URL" -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":12,"method":"sts_verifyCredential","params":[{"issuer":"synw1issuer...","subject":"synw1subject...","schema_id":"kyc-basic-v1"}]}'
```

Credential records include `credential_id`, `issuer`, optional `subject`, `subject_commitment`, `schema_id`, `credential_hash`, `status`, `issued_at`, `expires_at`, `revoked_at`, `revocation_reason_hash`, `transferable`, and `updated_at`.

For privacy, consumers should prefer `subject_commitment` over raw subject addresses when displaying or indexing credential records.
