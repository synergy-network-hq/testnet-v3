# STS CLI Guide

`synergy-sts` is the dedicated command-line tool for building, signing, and submitting Synergy Token System transactions on testnet.

Current scope in this branch:

- Native SNRG identity inspection.
- Fungible token payloads for `synb1`, `synb2`, and `synb3`.
- NFT collection and instance payloads for `synn1` and `synn2`.
- Multi-asset collection, item, balance, and batch payloads for `synj`.
- Identity and credential payloads for `synk`.
- Payload decode and gas/fee estimation.
- Metadata-file hashing with SHA3-256.
- Token image URI/hash attachment at creation and one-time post-create image setting.
- On-chain submission through `synergy_sendTransaction` using a Synergy wallet key file.
- Native SNRG gas/transaction fee payment from the submitting wallet.

By default the CLI emits deterministic STS payload artifacts for review. Add `--submit --wallet <wallet.dec.json>` to sign the Synergy carrier transaction, pay gas in native SNRG, and submit the payload through the public RPC transaction path.

## Install From GitHub Releases

The supported user install path is the dedicated CLI release repository:

[synergy-network-hq/synergy-sts-cli-releases](https://github.com/synergy-network-hq/synergy-sts-cli-releases)

macOS and Linux users can install the latest released CLI with:

```bash
curl -fsSL https://github.com/synergy-network-hq/synergy-sts-cli-releases/releases/latest/download/install-synergy-sts.sh | bash
```

The installer detects the local platform and downloads the matching binary:

- `synergy-sts-linux-amd64`
- `synergy-sts-linux-arm64`
- `synergy-sts-macos-amd64`
- `synergy-sts-macos-arm64`

By default the binary is installed to:

```text
$HOME/.local/bin/synergy-sts
```

Install a specific release tag:

```bash
curl -fsSL https://github.com/synergy-network-hq/synergy-sts-cli-releases/releases/latest/download/install-synergy-sts.sh \
  | bash -s -- --version synergy-sts-v15.0.14
```

Install to a different directory:

```bash
curl -fsSL https://github.com/synergy-network-hq/synergy-sts-cli-releases/releases/latest/download/install-synergy-sts.sh \
  | bash -s -- --install-dir /usr/local/bin
```

Add the install directory to your shell profile when needed:

```bash
curl -fsSL https://github.com/synergy-network-hq/synergy-sts-cli-releases/releases/latest/download/install-synergy-sts.sh \
  | bash -s -- --add-to-path
```

Verify installation:

```bash
synergy-sts version
synergy-sts native-info
```

The installer verifies release `.sha256` checksums by default. Advanced users can install a pinned binary URL with an expected hash:

```bash
./install-synergy-sts.sh \
  --url https://github.com/synergy-network-hq/synergy-sts-cli-releases/releases/download/synergy-sts-v15.0.14/synergy-sts-linux-amd64 \
  --sha256 <expected_sha256>
```

Release repository assets:

- `install-synergy-sts.sh`: portable macOS/Linux installer.
- `latest.json`: release metadata and asset names for automation.
- `synergy-sts-<os>-<arch>`: standalone executable.
- `synergy-sts-<os>-<arch>.sha256`: checksum used by the installer.

## Install From Source

From the testnet runtime repository:

```bash
cd /Volumes/xcode/Synergy-Network-Projects/network-components/01-Testnet/synergy-testnet
cargo build -p synergy-testnet --bin synergy-sts --release
```

Install the binary somewhere on your `PATH`:

```bash
mkdir -p "$HOME/.local/bin"
cp target/release/synergy-sts "$HOME/.local/bin/synergy-sts"
chmod 755 "$HOME/.local/bin/synergy-sts"
```

Verify installation:

```bash
synergy-sts version
synergy-sts native-info
```

For local development without installing:

```bash
cargo run -p synergy-testnet --bin synergy-sts -- native-info
```

## Native SNRG Address Rule

Native SNRG is the gas and fee asset. It is not an STS object and has no canonical token address.

`synergy-sts native-info` returns:

```json
{
  "symbol": "SNRG",
  "token_address": null,
  "compatibility_placeholder_address": "00000000000000000000000000000000000000000"
}
```

The 41-zero value is only for string-only compatibility surfaces. It is not a token contract, not an STS object ID, and not a signable address.

Every non-native STS token has a deterministic Bech32m token address. For fungible tokens, `expected_token_address` equals `expected_token_id` and starts with the class prefix:

- `synb1` for B1 basic fungible tokens.
- `synb2` for B2 managed fungible tokens.
- `synb3` for B3 policy fungible tokens.

## Payload Lifecycle

STS write commands produce a review artifact:

- `payload_hex`: hex-encoded STS payload bytes with the `synergy-sts-v1:` prefix.
- `payload`: the decoded payload JSON.
- `estimated_gas`: STS operation gas estimate.
- `estimated_fee_nwei`: `estimated_gas * gas_price_nwei`.
- `expected_token_id`: creation-only deterministic token ID.
- `expected_token_address`: creation-only non-native token address.

Recommended workflow:

1. Build a payload with `synergy-sts`.
2. Save the artifact with `--out`.
3. Review or decode it with `synergy-sts decode`.
4. Estimate gas with `synergy-sts estimate`.
5. Submit directly with `synergy-sts submit --file <artifact> --wallet <wallet.dec.json>`, or rebuild the command with `--submit`.
6. Query RPC/Atlas after finality.

## On-Chain Submit With A Synergy Wallet

`synergy-sts` can submit any STS payload on chain without a helper script. The CLI performs these steps:

1. Loads the submitting Synergy wallet from `--wallet`.
2. Loads the wallet public key from the same JSON, from `--wallet-public`, or from a sibling `.pub.json` file.
3. Verifies the public key derives the wallet address.
4. Reads the current account nonce, gas price, native SNRG balance, and native SNRG identity from the RPC endpoint.
5. Builds a Synergy transaction whose `data` field is the STS `payload_hex`.
6. Signs the transaction with FN-DSA and embeds the signer public key.
7. Submits it with `synergy_sendTransaction`.

Wallet file requirements:

- `--wallet` must point to decrypted Synergy wallet JSON containing `address` and `private_key`.
- The public key can be in the same file as `public_key`, in `--wallet-public <wallet.pub.json>`, or in a sibling file such as `faucet.pub.json` next to `faucet.dec.json`.
- The CLI refuses to submit when the wallet public key does not derive the wallet address.
- The CLI refuses to submit when `--from` does not match the wallet address.

Default RPC:

```bash
https://testnet-core-rpc.synergy-network.io
```

Override it with:

```bash
--rpc-url https://testnet-core-rpc.synergy-network.io
```

You can also set:

```bash
export SYNERGY_RPC_URL=https://testnet-core-rpc.synergy-network.io
export SYNERGY_WALLET_FILE=/path/to/wallet.dec.json
```

### Direct Submit From A Create Command

When `--submit` is present, `--from` and `--creator-nonce` can be omitted. The CLI derives `--from` from the wallet and defaults `--creator-nonce` to the creation timestamp.

```bash
synergy-sts token create \
  --network testnet \
  --class b1 \
  --name "CLI Gold" \
  --symbol CLIG \
  --decimals 9 \
  --initial-supply 1000000000 \
  --max-supply 1000000000 \
  --submit \
  --wallet ./wallet.dec.json \
  --out ./clig-create-submit.json
```

The response includes the payload review fields and a `submission` object:

```json
{
  "expected_token_address": "synb1...",
  "payload_hex": "73796e657267792d7374732d76313a...",
  "sender": "synw1...",
  "submission": {
    "submitted": true,
    "tx_hash": "syntxn-...",
    "mempool_status": "queued",
    "nonce": 21,
    "gas_price_nwei": 40,
    "gas_limit": 150000,
    "carrier_amount_nwei": 1,
    "fee_cap_nwei": "6000001"
  }
}
```

### Submit A Saved Artifact

Build and review first:

```bash
synergy-sts token create \
  --network testnet \
  --class b1 \
  --name "Review First" \
  --symbol RVW \
  --decimals 9 \
  --initial-supply 1000000000 \
  --max-supply 1000000000 \
  --from synw1creator... \
  --creator-nonce 42 \
  --out ./rvw-create.json
```

Submit later:

```bash
synergy-sts submit \
  --file ./rvw-create.json \
  --wallet ./wallet.dec.json \
  --out ./rvw-submit-result.json
```

### Gas And Carrier Amount

Fees are paid in native SNRG from the submitting wallet. The CLI estimates STS operation gas locally and reads the current RPC gas price when `--gas-price-nwei` is omitted.

Submit options:

```bash
--gas-price-nwei <u64>       Override RPC gas price.
--gas-limit <u64>            Override estimated gas plus safety buffer.
--nonce <u64>                Override RPC account nonce.
--carrier-amount-nwei <u64>  Native SNRG carrier amount.
```

The public RPC path currently accepts a one-nwei self-carrier by default. That has no practical balance-transfer effect beyond the SNRG fee charge because the receiver defaults to the sender. Protocol builds with zero-value STS carrier admission can use:

```bash
--carrier-amount-nwei 0
```

### Submit Mint, Transfer, Burn, And Images

Every payload-producing command accepts `--submit --wallet`.

```bash
synergy-sts token mint \
  --network testnet \
  --token synb1... \
  --to synw1holder... \
  --amount 250000000 \
  --submit \
  --wallet ./mint-authority.dec.json

synergy-sts token transfer \
  --network testnet \
  --token synb1... \
  --to synw1recipient... \
  --amount 100000000 \
  --submit \
  --wallet ./holder.dec.json

synergy-sts token set-image \
  --network testnet \
  --token synb1... \
  --image-uri https://example.com/token.png \
  --image-file ./token.png \
  --submit \
  --wallet ./creator.dec.json
```

## Read-Only STS RPC

The runtime exposes read-only STS RPC methods for wallets, SDKs, and explorer checks. These methods rebuild STS view state by replaying committed `synergy-sts-v1:` payloads from `data/chain.json`; if the local hot chain is compacted and no longer starts at genesis, the methods return `success: false` instead of pretending the STS registry is empty.

Supported method names:

- `sts_getNativeAsset` / `synergy_stsGetNativeAsset`
- `sts_getTokens` / `synergy_stsGetTokens`
- `sts_getToken` / `synergy_stsGetToken`
- `sts_getBalance` / `synergy_stsGetBalance`
- `sts_getBalances` / `synergy_stsGetBalances`
- `sts_getNftCollection` / `synergy_stsGetNftCollection`
- `sts_getNft` / `synergy_stsGetNft`
- `sts_getNftsByOwner` / `synergy_stsGetNftsByOwner`
- `sts_getNftsByCollection` / `synergy_stsGetNftsByCollection`
- `sts_getMultiAssetCollection` / `synergy_stsGetMultiAssetCollection`
- `sts_getMultiAssetItem` / `synergy_stsGetMultiAssetItem`
- `sts_getMultiAssetBalance` / `synergy_stsGetMultiAssetBalance`
- `sts_getMultiAssetBalances` / `synergy_stsGetMultiAssetBalances`
- `sts_getCredentialSchema` / `synergy_stsGetCredentialSchema`
- `sts_getCredential` / `synergy_stsGetCredential`
- `sts_getCredentialsBySubject` / `synergy_stsGetCredentialsBySubject`
- `sts_verifyCredential` / `synergy_stsVerifyCredential`
- `sts_getCredentialStatus` / `synergy_stsGetCredentialStatus`
- `sts_getEvents` / `synergy_stsGetEvents`

Examples:

```bash
curl -fsS "$SYNERGY_RPC_URL" \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"sts_getNativeAsset","params":[]}'

curl -fsS "$SYNERGY_RPC_URL" \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":2,"method":"sts_getTokens","params":[]}'

curl -fsS "$SYNERGY_RPC_URL" \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":3,"method":"sts_getToken","params":["synb1..."]}'

curl -fsS "$SYNERGY_RPC_URL" \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":4,"method":"sts_getBalance","params":["synw1owner...","synb1..."]}'

curl -fsS "$SYNERGY_RPC_URL" \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":5,"method":"sts_getNft","params":["synn1..."]}'

curl -fsS "$SYNERGY_RPC_URL" \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":6,"method":"sts_getMultiAssetBalances","params":[{"owner":"synw1owner...","collection":"synj..."}]}'

curl -fsS "$SYNERGY_RPC_URL" \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":7,"method":"sts_getCredentialStatus","params":["synk..."]}'
```

`sts_getNativeAsset` always returns native SNRG with `token_address: null` and the 41-zero value only as `compatibility_placeholder_address`. STS fungible tokens return `asset_kind: "sts"` and a non-empty `synb*` `token_address`.

The snake-case aliases such as `sts_get_nft` and `sts_get_multi_asset_balance` are also accepted for new NFT, multi-asset, and credential reads.

## Output Modes

All payload-producing commands support:

```bash
--output json
--output compact-json
--output payload-hex
--output payload-json
--out ./artifact.json
```

Examples:

```bash
synergy-sts token create ... --output json --out ./tgld-create.json
synergy-sts token transfer ... --output payload-hex --out ./transfer.payload.hex
```

If `--out` is provided, the CLI writes the selected output to the file and also prints it to stdout.

## Decode And Estimate

Decode an artifact JSON file:

```bash
synergy-sts decode --file ./tgld-create.json
```

Decode raw payload hex:

```bash
synergy-sts decode --payload-hex "$(cat ./transfer.payload.hex)"
```

Estimate gas and fee with the default 40 nWei gas price:

```bash
synergy-sts estimate --file ./tgld-create.json
```

Estimate with an explicit gas price:

```bash
synergy-sts estimate --file ./tgld-create.json --gas-price-nwei 50
```

## Metadata Files

The CLI can hash a metadata file:

```bash
synergy-sts token create \
  --network testnet \
  --class b1 \
  --name "Testnet Gold" \
  --symbol TGLD \
  --decimals 9 \
  --initial-supply 1000000000000000 \
  --max-supply 1000000000000000 \
  --metadata-uri ipfs://bafy.../metadata.json \
  --metadata-file ./metadata.json \
  --no-mint-authority \
  --from synw1... \
  --creator-nonce 1
```

Rules:

- Hash algorithm is SHA3-256.
- The emitted hash is lowercase hex without `0x`.
- If both `--metadata-file` and `--metadata-hash` are supplied, they must match.
- A metadata URI requires a metadata hash.
- Amounts are integer base units. The CLI does not accept floating-point token amounts.
- Metadata is immutable in the current protocol slice. `--metadata-mutable` and `--can-update-metadata` fail closed.

## Exhaustive Token Metadata Template

Store token metadata on IPFS, Arweave, or HTTPS and pass its SHA3-256 hash with `--metadata-hash` or `--metadata-file`. Atlas treats this metadata as descriptive; protocol identity and supply rules still come from the signed STS payload.

```json
{
  "schema": "synergy.sts.token.metadata.v1",
  "chain_id": 1264,
  "network": "testnet",
  "standard": "sts-fungible-v1",
  "asset": {
    "class": "b1",
    "token_address": "synb1...",
    "name": "Testnet Gold",
    "symbol": "TGLD",
    "decimals": 9,
    "description": "Short public description of the token purpose.",
    "category": "utility",
    "tags": ["testnet", "utility"],
    "image": "ipfs://bafy.../logo.png",
    "image_hash": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
    "external_url": "https://example.com/token"
  },
  "supply": {
    "initial_supply_base_units": "1000000000000000",
    "max_supply_base_units": "1000000000000000",
    "mint_authority": null,
    "burn_model": "holder_burn"
  },
  "authorities": {
    "creator": "synw1...",
    "metadata_authority": null,
    "freeze_authority": null,
    "compliance_authority": null
  },
  "security": {
    "native": false,
    "gas_asset": false,
    "immutable_metadata": true,
    "image_set_once": true,
    "impersonation_review": {
      "not_snrg": true,
      "not_synergy_official": true,
      "official_issuer_statement": ""
    }
  },
  "links": {
    "website": "https://example.com",
    "docs": "https://example.com/docs",
    "support": "https://example.com/support",
    "repository": "https://github.com/example/project"
  },
  "socials": {
    "x": "",
    "discord": "",
    "telegram": "",
    "matrix": ""
  },
  "compliance": {
    "issuer_name": "",
    "issuer_jurisdiction": "",
    "terms_url": "",
    "risk_disclosure_url": ""
  },
  "checksums": {
    "metadata_sha3_256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "image_sha3_256": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
  }
}
```

Required protocol fields are `class`, `name`, `symbol`, `decimals`, `initial_supply`, `creator`, `creator_nonce`, and `created_at`. Recommended metadata fields are all fields shown above so Atlas, wallets, and future SDKs can present the token consistently.

NFT collection metadata uses the same top-level structure with `"standard": "sts-nft-collection-v1"` and an `asset.class` of `nf1` or `nf2`. NFT instance metadata should include an `attributes` array, optional `animation_url`, and any off-chain media checksums:

```json
{
  "schema": "synergy.sts.nft.metadata.v1",
  "chain_id": 1264,
  "network": "testnet",
  "standard": "sts-nft-instance-v1",
  "collection": {
    "collection_id": "synn1...",
    "collection_address": "synn1...",
    "name": "Synergy Badges",
    "symbol": "SBADGE"
  },
  "asset": {
    "nft_id": "synn1...",
    "nft_address": "synn1...",
    "serial_number": 1,
    "name": "Genesis Badge #1",
    "description": "Short public description.",
    "image": "ipfs://bafy.../badge.png",
    "image_hash": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
    "animation_url": "",
    "external_url": "https://example.com/badges/1",
    "attributes": [
      {"trait_type": "tier", "value": "genesis"},
      {"trait_type": "transferable", "value": true}
    ]
  },
  "policy": {
    "transferable": true,
    "requires_issuer_approval": false,
    "expires_at": null,
    "royalty_basis_points": 250,
    "royalty_recipient": "synw1..."
  },
  "checksums": {
    "metadata_sha3_256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "image_sha3_256": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
  }
}
```

Multi-asset metadata uses `"standard": "sts-multi-asset-v1"`. Collection metadata describes the inventory namespace; each item can carry its own metadata URI/hash:

```json
{
  "schema": "synergy.sts.multi_asset.metadata.v1",
  "chain_id": 1264,
  "network": "testnet",
  "standard": "sts-multi-asset-v1",
  "collection": {
    "collection_id": "synj...",
    "collection_address": "synj...",
    "name": "Game Inventory",
    "symbol": "GINV",
    "image": "ipfs://bafy.../collection.png",
    "image_hash": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
  },
  "items": [
    {
      "item_id": 1,
      "item_type": "fungible",
      "name": "Energy Cell",
      "symbol": "CELL",
      "decimals": 0,
      "max_supply_base_units": "1000000",
      "transfer_policy": "open",
      "metadata_uri": "ipfs://bafy.../cell.json",
      "metadata_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    }
  ],
  "checksums": {
    "metadata_sha3_256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  }
}
```

Credential metadata must avoid private data. Put only schema hashes, credential hashes, and subject commitments on chain:

```json
{
  "schema": "synergy.sts.credential.metadata.v1",
  "chain_id": 1264,
  "network": "testnet",
  "standard": "sts-credential-v1",
  "issuer": {
    "address": "synw1...",
    "name": "Issuer Name",
    "website": "https://issuer.example"
  },
  "credential": {
    "credential_id": "synk...",
    "schema_id": "kyc-basic-v1",
    "schema_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "credential_hash": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "subject_commitment": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    "status": "active",
    "expires_at": null
  },
  "privacy": {
    "contains_pii": false,
    "on_chain_subject_is_commitment": true,
    "raw_claims_stored_off_chain": true
  }
}
```

## Token Images

Token images can be set at creation:

```bash
synergy-sts token create \
  --network testnet \
  --class b1 \
  --name "Testnet Gold" \
  --symbol TGLD \
  --decimals 9 \
  --initial-supply 1000000000000000 \
  --max-supply 1000000000000000 \
  --metadata-uri ipfs://bafy.../metadata.json \
  --metadata-file ./metadata.json \
  --image-uri ipfs://bafy.../logo.png \
  --image-file ./logo.png \
  --from synw1testcreator000000000000000000000000 \
  --creator-nonce 1 \
  --out ./tgld-create.json
```

Or after creation, exactly once, by the token creator:

```bash
synergy-sts token set-image \
  --network testnet \
  --token synb1... \
  --image-uri ipfs://bafy.../logo.png \
  --image-file ./logo.png \
  --image-hash dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd \
  --from synw1testcreator000000000000000000000000 \
  --out ./tgld-image.json
```

Image rules:

- `--image-uri` must be `ipfs://`, `ar://`, or `https://`.
- `--image-hash` is SHA3-256 lowercase hex without `0x`.
- `--image-file` computes SHA3-256 locally and must match `--image-hash` when both are supplied.
- SVG image URIs are rejected for explorer safety.
- If an image is present at token creation, the image is locked immediately.
- If no image is present at creation, Atlas allows the connected creator wallet to set it once from the token detail view.

## Create B1 Token

B1 is the basic fungible class. It does not allow freeze, pause, clawback, allowlist, denylist, or transfer approval flags.

```bash
synergy-sts token create \
  --network testnet \
  --class b1 \
  --name "Testnet Gold" \
  --symbol TGLD \
  --decimals 9 \
  --initial-supply 1000000000000000 \
  --max-supply 1000000000000000 \
  --metadata-uri ipfs://tgld \
  --metadata-hash aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  --image-uri ipfs://tgld/logo.png \
  --image-hash dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd \
  --from synw1testcreator000000000000000000000000 \
  --creator-nonce 1 \
  --created-at 1700000000 \
  --out ./tgld-create.json
```

The output includes:

```json
{
  "expected_token_id": "synb1...",
  "expected_token_address": "synb1...",
  "native_snrg_token_address": null,
  "payload_hex": "73796e657267792d7374732d76313a..."
}
```

## Create B2 Managed Token

B2 allows managed issuer powers, but dangerous powers must be declared at creation and must be enforceable by the current protocol slice.

```bash
synergy-sts token create \
  --network testnet \
  --class b2 \
  --name "Managed USD" \
  --symbol MUSD \
  --decimals 6 \
  --initial-supply 1000000000000 \
  --max-supply 1000000000000 \
  --metadata-uri ipfs://musd \
  --metadata-hash bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb \
  --from synw1issuer0000000000000000000000000000 \
  --creator-nonce 2 \
  --can-freeze \
  --can-pause \
  --can-clawback \
  --out ./musd-create.json
```

B2 control commands require a `synb2...` token ID:

```bash
synergy-sts token freeze --network testnet --token synb2... --owner synw1... --from synw1...
synergy-sts token thaw --network testnet --token synb2... --owner synw1... --from synw1...
synergy-sts token pause --network testnet --token synb2... --from synw1...
synergy-sts token unpause --network testnet --token synb2... --from synw1...
synergy-sts token clawback --network testnet --token synb2... --source synw1... --to synw1... --amount 1000 --from synw1...
```

## Create B3 Policy Token

B3 supports approved native policy templates. Current implemented templates:

- `transfer_fee_v1`
- `snapshot_v1`
- `vesting_v1`
- `max_wallet_v1`

Unsupported policy templates fail closed.

```bash
synergy-sts token create \
  --network testnet \
  --class b3 \
  --name "Governance Token" \
  --symbol GOV \
  --decimals 9 \
  --initial-supply 100000000000000000 \
  --max-supply 100000000000000000 \
  --metadata-uri ipfs://gov \
  --metadata-hash cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc \
  --from synw1issuer0000000000000000000000000000 \
  --creator-nonce 3 \
  --policy snapshot_v1 \
  --policy transfer_fee_v1:fee_bps=25,recipient=synw1fee000000000000000000000000000 \
  --policy max_wallet_v1:max_balance=50000000000000000 \
  --out ./gov-create.json
```

Create a B3 snapshot payload:

```bash
synergy-sts token snapshot --network testnet --token synb3... --from synw1... --out ./gov-snapshot.json
```

## Mint, Transfer, Burn

Mint:

```bash
synergy-sts token mint \
  --network testnet \
  --token synb1... \
  --to synw1recipient000000000000000000000000 \
  --amount 5000000000 \
  --from synw1mintauthority0000000000000000000 \
  --out ./mint.json
```

Transfer:

```bash
synergy-sts token transfer \
  --network testnet \
  --token synb1... \
  --from synw1sender00000000000000000000000000 \
  --to synw1recipient000000000000000000000000 \
  --amount 1250000000 \
  --out ./transfer.json
```

Burn:

```bash
synergy-sts token burn \
  --network testnet \
  --token synb1... \
  --from synw1holder00000000000000000000000000 \
  --amount 1000000000 \
  --out ./burn.json
```

## NFT Collections And Instances

Create an NF1 collection:

```bash
synergy-sts nft create-collection \
  --network testnet \
  --class nf1 \
  --name "Synergy Badges" \
  --symbol SBADGE \
  --metadata-uri ipfs://bafy.../collection.json \
  --metadata-file ./collection.json \
  --image-uri ipfs://bafy.../collection.png \
  --image-file ./collection.png \
  --royalty-bps 250 \
  --royalty-recipient synw1royalty00000000000000000000000 \
  --from synw1creator0000000000000000000000000 \
  --creator-nonce 10 \
  --out ./badge-collection.json
```

Create an NF2 controlled collection:

```bash
synergy-sts nft create-collection \
  --network testnet \
  --class nf2 \
  --name "Access Passes" \
  --symbol PASS \
  --metadata-uri ipfs://bafy.../passes.json \
  --metadata-file ./passes.json \
  --requires-issuer-approval \
  --from synw1issuer0000000000000000000000000 \
  --creator-nonce 11 \
  --out ./passes-collection.json
```

Mint an NFT:

```bash
synergy-sts nft mint \
  --network testnet \
  --collection synn1... \
  --to synw1owner00000000000000000000000000 \
  --metadata-uri ipfs://bafy.../badge-1.json \
  --metadata-file ./badge-1.json \
  --from synw1creator0000000000000000000000000 \
  --out ./badge-1-mint.json
```

Transfer, burn, and controlled lifecycle commands:

```bash
synergy-sts nft transfer --network testnet --nft synn1... --from synw1owner... --to synw1next...
synergy-sts nft burn --network testnet --nft synn1... --from synw1owner...
synergy-sts nft freeze --network testnet --nft synn2... --from synw1issuer...
synergy-sts nft thaw --network testnet --nft synn2... --from synw1issuer...
synergy-sts nft revoke --network testnet --nft synn2... --from synw1issuer...
synergy-sts nft use --network testnet --nft synn2... --from synw1owner...
synergy-sts nft update-metadata --network testnet --nft synn1... --metadata-uri ipfs://bafy.../updated.json --metadata-file ./updated.json --from synw1metadata...
synergy-sts nft verify-collection --network testnet --collection synn1... --from synw1collectionauthority...
```

NF1 assets are standard transferable NFTs. NF2 assets can enforce issuer approval, expiry, revocation, freeze/thaw, and single-use status. NFT IDs and collection IDs are deterministic `synn1` or `synn2` Bech32m object IDs; they are not signable wallet addresses.

## Multi-Asset Collections

Create a multi-asset collection:

```bash
synergy-sts ma create \
  --network testnet \
  --name "Game Inventory" \
  --symbol GINV \
  --metadata-uri ipfs://bafy.../inventory.json \
  --metadata-file ./inventory.json \
  --image-uri ipfs://bafy.../inventory.png \
  --image-file ./inventory.png \
  --from synw1creator0000000000000000000000000 \
  --creator-nonce 20 \
  --out ./inventory-create.json
```

Create items inside the collection:

```bash
synergy-sts ma create-item \
  --network testnet \
  --collection synj... \
  --item-id 1 \
  --type fungible \
  --name "Energy Cell" \
  --symbol CELL \
  --decimals 0 \
  --max-supply 1000000 \
  --transfer-policy open \
  --metadata-uri ipfs://bafy.../cell.json \
  --metadata-file ./cell.json \
  --from synw1creator0000000000000000000000000 \
  --out ./cell-create.json
```

Mint, transfer, burn, and batch operations:

```bash
synergy-sts ma mint --network testnet --collection synj... --item-id 1 --amount 100 --to synw1owner... --from synw1creator...
synergy-sts ma transfer --network testnet --collection synj... --item-id 1 --amount 10 --from synw1owner... --to synw1next...
synergy-sts ma burn --network testnet --collection synj... --item-id 1 --amount 5 --from synw1owner...
synergy-sts ma batch-mint --network testnet --collection synj... --item 1:100 --item 2:1 --to synw1owner... --from synw1creator...
synergy-sts ma batch-transfer --network testnet --collection synj... --item 1:10 --item 2:1 --from synw1owner... --to synw1next...
synergy-sts ma batch-burn --network testnet --collection synj... --item 1:5 --item 2:1 --from synw1owner...
```

Batch multi-asset operations are atomic in the runtime: if any item in the batch fails policy, supply, balance, or duplication checks, the whole batch fails.

## Credentials

Create a credential schema:

```bash
synergy-sts credential schema create \
  --network testnet \
  --schema-id kyc-basic-v1 \
  --name "KYC Basic" \
  --schema-hash aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  --description-hash bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb \
  --from synw1issuer0000000000000000000000000 \
  --out ./schema-create.json
```

Issue a credential using a subject address or a precomputed subject commitment:

```bash
synergy-sts credential issue \
  --network testnet \
  --schema-id kyc-basic-v1 \
  --subject synw1subject000000000000000000000000 \
  --credential-hash cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc \
  --expires-at 1893456000 \
  --from synw1issuer0000000000000000000000000 \
  --out ./credential-issue.json
```

Manage credential status:

```bash
synergy-sts credential verify-status --network testnet --credential synk... --from synw1issuer...
synergy-sts credential suspend --network testnet --credential synk... --from synw1issuer...
synergy-sts credential restore --network testnet --credential synk... --from synw1issuer...
synergy-sts credential revoke --network testnet --credential synk... --reason-hash dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd --from synw1issuer...
synergy-sts credential expire --network testnet --credential synk... --from synw1issuer...
```

Credential IDs are non-transferable `synk` object IDs. They are derived from chain ID, issuer, subject commitment, schema ID, credential hash, and issue timestamp.

## Payload Shape

STS payloads are JSON encoded under a binary prefix before being hex encoded.

Decoded create payload shape:

```json
{
  "version": 1,
  "chain_id": 1264,
  "network": "testnet",
  "tx": {
    "op": "create_fungible",
    "data": {
      "class": "b1",
      "creator": "synw1...",
      "creator_nonce": 1,
      "name": "Testnet Gold",
      "symbol": "TGLD",
      "decimals": 9,
      "initial_supply": 1000000000000000,
      "max_supply": 1000000000000000,
      "metadata_uri": "ipfs://...",
      "metadata_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "metadata_mutable": false,
      "image_uri": "ipfs://.../logo.png",
      "image_hash": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
    }
  }
}
```

The consensus payload bytes are:

```text
synergy-sts-v1:<json payload bytes>
```

Then those bytes are encoded as lowercase hex for CLI output.

## Safety Checks

The CLI fails closed when:

- Network is not `testnet`.
- Token class is not one of the supported stable wire strings.
- A B2 control command receives a non-`synb2` token ID.
- A B3 snapshot command receives a non-`synb3` token ID.
- Payload hex uses `0x`, uppercase hex, or malformed bytes.
- Metadata hash is uppercase, has `0x`, or does not match `--metadata-file`.
- Token image hash is uppercase, has `0x`, does not match `--image-file`, or image URI is unsafe.
- Amounts are not integer base units.
- Symbol is not 2-12 uppercase ASCII letters/digits starting with a letter.
- Name is empty, longer than 64 ASCII bytes, or impersonates `SNRG`/`Synergy`.
- Symbol contains `SNRG`, duplicates an existing STS token symbol in state, or attempts native-token impersonation.
- Mint authority exists without a bounded `--max-supply`.
- Fungible metadata mutability, allowlists, denylists, or transfer approvals are requested before full protocol enforcement exists.
- B3 transfer fee exceeds 1000 bps.
- A create payload is signed by a wallet other than the declared creator.
- NFT collection or instance IDs do not use the matching `synn1` or `synn2` Bech32m prefix.
- NFT royalties exceed 10000 bps or omit a royalty recipient when royalties are enabled.
- Multi-asset collection IDs are not valid `synj` object IDs.
- Multi-asset batch commands omit `--item`, duplicate item IDs, or use zero amounts.
- Credential IDs are not valid `synk` object IDs.
- Credential schema, credential, subject commitment, or reason hashes are not lowercase SHA3-256 hex.
- `--submit` is used without `--wallet` or `SYNERGY_WALLET_FILE`.
- The wallet is encrypted, missing `private_key`, or missing a matching `public_key`.
- The wallet public key does not derive the wallet address.
- The wallet address does not match the submitted `--from` address.
- The RPC native asset check does not return chain ID `1264`, native SNRG, and `token_address: null`.
- The wallet SNRG balance is below the calculated fee cap.
- `synergy_sendTransaction` rejects the signed transaction.

## Current Limitations

- `--wallet` expects decrypted wallet JSON. The CLI does not unlock encrypted wallet files or prompt for seed phrases.
- `--submit` queues a signed transaction and returns the transaction hash. It does not block until finality; use `sts_getToken`, `sts_getBalance`, `sts_getEvents`, or Atlas after the transaction finalizes.
- The public RPC-compatible default carrier amount is `1` nWei sent from the wallet back to itself. Use `--carrier-amount-nwei 0` only when the target RPC/runtime has zero-value STS carrier admission deployed.
- Hardware-wallet and interactive Synergy Wallet app signing are not part of this CLI release. This release signs from local Synergy wallet material.




- `synb1` = standard fungible token.
- `synb2` = managed fungible token.
- `synb3` = advanced or regulated fungible token.
- `synn1` = standard NFT.
- `synn2` = enhanced or restricted NFT.
- `synj` = multi-asset collection.
- `synk` = identity and credential token.
