# Synergy Testnet RPC Methods

This document lists all available JSON-RPC methods for Synergy Testnet.

## Endpoint

- **URL**: `http://localhost:5640/rpc`
- **Protocol**: JSON-RPC 2.0
- **Content-Type**: `application/json`

## Request Format

```json
{
  "jsonrpc": "2.0",
  "method": "method_name",
  "params": [...],
  "id": 1
}
```

## Blockchain Queries

### `synergy_blockNumber`

Get the current block number (height).

**Parameters**: None

**Returns**: `number` - Current block number

---

### `synergy_getBlockNumber`

Get the current block number (height). (Alias for `synergy_blockNumber`)

**Parameters**: None

**Returns**: `number` - Current block number

---

### `synergy_getBlockByNumber`

Get a block by its block number.

**Parameters**:

- `blockNumber` (number) - The block number to fetch

**Returns**: Block object or `null` if not found

---

### `synergy_getLatestBlock`

Get the most recent block.

**Parameters**: None

**Returns**: Block object or `null` if no blocks exist

---

### `synergy_getBlockRange`

Get a range of blocks.

**Parameters**:

- `start` (number) - Starting block number
- `end` (number) - Ending block number

**Returns**: Array of block objects

---

## Transaction Methods

### `synergy_sendTransaction`

Submit a signed transaction to the network.

**Parameters**:

- `transaction` (object) - Transaction object

**Returns**: `{success: boolean, tx_hash: string, message: string}` or error

---

### `synergy_getTransactionByHash`

Get a transaction by its hash. Supports multiple hash formats:

- Full hash: `syntxn-...`
- Raw hash: `a0d53ef9...`
- With or without `0x` prefix

**Parameters**:

- `txHash` (string) - Transaction hash

**Returns**: Transaction object or `null` if not found

---

### `synergy_getTransactionPool`

Get all pending transactions in the transaction pool.

**Parameters**: None

**Returns**: Array of pending transaction objects

---

### `synergy_getTransactionsInBlock`

Get all transactions in a specific block.

**Parameters**:

- `blockNumber` (number) - Block number

**Returns**: Array of transaction objects

---

## Node Information

### `synergy_nodeInfo`

Get node information.

**Parameters**: None

**Returns**: Node info object with:

- `name`: Node name
- `version`: Node version
- `protocolVersion`: Protocol version
- `networkId`: Network ID (1264 for testnet)
- `chainId`: Chain ID (1264 for testnet)
- `consensus`: Consensus algorithm
- `syncing`: Sync status
- `currentBlock`: Current block number
- `timestamp`: Current timestamp

---

### `synergy_getNodeStatus`

Get detailed node status including average block time and peer count.

**Parameters**: None

**Returns**: Status object with:

- `node_type`: Node type
- `status`: Node status
- `uptime`: Uptime percentage
- `version`: Node version
- `network`: Network name
- `sync_status`: Sync status
- `last_block`: Last block number
- `avg_block_time`: Average block time in seconds
- `average_block_time`: Alias for avg_block_time
- `peers_connected`: Number of connected peers
- `peer_count`: Alias for peers_connected
- `peers`: Alias for peers_connected
- `timestamp`: Current timestamp

---

### `synergy_status`

Simple status check (legacy method).

**Parameters**: None

**Returns**: `"ok"` string

---

## Validator Methods

### `synergy_getValidators`

Get all active validators.

**Parameters**: None

**Returns**: Array of validator objects

---

### `synergy_getValidator`

Get a specific validator by address.

**Parameters**:

- `address` (string) - Validator address

**Returns**: Validator object or `null` if not found

---

### `synergy_getTopValidators`

Get top validators by rank.

**Parameters**:

- `count` (number, optional) - Number of validators to return (default: 10)

**Returns**: Array of top validator objects

---

### `synergy_registerValidator`

Register a new validator.

**Parameters**:

- `address` (string) - Validator address
- `public_key` (string) - Validator public key
- `name` (string) - Validator name
- `stake_amount` (number) - Initial stake amount

**Returns**: `{success: boolean, message: string}` or error

---

### `synergy_approveValidator`

Approve a validator registration.

**Parameters**:

- `address` (string) - Validator address

**Returns**: `{success: boolean, message: string}` or error

---

### `synergy_slashValidator`

Slash a validator (penalize for misbehavior).

**Parameters**:

- `address` (string) - Validator address
- `reason` (string) - Reason for slashing

**Returns**: `{success: boolean, message: string}` or error

---

### `synergy_getValidatorStats`

Get validator statistics.

**Parameters**: None

**Returns**: Stats object with:

- `total_validators`: Total number of validators
- `active_validators`: Array of active validators
- `top_validators`: Array of top validators
- `epoch_rewards`: Epoch rewards information

---

### `synergy_getValidatorActivity`

Get validator activity information.

**Parameters**: None

**Returns**: Activity object with:

- `validators`: Array of validator activity objects
- `total_active`: Total active validators
- `average_synergy_score`: Average synergy score

---

### `synergy_getSynergyScoreBreakdown`

Get detailed Synergy Score components for a validator.

**Parameters**:

- `address` (string) - Validator address

**Returns**: Object with:

- `address`: Validator address
- `total_score`: Current normalized Synergy Score
- `components`: Synergy score component object containing:
  - `stake_weight`
  - `reputation`
  - `contribution_index`
  - `cartelization_penalty`
  - `normalized_score`
  - `last_updated`

---

## Token Methods

### `synergy_getTokenBalance`

Get token balance for an address.

**Parameters**:

- `address` (string) - Address to check
- `token` (string) - Token symbol (e.g., "SNRG")

**Returns**: Balance in nWei (nano-wei, smallest unit)

**Note**: 1 SNRG = 1,000,000,000 nWei

---

### `synergy_getTokens`

Get all tokens on the network.

**Parameters**: None

**Returns**: Array of token objects

---

### `synergy_getAllBalances`

Get all token balances for an address.

**Parameters**:

- `address` (string) - Address to check

**Returns**: Object mapping token symbols to balances

---

### `synergy_sendTokens`

Send tokens from one address to another.

**Parameters**:

- `from` (string) - Sender address
- `to` (string) - Recipient address
- `token_symbol` (string) - Token symbol (e.g., "SNRG")
- `amount` (number) - **Amount in SNRG** (will be converted to nWei internally)

**Returns**: `{success: boolean, tx_hash: string, transaction: object, message: string}` or error

**Note**: The `amount` parameter should be specified in SNRG units. The RPC automatically converts it to nWei (1 SNRG = 1,000,000,000 nWei).

---

### `synergy_createToken`

Create a new token.

**Parameters**:

- `symbol` (string) - Token symbol
- `name` (string) - Token name
- `decimals` (number) - Number of decimals
- `total_supply` (number) - Total supply
- `creator` (string) - Creator address

**Returns**: `{success: boolean, message: string}` or error

---

### `synergy_mintTokens`

Mint new tokens.

**Parameters**:

- `to` (string) - Recipient address
- `token_symbol` (string) - Token symbol
- `amount` (number) - Amount to mint

**Returns**: `{success: boolean, message: string}` or error

---

### `synergy_burnTokens`

Burn tokens.

**Parameters**:

- `from` (string) - Address to burn from
- `token_symbol` (string) - Token symbol
- `amount` (number) - Amount to burn

**Returns**: `{success: boolean, message: string}` or error

---

### `synergy_transferTokens`

Transfer tokens (low-level method).

**Parameters**:

- `from` (string) - Sender address
- `to` (string) - Recipient address
- `token_symbol` (string) - Token symbol
- `amount` (number) - Amount to transfer

**Returns**: `{success: boolean, message: string}` or error

---

### `synergy_getTokenStats`

Get token statistics.

**Parameters**: None

**Returns**: Array of token stat objects with:

- `symbol`: Token symbol
- `name`: Token name
- `total_supply`: Total supply
- `total_staked`: Total staked amount
- `holders`: Number of holders

---

### `synergy_getTransferHistory`

Get transfer history for an address.

**Parameters**:

- `address` (string) - Address to check
- `limit` (number, optional) - Maximum number of transfers to return (default: 50)

**Returns**: Array of transfer objects

---

## Staking Methods

### `synergy_stakeTokens`

Create a staking transaction.

**Parameters**:

- `staker` (string) - Staker address
- `validator` (string) - Validator address
- `token_symbol` (string) - Token symbol
- `amount` (number) - **Amount in SNRG** (will be converted to nWei)

**Returns**: `{success: boolean, transaction: object, message: string}` or error

---

### `synergy_stakeTokensDirect`

Stake tokens directly (without creating a transaction).

**Parameters**:

- `staker` (string) - Staker address
- `validator` (string) - Validator address
- `token_symbol` (string) - Token symbol
- `amount` (number) - **Amount in SNRG** (will be converted to nWei)

**Returns**: `{success: boolean, message: string}` or error

---

### `synergy_unstakeTokens`

Unstake tokens.

**Parameters**:

- `staker` (string) - Staker address
- `validator` (string) - Validator address
- `token_symbol` (string) - Token symbol
- `amount` (number) - Amount to unstake

**Returns**: `{success: boolean, message: string}` or error

---

### `synergy_getStakedBalance`

Get staked balance for an address.

**Parameters**:

- `address` (string) - Address to check
- `token_symbol` (string) - Token symbol

**Returns**: `{balance: number}` - Staked balance

---

### `synergy_getStakingInfo`

Get staking information for an address.

**Parameters**:

- `address` (string) - Address to check

**Returns**: Staking info object

---

## Wallet Methods

### `synergy_createWallet`

Create a new wallet.

**Parameters**: None

**Returns**: `{address: string, message: string}` or error

---

### `synergy_getWallet`

Get wallet information.

**Parameters**:

- `address` (string) - Wallet address

**Returns**: Wallet object or `null` if not found

---

### `synergy_createWalletFromKeypair`

Create a wallet from an existing keypair.

**Parameters**:

- `public_key` (string) - Public key
- `private_key` (string) - Private key

**Returns**: `{success: boolean, address: string, message: string}` or error

---

### `synergy_getAllWallets`

Get all wallets.

**Parameters**: None

**Returns**: Array of wallet objects

---

### `synergy_signTransaction`

Sign a transaction with a wallet.

**Parameters**:

- `address` (string) - Wallet address
- `transaction` (object) - Transaction object to sign

**Returns**: `{success: boolean, message: string, transaction: object}` or error

---

## Network Methods

### `synergy_getNetworkStats`

Get network statistics.

**Parameters**: None

**Returns**: Stats object with:

- `block_height`: Current block height
- `total_transactions`: Total number of transactions
- `active_validators`: Number of active validators
- `total_supply`: Total token supply
- `tokens`: Number of tokens
- `network_uptime`: Network uptime percentage
- `current_epoch`: Current epoch number
- `total_staked`: Total staked amount

---

### `synergy_getPeerInfo`

Get peer information.

**Parameters**: None

**Returns**: Object with:

- `peer_count`: Number of connected peers
- `peers`: Array of peer information objects

---

### `synergy_getBlockValidationStatus`

Get block validation status.

**Parameters**: None

**Returns**: Validation status object with:

- `current_block_height`: Current block height
- `recent_blocks`: Array of recent block validation info
- `validation_queue`: Pending validation queue
- `active_validators`: Number of active validators
- `total_validators`: Total number of validators
- `cluster_info`: Cluster information

---

## Error Responses

If an error occurs, the response will be:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "error": {
    "code": -32000,
    "message": "Error message"
  }
}
```

Or for simple errors, the result may be a string error message.

## Notes

1. **SNRG Denomination**: All amounts are stored internally as nWei (1 SNRG = 1,000,000,000 nWei). The `synergy_sendTokens` and staking methods accept amounts in SNRG and convert them automatically.

2. **Transaction Hashes**: Transaction hashes can be provided in multiple formats:
   - Full format: `syntxn-a0d53ef9...`
   - Raw format: `a0d53ef9...`
   - With or without `0x` prefix

3. **Timestamps**: All timestamps are Unix timestamps in seconds.

4. **AIVM Methods**: AIVM (Artificial Intelligence Virtual Machine) methods are currently disabled in the testnet.

## Example Usage

### Get Current Block Number

```bash
curl -X POST http://localhost:48638/rpc \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"synergy_getBlockNumber","params":[],"id":1}'
```

### Get Block by Number

```bash
curl -X POST http://localhost:48638/rpc \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"synergy_getBlockByNumber","params":[150],"id":1}'
```

### Send Tokens

```bash
curl -X POST http://localhost:48638/rpc \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc":"2.0",
    "method":"synergy_sendTokens",
    "params":[
      "synw1lfgerdqglc6p74p9u6k8ghfssl59q8jzhuwm07",
      "synv11gfutu5quzf9jc7tra0x4c95shaagaywxc6zae3",
      "SNRG",
      500000
    ],
    "id":1
  }'
```

### Get Transaction by Hash

```bash
curl -X POST http://localhost:48638/rpc \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc":"2.0",
    "method":"synergy_getTransactionByHash",
    "params":["syntxn-a0d53ef9548a458f16cfc6ae0f5e27a40765419633f19b9bf4e44a4cf4ace82d"],
    "id":1
  }'
```

### Get Node Status

```bash
curl -X POST http://localhost:48638/rpc \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"synergy_getNodeStatus","params":[],"id":1}'
```
