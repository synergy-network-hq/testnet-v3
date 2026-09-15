# Synergy Testnet Burn System

The testnet burn system recognizes the canonical network burn address in protocol code and genesis:

```text
NETWORK_BURN_ADDRESS = syn00000000000000000000000000000000000000
```

Do not use the internal `BURN_SINK_ADDRESS` constant as the official network burn address.

## Burn Address Rules

The burn address is protocol-controlled and non-spendable. It cannot:

- send funds
- pay transaction fees
- stake or delegate
- register as a validator
- receive validator reward payout
- act as a cluster reward escrow
- receive Treasury Recovery funds

## Explicit Burn

Native SNRG burns are submitted as normal signed transactions with a `burn:` payload:

```json
burn:{"asset":"SNRG","amount":"10000000000"}
```

Execution behavior:

1. Validate the sender is not the burn address.
2. Validate amount is greater than zero.
3. Classify the transaction as `burn`.
4. Charge gas plus the burn amount protocol fee.
5. Credit the total fee to the network fee collector.
6. Debit the burned amount from the sender.
7. Record a supply-reducing burn event.

Token burns remain owned by the token manager path, which records explicit burn ledger entries for burnable tokens.

## Direct Transfer To Burn Address

A direct native transfer to `syn00000000000000000000000000000000000000` is accepted and indexed as a burn-address transfer. It is recorded separately from explicit burns:

- explicit burn: `supply_reduced = true`
- direct transfer: `supply_reduced = false`, permanently locked at the burn address

## Burn Ledger RPC

Query all burn records:

```json
{"jsonrpc":"2.0","id":1,"method":"synergy_getBurnLedger","params":[]}
```

Query one asset:

```json
{"jsonrpc":"2.0","id":1,"method":"synergy_getBurnLedger","params":["SNRG"]}
```

The response includes:

- `assetId`
- `burnAddress`
- `totalBurnedRaw`
- `totalBurnedNwei` when the queried asset is `SNRG`
- `records`
- `chain`

Each record includes burner, asset ID, amount, burn address, fee charged, supply reduction status, transaction hash, block height, burn kind, and timestamp.

## Fee Example

For a native burn of `10 SNRG`:

```text
amount_nwei = 10,000,000,000
amount_fee_bps = 1
amount_protocol_fee_nwei = 1,000,000
total_network_fee_nwei = gas_fee_nwei + 1,000,000
```

The burned amount itself is not a fee and is not routed to the fee collector.
