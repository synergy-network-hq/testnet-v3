# Synergy Testnet Fee Model

This document describes the testnet protocol fee model implemented in the runtime and RPC surfaces. Fees are accounted in integer nWei only.

## Units

- Native asset: `SNRG`
- Base unit: `nWei`
- Precision: `1 SNRG = 1,000,000,000 nWei`

## Formula

Total network fee is not the same as gas fee.

```text
total_network_fee_nwei =
    gas_fee_nwei
  + amount_protocol_fee_nwei
  + storage_fee_nwei
  + priority_fee_nwei

gas_fee_nwei = gas_used * base_fee_per_gas_nwei

amount_protocol_fee_nwei =
    clamp(
        floor(amount_snrgequivalent_nwei * amount_fee_bps / 10000),
        min_amount_fee_nwei,
        max_amount_fee_nwei
    )
```

Two native sends with the same gas can have the same `gas_fee_nwei`, but different `total_network_fee_nwei` when the transferred amount differs.

Example with `gas_fee_nwei = 1,000`:

| Transaction | Amount nWei | Amount BPS | Amount fee nWei | Total fee nWei |
| --- | ---: | ---: | ---: | ---: |
| Send 1 SNRG | 1,000,000,000 | 2 | 200,000 | 201,000 |
| Send 100 SNRG | 100,000,000,000 | 2 | 20,000,000 | 20,001,000 |

## Default Testnet Schedule

The default schedule is defined by `src/gas/mod.rs` and exposed through `synergy_getFeeSchedule`.

| Transaction type | Amount fee BPS | Valuation required | Storage fee |
| --- | ---: | --- | --- |
| `native_snrg_send` | 2 | No | No |
| `token_send` | 3 | Yes | No |
| `swap` | 10 | Yes | No |
| `burn` | 1 | No for native SNRG | No |
| `mint` | 5 | Yes | No |
| `stake` | 0 | No | No |
| `unstake` | 0 | No | No |
| `contract_call` | 2 | No | No |
| `contract_deploy` | 0 | No | Yes |
| `ai_job_payment` | 5 | Yes | No |
| `sxcp_cross_chain_value_action` | 5 | Yes | No |

For non-SNRG assets, execution must use a deterministic valuation source. When no valuation exists, amount-based fee falls back to zero for valuation-required types and the fee response marks `valuationStatus` as `unavailable`.

## Fee Collection

Successful fee-bearing transactions debit the payer and credit:

```text
NETWORK_FEE_COLLECTOR_ADDRESS = synf1y42p7p6jrxrg472ts6jea5y34yg7tgj6qg2j
```

The runtime records fee audit state in the reward ledger by epoch. Transaction receipts and fee estimates expose `feeBreakdown` with:

- `txType`
- `assetId`
- `amountRaw`
- `amountSnrgEquivalentNwei`
- `valuationStatus`
- `amountFeeBps`
- `gasFeeNwei`
- `amountProtocolFeeNwei`
- `storageFeeNwei`
- `priorityFeeNwei`
- `totalNetworkFeeNwei`
- `feeCollector`

## RPC Surfaces

Query the schedule:

```json
{"jsonrpc":"2.0","id":1,"method":"synergy_getFeeSchedule","params":[]}
```

Estimate a fee:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "synergy_estimateFee",
  "params": [{
    "from": "synw1...",
    "to": "synw1...",
    "value": "100000000000",
    "gasPrice": 1
  }]
}
```

Read fee distribution for an epoch:

```json
{"jsonrpc":"2.0","id":1,"method":"synergy_getEpochFeeDistribution","params":[42]}
```

Check reward and fee invariants:

```json
{"jsonrpc":"2.0","id":1,"method":"synergy_checkRewardInvariants","params":[42]}
```
