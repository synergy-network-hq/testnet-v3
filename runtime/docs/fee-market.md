# Canonical Live Gas Pricing (the Synergy "fee market")

Status: implemented in the canonical `synergy_types` / `execution.rs` /
`consensus::coordinated_runtime` execution path and in the RPC-facing
legacy `BlockChain` (see "Two chain stacks" below for why both exist and
what that means for callers). Testnet v3, chain ID 1266.

This document is the authoritative description of how Synergy Network
determines, enforces, and reports the price of gas. It exists because
Forge, Atlas, wallets, and third-party tooling must never invent a gas
price -- they must read one the protocol actually computed and (where
applicable) enforced.

## 1. What a Synergy gas unit represents

Ordinary gas (`gas_used`) measures the deterministic computational cost of
a transaction, using the shared `crate::gas` activity-cost tables (transfer,
contract deploy, contract call, and so on). For SynQ contract deploy/call
transactions, `gas_used` is the real value reported by AIVM's weighted
execution metering (`SynQRuntimeReceipt.gas_used` via `aivm_core`), not an
estimate -- the interpreter actually ran and actually counted it.

## 2. What PQ gas represents

Post-quantum-cryptography operations performed during SynQ execution
(signature verification, KEM operations, and similar) are metered
*separately* as `pq_gas_used`, again a real value from AIVM
(`SynQRuntimeReceipt.pqc_gas_used`). PQ gas is never folded into ordinary
gas -- it is priced independently (see Â§4) and always reported alongside,
never merged into, the ordinary gas figures.

## 3. Denomination

SNRG has 9 decimal places. The smallest unit is `nWei`
(`1 SNRG = 1_000_000_000 nWei`, `NWEI_PER_SNRG` /
`crate::gas::constants::SNRG_DECIMALS`). Every fee-market value in this
document, in code, and in RPC responses is an integer number of nWei per
gas unit (or nWei total, for fees). Consensus code never uses floating
point for any monetary, fee, or pricing value.

## 4. How `base_fee_per_gas` is calculated

`base_fee_per_gas` is a protocol-defined, per-block value. It is derived
*deterministically* from the parent block's own declared base fee and its
actual ordinary gas utilization -- no node, validator, Atlas, or Forge ever
chooses it, and it is never an oracle price or an off-chain estimate.

```text
target        = target_block_gas
delta         = parent_gas_used - target                     (signed)
change        = parent_base_fee * |delta| / target / base_fee_change_denominator
next_base_fee = parent_base_fee + max(change, 1)   if delta > 0  (above target: increase)
              = parent_base_fee - min(change, parent_base_fee)    if delta < 0  (below target: decrease)
              = parent_base_fee                                    if delta == 0 (at target: unchanged)
next_base_fee = max(next_base_fee, base_fee_floor_nwei)
```

Implementation: `gas::fee_market::next_base_fee_per_gas` in
`runtime/src/gas/fee_market.rs`. All arithmetic is integer-only, computed
in `u128` internally with checked multiplication/division and explicit
overflow errors (`FeeMarketError::Overflow`), then narrowed back to `u64`
with an explicit fallibility check -- never a silent wraparound.

**Rounding rule.** `change` truncates toward zero (integer division). When
utilization is above target and truncation would otherwise produce a
`change` of `0` (small congestion), the base fee still increases by a
guaranteed minimum of `1` nWei, so upward pressure is never silently
absorbed by rounding. No equivalent minimum applies to decreases: a
below-target block may leave the fee unchanged if the computed decrease
truncates to zero, or if the fee is already at the floor -- this is correct
and expected (a fee "stuck" at a low value under light usage is not a bug).

**Floor.** `base_fee_floor_nwei` is an absolute lower bound; the algorithm
can never drive the price below it, regardless of how many consecutive
empty blocks occur.

### Worked example (Testnet v3 defaults)

Testnet v3 defaults (see Â§7): `initial_base_fee_nwei = 40`,
`base_fee_floor_nwei = 1`, `target_block_gas = 15_000_000`,
`max_block_gas = 30_000_000`, `base_fee_change_denominator = 8`.

**Above target.** Parent base fee `40` nWei/gas, parent block used
`18_000_000` gas (target is `15_000_000`):

```text
delta   = 18_000_000 - 15_000_000 = 3_000_000
change  = 40 * 3_000_000 / 15_000_000 / 8
        = 120_000_000 / 15_000_000 / 8
        = 8 / 8
        = 1
next    = 40 + max(1, 1) = 41 nWei/gas
```

**Below target.** Parent base fee `40` nWei/gas, parent block used
`5_000_000` gas:

```text
delta   = 15_000_000 - 5_000_000 = 10_000_000
change  = 40 * 10_000_000 / 15_000_000 / 8
        = 400_000_000 / 15_000_000 / 8
        = 26 / 8                      (400_000_000 // 15_000_000 = 26, integer division)
        = 3
next    = 40 - 3 = 37 nWei/gas
```

**At target.** Parent block used exactly `15_000_000` gas: `next = 40`
(unchanged).

**Maximum single-block move.** A full block (`gas_used = max_block_gas =
30_000_000`, i.e. `delta = target_block_gas`) produces
`change = base * target / target / denominator = base / denominator`, so
with `base_fee_change_denominator = 8` the maximum possible single-block
change is `1/8 = 12.5%` of the parent base fee, in either direction.

These sixteen-plus scenarios (zero/below/at/above/max utilization,
consecutive empty blocks decreasing until integer rounding stabilizes them,
consecutive full blocks
increasing every block, the minimum-upward-movement guarantee, overflow
boundaries, invalid configuration, and full determinism under repeated
execution) are exercised as automated tests in
`runtime/src/gas/fee_market.rs`'s `#[cfg(test)] mod tests`.

## 5. Gas vs. protocol fees

Execution gas fees (Â§6) are entirely separate from other Synergy protocol
fees -- contract deployment fees, PQC-specific fees, cross-chain fees,
API/network fees, and any future protocol fee. These are never collapsed
into "gas." `NetworkFeeBreakdown` (in `runtime/src/gas/mod.rs`) keeps
`gas_fee_nwei` (now itself `base_execution_fee_nwei + pq_execution_fee_nwei`,
see Â§6), `amount_protocol_fee_nwei`, `storage_fee_nwei`, and
`priority_fee_nwei` as always-separate, always-itemized components, summed
only in the final `total_network_fee_nwei`. Nothing here is ever
mislabeled as "gas" when it is a different protocol fee category.

## 6. How SNRG is charged (transaction-level formula)

```text
base_execution_fee  = gas_used * applied_base_fee_per_gas
pq_execution_fee     = pq_gas_used * applied_base_fee_per_gas * applied_pq_gas_multiplier
                      = pq_gas_used * effective_pq_gas_price
execution_fee_total  = base_execution_fee + pq_execution_fee
total_transaction_fee = execution_fee_total + protocol_fees   (itemized separately, see Â§5)
```

Where `effective_pq_gas_price = base_fee_per_gas * pq_gas_multiplier`
(`gas::fee_market::effective_pq_gas_price`, checked multiplication).

Implementation: `execution.rs::canonical_network_fee_breakdown` computes
this via `gas::fee_market::calculate_execution_fee` whenever a block
carries an applied fee market (`AppliedFeeMarket`, derived from the block
header's `fee_market_version != 0`). `gas_used` and `pq_gas_used` are the
*real* values AIVM reported for that transaction's execution
(`SynQAivmReceiptSummary`), not an estimate and not the transaction's
declared `gas_limit`/`max_fee_nwei`.

**Worked example.** `gas_used = 21_000`, `pq_gas_used = 0`,
`base_fee_per_gas = 41` nWei (from Â§4's worked example):

```text
base_execution_fee = 21_000 * 41 = 861_000 nWei = 0.000861 SNRG
pq_execution_fee    = 0 * 41 * 4 = 0
execution_fee_total = 861_000 nWei
```

A SynQ contract call with real PQ operations, `gas_used = 50_000`,
`pq_gas_used = 2_000`, same `base_fee_per_gas = 41`,
`pq_gas_multiplier = 4`:

```text
effective_pq_gas_price = 41 * 4 = 164 nWei/gas
base_execution_fee     = 50_000 * 41  =  2_050_000 nWei
pq_execution_fee        =  2_000 * 164 =    328_000 nWei
execution_fee_total     =                2_378_000 nWei = 0.002378 SNRG
```

**Payer protection / never-overcharge.** A transaction's `max_fee_nwei`
(its existing gas/fee envelope field -- no new field was added for this)
remains the hard cap the payer authorized. If
`execution_fee_total > max_fee_nwei` under an active fee market, the
transaction fails validation with `MAX_FEE_PER_GAS_TOO_LOW` and is not
charged at all, rather than being charged more than authorized. When the
real, usage-based `execution_fee_total` is *less* than `max_fee_nwei`
(the common case), the payer is charged the real, lower amount -- not the
full envelope -- which is a behavior change from the pre-existing flat
"charge the full envelope" logic; see the deliverables report,
Â§"Transaction charging flow," for the exact before/after.

## 7. Fee-market parameters (`gas::fee_market::FeeMarketParams`)

| Field | Testnet v3 default | Status |
|---|---|---|
| `fee_market_enabled` | `true` | algorithmic policy |
| `base_fee_floor_nwei` | `1` (= `MIN_GAS_PRICE`) | **inherited placeholder, not approved economics** |
| `initial_base_fee_nwei` | `40` (= `DEFAULT_GAS_PRICE`) | **inherited placeholder, not approved economics** |
| `target_block_gas` | `15_000_000` (= `BLOCK_GAS_LIMIT / 2`) | algorithmic policy (â‰ˆ50% target, per task guidance) |
| `max_block_gas` | `30_000_000` (= `BLOCK_GAS_LIMIT`) | pre-existing, already-shipped constant |
| `base_fee_change_denominator` | `8` (â‰ˆ12.5% max/block) | algorithmic policy, per task guidance |
| `pq_gas_multiplier` | `4` | **inherited placeholder, not approved economics** |
| `max_block_pq_gas` | `4_000_000` | **inherited placeholder, not approved economics** |
| `target_block_pq_gas` | `2_000_000` | **inherited placeholder, not approved economics**; currently informational only (Â§4's algorithm adjusts from ordinary-gas utilization only) |
| `activation_height` | `1` | see Â§9 |
| `fee_market_version` | `1` | see Â§9 |

### Values requiring economic sign-off

`base_fee_floor_nwei`, `initial_base_fee_nwei`, `pq_gas_multiplier`,
`max_block_pq_gas`, and `target_block_pq_gas` are **not** approved
Testnet v3 (let alone mainnet) economic policy. No such approved value
exists anywhere in this repository or in protocol documentation as of this
change. The values above are carried over from already-shipped,
pre-existing constants (`crate::gas::constants::MIN_GAS_PRICE`,
`DEFAULT_GAS_PRICE`) purely so the fee market has a deterministic,
non-arbitrary bootstrap value on day one, and so validators agree on
something concrete rather than nothing. Treat every value in that group as
a placeholder pending an explicit Testnet v3 economic-configuration
decision -- do not present it to users as final or permanent policy.

`target_block_gas` and `base_fee_change_denominator` are algorithmic/shape
policy (how aggressively the market responds to congestion), not SNRG
pricing, and follow the task's own suggested starting points (â‰ˆ50% target
utilization; a denominator giving â‰ˆ12.5% max per-block adjustment).

## 8. Precise definitions

- **`current_base_fee_per_gas`**: the base fee that applied to (was
  actually charged against) the latest canonical block.
- **`next_base_fee_per_gas`**: the deterministic base fee that will apply
  to the *next* block, computed from the latest canonical block's declared
  base fee and gas usage via Â§4's formula. This is what Forge quotes for
  estimation, and what `synergy_gasPrice` / `synergy_getFeeMarket` report
  as "the" current price, since it is the price a transaction submitted
  right now will actually be charged once included.
- **`effective_pq_gas_price`**: `next_base_fee_per_gas * pq_gas_multiplier`.
- **`priority_fee_per_gas`**: always `0`. No priority-fee/tip market
  exists yet on Synergy. Every RPC surface that could plausibly report a
  tip must explicitly report `priorityFeeEnabled: false` alongside the `0`
  value, and must never fabricate a "recommended tip."

## 9. Fee-market activation / versioning

`fee_market_version` (currently `1`, `gas::fee_market::FEE_MARKET_VERSION`)
is carried on every canonical block header
(`synergy_types::BlockHeader.fee_market_version`, an additive
`#[serde(default)]` field so old serialized blocks decode as version `0`,
i.e. legacy/pre-fee-market). `activation_height` (currently `1`, i.e. from
genesis on Testnet v3) is the height at and after which fee-market
enforcement applies; blocks below it are validated under legacy rules
(no protocol base fee is enforced, and the sender's declared
`max_fee_nwei` is charged in full, matching pre-existing behavior exactly).
Atlas must interpret pre-activation and post-activation blocks according to
each block's own `fee_market_version`, never assuming today's parameters
applied retroactively.

## 10. How Forge estimates costs

Forge's Gas & Fee Estimator (`/tools/gas-and-fee-estimator`) must present
three separate, clearly labeled sections and never fabricate a value for a
section whose input is unavailable:

1. **Execution Estimate** -- `gasUsed`, `pqGasUsed`, and execution status,
   from a real (non-persistent) dry run wherever the codebase's real AIVM
   dry-run path is reachable for the transaction kind in question.
2. **Live Network Price** -- `next_base_fee_per_gas`,
   `effective_pq_gas_price`, fee asset (`SNRG`), pricing block, and
   fee-market version, from the authoritative RPC (`synergy_getFeeMarket`
   preferred; `synergy_gasPrice` / `synergy_getFeeSchedule` as fallbacks).
3. **Estimated SNRG Cost** -- Â§6's formula applied to (1) and (2),
   itemizing ordinary vs. PQ execution cost and any additional protocol
   fees separately, never pre-summed into one opaque number.

See the deliverables report for the current status of Forge's actual
integration (not reached in this change; the app itself was not staged in
this environment -- see "Remaining blockers").

## 11. How Atlas reports live vs. historical

Atlas's `/gas` page must present two datasets that are never blended:

- **Live Protocol Pricing** -- read straight from the authoritative RPC
  (`synergy_getFeeMarket`): current/next base fee, effective PQ gas price,
  fee asset, current block gas utilization, target utilization,
  fee-market/version status. Labeled as protocol-derived.
- **Historical Fee Statistics** -- computed from Atlas's own indexed
  receipts (P25/P50/P90, min, max, average/median, count of fee-bearing
  transactions, time window). Labeled as historical observations, **not**
  authoritative current price. Zero fee-bearing indexed transactions must
  be reported honestly (e.g. `count: 0`) while the live protocol price is
  still shown -- an empty history must never hide or suppress the live
  price section.

**Status: frontend wired, backend contract not yet implemented.** Atlas's
`src/pages/GasPage.tsx` now renders both sections. The historical section
(`src/lib/gas.ts`, `src/components/GasPanel.tsx`) was already compliant.
The new live section calls `atlasApi.feeMarket()`
(`src/lib/atlasApi.ts`), polled independently of the indexed-history
snapshot by `src/lib/useFeeMarket.ts` (a 6s interval, deliberately decoupled
from `AtlasDataProvider` so live pricing is never staleness-coupled to
history refreshes).

Atlas's frontend never talks to the node's JSON-RPC directly -- every other
endpoint on `atlasApi` goes through Atlas's own backend indexer at
`VITE_ATLAS_API_BASE` (default `/api/v1`), and the fee-market endpoint
follows that same convention: `GET {ATLAS_API_BASE}/network/fee-market`.

**This backend endpoint does not exist yet and was not implemented in this
change** -- the Atlas backend/indexer source was not staged into this
environment (only `atlas-v3/src/{components,lib,pages}` were available), so
there was nothing to edit. Until the backend adds it, the frontend fails
closed: `useFeeMarket` reports `available: false` and the page renders an
honest "Unavailable" notice in the live-pricing section rather than
fabricating a price or silently falling back to the historical figures.

The required backend contract (for whoever implements the Atlas
backend/indexer side) is: proxy `synergy_getFeeMarket` verbatim as JSON at
`GET /network/fee-market`, returning the exact response shape documented in
Â§12 below (`version`, `enabled`, `feeAsset`, `current{...}`, `next{...}`,
`pq{...}`, `priorityFee{...}`, `parameters{...}`, `feeCollector`, `source`).
`atlasApi.ts`'s `normalizeFeeMarket()` accepts both camelCase and snake_case
keys, so either JSON convention the node/backend already uses is fine.

## 12. RPC method semantics

All six required methods, plus the new `synergy_getFeeMarket`, are
implemented in `runtime/src/rpc/rpc_server.rs`. **Important:** read
`canonical_fee_market_state`'s doc comment in that file first -- it
documents a pre-existing architecture split in this codebase (the RPC
server's `BlockChain` vs. the canonical `coordinated_runtime` chain) that
determines what "authoritative" means for these responses today. See the
deliverables report, "Remaining blockers," for the full explanation.

- **`synergy_gasPrice`**: returns `{baseFeePerGas, effectivePqGasPrice,
  pqGasMultiplier, feeAsset: "SNRG", source: "protocol", feeMarketVersion,
  blockNumber, forBlock}`. `baseFeePerGas` is `next_base_fee_per_gas` (Â§8),
  never a historical percentile and never computed with floating point.
- **`synergy_maxFeePerGas`**: since no priority-fee/tip market exists,
  returns the authoritative next-block base fee itself as `maxFeePerGas`,
  with `priorityFeeEnabled: false` and a `note` clarifying that any
  additional safety margin is a client-side choice, not a protocol value.
- **`synergy_maxPriorityFeePerGas`**: returns `0` with
  `priorityFeeEnabled: false`. Never a fabricated recommended tip.
- **`synergy_getFeeSchedule`**: fee-market version, current/next base fee,
  floor, target gas, max block gas, PQ multiplier, effective PQ price,
  `priorityFeeEnabled: false`, fee asset, collector address, activation
  height, plus the pre-existing per-tx-type amount-fee schedule.
- **`synergy_estimateGas`**: returns `gasUsed`/`pqGasUsed`/fee
  breakdowns. **Known gap:** for plain transfers this uses the shared
  deterministic activity-gas table (real, not fabricated); for SynQ
  deploy/call transactions it does **not yet** route through the real AIVM
  dry-run the way `synergy_call` does -- see the deliverables report.
- **`synergy_estimateFee`**: combines a gas estimate with the authoritative
  next-block price and returns an itemized breakdown
  (`fee_breakdown_json`) rather than one opaque total.
- **`synergy_getFeeMarket`** (new): the preferred, structured API --
  `version`, `enabled`, `feeAsset`, `current{blockNumber, baseFeePerGas,
  gasUsed, gasLimit, utilizationBps}`, `next{blockNumber, baseFeePerGas,
  effectivePqGasPrice}`, `pq{multiplier, maxBlockPqGas, targetBlockPqGas}`,
  `priorityFee{enabled: false, recommended: null}`, `parameters{...}`,
  `feeCollector`, `source: "protocol"`.

### JSON-RPC error semantics

An upstream JSON-RPC error object (e.g. `{"error": {"code": -32601}}`
returned inside a normal HTTP 200 response body) must never be reported by
a client as an HTTP transport failure such as "502." That translation bug,
if present in a given Forge deployment, is a Forge-side bug in how it
interprets JSON-RPC responses, not something this RPC server can enforce
from the server side -- the server's contribution is simply to return
correct, unambiguous JSON-RPC error objects, which it already does via its
existing `RpcError { code, message, data }` convention used consistently
across this file.

## 13. Two chain stacks (read this before assuming "the" chain)

This codebase currently contains two separate block/consensus
representations:

1. **Legacy**: `block.rs::{Block, BlockChain}` +
   `consensus::consensus_algorithm::ProofOfSynergy` +
   `crate::wallet::WALLET_MANAGER`. This is what
   `rpc_server.rs`'s `chain: Arc<Mutex<BlockChain>>` parameter actually is,
   and it is what real transactions are applied against today
   (`ProofOfSynergy` calls `chain.add_block_extending_tip`, and applies
   balances via `WALLET_MANAGER`, not `execution::execute_transaction`).
2. **Canonical**: `synergy_types::{Block, BlockHeader, Transaction}` +
   `execution.rs` (`execute_block`, `execute_transaction`,
   `ExecutionState`) + `consensus::coordinated_runtime::CoordinatedRuntime`
   (the `coordinated_round_robin_v1` single-authority path) + AIVM. This is
   where this change's full Canonical Live Gas Pricing engine is wired in
   end-to-end: block-header fee fields, deterministic base-fee derivation
   and independent block-validation re-derivation
   (`execute_coordinated_block`), real usage-based transaction charging,
   and auditable receipt fields.

The RPC server has no reference to `CoordinatedRuntime` or
`ExecutionState` anywhere (`grep -rn "CoordinatedRuntime" rpc_server.rs`
returns nothing). Because of this, this change applies the real,
deterministic, integer-only fee-market *formula* to stack (1)'s data too
(`canonical_fee_market_state`, replayed over `BlockChain`'s real observed
block usage) so that `synergy_gasPrice` and friends stop being a
floating-point historical average -- but stack (1)'s blocks do not persist
`base_fee_per_gas` headers and stack (1)'s fee charging does not go
through this fee market at all. Full single-source-of-truth enforcement
(a price Forge/Atlas display that the canonical transaction-processing
path can actually enforce and charge) requires either wiring RPC to stack
(2), or porting this fee market into stack (1)'s `ProofOfSynergy` /
`WALLET_MANAGER` charging path, or a decision to retire one stack in favor
of the other. See the deliverables report for the full analysis; this is
the single largest remaining blocker from this change.
