# SNRG Denominations & Gas Calculation Specification (Synergy Network)

This document defines how **SNRG** amounts and **gas fees** are represented and converted in Synergy tooling (Portal, RPC clients, explorers), including practical conversions to EVM-style units.

## 1) Core Units

### 1.1 SNRG (display unit)
- **Symbol:** `SNRG`
- **Purpose:** Human-facing display unit (wallet balances, fees).

### 1.2 nWei (gas/base unit)
- **Unit:** `nWei`
- **Definition:** `1 SNRG = 10^9 nWei`
- **Implication:** SNRG has **9 decimal places** when represented in its smallest unit (`nWei`).

> In other words, `nWei` is to `SNRG` what “nano” is to the full token unit: `1 nWei = 0.000000001 SNRG`.

## 2) Gas Calculation

Synergy gas uses the standard multiplication model:

- **Gas Used / Gas Limit:** an integer number of gas units
- **Gas Price:** specified in `nWei` per gas unit
- **Total Fee (in nWei):**
  - `fee_nWei = gas_limit * gas_price_nWei`
- **Total Fee (in SNRG):**
  - `fee_SNRG = fee_nWei / 10^9`

### 2.1 Display Formatting
- Gas price should be displayed in **`nWei`**.
- Total fee should be displayed in **`SNRG`** (typically with a small number of decimals, e.g. 6).
- Internally, calculations should prefer integers (base units) to avoid float rounding.

## 3) EVM Conversion Reference (Ethereum, Polygon, Arbitrum, Optimism, BSC, etc.)

Most EVM networks commonly quote gas price in **gwei**, where:

- `1 gwei = 10^9 wei`
- `1 ETH = 10^18 wei`

Synergy’s `nWei` is the same “10^-9 of the native token” scale that EVM uses for **gwei**, which allows the following practical mapping for tooling and UI comparisons:

### 3.1 Gas Price Mapping
- `gas_price_gwei (EVM)  ≈  gas_price_nWei (Synergy)`  (same numeric value)
- `gas_price_wei (EVM)   =  gas_price_nWei * 10^9`

### 3.2 Total Fee Mapping
Given `fee_nWei = gas_limit * gas_price_nWei`:
- `fee_gwei (EVM)  ≈  fee_nWei (Synergy)` (same numeric value)
- `fee_wei (EVM)   =  fee_nWei * 10^9`
- `fee_ETH (EVM)   =  fee_wei / 10^18`

> Important: The mapping above is a **denomination/format conversion**, not an economic comparison. Different networks have different native-asset market prices, so “same number of ETH” vs “same number of SNRG” does not imply same USD cost.

## 4) Implementation Notes (Portal)

- Denomination helpers live in `synergy-portal/frontend/src/utils/denominations.js`.
- The Gas Station page uses these conversions to show Synergy ↔ EVM breakdowns alongside the gas estimator.
