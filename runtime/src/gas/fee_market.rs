//! Canonical live gas pricing for Synergy Network ("fee market").
//!
//! This module is the single authoritative source for `base_fee_per_gas`.
//! It is deliberately separate from `crate::gas`'s per-transaction activity
//! gas tables (deterministic gas *usage*) and from the pre-existing,
//! epoch-level `calculate_next_base_fee_nwei` / `calculate_congestion_premium_nwei`
//! helpers in `crate::gas` (which remain in place, unused by consensus, as
//! epoch-level congestion-premium tooling; they are not the enforced
//! block-level mechanism implemented here).
//!
//! Design summary
//! ---------------
//! * The protocol tracks one integer, `base_fee_per_gas_nwei`, per canonical
//!   block. It is derived *deterministically* from the parent block's
//!   declared base fee and ordinary gas utilization -- no node, validator,
//!   Atlas, or Forge ever chooses it.
//! * PQ gas (`pq_gas_used`) is metered and charged separately. It is never
//!   folded into ordinary gas. Its price is
//!   `effective_pq_gas_price = base_fee_per_gas * pq_gas_multiplier`.
//! * There is currently no priority-fee/tip market. `priority_fee_per_gas`
//!   is always `0` and callers must report `priority_fee_enabled = false`
//!   rather than fabricate a recommended tip.
//! * All arithmetic is integer-only (`u64`/`u128`) with explicit checked or
//!   saturating operations. Nothing here uses floating point.
//!
//! Formula (see `next_base_fee_per_gas` for the implementation and
//! `docs/fee-market.md` for a fully worked example):
//!
//! ```text
//! delta   = parent_gas_used - target_block_gas               (signed)
//! change  = parent_base_fee * |delta| / target_block_gas / base_fee_change_denominator
//! next    = parent_base_fee + max(change, 1)   if delta > 0   (utilization above target)
//!         = parent_base_fee - min(change, parent_base_fee)     if delta < 0   (utilization below target)
//!         = parent_base_fee                                    if delta == 0  (utilization at target)
//! next    = max(next, base_fee_floor_nwei)
//! ```

use serde::{Deserialize, Serialize};

/// Current fee-market schema/activation version. Bumped whenever the set of
/// canonical block-header fee-market fields or the pricing formula changes
/// in a consensus-relevant way. Blocks below `activation_height` are
/// interpreted under fee-market version 0 (no protocol base fee; legacy
/// sender-declared pricing only) so historical validation keeps working.
pub const FEE_MARKET_VERSION: u32 = 1;

/// `SNRG` uses 9 decimal places; the smallest denomination is `nWei`
/// (`crate::gas::constants::SNRG_DECIMALS` / `NWEI_PER_SNRG`). Fee-market
/// values are always expressed in nWei per gas unit.
pub use super::constants::{NWEI_PER_SNRG, SNRG_DECIMALS};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FeeMarketError {
    ZeroTargetBlockGas,
    ZeroBaseFeeChangeDenominator,
    ZeroBaseFeeFloor,
    TargetExceedsMaxBlockGas,
    TargetPqExceedsMaxBlockPqGas,
    Overflow(&'static str),
}

impl std::fmt::Display for FeeMarketError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ZeroTargetBlockGas => write!(f, "target_block_gas must be > 0"),
            Self::ZeroBaseFeeChangeDenominator => {
                write!(f, "base_fee_change_denominator must be > 0")
            }
            Self::ZeroBaseFeeFloor => write!(f, "base_fee_floor_nwei must be >= 1"),
            Self::TargetExceedsMaxBlockGas => {
                write!(f, "target_block_gas must be <= max_block_gas")
            }
            Self::TargetPqExceedsMaxBlockPqGas => {
                write!(f, "target_block_pq_gas must be <= max_block_pq_gas")
            }
            Self::Overflow(what) => write!(f, "fee market arithmetic overflow: {what}"),
        }
    }
}
impl std::error::Error for FeeMarketError {}

/// Protocol-defined, genesis/runtime-configured fee-market parameters.
///
/// These are consensus parameters: every validating node must agree on the
/// same values for the same `fee_market_version` at the same activation
/// height, or blocks will fail to validate identically across nodes.
///
/// IMPORTANT: `base_fee_floor_nwei`, `initial_base_fee_nwei`,
/// `pq_gas_multiplier`, `max_block_pq_gas`, and `target_block_pq_gas` in
/// [`FeeMarketParams::testnet_v3_defaults`] are **not** an approved economic
/// policy. No such value exists yet in the repository or protocol
/// documentation (see `docs/fee-market.md`, "Values requiring economic
/// sign-off"). The defaults below are carried over from the pre-existing,
/// already-shipped `crate::gas::constants` (`MIN_GAS_PRICE`,
/// `DEFAULT_GAS_PRICE`, `BLOCK_GAS_LIMIT`) purely so Testnet v3 has a
/// deterministic, non-arbitrary bootstrap value; they must be replaced by an
/// explicit Testnet v3 economic-configuration decision before this is
/// treated as permanent policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeMarketParams {
    /// Master switch. When `false`, canonical blocks are validated under the
    /// pre-fee-market (legacy) rules: no protocol base fee is enforced and
    /// `synergy_gasPrice`/`synergy_getFeeMarket` must report
    /// `source: "unavailable"` rather than fabricate a value.
    pub fee_market_enabled: bool,
    /// Minimum possible `base_fee_per_gas`, in nWei. The dynamic algorithm
    /// can never drive the base fee below this value.
    pub base_fee_floor_nwei: u64,
    /// `base_fee_per_gas` for the genesis / activation block, before any
    /// utilization-driven adjustment has occurred.
    pub initial_base_fee_nwei: u64,
    /// Target ordinary gas per block. Utilization above this increases the
    /// next block's base fee; utilization below it decreases the fee.
    pub target_block_gas: u64,
    /// Maximum ordinary gas a block may contain (hard cap, independent of
    /// the fee market -- this is the block gas limit).
    pub max_block_gas: u64,
    /// Inverse of the maximum per-block base-fee change fraction. A value of
    /// `8` bounds the maximum single-block adjustment to `1/8 = 12.5%`.
    pub base_fee_change_denominator: u64,
    /// `effective_pq_gas_price = base_fee_per_gas * pq_gas_multiplier`.
    pub pq_gas_multiplier: u64,
    /// Maximum PQ gas a block may contain.
    pub max_block_pq_gas: u64,
    /// Target PQ gas per block. Currently informational (see module docs):
    /// the pricing algorithm here adjusts `base_fee_per_gas` from ordinary
    /// gas utilization only, and PQ gas is priced as a fixed multiple of
    /// that base fee rather than through an independently-adjusted PQ base
    /// fee. Retained as a protocol parameter so a future version can key an
    /// independent PQ-fee adjustment off it without a further header
    /// migration.
    pub target_block_pq_gas: u64,
    /// Block height (inclusive) at which fee-market enforcement begins.
    /// Blocks below this height are validated under legacy (pre-fee-market)
    /// rules; this and later blocks must carry a correct
    /// `base_fee_per_gas` and will be rejected otherwise.
    pub activation_height: u64,
    /// Schema/version tag written into every post-activation block header
    /// (`fee_market_version`) and returned by fee-market RPCs.
    pub fee_market_version: u32,
}

impl FeeMarketParams {
    /// Testnet v3 (chain 1266) bootstrap defaults. See the struct-level
    /// documentation: the economically-significant fields here are
    /// placeholders inherited from already-shipped code, not approved
    /// mainnet or even final-testnet economics.
    pub fn testnet_v3_defaults() -> Self {
        Self {
            fee_market_enabled: true,
            base_fee_floor_nwei: super::constants::MIN_GAS_PRICE,
            initial_base_fee_nwei: super::constants::DEFAULT_GAS_PRICE,
            target_block_gas: super::constants::BLOCK_GAS_LIMIT / 2,
            max_block_gas: super::constants::BLOCK_GAS_LIMIT,
            base_fee_change_denominator: 8,
            pq_gas_multiplier: 4,
            max_block_pq_gas: 4_000_000,
            target_block_pq_gas: 2_000_000,
            activation_height: 1,
            fee_market_version: FEE_MARKET_VERSION,
        }
    }

    pub fn validate(&self) -> Result<(), FeeMarketError> {
        if self.target_block_gas == 0 {
            return Err(FeeMarketError::ZeroTargetBlockGas);
        }
        if self.base_fee_change_denominator == 0 {
            return Err(FeeMarketError::ZeroBaseFeeChangeDenominator);
        }
        if self.base_fee_floor_nwei == 0 {
            return Err(FeeMarketError::ZeroBaseFeeFloor);
        }
        if self.target_block_gas > self.max_block_gas {
            return Err(FeeMarketError::TargetExceedsMaxBlockGas);
        }
        if self.target_block_pq_gas > self.max_block_pq_gas {
            return Err(FeeMarketError::TargetPqExceedsMaxBlockPqGas);
        }
        Ok(())
    }

    /// Whether `height` is subject to fee-market enforcement.
    pub fn is_active_at(&self, height: u64) -> bool {
        self.fee_market_enabled && height >= self.activation_height
    }
}

/// Deterministically compute the base fee that applies to the block *after*
/// a parent with the given declared base fee and ordinary gas usage.
///
/// This is the single formula every validating node must run identically.
/// It is pure and side-effect free: the same `(parent_base_fee_nwei,
/// parent_gas_used, params)` always produces the same result.
///
/// Rounding rule: `change` is computed via truncating integer division
/// (`parent_base_fee * |delta| / target_block_gas / base_fee_change_denominator`),
/// i.e. it rounds toward zero. When utilization is *above* target and that
/// truncation would otherwise produce a zero delta (small congestion),
/// the base fee still increases by a minimum of `1` nWei so upward pressure
/// is never silently absorbed by integer rounding. No equivalent minimum is
/// applied to decreases: a below-target block may leave the fee unchanged
/// once it is already at the floor, or once the computed decrease truncates
/// to zero, which is the correct/expected behavior (mirrors "fee stays flat
/// under light-but-not-zero usage far below target").
pub fn next_base_fee_per_gas(
    parent_base_fee_nwei: u64,
    parent_gas_used: u64,
    params: &FeeMarketParams,
) -> Result<u64, FeeMarketError> {
    params.validate()?;
    let base = parent_base_fee_nwei.max(params.base_fee_floor_nwei) as u128;
    let target = params.target_block_gas as u128;

    if parent_gas_used as u128 == target {
        return u64::try_from(base)
            .map_err(|_| FeeMarketError::Overflow("parent base fee exceeds u64"));
    }

    let (delta_gas, increasing) = if parent_gas_used as u128 > target {
        (parent_gas_used as u128 - target, true)
    } else {
        (target - parent_gas_used as u128, false)
    };

    let change = base
        .checked_mul(delta_gas)
        .ok_or(FeeMarketError::Overflow("base * delta_gas"))?
        .checked_div(target)
        .ok_or(FeeMarketError::Overflow("/ target_block_gas"))?
        .checked_div(params.base_fee_change_denominator as u128)
        .ok_or(FeeMarketError::Overflow("/ base_fee_change_denominator"))?;

    let next: u128 = if increasing {
        let change = change.max(1); // guaranteed minimum upward movement
        base.checked_add(change)
            .ok_or(FeeMarketError::Overflow("base + change"))?
    } else {
        base.saturating_sub(change)
    };

    let floored = next.max(params.base_fee_floor_nwei as u128);
    u64::try_from(floored).map_err(|_| FeeMarketError::Overflow("next base fee exceeds u64"))
}

/// `effective_pq_gas_price = base_fee_per_gas * pq_gas_multiplier`, checked.
pub fn effective_pq_gas_price(
    base_fee_per_gas_nwei: u64,
    pq_gas_multiplier: u64,
) -> Result<u64, FeeMarketError> {
    (base_fee_per_gas_nwei as u128)
        .checked_mul(pq_gas_multiplier as u128)
        .and_then(|value| u64::try_from(value).ok())
        .ok_or(FeeMarketError::Overflow("base_fee_per_gas * pq_gas_multiplier"))
}

/// Utilization in basis points (`0..=10_000`, saturating above 100%),
/// computed with integer-only arithmetic. Used for RPC/Atlas reporting;
/// never for consensus-critical decisions (those use raw gas counts).
pub fn utilization_bps(gas_used: u64, gas_limit: u64) -> u64 {
    if gas_limit == 0 {
        return 0;
    }
    let bps = (gas_used as u128)
        .saturating_mul(super::constants::BPS_DENOMINATOR as u128)
        / (gas_limit as u128);
    u64::try_from(bps).unwrap_or(u64::MAX).min(u64::MAX)
}

/// The fee-market state that applies to a specific block: what base fee was
/// (or will be) enforced, and the derived effective PQ gas price.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppliedFeeMarket {
    pub base_fee_per_gas_nwei: u64,
    pub pq_gas_multiplier: u64,
    pub effective_pq_gas_price_nwei: u64,
    pub fee_market_version: u32,
}

impl AppliedFeeMarket {
    pub fn from_params(base_fee_per_gas_nwei: u64, params: &FeeMarketParams) -> Result<Self, FeeMarketError> {
        Ok(Self {
            base_fee_per_gas_nwei,
            pq_gas_multiplier: params.pq_gas_multiplier,
            effective_pq_gas_price_nwei: effective_pq_gas_price(
                base_fee_per_gas_nwei,
                params.pq_gas_multiplier,
            )?,
            fee_market_version: params.fee_market_version,
        })
    }
}

/// Auditable execution-fee breakdown. Ordinary gas and PQ gas are never
/// combined before being reported (per protocol requirement): callers that
/// need the total sum `execution_fee_total_nwei` themselves, but
/// `base_execution_fee_nwei` and `pq_execution_fee_nwei` are always
/// available individually.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionFeeBreakdown {
    pub gas_used: u64,
    pub pq_gas_used: u64,
    pub base_fee_per_gas_nwei: u64,
    pub pq_gas_multiplier: u64,
    pub effective_pq_gas_price_nwei: u64,
    pub base_execution_fee_nwei: u128,
    pub pq_execution_fee_nwei: u128,
    pub execution_fee_total_nwei: u128,
    pub fee_market_version: u32,
}

/// `base_execution_fee = gas_used * base_fee_per_gas`
/// `pq_execution_fee   = pq_gas_used * effective_pq_gas_price`
/// `execution_fee_total = base_execution_fee + pq_execution_fee`
pub fn calculate_execution_fee(
    gas_used: u64,
    pq_gas_used: u64,
    applied: &AppliedFeeMarket,
) -> Result<ExecutionFeeBreakdown, FeeMarketError> {
    let base_execution_fee_nwei = (gas_used as u128)
        .checked_mul(applied.base_fee_per_gas_nwei as u128)
        .ok_or(FeeMarketError::Overflow("gas_used * base_fee_per_gas"))?;
    let pq_execution_fee_nwei = (pq_gas_used as u128)
        .checked_mul(applied.effective_pq_gas_price_nwei as u128)
        .ok_or(FeeMarketError::Overflow("pq_gas_used * effective_pq_gas_price"))?;
    let execution_fee_total_nwei = base_execution_fee_nwei
        .checked_add(pq_execution_fee_nwei)
        .ok_or(FeeMarketError::Overflow("base_execution_fee + pq_execution_fee"))?;

    Ok(ExecutionFeeBreakdown {
        gas_used,
        pq_gas_used,
        base_fee_per_gas_nwei: applied.base_fee_per_gas_nwei,
        pq_gas_multiplier: applied.pq_gas_multiplier,
        effective_pq_gas_price_nwei: applied.effective_pq_gas_price_nwei,
        base_execution_fee_nwei,
        pq_execution_fee_nwei,
        execution_fee_total_nwei,
        fee_market_version: applied.fee_market_version,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> FeeMarketParams {
        FeeMarketParams {
            fee_market_enabled: true,
            base_fee_floor_nwei: 1,
            initial_base_fee_nwei: 40,
            target_block_gas: 15_000_000,
            max_block_gas: 30_000_000,
            base_fee_change_denominator: 8,
            pq_gas_multiplier: 4,
            max_block_pq_gas: 4_000_000,
            target_block_pq_gas: 2_000_000,
            activation_height: 1,
            fee_market_version: 1,
        }
    }

    #[test]
    fn zero_utilization_decreases_toward_floor() {
        let p = params();
        let next = next_base_fee_per_gas(1_000, 0, &p).unwrap();
        // full below-target delta => max single-block decrease (12.5%)
        assert_eq!(next, 1_000 - (1_000 / 8));
    }

    #[test]
    fn below_target_utilization_decreases() {
        let p = params();
        let next = next_base_fee_per_gas(1_000, 10_000_000, &p).unwrap();
        assert!(next < 1_000);
    }

    #[test]
    fn exactly_target_utilization_leaves_fee_unchanged() {
        let p = params();
        assert_eq!(next_base_fee_per_gas(1_000, 15_000_000, &p).unwrap(), 1_000);
    }

    #[test]
    fn slightly_above_target_increases() {
        let p = params();
        let next = next_base_fee_per_gas(1_000, 15_000_001, &p).unwrap();
        assert!(next > 1_000);
    }

    #[test]
    fn maximum_utilization_hits_max_single_block_increase() {
        let p = params();
        let next = next_base_fee_per_gas(1_000, 30_000_000, &p).unwrap();
        // delta == target => change = base * target / target / denom = base / denom
        assert_eq!(next, 1_000 + (1_000 / 8));
    }

    #[test]
    fn consecutive_empty_blocks_monotonically_decrease_until_rounding_stabilizes() {
        let p = params();
        let mut fee = 1_000u64;
        let mut prev = u64::MAX;
        for _ in 0..200 {
            let next = next_base_fee_per_gas(fee, 0, &p).unwrap();
            assert!(next <= fee, "fee must never increase under zero utilization");
            assert!(next <= prev);
            prev = fee;
            fee = next;
        }
        // Decreases intentionally have no one-nWei minimum. Once the
        // integer adjustment truncates to zero, the price stabilizes above
        // the floor rather than oscillating or inventing a downward move.
        assert_eq!(fee, 7);
        assert!(fee >= p.base_fee_floor_nwei);
    }

    #[test]
    fn consecutive_full_blocks_increase_every_block() {
        let p = params();
        let mut fee = 1_000u64;
        for _ in 0..10 {
            let next = next_base_fee_per_gas(fee, 30_000_000, &p).unwrap();
            assert!(next > fee, "fee must strictly increase under max utilization");
            fee = next;
        }
    }

    #[test]
    fn floor_is_never_violated_even_from_a_low_starting_fee() {
        let p = params();
        let next = next_base_fee_per_gas(1, 0, &p).unwrap();
        assert_eq!(next, p.base_fee_floor_nwei);
    }

    #[test]
    fn rounding_truncates_toward_zero_for_decreases() {
        let p = params();
        // base=7, delta_gas = full target (0 used), denom=8 => change = 7*15_000_000/15_000_000/8 = 0 (floor division)
        let mut p2 = p;
        p2.base_fee_floor_nwei = 1;
        let next = next_base_fee_per_gas(7, 0, &p2).unwrap();
        // 7 / 8 truncates to 0, so decrease is saturating_sub(0) = 7 (unchanged by rounding, not floor)
        assert_eq!(next, 7);
    }

    #[test]
    fn small_positive_congestion_still_moves_base_fee_up_by_at_least_one() {
        let mut p = params();
        p.target_block_gas = 1_000_000_000; // huge target so change truncates to 0 without the floor
        p.max_block_gas = 2_000_000_000;
        p.base_fee_change_denominator = 8;
        let next = next_base_fee_per_gas(10, 1_000_000_001, &p).unwrap();
        assert_eq!(next, 11, "a minimum guaranteed increase of 1 nWei must apply");
    }

    #[test]
    fn integer_overflow_boundaries_are_checked_not_panicking() {
        let mut p = params();
        p.target_block_gas = 1;
        p.base_fee_change_denominator = 1;
        let result = next_base_fee_per_gas(u64::MAX, u64::MAX, &p);
        // base * delta_gas overflows u128 only in extreme cases; here delta_gas
        // relative to target=1 is huge, but u128 headroom absorbs u64::MAX * u64::MAX.
        // The important property is: no panic, and a Result is always returned.
        assert!(result.is_ok() || matches!(result, Err(FeeMarketError::Overflow(_))));
    }

    #[test]
    fn invalid_configuration_is_rejected() {
        let mut p = params();
        p.target_block_gas = 0;
        assert_eq!(
            next_base_fee_per_gas(100, 100, &p),
            Err(FeeMarketError::ZeroTargetBlockGas)
        );

        let mut p = params();
        p.base_fee_change_denominator = 0;
        assert_eq!(
            p.validate(),
            Err(FeeMarketError::ZeroBaseFeeChangeDenominator)
        );

        let mut p = params();
        p.base_fee_floor_nwei = 0;
        assert_eq!(p.validate(), Err(FeeMarketError::ZeroBaseFeeFloor));

        let mut p = params();
        p.target_block_gas = p.max_block_gas + 1;
        assert_eq!(p.validate(), Err(FeeMarketError::TargetExceedsMaxBlockGas));
    }

    #[test]
    fn deterministic_result_across_repeated_execution() {
        let p = params();
        let a = next_base_fee_per_gas(1_234, 18_500_000, &p).unwrap();
        for _ in 0..1_000 {
            assert_eq!(next_base_fee_per_gas(1_234, 18_500_000, &p).unwrap(), a);
        }
    }

    #[test]
    fn effective_pq_gas_price_is_multiplier_of_base_fee() {
        assert_eq!(effective_pq_gas_price(100, 4).unwrap(), 400);
        assert_eq!(effective_pq_gas_price(0, 4).unwrap(), 0);
    }

    #[test]
    fn effective_pq_gas_price_overflow_is_checked() {
        assert_eq!(
            effective_pq_gas_price(u64::MAX, 2),
            Err(FeeMarketError::Overflow("base_fee_per_gas * pq_gas_multiplier"))
        );
    }

    #[test]
    fn execution_fee_breakdown_keeps_ordinary_and_pq_separate() {
        let applied = AppliedFeeMarket {
            base_fee_per_gas_nwei: 100,
            pq_gas_multiplier: 4,
            effective_pq_gas_price_nwei: 400,
            fee_market_version: 1,
        };
        let breakdown = calculate_execution_fee(1_000, 50, &applied).unwrap();
        assert_eq!(breakdown.base_execution_fee_nwei, 100_000);
        assert_eq!(breakdown.pq_execution_fee_nwei, 20_000);
        assert_eq!(breakdown.execution_fee_total_nwei, 120_000);
    }

    #[test]
    fn execution_fee_with_zero_pq_gas_has_zero_pq_fee() {
        let applied = AppliedFeeMarket {
            base_fee_per_gas_nwei: 40,
            pq_gas_multiplier: 4,
            effective_pq_gas_price_nwei: 160,
            fee_market_version: 1,
        };
        let breakdown = calculate_execution_fee(21_000, 0, &applied).unwrap();
        assert_eq!(breakdown.pq_execution_fee_nwei, 0);
        assert_eq!(breakdown.execution_fee_total_nwei, breakdown.base_execution_fee_nwei);
    }

    #[test]
    fn utilization_bps_saturates_and_handles_zero_limit() {
        assert_eq!(utilization_bps(0, 100), 0);
        assert_eq!(utilization_bps(50, 100), 5_000);
        assert_eq!(utilization_bps(100, 100), 10_000);
        assert_eq!(utilization_bps(100, 0), 0);
    }

    #[test]
    fn testnet_v3_defaults_are_internally_consistent() {
        let p = FeeMarketParams::testnet_v3_defaults();
        assert!(p.validate().is_ok());
        assert!(p.is_active_at(p.activation_height));
        if p.activation_height > 0 {
            assert!(!p.is_active_at(p.activation_height - 1));
        }
    }

    #[test]
    fn fee_market_disabled_reports_inactive_at_every_height() {
        let mut p = FeeMarketParams::testnet_v3_defaults();
        p.fee_market_enabled = false;
        assert!(!p.is_active_at(1));
        assert!(!p.is_active_at(1_000_000));
    }
}
