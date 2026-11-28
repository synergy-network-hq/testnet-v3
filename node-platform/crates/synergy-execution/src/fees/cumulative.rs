//! Native fee allocation from Economics v3.2 §§4.5, 8.6–8.9 and QACE R1 p275.
//!
//! This prepares a complete monetary projection; it neither authenticates a
//! profile nor publishes state. The caller must resolve the enduring native
//! class domain and restricted bucket bindings from authenticated actual-parent
//! state, and atomically commit application effects, these postings, carry,
//! provenance, underlying replay identity and receipt. Source and operation types
//! are generic because this module does not allocate a signing codec, SRPA,
//! account, state key or freely chosen retry identity. Historical FeeSchedule
//! settlement is intentionally unchanged. No live caller is activated here.

use primitive_types::U256;

pub const MAX_NATIVE_STOCK_NWEI: u128 = 12_000_000_000_000_000_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AllocationError {
    InvalidCarry,
    InvalidEscrowBacking,
    MissingEscrowSource,
    UnexpectedEscrowSource,
    NativeAmountOutOfRange,
    ArithmeticViolation,
    ReplayContentConflict,
    InvalidPriorReceipt,
    StaleCarry,
}

/// One actual restricted coin backs the class interests when q is nonzero.
/// This snapshot must come from authenticated state in the selected carry domain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CarrySnapshot<S> {
    pub q: u8,
    pub escrow_nwei: u128,
    pub escrow_source: Option<S>,
}

impl<S> CarrySnapshot<S> {
    pub fn validate(&self) -> Result<(), AllocationError> {
        if self.q >= 5 {
            return Err(AllocationError::InvalidCarry);
        }
        if self.escrow_nwei != u128::from(self.q != 0) {
            return Err(AllocationError::InvalidEscrowBacking);
        }
        match (self.q != 0, self.escrow_source.is_some()) {
            (true, false) => Err(AllocationError::MissingEscrowSource),
            (false, true) => Err(AllocationError::UnexpectedEscrowSource),
            _ => Ok(()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeeRequest<S, O> {
    /// Authenticated underlying operation identity, not a caller retry label.
    pub operation: O,
    pub source: S,
    /// Actual eligible charge from the independently qualified resource profile.
    pub fee_nwei: u128,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceCredit<S> {
    pub source: S,
    pub amount_nwei: u128,
}

/// Whole class credits are not individual validator rewards. At most two lots
/// occur per destination: prior escrow first, then the current eligible fee.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllocationReceipt<S, O> {
    pub request: FeeRequest<S, O>,
    pub before: CarrySnapshot<S>,
    pub after: CarrySnapshot<S>,
    pub validator_nwei: u128,
    pub treasury_nwei: u128,
    pub validator_sources: Vec<SourceCredit<S>>,
    pub treasury_sources: Vec<SourceCredit<S>>,
}

impl<S: Eq, O> AllocationReceipt<S, O> {
    /// Compare-and-swap precondition for an unapplied prepared transition.
    /// The caller must also compare the authenticated domain, payer, bucket
    /// balances and underlying replay record in the same atomic operation.
    pub fn check_parent(&self, actual: &CarrySnapshot<S>) -> Result<(), AllocationError> {
        actual.validate()?;
        if self.before != *actual {
            return Err(AllocationError::StaleCarry);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreparedAllocation<S, O> {
    /// Debit payer F and the preceding restricted coin; credit the two classes
    /// and the next restricted coin. All legs and the receipt form one delta.
    Apply(AllocationReceipt<S, O>),
    /// Return this historical receipt with no new monetary or carry effect.
    AlreadyApplied(AllocationReceipt<S, O>),
}

/// Resolve replay *before* calculating against the new parent. A committed
/// historical receipt must be supplied from the same authenticated domain and
/// replay store. Its presence is not established by untrusted request bytes.
pub fn prepare<S: Clone + Eq, O: Clone + Eq>(
    parent: &CarrySnapshot<S>,
    request: &FeeRequest<S, O>,
    committed: Option<&AllocationReceipt<S, O>>,
) -> Result<PreparedAllocation<S, O>, AllocationError> {
    if let Some(receipt) = committed {
        if receipt.request != *request {
            return Err(AllocationError::ReplayContentConflict);
        }
        let expected = calculate(&receipt.before, request)
            .map_err(|_| AllocationError::InvalidPriorReceipt)?;
        if expected != *receipt {
            return Err(AllocationError::InvalidPriorReceipt);
        }
        return Ok(PreparedAllocation::AlreadyApplied(receipt.clone()));
    }
    calculate(parent, request).map(PreparedAllocation::Apply)
}

fn calculate<S: Clone + Eq, O: Clone>(
    parent: &CarrySnapshot<S>,
    request: &FeeRequest<S, O>,
) -> Result<AllocationReceipt<S, O>, AllocationError> {
    parent.validate()?;
    // No involved stock or newly posted amount may exceed native issued stock.
    // Historical gross turnover is deliberately not stored in a stock counter.
    if request.fee_nwei > MAX_NATIVE_STOCK_NWEI
        || request
            .fee_nwei
            .checked_add(parent.escrow_nwei)
            .is_none_or(|n| n > MAX_NATIVE_STOCK_NWEI)
    {
        return Err(AllocationError::NativeAmountOutOfRange);
    }
    let q = U256::from(parent.q);
    let f = U256::from(request.fee_nwei);
    let total = q
        .checked_add(f)
        .ok_or(AllocationError::ArithmeticViolation)?;
    let five = U256::from(5);
    let four = U256::from(4);
    let validator = total
        .checked_mul(four)
        .ok_or(AllocationError::ArithmeticViolation)?
        / five
        - q.checked_mul(four)
            .ok_or(AllocationError::ArithmeticViolation)?
            / five;
    let treasury = total / five;
    let q_next = (total % five).as_u32() as u8;
    let validator_nwei = checked_native(validator)?;
    let treasury_nwei = checked_native(treasury)?;
    let escrow_nwei = u128::from(q_next != 0);
    if f.checked_add(U256::from(parent.escrow_nwei))
        != validator
            .checked_add(treasury)
            .and_then(|n| n.checked_add(U256::from(escrow_nwei)))
    {
        return Err(AllocationError::ArithmeticViolation);
    }
    let mut lots = Vec::with_capacity(2);
    if let Some(source) = &parent.escrow_source {
        lots.push(SourceCredit {
            source: source.clone(),
            amount_nwei: 1,
        });
    }
    if request.fee_nwei != 0 {
        lots.push(SourceCredit {
            source: request.source.clone(),
            amount_nwei: request.fee_nwei,
        });
    }
    let validator_sources = consume(&mut lots, validator_nwei)?;
    let treasury_sources = consume(&mut lots, treasury_nwei)?;
    let remaining = consume(&mut lots, escrow_nwei)?;
    if lots.iter().any(|lot| lot.amount_nwei != 0) || remaining.len() > 1 {
        return Err(AllocationError::ArithmeticViolation);
    }
    Ok(AllocationReceipt {
        request: request.clone(),
        before: parent.clone(),
        after: CarrySnapshot {
            q: q_next,
            escrow_nwei,
            escrow_source: remaining.first().map(|lot| lot.source.clone()),
        },
        validator_nwei,
        treasury_nwei,
        validator_sources,
        treasury_sources,
    })
}

fn checked_native(value: U256) -> Result<u128, AllocationError> {
    if value > U256::from(MAX_NATIVE_STOCK_NWEI) {
        return Err(AllocationError::NativeAmountOutOfRange);
    }
    Ok(value.as_u128())
}

fn consume<S: Clone + Eq>(
    lots: &mut [SourceCredit<S>],
    mut amount: u128,
) -> Result<Vec<SourceCredit<S>>, AllocationError> {
    let mut result: Vec<SourceCredit<S>> = Vec::with_capacity(2);
    for lot in lots {
        let take = amount.min(lot.amount_nwei);
        if take == 0 {
            continue;
        }
        lot.amount_nwei -= take;
        amount -= take;
        if let Some(prior) = result.last_mut().filter(|p| p.source == lot.source) {
            prior.amount_nwei = prior
                .amount_nwei
                .checked_add(take)
                .ok_or(AllocationError::ArithmeticViolation)?;
        } else {
            result.push(SourceCredit {
                source: lot.source.clone(),
                amount_nwei: take,
            });
        }
    }
    if amount != 0 {
        return Err(AllocationError::ArithmeticViolation);
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zero() -> CarrySnapshot<&'static str> {
        CarrySnapshot {
            q: 0,
            escrow_nwei: 0,
            escrow_source: None,
        }
    }

    fn request(
        operation: u64,
        source: &'static str,
        fee_nwei: u128,
    ) -> FeeRequest<&'static str, u64> {
        FeeRequest {
            operation,
            source,
            fee_nwei,
        }
    }

    fn allocate(
        parent: &CarrySnapshot<&'static str>,
        op: u64,
        source: &'static str,
        fee: u128,
    ) -> AllocationReceipt<&'static str, u64> {
        match prepare(parent, &request(op, source, fee), None).unwrap() {
            PreparedAllocation::Apply(receipt) => receipt,
            _ => panic!("new request was treated as replay"),
        }
    }

    #[test]
    fn canonical_one_nwei_prefixes_preserve_every_coin() {
        let mut carry = zero();
        let mut validator = 0;
        let mut treasury = 0;
        for index in 1..=5 {
            let receipt = allocate(&carry, index, "A", 1);
            assert_eq!(receipt.validator_nwei, u128::from(index != 1));
            assert_eq!(receipt.treasury_nwei, u128::from(index == 5));
            validator += receipt.validator_nwei;
            treasury += receipt.treasury_nwei;
            assert_eq!(
                validator + treasury + receipt.after.escrow_nwei,
                u128::from(index)
            );
            assert_eq!(receipt.after.q, (index % 5) as u8);
            carry = receipt.after;
        }
        assert_eq!((validator, treasury, carry.escrow_nwei), (4, 1, 0));
    }

    #[test]
    fn one_hundred_one_fee_vectors_and_prior_source_first() {
        let first = allocate(&zero(), 1, "A", 101);
        assert_eq!((first.validator_nwei, first.treasury_nwei), (80, 20));
        let second = allocate(&first.after, 2, "B", 101);
        assert_eq!((second.validator_nwei, second.treasury_nwei), (81, 20));
        assert_eq!(
            second.validator_sources,
            vec![
                SourceCredit {
                    source: "A",
                    amount_nwei: 1
                },
                SourceCredit {
                    source: "B",
                    amount_nwei: 80
                },
            ]
        );
        assert_eq!(
            second.treasury_sources,
            vec![SourceCredit {
                source: "B",
                amount_nwei: 20
            }]
        );
        assert_eq!(
            second.after,
            CarrySnapshot {
                q: 2,
                escrow_nwei: 1,
                escrow_source: Some("B")
            }
        );
        let a = allocate(&zero(), 3, "A", 1);
        let b = allocate(&a.after, 4, "B", 4);
        assert_eq!(
            b.validator_sources,
            vec![
                SourceCredit {
                    source: "A",
                    amount_nwei: 1
                },
                SourceCredit {
                    source: "B",
                    amount_nwei: 3
                },
            ]
        );
        assert_eq!(
            b.treasury_sources,
            vec![SourceCredit {
                source: "B",
                amount_nwei: 1
            }]
        );
        assert_eq!(b.after, zero());
    }

    #[test]
    fn every_small_carry_and_fee_matches_independent_prefix_and_provenance() {
        for q in 0..5_u8 {
            let parent = CarrySnapshot {
                q,
                escrow_nwei: u128::from(q != 0),
                escrow_source: (q != 0).then_some("A"),
            };
            for fee in 0..=1024_u128 {
                let r = allocate(&parent, 1, "B", fee);
                let total = u128::from(q) + fee;
                assert_eq!(r.validator_nwei, 4 * total / 5 - 4 * u128::from(q) / 5);
                assert_eq!(r.treasury_nwei, total / 5);
                assert_eq!(r.after.q, (total % 5) as u8);
                assert_eq!(
                    fee + parent.escrow_nwei,
                    r.validator_nwei + r.treasury_nwei + r.after.escrow_nwei
                );
                for source in ["A", "B"] {
                    let inflow = if source == "A" {
                        parent.escrow_nwei
                    } else {
                        fee
                    };
                    let held: u128 = r
                        .validator_sources
                        .iter()
                        .chain(&r.treasury_sources)
                        .filter(|lot| lot.source == source)
                        .map(|lot| lot.amount_nwei)
                        .sum();
                    let escrow = if r.after.escrow_source == Some(source) {
                        r.after.escrow_nwei
                    } else {
                        0
                    };
                    assert_eq!(inflow, held + escrow);
                }
                assert!(r.validator_sources.len() <= 2 && r.treasury_sources.len() <= 2);
                r.after.validate().unwrap();
            }
        }
    }

    #[test]
    fn batch_roster_and_source_changes_do_not_reset_carry() {
        let fees = [1_u128, 1, 101, 2, 3, 0, 17, 1, 9];
        let mut carry = zero();
        let mut validator = 0;
        let mut treasury = 0;
        let mut gross = 0;
        for (position, fee) in fees.into_iter().enumerate() {
            // Different source tags and arbitrary physical block boundaries
            // change neither the enduring class domain nor its exact prefix.
            let r = allocate(
                &carry,
                position as u64,
                if position % 2 == 0 { "A" } else { "B" },
                fee,
            );
            gross += fee;
            validator += r.validator_nwei;
            treasury += r.treasury_nwei;
            carry = r.after;
            assert_eq!((validator, treasury), (4 * gross / 5, gross / 5));
        }
        let aggregate = allocate(&zero(), 100, "A", gross);
        assert_eq!(
            (validator, treasury, carry.q),
            (
                aggregate.validator_nwei,
                aggregate.treasury_nwei,
                aggregate.after.q
            )
        );
        // Branch abandonment uses the unchanged parent, never a losing carry.
        let parent = allocate(&zero(), 101, "A", 1).after;
        let abandoned = allocate(&parent, 102, "B", 4);
        let retained = allocate(&parent, 103, "A", 1);
        assert_eq!(abandoned.after.q, 0);
        assert_eq!(retained.after.q, 2);
        assert_eq!(retained.check_parent(&parent), Ok(()));
        assert_eq!(
            retained.check_parent(&abandoned.after),
            Err(AllocationError::StaleCarry)
        );
    }

    #[test]
    fn historical_replay_returns_original_result_after_later_fees() {
        let req = request(1, "A", 101);
        let original = allocate(&zero(), 1, "A", 101);
        let later = allocate(&original.after, 2, "B", 7);
        assert_eq!(
            prepare(&later.after, &req, Some(&original)),
            Ok(PreparedAllocation::AlreadyApplied(original.clone()))
        );
        for changed in [
            request(1, "B", 101),
            request(1, "A", 102),
            request(3, "A", 101),
        ] {
            assert_eq!(
                prepare(&later.after, &changed, Some(&original)),
                Err(AllocationError::ReplayContentConflict)
            );
        }
        let mut corrupt = original.clone();
        corrupt.validator_sources[0].amount_nwei += 1;
        assert_eq!(
            prepare(&later.after, &req, Some(&corrupt)),
            Err(AllocationError::InvalidPriorReceipt)
        );
        corrupt = original;
        corrupt.after.escrow_source = Some("B");
        assert_eq!(
            prepare(&later.after, &req, Some(&corrupt)),
            Err(AllocationError::InvalidPriorReceipt)
        );
    }

    #[test]
    fn malformed_or_unbacked_carry_rejects_without_preparing_effects() {
        let fixtures = [
            (
                CarrySnapshot {
                    q: 5,
                    escrow_nwei: 1,
                    escrow_source: Some("A"),
                },
                AllocationError::InvalidCarry,
            ),
            (
                CarrySnapshot {
                    q: 1,
                    escrow_nwei: 0,
                    escrow_source: Some("A"),
                },
                AllocationError::InvalidEscrowBacking,
            ),
            (
                CarrySnapshot {
                    q: 0,
                    escrow_nwei: 1,
                    escrow_source: Some("A"),
                },
                AllocationError::InvalidEscrowBacking,
            ),
            (
                CarrySnapshot {
                    q: 1,
                    escrow_nwei: 1,
                    escrow_source: None,
                },
                AllocationError::MissingEscrowSource,
            ),
            (
                CarrySnapshot {
                    q: 0,
                    escrow_nwei: 0,
                    escrow_source: Some("A"),
                },
                AllocationError::UnexpectedEscrowSource,
            ),
        ];
        for (parent, error) in fixtures {
            let before = parent.clone();
            assert_eq!(prepare(&parent, &request(1, "B", 1), None), Err(error));
            assert_eq!(parent, before);
        }
    }

    #[test]
    fn checked_wide_amount_bounds_and_turnover_are_separate_from_stock() {
        let first = allocate(&zero(), 1, "A", MAX_NATIVE_STOCK_NWEI);
        assert_eq!(first.validator_nwei, 9_600_000_000_000_000_000);
        assert_eq!(first.treasury_nwei, 2_400_000_000_000_000_000);
        let returned_claim_fee = allocate(&first.after, 2, "B", first.validator_nwei);
        assert!(
            first.request.fee_nwei + returned_claim_fee.request.fee_nwei > MAX_NATIVE_STOCK_NWEI
        );
        for fee in [MAX_NATIVE_STOCK_NWEI + 1, u128::MAX] {
            assert_eq!(
                prepare(&zero(), &request(3, "A", fee), None),
                Err(AllocationError::NativeAmountOutOfRange)
            );
        }
        let backed = allocate(&zero(), 4, "A", 1).after;
        assert_eq!(
            prepare(&backed, &request(5, "B", MAX_NATIVE_STOCK_NWEI), None),
            Err(AllocationError::NativeAmountOutOfRange)
        );
        let zero_fee = allocate(&backed, 6, "B", 0);
        assert_eq!(zero_fee.after, backed);
        assert_eq!((zero_fee.validator_nwei, zero_fee.treasury_nwei), (0, 0));
    }
}
