//! Native fee postings prepared against the actual ordered state. This data is
//! not execution/finality authority; caller commits it WITH effects and replay.
use crate::cumulative::{
    self, AllocationReceipt, CarrySnapshot, FeeRequest, PreparedAllocation, SourceCredit,
};
use synergy_address::r1_public::TransactionIdentifierPresentation;
use synergy_protocol_types::{
    c14n02::{Decoder, Encoder},
    R1NetworkRef,
};
use synergy_state::{
    r1::{
        R1StateDomain, R1StateError, R1StateKey, R1StateMap, R1StateOwner, R1StateValue,
        RestrictedRecordKind,
    },
    r1_fees::{self as stored, R1FeeCarry, R1FeeSource},
};
const MAX_RECORD: usize = 8192;
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FeeError {
    State(R1StateError),
    Encoding,
    Replay,
    Provenance,
    Arithmetic,
    Unfunded,
}
impl From<R1StateError> for FeeError {
    fn from(e: R1StateError) -> Self {
        Self::State(e)
    }
}
impl From<synergy_protocol_types::c14n02::Error> for FeeError {
    fn from(_: synergy_protocol_types::c14n02::Error) -> Self {
        Self::Encoding
    }
}
#[derive(Clone, Debug)]
pub struct R1FeeOrigin {
    pub source: R1FeeSource,
    pub fee_nwei: u128,
    pub before: R1FeeCarry,
    pub after: R1FeeCarry,
    pub validator_nwei: u128,
    pub treasury_nwei: u128,
    pub validator_sources: Vec<SourceCredit<R1FeeSource>>,
    pub treasury_sources: Vec<SourceCredit<R1FeeSource>>,
    pub pre_state_root: [u8; 48],
    pub position: u32,
    pub receipt_commitment: [u8; 48],
}
fn encode_credit(
    e: &mut Encoder,
    c: &SourceCredit<R1FeeSource>,
) -> Result<(), synergy_protocol_types::c14n02::Error> {
    c.source
        .encode_into(e)
        .map_err(|_| synergy_protocol_types::c14n02::Error::InvalidAscii)?;
    e.u128(c.amount_nwei)
}
fn decode_credit(
    d: &mut Decoder<'_>,
) -> Result<SourceCredit<R1FeeSource>, synergy_protocol_types::c14n02::Error> {
    Ok(SourceCredit {
        source: R1FeeSource::decode_from(d)
            .map_err(|_| synergy_protocol_types::c14n02::Error::InvalidAscii)?,
        amount_nwei: d.u128()?,
    })
}
impl R1FeeOrigin {
    pub fn allocation(&self) -> Result<AllocationReceipt<R1FeeSource, String>, FeeError> {
        let before = CarrySnapshot {
            q: self.before.q,
            escrow_nwei: u128::from(self.before.q != 0),
            escrow_source: self.before.source.clone(),
        };
        let request = FeeRequest {
            operation: self.source.operation.to_text(),
            source: self.source.clone(),
            fee_nwei: self.fee_nwei,
        };
        let PreparedAllocation::Apply(a) =
            cumulative::prepare(&before, &request, None).map_err(|_| FeeError::Provenance)?
        else {
            return Err(FeeError::Provenance);
        };
        if a.after.q != self.after.q
            || a.after.escrow_source != self.after.source
            || a.validator_nwei != self.validator_nwei
            || a.treasury_nwei != self.treasury_nwei
            || a.validator_sources != self.validator_sources
            || a.treasury_sources != self.treasury_sources
        {
            return Err(FeeError::Provenance);
        };
        Ok(a)
    }
    pub fn canonical_bytes(&self, n: R1NetworkRef) -> Result<Vec<u8>, FeeError> {
        self.allocation()?;
        let mut e = Encoder::new(MAX_RECORD);
        e.u16(3)?;
        e.u64(n.chain_id)?;
        e.fixed(&n.nic)?;
        self.source.encode_into(&mut e)?;
        e.u128(self.fee_nwei)?;
        e.bytes(&self.before.canonical_bytes(n)?, 512)?;
        e.bytes(&self.after.canonical_bytes(n)?, 512)?;
        e.u128(self.validator_nwei)?;
        e.u128(self.treasury_nwei)?;
        e.vector(&self.validator_sources, 2, encode_credit)?;
        e.vector(&self.treasury_sources, 2, encode_credit)?;
        e.fixed(&self.pre_state_root)?;
        e.u32(self.position)?;
        e.fixed(&self.receipt_commitment)?;
        Ok(e.finish()?)
    }
    pub fn decode(bytes: &[u8], n: R1NetworkRef) -> Result<Self, FeeError> {
        let mut d = Decoder::new(bytes, MAX_RECORD)?;
        if d.u16()? != 3 || d.u64()? != n.chain_id || d.fixed::<64>()? != n.nic {
            return Err(FeeError::Encoding);
        };
        let out = Self {
            source: R1FeeSource::decode_from(&mut d)?,
            fee_nwei: d.u128()?,
            before: R1FeeCarry::decode(d.bytes(512)?, n)?,
            after: R1FeeCarry::decode(d.bytes(512)?, n)?,
            validator_nwei: d.u128()?,
            treasury_nwei: d.u128()?,
            validator_sources: d.vector(2, 118, decode_credit)?,
            treasury_sources: d.vector(2, 118, decode_credit)?,
            pre_state_root: d.fixed()?,
            position: d.u32()?,
            receipt_commitment: d.fixed()?,
        };
        d.finish()?;
        if out.canonical_bytes(n)? != bytes {
            return Err(FeeError::Encoding);
        };
        Ok(out)
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct Lot {
    source: R1FeeSource,
    class: u8,
    credited: u128,
    disbursed: u128,
}
impl Lot {
    fn bytes(&self, n: R1NetworkRef) -> Result<Vec<u8>, FeeError> {
        if self.class > 1
            || self.disbursed > self.credited
            || self.credited > cumulative::MAX_NATIVE_STOCK_NWEI
        {
            return Err(FeeError::Provenance);
        };
        let mut e = Encoder::new(512);
        e.u16(2)?;
        e.u64(n.chain_id)?;
        e.fixed(&n.nic)?;
        e.u8(self.class)?;
        self.source.encode_into(&mut e)?;
        e.u128(self.credited)?;
        e.u128(self.disbursed)?;
        Ok(e.finish()?)
    }
    fn decode(bytes: &[u8], n: R1NetworkRef) -> Result<Self, FeeError> {
        let mut d = Decoder::new(bytes, 512)?;
        if d.u16()? != 2 || d.u64()? != n.chain_id || d.fixed::<64>()? != n.nic {
            return Err(FeeError::Encoding);
        };
        let out = Self {
            class: d.u8()?,
            source: R1FeeSource::decode_from(&mut d)?,
            credited: d.u128()?,
            disbursed: d.u128()?,
        };
        d.finish()?;
        if out.bytes(n)? != bytes {
            return Err(FeeError::Encoding);
        };
        Ok(out)
    }
}
fn protocol_key(
    prefix: &[u8],
    tx: &TransactionIdentifierPresentation,
    class: Option<u8>,
) -> R1StateKey {
    let mut local = prefix.to_vec();
    if let Some(c) = class {
        local.push(c)
    };
    local.push(u8::from(tx.to_text().starts_with("synxxn")));
    local.extend_from_slice(tx.digest48());
    R1StateKey {
        domain: R1StateDomain::ProtocolConfiguration,
        owner: R1StateOwner::Protocol,
        local_key: local,
    }
}
fn origin_key(tx: &TransactionIdentifierPresentation) -> R1StateKey {
    protocol_key(b"native-fee/origin/", tx, None)
}
fn lot_key(tx: &TransactionIdentifierPresentation, class: u8) -> R1StateKey {
    protocol_key(b"native-fee/source/", tx, Some(class))
}
fn record(bytes: Vec<u8>) -> R1StateValue {
    R1StateValue::ProtocolRecord {
        profile_name: stored::PROFILE_NAME.into(),
        profile_revision: 1,
        canonical_bytes: bytes,
    }
}
fn record_bytes<'a>(state: &'a R1StateMap, key: &R1StateKey) -> Result<Option<&'a [u8]>, FeeError> {
    match state.get(key) {
        None => Ok(None),
        Some(R1StateValue::ProtocolRecord {
            profile_name,
            profile_revision: 1,
            canonical_bytes,
        }) if profile_name == stored::PROFILE_NAME => Ok(Some(canonical_bytes)),
        _ => Err(FeeError::Provenance),
    }
}
fn read_lot(
    state: &R1StateMap,
    n: R1NetworkRef,
    source: &R1FeeSource,
    class: u8,
) -> Result<Lot, FeeError> {
    let Some(b) = record_bytes(state, &lot_key(&source.operation, class))? else {
        return Ok(Lot {
            source: source.clone(),
            class,
            credited: 0,
            disbursed: 0,
        });
    };
    let lot = Lot::decode(b, n)?;
    if lot.source != *source || lot.class != class {
        return Err(FeeError::Provenance);
    };
    Ok(lot)
}
fn prior_origin(
    state: &R1StateMap,
    n: R1NetworkRef,
    source: &R1FeeSource,
) -> Result<R1FeeOrigin, FeeError> {
    let bytes = record_bytes(state, &origin_key(&source.operation))?.ok_or(FeeError::Provenance)?;
    let out = R1FeeOrigin::decode(bytes, n)?;
    if out.source != *source || out.fee_nwei == 0 {
        return Err(FeeError::Provenance);
    };
    Ok(out)
}
#[derive(Clone, Debug)]
pub struct R1FeeSettlementPlan {
    pub changes: Vec<(R1StateKey, Option<R1StateValue>)>,
    pub origin: R1FeeOrigin,
}
/// Computes complete class postings and canonical source history. No payer debit
/// happens here: the execution owner includes that debit, application/nonce and
/// these changes in the SAME atomic state batch. Existing origins reject repeat
/// inclusion; historical API responses come from the original receipt.
pub fn prepare_settlement(
    state: &R1StateMap,
    n: R1NetworkRef,
    source: R1FeeSource,
    fee_nwei: u128,
    pre_state_root: [u8; 48],
    position: u32,
    receipt_commitment: [u8; 48],
) -> Result<R1FeeSettlementPlan, FeeError> {
    if state.get(&origin_key(&source.operation)).is_some() {
        return Err(FeeError::Replay);
    };
    let old = stored::read_fee_state(state, n)?;
    if old
        .carry
        .source
        .as_ref()
        .is_some_and(|s| s.operation == source.operation)
    {
        return Err(FeeError::Provenance);
    };
    let before = CarrySnapshot {
        q: old.carry.q,
        escrow_nwei: old.escrow_nwei,
        escrow_source: old.carry.source.clone(),
    };
    let request = FeeRequest {
        operation: source.operation.to_text(),
        source: source.clone(),
        fee_nwei,
    };
    let PreparedAllocation::Apply(a) =
        cumulative::prepare(&before, &request, None).map_err(|_| FeeError::Arithmetic)?
    else {
        return Err(FeeError::Replay);
    };
    let origin = R1FeeOrigin {
        source: source.clone(),
        fee_nwei,
        before: old.carry.clone(),
        after: R1FeeCarry {
            q: a.after.q,
            source: a.after.escrow_source.clone(),
        },
        validator_nwei: a.validator_nwei,
        treasury_nwei: a.treasury_nwei,
        validator_sources: a.validator_sources.clone(),
        treasury_sources: a.treasury_sources.clone(),
        pre_state_root,
        position,
        receipt_commitment,
    };
    let v = old
        .validator_class_nwei
        .checked_add(a.validator_nwei)
        .filter(|n| *n <= cumulative::MAX_NATIVE_STOCK_NWEI)
        .ok_or(FeeError::Arithmetic)?;
    let t = old
        .treasury_nwei
        .checked_add(a.treasury_nwei)
        .filter(|n| *n <= cumulative::MAX_NATIVE_STOCK_NWEI)
        .ok_or(FeeError::Arithmetic)?;
    let mut changes = vec![
        (stored::carry_key(), Some(origin.after.state_value(n)?)),
        (
            stored::validator_class_key(),
            Some(R1StateValue::ValidatorFunding { amount_nwei: v }),
        ),
        (
            stored::restricted_key(RestrictedRecordKind::Treasury),
            Some(R1StateValue::RestrictedBalance {
                amount_nwei: t,
                policy_commitment: old.treasury_policy64.to_vec(),
            }),
        ),
        (
            stored::restricted_key(RestrictedRecordKind::FeeRoundingEscrow),
            Some(R1StateValue::RestrictedBalance {
                amount_nwei: a.after.escrow_nwei,
                policy_commitment: old.escrow_policy64.to_vec(),
            }),
        ),
    ];
    let mut sources = vec![source.clone()];
    if let Some(prior) = &old.carry.source {
        sources.push(prior.clone())
    };
    for s in sources {
        let paid = if s == source {
            fee_nwei
        } else {
            prior_origin(state, n, &s)?.fee_nwei
        };
        let mut vl = read_lot(state, n, &s, 0)?;
        let mut tl = read_lot(state, n, &s, 1)?;
        let old_backing = u128::from(old.carry.source.as_ref() == Some(&s));
        let total_before = vl
            .credited
            .checked_add(tl.credited)
            .and_then(|n| n.checked_add(old_backing))
            .ok_or(FeeError::Arithmetic)?;
        if (s == source && total_before != 0) || (s != source && total_before != paid) {
            return Err(FeeError::Provenance);
        };
        for c in &a.validator_sources {
            if c.source == s {
                vl.credited = vl
                    .credited
                    .checked_add(c.amount_nwei)
                    .ok_or(FeeError::Arithmetic)?;
            }
        }
        for c in &a.treasury_sources {
            if c.source == s {
                tl.credited = tl
                    .credited
                    .checked_add(c.amount_nwei)
                    .ok_or(FeeError::Arithmetic)?;
            }
        }
        let backing = u128::from(a.after.escrow_source.as_ref() == Some(&s));
        if vl
            .credited
            .checked_add(tl.credited)
            .and_then(|n| n.checked_add(backing))
            != Some(paid)
        {
            return Err(FeeError::Provenance);
        };
        if vl.credited != 0 {
            changes.push((lot_key(&s.operation, 0), Some(record(vl.bytes(n)?))))
        };
        if tl.credited != 0 {
            changes.push((lot_key(&s.operation, 1), Some(record(tl.bytes(n)?))))
        };
    }
    changes.push((
        origin_key(&source.operation),
        Some(record(origin.canonical_bytes(n)?)),
    ));
    Ok(R1FeeSettlementPlan { changes, origin })
}
#[cfg(test)]
mod tests {
    use super::*;
    use synergy_address::r1_public::NativeIdentityPresentation;
    fn n() -> R1NetworkRef {
        R1NetworkRef {
            chain_id: u64::MAX - 1,
            nic: [13; 64],
        }
    }
    fn source(i: u8) -> R1FeeSource {
        R1FeeSource {
            operation: TransactionIdentifierPresentation::from_digest("syntxn", [i; 48]).unwrap(),
            payer: NativeIdentityPresentation::from_raw("syns", [i; 48]).unwrap(),
        }
    }
    fn initial() -> R1StateMap {
        let mut s = R1StateMap::new();
        stored::initialize_genesis(&mut s, n()).unwrap();
        for r in [
            RestrictedRecordKind::Treasury,
            RestrictedRecordKind::FeeRoundingEscrow,
        ] {
            s.insert(
                stored::restricted_key(r),
                R1StateValue::RestrictedBalance {
                    amount_nwei: 0,
                    policy_commitment: vec![7; 64],
                },
            )
            .unwrap();
        }
        s
    }
    #[test]
    fn five_small_fees_preserve_all_original_sources_and_backing() {
        let mut s = initial();
        let mut receipts = Vec::new();
        for i in 1..=5 {
            let plan =
                prepare_settlement(&s, n(), source(i), 1, s.root().unwrap(), i as u32, [i; 48])
                    .unwrap();
            let b = plan.origin.canonical_bytes(n()).unwrap();
            assert_eq!(R1FeeOrigin::decode(&b, n()).unwrap().fee_nwei, 1);
            s.apply_batch(&plan.changes).unwrap();
            receipts.push(b);
        }
        let v = stored::read_fee_state(&s, n()).unwrap();
        assert_eq!(
            (
                v.validator_class_nwei,
                v.treasury_nwei,
                v.escrow_nwei,
                v.carry.q
            ),
            (4, 1, 0, 0)
        );
        for i in 1..=5 {
            let vl = read_lot(&s, n(), &source(i), 0).unwrap();
            let tl = read_lot(&s, n(), &source(i), 1).unwrap();
            assert_eq!(vl.credited + tl.credited, 1);
        }
        let before = s.clone();
        assert!(matches!(
            prepare_settlement(&s, n(), source(1), 1, [0; 48], 99, [0; 48]),
            Err(FeeError::Replay)
        ));
        assert_eq!(s, before);
        assert_eq!(
            record_bytes(&s, &origin_key(&source(1).operation))
                .unwrap()
                .unwrap(),
            receipts[0]
        );
    }
    #[test]
    fn missing_provenance_or_unbacked_carry_rejects_without_partial_money() {
        let mut s = initial();
        let p = prepare_settlement(&s, n(), source(1), 1, s.root().unwrap(), 0, [2; 48]).unwrap();
        s.apply_batch(&p.changes).unwrap();
        s.remove(&origin_key(&source(1).operation));
        let before = s.clone();
        assert_eq!(
            prepare_settlement(&s, n(), source(2), 4, [0; 48], 1, [0; 48]).err(),
            Some(FeeError::Provenance)
        );
        assert_eq!(s, before);
    }
    #[test]
    fn prior_escrow_lot_is_used_first_and_survives_branch_discard() {
        let parent = initial();
        let p = prepare_settlement(
            &parent,
            n(),
            source(1),
            1,
            parent.root().unwrap(),
            0,
            [1; 48],
        )
        .unwrap();
        let mut branch = parent.clone();
        branch.apply_batch(&p.changes).unwrap();
        let p = prepare_settlement(
            &branch,
            n(),
            source(2),
            4,
            branch.root().unwrap(),
            1,
            [2; 48],
        )
        .unwrap();
        branch.apply_batch(&p.changes).unwrap();
        assert_eq!(read_lot(&branch, n(), &source(1), 0).unwrap().credited, 1);
        assert_eq!(read_lot(&branch, n(), &source(2), 0).unwrap().credited, 3);
        assert_eq!(read_lot(&branch, n(), &source(2), 1).unwrap().credited, 1);
        assert_eq!(stored::read_fee_state(&parent, n()).unwrap().carry.q, 0);
        assert!(record_bytes(&parent, &origin_key(&source(1).operation))
            .unwrap()
            .is_none());
    }
}
