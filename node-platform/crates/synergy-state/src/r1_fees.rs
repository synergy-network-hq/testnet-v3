//! Typed native fee carry state. Class funding is not an individual reward.
//! No authority, persistence, collector balance or new supply is created here.
use crate::r1::{
    R1StateDomain, R1StateError, R1StateKey, R1StateMap, R1StateOwner, R1StateValue,
    RestrictedRecordKind as RestrictedRecord,
};
use synergy_address::r1_public::{NativeIdentityPresentation, TransactionIdentifierPresentation};
use synergy_protocol_types::{
    c14n02::{Decoder, Encoder},
    R1NetworkRef,
};
pub const PROFILE_NAME: &str = "SYNERGY-NATIVE-CUMULATIVE-FEES-R1";
pub const PROFILE_REVISION: u32 = 1;
pub const PROFILE_SCHEMA:&str=concat!(
 "SYNERGY-NATIVE-CUMULATIVE-FEES-R1/1;codec=QACE-C14N-02;native-nwei;ratio=4:1;noordinaryburn;",
 "domain=N+nativeasset+enduringValidatorCompensation/Treasuryclasses+ratio4:1+approved-policy-lineage;noepoch-roster-source-partition-reset;",
 "Carry=(U16(1),chain:U64,NIC64,q:U8,Option(Source));Source=(TransactionRef(U8syntxn0/synxxn1,raw48),AccountRef(ASCII8namespace,raw48));",
 "q<5;source-present-iff-q>0;actualRestrictedFeeRoundingEscrowNwei=1-iff-q>0;",
 "ClassLot=(U16(2),chain:U64,NIC64,class:U8(0validator/1Treasury),Source,credited:U128,disbursed:U128);disbursed<=credited<=native-stock;",
 "Origin=(U16(3),chain:U64,NIC64,Source,fee:U128,beforeCarry:BYTES512,afterCarry:BYTES512,validator:U128,treasury:U128,validatorCredits:VECTOR2(Credit),treasuryCredits:VECTOR2(Credit),preStateRoot48,orderedPosition:U32,originalReceiptCommit48);Credit=(Source,amount:U128);",
 "origin-key=ProtocolConfiguration/Protocol/native-fee/origin/||txKindU8||txRaw48;source-key=ProtocolConfiguration/Protocol/native-fee/source/||classU8||txKindU8||txRaw48;bothProtocolRecord(thisprofile);",
 "Origin-immutable/recomputed-exact-allocation;source-lots-preserve-original-payer/operation;credited+remaining-source-escrow=original-fee;maxOrigin8192;allrecords-full-N-bound;",

 "statekeys:ProtocolConfiguration/Protocol/native-fee/carry=ProtocolRecord(thisprofile,Carry);SystemSettlement/Protocol/native-fee/validator-class=ValidatorFunding(amountU128);",
 "Treasury-and-FeeRoundingEscrow-remain-distinct-typed-restricted-records-with-existing-policy64;",
 "q0/sourceNone/pool0-atGenesis;V=floor(4*(q+F)/5)-floor(4*q/5);T=floor((q+F)/5);qnext=(q+F)%5;",
 "oldescrow-source-first,currentfee-second;creditorder=validator,Treasury,remainingescrow;",
 "actualbalance<=12000000000000000000;checkedU256intermediate/U128posted;aggregate-turnover-not-stock-capped;",
 "application+classcredits+sourceprovenance+backing+carry+underlying-replay+originalreceipt-atomic;",
 "unallocated-class-interest-is-not-individual-earned-reward;roster-bound-earned-claims-immutable;noordinaryterminal-disposal"
);
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct R1FeeSource {
    pub operation: TransactionIdentifierPresentation,
    pub payer: NativeIdentityPresentation,
}
impl R1FeeSource {
    pub fn encode_into(&self, e: &mut Encoder) -> Result<(), R1StateError> {
        if !matches!(
            self.payer.namespace(),
            "synw" | "syns" | "syna" | "synm" | "synu" | "synq"
        ) {
            return Err(R1StateError::InvalidValue);
        }
        e.u8(u8::from(self.operation.to_text().starts_with("synxxn")))?;
        e.fixed(self.operation.digest48())?;
        e.ascii(self.payer.namespace(), 8)?;
        e.fixed(self.payer.raw48())?;
        Ok(())
    }
    pub fn decode_from(d: &mut Decoder<'_>) -> Result<Self, R1StateError> {
        let ns = match d.u8()? {
            0 => "syntxn",
            1 => "synxxn",
            _ => return Err(R1StateError::InvalidValue),
        };
        let operation = TransactionIdentifierPresentation::from_digest(ns, d.fixed()?)
            .map_err(|_| R1StateError::InvalidValue)?;
        let namespace = d.ascii(8)?;
        let payer = NativeIdentityPresentation::from_raw(namespace, d.fixed()?)
            .map_err(|_| R1StateError::InvalidValue)?;
        if !matches!(
            payer.namespace(),
            "synw" | "syns" | "syna" | "synm" | "synu" | "synq"
        ) {
            return Err(R1StateError::InvalidValue);
        }
        Ok(Self { operation, payer })
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct R1FeeCarry {
    pub q: u8,
    pub source: Option<R1FeeSource>,
}
impl R1FeeCarry {
    pub fn canonical_bytes(&self, n: R1NetworkRef) -> Result<Vec<u8>, R1StateError> {
        if n.chain_id == 0 || self.q >= 5 || (self.q != 0) != self.source.is_some() {
            return Err(R1StateError::InvalidValue);
        }
        let mut e = Encoder::new(512);
        e.u16(1)?;
        e.u64(n.chain_id)?;
        e.fixed(&n.nic)?;
        e.u8(self.q)?;
        // The encoder closure preserves its own sticky error; ownership checks above
        // and below are independent of a textual identifier's presentation.
        e.option(&self.source, |e, s| {
            s.encode_into(e)
                .map_err(|_| synergy_protocol_types::c14n02::Error::InvalidAscii)
        })?;
        Ok(e.finish()?)
    }
    pub fn decode(bytes: &[u8], expected: R1NetworkRef) -> Result<Self, R1StateError> {
        let mut d = Decoder::new(bytes, 512)?;
        if d.u16()? != 1 || d.u64()? != expected.chain_id || d.fixed::<64>()? != expected.nic {
            return Err(R1StateError::Context);
        }
        let q = d.u8()?;
        let source = match d.u8()? {
            0 => None,
            1 => Some(R1FeeSource::decode_from(&mut d)?),
            _ => return Err(R1StateError::InvalidValue),
        };
        d.finish()?;
        let out = Self { q, source };
        if out.canonical_bytes(expected)? != bytes {
            return Err(R1StateError::InvalidValue);
        }
        Ok(out)
    }
    pub fn state_value(&self, n: R1NetworkRef) -> Result<R1StateValue, R1StateError> {
        Ok(R1StateValue::ProtocolRecord {
            profile_name: PROFILE_NAME.into(),
            profile_revision: 1,
            canonical_bytes: self.canonical_bytes(n)?,
        })
    }
}
pub fn carry_key() -> R1StateKey {
    R1StateKey {
        domain: R1StateDomain::ProtocolConfiguration,
        owner: R1StateOwner::Protocol,
        local_key: b"native-fee/carry".to_vec(),
    }
}
pub fn validator_class_key() -> R1StateKey {
    R1StateKey {
        domain: R1StateDomain::SystemSettlement,
        owner: R1StateOwner::Protocol,
        local_key: b"native-fee/validator-class".to_vec(),
    }
}
pub fn restricted_key(record: RestrictedRecord) -> R1StateKey {
    R1StateKey {
        domain: R1StateDomain::SystemSettlement,
        owner: R1StateOwner::Restricted { record },
        local_key: Vec::new(),
    }
}
/// Mandatory zero-valued initial accounting, never a new funding allocation.
pub fn initialize_genesis(state: &mut R1StateMap, n: R1NetworkRef) -> Result<(), R1StateError> {
    if state.get(&carry_key()).is_some() || state.get(&validator_class_key()).is_some() {
        return Err(R1StateError::Duplicate);
    }
    state.apply_batch(&[
        (
            carry_key(),
            Some(R1FeeCarry { q: 0, source: None }.state_value(n)?),
        ),
        (
            validator_class_key(),
            Some(R1StateValue::ValidatorFunding { amount_nwei: 0 }),
        ),
    ])
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct R1FeeStateView {
    pub carry: R1FeeCarry,
    pub escrow_nwei: u128,
    pub treasury_nwei: u128,
    pub validator_class_nwei: u128,
    pub escrow_policy64: [u8; 64],
    pub treasury_policy64: [u8; 64],
}
pub fn read_fee_state(state: &R1StateMap, n: R1NetworkRef) -> Result<R1FeeStateView, R1StateError> {
    let carry = match state.get(&carry_key()) {
        Some(R1StateValue::ProtocolRecord {
            profile_name,
            profile_revision: 1,
            canonical_bytes,
        }) if profile_name == PROFILE_NAME => R1FeeCarry::decode(canonical_bytes, n)?,
        _ => return Err(R1StateError::InvalidValue),
    };
    let balance = |record| match state.get(&restricted_key(record)) {
        Some(R1StateValue::RestrictedBalance {
            amount_nwei,
            policy_commitment,
        }) => Ok((
            *amount_nwei,
            policy_commitment
                .as_slice()
                .try_into()
                .map_err(|_| R1StateError::InvalidValue)?,
        )),
        _ => Err(R1StateError::InvalidValue),
    };
    let (escrow_nwei, escrow_policy64) = balance(RestrictedRecord::FeeRoundingEscrow)?;
    let (treasury_nwei, treasury_policy64) = balance(RestrictedRecord::Treasury)?;
    let Some(R1StateValue::ValidatorFunding {
        amount_nwei: validator_class_nwei,
    }) = state.get(&validator_class_key())
    else {
        return Err(R1StateError::InvalidValue);
    };
    if escrow_nwei != u128::from(carry.q != 0)
        || treasury_nwei > 12_000_000_000_000_000_000
        || *validator_class_nwei > 12_000_000_000_000_000_000
    {
        return Err(R1StateError::InvalidValue);
    }
    Ok(R1FeeStateView {
        carry,
        escrow_nwei,
        treasury_nwei,
        validator_class_nwei: *validator_class_nwei,
        escrow_policy64,
        treasury_policy64,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    fn n() -> R1NetworkRef {
        R1NetworkRef {
            chain_id: u64::MAX - 1,
            nic: [7; 64],
        }
    }
    #[test]
    fn carry_is_exact_incarnation_bound_and_retains_original_source() {
        let c = R1FeeCarry {
            q: 4,
            source: Some(R1FeeSource {
                operation: TransactionIdentifierPresentation::from_digest("syntxn", [3; 48])
                    .unwrap(),
                payer: NativeIdentityPresentation::from_raw("syns", [9; 48]).unwrap(),
            }),
        };
        let b = c.canonical_bytes(n()).unwrap();
        assert_eq!(R1FeeCarry::decode(&b, n()).unwrap(), c);
        let mut wrong = n();
        wrong.nic[63] ^= 1;
        assert!(R1FeeCarry::decode(&b, wrong).is_err());
        let mut b = b;
        b.push(0);
        assert!(R1FeeCarry::decode(&b, n()).is_err());
        assert!(R1FeeCarry { q: 1, source: None }
            .canonical_bytes(n())
            .is_err());
        let mut bad = c;
        bad.q = 0;
        assert!(bad.canonical_bytes(n()).is_err());
    }
    #[test]
    fn initial_pool_is_zero_and_missing_actual_backing_never_becomes_spendable() {
        let mut s = R1StateMap::new();
        initialize_genesis(&mut s, n()).unwrap();
        for r in [
            RestrictedRecord::Treasury,
            RestrictedRecord::FeeRoundingEscrow,
        ] {
            s.insert(
                restricted_key(r),
                R1StateValue::RestrictedBalance {
                    amount_nwei: 0,
                    policy_commitment: vec![1; 64],
                },
            )
            .unwrap();
        }
        let view = read_fee_state(&s, n()).unwrap();
        assert_eq!(view.validator_class_nwei, 0);
        assert_eq!(view.carry.q, 0);
        assert!(initialize_genesis(&mut s, n()).is_err());
        s.insert(
            restricted_key(RestrictedRecord::FeeRoundingEscrow),
            R1StateValue::RestrictedBalance {
                amount_nwei: 1,
                policy_commitment: vec![1; 64],
            },
        )
        .unwrap();
        assert!(read_fee_state(&s, n()).is_err());
    }
}
