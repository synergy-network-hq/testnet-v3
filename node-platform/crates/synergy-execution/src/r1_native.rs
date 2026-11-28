//! Deterministic R1 native-transfer reference computation. This result is NOT
//! authenticated ancestry, protected admission, VM qualification or finality.
//! The production owner must independently establish all those predicates.
use crate::r1_fees::{self, R1FeeOrigin};
use std::{sync::Arc, time::Instant};
use synergy_address::r1_public::{HashAlgorithm, Primitives};
use synergy_address_engine::apqe::{
    crypto_engine::CryptoEngine, policy_transition_r1::IndexedOrdinaryProof,
};
use synergy_protocol_types::{
    c14n02::{Decoder, Encoder},
    R1NetworkCoordinate, R1NetworkRef,
};
use synergy_state::{
    r1::{R1StateDomain, R1StateError, R1StateKey, R1StateMap, R1StateOwner, R1StateValue},
    r1_fees::R1FeeSource,
    r1_finalized::R1TransactionStatus,
    r1_receipts::R1ReceiptCore,
    world_resources::{WorldResourceBudget, WorldResourcePermit},
};
use synergy_transaction::r1::{R1Action, R1TransactionIntent};
pub const PROFILE_NAME: &str = "QACE-NATIVE-TRANSFER-R1";
pub const PROFILE_SCHEMA:&str=concat!(
 "QACE-NATIVE-TRANSFER-R1/1;reference-computation-not-authority;codec=QACE-C14N-02;",
 "Rules=(U16(1),base_units:U64,per_signature_units:U64,per_input_byte_units:U64,action_units:U64,unit_price_nwei:U64);",
 "base-includes-mandatory-outer-settlement;base>0;unit-price>0;checked-unit-prefix-no-charge-for-unexecuted-component;",
 "exactCurrentN+typedGen+profile-context;current-policy-epoch+MLDSA87ordinaryproof+exact-replay-nonce;",
 "signed-maximum-affordability=principal+gas_limit*max_price BEFORE eligible invocation;",
 "sourceSyns/Synw/Syna/Synm only;Synu requires separateinstitutionalpolicy;Synq throughAIVMcall;",
 "success=principal+nonce+actualfee+classcredits+carry+sources+receipt onebatch;resource-failure=no-principal,nonce+prior-work-fee;",
 "invalid-signature/nonce/affordability/dependency/localfault=no-canonical-receipt-or-fee;no-general-free-gaspolicy;",
 "NativeOutcome=(U16(1),ASCII8(senderNamespace),sender48,ASCII8(recipientNamespace),recipient48,amountU128);",
 "events=H(QACE/NATIVE-TRANSFER-EVENT/01,outcome);empty=H(QACE/NATIVE-EVENTS-EMPTY/01,U32(0));return=H(QACE/RETURN-EMPTY/01,U32(0));",
 "receipt-original=H(QACE/RECEIPT/02,ReceiptCore);allHAPQESHA3-384+C14N02wrapper-once;no-current-block-hash",
 ";compatible-profile-activation-resolver-and-protected-ETDAG/AIVM-integration-required-before-production"
);
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NativeError {
    Unsupported,
    Context,
    Policy,
    Nonce,
    Authorization,
    Affordability,
    Arithmetic,
    Dependency,
    LocalResource,
    State(R1StateError),
    Fee,
}
impl From<R1StateError> for NativeError {
    fn from(e: R1StateError) -> Self {
        Self::State(e)
    }
}
impl From<synergy_protocol_types::c14n02::Error> for NativeError {
    fn from(_: synergy_protocol_types::c14n02::Error) -> Self {
        Self::Policy
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct R1NativeTransferRules {
    pub base_units: u64,
    pub per_signature_units: u64,
    pub per_input_byte_units: u64,
    pub action_units: u64,
    pub unit_price_nwei: u64,
}
impl R1NativeTransferRules {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, NativeError> {
        if self.base_units == 0 || self.unit_price_nwei == 0 {
            return Err(NativeError::Policy);
        };
        let mut e = Encoder::new(64);
        e.u16(1)?;
        for n in [
            self.base_units,
            self.per_signature_units,
            self.per_input_byte_units,
            self.action_units,
            self.unit_price_nwei,
        ] {
            e.u64(n)?;
        }
        Ok(e.finish()?)
    }
    pub fn state_value(&self) -> Result<R1StateValue, NativeError> {
        Ok(R1StateValue::ProtocolRecord {
            profile_name: PROFILE_NAME.into(),
            profile_revision: 1,
            canonical_bytes: self.canonical_bytes()?,
        })
    }
    fn load(state: &R1StateMap) -> Result<Self, NativeError> {
        let Some(R1StateValue::ProtocolRecord {
            profile_name,
            profile_revision: 1,
            canonical_bytes,
        }) = state.get(&rules_key())
        else {
            return Err(NativeError::Dependency);
        };
        if profile_name != PROFILE_NAME {
            return Err(NativeError::Policy);
        };
        let mut d = Decoder::new(canonical_bytes, 64)?;
        if d.u16()? != 1 {
            return Err(NativeError::Policy);
        };
        let out = Self {
            base_units: d.u64()?,
            per_signature_units: d.u64()?,
            per_input_byte_units: d.u64()?,
            action_units: d.u64()?,
            unit_price_nwei: d.u64()?,
        };
        d.finish()?;
        if out.canonical_bytes()? != *canonical_bytes {
            return Err(NativeError::Policy);
        };
        Ok(out)
    }
}
pub fn rules_key() -> R1StateKey {
    R1StateKey {
        domain: R1StateDomain::ProtocolConfiguration,
        owner: R1StateOwner::Protocol,
        local_key: b"native-transfer/rules".to_vec(),
    }
}
pub struct R1NativeContext {
    pub coordinate: R1NetworkCoordinate,
    pub epoch: u64,
    pub height: u64,
    pub pre_state_root: [u8; 48],
    pub operation_position: u32,
    pub receipt_index: u32,
    pub deadline: Instant,
    pub maximum_state_hashes: u64,
}
pub struct ComputedR1Transfer {
    state: R1StateMap,
    receipt: R1ReceiptCore,
    origin: R1FeeOrigin,
    _permit: WorldResourcePermit,
}
impl ComputedR1Transfer {
    pub fn state(&self) -> &R1StateMap {
        &self.state
    }
    pub fn receipt(&self) -> &R1ReceiptCore {
        &self.receipt
    }
    pub fn fee_origin(&self) -> &R1FeeOrigin {
        &self.origin
    }
}
fn hash(tag: &str, body: &[u8]) -> Result<[u8; 48], NativeError> {
    let mut e = Encoder::with_domain(tag, 8192)?;
    for b in body {
        e.u8(*b)?;
    }
    Primitives
        .hash(HashAlgorithm::Sha3384, &e.finish()?)
        .map_err(|_| NativeError::Policy)?
        .try_into()
        .map_err(|_| NativeError::Policy)
}
fn key(domain: R1StateDomain, id: &str) -> Result<R1StateKey, NativeError> {
    Ok(R1StateKey::native(domain, id)?)
}
fn balance(state: &R1StateMap, k: &R1StateKey) -> Result<u128, NativeError> {
    match state.get(k) {
        Some(R1StateValue::NativeBalance { amount_nwei }) => Ok(*amount_nwei),
        _ => Err(NativeError::Dependency),
    }
}
/// Only explicitly supported exact profile contexts enter this reference. A
/// production compatibility resolver must preserve valid old intents across
/// unrelated profile activations; this helper does not certify that resolver.
pub fn compute_transfer(
    state: &R1StateMap,
    context: &R1NativeContext,
    tx: &R1TransactionIntent,
    proofs: &[IndexedOrdinaryProof<'_>],
    engine: &CryptoEngine,
    budget: &Arc<WorldResourceBudget>,
) -> Result<ComputedR1Transfer, NativeError> {
    tx.validate().map_err(|_| NativeError::Policy)?;
    context
        .coordinate
        .ensure_matches(&tx.coordinate)
        .map_err(|_| NativeError::Context)?;
    if context.epoch == 0
        || context.height == 0
        || context.height < tx.valid_from_height
        || context.height > tx.valid_until_height
    {
        return Err(NativeError::Context);
    };
    let R1Action::Transfer {
        recipient,
        amount_nwei,
    } = &tx.action
    else {
        return Err(NativeError::Unsupported);
    };
    if tx.sender.namespace() == "synu" || recipient.namespace() == "synu" {
        return Err(NativeError::Unsupported);
    };
    let message = tx.signing_frame().map_err(|_| NativeError::Policy)?;
    let encoded = state.canonical_storage_bytes();
    let reservation = encoded
        .checked_mul(64)
        .and_then(|n| n.checked_add(state.len().checked_mul(2048)?))
        .and_then(|n| n.checked_add(message.len().checked_mul(4)?))
        .and_then(|n| n.checked_add(512 * 1024))
        .ok_or(NativeError::Arithmetic)?;
    let permit = budget
        .reserve(reservation)
        .map_err(|_| NativeError::LocalResource)?;
    let mut remaining = context.maximum_state_hashes;
    if synergy_state::r1_smt::root_with_limits(state, context.deadline, &mut remaining)?
        != context.pre_state_root
    {
        return Err(NativeError::Context);
    };
    let sender = tx.sender.to_text();
    let recipient_text = recipient.to_text();
    let sender_balance_key = key(R1StateDomain::NativeBalance, &sender)?;
    let recipient_balance_key = key(R1StateDomain::NativeBalance, &recipient_text)?;
    let nonce_key = key(R1StateDomain::ReplayCoordinate, &sender)?;
    let Some(R1StateValue::ReplayNonce { nonce }) = state.get(&nonce_key) else {
        return Err(NativeError::Dependency);
    };
    if *nonce != tx.nonce {
        return Err(NativeError::Nonce);
    };
    let next_nonce = nonce.checked_add(1).ok_or(NativeError::Nonce)?;
    let Some(R1StateValue::AccountPolicy {
        policy_epoch,
        policy_commitment,
        full_policy_frame,
    }) = state.get(&key(R1StateDomain::AccountAuthorization, &sender)?)
    else {
        return Err(NativeError::Dependency);
    };
    if *policy_epoch != tx.policy_epoch {
        return Err(NativeError::Policy);
    };
    if !matches!(
        state.get(&key(R1StateDomain::AccountAuthorization, &recipient_text)?),
        Some(R1StateValue::AccountPolicy { .. })
    ) {
        return Err(NativeError::Dependency);
    };
    let policy_commitment: [u8; 64] = policy_commitment
        .as_slice()
        .try_into()
        .map_err(|_| NativeError::Policy)?;
    let rules = R1NativeTransferRules::load(state)?;
    if rules.unit_price_nwei > tx.max_fee_per_gas_nwei || rules.base_units > tx.gas_limit {
        return Err(NativeError::Affordability);
    };
    let before = balance(state, &sender_balance_key)?;
    let recipient_before = balance(state, &recipient_balance_key)?;
    let maximum_fee = u128::from(tx.gas_limit)
        .checked_mul(u128::from(tx.max_fee_per_gas_nwei))
        .ok_or(NativeError::Arithmetic)?;
    let maximum_debit = amount_nwei
        .checked_add(maximum_fee)
        .ok_or(NativeError::Arithmetic)?;
    if before < maximum_debit {
        return Err(NativeError::Affordability);
    };
    tx.verify_ordinary(engine, full_policy_frame, &policy_commitment, proofs)
        .map_err(|_| NativeError::Authorization)?;
    if Instant::now() >= context.deadline {
        return Err(NativeError::LocalResource);
    };
    let components = [
        rules.base_units,
        rules
            .per_signature_units
            .checked_mul(proofs.len() as u64)
            .ok_or(NativeError::Arithmetic)?,
        rules
            .per_input_byte_units
            .checked_mul(message.len() as u64)
            .ok_or(NativeError::Arithmetic)?,
        rules.action_units,
    ];
    let mut used = 0u64;
    let mut exhausted = false;
    for cost in components {
        let next = used.checked_add(cost).ok_or(NativeError::Arithmetic)?;
        if next > tx.gas_limit {
            exhausted = true;
            break;
        }
        used = next;
    }
    let paid = u128::from(used)
        .checked_mul(u128::from(rules.unit_price_nwei))
        .ok_or(NativeError::Arithmetic)?;
    let actual_principal = if exhausted { 0 } else { *amount_nwei };
    let debit = actual_principal
        .checked_add(paid)
        .ok_or(NativeError::Arithmetic)?;
    let mut sender_after = before
        .checked_sub(debit)
        .ok_or(NativeError::Affordability)?;
    let recipient_after = if sender_balance_key == recipient_balance_key {
        sender_after = sender_after
            .checked_add(actual_principal)
            .ok_or(NativeError::Arithmetic)?;
        sender_after
    } else {
        recipient_before
            .checked_add(actual_principal)
            .filter(|n| *n <= crate::cumulative::MAX_NATIVE_STOCK_NWEI)
            .ok_or(NativeError::Arithmetic)?
    };
    let mut outcome = Encoder::new(512);
    if !exhausted {
        outcome.u16(1)?;
        outcome.ascii(tx.sender.namespace(), 8)?;
        outcome.fixed(tx.sender.raw48())?;
        outcome.ascii(recipient.namespace(), 8)?;
        outcome.fixed(recipient.raw48())?;
        outcome.u128(*amount_nwei)?;
    }
    let outcome = outcome.finish()?;
    let events = if exhausted {
        hash("QACE/NATIVE-EVENTS-EMPTY/01", &0u32.to_be_bytes())?
    } else {
        hash("QACE/NATIVE-TRANSFER-EVENT/01", &outcome)?
    };
    let receipt = R1ReceiptCore {
        transaction: tx.identifier().map_err(|_| NativeError::Policy)?,
        sequence_index: context.receipt_index,
        result: if exhausted {
            R1TransactionStatus::ResourceExhausted
        } else {
            R1TransactionStatus::Applied
        },
        gas_used: used,
        paid_nwei: paid,
        refunded_nwei: 0,
        events_commitment: events,
        permitted_return_commitment: hash("QACE/RETURN-EMPTY/01", &0u32.to_be_bytes())?,
        error_code: exhausted.then(|| "METER_LIMIT".into()),
        operation_outcome: outcome,
    };
    let receipt_commitment = hash("QACE/RECEIPT/02", &receipt.canonical_bytes()?)?;
    let n = R1NetworkRef {
        chain_id: context.coordinate.network.chain_id,
        nic: context.coordinate.network.nic,
    };
    let fee_plan = r1_fees::prepare_settlement(
        state,
        n,
        R1FeeSource {
            operation: receipt.transaction.clone(),
            payer: tx.sender.clone(),
        },
        paid,
        context.pre_state_root,
        context.operation_position,
        receipt_commitment,
    )
    .map_err(|_| NativeError::Fee)?;
    let mut changes = fee_plan.changes;
    changes.push((
        sender_balance_key.clone(),
        Some(R1StateValue::NativeBalance {
            amount_nwei: sender_after,
        }),
    ));
    if sender_balance_key != recipient_balance_key {
        changes.push((
            recipient_balance_key,
            Some(R1StateValue::NativeBalance {
                amount_nwei: recipient_after,
            }),
        ));
    }
    changes.push((
        nonce_key,
        Some(R1StateValue::ReplayNonce { nonce: next_nonce }),
    ));
    let mut next = state.clone();
    next.apply_batch(&changes)?;
    if Instant::now() >= context.deadline {
        return Err(NativeError::LocalResource);
    };
    Ok(ComputedR1Transfer {
        state: next,
        receipt,
        origin: fee_plan.origin,
        _permit: permit,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use synergy_state::r1::RestrictedRecordKind;

    fn context(s: &R1StateMap, tx: &R1TransactionIntent) -> R1NativeContext {
        R1NativeContext {
            coordinate: tx.coordinate.clone(),
            epoch: 1,
            height: 1,
            pre_state_root: synergy_state::r1_smt::root(s).unwrap(),
            operation_position: 0,
            receipt_index: 0,
            deadline: Instant::now() + Duration::from_secs(20),
            maximum_state_hashes: 100_000,
        }
    }
    #[test]
    fn normal_financial_metering_cannot_select_general_zero_price() {
        let rules = R1NativeTransferRules {
            base_units: 1,
            per_signature_units: 0,
            per_input_byte_units: 0,
            action_units: 0,
            unit_price_nwei: 1,
        };
        assert!(rules.canonical_bytes().is_ok());
        assert!(R1NativeTransferRules {
            unit_price_nwei: 0,
            ..rules
        }
        .canonical_bytes()
        .is_err());
        assert!(R1NativeTransferRules {
            base_units: 0,
            ..rules
        }
        .canonical_bytes()
        .is_err());
    }
    fn set_balance(s: &mut R1StateMap, tx: &R1TransactionIntent, amount: u128) {
        s.insert(
            key(R1StateDomain::NativeBalance, &tx.sender.to_text()).unwrap(),
            R1StateValue::NativeBalance {
                amount_nwei: amount,
            },
        )
        .unwrap();
    }
    #[test]
    #[ignore = "requires exact canonical pinned native validation artifacts; no RNG or key creation"]
    fn genuine_signed_transfer_is_atomic_metered_and_never_promotes_local_failure() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let d: serde_json::Value = serde_json::from_slice(&std::fs::read(root.join(
            "../../../../21-Aegis-Engine/synergy-address-engine/tests/fixtures/r1_ordinary_transaction_public.json"
        )).unwrap()).unwrap();
        assert_eq!(
            d["purpose"],
            "PUBLIC_SYNTHETIC_R1_TRANSACTION_SIGNATURES_ONLY"
        );
        assert_eq!(d["production_import_permitted"], false);
        assert_eq!(d["chain_id"].as_u64(), Some(u64::MAX - 1));
        let decode = |k: &str| hex::decode(d[k].as_str().unwrap()).unwrap();
        let tx = R1TransactionIntent::decode_signing_frame(&decode("exact_message_hex")).unwrap();
        assert_eq!(tx.gas_limit, 1);
        assert_eq!(tx.max_fee_per_gas_nwei, 1);
        assert!(
            matches!(&tx.action,R1Action::Transfer {recipient,amount_nwei:1} if recipient == &tx.sender)
        );
        let signatures = d["proofs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| hex::decode(r["signature_hex"].as_str().unwrap()).unwrap())
            .collect::<Vec<_>>();
        let proofs = d["proofs"]
            .as_array()
            .unwrap()
            .iter()
            .zip(&signatures)
            .map(|(r, s)| IndexedOrdinaryProof {
                controller_index: r["controller_index"].as_u64().unwrap().try_into().unwrap(),
                key_generation: r["key_generation"].as_u64().unwrap(),
                signature: s,
            })
            .collect::<Vec<_>>();
        let report = root.join("../../../../24-Technical-Documentation/testnet-9969-preparation/revisions/r2/provider-validation/build-report.json");
        let pin = hex::decode("1c7851d11260c880aced3fbad8aadc7b68e1f02a379d8efc8846d65a7c89af9c")
            .unwrap()
            .try_into()
            .unwrap();
        // Exact previously reviewed public-test artifacts only. No dynamic caller path.
        let engine = unsafe {
            synergy_address_engine::apqe::native_manifest::received_r1_verification_engine(
                &report, pin,
            )
        }
        .unwrap();
        let mut state = R1StateMap::new();
        set_balance(&mut state, &tx, 2);
        state
            .insert(
                key(R1StateDomain::ReplayCoordinate, &tx.sender.to_text()).unwrap(),
                R1StateValue::ReplayNonce { nonce: 0 },
            )
            .unwrap();
        state
            .insert(
                key(R1StateDomain::AccountAuthorization, &tx.sender.to_text()).unwrap(),
                R1StateValue::AccountPolicy {
                    policy_epoch: 1,
                    policy_commitment: decode("policy_commitment_hex"),
                    full_policy_frame: decode("policy_frame_hex"),
                },
            )
            .unwrap();
        let n = tx.coordinate.network;
        synergy_state::r1_fees::initialize_genesis(&mut state, n).unwrap();
        for r in [
            RestrictedRecordKind::Treasury,
            RestrictedRecordKind::FeeRoundingEscrow,
        ] {
            state
                .insert(
                    synergy_state::r1_fees::restricted_key(r),
                    R1StateValue::RestrictedBalance {
                        amount_nwei: 0,
                        policy_commitment: vec![7; 64],
                    },
                )
                .unwrap();
        }
        let rules = R1NativeTransferRules {
            base_units: 1,
            per_signature_units: 0,
            per_input_byte_units: 0,
            action_units: 0,
            unit_price_nwei: 1,
        };
        state
            .insert(rules_key(), rules.state_value().unwrap())
            .unwrap();
        let before = synergy_state::r1_smt::root(&state).unwrap();
        let budget = WorldResourceBudget::new(16 * 1024 * 1024);
        let result = compute_transfer(
            &state,
            &context(&state, &tx),
            &tx,
            &proofs,
            &engine,
            &budget,
        )
        .unwrap();
        assert_eq!(result.receipt().result, R1TransactionStatus::Applied);
        assert_eq!(result.receipt().paid_nwei, 1);
        assert_eq!(result.receipt().gas_used, 1);
        assert_eq!(result.receipt().refunded_nwei, 0);
        assert_eq!(
            balance(
                result.state(),
                &key(R1StateDomain::NativeBalance, &tx.sender.to_text()).unwrap()
            )
            .unwrap(),
            1
        );
        assert_eq!(
            result
                .state()
                .get(&key(R1StateDomain::ReplayCoordinate, &tx.sender.to_text()).unwrap()),
            Some(&R1StateValue::ReplayNonce { nonce: 1 })
        );
        let fee = synergy_state::r1_fees::read_fee_state(result.state(), n).unwrap();
        assert_eq!(
            (
                fee.carry.q,
                fee.escrow_nwei,
                fee.validator_class_nwei,
                fee.treasury_nwei
            ),
            (1, 1, 0, 0)
        );
        assert_eq!(
            result.fee_origin().source.operation,
            tx.identifier().unwrap()
        );
        assert_eq!(result.fee_origin().pre_state_root, before);
        assert!(budget.used() > 0);
        drop(result);
        assert_eq!(budget.used(), 0);
        assert_eq!(synergy_state::r1_smt::root(&state).unwrap(), before);

        // Same signed maximum must be affordable even for a self transfer.
        let mut poor = state.clone();
        set_balance(&mut poor, &tx, 1);
        assert!(matches!(
            compute_transfer(&poor, &context(&poor, &tx), &tx, &proofs, &engine, &budget),
            Err(NativeError::Affordability)
        ));
        let mut wrong_nonce = tx.clone();
        wrong_nonce.nonce = 1;
        assert!(matches!(
            compute_transfer(
                &state,
                &context(&state, &tx),
                &wrong_nonce,
                &proofs,
                &engine,
                &budget
            ),
            Err(NativeError::Nonce)
        ));
        let mut sig = signatures[0].clone();
        sig[0] ^= 1;
        let bad = [IndexedOrdinaryProof {
            controller_index: proofs[0].controller_index,
            key_generation: proofs[0].key_generation,
            signature: &sig,
        }];
        assert!(matches!(
            compute_transfer(&state, &context(&state, &tx), &tx, &bad, &engine, &budget),
            Err(NativeError::Authorization)
        ));
        assert!(matches!(
            compute_transfer(
                &state,
                &context(&state, &tx),
                &tx,
                &proofs,
                &CryptoEngine::new(),
                &budget
            ),
            Err(NativeError::Authorization)
        ));
        let mut wrong = context(&state, &tx);
        wrong.coordinate.network.nic[63] ^= 1;
        assert!(matches!(
            compute_transfer(&state, &wrong, &tx, &proofs, &engine, &budget),
            Err(NativeError::Context)
        ));
        let small = WorldResourceBudget::new(1);
        assert!(matches!(
            compute_transfer(&state, &context(&state, &tx), &tx, &proofs, &engine, &small),
            Err(NativeError::LocalResource)
        ));
        let mut expired = context(&state, &tx);
        expired.deadline = Instant::now();
        assert!(compute_transfer(&state, &expired, &tx, &proofs, &engine, &budget).is_err());
        assert_eq!(small.used(), 0);
        assert_eq!(budget.used(), 0);
        assert_eq!(synergy_state::r1_smt::root(&state).unwrap(), before);

        // Eligible resource exhaustion charges completed work, never the unexecuted action.
        let mut limited = state.clone();
        limited
            .insert(
                rules_key(),
                R1NativeTransferRules {
                    action_units: 1,
                    ..rules
                }
                .state_value()
                .unwrap(),
            )
            .unwrap();
        let result = compute_transfer(
            &limited,
            &context(&limited, &tx),
            &tx,
            &proofs,
            &engine,
            &budget,
        )
        .unwrap();
        assert_eq!(
            result.receipt().result,
            R1TransactionStatus::ResourceExhausted
        );
        assert_eq!(result.receipt().gas_used, 1);
        assert_eq!(result.receipt().paid_nwei, 1);
        assert!(result.receipt().operation_outcome.is_empty());
        assert_eq!(result.receipt().error_code.as_deref(), Some("METER_LIMIT"));
        assert_eq!(
            balance(
                result.state(),
                &key(R1StateDomain::NativeBalance, &tx.sender.to_text()).unwrap()
            )
            .unwrap(),
            1
        );
        assert_eq!(
            result
                .state()
                .get(&key(R1StateDomain::ReplayCoordinate, &tx.sender.to_text()).unwrap()),
            Some(&R1StateValue::ReplayNonce { nonce: 1 })
        );
        assert_eq!(
            balance(
                &limited,
                &key(R1StateDomain::NativeBalance, &tx.sender.to_text()).unwrap()
            )
            .unwrap(),
            2
        );
        drop(result);
        assert_eq!(budget.used(), 0);
    }
}
