//! Narrow initial Wallet registration reference. Crypto possession is required;
//! there is no funded payer, sponsor, reimbursement or monetary fee. This
//! computation supplies no admission, protected-execution or finality authority.
use std::{sync::Arc, time::Instant};
use synergy_address::r1_public::{
    HashAlgorithm, NativeIdentityPresentation, Primitives, TransactionIdentifierPresentation,
};
use synergy_address_engine::apqe::{
    crypto_engine::CryptoEngine,
    managed_creation::identity_proof::{
        IdentityProofInput, SignatureKind, ValidatedIdentityProofPlan,
    },
    network_birth_r1::ProfileRef,
    provider::SignOptions,
    r1_framing::{self as c, Value},
};
use synergy_protocol_types::{
    c14n02::{Decoder, Encoder},
    R1NetworkCoordinate,
};
use synergy_state::{
    r1::{R1StateDomain, R1StateError, R1StateKey, R1StateMap, R1StateOwner, R1StateValue},
    r1_finalized::R1TransactionStatus,
    r1_receipts::R1ReceiptCore,
    world_resources::{WorldResourceBudget, WorldResourcePermit},
};
pub const PROFILE_NAME: &str = "QACE-INITIAL-WALLET-ENROLLMENT-R1";
pub const PROFILE_REVISION: u32 = 1;
pub const PROFILE_SCHEMA:&str=concat!(
 "QACE-INITIAL-WALLET-ENROLLMENT-R1/1;reference-not-admission-or-finality;APQE-C/F;N;",
 "intent=[schema1,typedGenesis48,typedActivatedProfiles64,completeAPQECustodyIdentityProofPlanFrame];",
 "ID=SHA3-384(F(TRANSACTION.ID,thisprofile,N,intent));syntxn-full48;signatures-detached;",
 "ONLYinitialsynw,D+PordinaryMLDSA87,optionalrecoveryR,everycontrollerexactAccountPoP;currentPolicy=birthPolicy;epoch1,replay0,balance0;",
 "existingidentity-or-partialaccount-record-reject;replay-exact-ID-returns-originalreceipt-without-effect-or-newreceipt;",
 "Rules=C14N02(U16(1),baseUnitsU64,signatureUnitsU64,inputByteUnitsU64,operationalCapacityPolicy48);base>0,signature>0,policy!=zero;NO-defaults;",
 "operation-effects=authorization+balance0+nonce0+originalreceiptmarker-oneatomicbatch;",
 "paid=refunded=0;no-payer/sponsor/funding-precondition;no-normal-fee-carry-change;ordinaryfinancialfees-unchanged;",
 "rules/state-root/current-context/local-budget/deadline/crypto-error=no-canonical-effect;resource-admission/exclusivecustody/protectedETDAG/exact-oncefinality-external"
);
#[derive(Debug, PartialEq, Eq)]
pub enum EnrollmentError {
    Context,
    Bounds,
    Policy,
    Dependency,
    AlreadyExists,
    Proof,
    Resource,
    Corrupt,
    State(R1StateError),
}
impl From<R1StateError> for EnrollmentError {
    fn from(e: R1StateError) -> Self {
        Self::State(e)
    }
}
#[derive(Clone, Copy)]
pub struct InitialWalletRules {
    pub base_units: u64,
    pub signature_units: u64,
    pub input_byte_units: u64,
    pub operational_capacity_policy: [u8; 48],
}
impl InitialWalletRules {
    pub fn state_value(&self) -> Result<R1StateValue, EnrollmentError> {
        if self.base_units == 0
            || self.signature_units == 0
            || self.operational_capacity_policy == [0; 48]
        {
            return Err(EnrollmentError::Policy);
        }
        let mut e = Encoder::new(128);
        e.u16(1).map_err(|_| EnrollmentError::Policy)?;
        for n in [self.base_units, self.signature_units, self.input_byte_units] {
            e.u64(n).map_err(|_| EnrollmentError::Policy)?;
        }
        e.fixed(&self.operational_capacity_policy)
            .map_err(|_| EnrollmentError::Policy)?;
        Ok(R1StateValue::ProtocolRecord {
            profile_name: PROFILE_NAME.into(),
            profile_revision: 1,
            canonical_bytes: e.finish().map_err(|_| EnrollmentError::Policy)?,
        })
    }
    fn load(s: &R1StateMap) -> Result<Self, EnrollmentError> {
        let Some(R1StateValue::ProtocolRecord {
            profile_name,
            profile_revision: 1,
            canonical_bytes,
        }) = s.get(&rules_key())
        else {
            return Err(EnrollmentError::Dependency);
        };
        if profile_name != PROFILE_NAME {
            return Err(EnrollmentError::Policy);
        }
        let mut d = Decoder::new(canonical_bytes, 128).map_err(|_| EnrollmentError::Policy)?;
        if d.u16().map_err(|_| EnrollmentError::Policy)? != 1 {
            return Err(EnrollmentError::Policy);
        }
        let r = Self {
            base_units: d.u64().map_err(|_| EnrollmentError::Policy)?,
            signature_units: d.u64().map_err(|_| EnrollmentError::Policy)?,
            input_byte_units: d.u64().map_err(|_| EnrollmentError::Policy)?,
            operational_capacity_policy: d.fixed().map_err(|_| EnrollmentError::Policy)?,
        };
        d.finish().map_err(|_| EnrollmentError::Policy)?;
        if r.state_value()? != *s.get(&rules_key()).unwrap() {
            return Err(EnrollmentError::Policy);
        }
        Ok(r)
    }
}
pub fn rules_key() -> R1StateKey {
    R1StateKey {
        domain: R1StateDomain::ProtocolConfiguration,
        owner: R1StateOwner::Protocol,
        local_key: b"wallet-initial/rules".to_vec(),
    }
}
pub struct InitialWalletIntent {
    pub coordinate: R1NetworkCoordinate,
    pub identity: IdentityProofInput,
}
fn profile_value(name: &str, revision: u32) -> Value {
    Value::Array(vec![c::text(name), Value::Unsigned(revision.into())])
}
impl InitialWalletIntent {
    fn plan(&self) -> Result<ValidatedIdentityProofPlan, EnrollmentError> {
        self.coordinate
            .validate()
            .map_err(|_| EnrollmentError::Context)?;
        if self.identity.namespace != "synw"
            || self.identity.node.is_some()
            || self.identity.birth_policy_frame_hex.len() > 262144
        {
            return Err(EnrollmentError::Policy);
        }
        ValidatedIdentityProofPlan::validate_received(
            synergy_address_engine::apqe::r1_framing::NetworkRef {
                chain_id: self.coordinate.network.chain_id,
                nic: self.coordinate.network.nic,
            },
            &self.identity,
        )
        .map_err(|_| EnrollmentError::Policy)
    }
    fn frame(
        &self,
        plan: &ValidatedIdentityProofPlan,
        domain: &str,
    ) -> Result<Vec<u8>, EnrollmentError> {
        c::frame(
            domain,
            ProfileRef {
                name: PROFILE_NAME,
                revision: 1,
            },
            Some(plan.network()),
            Value::Array(vec![
                Value::Unsigned(1),
                Value::Array(vec![
                    profile_value(
                        &self.coordinate.genesis.profile.name,
                        self.coordinate.genesis.profile.revision,
                    ),
                    c::text("SHA3-384"),
                    c::bytes(&self.coordinate.genesis.digest),
                ]),
                Value::Array(vec![
                    profile_value(
                        &self.coordinate.activated_profiles.profile.name,
                        self.coordinate.activated_profiles.profile.revision,
                    ),
                    c::text("SHA3-512"),
                    c::bytes(&self.coordinate.activated_profiles.commitment),
                ]),
                c::bytes(plan.canonical_frame()),
            ]),
            1024 * 1024,
        )
        .map_err(|_| EnrollmentError::Bounds)
    }
    pub fn canonical_intent(&self) -> Result<Vec<u8>, EnrollmentError> {
        self.frame(&self.plan()?, "TRANSACTION.INTENT")
    }
    pub fn identifier(&self) -> Result<TransactionIdentifierPresentation, EnrollmentError> {
        self.identifier_from_plan(&self.plan()?)
    }
    fn identifier_from_plan(
        &self,
        p: &ValidatedIdentityProofPlan,
    ) -> Result<TransactionIdentifierPresentation, EnrollmentError> {
        let digest = Primitives
            .hash(HashAlgorithm::Sha3384, &self.frame(p, "TRANSACTION.ID")?)
            .map_err(|_| EnrollmentError::Policy)?
            .try_into()
            .map_err(|_| EnrollmentError::Policy)?;
        TransactionIdentifierPresentation::from_digest("syntxn", digest)
            .map_err(|_| EnrollmentError::Policy)
    }
}
pub struct EnrollmentProof<'a> {
    pub controller_index: u32,
    pub key_generation: u64,
    pub signature: &'a [u8],
}
pub struct InitialWalletContext {
    pub coordinate: R1NetworkCoordinate,
    pub pre_state_root: [u8; 48],
    pub receipt_index: u32,
    pub deadline: Instant,
    pub maximum_state_hashes: u64,
}
pub struct ComputedInitialWallet {
    state: Option<R1StateMap>,
    receipt: R1ReceiptCore,
    _permit: WorldResourcePermit,
}
impl ComputedInitialWallet {
    pub fn state(&self) -> Option<&R1StateMap> {
        self.state.as_ref()
    }
    pub fn original_receipt(&self) -> &R1ReceiptCore {
        &self.receipt
    }
    pub fn is_replay(&self) -> bool {
        self.state.is_none()
    }
}
fn receipt_key(id: &TransactionIdentifierPresentation) -> R1StateKey {
    let mut local = b"wallet-initial/applied/".to_vec();
    local.extend_from_slice(id.digest48());
    R1StateKey {
        domain: R1StateDomain::ProtocolConfiguration,
        owner: R1StateOwner::Protocol,
        local_key: local,
    }
}
/// Produces only independently computed data. The caller must establish actual
/// protected admission/resource capacity/parent authority before invocation.
pub fn compute_initial_wallet(
    state: &R1StateMap,
    context: &InitialWalletContext,
    intent: &InitialWalletIntent,
    proofs: &[EnrollmentProof<'_>],
    engine: &CryptoEngine,
    budget: &Arc<WorldResourceBudget>,
) -> Result<ComputedInitialWallet, EnrollmentError> {
    context
        .coordinate
        .ensure_matches(&intent.coordinate)
        .map_err(|_| EnrollmentError::Context)?;
    if proofs.len() > 3
        || proofs.iter().any(|p| p.signature.len() != 4627)
        || intent.identity.birth_policy_frame_hex.len() > 262144
    {
        return Err(EnrollmentError::Bounds);
    }
    let bytes = state
        .canonical_storage_bytes()
        .checked_mul(64)
        .and_then(|n| n.checked_add(state.len().checked_mul(2048)?))
        .and_then(|n| n.checked_add(8 * 1024 * 1024))
        .ok_or(EnrollmentError::Resource)?;
    let permit = budget
        .reserve(bytes)
        .map_err(|_| EnrollmentError::Resource)?;
    let mut hashes = context.maximum_state_hashes;
    if synergy_state::r1_smt::root_with_limits(state, context.deadline, &mut hashes)?
        != context.pre_state_root
    {
        return Err(EnrollmentError::Context);
    }
    let plan = intent.plan()?;
    let id = intent.identifier_from_plan(&plan)?;
    let marker = receipt_key(&id);
    if let Some(value) = state.get(&marker) {
        let R1StateValue::ProtocolRecord {
            profile_name,
            profile_revision: 1,
            canonical_bytes,
        } = value
        else {
            return Err(EnrollmentError::Corrupt);
        };
        if profile_name != PROFILE_NAME {
            return Err(EnrollmentError::Corrupt);
        }
        let receipt = R1ReceiptCore::decode_canonical(canonical_bytes)?;
        if receipt.transaction != id
            || receipt.result != R1TransactionStatus::Applied
            || receipt.paid_nwei != 0
            || receipt.refunded_nwei != 0
        {
            return Err(EnrollmentError::Corrupt);
        }
        return Ok(ComputedInitialWallet {
            state: None,
            receipt,
            _permit: permit,
        });
    }
    let rules = InitialWalletRules::load(state)?;
    let identity =
        NativeIdentityPresentation::parse(plan.identity()).map_err(|_| EnrollmentError::Policy)?;
    let k = |domain| R1StateKey::native(domain, plan.identity());
    let auth = k(R1StateDomain::AccountAuthorization)?;
    let balance = k(R1StateDomain::NativeBalance)?;
    let nonce = k(R1StateDomain::ReplayCoordinate)?;
    if [&auth, &balance, &nonce]
        .iter()
        .any(|k| state.get(k).is_some())
    {
        return Err(EnrollmentError::AlreadyExists);
    }
    if plan.messages().len() != proofs.len() || !(2..=3).contains(&proofs.len()) {
        return Err(EnrollmentError::Proof);
    }
    for (m, p) in plan.messages().iter().zip(proofs) {
        if m.kind() != SignatureKind::AccountPossession
            || m.index() != p.controller_index
            || m.key().key_generation != p.key_generation
            || m.key().algorithm != "ML-DSA-87"
        {
            return Err(EnrollmentError::Proof);
        }
        let key = hex::decode(&m.key().full_public_key_hex).map_err(|_| EnrollmentError::Policy)?;
        if !engine
            .verify(
                synergy_address_engine::types::Algorithm::MlDsa87,
                &key,
                m.frame(),
                p.signature,
                SignOptions::Pure {
                    context: m.context(),
                },
            )
            .map_err(|_| EnrollmentError::Proof)?
        {
            return Err(EnrollmentError::Proof);
        }
        if Instant::now() >= context.deadline {
            return Err(EnrollmentError::Resource);
        }
    }
    let policy = hex::decode(&intent.identity.birth_policy_frame_hex)
        .map_err(|_| EnrollmentError::Policy)?;
    let commitment=synergy_address_engine::apqe::native_identity_derivation_r1::validate_received_policy_frame(plan.network(),&policy,131072).map_err(|_|EnrollmentError::Policy)?;
    let input_bytes = intent.frame(&plan, "TRANSACTION.INTENT")?.len() as u64;
    let fuel = rules
        .signature_units
        .checked_mul(proofs.len() as u64)
        .and_then(|n| n.checked_add(rules.base_units))
        .and_then(|n| n.checked_add(rules.input_byte_units.checked_mul(input_bytes)?))
        .ok_or(EnrollmentError::Resource)?;
    let mut outcome = Encoder::new(256);
    outcome.u16(1).map_err(|_| EnrollmentError::Policy)?;
    outcome
        .ascii(identity.namespace(), 8)
        .map_err(|_| EnrollmentError::Policy)?;
    outcome
        .fixed(identity.raw48())
        .map_err(|_| EnrollmentError::Policy)?;
    outcome
        .fixed(&commitment)
        .map_err(|_| EnrollmentError::Policy)?;
    let outcome = outcome.finish().map_err(|_| EnrollmentError::Policy)?;
    let receipt = R1ReceiptCore {
        transaction: id,
        sequence_index: context.receipt_index,
        result: R1TransactionStatus::Applied,
        gas_used: fuel,
        paid_nwei: 0,
        refunded_nwei: 0,
        events_commitment: crate::r1_native::hash("QACE/INITIAL-WALLET-EVENT/01", &outcome)
            .map_err(|_| EnrollmentError::Policy)?,
        permitted_return_commitment: crate::r1_native::hash(
            "QACE/RETURN-EMPTY/01",
            &0u32.to_be_bytes(),
        )
        .map_err(|_| EnrollmentError::Policy)?,
        error_code: None,
        operation_outcome: outcome,
    };
    let mut next = state.clone();
    next.apply_batch(&[
        (
            auth,
            Some(R1StateValue::AccountPolicy {
                policy_epoch: 1,
                policy_commitment: commitment.to_vec(),
                full_policy_frame: policy,
            }),
        ),
        (
            balance,
            Some(R1StateValue::NativeBalance { amount_nwei: 0 }),
        ),
        (nonce, Some(R1StateValue::ReplayNonce { nonce: 0 })),
        (
            marker,
            Some(R1StateValue::ProtocolRecord {
                profile_name: PROFILE_NAME.into(),
                profile_revision: 1,
                canonical_bytes: receipt.canonical_bytes()?,
            }),
        ),
    ])?;
    if Instant::now() >= context.deadline {
        return Err(EnrollmentError::Resource);
    }
    Ok(ComputedInitialWallet {
        state: Some(next),
        receipt,
        _permit: permit,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use synergy_protocol_types::{
        R1GenesisReference, R1NetworkRef, R1ProfileRef, R1ProfileSetReference,
    };
    fn fixture() -> (serde_json::Value, InitialWalletIntent) {
        let d: serde_json::Value = serde_json::from_str(include_str!(
            "../tests/fixtures/r1_initial_wallet_public.json"
        ))
        .unwrap();
        assert_eq!(d["production_import_permitted"], false);
        assert_eq!(d["chain_id"].as_u64(), Some(u64::MAX - 1));
        let c = &d["coordinate"];
        let bytes = |v: &serde_json::Value| serde_json::from_value::<Vec<u8>>(v.clone()).unwrap();
        let p = |v: &serde_json::Value| R1ProfileRef {
            name: v["name"].as_str().unwrap().into(),
            revision: v["revision"].as_u64().unwrap() as u32,
        };
        let coordinate = R1NetworkCoordinate {
            network: R1NetworkRef {
                chain_id: u64::MAX - 1,
                nic: bytes(&c["network"]["nic"]).try_into().unwrap(),
            },
            genesis: R1GenesisReference {
                profile: p(&c["genesis"]["profile"]),
                digest: bytes(&c["genesis"]["digest"]).try_into().unwrap(),
            },
            activated_profiles: R1ProfileSetReference {
                profile: p(&c["activated_profiles"]["profile"]),
                commitment: bytes(&c["activated_profiles"]["commitment"])
                    .try_into()
                    .unwrap(),
            },
        };
        let intent = InitialWalletIntent {
            coordinate,
            identity: serde_json::from_value(d["identity_input"].clone()).unwrap(),
        };
        (d, intent)
    }
    fn context(s: &R1StateMap, intent: &InitialWalletIntent, index: u32) -> InitialWalletContext {
        InitialWalletContext {
            coordinate: intent.coordinate.clone(),
            pre_state_root: s.root().unwrap(),
            receipt_index: index,
            deadline: Instant::now() + Duration::from_secs(20),
            maximum_state_hashes: 100_000,
        }
    }
    #[test]
    fn independent_python_wallet_policy_birth_plan_intent_and_identifier_match() {
        let (d, intent) = fixture();
        assert_eq!(
            hex::encode(intent.canonical_intent().unwrap()),
            d["exact_intent_hex"]
        );
        assert_eq!(intent.identifier().unwrap().to_text(), d["transaction_id"]);
        let mut bad = intent;
        bad.identity.namespace = "syns".into();
        assert!(bad.canonical_intent().is_err());
    }
    #[test]
    #[ignore = "requires exact pinned native validation artifacts/public fixed NIST proofs; no RNG or keygen"]
    fn initial_wallet_needs_no_money_and_replays_only_the_original_zero_fee_receipt() {
        let (d, intent) = fixture();
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let report=root.join("../../../../24-Technical-Documentation/testnet-9969-preparation/revisions/r2/provider-validation/build-report.json");
        let pin = hex::decode("1c7851d11260c880aced3fbad8aadc7b68e1f02a379d8efc8846d65a7c89af9c")
            .unwrap()
            .try_into()
            .unwrap();
        // Only previously reviewed local public-test native artifacts are selected.
        let engine = unsafe {
            synergy_address_engine::apqe::native_manifest::received_r1_verification_engine(
                &report, pin,
            )
        }
        .unwrap();
        let sigs = d["messages"]
            .as_array()
            .unwrap()
            .iter()
            .map(|m| hex::decode(m["signature_hex"].as_str().unwrap()).unwrap())
            .collect::<Vec<_>>();
        let proofs = sigs
            .iter()
            .enumerate()
            .map(|(i, s)| EnrollmentProof {
                controller_index: i as u32,
                key_generation: 1,
                signature: s,
            })
            .collect::<Vec<_>>();
        let mut state = R1StateMap::new();
        state
            .insert(
                rules_key(),
                InitialWalletRules {
                    base_units: 1,
                    signature_units: 2,
                    input_byte_units: 0,
                    operational_capacity_policy: [7; 48],
                }
                .state_value()
                .unwrap(),
            )
            .unwrap();
        let old = state.clone();
        let budget = WorldResourceBudget::new(32 * 1024 * 1024);
        let result = compute_initial_wallet(
            &state,
            &context(&state, &intent, 17),
            &intent,
            &proofs,
            &engine,
            &budget,
        )
        .unwrap();
        assert!(!result.is_replay());
        assert_eq!(result.original_receipt().paid_nwei, 0);
        assert_eq!(result.original_receipt().refunded_nwei, 0);
        assert_eq!(result.original_receipt().gas_used, 5);
        let wallet = &intent.identity.expected_identity;
        assert_eq!(
            result
                .state()
                .unwrap()
                .get(&R1StateKey::native(R1StateDomain::NativeBalance, wallet).unwrap()),
            Some(&R1StateValue::NativeBalance { amount_nwei: 0 })
        );
        assert_eq!(
            result
                .state()
                .unwrap()
                .get(&R1StateKey::native(R1StateDomain::ReplayCoordinate, wallet).unwrap()),
            Some(&R1StateValue::ReplayNonce { nonce: 0 })
        );
        assert!(matches!(
            result
                .state()
                .unwrap()
                .get(&R1StateKey::native(R1StateDomain::AccountAuthorization, wallet).unwrap()),
            Some(R1StateValue::AccountPolicy {
                policy_epoch: 1,
                ..
            })
        ));
        assert_eq!(result.state().unwrap().len(), old.len() + 4);
        assert_eq!(state, old);
        assert!(result
            .state()
            .unwrap()
            .get(&synergy_state::r1_fees::carry_key())
            .is_none());
        let enrolled = result.state().unwrap().clone();
        let original = result.original_receipt().clone();
        assert!(budget.used() > 0);
        drop(result);
        assert_eq!(budget.used(), 0);
        // An already applied ID is public original-result retrieval, not a new
        // canonical receipt/effect, even after the current receipt position changes.
        let replay = compute_initial_wallet(
            &enrolled,
            &context(&enrolled, &intent, 99),
            &intent,
            &[],
            &CryptoEngine::new(),
            &budget,
        )
        .unwrap();
        assert!(replay.is_replay());
        assert!(replay.state().is_none());
        assert_eq!(replay.original_receipt(), &original);
        assert_eq!(replay.original_receipt().sequence_index, 17);
        drop(replay);
        assert_eq!(budget.used(), 0);
        let mut bad_signature = sigs[1].clone();
        bad_signature[1] ^= 1;
        let bad = [
            EnrollmentProof {
                controller_index: 0,
                key_generation: 1,
                signature: &sigs[0],
            },
            EnrollmentProof {
                controller_index: 1,
                key_generation: 1,
                signature: &bad_signature,
            },
        ];
        assert!(matches!(
            compute_initial_wallet(
                &state,
                &context(&state, &intent, 17),
                &intent,
                &bad,
                &engine,
                &budget
            ),
            Err(EnrollmentError::Proof)
        ));
        assert!(matches!(
            compute_initial_wallet(
                &state,
                &context(&state, &intent, 17),
                &intent,
                &[],
                &engine,
                &budget
            ),
            Err(EnrollmentError::Proof)
        ));
        let tiny = WorldResourceBudget::new(1);
        assert!(matches!(
            compute_initial_wallet(
                &state,
                &context(&state, &intent, 17),
                &intent,
                &proofs,
                &engine,
                &tiny
            ),
            Err(EnrollmentError::Resource)
        ));
        let missing = R1StateMap::new();
        assert!(matches!(
            compute_initial_wallet(
                &missing,
                &context(&missing, &intent, 17),
                &intent,
                &proofs,
                &engine,
                &budget
            ),
            Err(EnrollmentError::Dependency)
        ));
        let mut wrong = context(&state, &intent, 17);
        wrong.coordinate.network.nic[63] ^= 1;
        assert!(matches!(
            compute_initial_wallet(&state, &wrong, &intent, &proofs, &engine, &budget),
            Err(EnrollmentError::Context)
        ));
        assert_eq!(state, old);
        assert_eq!(budget.used(), 0);
    }
}
