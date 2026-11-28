//! Full-width R1 transaction intent and detached native policy authorization.
//! APQE owns C/F and signatures; QACE owns this exact ordered intent schema.
//! No signature, arrival timestamp or current block digest enters the ID.
use synergy_address::r1_public::{
    HashAlgorithm, NativeIdentityPresentation, Primitives, TransactionIdentifierPresentation,
};
use synergy_address_engine::apqe::{
    crypto_engine::CryptoEngine,
    network_birth_r1::ProfileRef,
    policy_transition_r1::{
        verify_received_ordinary_authorization, IndexedOrdinaryProof,
        VerifiedOrdinaryAuthorization, ORDINARY_TRANSACTION_CONTEXT,
    },
    r1_framing::{self as c, NetworkRef, Value},
};
use synergy_protocol_types::{R1NetworkCoordinate, R1ProfileRef};

pub const PROFILE_NAME: &str = "QACE-NATIVE-TX-R1";
pub const PROFILE_REVISION: u32 = 1;
pub const MAX_INPUT_BYTES: usize = 1024 * 1024;
pub const MAX_FRAME_BYTES: usize = MAX_INPUT_BYTES + 8192;
pub const MAX_NATIVE_NWEI: u128 = 12_000_000_000_000_000_000;
pub const PROFILE_SCHEMA:&str=concat!(
 "QACE-NATIVE-TX-R1/1;framing=Identity-R1-C/F;N=[chain_id:u64,NIC:bstr64];",
 "body=[schema:u64(1),[GenesisProfileRef,SHA3-384,bstr48],[ProfileSetRef,SHA3-512,bstr64],[owner_namespace,owner_raw48],policy_epoch:u64,nonce:u64,valid_from_height:u64,valid_until_height:u64,gas_limit:u64,max_fee_per_gas_nwei:u64,action];",
 "action=[0,account_ref,amount_nwei:bstr16BE]|[1,contract_ref,input:bstr<=1048576,value_nwei:bstr16BE]|[2,AIVMProfileRef,code:bstr<=1048576,initializer:bstr<=1048576]|[3,qualified_operation_profile,operation_code:u64,body:bstr<=1048576];",
 "owner_account=synw,syns,syna,synm,synu;contract=synq;profile_exact_catalog_bound;",
 "ID=SHA3-384(F(TRANSACTION.ID,profile,N,body));syntxn+Base64URL64;",
 "approval=F(TRANSACTION.INTENT,profile,N,body);pure_context=QACE/TRANSACTION/R1;detachedindexedcurrentMLDSA87ordinarypolicyquorum;",
 "quantity<=12000000000000000000;epoch>=1;heightvalidityordered;gas_limit>0;checkedfees;noECDSAnativeauthority;noFNDsa/classicalfallback;",
 "native_operation_code_does_not_grant_fee_exemption_or_execution_authority;owninghandler_must_verify_exact_eligible_semantics"
);
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum R1TransactionError {
    Context,
    Profile,
    Identity,
    Bounds,
    Validity,
    Fee,
    Authorization,
    Encoding,
}

#[cfg(test)]
mod tests {
    use super::*;
    fn profile(name: &str) -> R1ProfileRef {
        R1ProfileRef {
            name: name.into(),
            revision: 1,
        }
    }
    fn fixture() -> R1TransactionIntent {
        R1TransactionIntent {
            coordinate: R1NetworkCoordinate {
                network: synergy_protocol_types::R1NetworkRef {
                    chain_id: u64::MAX - 1,
                    nic: [1; 64],
                },
                genesis: synergy_protocol_types::R1GenesisReference {
                    profile: profile("SYNERGY-GENESIS-R1"),
                    digest: [2; 48],
                },
                activated_profiles: synergy_protocol_types::R1ProfileSetReference {
                    profile: profile("APQE-PROFILE-SET"),
                    commitment: [3; 64],
                },
            },
            sender: NativeIdentityPresentation::from_raw("syns", [4; 48]).unwrap(),
            policy_epoch: 1,
            nonce: 0,
            valid_from_height: 1,
            valid_until_height: 100,
            gas_limit: 21000,
            max_fee_per_gas_nwei: 1,
            action: R1Action::Transfer {
                recipient: NativeIdentityPresentation::from_raw("syns", [5; 48]).unwrap(),
                amount_nwei: 7,
            },
        }
    }
    #[test]
    #[ignore = "requires canonical pinned native validation artifacts and public NIST signature fixture"]
    fn actual_native_ordinary_authorization_binds_the_complete_core_intent() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let fixture = root.join("../../../../21-Aegis-Engine/synergy-address-engine/tests/fixtures/r1_ordinary_transaction_public.json");
        let d: serde_json::Value =
            serde_json::from_slice(&std::fs::read(fixture).unwrap()).unwrap();
        assert_eq!(
            d["purpose"],
            "PUBLIC_SYNTHETIC_R1_TRANSACTION_SIGNATURES_ONLY"
        );
        assert_eq!(d["production_import_permitted"], false);
        assert_eq!(d["chain_id"].as_u64(), Some(u64::MAX - 1));
        let decode = |k: &str| hex::decode(d[k].as_str().unwrap()).unwrap();
        let encoded = decode("exact_message_hex");
        let tx = R1TransactionIntent::decode_signing_frame(&encoded).unwrap();
        assert_eq!(tx.sender.to_text(), d["sender"].as_str().unwrap());
        assert_eq!(
            tx.identifier().unwrap().to_text(),
            d["transaction_id"].as_str().unwrap()
        );
        let policy = decode("policy_frame_hex");
        let commitment: [u8; 64] = decode("policy_commitment_hex").try_into().unwrap();
        let report = root.join("../../../../24-Technical-Documentation/testnet-9969-preparation/revisions/r2/provider-validation/build-report.json");
        let pin = hex::decode("1c7851d11260c880aced3fbad8aadc7b68e1f02a379d8efc8846d65a7c89af9c")
            .unwrap()
            .try_into()
            .unwrap();
        // Exact previously qualified local public-test artifacts/report. This
        // loads no caller-supplied library and performs no RNG or key creation.
        let engine = unsafe {
            synergy_address_engine::apqe::native_manifest::received_r1_verification_engine(&report, pin)
        }
        .unwrap();
        let records = d["proofs"].as_array().unwrap();
        let signatures = records
            .iter()
            .map(|r| hex::decode(r["signature_hex"].as_str().unwrap()).unwrap())
            .collect::<Vec<_>>();
        let proofs = records
            .iter()
            .zip(&signatures)
            .map(|(r, s)| IndexedOrdinaryProof {
                controller_index: r["controller_index"].as_u64().unwrap().try_into().unwrap(),
                key_generation: r["key_generation"].as_u64().unwrap(),
                signature: s,
            })
            .collect::<Vec<_>>();
        tx.verify_ordinary(&engine, &policy, &commitment, &proofs)
            .unwrap();
        let mut bad = tx.clone();
        bad.nonce += 1;
        assert!(bad
            .verify_ordinary(&engine, &policy, &commitment, &proofs)
            .is_err());
        let mut bad = tx.clone();
        bad.coordinate.network.nic[63] ^= 1;
        assert!(bad
            .verify_ordinary(&engine, &policy, &commitment, &proofs)
            .is_err());
        let mut bad = tx.clone();
        bad.policy_epoch += 1;
        assert!(bad
            .verify_ordinary(&engine, &policy, &commitment, &proofs)
            .is_err());
        let mut bad_commitment = commitment;
        bad_commitment[63] ^= 1;
        assert!(tx
            .verify_ordinary(&engine, &policy, &bad_commitment, &proofs)
            .is_err());
        assert!(tx
            .verify_ordinary(&CryptoEngine::new(), &policy, &commitment, &proofs)
            .is_err());
        assert!(tx
            .verify_ordinary(&engine, &policy, &commitment, &[])
            .is_err());
    }
    #[test]
    fn independent_python_frame_and_full_transaction_id_match() {
        let v: serde_json::Value = serde_json::from_str(include_str!(
            "../tests/fixtures/r1_native_transaction_public.json"
        ))
        .unwrap();
        let tx = fixture();
        let frame = tx.signing_frame().unwrap();
        assert_eq!(
            hex::encode(&frame),
            v["signing_frame_hex"].as_str().unwrap()
        );
        assert_eq!(
            tx.identifier().unwrap().to_text(),
            v["transaction_id"].as_str().unwrap()
        );
        assert_eq!(
            R1TransactionIntent::decode_signing_frame(&frame).unwrap(),
            tx
        );
        let id_frame = hex::decode(v["id_frame_hex"].as_str().unwrap()).unwrap();
        assert!(R1TransactionIntent::decode_signing_frame(&id_frame).is_err());
    }
    #[test]
    fn network_policy_nonce_fee_and_action_are_independent_signed_bindings() {
        let tx = fixture();
        let original = tx.identifier().unwrap();
        let mut cases = Vec::new();
        let mut t = tx.clone();
        t.coordinate.network.nic[63] ^= 1;
        cases.push(t);
        let mut t = tx.clone();
        t.coordinate.genesis.digest[47] ^= 1;
        cases.push(t);
        let mut t = tx.clone();
        t.coordinate.activated_profiles.commitment[63] ^= 1;
        cases.push(t);
        let mut t = tx.clone();
        t.nonce = 1;
        cases.push(t);
        let mut t = tx.clone();
        t.policy_epoch = 2;
        cases.push(t);
        let mut t = tx.clone();
        t.max_fee_per_gas_nwei = 2;
        cases.push(t);
        for t in cases {
            assert_ne!(t.identifier().unwrap(), original)
        }
        let mut frame = tx.signing_frame().unwrap();
        frame.push(0);
        assert!(R1TransactionIntent::decode_signing_frame(&frame).is_err());
    }
    #[test]
    fn unsupported_types_and_resource_bounds_reject_without_crypto() {
        let mut t = fixture();
        t.sender = NativeIdentityPresentation::from_raw("synq", [4; 48]).unwrap();
        assert_eq!(t.validate(), Err(R1TransactionError::Identity));
        let mut t = fixture();
        t.gas_limit = u64::MAX;
        t.max_fee_per_gas_nwei = u64::MAX;
        assert_eq!(t.validate(), Err(R1TransactionError::Fee));
        let mut t = fixture();
        t.valid_until_height = 0;
        assert_eq!(t.validate(), Err(R1TransactionError::Validity));
        let mut t = fixture();
        t.action = R1Action::Transfer {
            recipient: t.sender.clone(),
            amount_nwei: MAX_NATIVE_NWEI + 1,
        };
        assert_eq!(t.validate(), Err(R1TransactionError::Bounds));
    }
}
impl std::fmt::Display for R1TransactionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "R1 transaction {:?}", self)
    }
}
impl std::error::Error for R1TransactionError {}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum R1Action {
    Transfer {
        recipient: NativeIdentityPresentation,
        amount_nwei: u128,
    },
    AivmCall {
        contract: NativeIdentityPresentation,
        input: Vec<u8>,
        value_nwei: u128,
    },
    AivmDeploy {
        vm_profile: R1ProfileRef,
        code: Vec<u8>,
        initializer: Vec<u8>,
    },
    NativeOperation {
        profile: R1ProfileRef,
        operation_code: u64,
        body: Vec<u8>,
    },
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct R1TransactionIntent {
    pub coordinate: R1NetworkCoordinate,
    pub sender: NativeIdentityPresentation,
    pub policy_epoch: u64,
    pub nonce: u64,
    pub valid_from_height: u64,
    pub valid_until_height: u64,
    pub gas_limit: u64,
    pub max_fee_per_gas_nwei: u64,
    pub action: R1Action,
}
fn profile(p: &R1ProfileRef) -> Result<Value, R1TransactionError> {
    p.validate().map_err(|_| R1TransactionError::Profile)?;
    Ok(Value::Array(vec![
        c::text(&p.name),
        Value::Unsigned(p.revision.into()),
    ]))
}
fn owner(id: &NativeIdentityPresentation) -> Value {
    Value::Array(vec![c::text(id.namespace()), c::bytes(id.raw48())])
}
fn account(id: &NativeIdentityPresentation) -> bool {
    matches!(id.namespace(), "synw" | "syns" | "syna" | "synm" | "synu")
}
fn amount(n: u128) -> Result<Value, R1TransactionError> {
    if n > MAX_NATIVE_NWEI {
        return Err(R1TransactionError::Bounds);
    }
    Ok(c::bytes(&n.to_be_bytes()))
}
impl R1TransactionIntent {
    /// Strict public decoding only. This establishes neither registered identity
    /// nor current policy authority. Historical profile compatibility is resolved
    /// by QACE against authenticated catalogs, never by rewriting this intent.
    pub fn decode_signing_frame(encoded: &[u8]) -> Result<Self, R1TransactionError> {
        fn array(v: &Value, n: usize) -> Result<&[Value], R1TransactionError> {
            match v {
                Value::Array(a) if a.len() == n => Ok(a),
                _ => Err(R1TransactionError::Encoding),
            }
        }
        fn uint(v: &Value) -> Result<u64, R1TransactionError> {
            match v {
                Value::Unsigned(n) => Ok(*n),
                _ => Err(R1TransactionError::Encoding),
            }
        }
        fn text(v: &Value) -> Result<&str, R1TransactionError> {
            match v {
                Value::Text(t) => Ok(t),
                _ => Err(R1TransactionError::Encoding),
            }
        }
        fn bytes(v: &Value) -> Result<&[u8], R1TransactionError> {
            match v {
                Value::Bytes(b) => Ok(b),
                _ => Err(R1TransactionError::Encoding),
            }
        }
        fn fixed<const N: usize>(v: &Value) -> Result<[u8; N], R1TransactionError> {
            bytes(v)?
                .try_into()
                .map_err(|_| R1TransactionError::Encoding)
        }
        fn p(v: &Value) -> Result<R1ProfileRef, R1TransactionError> {
            let a = array(v, 2)?;
            Ok(R1ProfileRef {
                name: text(&a[0])?.into(),
                revision: uint(&a[1])?
                    .try_into()
                    .map_err(|_| R1TransactionError::Profile)?,
            })
        }
        fn id(v: &Value) -> Result<NativeIdentityPresentation, R1TransactionError> {
            let a = array(v, 2)?;
            NativeIdentityPresentation::from_raw(text(&a[0])?, fixed(&a[1])?)
                .map_err(|_| R1TransactionError::Identity)
        }
        let value =
            Value::decode(encoded, MAX_FRAME_BYTES).map_err(|_| R1TransactionError::Encoding)?;
        let frame = array(&value, 6)?;
        if bytes(&frame[0])? != b"SYNERGY/APQE"
            || uint(&frame[1])? != 1
            || text(&frame[2])? != "TRANSACTION.INTENT"
            || p(&frame[3])?
                != (R1ProfileRef {
                    name: PROFILE_NAME.into(),
                    revision: PROFILE_REVISION,
                })
        {
            return Err(R1TransactionError::Encoding);
        }
        let network = array(&frame[4], 2)?;
        let body = array(&frame[5], 11)?;
        if uint(&body[0])? != 1 {
            return Err(R1TransactionError::Encoding);
        }
        let genesis = array(&body[1], 3)?;
        let profiles = array(&body[2], 3)?;
        if text(&genesis[1])? != "SHA3-384" || text(&profiles[1])? != "SHA3-512" {
            return Err(R1TransactionError::Profile);
        }
        let action = match &body[10] {
            Value::Array(a) if a.first().and_then(|v| uint(v).ok()) == Some(0) => {
                let a = array(&body[10], 3)?;
                R1Action::Transfer {
                    recipient: id(&a[1])?,
                    amount_nwei: u128::from_be_bytes(fixed(&a[2])?),
                }
            }
            Value::Array(a) if a.first().and_then(|v| uint(v).ok()) == Some(1) => {
                let a = array(&body[10], 4)?;
                R1Action::AivmCall {
                    contract: id(&a[1])?,
                    input: bytes(&a[2])?.to_vec(),
                    value_nwei: u128::from_be_bytes(fixed(&a[3])?),
                }
            }
            Value::Array(a) if a.first().and_then(|v| uint(v).ok()) == Some(2) => {
                let a = array(&body[10], 4)?;
                R1Action::AivmDeploy {
                    vm_profile: p(&a[1])?,
                    code: bytes(&a[2])?.to_vec(),
                    initializer: bytes(&a[3])?.to_vec(),
                }
            }
            Value::Array(a) if a.first().and_then(|v| uint(v).ok()) == Some(3) => {
                let a = array(&body[10], 4)?;
                R1Action::NativeOperation {
                    profile: p(&a[1])?,
                    operation_code: uint(&a[2])?,
                    body: bytes(&a[3])?.to_vec(),
                }
            }
            _ => return Err(R1TransactionError::Encoding),
        };
        let result = Self {
            coordinate: R1NetworkCoordinate {
                network: synergy_protocol_types::R1NetworkRef {
                    chain_id: uint(&network[0])?,
                    nic: fixed(&network[1])?,
                },
                genesis: synergy_protocol_types::R1GenesisReference {
                    profile: p(&genesis[0])?,
                    digest: fixed(&genesis[2])?,
                },
                activated_profiles: synergy_protocol_types::R1ProfileSetReference {
                    profile: p(&profiles[0])?,
                    commitment: fixed(&profiles[2])?,
                },
            },
            sender: id(&body[3])?,
            policy_epoch: uint(&body[4])?,
            nonce: uint(&body[5])?,
            valid_from_height: uint(&body[6])?,
            valid_until_height: uint(&body[7])?,
            gas_limit: uint(&body[8])?,
            max_fee_per_gas_nwei: uint(&body[9])?,
            action,
        };
        if result.signing_frame()?.as_slice() != encoded {
            return Err(R1TransactionError::Encoding);
        }
        Ok(result)
    }
    pub fn validate(&self) -> Result<(), R1TransactionError> {
        self.coordinate
            .validate()
            .map_err(|_| R1TransactionError::Context)?;
        if self.coordinate.genesis.profile.name != "SYNERGY-GENESIS-R1"
            || self.coordinate.genesis.profile.revision != 1
            || self.coordinate.activated_profiles.profile.name != "APQE-PROFILE-SET"
            || self.coordinate.activated_profiles.profile.revision != 1
        {
            return Err(R1TransactionError::Profile);
        }
        if !account(&self.sender) {
            return Err(R1TransactionError::Identity);
        }
        if self.policy_epoch == 0 || self.valid_from_height > self.valid_until_height {
            return Err(R1TransactionError::Validity);
        }
        if self.gas_limit == 0
            || u128::from(self.gas_limit)
                .checked_mul(u128::from(self.max_fee_per_gas_nwei))
                .is_none_or(|fee| fee > MAX_NATIVE_NWEI)
        {
            return Err(R1TransactionError::Fee);
        }
        match &self.action {
            R1Action::Transfer {
                recipient,
                amount_nwei,
            } => {
                if !account(recipient) {
                    return Err(R1TransactionError::Identity);
                }
                amount(*amount_nwei)?;
            }
            R1Action::AivmCall {
                contract,
                input,
                value_nwei,
            } => {
                if contract.namespace() != "synq" {
                    return Err(R1TransactionError::Identity);
                }
                if input.len() > MAX_INPUT_BYTES {
                    return Err(R1TransactionError::Bounds);
                }
                amount(*value_nwei)?;
            }
            R1Action::AivmDeploy {
                vm_profile,
                code,
                initializer,
            } => {
                vm_profile
                    .validate()
                    .map_err(|_| R1TransactionError::Profile)?;
                if code.is_empty()
                    || code.len() > MAX_INPUT_BYTES
                    || initializer.len() > MAX_INPUT_BYTES
                    || code
                        .len()
                        .checked_add(initializer.len())
                        .is_none_or(|n| n > MAX_INPUT_BYTES)
                {
                    return Err(R1TransactionError::Bounds);
                }
            }
            R1Action::NativeOperation {
                profile: p,
                operation_code,
                body,
            } => {
                p.validate().map_err(|_| R1TransactionError::Profile)?;
                if *operation_code == 0 || body.len() > MAX_INPUT_BYTES {
                    return Err(R1TransactionError::Bounds);
                }
            }
        }
        Ok(())
    }
    fn body(&self) -> Result<Value, R1TransactionError> {
        self.validate()?;
        let action = match &self.action {
            R1Action::Transfer {
                recipient,
                amount_nwei,
            } => Value::Array(vec![
                Value::Unsigned(0),
                owner(recipient),
                amount(*amount_nwei)?,
            ]),
            R1Action::AivmCall {
                contract,
                input,
                value_nwei,
            } => Value::Array(vec![
                Value::Unsigned(1),
                owner(contract),
                c::bytes(input),
                amount(*value_nwei)?,
            ]),
            R1Action::AivmDeploy {
                vm_profile,
                code,
                initializer,
            } => Value::Array(vec![
                Value::Unsigned(2),
                profile(vm_profile)?,
                c::bytes(code),
                c::bytes(initializer),
            ]),
            R1Action::NativeOperation {
                profile: p,
                operation_code,
                body,
            } => Value::Array(vec![
                Value::Unsigned(3),
                profile(p)?,
                Value::Unsigned(*operation_code),
                c::bytes(body),
            ]),
        };
        Ok(Value::Array(vec![
            Value::Unsigned(1),
            Value::Array(vec![
                profile(&self.coordinate.genesis.profile)?,
                c::text("SHA3-384"),
                c::bytes(&self.coordinate.genesis.digest),
            ]),
            Value::Array(vec![
                profile(&self.coordinate.activated_profiles.profile)?,
                c::text("SHA3-512"),
                c::bytes(&self.coordinate.activated_profiles.commitment),
            ]),
            owner(&self.sender),
            Value::Unsigned(self.policy_epoch),
            Value::Unsigned(self.nonce),
            Value::Unsigned(self.valid_from_height),
            Value::Unsigned(self.valid_until_height),
            Value::Unsigned(self.gas_limit),
            Value::Unsigned(self.max_fee_per_gas_nwei),
            action,
        ]))
    }
    fn frame(&self, domain: &str) -> Result<Vec<u8>, R1TransactionError> {
        c::frame(
            domain,
            ProfileRef {
                name: PROFILE_NAME,
                revision: PROFILE_REVISION,
            },
            Some(NetworkRef {
                chain_id: self.coordinate.network.chain_id,
                nic: self.coordinate.network.nic,
            }),
            self.body()?,
            MAX_FRAME_BYTES,
        )
        .map_err(|_| R1TransactionError::Encoding)
    }
    pub fn signing_frame(&self) -> Result<Vec<u8>, R1TransactionError> {
        self.frame("TRANSACTION.INTENT")
    }
    pub fn identifier(&self) -> Result<TransactionIdentifierPresentation, R1TransactionError> {
        let frame = self.frame("TRANSACTION.ID")?;
        let digest: [u8; 48] = Primitives
            .hash(HashAlgorithm::Sha3384, &frame)
            .map_err(|_| R1TransactionError::Encoding)?
            .try_into()
            .map_err(|_| R1TransactionError::Encoding)?;
        TransactionIdentifierPresentation::from_digest("syntxn", digest)
            .map_err(|_| R1TransactionError::Encoding)
    }
    /// Crypto-only. Caller MUST independently authenticate the current account
    /// policy/epoch, native admission and actual target/parent state before effect.
    pub fn verify_ordinary(
        &self,
        engine: &CryptoEngine,
        current_policy_frame: &[u8],
        current_policy_commitment: &[u8; 64],
        proofs: &[IndexedOrdinaryProof<'_>],
    ) -> Result<VerifiedOrdinaryAuthorization, R1TransactionError> {
        if current_policy_frame.len() > 131072 || proofs.len() > 32 {
            return Err(R1TransactionError::Bounds);
        }
        let message = self.signing_frame()?;
        verify_received_ordinary_authorization(
            engine,
            NetworkRef {
                chain_id: self.coordinate.network.chain_id,
                nic: self.coordinate.network.nic,
            },
            current_policy_frame,
            current_policy_commitment,
            &message,
            ORDINARY_TRANSACTION_CONTEXT,
            proofs,
            MAX_FRAME_BYTES,
        )
        .map_err(|_| R1TransactionError::Authorization)
    }
}
