//! Public authoring of the existing ordinary payer self-registration action.
//! This never opens payer custody or submits an admission. The native caller
//! must independently authenticate the supplied processing context and retain
//! its exact one-use request/stage pins before asking its sealed key to sign.
use crate::{
    aegis_keys::{read_bounded, write_public_bytes, write_public_json},
    provider::Engine,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};
use synergy_address_engine::{
    apqe::{provider::SignOptions, Primitives, SecretBytes},
    types::Algorithm,
};
use synergy_aegis::{AegisProtectedPrimitives, ApqeIdentityVerifier};
use synergy_etdag::{
    crypto::IngressKemKeyRegistry, EtdagDigest, ProcessingAdmissionRequest, ProcessingContext,
    ProcessingEnvelope, ProcessingEnvelopeAad, WalletProcessingAdmission, PROCESSING_PROFILE_ID,
};
use synergy_identity::authorization::{
    resolve_transaction_binding_with_verifier, IdentityAuthorizationCarrier,
    IDENTITY_AUTHORIZATION_BINDINGS_STATE_KEY,
};
use synergy_transaction::{
    FeeLimit, NetworkBinding, SignedTransaction, TransactionAction, TransactionClass,
    UnsignedTransaction,
};

pub(super) const USAGE:&str="prepare-wallet-payer-registration REQUEST_JSON OUTPUT_JSON; encrypt-wallet-payer-registration REQUEST_JSON INNER_ML_DSA_87_SIGNATURE STAGE_OUTPUT OUTER_TRANSCRIPT_OUTPUT REVIEW_OUTPUT; attach-wallet-payer-registration REQUEST_JSON STAGE_JSON STAGE_SHA256 OUTER_ML_DSA_87_SIGNATURE OUTPUT_JSON; all require authenticated --apqe-report/--apqe-report-sha256";
const MAX_REQUEST: u64 = 1024 * 1024;
const BASE_FEE: u64 = 40;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    version: u32,
    genesis_path: PathBuf,
    genesis_sha256: String,
    authority_root_path: PathBuf,
    authority_root_sha256: String,
    processing_context: ProcessingContext,
    ingress_kem_registry: IngressKemKeyRegistry,
    registration_carrier_json: String,
    signer_public_key_hex: String,
    payer: String,
    nonce: u64,
    timestamp_unix: u64,
    source_consensus_time_unix: u64,
    finalized_identity_authorization_bindings_json: String,
    max_fee_per_gas_nwei: u64,
}
struct Prepared {
    request: Request,
    request_sha256: String,
    carrier: IdentityAuthorizationCarrier,
    public: Vec<u8>,
    unsigned: UnsignedTransaction,
    genesis_hash: String,
    quoted_execution_gas: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Stage {
    schema: String,
    request_sha256: String,
    genesis_hash: String,
    transaction: SignedTransaction,
    admission: WalletProcessingAdmission,
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn sha(bytes: &[u8]) -> String {
    hex(&AegisProtectedPrimitives.sha256(bytes))
}
fn decode_public(text: &str) -> Result<Vec<u8>, String> {
    synergy_address_engine::snts07::decode_lower_hex("payer ML-DSA-87 public", text, 2592)
}
fn absolute(paths: &[&Path]) -> Result<(), String> {
    if paths.iter().all(|p| p.is_absolute()) {
        Ok(())
    } else {
        Err("explicit absolute public authoring paths required".into())
    }
}
impl Prepared {
    fn load(path: &Path, engine: &Engine) -> Result<Self, String> {
        let raw = read_bounded(path, MAX_REQUEST, "payer registration request")?;
        let r: Request = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
        absolute(&[path, &r.genesis_path, &r.authority_root_path])?;
        let origin = crate::wallet_sponsor_identity::selected_origin(
            &r.genesis_path,
            &r.genesis_sha256,
            &r.authority_root_path,
            &r.authority_root_sha256,
            engine,
        )?;
        r.processing_context
            .validate()
            .map_err(|e| format!("processing context: {e:?}"))?;
        r.ingress_kem_registry
            .validate_protected_profile()
            .map_err(|e| format!("ingress registry: {e:?}"))?;
        let c = &r.processing_context.authority;
        if r.version != 1
            || r.processing_context.profile_id != PROCESSING_PROFILE_ID
            || c.chain_id != origin.unsigned.network.chain_id
            || c.network_id != origin.unsigned.network.network_id
            || r.ingress_kem_registry
                .root()
                .map_err(|e| format!("ingress root: {e:?}"))?
                != c.ingress_kem_registry_root
            || r.timestamp_unix < origin.unsigned.network.activation_unix
            || r.source_consensus_time_unix < origin.unsigned.network.activation_unix
            || r.source_consensus_time_unix > r.timestamp_unix
            || r.nonce == u64::MAX
            || r.max_fee_per_gas_nwei != BASE_FEE
            || r.registration_carrier_json.len() > 128 * 1024
        {
            return Err(
                "payer request changes signed origin, ordinary scope, fee or nonce bounds".into(),
            );
        }
        let carrier = IdentityAuthorizationCarrier::from_canonical_json(
            r.registration_carrier_json.as_bytes(),
        )?;
        let public = decode_public(&r.signer_public_key_hex)?;
        let verifier = ApqeIdentityVerifier::new(engine.clone())?;
        resolve_transaction_binding_with_verifier(
            &BTreeMap::from([(
                IDENTITY_AUTHORIZATION_BINDINGS_STATE_KEY.into(),
                b"{}".to_vec(),
            )]),
            &r.payer,
            &carrier,
            &public,
            c.chain_id,
            &c.network_id,
            r.source_consensus_time_unix,
            Some(&verifier),
        )?;
        let input = r.registration_carrier_json.as_bytes().to_vec();
        let gas_limit = 50_000u64
            .checked_add(input.len() as u64)
            .ok_or("registration gas overflow")?;
        if r.finalized_identity_authorization_bindings_json.len()
            > synergy_identity::registration::MAX_AUTHORIZATION_TABLE_BYTES
        {
            return Err("finalized ordinary identity table exceeds its existing bound".into());
        }
        let resulting = synergy_identity::registration::register_authorization_with_verifier(
            &BTreeMap::from([(
                IDENTITY_AUTHORIZATION_BINDINGS_STATE_KEY.into(),
                r.finalized_identity_authorization_bindings_json
                    .as_bytes()
                    .to_vec(),
            )]),
            &r.payer,
            &carrier,
            c.chain_id,
            &c.network_id,
            r.source_consensus_time_unix,
            Some(&verifier),
        )?;
        let quoted_execution_gas = 50_000u64
            .checked_add(resulting.len() as u64)
            .ok_or("registration gas quote overflow")?;
        if quoted_execution_gas > gas_limit {
            return Err(
                "current canonical registration table requires more than this reviewed gas limit"
                    .into(),
            );
        }
        if gas_limit > origin.unsigned.etdag.parameters.max_protected_gas {
            return Err("registration exceeds existing signed ETDAG gas bound".into());
        }
        let payload = TransactionAction::Native {
            module: "identity".into(),
            method: "register_authorization".into(),
            input,
        }
        .encode()
        .map_err(|e| e.to_string())?;
        let unsigned = UnsignedTransaction {
            network: NetworkBinding::new(c.chain_id, c.network_id.clone())
                .map_err(|e| e.to_string())?,
            class: TransactionClass::User,
            sender: r.payer.clone(),
            receiver: r.payer.clone(),
            amount_nwei: 0,
            nonce: r.nonce,
            fee_limit: FeeLimit {
                gas_limit,
                max_fee_per_gas_nwei: BASE_FEE,
            },
            timestamp_unix: r.timestamp_unix,
            payload,
        };
        unsigned.validate_structure().map_err(|e| e.to_string())?;
        Ok(Self {
            request: r,
            request_sha256: sha(&raw),
            carrier,
            public,
            unsigned,
            genesis_hash: origin.genesis_hash,
            quoted_execution_gas,
        })
    }
    fn review(&self) -> Result<Value, String> {
        let transcript = self.unsigned.signing_bytes().map_err(|e| e.to_string())?;
        Ok(
            json!({"schema":"synergy-wallet-payer-registration-review-v1","request_sha256":self.request_sha256,
            "chain_id":self.unsigned.network.chain_id,"network_id":self.unsigned.network.network_id,"genesis_hash":self.genesis_hash,
            "payer":self.request.payer,"nonce":self.request.nonce,"gas_limit":self.unsigned.fee_limit.gas_limit,
            "maximum_fee_nwei":(u128::from(self.unsigned.fee_limit.gas_limit)*u128::from(BASE_FEE)).to_string(),
            "source_consensus_time_unix":self.request.source_consensus_time_unix,
            "quoted_execution_gas":self.quoted_execution_gas,
            "quoted_execution_fee_nwei":(u128::from(self.quoted_execution_gas)*u128::from(BASE_FEE)).to_string(),
            "actual_registration_gas_rule":"50000+resulting_identity_authorization_bindings_json_bytes",
            "registration_input_bytes":self.request.registration_carrier_json.len(),"transaction_id":self.unsigned.id().map_err(|e|e.to_string())?.0,
            "inner_transcript_hex":hex(&transcript),"inner_transcript_sha256":sha(&transcript),
            "processing_context_authenticated":false,"finalized_registration_verified":false}),
        )
    }
    fn verify(&self, bytes: &[u8], signature: &[u8], engine: &Engine) -> Result<(), String> {
        if signature.len() != 4627
            || !engine
                .lock()
                .map_err(|_| "native APQE unavailable")?
                .verify(
                    Algorithm::MlDsa87,
                    &self.public,
                    bytes,
                    signature,
                    SignOptions::default(),
                )
                .map_err(|e| e.to_string())?
        {
            return Err("invalid exact payer ML-DSA-87 signature".into());
        }
        Ok(())
    }
}
pub(super) fn prepare(request: &Path, output: &Path, engine: Engine) -> Result<(), String> {
    absolute(&[request, output])?;
    write_public_json(output, &Prepared::load(request, &engine)?.review()?)
}
pub(super) fn encrypt(
    request: &Path,
    inner_signature: &Path,
    stage_output: &Path,
    transcript_output: &Path,
    output: &Path,
    engine: Engine,
) -> Result<(), String> {
    absolute(&[
        request,
        inner_signature,
        stage_output,
        transcript_output,
        output,
    ])?;
    if [stage_output, transcript_output, output]
        .iter()
        .any(|p| p.exists())
        || stage_output == transcript_output
        || stage_output == output
        || transcript_output == output
    {
        return Err("fresh distinct native authoring outputs required".into());
    }
    let p = Prepared::load(request, &engine)?;
    let signature = read_bounded(inner_signature, 4627, "payer inner signature")?;
    p.verify(
        &p.unsigned.signing_bytes().map_err(|e| e.to_string())?,
        &signature,
        &engine,
    )?;
    let transaction = SignedTransaction {
        unsigned: p.unsigned.clone(),
        signer_public_key: p.public.clone(),
        signature,
        signature_algorithm: "ML-DSA-87".into(),
        identity_authorization: Some(p.carrier.clone()),
    };
    let plaintext = SecretBytes::from_bytes(synergy_transaction::encode_processing_transaction(
        &transaction,
    )?);
    let padded = SecretBytes::from_bytes(
        synergy_etdag::crypto::pad_plaintext(plaintext.as_bytes())
            .map_err(|e| format!("registration ciphertext class: {e:?}"))?,
    );
    let context = &p.request.processing_context;
    let c = &context.authority;
    let aad = ProcessingEnvelopeAad {
        profile_id: PROCESSING_PROFILE_ID.into(),
        chain_id: c.chain_id,
        network_id: c.network_id.clone(),
        protocol_version: c.protocol_version.clone(),
        epoch: c.epoch,
        processing_context_root: context
            .root()
            .map_err(|e| format!("processing root: {e:?}"))?,
        authorization_height: c.target_height,
        assigned_cluster_id: c.assigned_cluster_id,
        lane_id: "ordinary-user".into(),
        sender_id: p.request.payer.clone(),
        nonce_slot: p.request.nonce,
    };
    let recipients = p
        .request
        .ingress_kem_registry
        .records
        .iter()
        .filter(|r| {
            r.activation_height <= c.target_height
                && r.retirement_height.is_none_or(|h| c.target_height < h)
        })
        .cloned()
        .collect::<Vec<_>>();
    if recipients.len() != c.assigned_cluster_validator_count as usize {
        return Err("active authenticated ingress recipient count differs".into());
    }
    let kem = synergy_aegis::ApqeKem::mlkem1024(engine.clone())
        .map_err(|e| format!("native KEM: {e:?}"))?;
    let encrypted = synergy_etdag::crypto::encrypt_protected_payload_with_kem(
        &aad,
        &recipients,
        synergy_etdag::certificate_quorum(recipients.len())
            .map_err(|e| format!("quorum: {e:?}"))?,
        padded.as_bytes(),
        &kem,
    )
    .map_err(|e| format!("native encryption: {e:?}"))?;
    let empty = EtdagDigest::from_domain_bytes("SYNERGY_NATIVE_PAYER_REGISTRATION_PENDING_V1", b"");
    let mut order = [0; 32];
    Primitives
        .random_bytes(&mut order)
        .map_err(|_| "native secure entropy unavailable")?;
    let mut envelope = ProcessingEnvelope {
        envelope_version: 1,
        envelope_id: empty.clone(),
        aad,
        aead_nonce: encrypted.aead_nonce,
        key_commitment: encrypted.key_commitment,
        share_commitment_root: empty.clone(),
        share_capsule_root: empty,
        ciphertext: encrypted.ciphertext,
        share_capsules: encrypted.share_capsules,
        content_blind_order_key: EtdagDigest::from_domain_bytes(
            "SYNERGY_NATIVE_PAYER_REGISTRATION_ORDER_V1",
            &order,
        ),
    };
    envelope
        .refresh_capsule_roots()
        .map_err(|e| format!("capsule roots: {e:?}"))?;
    envelope.envelope_id = envelope
        .commitment()
        .map_err(|e| format!("envelope commitment: {e:?}"))?;
    let admission = WalletProcessingAdmission {
        request: ProcessingAdmissionRequest {
            request_version: 1,
            context_root: context.root().map_err(|e| format!("context root: {e:?}"))?,
            sender_wallet: p.request.payer.clone(),
            sender_nonce: p.request.nonce,
            gas_class_units: p.unsigned.fee_limit.gas_limit,
            fee_class: 1,
            signature_algorithm: "ML-DSA-87".into(),
            signer_public_key: p.public.clone(),
            envelope,
            signature: vec![],
        },
        identity_authorization: p.carrier.clone(),
    };
    let transcript = admission
        .request
        .signing_bytes()
        .map_err(|e| format!("outer transcript: {e:?}"))?;
    let stage = Stage {
        schema: "synergy-wallet-payer-registration-stage-v1".into(),
        request_sha256: p.request_sha256.clone(),
        genesis_hash: p.genesis_hash.clone(),
        transaction,
        admission,
    };
    let stage_json = serde_json::to_string(&stage).map_err(|e| e.to_string())?;
    let mut value = p.review()?;
    value["schema"] = json!("synergy-wallet-payer-registration-encrypted-v1");
    value["stage_sha256"] = json!(sha(stage_json.as_bytes()));
    value["plaintext_bytes"] = json!(plaintext.as_bytes().len());
    value["ciphertext_bytes"] = json!(stage.admission.request.envelope.ciphertext.len());
    value["outer_transcript_sha256"] = json!(sha(&transcript));
    write_public_bytes(stage_output, stage_json.as_bytes())?;
    if let Err(error) = write_public_bytes(transcript_output, &transcript) {
        let _ = std::fs::remove_file(stage_output);
        return Err(error);
    }
    if let Err(error) = write_public_json(output, &value) {
        let _ = std::fs::remove_file(stage_output);
        let _ = std::fs::remove_file(transcript_output);
        return Err(error);
    }
    Ok(())
}
pub(super) fn attach(
    request: &Path,
    stage_path: &Path,
    stage_sha256: &str,
    outer_signature: &Path,
    output: &Path,
    engine: Engine,
) -> Result<(), String> {
    absolute(&[request, stage_path, outer_signature, output])?;
    let p = Prepared::load(request, &engine)?;
    let raw = read_bounded(stage_path, 2 * 1024 * 1024, "original public payer stage")?;
    if sha(&raw) != stage_sha256 {
        return Err("payer encrypted stage differs from the exact one-use journal pin".into());
    }
    let mut stage: Stage = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
    if stage.schema != "synergy-wallet-payer-registration-stage-v1"
        || stage.request_sha256 != p.request_sha256
        || stage.genesis_hash != p.genesis_hash
        || stage.transaction.unsigned != p.unsigned
        || stage.transaction.signer_public_key != p.public
        || stage.transaction.identity_authorization.as_ref() != Some(&p.carrier)
        || stage.transaction.signature_algorithm != "ML-DSA-87"
        || stage.admission.identity_authorization != p.carrier
        || stage.admission.request.signer_public_key != p.public
        || stage.admission.request.gas_class_units != p.unsigned.fee_limit.gas_limit
        || stage.admission.request.fee_class != 1
    {
        return Err("payer stage changes the exact independently reviewed registration".into());
    }
    p.verify(
        &p.unsigned.signing_bytes().map_err(|e| e.to_string())?,
        &stage.transaction.signature,
        &engine,
    )?;
    let signature = read_bounded(outer_signature, 4627, "payer outer signature")?;
    p.verify(
        &stage
            .admission
            .request
            .signing_bytes()
            .map_err(|e| format!("outer transcript: {e:?}"))?,
        &signature,
        &engine,
    )?;
    stage.admission.request.signature = signature;
    stage
        .admission
        .request
        .validate_context(&p.request.processing_context)
        .map_err(|e| format!("outer context: {e:?}"))?;
    if stage.admission.request.sender_wallet != p.request.payer
        || stage.admission.request.sender_nonce != p.request.nonce
    {
        return Err("payer outer account or nonce changed".into());
    }
    let admission_json = serde_json::to_string(&stage.admission).map_err(|e| e.to_string())?;
    let mut value = p.review()?;
    value["schema"] = json!("synergy-wallet-payer-registration-admission-v1");
    value["receipt_id"] = json!(
        EtdagDigest::from_canonical(
            "SYNERGY_LOCAL_PROCESSING_ADMISSION_RECEIPT_V1",
            &stage.admission
        )
        .map_err(|e| format!("receipt id: {e:?}"))?
        .0
    );
    value["admission_sha256"] = json!(sha(admission_json.as_bytes()));
    value["admission_json"] = json!(admission_json);
    value["submitted"] = json!(false);
    write_public_json(output, &value)
}
