//! Ordinary engineering treasury custody for the existing Genesis allocation.
//! No raw key export, protected-account enrollment, or runtime mint operation.
use crate::validator_formation::{
    begin, decode, digest, passphrase, private_dir, read, sync, write,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::Path;
use synergy_address_engine::{
    apqe::{fixed_digest, provider::SignOptions, FixedDigest, Primitives, SecretBytes},
    encrypt::{decrypt_with_passphrase, encrypt_with_passphrase, EncryptedEnvelope},
    types::Algorithm,
    validator_provisioning::FormationContext,
};
use synergy_identity::authorization::*;

const LIMIT: u64 = 128 * 1024;
const ROLE: &str = "ordinary-genesis-treasury-fndsa1024-mldsa87-v1";
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Parameters {
    formation_sha256: String,
    effective_at_unix: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    version: u32,
    operation: String,
    parameters: Parameters,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Public {
    address: String,
    authorization: IdentityAuthorizationCarrier,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Custody {
    version: u32,
    role: String,
    formation: FormationContext,
    request_sha256: String,
    public_sha256: String,
    identity: EncryptedEnvelope,
    spending: EncryptedEnvelope,
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn hash(bytes: &[u8]) -> String {
    hex(&fixed_digest(&Primitives, FixedDigest::Sha3256, bytes))
}
fn encode(value: &impl Serialize) -> Result<Vec<u8>, String> {
    serde_json::to_vec_pretty(value).map_err(|_| "Cannot encode ordinary treasury".into())
}
fn request(path: &Path, pin: &str, formation_pin: &str) -> Result<(Request, SecretBytes), String> {
    let raw = read(path, 4096, true)?;
    let value: Request = decode(&raw)?;
    if pin.len() != 64
        || digest(raw.as_bytes()) != pin
        || value.version != 1
        || value.operation != "treasury_prepare"
        || value.parameters.formation_sha256 != formation_pin
        || value.parameters.effective_at_unix == 0
        || i64::try_from(value.parameters.effective_at_unix)
            .ok()
            .and_then(|t| chrono::DateTime::from_timestamp(t, 0))
            .is_none()
    {
        return Err("Exact ordinary treasury request and formation required".into());
    }
    Ok((value, raw))
}

pub fn prepare(
    context_path: &Path,
    context_pin: &str,
    request_path: &Path,
    request_pin: &str,
    directory: &Path,
    engine: crate::provider::Engine,
) -> Result<Value, String> {
    let context = crate::validator_formation::pinned_context(context_path, context_pin)?;
    let (request, raw) = request(request_path, request_pin, context_pin)?;
    let chain = u64::from_str_radix(&context.chain_id_hex, 16)
        .map_err(|_| "Treasury chain exceeds supported u64")?;
    // Reserve before generation; incomplete state is reconciled, never regenerated.
    begin(directory)?;
    write(&directory.join("request.json"), raw.as_bytes())?;
    let mut entropy = vec![0; 32];
    let generated = Primitives.random_bytes(&mut entropy);
    let entropy = SecretBytes::from_bytes(entropy);
    generated.map_err(|_| "APQE secure randomness unavailable")?;
    let unlock = SecretBytes::from_bytes(hex(entropy.as_bytes()).into_bytes());
    let provider = engine.lock().map_err(|_| "APQE provider unavailable")?;
    let root = provider
        .generate_keypair(Algorithm::FnDsa1024)
        .map_err(|e| e.to_string())?;
    let spending = provider
        .generate_keypair(Algorithm::MlDsa87)
        .map_err(|e| e.to_string())?;
    let address = synergy_address::derive_key_controlled_address("syna", &root.public_key)?;
    let effective =
        chrono::DateTime::from_timestamp(request.parameters.effective_at_unix as i64, 0)
            .ok_or("Invalid treasury effective time")?
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let mut binding: IdentityAuthorizationBinding = serde_json::from_value(json!({
        "schema_version":AUTH_BINDING_SCHEMA_VERSION,"binary_encoding":AUTH_BINDING_BINARY_ENCODING,
        "identity_id":"formation-treasury","identity_address":address,
        "identity_root":{"algorithm":"FN-DSA-1024","public_key":hex(&root.public_key),"public_key_sha3_256":hash(&root.public_key)},
        "authorization_policy":{"policy_type":"single-key","threshold":1,"principals":[{
            "principal_id":"treasury","principal_type":"public-key","algorithm":"ML-DSA-87",
            "public_key":hex(&spending.public_key),"public_key_sha3_256":hash(&spending.public_key),
            "status":"active","purposes":["transaction-signing"]}]},
        "authorization_scopes":[{"signature_domain":AEGIS_TRANSACTION_AUTHORIZATION_DOMAIN,"chain_id":chain,
            "network_id":context.network_id,"purpose":"transaction-signing"}],
        "current_auth_key_hash":hash(&spending.public_key),"auth_key_history":[],"supersession_history":[],
        "effective_at":effective,"binding_payload_sha3_256":"",
        "proofs":{"identity_root":{"algorithm":"FN-DSA-1024","signature":""}}
    })).map_err(|_| "Cannot form ordinary authorization")?;
    let payload = canonical_binding_payload(&binding)?;
    binding.binding_payload_sha3_256 = hash(&payload);
    let message = [AUTH_BINDING_SIGNATURE_DOMAIN, &payload].concat();
    binding.proofs.identity_root.signature = hex(&provider
        .sign(
            Algorithm::FnDsa1024,
            root.private_key.as_bytes(),
            &message,
            SignOptions::default(),
        )
        .map_err(|e| e.to_string())?);
    binding.proofs.authorization_key_possession = vec![AuthorizationKeyPossessionProof {
        principal_id: "treasury".into(),
        algorithm: "ML-DSA-87".into(),
        signature: hex(&provider
            .sign(
                Algorithm::MlDsa87,
                spending.private_key.as_bytes(),
                &message,
                SignOptions::default(),
            )
            .map_err(|e| e.to_string())?),
    }];
    let public = Public {
        address,
        authorization: IdentityAuthorizationCarrier {
            schema_version: AUTHORIZATION_CARRIER_SCHEMA_VERSION,
            signature_domain: AEGIS_TRANSACTION_AUTHORIZATION_DOMAIN.into(),
            binding,
        },
    };
    let public_raw = encode(&public)?;
    let custody = Custody {
        version: 1,
        role: ROLE.into(),
        formation: context,
        request_sha256: request_pin.into(),
        public_sha256: digest(&public_raw),
        identity: encrypt_with_passphrase(
            &provider,
            &Primitives,
            root.private_key.as_bytes(),
            passphrase(&unlock)?,
        )?,
        spending: encrypt_with_passphrase(
            &provider,
            &Primitives,
            spending.private_key.as_bytes(),
            passphrase(&unlock)?,
        )?,
    };
    drop(provider);
    write(&directory.join("treasury-public.json"), &public_raw)?;
    write(&directory.join("treasury.enc.json"), &encode(&custody)?)?;
    write(&directory.join("unlock"), unlock.as_bytes())?;
    sync(directory)?;
    status(context_path, context_pin, directory, engine, false)
}

pub fn status(
    context_path: &Path,
    context_pin: &str,
    directory: &Path,
    engine: crate::provider::Engine,
    export: bool,
) -> Result<Value, String> {
    private_dir(directory)?;
    let context = crate::validator_formation::pinned_context(context_path, context_pin)?;
    let custody: Custody = decode(&read(&directory.join("treasury.enc.json"), LIMIT, true)?)?;
    let (request, _) = request(
        &directory.join("request.json"),
        &custody.request_sha256,
        context_pin,
    )?;
    let raw = read(&directory.join("treasury-public.json"), LIMIT, true)?;
    let public: Public = decode(&raw)?;
    if custody.version != 1
        || custody.role != ROLE
        || custody.formation != context
        || custody.public_sha256 != digest(raw.as_bytes())
    {
        return Err("Ordinary treasury custody scope differs".into());
    }
    let chain = u64::from_str_radix(&context.chain_id_hex, 16)
        .map_err(|_| "Treasury chain exceeds supported u64")?;
    let binding = &public.authorization.binding;
    let root = synergy_address_engine::snts07::decode_lower_hex(
        "ordinary identity",
        &binding.identity_root.public_key,
        1793,
    )?;
    let principals = &binding.authorization_policy.principals;
    if principals.len() != 1
        || principals[0].principal_id != "treasury"
        || binding.identity_address != public.address
        || !public.address.starts_with("syna")
    {
        return Err("Ordinary treasury public identity differs".into());
    }
    let spending = synergy_address_engine::snts07::decode_lower_hex(
        "ordinary spending key",
        principals[0]
            .public_key
            .as_deref()
            .ok_or("Treasury key absent")?,
        2592,
    )?;
    let verifier = synergy_aegis::ApqeIdentityVerifier::new(engine.clone())?;
    resolve_transaction_binding_with_verifier(
        &std::collections::BTreeMap::from([(
            IDENTITY_AUTHORIZATION_BINDINGS_STATE_KEY.into(),
            b"{}".to_vec(),
        )]),
        &public.address,
        &public.authorization,
        &spending,
        chain,
        &context.network_id,
        request.parameters.effective_at_unix,
        Some(&verifier),
    )?;
    let unlock = read(&directory.join("unlock"), 64, true)?;
    let provider = engine.lock().map_err(|_| "APQE provider unavailable")?;
    // Fresh possession challenges tie BOTH encrypted keys to the verified public carrier.
    let challenge = format!(
        "SYNERGY-ORDINARY-TREASURY-CUSTODY-V1\0{}\0{}",
        custody.request_sha256, custody.public_sha256
    );
    for (algorithm, envelope, key) in [
        (Algorithm::FnDsa1024, &custody.identity, &root),
        (Algorithm::MlDsa87, &custody.spending, &spending),
    ] {
        let secret = SecretBytes::from_bytes(decrypt_with_passphrase(
            &provider,
            &Primitives,
            envelope,
            passphrase(&unlock)?,
        )?);
        let proof = provider
            .sign(
                algorithm,
                secret.as_bytes(),
                challenge.as_bytes(),
                SignOptions::default(),
            )
            .map_err(|e| e.to_string())?;
        if !provider
            .verify(
                algorithm,
                key,
                challenge.as_bytes(),
                &proof,
                SignOptions::default(),
            )
            .map_err(|e| e.to_string())?
        {
            return Err("Ordinary treasury custody possession failed".into());
        }
    }
    let mut result = json!({"schema":"nodenetwork-formation-treasury-v1","pending":true,
        "address":public.address,"network_id":context.network_id,"chain_id":chain.to_string(),
        "formation_sha256":context_pin,"request_sha256":custody.request_sha256,
        "effective_at_unix":request.parameters.effective_at_unix,"authorization_sha256":digest(&serde_json::to_vec(&serde_json::to_value(&public.authorization).map_err(|_|"Cannot encode public authorization")?).map_err(|_|"Cannot encode public authorization")?),
        "possession_verified":true,"allocation_nwei":"5000000000000000"});
    if export {
        result["schema"] = "nodenetwork-formation-treasury-export-v1".into();
        result["canary_testing_treasury"] =
            serde_json::to_value(public).map_err(|_| "Cannot export public treasury")?;
    }
    Ok(result)
}

// The controller obtains these public observations through its authenticated
// local RPC path. Frozen encryption authority is independently checked below
// against the APQE-signed formation, never granted by the observation hash.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SendParameters {
    formation_sha256: String,
    genesis_sha256: String,
    processing_context_json: String,
    processing_context_sha256: String,
    receiver: String,
    amount_nwei: String,
    nonce: u64,
    observed_balance_nwei: String,
    timestamp_unix: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SendRequest {
    version: u32,
    operation: String,
    parameters: SendParameters,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SendRecord {
    version: u32,
    request_sha256: String,
    formation_sha256: String,
    genesis_sha256: String,
    unsigned: synergy_transaction::UnsignedTransaction,
    transaction_id: String,
    transaction_signature: Vec<u8>,
    admission_sha256: String,
    receipt_id: String,
}
fn decimal(value: &str) -> Result<u128, String> {
    let n = value
        .parse::<u128>()
        .map_err(|_| "Canonical nWei decimal required")?;
    if n.to_string() != value {
        return Err("Canonical nWei decimal required".into());
    }
    Ok(n)
}
fn send_request(path: &Path, pin: &str) -> Result<(SendRequest, SecretBytes), String> {
    let raw = read(path, 2 * 1024 * 1024, true)?;
    let request: SendRequest = decode(&raw)?;
    if digest(raw.as_bytes()) != pin
        || request.version != 1
        || request.operation != "treasury_send_prepare"
    {
        return Err("Exact approved treasury send request required".into());
    }
    Ok((request, raw))
}
fn authenticated_send_context(
    formation: &FormationContext,
    p: &SendParameters,
    exported: &Value,
) -> Result<
    (
        synergy_etdag::ProcessingContext,
        synergy_etdag::crypto::IngressKemKeyRegistry,
    ),
    String,
> {
    let genesis_raw = exported["artifacts"]["genesis.json"]
        .as_str()
        .ok_or("Signed Genesis absent")?;
    let signed: synergy_genesis::signing::SignedGenesis =
        serde_json::from_str(genesis_raw).map_err(|_| "Invalid signed Genesis")?;
    let binding: synergy_genesis::authority::SignedAuthorityBinding = serde_json::from_str(
        exported["artifacts"]["authority.json"]
            .as_str()
            .ok_or("Signed authority absent")?,
    )
    .map_err(|_| "Invalid signed authority")?;
    // signed_public has already independently verified BOTH signatures and
    // their pinned root. This function never accepts a caller-created export.
    if p.genesis_sha256 != digest(genesis_raw.as_bytes())
        || signed.unsigned.network.network_id != formation.network_id
    {
        return Err("Treasury send differs from authenticated signed Genesis".into());
    }
    if p.processing_context_json.len() > 1024 * 1024
        || digest(p.processing_context_json.as_bytes()) != p.processing_context_sha256
    {
        return Err("Exact bounded processing response required".into());
    }
    let response: Value = serde_json::from_str(&p.processing_context_json)
        .map_err(|_| "Invalid processing response")?;
    let context: synergy_etdag::ProcessingContext =
        serde_json::from_value(response["context"].clone())
            .map_err(|_| "Processing context absent")?;
    let registry: synergy_etdag::crypto::IngressKemKeyRegistry =
        serde_json::from_value(response["ingress_kem_registry"].clone())
            .map_err(|_| "Processing registry absent")?;
    let a = &binding.payload;
    let policy = a
        .protected
        .as_ref()
        .ok_or("Signed processing policy absent")?;
    let frozen = synergy_posy::FrozenValidatorRegistry::new(
        a.epoch,
        a.validators.iter().map(|v| v.record.clone()).collect(),
    )
    .map_err(|e| e.to_string())?;
    let epoch = synergy_posy::SimplifiedEpochContext::from_frozen_registry(
        a.chain_id,
        a.network_id.clone(),
        a.epoch,
        a.epoch_start_height,
        a.epoch_end_height,
        a.finalized_epoch_seed_root.clone(),
        a.consensus_parameter_root.clone(),
        &frozen,
    )
    .map_err(|e| e.to_string())?;
    context
        .validate()
        .map_err(|e| format!("Processing context: {e:?}"))?;
    context
        .authority
        .validate_with_parameters(&policy.parameters)
        .map_err(|e| format!("Processing source mapping: {e:?}"))?;
    registry
        .validate_protected_profile()
        .map_err(|e| format!("Processing ingress: {e:?}"))?;
    let c = &context.authority;
    if a.epoch != 1
        || policy.cutoff_relationship
            != synergy_genesis::authority::ProtectedCutoffRelationship::ProcessingGroupsV1
        || response["profile_id"] != synergy_etdag::PROCESSING_PROFILE_ID
        || c.chain_id != epoch.chain_id
        || c.network_id != epoch.network_id
        || c.protocol_version != epoch.protocol_version
        || c.epoch != epoch.epoch
        || (c.source_finalized_height == 0
            && c.source_finality_context_root != a.anchor_parent.reference_id())
        || c.target_height < a.epoch_start_height
        || c.target_height > a.epoch_end_height
        || c.active_validator_set_root != epoch.active_validator_set_root
        || c.validator_consensus_key_root != epoch.validator_consensus_key_root
        || c.frozen_voting_weight_root != epoch.frozen_voting_weight_root
        || c.finalized_epoch_seed_root != epoch.finalized_epoch_seed_root
        || c.consensus_parameter_root != epoch.consensus_parameter_root
        || c.cluster_schedule_version != policy.cluster_schedule_version
        || c.assigned_height_schedule_root != policy.assigned_height_schedule_root
        || c.cluster_map_root != policy.cluster_map_root
        || c.assigned_cluster_id != policy.assigned_cluster_id
        || c.assigned_cluster_membership_root != policy.assigned_cluster_membership_root
        || c.cryptographic_profile_root != policy.cryptographic_profile_root
        || c.assigned_cluster_validator_count != frozen.active_count() as u64
        || u128::from(c.assigned_cluster_total_voting_weight)
            != frozen.active_weight().map_err(|e| e.to_string())?
        || registry != policy.ingress_kem_registry
        || registry
            .root()
            .map_err(|e| format!("Registry root: {e:?}"))?
            != c.ingress_kem_registry_root
    {
        return Err("Processing context is outside authenticated signed E1 authority; successor lineage is not supported by this adapter".into());
    }
    Ok((context, registry))
}
fn send_path(treasury: &Path, nonce: u64) -> Result<std::path::PathBuf, String> {
    private_dir(treasury)?;
    Ok(treasury.join("sends").join(format!("{nonce:020}")))
}
/// Prepare one immutable encrypted admission. No network request is made here.
/// Any partial reservation permanently fences this nonce until qualified recovery.
#[allow(clippy::too_many_arguments)]
pub fn prepare_send(
    context_path: &Path,
    context_pin: &str,
    formation_directory: &Path,
    request_path: &Path,
    request_pin: &str,
    treasury: &Path,
    engine: crate::provider::Engine,
) -> Result<Value, String> {
    use synergy_etdag::{
        EtdagDigest, ProcessingAdmissionRequest, ProcessingEnvelope, ProcessingEnvelopeAad,
        WalletProcessingAdmission, PROCESSING_PROFILE_ID,
    };
    let formation = crate::validator_formation::pinned_context(context_path, context_pin)?;
    let (request, raw) = send_request(request_path, request_pin)?;
    let p = &request.parameters;
    if p.formation_sha256 != context_pin {
        return Err("Treasury send formation differs".into());
    }
    let path = send_path(treasury, p.nonce)?;
    if path
        .try_exists()
        .map_err(|_| "Cannot inspect nonce reservation")?
    {
        // Reconciliation returns only already signed public metadata; it does
        // not sign, encrypt, expose an admission, or need a live RPC response.
        let receipt = send_status(treasury, p.nonce, engine)?;
        if receipt["request_sha256"] != request_pin {
            return Err("Nonce already reserved for a different immutable treasury intent".into());
        }
        return Ok(receipt);
    }
    status(context_path, context_pin, treasury, engine.clone(), false)?;
    let exported = crate::network_formation::signed_public(
        context_path,
        context_pin,
        formation_directory,
        engine.clone(),
    )?;
    let (context, registry) = authenticated_send_context(&formation, p, &exported)?;
    let public: Public = decode(&read(&treasury.join("treasury-public.json"), LIMIT, true)?)?;
    let amount = decimal(&p.amount_nwei)?;
    let total = amount
        .checked_add(21_000 * 40)
        .ok_or("Treasury transfer cost overflow")?;
    if amount == 0 || decimal(&p.observed_balance_nwei)? < total || p.nonce == u64::MAX {
        return Err(
            "Positive affordable treasury transfer and advanceable observed nonce required".into(),
        );
    }
    let unsigned = synergy_transaction::UnsignedTransaction {
        network: synergy_transaction::NetworkBinding::new(
            context.authority.chain_id,
            context.authority.network_id.clone(),
        )
        .map_err(|e| e.to_string())?,
        class: synergy_transaction::TransactionClass::User,
        sender: public.address.clone(),
        receiver: p.receiver.clone(),
        amount_nwei: amount,
        nonce: p.nonce,
        fee_limit: synergy_transaction::FeeLimit {
            gas_limit: 21_000,
            max_fee_per_gas_nwei: 40,
        },
        timestamp_unix: p.timestamp_unix,
        payload: Vec::new(),
    };
    let transcript = unsigned.signing_bytes().map_err(|e| e.to_string())?;
    let transaction_id = unsigned.id().map_err(|e| e.to_string())?.0;
    let spending = synergy_address_engine::snts07::decode_lower_hex(
        "Treasury spending public",
        public.authorization.binding.authorization_policy.principals[0]
            .public_key
            .as_deref()
            .ok_or("Spending public absent")?,
        2592,
    )?;
    let verifier = synergy_aegis::ApqeIdentityVerifier::new(engine.clone())?;
    resolve_transaction_binding_with_verifier(
        &std::collections::BTreeMap::from([(
            IDENTITY_AUTHORIZATION_BINDINGS_STATE_KEY.into(),
            b"{}".to_vec(),
        )]),
        &public.address,
        &public.authorization,
        &spending,
        context.authority.chain_id,
        &context.authority.network_id,
        p.timestamp_unix,
        Some(&verifier),
    )?;
    let parent = path.parent().ok_or("Send parent absent")?;
    if !parent
        .try_exists()
        .map_err(|_| "Cannot inspect send journal")?
    {
        begin(parent)?;
    }
    private_dir(parent)?;
    if path
        .try_exists()
        .map_err(|_| "Cannot inspect nonce reservation")?
    {
        let receipt = send_status(treasury, p.nonce, engine)?;
        if receipt["request_sha256"] != request_pin {
            return Err("Nonce already reserved for a different immutable treasury intent".into());
        }
        return Ok(receipt);
    }
    begin(&path)?;
    write(&path.join("request.json"), raw.as_bytes())?;
    sync(&path)?;
    let custody: Custody = decode(&read(&treasury.join("treasury.enc.json"), LIMIT, true)?)?;
    let unlock = read(&treasury.join("unlock"), 64, true)?;
    let signed = {
        let provider = engine.lock().map_err(|_| "APQE provider unavailable")?;
        let secret = SecretBytes::from_bytes(decrypt_with_passphrase(
            &provider,
            &Primitives,
            &custody.spending,
            passphrase(&unlock)?,
        )?);
        let signature = provider
            .sign(
                Algorithm::MlDsa87,
                secret.as_bytes(),
                &transcript,
                SignOptions::default(),
            )
            .map_err(|e| e.to_string())?;
        synergy_transaction::SignedTransaction {
            unsigned: unsigned.clone(),
            signer_public_key: spending.clone(),
            signature,
            signature_algorithm: "ML-DSA-87".into(),
            identity_authorization: Some(public.authorization.clone()),
        }
    };
    let plaintext = SecretBytes::from_bytes(
        serde_json::to_vec(&signed).map_err(|_| "Cannot encode treasury transfer")?,
    );
    let padded = SecretBytes::from_bytes(
        synergy_etdag::crypto::pad_plaintext(plaintext.as_bytes())
            .map_err(|e| format!("Transfer padding: {e:?}"))?,
    );
    let c = &context.authority;
    let root = context
        .root()
        .map_err(|e| format!("Processing root: {e:?}"))?;
    let aad = ProcessingEnvelopeAad {
        profile_id: PROCESSING_PROFILE_ID.into(),
        chain_id: c.chain_id,
        network_id: c.network_id.clone(),
        protocol_version: c.protocol_version.clone(),
        epoch: c.epoch,
        processing_context_root: root.clone(),
        authorization_height: c.target_height,
        assigned_cluster_id: c.assigned_cluster_id,
        lane_id: "ordinary-user".into(),
        sender_id: public.address.clone(),
        nonce_slot: p.nonce,
    };
    let recipients = registry
        .records
        .iter()
        .filter(|r| {
            r.activation_height <= c.target_height
                && r.retirement_height.is_none_or(|h| c.target_height < h)
        })
        .cloned()
        .collect::<Vec<_>>();
    if recipients.len() != c.assigned_cluster_validator_count as usize {
        return Err("Active authenticated ingress set differs".into());
    }
    let kem = synergy_aegis::ApqeKem::mlkem1024(engine.clone())
        .map_err(|e| format!("APQE KEM: {e:?}"))?;
    let payload = synergy_etdag::crypto::encrypt_protected_payload_with_kem(
        &aad,
        &recipients,
        synergy_etdag::certificate_quorum(recipients.len())
            .map_err(|e| format!("Count quorum: {e:?}"))?,
        padded.as_bytes(),
        &kem,
    )
    .map_err(|e| format!("Encrypted admission: {e:?}"))?;
    let placeholder = EtdagDigest::from_domain_bytes("SYNERGY_TREASURY_PENDING_V1", b"");
    let mut order = [0; 32];
    Primitives
        .random_bytes(&mut order)
        .map_err(|_| "APQE randomness unavailable")?;
    let mut envelope = ProcessingEnvelope {
        envelope_version: 1,
        envelope_id: placeholder.clone(),
        aad,
        aead_nonce: payload.aead_nonce,
        key_commitment: payload.key_commitment,
        share_commitment_root: placeholder.clone(),
        share_capsule_root: placeholder,
        ciphertext: payload.ciphertext,
        content_blind_order_key: EtdagDigest::from_domain_bytes(
            "SYNERGY_TREASURY_ORDER_V1",
            &order,
        ),
        share_capsules: payload.share_capsules,
    };
    envelope
        .refresh_capsule_roots()
        .map_err(|e| format!("Capsule roots: {e:?}"))?;
    envelope.envelope_id = envelope
        .commitment()
        .map_err(|e| format!("Envelope commitment: {e:?}"))?;
    let mut admission = ProcessingAdmissionRequest {
        request_version: 1,
        context_root: root,
        sender_wallet: public.address,
        sender_nonce: p.nonce,
        gas_class_units: 21_000,
        fee_class: 1,
        signature_algorithm: "ML-DSA-87".into(),
        signer_public_key: spending,
        envelope,
        signature: Vec::new(),
    };
    {
        let provider = engine.lock().map_err(|_| "APQE provider unavailable")?;
        let secret = SecretBytes::from_bytes(decrypt_with_passphrase(
            &provider,
            &Primitives,
            &custody.spending,
            passphrase(&unlock)?,
        )?);
        admission.signature = provider
            .sign(
                Algorithm::MlDsa87,
                secret.as_bytes(),
                &admission
                    .signing_bytes()
                    .map_err(|e| format!("Admission transcript: {e:?}"))?,
                SignOptions::default(),
            )
            .map_err(|e| e.to_string())?;
    }
    admission
        .validate_context(&context)
        .map_err(|e| format!("Admission context: {e:?}"))?;
    let admission = WalletProcessingAdmission {
        request: admission,
        identity_authorization: public.authorization,
    };
    let admission_raw =
        serde_json::to_vec(&admission).map_err(|_| "Cannot encode encrypted admission")?;
    let record = SendRecord {
        version: 1,
        request_sha256: request_pin.into(),
        formation_sha256: context_pin.into(),
        genesis_sha256: p.genesis_sha256.clone(),
        unsigned,
        transaction_id,
        transaction_signature: signed.signature.clone(),
        admission_sha256: digest(&admission_raw),
        receipt_id: EtdagDigest::from_canonical(
            "SYNERGY_LOCAL_PROCESSING_ADMISSION_RECEIPT_V1",
            &admission,
        )
        .map_err(|e| format!("Receipt ID: {e:?}"))?
        .0,
    };
    write(&path.join("admission.json"), &admission_raw)?;
    write(&path.join("prepared.json"), &encode(&record)?)?;
    sync(&path)?;
    send_status(treasury, p.nonce, engine)
}
/// Public state only. An exported admission is UNKNOWN, never sent/finalized.
pub fn send_status(
    treasury: &Path,
    nonce: u64,
    engine: crate::provider::Engine,
) -> Result<Value, String> {
    let path = send_path(treasury, nonce)?;
    private_dir(&path)?;
    let record: SendRecord = decode(&read(&path.join("prepared.json"), LIMIT, true)?)?;
    let (_, raw) = send_request(&path.join("request.json"), &record.request_sha256)?;
    let request: SendRequest = decode(&raw)?;
    let admission_raw = read(&path.join("admission.json"), 1024 * 1024, true)?;
    let admission: synergy_etdag::WalletProcessingAdmission = decode(&admission_raw)?;
    let public_raw = read(&treasury.join("treasury-public.json"), LIMIT, true)?;
    let public: Public = decode(&public_raw)?;
    let custody: Custody = decode(&read(&treasury.join("treasury.enc.json"), LIMIT, true)?)?;
    let p = &request.parameters;
    let principal = public
        .authorization
        .binding
        .authorization_policy
        .principals
        .first()
        .and_then(|p| p.public_key.as_deref())
        .ok_or("Treasury principal absent")?;
    let spending = synergy_address_engine::snts07::decode_lower_hex(
        "Treasury spending public",
        principal,
        2592,
    )?;
    let provider = engine.lock().map_err(|_| "APQE provider unavailable")?;
    if admission.request.signer_public_key != spending
        || custody.public_sha256 != digest(public_raw.as_bytes())
        || public.address != record.unsigned.sender
        || public.authorization != admission.identity_authorization
        || record.formation_sha256 != p.formation_sha256
        || record.genesis_sha256 != p.genesis_sha256
        || record.unsigned.receiver != p.receiver
        || record.unsigned.amount_nwei != decimal(&p.amount_nwei)?
        || record.unsigned.timestamp_unix != p.timestamp_unix
        || record.unsigned.fee_limit.gas_limit != 21_000
        || record.unsigned.fee_limit.max_fee_per_gas_nwei != 40
        || !record.unsigned.payload.is_empty()
        || !provider
            .verify(
                Algorithm::MlDsa87,
                &admission.request.signer_public_key,
                &record.unsigned.signing_bytes().map_err(|e| e.to_string())?,
                &record.transaction_signature,
                SignOptions::default(),
            )
            .map_err(|e| e.to_string())?
        || record.version != 1
        || record.unsigned.nonce != nonce
        || request.parameters.nonce != nonce
        || record.transaction_id != record.unsigned.id().map_err(|e| e.to_string())?.0
        || record.admission_sha256 != digest(admission_raw.as_bytes())
        || admission.request.sender_nonce != nonce
        || admission.request.sender_wallet != record.unsigned.sender
        || record.receipt_id
            != synergy_etdag::EtdagDigest::from_canonical(
                "SYNERGY_LOCAL_PROCESSING_ADMISSION_RECEIPT_V1",
                &admission,
            )
            .map_err(|e| format!("Receipt: {e:?}"))?
            .0
        || !provider
            .verify(
                Algorithm::MlDsa87,
                &admission.request.signer_public_key,
                &admission
                    .request
                    .signing_bytes()
                    .map_err(|e| format!("Admission transcript: {e:?}"))?,
                &admission.request.signature,
                SignOptions::default(),
            )
            .map_err(|e| e.to_string())?
    {
        return Err("Immutable treasury admission journal differs".into());
    }
    let taken = path
        .join("dispatch-intent.json")
        .try_exists()
        .map_err(|_| "Cannot inspect treasury dispatch fence")?;
    if taken {
        let intent: Value = decode(&read(&path.join("dispatch-intent.json"), 4096, true)?)?;
        if intent
            != json!({"request_sha256":record.request_sha256,"admission_sha256":record.admission_sha256,"transaction_id":record.transaction_id,"receipt_id":record.receipt_id})
        {
            return Err("Treasury dispatch fence differs".into());
        }
    }
    Ok(
        json!({"schema":"nodenetwork-formation-treasury-send-v1","request_sha256":record.request_sha256,"formation_sha256":record.formation_sha256,"genesis_sha256":record.genesis_sha256,"transaction_id":record.transaction_id,"receipt_id":record.receipt_id,"admission_sha256":record.admission_sha256,"sender":record.unsigned.sender,"receiver":record.unsigned.receiver,"amount_nwei":record.unsigned.amount_nwei.to_string(),"nonce":nonce,"fee_nwei":"840000","state":if taken{"dispatch_unknown"}else{"prepared"},"automatic_retry":false}),
    )
}
/// One-use native handoff. The fence is durable BEFORE ciphertext is returned.
/// Lost stdout is uncertain; status never re-exports and this call never retries.
pub fn take_send(
    treasury: &Path,
    nonce: u64,
    request_pin: &str,
    engine: crate::provider::Engine,
) -> Result<Value, String> {
    let mut receipt = send_status(treasury, nonce, engine)?;
    if receipt["request_sha256"] != request_pin || receipt["state"] != "prepared" {
        return Err("Exact unconsumed treasury send required; reconcile uncertain dispatch without re-export".into());
    }
    let path = send_path(treasury, nonce)?;
    let admission = read(&path.join("admission.json"), 1024 * 1024, true)?;
    if digest(admission.as_bytes()) != receipt["admission_sha256"] {
        return Err("Admission changed before handoff".into());
    }
    write(&path.join("dispatch-intent.json"),&serde_json::to_vec(&json!({"request_sha256":receipt["request_sha256"],"admission_sha256":receipt["admission_sha256"],"transaction_id":receipt["transaction_id"],"receipt_id":receipt["receipt_id"]})).map_err(|_|"Cannot encode dispatch fence")?)?;
    sync(&path)?;
    receipt["state"] = "dispatch_unknown".into();
    receipt["admission"] =
        serde_json::from_slice(admission.as_bytes()).map_err(|_| "Invalid admission")?;
    Ok(receipt)
}

#[cfg(test)]
pub(crate) fn prepare_send_fixture_treasury(
    context_path: &Path,
    pin: &str,
    parent: &Path,
    engine: crate::provider::Engine,
    effective: u64,
) -> Value {
    let treasury = parent.join("app-treasury");
    let path = parent.join("treasury-prepare.json");
    let raw=serde_json::to_vec(&json!({"version":1,"operation":"treasury_prepare","parameters":{"formation_sha256":pin,"effective_at_unix":effective}})).unwrap();
    write(&path, &raw).unwrap();
    prepare(
        context_path,
        pin,
        &path,
        &digest(&raw),
        &treasury,
        engine.clone(),
    )
    .unwrap();
    status(context_path, pin, &treasury, engine, true).unwrap()["canary_testing_treasury"].clone()
}

#[cfg(test)]
pub(crate) fn exercise_send_fixture(
    context_path: &Path,
    pin: &str,
    formation: &Path,
    parent: &Path,
    engine: crate::provider::Engine,
) {
    let export =
        crate::network_formation::signed_public(context_path, pin, formation, engine.clone())
            .unwrap();
    let binding: synergy_genesis::authority::SignedAuthorityBinding =
        serde_json::from_str(export["artifacts"]["authority.json"].as_str().unwrap()).unwrap();
    let a = &binding.payload;
    let policy = a.protected.as_ref().unwrap();
    let registry = synergy_posy::FrozenValidatorRegistry::new(
        a.epoch,
        a.validators.iter().map(|v| v.record.clone()).collect(),
    )
    .unwrap();
    let epoch = synergy_posy::SimplifiedEpochContext::from_frozen_registry(
        a.chain_id,
        a.network_id.clone(),
        a.epoch,
        a.epoch_start_height,
        a.epoch_end_height,
        a.finalized_epoch_seed_root.clone(),
        a.consensus_parameter_root.clone(),
        &registry,
    )
    .unwrap();
    let context = synergy_etdag::ProcessingContext {
        context_version: 1,
        profile_id: synergy_etdag::PROCESSING_PROFILE_ID.into(),
        authority: synergy_etdag::TargetAdmissionContextV3 {
            context_version: 1,
            chain_id: a.chain_id,
            network_id: a.network_id.clone(),
            protocol_version: epoch.protocol_version.clone(),
            epoch: a.epoch,
            target_height: policy.parameters.target_height_offset,
            target_height_offset: policy.parameters.target_height_offset,
            source_finalized_height: 0,
            source_finality_context_root: a.anchor_parent.reference_id().into(),
            active_validator_set_root: epoch.active_validator_set_root.clone(),
            validator_consensus_key_root: epoch.validator_consensus_key_root.clone(),
            frozen_voting_weight_root: epoch.frozen_voting_weight_root.clone(),
            cluster_schedule_version: policy.cluster_schedule_version.clone(),
            finalized_epoch_seed_root: epoch.finalized_epoch_seed_root.clone(),
            assigned_height_schedule_root: policy.assigned_height_schedule_root.clone(),
            cluster_map_root: policy.cluster_map_root.clone(),
            assigned_cluster_id: policy.assigned_cluster_id,
            assigned_cluster_membership_root: policy.assigned_cluster_membership_root.clone(),
            assigned_cluster_validator_count: registry.active_count() as u64,
            assigned_cluster_total_voting_weight: registry
                .active_weight()
                .unwrap()
                .try_into()
                .unwrap(),
            consensus_parameter_root: epoch.consensus_parameter_root.clone(),
            cryptographic_profile_root: policy.cryptographic_profile_root.clone(),
            ingress_kem_registry_root: policy.ingress_kem_registry.root().unwrap(),
        },
    };
    let response = json!({"profile_id":synergy_etdag::PROCESSING_PROFILE_ID,"context":context,"ingress_kem_registry":policy.ingress_kem_registry});
    let treasury = parent.join("app-treasury");
    let public: Public =
        decode(&read(&treasury.join("treasury-public.json"), LIMIT, true).unwrap()).unwrap();
    assert_eq!(
        policy.initial_world_state.accounts[&public.address].balance_nwei,
        5_000_000_000_000_000
    );
    let request = json!({"version":1,"operation":"treasury_send_prepare","parameters":{"formation_sha256":pin,"genesis_sha256":export["genesis_sha256"],"processing_context_json":response.to_string(),"processing_context_sha256":digest(response.to_string().as_bytes()),"receiver":synergy_address::derive_key_controlled_address("syna",&[9;1793]).unwrap(),"amount_nwei":"1000000","nonce":0,"observed_balance_nwei":"5000000000000000","timestamp_unix":policy.epoch_start_timestamp_ms/1000+5}});
    let context_formation = crate::validator_formation::pinned_context(context_path, pin).unwrap();
    for (field, value) in [
        ("epoch", json!(2)),
        ("validator_consensus_key_root", json!("forged")),
        ("assigned_cluster_total_voting_weight", json!(1)),
    ] {
        let mut changed = response.clone();
        changed["context"]["authority"][field] = value;
        let mut r: SendRequest = serde_json::from_value(request.clone()).unwrap();
        r.parameters.processing_context_json = changed.to_string();
        r.parameters.processing_context_sha256 = digest(changed.to_string().as_bytes());
        assert!(authenticated_send_context(&context_formation, &r.parameters, &export).is_err());
    }
    let mut changed = response.clone();
    changed["ingress_kem_registry"]["records"][0]["public_key"]["public_key"][0] = json!(99);
    let mut r: SendRequest = serde_json::from_value(request.clone()).unwrap();
    r.parameters.processing_context_json = changed.to_string();
    r.parameters.processing_context_sha256 = digest(changed.to_string().as_bytes());
    assert!(authenticated_send_context(&context_formation, &r.parameters, &export).is_err());
    let approved = parent.join("treasury-send.json");
    let raw = serde_json::to_vec(&request).unwrap();
    write(&approved, &raw).unwrap();
    let request_pin = digest(&raw);
    let first = prepare_send(
        context_path,
        pin,
        formation,
        &approved,
        &request_pin,
        &treasury,
        engine.clone(),
    )
    .unwrap();
    assert_eq!(first["state"], "prepared");
    assert_eq!(first["fee_nwei"], "840000");
    assert_eq!(
        prepare_send(
            context_path,
            pin,
            formation,
            &approved,
            &request_pin,
            &treasury,
            engine.clone()
        )
        .unwrap(),
        first
    );
    let path = send_path(&treasury, 0).unwrap();
    let original = std::fs::read(path.join("prepared.json")).unwrap();
    let mut record: Value = serde_json::from_slice(&original).unwrap();
    record["unsigned"]["amount_nwei"] = json!(2);
    std::fs::write(
        path.join("prepared.json"),
        serde_json::to_vec(&record).unwrap(),
    )
    .unwrap();
    assert!(send_status(&treasury, 0, engine.clone()).is_err());
    std::fs::write(path.join("prepared.json"), original).unwrap();
    assert!(take_send(&treasury, 0, &"0".repeat(64), engine.clone()).is_err());
    let taken = take_send(&treasury, 0, &request_pin, engine.clone()).unwrap();
    assert_eq!(taken["transaction_id"], first["transaction_id"]);
    assert_eq!(taken["state"], "dispatch_unknown");
    let admission: synergy_etdag::WalletProcessingAdmission =
        serde_json::from_value(taken["admission"].clone()).unwrap();
    admission.request.validate_context(&context).unwrap();
    assert_eq!(
        taken["receipt_id"],
        synergy_etdag::EtdagDigest::from_canonical(
            "SYNERGY_LOCAL_PROCESSING_ADMISSION_RECEIPT_V1",
            &admission
        )
        .unwrap()
        .0
    );
    assert_eq!(admission.request.envelope.share_capsules.len(), 5);
    assert!(take_send(&treasury, 0, &request_pin, engine.clone()).is_err());
    let status = prepare_send(
        context_path,
        pin,
        formation,
        &approved,
        &request_pin,
        &treasury,
        engine.clone(),
    )
    .unwrap();
    assert_eq!(status["state"], "dispatch_unknown");
    assert!(status.get("admission").is_none());
    let mut other = request;
    other["parameters"]["amount_nwei"] = json!("1000001");
    let raw = serde_json::to_vec(&other).unwrap();
    let other_path = parent.join("changed-send.json");
    write(&other_path, &raw).unwrap();
    assert!(prepare_send(
        context_path,
        pin,
        formation,
        &other_path,
        &digest(&raw),
        &treasury,
        engine.clone()
    )
    .is_err());
    let incomplete = send_path(&treasury, 1).unwrap();
    begin(&incomplete).unwrap();
    assert!(send_status(&treasury, 1, engine.clone()).is_err());
    let admission_path = path.join("admission.json");
    let mut raw = std::fs::read(&admission_path).unwrap();
    raw[20] ^= 1;
    std::fs::write(admission_path, raw).unwrap();
    assert!(send_status(&treasury, 0, engine).is_err());
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        os::unix::fs::{DirBuilderExt, PermissionsExt},
    };

    #[test]
    fn treasury_commands_require_explicit_provider_and_send_decimals_are_canonical() {
        for command in [
            "prepare-formation-treasury",
            "review-formation-treasury",
            "export-formation-treasury",
            "prepare-formation-treasury-send",
            "review-formation-treasury-send",
            "take-formation-treasury-send",
        ] {
            let arguments = vec![command.to_string()];
            assert_eq!(
                crate::selected_arguments(&arguments).err().unwrap(),
                "explicit APQE report and authenticated SHA256 flags required"
            );
        }
        assert_eq!(decimal("1000000").unwrap(), 1_000_000);
        for bad in [
            "01",
            "+1",
            "-1",
            "1.0",
            " 1",
            "340282366920938463463374607431768211456",
        ] {
            assert!(decimal(bad).is_err());
        }
    }

    #[test]
    #[ignore = "requires the independently authenticated native APQE provider"]
    fn ordinary_treasury_custody_roundtrip_and_scope_fail_closed() {
        let base = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("formation-treasury-{}", std::process::id()));
        fs::DirBuilder::new().mode(0o700).create(&base).unwrap();
        struct Cleanup(std::path::PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        let _cleanup = Cleanup(base.clone());
        let context = FormationContext {
            network_id: "new-treasury-fixture".into(),
            chain_id_hex: format!("{:064x}", 99999),
            formation_id: "a".repeat(64),
        };
        let context_path = base.join("context.json");
        let raw = encode(&context).unwrap();
        let pin = digest(&raw);
        write(&context_path, &raw).unwrap();
        let req = json!({"version":1,"operation":"treasury_prepare","parameters":{"formation_sha256":pin,"effective_at_unix":1700000000}});
        let request_path = base.join("approved.json");
        let raw = serde_json::to_vec(&req).unwrap();
        let request_pin = digest(&raw);
        write(&request_path, &raw).unwrap();
        let engine = crate::provider::native_test_engine();
        let dir = base.join("custody");
        assert!(prepare(
            &context_path,
            &pin,
            &request_path,
            &"0".repeat(64),
            &dir,
            engine.clone()
        )
        .is_err());
        assert!(!dir.exists());
        let first = prepare(
            &context_path,
            &pin,
            &request_path,
            &request_pin,
            &dir,
            engine.clone(),
        )
        .unwrap();
        assert_eq!(first["possession_verified"], true);
        assert!(first["address"].as_str().unwrap().starts_with("syna"));
        assert_eq!(
            status(&context_path, &pin, &dir, engine.clone(), false).unwrap(),
            first
        );
        assert!(prepare(
            &context_path,
            &pin,
            &request_path,
            &request_pin,
            &dir,
            engine.clone()
        )
        .is_err());
        let export = status(&context_path, &pin, &dir, engine.clone(), true).unwrap();
        assert_eq!(
            export["canary_testing_treasury"]["address"],
            first["address"]
        );
        assert_eq!(
            export["authorization_sha256"],
            digest(
                &serde_json::to_vec(&export["canary_testing_treasury"]["authorization"]).unwrap()
            )
        );
        crate::prepare_authority::qualify_treasury_allocation(
            export["canary_testing_treasury"].clone(),
            engine.clone(),
        );
        assert!(!serde_json::to_string(&export).unwrap().contains("PRIVATE"));
        let public_raw = fs::read(dir.join("treasury-public.json")).unwrap();
        let mut changed: Value = serde_json::from_slice(&public_raw).unwrap();
        changed["address"] = "synw1forged".into();
        fs::write(dir.join("treasury-public.json"), encode(&changed).unwrap()).unwrap();
        assert!(status(&context_path, &pin, &dir, engine.clone(), true).is_err());
        fs::write(dir.join("treasury-public.json"), public_raw).unwrap();
        let mut other = context;
        other.formation_id = "b".repeat(64);
        let other_raw = encode(&other).unwrap();
        let other_path = base.join("other.json");
        write(&other_path, &other_raw).unwrap();
        assert!(status(
            &other_path,
            &digest(&other_raw),
            &dir,
            engine.clone(),
            false
        )
        .is_err());
        let unlock = fs::read(dir.join("unlock")).unwrap();
        fs::write(dir.join("unlock"), vec![b'0'; 64]).unwrap();
        assert!(status(&context_path, &pin, &dir, engine.clone(), false).is_err());
        fs::write(dir.join("unlock"), unlock).unwrap();
        fs::set_permissions(dir.join("unlock"), fs::Permissions::from_mode(0o644)).unwrap();
        assert!(status(&context_path, &pin, &dir, engine.clone(), false).is_err());
        fs::set_permissions(dir.join("unlock"), fs::Permissions::from_mode(0o600)).unwrap();
        fs::remove_file(dir.join("treasury.enc.json")).unwrap();
        assert!(status(&context_path, &pin, &dir, engine, false).is_err());
    }
}
