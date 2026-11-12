//! Bounded wallet custody and protected transfer authoring. No network or runtime writes.
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, Read, Write};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use aegis_pqvm::pqc::signatures::{fndsa::fndsa1024, mldsa::mldsa87};
use pqrust_traits::sign::{DetachedSignature as _, PublicKey as _, SecretKey as _};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use synergy_etdag::{
    AdmissionRequest, EncryptedTransactionEnvelope, EnvelopeAad, EtdagDigest,
    IngressKemKeyRegistry, ProcessingAdmissionRequest, ProcessingContext, ProcessingEnvelope,
    ProcessingEnvelopeAad, WalletAdmission, WalletAdmissionContext, WalletProcessingAdmission,
    PROCESSING_PROFILE_ID,
};
use synergy_identity::authorization::*;
use synergy_transaction::{
    FeeLimit, NetworkBinding, SignedTransaction, TransactionAction, TransactionClass,
    UnsignedTransaction,
};

const MAX_JSON: u64 = 1024 * 1024;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn hash(bytes: &[u8]) -> String {
    hex(&Sha3_256::digest(bytes))
}
fn decode_hex(value: &str) -> Result<Vec<u8>, String> {
    if !value.len().is_multiple_of(2)
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("public key must be canonical lowercase hex".into());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).map_err(|_| "invalid public key")?;
            u8::from_str_radix(text, 16).map_err(|_| "invalid public key".into())
        })
        .collect()
}
fn directory(path: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !path.is_absolute() || metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("output directory must be absolute, existing and non-symlink".into());
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err("wallet output directory must be private (mode 0700)".into());
    }
    Ok(())
}
fn write_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_JSON {
        return Err("wallet output exceeds byte limit".into());
    }
    directory(path.parent().ok_or("explicit output parent required")?)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options
        .open(path)
        .map_err(|e| format!("create wallet output: {e}"))?;
    if let Err(error) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(error.to_string());
    }
    if let Err(error) =
        File::open(path.parent().ok_or("missing output parent")?).and_then(|f| f.sync_all())
    {
        let _ = fs::remove_file(path);
        return Err(error.to_string());
    }
    Ok(())
}
fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, String> {
    serde_json::from_slice(&crate::aegis_keys::read_bounded(
        path,
        MAX_JSON,
        "wallet public input",
    )?)
    .map_err(|e| e.to_string())
}

pub fn generate(
    output: &Path,
    chain_id: u64,
    network: &str,
    activation: u64,
    balance: u128,
    name: &str,
) -> Result<(), String> {
    directory(output)?;
    NetworkBinding::new(chain_id, network).map_err(|e| format!("network: {e:?}"))?;
    if activation == 0
        || balance == 0
        || name.is_empty()
        || name.len() > 64
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(
            "positive activation/balance and bounded alphanumeric wallet name required".into(),
        );
    }
    let effective = chrono::DateTime::from_timestamp(
        i64::try_from(activation).map_err(|_| "activation overflow")?,
        0,
    )
    .ok_or("activation out of range")?
    .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let paths = [
        output.join("identity-root.secret.key"),
        output.join("transaction.secret.key"),
        output.join("wallet.public.json"),
    ];
    if paths.iter().any(|p| p.exists()) {
        return Err("refusing to overwrite wallet custody".into());
    }
    let (root, root_secret) = fndsa1024::keypair();
    let (account, account_secret) = mldsa87::keypair();
    let sender = synergy_address::derive_key_controlled_address("syna", root.as_bytes())?;
    let account_hash = hash(account.as_bytes());
    let mut binding: IdentityAuthorizationBinding = serde_json::from_value(serde_json::json!({
        "schema_version":AUTH_BINDING_SCHEMA_VERSION,"binary_encoding":AUTH_BINDING_BINARY_ENCODING,
        "identity_id":name,"identity_address":sender,
        "identity_root":{"algorithm":"FN-DSA-1024","public_key":hex(root.as_bytes()),"public_key_sha3_256":hash(root.as_bytes())},
        "authorization_policy":{"policy_type":"single-key","threshold":1,"principals":[{
            "principal_id":"transaction","principal_type":"public-key","algorithm":"ML-DSA-87",
            "public_key":hex(account.as_bytes()),"public_key_sha3_256":account_hash,"status":"active","purposes":["transaction-signing"]}]},
        "authorization_scopes":[{"signature_domain":AEGIS_TRANSACTION_AUTHORIZATION_DOMAIN,"chain_id":chain_id,"network_id":network,"purpose":"transaction-signing"}],
        "current_auth_key_hash":account_hash,"auth_key_history":[],"supersession_history":[],"effective_at":effective,"binding_payload_sha3_256":"",
        "proofs":{"identity_root":{"algorithm":"FN-DSA-1024","signature":""}}
    })).map_err(|e| e.to_string())?;
    let payload = canonical_binding_payload(&binding)?;
    binding.binding_payload_sha3_256 = hash(&payload);
    let mut proof = AUTH_BINDING_SIGNATURE_DOMAIN.to_vec();
    proof.extend_from_slice(&payload);
    binding.proofs.identity_root.signature =
        hex(fndsa1024::detached_sign(&proof, &root_secret).as_bytes());
    binding.proofs.authorization_key_possession = vec![AuthorizationKeyPossessionProof {
        principal_id: "transaction".into(),
        algorithm: "ML-DSA-87".into(),
        signature: hex(mldsa87::detached_sign(&proof, &account_secret).as_bytes()),
    }];
    let commitment =
        IdentityAuthorizationBindingCommitment::from_verified_binding(&binding, activation)?;
    let carrier = IdentityAuthorizationCarrier {
        schema_version: AUTHORIZATION_CARRIER_SCHEMA_VERSION,
        signature_domain: AEGIS_TRANSACTION_AUTHORIZATION_DOMAIN.into(),
        binding,
    };
    #[derive(Serialize)]
    struct Account {
        balance_nwei: u128,
        nonce: u64,
        code_hash: Option<String>,
    }
    #[derive(Serialize)]
    struct GeneratedPublic {
        sender: String,
        identity_authorization: IdentityAuthorizationCarrier,
        genesis_account: Account,
        genesis_binding_commitment: IdentityAuthorizationBindingCommitment,
    }
    let public = GeneratedPublic {
        sender,
        identity_authorization: carrier,
        genesis_account: Account {
            balance_nwei: balance,
            nonce: 0,
            code_hash: None,
        },
        genesis_binding_commitment: commitment,
    };
    let public_bytes = serde_json::to_vec_pretty(&public).map_err(|e| e.to_string())?;
    let mut root_bytes = root_secret.as_bytes().to_vec();
    let mut account_bytes = account_secret.as_bytes().to_vec();
    let mut created = Vec::new();
    let result = (|| {
        for (path, bytes) in [
            (&paths[0], root_bytes.as_slice()),
            (&paths[1], account_bytes.as_slice()),
            (&paths[2], public_bytes.as_slice()),
        ] {
            write_new(path, bytes)?;
            created.push(path.clone());
        }
        Ok(())
    })();
    crate::aegis_keys::wipe(&mut root_bytes);
    crate::aegis_keys::wipe(&mut account_bytes);
    if result.is_err() {
        for path in created {
            let _ = fs::remove_file(path);
        }
    }
    result
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReauthorizeInput {
    wallet_public_path: PathBuf,
    identity_root_secret_path: PathBuf,
    transaction_secret_path: PathBuf,
    previous_chain_id: u64,
    previous_network_id: String,
    chain_id: u64,
    network_id: String,
    activation_unix: u64,
}

// Keep native allocation amounts typed end-to-end. Value's generic Number
// representation can round integers above u64 through floating point.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WalletGenesisAccount {
    balance_nwei: u128,
    nonce: u64,
    code_hash: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReauthorizationPublic {
    sender: String,
    identity_authorization: IdentityAuthorizationCarrier,
    genesis_account: WalletGenesisAccount,
    genesis_binding_commitment: IdentityAuthorizationBindingCommitment,
}

#[cfg(test)]
mod reauthorization_tests {
    #[test]
    fn legacy_wallet_generation_and_reauthorization_are_rejected_before_custody_access() {
        for command in ["generate-tps-wallet", "reauthorize-wallet"] {
            let arguments = vec![command.to_string(), "/must-not-read-custody".into()];
            let error = crate::selected_arguments(&arguments)
                .err()
                .expect("unqualified legacy command must stay disabled");
            assert!(error.contains("fail-closed"));
            assert!(error.contains("explicit APQE"));
        }
    }
}

/// Commission existing wallet custody for an explicitly selected new network.
/// Only a new public carrier is written; no key, address or live state is changed.
pub fn reauthorize(input_path: &Path, output: &Path) -> Result<(), String> {
    let input: ReauthorizeInput = read_json(input_path)?;
    NetworkBinding::new(input.chain_id, &input.network_id)
        .map_err(|e| format!("network: {e:?}"))?;
    NetworkBinding::new(input.previous_chain_id, &input.previous_network_id)
        .map_err(|e| format!("previous network: {e:?}"))?;
    if input.activation_unix == 0
        || (input.chain_id == input.previous_chain_id
            && input.network_id == input.previous_network_id)
    {
        return Err(
            "reauthorization requires a distinct selected network and positive activation".into(),
        );
    }
    no_symlink_path(&input.wallet_public_path)?;
    no_symlink_path(&input.identity_root_secret_path)?;
    no_symlink_path(&input.transaction_secret_path)?;
    let mut document: ReauthorizationPublic = read_json(&input.wallet_public_path)?;
    let mut carrier = document.identity_authorization;
    let principal = transaction_principal(&carrier.binding.authorization_policy)?;
    let transaction_public = decode_hex(
        principal
            .public_key
            .as_deref()
            .ok_or("transaction public key absent")?,
    )?;
    let address = carrier.identity_address_for_key_for_admission_at(
        AEGIS_TRANSACTION_AUTHORIZATION_DOMAIN,
        input.previous_chain_id,
        &input.previous_network_id,
        "ML-DSA-87",
        &transaction_public,
        "transaction-signing",
        input.activation_unix,
        &carrier.binding.binding_payload_sha3_256,
    )?;
    if address != document.sender {
        return Err("existing wallet address differs from authenticated carrier".into());
    }
    let root_metadata =
        fs::symlink_metadata(&input.identity_root_secret_path).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    if root_metadata.permissions().mode() & 0o077 != 0 {
        return Err("identity root custody must be private".into());
    }
    if !root_metadata.is_file() {
        return Err("identity root custody must be regular".into());
    }
    let root_bytes = SecretBytes(crate::aegis_keys::read_bounded(
        &input.identity_root_secret_path,
        64 * 1024,
        "identity root custody",
    )?);
    let transaction_bytes = load_secret(&input.transaction_secret_path)?;
    let root_secret = fndsa1024::SecretKey::from_bytes(&root_bytes.0)
        .map_err(|_| "invalid FN-DSA root custody")?;
    let transaction_secret = mldsa87::SecretKey::from_bytes(&transaction_bytes.0)
        .map_err(|_| "invalid transaction custody")?;
    let root_public_bytes = decode_hex(&carrier.binding.identity_root.public_key)?;
    let root_public = fndsa1024::PublicKey::from_bytes(&root_public_bytes)
        .map_err(|_| "invalid root public key")?;
    let transaction_public = mldsa87::PublicKey::from_bytes(&transaction_public)
        .map_err(|_| "invalid transaction public key")?;
    let challenge = b"SYNERGY_WALLET_REAUTHORIZATION_CUSTODY_V1";
    fndsa1024::verify_detached_signature(
        &fndsa1024::detached_sign(challenge, &root_secret),
        challenge,
        &root_public,
    )
    .map_err(|_| "identity root custody differs from existing wallet")?;
    mldsa87::verify_detached_signature(
        &mldsa87::detached_sign(challenge, &transaction_secret),
        challenge,
        &transaction_public,
    )
    .map_err(|_| "transaction custody differs from existing wallet")?;
    let mut selected = false;
    for scope in &mut carrier.binding.authorization_scopes {
        if scope.chain_id == input.previous_chain_id
            && scope.network_id == input.previous_network_id
            && scope.signature_domain == AEGIS_TRANSACTION_AUTHORIZATION_DOMAIN
            && scope.purpose == "transaction-signing"
        {
            scope.chain_id = input.chain_id;
            scope.network_id.clone_from(&input.network_id);
            selected = true;
        }
    }
    if !selected {
        return Err("previous selected transaction scope is absent".into());
    }
    carrier.binding.effective_at = chrono::DateTime::from_timestamp(
        i64::try_from(input.activation_unix).map_err(|_| "activation overflow")?,
        0,
    )
    .ok_or("activation out of range")?
    .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let payload = canonical_binding_payload(&carrier.binding)?;
    carrier.binding.binding_payload_sha3_256 = hash(&payload);
    let mut proof = AUTH_BINDING_SIGNATURE_DOMAIN.to_vec();
    proof.extend_from_slice(&payload);
    carrier.binding.proofs.identity_root.signature =
        hex(fndsa1024::detached_sign(&proof, &root_secret).as_bytes());
    carrier.binding.proofs.authorization_key_possession = vec![AuthorizationKeyPossessionProof {
        principal_id: transaction_principal(&carrier.binding.authorization_policy)?
            .principal_id
            .clone(),
        algorithm: "ML-DSA-87".into(),
        signature: hex(mldsa87::detached_sign(&proof, &transaction_secret).as_bytes()),
    }];
    let commitment = IdentityAuthorizationBindingCommitment::from_verified_binding(
        &carrier.binding,
        input.activation_unix,
    )?;
    let verified_address = carrier.identity_address_for_key_for_admission_at(
        AEGIS_TRANSACTION_AUTHORIZATION_DOMAIN,
        input.chain_id,
        &input.network_id,
        "ML-DSA-87",
        transaction_public.as_bytes(),
        "transaction-signing",
        input.activation_unix,
        &carrier.binding.binding_payload_sha3_256,
    )?;
    if verified_address != document.sender {
        return Err("reauthorization changed wallet identity".into());
    }
    document.identity_authorization = carrier;
    document.genesis_binding_commitment = commitment;
    no_symlink_path(output.parent().ok_or("output parent required")?)?;
    write_new(
        output,
        &serde_json::to_vec_pretty(&document).map_err(|e| e.to_string())?,
    )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TransferInput {
    wallet_public_path: PathBuf,
    transaction_secret_path: PathBuf,
    admission_context_path: PathBuf,
    sender: String,
    receiver: String,
    amount_nwei: u128,
    nonce: u64,
    timestamp_unix: u64,
    gas_limit: u64,
    max_fee_per_gas_nwei: u64,
    gas_class_units: u64,
    fee_class: u32,
    content_blind_order_key: EtdagDigest,
    #[serde(default)]
    action: Option<TransactionAction>,
}
#[derive(Clone, Deserialize)]
struct WalletPublic {
    sender: String,
    identity_authorization: IdentityAuthorizationCarrier,
}

/// Select by verified authorization semantics; principal IDs are labels.
/// The caller verifies the complete binding before this selection and the
/// presented key's network/domain authorization afterwards.
fn transaction_principal(policy: &AuthorizationPolicy) -> Result<&AuthorizationPrincipal, String> {
    let mut eligible = policy.principals.iter().filter(|principal| {
        principal.status == BindingStatus::Active
            && principal.principal_type == PrincipalType::PublicKey
            && principal.algorithm.as_deref() == Some("ML-DSA-87")
            && principal
                .purposes
                .iter()
                .any(|purpose| purpose == "transaction-signing")
            && principal
                .public_key
                .as_ref()
                .is_some_and(|key| !key.is_empty())
    });
    let principal = eligible
        .next()
        .ok_or("wallet transaction principal absent")?;
    if eligible.next().is_some() {
        return Err("wallet transaction principal is ambiguous".into());
    }
    Ok(principal)
}

pub fn prepare(input: &Path, output: &Path) -> Result<(), String> {
    if output.exists() {
        return Err("refusing to overwrite admission output".into());
    }
    directory(
        output
            .parent()
            .ok_or("explicit output directory required")?,
    )?;
    let input: TransferInput = read_json(input)?;
    if [
        &input.wallet_public_path,
        &input.transaction_secret_path,
        &input.admission_context_path,
    ]
    .iter()
    .any(|p| !p.is_absolute())
    {
        return Err("wallet/context/custody paths must be absolute".into());
    }
    let public: WalletPublic = read_json(&input.wallet_public_path)?;
    let exported: WalletAdmissionContext = read_json(&input.admission_context_path)?;
    let secret = load_secret(&input.transaction_secret_path)?;
    let admission = author(input, exported, &public, &secret.0)?;
    write_new(
        output,
        &serde_json::to_vec(&admission).map_err(|e| e.to_string())?,
    )
}

// A wiping owner also covers early returns and partial registry loading.
struct SecretBytes(Vec<u8>);
impl Drop for SecretBytes {
    fn drop(&mut self) {
        crate::aegis_keys::wipe(&mut self.0);
    }
}
fn load_secret(path: &Path) -> Result<SecretBytes, String> {
    let metadata = fs::symlink_metadata(path).map_err(|_| "custody unavailable")?;
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err("transaction custody must be mode 0600".into());
    }
    let secret = SecretBytes(crate::aegis_keys::read_bounded(
        path,
        64 * 1024,
        "transaction custody",
    )?);
    mldsa87::SecretKey::from_bytes(&secret.0).map_err(|_| "invalid ML-DSA-87 custody")?;
    Ok(secret)
}

// Shared wallet authorization and custody checks for both signed wire profiles.
fn signed_transfer(
    input: &TransferInput,
    chain_id: u64,
    network_id: &str,
    public: &WalletPublic,
    secret_bytes: &[u8],
) -> Result<(SignedTransaction, mldsa87::SecretKey), String> {
    if input.sender != public.sender
        || input.sender != public.identity_authorization.binding.identity_address
    {
        return Err("wallet sender differs from bound identity".into());
    }
    IdentityAuthorizationBindingCommitment::from_verified_binding(
        &public.identity_authorization.binding,
        input.timestamp_unix,
    )?;
    let principal =
        transaction_principal(&public.identity_authorization.binding.authorization_policy)?;
    let public_key_bytes = decode_hex(
        principal
            .public_key
            .as_deref()
            .ok_or("transaction public key absent")?,
    )?;
    let authorized = public
        .identity_authorization
        .identity_address_for_key_for_admission_at(
            AEGIS_TRANSACTION_AUTHORIZATION_DOMAIN,
            chain_id,
            network_id,
            "ML-DSA-87",
            &public_key_bytes,
            "transaction-signing",
            input.timestamp_unix,
            &public
                .identity_authorization
                .binding
                .binding_payload_sha3_256,
        )?;
    if authorized != input.sender {
        return Err("transaction key is not authorized for sender".into());
    }
    let public_key = mldsa87::PublicKey::from_bytes(&public_key_bytes)
        .map_err(|_| "invalid ML-DSA-87 public key")?;
    let secret =
        mldsa87::SecretKey::from_bytes(secret_bytes).map_err(|_| "invalid ML-DSA-87 custody")?;
    let action = input.action.clone().unwrap_or(TransactionAction::Transfer);
    if action.requires_system_authority() {
        return Err("user wallet authoring cannot authorize a system action".into());
    }
    if !matches!(action, TransactionAction::Transfer) && input.amount_nwei != 0 {
        return Err("native wallet action cannot transfer value".into());
    }
    let payload = if matches!(action, TransactionAction::Transfer) {
        Vec::new()
    } else {
        action
            .encode()
            .map_err(|e| format!("wallet action: {e:?}"))?
    };
    let unsigned = UnsignedTransaction {
        network: NetworkBinding::new(chain_id, network_id)
            .map_err(|e| format!("network: {e:?}"))?,
        class: TransactionClass::User,
        sender: input.sender.clone(),
        receiver: input.receiver.clone(),
        amount_nwei: input.amount_nwei,
        nonce: input.nonce,
        fee_limit: FeeLimit {
            gas_limit: input.gas_limit,
            max_fee_per_gas_nwei: input.max_fee_per_gas_nwei,
        },
        timestamp_unix: input.timestamp_unix,
        payload,
    };
    let signing = unsigned
        .signing_bytes()
        .map_err(|e| format!("transaction: {e:?}"))?;
    let signature = mldsa87::detached_sign(&signing, &secret);
    mldsa87::verify_detached_signature(&signature, &signing, &public_key)
        .map_err(|_| "transaction custody differs from bound public key")?;
    let transaction = SignedTransaction {
        unsigned,
        signer_public_key: public_key_bytes.clone(),
        signature: signature.as_bytes().to_vec(),
        signature_algorithm: "ML-DSA-87".into(),
        identity_authorization: Some(public.identity_authorization.clone()),
    };
    Ok((transaction, secret))
}

fn author(
    input: TransferInput,
    exported: WalletAdmissionContext,
    public: &WalletPublic,
    secret_bytes: &[u8],
) -> Result<WalletAdmission, String> {
    exported.validate().map_err(|e| format!("context: {e:?}"))?;
    exported
        .parameters
        .validate()
        .map_err(|e| format!("parameters: {e:?}"))?;
    let context = &exported.context;
    if input.sender != public.sender
        || input.sender != public.identity_authorization.binding.identity_address
        || input.gas_class_units == 0
        || input.gas_class_units > exported.parameters.max_protected_gas
    {
        return Err("wallet sender, chain or governed gas classification mismatch".into());
    }
    let (transaction, secret) = signed_transfer(
        &input,
        context.chain_id,
        &context.network_id,
        public,
        secret_bytes,
    )?;
    let public_key_bytes = transaction.signer_public_key.clone();
    let root = context.root().map_err(|e| format!("context root: {e:?}"))?;
    let aad = EnvelopeAad {
        profile_id: exported.parameters.profile_id.clone(),
        chain_id: context.chain_id,
        network_id: context.network_id.clone(),
        protocol_version: context.protocol_version.clone(),
        epoch: context.epoch,
        target_height: context.target_height,
        target_context_root: root.clone(),
        assigned_cluster_id: context.assigned_cluster_id,
        lane_id: "ordinary-user".into(),
        sender_id: input.sender.clone(),
        nonce_slot: input.nonce,
    };
    let count = usize::try_from(context.assigned_cluster_validator_count)
        .map_err(|_| "cluster size overflow")?;
    if exported.ingress_keys.len() != count {
        return Err("active ingress records differ from governed cluster size".into());
    }
    let quorum = synergy_etdag::certificate_quorum(count).map_err(|e| format!("quorum: {e:?}"))?;
    let padded = synergy_etdag::crypto::pad_plaintext(
        &serde_json::to_vec(&transaction).map_err(|e| e.to_string())?,
    )
    .map_err(|e| format!("padding: {e:?}"))?;
    let payload = synergy_etdag::crypto::encrypt_protected_payload(
        &aad,
        &exported.ingress_keys,
        quorum,
        &padded,
    )
    .map_err(|e| format!("encryption: {e:?}"))?;
    if payload.ciphertext.len() as u64 > exported.parameters.max_protected_bytes {
        return Err("ciphertext exceeds governed capacity".into());
    }
    let placeholder = EtdagDigest::from_domain_bytes("SYNERGY_KEYTOOL_PENDING_COMMITMENT", b"");
    let mut envelope = EncryptedTransactionEnvelope {
        envelope_version: 2,
        envelope_id: placeholder.clone(),
        target_context_root: root.clone(),
        target_height: context.target_height,
        aad,
        aead_nonce: payload.aead_nonce,
        key_commitment: payload.key_commitment,
        share_commitment_root: placeholder.clone(),
        share_capsule_root: placeholder,
        ciphertext: payload.ciphertext,
        content_blind_order_key: input.content_blind_order_key,
        share_capsules: payload.share_capsules,
    };
    envelope
        .refresh_capsule_roots()
        .map_err(|e| format!("capsule roots: {e:?}"))?;
    envelope.envelope_id = synergy_etdag::envelope_commitment(&envelope)
        .map_err(|e| format!("envelope commitment: {e:?}"))?;
    let mut request = AdmissionRequest {
        request_version: synergy_etdag::ADMISSION_REQUEST_VERSION,
        chain_id: context.chain_id,
        network_id: context.network_id.clone(),
        context_root: root,
        target_height: context.target_height,
        sender_wallet: input.sender,
        sender_nonce: input.nonce,
        gas_class_units: input.gas_class_units,
        fee_class: input.fee_class,
        signature_algorithm: "ML-DSA-87".into(),
        signer_public_key: public_key_bytes,
        envelope,
        signature: vec![],
    };
    let signing = request
        .signing_bytes()
        .map_err(|e| format!("admission transcript: {e:?}"))?;
    request.signature = mldsa87::detached_sign(&signing, &secret)
        .as_bytes()
        .to_vec();
    request
        .validate_shape()
        .map_err(|e| format!("admission: {e:?}"))?;
    Ok(WalletAdmission {
        request,
        identity_authorization: public.identity_authorization.clone(),
    })
}

/// Raw result of synergy_getProcessingContextV1, not a JSON-RPC wrapper.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WalletProcessingContext {
    context: ProcessingContext,
    profile_id: String,
    ingress_kem_registry: IngressKemKeyRegistry,
}

pub fn prepare_processing(input_path: &Path, output: &Path) -> Result<(), String> {
    if !output.is_absolute()
        || output
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
        || output.file_name().is_none()
    {
        return Err("absolute non-traversing output path required".into());
    }
    // Check parents independently because the output must not exist yet.
    let parent = output
        .parent()
        .ok_or("explicit output directory required")?;
    no_symlink_path(parent)?;
    directory(parent)?;
    if fs::symlink_metadata(output).is_ok() {
        return Err("refusing to overwrite admission output".into());
    }
    no_symlink_path(input_path)?;
    let input: TransferInput = read_json(input_path)?;
    for path in [
        &input.wallet_public_path,
        &input.transaction_secret_path,
        &input.admission_context_path,
    ] {
        no_symlink_path(path)?;
    }
    let public: WalletPublic = read_json(&input.wallet_public_path)?;
    let exported: WalletProcessingContext = read_json(&input.admission_context_path)?;
    let secret = load_secret(&input.transaction_secret_path)?;
    let admission = author_processing(input, exported, &public, &secret.0)?;
    write_new(
        output,
        &serde_json::to_vec(&admission).map_err(|e| e.to_string())?,
    )
}

fn author_processing(
    input: TransferInput,
    exported: WalletProcessingContext,
    public: &WalletPublic,
    secret_bytes: &[u8],
) -> Result<WalletProcessingAdmission, String> {
    exported
        .context
        .validate()
        .map_err(|e| format!("processing context: {e:?}"))?;
    let context = &exported.context;
    let authority = &context.authority;
    exported
        .ingress_kem_registry
        .validate_protected_profile()
        .map_err(|e| format!("ingress registry: {e:?}"))?;
    if exported.profile_id != PROCESSING_PROFILE_ID
        || exported.profile_id != context.profile_id
        || exported
            .ingress_kem_registry
            .root()
            .map_err(|e| format!("registry root: {e:?}"))?
            != authority.ingress_kem_registry_root
        || input.gas_class_units == 0
        || input.gas_class_units != input.gas_limit
    {
        return Err("processing profile, registry, chain or gas classification mismatch".into());
    }
    let active_keys: Vec<_> = exported
        .ingress_kem_registry
        .records
        .iter()
        .filter(|key| {
            key.activation_height <= authority.target_height
                && key
                    .retirement_height
                    .is_none_or(|height| authority.target_height < height)
        })
        .cloned()
        .collect();
    let count = usize::try_from(authority.assigned_cluster_validator_count)
        .map_err(|_| "cluster size overflow")?;
    if active_keys.len() != count {
        return Err("active ingress records differ from governed cluster size".into());
    }
    let quorum = synergy_etdag::certificate_quorum(count).map_err(|e| format!("quorum: {e:?}"))?;
    let (transaction, secret) = signed_transfer(
        &input,
        authority.chain_id,
        &authority.network_id,
        public,
        secret_bytes,
    )?;
    let context_root = context.root().map_err(|e| format!("context root: {e:?}"))?;
    let aad = ProcessingEnvelopeAad {
        profile_id: PROCESSING_PROFILE_ID.into(),
        chain_id: authority.chain_id,
        network_id: authority.network_id.clone(),
        protocol_version: authority.protocol_version.clone(),
        epoch: authority.epoch,
        processing_context_root: context_root.clone(),
        authorization_height: authority.target_height,
        assigned_cluster_id: authority.assigned_cluster_id,
        lane_id: "ordinary-user".into(),
        sender_id: input.sender.clone(),
        nonce_slot: input.nonce,
    };
    let plaintext = SecretBytes(serde_json::to_vec(&transaction).map_err(|e| e.to_string())?);
    let padded = SecretBytes(
        synergy_etdag::crypto::pad_plaintext(&plaintext.0)
            .map_err(|e| format!("padding: {e:?}"))?,
    );
    let payload =
        synergy_etdag::crypto::encrypt_protected_payload(&aad, &active_keys, quorum, &padded.0)
            .map_err(|e| format!("encryption: {e:?}"))?;
    drop(padded);
    drop(plaintext);
    let placeholder = EtdagDigest::from_domain_bytes("SYNERGY_KEYTOOL_PENDING_COMMITMENT", b"");
    let mut envelope = ProcessingEnvelope {
        envelope_version: 1,
        envelope_id: placeholder.clone(),
        aad,
        aead_nonce: payload.aead_nonce,
        key_commitment: payload.key_commitment,
        share_commitment_root: placeholder.clone(),
        share_capsule_root: placeholder,
        ciphertext: payload.ciphertext,
        content_blind_order_key: input.content_blind_order_key,
        share_capsules: payload.share_capsules,
    };
    envelope
        .refresh_capsule_roots()
        .map_err(|e| format!("capsule roots: {e:?}"))?;
    envelope.envelope_id = envelope
        .commitment()
        .map_err(|e| format!("envelope commitment: {e:?}"))?;
    let mut request = ProcessingAdmissionRequest {
        request_version: 1,
        context_root,
        sender_wallet: input.sender,
        sender_nonce: input.nonce,
        gas_class_units: input.gas_class_units,
        fee_class: input.fee_class,
        signature_algorithm: "ML-DSA-87".into(),
        signer_public_key: transaction.signer_public_key,
        envelope,
        signature: Vec::new(),
    };
    let signing = request
        .signing_bytes()
        .map_err(|e| format!("admission transcript: {e:?}"))?;
    request.signature = mldsa87::detached_sign(&signing, &secret)
        .as_bytes()
        .to_vec();
    request
        .validate_context(context)
        .map_err(|e| format!("processing admission: {e:?}"))?;
    Ok(WalletProcessingAdmission {
        request,
        identity_authorization: public.identity_authorization.clone(),
    })
}

const MAX_SESSION_WALLETS: usize = 64;
const MAX_SESSION_CUSTODY_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionRegistry {
    session_version: u32,
    synthetic: bool,
    chain_id: u64,
    network_id: String,
    fixture_root: PathBuf,
    authority_binding_path: PathBuf,
    authority_trust_key_path: PathBuf,
    authority_key_id: String,
    #[serde(default)]
    genesis_path: Option<PathBuf>,
    #[serde(default)]
    custody_kind: Option<String>,
    wallets: Vec<RegistryWallet>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistryWallet {
    wallet_id: String,
    wallet_public_path: PathBuf,
    transaction_secret_path: PathBuf,
}
struct LoadedWallet {
    public: WalletPublic,
    secret: SecretBytes,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionRequest {
    session_version: u32,
    request_id: u64,
    wallet_id: String,
    context_response: serde_json::Value,
    transfer: SessionTransfer,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionTransfer {
    sender: String,
    receiver: String,
    amount_nwei: u128,
    nonce: u64,
    timestamp_unix: u64,
    gas_limit: u64,
    max_fee_per_gas_nwei: u64,
    gas_class_units: u64,
    fee_class: u32,
    content_blind_order_key: EtdagDigest,
}
impl SessionTransfer {
    fn into_input(self) -> TransferInput {
        TransferInput {
            wallet_public_path: PathBuf::new(),
            transaction_secret_path: PathBuf::new(),
            admission_context_path: PathBuf::new(),
            sender: self.sender,
            receiver: self.receiver,
            amount_nwei: self.amount_nwei,
            nonce: self.nonce,
            timestamp_unix: self.timestamp_unix,
            gas_limit: self.gas_limit,
            max_fee_per_gas_nwei: self.max_fee_per_gas_nwei,
            gas_class_units: self.gas_class_units,
            fee_class: self.fee_class,
            content_blind_order_key: self.content_blind_order_key,
            action: None,
        }
    }
}
fn public_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}
fn no_symlink_path(path: &Path) -> Result<(), String> {
    if !path.is_absolute()
        || path
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err("absolute non-traversing fixture path required".into());
    }
    for ancestor in path.ancestors() {
        if fs::symlink_metadata(ancestor)
            .map_err(|_| "fixture path unavailable")?
            .file_type()
            .is_symlink()
        {
            return Err("symlink fixture path rejected".into());
        }
    }
    Ok(())
}
fn load_registry(
    path: &Path,
) -> Result<(String, BTreeMap<String, LoadedWallet>, SessionAuthority), String> {
    load_registry_with_mode(path, false)
}
fn load_registry_with_mode(
    path: &Path,
    operator: bool,
) -> Result<(String, BTreeMap<String, LoadedWallet>, SessionAuthority), String> {
    no_symlink_path(path)?;
    let registry: SessionRegistry = read_json(path)?;
    let leaf = registry
        .fixture_root
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");
    let selected_mode = if operator {
        !registry.synthetic
            && !registry.network_id.starts_with("posy-isolated-")
            && registry.custody_kind.as_deref() == Some("operator-wallet-allowlist-v1")
            && registry.genesis_path.is_some()
    } else {
        registry.synthetic
            && registry.network_id.starts_with("posy-isolated-")
            && leaf.starts_with("posy-isolated-")
    };
    if registry.session_version != 1
        || !selected_mode
        || registry.chain_id == 0
        || registry.network_id.is_empty()
        || registry.network_id.len() > 128
        || registry.network_id.chars().any(char::is_control)
        || registry.wallets.is_empty()
        || registry.wallets.len() > MAX_SESSION_WALLETS
        || !path.starts_with(&registry.fixture_root)
    {
        return Err("registry does not match explicit bounded custody mode".into());
    }
    #[cfg(unix)]
    if operator
        && fs::symlink_metadata(path)
            .map_err(|_| "registry unavailable")?
            .permissions()
            .mode()
            & 0o077
            != 0
    {
        return Err("registry must be private".into());
    }
    no_symlink_path(&registry.fixture_root)?;
    directory(&registry.fixture_root)?;
    for input in [
        &registry.authority_binding_path,
        &registry.authority_trust_key_path,
    ] {
        if !operator && !input.starts_with(&registry.fixture_root) {
            return Err("authority input outside fixture".into());
        }
        no_symlink_path(input)?;
    }
    let binding: synergy_genesis::authority::SignedAuthorityBinding =
        read_json(&registry.authority_binding_path)?;
    crate::authority::verify(
        &registry.authority_binding_path,
        registry.chain_id,
        &registry.network_id,
        synergy_aegis::KeyId::new(registry.authority_key_id).map_err(|e| e.to_string())?,
        &registry.authority_trust_key_path,
    )?;
    if operator {
        let genesis_path = registry
            .genesis_path
            .as_ref()
            .ok_or("operator custody requires pinned Genesis")?;
        no_symlink_path(genesis_path)?;
        let genesis: synergy_genesis::signing::SignedGenesis =
            serde_json::from_slice(&crate::aegis_keys::read_bounded(
                genesis_path,
                16 * 1024 * 1024,
                "public signed Genesis",
            )?)
            .map_err(|_| "invalid signed Genesis")?;
        let trust = crate::aegis_keys::read_bounded(
            &registry.authority_trust_key_path,
            8192,
            "public authority trust key",
        )?;
        synergy_genesis::verify_binding(&genesis, &trust, &binding)?;
    }
    let authority = SessionAuthority::new(binding)?;
    let mut wallets = BTreeMap::new();
    let mut senders = BTreeSet::new();
    let mut total = 0u64;
    for entry in registry.wallets {
        if !public_id(&entry.wallet_id) || wallets.contains_key(&entry.wallet_id) {
            return Err("invalid or duplicate wallet ID".into());
        }
        for file in [&entry.wallet_public_path, &entry.transaction_secret_path] {
            if !file.starts_with(&registry.fixture_root) {
                return Err("wallet custody outside explicit allowlist root".into());
            }
            no_symlink_path(file)?;
            directory(file.parent().ok_or("missing custody directory")?)?;
            let size = fs::symlink_metadata(file)
                .map_err(|_| "custody unavailable")?
                .len();
            total = total.checked_add(size).ok_or("registry size overflow")?;
            if total > MAX_SESSION_CUSTODY_BYTES {
                return Err("registry byte budget exceeded".into());
            }
        }
        let public: WalletPublic = read_json(&entry.wallet_public_path)?;
        if public.sender != public.identity_authorization.binding.identity_address
            || !senders.insert(public.sender.clone())
        {
            return Err("invalid or duplicate wallet sender".into());
        }
        transaction_principal(&public.identity_authorization.binding.authorization_policy)?;
        let secret = load_secret(&entry.transaction_secret_path)?;
        wallets.insert(entry.wallet_id, LoadedWallet { public, secret });
    }
    Ok((registry.network_id, wallets, authority))
}

// The registry pins public authority before accepting any untrusted RPC frame.
// Observation metadata is deliberately excluded from the authenticated context.
struct SessionAuthority {
    binding: synergy_genesis::authority::SignedAuthorityBinding,
    epoch: synergy_posy::SimplifiedEpochContext,
    registry: synergy_posy::FrozenValidatorRegistry,
    verifier: synergy_aegis::PqvmVerifier,
}
impl SessionAuthority {
    fn new(binding: synergy_genesis::authority::SignedAuthorityBinding) -> Result<Self, String> {
        let p = &binding.payload;
        p.validate()?;
        let registry = synergy_posy::FrozenValidatorRegistry::new(
            p.epoch,
            p.validators.iter().map(|v| v.record.clone()).collect(),
        )
        .map_err(|e| e.to_string())?;
        let epoch = synergy_posy::SimplifiedEpochContext::from_frozen_registry(
            p.chain_id,
            p.network_id.clone(),
            p.epoch,
            p.epoch_start_height,
            p.epoch_end_height,
            p.finalized_epoch_seed_root.clone(),
            p.consensus_parameter_root.clone(),
            &registry,
        )
        .map_err(|e| e.to_string())?;
        let verifier = synergy_aegis::PqvmVerifier::new(synergy_aegis::AegisPolicy {
            allowed_algorithms: vec![synergy_aegis::SignatureAlgorithm::MlDsa65],
            maximum_message_bytes: MAX_JSON as usize,
            maximum_signature_bytes: 16 * 1024,
        })
        .map_err(|e| e.to_string())?;
        Ok(Self {
            binding,
            epoch,
            registry,
            verifier,
        })
    }
    fn verify_context_response(
        &self,
        value: &serde_json::Value,
    ) -> Result<WalletAdmissionContext, String> {
        if value
            .get("schema_version")
            .and_then(serde_json::Value::as_u64)
            != Some(2)
        {
            return Err("versioned evidence required".into());
        }
        let exported: WalletAdmissionContext = serde_json::from_value(
            value
                .get("signing_context")
                .ok_or("missing signing context")?
                .clone(),
        )
        .map_err(|_| "invalid signing context")?;
        exported.validate().map_err(|e| format!("context: {e:?}"))?;
        let evidence = value
            .get("source_finality_evidence")
            .ok_or("source evidence absent")?;
        let presented: synergy_genesis::authority::SignedAuthorityBinding = serde_json::from_value(
            evidence
                .get("signed_authority_binding")
                .ok_or("signed authority absent")?
                .clone(),
        )
        .map_err(|_| "unsigned authority rejected")?;
        if presented.payload.signing_bytes()? != self.binding.payload.signing_bytes()?
            || presented.signer_key_id != self.binding.signer_key_id
            || presented.signature != self.binding.signature
        {
            return Err("RPC authority differs from locally pinned authority".into());
        }
        let source_height = exported.context.source_finalized_height;
        let source_root = if source_height == 0 {
            if evidence.get("kind").and_then(serde_json::Value::as_str) != Some("genesis") {
                return Err("wrong Genesis evidence".into());
            }
            let parent: synergy_posy::SimplifiedFinalityParent = serde_json::from_value(
                evidence
                    .get("genesis_reference")
                    .ok_or("Genesis absent")?
                    .clone(),
            )
            .map_err(|_| "invalid Genesis")?;
            if parent != self.binding.payload.anchor_parent || parent.height() != 0 {
                return Err("Genesis differs from pinned authority".into());
            }
            parent.reference_id().to_owned()
        } else {
            if evidence.get("kind").and_then(serde_json::Value::as_str) != Some("three_qc") {
                return Err("three-QC evidence required".into());
            }
            let record: synergy_posy::FinalizedBlockRecord = serde_json::from_value(
                evidence
                    .get("record")
                    .ok_or("source record absent")?
                    .clone(),
            )
            .map_err(|_| "invalid record")?;
            let witness: Vec<synergy_posy::SimplifiedQuorumCertificate> = serde_json::from_value(
                evidence
                    .get("quorum_certificates")
                    .ok_or("witness absent")?
                    .clone(),
            )
            .map_err(|_| "invalid witness")?;
            if witness.len() != 3 || record.height != source_height {
                return Err("wrong source height/witness length".into());
            }
            let mut finality = synergy_posy::ThreeQcFinality::default();
            for qc in witness {
                qc.verify(&self.epoch, &self.registry, self)
                    .map_err(|e| e.to_string())?;
                finality.accept(qc).map_err(|e| e.to_string())?;
            }
            if finality.last_finalized() != Some(&record) {
                return Err("source ancestry mismatch".into());
            }
            EtdagDigest::from_canonical("SYNERGY_ETDAG_FINALIZED_SOURCE_V1", &record)
                .map_err(|e| format!("source root: {e:?}"))?
                .0
        };
        let policy = self
            .binding
            .payload
            .protected
            .as_ref()
            .ok_or("protected authority absent")?;
        let mut expected = exported.context.clone();
        expected.chain_id = self.epoch.chain_id;
        expected.network_id = self.epoch.network_id.clone();
        expected.protocol_version = self.epoch.protocol_version.clone();
        expected.epoch = self.epoch.epoch;
        expected.target_height_offset = policy.parameters.target_height_offset;
        expected.source_finality_context_root = source_root;
        expected.active_validator_set_root = self.epoch.active_validator_set_root.clone();
        expected.validator_consensus_key_root = self.epoch.validator_consensus_key_root.clone();
        expected.frozen_voting_weight_root = self.epoch.frozen_voting_weight_root.clone();
        expected.cluster_schedule_version = policy.cluster_schedule_version.clone();
        expected.finalized_epoch_seed_root = self.epoch.finalized_epoch_seed_root.clone();
        expected.assigned_height_schedule_root = policy.assigned_height_schedule_root.clone();
        expected.cluster_map_root = policy.cluster_map_root.clone();
        expected.assigned_cluster_id = policy.assigned_cluster_id;
        expected.assigned_cluster_membership_root = policy.assigned_cluster_membership_root.clone();
        expected.assigned_cluster_validator_count = self.registry.active_count() as u64;
        expected.assigned_cluster_total_voting_weight =
            u64::try_from(self.registry.active_weight().map_err(|e| e.to_string())?)
                .map_err(|_| "weight overflow")?;
        expected.consensus_parameter_root = self.epoch.consensus_parameter_root.clone();
        expected.cryptographic_profile_root = policy.cryptographic_profile_root.clone();
        expected.ingress_kem_registry_root = policy
            .ingress_kem_registry
            .root()
            .map_err(|e| format!("KEM root: {e:?}"))?;
        if expected != exported.context
            || serde_json::to_vec(&exported.parameters).map_err(|e| e.to_string())?
                != serde_json::to_vec(&policy.parameters).map_err(|e| e.to_string())?
        {
            return Err("signing context differs from verified source and governed policy".into());
        }
        let mut expected_keys: Vec<_> = policy
            .ingress_kem_registry
            .records
            .iter()
            .filter(|r| {
                r.activation_height <= expected.target_height
                    && r.retirement_height
                        .is_none_or(|h| expected.target_height < h)
            })
            .cloned()
            .collect();
        let mut actual_keys = exported.ingress_keys.clone();
        expected_keys.sort_by(|a, b| {
            a.validator_id
                .cmp(&b.validator_id)
                .then(a.key_id.cmp(&b.key_id))
        });
        actual_keys.sort_by(|a, b| {
            a.validator_id
                .cmp(&b.validator_id)
                .then(a.key_id.cmp(&b.key_id))
        });
        if actual_keys != expected_keys {
            return Err("ingress keys differ from pinned policy".into());
        }
        Ok(exported)
    }
}
impl synergy_posy::ConsensusSignatureVerifier for SessionAuthority {
    fn verify_consensus_signature(
        &self,
        domain: &str,
        payload: &[u8],
        validator: &synergy_posy::ValidatorRecord,
        key_id: &str,
        epoch: u64,
        signature: &[u8],
    ) -> synergy_posy::PosyResult<()> {
        use synergy_aegis::AegisVerifier;
        let key = self
            .binding
            .payload
            .validators
            .iter()
            .find(|v| &v.record == validator)
            .ok_or_else(|| synergy_posy::PosyError::invalid("unknown pinned validator"))?;
        if key_id != key.record.consensus_key_id || epoch != self.epoch.epoch {
            return Err(synergy_posy::PosyError::invalid(
                "wrong consensus authority",
            ));
        }
        self.verifier
            .verify(
                &synergy_aegis::SigningContext {
                    domain: domain.into(),
                    chain_id: self.epoch.chain_id,
                    epoch: Some(epoch),
                    height: None,
                },
                payload,
                &synergy_aegis::Signature {
                    algorithm: key.algorithm,
                    key_id: synergy_aegis::KeyId::new(key_id)
                        .map_err(|e| synergy_posy::PosyError::invalid(e.to_string()))?,
                    bytes: signature.to_vec(),
                },
                &key.public_key,
            )
            .map_err(|e| synergy_posy::PosyError::invalid(e.to_string()))
    }
}

fn bounded_line(reader: &mut impl BufRead) -> Result<Option<Vec<u8>>, String> {
    let mut bytes = Vec::new();
    let count = reader
        .take(MAX_JSON + 1)
        .read_until(b'\n', &mut bytes)
        .map_err(|_| "session input failed")?;
    if count == 0 {
        return Ok(None);
    }
    if count as u64 > MAX_JSON || bytes.last() != Some(&b'\n') {
        return Err("oversized or truncated session frame".into());
    }
    Ok(Some(bytes))
}

/// Serial native authoring for an explicitly allowlisted isolated wallet pool.
/// Input/output are bounded JSONL; no request can select a custody path.
pub fn session(registry: &Path, reader: impl BufRead, writer: impl Write) -> Result<(), String> {
    session_with_mode(registry, reader, writer, false)
}
/// Explicit operator-owned existing-wallet custody. This is not protocol activation.
pub fn session_operator(
    registry: &Path,
    reader: impl BufRead,
    writer: impl Write,
) -> Result<(), String> {
    session_with_mode(registry, reader, writer, true)
}
fn session_with_mode(
    registry: &Path,
    mut reader: impl BufRead,
    mut writer: impl Write,
    operator: bool,
) -> Result<(), String> {
    let (network, wallets, authority) = if operator {
        load_registry_with_mode(registry, true)?
    } else {
        load_registry(registry)?
    };
    let mut last_id = 0;
    while let Some(bytes) = bounded_line(&mut reader)? {
        let request: SessionRequest =
            serde_json::from_slice(&bytes).map_err(|_| "invalid session frame")?;
        if request.session_version != 1
            || request.request_id <= last_id
            || !public_id(&request.wallet_id)
        {
            return Err("invalid session version or request ID".into());
        }
        last_id = request.request_id;
        let verified_context = authority.verify_context_response(&request.context_response);
        let result = match verified_context {
            Ok(context) if context.context.network_id == network => {
                if let Some(wallet) = wallets.get(&request.wallet_id) {
                    author(
                        request.transfer.into_input(),
                        context,
                        &wallet.public,
                        &wallet.secret.0,
                    )
                    .map_err(|_| "authoring_rejected")
                } else {
                    Err("unknown_wallet")
                }
            }
            _ => Err("source_authority_rejected"),
        };
        let response = match result {
            Ok(admission) => {
                serde_json::json!({"session_version":1,"request_id":last_id,"status":"signed","receipt_id":EtdagDigest::from_canonical("SYNERGY_LOCAL_ADMISSION_RECEIPT_V1", &admission).map_err(|_| "receipt identity failed")?.0,"admission":admission})
            }
            Err(reason) => {
                serde_json::json!({"session_version":1,"request_id":last_id,"status":"rejected","reason":reason})
            }
        };
        let encoded = serde_json::to_vec(&response).map_err(|_| "session encoding failed")?;
        if encoded.len() as u64 > MAX_JSON {
            return Err("session output byte budget exceeded".into());
        }
        writer
            .write_all(&encoded)
            .and_then(|()| writer.write_all(b"\n"))
            .and_then(|()| writer.flush())
            .map_err(|_| "session output failed")?;
    }
    Ok(())
}

#[cfg(test)]
mod transaction_principal_tests {
    use super::*;

    fn principal(label: &str) -> AuthorizationPrincipal {
        AuthorizationPrincipal {
            principal_id: label.into(),
            principal_type: PrincipalType::PublicKey,
            algorithm: Some("ML-DSA-87".into()),
            public_key: Some("01".into()),
            public_key_sha3_256: Some("00".repeat(32)),
            identity_reference: None,
            status: BindingStatus::Active,
            purposes: vec!["transaction-signing".into()],
        }
    }
    fn policy(principals: Vec<AuthorizationPrincipal>) -> AuthorizationPolicy {
        AuthorizationPolicy {
            policy_type: AuthorizationPolicyType::SingleKey,
            threshold: 1,
            principals,
        }
    }
    #[test]
    fn authorized_account_label_and_existing_transaction_label_both_select() {
        for label in ["account", "transaction"] {
            let policy = policy(vec![principal(label)]);
            assert_eq!(transaction_principal(&policy).unwrap().principal_id, label);
        }
    }
    #[test]
    fn misleading_label_does_not_authorize_wrong_role_algorithm_or_status() {
        let base = principal("transaction");
        let mut wrong_role = base.clone();
        wrong_role.purposes = vec!["validator-signing".into()];
        let mut wrong_algorithm = base.clone();
        wrong_algorithm.algorithm = Some("ML-DSA-65".into());
        let mut retired = base.clone();
        retired.status = BindingStatus::Retired;
        let mut absent = base.clone();
        absent.public_key = None;
        let mut reference = base;
        reference.principal_type = PrincipalType::IdentityReference;
        for rejected in [wrong_role, wrong_algorithm, retired, absent, reference] {
            assert!(transaction_principal(&policy(vec![rejected])).is_err());
        }
    }
    #[test]
    fn missing_and_ambiguous_keys_fail_closed() {
        assert!(transaction_principal(&policy(vec![])).is_err());
        assert!(transaction_principal(&policy(vec![
            principal("account"),
            principal("transaction")
        ]))
        .is_err());
    }
}

#[cfg(test)]
mod session_boundary_tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn session_eof_is_valid_only_between_complete_frames() {
        let mut input = Cursor::new(b"{}\n".as_slice());
        assert_eq!(bounded_line(&mut input).unwrap().unwrap(), b"{}\n");
        assert!(bounded_line(&mut input).unwrap().is_none());
        assert!(bounded_line(&mut Cursor::new(b"{}".as_slice())).is_err());
    }
    #[test]
    fn session_frame_bound_is_enforced_without_unbounded_read() {
        let mut input = vec![b' '; MAX_JSON as usize + 2];
        input.push(b'\n');
        assert!(bounded_line(&mut Cursor::new(input)).is_err());
    }
    #[test]
    fn session_cannot_select_custody_or_supply_unversioned_context() {
        let request = serde_json::json!({"session_version":1,"request_id":1,"wallet_id":"wallet-0",
            "context_response":{},"transfer":{"sender":"s","receiver":"r","amount_nwei":1,"nonce":0,
                "timestamp_unix":1,"gas_limit":1,"max_fee_per_gas_nwei":1,"gas_class_units":1,"fee_class":1,
                "content_blind_order_key":"a".repeat(128)}});
        assert!(serde_json::from_value::<SessionRequest>(request.clone()).is_ok());
        let mut custody = request.clone();
        custody["transaction_secret_path"] = serde_json::json!("/arbitrary");
        assert!(serde_json::from_value::<SessionRequest>(custody).is_err());
        let mut legacy = request;
        legacy.as_object_mut().unwrap().remove("context_response");
        legacy["context"] = serde_json::json!({});
        assert!(serde_json::from_value::<SessionRequest>(legacy).is_err());
    }
}

#[cfg(test)]
mod processing_author_tests {
    #[test]
    fn legacy_processing_commands_cannot_author_or_serialize_without_qualified_apqe() {
        for command in [
            "prepare-wallet-processing-admission",
            "prepare-wallet-admission",
            "prepare-wallet-admission-session",
            "prepare-wallet-admission-session-operator",
        ] {
            // Even supplied, authenticated provider flags do not qualify a
            // command whose implementation still embeds cryptography. Reject
            // before opening the input, custody, or output paths.
            let arguments = vec![
                command.to_string(),
                "/must-not-read".into(),
                "/must-not-write".into(),
                "--apqe-report".into(),
                "/must-not-read-report".into(),
                "--apqe-report-sha256".into(),
                "a".repeat(64),
            ];
            let error = crate::selected_arguments(&arguments)
                .err()
                .expect("legacy authoring must stay disabled");
            assert!(error.contains("fail-closed"));
            assert!(error.contains("embedded"));
        }
    }
}
