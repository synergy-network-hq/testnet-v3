//! Host-private fresh Genesis formation for the authenticated NodeNetwork owner.
//! Uses the existing Genesis/authority transcripts. It does not activate a node.
use crate::validator_formation::{
    begin, decode, digest, passphrase, private_dir, read, sync, write,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{fs, path::Path};
use synergy_address_engine::{
    apqe::{Primitives, SecretBytes},
    encrypt::{decrypt_with_passphrase, encrypt_with_passphrase, EncryptedEnvelope},
    types::Algorithm,
    validator_provisioning::{FormationContext, FormationRegistration},
};
use synergy_aegis::{AegisPolicy, AegisSigner, KeyId, SignatureAlgorithm, SigningContext};
use synergy_genesis::{
    authority::{AuthorityPayload, SignedAuthorityBinding, AUTHORITY_SIGNING_DOMAIN},
    builder::UnsignedGenesis,
    signing::SignedGenesis,
};
const REQUEST_LIMIT: u64 = 2 * 1024 * 1024;
const RECIPE_LIMIT: usize = 1024 * 1024;
const REGISTRATION_LIMIT: usize = 128 * 1024;
const ROLE: &str = "fresh-genesis-formation-ml-dsa-65";

pub(super) mod wallet_release_issuer;
pub(super) mod wallet_release_authoring;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request<T> {
    version: u32,
    operation: String,
    parameters: T,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Prepare {
    formation_sha256: String,
    recipe_json: String,
    registrations_json: Vec<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Sign {
    review_sha256: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Review {
    version: u32,
    formation: FormationContext,
    formation_sha256: String,
    request_sha256: String,
    key_id: String,
    validator_addresses: Vec<String>,
    unsigned_genesis_sha256: String,
    unsigned_authority_sha256: String,
    authority_root_sha256: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Custody {
    version: u32,
    role: String,
    formation: FormationContext,
    request_sha256: String,
    review_sha256: String,
    public_key: Vec<u8>,
    envelope: EncryptedEnvelope,
}
fn pin(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn exact_request<T: serde::de::DeserializeOwned>(
    path: &Path,
    expected: &str,
    operation: &str,
) -> Result<(Request<T>, SecretBytes), String> {
    if !pin(expected) {
        return Err("Exact canonical request digest required".into());
    }
    let raw = read(path, REQUEST_LIMIT, true)?;
    if digest(raw.as_bytes()) != expected {
        return Err("Reviewed canonical request changed".into());
    }
    let request: Request<T> = decode(&raw)?;
    if request.version != 1 || request.operation != operation {
        return Err("Network formation operation differs".into());
    }
    Ok((request, raw))
}
fn policy() -> AegisPolicy {
    AegisPolicy {
        allowed_algorithms: vec![SignatureAlgorithm::MlDsa65],
        maximum_message_bytes: RECIPE_LIMIT * 2,
        maximum_signature_bytes: 16384,
    }
}
fn encode(value: &impl Serialize) -> Result<Vec<u8>, String> {
    serde_json::to_vec_pretty(value).map_err(|_| "Cannot encode network formation".into())
}
fn prepare_parameters(
    p: &Prepare,
    context: &FormationContext,
    formation_pin: &str,
) -> Result<Value, String> {
    if p.formation_sha256 != formation_pin
        || p.recipe_json.len() > RECIPE_LIMIT
        || p.registrations_json.len() != 5
        || p.registrations_json
            .iter()
            .any(|x| x.len() > REGISTRATION_LIMIT)
    {
        return Err(
            "Exactly five bounded formation registrations and reviewed context required".into(),
        );
    }
    let recipe: Value = serde_json::from_str(&p.recipe_json)
        .map_err(|_| "Invalid explicit fresh network recipe")?;
    if recipe["validators"] != json!([])
        || recipe["authority"]["validators"].as_array().map(Vec::len) != Some(5)
        || recipe
            .get("formation_registrations")
            .is_some_and(|x| x != &json!([]))
        || recipe["network"]["network_id"] != context.network_id
        || recipe["network"]["chain_id"]
            .as_u64()
            .map(|n| format!("{n:064x}"))
            != Some(context.chain_id_hex.clone())
    {
        return Err(
            "Recipe must use the exact formation and only the five public registrations".into(),
        );
    }
    Ok(recipe)
}
fn registration_set(
    raw: &[String],
    context: &FormationContext,
    authority: &AuthorityPayload,
    engine: &crate::provider::Engine,
) -> Result<Vec<String>, String> {
    let mut addresses = std::collections::BTreeSet::new();
    let guard = engine.lock().map_err(|_| "APQE provider unavailable")?;
    for text in raw {
        let registration: FormationRegistration =
            serde_json::from_str(text).map_err(|_| "Invalid public registration")?;
        synergy_address_engine::validator_provisioning::verify_formation_registration(
            &guard,
            &registration,
            context,
        )?;
        crate::validator_formation::verify_authorized_keys(authority, &registration)?;
        if !addresses.insert(registration.payload.identity.address) {
            return Err("Duplicate formation registration identity".into());
        }
    }
    if addresses.len() != 5 || authority.validators.len() != 5 {
        return Err("Exact five-validator formation coverage required".into());
    }
    Ok(addresses.into_iter().collect())
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
    let (request, raw) =
        exact_request::<Prepare>(request_path, request_pin, "network_formation_prepare")?;
    let mut recipe = prepare_parameters(&request.parameters, &context, context_pin)?;
    // Reserve before any generation. Never reuse an incomplete directory/keyset.
    begin(directory)?;
    write(&directory.join("request.json"), raw.as_bytes())?;
    let mut paths = Vec::new();
    for (index, registration) in request.parameters.registrations_json.iter().enumerate() {
        let path = directory.join(format!("registration-{index}.json"));
        write(&path, registration.as_bytes())?;
        paths.push(path);
    }
    recipe["formation_registrations"] = json!(paths);
    write(&directory.join("recipe.json"), &encode(&recipe)?)?;
    crate::prepare_authority::prepare_formation_genesis(
        &directory.join("recipe.json"),
        context_path,
        context_pin,
        &directory.join("unsigned-genesis.json"),
        &directory.join("unsigned-authority.json"),
        engine.clone(),
    )?;
    // The reused public preparation writer creates0644 public artifacts. Keep
    // this private work area uniformly0600 before custody/status admission.
    use std::os::unix::fs::PermissionsExt;
    for name in ["unsigned-genesis.json", "unsigned-authority.json"] {
        fs::set_permissions(directory.join(name), fs::Permissions::from_mode(0o600))
            .map_err(|_| "Cannot restrict private formation output")?;
    }
    let genesis_raw = read(
        &directory.join("unsigned-genesis.json"),
        REQUEST_LIMIT,
        true,
    )?;
    let authority_raw = read(
        &directory.join("unsigned-authority.json"),
        REQUEST_LIMIT,
        true,
    )?;
    let genesis: UnsignedGenesis = decode(&genesis_raw)?;
    let authority: AuthorityPayload = decode(&authority_raw)?;
    let validator_addresses = registration_set(
        &request.parameters.registrations_json,
        &context,
        &authority,
        &engine,
    )?;
    let key_id = KeyId::new(genesis.authority_trust_key_id.clone()).map_err(|e| e.to_string())?;
    let mut entropy = vec![0; 32];
    let generated = Primitives.random_bytes(&mut entropy);
    let entropy = SecretBytes::from_bytes(entropy);
    generated.map_err(|_| "APQE secure randomness unavailable")?;
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let unlock = SecretBytes::from_bytes(
        entropy
            .as_bytes()
            .iter()
            .flat_map(|b| [HEX[(b >> 4) as usize], HEX[(b & 15) as usize]])
            .collect(),
    );
    let guard = engine.lock().map_err(|_| "APQE provider unavailable")?;
    let pair = guard
        .generate_keypair(Algorithm::MlDsa65)
        .map_err(|e| e.to_string())?;
    let envelope = encrypt_with_passphrase(
        &guard,
        &Primitives,
        pair.private_key.as_bytes(),
        passphrase(&unlock)?,
    )?;
    drop(guard);
    let review = Review {
        version: 1,
        formation: context.clone(),
        formation_sha256: context_pin.into(),
        request_sha256: request_pin.into(),
        key_id: key_id.as_str().into(),
        validator_addresses,
        unsigned_genesis_sha256: digest(genesis_raw.as_bytes()),
        unsigned_authority_sha256: digest(authority_raw.as_bytes()),
        authority_root_sha256: digest(&pair.public_key),
    };
    let review_raw = encode(&review)?;
    let custody = Custody {
        version: 1,
        role: ROLE.into(),
        formation: context,
        request_sha256: request_pin.into(),
        review_sha256: digest(&review_raw),
        public_key: pair.public_key.clone(),
        envelope,
    };
    write(&directory.join("unlock"), unlock.as_bytes())?;
    write(&directory.join("authority.enc.json"), &encode(&custody)?)?;
    write(&directory.join("authority-root.pub"), &pair.public_key)?;
    write(&directory.join("review.json"), &review_raw)?;
    sync(directory)?;
    status(context_path, context_pin, directory, engine, false)
}

struct Prepared {
    review: Review,
    review_pin: String,
    genesis: UnsignedGenesis,
    authority: AuthorityPayload,
    public: Vec<u8>,
    signer: crate::provider::Engine,
}

struct FormationKey {
    envelope: EncryptedEnvelope,
    unlock: SecretBytes,
}

struct SignedFormation {
    genesis: SignedGenesis,
    authority: SignedAuthorityBinding,
    genesis_bytes: SecretBytes,
    authority_bytes: SecretBytes,
    sign_request_sha256: String,
}
fn load(
    context_path: &Path,
    context_pin: &str,
    directory: &Path,
    engine: crate::provider::Engine,
) -> Result<Prepared, String> {
    private_dir(directory)?;
    let context = crate::validator_formation::pinned_context(context_path, context_pin)?;
    let raw = read(
        &directory.join("review.json"),
        REGISTRATION_LIMIT as u64,
        true,
    )?;
    let review: Review = decode(&raw)?;
    let review_pin = digest(raw.as_bytes());
    if review.version != 1 || review.formation != context || review.formation_sha256 != context_pin
    {
        return Err("Prepared formation context differs".into());
    }
    let (request, _) = exact_request::<Prepare>(
        &directory.join("request.json"),
        &review.request_sha256,
        "network_formation_prepare",
    )?;
    prepare_parameters(&request.parameters, &context, context_pin)?;
    let g = read(
        &directory.join("unsigned-genesis.json"),
        REQUEST_LIMIT,
        true,
    )?;
    let a = read(
        &directory.join("unsigned-authority.json"),
        REQUEST_LIMIT,
        true,
    )?;
    let public = read(&directory.join("authority-root.pub"), 1952, true)?
        .as_bytes()
        .to_vec();
    if digest(g.as_bytes()) != review.unsigned_genesis_sha256
        || digest(a.as_bytes()) != review.unsigned_authority_sha256
        || public.len() != 1952
        || digest(&public) != review.authority_root_sha256
    {
        return Err("Prepared public artifact changed".into());
    }
    let genesis: UnsignedGenesis = decode(&g)?;
    let authority: AuthorityPayload = decode(&a)?;
    genesis.validate()?;
    authority.validate()?;
    if genesis.authority_trust_key_id != review.key_id
        || genesis.network.network_id != context.network_id
        || format!("{:064x}", genesis.network.chain_id) != context.chain_id_hex
        || authority.network_id != context.network_id
        || authority.chain_id != genesis.network.chain_id
        || registration_set(
            &request.parameters.registrations_json,
            &context,
            &authority,
            &engine,
        )? != review.validator_addresses
    {
        return Err("Prepared Genesis, authority or registration coverage differs".into());
    }
    Ok(Prepared {
        review,
        review_pin,
        genesis,
        authority,
        public,
        signer: engine,
    })
}
impl Prepared {
    fn read_custody(&self, directory: &Path) -> Result<FormationKey, String> {
        let custody: Custody = decode(&read(
            &directory.join("authority.enc.json"),
            REQUEST_LIMIT,
            true,
        )?)?;
        if custody.version != 1
            || custody.role != ROLE
            || custody.formation != self.review.formation
            || custody.request_sha256 != self.review.request_sha256
            || custody.review_sha256 != self.review_pin
            || custody.public_key != self.public
        {
            return Err("Authority custody scope differs".into());
        }
        let unlock = read(&directory.join("unlock"), 64, true)?;
        passphrase(&unlock)?;
        Ok(FormationKey {
            envelope: custody.envelope,
            unlock,
        })
    }

    fn read_signed_formation(&self, directory: &Path) -> Result<Option<SignedFormation>, String> {
        if directory.join("signed-pending").exists() {
            return Err(
                "Interrupted formation signing requires reconciliation; no regeneration".into(),
            );
        }
        let signed = directory.join("signed");
        if !signed.exists() {
            return Ok(None);
        }
        private_dir(&signed)?;
        let request = read(&signed.join("sign-request.json"), 4096, true)?;
        let request_sha256 = digest(request.as_bytes());
        let request: Request<Sign> = decode(&request)?;
        if request.version != 1
            || request.operation != "network_formation_sign"
            || request.parameters.review_sha256 != self.review_pin
        {
            return Err("Signed request differs from reviewed formation".into());
        }
        let genesis_bytes = read(&signed.join("genesis.json"), REQUEST_LIMIT, true)?;
        let authority_bytes = read(&signed.join("authority.json"), REQUEST_LIMIT, true)?;
        let genesis: SignedGenesis = decode(&genesis_bytes)?;
        let authority: SignedAuthorityBinding = decode(&authority_bytes)?;
        if genesis.unsigned != self.genesis
            || authority.payload.signing_bytes()? != self.authority.signing_bytes()?
        {
            return Err("Signed outputs differ from reviewed source".into());
        }
        let id = KeyId::new(self.review.key_id.clone()).map_err(|e| e.to_string())?;
        synergy_genesis::signing::verify(
            &genesis,
            &crate::provider::verifier(policy(), Some(self.signer.clone()))?,
            &self.public,
        )?;
        crate::authority::check_with_provider(
            &authority, &id, &self.public, Some(self.signer.clone())
        )?;
        Ok(Some(SignedFormation {
            genesis,
            authority,
            genesis_bytes,
            authority_bytes,
            sign_request_sha256: request_sha256,
        }))
    }

    fn signer(&self, key: &FormationKey) -> Result<impl AegisSigner, String> {
        let guard = self
            .signer
            .lock()
            .map_err(|_| "APQE provider unavailable")?;
        let secret = SecretBytes::from_bytes(decrypt_with_passphrase(
            &guard,
            &Primitives,
            &key.envelope,
            passphrase(&key.unlock)?,
        )?);
        drop(guard);
        crate::provider::signer(
            policy(),
            KeyId::new(self.review.key_id.clone()).map_err(|e| e.to_string())?,
            &self.public,
            secret.as_bytes().to_vec(),
            Some(self.signer.clone()),
        )
    }
    fn receipt(&self) -> Value {
        json!({"schema":"nodenetwork-network-formation-v1","pending":true,"signed":false,
        "network_id":self.review.formation.network_id,"chain_id":self.genesis.network.chain_id.to_string(),
        "formation_sha256":self.review.formation_sha256,"request_sha256":self.review.request_sha256,
        "review_sha256":self.review_pin,"validator_addresses":self.review.validator_addresses,
        "unsigned_genesis_sha256":self.review.unsigned_genesis_sha256,"unsigned_authority_sha256":self.review.unsigned_authority_sha256,
        "authority_root_sha256":self.review.authority_root_sha256})
    }
}

pub fn status(
    context_path: &Path,
    context_pin: &str,
    directory: &Path,
    engine: crate::provider::Engine,
    export: bool,
) -> Result<Value, String> {
    let p = load(context_path, context_pin, directory, engine.clone())?;
    let key = p.read_custody(directory)?;
    let possession = format!(
        "SYNERGY-AUTHORITY-CUSTODY-POSSESSION-V1\0{}\0{}",
        p.review.request_sha256, p.review_pin
    );
    let ctx = SigningContext {
        domain: "SYNERGY-AUTHORITY-CUSTODY-POSSESSION-V1".into(),
        chain_id: p.genesis.network.chain_id,
        epoch: None,
        height: None,
    };
    let id = KeyId::new(p.review.key_id.clone()).map_err(|e| e.to_string())?;
    let proof = p
        .signer(&key)?
        .sign(&id, &ctx, possession.as_bytes())
        .map_err(|e| e.to_string())?;
    use synergy_aegis::AegisVerifier;
    crate::provider::verifier(policy(), Some(engine.clone()))?
        .verify(&ctx, possession.as_bytes(), &proof, &p.public)
        .map_err(|e| e.to_string())?;
    let mut result = p.receipt();
    let Some(signed) = p.read_signed_formation(directory)? else {
        if export {
            return Err("Reviewed network formation has not been signed".into());
        }
        return Ok(result);
    };
    let g = signed.genesis_bytes;
    let a = signed.authority_bytes;
    result["signed"] = true.into();
    result["genesis_sha256"] = digest(g.as_bytes()).into();
    result["authority_sha256"] = digest(a.as_bytes()).into();
    result["sign_request_sha256"] = signed.sign_request_sha256.into();
    if export {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let exported = json!({"schema":"nodenetwork-network-formation-export-v1","review_sha256":p.review_pin,
            "genesis_sha256":result["genesis_sha256"],"authority_sha256":result["authority_sha256"],"authority_root_sha256":p.review.authority_root_sha256,
            "artifacts":{"genesis.json":std::str::from_utf8(g.as_bytes()).map_err(|_| "Invalid public Genesis UTF8")?,
            "authority.json":std::str::from_utf8(a.as_bytes()).map_err(|_| "Invalid public authority UTF8")?,"authority-root.pub":STANDARD.encode(p.public)}});
        if serde_json::to_vec(&exported)
            .map_err(|_| "Cannot encode public export")?
            .len()
            > REQUEST_LIMIT as usize
        {
            return Err("Public formation export exceeds 2 MiB".into());
        }
        return Ok(exported);
    }
    Ok(result)
}

pub fn sign(
    context_path: &Path,
    context_pin: &str,
    directory: &Path,
    request_path: &Path,
    request_pin: &str,
    engine: crate::provider::Engine,
) -> Result<Value, String> {
    let (request, raw) =
        exact_request::<Sign>(request_path, request_pin, "network_formation_sign")?;
    let p = load(context_path, context_pin, directory, engine.clone())?;
    let key = p.read_custody(directory)?;
    if request.parameters.review_sha256 != p.review_pin {
        return Err("Explicit public review digest changed".into());
    }
    if directory.join("signed").exists() || directory.join("signed-pending").exists() {
        return Err(
            "Network formation signing already exists; reconcile without re-signing".into(),
        );
    }
    let pending = directory.join("signed-pending");
    begin(&pending)?;
    write(&pending.join("sign-request.json"), raw.as_bytes())?;
    let signer = p.signer(&key)?;
    let id = KeyId::new(p.review.key_id.clone()).map_err(|e| e.to_string())?;
    let genesis = synergy_genesis::signing::sign(p.genesis.clone(), &signer, id.clone())?;
    let signature = signer
        .sign(
            &id,
            &SigningContext {
                domain: AUTHORITY_SIGNING_DOMAIN.into(),
                chain_id: p.authority.chain_id,
                epoch: Some(p.authority.epoch),
                height: None,
            },
            &p.authority.signing_bytes()?,
        )
        .map_err(|e| e.to_string())?;
    let authority = SignedAuthorityBinding {
        payload: p.authority.clone(),
        signer_key_id: p.review.key_id.clone(),
        signature: signature.bytes,
    };
    synergy_genesis::signing::verify(
        &genesis,
        &crate::provider::verifier(policy(), Some(engine.clone()))?,
        &p.public,
    )?;
    crate::authority::check_with_provider(&authority, &id, &p.public, Some(engine.clone()))?;
    write(&pending.join("genesis.json"), &encode(&genesis)?)?;
    write(&pending.join("authority.json"), &encode(&authority)?)?;
    sync(&pending)?;
    fs::rename(&pending, directory.join("signed"))
        .map_err(|_| "Cannot publish signed formation")?;
    sync(directory)?;
    status(context_path, context_pin, directory, engine, false)
}

/// Called only inside the existing real-APQE five-registration qualification.
#[cfg(test)]
pub(crate) fn exercise_native_fixture(
    context_path: &Path,
    context_pin: &str,
    recipe_path: &Path,
    parent: &Path,
    engine: crate::provider::Engine,
    transport_custodies:&[(EncryptedEnvelope,SecretBytes)],
) {
    let mut recipe: Value = decode(&read(recipe_path, REQUEST_LIMIT, true).unwrap()).unwrap();
    recipe["network"]["autonomous_epoch_protocol"] =
        json!(synergy_genesis::network::AUTONOMOUS_EPOCH_PROTOCOL_V1);
    recipe["authority"]["protected"]["version"] = json!(2);
    recipe["authority"]["protected"]["cutoff_relationship"] = json!("processing_groups_v1");
    recipe["canary_testing_treasury"] = crate::formation_treasury::prepare_send_fixture_treasury(context_path,context_pin,parent,engine.clone(),recipe["network"]["activation_unix"].as_u64().unwrap());
    let registrations: Vec<String> = recipe["formation_registrations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| fs::read_to_string(p.as_str().unwrap()).unwrap())
        .collect();
    recipe["formation_registrations"] = json!([]);
    let request = json!({"version":1,"operation":"network_formation_prepare","parameters":{"formation_sha256":context_pin,"recipe_json":recipe.to_string(),"registrations_json":registrations}});
    let request_path = parent.join("app-prepare-request.json");
    let raw = encode(&request).unwrap();
    write(&request_path, &raw).unwrap();
    let request_pin = digest(&raw);
    let directory = parent.join("app-network-formation");
    assert!(prepare(
        context_path,
        context_pin,
        &request_path,
        &"0".repeat(64),
        &directory,
        engine.clone()
    )
    .is_err());
    assert!(!directory.exists());
    let prepared = prepare(
        context_path,
        context_pin,
        &request_path,
        &request_pin,
        &directory,
        engine.clone(),
    )
    .unwrap();
    assert_eq!(prepared["pending"], true);
    assert_eq!(prepared["signed"], false);
    assert_eq!(prepared["request_sha256"], request_pin);
    assert!(status(context_path, context_pin, &directory, engine.clone(), true).is_err());
    assert_eq!(
        status(context_path, context_pin, &directory, engine.clone(), false).unwrap(),
        prepared
    );
    assert!(prepare(
        context_path,
        context_pin,
        &request_path,
        &request_pin,
        &directory,
        engine.clone()
    )
    .is_err());
    let sign_path = parent.join("app-sign-request.json");
    let wrong=encode(&json!({"version":1,"operation":"network_formation_sign","parameters":{"review_sha256":"0".repeat(64)}})).unwrap();
    write(&sign_path, &wrong).unwrap();
    assert!(sign(
        context_path,
        context_pin,
        &directory,
        &sign_path,
        &digest(&wrong),
        engine.clone()
    )
    .is_err());
    assert!(!directory.join("signed-pending").exists());
    fs::remove_file(&sign_path).unwrap();
    let raw=encode(&json!({"version":1,"operation":"network_formation_sign","parameters":{"review_sha256":prepared["review_sha256"]}})).unwrap();
    write(&sign_path, &raw).unwrap();
    let signed = sign(
        context_path,
        context_pin,
        &directory,
        &sign_path,
        &digest(&raw),
        engine.clone(),
    )
    .unwrap();
    assert_eq!(signed["signed"], true);
    assert_eq!(
        status(context_path, context_pin, &directory, engine.clone(), false).unwrap(),
        signed
    );
    assert!(sign(
        context_path,
        context_pin,
        &directory,
        &sign_path,
        &digest(&raw),
        engine.clone()
    )
    .is_err());
    let exported = status(context_path, context_pin, &directory, engine.clone(), true).unwrap();
    assert_eq!(exported["artifacts"].as_object().unwrap().len(), 3);
    assert_eq!(
        digest(
            exported["artifacts"]["genesis.json"]
                .as_str()
                .unwrap()
                .as_bytes()
        ),
        signed["genesis_sha256"]
    );
    let mut enrolled=Vec::new();
    for (raw,(envelope,unlock)) in request["parameters"]["registrations_json"].as_array().unwrap().iter().zip(transport_custodies){
        let registration:FormationRegistration=serde_json::from_str(raw.as_str().unwrap()).unwrap();
        let (enrollment,_)=synergy_address_engine::validator_provisioning::bind_formation(&engine.lock().unwrap(),&registration,&registration.payload.formation,envelope,std::str::from_utf8(unlock.as_bytes()).unwrap(),synergy_address_engine::validator_provisioning::NetworkBinding{chain_id_hex:registration.payload.formation.chain_id_hex.clone(),genesis_sha256:signed["genesis_sha256"].as_str().unwrap().into()}).unwrap();
        enrolled.push(serde_json::to_string(&enrollment).unwrap());
    }
    wallet_release_issuer::tests::exercise(
        context_path, context_pin, &directory, parent, engine.clone(),
    );
    crate::network_transport::exercise_native_fixture(context_path,context_pin,&directory,parent,engine.clone(),&enrolled);
    crate::formation_treasury::exercise_send_fixture(context_path,context_pin,&directory,parent,engine.clone());
    let unlock = SecretBytes::from_bytes(fs::read(directory.join("unlock")).unwrap());
    fs::write(directory.join("unlock"), [b'0'; 64]).unwrap();
    assert!(status(context_path, context_pin, &directory, engine.clone(), false).is_err());
    fs::write(directory.join("unlock"), unlock.as_bytes()).unwrap();
    let public_path = directory.join("signed/genesis.json");
    let original = fs::read(&public_path).unwrap();
    let mut changed: Value = serde_json::from_slice(&original).unwrap();
    changed["genesis_hash"] = json!("0".repeat(64));
    fs::write(&public_path, encode(&changed).unwrap()).unwrap();
    assert!(status(context_path, context_pin, &directory, engine.clone(), true).is_err());
    fs::write(&public_path, original).unwrap();
    begin(&directory.join("signed-pending")).unwrap();
    assert!(status(context_path, context_pin, &directory, engine, false)
        .unwrap_err()
        .contains("Interrupted"));
}


/// Public, already APQE-verified source for the separately reviewed transport issuer.
/// Never exposes authority custody or its unlock material.
pub(super) fn signed_public(context:&Path,pin:&str,directory:&Path,engine:crate::provider::Engine)->Result<Value,String>{
    status(context,pin,directory,engine,true)
}


#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn recipe_requires_exact_context_five_public_registrations_and_no_external_paths() {
        let context = FormationContext {
            network_id: "fixture".into(),
            chain_id_hex: format!("{:064x}", 99999),
            formation_id: "ab".repeat(32),
        };
        let mut p = Prepare { formation_sha256: "a".repeat(64), registrations_json: vec!["{}".into(); 5],
            recipe_json: json!({"validators":[],"authority":{"validators":[{},{},{},{},{}]},"network":{"network_id":"fixture","chain_id":99999}}).to_string() };
        assert!(prepare_parameters(&p, &context, &"a".repeat(64)).is_ok());
        p.registrations_json.pop();
        assert!(prepare_parameters(&p, &context, &"a".repeat(64)).is_err());
        p.registrations_json
            .push("x".repeat(REGISTRATION_LIMIT + 1));
        assert!(prepare_parameters(&p, &context, &"a".repeat(64)).is_err());
        p.registrations_json[4] = "{}".into();
        let mut recipe: Value = serde_json::from_str(&p.recipe_json).unwrap();
        recipe["formation_registrations"] = json!(["/outside/registration.json"]);
        p.recipe_json = recipe.to_string();
        assert!(prepare_parameters(&p, &context, &"a".repeat(64)).is_err());
        assert!(serde_json::from_value::<Request<Sign>>(json!({"version":1,"operation":"network_formation_sign","parameters":{"review_sha256":"a".repeat(64),"secret":"forbidden"}})).is_err());
    }
}
