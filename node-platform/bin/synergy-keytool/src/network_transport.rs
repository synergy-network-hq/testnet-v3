//! Reviewed, host-private engineering transport issuance. No node activation.
//! The registry transcript is shared verbatim with the actual session verifier.
#[path = "network_gateway.rs"]
pub(crate) mod gateway;
#[path = "../../synergy-node/src/services/apqe_registry_wire.rs"]
mod wire;
use crate::validator_formation::{
    begin, decode, digest, passphrase, private_dir, read, sync, write,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    net::{IpAddr, SocketAddr},
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};
use synergy_address_engine::{
    apqe::{provider::SignOptions, Primitives, SecretBytes},
    encrypt::{decrypt_with_passphrase, encrypt_with_passphrase, EncryptedEnvelope},
    types::Algorithm,
    validator_provisioning::{verify_enrollment, EnrollmentRequest, NetworkBinding},
};
use synergy_genesis::{authority::SignedAuthorityBinding, signing::SignedGenesis};
use wire::{signing_bytes, RegistryPayload, SignedRegistry, TransportEntry, REGISTRY_CONTEXT};
const LIMIT: u64 = 2 * 1024 * 1024;
const ROLE: &str = "formation-transport-issuer-ml-dsa-87-v1";
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request<T> {
    version: u32,
    operation: String,
    parameters: T,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Member {
    enrollment_json: String,
    dial_address: SocketAddr,
    transport_key_id: String,
    configuration_json: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Prepare {
    formation_sha256: String,
    genesis_review_sha256: String,
    target_provider_report_sha256: String,
    valid_from_unix: u64,
    expires_at_unix: u64,
    members: Vec<Member>,
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
    formation_sha256: String,
    genesis_review_sha256: String,
    request_sha256: String,
    genesis_sha256: String,
    authority_sha256: String,
    authority_root_sha256: String,
    issuer_root_sha256: String,
    payload_sha256: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Custody {
    version: u32,
    role: String,
    formation_sha256: String,
    request_sha256: String,
    review_sha256: String,
    public_key: Vec<u8>,
    envelope: EncryptedEnvelope,
}
fn pin(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn encode(v: &impl Serialize) -> Result<Vec<u8>, String> {
    serde_json::to_vec_pretty(v).map_err(|_| "Cannot encode transport formation".into())
}
fn clock() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|t| t.as_secs())
        .map_err(|_| "Clock unavailable".into())
}
fn exact<T: serde::de::DeserializeOwned>(
    path: &Path,
    pin_expected: &str,
    operation: &str,
) -> Result<(Request<T>, SecretBytes), String> {
    if !pin(pin_expected) {
        return Err("Exact request SHA256 required".into());
    }
    let raw = read(path, LIMIT, true)?;
    if digest(raw.as_bytes()) != pin_expected {
        return Err("Exact reviewed transport request changed".into());
    }
    let r: Request<T> = decode(&raw)?;
    if r.version != 1 || r.operation != operation {
        return Err("Transport operation differs".into());
    }
    Ok((r, raw))
}
fn isolated(address: SocketAddr) -> bool {
    address.port() != 0
        && match address.ip() {
            IpAddr::V4(ip) => {
                ip.is_loopback() || ip.is_private() || {
                    let [a, b, _, _] = ip.octets();
                    a == 100 && (64..128).contains(&b)
                }
            }
            IpAddr::V6(ip) => {
                matches!(address,SocketAddr::V6(a) if a.scope_id()==0)
                    && (ip.is_loopback() || ip.is_unique_local())
            }
        }
}
struct Source {
    export: Value,
    genesis: SignedGenesis,
    authority: SignedAuthorityBinding,
    root: Vec<u8>,
}
fn source(
    context: &Path,
    pin: &str,
    formation: &Path,
    engine: crate::provider::Engine,
) -> Result<Source, String> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let export = crate::network_formation::signed_public(context, pin, formation, engine.clone())?;
    let artifacts = &export["artifacts"];
    let genesis = serde_json::from_str(
        artifacts["genesis.json"]
            .as_str()
            .ok_or("Missing exact signed Genesis")?,
    )
    .map_err(|_| "Invalid signed Genesis")?;
    let authority = serde_json::from_str(
        artifacts["authority.json"]
            .as_str()
            .ok_or("Missing exact signed authority")?,
    )
    .map_err(|_| "Invalid signed authority")?;
    let root = STANDARD
        .decode(
            artifacts["authority-root.pub"]
                .as_str()
                .ok_or("Missing exact public root")?,
        )
        .map_err(|_| "Invalid public root encoding")?;
    let verifier = crate::provider::verifier(
        synergy_aegis::AegisPolicy {
            allowed_algorithms: vec![synergy_aegis::SignatureAlgorithm::MlDsa65],
            maximum_message_bytes: 16 * 1024 * 1024,
            maximum_signature_bytes: 16 * 1024,
        },
        Some(engine.clone()),
    )?;
    synergy_genesis::verify_binding_with_verifier(&genesis, &root, &authority, &verifier)?;
    Ok(Source {
        export,
        genesis,
        authority,
        root,
    })
}
fn payload(
    p: &Prepare,
    source: &Source,
    context_pin: &str,
    engine: &crate::provider::Engine,
    now: u64,
) -> Result<RegistryPayload, String> {
    if p.formation_sha256 != context_pin
        || p.genesis_review_sha256 != source.export["review_sha256"]
        || !pin(&p.target_provider_report_sha256)
        || p.members.len() != 5
        || p.valid_from_unix > now
        || p.expires_at_unix <= now
        || p.expires_at_unix <= p.valid_from_unix
        || p.expires_at_unix - p.valid_from_unix > 7 * 86400
    {
        return Err(
            "Exact signed formation, five bounded members and current seven-day validity required"
                .into(),
        );
    }
    let authority = &source.authority.payload;
    if authority.epoch != 1
        || authority.epoch_start_height != 1
        || authority.validators.len() != 5
        || !authority
            .validators
            .iter()
            .all(|v| v.record.may_sign_consensus())
    {
        return Err("Exactly five active authenticated Genesis validators required".into());
    }
    let protected = authority
        .protected
        .as_ref()
        .ok_or("Governed processing policy required")?;
    protected
        .ingress_kem_registry
        .validate_protected_profile()
        .map_err(|_| "Invalid governed ingress profile")?;
    let network = NetworkBinding {
        chain_id_hex: format!("{:064x}", authority.chain_id),
        genesis_sha256: source.export["genesis_sha256"]
            .as_str()
            .ok_or("Missing Genesis pin")?
            .into(),
    };
    let (mut ids, mut endpoints, mut key_ids, mut keys) = (
        BTreeSet::new(),
        BTreeSet::new(),
        BTreeSet::new(),
        BTreeSet::new(),
    );
    let guard = engine.lock().map_err(|_| "APQE provider unavailable")?;
    let mut validators = Vec::new();
    for m in &p.members {
        if m.enrollment_json.len() > 128 * 1024
            || m.configuration_json.len() > 64 * 1024
            || !isolated(m.dial_address)
            || !endpoints.insert(m.dial_address)
            || m.transport_key_id.is_empty()
            || m.transport_key_id.len() > 128
            || !m
                .transport_key_id
                .bytes()
                .all(|b| (0x21..=0x7e).contains(&b))
            || !key_ids.insert(m.transport_key_id.clone())
        {
            return Err("Duplicate, oversized or nonisolated transport member".into());
        }
        let enrollment: EnrollmentRequest = serde_json::from_str(&m.enrollment_json)
            .map_err(|_| "Invalid bound public enrollment")?;
        verify_enrollment(&guard, &enrollment, &network)?;
        let identity = &enrollment.payload.identity;
        let consensus = synergy_address_engine::snts07::decode_lower_hex(
            "consensus",
            &identity.consensus_key.public_key,
            1952,
        )?;
        let transport = synergy_address_engine::snts07::decode_lower_hex(
            "transport",
            &identity.node_identity_key.public_key,
            1952,
        )?;
        let ingress = synergy_address_engine::snts07::decode_lower_hex(
            "ingress",
            &enrollment.payload.ingress_key.public_key,
            1568,
        )?;
        let member = authority
            .validators
            .iter()
            .find(|v| v.record.validator_id == identity.address)
            .ok_or("Enrollment is not active signed membership")?;
        let active: Vec<_> = protected
            .ingress_kem_registry
            .records
            .iter()
            .filter(|r| {
                r.validator_id == identity.address
                    && r.activation_height <= authority.epoch_start_height
                    && r.retirement_height
                        .is_none_or(|h| authority.epoch_start_height < h)
            })
            .collect();
        if member.algorithm != synergy_aegis::SignatureAlgorithm::MlDsa65
            || member.public_key != consensus
            || active.len() != 1
            || active[0].public_key.public_key != ingress
            || !ids.insert(identity.address.clone())
            || !keys.insert(transport.clone())
            || transport == source.root
            || authority.validators.iter().any(|v| {
                v.public_key == transport || v.record.consensus_key_id == m.transport_key_id
            })
        {
            return Err("Enrollment changes governed keys or reuses a transport role".into());
        }
        validators.push(TransportEntry {
            node_address: identity.address.clone(),
            dial_address: m.dial_address,
            transport_key_id: m.transport_key_id.clone(),
            transport_key_version: 1,
            transport_public_key: transport,
            enrollment_sha256: digest(m.enrollment_json.as_bytes()),
            revoked: false,
        });
    }
    validators.sort_by(|a, b| a.node_address.cmp(&b.node_address));
    Ok(RegistryPayload {
        schema_version: 1,
        scope: "isolated-development-canary".into(),
        chain_id: authority.chain_id,
        network_id: authority.network_id.clone(),
        protocol: source.genesis.unsigned.network.protocol_version.clone(),
        genesis_hash: source.genesis.genesis_hash.clone(),
        genesis_artifact_sha256: network.genesis_sha256,
        authority_binding_sha256: source.export["authority_sha256"]
            .as_str()
            .ok_or("Missing authority pin")?
            .into(),
        epoch: 1,
        generation: 1,
        valid_from_unix: p.valid_from_unix,
        expires_at_unix: p.expires_at_unix,
        validators,
    })
}
fn configuration(
    m: &Member,
    p: &Prepare,
    source: &Source,
    issuer: &[u8],
) -> Result<String, String> {
    use synergy_config::{
        ApqeProviderConfiguration, ApqeTransportConfiguration, ApqeTransportProfile, ConsensusMode,
    };
    let mut c: synergy_config::NodeConfiguration = serde_json::from_str(&m.configuration_json)
        .map_err(|_| "Invalid typed public node configuration")?;
    if c.aegis_signing_key_path.is_some()
        || c.consensus.signing_key_path.is_some()
        || c.etdag.ingress_kem_secret_key_path.is_some()
        || c.consensus.authority_recovery_certificate_path.is_some()
        || c.consensus.autonomous_epoch_activation.is_some()
        || c.update.enabled
        || c.rpc.listen_address.is_some_and(|a| !a.ip().is_loopback())
        || serde_json::to_value(c.role).map_err(|_| "Invalid role")? != json!("validator")
    {
        return Err("Fresh canonical validator config forbids raw custody, recovery, remote RPC or automatic updates".into());
    }
    let root = Path::new("/opt/synergy");
    c.chain_id = source.genesis.unsigned.network.chain_id;
    c.network_id = source.genesis.unsigned.network.network_id.clone();
    c.manifest_path = root.join("network/network-manifest.json");
    c.genesis_path = Some(root.join("network/genesis.json"));
    c.public_identity_path = root.join("keys/apqe/validator.pub.json");
    c.aegis_key_bindings_path = None;
    c.admin_socket_path = root.join("run/admin.sock");
    c.aegis_provider = Some(ApqeProviderConfiguration {
        report_path: root.join("lib/apqe/build-report.json"),
        authenticated_report_sha256: p.target_provider_report_sha256.clone(),
    });
    c.apqe_transport = Some(ApqeTransportConfiguration {
        profile: ApqeTransportProfile::EngineeringCanaryPqVsessionV1,
        registry_path: root.join("network/transport-registry.json"),
        registry_trust_key_path: root.join("network/transport-root.pub"),
        registry_trust_key_sha256: digest(issuer),
        genesis_trust_key_sha256: digest(&source.root),
        enrollment_path: root.join("keys/apqe/enrollment.json"),
        custody_path: root.join("keys/apqe/custody.json"),
        custody_unlock_path: root.join("keys/apqe/unlock"),
    });
    c.consensus.mode = ConsensusMode::ValidateAndVote;
    c.consensus.authority_binding = Some(root.join("network/authority.json"));
    c.consensus.authority_trust_key_path = Some(root.join("network/authority-root.pub"));
    c.etdag.enabled = true;
    c.storage.data_directory = root.join("data");
    c.network.listen_addresses = vec![m.dial_address];
    c.network.advertised_addresses = vec![m.dial_address];
    c.vpn = Default::default();
    c.validate().map_err(|e| e.to_string())?;
    String::from_utf8(encode(&c)?).map_err(|_| "Invalid public config UTF8".into())
}
fn unlock() -> Result<SecretBytes, String> {
    let mut bytes = vec![0; 32];
    let result = Primitives.random_bytes(&mut bytes);
    let bytes = SecretBytes::from_bytes(bytes);
    result.map_err(|_| "APQE CSPRNG unavailable")?;
    Ok(SecretBytes::from_bytes(
        bytes
            .as_bytes()
            .iter()
            .flat_map(|b| {
                const HEX: &[u8; 16] = b"0123456789abcdef";
                [HEX[(b >> 4) as usize], HEX[(b & 15) as usize]]
            })
            .collect(),
    ))
}
pub fn prepare(
    context: &Path,
    pin: &str,
    formation: &Path,
    request_path: &Path,
    request_pin: &str,
    directory: &Path,
    engine: crate::provider::Engine,
) -> Result<Value, String> {
    let source = source(context, pin, formation, engine.clone())?;
    let (req, raw) = exact::<Prepare>(request_path, request_pin, "network_transport_prepare")?;
    let payload = payload(&req.parameters, &source, pin, &engine, clock()?)?;
    // Validate public templates before reserving or generating an issuer.
    for m in &req.parameters.members {
        configuration(m, &req.parameters, &source, &[0u8; 2592])?;
    }
    begin(directory)?;
    write(&directory.join("request.json"), raw.as_bytes())?;
    let pass = unlock()?;
    let guard = engine.lock().map_err(|_| "APQE provider unavailable")?;
    let pair = guard
        .generate_keypair(Algorithm::MlDsa87)
        .map_err(|e| e.to_string())?;
    let envelope = encrypt_with_passphrase(
        &guard,
        &Primitives,
        pair.private_key.as_bytes(),
        passphrase(&pass)?,
    )?;
    drop(guard);
    let payload_raw = encode(&payload)?;
    let review = Review {
        version: 1,
        formation_sha256: pin.into(),
        genesis_review_sha256: req.parameters.genesis_review_sha256,
        request_sha256: request_pin.into(),
        genesis_sha256: source.export["genesis_sha256"]
            .as_str()
            .ok_or("Missing Genesis pin")?
            .into(),
        authority_sha256: source.export["authority_sha256"]
            .as_str()
            .ok_or("Missing authority pin")?
            .into(),
        authority_root_sha256: digest(&source.root),
        issuer_root_sha256: digest(&pair.public_key),
        payload_sha256: digest(&payload_raw),
    };
    let review_raw = encode(&review)?;
    let custody = Custody {
        version: 1,
        role: ROLE.into(),
        formation_sha256: pin.into(),
        request_sha256: request_pin.into(),
        review_sha256: digest(&review_raw),
        public_key: pair.public_key.clone(),
        envelope,
    };
    write(&directory.join("unlock"), pass.as_bytes())?;
    write(&directory.join("issuer.enc.json"), &encode(&custody)?)?;
    write(&directory.join("issuer-root.pub"), &pair.public_key)?;
    write(&directory.join("registry-payload.json"), &payload_raw)?;
    write(&directory.join("review.json"), &review_raw)?;
    sync(directory)?;
    status(context, pin, formation, directory, engine, false)
}
struct Loaded {
    source: Source,
    parameters: Prepare,
    payload: RegistryPayload,
    review: Review,
    review_pin: String,
    public: Vec<u8>,
    secret: SecretBytes,
}
fn load(
    context: &Path,
    pin: &str,
    formation: &Path,
    directory: &Path,
    engine: &crate::provider::Engine,
) -> Result<Loaded, String> {
    load_at(context, pin, formation, directory, engine, None)
}
// Historical validation is read-only and never used by prepare/sign entrypoints.
fn load_at(
    context: &Path,
    pin: &str,
    formation: &Path,
    directory: &Path,
    engine: &crate::provider::Engine,
    at: Option<u64>,
) -> Result<Loaded, String> {
    private_dir(directory)?;
    let raw = read(&directory.join("review.json"), 128 * 1024, true)?;
    let review: Review = decode(&raw)?;
    let review_pin = digest(raw.as_bytes());
    if review.version != 1 || review.formation_sha256 != pin {
        return Err("Transport review context changed".into());
    }
    let source = source(context, pin, formation, engine.clone())?;
    if source.export["review_sha256"] != review.genesis_review_sha256
        || source.export["genesis_sha256"] != review.genesis_sha256
        || source.export["authority_sha256"] != review.authority_sha256
        || digest(&source.root) != review.authority_root_sha256
    {
        return Err("Signed formation source changed".into());
    }
    let (req, _) = exact::<Prepare>(
        &directory.join("request.json"),
        &review.request_sha256,
        "network_transport_prepare",
    )?;
    let expected = payload(
        &req.parameters,
        &source,
        pin,
        engine,
        match at {
            Some(v) => v,
            None => clock()?,
        },
    )?;
    let raw_payload = read(&directory.join("registry-payload.json"), LIMIT, true)?;
    if digest(raw_payload.as_bytes()) != review.payload_sha256
        || serde_json::to_value(&expected).map_err(|_| "Invalid registry")?
            != serde_json::from_slice::<Value>(raw_payload.as_bytes())
                .map_err(|_| "Invalid stored registry")?
    {
        return Err("Reviewed transport payload changed".into());
    }
    let public = read(&directory.join("issuer-root.pub"), 2592, true)?
        .as_bytes()
        .to_vec();
    let custody: Custody = decode(&read(&directory.join("issuer.enc.json"), LIMIT, true)?)?;
    if public.len() != 2592
        || digest(&public) != review.issuer_root_sha256
        || custody.version != 1
        || custody.role != ROLE
        || custody.formation_sha256 != pin
        || custody.request_sha256 != review.request_sha256
        || custody.review_sha256 != review_pin
        || custody.public_key != public
    {
        return Err("Transport issuer custody role or binding changed".into());
    }
    let pass = read(&directory.join("unlock"), 64, true)?;
    let guard = engine.lock().map_err(|_| "APQE provider unavailable")?;
    let secret = SecretBytes::from_bytes(decrypt_with_passphrase(
        &guard,
        &Primitives,
        &custody.envelope,
        passphrase(&pass)?,
    )?);
    if !guard
        .keypair_corresponds(Algorithm::MlDsa87, &public, secret.as_bytes())
        .map_err(|e| e.to_string())?
    {
        return Err("Transport custody does not possess exact issuer root".into());
    }
    drop(guard);
    for m in &req.parameters.members {
        configuration(m, &req.parameters, &source, &public)?;
    }
    Ok(Loaded {
        source,
        parameters: req.parameters,
        payload: expected,
        review,
        review_pin,
        public,
        secret,
    })
}
fn receipt(p: &Loaded) -> Value {
    json!({"schema":"nodenetwork-network-transport-v1","pending":true,"signed":false,"formation_sha256":p.review.formation_sha256,"genesis_review_sha256":p.review.genesis_review_sha256,"request_sha256":p.review.request_sha256,"review_sha256":p.review_pin,"genesis_sha256":p.review.genesis_sha256,"authority_sha256":p.review.authority_sha256,"issuer_root_sha256":p.review.issuer_root_sha256,"valid_from_unix":p.payload.valid_from_unix,"expires_at_unix":p.payload.expires_at_unix,"validator_addresses":p.payload.validators.iter().map(|v|&v.node_address).collect::<Vec<_>>(),"runtime_admission":false,"fleet_readiness_verified":false})
}
pub fn sign(
    context: &Path,
    pin: &str,
    formation: &Path,
    directory: &Path,
    request_path: &Path,
    request_pin: &str,
    engine: crate::provider::Engine,
) -> Result<Value, String> {
    let (req, raw) = exact::<Sign>(request_path, request_pin, "network_transport_sign")?;
    let p = load(context, pin, formation, directory, &engine)?;
    if req.parameters.review_sha256 != p.review_pin {
        return Err("Explicit transport review changed".into());
    }
    if directory.join("signed").exists() || directory.join("signed-pending").exists() {
        return Err(
            "Transport signing exists or is interrupted; reconcile without re-signing".into(),
        );
    }
    let pending = directory.join("signed-pending");
    begin(&pending)?;
    write(&pending.join("sign-request.json"), raw.as_bytes())?;
    let guard = engine.lock().map_err(|_| "APQE provider unavailable")?;
    let signature = guard
        .sign(
            Algorithm::MlDsa87,
            p.secret.as_bytes(),
            &signing_bytes(&p.payload)?,
            SignOptions::Pure {
                context: REGISTRY_CONTEXT,
            },
        )
        .map_err(|e| e.to_string())?;
    if !guard
        .verify(
            Algorithm::MlDsa87,
            &p.public,
            &signing_bytes(&p.payload)?,
            &signature,
            SignOptions::Pure {
                context: REGISTRY_CONTEXT,
            },
        )
        .map_err(|e| e.to_string())?
    {
        return Err("APQE transport signature failed before publication".into());
    }
    drop(guard);
    let signed = SignedRegistry {
        payload: p.payload,
        signature,
    };
    write(&pending.join("transport-registry.json"), &encode(&signed)?)?;
    sync(&pending)?;
    fs::rename(&pending, directory.join("signed"))
        .map_err(|_| "Cannot publish signed transport")?;
    sync(directory)?;
    status(context, pin, formation, directory, engine, false)
}
pub fn status(
    context: &Path,
    pin: &str,
    formation: &Path,
    directory: &Path,
    engine: crate::provider::Engine,
    export: bool,
) -> Result<Value, String> {
    status_at(context, pin, formation, directory, engine, export, None)
}
fn evidence_time(directory: &Path) -> Result<u64, String> {
    let review: Review = decode(&read(&directory.join("review.json"), 128 * 1024, true)?)?;
    let (q, _) = exact::<Prepare>(
        &directory.join("request.json"),
        &review.request_sha256,
        "network_transport_prepare",
    )?;
    q.parameters
        .expires_at_unix
        .checked_sub(1)
        .ok_or("Invalid historical transport window".into())
}
pub(super) fn status_evidence(
    context: &Path,
    pin: &str,
    formation: &Path,
    directory: &Path,
    engine: crate::provider::Engine,
) -> Result<Value, String> {
    status_at(
        context,
        pin,
        formation,
        directory,
        engine,
        false,
        Some(evidence_time(directory)?),
    )
}
fn status_at(
    context: &Path,
    pin: &str,
    formation: &Path,
    directory: &Path,
    engine: crate::provider::Engine,
    export: bool,
    at: Option<u64>,
) -> Result<Value, String> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let p = load_at(context, pin, formation, directory, &engine, at)?;
    let mut result = receipt(&p);
    if directory.join("signed-pending").exists() {
        return Err("Interrupted transport signing requires reconciliation".into());
    }
    let signed_path = directory.join("signed");
    if !signed_path.exists() {
        if export {
            return Err("Transport has not been separately reviewed and signed".into());
        }
        return Ok(result);
    }
    private_dir(&signed_path)?;
    let raw = read(&signed_path.join("transport-registry.json"), LIMIT, true)?;
    let signed: SignedRegistry = decode(&raw)?;
    if serde_json::to_value(&signed.payload).map_err(|_| "Invalid signed registry")?
        != serde_json::to_value(&p.payload).map_err(|_| "Invalid reviewed registry")?
    {
        return Err("Signed transport payload substituted".into());
    }
    let sign_raw = read(&signed_path.join("sign-request.json"), 4096, true)?;
    let sign: Request<Sign> = decode(&sign_raw)?;
    if sign.version != 1
        || sign.operation != "network_transport_sign"
        || sign.parameters.review_sha256 != p.review_pin
    {
        return Err("Signed transport request changed".into());
    }
    if !engine
        .lock()
        .map_err(|_| "APQE provider unavailable")?
        .verify(
            Algorithm::MlDsa87,
            &p.public,
            &signing_bytes(&signed.payload)?,
            &signed.signature,
            SignOptions::Pure {
                context: REGISTRY_CONTEXT,
            },
        )
        .map_err(|e| e.to_string())?
    {
        return Err("Invalid APQE transport signature".into());
    }
    result["signed"] = json!(true);
    result["registry_sha256"] = json!(digest(raw.as_bytes()));
    result["sign_request_sha256"] = json!(digest(sign_raw.as_bytes()));
    if !export {
        return Ok(result);
    }
    let manifest=json!({"chain_id":p.payload.chain_id,"network_id":p.payload.network_id,"genesis_hash":p.payload.genesis_hash,"protocol_version":p.payload.protocol,"manifest_hash":p.review.genesis_sha256}).to_string();
    let mut network = BTreeMap::new();
    for name in ["genesis.json", "authority.json", "authority-root.pub"] {
        network.insert(
            name,
            p.source.export["artifacts"][name]
                .as_str()
                .ok_or("Missing signed public artifact")?
                .to_string(),
        );
    }
    network.insert("network-manifest.json", manifest);
    network.insert(
        "transport-registry.json",
        std::str::from_utf8(raw.as_bytes())
            .map_err(|_| "Invalid public registry UTF8")?
            .into(),
    );
    network.insert("transport-root.pub", STANDARD.encode(&p.public));
    let hashes: BTreeMap<_, _> = network
        .iter()
        .map(|(name, text)| {
            let hash = if name.ends_with(".pub") {
                STANDARD
                    .decode(text)
                    .map(|b| digest(&b))
                    .map_err(|_| "Invalid public root")?
            } else {
                digest(text.as_bytes())
            };
            Ok((*name, hash))
        })
        .collect::<Result<_, String>>()?;
    let start=json!({"profile":"engineering_canary_pq_vsession_v1","production_approved":false,"network_id":p.payload.network_id,"chain_id":p.payload.chain_id,"all_validators_ready":false,"all_pairs_vpn_verified":false,"validator_addresses":p.payload.validators.iter().map(|v|&v.node_address).collect::<Vec<_>>(),"public_file_sha256":hashes}).to_string();
    let mut nodes = Vec::new();
    for member in &p.parameters.members {
        let enrollment: EnrollmentRequest =
            serde_json::from_str(&member.enrollment_json).map_err(|_| "Invalid enrollment")?;
        let config = configuration(member, &p.parameters, &p.source, &p.public)?;
        let mut artifacts = BTreeMap::new();
        for (name, body) in &network {
            artifacts.insert(format!("network/{name}"), body.clone());
        }
        artifacts.insert("config/node.json".into(), config);
        artifacts.insert("config/start-authorized.json".into(), start.clone());
        nodes.push(json!({"address":enrollment.payload.identity.address,"artifacts":artifacts}));
    }
    let value = json!({"schema":"nodenetwork-network-transport-export-v1","review_sha256":p.review_pin,"registry_sha256":digest(raw.as_bytes()),"issuer_root_sha256":p.review.issuer_root_sha256,"fleet_readiness_verified":false,"nodes":nodes});
    if serde_json::to_vec(&value)
        .map_err(|_| "Cannot encode public transport export")?
        .len()
        > 4 * 1024 * 1024
    {
        return Err("Public transport export exceeds 4MiB".into());
    }
    Ok(value)
}

#[cfg(test)]
fn fixture_configuration(index: usize) -> Value {
    json!({"schema_version":1,"node_name":format!("validator-{}",index+1),"role":"validator","chain_id":1266,"network_id":"nodenetwork-formation-disposable-fixture","manifest_path":"/opt/synergy/network/network-manifest.json","public_identity_path":"/opt/synergy/keys/apqe/validator.pub.json","admin_socket_path":"/opt/synergy/run/admin.sock","rpc":{"enabled":true,"listen_address":"127.0.0.1:8545","max_request_bytes":2097152,"max_concurrent_requests":8},"storage":{"data_directory":"/opt/synergy/data","wal_sync":"every_commit","max_open_files":128,"world_memory_budget_bytes":536870912,"minimum_free_bytes":2147483648u64,"prune_finalized_history_after_blocks":null}})
}
/// Extends the existing real five-registration fixture; generates no replacement validator keys.
#[cfg(test)]
pub(crate) fn exercise_native_fixture(
    context: &Path,
    pin: &str,
    formation: &Path,
    parent: &Path,
    engine: crate::provider::Engine,
    enrollments: &[String],
) {
    let source = source(context, pin, formation, engine.clone()).unwrap();
    let now = clock().unwrap();
    let members:Vec<_>=enrollments.iter().enumerate().map(|(i,e)|json!({"enrollment_json":e,"dial_address":format!("10.90.0.{}:5622",i+1),"transport_key_id":format!("transport-{}",i+1),"configuration_json":({let mut c=fixture_configuration(i);c["chain_id"]=json!(source.genesis.unsigned.network.chain_id);c.to_string()})})).collect();
    let request = json!({"version":1,"operation":"network_transport_prepare","parameters":{"formation_sha256":pin,"genesis_review_sha256":source.export["review_sha256"],"target_provider_report_sha256":"a".repeat(64),"valid_from_unix":now,"expires_at_unix":now+3600,"members":members}});
    let path = parent.join("transport-prepare-request.json");
    let raw = encode(&request).unwrap();
    write(&path, &raw).unwrap();
    let directory = parent.join("network-transport");
    assert!(prepare(
        context,
        pin,
        formation,
        &path,
        &"0".repeat(64),
        &directory,
        engine.clone()
    )
    .is_err());
    assert!(!directory.exists());
    let prepared = prepare(
        context,
        pin,
        formation,
        &path,
        &digest(&raw),
        &directory,
        engine.clone(),
    )
    .unwrap();
    assert_eq!(prepared["signed"], false);
    assert_eq!(prepared["fleet_readiness_verified"], false);
    assert_eq!(
        status(context, pin, formation, &directory, engine.clone(), false).unwrap(),
        prepared
    );
    assert!(status(context, pin, formation, &directory, engine.clone(), true).is_err());
    assert!(prepare(
        context,
        pin,
        formation,
        &path,
        &digest(&raw),
        &directory,
        engine.clone()
    )
    .is_err());
    let sign_path = parent.join("transport-sign-request.json");
    let wrong=encode(&json!({"version":1,"operation":"network_transport_sign","parameters":{"review_sha256":"0".repeat(64)}})).unwrap();
    write(&sign_path, &wrong).unwrap();
    assert!(sign(
        context,
        pin,
        formation,
        &directory,
        &sign_path,
        &digest(&wrong),
        engine.clone()
    )
    .is_err());
    assert!(!directory.join("signed-pending").exists());
    fs::remove_file(&sign_path).unwrap();
    let raw=encode(&json!({"version":1,"operation":"network_transport_sign","parameters":{"review_sha256":prepared["review_sha256"]}})).unwrap();
    write(&sign_path, &raw).unwrap();
    let signed = sign(
        context,
        pin,
        formation,
        &directory,
        &sign_path,
        &digest(&raw),
        engine.clone(),
    )
    .unwrap();
    assert_eq!(signed["signed"], true);
    assert!(sign(
        context,
        pin,
        formation,
        &directory,
        &sign_path,
        &digest(&raw),
        engine.clone()
    )
    .is_err());
    let exported = status(context, pin, formation, &directory, engine.clone(), true).unwrap();
    assert_eq!(exported["nodes"].as_array().unwrap().len(), 5);
    for node in exported["nodes"].as_array().unwrap() {
        let artifacts = node["artifacts"].as_object().unwrap();
        assert_eq!(artifacts.len(), 8);
        assert!(!artifacts.keys().any(|k| k.starts_with("keys/")));
        let c: synergy_config::NodeConfiguration =
            serde_json::from_str(artifacts["config/node.json"].as_str().unwrap()).unwrap();
        c.validate().unwrap();
        let start: Value =
            serde_json::from_str(artifacts["config/start-authorized.json"].as_str().unwrap())
                .unwrap();
        assert_eq!(start["all_pairs_vpn_verified"], false);
        assert_eq!(start["all_validators_ready"], false);
    }
    if source.genesis.unsigned.network.chain_id == 99999 {
        gateway::exercise_fixture(context, pin, formation, &directory, parent, engine.clone());
    }
    // Actual registry verification succeeds only for the signed exact payload/context.
    let registry_path = directory.join("signed/transport-registry.json");
    let original = read(&registry_path, LIMIT, true).unwrap();
    let mut changed: Value = decode(&original).unwrap();
    changed["payload"]["validators"][0]["dial_address"] = json!("10.91.0.1:5622");
    fs::write(&registry_path, encode(&changed).unwrap()).unwrap();
    assert!(status(context, pin, formation, &directory, engine.clone(), true).is_err());
    fs::write(&registry_path, original.as_bytes()).unwrap();
    let unlock_path = directory.join("unlock");
    let original_unlock = read(&unlock_path, 64, true).unwrap();
    fs::write(&unlock_path, [b'0'; 64]).unwrap();
    assert!(status(context, pin, formation, &directory, engine.clone(), false).is_err());
    fs::write(&unlock_path, original_unlock.as_bytes()).unwrap();
    let mut parameters: Prepare = serde_json::from_value(request["parameters"].clone()).unwrap();
    parameters.members.swap(0, 1);
    assert!(payload(&parameters, &source, pin, &engine, now).is_ok());
    parameters.members[0].enrollment_json = parameters.members[1].enrollment_json.clone();
    assert!(payload(&parameters, &source, pin, &engine, now).is_err());
    begin(&directory.join("signed-pending")).unwrap();
    assert!(status(context, pin, formation, &directory, engine, false)
        .unwrap_err()
        .contains("Interrupted"));
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_request_schema_and_isolated_endpoint_bounds() {
        for address in [
            "10.1.2.3:5622",
            "127.0.0.1:5622",
            "100.70.1.2:5622",
            "[fd00::1]:5622",
        ] {
            assert!(isolated(address.parse().unwrap()))
        }
        for address in ["8.8.8.8:5622", "10.1.2.3:0", "0.0.0.0:5622", "[::]:5622"] {
            assert!(!isolated(address.parse().unwrap()))
        }
        assert!(serde_json::from_value::<Request<Sign>>(json!({"version":1,"operation":"network_transport_sign","parameters":{"review_sha256":"a".repeat(64),"private_key":"forbidden"}})).is_err());
    }
}
