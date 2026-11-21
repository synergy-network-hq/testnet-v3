//! Explicit additional-purpose admission issuance by the existing formation owner.
//! The role-bound issuer is never unwrapped or delegated to a generic signer.
use super::*;
use crate::gateway_wire::{self, AdmissionPayload, GatewayEntry, SignedAdmission};
use synergy_address_engine::apqe::gateway_transport::GatewayEnrollment;
const PURPOSE: &str = "engineering-rpc-gateway-admission-v1";
const SCHEMA: &str = "nodenetwork-gateway-admission-v1";
pub(crate) struct Inputs<'a> {
    pub context: &'a Path,
    pub pin: &'a str,
    pub formation: &'a Path,
    pub transport: &'a Path,
    pub approval: &'a Path,
    pub approval_pin: &'a str,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Approval {
    format: String,
    purpose: String,
    formation_sha256: String,
    transport_review_sha256: String,
    issuer_root_sha256: String,
    gateway_enrollment_sha256: String,
    genesis_sha256: String,
    authority_sha256: String,
    registry_sha256: String,
    valid_from_unix: u64,
    expires_at_unix: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrepareGateway {
    formation_sha256: String,
    transport_review_sha256: String,
    gateway_enrollment_json: String,
    purpose_approval_sha256: String,
    purpose_approval_json: String,
    valid_from_unix: u64,
    expires_at_unix: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignGateway {
    review_sha256: String,
    purpose_approval_sha256: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Review {
    version: u32,
    request_sha256: String,
    purpose_approval_sha256: String,
    payload: AdmissionPayload,
}

// Signed registry digest is supplied from the role-bound directory, not a request URL/path.
fn validate_payload(
    owner: &Loaded,
    p: &PrepareGateway,
    a: &Approval,
    approval_raw: &[u8],
    engine: &crate::provider::Engine,
    now: u64,
) -> Result<AdmissionPayload, String> {
    if a.format != "synergy-engineering-gateway-purpose-v1"
        || a.purpose != PURPOSE
        || !pin(&p.purpose_approval_sha256)
        || digest(approval_raw) != p.purpose_approval_sha256
        || p.purpose_approval_json.as_bytes() != approval_raw
        || a.formation_sha256 != owner.review.formation_sha256
        || p.formation_sha256 != a.formation_sha256
        || a.transport_review_sha256 != owner.review_pin
        || p.transport_review_sha256 != a.transport_review_sha256
        || a.issuer_root_sha256 != owner.review.issuer_root_sha256
        || a.genesis_sha256 != owner.review.genesis_sha256
        || a.authority_sha256 != owner.review.authority_sha256
        || a.gateway_enrollment_sha256 != digest(p.gateway_enrollment_json.as_bytes())
        || a.valid_from_unix != p.valid_from_unix
        || a.expires_at_unix != p.expires_at_unix
        || a.valid_from_unix > now
        || a.expires_at_unix <= now
        || a.expires_at_unix <= a.valid_from_unix
        || a.expires_at_unix - a.valid_from_unix > 7 * 86400
        || a.valid_from_unix < owner.payload.valid_from_unix
        || a.expires_at_unix > owner.payload.expires_at_unix
        || p.gateway_enrollment_json.len() > 128 * 1024
        || owner.payload.chain_id == 0
    {
        return Err(
            "Gateway additional-purpose approval differs from exact formation owner".into(),
        );
    }
    let e: GatewayEnrollment = serde_json::from_str(&p.gateway_enrollment_json)
        .map_err(|_| "Invalid public gateway enrollment")?;
    e.verify(&*engine.lock().map_err(|_| "APQE provider unavailable")?)
        .map_err(|_| "Gateway enrollment signature refused")?;
    let g = e.payload;
    if g.chain_id != owner.payload.chain_id
        || g.network_id != owner.payload.network_id
        || g.genesis_artifact_sha256 != owner.review.genesis_sha256
        || g.transport_public_key.len() != 1952
        || g.transport_key_version == 0
        || owner.payload.validators.iter().any(|v| {
            v.node_address == g.node_address
                || v.transport_key_id == g.transport_key_id
                || v.transport_public_key == g.transport_public_key
        })
        || owner.source.authority.payload.validators.iter().any(|v| {
            v.public_key == g.transport_public_key
                || v.record.consensus_key_id == g.transport_key_id
        })
    {
        return Err("Gateway enrollment differs from signed isolated formation or role".into());
    }
    Ok(AdmissionPayload {
        schema_version: 1,
        scope: "isolated-development-canary".into(),
        protocol: gateway_wire::PROTOCOL.into(),
        chain_id: owner.payload.chain_id,
        network_id: owner.payload.network_id.clone(),
        genesis_artifact_sha256: owner.review.genesis_sha256.clone(),
        authority_binding_sha256: owner.review.authority_sha256.clone(),
        validator_registry_sha256: a.registry_sha256.clone(),
        epoch: owner.payload.epoch,
        generation: owner.payload.generation,
        valid_from_unix: a.valid_from_unix,
        expires_at_unix: a.expires_at_unix,
        gateways: vec![GatewayEntry {
            node_address: g.node_address,
            role: "rpc_gateway".into(),
            transport_key_id: g.transport_key_id,
            transport_key_version: g.transport_key_version,
            transport_public_key: g.transport_public_key,
            enrollment_sha256: a.gateway_enrollment_sha256.clone(),
            revoked: false,
        }],
    })
}
pub(crate) fn preflight(
    context: &Path,
    pin: &str,
    formation: &Path,
    transport: &Path,
    raw: &[u8],
    engine: crate::provider::Engine,
) -> Result<Value, String> {
    if raw.len() > 2 * 1024 * 1024 {
        return Err("Gateway preflight request exceeds bound".into());
    }
    let q: Request<PrepareGateway> =
        serde_json::from_slice(raw).map_err(|_| "Invalid exact gateway preflight")?;
    if q.version != 1 || q.operation != "gateway_admission_prepare" {
        return Err("Gateway preflight operation differs".into());
    }
    let o = owner(context, pin, formation, transport, &engine, false)?;
    let a: Approval = serde_json::from_str(&q.parameters.purpose_approval_json)
        .map_err(|_| "Invalid exact gateway purpose")?;
    if a.registry_sha256
        != digest(
            read(
                &transport.join("signed/transport-registry.json"),
                LIMIT,
                true,
            )?
            .as_bytes(),
        )
    {
        return Err("Gateway approved registry changed".into());
    }
    let p = validate_payload(
        &o,
        &q.parameters,
        &a,
        q.parameters.purpose_approval_json.as_bytes(),
        &engine,
        clock()?,
    )?;
    Ok(
        json!({"schema":"nodenetwork-gateway-admission-preflight-v1","ready":true,"request_sha256":digest(raw),"formation_sha256":pin,
        "transport_review_sha256":o.review_pin,"issuer_root_sha256":o.review.issuer_root_sha256,"purpose_approval_sha256":q.parameters.purpose_approval_sha256,
        "genesis_sha256":p.genesis_artifact_sha256,"authority_sha256":p.authority_binding_sha256,"registry_sha256":p.validator_registry_sha256,
        "gateway_enrollment_sha256":p.gateways[0].enrollment_sha256,"gateway_address":p.gateways[0].node_address,"network_id":p.network_id,"chain_id":p.chain_id.to_string(),
        "valid_from_unix":p.valid_from_unix,"expires_at_unix":p.expires_at_unix,"mutation_performed":false,"services_started":false,"public_listener":false,"production_qualified":false}),
    )
}
fn owner(
    context: &Path,
    pin: &str,
    formation: &Path,
    transport: &Path,
    engine: &crate::provider::Engine,
    historical: bool,
) -> Result<Loaded, String> {
    // Historical reads verify the same signature/custody, without renewing authority.
    if historical {
        super::status_evidence(context, pin, formation, transport, engine.clone())?;
        super::load_at(
            context,
            pin,
            formation,
            transport,
            engine,
            Some(super::evidence_time(transport)?),
        )
    } else {
        super::status(context, pin, formation, transport, engine.clone(), false)?;
        super::load(context, pin, formation, transport, engine)
    }
}
fn reviewed(
    i: &Inputs<'_>,
    directory: &Path,
    engine: &crate::provider::Engine,
) -> Result<(Loaded, Review, String), String> {
    let Inputs {
        context,
        pin,
        formation,
        transport,
        approval,
        approval_pin,
    } = *i;
    private_dir(directory)?;
    let o = owner(context, pin, formation, transport, engine, true)?;
    let raw = read(&directory.join("review.json"), 128 * 1024, true)?;
    let r: Review = decode(&raw)?;
    let (request, _) = exact::<PrepareGateway>(
        &directory.join("request.json"),
        &r.request_sha256,
        "gateway_admission_prepare",
    )?;
    let a = read(approval, 16384, true)?;
    if approval_pin != r.purpose_approval_sha256 || digest(a.as_bytes()) != approval_pin {
        return Err("Gateway purpose approval changed".into());
    }
    let approved: Approval = decode(&a)?;
    if approved.registry_sha256
        != digest(
            read(
                &transport.join("signed/transport-registry.json"),
                LIMIT,
                true,
            )?
            .as_bytes(),
        )
    {
        return Err("Gateway approved registry changed".into());
    }
    let expected = validate_payload(
        &o,
        &request.parameters,
        &approved,
        a.as_bytes(),
        engine,
        approved
            .expires_at_unix
            .checked_sub(1)
            .ok_or("Invalid retained purpose window")?,
    )?;
    if r.version != 1
        || serde_json::to_value(&r.payload).map_err(|_| "Invalid gateway review")?
            != serde_json::to_value(expected).map_err(|_| "Invalid gateway payload")?
    {
        return Err("Gateway reviewed payload changed".into());
    }
    Ok((o, r, digest(raw.as_bytes())))
}
fn receipt(
    r: &Review,
    review_pin: &str,
    signed: bool,
    admission_pin: Option<String>,
    sign_pin: Option<String>,
) -> Value {
    json!({"schema":SCHEMA,"pending":true,"signed":signed,"request_sha256":r.request_sha256,"review_sha256":review_pin,"purpose_approval_sha256":r.purpose_approval_sha256,
        "formation_sha256":null,"network_id":r.payload.network_id,"chain_id":r.payload.chain_id.to_string(),"genesis_sha256":r.payload.genesis_artifact_sha256,
        "authority_sha256":r.payload.authority_binding_sha256,"registry_sha256":r.payload.validator_registry_sha256,
        "gateway_address":r.payload.gateways[0].node_address,"gateway_enrollment_sha256":r.payload.gateways[0].enrollment_sha256,
        "valid_from_unix":r.payload.valid_from_unix,"expires_at_unix":r.payload.expires_at_unix,"admission_sha256":admission_pin,"sign_request_sha256":sign_pin,
        "gateway_commissioned":false,"services_started":false,"public_listener":false,"production_qualified":false,"automatic_retry":false})
}
pub(crate) fn prepare(
    i: &Inputs<'_>,
    request: &Path,
    request_pin: &str,
    directory: &Path,
    engine: crate::provider::Engine,
) -> Result<Value, String> {
    let Inputs {
        context,
        pin,
        formation,
        transport,
        approval,
        approval_pin,
    } = *i;
    let o = owner(context, pin, formation, transport, &engine, false)?;
    let (q, raw) = exact::<PrepareGateway>(request, request_pin, "gateway_admission_prepare")?;
    let a = read(approval, 16384, true)?;
    if approval_pin != q.parameters.purpose_approval_sha256 || digest(a.as_bytes()) != approval_pin
    {
        return Err("Independent gateway purpose pin required".into());
    }
    let approved: Approval = decode(&a)?;
    if approved.registry_sha256
        != digest(
            read(
                &transport.join("signed/transport-registry.json"),
                LIMIT,
                true,
            )?
            .as_bytes(),
        )
    {
        return Err("Gateway approved registry changed".into());
    }
    let payload = validate_payload(
        &o,
        &q.parameters,
        &approved,
        a.as_bytes(),
        &engine,
        clock()?,
    )?;
    let review = Review {
        version: 1,
        request_sha256: request_pin.into(),
        purpose_approval_sha256: approval_pin.into(),
        payload,
    };
    begin(directory)?;
    write(&directory.join("request.json"), raw.as_bytes())?;
    write(&directory.join("review.json"), &encode(&review)?)?;
    sync(directory)?;
    status(i, directory, engine, false)
}
pub(crate) fn sign(
    i: &Inputs<'_>,
    directory: &Path,
    request: &Path,
    request_pin: &str,
    engine: crate::provider::Engine,
) -> Result<Value, String> {
    let approval_pin = i.approval_pin;
    let (o, r, review_pin) = reviewed(i, directory, &engine)?;
    if r.payload.valid_from_unix > clock()? || r.payload.expires_at_unix <= clock()? {
        return Err("Current exact gateway purpose approval required for signing".into());
    }
    let (q, raw) = exact::<SignGateway>(request, request_pin, "gateway_admission_sign")?;
    if q.parameters.review_sha256 != review_pin
        || q.parameters.purpose_approval_sha256 != approval_pin
    {
        return Err("Exact gateway sign review required".into());
    }
    if directory.join("signed").exists() || directory.join("signed-pending").exists() {
        return Err("Gateway signing dispatched; read original status without re-signing".into());
    }
    let pending = directory.join("signed-pending");
    begin(&pending)?;
    write(&pending.join("sign-request.json"), raw.as_bytes())?;
    let guard = engine.lock().map_err(|_| "APQE provider unavailable")?;
    let signature = guard
        .sign(
            Algorithm::MlDsa87,
            o.secret.as_bytes(),
            &gateway_wire::signing_bytes(&r.payload)?,
            SignOptions::Pure {
                context: gateway_wire::SIGN_CONTEXT,
            },
        )
        .map_err(|_| "Gateway signing failed")?;
    let signed = SignedAdmission {
        payload: r.payload,
        signature,
    };
    verify_signature(&signed, &o.public, &guard)?;
    drop(guard);
    write(
        &pending.join("rpc-gateway-admission.json"),
        &encode(&signed)?,
    )?;
    sync(&pending)?;
    fs::rename(&pending, directory.join("signed"))
        .map_err(|_| "Cannot publish gateway admission")?;
    sync(directory)?;
    status(i, directory, engine, false)
}
fn verify_signature(
    s: &SignedAdmission,
    root: &[u8],
    engine: &synergy_address_engine::apqe::crypto_engine::CryptoEngine,
) -> Result<(), String> {
    if !engine
        .verify(
            Algorithm::MlDsa87,
            root,
            &gateway_wire::signing_bytes(&s.payload)?,
            &s.signature,
            SignOptions::Pure {
                context: gateway_wire::SIGN_CONTEXT,
            },
        )
        .map_err(|_| "Gateway signature verification failed")?
    {
        return Err("Invalid gateway admission signature".into());
    }
    Ok(())
}
pub(crate) fn status(
    i: &Inputs<'_>,
    directory: &Path,
    engine: crate::provider::Engine,
    export: bool,
) -> Result<Value, String> {
    let Inputs {
        pin, approval_pin, ..
    } = *i;
    let (o, r, review_pin) = reviewed(i, directory, &engine)?;
    if directory.join("signed-pending").exists() {
        return Err(
            "Interrupted gateway signature remains uncertain; preserve original request".into(),
        );
    }
    let mut result = receipt(&r, &review_pin, false, None, None);
    result["formation_sha256"] = json!(pin);
    if directory.join("signed").exists() {
        private_dir(&directory.join("signed"))?;
        let raw = read(
            &directory.join("signed/rpc-gateway-admission.json"),
            128 * 1024,
            true,
        )?;
        let signed: SignedAdmission = decode(&raw)?;
        if serde_json::to_value(&signed.payload).map_err(|_| "Invalid gateway admission")?
            != serde_json::to_value(&r.payload).map_err(|_| "Invalid gateway review")?
        {
            return Err("Gateway signed payload changed".into());
        }
        verify_signature(
            &signed,
            &o.public,
            &*engine.lock().map_err(|_| "APQE provider unavailable")?,
        )?;
        let sign_raw = read(&directory.join("signed/sign-request.json"), 4096, true)?;
        let q: Request<SignGateway> = decode(&sign_raw)?;
        if q.version != 1
            || q.operation != "gateway_admission_sign"
            || q.parameters.review_sha256 != review_pin
            || q.parameters.purpose_approval_sha256 != approval_pin
        {
            return Err("Gateway sign request changed".into());
        }
        result["signed"] = json!(true);
        result["admission_sha256"] = json!(digest(raw.as_bytes()));
        result["sign_request_sha256"] = json!(digest(sign_raw.as_bytes()));
        if export {
            result["admission_json"] =
                json!(String::from_utf8(raw.as_bytes().to_vec())
                    .map_err(|_| "Invalid admission UTF8")?);
        }
    } else if export {
        return Err("Gateway admission has not been explicitly signed".into());
    }
    Ok(result)
}

#[cfg(test)]
pub(crate) fn fixture_unlocks() -> (&'static str, &'static str) {
    let transport = "fixture-only gateway transport strong unlock phrase";
    let identity = "fixture-only offline gateway identity strong unlock phrase";
    assert!(transport.len() >= 32 && identity.len() >= 32 && transport != identity);
    (transport, identity)
}

#[cfg(test)]
#[test]
fn gateway_fixture_unlock_inputs_are_valid_before_engine_setup() {
    fixture_unlocks();
}

#[cfg(test)]
pub(super) fn exercise_fixture(
    context: &Path,
    pin: &str,
    formation: &Path,
    transport: &Path,
    parent: &Path,
    engine: crate::provider::Engine,
) {
    let o = owner(context, pin, formation, transport, &engine, false).unwrap();
    let target = target_fixture_begin(context, pin, formation, transport, parent, &engine);
    let enrollment = if let Some((_, _, _, enrollment)) = &target {
        enrollment.clone()
    } else {
        let generated = synergy_address_engine::apqe::gateway_transport::provision(
            &engine.lock().unwrap(),
            99999,
            o.payload.network_id.clone(),
            o.review.genesis_sha256.clone(),
            fixture_unlocks().0,
            fixture_unlocks().1,
        )
        .unwrap();
        serde_json::to_string(&generated.enrollment).unwrap()
    };
    let approved = Approval {
        format: "synergy-engineering-gateway-purpose-v1".into(),
        purpose: PURPOSE.into(),
        formation_sha256: pin.into(),
        transport_review_sha256: o.review_pin.clone(),
        issuer_root_sha256: o.review.issuer_root_sha256.clone(),
        gateway_enrollment_sha256: digest(enrollment.as_bytes()),
        genesis_sha256: o.review.genesis_sha256.clone(),
        authority_sha256: o.review.authority_sha256.clone(),
        registry_sha256: digest(
            read(
                &transport.join("signed/transport-registry.json"),
                LIMIT,
                true,
            )
            .unwrap()
            .as_bytes(),
        ),
        valid_from_unix: o.payload.valid_from_unix,
        expires_at_unix: o.payload.expires_at_unix,
    };
    let approval = parent.join("gateway-purpose.json");
    let approval_raw = encode(&approved).unwrap();
    write(&approval, &approval_raw).unwrap();
    let approval_pin = digest(&approval_raw);
    let i = Inputs {
        context,
        pin,
        formation,
        transport,
        approval: &approval,
        approval_pin: &approval_pin,
    };
    let p = PrepareGateway {
        formation_sha256: pin.into(),
        transport_review_sha256: o.review_pin.clone(),
        gateway_enrollment_json: enrollment,
        purpose_approval_sha256: approval_pin.clone(),
        purpose_approval_json: String::from_utf8(approval_raw.clone()).unwrap(),
        valid_from_unix: approved.valid_from_unix,
        expires_at_unix: approved.expires_at_unix,
    };
    // Each proposed authorization is independently bound before any output exists.
    for field in [
        "purpose",
        "formation_sha256",
        "issuer_root_sha256",
        "gateway_enrollment_sha256",
        "registry_sha256",
        "expires_at_unix",
    ] {
        let mut changed = serde_json::to_value(&approved).unwrap();
        changed[field] = if field == "expires_at_unix" {
            json!(1)
        } else {
            json!("0".repeat(64))
        };
        let raw = encode(&changed).unwrap();
        let mut proposed: PrepareGateway =
            serde_json::from_value(serde_json::to_value(&p).unwrap()).unwrap();
        proposed.purpose_approval_json = String::from_utf8(raw.clone()).unwrap();
        proposed.purpose_approval_sha256 = digest(&raw);
        let request = encode(
            &json!({"version":1,"operation":"gateway_admission_prepare","parameters":proposed}),
        )
        .unwrap();
        assert!(
            preflight(context, pin, formation, transport, &request, engine.clone()).is_err(),
            "public preflight accepted changed {field}"
        );
    }
    let mut foreign: Value = serde_json::from_slice(
        read(&transport.join("issuer.enc.json"), LIMIT, true)
            .unwrap()
            .as_bytes(),
    )
    .unwrap();
    let custody_path = transport.join("issuer.enc.json");
    let custody = fs::read(&custody_path).unwrap();
    foreign["role"] = json!("generic-signing-key");
    fs::write(&custody_path, encode(&foreign).unwrap()).unwrap();
    assert!(owner(context, pin, formation, transport, &engine, false).is_err());
    fs::write(&custody_path, custody).unwrap();
    assert!(validate_payload(
        &o,
        &p,
        &approved,
        &approval_raw,
        &engine,
        approved.expires_at_unix
    )
    .is_err());
    let mut q = json!({"version":1,"operation":"gateway_admission_prepare","parameters":p});
    let request = parent.join("gateway-request.json");
    let directory = parent.join("gateway-admission");
    q["parameters"]["purpose_approval_sha256"] = json!("0".repeat(64));
    let bad = encode(&q).unwrap();
    write(&request, &bad).unwrap();
    assert!(prepare(&i, &request, &digest(&bad), &directory, engine.clone()).is_err());
    assert!(!directory.exists());
    fs::remove_file(&request).unwrap();
    q["parameters"]["purpose_approval_sha256"] = json!(approval_pin);
    let raw = encode(&q).unwrap();
    let checked = preflight(context, pin, formation, transport, &raw, engine.clone()).unwrap();
    assert_eq!(checked["request_sha256"], digest(&raw));
    assert_eq!(checked["mutation_performed"], false);
    write(&request, &raw).unwrap();
    let reviewed = prepare(&i, &request, &digest(&raw), &directory, engine.clone()).unwrap();
    assert_eq!(reviewed["signed"], false);
    assert_eq!(reviewed["gateway_commissioned"], false);
    assert_eq!(
        status(&i, &directory, engine.clone(), false).unwrap(),
        reviewed
    );
    let sign_request = parent.join("gateway-sign-request.json");
    let sign_raw=encode(&json!({"version":1,"operation":"gateway_admission_sign","parameters":{"review_sha256":reviewed["review_sha256"],"purpose_approval_sha256":approval_pin}})).unwrap();
    write(&sign_request, &sign_raw).unwrap();
    // A dispatched signing intent is uncertainty, never permission to sign again.
    begin(&directory.join("signed-pending")).unwrap();
    assert!(status(&i, &directory, engine.clone(), false).is_err());
    assert!(sign(
        &i,
        &directory,
        &sign_request,
        &digest(&sign_raw),
        engine.clone()
    )
    .is_err());
    fs::remove_dir(directory.join("signed-pending")).unwrap();
    let signed = sign(
        &i,
        &directory,
        &sign_request,
        &digest(&sign_raw),
        engine.clone(),
    )
    .unwrap();
    assert_eq!(signed["signed"], true);
    assert!(sign(
        &i,
        &directory,
        &sign_request,
        &digest(&sign_raw),
        engine.clone()
    )
    .is_err());
    let exported = status(&i, &directory, engine.clone(), true).unwrap();
    let admission: SignedAdmission =
        serde_json::from_str(exported["admission_json"].as_str().unwrap()).unwrap();
    verify_signature(&admission, &o.public, &engine.lock().unwrap()).unwrap();
    if let Some((node, config, keys, enrollment)) = &target {
        target_fixture_finish(node, config, keys, enrollment, &exported);
    }
    // Neither signer custody nor gateway encrypted identity is included in public output.
    assert!(!exported.to_string().contains("envelope"));
    assert!(!exported.to_string().contains("secret"));
    let admission_path = directory.join("signed/rpc-gateway-admission.json");
    let original = fs::read(&admission_path).unwrap();
    let mut changed: Value = serde_json::from_slice(&original).unwrap();
    changed["payload"]["genesis_artifact_sha256"] = json!("0".repeat(64));
    fs::write(&admission_path, encode(&changed).unwrap()).unwrap();
    assert!(status(&i, &directory, engine.clone(), true).is_err());
    fs::write(&admission_path, original).unwrap();
    let mut wrong: Value = serde_json::from_slice(&approval_raw).unwrap();
    wrong["purpose"] = json!("sign-anything");
    fs::write(&approval, encode(&wrong).unwrap()).unwrap();
    assert!(status(&i, &directory, engine.clone(), false).is_err());
    fs::write(&approval, approval_raw).unwrap();
    assert_eq!(
        status(&i, &directory, engine.clone(), false).unwrap(),
        signed
    );
}

// Explicit opt-in qualification invokes the actual CLI against this already
// signed fixture; no copied host custody or second running chain is involved.
#[cfg(test)]
fn target_cli(
    node: &Path,
    operation: &str,
    args: &[&Path],
    input: Option<&Value>,
    success: bool,
) -> Vec<u8> {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let mut child = Command::new(node)
        .arg("canary-rpc-relay")
        .arg(operation)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    if let Some(value) = input {
        child
            .stdin
            .take()
            .unwrap()
            .write_all(&serde_json::to_vec(value).unwrap())
            .unwrap();
    } else {
        drop(child.stdin.take());
    }
    let output = child.wait_with_output().unwrap();
    assert_eq!(
        output.status.success(),
        success,
        "target CLI {operation} refused: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.len() <= 2 * 1024 * 1024);
    output.stdout
}
#[cfg(test)]
fn target_fixture_begin(
    context: &Path,
    pin: &str,
    formation: &Path,
    transport: &Path,
    parent: &Path,
    engine: &crate::provider::Engine,
) -> Option<(std::path::PathBuf, Value, std::path::PathBuf, String)> {
    let node =
        std::env::var_os("SYNERGY_GATEWAY_TARGET_FIXTURE_NODE").map(std::path::PathBuf::from)?;
    let exported = super::status(context, pin, formation, transport, engine.clone(), true).unwrap();
    let artifact = &exported["nodes"][0]["artifacts"];
    let root = parent.join("target-gateway");
    begin(&root).unwrap();
    let network = root.join("network");
    begin(&network).unwrap();
    for name in [
        "genesis.json",
        "authority.json",
        "authority-root.pub",
        "network-manifest.json",
        "transport-registry.json",
        "transport-root.pub",
    ] {
        let text = artifact[format!("network/{name}")].as_str().unwrap();
        let bytes = if name.ends_with(".pub") {
            {
                use base64::Engine as _;
                base64::engine::general_purpose::STANDARD
                    .decode(text)
                    .unwrap()
            }
        } else {
            text.as_bytes().to_vec()
        };
        write(&network.join(name), &bytes).unwrap();
    }
    let mut config: Value =
        serde_json::from_str(artifact["config/node.json"].as_str().unwrap()).unwrap();
    let keys = root.join("keys");
    config["node_name"] = json!("gateway-fixture");
    config["role"] = json!("rpc_gateway");
    config["public_identity_path"] = json!(keys.join("gateway-enrollment.json"));
    config["manifest_path"] = json!(network.join("network-manifest.json"));
    config["genesis_path"] = json!(network.join("genesis.json"));
    config["aegis_signing_key_path"] = Value::Null;
    config["aegis_key_bindings_path"] = Value::Null;
    config["aegis_provider"] = json!({"report_path":std::env::var("APQE_TRUSTED_NATIVE_REPORT").unwrap(),"authenticated_report_sha256":std::env::var("APQE_AUTHENTICATED_REPORT_SHA256").unwrap()});
    config["admin_socket_path"] = json!(root.join("run/admin.sock"));
    config["storage"]["data_directory"] = json!(root.join("data"));
    config["consensus"]["mode"] = json!("observe");
    config["consensus"]["signing_key_path"] = Value::Null;
    config["consensus"]["authority_binding"] = json!(network.join("authority.json"));
    config["consensus"]["authority_trust_key_path"] = json!(network.join("authority-root.pub"));
    config["etdag"]["enabled"] = json!(false);
    config["etdag"]["ingress_kem_secret_key_path"] = Value::Null;
    config["rpc"]["enabled"] = json!(false);
    config["rpc"]["listen_address"] = Value::Null;
    config["apqe_transport"]["registry_path"] = json!(network.join("transport-registry.json"));
    config["apqe_transport"]["registry_trust_key_path"] = json!(network.join("transport-root.pub"));
    for (field, name) in [
        ("enrollment_path", "gateway-enrollment.json"),
        ("custody_path", "gateway-transport.encrypted.json"),
        ("custody_unlock_path", "gateway-transport.unlock"),
    ] {
        config["apqe_transport"][field] = json!(keys.join(name));
    }
    let transport_root = fs::read(network.join("transport-root.pub")).unwrap();
    assert_eq!(
        transport_root.len(),
        2592,
        "native ML-DSA-87 root is binary, never exported base64 text"
    );
    assert_eq!(
        config["apqe_transport"]["registry_trust_key_sha256"],
        json!(digest(&transport_root))
    );
    assert_eq!(
        config["apqe_transport"]["genesis_trust_key_sha256"],
        json!(digest(
            &fs::read(network.join("authority-root.pub")).unwrap()
        ))
    );
    serde_json::from_value::<synergy_config::NodeConfiguration>(config.clone())
        .unwrap()
        .validate()
        .unwrap();
    let origin: Value = serde_json::from_slice(&target_cli(
        &node,
        "inspect-origin",
        &[],
        Some(&config),
        true,
    ))
    .unwrap();
    assert_eq!(
        origin["genesis_sha256"],
        json!(digest(
            fs::read(network.join("genesis.json")).unwrap().as_slice()
        ))
    );
    assert_eq!(origin["mutation_performed"], false);
    assert!(!keys.exists());
    let cfg = root.join("origin.json");
    write(&cfg, &serde_json::to_vec(&config).unwrap()).unwrap();
    let t = root.join("transport.unlock");
    let i = root.join("identity.unlock");
    write(&t, fixture_unlocks().0.as_bytes()).unwrap();
    write(&i, fixture_unlocks().1.as_bytes()).unwrap();
    target_cli(&node, "provision", &[&cfg, &keys, &t, &i], None, true);
    fs::rename(&t, keys.join("gateway-transport.unlock")).unwrap();
    fs::rename(&i, keys.join("gateway-identity.unlock")).unwrap();
    let enrollment = fs::read_to_string(keys.join("gateway-enrollment.json")).unwrap();
    let result: Value = serde_json::from_slice(&target_cli(
        &node,
        "inspect-target-enrollment",
        &[],
        Some(&json!({"node_configuration":config,"enrollment_json":enrollment})),
        true,
    ))
    .unwrap();
    assert_eq!(
        result["enrollment_sha256"],
        json!(digest(enrollment.as_bytes()))
    );
    assert_eq!(result["mutation_performed"], false);
    Some((node, config, keys, enrollment))
}
#[cfg(test)]
fn target_fixture_finish(
    node: &Path,
    config: &Value,
    keys: &Path,
    enrollment: &str,
    exported: &Value,
) {
    let files = fs::read_dir(keys)
        .unwrap()
        .map(|p| {
            let p = p.unwrap().path();
            let raw = fs::read(&p).unwrap();
            (p, raw)
        })
        .collect::<Vec<_>>();
    let registry: Value = serde_json::from_slice(
        &fs::read(config["apqe_transport"]["registry_path"].as_str().unwrap()).unwrap(),
    )
    .unwrap();
    let validator = registry["payload"]["validators"][0]["node_address"]
        .as_str()
        .unwrap();
    let address: GatewayEnrollment = serde_json::from_str(enrollment).unwrap();
    let relay = json!({"schema_version":1,"node_config_path":keys.parent().unwrap().join("node.json"),"admission_path":keys.parent().unwrap().join("admission.json"),"listen_address":"127.0.0.1:9944","role":{"kind":"gateway","gateway_address":address.payload.node_address,"validator_address":validator,"validator_relay_port":8551,"enrollment_path":keys.join("gateway-enrollment.json"),"custody_path":keys.join("gateway-transport.encrypted.json"),"custody_unlock_path":keys.join("gateway-transport.unlock"),"allowed_origins":[]}});
    let input = json!({"node_configuration":config,"relay_configuration":relay,"admission_json":exported["admission_json"]});
    let result: Value = serde_json::from_slice(&target_cli(
        node,
        "inspect-target-candidate",
        &[],
        Some(&input),
        true,
    ))
    .unwrap();
    assert_eq!(
        result,
        json!({"transport_custody_verified":true,"mutation_performed":false})
    );
    for defect in [
        "foreign_origin",
        "wrong_gateway",
        "tampered_admission",
        "foreign_custody",
    ] {
        let mut bad = input.clone();
        match defect {
            "foreign_origin" => {
                bad["node_configuration"]["network_id"] = json!("synergy-posy-canary-foreign")
            }
            "wrong_gateway" => {
                bad["relay_configuration"]["role"]["gateway_address"] = json!(validator)
            }
            "tampered_admission" => {
                let mut admission: Value =
                    serde_json::from_str(exported["admission_json"].as_str().unwrap()).unwrap();
                admission["payload"]["genesis_artifact_sha256"] = json!("0".repeat(64));
                bad["admission_json"] = json!(admission.to_string());
            }
            _ => {
                bad["relay_configuration"]["role"]["custody_path"] =
                    json!(keys.join("gateway-identity.encrypted.json"))
            }
        }
        target_cli(node, "inspect-target-candidate", &[], Some(&bad), false);
    }
    for (path, raw) in files {
        assert_eq!(fs::read(path).unwrap(), raw);
    }
    assert!(!keys.parent().unwrap().join("data").exists());
}
