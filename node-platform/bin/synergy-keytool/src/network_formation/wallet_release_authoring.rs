//! Domain-scoped Wallet release authoring in the original formation owner.
//! The separate issuer never leaves encrypted host custody. Public release
//! bytes still need the existing origin delegation and certified epoch close.
use super::*;
use std::{
    fs::{File, OpenOptions},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
};
use synergy_address_engine::apqe::{
    enrollment::{UnactivatedWireAssignments, UnactivatedWireProfile},
    enrollment_commit::UnactivatedCommitmentProfile,
    enrollment_registry::{EnrollmentRegistryRelease, EnrollmentRegistryReleaseIssuer},
    provider::{
        NativeVerificationQualification, SignOptions, SignedNativeVerificationQualification,
        Target, VerifiedNativeVerificationQualification, BACKEND_ABI, IMPORT_MANIFEST_SHA256,
        MODULE_REVISION, SELECTED_MANIFEST_SHA256,
    },
};
use synergy_etdag::EtdagParameters;
use synergy_genesis::authority::{
    ProtectedWalletDispatchPolicy, SignedWalletDispatchRelease, VerifiedWalletDispatchRelease,
    WalletDispatchReleasePayload, WalletDispatchReleaseTrust,
};
use synergy_posy::SimplifiedEpochContext;

const DIRECTORY: &str = "wallet-release-authoring";
const PREPARING: &str = ".wallet-release-authoring-preparing";
const OPERATION: &str = "wallet_release_authoring_prepare";

/// The canonical consumer contract, read from the same source bytes used by
/// the runtime. This is public preparation data and grants no admission.
pub(crate) fn contract(engine: &crate::provider::Engine, report: &str) -> Result<Value, String> {
    digest_bytes(report)?;
    let wire = UnactivatedWireProfile::new(UnactivatedWireAssignments {
        ordinary_roles_key: 0,
        recovery_pairs_key: 1,
        recovery_only_key: 2,
        initial_status: 0,
        initial_epoch: 0,
        mldsa87_algorithm_id: 1,
        dkg_commitment_bytes: 32,
        recovery_ack_domain: b"AEGIS/RECOVERY-ENROLL/v1",
        recovery_ack_context: b"AEGIS.RECOVERY.ENROLL.V1",
    })
    .map_err(|e| e.to_string())?;
    let hex = |v: [u8; 32]| v.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let guard = engine.lock().map_err(|_| "native APQE unavailable")?;
    let proof = guard
        .provider_provenance(Algorithm::MlDsa87)
        .map_err(|e| e.to_string())?;
    let issuer = guard
        .provider_provenance(Algorithm::MlDsa65)
        .map_err(|e| e.to_string())?;
    Ok(
        json!({"schema":"nodenetwork-wallet-release-contract-v1","candidate_only":true,
        "action_registry_sha256":digest(include_bytes!("../../../synergy-node/src/services/protected_quick_setup_registry.json")),
        "wire_schema_sha256":digest(include_bytes!("../../../synergy-node/src/services/protected_quick_setup_wire.cddl")),
        "action_vectors_sha256":digest(include_bytes!("../../../synergy-node/src/services/protected_quick_setup_vectors.json")),
        "enrollment_wire_profile_fingerprint":hex(wire.dual_enrollment_profile_fingerprint().map_err(|e|e.to_string())?),
        "enrollment_commitment_profile_fingerprint":hex(EnrollmentRegistryRelease::commitment_fingerprint(UnactivatedCommitmentProfile::candidate_concat_v1())),
        "target":target()?,"apqe_report_sha256":report,"native_identity":proof.native_identity,
        "proof_artifact_sha256":hex(proof.artifact_sha256),"release_verifier_artifact_sha256":hex(issuer.artifact_sha256)}),
    )
}

fn lock(root: &Path) -> Result<File, String> {
    private_dir(root)?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(root.join("wallet-release-authoring.lock"))
        .map_err(|_| "cannot open native Wallet authoring lock")?;
    let m = file.metadata().map_err(|e| e.to_string())?;
    if !m.is_file()
        || m.nlink() != 1
        || m.uid() != unsafe { libc::geteuid() }
        || m.mode() & 0o777 != 0o600
        || m.len() != 0
        || unsafe {
            libc::flock(
                std::os::fd::AsRawFd::as_raw_fd(&file),
                libc::LOCK_EX | libc::LOCK_NB,
            )
        } != 0
    {
        return Err("native Wallet authoring is busy or its lock is unsafe".into());
    }
    Ok(file)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactIndex {
    version: u32,
    chain_id: u64,
    network_id: String,
    genesis_hash: String,
    platforms: Vec<PlatformArtifact>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PlatformArtifact {
    target: String,
    base_package_manifest_sha256: String,
    executable_size: u64,
    executable_sha256: String,
    apqe_report_sha256: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Parameters {
    pub(super) policy: ProtectedWalletDispatchPolicy,
    pub(super) predecessor: SimplifiedEpochContext,
    pub(super) parameters: EtdagParameters,
    pub(super) managed_artifacts_json: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Review {
    version: u32,
    request_sha256: String,
    formation_review_sha256: String,
    issuer_public_key: Vec<u8>,
    payload: WalletDispatchReleasePayload,
    predecessor: SimplifiedEpochContext,
    parameters: EtdagParameters,
    managed_artifacts_json: String,
    qualification: NativeVerificationQualification,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SealedIssuer {
    version: u32,
    review_sha256: String,
    public_key: Vec<u8>,
    envelope: EncryptedEnvelope,
}

pub(crate) struct Inputs<'a> {
    pub(crate) context: &'a Path,
    pub(crate) formation_sha256: &'a str,
    pub(crate) formation: &'a Path,
    pub(crate) request: &'a Path,
    pub(crate) request_sha256: &'a str,
    pub(crate) provider_report_sha256: &'a str,
}

fn target() -> Result<&'static str, String> {
    match Target::current() {
        Target::DarwinArm64 => Ok("aarch64-apple-darwin"),
        Target::LinuxX86_64Gnu => Ok("x86_64-unknown-linux-gnu"),
        Target::LinuxArm64Gnu => Ok("aarch64-unknown-linux-gnu"),
        _ => Err("Wallet release has no qualified verifier for this native target".into()),
    }
}

fn digest_bytes(value: &str) -> Result<[u8; 32], String> {
    let bytes = synergy_posy::parse_hash_bytes(value).map_err(|e| e.to_string())?;
    if bytes == [0; 32] {
        return Err("Wallet release requires nonzero independently reviewed pins".into());
    }
    Ok(bytes)
}

fn validate_parameters(
    p: &Parameters,
    prepared: &Prepared,
    signed: &SignedFormation,
    report: &str,
    engine: &crate::provider::Engine,
) -> Result<NativeVerificationQualification, String> {
    synergy_genesis::verify_binding_with_verifier(
        &signed.genesis,
        &prepared.public,
        &signed.authority,
        &crate::provider::verifier(policy(), Some(prepared.signer.clone()))?,
    )?;
    let policy = &p.policy;
    let compiled = contract(engine, report)?;
    if compiled["action_registry_sha256"] != policy.action_registry_sha256
        || compiled["wire_schema_sha256"] != policy.wire_schema_sha256
        || compiled["action_vectors_sha256"] != policy.action_vectors_sha256
        || compiled["enrollment_wire_profile_fingerprint"]
            != policy.enrollment_wire_profile_fingerprint
        || compiled["enrollment_commitment_profile_fingerprint"]
            != policy.enrollment_commitment_profile_fingerprint
    {
        return Err("Wallet release must select the exact compiled Quick Setup contract".into());
    }
    p.parameters
        .validate()
        .map_err(|e| format!("protected parameters: {e:?}"))?;
    // A new release activates in the successor, not the predecessor.
    WalletDispatchReleasePayload {
        version: 1,
        predecessor_context_root: p.predecessor.root().map_err(|e| e.to_string())?,
        signer_key_id: "wallet-release-authoring-scope".into(),
        policy: policy.clone(),
    }
    .check_predecessor(&p.predecessor, &p.parameters)?;
    if policy.genesis_hash != signed.genesis.genesis_hash
        || policy.chain_id != signed.genesis.unsigned.network.chain_id
        || policy.network_id != signed.genesis.unsigned.network.network_id
        || p.predecessor.chain_id != policy.chain_id
        || p.predecessor.network_id != policy.network_id
        || p.predecessor.epoch < signed.authority.payload.epoch
        || !synergy_genesis::validate_autonomous_origin(
            &signed.genesis.unsigned,
            &signed.authority.payload,
        )?
        || policy.managed_release_manifest_sha256 != digest(p.managed_artifacts_json.as_bytes())
        || p.managed_artifacts_json.len() > 8192
    {
        return Err("Wallet authoring differs from the original signed formation or reviewed artifact index".into());
    }
    // Reuse the existing E1 check; later predecessors will independently need
    // their genuine certified close before any release can become authority.
    if p.predecessor.epoch == signed.authority.payload.epoch {
        let a = &signed.authority.payload;
        let registry = synergy_posy::FrozenValidatorRegistry::new(
            a.epoch,
            a.validators.iter().map(|v| v.record.clone()).collect(),
        )
        .map_err(|e| e.to_string())?;
        let first = SimplifiedEpochContext::from_frozen_registry(
            a.chain_id,
            a.network_id.clone(),
            a.epoch,
            a.epoch_start_height,
            a.epoch_end_height,
            a.finalized_epoch_seed_root.clone(),
            a.consensus_parameter_root.clone(),
            &registry,
        )
        .map_err(|e| e.to_string())?;
        if p.predecessor != first
            || a.protected.as_ref().map(|v| &v.parameters) != Some(&p.parameters)
        {
            return Err("Wallet E1 predecessor differs from the signed formation".into());
        }
    }
    if synergy_address::address_kind(&policy.fee_collector)
        != synergy_address::AddressKind::FeeCollector
    {
        return Err("Wallet release requires a genuine native fee collector".into());
    }
    let index: ArtifactIndex = serde_json::from_str(&p.managed_artifacts_json)
        .map_err(|_| "invalid Wallet artifact index")?;
    let platforms = &index.platforms;
    if index.version != 1
        || index.chain_id != policy.chain_id
        || index.network_id != policy.network_id
        || index.genesis_hash != policy.genesis_hash
        || platforms.is_empty()
        || platforms.len() > 3
        || serde_json::to_string(&index).map_err(|e| e.to_string())? != p.managed_artifacts_json
        || !platforms.windows(2).all(|p| p[0].target < p[1].target)
        || platforms.iter().any(|e| {
            !matches!(
                e.target.as_str(),
                "aarch64-apple-darwin" | "aarch64-unknown-linux-gnu" | "x86_64-unknown-linux-gnu"
            ) || digest_bytes(&e.apqe_report_sha256).is_err()
                || digest_bytes(&e.executable_sha256).is_err()
                || digest_bytes(&e.base_package_manifest_sha256).is_err()
                || e.executable_size == 0
                || e.executable_size > 512 * 1024 * 1024
        })
        || platforms
            .iter()
            .filter(|v| v.target == target().unwrap_or(""))
            .count()
            != 1
    {
        return Err("Wallet artifact index has a different native chain or target".into());
    }
    let entry = platforms
        .iter()
        .find(|v| v.target == target().unwrap_or(""))
        .unwrap();
    if entry.apqe_report_sha256 != report {
        return Err(
            "Wallet artifact index is not pinned to this authenticated native provider".into(),
        );
    }
    let engine = engine.lock().map_err(|_| "native APQE unavailable")?;
    let proof = engine
        .provider_provenance(Algorithm::MlDsa87)
        .map_err(|e| e.to_string())?;
    let hex: String = proof
        .artifact_sha256
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    if !policy.enrollment_proof_provider_artifacts.contains(&hex) {
        return Err("Wallet policy does not admit this exact ML-DSA-87 artifact".into());
    }
    Ok(NativeVerificationQualification {
        version: 1,
        target: target()?.into(),
        artifact_sha256: proof.artifact_sha256,
        report_sha256: digest_bytes(report)?,
        release_attestation_sha256: digest_bytes(&policy.release_attestation_sha256)?,
        release_context: [0; 32],
        backend_abi: BACKEND_ABI,
        backend_revision: MODULE_REVISION.into(),
        selected_manifest_sha256: SELECTED_MANIFEST_SHA256.into(),
        import_manifest_sha256: IMPORT_MANIFEST_SHA256.into(),
        native_identity: proof.native_identity.clone(),
    })
}

fn load_review(input: &Inputs<'_>, prepared: &Prepared) -> Result<(Review, Vec<u8>), String> {
    let slot = input.formation.join(DIRECTORY);
    private_dir(&slot)?;
    let raw = read(&slot.join("review.json"), REQUEST_LIMIT, true)?;
    let review: Review = decode(&raw)?;
    if review.version != 1
        || review.request_sha256 != input.request_sha256
        || review.formation_review_sha256 != prepared.review_pin
    {
        return Err("Wallet issuer belongs to a different exact reviewed request".into());
    }
    Ok((review, raw.as_bytes().to_vec()))
}

fn native_predecessor(
    input: &Inputs<'_>,
    p: &Parameters,
    prepared: &Prepared,
    signed: &SignedFormation,
) -> Result<bool, String> {
    // E1 is fully independently checked against signed Genesis above. A later
    // predecessor must come from the original managed owner's actual native
    // three-QC history, rather than a caller's exported context JSON.
    if p.predecessor.epoch == signed.authority.payload.epoch {
        return Ok(true);
    }
    let value = crate::formation_treasury::bundled_authority_descriptor(
        input.formation,
        "check-wallet-release-predecessor",
        input.request,
    )?;
    let fields = [
        "schema",
        "request_sha256",
        "genesis_sha256",
        "authority_root_sha256",
        "genesis_hash",
        "predecessor_context_root",
        "predecessor_epoch",
        "policy_sha256",
        "finalized_height",
        "predecessor_close_height",
        "initial_adoption_before_close",
        "mutation_performed",
    ];
    if !value
        .as_object()
        .is_some_and(|m| m.len() == fields.len() && fields.iter().all(|k| m.contains_key(*k)))
        || value["schema"] != "nodenetwork-verified-wallet-release-predecessor-v1"
        || value["request_sha256"] != input.request_sha256
        || value["genesis_sha256"] != digest(signed.genesis_bytes.as_bytes())
        || value["authority_root_sha256"] != digest(&prepared.public)
        || value["genesis_hash"] != signed.genesis.genesis_hash
        || value["predecessor_context_root"] != p.predecessor.root().map_err(|e| e.to_string())?
        || value["predecessor_epoch"] != p.predecessor.epoch
        || value["policy_sha256"]
            != digest(&serde_json::to_vec(&p.policy).map_err(|e| e.to_string())?)
        || value["predecessor_close_height"]
            != p.predecessor
                .epoch_end_height
                .checked_sub(2)
                .ok_or("predecessor close underflow")?
        || !value["finalized_height"].is_u64()
        || value["mutation_performed"] != false
    {
        return Err(
            "native Wallet predecessor descriptor differs from exact reviewed formation".into(),
        );
    }
    value["initial_adoption_before_close"]
        .as_bool()
        .ok_or_else(|| "native Wallet adoption window missing".into())
}

fn reply(review: &Review, raw: &[u8], state: &str) -> Result<Value, String> {
    Ok(
        json!({"schema":"nodenetwork-wallet-release-authoring-v1","state":state,
        "request_sha256":review.request_sha256,"review_sha256":digest(raw),
        "issuer_public_key":review.issuer_public_key,"issuer_sha256":digest(&review.issuer_public_key),
        "payload":review.payload,"predecessor":review.predecessor,"parameters":review.parameters,
        "qualification":review.qualification,"managed_artifacts_json":review.managed_artifacts_json,
        "origin_delegation_verified":false,"certified_activation_verified":false}),
    )
}

fn verify_cached(
    value: Value,
    review: &Review,
    raw: &[u8],
    report: &str,
    engine: &crate::provider::Engine,
) -> Result<Value, String> {
    let release = value["attachment_json"]
        .as_str()
        .ok_or("retained Wallet attachment absent")?
        .as_bytes();
    let qualification = value["qualification_json"]
        .as_str()
        .ok_or("retained Wallet qualification absent")?
        .as_bytes();
    if release.len() > 32 * 1024 || qualification.len() > 24 * 1024 {
        return Err("retained Wallet release exceeds its bound".into());
    }
    let mut expected = reply(review, raw, "signed")?;
    expected["attachment_sha256"] = json!(digest(release));
    expected["qualification_sha256"] = json!(digest(qualification));
    expected["attachment_json"] = json!(std::str::from_utf8(release).map_err(|e| e.to_string())?);
    expected["qualification_json"] =
        json!(std::str::from_utf8(qualification).map_err(|e| e.to_string())?);
    if expected != value {
        return Err("retained Wallet authoring reply differs from exact native review".into());
    }
    let guard = engine.lock().map_err(|_| "native APQE unavailable")?;
    let verifier = guard
        .provider_provenance(Algorithm::MlDsa65)
        .map_err(|e| e.to_string())?
        .artifact_sha256;
    let key = KeyId::new(&review.payload.signer_key_id).map_err(|e| e.to_string())?;
    let p = &review.payload.policy;
    let trust = WalletDispatchReleaseTrust {
        genesis_hash: &p.genesis_hash,
        release_signer_key_id: &key,
        release_signer_public_key: &review.issuer_public_key,
        release_verifier_artifact_sha256: verifier,
        managed_release_manifest_sha256: &p.managed_release_manifest_sha256,
        off_chain_approval_sha256: &p.off_chain_approval_sha256,
        release_attestation_sha256: &p.release_attestation_sha256,
    };
    let verified = VerifiedWalletDispatchRelease::verify(
        release,
        &trust,
        &review.predecessor,
        &review.parameters,
        &guard,
    )?;
    if verified.policy() != p {
        return Err("retained Wallet release changes native policy".into());
    }
    VerifiedNativeVerificationQualification::verify(
        qualification,
        verified.enrollment(),
        &EnrollmentRegistryReleaseIssuer {
            public_key: &review.issuer_public_key,
            verifier_artifact_sha256: verifier,
        },
        &guard,
        digest_bytes(report)?,
        digest_bytes(&p.release_attestation_sha256)?,
    )
    .map_err(|e| e.to_string())?;
    Ok(value)
}

/// Reconcile a lost application reply without creating a directory, lock,
/// key, approval or signature. The exact original public request is required.
pub(crate) fn status(input: Inputs<'_>, engine: crate::provider::Engine) -> Result<Value, String> {
    private_dir(input.formation)?;
    let prepared = load(
        input.context,
        input.formation_sha256,
        input.formation,
        engine.clone(),
    )?;
    let signed = prepared
        .read_signed_formation(input.formation)?
        .ok_or("signed original formation required")?;
    let (request, _) = exact_request::<Parameters>(input.request, input.request_sha256, OPERATION)?;
    validate_parameters(
        &request.parameters,
        &prepared,
        &signed,
        input.provider_report_sha256,
        &engine,
    )?;
    native_predecessor(&input, &request.parameters, &prepared, &signed)?;
    let slot = input.formation.join(DIRECTORY);
    if !slot.exists() {
        return Ok(
            json!({"schema":"nodenetwork-wallet-release-authoring-v1","state":"absent",
        "request_sha256":input.request_sha256,"custody_created":false}),
        );
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(input.formation.join("wallet-release-authoring.lock"))
        .map_err(|_| "Wallet authoring lock absent")?;
    let m = file.metadata().map_err(|e| e.to_string())?;
    if !m.is_file()
        || m.uid() != unsafe { libc::geteuid() }
        || m.mode() & 0o777 != 0o600
        || m.nlink() != 1
        || m.len() != 0
        || unsafe {
            libc::flock(
                std::os::fd::AsRawFd::as_raw_fd(&file),
                libc::LOCK_SH | libc::LOCK_NB,
            )
        } != 0
    {
        return Err("native Wallet authoring is busy or its retained lock is unsafe".into());
    }
    let (review, raw) = load_review(&input, &prepared)?;
    if slot.join("signed.json").exists() {
        let value = decode(&read(&slot.join("signed.json"), 128 * 1024, true)?)?;
        verify_cached(value, &review, &raw, input.provider_report_sha256, &engine)
    } else {
        reply(&review, &raw, "prepared")
    }
}

pub(crate) fn prepare(input: Inputs<'_>, engine: crate::provider::Engine) -> Result<Value, String> {
    let _lock = lock(input.formation)?;
    let prepared = load(
        input.context,
        input.formation_sha256,
        input.formation,
        engine.clone(),
    )?;
    let signed = prepared
        .read_signed_formation(input.formation)?
        .ok_or("signed original formation required")?;
    let (request, _) = exact_request::<Parameters>(input.request, input.request_sha256, OPERATION)?;
    let mut qualification = validate_parameters(
        &request.parameters,
        &prepared,
        &signed,
        input.provider_report_sha256,
        &engine,
    )?;
    let slot = input.formation.join(DIRECTORY);
    if slot.exists() {
        let (review, raw) = load_review(&input, &prepared)?;
        return reply(&review, &raw, "prepared");
    }
    if !native_predecessor(&input, &request.parameters, &prepared, &signed)? {
        return Err("Wallet predecessor's genuine certified close has already been reached".into());
    }
    let staging = input.formation.join(PREPARING);
    // No published issuer exists in this staging directory. Recover an
    // interrupted generation by removing only its closed, never-signed files.
    if staging.exists() {
        private_dir(&staging)?;
        let names = fs::read_dir(&staging)
            .map_err(|e| e.to_string())?
            .map(|e| e.map(|v| v.file_name()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?;
        if names
            .iter()
            .any(|n| n != "issuer.enc.json" && n != "review.json")
        {
            return Err("unexpected Wallet issuer preparation contents".into());
        }
        for name in names {
            fs::remove_file(staging.join(name)).map_err(|e| e.to_string())?;
        }
        fs::remove_dir(&staging).map_err(|e| e.to_string())?;
    }
    begin(&staging)?;
    let result = (|| {
        let guard = engine.lock().map_err(|_| "native APQE unavailable")?;
        let pair = guard
            .generate_keypair(Algorithm::MlDsa65)
            .map_err(|e| e.to_string())?;
        let unlock = read(&input.formation.join("unlock"), 64, true)?;
        let envelope = encrypt_with_passphrase(
            &guard,
            &Primitives,
            pair.private_key.as_bytes(),
            passphrase(&unlock)?,
        )?;
        drop(guard);
        let payload = WalletDispatchReleasePayload {
            version: 1,
            predecessor_context_root: request
                .parameters
                .predecessor
                .root()
                .map_err(|e| e.to_string())?,
            signer_key_id: format!("wallet-release-{}", &input.request_sha256[..24]),
            policy: request.parameters.policy,
        };
        payload.check_predecessor(
            &request.parameters.predecessor,
            &request.parameters.parameters,
        )?;
        qualification.release_context = payload.release_context()?;
        qualification.signing_bytes().map_err(|e| e.to_string())?;
        let review = Review {
            version: 1,
            request_sha256: input.request_sha256.into(),
            formation_review_sha256: prepared.review_pin.clone(),
            issuer_public_key: pair.public_key.clone(),
            payload,
            predecessor: request.parameters.predecessor,
            parameters: request.parameters.parameters,
            managed_artifacts_json: request.parameters.managed_artifacts_json,
            qualification,
        };
        let raw = serde_json::to_vec(&review).map_err(|e| e.to_string())?;
        let custody = SealedIssuer {
            version: 1,
            review_sha256: digest(&raw),
            public_key: pair.public_key,
            envelope,
        };
        write(
            &staging.join("issuer.enc.json"),
            &serde_json::to_vec(&custody).map_err(|e| e.to_string())?,
        )?;
        write(&staging.join("review.json"), &raw)?;
        sync(&staging)?;
        fs::rename(&staging, &slot).map_err(|e| e.to_string())?;
        sync(input.formation)?;
        reply(&review, &raw, "prepared")
    })();
    if result.is_err() && staging.exists() {
        for name in ["issuer.enc.json", "review.json"] {
            let _ = fs::remove_file(staging.join(name));
        }
        let _ = fs::remove_dir(staging);
    }
    result
}

pub(crate) fn sign(
    input: Inputs<'_>,
    review_sha256: &str,
    engine: crate::provider::Engine,
) -> Result<Value, String> {
    let _lock = lock(input.formation)?;
    let prepared = load(
        input.context,
        input.formation_sha256,
        input.formation,
        engine.clone(),
    )?;
    let signed = prepared
        .read_signed_formation(input.formation)?
        .ok_or("signed original formation required")?;
    let (request, _) = exact_request::<Parameters>(input.request, input.request_sha256, OPERATION)?;
    let (review, raw) = load_review(&input, &prepared)?;
    if digest(&raw) != review_sha256 {
        return Err("exact native Wallet authoring review changed".into());
    }
    let mut qualification = validate_parameters(
        &request.parameters,
        &prepared,
        &signed,
        input.provider_report_sha256,
        &engine,
    )?;
    qualification.release_context = review.payload.release_context()?;
    if review.payload.policy != request.parameters.policy
        || review.predecessor != request.parameters.predecessor
        || review.parameters != request.parameters.parameters
        || review.managed_artifacts_json != request.parameters.managed_artifacts_json
        || review.qualification != qualification
    {
        return Err("sealed Wallet authoring review differs from native inputs".into());
    }
    let slot = input.formation.join(DIRECTORY);
    let output = slot.join("signed.json");
    if output.exists() {
        let cached = read(&output, 128 * 1024, true)?;
        let value: Value = decode(&cached)?;
        return verify_cached(value, &review, &raw, input.provider_report_sha256, &engine);
    }
    if !native_predecessor(&input, &request.parameters, &prepared, &signed)? {
        return Err("Wallet release signing window is no longer open".into());
    }
    let custody: SealedIssuer = decode(&read(&slot.join("issuer.enc.json"), 128 * 1024, true)?)?;
    if custody.version != 1
        || custody.review_sha256 != review_sha256
        || custody.public_key != review.issuer_public_key
    {
        return Err("Wallet issuer custody scope differs".into());
    }
    let unlock = read(&input.formation.join("unlock"), 64, true)?;
    let guard = engine.lock().map_err(|_| "native APQE unavailable")?;
    let secret = SecretBytes::from_bytes(decrypt_with_passphrase(
        &guard,
        &Primitives,
        &custody.envelope,
        passphrase(&unlock)?,
    )?);
    let signature = guard
        .sign(
            Algorithm::MlDsa65,
            secret.as_bytes(),
            &review.payload.signing_bytes()?,
            SignOptions::default(),
        )
        .map_err(|e| e.to_string())?;
    let qualification_signature = guard
        .sign(
            Algorithm::MlDsa65,
            secret.as_bytes(),
            &qualification.signing_bytes().map_err(|e| e.to_string())?,
            SignOptions::default(),
        )
        .map_err(|e| e.to_string())?;
    let release = serde_json::to_vec(&SignedWalletDispatchRelease {
        payload: review.payload.clone(),
        signature_algorithm: SignatureAlgorithm::MlDsa65,
        signature,
    })
    .map_err(|e| e.to_string())?;
    let qualification = serde_json::to_vec(&SignedNativeVerificationQualification {
        qualification,
        signature: qualification_signature,
    })
    .map_err(|e| e.to_string())?;
    drop(guard);
    let mut value = reply(&review, &raw, "signed")?;
    value["attachment_sha256"] = json!(digest(&release));
    value["qualification_sha256"] = json!(digest(&qualification));
    value["attachment_json"] = json!(std::str::from_utf8(&release).map_err(|e| e.to_string())?);
    value["qualification_json"] =
        json!(std::str::from_utf8(&qualification).map_err(|e| e.to_string())?);
    let value = verify_cached(value, &review, &raw, input.provider_report_sha256, &engine)?;
    let staged = slot.join("signed-preparing.json");
    if staged.exists() {
        let m = fs::symlink_metadata(&staged).map_err(|e| e.to_string())?;
        if !m.is_file()
            || m.uid() != unsafe { libc::geteuid() }
            || m.mode() & 0o777 != 0o600
            || m.nlink() != 1
            || m.len() > 128 * 1024
        {
            return Err("unsafe unpublished Wallet signature staging file".into());
        }
        fs::remove_file(&staged).map_err(|e| e.to_string())?;
    }
    write(
        &staged,
        &serde_json::to_vec(&value).map_err(|e| e.to_string())?,
    )?;
    fs::rename(&staged, &output).map_err(|e| e.to_string())?;
    sync(&slot)?;
    Ok(value)
}

#[cfg(test)]
pub(super) fn exercise(
    context: &Path,
    formation_sha256: &str,
    formation: &Path,
    parent: &Path,
    payload: &WalletDispatchReleasePayload,
    predecessor: &SimplifiedEpochContext,
    parameters: &EtdagParameters,
    index: &[u8],
    engine: crate::provider::Engine,
) {
    let report = std::env::var("APQE_AUTHENTICATED_REPORT_SHA256").unwrap();
    let compiled = contract(&engine, &report).unwrap();
    let canonical_index =
        serde_json::to_string(&serde_json::from_slice::<ArtifactIndex>(index).unwrap()).unwrap();
    let mut policy = payload.policy.clone();
    policy.fee_collector = "synf1pnchsrnyral0u9r65xusjrexuctfh465h06l".into();
    policy.action_registry_sha256 = compiled["action_registry_sha256"].as_str().unwrap().into();
    policy.wire_schema_sha256 = compiled["wire_schema_sha256"].as_str().unwrap().into();
    policy.action_vectors_sha256 = compiled["action_vectors_sha256"].as_str().unwrap().into();
    policy.enrollment_wire_profile_fingerprint = compiled["enrollment_wire_profile_fingerprint"]
        .as_str()
        .unwrap()
        .into();
    policy.enrollment_commitment_profile_fingerprint = compiled
        ["enrollment_commitment_profile_fingerprint"]
        .as_str()
        .unwrap()
        .into();
    policy.managed_release_manifest_sha256 = digest(canonical_index.as_bytes());
    policy.enroll_commit_gas = parameters.max_protected_gas;
    policy.enroll_reveal_gas = parameters.max_protected_gas;
    policy.transfer_gas = parameters.max_protected_gas;
    let p = Parameters {
        policy,
        predecessor: predecessor.clone(),
        parameters: parameters.clone(),
        managed_artifacts_json: canonical_index,
    };
    let raw =
        serde_json::to_vec(&json!({"version":1,"operation":OPERATION,"parameters":p})).unwrap();
    let request = parent.join("native-wallet-authoring-request.json");
    write(&request, &raw).unwrap();
    let pin = digest(&raw);
    let inputs = || Inputs {
        context,
        formation_sha256,
        formation,
        request: &request,
        request_sha256: &pin,
        provider_report_sha256: &report,
    };
    assert!(!formation.join(DIRECTORY).exists());
    assert_eq!(status(inputs(), engine.clone()).unwrap()["state"], "absent");
    assert!(!formation.join("wallet-release-authoring.lock").exists());
    let mut bad = inputs();
    bad.provider_report_sha256 = "0000000000000000000000000000000000000000000000000000000000000000";
    assert!(prepare(bad, engine.clone()).is_err());
    assert!(!formation.join(DIRECTORY).exists());
    // Recover only an unpublished interrupted preparation, without replacing
    // an exported public issuer or any finalized/native signing state.
    begin(&formation.join(PREPARING)).unwrap();
    write(
        &formation.join(PREPARING).join("issuer.enc.json"),
        b"incomplete unpublished seal",
    )
    .unwrap();
    let first = prepare(inputs(), engine.clone()).unwrap();
    assert_eq!(first["state"], "prepared");
    assert_eq!(
        first["payload"]["policy"]["enroll_reveal_gas"],
        parameters.max_protected_gas
    );
    assert!(!formation.join(PREPARING).exists());
    assert_eq!(prepare(inputs(), engine.clone()).unwrap(), first);
    assert_eq!(status(inputs(), engine.clone()).unwrap(), first);
    let review = first["review_sha256"].as_str().unwrap();
    assert!(sign(inputs(), &"aa".repeat(32), engine.clone()).is_err());
    assert!(!formation.join(DIRECTORY).join("signed.json").exists());
    let signed = sign(inputs(), review, engine.clone()).unwrap();
    assert_eq!(signed["state"], "signed");
    assert_eq!(signed["origin_delegation_verified"], false);
    assert_eq!(signed["certified_activation_verified"], false);
    assert_eq!(
        signed["attachment_sha256"],
        digest(signed["attachment_json"].as_str().unwrap().as_bytes())
    );
    assert_eq!(sign(inputs(), review, engine.clone()).unwrap(), signed);
    assert_eq!(status(inputs(), engine.clone()).unwrap(), signed);
    let cached_path = formation.join(DIRECTORY).join("signed.json");
    let original = fs::read(&cached_path).unwrap();
    let mut corrupt: Value = serde_json::from_slice(&original).unwrap();
    corrupt["attachment_sha256"] = json!("ff".repeat(32));
    fs::write(&cached_path, serde_json::to_vec(&corrupt).unwrap()).unwrap();
    assert!(status(inputs(), engine.clone()).is_err());
    fs::write(&cached_path, &original).unwrap();
    let public = serde_json::to_vec(&signed).unwrap();
    assert!(!String::from_utf8_lossy(&public).contains("private_key"));
    assert!(!String::from_utf8_lossy(&public).contains("envelope"));
    let mut changed: Value = serde_json::from_slice(&raw).unwrap();
    changed["parameters"]["policy"]["base_fee_per_gas_nwei"] = json!(41);
    let altered = parent.join("native-wallet-authoring-altered.json");
    let altered_raw = serde_json::to_vec(&changed).unwrap();
    write(&altered, &altered_raw).unwrap();
    assert!(prepare(
        Inputs {
            request: &altered,
            request_sha256: &digest(&altered_raw),
            ..inputs()
        },
        engine.clone()
    )
    .is_err());
    assert_eq!(sign(inputs(), review, engine).unwrap(), signed);
}
