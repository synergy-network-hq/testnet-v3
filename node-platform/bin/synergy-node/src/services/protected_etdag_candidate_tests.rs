//! Native-APQE fixture for the distinct PW13 envelope profile. It exercises
//! local encrypt and reveal without starting any validator or network.
#![cfg(test)]
use std::path::Path;
use synergy_address_engine::{apqe::SecretBytes, types::Algorithm};
use synergy_aegis::{AegisProtectedPrimitives, ApqeKem};
use synergy_etdag::{
    admission::{
        PW13_SPONSOR_CANDIDATE_LANE, PW13_SPONSOR_CANDIDATE_PROFILE_ID,
        PW13_TRANSFER_CANDIDATE_LANE, PW13_TRANSFER_CANDIDATE_PROFILE_ID,
    },
    crypto::{
        decrypt_protected_payload, decrypt_share_capsule_with_kem_diagnostic,
        encrypt_protected_payload_with_kem, governed_reveal_threshold, pad_plaintext,
        unpad_plaintext, IngressKemKeyRecord, IngressKemKeyRegistry, IngressKemPublicKey,
        ShamirShare, ML_KEM_1024_ALGORITHM,
    },
    EtdagDigest, EtdagParameters, ProcessingContext, ProcessingEnvelope, ProcessingEnvelopeAad,
    TargetAdmissionContextV3,
};
use synergy_posy::FinalizedBlockRecord;

pub(super) struct OpenedCandidateEnvelope {
    plaintext: SecretBytes,
    envelope: ProcessingEnvelope,
    context: ProcessingContext,
}

pub(super) enum CandidateEnvelopeProfile {
    Transfer,
    SponsoredEnrollment,
}
impl OpenedCandidateEnvelope {
    pub(super) fn plaintext(&self) -> &[u8] {
        self.plaintext.as_bytes()
    }
    pub(super) fn envelope(&self) -> &ProcessingEnvelope {
        &self.envelope
    }
    pub(super) fn context(&self) -> &ProcessingContext {
        &self.context
    }
}
struct Shares(Vec<(String, ShamirShare)>);
impl Drop for Shares {
    fn drop(&mut self) {
        for (_, share) in &mut self.0 {
            share.value.fill(0);
        }
    }
}
fn err(error: impl std::fmt::Debug) -> String {
    format!("isolated ETDAG crypto fixture refused: {error:?}")
}

/// Opens exactly the original supplied bytes. Report authentication and every
/// KEM operation use the native APQE owner; no embedded crypto fallback exists.
/// Passed chain/source/sender/nonce values are fixture coordinates only. This
/// constructs neither a signed authority context nor a network admission.
#[allow(clippy::too_many_arguments)]
pub(super) fn open_candidate_envelope<T>(
    content: &[u8],
    report: &Path,
    report_sha256: &str,
    chain_id: u64,
    source: &FinalizedBlockRecord,
    sender_id: &str,
    nonce: u64,
    profile: CandidateEnvelopeProfile,
    before_open: impl FnOnce(&ProcessingEnvelope, &ProcessingContext) -> Result<T, String>,
) -> Result<(OpenedCandidateEnvelope, T), String> {
    let source_height = source.height;
    if chain_id == 0 || source_height == 0 {
        return Err("invalid isolated fixture coordinate".into());
    }
    let padded = SecretBytes::from_bytes(pad_plaintext(content).map_err(err)?);
    let engine = synergy_aegis::load_authenticated_native_engine(report, report_sha256)?;
    let kem = ApqeKem::mlkem1024(engine.clone()).map_err(err)?;
    // A synthetic four-member strict-count quorum. The actual reveal threshold
    // is derived by the existing shared governed primitive, never reassigned.
    const MEMBERS: usize = 4;
    const COUNT_QUORUM: usize = 3;
    let threshold = governed_reveal_threshold(MEMBERS, COUNT_QUORUM).map_err(err)?;
    let parameters = EtdagParameters::default();
    let target_height = parameters
        .protected_target_height(source_height)
        .map_err(err)?;
    let mut fresh = [0u8; 32];
    AegisProtectedPrimitives
        .random_bytes(&mut fresh)
        .map_err(err)?;
    let fixture_root = EtdagDigest::from_domain_bytes("isolated-engineering-source", &fresh);
    let roots = fixture_root.0.clone();
    let mut recipients = Vec::with_capacity(MEMBERS);
    let mut secrets = Vec::with_capacity(MEMBERS);
    for i in 0..MEMBERS {
        let pair = engine
            .lock()
            .map_err(|_| "isolated APQE lock poisoned")?
            .generate_keypair(Algorithm::MlKem1024)
            .map_err(err)?;
        recipients.push(IngressKemKeyRecord {
            key_id: format!("fixture-key-{i}"),
            validator_id: format!("fixture-recipient-{i}"),
            public_key: IngressKemPublicKey {
                algorithm: ML_KEM_1024_ALGORITHM.into(),
                public_key: pair.public_key,
            },
            activation_height: 1,
            retirement_height: None,
        });
        secrets.push(pair.private_key);
    }
    let registry = IngressKemKeyRegistry {
        context_root: fixture_root.clone(),
        records: recipients,
    };
    registry.validate_protected_profile().map_err(err)?;
    let (profile, lane, network) = match profile {
        CandidateEnvelopeProfile::Transfer => (
            PW13_TRANSFER_CANDIDATE_PROFILE_ID,
            PW13_TRANSFER_CANDIDATE_LANE,
            "isolated-protected-content-fixture",
        ),
        CandidateEnvelopeProfile::SponsoredEnrollment => (
            PW13_SPONSOR_CANDIDATE_PROFILE_ID,
            PW13_SPONSOR_CANDIDATE_LANE,
            "test-sponsor",
        ),
    };
    let context = ProcessingContext {
        context_version: 1,
        profile_id: profile.into(),
        authority: TargetAdmissionContextV3 {
            context_version: 1,
            chain_id,
            network_id: network.into(),
            protocol_version: "v3".into(),
            epoch: 1,
            target_height,
            target_height_offset: parameters.target_height_offset,
            source_finalized_height: source_height,
            source_finality_context_root: super::super::authority::processing_finality_root(
                source,
            )?
            .0,
            active_validator_set_root: roots.clone(),
            validator_consensus_key_root: roots.clone(),
            frozen_voting_weight_root: roots.clone(),
            cluster_schedule_version: "1".into(),
            finalized_epoch_seed_root: roots.clone(),
            assigned_height_schedule_root: roots.clone(),
            cluster_map_root: roots.clone(),
            assigned_cluster_id: 1,
            assigned_cluster_membership_root: roots.clone(),
            assigned_cluster_validator_count: MEMBERS as u64,
            assigned_cluster_total_voting_weight: MEMBERS as u64,
            consensus_parameter_root: roots.clone(),
            cryptographic_profile_root: roots,
            ingress_kem_registry_root: registry.root().map_err(err)?,
        },
    };
    context.validate().map_err(err)?;
    let aad = ProcessingEnvelopeAad {
        profile_id: profile.into(),
        chain_id,
        network_id: context.authority.network_id.clone(),
        protocol_version: context.authority.protocol_version.clone(),
        epoch: context.authority.epoch,
        processing_context_root: context.root().map_err(err)?,
        authorization_height: target_height,
        assigned_cluster_id: context.authority.assigned_cluster_id,
        lane_id: lane.into(),
        sender_id: sender_id.into(),
        nonce_slot: nonce,
    };
    aad.validate_context(&context).map_err(err)?;
    let encrypted = encrypt_protected_payload_with_kem(
        &aad,
        &registry.records,
        COUNT_QUORUM,
        padded.as_bytes(),
        &kem,
    )
    .map_err(err)?;
    let mut envelope = ProcessingEnvelope {
        envelope_version: 1,
        envelope_id: fixture_root.clone(),
        aad,
        aead_nonce: encrypted.aead_nonce,
        key_commitment: encrypted.key_commitment,
        share_commitment_root: fixture_root.clone(),
        share_capsule_root: fixture_root.clone(),
        ciphertext: encrypted.ciphertext,
        content_blind_order_key: fixture_root,
        share_capsules: encrypted.share_capsules,
    };
    envelope.refresh_capsule_roots().map_err(err)?;
    envelope.envelope_id = envelope.commitment().map_err(err)?;
    envelope.validate_context(&context).map_err(err)?;
    let admission = before_open(&envelope, &context)?;
    let mut shares = Shares(Vec::with_capacity(MEMBERS));
    for ((capsule, record), secret) in envelope
        .share_capsules
        .iter()
        .zip(&registry.records)
        .zip(&secrets)
    {
        let share = decrypt_share_capsule_with_kem_diagnostic(
            &envelope,
            capsule,
            record,
            secret.as_bytes(),
            false,
            &kem,
        )
        .map_err(|failure| err(failure.stage))?;
        shares.0.push((record.validator_id.clone(), share));
    }
    let opened = SecretBytes::from_bytes(
        decrypt_protected_payload(&envelope, &shares.0[..threshold], MEMBERS, COUNT_QUORUM)
            .map_err(err)?,
    );
    let plaintext = SecretBytes::from_bytes(unpad_plaintext(opened.as_bytes()).map_err(err)?);
    if plaintext.as_bytes() != content {
        return Err("isolated ETDAG open changed original content".into());
    }
    if decrypt_protected_payload(&envelope, &shares.0[..threshold - 1], MEMBERS, COUNT_QUORUM)
        .is_ok()
    {
        return Err("isolated ETDAG accepted insufficient shares".into());
    }
    let mut wrong_context = context.clone();
    wrong_context.authority.epoch += 1;
    if envelope.validate_context(&wrong_context).is_ok() {
        return Err("isolated ETDAG accepted foreign context".into());
    }
    // Recompute the outer commitment so rejection must involve authenticated
    // AAD/capsule/key binding, rather than only a stale envelope identifier.
    let mut wrong_aad = envelope.clone();
    wrong_aad.aad.nonce_slot ^= 1;
    wrong_aad.envelope_id = wrong_aad.commitment().map_err(err)?;
    wrong_aad.validate().map_err(err)?;
    if decrypt_share_capsule_with_kem_diagnostic(
        &wrong_aad,
        &wrong_aad.share_capsules[0],
        &registry.records[0],
        secrets[0].as_bytes(),
        false,
        &kem,
    )
    .is_ok()
        || decrypt_protected_payload(&wrong_aad, &shares.0[..threshold], MEMBERS, COUNT_QUORUM)
            .is_ok()
    {
        return Err("isolated ETDAG accepted substituted AAD".into());
    }
    Ok((
        OpenedCandidateEnvelope {
            plaintext,
            envelope,
            context,
        },
        admission,
    ))
}

fn fixture_source() -> FinalizedBlockRecord {
    FinalizedBlockRecord {
        height: 3,
        block_id: "1".repeat(64),
        finality_certificate_id: "2".repeat(64),
        protected_execution_root: "3".repeat(64),
    }
}

#[test]
fn isolated_etdag_candidate_missing_provider_cannot_fall_back() {
    assert!(open_candidate_envelope(
        b"fixture",
        Path::new("/missing/isolated-apqe-report.json"),
        &"0".repeat(64),
        77,
        &fixture_source(),
        "fixture-sender",
        0,
        CandidateEnvelopeProfile::Transfer,
        |_, _| Ok(()),
    )
    .is_err());
}
#[test]
#[ignore = "requires explicit pinned APQE_TRUSTED_NATIVE_REPORT and APQE_AUTHENTICATED_REPORT_SHA256"]
fn isolated_etdag_candidate_real_native_mlkem_roundtrip_and_rejection_checks() {
    let report = std::path::PathBuf::from(std::env::var_os("APQE_TRUSTED_NATIVE_REPORT").unwrap());
    let digest = std::env::var("APQE_AUTHENTICATED_REPORT_SHA256").unwrap();
    let original = b"\x84\x19\x70\x03exact candidate content\x00\xff";
    let (opened, _) = open_candidate_envelope(
        original,
        &report,
        &digest,
        77,
        &fixture_source(),
        "fixture-sender",
        9,
        CandidateEnvelopeProfile::Transfer,
        |_, _| Ok(()),
    )
    .unwrap();
    assert_eq!(opened.plaintext(), original);
    assert_eq!(opened.envelope().aad.chain_id, 77);
    assert_eq!(opened.envelope().aad.nonce_slot, 9);
    opened
        .envelope()
        .validate_context(opened.context())
        .unwrap();
    assert_eq!(opened.envelope().share_capsules.len(), 4);
}
