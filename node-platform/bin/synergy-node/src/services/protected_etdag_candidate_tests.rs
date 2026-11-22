//! Native-APQE fixture for the distinct PW13 envelope profile. It exercises
//! local encrypt and reveal without starting any validator or network.
#![cfg(test)]
use super::super::processing_pipeline::{
    qualify_processing_vertex, AuthenticatedProcessingOpening, RevealedProcessingPayload,
};
use super::{
    processing_admission::CandidateAdmission,
    processing_execution::{
        execute_protected_candidate, CandidateActionOutcome, CandidateDispatch, CandidateSlot,
        PreparedProtectedAction,
    },
    FinalizedSnapshot, Position, WorldState,
};
use std::{
    path::Path,
    sync::{Arc, Mutex},
};
use synergy_address_engine::{
    apqe::{crypto_engine::CryptoEngine, provider::SignOptions, SecretBytes},
    types::Algorithm,
};
use synergy_aegis::{AegisProtectedPrimitives, ApqeKem};
use synergy_etdag::{
    admission::{
        PW13_SPONSOR_CANDIDATE_LANE, PW13_SPONSOR_CANDIDATE_PROFILE_ID,
        PW13_TRANSFER_CANDIDATE_LANE, PW13_TRANSFER_CANDIDATE_PROFILE_ID,
    },
    crypto::{
        canonical_signing_bytes, decrypt_share_capsule_with_kem_diagnostic,
        encrypt_protected_payload_with_kem, governed_reveal_threshold, pad_plaintext,
        IngressKemKeyRecord, IngressKemKeyRegistry, IngressKemPublicKey, ML_KEM_1024_ALGORITHM,
    },
    execution::{
        processing_genesis_group_root, ProcessingDecryptShare, ProcessingOrderGroup,
        ProcessingRevealPermission, ProcessingVertex,
    },
    AvailabilityCertificate, AvailabilityVote, CertifiedEnvelopeRef, EtdagDigest, EtdagParameters,
    ProcessingContext, ProcessingEnvelope, ProcessingEnvelopeAad, TargetAdmissionContextV3,
};
use synergy_execution::{
    processing_group_state, processing_group_transition, processing_member_claim,
    processing_member_claim_optional, ParentProcessingRegistry, ProcessingReadinessVerifier,
    ProcessingReadyRecord,
};
use synergy_posy::{FinalizedBlockRecord, ValidatorRecord, ValidatorStatus};
use synergy_state::world_resources::{BudgetedWorld, WorldResourceBudget};

pub(super) struct ClosedCandidateOrder {
    permission: ProcessingRevealPermission,
    world: BudgetedWorld,
}

pub(super) struct OpenedCandidateEnvelope {
    opening: AuthenticatedProcessingOpening,
    envelope: ProcessingEnvelope,
    context: ProcessingContext,
    order: Option<ClosedCandidateOrder>,
}

pub(super) enum CandidateEnvelopeProfile {
    Transfer,
    SponsoredEnrollment,
}
impl OpenedCandidateEnvelope {
    pub(super) fn plaintext(&self) -> &[u8] {
        self.payload().plaintext()
    }
    pub(super) fn payload(&self) -> RevealedProcessingPayload<'_> {
        self.opening
            .payload(&self.envelope, &self.context)
            .expect("qualification retains the exact opened envelope and context")
    }
    pub(super) fn envelope(&self) -> &ProcessingEnvelope {
        &self.envelope
    }
    pub(super) fn context(&self) -> &ProcessingContext {
        &self.context
    }

    pub(super) fn execute_ordered(
        &self,
        dispatch: CandidateDispatch<'_>,
        inclusion: Position,
        execution_finalized_parent: &FinalizedSnapshot<'_>,
        parameters: &EtdagParameters,
    ) -> Result<(BudgetedWorld, CandidateActionOutcome), String> {
        let order = self
            .order
            .as_ref()
            .ok_or("candidate lacks a closed order")?;
        let namespace = &order.permission.namespace_root;
        let publication = CandidateSlot {
            inclusion: Position {
                height: inclusion.height - 1,
                ..inclusion
            },
            finalized_parent: dispatch.source,
        };
        let action =
            PreparedProtectedAction::prepare(dispatch, self.payload(), &order.world, publication)?;
        let (published, results) = execute_protected_candidate(
            &order.world,
            namespace,
            parameters,
            publication,
            &[&action],
            &[&action],
        )?;
        assert!(results.is_empty());
        assert_eq!(published.accounts, order.world.accounts);

        let execution = CandidateSlot {
            inclusion,
            finalized_parent: execution_finalized_parent,
        };
        let mut changed_limits = parameters.clone();
        changed_limits.max_protected_gas += 1;
        assert!(matches!(
            execute_protected_candidate(
                &published, namespace, &changed_limits, execution, &[&action], &[],
            ),
            Err(error) if error == "protected processing limits differ from the authenticated admission"
        ));
        let (settled, outcomes) = execute_protected_candidate(
            &published,
            namespace,
            parameters,
            execution,
            &[&action],
            &[],
        )?;
        let [outcome] =
            <[_; 1]>::try_from(outcomes).map_err(|_| "expected one protected action settlement")?;
        assert!(processing_member_claim_optional(
            settled.as_ref(),
            &self.envelope.aad.sender_id,
            self.envelope.aad.nonce_slot,
        )
        .map_err(err)?
        .is_none());
        let consumed =
            ParentProcessingRegistry::read(settled.as_ref(), namespace, settled.budget())
                .map_err(err)?;
        assert!(consumed.records().is_empty());
        let (replayed, duplicate) = execute_protected_candidate(
            &settled,
            namespace,
            parameters,
            execution,
            &[&action],
            &[],
        )?;
        assert!(duplicate.is_empty());
        assert_eq!(replayed.as_ref(), settled.as_ref());
        Ok((settled, outcome))
    }

}
struct SignedShares(Vec<ProcessingDecryptShare>);
impl Drop for SignedShares {
    fn drop(&mut self) {
        for message in &mut self.0 {
            message.share_bytes.fill(0);
        }
    }
}
fn err(error: impl std::fmt::Debug) -> String {
    format!("isolated ETDAG crypto fixture refused: {error:?}")
}

pub(super) struct CandidateOrderFixture<'a> {
    authority: &'a super::super::authority::VerifiedAuthority,
    registry: &'a IngressKemKeyRegistry,
    engine: &'a Arc<Mutex<CryptoEngine>>,
    signers: &'a [SecretBytes],
    source: &'a FinalizedBlockRecord,
    budget: &'a Arc<WorldResourceBudget>,
}

impl CandidateOrderFixture<'_> {
    fn sign(&self, index: usize, message: &[u8]) -> Result<Vec<u8>, String> {
        self.engine
            .lock()
            .map_err(|_| "isolated APQE lock poisoned")?
            .sign(
                Algorithm::MlDsa65,
                self.signers[index].as_bytes(),
                message,
                SignOptions::default(),
            )
            .map_err(err)
    }

    pub(super) fn certify<T>(
        &self,
        admission: CandidateAdmission,
        context: &ProcessingContext,
        parent: &WorldState,
        authenticate: impl Fn(&CandidateAdmission) -> Result<T, String>,
    ) -> Result<(T, ClosedCandidateOrder), String> {
        let envelope = &admission.envelope;
        // Selected for this isolated ordering fixture. The deployed profile
        // supplies its ratified class policy and authenticated fee schedule.
        const FEE_CLASS: u32 = 1;
        let mut vertex = ProcessingVertex {
            vertex_version: 1,
            envelope_ref: CertifiedEnvelopeRef {
                tx_commitment: envelope.envelope_id.clone(),
                sender_id: envelope.aad.sender_id.clone(),
                nonce_slot: envelope.aad.nonce_slot,
                certified_dag_round: 0,
                gas_class_units: admission.gas_limit(),
                ciphertext_bytes: envelope.ciphertext.len() as u64,
                fee_class: FEE_CLASS,
                protocol_dependencies: vec![],
            },
            admission,
            parents: vec![],
            author_id: self.registry.records[0].validator_id.clone(),
            key_id: "fixture-consensus-key-0".into(),
            author_signature: vec![],
        };
        vertex.author_signature = self.sign(0, &vertex.signing_bytes().map_err(err)?)?;
        let vertex_id = vertex.id().map_err(err)?;
        let context_root = context.root().map_err(err)?;
        let membership = self.registry.records.len();
        let votes = self
            .registry
            .records
            .iter()
            .enumerate()
            .take(membership - 1)
            .map(|(index, record)| {
                let mut vote = AvailabilityVote {
                    context_root: context_root.clone(),
                    vertex_id: vertex_id.clone(),
                    validator_id: record.validator_id.clone(),
                    key_id: format!("fixture-consensus-key-{index}"),
                    signature: Vec::new(),
                };
                let transcript = canonical_signing_bytes(
                    "SYNERGY_ETDAG_AVAILABILITY_VOTE_V1",
                    &(
                        &vote.context_root,
                        &vote.vertex_id,
                        &vote.validator_id,
                        &vote.key_id,
                    ),
                )
                .map_err(err)?;
                vote.signature = self.sign(index, &transcript)?;
                Ok(vote)
            })
            .collect::<Result<Vec<_>, String>>()?;
        let certificate =
            AvailabilityCertificate::from_votes(context_root.clone(), vertex_id, votes, membership)
                .map_err(err)?;
        let mut substituted = certificate.clone();
        substituted.vertex_id = context_root.clone();
        assert!(qualify_processing_vertex(
            self.authority,
            context,
            self.registry,
            &vertex,
            &substituted,
            self.budget,
            &authenticate
        )
        .is_err());
        let (member, authorized) = qualify_processing_vertex(
            self.authority,
            context,
            self.registry,
            &vertex,
            &certificate,
            self.budget,
            authenticate,
        )?;
        let namespace = context_root.clone();
        let ordered = ProcessingOrderGroup {
            group_version: 1,
            namespace_root: namespace.clone(),
            group_number: 1,
            previous_group_root: processing_genesis_group_root(&namespace).map_err(err)?,
            order_seed: context_root,
            members: vec![member],
        };
        let successor = ProcessingOrderGroup {
            group_number: 2,
            previous_group_root: ordered.root().map_err(err)?,
            members: vec![],
            ..ordered.clone()
        };
        let verifier = FixtureOrder {
            ordered: &ordered,
            successor: &successor,
        };
        let mut world = BudgetedWorld::try_clone_world(parent, self.budget).map_err(err)?;
        let publish = processing_group_transition(
            world.as_ref(),
            &namespace,
            std::iter::empty(),
            Some(&ordered),
            &verifier,
            self.budget,
        )
        .map_err(err)?;
        world.try_apply(publish.diff()).map_err(err)?;
        assert!(processing_group_state(world.as_ref(), &namespace, 1)
            .map_err(err)?
            .closed_by_successor
            .is_none());
        let close = processing_group_transition(
            world.as_ref(),
            &namespace,
            std::iter::empty(),
            Some(&successor),
            &verifier,
            self.budget,
        )
        .map_err(err)?;
        world.try_apply(close.diff()).map_err(err)?;
        let item = &ordered.members[0];
        let claim = processing_member_claim(
            world.as_ref(),
            &item.envelope.sender_id,
            item.envelope.nonce_slot,
        )
        .map_err(err)?;
        assert_eq!(&claim.member, item);
        let group =
            processing_group_state(world.as_ref(), &namespace, claim.group_number).map_err(err)?;
        let permission = ProcessingRevealPermission {
            namespace_root: namespace,
            group_number: claim.group_number,
            group_root: claim.group_root,
            successor_root: group
                .closed_by_successor
                .ok_or("fixture predecessor is still open")?,
            processing_context_root: claim.member.processing_context_root,
            envelope_id: claim.member.envelope.tx_commitment,
            parent_block_id: self.source.block_id.clone(),
            validation_id: self.source.finality_certificate_id.clone(),
        };
        Ok((authorized, ClosedCandidateOrder { permission, world }))
    }
}

struct FixtureOrder<'a> {
    ordered: &'a ProcessingOrderGroup,
    successor: &'a ProcessingOrderGroup,
}

impl ProcessingReadinessVerifier for FixtureOrder<'_> {
    fn verify_ordered_group(
        &self,
        group: &ProcessingOrderGroup,
        _: &WorldState,
    ) -> Result<(), String> {
        if group != self.ordered && group != self.successor {
            return Err("fixture group differs from the verified assignment".into());
        }
        Ok(())
    }

    fn verify_publication(&self, _: &ProcessingReadyRecord, _: &WorldState) -> Result<(), String> {
        Err("fixture order cannot verify a READY publication".into())
    }

    fn identity_is_current(
        &self,
        _: &ProcessingReadyRecord,
        _: &WorldState,
    ) -> Result<bool, String> {
        Err("fixture order cannot verify inclusion eligibility".into())
    }
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
    before_open: impl FnOnce(
        &ProcessingEnvelope,
        &ProcessingContext,
        &CandidateOrderFixture<'_>,
    ) -> Result<(T, Option<ClosedCandidateOrder>), String>,
) -> Result<(OpenedCandidateEnvelope, T), String> {
    let source_height = source.height;
    if chain_id == 0 || source_height == 0 {
        return Err("invalid isolated fixture coordinate".into());
    }
    let padded = SecretBytes::from_bytes(pad_plaintext(content).map_err(err)?);
    let engine = synergy_aegis::load_authenticated_native_engine(report, report_sha256)?;
    let kem = ApqeKem::mlkem1024(engine.clone()).map_err(err)?;
    // Five in-memory signing records satisfy the existing PoSy registry
    // validation. The native reveal owner applies the same share threshold.
    const MEMBERS: usize = 5;
    const COUNT_QUORUM: usize = MEMBERS - 1;
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
    let mut signers = Vec::with_capacity(MEMBERS);
    let mut validators = Vec::with_capacity(MEMBERS);
    for (index, record) in registry.records.iter().enumerate() {
        let pair = engine
            .lock()
            .map_err(|_| "isolated APQE lock poisoned")?
            .generate_keypair(Algorithm::MlDsa65)
            .map_err(err)?;
        validators.push((
            ValidatorRecord {
                validator_id: record.validator_id.clone(),
                consensus_key_id: format!("fixture-consensus-key-{index}"),
                frozen_voting_weight: 1,
                status: ValidatorStatus::Active,
            },
            pair.public_key,
        ));
        signers.push(pair.private_key);
    }
    let authority = super::super::authority::qualification_authority_for_network(
        validators,
        Some(engine.clone()),
        chain_id,
        network,
    );
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
            active_validator_set_root: authority.epoch.active_validator_set_root.clone(),
            validator_consensus_key_root: authority.epoch.validator_consensus_key_root.clone(),
            frozen_voting_weight_root: authority.epoch.frozen_voting_weight_root.clone(),
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
    let budget = WorldResourceBudget::new(128 * 1024 * 1024);
    let ordering = CandidateOrderFixture {
        authority: &authority,
        registry: &registry,
        engine: &engine,
        signers: &signers,
        source,
        budget: &budget,
    };
    let (admission, order) = before_open(&envelope, &context, &ordering)?;
    let permission = order
        .as_ref()
        .map(|order| order.permission.clone())
        .unwrap_or_else(|| ProcessingRevealPermission {
            namespace_root: envelope.content_blind_order_key.clone(),
            group_number: 1,
            group_root: envelope.share_commitment_root.clone(),
            successor_root: envelope.share_capsule_root.clone(),
            processing_context_root: envelope.aad.processing_context_root.clone(),
            envelope_id: envelope.envelope_id.clone(),
            parent_block_id: source.block_id.clone(),
            validation_id: source.finality_certificate_id.clone(),
        });
    let mut shares = SignedShares(Vec::with_capacity(MEMBERS));
    for (index, ((capsule, record), secret)) in envelope
        .share_capsules
        .iter()
        .zip(&registry.records)
        .zip(&secrets)
        .enumerate()
    {
        let mut share = decrypt_share_capsule_with_kem_diagnostic(
            &envelope,
            capsule,
            record,
            secret.as_bytes(),
            false,
            &kem,
        )
        .map_err(|failure| err(failure.stage))?;
        let share_bytes = share.canonical_bytes();
        share.value.fill(0);
        shares.0.push(ProcessingDecryptShare {
            share_version: 1,
            permission: permission.clone(),
            validator_id: record.validator_id.clone(),
            key_id: format!("fixture-consensus-key-{index}"),
            ingress_kem_key_id: record.key_id.clone(),
            share_index: capsule.share_index,
            share_commitment: capsule.share_commitment.clone(),
            share_bytes: share_bytes.map_err(err)?,
            signature: Vec::new(),
        });
        let message = shares.0.last_mut().expect("inserted share");
        let transcript = SecretBytes::from_bytes(message.signing_bytes().map_err(err)?);
        message.signature = engine
            .lock()
            .map_err(|_| "isolated APQE lock poisoned")?
            .sign(
                Algorithm::MlDsa65,
                signers[index].as_bytes(),
                transcript.as_bytes(),
                SignOptions::default(),
            )
            .map_err(err)?;
    }
    let open = |envelope: &ProcessingEnvelope, shares: &[ProcessingDecryptShare]| {
        AuthenticatedProcessingOpening::open_qualification_shares(
            &authority,
            envelope,
            &permission,
            shares,
            &budget,
        )
    };
    let opening = open(&envelope, &shares.0[..threshold])?;
    if opening.payload(&envelope, &context)?.plaintext() != content {
        return Err("isolated ETDAG open changed original content".into());
    }
    if open(&envelope, &shares.0[..threshold - 1]).is_ok() {
        return Err("isolated ETDAG accepted insufficient shares".into());
    }
    shares.0[0].signature[0] ^= 1;
    if open(&envelope, &shares.0[..threshold]).is_ok() {
        return Err("isolated ETDAG accepted a changed validator share signature".into());
    }
    shares.0[0].signature[0] ^= 1;
    let mut wrong_context = context.clone();
    wrong_context.authority.epoch += 1;
    if opening.payload(&envelope, &wrong_context).is_ok() {
        return Err("isolated ETDAG accepted foreign context".into());
    }
    // Recompute the outer commitment so rejection must involve authenticated
    // AAD/capsule/key binding, rather than only a stale envelope identifier.
    let mut wrong_aad = envelope.clone();
    wrong_aad.aad.nonce_slot ^= 1;
    if opening.payload(&wrong_aad, &context).is_ok() {
        return Err("isolated ETDAG reused opened content with changed envelope fields".into());
    }
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
        || open(&wrong_aad, &shares.0[..threshold]).is_ok()
    {
        return Err("isolated ETDAG accepted substituted AAD".into());
    }
    Ok((
        OpenedCandidateEnvelope {
            opening,
            envelope,
            context,
            order,
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
        |_, _, _| Ok(((), None)),
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
        |_, _, _| Ok(((), None)),
    )
    .unwrap();
    assert_eq!(opened.plaintext(), original);
    assert_eq!(opened.envelope().aad.chain_id, 77);
    assert_eq!(opened.envelope().aad.nonce_slot, 9);
    opened
        .envelope()
        .validate_context(opened.context())
        .unwrap();
    assert_eq!(opened.envelope().share_capsules.len(), 5);
}
