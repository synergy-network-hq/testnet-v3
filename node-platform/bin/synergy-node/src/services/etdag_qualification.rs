//! Real ML-DSA cutoff verification; no mock signature acceptance.
fn retained_generations(
    owner: &synergy_etdag::persistence::ProtectedPipeline,
) -> Vec<synergy_etdag::persistence::CutRecoveryGeneration> {
    (0..owner.cut_recovery_generation_count())
        .map(|i| owner.read_cut_recovery_generation(i).unwrap().unwrap())
        .collect()
}
fn retained_markers(
    owner: &synergy_etdag::persistence::ProtectedPipeline,
) -> Vec<synergy_etdag::ordering::ProtectedCutMarker> {
    (0..owner.retained_local_marker_count())
        .map(|i| owner.read_retained_local_marker(i).unwrap().unwrap())
        .collect()
}
use super::posy::qualification::Fleet;
use std::collections::BTreeMap;
use synergy_aegis::{
    AegisPolicy, AegisSigner, KeyId, PqvmSigner, SignatureAlgorithm, SigningContext,
};
use synergy_etdag::ordering::{CutoffMembers, ProtectedCutMarker};
use synergy_etdag::{EtdagDigest, EtdagGraph, ProtectedCutProof, TargetAdmissionContextV3};

fn digest(value: &str) -> EtdagDigest {
    EtdagDigest::from_domain_bytes("qualification", value.as_bytes())
}

/// Focused native-store/cryptographic R3 qualification. The opaque ciphertext
/// is not a real wallet transfer, socket test, execution or live activation.
#[test]
fn r3_genuine_timeout_recovers_three_empty_two_vertex_close_and_restart() {
    use super::cut_recovery::{generation_from_certificates as generation, CutRecoveryVerifier};
    use synergy_etdag::persistence::{ProtectedPipeline, ProtectedRecoveryVerifier};
    use synergy_etdag::{
        AvailabilityCertificate, AvailabilityVote, CertifiedEnvelopeRef, EtdagParameters,
        TransactionVertex,
    };
    use synergy_posy::{
        ConsensusObjectContext, ProposalDelivery, ProposalValidationCertificate,
        SimplifiedFinalityParent, SimplifiedTimeoutCertificate, TimeoutVote,
        VerifiedQuorumCertificateStore, VerifiedTimeoutCertificateStore,
        POSY_SIMPLIFIED_TIMEOUT_VOTE_DOMAIN,
    };
    let mut fleet = Fleet::new();
    let material = synergy_etdag::execution::ProtectedProposalMaterial {
        material_version: 2,
        height: 1,
        execution_root: digest("H1"),
        next_batch_root: digest("H2"),
        cutoff_boundary_root: digest("H3"),
    };
    let original_vc = fleet.validate_protected_parent(&material);
    let consensus = fleet.root.join("node-0");
    let authority = fleet.authority.as_ref();
    let qc = VerifiedQuorumCertificateStore::new(&consensus)
        .unwrap()
        .get_verified(1, &authority.epoch, &authority.registry, authority)
        .unwrap()
        .unwrap();
    let parent = SimplifiedFinalityParent::QuorumCertificate {
        height: 1,
        block_id: qc.block_id.clone(),
        qc_id: qc.id().unwrap(),
    };
    let make_timeout_with_parent =
        |round: u64,
         previous: Option<String>,
         carry: Option<synergy_posy::CertifiedCandidateSubject>,
         highest_parent: SimplifiedFinalityParent| {
            let reports = (0..4)
                .map(|index| {
                    let key = KeyId::new(format!("key-{index}")).unwrap();
                    let signer = PqvmSigner::from_secret_key_bytes(
                        AegisPolicy {
                            allowed_algorithms: vec![SignatureAlgorithm::MlDsa65],
                            maximum_message_bytes: 1024 * 1024,
                            maximum_signature_bytes: 16 * 1024,
                        },
                        key.clone(),
                        fleet.secrets[index].clone(),
                    )
                    .unwrap();
                    let mut report = TimeoutVote {
                        context: ConsensusObjectContext::for_height(&authority.epoch, 2, round)
                            .unwrap(),
                        lease_index: authority.epoch.lease_index(2).unwrap(),
                        timed_out_proposer: authority
                            .epoch
                            .authorized_proposer(2, round)
                            .unwrap()
                            .into(),
                        highest_parent: highest_parent.clone(),
                        previous_tc_id: previous.clone(),
                        last_voted_candidate: carry.clone(),
                        validator_id: format!("qualification-{index}"),
                        key_id: format!("key-{index}"),
                        signature: vec![],
                    };
                    report.signature = signer
                        .sign(
                            &key,
                            &SigningContext {
                                domain: POSY_SIMPLIFIED_TIMEOUT_VOTE_DOMAIN.into(),
                                chain_id: 1266,
                                epoch: Some(1),
                                height: Some(2),
                            },
                            &synergy_posy::timeout_vote_signing_bytes(&report).unwrap(),
                        )
                        .unwrap()
                        .bytes;
                    report
                })
                .collect();
            SimplifiedTimeoutCertificate::from_votes_with_qc_proofs(reports, vec![qc.clone()])
                .unwrap()
        };
    let make_timeout =
        |round: u64,
         previous: Option<String>,
         carry: Option<synergy_posy::CertifiedCandidateSubject>| {
            make_timeout_with_parent(round, previous, carry, parent.clone())
        };
    let timeout = make_timeout(0, None, None::<synergy_posy::CertifiedCandidateSubject>);
    let store = VerifiedTimeoutCertificateStore::new(&consensus).unwrap();
    store
        .put_verified(&timeout, &authority.epoch, &authority.registry, authority)
        .unwrap();
    ProposalDelivery::open(&consensus, &authority.epoch, &authority.registry, authority)
        .unwrap()
        .persist_validation(
            &original_vc,
            &authority.epoch,
            &authority.registry,
            authority,
        )
        .unwrap();
    let original = EtdagDigest::from_domain_bytes(
        "SYNERGY_ETDAG_CUTOFF_VC_V1",
        original_vc.id().unwrap().as_bytes(),
    );
    let mut context = context(&fleet);
    context.assigned_cluster_membership_root = authority.epoch.active_validator_set_root.clone();
    let root = context.root().unwrap();
    let envelope = opaque_envelope(&context, digest("r3-opaque-transaction"), 0);
    let mut vertex = TransactionVertex {
        vertex_id: digest("pending"),
        target_context_root: root.clone(),
        target_height: 3,
        envelope_ref: CertifiedEnvelopeRef {
            tx_commitment: envelope.envelope_id.clone(),
            sender_id: "alice".into(),
            nonce_slot: 0,
            certified_dag_round: 0,
            gas_class_units: 10,
            ciphertext_bytes: 512,
            fee_class: 1,
            protocol_dependencies: vec![],
        },
        envelope,
        parents: vec![],
        author_id: "qualification-0".into(),
        author_signature: vec![],
        wallet_admission: None,
    };
    vertex.vertex_id = synergy_etdag::dag::derive_vertex_id(&vertex).unwrap();
    vertex.author_signature = sign(&fleet, 0, vertex.vertex_id.0.as_bytes());
    let id = vertex.vertex_id.clone();
    let votes = (0..5)
        .map(|index| {
            let mut vote = AvailabilityVote {
                context_root: root.clone(),
                vertex_id: id.clone(),
                validator_id: format!("qualification-{index}"),
                key_id: format!("key-{index}"),
                signature: vec![],
            };
            let bytes = synergy_etdag::crypto::canonical_signing_bytes(
                "SYNERGY_ETDAG_AVAILABILITY_VOTE_V1",
                &(
                    &vote.context_root,
                    &vote.vertex_id,
                    &vote.validator_id,
                    &vote.key_id,
                ),
            )
            .unwrap();
            vote.signature = sign(&fleet, index, &bytes);
            vote
        })
        .collect();
    let certificate =
        AvailabilityCertificate::from_votes(root.clone(), id.clone(), votes, 5).unwrap();
    let verifier = CutRecoveryVerifier::new(fleet.authority.clone(), consensus.clone());
    let close = |index: usize, cutoff: EtdagDigest, frontier: Vec<EtdagDigest>| {
        let mut marker = ProtectedCutMarker {
            marker_version: 1,
            context_root: root.clone(),
            target_height: 3,
            cutoff_context_root: cutoff,
            frontier,
            validator_id: format!("qualification-{index}"),
            key_id: format!("key-{index}"),
            signature: vec![],
        };
        marker.signature = sign(&fleet, index, &marker.signing_bytes().unwrap());
        marker
    };
    let old_markers = (0..5)
        .map(|i| {
            close(
                i,
                original.clone(),
                if i < 3 { vec![] } else { vec![id.clone()] },
            )
        })
        .collect::<Vec<_>>();
    let mut graph = EtdagGraph::new(root.clone(), 3).unwrap();
    graph.insert(vertex.clone()).unwrap();
    let availability = BTreeMap::from([(id.clone(), certificate.clone())]);
    assert!(ProtectedCutProof::derive(
        &context,
        &original,
        &old_markers[..3],
        &graph,
        &availability,
        &members(),
        authority
    )
    .is_err());
    assert!(ProtectedCutProof::derive(
        &context,
        &original,
        &old_markers[3..],
        &graph,
        &availability,
        &members(),
        authority
    )
    .is_err());
    let next = generation(
        3,
        &original_vc,
        original.clone(),
        std::slice::from_ref(&timeout),
    )
    .unwrap();
    // A cryptographically valid timeout certificate with a conflicting
    // certified parent must not authorize a replacement generation.
    let conflicting_parent = SimplifiedFinalityParent::QuorumCertificate {
        height: 1,
        block_id: "b".repeat(64),
        qc_id: qc.id().unwrap(),
    };
    let conflicting_parent_tc =
        make_timeout_with_parent(1, Some(timeout.id().unwrap()), None, conflicting_parent);
    assert!(store
        .put_verified(
            &conflicting_parent_tc,
            &authority.epoch,
            &authority.registry,
            authority,
        )
        .is_err());
    let conflicting_parent_generation = generation(
        3,
        &original_vc,
        next.cutoff_context_root.clone(),
        &[timeout.clone(), conflicting_parent_tc.clone()],
    )
    .unwrap();
    assert!(verifier
        .verify_cut_recovery_generation(&context, &conflicting_parent_generation)
        .is_err());
    let mut wrong_target = context.clone();
    wrong_target.target_height += 1;
    assert!(verifier
        .verify_cut_recovery_generation(&wrong_target, &next)
        .is_err());
    let mut bad = next.clone();
    bad.timeout_id = "0".repeat(64);
    assert!(verifier
        .verify_cut_recovery_generation(&context, &bad)
        .is_err());
    let mut bad = next.clone();
    bad.authorization[0] ^= 1;
    assert!(verifier
        .verify_cut_recovery_generation(&context, &bad)
        .is_err());
    // A genuine four-signature conflicting candidate is rejected by the
    // native QC store before it can become timeout-parent evidence.
    let alternate_votes = (0..4)
        .map(|index| {
            let key = KeyId::new(format!("key-{index}")).unwrap();
            let signer = PqvmSigner::from_secret_key_bytes(
                AegisPolicy {
                    allowed_algorithms: vec![SignatureAlgorithm::MlDsa65],
                    maximum_message_bytes: 1024 * 1024,
                    maximum_signature_bytes: 16 * 1024,
                },
                key.clone(),
                fleet.secrets[index].clone(),
            )
            .unwrap();
            let mut vote = synergy_posy::BlockVote {
                context: qc.context.clone(),
                block_id: "b".repeat(64),
                parent_block_id: qc.parent_block_id.clone(),
                parent: qc.parent.clone(),
                takeover_tc_id: qc.takeover_tc_id.clone(),
                protected_execution_root: qc.protected_execution_root.clone(),
                validator_id: format!("qualification-{index}"),
                key_id: format!("key-{index}"),
                signature: vec![],
            };
            vote.signature = signer
                .sign(
                    &key,
                    &SigningContext {
                        domain: synergy_posy::POSY_SIMPLIFIED_BLOCK_VOTE_DOMAIN.into(),
                        chain_id: 1266,
                        epoch: Some(1),
                        height: Some(1),
                    },
                    &synergy_posy::block_vote_signing_bytes(&vote).unwrap(),
                )
                .unwrap()
                .bytes;
            vote
        })
        .collect();
    let alternate_qc =
        synergy_posy::SimplifiedQuorumCertificate::from_votes(alternate_votes).unwrap();
    assert!(VerifiedQuorumCertificateStore::new(&consensus)
        .unwrap()
        .put_verified(
            &alternate_qc,
            &authority.epoch,
            &authority.registry,
            authority,
        )
        .is_err());
    let missing = make_timeout(1, Some(timeout.id().unwrap()), None);
    let missing_generation = generation(
        3,
        &original_vc,
        next.cutoff_context_root.clone(),
        &[timeout.clone(), missing.clone()],
    )
    .unwrap();
    assert!(verifier
        .verify_cut_recovery_generation(&context, &missing_generation)
        .is_err());
    // The report signatures are valid, but a round-one TC naming an unknown
    // predecessor is not a verified timeout path and cannot authorize R3.
    // Keep it in an isolated native evidence store so it cannot conflict with
    // the valid round-one TC installed below for the main recovery path.
    let unknown_predecessor = make_timeout(1, Some("0".repeat(64)), None);
    let unknown_root = fleet.root.join("r3-unknown-predecessor");
    VerifiedQuorumCertificateStore::new(&unknown_root)
        .unwrap()
        .put_verified(&qc, &authority.epoch, &authority.registry, authority)
        .unwrap();
    ProposalDelivery::open(
        &unknown_root,
        &authority.epoch,
        &authority.registry,
        authority,
    )
    .unwrap()
    .persist_validation(
        &original_vc,
        &authority.epoch,
        &authority.registry,
        authority,
    )
    .unwrap();
    let unknown_store = VerifiedTimeoutCertificateStore::new(&unknown_root).unwrap();
    unknown_store
        .put_verified(&timeout, &authority.epoch, &authority.registry, authority)
        .unwrap();
    unknown_store
        .put_verified(
            &unknown_predecessor,
            &authority.epoch,
            &authority.registry,
            authority,
        )
        .unwrap();
    let unknown_predecessor_generation = generation(
        3,
        &original_vc,
        next.cutoff_context_root.clone(),
        &[timeout.clone(), unknown_predecessor.clone()],
    )
    .unwrap();
    let unknown_verifier = CutRecoveryVerifier::new(fleet.authority.clone(), unknown_root);
    assert!(unknown_verifier
        .verify_cut_recovery_generation(&context, &unknown_predecessor_generation)
        .is_err());
    let mut invalid_signature = missing.clone();
    invalid_signature.reports[0].signature[0] ^= 1;
    assert!(store
        .put_verified(
            &invalid_signature,
            &authority.epoch,
            &authority.registry,
            authority
        )
        .is_err());
    // Prime a separate verifier's same-lease cache with only round zero,
    // then persist later rounds. Round two can resolve its new round-one
    // predecessor only by refreshing the native verified lease journal.
    let delayed_verifier = CutRecoveryVerifier::new(fleet.authority.clone(), consensus.clone());
    delayed_verifier
        .verify_cut_recovery_generation(&context, &next)
        .unwrap();
    store
        .put_verified(&missing, &authority.epoch, &authority.registry, authority)
        .unwrap();
    let late_round_two = make_timeout(2, Some(missing.id().unwrap()), None);
    store
        .put_verified(
            &late_round_two,
            &authority.epoch,
            &authority.registry,
            authority,
        )
        .unwrap();
    let later = generation(
        3,
        &original_vc,
        missing_generation.cutoff_context_root.clone(),
        &[timeout.clone(), missing.clone(), late_round_two.clone()],
    )
    .unwrap();
    delayed_verifier
        .verify_cut_recovery_generation(&context, &later)
        .unwrap();
    // A valid signed carry at the affected slot makes recovery fail closed.
    let carry_subject = synergy_posy::CertifiedCandidateSubject::new(
        ConsensusObjectContext::for_height(&authority.epoch, 2, 0).unwrap(),
        "qualified-H2-candidate".into(),
        qc.block_id.clone(),
        parent.clone(),
        "a".repeat(64),
    )
    .unwrap();
    let carried = make_timeout(3, Some(late_round_two.id().unwrap()), Some(carry_subject));
    store
        .put_verified(&carried, &authority.epoch, &authority.registry, authority)
        .unwrap();
    let carry_generation = generation(
        3,
        &original_vc,
        later.cutoff_context_root.clone(),
        &[
            timeout.clone(),
            missing.clone(),
            late_round_two.clone(),
            carried,
        ],
    )
    .unwrap();
    assert!(delayed_verifier
        .verify_cut_recovery_generation(&context, &carry_generation)
        .is_err());
    let second = missing_generation;
    verifier
        .verify_cut_recovery_generation(&context, &second)
        .unwrap();
    let mut wrong_domain = context.clone();
    wrong_domain.network_id.push_str("-foreign");
    assert!(verifier
        .verify_cut_recovery_generation(&wrong_domain, &second)
        .is_err());
    let mut recovered = Vec::new();
    for (index, old) in old_markers.iter().enumerate() {
        let directory = fleet.root.join(format!("r3-pipeline-{index}"));
        let mut owner = ProtectedPipeline::open_collecting(
            &directory,
            context.clone(),
            EtdagParameters::default(),
            format!("qualification-{index}"),
            &members(),
            &verifier,
        )
        .unwrap();
        owner
            .persist_vertex(vertex.clone(), &members(), &verifier)
            .unwrap();
        if index >= 3 {
            owner
                .persist_availability(certificate.clone(), &members(), &verifier)
                .unwrap();
        }
        owner.bind_cutoff(original.clone()).unwrap();
        owner
            .persist_local_marker(old.clone(), &members(), &verifier)
            .unwrap();
        if index == 0 {
            let mut unknown_previous = next.clone();
            unknown_previous.previous_cutoff_context_root = digest("unknown-prior-generation");
            assert!(owner
                .apply_cut_recovery_generation(unknown_previous, &verifier)
                .is_err());
            assert_eq!(owner.cutoff_context_root(), Some(&original));
            assert!(owner.cut_recovery_generation_count() == 0);
            assert_eq!(owner.local_marker(), Some(old));
            assert_eq!(owner.retained_local_marker_count(), 0);
        }
        // Late genuine VAC does not change the original signature.
        owner
            .persist_availability(certificate.clone(), &members(), &verifier)
            .unwrap();
        assert!(
            owner
                .persist_local_marker(
                    close(index, original.clone(), vec![id.clone()]),
                    &members(),
                    &verifier
                )
                .is_err()
                || index >= 3
        );
        owner
            .apply_cut_recovery_generation(next.clone(), &verifier)
            .unwrap();
        if index == 0 {
            let mut stale_previous = second.clone();
            stale_previous.previous_cutoff_context_root = original.clone();
            assert!(owner
                .apply_cut_recovery_generation(stale_previous, &verifier)
                .is_err());
            assert_eq!(owner.cutoff_context_root(), Some(&next.cutoff_context_root));
            assert_eq!(retained_generations(&owner), std::slice::from_ref(&next));
            assert_eq!(owner.retained_local_marker_count(), 1);
        }
        let marker = close(index, next.cutoff_context_root.clone(), vec![id.clone()]);
        owner
            .persist_local_marker(marker.clone(), &members(), &verifier)
            .unwrap();
        drop(owner);
        let mut owner = ProtectedPipeline::open(
            &directory,
            context.clone(),
            EtdagParameters::default(),
            original.clone(),
            format!("qualification-{index}"),
            &members(),
            &verifier,
        )
        .unwrap();
        assert_eq!(
            owner.read_retained_local_marker(0).unwrap().as_ref(),
            Some(old)
        );
        assert_eq!(owner.local_marker(), Some(&marker));
        owner
            .apply_cut_recovery_generation(second.clone(), &verifier)
            .unwrap();
        let second_marker = close(index, second.cutoff_context_root.clone(), vec![id.clone()]);
        owner
            .persist_local_marker(second_marker.clone(), &members(), &verifier)
            .unwrap();
        drop(owner);
        let mut owner = ProtectedPipeline::open(
            &directory,
            context.clone(),
            EtdagParameters::default(),
            original.clone(),
            format!("qualification-{index}"),
            &members(),
            &verifier,
        )
        .unwrap();
        assert_eq!(owner.retained_local_marker_count(), 2);
        assert_eq!(owner.local_marker(), Some(&second_marker));
        assert_eq!(owner.cut_recovery_generation_count(), 2);
        assert!(!owner
            .apply_cut_recovery_generation(next.clone(), &verifier)
            .unwrap());
        assert_eq!(owner.local_marker(), Some(&second_marker));
        let equal = (0..5)
            .map(|i| close(i, second.cutoff_context_root.clone(), vec![id.clone()]))
            .collect::<Vec<_>>();
        assert!(owner
            .accept_cut(&equal[..3], &graph, &availability, &members(), &verifier)
            .is_err());
        owner
            .accept_cut(&equal[..4], &graph, &availability, &members(), &verifier)
            .unwrap();
        let batch = owner.batch().unwrap().clone();
        assert_eq!(batch.ordered_transaction_ids.len(), 1);
        let original_markers = retained_markers(&owner);
        let generations = retained_generations(&owner);
        verifier
            .verify_cut_recovery_generation(&context, &second)
            .unwrap();
        verifier
            .verify_cut_recovery_batch_binding(&context, &second, None)
            .unwrap();
        assert_eq!(
            owner.apply_cut_recovery_generation(second.clone(), &verifier),
            Err(synergy_etdag::EtdagError::ConflictingArtifact(
                "committed protected cut cannot recover".into()
            )),
        );
        assert_eq!(owner.batch(), Some(&batch));
        assert_eq!(retained_generations(&owner), generations.as_slice());
        assert_eq!(retained_markers(&owner), original_markers);
        recovered.push(batch);
    }
    assert!(recovered.windows(2).all(|pair| pair[0] == pair[1]));

    // Durable H2 VC and QC evidence independently block an empty/unselected
    // R3 batch, exercising the production historical-evidence hook.
    let bound_context = ConsensusObjectContext::for_height(&authority.epoch, 2, 0).unwrap();
    let bound_parent = SimplifiedFinalityParent::QuorumCertificate {
        height: 1,
        block_id: qc.block_id.clone(),
        qc_id: qc.id().unwrap(),
    };
    let bound_candidate = synergy_posy::CertifiedCandidateSubject::new(
        bound_context.clone(),
        "c".repeat(64),
        qc.block_id.clone(),
        bound_parent.clone(),
        "d".repeat(64),
    )
    .unwrap();
    let echoes = (0..4)
        .map(|index| {
            let key = KeyId::new(format!("key-{index}")).unwrap();
            let signer = PqvmSigner::from_secret_key_bytes(
                AegisPolicy {
                    allowed_algorithms: vec![SignatureAlgorithm::MlDsa65],
                    maximum_message_bytes: 1024 * 1024,
                    maximum_signature_bytes: 16 * 1024,
                },
                key.clone(),
                fleet.secrets[index].clone(),
            )
            .unwrap();
            let mut statement = synergy_posy::ProposalDeliveryStatement {
                context: bound_context.clone(),
                phase: synergy_posy::ProposalDeliveryPhase::Echo,
                candidate: bound_candidate.clone(),
                validator_id: format!("qualification-{index}"),
                key_id: format!("key-{index}"),
                signature: vec![],
            };
            statement.signature = signer
                .sign(
                    &key,
                    &SigningContext {
                        domain: synergy_posy::PROPOSAL_ECHO_DOMAIN.into(),
                        chain_id: 1266,
                        epoch: Some(1),
                        height: Some(2),
                    },
                    &statement.signing_bytes().unwrap(),
                )
                .unwrap()
                .bytes;
            statement
        })
        .collect();
    let vc = ProposalValidationCertificate {
        context: bound_context.clone(),
        candidate: bound_candidate.clone(),
        echoes,
    };
    let vc_root = fleet.root.join("r3-vc-only");
    let vc_delivery =
        ProposalDelivery::open(&vc_root, &authority.epoch, &authority.registry, authority).unwrap();
    vc_delivery
        .persist_validation(&vc, &authority.epoch, &authority.registry, authority)
        .unwrap();
    let vc_only_verifier = CutRecoveryVerifier::new(fleet.authority.clone(), vc_root);
    let durable_vc_before = vc_delivery
        .stored_validation(2, &authority.epoch, &authority.registry, authority)
        .unwrap()
        .unwrap();
    let durable_vc_bytes = serde_json::to_vec(&durable_vc_before).unwrap();
    assert!(vc_only_verifier
        .verify_cut_recovery_batch_binding(&context, &next, None,)
        .is_err());
    let durable_vc_after = vc_delivery
        .stored_validation(2, &authority.epoch, &authority.registry, authority)
        .unwrap()
        .unwrap();
    assert_eq!(
        serde_json::to_vec(&durable_vc_after).unwrap(),
        durable_vc_bytes
    );

    let qc_root = fleet.root.join("r3-qc-only");
    let qcs = VerifiedQuorumCertificateStore::new(&qc_root).unwrap();
    qcs.put_verified(&qc, &authority.epoch, &authority.registry, authority)
        .unwrap();
    let h2_votes = (0..4)
        .map(|index| {
            let key = KeyId::new(format!("key-{index}")).unwrap();
            let signer = PqvmSigner::from_secret_key_bytes(
                AegisPolicy {
                    allowed_algorithms: vec![SignatureAlgorithm::MlDsa65],
                    maximum_message_bytes: 1024 * 1024,
                    maximum_signature_bytes: 16 * 1024,
                },
                key.clone(),
                fleet.secrets[index].clone(),
            )
            .unwrap();
            let mut vote = synergy_posy::BlockVote {
                context: bound_context.clone(),
                block_id: bound_candidate.block_id.clone(),
                parent_block_id: bound_candidate.parent_block_id.clone(),
                parent: bound_parent.clone(),
                takeover_tc_id: None,
                protected_execution_root: bound_candidate.protected_execution_root.clone(),
                validator_id: format!("qualification-{index}"),
                key_id: format!("key-{index}"),
                signature: vec![],
            };
            vote.signature = signer
                .sign(
                    &key,
                    &SigningContext {
                        domain: synergy_posy::POSY_SIMPLIFIED_BLOCK_VOTE_DOMAIN.into(),
                        chain_id: 1266,
                        epoch: Some(1),
                        height: Some(2),
                    },
                    &synergy_posy::block_vote_signing_bytes(&vote).unwrap(),
                )
                .unwrap()
                .bytes;
            vote
        })
        .collect();
    let h2_qc = synergy_posy::SimplifiedQuorumCertificate::from_votes(h2_votes).unwrap();
    qcs.put_verified(&h2_qc, &authority.epoch, &authority.registry, authority)
        .unwrap();
    let qc_only_verifier = CutRecoveryVerifier::new(fleet.authority.clone(), qc_root);
    let durable_h2_qc_before = qcs
        .get_verified(2, &authority.epoch, &authority.registry, authority)
        .unwrap()
        .unwrap();
    let durable_h2_qc_bytes = serde_json::to_vec(&durable_h2_qc_before).unwrap();
    assert!(qc_only_verifier
        .verify_cut_recovery_batch_binding(&context, &next, None,)
        .is_err());
    let durable_h2_qc_after = qcs
        .get_verified(2, &authority.epoch, &authority.registry, authority)
        .unwrap()
        .unwrap();
    assert_eq!(
        serde_json::to_vec(&durable_h2_qc_after).unwrap(),
        durable_h2_qc_bytes
    );

    let candidate_consensus = fleet.root.join("r3-candidate-node/data/consensus/posy");
    std::fs::create_dir_all(&candidate_consensus).unwrap();
    let candidate_verifier =
        CutRecoveryVerifier::new(fleet.authority.clone(), candidate_consensus.clone());
    let selected = recovered[0].clone();
    let material = synergy_etdag::execution::ProtectedProposalMaterial {
        material_version: 2,
        height: 2,
        execution_root: digest("r3-retained-execution"),
        next_batch_root: selected.protected_batch_root.clone(),
        cutoff_boundary_root: digest("r3-retained-cutoff"),
    };
    let state = synergy_state::WorldState::default();
    let mut candidate = synergy_execution::ExecutionCandidate {
        resource_permit: None,
        height: 2,
        block_id: String::new(),
        parent_block_id: qc.block_id.clone(),
        protected_execution_root: synergy_block::hash_block_bytes(
            &material.commitment_bytes().unwrap(),
        ),
        protected_material: material.into(),
        state_root: synergy_state::state_root(&state).unwrap(),
        transactions: vec![],
        receipts: vec![],
        state: std::sync::Arc::new(state),
    };
    candidate.block_id = candidate.commitment_id().unwrap();
    candidate.validate().unwrap();
    let data_root = candidate_consensus
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    let candidate_path =
        data_root.join("blocks/execution-candidates/candidate/00000000000000000002.json");
    std::fs::create_dir_all(candidate_path.parent().unwrap()).unwrap();
    let retained_candidate_bytes = serde_json::to_vec(&candidate).unwrap();
    std::fs::write(&candidate_path, &retained_candidate_bytes).unwrap();
    assert!(candidate_verifier
        .verify_cut_recovery_batch_binding(&context, &next, None)
        .is_err());
    assert!(candidate_verifier
        .verify_cut_recovery_batch_binding(&context, &next, Some(&selected))
        .is_ok());
    // The same recovery authority must bind the new split durable format.
    let split_root = fleet.root.join("r3-split-candidate-node/data");
    let mut split_store =
        synergy_execution::CandidateStore::new(split_root.join("blocks/execution-candidates"))
            .unwrap();
    split_store
        .put_once(&candidate, &synergy_state::WorldState::default())
        .unwrap();
    let split_verifier =
        CutRecoveryVerifier::new(fleet.authority.clone(), split_root.join("consensus/posy"));
    assert!(split_verifier
        .verify_cut_recovery_batch_binding(&context, &next, None)
        .is_err());
    assert!(split_verifier
        .verify_cut_recovery_batch_binding(&context, &next, Some(&selected))
        .is_ok());
    let mut wrong_batch = selected;
    wrong_batch.protected_batch_root = digest("different-recovered-batch");
    assert!(split_verifier
        .verify_cut_recovery_batch_binding(&context, &next, Some(&wrong_batch))
        .is_err());
    assert!(candidate_verifier
        .verify_cut_recovery_batch_binding(&context, &next, Some(&wrong_batch))
        .is_err());
    assert_eq!(
        std::fs::read(&candidate_path).unwrap(),
        retained_candidate_bytes
    );
}

pub(super) fn context(fleet: &Fleet) -> TargetAdmissionContextV3 {
    let epoch = &fleet.authority.epoch;
    TargetAdmissionContextV3 {
        context_version: 1,
        chain_id: epoch.chain_id,
        network_id: epoch.network_id.clone(),
        protocol_version: epoch.protocol_version.clone(),
        epoch: epoch.epoch,
        target_height: 3,
        target_height_offset: 5,
        source_finalized_height: 0,
        source_finality_context_root: "d".repeat(64),
        active_validator_set_root: epoch.active_validator_set_root.clone(),
        validator_consensus_key_root: epoch.validator_consensus_key_root.clone(),
        frozen_voting_weight_root: epoch.frozen_voting_weight_root.clone(),
        cluster_schedule_version: "qualification".into(),
        finalized_epoch_seed_root: epoch.finalized_epoch_seed_root.clone(),
        assigned_height_schedule_root: "e".repeat(64),
        cluster_map_root: "f".repeat(64),
        assigned_cluster_id: 0,
        assigned_cluster_membership_root: epoch.active_validator_set_root.clone(),
        assigned_cluster_validator_count: 5,
        assigned_cluster_total_voting_weight: 5,
        consensus_parameter_root: epoch.consensus_parameter_root.clone(),
        cryptographic_profile_root: "a".repeat(64),
        ingress_kem_registry_root: digest("kem-registry"),
    }
}

// Structural fixture only: these tests qualify availability and durable cutoff,
// not encryption. Crypto qualification uses the real provider separately.
fn opaque_envelope(
    context: &TargetAdmissionContextV3,
    envelope_id: EtdagDigest,
    nonce_slot: u64,
) -> synergy_etdag::EncryptedTransactionEnvelope {
    use synergy_etdag::crypto::EnvelopeAad;
    use synergy_etdag::{EncryptedTransactionEnvelope, ShareCapsule};
    let root = context.root().unwrap();
    let mut envelope = EncryptedTransactionEnvelope {
        envelope_version: 2,
        envelope_id,
        target_context_root: root.clone(),
        target_height: context.target_height,
        aad: EnvelopeAad {
            profile_id: synergy_etdag::ETDAG_PROFILE_ID.into(),
            chain_id: context.chain_id,
            network_id: context.network_id.clone(),
            protocol_version: context.protocol_version.clone(),
            epoch: context.epoch,
            target_height: context.target_height,
            target_context_root: root,
            assigned_cluster_id: context.assigned_cluster_id,
            lane_id: "ordinary-user".into(),
            sender_id: "alice".into(),
            nonce_slot,
        },
        aead_nonce: [0; 12],
        key_commitment: digest("fixture-key-commitment"),
        share_commitment_root: digest("pending"),
        share_capsule_root: digest("pending"),
        ciphertext: vec![42; 512],
        content_blind_order_key: digest("opaque-order-key"),
        share_capsules: vec![ShareCapsule {
            validator_id: "qualification-0".into(),
            ingress_kem_key_id: "ingress-key-0".into(),
            share_index: 1,
            share_commitment: digest("fixture-share-commitment"),
            kem_ciphertext: vec![1; synergy_etdag::crypto::ML_KEM_1024_CIPHERTEXT_BYTES],
            aead_nonce: [0; 12],
            encrypted_share: vec![2; 48],
        }],
    };
    envelope.refresh_capsule_roots().unwrap();
    envelope
}

fn sign(fleet: &Fleet, index: usize, bytes: &[u8]) -> Vec<u8> {
    let key = KeyId::new(format!("key-{index}")).unwrap();
    let signer = PqvmSigner::from_secret_key_bytes(
        AegisPolicy {
            allowed_algorithms: vec![SignatureAlgorithm::MlDsa65],
            maximum_message_bytes: 1024 * 1024,
            maximum_signature_bytes: 16 * 1024,
        },
        key.clone(),
        fleet.secrets[index].clone(),
    )
    .unwrap();
    signer
        .sign(
            &key,
            &SigningContext {
                domain: "SYNERGY-ETDAG-SIGNATURE-V1".into(),
                chain_id: 1266,
                epoch: Some(1),
                height: None,
            },
            bytes,
        )
        .unwrap()
        .bytes
}

fn markers(
    fleet: &Fleet,
    context: &TargetAdmissionContextV3,
    frontier: Vec<EtdagDigest>,
) -> Vec<ProtectedCutMarker> {
    (0..5)
        .map(|index| {
            let mut marker = ProtectedCutMarker {
                marker_version: 1,
                context_root: context.root().unwrap(),
                target_height: context.target_height,
                cutoff_context_root: digest("cutoff"),
                frontier: frontier.clone(),
                validator_id: format!("qualification-{index}"),
                key_id: format!("key-{index}"),
                signature: vec![],
            };
            marker.signature = sign(fleet, index, &marker.signing_bytes().unwrap());
            marker
        })
        .collect()
}

fn members() -> CutoffMembers {
    (0..5)
        .map(|i| (format!("qualification-{i}"), (format!("key-{i}"), 1)))
        .collect()
}

#[test]
fn cutoff_requires_real_dual_quorum_and_has_subset_independent_empty_semantics() {
    let fleet = Fleet::new();
    let context = context(&fleet);
    let graph = EtdagGraph::new(context.root().unwrap(), 3).unwrap();
    let markers = markers(&fleet, &context, vec![]);
    let certificates = BTreeMap::new();
    let members = members();
    let derive = |m: &[ProtectedCutMarker]| {
        ProtectedCutProof::derive(
            &context,
            &digest("cutoff"),
            m,
            &graph,
            &certificates,
            &members,
            fleet.authority.as_ref(),
        )
    };
    assert!(derive(&markers[..3]).is_err());
    let first = derive(&markers[..4]).unwrap();
    let second = derive(&markers[1..]).unwrap();
    assert!(first.vertices().is_empty());
    assert_eq!(first.semantic_root(), second.semantic_root());
    let first_batch = synergy_etdag::DeterministicProtectedBatch::derive(
        &first,
        &digest("order-seed"),
        &synergy_etdag::EtdagParameters::default(),
    )
    .unwrap();
    let second_batch = synergy_etdag::DeterministicProtectedBatch::derive(
        &second,
        &digest("order-seed"),
        &synergy_etdag::EtdagParameters::default(),
    )
    .unwrap();
    assert_eq!(first_batch, second_batch);
    assert!(first_batch.ordered_transaction_ids.is_empty());
    assert_eq!(
        (first_batch.protected_gas, first_batch.protected_bytes),
        (0, 0)
    );
    assert_ne!(first.proof().markers, second.proof().markers);
    let mut reordered = markers[..4].to_vec();
    reordered.reverse();
    assert_eq!(first, derive(&reordered).unwrap());
    let mut tampered = markers[..4].to_vec();
    tampered[0].signature[0] ^= 1;
    assert!(derive(&tampered).is_err());
    let mut duplicate = markers[..4].to_vec();
    duplicate[3] = duplicate[0].clone();
    assert!(derive(&duplicate).is_err());
    let mut wrong_target = markers[..4].to_vec();
    wrong_target[0].target_height = 4;
    assert!(derive(&wrong_target).is_err());
    assert!(ProtectedCutProof::derive(
        &context,
        &digest("other-cutoff"),
        &markers,
        &graph,
        &certificates,
        &members,
        fleet.authority.as_ref()
    )
    .is_err());
    let mut heavy_members = members.clone();
    heavy_members.get_mut("qualification-4").unwrap().1 = 100;
    let mut heavy_context = context.clone();
    heavy_context.assigned_cluster_total_voting_weight = 104;
    let heavy_graph = EtdagGraph::new(heavy_context.root().unwrap(), 3).unwrap();
    let heavy_markers = self::markers(&fleet, &heavy_context, vec![]);
    assert!(ProtectedCutProof::derive(
        &heavy_context,
        &digest("cutoff"),
        &heavy_markers[..4],
        &heavy_graph,
        &certificates,
        &heavy_members,
        fleet.authority.as_ref()
    )
    .is_err());
}

#[test]
fn cutoff_missing_certified_frontier_never_becomes_an_empty_batch() {
    let fleet = Fleet::new();
    let context = context(&fleet);
    let graph = EtdagGraph::new(context.root().unwrap(), 3).unwrap();
    let markers = markers(&fleet, &context, vec![digest("missing-vertex")]);
    assert!(matches!(
        ProtectedCutProof::derive(
            &context,
            &digest("cutoff"),
            &markers,
            &graph,
            &BTreeMap::new(),
            &members(),
            fleet.authority.as_ref()
        ),
        Err(synergy_etdag::EtdagError::MissingArtifact(_))
    ));
}

#[test]
fn certified_cut_preserves_ancestors_nonce_order_and_governed_capacity() {
    use synergy_etdag::{
        AvailabilityCertificate, AvailabilityVote, CertifiedEnvelopeRef,
        DeterministicProtectedBatch, EtdagParameters, TransactionVertex,
    };
    let fleet = Fleet::new();
    let context = context(&fleet);
    let root = context.root().unwrap();
    let mut graph = EtdagGraph::new(root.clone(), 3).unwrap();
    let mut certificates = BTreeMap::new();
    let mut ids = Vec::new();
    for index in 0..2 {
        let commitment = digest(&format!("transaction-{index}"));
        let mut vertex = TransactionVertex {
            vertex_id: digest("pending"),
            target_context_root: root.clone(),
            target_height: 3,
            envelope: opaque_envelope(&context, commitment.clone(), index),
            envelope_ref: CertifiedEnvelopeRef {
                tx_commitment: commitment,
                sender_id: "alice".into(),
                nonce_slot: index,
                certified_dag_round: index,
                gas_class_units: 10,
                ciphertext_bytes: 512,
                fee_class: 1,
                protocol_dependencies: vec![],
            },
            parents: ids.clone(),
            author_id: "qualification-0".into(),
            author_signature: vec![],

            wallet_admission: None,
        };
        vertex.vertex_id = synergy_etdag::dag::derive_vertex_id(&vertex).unwrap();
        vertex.author_signature = sign(&fleet, 0, vertex.vertex_id.0.as_bytes());
        let id = vertex.vertex_id.clone();
        graph.insert(vertex).unwrap();
        let votes = (0..4)
            .map(|i| {
                let mut vote = AvailabilityVote {
                    context_root: root.clone(),
                    vertex_id: id.clone(),
                    validator_id: format!("qualification-{i}"),
                    key_id: format!("key-{i}"),
                    signature: vec![],
                };
                let bytes = synergy_etdag::crypto::canonical_signing_bytes(
                    "SYNERGY_ETDAG_AVAILABILITY_VOTE_V1",
                    &(
                        &vote.context_root,
                        &vote.vertex_id,
                        &vote.validator_id,
                        &vote.key_id,
                    ),
                )
                .unwrap();
                vote.signature = sign(&fleet, i, &bytes);
                vote
            })
            .collect();
        certificates.insert(
            id.clone(),
            AvailabilityCertificate::from_votes(root.clone(), id.clone(), votes, 5).unwrap(),
        );
        ids.push(id);
    }
    let markers = markers(&fleet, &context, vec![ids[1].clone()]);
    let cut = ProtectedCutProof::derive(
        &context,
        &digest("cutoff"),
        &markers,
        &graph,
        &certificates,
        &members(),
        fleet.authority.as_ref(),
    )
    .unwrap();
    assert_eq!(cut.vertices().len(), 2);
    // Four empty close statements can establish an empty cut. Substituting
    // a fifth signer's different frontier must not establish another cut.
    let mut mixed = markers.clone();
    for (index, marker) in mixed.iter_mut().take(4).enumerate() {
        marker.frontier.clear();
        marker.signature = sign(&fleet, index, &marker.signing_bytes().unwrap());
    }
    let empty = ProtectedCutProof::derive(
        &context,
        &digest("cutoff"),
        &mixed[..4],
        &graph,
        &certificates,
        &members(),
        fleet.authority.as_ref(),
    )
    .unwrap();
    assert!(empty.vertices().is_empty());
    assert!(
        ProtectedCutProof::derive(
            &context,
            &digest("cutoff"),
            &mixed[1..],
            &graph,
            &certificates,
            &members(),
            fleet.authority.as_ref(),
        )
        .is_err(),
        "different quorum subsets must not certify different causal cuts"
    );
    let mut redundant = markers.clone();
    redundant[0].frontier = ids.clone();
    redundant[0].frontier.sort();
    redundant[0].signature = sign(&fleet, 0, &redundant[0].signing_bytes().unwrap());
    let equivalent = ProtectedCutProof::derive(
        &context,
        &digest("cutoff"),
        &redundant[..4],
        &graph,
        &certificates,
        &members(),
        fleet.authority.as_ref(),
    )
    .unwrap();
    assert_eq!(equivalent.semantic_root(), cut.semantic_root());
    let batch = DeterministicProtectedBatch::derive(
        &cut,
        &digest("order-seed"),
        &EtdagParameters::default(),
    )
    .unwrap();
    assert_eq!(
        batch.ordered_transaction_ids,
        vec![digest("transaction-0"), digest("transaction-1")]
    );
    assert_eq!(batch.protected_gas, 20);
    assert_eq!(batch.protected_bytes, 1024);
    let limited = EtdagParameters {
        max_protected_gas: 10,
        ..EtdagParameters::default()
    };
    let prefix =
        DeterministicProtectedBatch::derive(&cut, &digest("order-seed"), &limited).unwrap();
    assert_eq!(
        prefix.ordered_transaction_ids,
        vec![digest("transaction-0")]
    );
    assert_ne!(batch.protected_batch_root, prefix.protected_batch_root);
    certificates.remove(&ids[0]);
    assert!(matches!(
        ProtectedCutProof::derive(
            &context,
            &digest("cutoff"),
            &markers,
            &graph,
            &certificates,
            &members(),
            fleet.authority.as_ref()
        ),
        Err(synergy_etdag::EtdagError::MissingArtifact(_))
    ));
}

#[test]
fn reveal_requires_exact_parent_quorum_and_committed_future_material() {
    use synergy_etdag::execution::{ParentProposalRevealEvidence, ProtectedProposalMaterial};
    use synergy_etdag::reveal::{parent_reveal_reference, RevealGate, VerifiedRevealAuthorization};
    use synergy_etdag::{
        DeterministicProtectedBatch, EtdagParameters, ProtectedRevealAuthorization,
    };
    let mut fleet = Fleet::new();
    let original_cutoff_vc = fleet.validate_protected_parent(&ProtectedProposalMaterial {
        material_version: 2,
        height: 1,
        execution_root: digest("consumed-H1"),
        next_batch_root: digest("consumed-H2"),
        cutoff_boundary_root: digest("consumed-H3"),
    });
    let cutoff = EtdagDigest::from_domain_bytes(
        "SYNERGY_ETDAG_CUTOFF_VC_V1",
        original_cutoff_vc.id().unwrap().as_bytes(),
    );
    let context = context(&fleet);
    let graph = EtdagGraph::new(context.root().unwrap(), 3).unwrap();
    let mut markers = markers(&fleet, &context, vec![]);
    for (index, marker) in markers.iter_mut().enumerate() {
        marker.cutoff_context_root = cutoff.clone();
        marker.signature = sign(&fleet, index, &marker.signing_bytes().unwrap());
    }
    let cut = ProtectedCutProof::derive(
        &context,
        &cutoff.clone(),
        &markers,
        &graph,
        &BTreeMap::new(),
        &members(),
        fleet.authority.as_ref(),
    )
    .unwrap();
    let batch = DeterministicProtectedBatch::derive(
        &cut,
        &synergy_etdag::ordering::derive_target_order_seed(&context, &cut).unwrap(),
        &EtdagParameters::default(),
    )
    .unwrap();
    use synergy_etdag::persistence::ProtectedPipeline;
    let directory = fleet.root.join("protected-pipeline");
    let mut pipeline = ProtectedPipeline::open(
        &directory,
        context.clone(),
        EtdagParameters::default(),
        cutoff.clone(),
        "qualification-0".into(),
        &members(),
        fleet.authority.as_ref(),
    )
    .unwrap();
    assert!(pipeline.prepared().is_none());
    assert!(pipeline
        .accept_cut(
            &markers,
            &graph,
            &BTreeMap::new(),
            &members(),
            fleet.authority.as_ref()
        )
        .unwrap());
    assert_eq!(pipeline.batch(), Some(&batch));
    assert!(!pipeline
        .accept_cut(
            &markers[1..],
            &graph,
            &BTreeMap::new(),
            &members(),
            fleet.authority.as_ref()
        )
        .unwrap());
    let material = ProtectedProposalMaterial {
        material_version: 2,
        height: 2,
        execution_root: digest("genesis-bootstrap-H2"),
        next_batch_root: batch.protected_batch_root.clone(),
        cutoff_boundary_root: digest("H4-boundary-descriptor"),
    };
    let certificate = fleet.validate_protected_parent(&material);
    let evidence = ParentProposalRevealEvidence {
        material,
        next_batch: batch.clone(),
        validation_proof: serde_json::to_vec(&certificate).unwrap(),
    };
    let mut authorization = ProtectedRevealAuthorization {
        authorization_version: 1,
        context_root: context.root().unwrap(),
        target_height: 3,
        protected_batch_root: batch.protected_batch_root,
        finality_reference: digest("pending"),
    };
    authorization.finality_reference = parent_reveal_reference(
        &certificate.candidate.block_id,
        &certificate.id().unwrap(),
        &authorization,
    )
    .unwrap();
    let verified = VerifiedRevealAuthorization::verify(
        authorization.clone(),
        &evidence,
        fleet.authority.as_ref(),
    )
    .unwrap();
    let mut gate = RevealGate::new(
        authorization.context_root.clone(),
        3,
        authorization.protected_batch_root.clone(),
    )
    .unwrap();
    assert!(gate.authorization().is_err());
    gate.authorize(verified.clone()).unwrap();
    assert_eq!(
        gate.authorization().unwrap().authorization(),
        &authorization
    );
    let empty_transcript = EtdagDigest::from_canonical(
        "SYNERGY_ETDAG_BATCH_REVEAL_TRANSCRIPTS_V1",
        &Vec::<(EtdagDigest, EtdagDigest)>::new(),
    )
    .unwrap();
    let input = synergy_etdag::DeterministicProtectedExecutionInput::from_batch(
        &evidence.next_batch,
        &BTreeMap::new(),
        empty_transcript,
    )
    .unwrap();
    input.validate().unwrap();
    let prepared = synergy_etdag::execution::prepare_deterministic_batch(
        context.clone(),
        &input,
        &BTreeMap::new(),
        &[],
        &verified,
        evidence.clone(),
    )
    .unwrap();
    prepared.validate().unwrap();
    assert!(prepared.transactions.is_empty());
    assert!(!super::execution::protected_parent_ready(&prepared, None).unwrap());
    assert!(super::execution::protected_parent_ready(&prepared, Some(&certificate)).unwrap());
    let mut other_parent = certificate.clone();
    other_parent.candidate.block_id = "other-parent".into();
    assert!(super::execution::protected_parent_ready(&prepared, Some(&other_parent)).is_err());
    assert!(pipeline
        .prepare_empty(
            authorization.clone(),
            evidence.clone(),
            fleet.authority.as_ref()
        )
        .unwrap());
    assert_eq!(pipeline.prepared(), Some(&prepared));
    drop(pipeline);
    let mut pipeline = ProtectedPipeline::open(
        &directory,
        context.clone(),
        EtdagParameters::default(),
        cutoff.clone(),
        "qualification-0".into(),
        &members(),
        fleet.authority.as_ref(),
    )
    .unwrap();
    assert_eq!(pipeline.prepared(), Some(&prepared));
    assert!(ProtectedPipeline::open(
        &directory,
        context.clone(),
        EtdagParameters::default(),
        digest("another-cutoff"),
        "qualification-0".into(),
        &members(),
        fleet.authority.as_ref(),
    )
    .is_err());
    assert!(!pipeline
        .prepare_empty(
            authorization.clone(),
            evidence.clone(),
            fleet.authority.as_ref()
        )
        .unwrap());
    assert!(pipeline
        .mark_consumed(&prepared.protected_batch_root)
        .unwrap());
    assert!(!pipeline
        .mark_consumed(&prepared.protected_batch_root)
        .unwrap());
    let consumed_record =
        ProtectedPipeline::read_durable_evidence(&directory, context.target_height)
            .unwrap()
            .unwrap();
    assert_eq!(consumed_record["committed"]["consumed"], true);
    assert!(!consumed_record["committed"].is_null());
    let consumed_batch = pipeline.batch().unwrap().clone();
    drop(pipeline);
    let mut pipeline = ProtectedPipeline::open(
        &directory,
        context.clone(),
        EtdagParameters::default(),
        cutoff.clone(),
        "qualification-0".into(),
        &members(),
        fleet.authority.as_ref(),
    )
    .unwrap();
    // Consumption preserves the committed record that excludes cut recovery.
    assert_eq!(pipeline.batch(), Some(&consumed_batch));
    assert_eq!(pipeline.prepared(), Some(&prepared));
    assert!(!pipeline
        .mark_consumed(&prepared.protected_batch_root)
        .unwrap());
    // Model a retained consumed owner whose recovery proof store has not yet
    // received H2 certification. The consumed record must independently block
    // a genuine no-carry recovery authorization even in this arrival order.
    let recovery_root = fleet.root.join("consumed-recovery-proof");
    let authority = fleet.authority.as_ref();
    let original = synergy_posy::ProposalDelivery::open(
        &fleet.root.join("node-0"),
        &authority.epoch,
        &authority.registry,
        authority,
    )
    .unwrap()
    .stored_validation(1, &authority.epoch, &authority.registry, authority)
    .unwrap()
    .unwrap();
    let qc = synergy_posy::VerifiedQuorumCertificateStore::new(fleet.root.join("node-0"))
        .unwrap()
        .get_verified(1, &authority.epoch, &authority.registry, authority)
        .unwrap()
        .unwrap();
    synergy_posy::VerifiedQuorumCertificateStore::new(&recovery_root)
        .unwrap()
        .put_verified(&qc, &authority.epoch, &authority.registry, authority)
        .unwrap();
    synergy_posy::ProposalDelivery::open(
        &recovery_root,
        &authority.epoch,
        &authority.registry,
        authority,
    )
    .unwrap()
    .persist_validation(&original, &authority.epoch, &authority.registry, authority)
    .unwrap();
    let reports = (0..4)
        .map(|index| {
            let key = KeyId::new(format!("key-{index}")).unwrap();
            let signer = PqvmSigner::from_secret_key_bytes(
                AegisPolicy {
                    allowed_algorithms: vec![SignatureAlgorithm::MlDsa65],
                    maximum_message_bytes: 1024 * 1024,
                    maximum_signature_bytes: 16 * 1024,
                },
                key.clone(),
                fleet.secrets[index].clone(),
            )
            .unwrap();
            let mut vote = synergy_posy::TimeoutVote {
                context: synergy_posy::ConsensusObjectContext::for_height(&authority.epoch, 2, 0)
                    .unwrap(),
                lease_index: authority.epoch.lease_index(2).unwrap(),
                timed_out_proposer: authority.epoch.authorized_proposer(2, 0).unwrap().into(),
                highest_parent: synergy_posy::SimplifiedFinalityParent::QuorumCertificate {
                    height: 1,
                    block_id: qc.block_id.clone(),
                    qc_id: qc.id().unwrap(),
                },
                previous_tc_id: None,
                last_voted_candidate: None,
                validator_id: format!("qualification-{index}"),
                key_id: format!("key-{index}"),
                signature: vec![],
            };
            vote.signature = signer
                .sign(
                    &key,
                    &SigningContext {
                        domain: synergy_posy::POSY_SIMPLIFIED_TIMEOUT_VOTE_DOMAIN.into(),
                        chain_id: 1266,
                        epoch: Some(1),
                        height: Some(2),
                    },
                    &synergy_posy::timeout_vote_signing_bytes(&vote).unwrap(),
                )
                .unwrap()
                .bytes;
            vote
        })
        .collect();
    let tc =
        synergy_posy::SimplifiedTimeoutCertificate::from_votes_with_qc_proofs(reports, vec![qc])
            .unwrap();
    synergy_posy::VerifiedTimeoutCertificateStore::new(&recovery_root)
        .unwrap()
        .put_verified(&tc, &authority.epoch, &authority.registry, authority)
        .unwrap();
    let generation = super::cut_recovery::generation_from_certificates(
        3,
        &original,
        EtdagDigest::from_domain_bytes(
            "SYNERGY_ETDAG_CUTOFF_VC_V1",
            original.id().unwrap().as_bytes(),
        ),
        &[tc],
    )
    .unwrap();
    let verifier =
        super::cut_recovery::CutRecoveryVerifier::new(fleet.authority.clone(), recovery_root);
    use synergy_etdag::persistence::ProtectedRecoveryVerifier;
    verifier
        .verify_cut_recovery_generation(&context, &generation)
        .unwrap();
    verifier
        .verify_cut_recovery_batch_binding(&context, &generation, None)
        .unwrap();
    let record_path = directory.join(format!("protected-h{}.json", context.target_height));
    let before = std::fs::read(&record_path).unwrap();
    let markers = retained_markers(&pipeline);
    let generations = retained_generations(&pipeline);
    assert_eq!(
        pipeline.apply_cut_recovery_generation(generation, &verifier),
        Err(synergy_etdag::EtdagError::ConflictingArtifact(
            "committed protected cut cannot recover".into()
        ))
    );
    assert_eq!(std::fs::read(record_path).unwrap(), before);
    assert_eq!(retained_markers(&pipeline), markers);
    assert_eq!(retained_generations(&pipeline), generations.as_slice());
    let mut wrong_material = evidence.clone();
    wrong_material.material.cutoff_boundary_root = digest("other-frontier");
    assert!(VerifiedRevealAuthorization::verify(
        authorization.clone(),
        &wrong_material,
        fleet.authority.as_ref()
    )
    .is_err());
    let mut wrong_target = authorization.clone();
    wrong_target.target_height = 4;
    assert!(
        VerifiedRevealAuthorization::verify(wrong_target, &evidence, fleet.authority.as_ref())
            .is_err()
    );
    let mut wrong_context = authorization.clone();
    wrong_context.context_root = digest("other-context");
    assert!(VerifiedRevealAuthorization::verify(
        wrong_context,
        &evidence,
        fleet.authority.as_ref()
    )
    .is_err());
    let mut no_quorum = certificate.clone();
    no_quorum.echoes.truncate(3);
    let mut missing = evidence.clone();
    missing.validation_proof = serde_json::to_vec(&no_quorum).unwrap();
    assert!(
        VerifiedRevealAuthorization::verify(authorization, &missing, fleet.authority.as_ref())
            .is_err()
    );
}

#[test]
fn cutoff_statement_survives_restart_before_quorum_and_cannot_equivocate() {
    use synergy_etdag::persistence::ProtectedPipeline;
    use synergy_etdag::EtdagParameters;
    let fleet = Fleet::new();
    let context = context(&fleet);
    let directory = fleet.root.join("cutoff-restart");
    let signed = markers(&fleet, &context, vec![]);
    let open = || {
        ProtectedPipeline::open(
            &directory,
            context.clone(),
            EtdagParameters::default(),
            digest("cutoff"),
            "qualification-0".into(),
            &members(),
            fleet.authority.as_ref(),
        )
    };
    let mut pipeline = open().unwrap();
    assert!(pipeline
        .persist_local_marker(signed[0].clone(), &members(), fleet.authority.as_ref())
        .unwrap());
    assert!(pipeline.batch().is_none());
    drop(pipeline);
    let mut pipeline = open().unwrap();
    assert_eq!(pipeline.local_marker(), Some(&signed[0]));
    assert!(!pipeline
        .persist_local_marker(signed[0].clone(), &members(), fleet.authority.as_ref())
        .unwrap());
    let mut changed = signed[0].clone();
    changed.frontier = vec![digest("later-vertex")];
    changed.signature = sign(&fleet, 0, &changed.signing_bytes().unwrap());
    assert!(matches!(
        pipeline.persist_local_marker(changed, &members(), fleet.authority.as_ref()),
        Err(synergy_etdag::EtdagError::ConflictingArtifact(_))
    ));
    assert!(pipeline
        .persist_local_marker(signed[1].clone(), &members(), fleet.authority.as_ref())
        .is_err());
    drop(pipeline);
    assert_eq!(open().unwrap().local_marker(), Some(&signed[0]));
    let path = directory.join("protected-h3.json");
    let mut stored: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    stored["local_marker"]["signature"][0] =
        serde_json::json!(stored["local_marker"]["signature"][0].as_u64().unwrap() ^ 1);
    std::fs::write(&path, serde_json::to_vec(&stored).unwrap()).unwrap();
    assert!(
        open().is_err(),
        "recovery must authenticate persisted local evidence"
    );
}

#[test]
fn availability_custody_votes_survive_restart_and_cutoff_closes_new_signatures() {
    use synergy_etdag::persistence::ProtectedPipeline;
    use synergy_etdag::{
        AvailabilityVote, CertifiedEnvelopeRef, EtdagParameters, TransactionVertex,
    };
    let fleet = Fleet::new();
    let context = context(&fleet);
    let root = context.root().unwrap();
    let directory = fleet.root.join("durable-availability");
    let members = members();
    let make_vertex = |nonce: u64| {
        let id = digest(&format!("durable-ciphertext-{nonce}"));
        let mut vertex = TransactionVertex {
            vertex_id: digest("pending"),
            target_context_root: root.clone(),
            target_height: 3,
            envelope: opaque_envelope(&context, id.clone(), nonce),
            envelope_ref: CertifiedEnvelopeRef {
                tx_commitment: id,
                sender_id: "alice".into(),
                nonce_slot: nonce,
                certified_dag_round: nonce,
                gas_class_units: 10,
                ciphertext_bytes: 512,
                fee_class: 1,
                protocol_dependencies: vec![],
            },
            parents: vec![],
            author_id: "qualification-0".into(),
            author_signature: vec![],

            wallet_admission: None,
        };
        vertex.vertex_id = synergy_etdag::dag::derive_vertex_id(&vertex).unwrap();
        vertex.author_signature = sign(&fleet, 0, vertex.vertex_id.0.as_bytes());
        vertex
    };
    let vote = |index: usize, vertex: &EtdagDigest| {
        let mut vote = AvailabilityVote {
            context_root: root.clone(),
            vertex_id: vertex.clone(),
            validator_id: format!("qualification-{index}"),
            key_id: format!("key-{index}"),
            signature: vec![],
        };
        let bytes = synergy_etdag::crypto::canonical_signing_bytes(
            "SYNERGY_ETDAG_AVAILABILITY_VOTE_V1",
            &(
                &vote.context_root,
                &vote.vertex_id,
                &vote.validator_id,
                &vote.key_id,
            ),
        )
        .unwrap();
        vote.signature = sign(&fleet, index, &bytes);
        vote
    };
    let mut owner = ProtectedPipeline::open_collecting(
        &directory,
        context.clone(),
        EtdagParameters::default(),
        "qualification-0".into(),
        &members,
        fleet.authority.as_ref(),
    )
    .unwrap();
    let vertex = make_vertex(0);
    let id = vertex.vertex_id.clone();
    owner
        .persist_vertex(vertex, &members, fleet.authority.as_ref())
        .unwrap();
    let original = vote(0, &id);
    owner
        .persist_local_vote(original.clone(), &members, fleet.authority.as_ref())
        .unwrap();
    for index in 1..3 {
        owner
            .persist_vote(vote(index, &id), &members, fleet.authority.as_ref())
            .unwrap();
    }
    assert!(owner
        .assembled_availability(&id, &members, fleet.authority.as_ref())
        .is_err());
    owner
        .persist_vote(vote(3, &id), &members, fleet.authority.as_ref())
        .unwrap();
    let certificate = owner
        .assembled_availability(&id, &members, fleet.authority.as_ref())
        .unwrap();
    owner
        .persist_availability(certificate.clone(), &members, fleet.authority.as_ref())
        .unwrap();
    let mut tampered = vote(4, &id);
    tampered.signature[0] ^= 1;
    assert!(owner
        .persist_vote(tampered, &members, fleet.authority.as_ref())
        .is_err());
    drop(owner);
    let mut owner = ProtectedPipeline::open_collecting(
        &directory,
        context.clone(),
        EtdagParameters::default(),
        "qualification-0".into(),
        &members,
        fleet.authority.as_ref(),
    )
    .unwrap();
    assert_eq!(owner.local_votes().get(&id), Some(&original));
    assert_eq!(owner.availability().get(&id), Some(&certificate));
    assert_eq!(owner.graph().len(), 1);
    owner.bind_cutoff(digest("accepted-vc1")).unwrap();
    let second = make_vertex(1);
    let second_id = second.vertex_id.clone();
    owner
        .persist_vertex(second, &members, fleet.authority.as_ref())
        .unwrap();
    assert_eq!(
        owner.persist_local_vote(vote(0, &second_id), &members, fleet.authority.as_ref()),
        Err(synergy_etdag::EtdagError::AdmissionClosed)
    );
    drop(owner);
    assert!(ProtectedPipeline::open_collecting(
        &directory,
        context.clone(),
        EtdagParameters::default(),
        "qualification-0".into(),
        &members,
        fleet.authority.as_ref()
    )
    .is_err());
    assert!(ProtectedPipeline::open(
        &directory,
        context.clone(),
        EtdagParameters::default(),
        digest("wrong-cutoff"),
        "qualification-0".into(),
        &members,
        fleet.authority.as_ref()
    )
    .is_err());
    let owner = ProtectedPipeline::open(
        &directory,
        context,
        EtdagParameters::default(),
        digest("accepted-vc1"),
        "qualification-0".into(),
        &members,
        fleet.authority.as_ref(),
    )
    .unwrap();
    assert!(owner.admission_closed());
    assert!(!owner.local_votes().contains_key(&second_id));
}

#[test]
fn registration_restores_cutoff_vc_before_closed_target_reopens() {
    use synergy_etdag::{
        execution::ProtectedProposalMaterial, persistence::ProtectedPipeline, EtdagParameters,
    };
    let mut fleet = Fleet::new();
    let material = ProtectedProposalMaterial {
        material_version: 2,
        height: 2,
        execution_root: digest("H2"),
        next_batch_root: digest("H3"),
        cutoff_boundary_root: digest("H4"),
    };
    fleet.validate_protected_parent(&material);
    let fresh_ingress = super::ingress::AuthenticatedIngress::default();
    assert!(fresh_ingress
        .protected_cutoff_authority(3)
        .unwrap()
        .is_none());
    // This is the exact restore called during registration, before start_all.
    fleet.restore_registration_validation(&fresh_ingress);
    let cutoff = fresh_ingress
        .protected_cutoff_authority(3)
        .unwrap()
        .unwrap();
    let context = context(&fleet);
    let root = fleet.root.join("closed-pipeline-startup");
    let mut pipeline = ProtectedPipeline::open_collecting(
        &root,
        context.clone(),
        EtdagParameters::default(),
        "qualification-0".into(),
        &members(),
        fleet.authority.as_ref(),
    )
    .unwrap();
    pipeline.bind_cutoff(cutoff.clone()).unwrap();
    drop(pipeline);
    assert!(ProtectedPipeline::open_collecting(
        &root,
        context.clone(),
        EtdagParameters::default(),
        "qualification-0".into(),
        &members(),
        fleet.authority.as_ref()
    )
    .is_err());
    let reopened = ProtectedPipeline::open(
        &root,
        context,
        EtdagParameters::default(),
        cutoff,
        "qualification-0".into(),
        &members(),
        fleet.authority.as_ref(),
    )
    .unwrap();
    assert!(reopened.admission_closed());
}

#[test]
fn genuine_nonempty_threshold_reveal_survives_restart_and_rejects_disk_tampering() {
    use aegis_pqvm::pqc::kem::mlkem::mlkem1024;
    use pqrust_traits::kem::{PublicKey as _, SecretKey as _};
    use synergy_etdag::{
        crypto::{
            decrypt_share_capsule, encrypt_protected_payload, pad_plaintext, EnvelopeAad,
            GovernedThresholdDecryptor,
        },
        execution::{ParentProposalRevealEvidence, ProtectedProposalMaterial},
        persistence::ProtectedPipeline,
        reveal::{
            decrypt_authorized_envelope, parent_reveal_reference, verify_decrypt_share,
            RevealTranscript, VerifiedRevealAuthorization, VerifiedShareCollector,
        },
        AvailabilityCertificate, AvailabilityVote, CertifiedEnvelopeRef, DecryptShareMessage,
        EtdagParameters, IngressKemKeyRecord, IngressKemKeyRegistry, IngressKemPublicKey,
        ProtectedRevealAuthorization, TransactionVertex,
    };
    // The authority fixture is unsigned; custody encryption, availability/cutoff
    // signatures, parent PoSy VC, and reveal signatures all use real primitives.
    let mut fleet = Fleet::new();
    let mut kem_secrets = Vec::new();
    let records = (0..5)
        .map(|index| {
            let (public, secret) = mlkem1024::keypair();
            kem_secrets.push(secret.as_bytes().to_vec());
            IngressKemKeyRecord {
                key_id: format!("ingress-key-{index}"),
                validator_id: format!("qualification-{index}"),
                public_key: IngressKemPublicKey {
                    algorithm: "ML-KEM-1024".into(),
                    public_key: public.as_bytes().to_vec(),
                },
                activation_height: 1,
                retirement_height: None,
            }
        })
        .collect::<Vec<_>>();
    let registry = IngressKemKeyRegistry {
        context_root: digest("governed-static-ingress"),
        records,
    };
    registry.validate_protected_profile().unwrap();
    fleet.authority =
        std::sync::Arc::new(fleet.authority.qualification_with_ingress(registry.clone()));
    let mut context = context(&fleet);
    context.ingress_kem_registry_root = registry.root().unwrap();
    let root = context.root().unwrap();
    let aad = EnvelopeAad {
        profile_id: synergy_etdag::ETDAG_PROFILE_ID.into(),
        chain_id: context.chain_id,
        network_id: context.network_id.clone(),
        protocol_version: context.protocol_version.clone(),
        epoch: context.epoch,
        target_height: 3,
        target_context_root: root.clone(),
        assigned_cluster_id: context.assigned_cluster_id,
        lane_id: "ordinary-user".into(),
        sender_id: "alice".into(),
        nonce_slot: 0,
    };
    let plaintext = b"real protected payload survives authenticated durable recovery";
    let payload = encrypt_protected_payload(
        &aad,
        &registry.records,
        4,
        &pad_plaintext(plaintext).unwrap(),
    )
    .unwrap();
    let mut envelope = synergy_etdag::EncryptedTransactionEnvelope {
        envelope_version: 2,
        envelope_id: digest("genuine-envelope"),
        target_context_root: root.clone(),
        target_height: 3,
        aad,
        aead_nonce: payload.aead_nonce,
        key_commitment: payload.key_commitment,
        share_commitment_root: digest("pending"),
        share_capsule_root: digest("pending"),
        ciphertext: payload.ciphertext,
        content_blind_order_key: digest("genuine-ingress-order"),
        share_capsules: payload.share_capsules,
    };
    envelope.refresh_capsule_roots().unwrap();
    let mut vertex = TransactionVertex {
        vertex_id: digest("pending"),
        target_context_root: root.clone(),
        target_height: 3,
        envelope: envelope.clone(),
        envelope_ref: CertifiedEnvelopeRef {
            tx_commitment: envelope.envelope_id.clone(),
            sender_id: "alice".into(),
            nonce_slot: 0,
            certified_dag_round: 0,
            gas_class_units: 10,
            ciphertext_bytes: envelope.ciphertext.len() as u64,
            fee_class: 1,
            protocol_dependencies: vec![],
        },
        parents: vec![],
        author_id: "qualification-0".into(),
        author_signature: vec![],

        wallet_admission: None,
    };
    vertex.vertex_id = synergy_etdag::dag::derive_vertex_id(&vertex).unwrap();
    vertex.author_signature = sign(&fleet, 0, vertex.vertex_id.0.as_bytes());
    let vertex_id = vertex.vertex_id.clone();
    let mut graph = EtdagGraph::new(root.clone(), 3).unwrap();
    graph.insert(vertex).unwrap();
    let votes = (0..4)
        .map(|index| {
            let mut vote = AvailabilityVote {
                context_root: root.clone(),
                vertex_id: vertex_id.clone(),
                validator_id: format!("qualification-{index}"),
                key_id: format!("key-{index}"),
                signature: vec![],
            };
            vote.signature = sign(
                &fleet,
                index,
                &synergy_etdag::crypto::canonical_signing_bytes(
                    "SYNERGY_ETDAG_AVAILABILITY_VOTE_V1",
                    &(
                        &vote.context_root,
                        &vote.vertex_id,
                        &vote.validator_id,
                        &vote.key_id,
                    ),
                )
                .unwrap(),
            );
            vote
        })
        .collect();
    let certificates = BTreeMap::from([(
        vertex_id.clone(),
        AvailabilityCertificate::from_votes(root.clone(), vertex_id.clone(), votes, 5).unwrap(),
    )]);
    let signed_markers = markers(&fleet, &context, vec![vertex_id]);
    let directory = fleet.root.join("genuine-nonempty-recovery");
    let mut pipeline = ProtectedPipeline::open(
        &directory,
        context.clone(),
        EtdagParameters::default(),
        digest("cutoff"),
        "qualification-0".into(),
        &members(),
        fleet.authority.as_ref(),
    )
    .unwrap();
    pipeline
        .accept_cut(
            &signed_markers[..4],
            &graph,
            &certificates,
            &members(),
            fleet.authority.as_ref(),
        )
        .unwrap();
    let batch = pipeline.batch().unwrap().clone();
    assert_eq!(
        batch.ordered_transaction_ids,
        vec![envelope.envelope_id.clone()]
    );
    assert!(
        graph.get(&envelope.envelope_id).is_none(),
        "real vertex ID differs from envelope ID"
    );
    assert_eq!(
        super::etdag::selected_envelope(&graph, &batch, &envelope.envelope_id).unwrap(),
        &envelope
    );
    assert!(super::etdag::selected_envelope(&graph, &batch, &digest("not-in-cut")).is_err());
    let material = ProtectedProposalMaterial {
        material_version: 2,
        height: 2,
        execution_root: digest("genesis-bootstrap-H2"),
        next_batch_root: batch.protected_batch_root.clone(),
        cutoff_boundary_root: digest("H4-boundary-descriptor"),
    };
    let certificate = fleet.validate_protected_parent(&material);
    let evidence = ParentProposalRevealEvidence {
        material,
        next_batch: batch.clone(),
        validation_proof: serde_json::to_vec(&certificate).unwrap(),
    };
    let mut authorization = ProtectedRevealAuthorization {
        authorization_version: 1,
        context_root: root,
        target_height: 3,
        protected_batch_root: batch.protected_batch_root.clone(),
        finality_reference: digest("pending"),
    };
    authorization.finality_reference = parent_reveal_reference(
        &certificate.candidate.block_id,
        &certificate.id().unwrap(),
        &authorization,
    )
    .unwrap();
    let verified = VerifiedRevealAuthorization::verify(
        authorization.clone(),
        &evidence,
        fleet.authority.as_ref(),
    )
    .unwrap();
    let allowed = members().into_keys().collect();
    let mut collector =
        VerifiedShareCollector::new(verified, envelope.envelope_id.clone(), 4, 5).unwrap();
    let mut messages = Vec::new();
    for (index, secret) in kem_secrets.iter_mut().enumerate().take(2) {
        let capsule = &envelope.share_capsules[index];
        let share =
            decrypt_share_capsule(&envelope, capsule, &registry.records[index], secret).unwrap();
        let mut message = DecryptShareMessage {
            share_version: 2,
            authorization: authorization.clone(),
            envelope_id: envelope.envelope_id.clone(),
            validator_id: format!("qualification-{index}"),
            key_id: format!("key-{index}"),
            ingress_kem_key_id: capsule.ingress_kem_key_id.clone(),
            share_index: share.index,
            share_commitment: capsule.share_commitment.clone(),
            encrypted_share: share.canonical_bytes().unwrap(),
            signature: vec![],
        };
        message.signature = sign(&fleet, index, &message.signing_bytes().unwrap());
        collector
            .insert(
                verify_decrypt_share(
                    &message,
                    &authorization,
                    &allowed,
                    &envelope,
                    &registry,
                    &context,
                    fleet.authority.as_ref(),
                )
                .unwrap(),
            )
            .unwrap();
        messages.push(message);
        secret.fill(0);
    }
    let shares = collector.into_threshold_shares().unwrap();
    assert_eq!(shares.shares().len(), 2);
    let revealed = decrypt_authorized_envelope(
        &envelope,
        &shares,
        &GovernedThresholdDecryptor::new(5, 4).unwrap(),
    )
    .unwrap();
    assert_eq!(revealed.plaintext(), plaintext);
    let transcripts = BTreeMap::from([(
        envelope.envelope_id.clone(),
        RevealTranscript {
            transcript_version: 1,
            authorization: authorization.clone(),
            shares: messages,
        },
    )]);
    assert!(pipeline
        .prepare_revealed(
            authorization.clone(),
            evidence.clone(),
            &[revealed],
            transcripts,
            fleet.authority.as_ref()
        )
        .unwrap());
    let expected = pipeline.prepared().unwrap().clone();
    drop(pipeline);
    let open = || {
        ProtectedPipeline::open(
            &directory,
            context.clone(),
            EtdagParameters::default(),
            digest("cutoff"),
            "qualification-0".into(),
            &members(),
            fleet.authority.as_ref(),
        )
    };
    assert_eq!(open().unwrap().prepared(), Some(&expected));
    assert_eq!(expected.transactions[0].plaintext, plaintext);
    let path = directory.join("protected-h3.json");
    let original: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let mut changed = original.clone();
    changed["committed"]["prepared"]["transactions"][0]["plaintext"][0] = serde_json::json!(0);
    std::fs::write(&path, serde_json::to_vec(&changed).unwrap()).unwrap();
    assert!(
        open().is_err(),
        "restart must reject altered plaintext despite valid parent QC"
    );
    changed = original.clone();
    let first = changed["committed"]["reveal_transcripts"]
        .as_object_mut()
        .unwrap()
        .values_mut()
        .next()
        .unwrap();
    first["shares"][0]["signature"][0] =
        serde_json::json!(first["shares"][0]["signature"][0].as_u64().unwrap() ^ 1);
    std::fs::write(&path, serde_json::to_vec(&changed).unwrap()).unwrap();
    assert!(
        open().is_err(),
        "restart must reverify signed share witnesses"
    );
    changed = original.clone();
    changed["committed"]["prepared"]["parent_evidence"]["validation_proof"] = serde_json::json!([]);
    std::fs::write(&path, serde_json::to_vec(&changed).unwrap()).unwrap();
    assert!(
        open().is_err(),
        "restart must reject missing parent validation proof"
    );
    changed = original.clone();
    changed["committed"]
        .as_object_mut()
        .unwrap()
        .remove("reveal_transcripts");
    std::fs::write(&path, serde_json::to_vec(&changed).unwrap()).unwrap();
    assert!(
        open().is_err(),
        "legacy missing witness cannot authorize nonempty execution"
    );
    std::fs::write(&path, serde_json::to_vec(&original).unwrap()).unwrap();
    assert_eq!(open().unwrap().prepared(), Some(&expected));
    for secret in &mut kem_secrets {
        secret.fill(0);
    }
}
