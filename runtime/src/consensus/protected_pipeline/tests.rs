use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::etdag::{
    self, form_etdag_certificate, sign_vac_vote, sign_vertex, CertifiedEnvelopeRef,
    CertifiedVertex, EtdagPhase, EtdagSafetyJournal, EtdagVoteTranscript, ProtectedBatchSource,
    ProtectedPipelinePhase, TransactionVertex, VertexKind, DOMAIN_PROTECTED_BATCH,
    DOMAIN_PROTECTED_CUT_SEMANTIC, DOMAIN_VAC, ETDAG_LANE_ID, ETDAG_PROFILE_ID,
};
use crate::synergy_types::{Hash, Round, ValidatorRecord};

use super::*;

static TEST_DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct GraphFixture {
    graph: BTreeMap<EtdagDigest, CertifiedVertex>,
    transaction_vertices: Vec<CertifiedVertex>,
    marker_vertices: Vec<CertifiedVertex>,
    marker_digests: Vec<EtdagDigest>,
}

#[derive(Default)]
struct TestEvidenceVerifier {
    reject: bool,
}

impl ProtectedPipelineEvidenceVerifier for TestEvidenceVerifier {
    fn verify_order_seed(
        &self,
        _target: &TargetAdmissionContext,
        _evidence: &ProtectedOrderSeedEvidence,
    ) -> Result<(), String> {
        if self.reject {
            Err("test verifier rejected order seed".to_string())
        } else {
            Ok(())
        }
    }

    fn verify_observation(
        &self,
        _target: &TargetAdmissionContext,
        _expected_commitment: &NextProtectedBatchCommitment,
        _observation: &ProtectedPipelineObservation,
    ) -> Result<(), String> {
        if self.reject {
            Err("test verifier rejected observation".to_string())
        } else {
            Ok(())
        }
    }
}

fn members(fixture: &etdag::tests::Fixture) -> Vec<ValidatorRecord> {
    fixture
        .validator_set
        .active_for_epoch(fixture.context.epoch)
        .active_for_cluster(fixture.context.assigned_cluster_id)
}

fn unique_test_path(label: &str) -> PathBuf {
    let sequence = TEST_DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    crate::utils::test_temp_root(format!(
        "protected-pipeline-{label}-{}-{sequence}/record.json",
        std::process::id(),
    ))
}

fn vote_transcript(
    context: &TargetAdmissionContext,
    phase: EtdagPhase,
    round: u64,
    candidate: EtdagDigest,
) -> EtdagVoteTranscript {
    EtdagVoteTranscript {
        phase,
        chain_id: context.chain_id,
        network_id: context.network_id.clone(),
        protocol_version: context.protocol_version.clone(),
        profile_id: ETDAG_PROFILE_ID.to_string(),
        epoch: context.epoch,
        target_height: context.target_height,
        target_context_root: context.root().expect("target context root"),
        assigned_cluster_id: context.assigned_cluster_id,
        lane_id: ETDAG_LANE_ID.to_string(),
        round: Round(round),
        candidate_digest: candidate,
        highest_prepared_bvc_digest: None,
    }
}

fn certify_vertex(
    fixture: &mut etdag::tests::Fixture,
    vertex: TransactionVertex,
) -> CertifiedVertex {
    let context = fixture.context.clone();
    let validator_set = fixture.validator_set.clone();
    let cluster_map = fixture.cluster_map.clone();
    let cluster_members = members(fixture);
    let transcript = vote_transcript(
        &context,
        EtdagPhase::Vac,
        vertex.dag_round,
        vertex.digest().expect("vertex digest"),
    );
    let journal = EtdagSafetyJournal::at_path(unique_test_path("vac-journal"));
    let votes = cluster_members
        .iter()
        .take(4)
        .map(|member| {
            sign_vac_vote(
                &mut fixture.signer,
                &journal,
                &context,
                member,
                &[],
                &transcript,
            )
            .expect("sign VAC vote")
        })
        .collect::<Vec<_>>();
    let verifier = fixture.signer.verifier();
    let availability_certificate =
        form_etdag_certificate(transcript, votes, &verifier, &validator_set, &cluster_map)
            .expect("form VAC");
    CertifiedVertex {
        vertex,
        availability_certificate,
    }
}

fn envelope(index: u8) -> CertifiedEnvelopeRef {
    CertifiedEnvelopeRef {
        tx_commitment: EtdagDigest::from_domain_bytes("protected-test-tx", &[index]),
        sender_id: format!("sender-{index}"),
        nonce_slot: 0,
        certified_dag_round: 0,
        gas_class_units: 10 + u64::from(index),
        ciphertext_bytes: 100 + u64::from(index),
        fee_class: u32::from(index),
        protocol_dependencies: Vec::new(),
    }
}

fn graph_fixture(fixture: &mut etdag::tests::Fixture) -> GraphFixture {
    let context = fixture.context.clone();
    let cluster_members = members(fixture);
    assert_eq!(
        cluster_members.len(),
        5,
        "test requires one five-validator cluster"
    );
    let mut graph = BTreeMap::new();
    let mut transaction_vertices = Vec::new();
    let mut transaction_digests = Vec::new();
    for (index, author) in cluster_members.iter().take(4).enumerate() {
        let envelopes = if index == 0 {
            (0..4).map(envelope).collect()
        } else {
            Vec::new()
        };
        let vertex = sign_vertex(
            &mut fixture.signer,
            &context,
            author,
            VertexKind::Transactions,
            0,
            index as u64,
            Vec::new(),
            envelopes,
            EtdagDigest::from_domain_bytes("protected-test-capsule", &[index as u8]),
            None,
        )
        .expect("sign transaction vertex");
        let digest = vertex.digest().expect("transaction vertex digest");
        let certified = certify_vertex(fixture, vertex);
        graph.insert(digest.clone(), certified.clone());
        transaction_vertices.push(certified);
        transaction_digests.push(digest);
    }

    let cutoff_root = Hash::from_domain_bytes("protected-test-cutoff-vc", b"height");
    let mut marker_vertices = Vec::new();
    let mut marker_digests = Vec::new();
    for (index, author) in cluster_members.iter().enumerate() {
        let marker = sign_vertex(
            &mut fixture.signer,
            &context,
            author,
            VertexKind::CutoffMarker,
            1,
            100 + index as u64,
            transaction_digests.clone(),
            Vec::new(),
            EtdagDigest::from_domain_bytes("protected-test-marker", &[index as u8]),
            Some(cutoff_root),
        )
        .expect("sign cutoff marker");
        let digest = marker.digest().expect("marker digest");
        let certified = certify_vertex(fixture, marker);
        graph.insert(digest.clone(), certified.clone());
        marker_vertices.push(certified);
        marker_digests.push(digest);
    }
    GraphFixture {
        graph,
        transaction_vertices,
        marker_vertices,
        marker_digests,
    }
}

fn all_permutations<T: Clone>(values: &[T]) -> Vec<Vec<T>> {
    fn recurse<T: Clone>(remaining: Vec<T>, prefix: &mut Vec<T>, output: &mut Vec<Vec<T>>) {
        if remaining.is_empty() {
            output.push(prefix.clone());
            return;
        }
        for index in 0..remaining.len() {
            let mut next = remaining.clone();
            let value = next.remove(index);
            prefix.push(value);
            recurse(next, prefix, output);
            prefix.pop();
        }
    }
    let mut output = Vec::new();
    recurse(values.to_vec(), &mut Vec::new(), &mut output);
    output
}

fn root(label: &str) -> EtdagDigest {
    EtdagDigest::from_domain_bytes("protected-test-observation", label.as_bytes())
}

fn reopen(
    pipeline: ProtectedPipeline,
    path: &Path,
    target: &TargetAdmissionContext,
) -> ProtectedPipeline {
    drop(pipeline);
    ProtectedPipeline::open(
        path,
        target.clone(),
        ProtectedBatchSource::NormalEtdagSteadyState,
    )
    .expect("restart protected pipeline")
}

#[test]
fn cut_construction_is_identical_for_all_arrival_permutations() {
    let mut fixture = etdag::tests::fixture(5, None);
    let graph = graph_fixture(&mut fixture);
    let verifier = fixture.signer.verifier();
    let expected = construct_protected_cut_proof(
        &fixture.context,
        &graph.graph,
        &graph.marker_digests,
        &verifier,
        &fixture.validator_set,
        &fixture.cluster_map,
    )
    .expect("reference cut proof");

    for markers in all_permutations(&graph.marker_digests) {
        let mut entries = graph.graph.iter().collect::<Vec<_>>();
        entries.reverse();
        let arrival_map = entries.into_iter().collect::<HashMap<_, _>>();
        let actual = construct_protected_cut_proof(
            &fixture.context,
            arrival_map,
            &markers,
            &verifier,
            &fixture.validator_set,
            &fixture.cluster_map,
        )
        .expect("permuted cut proof");
        assert_eq!(actual, expected, "arrival permutation changed exact proof");
    }
}

#[test]
fn every_valid_four_of_five_marker_subset_has_the_same_semantic_cut() {
    let mut fixture = etdag::tests::fixture(5, None);
    let graph = graph_fixture(&mut fixture);
    let verifier = fixture.signer.verifier();
    let mut semantic_roots = BTreeSet::new();
    let mut exact_roots = BTreeSet::new();

    for omitted in 0..graph.marker_digests.len() {
        let subset = graph
            .marker_digests
            .iter()
            .enumerate()
            .filter(|(index, _)| *index != omitted)
            .map(|(_, digest)| digest.clone())
            .collect::<Vec<_>>();
        let proof = construct_protected_cut_proof(
            &fixture.context,
            &graph.graph,
            &subset,
            &verifier,
            &fixture.validator_set,
            &fixture.cluster_map,
        )
        .expect("valid four-of-five cut");
        semantic_roots.insert(proof.cut_root.clone());
        exact_roots.insert(proof.proof_root().expect("exact proof root"));
    }
    assert_eq!(
        semantic_roots.len(),
        1,
        "semantic cut depends on marker subset"
    );
    assert_eq!(
        exact_roots.len(),
        5,
        "exact audit roots should bind marker subsets"
    );
}

#[test]
fn cut_and_batch_are_independent_of_hashmap_iteration_order() {
    let mut fixture = etdag::tests::fixture(5, None);
    let graph = graph_fixture(&mut fixture);
    let verifier = fixture.signer.verifier();
    let ordered = construct_protected_cut_proof(
        &fixture.context,
        &graph.graph,
        &graph.marker_digests,
        &verifier,
        &fixture.validator_set,
        &fixture.cluster_map,
    )
    .expect("BTreeMap proof");
    let hash_map = graph.graph.iter().collect::<HashMap<_, _>>();
    let unordered = construct_protected_cut_proof(
        &fixture.context,
        hash_map,
        &graph.marker_digests,
        &verifier,
        &fixture.validator_set,
        &fixture.cluster_map,
    )
    .expect("HashMap proof");
    let seed = root("order-seed");
    let ordered_batch = derive_protected_batch(
        &fixture.context,
        &ordered,
        &seed,
        &EtdagParameters::default(),
    )
    .expect("ordered batch");
    let unordered_batch = derive_protected_batch(
        &fixture.context,
        &unordered,
        &seed,
        &EtdagParameters::default(),
    )
    .expect("unordered batch");
    assert_eq!(ordered_batch, unordered_batch);
}

#[test]
fn duplicate_evidence_is_idempotent() {
    let mut fixture = etdag::tests::fixture(5, None);
    let graph = graph_fixture(&mut fixture);
    let verifier = fixture.signer.verifier();
    let mut duplicated_markers = graph.marker_digests.clone();
    duplicated_markers.extend(graph.marker_digests.clone());
    let proof = construct_protected_cut_proof(
        &fixture.context,
        &graph.graph,
        &duplicated_markers,
        &verifier,
        &fixture.validator_set,
        &fixture.cluster_map,
    )
    .expect("duplicate markers are canonicalized");
    assert_eq!(proof.cutoff_marker_digests.len(), 5);

    let path = unique_test_path("duplicates");
    let parameters = EtdagParameters::default();
    let inputs = ProtectedPipelineReconcileContext {
        target: &fixture.context,
        verifier: &verifier,
        validator_set: &fixture.validator_set,
        cluster_map: &fixture.cluster_map,
        parameters: &parameters,
    };
    let mut pipeline = ProtectedPipeline::open(
        &path,
        fixture.context.clone(),
        ProtectedBatchSource::NormalEtdagSteadyState,
    )
    .expect("open pipeline");
    let all_vertices = graph.graph.values().cloned().collect::<Vec<_>>();
    let first = pipeline
        .merge_etdag_evidence(&all_vertices, &duplicated_markers, &inputs)
        .expect("first merge");
    let second = pipeline
        .merge_etdag_evidence(&all_vertices, &duplicated_markers, &inputs)
        .expect("duplicate merge");
    assert!(first.changed, "first evidence merge must persist");
    assert!(!second.changed, "duplicate evidence changed durable state");
}

#[test]
fn invalid_cryptographic_evidence_latches_a_restart_safe_fault() {
    let mut fixture = etdag::tests::fixture(5, None);
    let graph = graph_fixture(&mut fixture);
    let mut invalid = graph.transaction_vertices[0].clone();
    invalid.availability_certificate.votes[0]
        .signature
        .signature_bytes[0] ^= 0x01;
    let verifier = fixture.signer.verifier();
    let parameters = EtdagParameters::default();
    let inputs = ProtectedPipelineReconcileContext {
        target: &fixture.context,
        verifier: &verifier,
        validator_set: &fixture.validator_set,
        cluster_map: &fixture.cluster_map,
        parameters: &parameters,
    };
    let path = unique_test_path("invalid-crypto");
    let mut pipeline = ProtectedPipeline::open(
        &path,
        fixture.context.clone(),
        ProtectedBatchSource::NormalEtdagSteadyState,
    )
    .expect("open pipeline");
    let error = pipeline
        .merge_etdag_evidence(&[invalid], &[], &inputs)
        .expect_err("invalid VAC must fail closed");
    assert_eq!(error.kind, ProtectedPipelineErrorKind::InvalidEvidence);

    let restarted = reopen(pipeline, &path, &fixture.context);
    let snapshot = restarted.snapshot().expect("fault snapshot");
    assert!(snapshot.fault.is_some(), "fault did not survive restart");
}

#[test]
fn deterministic_batch_is_bound_to_seed_and_capacity_policy() {
    let mut fixture = etdag::tests::fixture(5, None);
    let graph = graph_fixture(&mut fixture);
    let verifier = fixture.signer.verifier();
    let proof = construct_protected_cut_proof(
        &fixture.context,
        &graph.graph,
        &graph.marker_digests,
        &verifier,
        &fixture.validator_set,
        &fixture.cluster_map,
    )
    .expect("cut proof");
    let seed = root("batch-seed");
    let default_batch =
        derive_protected_batch(&fixture.context, &proof, &seed, &EtdagParameters::default())
            .expect("default-policy batch");
    let repeated =
        derive_protected_batch(&fixture.context, &proof, &seed, &EtdagParameters::default())
            .expect("repeated batch");
    let mut constrained = EtdagParameters::default();
    constrained.max_protected_gas = 15;
    let constrained_batch = derive_protected_batch(&fixture.context, &proof, &seed, &constrained)
        .expect("constrained batch");
    assert_eq!(default_batch, repeated, "same governed inputs diverged");
    assert_ne!(
        default_batch.protected_batch_root, constrained_batch.protected_batch_root,
        "capacity policy did not affect the exact selected batch",
    );
}

#[test]
fn durable_phases_are_monotonic_and_restart_safe_at_every_phase() {
    let mut fixture = etdag::tests::fixture(5, None);
    let graph = graph_fixture(&mut fixture);
    let verifier = fixture.signer.verifier();
    let parameters = EtdagParameters::default();
    let inputs = ProtectedPipelineReconcileContext {
        target: &fixture.context,
        verifier: &verifier,
        validator_set: &fixture.validator_set,
        cluster_map: &fixture.cluster_map,
        parameters: &parameters,
    };
    let evidence_verifier = TestEvidenceVerifier::default();
    let path = unique_test_path("phase-restarts");
    let mut pipeline = ProtectedPipeline::open(
        &path,
        fixture.context.clone(),
        ProtectedBatchSource::NormalEtdagSteadyState,
    )
    .expect("open pipeline");
    assert_eq!(pipeline.record().phase, ProtectedPipelinePhase::Collecting);
    pipeline = reopen(pipeline, &path, &fixture.context);

    pipeline
        .merge_etdag_evidence(&graph.marker_vertices, &graph.marker_digests, &inputs)
        .expect("merge quorum markers without ancestors");
    assert_eq!(pipeline.record().phase, ProtectedPipelinePhase::CutoffReady);
    pipeline = reopen(pipeline, &path, &fixture.context);

    pipeline
        .merge_etdag_evidence(&graph.transaction_vertices, &[], &inputs)
        .expect("complete causal closure");
    assert_eq!(pipeline.record().phase, ProtectedPipelinePhase::CutReady);
    pipeline = reopen(pipeline, &path, &fixture.context);

    pipeline
        .merge_order_seed(
            ProtectedOrderSeedEvidence {
                order_seed: root("phase-order-seed"),
                authority_root: root("phase-order-authority"),
            },
            &evidence_verifier,
            &inputs,
        )
        .expect("merge order seed");
    assert_eq!(pipeline.record().phase, ProtectedPipelinePhase::OrderReady);
    pipeline = reopen(pipeline, &path, &fixture.context);

    let commitment_root = pipeline
        .record()
        .next_commitment
        .as_ref()
        .expect("next commitment")
        .root()
        .expect("next commitment root");
    let proposal_id = root("phase-proposal");
    pipeline
        .merge_observation(
            ProtectedPipelineObservation::ParentCommitment {
                proposal_id: proposal_id.clone(),
                commitment_root: commitment_root.clone(),
                evidence_root: root("phase-parent-evidence"),
            },
            &evidence_verifier,
            &inputs,
        )
        .expect("observe parent commitment");
    assert_eq!(
        pipeline.record().phase,
        ProtectedPipelinePhase::CommittedInParent
    );
    pipeline = reopen(pipeline, &path, &fixture.context);

    pipeline
        .merge_observation(
            ProtectedPipelineObservation::RevealAuthorization {
                proposal_id,
                vc_root: root("phase-vc"),
                commitment_root: commitment_root.clone(),
                evidence_root: root("phase-vc-evidence"),
            },
            &evidence_verifier,
            &inputs,
        )
        .expect("authorize reveal");
    assert_eq!(
        pipeline.record().phase,
        ProtectedPipelinePhase::RevealAuthorized
    );
    pipeline = reopen(pipeline, &path, &fixture.context);

    let reveal_validator = members(&fixture)[0].validator_id.clone();
    pipeline
        .merge_observation(
            ProtectedPipelineObservation::RevealShare {
                validator_id: reveal_validator,
                commitment_root: commitment_root.clone(),
                share_root: root("phase-share"),
            },
            &evidence_verifier,
            &inputs,
        )
        .expect("merge reveal share");
    assert_eq!(pipeline.record().phase, ProtectedPipelinePhase::Revealing);
    pipeline = reopen(pipeline, &path, &fixture.context);

    let execution_root = root("phase-execution");
    pipeline
        .merge_observation(
            ProtectedPipelineObservation::ExecutionReady {
                commitment_root: commitment_root.clone(),
                execution_root: execution_root.clone(),
                evidence_root: root("phase-execution-evidence"),
            },
            &evidence_verifier,
            &inputs,
        )
        .expect("mark execution ready");
    assert_eq!(
        pipeline.record().phase,
        ProtectedPipelinePhase::ReadyForExecution
    );
    pipeline = reopen(pipeline, &path, &fixture.context);

    pipeline
        .merge_observation(
            ProtectedPipelineObservation::QcObserved {
                commitment_root: commitment_root.clone(),
                qc_root: root("phase-qc"),
                evidence_root: root("phase-qc-evidence"),
            },
            &evidence_verifier,
            &inputs,
        )
        .expect("observe QC");
    pipeline
        .merge_observation(
            ProtectedPipelineObservation::Finalized {
                commitment_root: commitment_root.clone(),
                finality_root: root("phase-finality"),
                evidence_root: root("phase-finality-evidence"),
            },
            &evidence_verifier,
            &inputs,
        )
        .expect("observe finality");
    assert_eq!(
        pipeline.record().phase,
        ProtectedPipelinePhase::ReadyForExecution,
        "diagnostic observations must not skip CONSUMED",
    );

    pipeline
        .merge_observation(
            ProtectedPipelineObservation::Consumed {
                commitment_root,
                execution_root,
                evidence_root: root("phase-consumed-evidence"),
            },
            &evidence_verifier,
            &inputs,
        )
        .expect("consume protected input");
    assert_eq!(pipeline.record().phase, ProtectedPipelinePhase::Consumed);
    pipeline = reopen(pipeline, &path, &fixture.context);
    let snapshot = pipeline.snapshot().expect("final snapshot");
    assert!(snapshot.diagnostic.qc_seen && snapshot.diagnostic.finalized);

    let mut rollback = pipeline.record().clone();
    let error = advance_phase(&mut rollback, ProtectedPipelinePhase::Collecting)
        .expect_err("phase rollback must fail");
    assert_eq!(error.kind, ProtectedPipelineErrorKind::Conflict);
}

#[test]
fn conflicting_valid_semantic_input_fails_closed() {
    let mut fixture = etdag::tests::fixture(5, None);
    let graph = graph_fixture(&mut fixture);
    let verifier = fixture.signer.verifier();
    let parameters = EtdagParameters::default();
    let inputs = ProtectedPipelineReconcileContext {
        target: &fixture.context,
        verifier: &verifier,
        validator_set: &fixture.validator_set,
        cluster_map: &fixture.cluster_map,
        parameters: &parameters,
    };
    let evidence_verifier = TestEvidenceVerifier::default();
    let path = unique_test_path("semantic-conflict");
    let mut pipeline = ProtectedPipeline::open(
        &path,
        fixture.context.clone(),
        ProtectedBatchSource::NormalEtdagSteadyState,
    )
    .expect("open pipeline");
    let all_vertices = graph.graph.values().cloned().collect::<Vec<_>>();
    pipeline
        .merge_etdag_evidence(&all_vertices, &graph.marker_digests, &inputs)
        .expect("merge cut evidence");
    pipeline
        .merge_order_seed(
            ProtectedOrderSeedEvidence {
                order_seed: root("first-seed"),
                authority_root: root("first-authority"),
            },
            &evidence_verifier,
            &inputs,
        )
        .expect("merge first seed");
    let error = pipeline
        .merge_order_seed(
            ProtectedOrderSeedEvidence {
                order_seed: root("conflicting-seed"),
                authority_root: root("conflicting-authority"),
            },
            &evidence_verifier,
            &inputs,
        )
        .expect_err("conflicting verified seed must fail closed");
    assert_eq!(error.kind, ProtectedPipelineErrorKind::Conflict);
    assert!(pipeline.snapshot().expect("snapshot").fault.is_some());
}

#[test]
fn verifier_rejection_cannot_advance_order_or_consensus_phase() {
    let mut fixture = etdag::tests::fixture(5, None);
    let graph = graph_fixture(&mut fixture);
    let verifier = fixture.signer.verifier();
    let parameters = EtdagParameters::default();
    let inputs = ProtectedPipelineReconcileContext {
        target: &fixture.context,
        verifier: &verifier,
        validator_set: &fixture.validator_set,
        cluster_map: &fixture.cluster_map,
        parameters: &parameters,
    };
    let path = unique_test_path("verifier-rejects");
    let mut pipeline = ProtectedPipeline::open(
        &path,
        fixture.context.clone(),
        ProtectedBatchSource::NormalEtdagSteadyState,
    )
    .expect("open pipeline");
    let all_vertices = graph.graph.values().cloned().collect::<Vec<_>>();
    pipeline
        .merge_etdag_evidence(&all_vertices, &graph.marker_digests, &inputs)
        .expect("merge cut evidence");
    let error = pipeline
        .merge_order_seed(
            ProtectedOrderSeedEvidence {
                order_seed: root("rejected-seed"),
                authority_root: root("rejected-authority"),
            },
            &TestEvidenceVerifier { reject: true },
            &inputs,
        )
        .expect_err("unverified seed must fail closed");
    assert_eq!(error.kind, ProtectedPipelineErrorKind::InvalidEvidence);
    assert_eq!(pipeline.record().phase, ProtectedPipelinePhase::CutReady);
}

#[test]
fn next_commitment_is_semantic_across_valid_marker_subsets() {
    let mut fixture = etdag::tests::fixture(5, None);
    let graph = graph_fixture(&mut fixture);
    let verifier = fixture.signer.verifier();
    let seed = root("subset-commitment-seed");
    let mut commitment_roots = BTreeSet::new();
    for omitted in 0..graph.marker_digests.len() {
        let subset = graph
            .marker_digests
            .iter()
            .enumerate()
            .filter(|(index, _)| *index != omitted)
            .map(|(_, digest)| digest.clone())
            .collect::<Vec<_>>();
        let proof = construct_protected_cut_proof(
            &fixture.context,
            &graph.graph,
            &subset,
            &verifier,
            &fixture.validator_set,
            &fixture.cluster_map,
        )
        .expect("valid subset proof");
        let batch =
            derive_protected_batch(&fixture.context, &proof, &seed, &EtdagParameters::default())
                .expect("subset batch");
        let commitment = derive_next_protected_batch_commitment(&fixture.context, &proof, &batch)
            .expect("subset commitment");
        commitment_roots.insert(commitment.root().expect("commitment root"));
    }
    assert_eq!(
        commitment_roots.len(),
        1,
        "proposal-visible commitment depends on exact marker quorum",
    );
}

#[test]
fn domain_constants_remain_distinct_for_semantic_products() {
    assert_ne!(DOMAIN_PROTECTED_CUT_SEMANTIC, DOMAIN_PROTECTED_BATCH);
    assert_ne!(DOMAIN_PROTECTED_CUT_MARKER_EVIDENCE, DOMAIN_PROTECTED_BATCH);
    assert_ne!(DOMAIN_VAC, DOMAIN_PROTECTED_CUT_SEMANTIC);
}
