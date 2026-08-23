use super::*;
use crate::consensus::signing_authority::{
    ConsensusSigningAuthorization, ConsensusSigningPhase, DurableConsensusSigningAuthority,
};
use crate::consensus_parameters::ConsensusParameterRoot;
use crate::crypto::aegis_pqvm::AegisPqvmSigner;
use crate::synergy_types::{
    AegisPqKeyId, AegisPqKeyRole, AegisPqPublicKey, AegisPqSignature, BlockId, ClusterId, Epoch,
    Hash, Height, Round, UmaId, ValidatorId, ValidatorRecord, ValidatorSet, ValidatorStatus,
    TESTNET_V3_CONSENSUS_SIGNATURE_ALGORITHM, TESTNET_V3_MLDSA65_PUBLIC_KEY_BYTES,
};
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy)]
struct DeterministicTestVerifier;

impl ConsensusSignatureVerifier for DeterministicTestVerifier {
    fn verify_consensus_signature(
        &self,
        domain: &str,
        payload: &[u8],
        validator: &ValidatorRecord,
        key_id: &AegisPqKeyId,
        _epoch: Epoch,
        signature: &AegisPqSignature,
    ) -> Result<(), String> {
        let expected = fake_signature(domain, payload, &validator.validator_id, key_id);
        if signature == &expected {
            Ok(())
        } else {
            Err("deterministic test signature failed".to_string())
        }
    }
}

fn fake_signature(
    domain: &str,
    payload: &[u8],
    validator_id: &ValidatorId,
    key_id: &AegisPqKeyId,
) -> AegisPqSignature {
    let mut transcript = Vec::new();
    transcript.extend_from_slice(payload);
    transcript.extend_from_slice(validator_id.0.as_bytes());
    transcript.extend_from_slice(key_id.0.as_bytes());
    AegisPqSignature {
        algorithm: TESTNET_V3_CONSENSUS_SIGNATURE_ALGORITHM.to_string(),
        signature_bytes: Hash::from_domain_bytes(domain, &transcript).0.to_vec(),
    }
}

fn validator_set<const N: usize>(weights: [u64; N]) -> ValidatorSet {
    ValidatorSet {
        epoch: Epoch(7),
        validators: weights
            .into_iter()
            .enumerate()
            .map(|(index, voting_weight)| {
                let key_id = AegisPqKeyId(format!("consensus-key-{index}"));
                let public_key = AegisPqPublicKey {
                    key_id,
                    algorithm: TESTNET_V3_CONSENSUS_SIGNATURE_ALGORITHM.to_string(),
                    key_bytes: vec![index as u8 + 1; TESTNET_V3_MLDSA65_PUBLIC_KEY_BYTES],
                };
                ValidatorRecord {
                    validator_id: ValidatorId(format!("validator-{index}")),
                    validator_uma_id: UmaId(format!("uma:validator-{index}")),
                    consensus_public_key: public_key.clone(),
                    peer_public_key: public_key.clone(),
                    operator_public_key: public_key,
                    voting_weight,
                    status: ValidatorStatus::Active,
                    cluster_id: ClusterId(0),
                    activation_epoch: Epoch(7),
                }
            })
            .collect(),
    }
}

#[test]
fn finalized_epoch_context_accepts_a_larger_dynamic_validator_ring() {
    let validators = validator_set([1, 1, 1, 1, 1, 1, 1]);
    let context = epoch_context(&validators, 1_999);
    context.validate_against(&validators).unwrap();
    assert_eq!(context.leader_ring.len(), 7);
    assert_eq!(
        context
            .leader_ring
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        7
    );

    assert!(verify_strict_dual_quorum(5, 7, 5, 7).is_ok());
    assert!(verify_strict_dual_quorum(4, 7, 4, 7).is_err());
}

#[test]
fn simplified_epoch_rejects_a_set_below_the_testnet_cluster_minimum() {
    let validators = validator_set([1, 1, 1, 1]);
    let error = SimplifiedEpochContext::derive(
        Epoch(7),
        Height(1_000),
        Height(1_999),
        Hash::from_domain_bytes("test-epoch-seed", b"epoch-7"),
        ConsensusParameterRoot::from_canonical_manifest_bytes(b"posy-v3-test-manifest"),
        &validators,
    )
    .unwrap_err();
    assert!(error.contains("at least 5 active validators"));
}

fn epoch_context(validators: &ValidatorSet, end_height: u64) -> SimplifiedEpochContext {
    SimplifiedEpochContext::derive(
        Epoch(7),
        Height(1_000),
        Height(end_height),
        Hash::from_domain_bytes("test-epoch-seed", b"epoch-7"),
        ConsensusParameterRoot::from_canonical_manifest_bytes(b"posy-v3-test-manifest"),
        validators,
    )
    .expect("valid simplified epoch context")
}

fn anchor() -> QuorumCertificateReference {
    QuorumCertificateReference {
        height: Height(999),
        block_id: BlockId("block-999".to_string()),
        qc_id: Hash::from_domain_bytes("test-anchor-qc", b"block-999"),
    }
}

fn temp_path(label: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    crate::utils::test_temp_root(format!(
        "posy-simplified-{label}-{}-{stamp}/state.json",
        std::process::id()
    ))
}

#[test]
fn exact_v2_boundary_anchor_is_committed_and_cannot_be_substituted_on_restart() {
    let validators = validator_set([1, 1, 1, 1, 1]);
    let expected = anchor();
    let context = SimplifiedEpochContext::derive_from_v2_boundary(
        Epoch(7),
        Height(1_000),
        Height(1_999),
        SimplifiedEpochAnchor {
            height: expected.height,
            round: Round(0),
            block_id: expected.block_id.clone(),
            qc_finality_context_root: expected.qc_id,
        },
        ConsensusParameterRoot::from_canonical_manifest_bytes(b"posy-v3-test-manifest"),
        &validators,
    )
    .unwrap();
    context.validate_against(&validators).unwrap();
    let path = temp_path("exact-v2-boundary-anchor");
    let store = DurableSimplifiedPosyStore::at_path(path);
    store
        .initialize(&context, expected.clone())
        .expect("exact boundary anchor initializes durable state");

    let mut substituted = expected;
    substituted.block_id = BlockId("substituted-boundary-block".to_string());
    assert!(store.initialize(&context, substituted).is_err());
}

fn authority(label: &str) -> DurableConsensusSigningAuthority {
    DurableConsensusSigningAuthority::at_path(temp_path(label).with_file_name("journal.json"))
}

fn reliable_delivery_statement(
    context: &ConsensusObjectContext,
    candidate: &CertifiedCandidateSubject,
    validator: &ValidatorRecord,
    phase: ReliableDeliveryPhase,
) -> ReliableDeliveryStatement {
    let mut statement = ReliableDeliveryStatement {
        context: context.clone(),
        phase,
        candidate: candidate.clone(),
        validator_id: validator.validator_id.clone(),
        key_id: validator.consensus_public_key.key_id.clone(),
        signature: AegisPqSignature {
            algorithm: String::new(),
            signature_bytes: Vec::new(),
        },
    };
    let domain = match phase {
        ReliableDeliveryPhase::Echo => POSY_SIMPLIFIED_PROPOSAL_ECHO_DOMAIN,
        ReliableDeliveryPhase::Ready => POSY_SIMPLIFIED_PROPOSAL_READY_DOMAIN,
    };
    statement.signature = fake_signature(
        domain,
        &statement.signing_bytes().unwrap(),
        &statement.validator_id,
        &statement.key_id,
    );
    statement
}

fn state_machine(
    label: &str,
    context: &SimplifiedEpochContext,
    validators: &ValidatorSet,
) -> SimplifiedConsensusStateMachine {
    SimplifiedConsensusStateMachine::open(
        context.clone(),
        validators.clone(),
        DurableSimplifiedPosyStore::at_path(temp_path(label)),
        anchor(),
    )
    .expect("open simplified state machine")
}

#[test]
fn startup_reconciles_a_journaled_vote_from_durable_delivery_evidence() {
    let validators = validator_set([1, 1, 1, 1, 1]);
    let context = epoch_context(&validators, 1_030);
    let state_path = temp_path("journal-delivery-reconciliation");
    let store = DurableSimplifiedPosyStore::at_path(state_path.clone());
    let mut machine =
        SimplifiedConsensusStateMachine::open(context.clone(), validators.clone(), store, anchor())
            .unwrap();
    let object_context =
        ConsensusObjectContext::for_height(&context, Height(1_000), Round(0)).unwrap();
    let candidate = CertifiedCandidateSubject::new(
        object_context.clone(),
        BlockId("journaled-delivered-candidate".to_string()),
        anchor().block_id,
        anchor(),
        Hash::from_domain_bytes("protected", b"journaled-delivered-candidate"),
    )
    .unwrap();
    let mut delivery = ReliableDeliveryState::new(object_context.clone(), &context).unwrap();
    for validator in validators.validators.iter().take(3) {
        delivery
            .accept_statement(
                reliable_delivery_statement(
                    &object_context,
                    &candidate,
                    validator,
                    ReliableDeliveryPhase::Ready,
                ),
                &context,
                &validators,
                &DeterministicTestVerifier,
            )
            .unwrap();
    }
    assert_eq!(delivery.delivered_candidate, Some(candidate.clone()));
    machine.persist_reliable_delivery(delivery).unwrap();

    let validator = &validators.validators[0];
    let validator_id = validator.validator_id.clone();
    let validator_key_id = validator.consensus_public_key.key_id.clone();
    let journal = DurableConsensusSigningAuthority::at_path(
        state_path.with_file_name("reconciliation-journal.json"),
    );
    journal
        .authorize_before_signature(&ConsensusSigningAuthorization {
            chain_id: object_context.chain_id,
            network_id: object_context.network_id.clone(),
            protocol_version: object_context.protocol_version.clone(),
            epoch: object_context.epoch,
            height: object_context.height,
            round: object_context.round,
            cluster_id: ClusterId(0),
            height_context_root: object_context.epoch_context_root,
            validator_id: validator_id.clone(),
            key_id: validator_key_id.clone(),
            phase: ConsensusSigningPhase::Vote,
            candidate_id: Some(BlockId(format!(
                "posy-v3:{}",
                candidate.id().unwrap().to_hex()
            ))),
            highest_prepared_vc_root: None,
            conflict_unlock_tc_id: None,
        })
        .unwrap();

    machine
        .reconcile_local_signing_journal(&validator_id, &validator_key_id, &journal)
        .unwrap();
    let recovered = machine.state().last_vote.as_ref().unwrap();
    assert_eq!(recovered.height, Height(1_000));
    assert_eq!(recovered.round, Round(0));
    assert_eq!(recovered.candidate, candidate);
    assert!(!recovered.transcript_root.is_zero());

    let mut restarted = SimplifiedConsensusStateMachine::open(
        context,
        validators,
        DurableSimplifiedPosyStore::at_path(state_path),
        anchor(),
    )
    .unwrap();
    restarted
        .reconcile_local_signing_journal(&validator_id, &validator_key_id, &journal)
        .unwrap();
    assert_eq!(restarted.state().last_vote.as_ref(), Some(recovered));
}

fn qc(
    context: &SimplifiedEpochContext,
    validators: &ValidatorSet,
    height: u64,
    round: u64,
    block: &str,
    parent: &QuorumCertificateReference,
    takeover_tc_id: Option<Hash>,
    signer_indexes: &[usize],
) -> SimplifiedQuorumCertificate {
    let object_context =
        ConsensusObjectContext::for_height(context, Height(height), Round(round)).unwrap();
    let mut votes = Vec::new();
    for index in signer_indexes {
        let validator = &validators.validators[*index];
        let mut vote = BlockVote {
            context: object_context.clone(),
            block_id: BlockId(block.to_string()),
            parent_block_id: parent.block_id.clone(),
            parent_qc: parent.clone(),
            takeover_tc_id,
            protected_execution_root: Hash::from_domain_bytes(
                "test-protected-execution",
                block.as_bytes(),
            ),
            validator_id: validator.validator_id.clone(),
            key_id: validator.consensus_public_key.key_id.clone(),
            signature: AegisPqSignature {
                algorithm: String::new(),
                signature_bytes: Vec::new(),
            },
        };
        vote.signature = fake_signature(
            POSY_SIMPLIFIED_BLOCK_VOTE_DOMAIN,
            &vote.signing_bytes().unwrap(),
            &vote.validator_id,
            &vote.key_id,
        );
        votes.push(vote);
    }
    SimplifiedQuorumCertificate::from_votes(votes).unwrap()
}

fn tc(
    machine: &SimplifiedConsensusStateMachine,
    context: &SimplifiedEpochContext,
    validators: &ValidatorSet,
    signer_indexes: &[usize],
) -> SimplifiedTimeoutCertificate {
    let height = machine.state().next_height().unwrap();
    let (round, previous_tc_id) = machine
        .state()
        .takeover_for_height(context, height)
        .unwrap();
    let object_context = ConsensusObjectContext::for_height(context, height, Round(round)).unwrap();
    let lease_index = context.lease_index(height).unwrap();
    let timed_out_proposer = context.authorized_proposer(height, round).unwrap().clone();
    let mut votes = Vec::new();
    for index in signer_indexes {
        let validator = &validators.validators[*index];
        let mut vote = TimeoutVote {
            context: object_context.clone(),
            lease_index,
            timed_out_proposer: timed_out_proposer.clone(),
            highest_qc: machine.state().highest_qc.clone(),
            previous_tc_id,
            last_voted_candidate: machine
                .state()
                .last_vote
                .as_ref()
                .filter(|last_vote| last_vote.height == height)
                .map(|last_vote| last_vote.candidate.clone()),
            validator_id: validator.validator_id.clone(),
            key_id: validator.consensus_public_key.key_id.clone(),
            signature: AegisPqSignature {
                algorithm: String::new(),
                signature_bytes: Vec::new(),
            },
        };
        vote.signature = fake_signature(
            POSY_SIMPLIFIED_TIMEOUT_VOTE_DOMAIN,
            &vote.signing_bytes().unwrap(),
            &vote.validator_id,
            &vote.key_id,
        );
        votes.push(vote);
    }
    let proofs = machine
        .state()
        .certified_qcs
        .get(&machine.state().highest_qc.height.0)
        .cloned()
        .into_iter()
        .collect();
    SimplifiedTimeoutCertificate::from_votes_with_qc_proofs(votes, proofs).unwrap()
}

fn timeout_vote(
    context: &SimplifiedEpochContext,
    validators: &ValidatorSet,
    height: Height,
    round: Round,
    previous_tc_id: Option<Hash>,
    highest_qc: QuorumCertificateReference,
    last_voted_candidate: Option<CertifiedCandidateSubject>,
    signer_index: usize,
) -> TimeoutVote {
    let object_context = ConsensusObjectContext::for_height(context, height, round).unwrap();
    let validator = &validators.validators[signer_index];
    let mut vote = TimeoutVote {
        context: object_context,
        lease_index: context.lease_index(height).unwrap(),
        timed_out_proposer: context
            .authorized_proposer(height, round.0)
            .unwrap()
            .clone(),
        highest_qc,
        previous_tc_id,
        last_voted_candidate,
        validator_id: validator.validator_id.clone(),
        key_id: validator.consensus_public_key.key_id.clone(),
        signature: AegisPqSignature {
            algorithm: String::new(),
            signature_bytes: Vec::new(),
        },
    };
    vote.signature = fake_signature(
        POSY_SIMPLIFIED_TIMEOUT_VOTE_DOMAIN,
        &vote.signing_bytes().unwrap(),
        &vote.validator_id,
        &vote.key_id,
    );
    vote
}

fn resign_tc(certificate: &mut SimplifiedTimeoutCertificate, validators: &ValidatorSet) {
    for vote in &mut certificate.reports {
        vote.context = certificate.context.clone();
        vote.lease_index = certificate.lease_index;
        vote.timed_out_proposer = certificate.timed_out_proposer.clone();
        vote.previous_tc_id = certificate.previous_tc_id;
        let validator = validators
            .validators
            .iter()
            .find(|validator| validator.validator_id == vote.validator_id)
            .unwrap();
        vote.signature = fake_signature(
            POSY_SIMPLIFIED_TIMEOUT_VOTE_DOMAIN,
            &vote.signing_bytes().unwrap(),
            &validator.validator_id,
            &vote.key_id,
        );
    }
}

fn accept_next_qc(
    machine: &mut SimplifiedConsensusStateMachine,
    context: &SimplifiedEpochContext,
    validators: &ValidatorSet,
    signing_authority: &DurableConsensusSigningAuthority,
    block_label: &str,
) -> SimplifiedQuorumCertificate {
    let height = machine.state().next_height().unwrap();
    let parent = machine.state().highest_qc.clone();
    let (round, takeover_tc_id) = machine
        .state()
        .takeover_for_height(context, height)
        .unwrap();
    let certificate = qc(
        context,
        validators,
        height.0,
        round,
        block_label,
        &parent,
        takeover_tc_id,
        &[0, 1, 2, 3],
    );
    machine
        .accept_quorum_certificate(
            certificate.clone(),
            &DeterministicTestVerifier,
            signing_authority,
        )
        .unwrap();
    certificate
}

#[test]
fn every_validator_derives_the_same_full_epoch_ring() {
    let validators = validator_set([1, 1, 1, 1, 1]);
    let expected = derive_epoch_leader_ring(
        Hash::from_domain_bytes("test-epoch-seed", b"epoch-7"),
        &validators,
    )
    .unwrap();
    for rotation in 0..validators.validators.len() {
        let mut reordered = validators.clone();
        reordered.validators.rotate_left(rotation);
        assert_eq!(
            derive_epoch_leader_ring(
                Hash::from_domain_bytes("test-epoch-seed", b"epoch-7"),
                &reordered,
            )
            .unwrap(),
            expected
        );
    }
}

#[test]
fn leader_identity_depends_only_on_epoch_height_and_verified_tc_offset() {
    let validators = validator_set([1, 1, 1, 1, 1]);
    let context = epoch_context(&validators, 1_024);
    for height in 1_000..=1_024 {
        for round in 0..15 {
            let first = context.authorized_proposer(Height(height), round).unwrap();
            let different_clock_and_health_observation =
                context.authorized_proposer(Height(height), round).unwrap();
            assert_eq!(first, different_clock_and_health_observation);
        }
    }
    assert_eq!(
        context.scheduled_owner(Height(1_000)).unwrap(),
        context.scheduled_owner(Height(1_009)).unwrap()
    );
    assert_ne!(
        context.scheduled_owner(Height(1_009)).unwrap(),
        context.scheduled_owner(Height(1_010)).unwrap()
    );
    assert_eq!(context.lease_index(Height(1_024)).unwrap(), 2);
    assert_eq!(
        context.scheduled_owner(Height(1_020)).unwrap(),
        context.scheduled_owner(Height(1_024)).unwrap(),
        "a partial final lease retains one deterministic owner"
    );
}

#[test]
fn epoch_boundary_derives_a_new_context_and_deterministic_ring() {
    let validators = validator_set([1, 1, 1, 1, 1]);
    let first = epoch_context(&validators, 1_024);
    let second = SimplifiedEpochContext::derive(
        Epoch(7),
        Height(1_025),
        Height(1_049),
        Hash::from_domain_bytes("test-epoch-seed", b"epoch-8"),
        ConsensusParameterRoot::from_canonical_manifest_bytes(b"posy-v3-test-manifest"),
        &validators,
    )
    .unwrap();
    let independently_derived = derive_epoch_leader_ring(
        Hash::from_domain_bytes("test-epoch-seed", b"epoch-8"),
        &validators,
    )
    .unwrap();
    assert_eq!(second.leader_ring, independently_derived);
    assert_ne!(first.root().unwrap(), second.root().unwrap());
    assert_eq!(second.lease_index(Height(1_025)).unwrap(), 0);
}

#[test]
fn strict_dual_quorum_is_four_of_five_and_exact_weight() {
    assert!(verify_strict_dual_quorum(4, 5, 4, 5).is_ok());
    assert!(verify_strict_dual_quorum(3, 5, 3, 5)
        .unwrap_err()
        .contains("distinct-signer"));
    assert!(verify_strict_dual_quorum(4, 5, 6, 10)
        .unwrap_err()
        .contains("frozen-weight"));
    assert!(verify_strict_dual_quorum(4, 5, 7, 10).is_ok());
}

#[test]
fn model_all_four_of_five_quorums_intersect_in_at_least_three_validators() {
    let quorums = (0u8..32)
        .filter(|mask| mask.count_ones() >= 4)
        .collect::<Vec<_>>();
    for left in &quorums {
        for right in &quorums {
            assert!((left & right).count_ones() >= 3);
        }
    }
    // Durable non-equivocation plus this intersection prevents two
    // conflicting QCs in the modeled at-most-one-Byzantine fault bound.
}

#[test]
fn launch_preflight_rejects_one_third_weight_holder() {
    let unsafe_weights = validator_set([4, 2, 2, 2, 2]);
    assert!(validate_single_validator_failure_liveness(&unsafe_weights)
        .unwrap_err()
        .contains("at least one third"));
}

#[test]
fn qc_identity_is_independent_of_vote_arrival_order() {
    let validators = validator_set([1, 1, 1, 1, 1]);
    let context = epoch_context(&validators, 1_030);
    let left = qc(
        &context,
        &validators,
        1_000,
        0,
        "block-a",
        &anchor(),
        None,
        &[0, 1, 2, 3],
    );
    let right = qc(
        &context,
        &validators,
        1_000,
        0,
        "block-a",
        &anchor(),
        None,
        &[3, 1, 0, 2],
    );
    assert_eq!(left, right);
    assert_eq!(left.id().unwrap(), right.id().unwrap());
    assert!(left
        .verify(&context, &validators, &DeterministicTestVerifier)
        .is_ok());
}

#[test]
fn certificate_subject_ids_converge_across_valid_quorum_subsets() {
    let validators = validator_set([1, 1, 1, 1, 1]);
    let context = epoch_context(&validators, 1_030);
    let first_qc = qc(
        &context,
        &validators,
        1_000,
        0,
        "same-certified-block",
        &anchor(),
        None,
        &[0, 1, 2, 3],
    );
    let second_qc = qc(
        &context,
        &validators,
        1_000,
        0,
        "same-certified-block",
        &anchor(),
        None,
        &[1, 2, 3, 4],
    );
    assert_ne!(first_qc.participants, second_qc.participants);
    assert_eq!(first_qc.id().unwrap(), second_qc.id().unwrap());
    assert_eq!(
        first_qc.reference().unwrap(),
        second_qc.reference().unwrap()
    );

    let left_machine = state_machine("tc-subset-left", &context, &validators);
    let right_machine = state_machine("tc-subset-right", &context, &validators);
    let first_tc = tc(&left_machine, &context, &validators, &[0, 1, 2, 3]);
    let second_tc = tc(&right_machine, &context, &validators, &[1, 2, 3, 4]);
    assert_ne!(first_tc.reports, second_tc.reports);
    assert_eq!(first_tc.id().unwrap(), second_tc.id().unwrap());

    let journal = authority("qc-subset-authority-root");
    let mut left = state_machine("qc-subset-state-left", &context, &validators);
    let mut right = state_machine("qc-subset-state-right", &context, &validators);
    left.accept_quorum_certificate(first_qc, &DeterministicTestVerifier, &journal)
        .unwrap();
    right
        .accept_quorum_certificate(second_qc, &DeterministicTestVerifier, &journal)
        .unwrap();
    assert_eq!(
        left.state().consensus_authority_root().unwrap(),
        right.state().consensus_authority_root().unwrap()
    );
}

#[test]
fn timeout_closure_id_is_independent_of_every_valid_four_of_five_report_subset() {
    let validators = validator_set([1, 1, 1, 1, 1]);
    let context = epoch_context(&validators, 1_030);
    let reports = (0..5)
        .map(|signer_index| {
            timeout_vote(
                &context,
                &validators,
                Height(1_000),
                Round(0),
                None,
                anchor(),
                None,
                signer_index,
            )
        })
        .collect::<Vec<_>>();
    let mut expected_id = None;

    for omitted in 0..reports.len() {
        let subset = reports
            .iter()
            .enumerate()
            .filter(|(index, _)| *index != omitted)
            .map(|(_, report)| report.clone())
            .collect::<Vec<_>>();
        let certificate = SimplifiedTimeoutCertificate::from_votes(subset).unwrap();
        certificate
            .verify(&context, &validators, &DeterministicTestVerifier)
            .unwrap();
        let certificate_id = certificate.id().unwrap();
        if let Some(expected_id) = expected_id {
            assert_eq!(certificate_id, expected_id);
        } else {
            expected_id = Some(certificate_id);
        }
    }
}

#[test]
fn heterogeneous_timeout_reports_choose_one_maximum_and_require_every_qc_proof() {
    let validators = validator_set([1, 1, 1, 1, 1]);
    let context = epoch_context(&validators, 1_030);
    let lower_qc = qc(
        &context,
        &validators,
        1_000,
        0,
        "heterogeneous-lower",
        &anchor(),
        None,
        &[0, 1, 2, 3],
    );
    let higher_qc = qc(
        &context,
        &validators,
        1_001,
        0,
        "heterogeneous-higher",
        &lower_qc.reference().unwrap(),
        None,
        &[0, 1, 2, 3],
    );
    let lower_reference = lower_qc.reference().unwrap();
    let higher_reference = higher_qc.reference().unwrap();
    let reports = [
        lower_reference.clone(),
        higher_reference.clone(),
        lower_reference,
        higher_reference.clone(),
    ]
    .into_iter()
    .enumerate()
    .map(|(signer_index, highest_qc)| {
        timeout_vote(
            &context,
            &validators,
            Height(1_002),
            Round(0),
            None,
            highest_qc,
            None,
            signer_index,
        )
    })
    .collect::<Vec<_>>();

    let absent = SimplifiedTimeoutCertificate::from_votes(reports.clone()).unwrap();
    assert!(absent
        .verify(&context, &validators, &DeterministicTestVerifier)
        .unwrap_err()
        .contains("omits a full proof"));

    let incomplete = SimplifiedTimeoutCertificate::from_votes_with_qc_proofs(
        reports.clone(),
        vec![lower_qc.clone()],
    )
    .unwrap();
    assert!(incomplete
        .verify(&context, &validators, &DeterministicTestVerifier)
        .unwrap_err()
        .contains("omits a full proof"));

    let complete = SimplifiedTimeoutCertificate::from_votes_with_qc_proofs(
        reports.clone(),
        vec![lower_qc.clone(), higher_qc.clone()],
    )
    .unwrap();
    complete
        .verify(&context, &validators, &DeterministicTestVerifier)
        .unwrap();
    assert_eq!(complete.highest_qc().unwrap(), higher_reference);

    let reversed = SimplifiedTimeoutCertificate::from_votes_with_qc_proofs(
        reports.into_iter().rev().collect(),
        vec![higher_qc, lower_qc],
    )
    .unwrap();
    assert_eq!(
        reversed.highest_qc().unwrap(),
        complete.highest_qc().unwrap()
    );
}

#[test]
fn every_valid_timeout_subset_carries_the_candidate_with_a_hidden_qc() {
    let validators = validator_set([1, 1, 1, 1, 1]);
    let context = epoch_context(&validators, 1_030);
    let hidden_qc = qc(
        &context,
        &validators,
        1_000,
        0,
        "hidden-certified-candidate",
        &anchor(),
        None,
        &[0, 1, 2, 3],
    );
    let hidden_candidate = hidden_qc.subject().unwrap();
    let reports = (0..5)
        .map(|signer_index| {
            // Validator 0 models the one Byzantine hidden-QC signer and may
            // omit its prior vote. The other three hidden-QC signers report
            // it, so every 4-of-5 TC still contains at least f+1 reports.
            let last_voted_candidate = [1, 2, 3]
                .contains(&signer_index)
                .then(|| hidden_candidate.clone());
            timeout_vote(
                &context,
                &validators,
                Height(1_000),
                Round(0),
                None,
                anchor(),
                last_voted_candidate,
                signer_index,
            )
        })
        .collect::<Vec<_>>();

    for omitted in 0..reports.len() {
        let subset = reports
            .iter()
            .enumerate()
            .filter(|(index, _)| *index != omitted)
            .map(|(_, report)| report.clone())
            .collect::<Vec<_>>();
        let certificate = SimplifiedTimeoutCertificate::from_votes(subset).unwrap();
        certificate
            .verify(&context, &validators, &DeterministicTestVerifier)
            .unwrap();
        assert_eq!(
            certificate.mandatory_carry_candidate().unwrap(),
            Some(hidden_candidate.clone())
        );
    }
}

#[test]
fn every_dynamic_seven_validator_timeout_quorum_carries_a_possible_hidden_qc() {
    let validators = validator_set([1, 1, 1, 1, 1, 1, 1]);
    let context = epoch_context(&validators, 1_030);
    let hidden_qc = qc(
        &context,
        &validators,
        1_000,
        0,
        "hidden-seven-validator-candidate",
        &anchor(),
        None,
        &[0, 1, 2, 3, 4],
    );
    let hidden_candidate = hidden_qc.subject().unwrap();
    let reports = (0..7)
        .map(|signer_index| {
            // Validator 0 is the one faulty hidden-QC signer and may omit its
            // vote. The remaining four QC signers report the stable candidate.
            let last_voted_candidate = (1..=4)
                .contains(&signer_index)
                .then(|| hidden_candidate.clone());
            timeout_vote(
                &context,
                &validators,
                Height(1_000),
                Round(0),
                None,
                anchor(),
                last_voted_candidate,
                signer_index,
            )
        })
        .collect::<Vec<_>>();

    // q=floor(2*7/3)+1=5. Enumerate every 5-of-7 TC report subset.
    for first_omitted in 0..reports.len() {
        for second_omitted in (first_omitted + 1)..reports.len() {
            let subset = reports
                .iter()
                .enumerate()
                .filter(|(index, _)| *index != first_omitted && *index != second_omitted)
                .map(|(_, report)| report.clone())
                .collect::<Vec<_>>();
            let certificate = SimplifiedTimeoutCertificate::from_votes(subset).unwrap();
            certificate
                .verify(&context, &validators, &DeterministicTestVerifier)
                .unwrap();
            assert_eq!(
                certificate.mandatory_carry_candidate().unwrap(),
                Some(hidden_candidate.clone()),
                "dynamic TC omitted signers {first_omitted} and {second_omitted}",
            );
        }
    }
}

#[test]
fn all_timeout_subsets_carry_every_possible_hidden_qc_and_unlock_only_nonquorate_support() {
    let validators = validator_set([1, 1, 1, 1, 1]);
    let context = epoch_context(&validators, 1_030);
    let candidate = CertifiedCandidateSubject::new(
        ConsensusObjectContext::for_height(&context, Height(1_000), Round(0)).unwrap(),
        BlockId("timeout-subset-candidate".to_string()),
        anchor().block_id,
        anchor(),
        Hash::from_domain_bytes("protected", b"timeout-subset-candidate"),
    )
    .unwrap();

    // Index 0 models the one Byzantine validator and never reports its vote.
    // Indices 1..=4 are honest. Enumerate every possible honest prior-voter
    // count and every valid 4-of-5 TC subset.
    for honest_prior_voters in 0..=4 {
        let reports = (0..5)
            .map(|signer_index| {
                let reports_candidate = signer_index > 0 && signer_index <= honest_prior_voters;
                timeout_vote(
                    &context,
                    &validators,
                    Height(1_000),
                    Round(0),
                    None,
                    anchor(),
                    reports_candidate.then(|| candidate.clone()),
                    signer_index,
                )
            })
            .collect::<Vec<_>>();

        for omitted in 0..reports.len() {
            let subset = reports
                .iter()
                .enumerate()
                .filter(|(index, _)| *index != omitted)
                .map(|(_, report)| report.clone())
                .collect::<Vec<_>>();
            let reported_honest_votes = subset
                .iter()
                .filter(|report| report.last_voted_candidate.is_some())
                .count();
            let certificate = SimplifiedTimeoutCertificate::from_votes(subset).unwrap();
            certificate
                .verify(&context, &validators, &DeterministicTestVerifier)
                .unwrap();

            assert_eq!(
                certificate.mandatory_carry_candidate().unwrap(),
                (reported_honest_votes >= 2).then(|| candidate.clone()),
                "unexpected carry result with {honest_prior_voters} honest prior voters and omitted signer {omitted}",
            );

            if honest_prior_voters >= 3 {
                // Three honest votes plus the Byzantine vote can form a hidden
                // QC. Every four-report TC subset must therefore carry.
                assert!(reported_honest_votes >= 2);
            } else if reported_honest_votes < 2 {
                // At most two honest votes plus the Byzantine vote cannot meet
                // the strict four-signature QC. Only these schedules may
                // legitimately yield the verified no-carry unlock.
                assert!(honest_prior_voters <= 2);
            }
        }
    }
}

#[test]
fn certified_candidate_id_is_independent_of_round_and_takeover_envelope() {
    let validators = validator_set([1, 1, 1, 1, 1]);
    let context = epoch_context(&validators, 1_030);
    let initial = qc(
        &context,
        &validators,
        1_000,
        0,
        "stable-candidate",
        &anchor(),
        None,
        &[0, 1, 2, 3],
    );
    let takeover = qc(
        &context,
        &validators,
        1_000,
        1,
        "stable-candidate",
        &anchor(),
        Some(Hash::from_domain_bytes("test-takeover", b"round-0")),
        &[1, 2, 3, 4],
    );

    assert_ne!(initial.context.round, takeover.context.round);
    assert_ne!(initial.takeover_tc_id, takeover.takeover_tc_id);
    initial
        .verify(&context, &validators, &DeterministicTestVerifier)
        .unwrap();
    takeover
        .verify(&context, &validators, &DeterministicTestVerifier)
        .unwrap();
    assert_eq!(initial.subject().unwrap(), takeover.subject().unwrap());
    assert_eq!(initial.id().unwrap(), takeover.id().unwrap());
    assert_eq!(initial.reference().unwrap(), takeover.reference().unwrap());
}

#[test]
fn timeout_takeover_inherits_only_the_current_lease() {
    let validators = validator_set([1, 1, 1, 1, 1]);
    let context = epoch_context(&validators, 1_030);
    let mut machine = state_machine("lease-takeover", &context, &validators);
    let signer_journal = authority("lease-takeover");
    for height in 1_000..=1_002 {
        accept_next_qc(
            &mut machine,
            &context,
            &validators,
            &signer_journal,
            &format!("block-{height}"),
        );
    }
    let scheduled = context.scheduled_owner(Height(1_003)).unwrap().clone();
    let first_tc = tc(&machine, &context, &validators, &[0, 1, 2, 3]);
    machine
        .accept_timeout_certificate(first_tc, &DeterministicTestVerifier)
        .unwrap();
    let successor = context
        .authorized_proposer(Height(1_003), 1)
        .unwrap()
        .clone();
    assert_ne!(scheduled, successor);
    for height in 1_003..=1_009 {
        assert_eq!(
            machine
                .state()
                .takeover_for_height(&context, Height(height))
                .unwrap()
                .0,
            1
        );
        accept_next_qc(
            &mut machine,
            &context,
            &validators,
            &signer_journal,
            &format!("block-{height}"),
        );
    }
    assert_eq!(
        context.scheduled_owner(Height(1_010)).unwrap(),
        &successor,
        "the successor intentionally continues through its own following lease"
    );
    assert_eq!(
        machine
            .state()
            .takeover_for_height(&context, Height(1_010))
            .unwrap(),
        (0, None),
        "takeover is reset at the predetermined lease boundary"
    );
}

#[test]
fn sequential_tcs_advance_to_the_third_ring_member_and_reject_replay() {
    let validators = validator_set([1, 1, 1, 1, 1]);
    let context = epoch_context(&validators, 1_030);
    let mut machine = state_machine("sequential-tc", &context, &validators);
    let first = tc(&machine, &context, &validators, &[0, 1, 2, 3]);
    machine
        .accept_timeout_certificate(first.clone(), &DeterministicTestVerifier)
        .unwrap();
    assert!(machine
        .accept_timeout_certificate(first, &DeterministicTestVerifier)
        .unwrap_err()
        .contains("stale, skipped, or non-sequential"));
    let second = tc(&machine, &context, &validators, &[0, 1, 2, 3]);
    machine
        .accept_timeout_certificate(second, &DeterministicTestVerifier)
        .unwrap();
    assert_eq!(
        machine
            .state()
            .takeover_for_height(&context, Height(1_000))
            .unwrap()
            .0,
        2
    );
    assert_eq!(
        context.authorized_proposer(Height(1_000), 2).unwrap(),
        &context.leader_ring[2]
    );
}

#[test]
fn replacement_can_certify_then_time_out_later_in_the_same_lease() {
    let validators = validator_set([1, 1, 1, 1, 1]);
    let context = epoch_context(&validators, 1_030);
    let signer_journal = authority("later-same-lease-tc");
    let path = temp_path("later-same-lease-tc");
    let mut machine = SimplifiedConsensusStateMachine::open(
        context.clone(),
        validators.clone(),
        DurableSimplifiedPosyStore::at_path(path.clone()),
        anchor(),
    )
    .unwrap();

    let first = tc(&machine, &context, &validators, &[0, 1, 2, 3]);
    machine
        .accept_timeout_certificate(first.clone(), &DeterministicTestVerifier)
        .unwrap();
    accept_next_qc(
        &mut machine,
        &context,
        &validators,
        &signer_journal,
        "block-1000-by-replacement",
    );

    let second = tc(&machine, &context, &validators, &[0, 1, 2, 3]);
    assert_eq!(second.context.height, Height(1_001));
    assert_eq!(second.context.round, Round(1));
    assert_eq!(second.previous_tc_id, Some(first.id().unwrap()));
    machine
        .accept_timeout_certificate(second.clone(), &DeterministicTestVerifier)
        .unwrap();
    assert_eq!(
        machine
            .state()
            .takeover_for_height(&context, Height(1_001))
            .unwrap(),
        (2, Some(second.id().unwrap()))
    );
    machine.state().validate(&context).unwrap();

    let expected = machine.state().clone();
    drop(machine);
    let restarted = SimplifiedConsensusStateMachine::open(
        context,
        validators,
        DurableSimplifiedPosyStore::at_path(path),
        anchor(),
    )
    .unwrap();
    assert_eq!(restarted.state(), &expected);
}

#[test]
fn wrong_height_and_wrong_round_timeout_certificates_fail_closed() {
    let validators = validator_set([1, 1, 1, 1, 1]);
    let context = epoch_context(&validators, 1_030);
    let mut machine = state_machine("wrong-tc", &context, &validators);

    let mut wrong_height = tc(&machine, &context, &validators, &[0, 1, 2, 3]);
    wrong_height.context.height = Height(1_001);
    wrong_height.lease_index = context.lease_index(Height(1_001)).unwrap();
    wrong_height.timed_out_proposer = context
        .authorized_proposer(Height(1_001), 0)
        .unwrap()
        .clone();
    resign_tc(&mut wrong_height, &validators);
    assert!(machine
        .accept_timeout_certificate(wrong_height, &DeterministicTestVerifier)
        .unwrap_err()
        .contains("stale, skipped, or non-sequential"));

    let mut wrong_round = tc(&machine, &context, &validators, &[0, 1, 2, 3]);
    wrong_round.context.round = Round(1);
    wrong_round.previous_tc_id = Some(Hash::from_domain_bytes("wrong-tc", b"missing"));
    wrong_round.timed_out_proposer = context
        .authorized_proposer(Height(1_000), 1)
        .unwrap()
        .clone();
    resign_tc(&mut wrong_round, &validators);
    assert!(machine
        .accept_timeout_certificate(wrong_round, &DeterministicTestVerifier)
        .unwrap_err()
        .contains("stale, skipped, or non-sequential"));
}

#[test]
fn timeout_takeover_never_erases_or_bypasses_the_qc_lock() {
    let validators = validator_set([1, 1, 1, 1, 1]);
    let context = epoch_context(&validators, 1_030);
    let signer_journal = authority("tc-lock");
    let mut machine = state_machine("tc-lock", &context, &validators);
    accept_next_qc(
        &mut machine,
        &context,
        &validators,
        &signer_journal,
        "block-1000",
    );
    accept_next_qc(
        &mut machine,
        &context,
        &validators,
        &signer_journal,
        "block-1001",
    );
    let lock_before = machine.state().locked_qc.clone();
    let timeout = tc(&machine, &context, &validators, &[0, 1, 2, 3]);
    machine
        .accept_timeout_certificate(timeout, &DeterministicTestVerifier)
        .unwrap();
    assert_eq!(machine.state().locked_qc, lock_before);

    let proposer = context
        .authorized_proposer(Height(1_002), 1)
        .unwrap()
        .clone();
    let proposer_record = validators
        .validators
        .iter()
        .find(|validator| validator.validator_id == proposer)
        .unwrap();
    let mut unsafe_proposal = SimplifiedProposal {
        context: ConsensusObjectContext::for_height(&context, Height(1_002), Round(1)).unwrap(),
        proposer_id: proposer.clone(),
        block_id: BlockId("unsafe-fork".to_string()),
        parent_block_id: anchor().block_id,
        parent_qc: anchor(),
        takeover_tc_id: machine
            .state()
            .takeover_for_height(&context, Height(1_002))
            .unwrap()
            .1,
        protected_execution_root: Hash::from_domain_bytes("protected", b"unsafe-fork"),
        proposer_key_id: proposer_record.consensus_public_key.key_id.clone(),
        proposer_signature: AegisPqSignature {
            algorithm: String::new(),
            signature_bytes: Vec::new(),
        },
    };
    unsafe_proposal.proposer_signature = fake_signature(
        POSY_SIMPLIFIED_PROPOSAL_DOMAIN,
        &unsafe_proposal.signing_bytes().unwrap(),
        &proposer,
        &unsafe_proposal.proposer_key_id,
    );
    assert!(machine
        .validate_proposal(&unsafe_proposal, &DeterministicTestVerifier)
        .is_err());
    assert_eq!(machine.state().locked_qc, lock_before);
}

#[test]
fn three_chain_finality_crosses_takeover_and_lease_boundaries() {
    let validators = validator_set([1, 1, 1, 1, 1]);
    let context = epoch_context(&validators, 1_030);
    let signer_journal = authority("three-chain");
    let mut machine = state_machine("three-chain", &context, &validators);
    for height in 1_000..=1_008 {
        accept_next_qc(
            &mut machine,
            &context,
            &validators,
            &signer_journal,
            &format!("block-{height}"),
        );
    }
    let takeover = tc(&machine, &context, &validators, &[0, 1, 2, 3]);
    machine
        .accept_timeout_certificate(takeover, &DeterministicTestVerifier)
        .unwrap();
    accept_next_qc(
        &mut machine,
        &context,
        &validators,
        &signer_journal,
        "block-1009",
    );
    accept_next_qc(
        &mut machine,
        &context,
        &validators,
        &signer_journal,
        "block-1010",
    );
    accept_next_qc(
        &mut machine,
        &context,
        &validators,
        &signer_journal,
        "block-1011",
    );
    assert_eq!(machine.state().finalized.height, Height(1_009));
    assert_eq!(
        machine.state().finalized.block_id,
        BlockId("block-1009".to_string())
    );
}

#[test]
fn restart_restores_lock_vote_takeover_and_finalized_state() {
    let validators = validator_set([1, 1, 1, 1, 1]);
    let context = epoch_context(&validators, 1_030);
    let path = temp_path("restart");
    let store = DurableSimplifiedPosyStore::at_path(path.clone());
    let mut machine =
        SimplifiedConsensusStateMachine::open(context.clone(), validators.clone(), store, anchor())
            .unwrap();
    let signer_journal = authority("restart");
    accept_next_qc(
        &mut machine,
        &context,
        &validators,
        &signer_journal,
        "block-1000",
    );
    let timeout = tc(&machine, &context, &validators, &[0, 1, 2, 3]);
    machine
        .accept_timeout_certificate(timeout, &DeterministicTestVerifier)
        .unwrap();
    let before = machine.state().clone();
    drop(machine);
    let restarted = SimplifiedConsensusStateMachine::open(
        context,
        validators,
        DurableSimplifiedPosyStore::at_path(path),
        anchor(),
    )
    .unwrap();
    assert_eq!(restarted.state(), &before);
    assert_eq!(
        restarted.state().takeover.as_ref().unwrap().takeover_offset,
        1
    );
}

#[test]
fn timeout_certificate_persist_failure_keeps_live_state_unchanged() {
    let validators = validator_set([1, 1, 1, 1, 1]);
    let context = epoch_context(&validators, 1_030);
    let path = temp_path("tc-persist-failure");
    let mut machine = SimplifiedConsensusStateMachine::open(
        context.clone(),
        validators.clone(),
        DurableSimplifiedPosyStore::at_path(path.clone()),
        anchor(),
    )
    .unwrap();
    let certificate = tc(&machine, &context, &validators, &[0, 1, 2, 3]);
    let before = machine.state().clone();
    fs::remove_file(&path).unwrap();
    fs::create_dir(&path).unwrap();

    machine
        .accept_timeout_certificate(certificate, &DeterministicTestVerifier)
        .unwrap_err();

    assert_eq!(machine.state(), &before);
}

#[test]
fn quorum_certificate_persist_failure_keeps_live_state_unchanged() {
    let validators = validator_set([1, 1, 1, 1, 1]);
    let context = epoch_context(&validators, 1_030);
    let path = temp_path("qc-persist-failure");
    let mut machine = SimplifiedConsensusStateMachine::open(
        context.clone(),
        validators.clone(),
        DurableSimplifiedPosyStore::at_path(path.clone()),
        anchor(),
    )
    .unwrap();
    let signing_authority = authority("qc-persist-failure");
    accept_next_qc(
        &mut machine,
        &context,
        &validators,
        &signing_authority,
        "block-1000",
    );
    accept_next_qc(
        &mut machine,
        &context,
        &validators,
        &signing_authority,
        "block-1001",
    );
    let certificate = qc(
        &context,
        &validators,
        1_002,
        0,
        "unpersisted-block-1002",
        &machine.state().highest_qc,
        None,
        &[0, 1, 2, 3],
    );
    let before = machine.state().clone();
    fs::remove_file(&path).unwrap();
    fs::create_dir(&path).unwrap();

    machine
        .accept_quorum_certificate(certificate, &DeterministicTestVerifier, &signing_authority)
        .unwrap_err();

    assert_eq!(machine.state(), &before);
}

#[test]
fn verified_state_sync_reconstructs_qc_tc_lock_and_finality_state() {
    let validators = validator_set([1, 1, 1, 1, 1]);
    let context = epoch_context(&validators, 1_030);
    let signer_journal = authority("state-sync-source");
    let mut source = state_machine("state-sync-source", &context, &validators);
    for height in 1_000..=1_002 {
        accept_next_qc(
            &mut source,
            &context,
            &validators,
            &signer_journal,
            &format!("block-{height}"),
        );
    }
    let timeout = tc(&source, &context, &validators, &[0, 1, 2, 3]);
    source
        .accept_timeout_certificate(timeout, &DeterministicTestVerifier)
        .unwrap();
    let bundle = source.export_state_sync_bundle().unwrap();

    let local_vote = LastVoteRecord {
        height: Height(1_003),
        round: Round(0),
        candidate: CertifiedCandidateSubject::new(
            ConsensusObjectContext::for_height(&context, Height(1_003), Round(0)).unwrap(),
            BlockId("locally-signed-before-sync".to_string()),
            source.state().highest_qc.block_id.clone(),
            source.state().highest_qc.clone(),
            Hash::from_domain_bytes("local-protected-execution", b"do-not-overwrite"),
        )
        .unwrap(),
        transcript_root: Hash::from_domain_bytes("local-vote", b"do-not-overwrite"),
    };
    let reconstructed = bundle
        .verify_and_reconstruct(
            &context,
            &validators,
            &anchor(),
            &DeterministicTestVerifier,
            Some(local_vote.clone()),
            None,
        )
        .unwrap();
    assert_eq!(reconstructed.highest_qc, source.state().highest_qc);
    assert_eq!(reconstructed.locked_qc, source.state().locked_qc);
    assert_eq!(reconstructed.finalized, source.state().finalized);
    assert_eq!(reconstructed.takeover, source.state().takeover);
    assert_eq!(reconstructed.last_vote, Some(local_vote));

    let mut target = state_machine("state-sync-target", &context, &validators);
    let target_authority = authority("state-sync-target");
    target
        .install_state_sync_bundle(&bundle, &DeterministicTestVerifier, &target_authority)
        .unwrap();
    assert_eq!(target.state().highest_qc, source.state().highest_qc);
    assert_eq!(target.state().takeover, source.state().takeover);

    let mut tampered = bundle;
    tampered.claimed_finalized.block_id = BlockId("unproven-finalized-head".to_string());
    assert!(tampered
        .verify_and_reconstruct(
            &context,
            &validators,
            &anchor(),
            &DeterministicTestVerifier,
            None,
            None,
        )
        .unwrap_err()
        .contains("not derivable"));
}

#[test]
fn state_sync_conflicting_qc_enters_safety_halt_before_fork_ordering() {
    let validators = validator_set([1, 1, 1, 1, 1]);
    let context = epoch_context(&validators, 1_099);
    let mut local = state_machine("state-sync-conflict-local", &context, &validators);
    let local_authority = authority("state-sync-conflict-local");
    let mut peer = state_machine("state-sync-conflict-peer", &context, &validators);
    let peer_authority = authority("state-sync-conflict-peer");

    accept_next_qc(
        &mut local,
        &context,
        &validators,
        &local_authority,
        "local-height-1000",
    );
    accept_next_qc(
        &mut peer,
        &context,
        &validators,
        &peer_authority,
        "peer-height-1000",
    );
    let peer_bundle = peer.export_state_sync_bundle().unwrap();
    let error = local
        .install_state_sync_bundle(&peer_bundle, &DeterministicTestVerifier, &local_authority)
        .unwrap_err();
    assert!(error.contains("CONSENSUS_SAFETY_HALT"));
    assert_eq!(
        local.state().safety_halt.as_ref().map(|halt| &halt.kind),
        Some(&crate::consensus::signing_authority::SafetyHaltKind::ConflictingQuorumCertificates)
    );
    assert!(local_authority.require_signing_allowed().is_err());
    assert_eq!(
        local.state().certified_qcs.get(&1_000).unwrap().block_id,
        BlockId("local-height-1000".to_string())
    );
}

#[test]
fn conflicting_valid_qcs_enter_irreversible_safety_halt() {
    let validators = validator_set([1, 1, 1, 1, 1]);
    let context = epoch_context(&validators, 1_030);
    let mut machine = state_machine("conflicting-qc", &context, &validators);
    let signer_journal = authority("conflicting-qc");
    let first = qc(
        &context,
        &validators,
        1_000,
        0,
        "block-a",
        &anchor(),
        None,
        &[0, 1, 2, 3],
    );
    let second = qc(
        &context,
        &validators,
        1_000,
        0,
        "block-b",
        &anchor(),
        None,
        &[0, 1, 2, 3],
    );
    machine
        .accept_quorum_certificate(first, &DeterministicTestVerifier, &signer_journal)
        .unwrap();
    assert!(machine
        .accept_quorum_certificate(second, &DeterministicTestVerifier, &signer_journal)
        .unwrap_err()
        .contains("CONSENSUS_SAFETY_HALT"));
    assert!(machine.state().safety_halt.is_some());
    assert!(signer_journal.require_signing_allowed().is_err());
}

#[test]
fn hidden_qc_conflict_is_detected_even_after_local_takeover_advanced() {
    let validators = validator_set([1, 1, 1, 1, 1]);
    let context = epoch_context(&validators, 1_030);
    let mut machine = state_machine("hidden-qc-conflict", &context, &validators);
    let signer_journal = authority("hidden-qc-conflict");
    let first = qc(
        &context,
        &validators,
        1_000,
        0,
        "hidden-block-a",
        &anchor(),
        None,
        &[0, 1, 2, 3],
    );
    machine
        .accept_quorum_certificate(first, &DeterministicTestVerifier, &signer_journal)
        .unwrap();

    // The second certificate is independently valid evidence for the same
    // height but names a later takeover subject unknown to this local state.
    // Conflict detection must run before a local stale/takeover classification
    // or honest replicas could silently retain different QCs.
    let second = qc(
        &context,
        &validators,
        1_000,
        1,
        "hidden-block-b",
        &anchor(),
        Some(Hash::from_domain_bytes("hidden-tc", b"round-0")),
        &[1, 2, 3, 4],
    );
    assert!(machine
        .accept_quorum_certificate(second, &DeterministicTestVerifier, &signer_journal)
        .unwrap_err()
        .contains("CONSENSUS_SAFETY_HALT"));
}

#[test]
fn last_vote_prohibits_a_different_candidate_across_takeover_rounds() {
    let validators = validator_set([1, 1, 1, 1, 1]);
    let context = epoch_context(&validators, 1_030);
    let prior_candidate = CertifiedCandidateSubject::new(
        ConsensusObjectContext::for_height(&context, Height(1_000), Round(0)).unwrap(),
        BlockId("hidden-block-a".to_string()),
        anchor().block_id,
        anchor(),
        Hash::from_domain_bytes("protected", b"hidden-block-a"),
    )
    .unwrap();
    let takeover = SimplifiedTimeoutCertificate::from_votes(
        (0..4)
            .map(|index| {
                timeout_vote(
                    &context,
                    &validators,
                    Height(1_000),
                    Round(0),
                    None,
                    anchor(),
                    Some(prior_candidate.clone()),
                    index,
                )
            })
            .collect(),
    )
    .unwrap();
    let path = temp_path("cross-round-vote");
    let store = DurableSimplifiedPosyStore::at_path(path.clone());
    let mut state = SimplifiedSafetyState::new(&context, anchor()).unwrap();
    state.takeover = Some(LeaseTakeoverState {
        lease_index: 0,
        effective_height: Height(1_000),
        takeover_offset: 1,
        certificates: vec![takeover.clone()],
    });
    state.certified_tcs.insert(1_000, vec![takeover.clone()]);
    state.last_vote = Some(LastVoteRecord {
        height: Height(1_000),
        round: Round(0),
        candidate: prior_candidate,
        transcript_root: Hash::from_domain_bytes("vote", b"hidden-block-a-round-0"),
    });
    store.persist(&context, &state).unwrap();
    let mut machine = SimplifiedConsensusStateMachine::open(
        context.clone(),
        validators.clone(),
        DurableSimplifiedPosyStore::at_path(path),
        anchor(),
    )
    .unwrap();
    let proposer_id = context
        .authorized_proposer(Height(1_000), 1)
        .unwrap()
        .clone();
    let proposer = validators
        .validators
        .iter()
        .find(|validator| validator.validator_id == proposer_id)
        .unwrap();
    let mut proposal = SimplifiedProposal {
        context: ConsensusObjectContext::for_height(&context, Height(1_000), Round(1)).unwrap(),
        proposer_id: proposer_id.clone(),
        block_id: BlockId("hidden-block-b".to_string()),
        parent_block_id: anchor().block_id,
        parent_qc: anchor(),
        takeover_tc_id: Some(takeover.id().unwrap()),
        protected_execution_root: Hash::from_domain_bytes("protected", b"hidden-block-b"),
        proposer_key_id: proposer.consensus_public_key.key_id.clone(),
        proposer_signature: AegisPqSignature {
            algorithm: String::new(),
            signature_bytes: Vec::new(),
        },
    };
    proposal.proposer_signature = fake_signature(
        POSY_SIMPLIFIED_PROPOSAL_DOMAIN,
        &proposal.signing_bytes().unwrap(),
        &proposer_id,
        &proposal.proposer_key_id,
    );
    let voter = &validators.validators[0];
    let mut signer = AegisPqvmSigner::initialize_required().unwrap();
    assert!(machine
        .sign_block_vote(
            &proposal,
            &DeterministicTestVerifier,
            voter.validator_id.clone(),
            voter.consensus_public_key.key_id.clone(),
            &authority("cross-round-vote"),
            &mut signer,
        )
        .unwrap_err()
        .contains("TC-mandated stable candidate"));
}

#[test]
fn conflicting_chain_cannot_replace_an_already_finalized_head() {
    let validators = validator_set([1, 1, 1, 1, 1]);
    let context = epoch_context(&validators, 1_030);
    let signer_journal = authority("finalized-conflict");
    let mut machine = state_machine("finalized-conflict", &context, &validators);
    for height in 1_000..=1_002 {
        accept_next_qc(
            &mut machine,
            &context,
            &validators,
            &signer_journal,
            &format!("block-{height}"),
        );
    }
    let finalized_before = machine.state().finalized.clone();
    let conflicting = qc(
        &context,
        &validators,
        1_000,
        0,
        "conflicting-block-1000",
        &anchor(),
        None,
        &[0, 1, 2, 3],
    );
    assert!(machine
        .accept_quorum_certificate(conflicting, &DeterministicTestVerifier, &signer_journal,)
        .unwrap_err()
        .contains("CONSENSUS_SAFETY_HALT"));
    assert_eq!(machine.state().finalized, finalized_before);
}

#[test]
fn four_real_mldsa65_signatures_form_a_qc() {
    let mut signer = AegisPqvmSigner::initialize_required().unwrap();
    let mut records = Vec::new();
    for index in 0..5 {
        let uma = format!("uma:real-validator-{index}");
        let key_id = signer
            .generate_and_register_key(&uma, vec![AegisPqKeyRole::ConsensusVote], Epoch(7))
            .unwrap();
        let public_key = signer.public_key_record(&key_id).unwrap();
        records.push(ValidatorRecord {
            validator_id: ValidatorId(format!("real-validator-{index}")),
            validator_uma_id: UmaId(uma),
            consensus_public_key: public_key.clone(),
            peer_public_key: public_key.clone(),
            operator_public_key: public_key,
            voting_weight: 1,
            status: ValidatorStatus::Active,
            cluster_id: ClusterId(0),
            activation_epoch: Epoch(7),
        });
    }
    let validators = ValidatorSet {
        epoch: Epoch(7),
        validators: records,
    };
    let context = epoch_context(&validators, 1_030);
    let object_context =
        ConsensusObjectContext::for_height(&context, Height(1_000), Round(0)).unwrap();
    let mut votes = Vec::new();
    for validator in validators.validators.iter().take(4) {
        let mut vote = BlockVote {
            context: object_context.clone(),
            block_id: BlockId("real-pqc-block".to_string()),
            parent_block_id: anchor().block_id,
            parent_qc: anchor(),
            takeover_tc_id: None,
            protected_execution_root: Hash::from_domain_bytes(
                "real-protected-execution",
                b"real-pqc-block",
            ),
            validator_id: validator.validator_id.clone(),
            key_id: validator.consensus_public_key.key_id.clone(),
            signature: AegisPqSignature {
                algorithm: String::new(),
                signature_bytes: Vec::new(),
            },
        };
        vote.signature = signer
            .sign_domain(
                POSY_SIMPLIFIED_BLOCK_VOTE_DOMAIN,
                &vote.signing_bytes().unwrap(),
                &vote.key_id,
            )
            .unwrap();
        votes.push(vote);
    }
    let certificate = SimplifiedQuorumCertificate::from_votes(votes).unwrap();
    certificate
        .verify(&context, &validators, &signer.verifier())
        .unwrap();
}

#[test]
fn proposal_uses_real_mldsa65_and_the_durable_proposal_journal() {
    let mut signer = AegisPqvmSigner::initialize_required().unwrap();
    let mut records = Vec::new();
    for index in 0..5 {
        let uma = format!("uma:proposal-validator-{index}");
        let key_id = signer
            .generate_and_register_key(
                &uma,
                vec![
                    AegisPqKeyRole::ConsensusProposer,
                    AegisPqKeyRole::ConsensusVote,
                ],
                Epoch(7),
            )
            .unwrap();
        let public_key = signer.public_key_record(&key_id).unwrap();
        records.push(ValidatorRecord {
            validator_id: ValidatorId(format!("proposal-validator-{index}")),
            validator_uma_id: UmaId(uma),
            consensus_public_key: public_key.clone(),
            peer_public_key: public_key.clone(),
            operator_public_key: public_key,
            voting_weight: 1,
            status: ValidatorStatus::Active,
            cluster_id: ClusterId(0),
            activation_epoch: Epoch(7),
        });
    }
    let validators = ValidatorSet {
        epoch: Epoch(7),
        validators: records,
    };
    let context = epoch_context(&validators, 1_030);
    let mut machine = state_machine("real-proposal", &context, &validators);
    let proposer_id = context.scheduled_owner(Height(1_000)).unwrap().clone();
    let proposer = validators
        .validators
        .iter()
        .find(|validator| validator.validator_id == proposer_id)
        .unwrap();
    let proposal = SimplifiedProposal {
        context: ConsensusObjectContext::for_height(&context, Height(1_000), Round(0)).unwrap(),
        proposer_id,
        block_id: BlockId("real-proposal-block".to_string()),
        parent_block_id: anchor().block_id,
        parent_qc: anchor(),
        takeover_tc_id: None,
        protected_execution_root: Hash::from_domain_bytes("protected", b"real-proposal"),
        proposer_key_id: proposer.consensus_public_key.key_id.clone(),
        proposer_signature: AegisPqSignature {
            algorithm: String::new(),
            signature_bytes: Vec::new(),
        },
    };
    let journal = authority("real-proposal");
    let proposal = machine
        .sign_proposal(proposal, &journal, &mut signer)
        .unwrap();
    machine
        .validate_proposal(&proposal, &signer.verifier())
        .unwrap();
    assert!(journal.require_signing_allowed().is_ok());
}

#[test]
fn proposal_journal_restart_binds_the_complete_stable_candidate_subject() {
    let mut signer = AegisPqvmSigner::initialize_required().unwrap();
    let mut records = Vec::new();
    for index in 0..5 {
        let uma = format!("uma:proposal-restart-validator-{index}");
        let key_id = signer
            .generate_and_register_key(
                &uma,
                vec![
                    AegisPqKeyRole::ConsensusProposer,
                    AegisPqKeyRole::ConsensusVote,
                ],
                Epoch(7),
            )
            .unwrap();
        let public_key = signer.public_key_record(&key_id).unwrap();
        records.push(ValidatorRecord {
            validator_id: ValidatorId(format!("proposal-restart-validator-{index}")),
            validator_uma_id: UmaId(uma),
            consensus_public_key: public_key.clone(),
            peer_public_key: public_key.clone(),
            operator_public_key: public_key,
            voting_weight: 1,
            status: ValidatorStatus::Active,
            cluster_id: ClusterId(0),
            activation_epoch: Epoch(7),
        });
    }
    let validators = ValidatorSet {
        epoch: Epoch(7),
        validators: records,
    };
    let context = epoch_context(&validators, 1_030);
    let state_path = temp_path("proposal-subject-restart");
    let journal_path = state_path.with_file_name("proposal-journal.json");
    let proposer_id = context.scheduled_owner(Height(1_000)).unwrap().clone();
    let proposer = validators
        .validators
        .iter()
        .find(|validator| validator.validator_id == proposer_id)
        .unwrap();
    let proposal = SimplifiedProposal {
        context: ConsensusObjectContext::for_height(&context, Height(1_000), Round(0)).unwrap(),
        proposer_id,
        block_id: BlockId("restart-stable-subject-block".to_string()),
        parent_block_id: anchor().block_id,
        parent_qc: anchor(),
        takeover_tc_id: None,
        protected_execution_root: Hash::from_domain_bytes(
            "protected",
            b"restart-stable-subject-block",
        ),
        proposer_key_id: proposer.consensus_public_key.key_id.clone(),
        proposer_signature: AegisPqSignature {
            algorithm: String::new(),
            signature_bytes: Vec::new(),
        },
    };
    let machine = SimplifiedConsensusStateMachine::open(
        context.clone(),
        validators.clone(),
        DurableSimplifiedPosyStore::at_path(state_path.clone()),
        anchor(),
    )
    .unwrap();
    let journal = DurableConsensusSigningAuthority::at_path(journal_path.clone());
    machine
        .sign_proposal(proposal.clone(), &journal, &mut signer)
        .unwrap();
    drop(machine);
    drop(journal);

    let restarted = SimplifiedConsensusStateMachine::open(
        context.clone(),
        validators.clone(),
        DurableSimplifiedPosyStore::at_path(state_path),
        anchor(),
    )
    .unwrap();
    let restarted_journal = DurableConsensusSigningAuthority::at_path(journal_path.clone());
    restarted
        .sign_proposal(proposal.clone(), &restarted_journal, &mut signer)
        .expect("exact proposal replay remains idempotent after journal restart");

    let mut execution_conflict = proposal.clone();
    execution_conflict.protected_execution_root =
        Hash::from_domain_bytes("protected", b"substituted-execution-root");
    assert!(restarted
        .sign_proposal(execution_conflict, &restarted_journal, &mut signer)
        .unwrap_err()
        .contains("CONSENSUS_SIGNING_CONFLICT"));

    let alternate_parent = QuorumCertificateReference {
        height: Height(999),
        block_id: BlockId("alternate-block-999".to_string()),
        qc_id: Hash::from_domain_bytes("alternate-anchor-qc", b"alternate-block-999"),
    };
    let alternate_machine = SimplifiedConsensusStateMachine::open(
        context,
        validators,
        DurableSimplifiedPosyStore::at_path(temp_path("proposal-subject-alternate-parent")),
        alternate_parent.clone(),
    )
    .unwrap();
    let mut parent_conflict = proposal;
    parent_conflict.parent_block_id = alternate_parent.block_id.clone();
    parent_conflict.parent_qc = alternate_parent;
    assert!(alternate_machine
        .sign_proposal(parent_conflict, &restarted_journal, &mut signer)
        .unwrap_err()
        .contains("CONSENSUS_SIGNING_CONFLICT"));
}
