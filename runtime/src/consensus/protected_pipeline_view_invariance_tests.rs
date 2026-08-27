use crate::consensus::protected_pipeline::derive_next_protected_batch_commitment;
use crate::consensus::simplified_posy::{
    protected_pipeline_qc_evidence_root, protected_pipeline_qc_id, BlockVote,
    ConsensusObjectContext, QuorumCertificateReference, SimplifiedEpochContext,
    SimplifiedFinalityParent, SimplifiedQuorumCertificate, POSY_SIMPLIFIED_BLOCK_VOTE_DOMAIN,
};
use crate::crypto::aegis_pqvm::AegisPqvmSigner;
use crate::etdag::{self, NextProtectedBatchCommitment};
use crate::synergy_types::{
    AegisPqSignature, BlockId, CanonicalSerialize, Hash, Height, Round, ValidatorRecord,
    ValidatorSet,
};

const DOMAIN_TEST_FUTURE_BATCH_EXECUTION: &str =
    "PoSy/ProtectedPipeline/Test/FutureBatchExecution/v1";

fn epoch_context(
    target: &etdag::TargetAdmissionContext,
    validators: &ValidatorSet,
) -> SimplifiedEpochContext {
    SimplifiedEpochContext::derive(
        target.epoch,
        Height(1),
        Height(1_000),
        target.finalized_epoch_seed_root,
        target.consensus_parameter_root,
        validators,
    )
    .expect("derive frozen simplified epoch")
}

fn parent() -> SimplifiedFinalityParent {
    SimplifiedFinalityParent::quorum_certificate(QuorumCertificateReference {
        height: Height(6),
        block_id: BlockId("view-invariance-parent-h6".to_string()),
        qc_id: Hash::from_domain_bytes("view-invariance-parent-qc", b"height-six"),
    })
    .expect("valid H6 parent")
}

fn protected_execution_root(commitment: &NextProtectedBatchCommitment) -> Hash {
    Hash::from_domain_bytes(
        DOMAIN_TEST_FUTURE_BATCH_EXECUTION,
        &commitment
            .canonical_bytes()
            .expect("canonical future-batch commitment"),
    )
}

fn signed_vote(
    signer: &mut AegisPqvmSigner,
    validator: &ValidatorRecord,
    context: &ConsensusObjectContext,
    commitment: &NextProtectedBatchCommitment,
) -> BlockVote {
    let takeover_tc_id = (context.round != Round(0)).then(|| {
        Hash::from_domain_bytes(
            "view-invariance-certified-takeover",
            &context.round.0.to_be_bytes(),
        )
    });
    let mut vote = BlockVote {
        context: context.clone(),
        block_id: BlockId("view-invariance-parent-proposal-h7".to_string()),
        parent_block_id: parent().block_id().clone(),
        parent: parent(),
        takeover_tc_id,
        protected_execution_root: protected_execution_root(commitment),
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
            &vote.signing_bytes().expect("block-vote signing bytes"),
            &vote.key_id,
        )
        .expect("sign view-invariance block vote");
    vote
}

fn qc_for_view_and_subset(
    signer: &mut AegisPqvmSigner,
    validators: &ValidatorSet,
    epoch: &SimplifiedEpochContext,
    commitment: &NextProtectedBatchCommitment,
    round: Round,
    signer_indices: &[usize],
) -> SimplifiedQuorumCertificate {
    let context = ConsensusObjectContext::for_height(epoch, Height(7), round)
        .expect("valid H-1 consensus view");
    let votes = signer_indices
        .iter()
        .map(|index| {
            signed_vote(
                signer,
                validators
                    .validators
                    .get(*index)
                    .expect("signer index in frozen set"),
                &context,
                commitment,
            )
        })
        .collect::<Vec<_>>();
    let certificate = SimplifiedQuorumCertificate::from_votes(votes).expect("form H-1 QC");
    certificate
        .verify(epoch, validators, &signer.verifier())
        .expect("independently verify H-1 QC");
    certificate
}

#[test]
fn next_protected_batch_commitment_is_invariant_across_valid_h_minus_one_views() {
    let mut fixture = etdag::tests::fixture(5, None);
    let input = etdag::tests::complete_r11_execution_input(&mut fixture);
    let target = fixture.context.clone();
    assert_eq!(target.target_height, Height(8));
    let cut = input.cut_proof.as_ref().expect("normal input cut proof");
    let commitment = derive_next_protected_batch_commitment(&target, cut, &input.protected_batch)
        .expect("derive semantic future-batch commitment");
    assert_eq!(commitment, input.next_commitment);

    let epoch = epoch_context(&target, &fixture.validator_set);
    let round_zero = qc_for_view_and_subset(
        &mut fixture.signer,
        &fixture.validator_set,
        &epoch,
        &commitment,
        Round(0),
        &[0, 1, 2, 3],
    );
    let round_one = qc_for_view_and_subset(
        &mut fixture.signer,
        &fixture.validator_set,
        &epoch,
        &commitment,
        Round(1),
        &[0, 1, 2, 3],
    );

    assert_ne!(round_zero.context.round, round_one.context.round);
    assert!(round_zero.takeover_tc_id.is_none());
    assert!(round_one.takeover_tc_id.is_some());
    assert_eq!(
        protected_pipeline_qc_id(&round_zero).expect("round-zero semantic QC"),
        protected_pipeline_qc_id(&round_one).expect("round-one semantic QC"),
        "a valid retransmission view changed the certified candidate",
    );
    assert_ne!(
        protected_pipeline_qc_evidence_root(&round_zero).expect("round-zero exact QC evidence"),
        protected_pipeline_qc_evidence_root(&round_one).expect("round-one exact QC evidence"),
        "exact QC evidence failed to bind the H-1 view",
    );
    assert_eq!(
        commitment.root().expect("future commitment root"),
        input.next_commitment.root().expect("input commitment root"),
        "H-1 view leaked into the target-height protected commitment",
    );
}

#[test]
fn valid_signer_subsets_change_exact_qc_evidence_not_semantic_future_batch() {
    let mut fixture = etdag::tests::fixture(5, None);
    let input = etdag::tests::complete_r11_execution_input(&mut fixture);
    let target = fixture.context.clone();
    let cut = input.cut_proof.as_ref().expect("normal input cut proof");
    let commitment = derive_next_protected_batch_commitment(&target, cut, &input.protected_batch)
        .expect("derive semantic future-batch commitment");
    let epoch = epoch_context(&target, &fixture.validator_set);

    let omit_four = qc_for_view_and_subset(
        &mut fixture.signer,
        &fixture.validator_set,
        &epoch,
        &commitment,
        Round(0),
        &[0, 1, 2, 3],
    );
    let omit_three = qc_for_view_and_subset(
        &mut fixture.signer,
        &fixture.validator_set,
        &epoch,
        &commitment,
        Round(0),
        &[0, 1, 2, 4],
    );

    assert_ne!(omit_four.participants, omit_three.participants);
    assert_ne!(
        protected_pipeline_qc_evidence_root(&omit_four).expect("first exact QC evidence"),
        protected_pipeline_qc_evidence_root(&omit_three).expect("second exact QC evidence"),
        "exact evidence must retain the authenticated signer subset",
    );
    assert_eq!(
        protected_pipeline_qc_id(&omit_four).expect("first semantic QC"),
        protected_pipeline_qc_id(&omit_three).expect("second semantic QC"),
        "valid 4-of-5 subsets changed the signer-independent QC subject",
    );
    assert_eq!(
        omit_four.protected_execution_root,
        protected_execution_root(&commitment),
    );
    assert_eq!(
        omit_three.protected_execution_root,
        protected_execution_root(&commitment),
    );
    assert_eq!(
        commitment, input.next_commitment,
        "valid signer-subset choice changed the semantic future batch",
    );
}
