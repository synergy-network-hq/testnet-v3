//! Real-provider component regression, invoked by the existing native fixture.
use super::*;
use std::collections::{BTreeMap, BTreeSet};
use synergy_etdag::EtdagDigest;
use synergy_governance::*;
use synergy_state::world_resources::WorldResourceBudget;

pub(crate) fn qualify_membership_transition(
    previous: Arc<VerifiedAuthority>,
    signers: &[Arc<dyn synergy_aegis::AegisSigner>],
) {
    let records = previous.registry.active().cloned().collect::<Vec<_>>();
    assert_eq!(records.len(), 5);
    assert!(signers.len() >= 5);
    let first = previous.epoch.epoch_start_height;
    let spec = MembershipRetirementSpec {
        schema_version: 1,
        chain_id: previous.epoch.chain_id,
        network_id: previous.epoch.network_id.clone(),
        genesis_hash: crate::services::membership_retirement::genesis(&previous)
            .unwrap()
            .into(),
        frozen_epoch: previous.epoch.epoch,
        frozen_epoch_context_root: previous.epoch.root().unwrap(),
        install_not_before_finalized_height: first + 1,
        effective_epoch: previous.epoch.epoch + 1,
        retired_validator_id: records[4].validator_id.clone(),
    };
    let mutation = spec.mutation().unwrap();
    let mut constitution = Constitution {
        version: 1,
        constitution_root: String::new(),
        rules: BTreeMap::from([(
            MEMBERSHIP_RETIREMENT_ACTION_V1.into(),
            GovernanceRule {
                action_kind: MEMBERSHIP_RETIREMENT_ACTION_V1.into(),
                eligible_authorities: records.iter().map(|r| r.validator_id.clone()).collect(),
                approval_threshold: 1,
                minimum_delay_blocks: 0,
                emergency_permitted: false,
            },
        )]),
    };
    constitution.constitution_root = constitution.canonical_root().unwrap();
    let mut proposal = GovernanceProposal {
        proposal_id: "real-native-membership-retirement".into(),
        proposal_root: String::new(),
        proposer: records[0].validator_id.clone(),
        constitution_version: 1,
        created_at_height: first,
        expires_at_height: first + 3,
        actions: vec![GovernanceAction {
            kind: mutation.action_kind.clone(),
            target: mutation.target.clone(),
            payload_root: mutation.payload_root().unwrap(),
        }],
        state: ProposalState::Authorized,
    };
    proposal.proposal_root = proposal.canonical_root().unwrap();
    let votes = (0..4)
        .map(|i| {
            let r = &records[i];
            let mut v = GovernanceVote {
                proposal_root: proposal.proposal_root.clone(),
                authority_id: r.validator_id.clone(),
                key_id: r.consensus_key_id.clone(),
                choice: VoteChoice::Approve,
                signature: vec![1],
            };
            v.signature = signers[r.consensus_key_id.strip_prefix("consensus-").unwrap().parse::<usize>().unwrap()]
                .sign(
                    &KeyId::new(v.key_id.clone()).unwrap(),
                    &SigningContext {
                        domain: "SYNERGY-GOVERNANCE-VOTE-V1".into(),
                        chain_id: previous.epoch.chain_id,
                        epoch: Some(previous.epoch.epoch),
                        height: None,
                    },
                    &v.signing_bytes().unwrap(),
                )
                .unwrap()
                .bytes;
            v
        })
        .collect::<Vec<_>>();
    let approvals = votes
        .iter()
        .map(|v| v.authority_id.clone())
        .collect::<BTreeSet<_>>();
    let payload = serde_json::to_vec(&(
        &proposal.proposal_root,
        &constitution.constitution_root,
        &approvals,
    ))
    .unwrap();
    let root = synergy_crypto::sha3_256_segments(
        &synergy_crypto::AegisSha3_256,
        &[b"SYNERGY_GOVERNANCE_AUTHORIZATION_V1", &payload],
    )
    .unwrap()
    .0
    .iter()
    .map(|b| format!("{b:02x}"))
    .collect::<String>();
    let approval = GovernanceAuthorization::assemble(
        &proposal,
        &constitution,
        &votes,
        previous.as_ref(),
        root.clone(),
    )
    .unwrap();
    let activation = GovernedActivation::new(
        &proposal,
        &approval,
        ActivationPoint::FinalizedHeight {
            height: spec.install_not_before_finalized_height,
        },
    )
    .unwrap();
    let execution = GovernanceExecution {
        proposal,
        constitution,
        votes,
        authorization_root: root,
        activation,
        mutation,
    };
    let verified = synergy_genesis::membership::VerifiedMembershipRetirement::verify(
        &execution,
        &spec.genesis_hash,
        &previous.epoch,
        &previous.registry,
        previous.as_ref(),
    )
    .unwrap();
    let (authorization, next_policy, next_registry) = verified
        .prepare_successor(
            &previous.epoch,
            previous.protected.as_ref().unwrap(),
            &previous.registry,
        )
        .unwrap();
    assert_eq!(next_registry.active_count(), 4);
    assert!(next_registry
        .active_validator(&spec.retired_validator_id)
        .is_err());
    assert_eq!(next_policy.ingress_kem_registry.records.len(), 4);
    assert_eq!(
        synergy_etdag::certificate_quorum(next_registry.active_count()).unwrap(),
        3
    );
    let weak_draft = MembershipRetirementDraft {
        spec: spec.clone(),
        proposal: execution.proposal.clone(),
        constitution: execution.constitution.clone(),
    };
    let insufficient = weak_draft
        .assemble(execution.votes[..3].to_vec(), previous.as_ref())
        .unwrap();
    assert!(insufficient
        .verify(
            previous.as_ref(),
            &insufficient.authorization_root,
            spec.install_not_before_finalized_height
        )
        .is_ok());
    assert!(
        synergy_genesis::membership::VerifiedMembershipRetirement::verify(
            &insufficient,
            &spec.genesis_hash,
            &previous.epoch,
            &previous.registry,
            previous.as_ref()
        )
        .is_err()
    );
    let mut forged = execution.clone();
    forged.votes[0].signature[0] ^= 1;
    assert!(
        synergy_genesis::membership::VerifiedMembershipRetirement::verify(
            &forged,
            &spec.genesis_hash,
            &previous.epoch,
            &previous.registry,
            previous.as_ref()
        )
        .is_err()
    );
    assert!(
        synergy_genesis::membership::VerifiedMembershipRetirement::verify(
            &execution,
            &"f".repeat(64),
            &previous.epoch,
            &previous.registry,
            previous.as_ref()
        )
        .is_err()
    );
    // The old committee certifies all three closing QCs. The next registry is
    // data inside that authenticated subject, never the closing vote authority.
    let root = EtdagDigest::from_domain_bytes("membership-qualification", b"native-processing");
    let (material, commitment) = synergy_etdag::execution::ProcessingProposalMaterial {
        material_version: 1,
        profile_id: synergy_etdag::PROCESSING_PROFILE_ID.into(),
        height: authorization.finalized_height,
        namespace_root: root.clone(),
        selection: synergy_etdag::execution::ProcessingReadyView {
            namespace_root: root.clone(),
            items: vec![],
        }
        .select(30000000, 1048576)
        .unwrap(),
        transition_root: root,
        ordered_group: None,
        epoch_transition_subject_root: None,
    }
    .with_epoch_close_subject(authorization.subject_root_v2().unwrap())
    .unwrap();
    let protected = synergy_block::hash_block_bytes(&commitment);
    let mut parent = SimplifiedFinalityParent::QuorumCertificate {
        height: authorization.finalized_height - 1,
        block_id: "d".repeat(64),
        qc_id: "e".repeat(64),
    };
    let mut finality = ThreeQcFinality::default();
    let mut qcs = vec![];
    for height in authorization.finalized_height..=previous.epoch.epoch_end_height {
        let votes = (0..4)
            .map(|i| {
                let r = &records[i];
                let mut vote = synergy_posy::BlockVote {
                    context: synergy_posy::ConsensusObjectContext::for_height(
                        &previous.epoch,
                        height,
                        0,
                    )
                    .unwrap(),
                    block_id: format!("{height:064x}"),
                    parent_block_id: parent.block_id().into(),
                    parent: parent.clone(),
                    takeover_tc_id: None,
                    protected_execution_root: if height == authorization.finalized_height {
                        protected.clone()
                    } else {
                        "f".repeat(64)
                    },
                    validator_id: r.validator_id.clone(),
                    key_id: r.consensus_key_id.clone(),
                    signature: vec![],
                };
                vote.signature = signers[r.consensus_key_id.strip_prefix("consensus-").unwrap().parse::<usize>().unwrap()]
                    .sign(
                        &KeyId::new(vote.key_id.clone()).unwrap(),
                        &SigningContext {
                            domain: "SYNERGY-POSY-BLOCK-VOTE-V1".into(),
                            chain_id: previous.epoch.chain_id,
                            epoch: Some(previous.epoch.epoch),
                            height: Some(height),
                        },
                        &synergy_posy::block_vote_signing_bytes(&vote).unwrap(),
                    )
                    .unwrap()
                    .bytes;
                vote
            })
            .collect();
        let qc = SimplifiedQuorumCertificate::from_votes(votes).unwrap();
        finality.accept(qc.clone()).unwrap();
        parent = SimplifiedFinalityParent::QuorumCertificate {
            height,
            block_id: qc.block_id.clone(),
            qc_id: qc.id().unwrap(),
        };
        qcs.push(qc);
    }
    let proof = DerivedEpochProof {
        authorization,
        finalized: finality.last_finalized().unwrap().clone(),
        witness: synergy_posy::FinalitySyncWitness {
            quorum_certificates: qcs.try_into().unwrap(),
            timeout_certificates: vec![],
        },
        closing_material: material.into(),
        next_validators: next_registry.active().cloned().collect(),
        membership_execution: Some(execution.clone()),
    };
    let decoded = serde_json::from_slice(&serde_json::to_vec(&proof).unwrap()).unwrap();
    let next = verify_native_successor(previous.clone(), decoded, None).unwrap();
    assert_eq!(next.registry.active_count(), 4);
    assert_eq!(
        next.protected.as_ref().unwrap().commitment().unwrap(),
        next_policy.commitment().unwrap()
    );
    let budget = WorldResourceBudget::new(16 * 1024 * 1024);
    assert_eq!(
        processing_namespace(&previous, &budget).unwrap(),
        processing_namespace(&next, &budget).unwrap()
    );
    assert_eq!(
        next.authenticated_history_ref_at(first)
            .unwrap()
            .registry
            .active_count(),
        5
    );
    assert!(next.consensus_binding(&spec.retired_validator_id).is_err());
    assert!(next.authenticated_history_ref_at(first).unwrap().consensus_binding(&spec.retired_validator_id).is_ok());

    // Existing native controller owner: exact review, durable sign-once,
    // lost-reply lookup, and genuine old quorum assembly. The injected World
    // position is a caller-context fixture, not a claimed live finality result.
    let root=std::env::temp_dir().join(format!("core-membership-owner-{}-{}",std::process::id(),&previous.epoch.root().unwrap()[..16]));
    std::fs::create_dir(&root).unwrap();
    struct Cleanup(std::path::PathBuf);impl Drop for Cleanup{fn drop(&mut self){let _=std::fs::remove_dir_all(&self.0);}}
    let _cleanup=Cleanup(root.clone());
    let ingress=crate::services::ingress::AuthenticatedIngress::with_world_budget(budget.clone());
    let initial=previous.initial_world_state_budgeted(&budget).unwrap();
    ingress.submit_finality(FinalizedBlockRecord{height:first,block_id:"31".repeat(32),finality_certificate_id:"32".repeat(32),protected_execution_root:"33".repeat(32)},vec![1]).unwrap();
    ingress.publish_processing_finalized_world(first,Arc::new(initial)).unwrap();
    let mut native_draft=None;let mut native_votes=vec![];
    for r in records.iter().take(4){
        let signer=signers[r.consensus_key_id.strip_prefix("consensus-").unwrap().parse::<usize>().unwrap()].clone();
        let owner_root=root.join(&r.consensus_key_id);
        let create=||crate::services::governance_admin::GovernanceApprovalOwner::new(r.validator_id.clone(),KeyId::new(r.consensus_key_id.clone()).unwrap(),signer.clone(),&owner_root).unwrap();
        let mut owner=create();
        if native_draft.is_none(){native_draft=Some(serde_json::from_value::<MembershipRetirementDraft>(owner.prepare_membership(&previous,&ingress,&spec.retired_validator_id).unwrap()["draft"].clone()).unwrap());}
        let draft=native_draft.as_ref().unwrap();let review_root=draft.review_root().unwrap();
        assert_eq!(owner.review_membership(&previous,&ingress,draft).unwrap()["review_root"],review_root);
        let approved=owner.approve_membership(&previous,&ingress,draft,&review_root).unwrap();
        assert!(owner.approve_membership(&previous,&ingress,draft,&"f".repeat(64)).is_err());
        drop(owner);let mut reopened=create();
        assert_eq!(reopened.membership_approval_status(&previous,draft).unwrap(),approved);
        assert_eq!(reopened.approve_membership(&previous,&ingress,draft,&review_root).unwrap(),approved);
        native_votes.push(serde_json::from_value::<GovernanceVote>(approved["vote"].clone()).unwrap());
        if native_votes.len()==3{assert!(reopened.assemble_membership(&previous,&ingress,draft,&review_root,native_votes.clone()).is_err());}
        if native_votes.len()==4{
            let reply=reopened.assemble_membership(&previous,&ingress,draft,&review_root,native_votes.clone()).unwrap();
            let execution:GovernanceExecution=serde_json::from_value(reply["execution"].clone()).unwrap();
            let mut applied=previous.protected.as_ref().unwrap().initial_world_state.clone();
            let height=draft.spec.install_not_before_finalized_height;
            crate::services::membership_retirement::dispatch(&previous,&execution,height,&applied).unwrap().apply(&mut applied).unwrap();
            let stored=applied.protocol[&draft.spec.record_key()].clone();
            crate::services::membership_retirement::dispatch(&previous,&execution,height+1,&applied).unwrap().apply(&mut applied).unwrap();
            assert_eq!(applied.protocol[&draft.spec.record_key()],stored);
            let mut isolated=previous.as_ref().clone();isolated.membership_retirement=Arc::new(std::sync::Mutex::new(None));
            crate::services::membership_retirement::refresh_finalized(&isolated,height,&applied).unwrap();
            assert_eq!(isolated.pending_membership_retirement().unwrap().unwrap().spec(),&draft.spec);
            crate::services::rpc::proofs::require_public_world(&applied,None).unwrap();
        }
    }
    let mut missing = proof;
    missing.membership_execution = None;
    assert!(verify_native_successor(previous, missing, None).is_err());
    eprintln!("Real native ML65 old4/5 retirement authorization + three-QC successor/new3/4, exact KEM projection, source/restart decoding and stable processing namespace passed");
}
