//! Native-APQE fixture for the distinct PW13 envelope profile. It exercises
//! local encrypt and reveal without starting any validator or network.
#![cfg(test)]
use super::super::processing_pipeline::{
    processing_namespace, qualify_processing_vertex, AuthenticatedProcessingOpening,
    NativeProcessingContext, NativeProcessingRecovery, ProcessingCompletionEvidence,
    ProcessingSource, RevealedProcessingPayload,
};
use super::{
    processing_admission::{CandidateAdmission, CandidateAuthorization},
    processing_disposition::{self, Disposition, DispositionQuery},
    processing_execution::{
        execute_protected_candidate, execute_protected_journal_candidate,
        replay_protected_candidate, replay_protected_journal_candidate, CandidateActionOutcome,
        CandidateDispatch, CandidateSlot, PreparedProtectedAction, ProtectedAdmissionRecovery,
        ProtectedCandidateContext, ProtectedJournalRecovery, ProtectedRecoveryTerms,
    },
    tests::Scratch,
    FinalizedSnapshot, Position, WorldState,
};
use crate::services::processing_store::{
    PendingProcessingStore, ProcessingStoreError, ProcessingStoreLimits,
    PROCESSING_INTAKE_HEADROOM_BYTES,
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
        ProcessingProposalMaterial, ProcessingReadyView, ProcessingRevealPermission,
        ProcessingSelection, ProcessingVertex,
    },
    AvailabilityCertificate, AvailabilityVote, CertifiedEnvelopeRef, EtdagDigest, EtdagParameters,
    ProcessingContext, ProcessingEnvelope, ProcessingEnvelopeAad, TargetAdmissionContextV3,
};
use synergy_execution::{
    decode_budgeted_candidate, processing_group_state, processing_group_transition,
    processing_member_claim, processing_member_claim_optional, BudgetedExecutionCandidate,
    ParentProcessingRegistry, ProcessingReadinessVerifier, ProcessingReadyRecord,
};
use synergy_posy::{
    block_vote_signing_bytes, BlockVote, CertifiedCandidateSubject, ConsensusObjectContext,
    FinalizedBlockRecord, ProposalDeliveryPhase, ProposalDeliveryStatement,
    ProposalValidationCertificate, SimplifiedFinalityParent, SimplifiedQuorumCertificate,
    ThreeQcFinality, ValidatorRecord, ValidatorStatus,
};
use synergy_state::{
    state_root,
    world_resources::{BudgetedWorld, WorldResourceBudget},
    ProtocolChange, StateDiff,
};

struct RetainedNativeFixture {
    vertex: ProcessingVertex<CandidateAdmission>,
    availability: AvailabilityCertificate,
    parent: BudgetedExecutionCandidate,
    validation: ProposalValidationCertificate,
    latest: NativeSourceFixture,
}

struct NativeSourceFixture {
    candidate: BudgetedExecutionCandidate,
    witness: [SimplifiedQuorumCertificate; 3],
    finalized: FinalizedBlockRecord,
}

pub(super) struct ClosedCandidateOrder {
    permission: ProcessingRevealPermission,
    world: BudgetedWorld,
    native: Option<RetainedNativeFixture>,
}

#[derive(Clone, Copy)]
pub(super) struct NativeSourceTerms<'a> {
    pub(super) source: &'a FinalizedSnapshot<'a>,
    pub(super) recovery: ProtectedRecoveryTerms<'a>,
}

pub(super) struct OpenedCandidateEnvelope {
    opening: AuthenticatedProcessingOpening,
    envelope: ProcessingEnvelope,
    context: ProcessingContext,
    order: Option<ClosedCandidateOrder>,
    pub(super) native_result: Option<(Arc<BudgetedWorld>, CandidateActionOutcome)>,
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
                height: inclusion
                    .height
                    .checked_sub(1)
                    .ok_or("invalid fixture inclusion")?,
                ..inclusion
            },
            finalized_parent: dispatch.source,
        };
        let publication_context = ProtectedCandidateContext {
            parent_block_id: &order.permission.parent_block_id,
            namespace,
            parameters,
            slot: publication,
        };
        let action =
            PreparedProtectedAction::prepare(dispatch, self.payload(), &order.world, publication)?;
        let (published, results) =
            execute_protected_candidate(&order.world, publication_context, &[&action], &[&action])?;
        assert!(results.is_empty());
        assert_eq!(published.state.accounts, order.world.accounts);
        assert!(published.validate().is_err());
        assert!(published.validate_archived().is_err());
        let published_bytes = serde_json::to_vec(&published).map_err(err)?;
        assert!(decode_budgeted_candidate(&published_bytes, order.world.budget()).is_err());

        let restored_order =
            BudgetedWorld::try_clone_world(order.world.as_ref(), order.world.budget())
                .map_err(err)?;
        let restored_action = PreparedProtectedAction::prepare(
            dispatch,
            self.payload(),
            &restored_order,
            publication,
        )?;
        let replayed_publication = replay_protected_candidate(
            &published_bytes,
            &restored_order,
            publication_context,
            &[&restored_action],
            &[&restored_action],
        )?;
        assert_eq!(replayed_publication, published);

        let execution = ProtectedCandidateContext {
            parent_block_id: &published.block_id,
            slot: CandidateSlot {
                inclusion,
                finalized_parent: execution_finalized_parent,
            },
            ..publication_context
        };
        let mut changed_limits = parameters.clone();
        changed_limits.max_protected_gas += 1;
        let altered = ProtectedCandidateContext {
            parameters: &changed_limits,
            ..execution
        };
        assert!(matches!(
            execute_protected_candidate(&published.state, altered, &[&action], &[]),
            Err(error) if error == "protected processing limits differ from the authenticated admission"
        ));
        let (settled, outcomes) =
            execute_protected_candidate(&published.state, execution, &[&action], &[])?;
        let [outcome] =
            <[_; 1]>::try_from(outcomes).map_err(|_| "expected one protected action settlement")?;

        let settled_bytes = serde_json::to_vec(&settled).map_err(err)?;
        let replayed = replay_protected_candidate(
            &settled_bytes,
            &replayed_publication.state,
            execution,
            &[&restored_action],
            &[],
        )?;
        assert_eq!(replayed, settled);
        assert!(
            replay_protected_candidate(&settled_bytes, &published.state, execution, &[], &[])
                .is_err()
        );
        let other_time = ProtectedCandidateContext {
            slot: CandidateSlot {
                inclusion: Position {
                    consensus_time: inclusion.consensus_time + 1,
                    ..inclusion
                },
                ..execution.slot
            },
            ..execution
        };
        assert!(replay_protected_candidate(
            &settled_bytes,
            &published.state,
            other_time,
            &[&action],
            &[],
        )
        .is_err());
        assert_replay_refuses_changed_world(&settled, &published.state, execution, &action)?;

        assert!(processing_member_claim_optional(
            settled.state.as_ref().as_ref(),
            &self.envelope.aad.sender_id,
            self.envelope.aad.nonce_slot,
        )
        .map_err(err)?
        .is_none());
        let consumed = ParentProcessingRegistry::read(
            settled.state.as_ref().as_ref(),
            namespace,
            settled.state.budget(),
        )
        .map_err(err)?;
        assert!(consumed.records().is_empty());
        drop(consumed);
        let next = ProtectedCandidateContext {
            parent_block_id: &settled.block_id,
            slot: CandidateSlot {
                inclusion: Position {
                    height: inclusion.height + 1,
                    ..inclusion
                },
                ..execution.slot
            },
            ..execution
        };
        let (empty, duplicate) = execute_protected_candidate(&settled.state, next, &[], &[])?;
        assert!(duplicate.is_empty());
        assert_eq!(empty.state, settled.state);
        let world =
            Arc::try_unwrap(settled.state).map_err(|_| "unexpected shared fixture World")?;
        Ok((world, outcome))
    }
}

fn assert_replay_refuses_changed_world(
    settled: &BudgetedExecutionCandidate,
    parent: &BudgetedWorld,
    context: ProtectedCandidateContext<'_>,
    action: &PreparedProtectedAction<'_>,
) -> Result<(), String> {
    let mut substituted =
        BudgetedWorld::try_clone_world(settled.state.as_ref().as_ref(), parent.budget())
            .map_err(err)?;
    substituted
        .try_apply(&StateDiff {
            protocol_changes: vec![ProtocolChange {
                key: "pw13-fixture-replay".into(),
                expected_value: None,
                value: Some(vec![1]),
            }],
            ..StateDiff::default()
        })
        .map_err(err)?;
    let mut changed = BudgetedExecutionCandidate {
        height: settled.height,
        block_id: String::new(),
        parent_block_id: settled.parent_block_id.clone(),
        protected_execution_root: settled.protected_execution_root.clone(),
        protected_material: settled.protected_material.clone(),
        state_root: state_root(substituted.as_ref()).map_err(err)?,
        transactions: Vec::new(),
        receipts: Vec::new(),
        state: Arc::new(substituted),
        resource_permit: None,
    };
    changed.block_id = changed.commitment_id()?;
    changed.validate_pw13_engineering()?;
    let changed_bytes = serde_json::to_vec(&changed).map_err(err)?;
    assert!(matches!(
        replay_protected_candidate(&changed_bytes, parent, context, &[action], &[]),
        Err(error) if error == "protected execution candidate disagrees with canonical parent replay"
    ));
    Ok(())
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


fn fixture_sign(
    engine: &Arc<Mutex<CryptoEngine>>,
    signers: &[SecretBytes],
    index: usize,
    message: &[u8],
) -> Result<Vec<u8>, String> {
    engine
        .lock()
        .map_err(|_| "isolated APQE lock poisoned")?
        .sign(
            Algorithm::MlDsa65,
            signers[index].as_bytes(),
            message,
            SignOptions::default(),
        )
        .map_err(err)
}

fn proof_candidate(
    world: &BudgetedWorld,
    namespace: &EtdagDigest,
    height: u64,
    parent: &SimplifiedFinalityParent,
) -> Result<BudgetedExecutionCandidate, String> {
    let state = BudgetedWorld::try_clone_world(world.as_ref(), world.budget()).map_err(err)?;
    let parameters = EtdagParameters::default();
    let ready = ProcessingReadyView {
        namespace_root: namespace.clone(),
        items: Vec::new(),
    };
    let material = ProcessingProposalMaterial {
        material_version: 1,
        profile_id: synergy_etdag::PROCESSING_PROFILE_ID.into(),
        height,
        namespace_root: namespace.clone(),
        selection: ProcessingSelection {
            parent_ready_root: ready.root().map_err(err)?,
            maximum_gas: parameters.max_protected_gas,
            maximum_bytes: parameters.max_protected_bytes,
            item_indices: Vec::new(),
            protected_gas: 0,
            protected_bytes: 0,
        },
        transition_root: EtdagDigest::from_canonical("PW13_SIGNED_QUALIFICATION_PARENT", &height)
            .map_err(err)?,
        ordered_group: None,
        epoch_transition_subject_root: None,
    };
    let mut candidate = BudgetedExecutionCandidate {
        resource_permit: None,
        height,
        block_id: String::new(),
        parent_block_id: parent.block_id().into(),
        protected_execution_root: synergy_block::hash_block_bytes(
            &material.commitment_bytes().map_err(err)?,
        ),
        protected_material: material.into(),
        state_root: state_root(state.as_ref()).map_err(err)?,
        transactions: Vec::new(),
        receipts: Vec::new(),
        state: Arc::new(state),
    };
    candidate.block_id = candidate.commitment_id()?;
    Ok(candidate)
}

fn next_fixture_parent(
    qc: &SimplifiedQuorumCertificate,
) -> Result<SimplifiedFinalityParent, String> {
    Ok(SimplifiedFinalityParent::QuorumCertificate {
        height: qc.context.height,
        block_id: qc.block_id.clone(),
        qc_id: qc.id().map_err(err)?,
    })
}

fn certify_fixture_qc(
    candidate: &BudgetedExecutionCandidate,
    parent: &SimplifiedFinalityParent,
    authority: &super::super::authority::VerifiedAuthority,
    engine: &Arc<Mutex<CryptoEngine>>,
    signers: &[SecretBytes],
) -> Result<SimplifiedQuorumCertificate, String> {
    let context =
        ConsensusObjectContext::for_height(&authority.epoch, candidate.height, 0).map_err(err)?;
    let votes = authority
        .registry
        .active()
        .enumerate()
        .take(signers.len() - 1)
        .map(|(index, signer)| {
            let mut vote = BlockVote {
                context: context.clone(),
                block_id: candidate.block_id.clone(),
                parent_block_id: candidate.parent_block_id.clone(),
                parent: parent.clone(),
                takeover_tc_id: None,
                protected_execution_root: candidate.protected_execution_root.clone(),
                validator_id: signer.validator_id.clone(),
                key_id: signer.consensus_key_id.clone(),
                signature: Vec::new(),
            };
            vote.signature = fixture_sign(
                engine,
                signers,
                index,
                &block_vote_signing_bytes(&vote).map_err(err)?,
            )?;
            Ok(vote)
        })
        .collect::<Result<Vec<_>, String>>()?;
    SimplifiedQuorumCertificate::from_votes(votes).map_err(err)
}

fn certify_fixture_source(
    snapshot: &FinalizedSnapshot<'_>,
    authority: &super::super::authority::VerifiedAuthority,
    engine: &Arc<Mutex<CryptoEngine>>,
    signers: &[SecretBytes],
    budget: &Arc<WorldResourceBudget>,
) -> Result<NativeSourceFixture, String> {
    let source_height = snapshot.position.height;
    let witness_tip = source_height
        .checked_add(2)
        .ok_or("fixture height overflow")?;
    let world = BudgetedWorld::try_clone_world(snapshot.world, budget).map_err(err)?;
    let namespace = processing_namespace(authority, budget)?;
    let mut parent = authority.anchor_parent.clone();
    let mut source_candidate = None;
    let mut witness = Vec::new();
    let mut finality = ThreeQcFinality::default();
    for height in 1..=witness_tip {
        let candidate = proof_candidate(&world, &namespace, height, &parent)?;
        let qc = certify_fixture_qc(&candidate, &parent, authority, engine, signers)?;
        parent = next_fixture_parent(&qc)?;
        if height >= source_height {
            finality.accept(qc.clone()).map_err(err)?;
            witness.push(qc);
        }
        if height == source_height {
            source_candidate = Some(candidate);
        }
    }
    Ok(NativeSourceFixture {
        candidate: source_candidate.expect("signed source candidate"),
        witness: witness.try_into().expect("exact three QCs"),
        finalized: finality
            .last_finalized()
            .expect("signed fixture finality")
            .clone(),
    })
}

pub(super) struct CandidateOrderFixture<'a> {
    authority: &'a super::super::authority::VerifiedAuthority,
    registry: &'a IngressKemKeyRegistry,
    engine: &'a Arc<Mutex<CryptoEngine>>,
    signers: &'a [SecretBytes],
    source: &'a FinalizedBlockRecord,
    native_source: Option<&'a NativeSourceFixture>,
    budget: &'a Arc<WorldResourceBudget>,
}

impl CandidateOrderFixture<'_> {
    fn sign(&self, index: usize, message: &[u8]) -> Result<Vec<u8>, String> {
        fixture_sign(self.engine, self.signers, index, message)
    }

    fn certify_reveal_parent(
        &self,
        world: &BudgetedWorld,
        open_world: &BudgetedWorld,
        namespace: &EtdagDigest,
        context: &ProcessingContext,
        retained_source: &NativeSourceFixture,
    ) -> Result<
        (
            BudgetedExecutionCandidate,
            ProposalValidationCertificate,
            NativeSourceFixture,
        ),
        String,
    > {
        let height = context.authority.target_height + 1;
        let tail = &retained_source.witness[2];
        let mut parent = next_fixture_parent(tail)?;
        let mut witness = Vec::new();
        let mut finalized_candidate = None;
        let mut finality = ThreeQcFinality::default();
        for preceding in tail.context.height + 1..height {
            let state = if preceding + 1 == height {
                open_world
            } else {
                retained_source.candidate.state.as_ref()
            };
            let candidate = proof_candidate(state, namespace, preceding, &parent)?;
            let qc = certify_fixture_qc(
                &candidate,
                &parent,
                self.authority,
                self.engine,
                self.signers,
            )?;
            parent = next_fixture_parent(&qc)?;
            finality.accept(qc.clone()).map_err(err)?;
            if finalized_candidate.is_none() {
                finalized_candidate = Some(candidate);
            }
            witness.push(qc);
        }
        let latest = NativeSourceFixture {
            candidate: finalized_candidate.ok_or("no certified predecessor candidate")?,
            witness: witness
                .try_into()
                .map_err(|_| "expected three predecessor QCs")?,
            finalized: finality
                .last_finalized()
                .ok_or("no finalized predecessor")?
                .clone(),
        };
        let candidate = proof_candidate(world, namespace, height, &parent)?;
        let context =
            ConsensusObjectContext::for_height(&self.authority.epoch, height, 0).map_err(err)?;
        let subject = CertifiedCandidateSubject::new(
            context.clone(),
            candidate.block_id.clone(),
            candidate.parent_block_id.clone(),
            parent,
            candidate.protected_execution_root.clone(),
        )
        .map_err(err)?;
        let echoes = self
            .authority
            .registry
            .active()
            .enumerate()
            .take(self.signers.len() - 1)
            .map(|(index, signer)| {
                let mut echo = ProposalDeliveryStatement {
                    context: context.clone(),
                    phase: ProposalDeliveryPhase::Echo,
                    candidate: subject.clone(),
                    validator_id: signer.validator_id.clone(),
                    key_id: signer.consensus_key_id.clone(),
                    signature: Vec::new(),
                };
                echo.signature = self.sign(index, &echo.signing_bytes().map_err(err)?)?;
                Ok(echo)
            })
            .collect::<Result<Vec<_>, String>>()?;
        let validation = ProposalValidationCertificate {
            context,
            candidate: subject,
            echoes,
        };
        Ok((candidate, validation, latest))
    }

    pub(super) fn native_snapshot<'a>(
        &'a self,
        registry: &'a super::CandidateProtectedAccounts<'a>,
    ) -> Result<FinalizedSnapshot<'a>, String> {
        let source = self.native_source.ok_or("missing signed source fixture")?;
        let durable = synergy_state::FinalizedState {
            finalized_height: source.candidate.height,
            finalized_block_id: source.candidate.block_id.clone(),
            state_root: source.candidate.state_root.clone(),
        };
        registry.finalized_snapshot(
            source.candidate.state.as_ref().as_ref(),
            &durable,
            &source.finalized,
            self.authority
                .consensus_timestamp_unix(source.candidate.height)?,
        )
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
        let namespace = if self.native_source.is_some() {
            processing_namespace(self.authority, self.budget)?
        } else {
            context_root.clone()
        };
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
        let before_close = self
            .native_source
            .map(|_| BudgetedWorld::try_clone_world(world.as_ref(), self.budget).map_err(err))
            .transpose()?;
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
        let native = self
            .native_source
            .map(|proof| {
                let (parent, validation, latest) = self.certify_reveal_parent(
                    &world,
                    before_close.as_ref().expect("native ordering parent"),
                    &namespace,
                    context,
                    proof,
                )?;
                Ok::<_, String>(RetainedNativeFixture {
                    vertex,
                    availability: certificate,
                    parent,
                    validation,
                    latest,
                })
            })
            .transpose()?;
        let permission = ProcessingRevealPermission {
            namespace_root: namespace,
            group_number: claim.group_number,
            group_root: claim.group_root,
            successor_root: group
                .closed_by_successor
                .ok_or("fixture predecessor is still open")?,
            processing_context_root: claim.member.processing_context_root,
            envelope_id: claim.member.envelope.tx_commitment,
            parent_block_id: native.as_ref().map_or_else(
                || self.source.block_id.clone(),
                |proof| proof.parent.block_id.clone(),
            ),
            validation_id: match &native {
                Some(proof) => proof.validation.id().map_err(err)?,
                None => self.source.finality_certificate_id.clone(),
            },
        };
        Ok((
            authorized,
            ClosedCandidateOrder {
                permission,
                world,
                native,
            },
        ))
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

#[allow(clippy::too_many_arguments)]
fn qualify_retained_replay(
    fixture: &CandidateOrderFixture<'_>,
    source: &NativeSourceFixture,
    context: &ProcessingContext,
    order: &ClosedCandidateOrder,
    opened: RevealedProcessingPayload<'_>,
    shares: &[ProcessingDecryptShare],
    terms: NativeSourceTerms<'_>,
) -> Result<(Arc<BudgetedWorld>, CandidateActionOutcome), String> {
    let authority = fixture.authority;
    let retained = order
        .native
        .as_ref()
        .ok_or("missing native reveal fixture")?;
    let native = NativeProcessingContext::verify_pw13(
        authority,
        context,
        &source.candidate,
        &source.witness,
    )?;
    assert!(NativeProcessingContext::verify(
        authority,
        context,
        ProcessingSource::Finalized {
            candidate: &source.candidate,
            witness: &source.witness
        },
    )
    .is_err());

    let mut altered_witness = source.witness.clone();
    altered_witness[0].participants[0].signature[0] ^= 1;
    assert!(NativeProcessingContext::verify_pw13(
        authority,
        context,
        &source.candidate,
        &altered_witness,
    )
    .is_err());

    let source_recovery = ProtectedAdmissionRecovery::new(
        terms.source.registry,
        NativeProcessingRecovery {
            source: &native,
            reveal_parent: &retained.parent,
            dag_parents: &[],
        },
        terms.recovery,
    )?;
    let snapshot = source_recovery.snapshot().position;
    let parameters = authority.protected_parameters()?;
    let latest_authorization_height = parameters
        .protected_target_height(retained.latest.finalized.height)
        .map_err(err)?;
    let latest_context = ProcessingContext {
        authority: authority
            .protected_target(
                Some(&retained.latest.finalized),
                latest_authorization_height,
            )?
            .0,
        ..context.clone()
    };
    let latest_native = NativeProcessingContext::verify_pw13(
        authority,
        &latest_context,
        &retained.latest.candidate,
        &retained.latest.witness,
    )?;
    let latest = terms
        .source
        .registry
        .native_finalized_snapshot(&latest_native.pw13_finalized_source()?)?;
    assert!(latest.position.height > snapshot.height);
    let namespace = &order.permission.namespace_root;
    let evidence = ProcessingCompletionEvidence::from_inputs(
        &retained.vertex,
        &retained.availability,
        &retained.validation,
        shares,
        &opened.ready_record(&retained.parent.state)?,
    );
    let scratch = Scratch::new();
    let budget = WorldResourceBudget::new(PROCESSING_INTAKE_HEADROOM_BYTES + 128 * 1024 * 1024);
    // Use the existing native pending owner's completion workspace.
    let limits = ProcessingStoreLimits {
        slots: 2,
        completion_bytes_per_item: 64 * 1024 * 1024,
    };
    // The same authority may have another live protected profile and more
    // than one retained candidate for this admission context. Neither may
    // substitute for the exact pair named by the original completion.
    let other_context = ProcessingContext {
        profile_id: if context.profile_id == PW13_TRANSFER_CANDIDATE_PROFILE_ID {
            PW13_SPONSOR_CANDIDATE_PROFILE_ID
        } else {
            PW13_TRANSFER_CANDIDATE_PROFILE_ID
        }
        .into(),
        ..context.clone()
    };
    let other_native = NativeProcessingContext::verify_pw13(
        authority,
        &other_context,
        &source.candidate,
        &source.witness,
    )?;
    let other_scope = ProtectedAdmissionRecovery::new(
        terms.source.registry,
        NativeProcessingRecovery {
            source: &other_native,
            reveal_parent: &retained.parent,
            dag_parents: &[],
        },
        terms.recovery,
    )?;
    let other_parent = ProtectedAdmissionRecovery::new(
        terms.source.registry,
        NativeProcessingRecovery {
            source: &native,
            reveal_parent: &source.candidate,
            dag_parents: &[],
        },
        terms.recovery,
    )?;
    let recovery = ProtectedJournalRecovery {
        sources: &[other_scope, other_parent, source_recovery],
    };
    let open = || {
        PendingProcessingStore::open(&scratch.0, namespace.clone(), limits, &budget, &recovery)
            .map_err(err)
    };
    let request_bytes = serde_json::to_vec(&retained.vertex.admission).map_err(err)?;
    let mut pending = open()?;
    let identity = pending
        .admit(context, snapshot.consensus_time, &request_bytes, &recovery)
        .map_err(err)?;
    let mut changed = evidence.clone();
    changed.reveal_validation.echoes[0].signature[0] ^= 1;
    assert!(matches!(
        pending.complete(&identity.envelope_id, &changed, &recovery),
        Err(ProcessingStoreError::Verification(_))
    ));
    for share in &mut changed.shares {
        share.share_bytes.fill(0);
    }
    assert!(!pending.has_completion(&identity.envelope_id));
    let foreign_source = ProtectedJournalRecovery {
        sources: &recovery.sources[..2],
    };
    assert!(matches!(
        pending.complete(&identity.envelope_id, &evidence, &foreign_source),
        Err(ProcessingStoreError::Verification(_))
    ));
    pending
        .complete(&identity.envelope_id, &evidence, &recovery)
        .map_err(|error| format!("persist verified PW13 completion: {error:?}"))?;
    drop(pending);
    let pending = open().map_err(|error| format!("reopen PW13 pending journal: {error}"))?;
    let publication_height = retained.parent.height + 1;
    let execution_height = publication_height + 1;
    let parent = retained.parent.state.as_ref();
    let publication = ProtectedCandidateContext {
        parent_block_id: &retained.parent.block_id,
        namespace,
        parameters: &parameters,
        slot: CandidateSlot {
            inclusion: Position {
                height: publication_height,
                consensus_time: authority.consensus_timestamp_unix(publication_height)?,
            },
            finalized_parent: &latest,
        },
    };
    let records = std::slice::from_ref(&evidence.record);
    let (published, outcomes) =
        execute_protected_journal_candidate(parent, publication, records, &pending, &recovery)?;
    assert!(outcomes.is_empty());
    assert_eq!(published.state.accounts, parent.accounts);
    let publication_bytes = serde_json::to_vec(&published).map_err(err)?;
    let mut substituted_record = evidence.record.clone();
    substituted_record.item.payload_root =
        EtdagDigest::from_canonical("TEST", &"substituted plaintext").map_err(err)?;
    assert!(replay_protected_journal_candidate(
        &publication_bytes,
        parent,
        publication,
        &[substituted_record],
        &pending,
        &recovery,
    )
    .is_err());
    let published = replay_protected_journal_candidate(
        &publication_bytes,
        parent,
        publication,
        records,
        &pending,
        &recovery,
    )?;
    let execution = ProtectedCandidateContext {
        parent_block_id: &published.block_id,
        slot: CandidateSlot {
            inclusion: Position {
                height: execution_height,
                consensus_time: authority.consensus_timestamp_unix(execution_height)?,
            },
            finalized_parent: &latest,
        },
        ..publication
    };
    let (settled, outcomes) =
        execute_protected_journal_candidate(&published.state, execution, &[], &pending, &recovery)?;
    let [outcome] =
        <[_; 1]>::try_from(outcomes).map_err(|_| "expected one native proof settlement")?;
    let original = serde_json::to_vec(&settled).map_err(err)?;
    assert!(replay_protected_journal_candidate(
        &original,
        &published.state,
        execution,
        &[],
        &pending,
        &foreign_source,
    )
    .is_err());
    let missing = Scratch::new();
    let empty =
        PendingProcessingStore::open(&missing.0, namespace.clone(), limits, &budget, &recovery)
            .map_err(err)?;
    assert!(replay_protected_journal_candidate(
        &original,
        &published.state,
        execution,
        &[],
        &empty,
        &recovery,
    )
    .is_err());
    drop(pending);
    let reopened = open()?;
    let replayed = replay_protected_journal_candidate(
        &original,
        &published.state,
        execution,
        &[],
        &reopened,
        &recovery,
    )?;
    assert_eq!(replayed, settled);
    if let CandidateAuthorization::Transfer(proof) = &retained.vertex.admission.authorization {
        qualify_expired_journal_receipt(
            fixture,
            retained,
            context,
            &published,
            execution,
            &reopened,
            &recovery,
            &evidence.record,
            &proof.resources,
        )?;
    }
    Ok((replayed.state, outcome))
}

#[allow(clippy::too_many_arguments)]
fn qualify_expired_journal_receipt(
    fixture: &CandidateOrderFixture<'_>,
    retained: &RetainedNativeFixture,
    context: &ProcessingContext,
    published: &BudgetedExecutionCandidate,
    execution: ProtectedCandidateContext<'_>,
    pending: &PendingProcessingStore<CandidateAdmission>,
    recovery: &ProtectedJournalRecovery<'_>,
    record: &ProcessingReadyRecord,
    resources: &synergy_etdag::admission::Pw13TransferResources,
) -> Result<(), String> {
    let authority = fixture.authority;
    let certify = |candidate: &BudgetedExecutionCandidate, parent: &SimplifiedFinalityParent| {
        certify_fixture_qc(
            candidate,
            parent,
            authority,
            fixture.engine,
            fixture.signers,
        )
    };
    let reveal = certify(&retained.parent, &retained.validation.candidate.parent)?;
    let publication = certify(published, &next_fixture_parent(&reveal)?)?;
    let deciding_height = (published.height + 1).max(resources.valid_until_finalized_height + 1);
    let mut witness = Vec::new();
    let mut deciding_candidate = None;
    let mut tip_qc = publication;
    for height in published.height + 1..=deciding_height + 2 {
        let parent = next_fixture_parent(&tip_qc)?;
        let candidate = proof_candidate(&published.state, execution.namespace, height, &parent)?;
        tip_qc = certify(&candidate, &parent)?;
        if height >= deciding_height {
            witness.push(tip_qc.clone());
        }
        if height == deciding_height {
            deciding_candidate = Some(candidate);
        }
    }
    let deciding_candidate = deciding_candidate.ok_or("missing expiry source candidate")?;
    let mut finality = ThreeQcFinality::default();
    for qc in &witness {
        finality.accept(qc.clone()).map_err(err)?;
    }
    let deciding_finality = finality
        .last_finalized()
        .ok_or("missing expiry source finality")?;
    let latest_context = ProcessingContext {
        authority: authority
            .protected_target(
                Some(deciding_finality),
                authority
                    .protected_parameters()?
                    .protected_target_height(deciding_height)
                    .map_err(err)?,
            )?
            .0,
        ..context.clone()
    };
    let native = NativeProcessingContext::verify_pw13(
        authority,
        &latest_context,
        &deciding_candidate,
        witness
            .as_slice()
            .try_into()
            .map_err(|_| "expected three expiry source QCs")?,
    )?;
    let registry = execution.slot.finalized_parent.registry;
    let latest = registry.native_finalized_snapshot(&native.pw13_finalized_source()?)?;
    let expired_height = tip_qc.context.height + 1;
    let expired_slot = ProtectedCandidateContext {
        parent_block_id: &tip_qc.block_id,
        slot: CandidateSlot {
            inclusion: Position {
                height: expired_height,
                consensus_time: authority.consensus_timestamp_unix(expired_height)?,
            },
            finalized_parent: &latest,
        },
        ..execution
    };
    let (expired, result) = execute_protected_journal_candidate(
        &published.state,
        expired_slot,
        &[],
        pending,
        recovery,
    )?;
    assert_eq!(
        result,
        vec![CandidateActionOutcome::Disposition(Disposition::Expired)]
    );
    assert_eq!(expired.state.accounts, published.state.accounts);
    let original = serde_json::to_vec(&expired).map_err(err)?;
    let expired = replay_protected_journal_candidate(
        &original,
        &published.state,
        expired_slot,
        &[],
        pending,
        recovery,
    )?;
    assert!(ParentProcessingRegistry::read(
        expired.state.as_ref().as_ref(),
        execution.namespace,
        expired.state.budget(),
    )
    .map_err(err)?
    .records()
    .is_empty());
    assert!(processing_member_claim_optional(
        expired.state.as_ref().as_ref(),
        &record.sender_wallet,
        record.sender_nonce,
    )
    .map_err(err)?
    .is_none());

    // Reconstruct a signed three-QC witness for the actual terminal World.
    // All signing keys and these candidate Worlds are isolated fixture inputs.
    let inclusion_qc = certify(&expired, &next_fixture_parent(&tip_qc)?)?;
    let mut parent = next_fixture_parent(&inclusion_qc)?;
    let mut witness = vec![tip_qc.clone(), inclusion_qc];
    for height in expired.height + 1..=expired.height + 2 {
        let successor = proof_candidate(&expired.state, execution.namespace, height, &parent)?;
        let qc = certify(&successor, &parent)?;
        parent = next_fixture_parent(&qc)?;
        witness.push(qc);
    }
    let mut finality = ThreeQcFinality::default();
    let mut finalized_predecessor = None;
    for qc in witness {
        qc.verify(&authority.epoch, &authority.registry, authority)
            .map_err(err)?;
        finality.accept(qc).map_err(err)?;
        if let Some(record) = finality.last_finalized() {
            if record.height == tip_qc.context.height {
                finalized_predecessor = Some(record.clone());
            }
        }
    }
    let finality = finality
        .last_finalized()
        .ok_or("expiry receipt lacks certified inclusion")?;
    assert_eq!(finality.block_id, expired.block_id);
    assert_eq!(
        finality.protected_execution_root,
        expired.protected_execution_root
    );
    let state = synergy_state::FinalizedState {
        finalized_height: expired.height,
        finalized_block_id: expired.block_id.clone(),
        state_root: expired.state_root.clone(),
    };
    let world: WorldState =
        serde_json::from_slice(&serde_json::to_vec(expired.state.as_ref().as_ref()).map_err(err)?)
            .map_err(err)?;
    let snapshot = registry.finalized_snapshot(
        &world,
        &state,
        finality,
        expired_slot.slot.inclusion.consensus_time,
    )?;
    let query = DispositionQuery {
        opening: super::settlement::EngineeringEtdagOpening {
            envelope_id: record.item.envelope_id.clone(),
            processing_context_root: record.processing_context_root.clone(),
            authorization_height: context.authority.target_height,
            payload_root: record.item.payload_root.clone(),
        },
        authorization_root: record.authorization_root.clone(),
        signed_intent_digest: super::inspection::hex_bytes(&resources.native_intent_digest),
    };
    let receipt = processing_disposition::inspect(&snapshot, &query)?;
    assert_eq!(receipt["status"], "expired_candidate");
    assert_eq!(receipt["fee_nwei"], "0");
    assert_eq!(receipt["gas_used"], 0);
    assert_eq!(receipt["nonce_consumed"], false);
    assert_eq!(receipt["deciding_finalized_height"], deciding_height);
    let previous = finalized_predecessor.ok_or("expiry receipt lacks certified predecessor")?;
    let policy = registry.read_policy(&world, super::AccountIdentifier::from_bytes(resources.account))?;
    let enrollment = super::CanonicalEnrollment::decode(&policy.enrollment, registry.wire)
        .map_err(err)?;
    let project = super::inspection::inspect_settlement_inclusion(
        super::inspection::CandidateWorld {
            world: published.state.as_ref().as_ref(),
            finality: &previous,
            state_root: &published.state_root,
            consensus_time: authority.consensus_timestamp_unix(previous.height)?,
        },
        super::inspection::CandidateWorld {
            world: &world,
            finality,
            state_root: &expired.state_root,
            consensus_time: expired_slot.slot.inclusion.consensus_time,
        },
        authority.epoch.chain_id,
        &super::inspection::hex_bytes(&registry.network.genesis),
        serde_json::from_value(serde_json::json!({
            "height": expired.height,
            "block_id": expired.block_id,
            "state_root": expired.state_root,
            "ownership_chain_id": super::inspection::hex_bytes(&registry.network.ownership_chain),
            "provider_manifests": [super::inspection::hex_bytes(&enrollment.policy().provider_manifest_hash)],
            "dispositions": [query],
        })).map_err(err)?,
    )?;
    assert_eq!(project["dispositions"][0], receipt);
    assert_eq!(project["ledger"][0]["predecessor"], project["ledger"][0]["inclusion"]);
    let mut substituted = query;
    substituted.signed_intent_digest = "ac".repeat(64);
    assert!(processing_disposition::inspect(&snapshot, &substituted).is_err());
    Ok(())
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
    native: Option<NativeSourceTerms<'_>>,
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
    let authority = match native {
        Some(terms) => Arc::new(authority.qualification_with_processing_ingress(
            registry.clone(),
            super::inspection::hex_bytes(&terms.source.registry.network.genesis),
        )),
        None => authority,
    };
    let budget = WorldResourceBudget::new(128 * 1024 * 1024);
    let native_source = native
        .map(|terms| certify_fixture_source(terms.source, &authority, &engine, &signers, &budget))
        .transpose()?;
    let source = native_source
        .as_ref()
        .map_or(source, |proof| &proof.finalized);
    let context = ProcessingContext {
        context_version: 1,
        profile_id: profile.into(),
        authority: if native_source.is_some() {
            authority.protected_target(Some(source), target_height)?.0
        } else {
            TargetAdmissionContextV3 {
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
            }
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
    let ordering = CandidateOrderFixture {
        authority: &authority,
        registry: &registry,
        engine: &engine,
        signers: &signers,
        source,
        native_source: native_source.as_ref(),
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
    let native_result = match (native, native_source.as_ref(), order.as_ref()) {
        (Some(terms), Some(source), Some(order)) => Some(qualify_retained_replay(
            &ordering,
            source,
            &context,
            order,
            opening.payload(&envelope, &context)?,
            &shares.0[..threshold],
            terms,
        )?),
        (Some(_), _, _) => return Err("native test did not retain its complete proof".into()),
        (None, _, _) => None,
    };
    Ok((
        OpenedCandidateEnvelope {
            opening,
            envelope,
            context,
            order,
            native_result,
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
        None,
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
        None,
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
