//! Native verification boundary for the explicitly versioned processing path.
//! Existing PoSy certificates authenticate the parent World. ETDAG certifies
//! encrypted material and releases shares only after successor closure there.
//! No new consensus or finality certificate is introduced.
#![cfg_attr(not(test), allow(dead_code))] // Governed owner activation remains explicit.
#[cfg(feature = "qualification-timing")]
use crate::services::qualification_timing::{
    processing_span as diagnostic_span, ProcessingStage as DiagnosticStage,
};

use super::{
    authority::VerifiedAuthority,
    protected_admission::verify_wallet_processing_admission_with_authority,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};
use synergy_etdag::{
    crypto::{ShamirShare, SignatureVerifier},
    execution::{
        ProcessingDecryptShare, ProcessingGroupMember, ProcessingOrderGroup, ProcessingReadyItem,
        ProcessingRevealPermission, ProcessingVertex,
    },
    AvailabilityCertificate, EtdagDigest, ProcessingContext,
};
use synergy_execution::{
    BudgetedExecutionCandidate, ProcessingPayloadError, ProcessingPayloadProvider,
    ProcessingReadinessVerifier, ProcessingReadyRecord,
};
use synergy_posy::{ProposalValidationCertificate, SimplifiedQuorumCertificate, ThreeQcFinality};
use synergy_state::{
    world_resources::{BudgetedWorld, WorldResourceBudget, WorldResourcePermit},
    WorldState,
};

fn err(error: impl std::fmt::Debug) -> String {
    format!("native processing: {error:?}")
}
fn encoded_len(value: &(impl Serialize + ?Sized)) -> Result<usize, String> {
    struct Counter(usize);
    impl std::io::Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self
                .0
                .checked_add(bytes.len())
                .ok_or_else(|| std::io::Error::other("processing size overflow"))?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut count = Counter(0);
    serde_json::to_writer(&mut count, value).map_err(err)?;
    Ok(count.0)
}
fn reserve(
    value: &(impl Serialize + ?Sized),
    budget: &Arc<WorldResourceBudget>,
) -> Result<WorldResourcePermit, String> {
    let mut permit = budget.reserve(16 * 1024).map_err(err)?;
    let size = encoded_len(value)?;
    permit
        .grow(size.checked_mul(16).ok_or("processing size overflow")?)
        .map_err(err)?;
    Ok(permit)
}
pub(super) fn processing_namespace(
    authority: &VerifiedAuthority,
    budget: &Arc<WorldResourceBudget>,
) -> Result<EtdagDigest, String> {
    let _scratch = reserve(
        &(&authority.epoch, authority.protected_ingress_registry()?),
        budget,
    )?;
    EtdagDigest::from_canonical(
        "SYNERGY_ETDAG_PROCESSING_NAMESPACE_V1",
        &(
            synergy_etdag::PROCESSING_PROFILE_ID,
            authority.epoch.root().map_err(err)?,
            authority
                .protected_ingress_registry()?
                .root()
                .map_err(err)?,
        ),
    )
    .map_err(err)
}

/// Advisory/live assembly may defer allocation under pressure. Invalid native
/// authority still fails closed; only the typed capacity result is retryable.
pub(super) fn try_processing_namespace(
    authority: &VerifiedAuthority,
    budget: &Arc<WorldResourceBudget>,
) -> Result<Option<EtdagDigest>, String> {
    use synergy_state::world_resources::WorldResourceError;
    let mut scratch = match budget.reserve(16 * 1024) {
        Ok(permit) => permit,
        Err(WorldResourceError::Capacity { .. }) => return Ok(None),
        Err(error) => return Err(err(error)),
    };
    let registry = authority.protected_ingress_registry()?;
    let size = encoded_len(&(&authority.epoch, &registry))?;
    match scratch.grow(size.checked_mul(16).ok_or("processing size overflow")?) {
        Ok(()) => {}
        Err(WorldResourceError::Capacity { .. }) => return Ok(None),
        Err(error) => return Err(err(error)),
    }
    EtdagDigest::from_canonical(
        "SYNERGY_ETDAG_PROCESSING_NAMESPACE_V1",
        &(
            synergy_etdag::PROCESSING_PROFILE_ID,
            authority.epoch.root().map_err(err)?,
            registry.root().map_err(err)?,
        ),
    )
    .map(Some)
    .map_err(err)
}
pub(super) fn processing_order_seed(
    authority: &VerifiedAuthority,
    group: &ProcessingOrderGroup,
) -> Result<EtdagDigest, String> {
    EtdagDigest::from_canonical(
        "SYNERGY_ETDAG_PROCESSING_ORDER_SEED_V1",
        &(
            &group.namespace_root,
            group.group_number,
            &group.previous_group_root,
            &authority.epoch.finalized_epoch_seed_root,
        ),
    )
    .map_err(err)
}

/// Source state is authenticated by Genesis or the existing three-QC witness.
/// No caller-supplied timestamp, target policy, account snapshot or opaque root
/// is accepted as authorization merely because it appears in a disk record.
pub(super) enum ProcessingSource<'a> {
    Genesis(&'a BudgetedWorld),
    Finalized {
        candidate: &'a BudgetedExecutionCandidate,
        witness: &'a [SimplifiedQuorumCertificate; 3],
    },
}
enum ProcessingSourceWorld<'a> {
    Borrowed(&'a WorldState),
    Shared(Arc<BudgetedWorld>),
}
impl std::ops::Deref for ProcessingSourceWorld<'_> {
    type Target = WorldState;
    fn deref(&self) -> &WorldState {
        match self {
            Self::Borrowed(world) => world,
            Self::Shared(world) => world.as_ref().as_ref(),
        }
    }
}
pub(super) struct NativeProcessingContext<'a> {
    context: &'a ProcessingContext,
    authority: &'a VerifiedAuthority,
    world: ProcessingSourceWorld<'a>,
    timestamp: u64,
    _permit: WorldResourcePermit,
}
impl<'a> NativeProcessingContext<'a> {
    pub(super) fn authorization_root(&self) -> String {
        let bytes = self
            .world
            .protocol
            .get(synergy_identity::authorization::IDENTITY_AUTHORIZATION_BINDINGS_STATE_KEY)
            .map(Vec::as_slice)
            .unwrap_or_default();
        synergy_block::hash_block_bytes(bytes)
    }
    /// Share the already charged immutable World after verifying the exact
    /// candidate and its ordinary three-QC witness; never clone a source World.
    pub(super) fn verify_owned_finalized(
        authority: &'a VerifiedAuthority,
        context: &'a ProcessingContext,
        candidate: BudgetedExecutionCandidate,
        witness: &[SimplifiedQuorumCertificate; 3],
        budget: &Arc<WorldResourceBudget>,
    ) -> Result<Self, String> {
        Self::verify_owned_finalized_with_transition(
            authority, context, candidate, witness, budget, None,
        )
    }
    pub(super) fn verify_owned_finalized_with_transition(
        authority: &'a VerifiedAuthority,
        context: &'a ProcessingContext,
        candidate: BudgetedExecutionCandidate,
        witness: &[SimplifiedQuorumCertificate; 3],
        budget: &Arc<WorldResourceBudget>,
        transition: Option<&super::authority::VerifiedTransitionContext>,
    ) -> Result<Self, String> {
        let (timestamp, permit) = {
            let verified = NativeProcessingContext::verify_in_with_transition(
                authority,
                context,
                ProcessingSource::Finalized {
                    candidate: &candidate,
                    witness,
                },
                budget,
                transition,
            )?;
            (verified.timestamp, verified._permit)
        };
        Ok(Self {
            context,
            authority,
            timestamp,
            world: ProcessingSourceWorld::Shared(Arc::clone(&candidate.state)),
            _permit: permit,
        })
    }
    pub(super) fn verify(
        authority: &'a VerifiedAuthority,
        context: &'a ProcessingContext,
        source: ProcessingSource<'a>,
    ) -> Result<Self, String> {
        let budget = match &source {
            ProcessingSource::Genesis(world) => world.budget(),
            ProcessingSource::Finalized { candidate, .. } => candidate.state.budget(),
        };
        Self::verify_in(authority, context, source, budget)
    }
    pub(super) fn verify_in(
        authority: &'a VerifiedAuthority,
        context: &'a ProcessingContext,
        source: ProcessingSource<'a>,
        budget: &Arc<WorldResourceBudget>,
    ) -> Result<Self, String> {
        Self::verify_in_with_transition(authority, context, source, budget, None)
    }
    fn verify_in_with_transition(
        authority: &'a VerifiedAuthority,
        context: &'a ProcessingContext,
        source: ProcessingSource<'a>,
        budget: &Arc<WorldResourceBudget>,
        transition: Option<&super::authority::VerifiedTransitionContext>,
    ) -> Result<Self, String> {
        context.validate().map_err(err)?;
        if let Some(transition) = transition {
            transition.verify_current(authority)?;
        }
        let (world, record, permit) = match source {
            ProcessingSource::Genesis(world) => {
                let permit = budget.reserve(16 * 1024).map_err(err)?;
                let initial = authority.initial_world_state_root()?;
                if authority.anchor_parent.height() != 0
                    || synergy_state::state_root(world.as_ref()).map_err(err)? != initial
                {
                    return Err("processing source differs from governed Genesis".into());
                }
                (world.as_ref(), None, permit)
            }
            ProcessingSource::Finalized { candidate, witness } => {
                let mut permit = reserve(
                    &(
                        &candidate.transactions,
                        &candidate.receipts,
                        &candidate.protected_material,
                    ),
                    budget,
                )?;
                permit
                    .grow(
                        encoded_len(witness)?
                            .checked_mul(16)
                            .ok_or("processing witness overflow")?,
                    )
                    .map_err(err)?;
                candidate.validate()?;
                let mut finality = ThreeQcFinality::default();
                for qc in witness {
                    let original = if authority.epoch.contains_height(qc.context.height) {
                        authority
                    } else {
                        let previous = transition
                            .ok_or("processing source lacks authenticated historical authority")?;
                        if qc.context.height < previous.finalized().height
                            || qc.context.height > authority.anchor_parent.height()
                            || !previous
                                .previous_authority()
                                .epoch
                                .contains_height(qc.context.height)
                        {
                            return Err(
                                "processing source is outside authenticated transition tail".into(),
                            );
                        }
                        previous.previous_authority().as_ref()
                    };
                    qc.verify(&original.epoch, &original.registry, original)
                        .map_err(err)?;
                    finality.accept(qc.clone()).map_err(err)?;
                }
                let record = finality
                    .last_finalized()
                    .ok_or("processing source lacks three-QC finality")?
                    .clone();
                if record.height != candidate.height
                    || record.block_id != candidate.block_id
                    || record.protected_execution_root != candidate.protected_execution_root
                {
                    return Err("processing source finality and World disagree".into());
                }
                (candidate.state.as_ref().as_ref(), Some(record), permit)
            }
        };
        let expected = authority
            .protected_target(record.as_ref(), context.authority.target_height)?
            .0;
        if context.authority != expected {
            return Err("processing context differs from frozen native authority".into());
        }
        let timestamp = authority.consensus_timestamp_unix(context.authority.target_height)?;
        Ok(Self {
            context,
            authority,
            world: ProcessingSourceWorld::Borrowed(world),
            timestamp,
            _permit: permit,
        })
    }
}

/// This value cannot be deserialized. Every envelope, author, availability vote,
/// DAG parent and original wallet authorization has passed native verification.
pub(super) struct NativeProcessingVertex<'a> {
    vertex: &'a ProcessingVertex,
    source: &'a NativeProcessingContext<'a>,
    member: ProcessingGroupMember,
    vertex_id: EtdagDigest,
    _permit: WorldResourcePermit,
}
/// Charged compact member/DAG capability retained after original decoding.
/// It cannot be deserialized, so only native verification creates this value.
pub(super) struct NativeProcessingMember {
    namespace: EtdagDigest,
    vertex_id: EtdagDigest,
    member: ProcessingGroupMember,
    _permit: WorldResourcePermit,
}
impl NativeProcessingMember {
    pub(super) fn member(&self) -> &ProcessingGroupMember {
        &self.member
    }
    pub(super) fn vertex_id(&self) -> &EtdagDigest {
        &self.vertex_id
    }
}

impl<'a> NativeProcessingVertex<'a> {
    pub(super) fn verify(
        source: &'a NativeProcessingContext<'a>,
        vertex: &'a ProcessingVertex,
        certificate: &AvailabilityCertificate,
        parents: &[&NativeProcessingMember],
        budget: &Arc<WorldResourceBudget>,
    ) -> Result<Self, String> {
        Self::verify_inner(source, vertex, Some(certificate), parents, budget)
    }
    /// Before a custody vote, authenticate original wallet bytes, vertex author,
    /// frozen keys and DAG ancestry. No available-member capability escapes.
    pub(super) fn verify_for_availability(
        source: &'a NativeProcessingContext<'a>,
        vertex: &'a ProcessingVertex,
        parents: &[&NativeProcessingMember],
        budget: &Arc<WorldResourceBudget>,
    ) -> Result<(), String> {
        Self::verify_inner(source, vertex, None, parents, budget).map(drop)
    }
    fn verify_inner(
        source: &'a NativeProcessingContext<'a>,
        vertex: &'a ProcessingVertex,
        certificate: Option<&AvailabilityCertificate>,
        parents: &[&NativeProcessingMember],
        budget: &Arc<WorldResourceBudget>,
    ) -> Result<Self, String> {
        #[cfg(feature = "qualification-timing")]
        let _diagnostic = diagnostic_span(DiagnosticStage::VertexVerification);
        if certificate
            .is_some_and(|cert| cert.votes.len() > source.authority.registry.active_count())
            || vertex.parents.len() != parents.len()
            || parents.len() > 64
        {
            return Err("processing vertex proof exceeds governed bounds".into());
        }
        let mut permit = reserve(vertex, budget)?;
        permit
            .grow(
                encoded_len(&certificate)?
                    .checked_mul(16)
                    .ok_or("processing certificate overflow")?,
            )
            .map_err(err)?;
        let vertex_id = vertex.id().map_err(err)?;
        let context_root = source.context.root().map_err(err)?;
        if vertex.admission.request.context_root != context_root
            || certificate.is_some_and(|cert| {
                cert.context_root != context_root || cert.vertex_id != vertex_id
            })
        {
            return Err("processing availability binds different original material".into());
        }
        verify_wallet_processing_admission_with_authority(
            &vertex.admission,
            source.context,
            &source.world,
            source.timestamp,
            Some(source.authority),
        )?;
        source
            .authority
            .verify(
                &vertex.author_id,
                &vertex.key_id,
                &vertex.signing_bytes().map_err(err)?,
                &vertex.author_signature,
            )
            .map_err(err)?;
        let members = source
            .authority
            .registry
            .active()
            .map(|v| v.validator_id.clone())
            .collect::<BTreeSet<_>>();
        if let Some(certificate) = certificate {
            synergy_etdag::availability::verify_availability_certificate(
                certificate,
                &members,
                source.authority,
            )
            .map_err(err)?;
            let signed_weight = certificate.votes.iter().try_fold(0u128, |sum, vote| {
                sum.checked_add(
                    source
                        .authority
                        .registry
                        .active_validator(&vote.validator_id)
                        .map_err(err)?
                        .frozen_voting_weight,
                )
                .ok_or_else(|| "processing availability weight overflow".to_owned())
            })?;
            let total = source.authority.registry.active_weight().map_err(err)?;
            if signed_weight
                .checked_mul(3)
                .ok_or("processing weight overflow")?
                <= total.checked_mul(2).ok_or("processing weight overflow")?
            {
                return Err("processing availability lacks strict weight quorum".into());
            }
        }
        for (id, parent) in vertex.parents.iter().zip(parents) {
            if *id != parent.vertex_id
                || parent.member.processing_context_root != context_root
                || parent.member.envelope.certified_dag_round.checked_add(1)
                    != Some(vertex.envelope_ref.certified_dag_round)
            {
                return Err("processing DAG parent is not an authenticated preceding round".into());
            }
        }
        // Resolve every capsule against the ORIGINAL key-validity anchor.
        let registry = source.authority.protected_ingress_registry()?;
        if vertex.admission.request.envelope.share_capsules.len() != members.len() {
            return Err("processing capsule membership mismatch".into());
        }
        for capsule in &vertex.admission.request.envelope.share_capsules {
            let key = synergy_etdag::crypto::active_key_for_validator(
                registry,
                &capsule.validator_id,
                source.context.authority.target_height,
            )
            .map_err(err)?;
            if !members.contains(&capsule.validator_id) || key.key_id != capsule.ingress_kem_key_id
            {
                return Err("processing capsule key is outside original authority".into());
            }
        }
        let member = ProcessingGroupMember {
            processing_context_root: context_root,
            authorization_root: vertex.authorization_root().map_err(err)?,
            envelope: vertex.envelope_ref.clone(),
        };
        Ok(Self {
            vertex,
            source,
            member,
            vertex_id,
            _permit: permit,
        })
    }
    pub(super) fn member(&self) -> &ProcessingGroupMember {
        &self.member
    }
    pub(super) fn retain_member(
        &self,
        budget: &Arc<WorldResourceBudget>,
    ) -> Result<NativeProcessingMember, String> {
        let permit = reserve(&self.member, budget)?;
        Ok(NativeProcessingMember {
            namespace: processing_namespace(self.source.authority, budget)?,
            vertex_id: self.vertex_id.clone(),
            member: self.member.clone(),
            _permit: permit,
        })
    }
}

/// Existing n-1 ECHOs authenticate the exact ordinary candidate/World; they do
/// not become an alternate finality mechanism. Finality still needs three QCs.
pub(super) struct NativeProcessingParent<'a> {
    world: &'a BudgetedWorld,
    epoch_world: Option<BudgetedWorld>,
    epoch_transition: Option<synergy_execution::ProcessingEpochTransition>,
    height: u64,
    block_id: &'a str,
    authority: &'a VerifiedAuthority,
    namespace: EtdagDigest,
    validation_id: Option<String>,
    _permit: WorldResourcePermit,
}
impl<'a> NativeProcessingParent<'a> {
    pub(super) fn world(&self) -> &BudgetedWorld {
        self.epoch_world.as_ref().unwrap_or(self.world)
    }
    pub(super) fn epoch_transition(&self) -> Option<&synergy_execution::ProcessingEpochTransition> {
        self.epoch_transition.as_ref()
    }
    /// H1 uses only the signed Genesis parent. There is no invented VC and
    /// Genesis cannot authorize reveal, because no successor has been committed.
    pub(super) fn genesis(
        world: &'a BudgetedWorld,
        authority: &'a VerifiedAuthority,
    ) -> Result<Self, String> {
        if !authority.processing_profile_enabled()
            || authority.anchor_parent.height() != 0
            || synergy_state::state_root(world.as_ref()).map_err(err)?
                != authority.initial_world_state_root()?
        {
            return Err("processing bootstrap differs from signed Genesis".into());
        }
        let namespace = processing_namespace(authority, world.budget())?;
        let permit = world.budget().reserve(16 * 1024).map_err(err)?;
        Ok(Self {
            world,
            epoch_world: None,
            epoch_transition: None,
            height: 0,
            block_id: authority.anchor_parent.block_id(),
            authority,
            namespace,
            validation_id: None,
            _permit: permit,
        })
    }
    pub(super) fn verify(
        candidate: &'a BudgetedExecutionCandidate,
        certificate: &ProposalValidationCertificate,
        authority: &'a VerifiedAuthority,
    ) -> Result<Self, String> {
        Self::verify_in(candidate, certificate, authority, candidate.state.budget())
    }
    fn verify_in(
        candidate: &'a BudgetedExecutionCandidate,
        certificate: &ProposalValidationCertificate,
        authority: &'a VerifiedAuthority,
        budget: &Arc<WorldResourceBudget>,
    ) -> Result<Self, String> {
        #[cfg(feature = "qualification-timing")]
        let _diagnostic = diagnostic_span(DiagnosticStage::ParentVerification);
        if certificate.echoes.len() > authority.registry.active_count() {
            return Err("processing parent proof exceeds membership".into());
        }
        let mut permit = reserve(
            &(
                &candidate.transactions,
                &candidate.receipts,
                &candidate.protected_material,
            ),
            budget,
        )?;
        permit
            .grow(
                encoded_len(certificate)?
                    .checked_mul(16)
                    .ok_or("processing validation proof overflow")?,
            )
            .map_err(err)?;
        candidate.validate()?;
        certificate
            .verify(&authority.epoch, &authority.registry, authority)
            .map_err(err)?;
        if certificate.context.height != candidate.height
            || certificate.candidate.context.height != candidate.height
            || certificate.candidate.block_id != candidate.block_id
            || certificate.candidate.parent_block_id != candidate.parent_block_id
            || certificate.candidate.protected_execution_root != candidate.protected_execution_root
        {
            return Err("processing parent certificate differs from candidate World".into());
        }
        let namespace = processing_namespace(authority, budget)?;
        let synergy_etdag::execution::CandidateProtectedMaterial::Processing(material) =
            &candidate.protected_material
        else {
            return Err("processing parent has another governed profile".into());
        };
        if material.namespace_root != namespace {
            return Err("processing parent namespace mismatch".into());
        }
        Ok(Self {
            world: &candidate.state,
            epoch_world: None,
            epoch_transition: None,
            height: candidate.height,
            block_id: &candidate.block_id,
            authority,
            namespace,
            validation_id: Some(certificate.id().map_err(err)?),
            _permit: permit,
        })
    }
    /// The predecessor's original VC certifies this exact World. The signed
    /// successor transition separately authorizes it as the new epoch's parent;
    /// neither the old VC nor old material is relabeled into the new namespace.
    pub(super) fn verify_transition(
        candidate: &'a BudgetedExecutionCandidate,
        certificate: &ProposalValidationCertificate,
        previous: &'a VerifiedAuthority,
        current: &'a VerifiedAuthority,
        transition: &super::authority::VerifiedTransitionContext,
    ) -> Result<Self, String> {
        transition.verify_current(current)?;
        if previous.epoch.epoch.checked_add(1) != Some(current.epoch.epoch)
            || previous.epoch.epoch_end_height != current.anchor_parent.height()
            || current.anchor_parent.height().checked_add(1)
                != Some(current.epoch.epoch_start_height)
        {
            return Err("processing handoff is not a sequential epoch boundary".into());
        }
        if previous.epoch.root().map_err(err)?
            != transition.previous_authority().epoch.root().map_err(err)?
        {
            return Err("processing transition parent has another historical authority".into());
        }
        let boundary = &transition.certificates()[2];
        boundary
            .verify(&previous.epoch, &previous.registry, previous)
            .map_err(err)?;
        if candidate.height != current.anchor_parent.height()
            || candidate.height != boundary.context.height
            || candidate.block_id != boundary.block_id
            || candidate.parent_block_id != boundary.parent_block_id
            || candidate.protected_execution_root != boundary.protected_execution_root
            || current
                .anchor_parent
                .quorum_certificate_reference()
                .as_ref()
                != Some(&boundary.reference().map_err(err)?)
        {
            return Err("processing transition parent differs from signed epoch anchor".into());
        }
        let mut verified = Self::verify(candidate, certificate, previous)?;
        let next_namespace = processing_namespace(current, candidate.state.budget())?;
        let epoch_transition = synergy_execution::propose_empty_processing_epoch_transition(
            candidate.state.as_ref().as_ref(),
            &verified.namespace,
            &next_namespace,
            candidate.state.budget(),
        )
        .map_err(err)?;
        let mut epoch_world = candidate.state.try_clone().map_err(err)?;
        epoch_world
            .try_apply(epoch_transition.diff())
            .map_err(err)?;
        verified.authority = current;
        verified.namespace = next_namespace;
        verified.epoch_world = Some(epoch_world);
        verified.epoch_transition = Some(epoch_transition);
        Ok(verified)
    }

    pub(super) fn reveal_permission(
        &self,
        vertex: &NativeProcessingVertex<'_>,
    ) -> Result<ProcessingRevealPermission, String> {
        self.reveal_permission_in(vertex, self.world().budget())
    }
    fn reveal_permission_in(
        &self,
        vertex: &NativeProcessingVertex<'_>,
        budget: &Arc<WorldResourceBudget>,
    ) -> Result<ProcessingRevealPermission, String> {
        let validation_id = self
            .validation_id
            .as_ref()
            .ok_or("Genesis does not authorize processing reveal")?;
        let world = self.world().as_ref();
        let _scratch = budget.reserve(128 * 1024).map_err(err)?;
        if processing_namespace(vertex.source.authority, budget)? != self.namespace {
            return Err("processing reveal has foreign frozen authority".into());
        }
        let request = &vertex.vertex.admission.request;
        let claim = synergy_execution::processing_member_claim(
            world,
            &request.sender_wallet,
            request.sender_nonce,
        )
        .map_err(err)?;
        let group =
            synergy_execution::processing_group_state(world, &self.namespace, claim.group_number)
                .map_err(err)?;
        if claim.member != vertex.member || group.group_root != claim.group_root {
            return Err("processing reveal differs from original assignment".into());
        }
        let permission = ProcessingRevealPermission {
            namespace_root: self.namespace.clone(),
            group_number: claim.group_number,
            group_root: group.group_root,
            successor_root: group
                .closed_by_successor
                .ok_or("processing reveal precedes successor closure")?,
            processing_context_root: request.context_root.clone(),
            envelope_id: request.envelope.envelope_id.clone(),
            parent_block_id: self.block_id.to_owned(),
            validation_id: validation_id.clone(),
        };
        permission.validate().map_err(err)?;
        Ok(permission)
    }
}

/// Owns the charged plaintext only after native signed threshold reconstruction.
/// Native durable ownership must retain this reservation through publication.
pub(super) struct NativeProcessingCompletion {
    // Retain only the authenticated authorization needed at inclusion. Worker
    // handoff must not pin an entire historical source World or a decode stack.
    source_binding: synergy_identity::authorization::IdentityAuthorizationBindingCommitment,
    identity_authorization: synergy_identity::authorization::IdentityAuthorizationCarrier,
    signer_public_key: Vec<u8>,
    chain_id: u64,
    network_id: String,
    pub(super) record: ProcessingReadyRecord,
    plaintext: Vec<u8>,
    _permit: WorldResourcePermit,
}
impl Drop for NativeProcessingCompletion {
    fn drop(&mut self) {
        self.plaintext.fill(0);
    }
}
impl NativeProcessingCompletion {
    pub(super) fn decrypt(
        parent: &NativeProcessingParent<'_>,
        vertex: &NativeProcessingVertex<'_>,
        shares: &[ProcessingDecryptShare],
    ) -> Result<Self, String> {
        Self::decrypt_in(parent, vertex, shares, parent.world().budget())
    }
    pub(super) fn decrypt_in(
        parent: &NativeProcessingParent<'_>,
        vertex: &NativeProcessingVertex<'_>,
        shares: &[ProcessingDecryptShare],
        budget: &Arc<WorldResourceBudget>,
    ) -> Result<Self, String> {
        let authority = parent.authority;
        if shares.len() > authority.registry.active_count() {
            return Err("processing share count exceeds membership".into());
        }
        let permission = parent.reveal_permission_in(vertex, budget)?;
        let envelope = &vertex.vertex.admission.request.envelope;
        let mut permit = reserve(shares, budget)?;
        permit
            .grow(
                envelope
                    .ciphertext
                    .len()
                    .checked_mul(128)
                    .and_then(|n| n.checked_add(128 * 1024))
                    .ok_or("processing plaintext overflow")?,
            )
            .map_err(err)?;
        let mut signers = BTreeSet::new();
        let mut indices = BTreeSet::new();
        struct SecretShares(Vec<(String, ShamirShare)>);
        impl Drop for SecretShares {
            fn drop(&mut self) {
                for (_, share) in &mut self.0 {
                    share.value.fill(0);
                }
            }
        }
        let mut verified = SecretShares(Vec::new());
        for message in shares {
            if message.permission != permission
                || message.signature.len() > 16 * 1024
                || !signers.insert(&message.validator_id)
                || !indices.insert(message.share_index)
            {
                return Err("processing share replay or permission mismatch".into());
            }
            authority
                .verify(
                    &message.validator_id,
                    &message.key_id,
                    &message.signing_bytes().map_err(err)?,
                    &message.signature,
                )
                .map_err(err)?;
            let share = ShamirShare::from_canonical_bytes(&message.share_bytes).map_err(err)?;
            let capsule = envelope
                .share_capsules
                .iter()
                .find(|c| c.validator_id == message.validator_id)
                .ok_or("processing share lacks original capsule")?;
            if capsule.ingress_kem_key_id != message.ingress_kem_key_id
                || capsule.share_index != message.share_index
                || share.index != message.share_index
                || capsule.share_commitment != message.share_commitment
                || share
                    .commitment(
                        &message.validator_id,
                        &envelope.aad.processing_context_root,
                        envelope.aad.authorization_height,
                    )
                    .map_err(err)?
                    != message.share_commitment
            {
                return Err("processing share differs from original encrypted capsule".into());
            }
            verified.0.push((message.validator_id.clone(), share));
        }
        let count_quorum = authority.registry.active_count() - 1;
        let mut padded = synergy_etdag::crypto::decrypt_protected_payload(
            envelope,
            &verified.0,
            authority.registry.active_count(),
            count_quorum,
        )
        .map_err(err)?;
        drop(verified);
        let plaintext = synergy_etdag::crypto::unpad_plaintext(&padded).map_err(err);
        padded.fill(0);
        let plaintext = plaintext?;
        let transaction: synergy_transaction::SignedTransaction =
            serde_json::from_slice(&plaintext).map_err(err)?;
        transaction.validate_structure().map_err(err)?;
        let request = &vertex.vertex.admission.request;
        if transaction.unsigned.class != synergy_transaction::TransactionClass::User
            || transaction.unsigned.sender != request.sender_wallet
            || transaction.unsigned.nonce != request.sender_nonce
            || transaction.unsigned.network.chain_id != vertex.source.context.authority.chain_id
            || transaction.unsigned.network.network_id != vertex.source.context.authority.network_id
            || transaction.unsigned.fee_limit.gas_limit != request.gas_class_units
            || transaction.signer_public_key != request.signer_public_key
            || transaction.identity_authorization.as_ref()
                != Some(&vertex.vertex.admission.identity_authorization)
        {
            return Err(
                "processing plaintext differs from original native wallet admission".into(),
            );
        }
        let binding = synergy_identity::authorization::resolve_transaction_binding_with_verifier(
            &vertex.source.world.protocol,
            &request.sender_wallet,
            &vertex.vertex.admission.identity_authorization,
            &request.signer_public_key,
            vertex.source.context.authority.chain_id,
            &vertex.source.context.authority.network_id,
            vertex.source.timestamp,
            vertex.source.authority.identity_verifier(),
        )?;
        synergy_transaction::verify_aegis_signature_with_admission(
            &transaction,
            &super::execution::TransactionPqvmVerifier::from_authority(
                vertex.source.authority,
                transaction.unsigned.network.chain_id,
            ),
            synergy_transaction::TransactionAdmissionContext {
                consensus_timestamp_unix: vertex.source.timestamp,
                canonical_binding: &binding,
            },
        )
        .map_err(err)?;
        let claim = synergy_execution::processing_member_claim(
            parent.world().as_ref(),
            &request.sender_wallet,
            request.sender_nonce,
        )
        .map_err(err)?;
        let payload_root = synergy_execution::processing_payload_root(
            &request.context_root,
            &envelope.envelope_id,
            &plaintext,
        )
        .map_err(err)?;
        let readiness_root = EtdagDigest::from_canonical(
            "SYNERGY_ETDAG_PROCESSING_NATIVE_READY_V1",
            &(&parent.namespace, &claim, &payload_root),
        )
        .map_err(err)?;
        let record = ProcessingReadyRecord {
            processing_context_root: request.context_root.clone(),
            authorization_root: vertex.member.authorization_root.clone(),
            sender_wallet: request.sender_wallet.clone(),
            sender_nonce: request.sender_nonce,
            item: ProcessingReadyItem {
                group_number: claim.group_number,
                group_root: claim.group_root,
                order_position: claim.order_position,
                envelope_id: envelope.envelope_id.clone(),
                payload_root,
                readiness_root,
                gas_class_units: request.gas_class_units,
                encoded_bytes: plaintext.len() as u64,
                remaining_dependencies: vertex.member.envelope.protocol_dependencies.clone(),
            },
        };
        let retained = plaintext
            .capacity()
            .checked_add(
                encoded_len(&vertex.vertex.admission.identity_authorization)?
                    .checked_mul(16)
                    .ok_or("processing completion size overflow")?,
            )
            .and_then(|n| n.checked_add(128 * 1024))
            .ok_or("processing completion size overflow")?;
        // All decode/signature/crypto scratch must die before its charge can be
        // released. The original transaction and claim are no longer retained.
        drop(transaction);
        permit.shrink(retained).map_err(err)?;
        Ok(Self {
            source_binding: binding,
            identity_authorization: vertex.vertex.admission.identity_authorization.clone(),
            signer_public_key: request.signer_public_key.clone(),
            chain_id: vertex.source.context.authority.chain_id,
            network_id: vertex.source.context.authority.network_id.clone(),
            record,
            plaintext,
            _permit: permit,
        })
    }
}

/// Borrowed bounded worker results. This adapter grants no authority to arbitrary
/// caller records: only private, natively verified vertex/completion values enter.
pub(super) struct NativeProcessingPipeline<'a> {
    parent: &'a NativeProcessingParent<'a>,
    vertices: BTreeMap<EtdagDigest, (EtdagDigest, ProcessingGroupMember)>,
    completions: BTreeMap<EtdagDigest, &'a NativeProcessingCompletion>,
    _permit: WorldResourcePermit,
}
impl<'a> NativeProcessingPipeline<'a> {
    pub(super) fn new(
        parent: &'a NativeProcessingParent<'a>,
        vertices: &[&NativeProcessingVertex<'_>],
        completions: &[&'a NativeProcessingCompletion],
    ) -> Result<Self, String> {
        let namespace = processing_namespace(parent.authority, parent.world().budget())?;
        for vertex in vertices {
            if processing_namespace(vertex.source.authority, parent.world().budget())? != namespace
            {
                return Err("processing member has foreign frozen authority".into());
            }
        }
        Self::assemble(
            parent,
            vertices.iter().map(|vertex| (&namespace, &vertex.member)),
            vertices.len(),
            completions,
        )
    }
    pub(super) fn from_members(
        parent: &'a NativeProcessingParent<'a>,
        members: &[&NativeProcessingMember],
        completions: &[&'a NativeProcessingCompletion],
    ) -> Result<Self, String> {
        Self::assemble(
            parent,
            members
                .iter()
                .map(|member| (&member.namespace, &member.member)),
            members.len(),
            completions,
        )
    }
    fn assemble<'m>(
        parent: &'a NativeProcessingParent<'a>,
        members: impl Iterator<Item = (&'m EtdagDigest, &'m ProcessingGroupMember)>,
        count: usize,
        completions: &[&'a NativeProcessingCompletion],
    ) -> Result<Self, String> {
        if count > 4096 || completions.len() > 4096 {
            return Err("processing native index capacity".into());
        }
        let mut permit = parent
            .world()
            .budget()
            .reserve((count + completions.len()) * 4096 + 16 * 1024)
            .map_err(err)?;
        let mut vertex_map = BTreeMap::new();
        let mut completion_map = BTreeMap::new();
        for (namespace, member) in members {
            permit
                .grow(
                    encoded_len(member)?
                        .checked_mul(16)
                        .ok_or("processing member size overflow")?,
                )
                .map_err(err)?;
            if vertex_map
                .insert(
                    member.envelope.tx_commitment.clone(),
                    (namespace.clone(), member.clone()),
                )
                .is_some()
            {
                return Err("duplicate processing vertex".into());
            }
        }
        for completion in completions {
            if completion_map
                .insert(completion.record.item.envelope_id.clone(), *completion)
                .is_some()
            {
                return Err("duplicate processing completion".into());
            }
        }
        Ok(Self {
            parent,
            vertices: vertex_map,
            completions: completion_map,
            _permit: permit,
        })
    }
    fn check_parent(&self, world: &WorldState) -> Result<(), String> {
        if !std::ptr::eq(world, self.parent.world().as_ref()) {
            return Err("processing verifier used with another parent World".into());
        }
        Ok(())
    }
}
impl ProcessingReadinessVerifier for NativeProcessingPipeline<'_> {
    fn first_unconsumed_position(
        &self,
        record: &ProcessingReadyRecord,
        parent: &WorldState,
    ) -> Result<Option<u32>, String> {
        self.check_parent(parent)?;
        Ok(Some(
            synergy_execution::processing_group_state(
                parent,
                &self.parent.namespace,
                record.item.group_number,
            )
            .map_err(err)?
            .next_position,
        ))
    }

    fn verify_ordered_group(
        &self,
        group: &ProcessingOrderGroup,
        parent: &WorldState,
    ) -> Result<(), String> {
        self.check_parent(parent)?;
        if group.namespace_root != self.parent.namespace
            || group.order_seed != processing_order_seed(self.parent.authority, group)?
        {
            return Err("processing group scope/seed mismatch".into());
        }
        for member in &group.members {
            let (namespace, original) = self
                .vertices
                .get(&member.envelope.tx_commitment)
                .ok_or("processing group lacks native availability material")?;
            if *namespace != self.parent.namespace || original != member {
                return Err("processing group rewrites original encrypted DAG member".into());
            }
        }
        Ok(())
    }
    fn verify_publication(
        &self,
        record: &ProcessingReadyRecord,
        parent: &WorldState,
    ) -> Result<(), String> {
        self.check_parent(parent)?;
        let completion = self
            .completions
            .get(&record.item.envelope_id)
            .ok_or("processing completion is not natively verified")?;
        if completion.record != *record {
            return Err(
                "processing ready publication differs from reconstructed native payload".into(),
            );
        }
        synergy_execution::verify_processing_record_assignment(
            parent,
            &self.parent.namespace,
            record,
        )
        .map_err(err)?;
        Ok(())
    }
    fn identity_is_current(
        &self,
        record: &ProcessingReadyRecord,
        parent: &WorldState,
    ) -> Result<bool, String> {
        self.check_parent(parent)?;
        let completion = self
            .completions
            .get(&record.item.envelope_id)
            .ok_or("processing eligibility lacks original native authorization")?;
        self.parent.identity_is_current(
            record,
            &completion.source_binding,
            &completion.identity_authorization,
            completion.chain_id,
            &completion.network_id,
            &completion.signer_public_key,
        )
    }
}
impl NativeProcessingParent<'_> {
    pub(super) fn identity_is_current(
        &self,
        record: &ProcessingReadyRecord,
        before: &synergy_identity::authorization::IdentityAuthorizationBindingCommitment,
        carrier: &synergy_identity::authorization::IdentityAuthorizationCarrier,
        chain_id: u64,
        network_id: &str,
        signer_public_key: &[u8],
    ) -> Result<bool, String> {
        let current = synergy_identity::authorization::canonical_binding_commitment_if_present(
            &self.world.protocol,
            &record.sender_wallet,
        )?;
        if current.as_ref().is_some_and(|current| current != before) {
            return Ok(false);
        }
        let timestamp = self.authority.consensus_timestamp_unix(
            self.height
                .checked_add(1)
                .ok_or("processing height overflow")?,
        )?;
        Ok(carrier
            .identity_address_for_key_for_admission_at_with_verifier(
                synergy_identity::authorization::AEGIS_TRANSACTION_AUTHORIZATION_DOMAIN,
                chain_id,
                network_id,
                "ML-DSA-87",
                signer_public_key,
                "transaction-signing",
                timestamp,
                &before.binding_payload_sha3_256,
                self.authority.identity_verifier(),
            )
            .is_ok_and(|sender| sender == record.sender_wallet))
    }
}
impl ProcessingPayloadProvider for NativeProcessingPipeline<'_> {
    fn plaintext<'a>(
        &'a self,
        record: &ProcessingReadyRecord,
    ) -> Result<&'a [u8], ProcessingPayloadError> {
        let completion = self
            .completions
            .get(&record.item.envelope_id)
            .ok_or_else(|| ProcessingPayloadError::Unavailable(record.item.envelope_id.clone()))?;
        // Dependencies may have been retired by prior canonical transitions.
        let mut original = completion.record.item.clone();
        if record
            .item
            .remaining_dependencies
            .iter()
            .any(|id| !original.remaining_dependencies.contains(id))
        {
            return Err(ProcessingPayloadError::Corrupt(
                "processing payload adds unauthenticated dependencies".into(),
            ));
        }
        original.remaining_dependencies = record.item.remaining_dependencies.clone();
        if original != record.item
            || completion.record.processing_context_root != record.processing_context_root
            || completion.record.authorization_root != record.authorization_root
            || completion.record.sender_wallet != record.sender_wallet
            || completion.record.sender_nonce != record.sender_nonce
        {
            return Err(ProcessingPayloadError::Corrupt(
                "processing payload lookup differs from native completion".into(),
            ));
        }
        Ok(&completion.plaintext)
    }
}

impl super::processing_store::ProcessingAdmissionAuthenticator for NativeProcessingContext<'_> {
    fn verify(
        &self,
        context: &ProcessingContext,
        timestamp: u64,
        admission: &synergy_etdag::WalletProcessingAdmission,
    ) -> Result<(), String> {
        if context != self.context || timestamp != self.timestamp {
            return Err("processing pending journal changed frozen native authority/time".into());
        }
        verify_wallet_processing_admission_with_authority(
            admission,
            self.context,
            &self.world,
            self.timestamp,
            Some(self.authority),
        )
    }
}

/// Per-item recovery evidence before the threshold is complete. Original
/// ciphertext is referenced from the immutable pending slot and is not copied.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProcessingProgressEvidence {
    pub(super) version: u32,
    pub(super) vertex_version: u32,
    pub(super) envelope_ref: synergy_etdag::CertifiedEnvelopeRef,
    pub(super) parents: Vec<EtdagDigest>,
    pub(super) author_id: String,
    pub(super) key_id: String,
    pub(super) author_signature: Vec<u8>,
    pub(super) availability: Option<AvailabilityCertificate>,
    pub(super) reveal_validation: Option<ProposalValidationCertificate>,
    pub(super) shares: Vec<ProcessingDecryptShare>,
}
impl ProcessingProgressEvidence {
    pub(super) fn from_vertex(vertex: &ProcessingVertex) -> Self {
        Self {
            version: 1,
            vertex_version: vertex.vertex_version,
            envelope_ref: vertex.envelope_ref.clone(),
            parents: vertex.parents.clone(),
            author_id: vertex.author_id.clone(),
            key_id: vertex.key_id.clone(),
            author_signature: vertex.author_signature.clone(),
            availability: None,
            reveal_validation: None,
            shares: Vec::new(),
        }
    }
    pub(super) fn preserves(&self, old: &Self) -> bool {
        self.version == old.version
            && self.vertex_version == old.vertex_version
            && self.envelope_ref == old.envelope_ref
            && self.parents == old.parents
            && self.author_id == old.author_id
            && self.key_id == old.key_id
            && self.author_signature == old.author_signature
            && old
                .availability
                .as_ref()
                .is_none_or(|cert| self.availability.as_ref() == Some(cert))
            && old
                .reveal_validation
                .as_ref()
                .is_none_or(|cert| self.reveal_validation.as_ref() == Some(cert))
            && old.shares.iter().all(|share| self.shares.contains(share))
    }
}

pub(super) struct NativeProcessingProgressRecovery<'a> {
    pub(super) source: &'a NativeProcessingContext<'a>,
    pub(super) reveal_parent: Option<&'a BudgetedExecutionCandidate>,
    pub(super) dag_parents: &'a [&'a NativeProcessingMember],
}
impl super::processing_store::ProcessingAdmissionAuthenticator
    for NativeProcessingProgressRecovery<'_>
{
    fn verify(
        &self,
        context: &ProcessingContext,
        timestamp: u64,
        admission: &synergy_etdag::WalletProcessingAdmission,
    ) -> Result<(), String> {
        super::processing_store::ProcessingAdmissionAuthenticator::verify(
            self.source,
            context,
            timestamp,
            admission,
        )
    }
    fn verify_progress(
        &self,
        context: &ProcessingContext,
        admission: &synergy_etdag::WalletProcessingAdmission,
        evidence: &ProcessingProgressEvidence,
        budget: &Arc<WorldResourceBudget>,
    ) -> Result<(), String> {
        #[cfg(feature = "qualification-timing")]
        let _diagnostic = diagnostic_span(DiagnosticStage::ProgressVerification);
        if evidence.version != 1
            || context != self.source.context
            || evidence.shares.len() > self.source.authority.registry.active_count()
        {
            return Err("processing progress has foreign context or excessive shares".into());
        }
        let _copy = reserve(admission, budget)?;
        let vertex = ProcessingVertex {
            vertex_version: evidence.vertex_version,
            admission: admission.clone(),
            envelope_ref: evidence.envelope_ref.clone(),
            parents: evidence.parents.clone(),
            author_id: evidence.author_id.clone(),
            key_id: evidence.key_id.clone(),
            author_signature: evidence.author_signature.clone(),
        };
        let Some(certificate) = evidence.availability.as_ref() else {
            NativeProcessingVertex::verify_for_availability(
                self.source,
                &vertex,
                self.dag_parents,
                budget,
            )?;
            return if evidence.reveal_validation.is_none() && evidence.shares.is_empty() {
                Ok(())
            } else {
                Err("processing reveal lacks native availability".into())
            };
        };
        let verified = NativeProcessingVertex::verify(
            self.source,
            &vertex,
            certificate,
            self.dag_parents,
            budget,
        )?;
        let Some(vc) = evidence.reveal_validation.as_ref() else {
            return if evidence.shares.is_empty() {
                Ok(())
            } else {
                Err("processing shares lack durable native reveal permission".into())
            };
        };
        let parent = NativeProcessingParent::verify_in(
            self.reveal_parent
                .ok_or("processing progress lacks exact reveal World")?,
            vc,
            self.source.authority,
            budget,
        )?;
        let permission = parent.reveal_permission_in(&verified, budget)?;
        let envelope = &admission.request.envelope;
        let mut validators = BTreeSet::new();
        let mut indices = BTreeSet::new();
        for message in &evidence.shares {
            if message.permission != permission
                || !validators.insert(&message.validator_id)
                || !indices.insert(message.share_index)
                || message.signature.len() > 16 * 1024
            {
                return Err("processing partial reveal replay or permission mismatch".into());
            }
            self.source
                .authority
                .verify(
                    &message.validator_id,
                    &message.key_id,
                    &message.signing_bytes().map_err(err)?,
                    &message.signature,
                )
                .map_err(err)?;
            let capsule = envelope
                .share_capsules
                .iter()
                .find(|c| c.validator_id == message.validator_id)
                .ok_or("processing partial share lacks original capsule")?;
            let mut share = ShamirShare::from_canonical_bytes(&message.share_bytes).map_err(err)?;
            let commitment = share
                .commitment(
                    &message.validator_id,
                    &envelope.aad.processing_context_root,
                    envelope.aad.authorization_height,
                )
                .map_err(err);
            let index = share.index;
            share.value.fill(0);
            if capsule.ingress_kem_key_id != message.ingress_kem_key_id
                || capsule.share_index != message.share_index
                || index != message.share_index
                || capsule.share_commitment != message.share_commitment
                || commitment? != message.share_commitment
            {
                return Err(
                    "processing partial share differs from original encrypted capsule".into(),
                );
            }
        }
        Ok(())
    }
    fn verify_completion(
        &self,
        context: &ProcessingContext,
        admission: &synergy_etdag::WalletProcessingAdmission,
        evidence: &ProcessingCompletionEvidence,
        budget: &Arc<WorldResourceBudget>,
    ) -> Result<(), String> {
        let recovery = NativeProcessingRecovery {
            source: self.source,
            reveal_parent: self.reveal_parent.ok_or("completion lacks reveal World")?,
            dag_parents: self.dag_parents,
        };
        super::processing_store::ProcessingAdmissionAuthenticator::verify_completion(
            &recovery, context, admission, evidence, budget,
        )
    }
}

/// Durable proof inputs, not a trusted completion flag. The original wallet
/// request is kept once in its immutable pending slot. Parent Worlds remain in
/// the ordinary candidate store; this witness names the existing native VC.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProcessingCompletionEvidence {
    pub(super) version: u32,
    pub(super) vertex_version: u32,
    pub(super) envelope_ref: synergy_etdag::CertifiedEnvelopeRef,
    pub(super) parents: Vec<EtdagDigest>,
    pub(super) author_id: String,
    pub(super) key_id: String,
    pub(super) author_signature: Vec<u8>,
    pub(super) availability: AvailabilityCertificate,
    pub(super) reveal_validation: ProposalValidationCertificate,
    pub(super) shares: Vec<ProcessingDecryptShare>,
    pub(super) record: ProcessingReadyRecord,
}

impl ProcessingCompletionEvidence {
    pub(super) fn from_inputs(
        vertex: &ProcessingVertex,
        availability: &AvailabilityCertificate,
        reveal_validation: &ProposalValidationCertificate,
        shares: &[ProcessingDecryptShare],
        record: &ProcessingReadyRecord,
    ) -> Self {
        Self {
            version: 1,
            vertex_version: vertex.vertex_version,
            envelope_ref: vertex.envelope_ref.clone(),
            parents: vertex.parents.clone(),
            author_id: vertex.author_id.clone(),
            key_id: vertex.key_id.clone(),
            author_signature: vertex.author_signature.clone(),
            availability: availability.clone(),
            reveal_validation: reveal_validation.clone(),
            shares: shares.to_vec(),
            record: record.clone(),
        }
    }
}

/// Resolution is supplied by the existing owner from its retained candidate and
/// DAG stores. Neither a disk root nor an ECHO certificate substitutes for the
/// authenticated World or the original context's Genesis/three-QC source.
pub(super) struct NativeProcessingRecovery<'a> {
    pub(super) source: &'a NativeProcessingContext<'a>,
    pub(super) reveal_parent: &'a BudgetedExecutionCandidate,
    pub(super) dag_parents: &'a [&'a NativeProcessingMember],
}
impl NativeProcessingRecovery<'_> {
    pub(super) fn with_completion<T>(
        &self,
        admission: &synergy_etdag::WalletProcessingAdmission,
        evidence: &ProcessingCompletionEvidence,
        budget: &Arc<WorldResourceBudget>,
        action: impl FnOnce(&NativeProcessingCompletion) -> Result<T, String>,
    ) -> Result<T, String> {
        let completion = self.recover(admission, evidence, budget)?;
        action(&completion)
    }
    pub(super) fn recover(
        &self,
        admission: &synergy_etdag::WalletProcessingAdmission,
        evidence: &ProcessingCompletionEvidence,
        budget: &Arc<WorldResourceBudget>,
    ) -> Result<NativeProcessingCompletion, String> {
        if evidence.version != 1 {
            return Err("unsupported durable processing completion".into());
        }
        // Charge the owned reconstruction before cloning original wallet bytes.
        let _vertex_copy = reserve(admission, budget)?;
        let vertex = ProcessingVertex {
            vertex_version: evidence.vertex_version,
            admission: admission.clone(),
            envelope_ref: evidence.envelope_ref.clone(),
            parents: evidence.parents.clone(),
            author_id: evidence.author_id.clone(),
            key_id: evidence.key_id.clone(),
            author_signature: evidence.author_signature.clone(),
        };
        let verified = NativeProcessingVertex::verify(
            self.source,
            &vertex,
            &evidence.availability,
            self.dag_parents,
            budget,
        )?;
        let parent = NativeProcessingParent::verify_in(
            self.reveal_parent,
            &evidence.reveal_validation,
            self.source.authority,
            budget,
        )?;
        let completion =
            NativeProcessingCompletion::decrypt_in(&parent, &verified, &evidence.shares, budget)?;
        if completion.record != evidence.record {
            return Err("durable processing completion differs from native reconstruction".into());
        }
        Ok(completion)
    }
}
impl super::processing_store::ProcessingAdmissionAuthenticator for NativeProcessingRecovery<'_> {
    fn verify(
        &self,
        context: &ProcessingContext,
        timestamp: u64,
        admission: &synergy_etdag::WalletProcessingAdmission,
    ) -> Result<(), String> {
        super::processing_store::ProcessingAdmissionAuthenticator::verify(
            self.source,
            context,
            timestamp,
            admission,
        )
    }
    fn verify_progress(
        &self,
        context: &ProcessingContext,
        admission: &synergy_etdag::WalletProcessingAdmission,
        evidence: &ProcessingProgressEvidence,
        budget: &Arc<WorldResourceBudget>,
    ) -> Result<(), String> {
        let recovery = NativeProcessingProgressRecovery {
            source: self.source,
            reveal_parent: Some(self.reveal_parent),
            dag_parents: self.dag_parents,
        };
        super::processing_store::ProcessingAdmissionAuthenticator::verify_progress(
            &recovery, context, admission, evidence, budget,
        )
    }
    fn verify_completion(
        &self,
        _: &ProcessingContext,
        admission: &synergy_etdag::WalletProcessingAdmission,
        evidence: &ProcessingCompletionEvidence,
        budget: &Arc<WorldResourceBudget>,
    ) -> Result<(), String> {
        #[cfg(feature = "qualification-timing")]
        let _diagnostic = diagnostic_span(DiagnosticStage::CompletionVerification);
        self.with_completion(admission, evidence, budget, |_| Ok(()))
    }
}

/// Physical retirement is authorized only by an exact finalized selection,
/// durable execution commitment and the configured finalized retention fence.
/// Speculative World deletion or a changed sender nonce cannot grant it.
pub(super) struct NativeProcessingRetirement {
    height: u64,
    block_id: String,
    state_root: String,
    consumed: BTreeMap<EtdagDigest, super::processing_store::PendingProcessingIdentity>,
    _permit: WorldResourcePermit,
}
impl NativeProcessingRetirement {
    pub(super) fn identities(
        &self,
    ) -> impl Iterator<Item = &super::processing_store::PendingProcessingIdentity> {
        self.consumed.values()
    }

    /// Authorization-source pins can contain unrelated historical transactions
    /// after their consumption parent has retired. They are not retirement
    /// dependencies of every newly pending envelope. Filter only by exact
    /// replay identity before loading that parent; a match still requires the
    /// complete native selection, execution and three-QC proof below.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn recover_pending<'a>(
        authority: &VerifiedAuthority,
        height: u64,
        block_id: &str,
        candidate_root: &std::path::Path,
        state_root: &std::path::Path,
        consensus_root: &std::path::Path,
        mut pending: impl Iterator<Item = &'a super::processing_store::PendingProcessingIdentity>,
        budget: &Arc<WorldResourceBudget>,
    ) -> Result<Option<Self>, String> {
        let candidates = synergy_execution::BudgetedCandidateStore::new_budgeted(
            candidate_root,
            budget.clone(),
        )?;
        let candidate = candidates
            .get_budgeted(height)
            .map_err(err)?
            .ok_or("finalized processing candidate is unavailable")?;
        if candidate.block_id != block_id {
            return Err("finalized processing subject mismatch".into());
        }
        if !pending.any(|identity| {
            candidate.transactions.iter().any(|transaction| {
                transaction.unsigned.sender == identity.sender_wallet
                    && transaction.unsigned.nonce == identity.sender_nonce
            })
        }) {
            return Ok(None);
        }
        drop(candidate);
        Self::recover(
            authority,
            height,
            block_id,
            candidate_root,
            state_root,
            consensus_root,
            0,
            budget,
        )
        .map(Some)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn recover(
        authority: &VerifiedAuthority,
        height: u64,
        block_id: &str,
        candidate_root: &std::path::Path,
        state_root: &std::path::Path,
        consensus_root: &std::path::Path,
        retain_blocks: u64,
        budget: &Arc<WorldResourceBudget>,
    ) -> Result<Self, String> {
        let candidates = synergy_execution::BudgetedCandidateStore::new_budgeted(
            candidate_root,
            budget.clone(),
        )?;
        let candidate = candidates
            .get_budgeted(height)
            .map_err(err)?
            .ok_or("finalized processing candidate is unavailable")?;
        if candidate.block_id != block_id {
            return Err("finalized processing subject mismatch".into());
        }
        let parent = candidates
            .get_budgeted(
                height
                    .checked_sub(1)
                    .ok_or("processing consumption at Genesis")?,
            )
            .map_err(err)?
            .ok_or("finalized processing parent is unavailable")?;
        let qcs = synergy_posy::VerifiedQuorumCertificateStore::new(consensus_root).map_err(err)?;
        let heights = [
            height,
            height.checked_add(1).ok_or("processing witness overflow")?,
            height.checked_add(2).ok_or("processing witness overflow")?,
        ];
        let mut verified = Vec::with_capacity(3);
        for value in heights {
            verified.push(
                qcs.get_verified(value, &authority.epoch, &authority.registry, authority)
                    .map_err(err)?
                    .ok_or("processing retirement QC is unavailable")?,
            );
        }
        let witness: [SimplifiedQuorumCertificate; 3] = verified
            .try_into()
            .map_err(|_| "processing retirement witness length")?;
        let states = synergy_state::FinalizedStateStore::load_budgeted(state_root, budget.clone())
            .map_err(err)?;
        let finality =
            synergy_posy::persistence::FinalityStore::new(consensus_root).map_err(err)?;
        Self::verify(
            authority,
            &candidate,
            &parent,
            &witness,
            &candidates,
            &states,
            &finality,
            retain_blocks,
            budget,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn verify(
        authority: &VerifiedAuthority,
        candidate: &BudgetedExecutionCandidate,
        parent: &BudgetedExecutionCandidate,
        witness: &[SimplifiedQuorumCertificate; 3],
        candidates: &synergy_execution::BudgetedCandidateStore,
        states: &synergy_state::FinalizedStateStore,
        finality_store: &synergy_posy::persistence::FinalityStore,
        retain_blocks: u64,
        budget: &Arc<WorldResourceBudget>,
    ) -> Result<Self, String> {
        let mut permit = reserve(
            &(
                &candidate.protected_material,
                &parent.protected_material,
                witness,
            ),
            budget,
        )?;
        candidate.validate()?;
        parent.validate()?;
        if parent.height.checked_add(1) != Some(candidate.height)
            || candidate.parent_block_id != parent.block_id
        {
            return Err("processing retirement has another canonical parent".into());
        }
        let mut finality = ThreeQcFinality::default();
        for qc in witness {
            qc.verify(&authority.epoch, &authority.registry, authority)
                .map_err(err)?;
            finality.accept(qc.clone()).map_err(err)?;
        }
        let finalized = finality
            .last_finalized()
            .ok_or("processing retirement lacks finality")?;
        if finalized.height != candidate.height
            || finalized.block_id != candidate.block_id
            || finalized.protected_execution_root != candidate.protected_execution_root
            || finality_store.get(candidate.height).map_err(err)?.as_ref() != Some(finalized)
        {
            return Err("processing retirement differs from durable PoSy finality".into());
        }
        let state = states
            .history_at(candidate.height)
            .map_err(err)?
            .ok_or("processing retirement lacks durable execution state")?;
        let tip = states
            .current()
            .ok_or("processing retirement lacks execution tip")?;
        if state.finalized_block_id != candidate.block_id
            || state.state_root != candidate.state_root
            || tip.finalized_height
                < candidate
                    .height
                    .checked_add(retain_blocks)
                    .ok_or("processing retirement retention overflow")?
        {
            return Err("processing retirement precedes execution/retention fence".into());
        }
        for value in [candidate, parent] {
            let durable = candidates
                .commitment(value.height)?
                .ok_or("processing retirement lacks durable candidate")?;
            if durable.block_id != value.block_id
                || durable.state_root != value.state_root
                || durable.protected_execution_root != value.protected_execution_root
            {
                return Err("processing retirement candidate differs from durable bytes".into());
            }
        }
        let synergy_etdag::execution::CandidateProtectedMaterial::Processing(material) =
            &candidate.protected_material
        else {
            return Err("processing retirement has another governed profile".into());
        };
        let namespace = processing_namespace(authority, budget)?;
        if material.namespace_root != namespace {
            return Err("processing retirement scope mismatch".into());
        }
        // A finalized empty selection consumes no identity and grants no
        // physical deletion. In particular the first new-epoch parent retains
        // its historical namespace; it must not be reinterpreted for retirement.
        if material.selection.item_indices.is_empty() && candidate.transactions.is_empty() {
            return Ok(Self {
                height: candidate.height,
                block_id: candidate.block_id.clone(),
                state_root: candidate.state_root.clone(),
                consumed: BTreeMap::new(),
                _permit: permit,
            });
        }
        let registry = synergy_execution::ParentProcessingRegistry::read(
            parent.state.as_ref().as_ref(),
            &namespace,
            budget,
        )
        .map_err(err)?;
        if registry.view().root().map_err(err)? != material.selection.parent_ready_root {
            return Err("processing retirement selection has another parent ready view".into());
        }
        permit
            .grow(material.selection.item_indices.len() * 4096)
            .map_err(err)?;
        let mut consumed = BTreeMap::new();
        for (position, index) in material.selection.item_indices.iter().enumerate() {
            let record = registry
                .records()
                .get(*index as usize)
                .ok_or("processing retirement selection index missing")?;
            let transaction = candidate
                .transactions
                .get(position)
                .ok_or("processing retirement transaction missing")?;
            if transaction.unsigned.sender != record.sender_wallet
                || transaction.unsigned.nonce != record.sender_nonce
            {
                return Err(
                    "processing retirement transaction differs from selected replay identity"
                        .into(),
                );
            }
            consumed.insert(
                record.item.envelope_id.clone(),
                super::processing_store::PendingProcessingIdentity {
                    envelope_id: record.item.envelope_id.clone(),
                    context_root: record.processing_context_root.clone(),
                    sender_wallet: record.sender_wallet.clone(),
                    sender_nonce: record.sender_nonce,
                },
            );
        }
        Ok(Self {
            height: candidate.height,
            block_id: candidate.block_id.clone(),
            state_root: candidate.state_root.clone(),
            consumed,
            _permit: permit,
        })
    }
}
impl super::processing_store::ProcessingRetirementVerifier for NativeProcessingRetirement {
    fn finalized_subject(&self) -> Option<(u64, &str)> {
        Some((self.height, &self.block_id))
    }
    fn finalized_state_root(&self) -> Option<&str> {
        Some(&self.state_root)
    }
    fn verify_retirement(
        &self,
        item: &super::processing_store::PendingProcessingIdentity,
    ) -> Result<(), String> {
        if self.consumed.get(&item.envelope_id) != Some(item) {
            return Err(
                "pending processing envelope was not finalized by this exact selection".into(),
            );
        }
        Ok(())
    }
}
