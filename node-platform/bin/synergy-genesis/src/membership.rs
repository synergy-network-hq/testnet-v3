//! Shared membership provenance consumed by the native owner and independent
//! clients. A signed retirement becomes active only in a certified successor.
use crate::authority::{ProtectedCutoffRelationship, ProtectedEpochPolicy};
use synergy_governance::{GovernanceExecution, MembershipRetirementSpec, VoteChoice, VoteVerifier,
    MEMBERSHIP_RETIREMENT_ACTION_V1};
use synergy_posy::{EpochTransitionAuthorization, FrozenValidatorRegistry, SimplifiedEpochContext};

#[derive(Debug, Clone)]
pub struct VerifiedMembershipRetirement {
    execution: GovernanceExecution,
    spec: MembershipRetirementSpec,
    next_registry: FrozenValidatorRegistry,
}
impl VerifiedMembershipRetirement {
    pub fn verify(
        execution: &GovernanceExecution,
        genesis_hash: &str,
        previous: &SimplifiedEpochContext,
        registry: &FrozenValidatorRegistry,
        verifier: &impl VoteVerifier,
    ) -> Result<Self, String> {
        previous.validate_against(registry).map_err(|e|e.to_string())?;
        if execution.mutation.action_kind != MEMBERSHIP_RETIREMENT_ACTION_V1
            || execution.mutation.value.is_empty() || execution.mutation.value.len()>4096 {
            return Err("unsupported bounded membership retirement".into());
        }
        let spec:MembershipRetirementSpec=serde_json::from_slice(&execution.mutation.value).map_err(|e|e.to_string())?;
        if let Some(policy)=&spec.automatic_admission_policy {policy.validate()?;}
        let close=previous.epoch_end_height.checked_sub(2).ok_or("membership close underflow")?;
        if spec.schema_version!=1 || spec.chain_id!=previous.chain_id || spec.network_id!=previous.network_id
            || spec.genesis_hash!=genesis_hash || spec.frozen_epoch!=previous.epoch
            || spec.frozen_epoch_context_root!=previous.root().map_err(|e|e.to_string())?
            || previous.epoch.checked_add(1)!=Some(spec.effective_epoch)
            || execution.mutation!=spec.mutation()? || execution.proposal.actions.len()!=1
            || !previous.contains_height(spec.install_not_before_finalized_height)
            || spec.install_not_before_finalized_height<execution.proposal.created_at_height
            || spec.install_not_before_finalized_height>execution.proposal.expires_at_height
            // Its three-QC finality must precede proposing the closing subject.
            || execution.proposal.expires_at_height.checked_add(2).is_none_or(|h|h>=close)
            || !previous.contains_height(execution.proposal.created_at_height)
            || execution.votes.len()>registry.active_count() {
            return Err("membership retirement differs from exact chain, original epoch or finalized-height window".into());
        }
        if execution.verify(verifier,&execution.authorization_root,spec.install_not_before_finalized_height)?!=spec.record_key() {
            return Err("membership retirement authorization key differs".into());
        }
        let mut signers=Vec::new();
        for vote in &execution.votes {
            let record=registry.active_validator(&vote.authority_id).map_err(|e|e.to_string())?;
            if vote.choice!=VoteChoice::Approve || vote.key_id!=record.consensus_key_id {
                return Err("membership retirement vote is not an original frozen approval".into());
            }
            verifier.verify(vote)?;
            signers.push(vote.authority_id.clone());
        }
        synergy_posy::verify_strict_dual_quorum(&registry.quorum_validators(),&signers).map_err(|e|format!("{e:?}"))?;
        registry.active_validator(&spec.retired_validator_id).map_err(|e|e.to_string())?;
        let next_registry=FrozenValidatorRegistry::new(spec.effective_epoch,
            registry.active().filter(|record|record.validator_id!=spec.retired_validator_id).cloned().collect())
            .map_err(|e|e.to_string())?;
        Ok(Self{execution:execution.clone(),spec,next_registry})
    }
    pub fn spec(&self)->&MembershipRetirementSpec { &self.spec }
    pub fn execution(&self)->&GovernanceExecution { &self.execution }
    pub fn next_registry(&self)->&FrozenValidatorRegistry { &self.next_registry }
    pub fn prepare_successor(
        &self, previous:&SimplifiedEpochContext, current:&ProtectedEpochPolicy,
        registry:&FrozenValidatorRegistry,
    )->Result<(EpochTransitionAuthorization,ProtectedEpochPolicy,FrozenValidatorRegistry),String> {
        self.prepare_successor_with_wallet(previous,current,registry,None)
    }
    pub fn prepare_successor_with_wallet(
        &self, previous:&SimplifiedEpochContext, current:&ProtectedEpochPolicy,
        registry:&FrozenValidatorRegistry, wallet:Option<&crate::authority::VerifiedWalletDispatchRelease>,
    )->Result<(EpochTransitionAuthorization,ProtectedEpochPolicy,FrozenValidatorRegistry),String> {
        if previous.root().map_err(|e|e.to_string())?!=self.spec.frozen_epoch_context_root
            || current.cutoff_relationship!=ProtectedCutoffRelationship::ProcessingGroupsV1 {
            return Err("retirement does not extend the exact native asynchronous epoch".into());
        }
        current.validate(registry,previous)?;
        let mut next=current.successor_clock(previous.epoch_start_height,previous.epoch_end_height)?;
        next.membership_authorization_root=Some(self.execution.authorization_root.clone());
        if let Some(policy)=&self.spec.automatic_admission_policy {next.automatic_validator_admission=Some(policy.clone());}
        let active:std::collections::BTreeSet<_>=self.next_registry.active().map(|v|v.validator_id.as_str()).collect();
        next.ingress_kem_registry.records.retain(|record|active.contains(record.validator_id.as_str()));
        next.assigned_cluster_membership_root=self.next_registry.active_set_root().map_err(|e|e.to_string())?;
        rebind_processing_membership(&mut next,previous,&self.next_registry)?;
        if let Some(release)=wallet {
            let (_,wallet_next)=release.prepare_successor(previous,current,registry)?;
            next.wallet_dispatch=wallet_next.wallet_dispatch;
        }
        let authorization=EpochTransitionAuthorization::for_governed_successor(previous,&self.next_registry,next.commitment()?)
            .map_err(|e|e.to_string())?;
        let context=SimplifiedEpochContext::from_frozen_registry(previous.chain_id,previous.network_id.clone(),
            authorization.next_epoch,authorization.next_epoch_start_height,authorization.next_epoch_end_height,
            previous.finalized_epoch_seed_root.clone(),authorization.next_consensus_parameter_root.clone(),&self.next_registry)
            .map_err(|e|e.to_string())?;
        next.validate(&self.next_registry,&context)?;
        Ok((authorization,next,self.next_registry.clone()))
    }
}

// Exact serialization/domain definitions are the existing native single-cluster
// descriptors, extended to the next authenticated membership and epoch range.
pub(crate) fn rebind_processing_membership(
    next:&mut ProtectedEpochPolicy, previous:&SimplifiedEpochContext, registry:&FrozenValidatorRegistry,
) ->Result<(),String> {
    #[derive(serde::Serialize)]
    struct Cluster<'a>{version:u32,chain_id:u64,network_id:&'a str,epoch:u64,cluster_id:u64,members:Vec<&'a synergy_posy::ValidatorRecord>}
    let cluster=Cluster{version:1,chain_id:previous.chain_id,network_id:&previous.network_id,epoch:registry.epoch(),
        cluster_id:0,members:registry.active().collect()};
    next.cluster_map_root=synergy_posy::canonical_hash("SYNERGY_FRESH_SINGLE_CLUSTER_MAP_V1",&cluster).map_err(|e|e.to_string())?;
    #[derive(serde::Serialize)]
    struct Schedule<'a>{version:u32,chain_id:u64,network_id:&'a str,epoch:u64,epoch_start_height:u64,epoch_end_height:u64,
        assigned_cluster_id:u64,cluster_map_root:&'a str,processing_profile_id:&'static str,authorization_height_offset:u64,
        authorization_anchor_is_inclusion_deadline:bool,cutoff_relationship:&'static str}
    let first=previous.epoch_end_height.checked_add(1).ok_or("membership height overflow")?;
    let schedule=Schedule{version:1,chain_id:previous.chain_id,network_id:&previous.network_id,epoch:registry.epoch(),
        epoch_start_height:first,epoch_end_height:first.checked_add(999).ok_or("membership height overflow")?,assigned_cluster_id:0,
        cluster_map_root:&next.cluster_map_root,processing_profile_id:synergy_etdag::PROCESSING_PROFILE_ID,
        authorization_height_offset:next.parameters.target_height_offset,authorization_anchor_is_inclusion_deadline:false,
        cutoff_relationship:"processing_groups_v1"};
    next.assigned_height_schedule_root=synergy_posy::canonical_hash("SYNERGY_ASYNC_AUTHORIZATION_SCHEDULE_V1",&schedule).map_err(|e|e.to_string())?;
    // This descriptor is validated against the selected member count below;
    // both count quorum and Shamir threshold use their canonical ETDAG helpers.
    next.cryptographic_profile_root=processing_crypto_profile(registry.active_count())?;
    Ok(())
}

pub fn processing_crypto_profile(member_count:usize)->Result<String,String> {
    #[derive(serde::Serialize)]
    struct Crypto<'a>{version:u32,profile_id:&'a str,envelope_version:u32,decrypt_share_version:u32,
        author_and_reveal_signature:&'a str,ingress_kem:&'a str,ingress_public_key_bytes:usize,ingress_ciphertext_bytes:usize,
        aead:&'a str,aead_key_bytes:usize,aead_nonce_bytes:usize,sharing:&'a str,sharing_field_polynomial:u16,sharing_key_bytes:usize,
        member_count:usize,count_quorum:usize,reveal_threshold:usize,capsule_key_domain:&'a str,key_commitment_domain:&'a str,
        share_commitment_domain:&'a str,share_commitment_root_domain:&'a str,capsule_root_domain:&'a str}
    let count_quorum=synergy_etdag::certificate_quorum(member_count).map_err(|e|format!("{e:?}"))?;
    let value=Crypto{version:1,profile_id:synergy_etdag::PROCESSING_PROFILE_ID,envelope_version:1,decrypt_share_version:1,
        author_and_reveal_signature:"ML-DSA-65",ingress_kem:"ML-KEM-1024",ingress_public_key_bytes:1568,ingress_ciphertext_bytes:1568,
        aead:"AES-256-GCM",aead_key_bytes:32,aead_nonce_bytes:12,sharing:"Shamir-GF256",sharing_field_polynomial:0x11b,sharing_key_bytes:32,
        member_count,count_quorum,reveal_threshold:member_count-count_quorum+1,capsule_key_domain:"PoSy/ETDAG/CapsuleKey/v3",
        key_commitment_domain:"PoSy/ETDAG/KeyCommitment/v3",share_commitment_domain:"PoSy/ETDAG/ShareCommitment/v3",
        share_commitment_root_domain:"PoSy/ETDAG/ShareCommitmentRoot/v3",capsule_root_domain:"PoSy/ETDAG/ShareCapsuleRoot/v3"};
    synergy_posy::canonical_hash("SYNERGY_ASYNC_CRYPTO_PROFILE_V1",&value).map_err(|e|e.to_string())
}
