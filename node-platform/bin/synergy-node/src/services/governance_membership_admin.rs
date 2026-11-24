//! Closed retirement review and sign-once journal on the existing native owner.
use super::*;
use synergy_governance::{MembershipRetirementDraft, MEMBERSHIP_RETIREMENT_ACTION_V1};
const JOURNAL: &str = "membership-retirement.json";
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MembershipReservation {
    schema_version: u32,
    review_root: String,
    draft: MembershipRetirementDraft,
    vote: Option<GovernanceVote>,
}
pub(in crate::services) fn pending(
    store: &AtomicStore,
) -> Result<Option<(MembershipRetirementDraft, String, Instant)>, String> {
    if !store.exists(JOURNAL).map_err(|e| e.to_string())? {
        return Ok(None);
    }
    let r: MembershipReservation =
        serde_json::from_slice(&store.read_bounded(JOURNAL).map_err(|e| e.to_string())?)
            .map_err(|_| "invalid membership approval journal")?;
    if r.schema_version != 1 || r.review_root != r.draft.review_root()? {
        return Err("membership approval journal is corrupt".into());
    }
    Ok(r.vote
        .is_none()
        .then(|| (r.draft, r.review_root, Instant::now())))
}
impl GovernanceApprovalOwner {
    pub(in crate::services) fn recover_membership_pending(
        &mut self,
        authority: &VerifiedAuthority,
        ingress: &AuthenticatedIngress,
    ) {
        let Some((draft, root, next)) = self.pending_membership.take() else {
            return;
        };
        if authority.epoch.epoch != draft.spec.frozen_epoch {
            return;
        }
        if ingress
            .processing_finalized_world()
            .ok()
            .flatten()
            .is_some_and(|(h, _)| h >= draft.proposal.expires_at_height)
        {
            return;
        }
        if Instant::now() < next {
            self.pending_membership = Some((draft, root, next));
            return;
        }
        if self
            .approve_membership(authority, ingress, &draft, &root)
            .is_err()
        {
            self.pending_membership = Some((draft, root, Instant::now() + Duration::from_secs(5)));
        }
    }
    pub(in crate::services) fn prepare_membership(
        &self,
        authority: &VerifiedAuthority,
        ingress: &AuthenticatedIngress,
        target: &str,
    ) -> Result<Value, String> {
        use synergy_governance::*;
        authority
            .registry
            .active_validator(target)
            .map_err(|e| e.to_string())?;
        if authority.registry.active_count() <= synergy_posy::POSY_MIN_VALIDATOR_COUNT {
            return Err("retirement would fall below native minimum committee".into());
        }
        let (height, _) = ingress
            .processing_finalized_world()?
            .ok_or("authenticated finalized World unavailable")?;
        let expires = height
            .checked_add(512)
            .ok_or("retirement window overflow")?
            .min(
                authority
                    .epoch
                    .epoch_end_height
                    .checked_sub(5)
                    .ok_or("retirement close underflow")?,
            );
        if expires.checked_sub(height).is_none_or(|n| n < 64) {
            return Err("current frozen epoch has insufficient retirement review window; wait for certified successor".into());
        }
        let spec = MembershipRetirementSpec {
            schema_version: 1,
            chain_id: authority.epoch.chain_id,
            network_id: authority.epoch.network_id.clone(),
            genesis_hash: crate::services::membership_retirement::genesis(authority)?.into(),
            frozen_epoch: authority.epoch.epoch,
            frozen_epoch_context_root: authority.epoch.root().map_err(|e| e.to_string())?,
            install_not_before_finalized_height: height + 2,
            effective_epoch: authority
                .epoch
                .epoch
                .checked_add(1)
                .ok_or("retirement epoch overflow")?,
            retired_validator_id: target.into(),
        };
        let members = authority.registry.quorum_validators();
        let mut constitution = Constitution {
            version: 1,
            constitution_root: String::new(),
            rules: std::collections::BTreeMap::from([(
                MEMBERSHIP_RETIREMENT_ACTION_V1.into(),
                GovernanceRule {
                    action_kind: MEMBERSHIP_RETIREMENT_ACTION_V1.into(),
                    eligible_authorities: members.iter().map(|m| m.validator_id.clone()).collect(),
                    approval_threshold: members.len() * 2 / 3 + 1,
                    minimum_delay_blocks: 1,
                    emergency_permitted: false,
                },
            )]),
        };
        constitution.constitution_root = constitution.canonical_root()?;
        let mutation = spec.mutation()?;
        let mut proposal = GovernanceProposal {
            proposal_id: format!("posy-retirement-{}-{height}", authority.epoch.epoch),
            proposal_root: String::new(),
            proposer: self.validator_id.clone(),
            constitution_version: 1,
            created_at_height: height,
            expires_at_height: expires,
            actions: vec![GovernanceAction {
                kind: mutation.action_kind.clone(),
                target: mutation.target.clone(),
                payload_root: mutation.payload_root()?,
            }],
            state: ProposalState::Authorized,
        };
        proposal.proposal_root = proposal.canonical_root()?;
        self.review_membership(
            authority,
            ingress,
            &MembershipRetirementDraft {
                spec,
                proposal,
                constitution,
            },
        )
    }
    pub(in crate::services) fn review_membership(
        &self,
        authority: &VerifiedAuthority,
        ingress: &AuthenticatedIngress,
        draft: &MembershipRetirementDraft,
    ) -> Result<Value, String> {
        let root = draft.review_root()?;
        let s = &draft.spec;
        let (height, world) = ingress
            .processing_finalized_world()?
            .ok_or("membership review requires authenticated finalized World")?;
        let block = ingress
            .finalized_record(height)?
            .ok_or("membership review finalized commitment unavailable")?;
        let rule = draft.constitution.rule(MEMBERSHIP_RETIREMENT_ACTION_V1)?;
        let actual = authority
            .registry
            .quorum_validators()
            .into_iter()
            .map(|r| r.validator_id)
            .collect::<std::collections::BTreeSet<_>>();
        if s.chain_id != authority.epoch.chain_id
            || s.network_id != authority.epoch.network_id
            || s.genesis_hash != crate::services::membership_retirement::genesis(authority)?
            || s.frozen_epoch != authority.epoch.epoch
            || s.frozen_epoch_context_root != authority.epoch.root().map_err(|e| e.to_string())?
            || !authority.epoch.contains_height(height)
            || !authority
                .epoch
                .contains_height(draft.proposal.created_at_height)
            || draft.proposal.created_at_height > height
            || height >= draft.proposal.expires_at_height
            || draft
                .proposal
                .expires_at_height
                .checked_add(2)
                .is_none_or(|h| h >= authority.epoch.epoch_end_height.saturating_sub(2))
            || actual != rule.eligible_authorities.iter().cloned().collect()
            || rule.approval_threshold != actual.len() * 2 / 3 + 1
            || rule.emergency_permitted
            || world.protocol.contains_key(&s.record_key())
            || authority.registry.active_count() <= synergy_posy::POSY_MIN_VALIDATOR_COUNT
        {
            return Err(
                "retirement review differs from actual frozen authority or finalized window".into(),
            );
        }
        authority
            .registry
            .active_validator(&s.retired_validator_id)
            .map_err(|e| e.to_string())?;
        let (key_id, _) = authority.consensus_binding(&self.validator_id)?;
        if key_id != self.key_id.as_str() {
            return Err("retirement signer differs from frozen key".into());
        }
        Ok(
            json!({"schema":"synergy-membership-retirement-review-v1","review_root":root,"draft":draft,
            "validator_id":self.validator_id,"key_id":key_id,"finalized_height":height,"finalized_block_id":block.block_id,
            "old_validator_count":actual.len(),"old_count_quorum":actual.len()*2/3+1,
            "next_validator_count":actual.len()-1,"next_count_quorum":(actual.len()-1)*2/3+1,
            "frozen_validators":authority.registry.quorum_validators(),"weighted_quorum_required":true}),
        )
    }
    pub(in crate::services) fn approve_membership(
        &mut self,
        authority: &VerifiedAuthority,
        ingress: &AuthenticatedIngress,
        draft: &MembershipRetirementDraft,
        root: &str,
    ) -> Result<Value, String> {
        let review = self.review_membership(authority, ingress, draft)?;
        if review["review_root"] != root {
            return Err("exact retirement review changed".into());
        }
        let reserve = || MembershipReservation {
            schema_version: 1,
            review_root: root.into(),
            draft: draft.clone(),
            vote: None,
        };
        let mut record = if self.store.exists(JOURNAL).map_err(|e| e.to_string())? {
            let old: MembershipReservation = serde_json::from_slice(
                &self
                    .store
                    .read_bounded(JOURNAL)
                    .map_err(|e| e.to_string())?,
            )
            .map_err(|_| "invalid retirement approval journal")?;
            if old.schema_version != 1 || old.review_root != old.draft.review_root()? {
                return Err("corrupt retirement approval journal".into());
            }
            if old.review_root == root && old.draft == *draft {
                old
            } else {
                if old.draft.spec.genesis_hash != draft.spec.genesis_hash
                    || old.draft.spec.frozen_epoch >= draft.spec.frozen_epoch
                    || review["finalized_height"]
                        .as_u64()
                        .is_none_or(|h| h <= old.draft.proposal.expires_at_height)
                {
                    return Err("validator already reserved another still-valid retirement".into());
                }
                reserve()
            }
        } else {
            reserve()
        };
        if let Some(vote) = record.vote.as_ref() {
            authority.verify(vote)?;
            if vote.authority_id != self.validator_id
                || vote.key_id != self.key_id.as_str()
                || vote.proposal_root != draft.proposal.proposal_root
                || vote.choice != VoteChoice::Approve
            {
                return Err("stored retirement vote differs".into());
            }
            self.pending_membership = None;
            return Ok(
                json!({"schema":"synergy-membership-retirement-approval-v1","review_root":root,"vote":vote}),
            );
        }
        self.store
            .write_atomic(
                JOURNAL,
                &serde_json::to_vec(&record).map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())?;
        self.pending_membership = Some((
            draft.clone(),
            root.into(),
            Instant::now() + Duration::from_secs(5),
        ));
        let mut vote = GovernanceVote {
            proposal_root: draft.proposal.proposal_root.clone(),
            authority_id: self.validator_id.clone(),
            key_id: self.key_id.as_str().into(),
            choice: VoteChoice::Approve,
            signature: vec![0],
        };
        vote.signature = self
            .signer
            .sign(
                &self.key_id,
                &SigningContext {
                    domain: "SYNERGY-GOVERNANCE-VOTE-V1".into(),
                    chain_id: authority.epoch.chain_id,
                    epoch: Some(authority.epoch.epoch),
                    height: None,
                },
                &vote.signing_bytes()?,
            )
            .map_err(|e| e.to_string())?
            .bytes;
        authority.verify(&vote)?;
        record.vote = Some(vote.clone());
        self.store
            .write_atomic(
                JOURNAL,
                &serde_json::to_vec(&record).map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())?;
        self.pending_membership = None;
        Ok(
            json!({"schema":"synergy-membership-retirement-approval-v1","review_root":root,"vote":vote}),
        )
    }
    pub(in crate::services) fn membership_approval_status(
        &self,
        authority: &VerifiedAuthority,
        draft: &MembershipRetirementDraft,
    ) -> Result<Value, String> {
        let root = draft.review_root()?;
        if draft.spec.genesis_hash != crate::services::membership_retirement::genesis(authority)?
            || draft.spec.chain_id != authority.epoch.chain_id
            || draft.spec.network_id != authority.epoch.network_id
        {
            return Err("retirement lookup scope differs".into());
        }
        let r: MembershipReservation = serde_json::from_slice(
            &self
                .store
                .read_bounded(JOURNAL)
                .map_err(|e| e.to_string())?,
        )
        .map_err(|_| "invalid original retirement approval")?;
        if r.schema_version != 1 || r.review_root != root || r.draft != *draft {
            return Err("original retirement reservation differs".into());
        }
        let vote = r.vote.ok_or("retirement approval not durably available")?;
        if vote.authority_id != self.validator_id
            || vote.key_id != self.key_id.as_str()
            || vote.proposal_root != draft.proposal.proposal_root
            || vote.choice != VoteChoice::Approve
        {
            return Err("original retirement approval signer differs".into());
        }
        authority
            .authenticated_history_ref_at(draft.spec.install_not_before_finalized_height)
            .ok_or("retirement original authority absent")?
            .verify(&vote)?;
        Ok(
            json!({"schema":"synergy-membership-retirement-approval-v1","review_root":root,"vote":vote}),
        )
    }
    pub(in crate::services) fn assemble_membership(
        &self,
        authority: &VerifiedAuthority,
        ingress: &AuthenticatedIngress,
        draft: &MembershipRetirementDraft,
        root: &str,
        votes: Vec<GovernanceVote>,
    ) -> Result<Value, String> {
        if self.review_membership(authority, ingress, draft)?["review_root"] != root {
            return Err("retirement review changed".into());
        }
        let execution = draft.assemble(votes, authority)?;
        crate::services::membership_retirement::authorize_request(authority, &execution)?;
        let gas = 75000u64
            .checked_add(
                serde_json::to_vec(&execution)
                    .map_err(|e| e.to_string())?
                    .len() as u64,
            )
            .ok_or("retirement gas overflow")?;
        Ok(
            json!({"schema":"synergy-membership-retirement-execution-v1","review_root":root,"execution":execution,"gas_limit":gas,"maximum_fee_nwei":(u128::from(gas)*40).to_string(),"fee_authority":"separate-identity-bound-mldsa87-account-v1"}),
        )
    }
}
