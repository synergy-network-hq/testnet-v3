//! Dedicated, typed governance signing on the live PoSy owner's thread.
//! This is separate from the consensus sign-once journal and cannot sign a
//! proposal/vote/timeout transcript or spend a native account.
use super::{authority::VerifiedAuthority, ethereum_activation, ingress::AuthenticatedIngress};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};
use synergy_aegis::{AegisSigner, KeyId, SigningContext};
use synergy_governance::{EthereumActivationDraft, GovernanceVote, VoteChoice, VoteVerifier};
use synergy_storage::AtomicStore;
#[path="governance_membership_admin.rs"]
mod membership;

pub(super) struct GovernanceApprovalOwner {
    validator_id: String,
    key_id: KeyId,
    signer: Arc<dyn AegisSigner>,
    store: AtomicStore,
    pending_recovery: Option<(EthereumActivationDraft, String, Instant)>,
    pending_membership:Option<(synergy_governance::MembershipRetirementDraft,String,Instant)>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Reservation {
    schema_version: u32,
    review_root: String,
    draft: EthereumActivationDraft,
    vote: Option<GovernanceVote>,
}
impl GovernanceApprovalOwner {
    pub(super) fn new(
        validator_id: String,
        key_id: KeyId,
        signer: Arc<dyn AegisSigner>,
        root: &Path,
    ) -> Result<Self, String> {
        let store = AtomicStore::new(root, 256 * 1024).map_err(|e| e.to_string())?;
        let pending_recovery = if store
            .exists("ethereum-initial.json")
            .map_err(|e| e.to_string())?
        {
            let record: Reservation = serde_json::from_slice(
                &store
                    .read_bounded("ethereum-initial.json")
                    .map_err(|e| e.to_string())?,
            )
            .map_err(|_| "invalid durable governance reservation")?;
            if record.schema_version != 1 || record.review_root != record.draft.review_root()? {
                return Err("durable governance reservation is corrupt".into());
            }
            record
                .vote
                .is_none()
                .then(|| (record.draft, record.review_root, Instant::now()))
        } else {
            None
        };
        let pending_membership=membership::pending(&store)?;
        Ok(Self {
            pending_membership,
            validator_id,
            key_id,
            signer,
            store,
            pending_recovery,
        })
    }
    /// Complete only an already authorized, durably reserved exact proposal.
    /// No new grant, draft or signature scope is inferred from a status read.
    pub(super) fn recover_pending(
        &mut self,
        authority: &VerifiedAuthority,
        ingress: &AuthenticatedIngress,
    ) {
        self.recover_membership_pending(authority,ingress);
        let Some((draft, root, next)) = self.pending_recovery.take() else {
            return;
        };
        if Instant::now() < next {
            self.pending_recovery = Some((draft, root, next));
            return;
        }
        if ingress
            .processing_finalized_world()
            .ok()
            .flatten()
            .is_some_and(|(h, _)| h >= draft.proposal.expires_at_height)
            || authority.epoch.epoch != draft.spec.frozen_epoch
        {
            return;
        }
        if self.approve(authority, ingress, &draft, &root).is_err() {
            self.pending_recovery = Some((draft, root, Instant::now() + Duration::from_secs(5)));
        }
    }
    pub(super) fn prepare(
        &self,
        authority: &VerifiedAuthority,
        ingress: &AuthenticatedIngress,
        policy_json: &str,
    ) -> Result<Value, String> {
        use synergy_governance::{
            Constitution, EthereumActivationSpec, GovernanceAction, GovernanceProposal,
            GovernanceRule, ProposalState, ETHEREUM_ACTIVATION_ACTION_V1,
            ETHEREUM_ACTIVATION_HISTORY_WARMUP_BLOCKS,
        };
        let policy: synergy_aivm::ethereum_execution::EvmCompatibilityPolicy =
            serde_json::from_str(policy_json).map_err(|_| "invalid explicit Ethereum policy")?;
        let bytes = serde_json::to_vec(&policy).map_err(|e| e.to_string())?;
        let (height, _) = ingress
            .processing_finalized_world()?
            .ok_or("authenticated finalized World unavailable")?;
        let expires = height
            .checked_add(512)
            .ok_or("governance window overflow")?
            .min(authority.epoch.epoch_end_height);
        if !authority.epoch.contains_height(height)
            || expires.checked_sub(height).is_none_or(|n| n < 128)
        {
            return Err("current frozen epoch has insufficient review window; wait for authenticated successor".into());
        }
        let spec = EthereumActivationSpec {
            schema_version: 1,
            profile_id: synergy_genesis::network::ETHEREUM_COMPATIBILITY_PROFILE_V1.into(),
            chain_id: authority.epoch.chain_id,
            network_id: authority.epoch.network_id.clone(),
            genesis_hash: ethereum_activation::genesis_hash(authority)?.into(),
            frozen_epoch: authority.epoch.epoch,
            frozen_epoch_context_root: authority.epoch.root().map_err(|e| e.to_string())?,
            install_height: height.checked_add(2).ok_or("governance window overflow")?,
            activation_height: expires
                .checked_add(ETHEREUM_ACTIVATION_HISTORY_WARMUP_BLOCKS)
                .ok_or("activation overflow")?,
            policy_sha256: synergy_aegis::AegisProtectedPrimitives
                .sha256(&bytes)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect(),
            policy_bytes: bytes,
        };
        let members = authority.registry.quorum_validators();
        let mut constitution = Constitution {
            version: 1,
            constitution_root: String::new(),
            rules: std::collections::BTreeMap::from([(
                ETHEREUM_ACTIVATION_ACTION_V1.into(),
                GovernanceRule {
                    action_kind: ETHEREUM_ACTIVATION_ACTION_V1.into(),
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
            proposal_id: format!("canary-aivm-ethereum-{}-{height}", authority.epoch.epoch),
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
        self.review(
            authority,
            ingress,
            &EthereumActivationDraft {
                spec,
                proposal,
                constitution,
            },
        )
    }
    pub(super) fn review(
        &self,
        authority: &VerifiedAuthority,
        ingress: &AuthenticatedIngress,
        draft: &EthereumActivationDraft,
    ) -> Result<Value, String> {
        let root = draft.review_root()?;
        let (height, world) = ingress
            .processing_finalized_world()?
            .ok_or("governance needs an authenticated finalized World")?;
        let record = ingress
            .finalized_record(height)?
            .ok_or("governance finalized commitment unavailable")?;
        if record.height != height
            || !authority.epoch.contains_height(height)
            || draft.proposal.created_at_height > height
            || height >= draft.proposal.expires_at_height
        {
            return Err("governance review is outside the current frozen inclusion window".into());
        }
        ethereum_activation::review_draft(authority, draft, &world)?;
        let (key_id, _) = authority.consensus_binding(&self.validator_id)?;
        if key_id != self.key_id.as_str() {
            return Err("governance signer differs from current frozen authority".into());
        }
        let frozen=authority.registry.quorum_validators().into_iter().map(|v|
            json!({"validator_id":v.validator_id,"voting_weight":v.frozen_voting_weight.to_string()})).collect::<Vec<_>>();
        Ok(
            json!({"schema":"synergy-ethereum-activation-review-v1","review_root":root,
            "finalized_height":height,"finalized_block_id":record.block_id,"validator_id":self.validator_id,
            "key_id":key_id,"draft":draft,"frozen_validators":frozen}),
        )
    }
    pub(super) fn approve(
        &mut self,
        authority: &VerifiedAuthority,
        ingress: &AuthenticatedIngress,
        draft: &EthereumActivationDraft,
        review_root: &str,
    ) -> Result<Value, String> {
        let reviewed = self.review(authority, ingress, draft)?;
        if reviewed["review_root"] != review_root {
            return Err("exact native governance review changed".into());
        }
        // One bounded active reservation, never a growing approval archive.
        // Only a strictly later frozen epoch after the original signed expiry
        // may replace it. A crash may complete only the exact reserved draft.
        let name = "ethereum-initial.json";
        let reserve = || Reservation {
            schema_version: 1,
            review_root: review_root.into(),
            draft: draft.clone(),
            vote: None,
        };
        let mut record = if self.store.exists(&name).map_err(|e| e.to_string())? {
            let bytes = self.store.read_bounded(&name).map_err(|e| e.to_string())?;
            let r: Reservation = serde_json::from_slice(&bytes)
                .map_err(|_| "invalid durable governance reservation")?;
            if r.schema_version != 1 || r.review_root != r.draft.review_root()? {
                return Err("durable governance reservation is corrupt".into());
            }
            if r.review_root != review_root || r.draft != *draft {
                if r.draft.spec.genesis_hash != draft.spec.genesis_hash
                    || r.draft.spec.frozen_epoch >= draft.spec.frozen_epoch
                    || reviewed["finalized_height"]
                        .as_u64()
                        .is_none_or(|h| h <= r.draft.proposal.expires_at_height)
                {
                    return Err(
                        "validator already reserved a different still-valid amendment".into(),
                    );
                }
                let replacement = reserve();
                self.store
                    .write_atomic(
                        &name,
                        &serde_json::to_vec(&replacement).map_err(|e| e.to_string())?,
                    )
                    .map_err(|e| e.to_string())?;
                replacement
            } else {
                r
            }
        } else {
            let r = reserve();
            self.store
                .write_atomic(&name, &serde_json::to_vec(&r).map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())?;
            r
        };
        if let Some(vote) = record.vote.as_ref() {
            authority.verify(vote)?;
            if vote.authority_id != self.validator_id
                || vote.key_id != self.key_id.as_str()
                || vote.proposal_root != draft.proposal.proposal_root
                || vote.choice != VoteChoice::Approve
            {
                return Err("durable governance approval differs from exact reservation".into());
            }
            self.pending_recovery = None;
            return Ok(
                json!({"schema":"synergy-ethereum-activation-approval-v1","review_root":review_root,"vote":vote}),
            );
        }
        // Shape validation requires a nonempty signature; this placeholder is
        // used only while constructing the existing signature-free transcript.
        self.pending_recovery = Some((
            draft.clone(),
            review_root.into(),
            Instant::now() + Duration::from_secs(5),
        ));
        let mut vote = GovernanceVote {
            proposal_root: draft.proposal.proposal_root.clone(),
            authority_id: self.validator_id.clone(),
            key_id: self.key_id.as_str().into(),
            choice: VoteChoice::Approve,
            signature: vec![0],
        };
        let transcript = vote.signing_bytes()?;
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
                &transcript,
            )
            .map_err(|e| format!("native governance approval failed: {e}"))?
            .bytes;
        authority.verify(&vote)?;
        record.vote = Some(vote.clone());
        self.store
            .write_atomic(
                &name,
                &serde_json::to_vec(&record).map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())?;
        self.pending_recovery = None;
        Ok(
            json!({"schema":"synergy-ethereum-activation-approval-v1","review_root":review_root,"vote":vote}),
        )
    }
    pub(super) fn assemble(
        &self,
        authority: &VerifiedAuthority,
        ingress: &AuthenticatedIngress,
        draft: &EthereumActivationDraft,
        review_root: &str,
        votes: Vec<GovernanceVote>,
    ) -> Result<Value, String> {
        if self.review(authority, ingress, draft)?["review_root"] != review_root {
            return Err("governance review changed".into());
        }
        let execution = draft.assemble(votes, authority)?;
        // Independently enforces actual frozen count AND voting weight,
        // regardless of the supplied Constitution's claimed threshold.
        ethereum_activation::authorize_request(authority, &execution)?;
        let bytes = serde_json::to_vec(&execution).map_err(|e| e.to_string())?;
        let gas = 75_000u64
            .checked_add(bytes.len() as u64)
            .ok_or("governance gas overflow")?;
        Ok(
            json!({"schema":"synergy-ethereum-activation-execution-v1","review_root":review_root,
            "execution":execution,"gas_limit":gas,"maximum_fee_nwei":(u128::from(gas)*40).to_string(),
            "fee_authority":"separate-identity-bound-mldsa87-account-v1"}),
        )
    }
    /// Read the original durable signature after a lost reply/restart. This
    /// never opens a new reservation or signs, even after the window expires.
    pub(super) fn approval_status(
        &self,
        authority: &VerifiedAuthority,
        draft: &EthereumActivationDraft,
        review_root: &str,
    ) -> Result<Value, String> {
        if draft.review_root()? != review_root
            || draft.spec.genesis_hash != ethereum_activation::genesis_hash(authority)?
            || draft.spec.chain_id != authority.epoch.chain_id
            || draft.spec.network_id != authority.epoch.network_id
        {
            return Err("approval lookup differs from authenticated original scope".into());
        }
        let name = "ethereum-initial.json";
        if !self.store.exists(name).map_err(|e| e.to_string())? {
            return Err("original native approval reservation is absent".into());
        }
        let record: Reservation =
            serde_json::from_slice(&self.store.read_bounded(name).map_err(|e| e.to_string())?)
                .map_err(|_| "invalid original approval")?;
        if record.schema_version != 1 || record.review_root != review_root || record.draft != *draft
        {
            return Err("original native approval reservation differs".into());
        }
        let vote = record
            .vote
            .ok_or("original approval was reserved but its signature is not durably available")?;
        let frozen = authority
            .authenticated_history_ref_at(draft.spec.install_height)
            .ok_or("original frozen authority unavailable")?;
        if vote.authority_id != self.validator_id
            || vote.proposal_root != draft.proposal.proposal_root
            || vote.choice != VoteChoice::Approve
        {
            return Err("original native approval signer differs".into());
        }
        frozen.verify(&vote)?;
        Ok(
            json!({"schema":"synergy-ethereum-activation-approval-v1","review_root":review_root,"vote":vote}),
        )
    }
}
