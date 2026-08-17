use super::certificates::{
    BlockVote, CertifiedCandidateSubject, ConsensusObjectContext, ConsensusSignatureVerifier,
    QuorumCertificateReference, SimplifiedQuorumCertificate, SimplifiedTimeoutCertificate,
    TimeoutVote, POSY_SIMPLIFIED_BLOCK_VOTE_DOMAIN, POSY_SIMPLIFIED_PROPOSAL_DOMAIN,
    POSY_SIMPLIFIED_TIMEOUT_VOTE_DOMAIN,
};
use super::schedule::SimplifiedEpochContext;
use super::VerifiedSimplifiedEpochTransition;
use super::{ReliableDeliveryState, SimplifiedConsensusMetrics, SimplifiedMetricKind};
use crate::consensus::signing_authority::{
    ConsensusSigningAuthorization, ConsensusSigningPhase, DurableConsensusSigningAuthority,
    SafetyHaltIncident, SafetyHaltKind,
};
use crate::crypto::aegis_pqvm::AegisPqvmSigner;
use crate::synergy_types::{
    AegisPqKeyId, AegisPqSignature, BlockId, CanonicalSerialize, Hash, Height, Round, ValidatorId,
    ValidatorSet,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Instant;
use std::time::{SystemTime, UNIX_EPOCH};

pub const POSY_SIMPLIFIED_STATE_FORMAT: &str = "synergy-posy-simplified-state-v1";
pub const POSY_SIMPLIFIED_STATE_SYNC_FORMAT: &str = "synergy-posy-simplified-state-sync-v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SimplifiedProposal {
    pub context: ConsensusObjectContext,
    pub proposer_id: ValidatorId,
    pub block_id: BlockId,
    pub parent_block_id: BlockId,
    pub parent_qc: QuorumCertificateReference,
    pub takeover_tc_id: Option<Hash>,
    /// Commits the BOC/reveal/manifest/protected execution validation result.
    /// The simplified finality path does not weaken the v2.2 execution boundary.
    pub protected_execution_root: Hash,
    pub proposer_key_id: AegisPqKeyId,
    pub proposer_signature: AegisPqSignature,
}

#[derive(Debug, Clone, Serialize)]
struct SimplifiedProposalSigningPayload<'a> {
    context: &'a ConsensusObjectContext,
    proposer_id: &'a ValidatorId,
    block_id: &'a BlockId,
    parent_block_id: &'a BlockId,
    parent_qc: &'a QuorumCertificateReference,
    takeover_tc_id: Option<Hash>,
    protected_execution_root: Hash,
    proposer_key_id: &'a AegisPqKeyId,
}

impl SimplifiedProposal {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, String> {
        serde_json::to_vec(&SimplifiedProposalSigningPayload {
            context: &self.context,
            proposer_id: &self.proposer_id,
            block_id: &self.block_id,
            parent_block_id: &self.parent_block_id,
            parent_qc: &self.parent_qc,
            takeover_tc_id: self.takeover_tc_id,
            protected_execution_root: self.protected_execution_root,
            proposer_key_id: &self.proposer_key_id,
        })
        .map_err(|error| format!("serialize simplified proposal transcript: {error}"))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LastVoteRecord {
    pub height: Height,
    pub round: Round,
    pub candidate: CertifiedCandidateSubject,
    pub transcript_root: Hash,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LeaseTakeoverState {
    pub lease_index: u64,
    pub effective_height: Height,
    pub takeover_offset: u64,
    pub certificates: Vec<SimplifiedTimeoutCertificate>,
}

impl LeaseTakeoverState {
    pub fn latest_tc_id(&self) -> Result<Option<Hash>, String> {
        self.certificates
            .last()
            .map(SimplifiedTimeoutCertificate::id)
            .transpose()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FinalizedBlockRecord {
    pub height: Height,
    pub block_id: BlockId,
    pub qc_id: Hash,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SimplifiedSafetyState {
    pub state_version: u32,
    pub epoch_context_root: Hash,
    pub anchor_qc: QuorumCertificateReference,
    pub highest_qc: QuorumCertificateReference,
    pub locked_qc: Option<QuorumCertificateReference>,
    pub last_vote: Option<LastVoteRecord>,
    /// Local authenticated proposal-delivery evidence for the active slot.
    /// It is persisted for crash safety but deliberately excluded from the
    /// replica authority root because proof subsets and ML-DSA bytes may vary.
    #[serde(default)]
    pub reliable_delivery: Option<ReliableDeliveryState>,
    pub takeover: Option<LeaseTakeoverState>,
    pub finalized: FinalizedBlockRecord,
    /// Fully verified previous-epoch three-QC tail.  Empty for the one-time
    /// v2 boundary and synthetic contexts.  At a v3-to-v3 transition this
    /// retains the two certified-but-not-yet-finalized tail blocks so new
    /// epoch QCs can continue (rather than reset) three-chain finality.
    #[serde(default)]
    pub epoch_transition_tail_qcs: Vec<SimplifiedQuorumCertificate>,
    pub certified_qcs: BTreeMap<u64, SimplifiedQuorumCertificate>,
    /// Complete verified timeout evidence retained for deterministic state
    /// sync. The active `takeover` is a compact pointer into this evidence;
    /// old TCs remain available to prove historic proposer authority.
    pub certified_tcs: BTreeMap<u64, Vec<SimplifiedTimeoutCertificate>>,
    pub safety_halt: Option<SafetyHaltIncident>,
}

impl SimplifiedSafetyState {
    pub fn new(
        epoch_context: &SimplifiedEpochContext,
        anchor_qc: QuorumCertificateReference,
    ) -> Result<Self, String> {
        epoch_context.validate()?;
        if epoch_context.v3_transition_anchor.is_some() {
            return Err(
                "v3-to-v3 safety state requires a verified durable epoch-transition proof"
                    .to_string(),
            );
        }
        anchor_qc.validate()?;
        if anchor_qc.height.0.checked_add(1) != Some(epoch_context.epoch_start_height.0) {
            return Err("simplified epoch anchor must certify the preceding height".to_string());
        }
        if let Some(expected) = &epoch_context.v2_boundary_anchor {
            if anchor_qc.height != expected.height
                || anchor_qc.block_id != expected.block_id
                || anchor_qc.qc_id != expected.qc_finality_context_root
            {
                return Err(
                    "simplified state anchor does not match the exact v2 boundary QC".to_string(),
                );
            }
        }
        Ok(Self {
            state_version: 1,
            epoch_context_root: epoch_context.root()?,
            highest_qc: anchor_qc.clone(),
            locked_qc: None,
            last_vote: None,
            reliable_delivery: None,
            takeover: None,
            finalized: FinalizedBlockRecord {
                height: anchor_qc.height,
                block_id: anchor_qc.block_id.clone(),
                qc_id: anchor_qc.qc_id,
            },
            anchor_qc,
            epoch_transition_tail_qcs: Vec::new(),
            certified_qcs: BTreeMap::new(),
            certified_tcs: BTreeMap::new(),
            safety_halt: None,
        })
    }

    /// Initializes a new v3 epoch without conflating its certified parent and
    /// finalized seed.  The verified proof is intentionally required as a
    /// capability; callers cannot construct this state from a single QC
    /// reference or an unsigned validator list.
    pub fn new_from_verified_v3_transition(
        epoch_context: &SimplifiedEpochContext,
        transition: &VerifiedSimplifiedEpochTransition,
    ) -> Result<Self, String> {
        epoch_context.validate()?;
        if epoch_context != transition.next_epoch_context() {
            return Err("verified transition does not derive this epoch context".to_string());
        }
        let anchor = epoch_context
            .v3_transition_anchor
            .as_ref()
            .ok_or_else(|| "verified v3 transition context has no transition anchor".to_string())?;
        let certified_parent = transition.certified_parent().clone();
        let finalized_seed = transition.finalized_seed().clone();
        if certified_parent.height != anchor.certified_parent_height
            || certified_parent.block_id != anchor.certified_parent_block_id
            || certified_parent.qc_id != anchor.certified_parent_qc_id
            || finalized_seed.height != anchor.finalized_seed_height
            || finalized_seed.block_id != anchor.finalized_seed_block_id
            || finalized_seed.qc_id != anchor.finalized_seed_qc_id
            || transition.transition_tail().len() != 3
        {
            return Err("verified transition pointers do not match the epoch anchor".to_string());
        }
        let locked_qc = transition
            .transition_tail()
            .get(1)
            .ok_or_else(|| "verified transition lacks its parent lock".to_string())?
            .reference()?;
        let state = Self {
            state_version: 1,
            epoch_context_root: epoch_context.root()?,
            anchor_qc: certified_parent.clone(),
            highest_qc: certified_parent,
            locked_qc: Some(locked_qc),
            last_vote: None,
            reliable_delivery: None,
            takeover: None,
            finalized: FinalizedBlockRecord {
                height: finalized_seed.height,
                block_id: finalized_seed.block_id,
                qc_id: finalized_seed.qc_id,
            },
            epoch_transition_tail_qcs: transition.transition_tail().to_vec(),
            certified_qcs: BTreeMap::new(),
            certified_tcs: BTreeMap::new(),
            safety_halt: None,
        };
        state.validate(epoch_context)?;
        Ok(state)
    }

    pub fn validate(&self, epoch_context: &SimplifiedEpochContext) -> Result<(), String> {
        epoch_context.validate()?;
        if self.state_version != 1 || self.epoch_context_root != epoch_context.root()? {
            return Err("simplified safety state does not match the activated epoch".to_string());
        }
        self.anchor_qc.validate()?;
        if let Some(expected) = &epoch_context.v2_boundary_anchor {
            if self.anchor_qc.height != expected.height
                || self.anchor_qc.block_id != expected.block_id
                || self.anchor_qc.qc_id != expected.qc_finality_context_root
            {
                return Err(
                    "persisted simplified state substituted another v2 boundary anchor".to_string(),
                );
            }
        }
        let minimum_finalized_height = if let Some(expected) = &epoch_context.v3_transition_anchor {
            if self.anchor_qc.height != expected.certified_parent_height
                || self.anchor_qc.block_id != expected.certified_parent_block_id
                || self.anchor_qc.qc_id != expected.certified_parent_qc_id
                || self.epoch_transition_tail_qcs.len() != 3
            {
                return Err(
                    "persisted state substituted the v3 transition certified parent or proof tail"
                        .to_string(),
                );
            }
            for (index, certificate) in self.epoch_transition_tail_qcs.iter().enumerate() {
                let expected_height = expected
                    .finalized_seed_height
                    .0
                    .checked_add(index as u64)
                    .ok_or_else(|| "transition-tail height overflow".to_string())?;
                if certificate.context.epoch != expected.previous_epoch
                    || certificate.context.epoch_context_root
                        != expected.previous_epoch_context_root
                    || certificate.context.height != Height(expected_height)
                    || (index > 0
                        && certificate.parent_qc
                            != self.epoch_transition_tail_qcs[index - 1].reference()?)
                {
                    return Err(
                        "persisted v3 transition tail is not the exact consecutive prior-epoch proof"
                            .to_string(),
                    );
                }
            }
            let finalized = self.epoch_transition_tail_qcs[0].reference()?;
            let certified = self.epoch_transition_tail_qcs[2].reference()?;
            if finalized.height != expected.finalized_seed_height
                || finalized.block_id != expected.finalized_seed_block_id
                || finalized.qc_id != expected.finalized_seed_qc_id
                || certified != self.anchor_qc
            {
                return Err("persisted v3 transition proof pointers do not match".to_string());
            }
            expected.finalized_seed_height.0
        } else {
            if !self.epoch_transition_tail_qcs.is_empty() {
                return Err("non-transition state carries a v3 transition proof tail".to_string());
            }
            self.anchor_qc.height.0
        };
        self.highest_qc.validate()?;
        if self.highest_qc.height.0 < self.anchor_qc.height.0
            || self.finalized.height.0 < minimum_finalized_height
            || self.finalized.height.0 > self.highest_qc.height.0
        {
            return Err("simplified safety pointers are not monotonic".to_string());
        }
        if let Some(lock) = &self.locked_qc {
            lock.validate()?;
            if lock.height.0 > self.highest_qc.height.0 {
                return Err("locked QC is higher than highest QC".to_string());
            }
        }
        if let Some(last_vote) = &self.last_vote {
            if last_vote.height.0 == 0
                || last_vote.candidate.context.height != last_vote.height
                || last_vote.candidate.id()?.is_zero()
                || last_vote.transcript_root.is_zero()
            {
                return Err("invalid durable last-vote record".to_string());
            }
        }
        if let Some(delivery) = &self.reliable_delivery {
            delivery.validate(epoch_context)?;
            let next_height = self.next_height()?;
            let (round, _) = self.takeover_for_height(epoch_context, next_height)?;
            if delivery.context.height != next_height || delivery.context.round.0 != round {
                return Err(
                    "persisted reliable-delivery state is not for the active slot".to_string(),
                );
            }
        }
        for (height, qc) in &self.certified_qcs {
            if *height != qc.context.height.0 || qc.id()?.is_zero() {
                return Err("certified-QC index is inconsistent".to_string());
            }
        }
        // TC rounds are lease-wide takeover offsets, not per-height counters.
        // A replacement may certify one or more blocks and then itself time
        // out later in the same lease. In that case the first TC stored under
        // the later height legitimately has round > 0 and names the TC stored
        // under an earlier height. Reconstruct one predecessor chain per
        // immutable lease instead of incorrectly resetting at every height.
        let mut last_tc_by_lease = BTreeMap::<u64, (u64, Hash)>::new();
        for (height, certificates) in &self.certified_tcs {
            if certificates.is_empty() {
                return Err("certified-TC index contains an empty chain".to_string());
            }
            let lease_index = epoch_context.lease_index(Height(*height))?;
            for tc in certificates {
                let (expected_round, expected_previous) = last_tc_by_lease
                    .get(&lease_index)
                    .map(|(round, id)| {
                        round
                            .checked_add(1)
                            .map(|next_round| (next_round, Some(*id)))
                            .ok_or_else(|| "certified-TC round overflow".to_string())
                    })
                    .transpose()?
                    .unwrap_or((0, None));
                if tc.context.height.0 != *height
                    || tc.lease_index != lease_index
                    || tc.context.round.0 != expected_round
                    || tc.previous_tc_id != expected_previous
                {
                    return Err("certified-TC index is inconsistent".to_string());
                }
                last_tc_by_lease.insert(lease_index, (expected_round, tc.id()?));
            }
        }
        if let Some(takeover) = &self.takeover {
            if takeover.takeover_offset == 0
                || takeover.certificates.len() as u64 != takeover.takeover_offset
                || takeover.certificates.is_empty()
            {
                return Err("invalid durable lease-takeover state".to_string());
            }
            for (expected_round, tc) in takeover.certificates.iter().enumerate() {
                if tc.lease_index != takeover.lease_index
                    || tc.context.round.0 != expected_round as u64
                    || (expected_round == 0) != tc.previous_tc_id.is_none()
                {
                    return Err("durable TC chain is not sequential".to_string());
                }
                if expected_round > 0
                    && tc.previous_tc_id != Some(takeover.certificates[expected_round - 1].id()?)
                {
                    return Err("durable TC chain predecessor mismatch".to_string());
                }
            }
        }
        if let Some(incident) = &self.safety_halt {
            incident.validate()?;
        }
        Ok(())
    }

    pub fn next_height(&self) -> Result<Height, String> {
        self.highest_qc
            .height
            .0
            .checked_add(1)
            .map(Height)
            .ok_or_else(|| "next consensus height overflow".to_string())
    }

    /// Canonical consensus-authority view shared by replicas that learned
    /// different valid signature subsets for the same QC/TC subjects.
    ///
    /// The persisted envelope separately hashes the complete local evidence
    /// for corruption detection. That local integrity hash is intentionally
    /// not an all-node agreement root: ML-DSA proof bytes and valid 4-of-5
    /// subsets may differ. This root excludes those proof bundles and local
    /// signer/SafetyHalt records while retaining every authority pointer.
    pub fn consensus_authority_root(&self) -> Result<Hash, String> {
        let certified_qc_subjects = self
            .certified_qcs
            .iter()
            .map(|(height, certificate)| Ok((*height, certificate.id()?)))
            .collect::<Result<BTreeMap<_, _>, String>>()?;
        let certified_tc_subjects = self
            .certified_tcs
            .iter()
            .map(|(height, certificates)| {
                Ok((
                    *height,
                    certificates
                        .iter()
                        .map(SimplifiedTimeoutCertificate::id)
                        .collect::<Result<Vec<_>, _>>()?,
                ))
            })
            .collect::<Result<BTreeMap<_, _>, String>>()?;
        let takeover = self
            .takeover
            .as_ref()
            .map(|state| {
                Ok::<ConsensusAuthorityTakeover, String>(ConsensusAuthorityTakeover {
                    lease_index: state.lease_index,
                    effective_height: state.effective_height,
                    takeover_offset: state.takeover_offset,
                    certificate_ids: state
                        .certificates
                        .iter()
                        .map(SimplifiedTimeoutCertificate::id)
                        .collect::<Result<Vec<_>, _>>()?,
                })
            })
            .transpose()?;
        let view = ConsensusAuthorityView {
            state_version: self.state_version,
            epoch_context_root: self.epoch_context_root,
            anchor_qc: self.anchor_qc.clone(),
            highest_qc: self.highest_qc.clone(),
            locked_qc: self.locked_qc.clone(),
            takeover,
            finalized: self.finalized.clone(),
            certified_qc_subjects,
            certified_tc_subjects,
        };
        Ok(Hash::from_domain_bytes(
            "SYNERGY_POSY_SIMPLIFIED_AUTHORITY_STATE_V1",
            &view.canonical_bytes()?,
        ))
    }

    pub fn takeover_for_height(
        &self,
        epoch_context: &SimplifiedEpochContext,
        height: Height,
    ) -> Result<(u64, Option<Hash>), String> {
        let lease_index = epoch_context.lease_index(height)?;
        match &self.takeover {
            Some(takeover)
                if takeover.lease_index == lease_index
                    && height.0 >= takeover.effective_height.0 =>
            {
                Ok((takeover.takeover_offset, takeover.latest_tc_id()?))
            }
            _ => Ok((0, None)),
        }
    }

    fn known_qc(&self, reference: &QuorumCertificateReference) -> Result<bool, String> {
        if &self.anchor_qc == reference {
            return Ok(true);
        }
        self.certified_qcs
            .get(&reference.height.0)
            .map(|qc| qc.reference().map(|known| known == *reference))
            .transpose()
            .map(Option::unwrap_or_default)
    }

    fn certificate_at(&self, height: Height) -> Option<&SimplifiedQuorumCertificate> {
        self.certified_qcs.get(&height.0).or_else(|| {
            self.epoch_transition_tail_qcs
                .iter()
                .find(|certificate| certificate.context.height == height)
        })
    }

    fn proposal_extends_lock(
        &self,
        parent_qc: &QuorumCertificateReference,
    ) -> Result<bool, String> {
        let Some(lock) = &self.locked_qc else {
            return Ok(true);
        };
        if parent_qc == lock {
            return Ok(true);
        }
        let mut cursor = parent_qc.clone();
        while cursor.height.0 > lock.height.0 {
            let Some(qc) = self.certificate_at(cursor.height) else {
                break;
            };
            if qc.reference()? != cursor {
                break;
            }
            cursor = qc.parent_qc.clone();
            if &cursor == lock {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ConsensusAuthorityTakeover {
    lease_index: u64,
    effective_height: Height,
    takeover_offset: u64,
    certificate_ids: Vec<Hash>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ConsensusAuthorityView {
    state_version: u32,
    epoch_context_root: Hash,
    anchor_qc: QuorumCertificateReference,
    highest_qc: QuorumCertificateReference,
    locked_qc: Option<QuorumCertificateReference>,
    takeover: Option<ConsensusAuthorityTakeover>,
    finalized: FinalizedBlockRecord,
    certified_qc_subjects: BTreeMap<u64, Hash>,
    certified_tc_subjects: BTreeMap<u64, Vec<Hash>>,
}

/// Peer-transferable consensus evidence. Local last-vote and SafetyHalt state
/// are deliberately excluded: those records are node-local safety authority
/// and may never be overwritten by a peer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SimplifiedStateSyncBundle {
    pub format: String,
    pub epoch_context: SimplifiedEpochContext,
    pub anchor_qc: QuorumCertificateReference,
    pub certified_qcs: Vec<SimplifiedQuorumCertificate>,
    pub certified_tcs: BTreeMap<u64, Vec<SimplifiedTimeoutCertificate>>,
    pub claimed_finalized: FinalizedBlockRecord,
}

impl SimplifiedStateSyncBundle {
    pub fn from_verified_state(
        epoch_context: &SimplifiedEpochContext,
        state: &SimplifiedSafetyState,
    ) -> Result<Self, String> {
        state.validate(epoch_context)?;
        Ok(Self {
            format: POSY_SIMPLIFIED_STATE_SYNC_FORMAT.to_string(),
            epoch_context: epoch_context.clone(),
            anchor_qc: state.anchor_qc.clone(),
            certified_qcs: state.certified_qcs.values().cloned().collect(),
            certified_tcs: state.certified_tcs.clone(),
            claimed_finalized: state.finalized.clone(),
        })
    }

    /// Reconstructs safety pointers from signatures and ancestry instead of
    /// trusting peer-supplied cached `highest`, `locked`, or quorum fields.
    pub fn verify_and_reconstruct<V: ConsensusSignatureVerifier>(
        &self,
        expected_epoch_context: &SimplifiedEpochContext,
        validator_set: &ValidatorSet,
        expected_anchor_qc: &QuorumCertificateReference,
        verifier: &V,
        local_last_vote: Option<LastVoteRecord>,
        local_safety_halt: Option<SafetyHaltIncident>,
    ) -> Result<SimplifiedSafetyState, String> {
        self.validate_pinned_envelope(expected_epoch_context, expected_anchor_qc)?;
        expected_epoch_context.validate_against(validator_set)?;
        if expected_epoch_context.v3_transition_anchor.is_some() {
            return Err(
                "v3-to-v3 state sync requires the receiver's independently verified durable transition proof"
                    .to_string(),
            );
        }
        let state = SimplifiedSafetyState::new(expected_epoch_context, expected_anchor_qc.clone())?;
        self.reconstruct_from_initial_state(
            expected_epoch_context,
            validator_set,
            verifier,
            state,
            local_last_vote,
            local_safety_halt,
        )
    }

    /// Reconstructs a later v3 epoch from the receiver's independently
    /// verified transition capability. Peer bytes cannot select membership,
    /// replace the certified parent, or promote it to finality.
    pub fn verify_and_reconstruct_from_verified_v3_transition<V: ConsensusSignatureVerifier>(
        &self,
        transition: &VerifiedSimplifiedEpochTransition,
        verifier: &V,
        local_last_vote: Option<LastVoteRecord>,
        local_safety_halt: Option<SafetyHaltIncident>,
    ) -> Result<SimplifiedSafetyState, String> {
        let epoch_context = transition.next_epoch_context();
        self.validate_pinned_envelope(epoch_context, transition.certified_parent())?;
        epoch_context.validate_against(transition.next_validator_set())?;
        let state =
            SimplifiedSafetyState::new_from_verified_v3_transition(epoch_context, transition)?;
        self.reconstruct_from_initial_state(
            epoch_context,
            transition.next_validator_set(),
            verifier,
            state,
            local_last_vote,
            local_safety_halt,
        )
    }

    fn validate_pinned_envelope(
        &self,
        expected_epoch_context: &SimplifiedEpochContext,
        expected_anchor_qc: &QuorumCertificateReference,
    ) -> Result<(), String> {
        if self.format != POSY_SIMPLIFIED_STATE_SYNC_FORMAT
            || &self.epoch_context != expected_epoch_context
            || &self.anchor_qc != expected_anchor_qc
        {
            return Err("state-sync bundle does not match the pinned epoch anchor".to_string());
        }
        Ok(())
    }

    fn reconstruct_from_initial_state<V: ConsensusSignatureVerifier>(
        &self,
        expected_epoch_context: &SimplifiedEpochContext,
        validator_set: &ValidatorSet,
        verifier: &V,
        mut state: SimplifiedSafetyState,
        local_last_vote: Option<LastVoteRecord>,
        local_safety_halt: Option<SafetyHaltIncident>,
    ) -> Result<SimplifiedSafetyState, String> {
        let mut certificates = self.certified_qcs.clone();
        certificates.sort_by_key(|certificate| certificate.context.height.0);
        if certificates
            .windows(2)
            .any(|pair| pair[0].context.height == pair[1].context.height)
        {
            return Err("state-sync bundle contains duplicate QC heights".to_string());
        }

        for certificate in certificates {
            let expected_height = state.next_height()?;
            if certificate.context.height != expected_height
                || certificate.parent_qc != state.highest_qc
            {
                return Err("state-sync QCs do not form one consecutive anchored chain".to_string());
            }
            install_state_sync_tcs_for_height(
                &mut state,
                expected_epoch_context,
                validator_set,
                verifier,
                expected_height,
                self.certified_tcs.get(&expected_height.0),
            )?;
            certificate.verify(expected_epoch_context, validator_set, verifier)?;
            let (expected_round, expected_tc_id) =
                state.takeover_for_height(expected_epoch_context, expected_height)?;
            if certificate.context.round.0 != expected_round
                || certificate.takeover_tc_id != expected_tc_id
            {
                return Err("state-sync QC lacks its sequential TC authority".to_string());
            }
            let reference = certificate.reference()?;
            state
                .certified_qcs
                .insert(expected_height.0, certificate.clone());
            state.highest_qc = reference;
            state.locked_qc = Some(certificate.parent_qc.clone());
            reconstruct_three_chain_commit(&mut state, &certificate)?;
        }

        let next_height = state.next_height()?;
        install_state_sync_tcs_for_height(
            &mut state,
            expected_epoch_context,
            validator_set,
            verifier,
            next_height,
            self.certified_tcs.get(&next_height.0),
        )?;
        let consumed_tc_heights = state
            .certified_tcs
            .keys()
            .copied()
            .collect::<std::collections::BTreeSet<_>>();
        let supplied_tc_heights = self
            .certified_tcs
            .keys()
            .copied()
            .collect::<std::collections::BTreeSet<_>>();
        if consumed_tc_heights != supplied_tc_heights {
            return Err("state-sync bundle contains out-of-chain TC evidence".to_string());
        }
        if state.finalized != self.claimed_finalized {
            return Err("state-sync claimed finalized head is not derivable".to_string());
        }
        state.last_vote = local_last_vote;
        state.safety_halt = local_safety_halt;
        state.validate(expected_epoch_context)?;
        Ok(state)
    }
}

fn install_state_sync_tcs_for_height<V: ConsensusSignatureVerifier>(
    state: &mut SimplifiedSafetyState,
    epoch_context: &SimplifiedEpochContext,
    validator_set: &ValidatorSet,
    verifier: &V,
    height: Height,
    certificates: Option<&Vec<SimplifiedTimeoutCertificate>>,
) -> Result<(), String> {
    let Some(certificates) = certificates else {
        return Ok(());
    };
    if certificates.is_empty() {
        return Err("state-sync TC chain cannot be empty".to_string());
    }
    for certificate in certificates {
        certificate.verify(epoch_context, validator_set, verifier)?;
        let (expected_round, expected_previous) =
            state.takeover_for_height(epoch_context, height)?;
        if certificate.context.height != height
            || certificate.context.round.0 != expected_round
            || certificate.previous_tc_id != expected_previous
            || certificate.highest_qc()? != state.highest_qc
        {
            return Err("state-sync TC evidence is stale or non-sequential".to_string());
        }
        let lease_index = epoch_context.lease_index(height)?;
        let mut takeover = match state.takeover.take() {
            Some(existing) if existing.lease_index == lease_index => existing,
            _ => LeaseTakeoverState {
                lease_index,
                effective_height: height,
                takeover_offset: 0,
                certificates: Vec::new(),
            },
        };
        takeover.certificates.push(certificate.clone());
        takeover.takeover_offset = takeover
            .takeover_offset
            .checked_add(1)
            .ok_or_else(|| "state-sync takeover offset overflow".to_string())?;
        state.takeover = Some(takeover);
    }
    state.certified_tcs.insert(height.0, certificates.clone());
    Ok(())
}

fn reconstruct_three_chain_commit(
    state: &mut SimplifiedSafetyState,
    newest: &SimplifiedQuorumCertificate,
) -> Result<(), String> {
    let Some(parent) = state.certificate_at(newest.parent_qc.height) else {
        return Ok(());
    };
    if parent.reference()? != newest.parent_qc {
        return Err("state-sync newest QC does not extend its certified parent".to_string());
    }
    let Some(grandparent) = state.certificate_at(parent.parent_qc.height) else {
        return Ok(());
    };
    if grandparent.reference()? != parent.parent_qc
        || grandparent.context.height.0.checked_add(1) != Some(parent.context.height.0)
        || parent.context.height.0.checked_add(1) != Some(newest.context.height.0)
    {
        return Err("state-sync certificates do not form a consecutive three-chain".to_string());
    }
    if grandparent.context.height.0 > state.finalized.height.0 {
        state.finalized = FinalizedBlockRecord {
            height: grandparent.context.height,
            block_id: grandparent.block_id.clone(),
            qc_id: grandparent.id()?,
        };
    }
    Ok(())
}

#[derive(Debug, Clone)]
pub struct DurableSimplifiedPosyStore {
    path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct PersistedSafetyState {
    format: String,
    state: SimplifiedSafetyState,
    state_root: Hash,
}

impl DurableSimplifiedPosyStore {
    pub fn at_path(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn initialize(
        &self,
        epoch_context: &SimplifiedEpochContext,
        anchor_qc: QuorumCertificateReference,
    ) -> Result<SimplifiedSafetyState, String> {
        if epoch_context.v3_transition_anchor.is_some() {
            return Err(
                "v3-to-v3 restart requires initialize_from_verified_v3_transition".to_string(),
            );
        }
        if self.path.exists() {
            let state = self.load(epoch_context)?;
            if state.anchor_qc != anchor_qc {
                return Err(
                    "simplified restart supplied a different epoch anchor than durable state"
                        .to_string(),
                );
            }
            return Ok(state);
        }
        let state = SimplifiedSafetyState::new(epoch_context, anchor_qc)?;
        self.persist(epoch_context, &state)?;
        Ok(state)
    }

    pub fn initialize_from_verified_v3_transition(
        &self,
        transition: &VerifiedSimplifiedEpochTransition,
    ) -> Result<SimplifiedSafetyState, String> {
        let epoch_context = transition.next_epoch_context();
        if self.path.exists() {
            let state = self.load(epoch_context)?;
            if state.anchor_qc != *transition.certified_parent()
                || state.epoch_transition_tail_qcs != transition.transition_tail()
            {
                return Err(
                    "simplified restart supplied a different verified epoch transition".to_string(),
                );
            }
            return Ok(state);
        }
        let state =
            SimplifiedSafetyState::new_from_verified_v3_transition(epoch_context, transition)?;
        self.persist(epoch_context, &state)?;
        Ok(state)
    }

    pub fn load(
        &self,
        epoch_context: &SimplifiedEpochContext,
    ) -> Result<SimplifiedSafetyState, String> {
        let bytes = fs::read(&self.path).map_err(|error| {
            format!(
                "read simplified consensus state {}: {error}",
                self.path.display()
            )
        })?;
        let envelope: PersistedSafetyState = serde_json::from_slice(&bytes).map_err(|error| {
            format!(
                "parse simplified consensus state {}: {error}",
                self.path.display()
            )
        })?;
        if envelope.format != POSY_SIMPLIFIED_STATE_FORMAT {
            return Err(format!(
                "unsupported simplified state format {}",
                envelope.format
            ));
        }
        envelope.state.validate(epoch_context)?;
        let expected_root = state_root(&envelope.state)?;
        if envelope.state_root != expected_root {
            return Err("simplified consensus state root mismatch".to_string());
        }
        Ok(envelope.state)
    }

    pub fn persist(
        &self,
        epoch_context: &SimplifiedEpochContext,
        state: &SimplifiedSafetyState,
    ) -> Result<(), String> {
        state.validate(epoch_context)?;
        let envelope = PersistedSafetyState {
            format: POSY_SIMPLIFIED_STATE_FORMAT.to_string(),
            state: state.clone(),
            state_root: state_root(state)?,
        };
        let parent = self
            .path
            .parent()
            .ok_or_else(|| "simplified state path has no parent".to_string())?;
        fs::create_dir_all(parent).map_err(|error| {
            format!(
                "create simplified state directory {}: {error}",
                parent.display()
            )
        })?;
        let file_name = self
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| "simplified state path has no valid file name".to_string())?;
        let temp_path = parent.join(format!(
            ".{file_name}.tmp-{}-{}",
            std::process::id(),
            current_unix_nanos()
        ));
        let bytes = serde_json::to_vec_pretty(&envelope)
            .map_err(|error| format!("serialize simplified consensus state: {error}"))?;
        let write_result = (|| -> Result<(), String> {
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&temp_path)
                .map_err(|error| {
                    format!("create temporary state {}: {error}", temp_path.display())
                })?;
            file.write_all(&bytes).map_err(|error| {
                format!("write temporary state {}: {error}", temp_path.display())
            })?;
            file.sync_all().map_err(|error| {
                format!("fsync temporary state {}: {error}", temp_path.display())
            })?;
            fs::rename(&temp_path, &self.path).map_err(|error| {
                format!("atomically replace state {}: {error}", self.path.display())
            })?;
            OpenOptions::new()
                .read(true)
                .open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(|error| format!("fsync state directory {}: {error}", parent.display()))
        })();
        if write_result.is_err() {
            let _ = fs::remove_file(&temp_path);
        }
        write_result
    }
}

pub struct SimplifiedConsensusStateMachine {
    epoch_context: SimplifiedEpochContext,
    validator_set: ValidatorSet,
    /// Receiver-owned verified transition authority. This is never replaced
    /// by peer state-sync bytes.
    epoch_transition: Option<VerifiedSimplifiedEpochTransition>,
    store: DurableSimplifiedPosyStore,
    state: SimplifiedSafetyState,
    metrics: SimplifiedConsensusMetrics,
}

impl SimplifiedConsensusStateMachine {
    pub fn open(
        epoch_context: SimplifiedEpochContext,
        validator_set: ValidatorSet,
        store: DurableSimplifiedPosyStore,
        anchor_qc: QuorumCertificateReference,
    ) -> Result<Self, String> {
        let restart = store.path().exists();
        let opened_at = Instant::now();
        epoch_context.validate_against(&validator_set)?;
        let state = store.initialize(&epoch_context, anchor_qc)?;
        state.validate(&epoch_context)?;
        let mut machine = Self {
            epoch_context,
            validator_set,
            epoch_transition: None,
            store,
            state,
            metrics: SimplifiedConsensusMetrics::default(),
        };
        if restart {
            machine.metrics.record_duration(
                SimplifiedMetricKind::RestartRejoinMicros,
                opened_at.elapsed(),
            );
        }
        Ok(machine)
    }

    pub fn open_from_verified_v3_transition(
        transition: &VerifiedSimplifiedEpochTransition,
        store: DurableSimplifiedPosyStore,
    ) -> Result<Self, String> {
        let restart = store.path().exists();
        let opened_at = Instant::now();
        let epoch_context = transition.next_epoch_context().clone();
        let validator_set = transition.next_validator_set().clone();
        epoch_context.validate_against(&validator_set)?;
        let state = store.initialize_from_verified_v3_transition(transition)?;
        state.validate(&epoch_context)?;
        let mut machine = Self {
            epoch_context,
            validator_set,
            epoch_transition: Some(transition.clone()),
            store,
            state,
            metrics: SimplifiedConsensusMetrics::default(),
        };
        if restart {
            machine.metrics.record_duration(
                SimplifiedMetricKind::RestartRejoinMicros,
                opened_at.elapsed(),
            );
        }
        Ok(machine)
    }

    pub fn state(&self) -> &SimplifiedSafetyState {
        &self.state
    }

    /// Reconciles the receiver-owned safety state with its fsynced signing
    /// journal before the driver accepts network traffic or releases another
    /// signature.
    ///
    /// The journal is written before `last_vote`. A crash in that narrow
    /// interval is recoverable only when the already-durable reliable-delivery
    /// record identifies the exact journaled candidate and slot. Every other
    /// mismatch is treated as a local durable-authority inconsistency and
    /// enters irreversible SafetyHalt.
    pub fn reconcile_local_signing_journal(
        &mut self,
        validator_id: &ValidatorId,
        key_id: &AegisPqKeyId,
        signing_authority: &DurableConsensusSigningAuthority,
    ) -> Result<(), String> {
        self.require_active_signer(validator_id, key_id)?;
        if let Some(incident) = &self.state.safety_halt {
            signing_authority.enter_safety_halt(incident)?;
            return Err(
                "CONSENSUS_SAFETY_HALT: durable safety state disables driver startup".to_string(),
            );
        }
        signing_authority.require_signing_allowed()?;
        let epoch_context_root = self.epoch_context.root()?;
        let mut vote_authorizations = signing_authority
            .recorded_authorizations()?
            .into_iter()
            .filter(|authorization| {
                authorization.chain_id == self.epoch_context.chain_id
                    && authorization.network_id == self.epoch_context.network_id
                    && authorization.protocol_version == self.epoch_context.protocol_version
                    && authorization.epoch == self.epoch_context.epoch
                    && authorization.height_context_root == epoch_context_root
                    && &authorization.validator_id == validator_id
                    && &authorization.key_id == key_id
                    && authorization.phase == ConsensusSigningPhase::Vote
            })
            .collect::<Vec<_>>();
        vote_authorizations
            .sort_by_key(|authorization| (authorization.height.0, authorization.round.0));
        let latest_authorization = vote_authorizations.last();
        let state_vote_key = self
            .state
            .last_vote
            .as_ref()
            .map(|vote| (vote.height.0, vote.round.0));
        let journal_vote_key = latest_authorization
            .map(|authorization| (authorization.height.0, authorization.round.0));

        if let (Some(last_vote), Some(authorization)) =
            (&self.state.last_vote, latest_authorization)
        {
            let expected_candidate = simplified_vote_authorization_candidate(&last_vote.candidate)?;
            if state_vote_key == journal_vote_key
                && authorization.candidate_id.as_ref() == Some(&expected_candidate)
            {
                return Ok(());
            }
        } else if self.state.last_vote.is_none() && latest_authorization.is_none() {
            return Ok(());
        }

        if let Some(authorization) = latest_authorization {
            if journal_vote_key > state_vote_key {
                if let Some(recovered) =
                    self.recover_last_vote_from_delivery(authorization, validator_id, key_id)?
                {
                    let mut staged_state = self.state.clone();
                    staged_state.last_vote = Some(recovered);
                    self.store.persist(&self.epoch_context, &staged_state)?;
                    self.state = staged_state;
                    return Ok(());
                }
            }
        }

        let height = latest_authorization
            .map(|authorization| authorization.height)
            .or_else(|| self.state.last_vote.as_ref().map(|vote| vote.height))
            .unwrap_or(self.state.next_height()?);
        let state_evidence_root = state_root(&self.state)?;
        let journal_evidence_root = latest_authorization
            .map(signing_authorization_root)
            .transpose()?
            .unwrap_or_else(|| {
                Hash::from_domain_bytes(
                    "SYNERGY_POSY_SIMPLIFIED_MISSING_SIGNING_AUTHORIZATION_V1",
                    &height.0.to_be_bytes(),
                )
            });
        let incident = SafetyHaltIncident {
            incident_version: 1,
            kind: SafetyHaltKind::SigningJournalInconsistency,
            chain_id: self.epoch_context.chain_id,
            network_id: self.epoch_context.network_id.clone(),
            protocol_version: self.epoch_context.protocol_version.clone(),
            epoch: self.epoch_context.epoch,
            height,
            context_root: epoch_context_root,
            first_evidence_root: state_evidence_root,
            second_evidence_root: journal_evidence_root,
        };
        signing_authority.enter_safety_halt(&incident)?;
        let mut staged_state = self.state.clone();
        staged_state.safety_halt = Some(incident);
        self.store.persist(&self.epoch_context, &staged_state)?;
        self.state = staged_state;
        Err("CONSENSUS_SAFETY_HALT: safety state and signing journal are inconsistent".to_string())
    }

    fn recover_last_vote_from_delivery(
        &self,
        authorization: &ConsensusSigningAuthorization,
        validator_id: &ValidatorId,
        key_id: &AegisPqKeyId,
    ) -> Result<Option<LastVoteRecord>, String> {
        let Some(delivery) = &self.state.reliable_delivery else {
            return Ok(None);
        };
        if delivery.context.height != authorization.height
            || delivery.context.round != authorization.round
        {
            return Ok(None);
        }
        let Some(candidate) = delivery.delivered_candidate.clone() else {
            return Ok(None);
        };
        if authorization.candidate_id.as_ref()
            != Some(&simplified_vote_authorization_candidate(&candidate)?)
        {
            return Ok(None);
        }
        let (round, takeover_tc_id) = self
            .state
            .takeover_for_height(&self.epoch_context, authorization.height)?;
        if round != authorization.round.0
            || authorization
                .conflict_unlock_tc_id
                .is_some_and(|unlock| Some(unlock) != takeover_tc_id)
        {
            return Ok(None);
        }
        let vote = BlockVote {
            context: delivery.context.clone(),
            block_id: candidate.block_id.clone(),
            parent_block_id: candidate.parent_block_id.clone(),
            parent_qc: candidate.parent_qc.clone(),
            takeover_tc_id,
            protected_execution_root: candidate.protected_execution_root,
            validator_id: validator_id.clone(),
            key_id: key_id.clone(),
            signature: AegisPqSignature {
                algorithm: String::new(),
                signature_bytes: Vec::new(),
            },
        };
        Ok(Some(LastVoteRecord {
            height: authorization.height,
            round: authorization.round,
            candidate,
            transcript_root: Hash::from_domain_bytes(
                POSY_SIMPLIFIED_BLOCK_VOTE_DOMAIN,
                &vote.signing_bytes()?,
            ),
        }))
    }

    /// Durably records authenticated reliable-delivery progress before any
    /// ECHO/READY statement or delivered block vote may leave the process.
    pub fn persist_reliable_delivery(
        &mut self,
        delivery: ReliableDeliveryState,
    ) -> Result<(), String> {
        delivery.validate(&self.epoch_context)?;
        let height = self.state.next_height()?;
        let (round, _) = self
            .state
            .takeover_for_height(&self.epoch_context, height)?;
        if delivery.context.height != height || delivery.context.round.0 != round {
            return Err("reliable-delivery state is not for the active slot".to_string());
        }
        let mut staged_state = self.state.clone();
        staged_state.reliable_delivery = Some(delivery);
        self.store.persist(&self.epoch_context, &staged_state)?;
        self.state = staged_state;
        Ok(())
    }

    fn clear_reliable_delivery(staged_state: &mut SimplifiedSafetyState) {
        staged_state.reliable_delivery = None;
    }

    /// Reports whether accepting this candidate QC would advance three-chain
    /// finality, without mutating or persisting safety state. Operational
    /// wiring uses this to require an atomic protected block/application sink
    /// before consensus finality can move ahead of execution durability.
    pub fn would_finalize_with_qc(
        &self,
        newest: &SimplifiedQuorumCertificate,
    ) -> Result<bool, String> {
        Ok(self.preview_finalized_with_qc(newest)?.is_some())
    }

    /// Returns the exact block record that a candidate QC would finalize.
    /// Callers use this preview to durably commit protected execution and the
    /// application database before admitting the QC into consensus state.
    pub fn preview_finalized_with_qc(
        &self,
        newest: &SimplifiedQuorumCertificate,
    ) -> Result<Option<FinalizedBlockRecord>, String> {
        let Some(parent) = self.state.certificate_at(newest.parent_qc.height) else {
            return Ok(None);
        };
        if parent.reference()? != newest.parent_qc {
            return Err("candidate QC does not extend its claimed certified parent".to_string());
        }
        let Some(grandparent) = self.state.certificate_at(parent.parent_qc.height) else {
            return Ok(None);
        };
        if grandparent.reference()? != parent.parent_qc
            || grandparent.context.height.0.checked_add(1) != Some(parent.context.height.0)
            || parent.context.height.0.checked_add(1) != Some(newest.context.height.0)
        {
            return Err("candidate QCs do not form a consecutive three-chain".to_string());
        }
        if grandparent.context.height.0 <= self.state.finalized.height.0 {
            return Ok(None);
        }
        Ok(Some(FinalizedBlockRecord {
            height: grandparent.context.height,
            block_id: grandparent.block_id.clone(),
            qc_id: grandparent.id()?,
        }))
    }

    pub fn metrics(&self) -> &SimplifiedConsensusMetrics {
        &self.metrics
    }

    pub fn export_state_sync_bundle(&self) -> Result<SimplifiedStateSyncBundle, String> {
        SimplifiedStateSyncBundle::from_verified_state(&self.epoch_context, &self.state)
    }

    /// Installs a fully verified peer bundle without allowing the peer to
    /// overwrite local signing history or an existing SafetyHalt. Rollback to
    /// a lower certified head is rejected even if the bundle is otherwise
    /// internally valid.
    pub fn install_state_sync_bundle<V: ConsensusSignatureVerifier>(
        &mut self,
        bundle: &SimplifiedStateSyncBundle,
        verifier: &V,
        signing_authority: &DurableConsensusSigningAuthority,
    ) -> Result<(), String> {
        let started = Instant::now();
        let mut reconstructed = match &self.epoch_transition {
            Some(transition) => bundle.verify_and_reconstruct_from_verified_v3_transition(
                transition,
                verifier,
                self.state.last_vote.clone(),
                self.state.safety_halt.clone(),
            )?,
            None => bundle.verify_and_reconstruct(
                &self.epoch_context,
                &self.validator_set,
                &self.state.anchor_qc,
                verifier,
                self.state.last_vote.clone(),
                self.state.safety_halt.clone(),
            )?,
        };
        if let Some(incident) = self.state_sync_conflict(&reconstructed)? {
            signing_authority.enter_safety_halt(&incident)?;
            let mut staged_state = self.state.clone();
            staged_state.safety_halt = Some(incident);
            self.store.persist(&self.epoch_context, &staged_state)?;
            self.state = staged_state;
            return Err(
                "CONSENSUS_SAFETY_HALT: state sync contains conflicting certified evidence"
                    .to_string(),
            );
        }
        if qc_order(&reconstructed.highest_qc) < qc_order(&self.state.highest_qc)
            || reconstructed.finalized.height.0 < self.state.finalized.height.0
        {
            return Err(
                "state-sync bundle would roll consensus safety state backwards".to_string(),
            );
        }
        if let Some(delivery) = self.state.reliable_delivery.clone() {
            let next_height = reconstructed.next_height()?;
            let (round, _) = reconstructed.takeover_for_height(&self.epoch_context, next_height)?;
            if delivery.context.height == next_height && delivery.context.round.0 == round {
                reconstructed.reliable_delivery = Some(delivery);
            }
        }
        self.store.persist(&self.epoch_context, &reconstructed)?;
        self.state = reconstructed;
        self.metrics
            .record_duration(SimplifiedMetricKind::RestartRejoinMicros, started.elapsed());
        Ok(())
    }

    fn state_sync_conflict(
        &self,
        reconstructed: &SimplifiedSafetyState,
    ) -> Result<Option<SafetyHaltIncident>, String> {
        for (height, local) in &self.state.certified_qcs {
            let Some(peer) = reconstructed.certified_qcs.get(height) else {
                continue;
            };
            let local_id = local.id()?;
            let peer_id = peer.id()?;
            if local_id != peer_id {
                return Ok(Some(SafetyHaltIncident {
                    incident_version: 1,
                    kind: SafetyHaltKind::ConflictingQuorumCertificates,
                    chain_id: peer.context.chain_id,
                    network_id: peer.context.network_id.clone(),
                    protocol_version: peer.context.protocol_version.clone(),
                    epoch: peer.context.epoch,
                    height: peer.context.height,
                    context_root: peer.context.epoch_context_root,
                    first_evidence_root: local_id,
                    second_evidence_root: peer_id,
                }));
            }
        }
        let mut local_tcs = BTreeMap::<(u64, u64), Hash>::new();
        for certificates in self.state.certified_tcs.values() {
            for certificate in certificates {
                local_tcs.insert(
                    (certificate.context.height.0, certificate.context.round.0),
                    certificate.id()?,
                );
            }
        }
        for certificates in reconstructed.certified_tcs.values() {
            for certificate in certificates {
                let slot = (certificate.context.height.0, certificate.context.round.0);
                let Some(local_id) = local_tcs.get(&slot) else {
                    continue;
                };
                let peer_id = certificate.id()?;
                if *local_id != peer_id {
                    return Ok(Some(SafetyHaltIncident {
                        incident_version: 1,
                        kind: SafetyHaltKind::ConflictingTimeoutCertificates,
                        chain_id: certificate.context.chain_id,
                        network_id: certificate.context.network_id.clone(),
                        protocol_version: certificate.context.protocol_version.clone(),
                        epoch: certificate.context.epoch,
                        height: certificate.context.height,
                        context_root: certificate.context.epoch_context_root,
                        first_evidence_root: *local_id,
                        second_evidence_root: peer_id,
                    }));
                }
            }
        }
        Ok(None)
    }

    pub fn record_proposal_latency(&mut self, latency: std::time::Duration) {
        self.metrics
            .record_duration(SimplifiedMetricKind::ProposalLatencyMicros, latency);
    }

    pub fn record_vote_propagation(&mut self, latency: std::time::Duration) {
        self.metrics
            .record_duration(SimplifiedMetricKind::VotePropagationMicros, latency);
    }

    pub fn record_qc_formation(&mut self, latency: std::time::Duration) {
        self.metrics.record_duration(
            SimplifiedMetricKind::QuorumCertificateFormationMicros,
            latency,
        );
    }

    pub fn record_chained_finality(&mut self, latency: std::time::Duration) {
        self.metrics
            .record_duration(SimplifiedMetricKind::ChainedFinalityMicros, latency);
    }

    fn require_active_signer(
        &self,
        validator_id: &ValidatorId,
        key_id: &AegisPqKeyId,
    ) -> Result<(), String> {
        let validator = self
            .validator_set
            .active_for_epoch(self.epoch_context.epoch)
            .validators
            .into_iter()
            .find(|validator| &validator.validator_id == validator_id)
            .ok_or_else(|| "local signer is not in the frozen active set".to_string())?;
        if &validator.consensus_public_key.key_id != key_id {
            return Err("local signer key does not match the frozen consensus key".to_string());
        }
        Ok(())
    }

    fn validate_proposal_safety(&self, proposal: &SimplifiedProposal) -> Result<(), String> {
        if self.state.safety_halt.is_some() {
            return Err("CONSENSUS_SAFETY_HALT: proposal processing is disabled".to_string());
        }
        proposal.context.validate_against(&self.epoch_context)?;
        if proposal.context.height != self.state.next_height()? {
            return Err(format!(
                "proposal height {} is not next certified height {}",
                proposal.context.height.0,
                self.state.next_height()?.0
            ));
        }
        if proposal.block_id.0.trim().is_empty()
            || proposal.parent_block_id != proposal.parent_qc.block_id
            || proposal.parent_qc.height.0.checked_add(1) != Some(proposal.context.height.0)
            || proposal.protected_execution_root.is_zero()
            || proposal.takeover_tc_id.is_some_and(Hash::is_zero)
        {
            return Err(
                "proposal has invalid ancestry or protected-execution commitment".to_string(),
            );
        }
        if !self.state.known_qc(&proposal.parent_qc)? {
            return Err("proposal parent QC is not verified local safety state".to_string());
        }
        let (expected_round, expected_tc_id) = self
            .state
            .takeover_for_height(&self.epoch_context, proposal.context.height)?;
        if proposal.context.round.0 != expected_round || proposal.takeover_tc_id != expected_tc_id {
            return Err(
                "proposal does not carry the active sequential TC takeover proof".to_string(),
            );
        }
        if let Some(expected_tc_id) = expected_tc_id {
            let certificate = self
                .state
                .takeover
                .as_ref()
                .and_then(|takeover| takeover.certificates.last())
                .ok_or_else(|| "active takeover is missing its durable TC evidence".to_string())?;
            if certificate.id()? != expected_tc_id {
                return Err("active takeover TC pointer is inconsistent".to_string());
            }
            // The TC's view-change report closes only its effective height.
            // The replacement retains proposer authority through the rest of
            // the lease, but later heights extend newly certified QCs and must
            // never replay the old carried candidate.
            if certificate.context.height == proposal.context.height {
                let candidate = CertifiedCandidateSubject::new(
                    proposal.context.clone(),
                    proposal.block_id.clone(),
                    proposal.parent_block_id.clone(),
                    proposal.parent_qc.clone(),
                    proposal.protected_execution_root,
                )?;
                if let Some(mandatory) = certificate.mandatory_carry_candidate()? {
                    if candidate.id()? != mandatory.id()? {
                        return Err(
                            "takeover proposal does not carry the TC-mandated stable candidate"
                                .to_string(),
                        );
                    }
                } else if proposal.parent_qc != certificate.highest_qc()? {
                    return Err(
                        "fresh takeover proposal does not extend the TC maximum verified QC"
                            .to_string(),
                    );
                }
            }
        }
        let expected_proposer = self
            .epoch_context
            .authorized_proposer(proposal.context.height, expected_round)?;
        if &proposal.proposer_id != expected_proposer {
            return Err(format!(
                "unauthorized proposer: expected {}, found {}",
                expected_proposer.0, proposal.proposer_id.0
            ));
        }

        // A TC only changes lease authority. It never unlocks a branch. The
        // proposal must still extend the durable lock, or be justified by a
        // strictly higher *verified QC*. This is the core chained-QC safety
        // boundary that prevents timeout-driven forks.
        let extends_lock = self.state.proposal_extends_lock(&proposal.parent_qc)?;
        let higher_qc_unlock = self
            .state
            .locked_qc
            .as_ref()
            .is_some_and(|lock| proposal.parent_qc.height.0 > lock.height.0);
        if !extends_lock && !higher_qc_unlock {
            return Err("proposal conflicts with the durable QC lock".to_string());
        }
        Ok(())
    }

    pub fn validate_proposal<V: ConsensusSignatureVerifier>(
        &mut self,
        proposal: &SimplifiedProposal,
        verifier: &V,
    ) -> Result<(), String> {
        let started = Instant::now();
        self.validate_proposal_safety(proposal)?;
        let validator = self
            .validator_set
            .active_for_epoch(proposal.context.epoch)
            .validators
            .into_iter()
            .find(|validator| validator.validator_id == proposal.proposer_id)
            .ok_or_else(|| "proposal signer is not in the frozen active set".to_string())?;
        if proposal.proposer_key_id != validator.consensus_public_key.key_id {
            return Err("proposal uses the wrong frozen consensus key".to_string());
        }
        verifier.verify_consensus_signature(
            POSY_SIMPLIFIED_PROPOSAL_DOMAIN,
            &proposal.signing_bytes()?,
            &validator,
            &proposal.proposer_key_id,
            proposal.context.epoch,
            &proposal.proposer_signature,
        )?;
        self.metrics.record_duration(
            SimplifiedMetricKind::PqcVerificationMicros,
            started.elapsed(),
        );
        Ok(())
    }

    pub fn sign_proposal(
        &self,
        mut proposal: SimplifiedProposal,
        signing_authority: &DurableConsensusSigningAuthority,
        signer: &mut AegisPqvmSigner,
    ) -> Result<SimplifiedProposal, String> {
        self.validate_proposal_safety(&proposal)?;
        let validator = self
            .validator_set
            .validators
            .iter()
            .find(|validator| validator.validator_id == proposal.proposer_id)
            .ok_or_else(|| "proposal signer is not in the frozen active set".to_string())?;
        if proposal.proposer_key_id != validator.consensus_public_key.key_id {
            return Err("proposal uses the wrong frozen consensus key".to_string());
        }
        let candidate = CertifiedCandidateSubject::new(
            proposal.context.clone(),
            proposal.block_id.clone(),
            proposal.parent_block_id.clone(),
            proposal.parent_qc.clone(),
            proposal.protected_execution_root,
        )?;
        signing_authority.authorize_before_signature(&ConsensusSigningAuthorization {
            chain_id: proposal.context.chain_id,
            network_id: proposal.context.network_id.clone(),
            protocol_version: proposal.context.protocol_version.clone(),
            epoch: proposal.context.epoch,
            height: proposal.context.height,
            round: proposal.context.round,
            height_context_root: proposal.context.epoch_context_root,
            validator_id: proposal.proposer_id.clone(),
            key_id: proposal.proposer_key_id.clone(),
            phase: ConsensusSigningPhase::Proposal,
            candidate_id: Some(BlockId(format!("posy-v3:{}", candidate.id()?.to_hex()))),
            highest_prepared_vc_root: None,
            conflict_unlock_tc_id: None,
        })?;
        proposal.proposer_signature = signer
            .sign_domain(
                POSY_SIMPLIFIED_PROPOSAL_DOMAIN,
                &proposal.signing_bytes()?,
                &proposal.proposer_key_id,
            )
            .map_err(|error| error.to_string())?;
        Ok(proposal)
    }

    pub fn sign_block_vote(
        &mut self,
        proposal: &SimplifiedProposal,
        proposal_verifier: &impl ConsensusSignatureVerifier,
        validator_id: ValidatorId,
        key_id: AegisPqKeyId,
        signing_authority: &DurableConsensusSigningAuthority,
        signer: &mut AegisPqvmSigner,
    ) -> Result<BlockVote, String> {
        self.validate_proposal(proposal, proposal_verifier)?;
        self.require_active_signer(&validator_id, &key_id)?;
        let mut vote = BlockVote {
            context: proposal.context.clone(),
            block_id: proposal.block_id.clone(),
            parent_block_id: proposal.parent_block_id.clone(),
            parent_qc: proposal.parent_qc.clone(),
            takeover_tc_id: proposal.takeover_tc_id,
            protected_execution_root: proposal.protected_execution_root,
            validator_id: validator_id.clone(),
            key_id: key_id.clone(),
            signature: AegisPqSignature {
                algorithm: String::new(),
                signature_bytes: Vec::new(),
            },
        };
        let transcript_root =
            Hash::from_domain_bytes(POSY_SIMPLIFIED_BLOCK_VOTE_DOMAIN, &vote.signing_bytes()?);
        let candidate = CertifiedCandidateSubject::new(
            proposal.context.clone(),
            proposal.block_id.clone(),
            proposal.parent_block_id.clone(),
            proposal.parent_qc.clone(),
            proposal.protected_execution_root,
        )?;
        let mut conflict_unlock_tc_id = None;
        if let Some(last_vote) = &self.state.last_vote {
            if (proposal.context.height.0, proposal.context.round.0)
                < (last_vote.height.0, last_vote.round.0)
            {
                return Err("last-voted height/round would move backwards".to_string());
            }
            if last_vote.height == proposal.context.height
                && last_vote.candidate.id()? != candidate.id()?
            {
                if proposal.context.round.0 <= last_vote.round.0 {
                    return Err(
                        "conflicting block vote in the same or an older takeover round".to_string(),
                    );
                }
                let expected_tc_id = proposal.takeover_tc_id.ok_or_else(|| {
                    "same-height vote change requires a verified no-carry TC".to_string()
                })?;
                let certificate = self
                    .state
                    .takeover
                    .as_ref()
                    .and_then(|takeover| takeover.certificates.last())
                    .ok_or_else(|| "vote conflict-unlock TC evidence is missing".to_string())?;
                if certificate.context.height != proposal.context.height
                    || certificate.id()? != expected_tc_id
                    || certificate.mandatory_carry_candidate()?.is_some()
                {
                    return Err(
                        "same-height vote change lacks a verified no-carry TC intersection proof"
                            .to_string(),
                    );
                }
                conflict_unlock_tc_id = Some(expected_tc_id);
            }
        }
        let timeout_probe = ConsensusSigningAuthorization {
            chain_id: proposal.context.chain_id,
            network_id: proposal.context.network_id.clone(),
            protocol_version: proposal.context.protocol_version.clone(),
            epoch: proposal.context.epoch,
            height: proposal.context.height,
            round: proposal.context.round,
            height_context_root: proposal.context.epoch_context_root,
            validator_id: validator_id.clone(),
            key_id: key_id.clone(),
            phase: ConsensusSigningPhase::Timeout,
            candidate_id: None,
            highest_prepared_vc_root: None,
            conflict_unlock_tc_id: None,
        };
        if signing_authority
            .recorded_authorization_for_slot(&timeout_probe)?
            .is_some()
        {
            return Err(
                "block vote is forbidden after a durable timeout vote for the same slot"
                    .to_string(),
            );
        }
        signing_authority.authorize_before_signature(&ConsensusSigningAuthorization {
            chain_id: proposal.context.chain_id,
            network_id: proposal.context.network_id.clone(),
            protocol_version: proposal.context.protocol_version.clone(),
            epoch: proposal.context.epoch,
            height: proposal.context.height,
            round: proposal.context.round,
            height_context_root: proposal.context.epoch_context_root,
            validator_id,
            key_id: key_id.clone(),
            phase: ConsensusSigningPhase::Vote,
            candidate_id: Some(BlockId(format!("posy-v3:{}", candidate.id()?.to_hex()))),
            highest_prepared_vc_root: None,
            conflict_unlock_tc_id,
        })?;
        self.state.last_vote = Some(LastVoteRecord {
            height: proposal.context.height,
            round: proposal.context.round,
            candidate: candidate.clone(),
            transcript_root,
        });
        // Persist both durable authorities before releasing the signature.
        // The signer journal is written first: if safety-state persistence
        // then fails, retry re-derives the same TC unlock and takes the
        // journal's idempotent path instead of wedging on an A/B mismatch.
        self.store.persist(&self.epoch_context, &self.state)?;
        vote.signature = signer
            .sign_domain(
                POSY_SIMPLIFIED_BLOCK_VOTE_DOMAIN,
                &vote.signing_bytes()?,
                &key_id,
            )
            .map_err(|error| error.to_string())?;
        Ok(vote)
    }

    pub fn sign_timeout_vote(
        &mut self,
        validator_id: ValidatorId,
        key_id: AegisPqKeyId,
        signing_authority: &DurableConsensusSigningAuthority,
        signer: &mut AegisPqvmSigner,
    ) -> Result<TimeoutVote, String> {
        if self.state.safety_halt.is_some() {
            return Err("CONSENSUS_SAFETY_HALT: timeout signing is disabled".to_string());
        }
        self.require_active_signer(&validator_id, &key_id)?;
        let height = self.state.next_height()?;
        let (round, previous_tc_id) = self
            .state
            .takeover_for_height(&self.epoch_context, height)?;
        let context =
            ConsensusObjectContext::for_height(&self.epoch_context, height, Round(round))?;
        let inherited_carry = if let Some(expected_tc_id) = previous_tc_id {
            let certificate = self
                .state
                .takeover
                .as_ref()
                .and_then(|takeover| takeover.certificates.last())
                .ok_or_else(|| "active takeover is missing its latest TC".to_string())?;
            if certificate.id()? != expected_tc_id {
                return Err("active takeover latest TC pointer is inconsistent".to_string());
            }
            certificate
                .mandatory_carry_candidate()?
                .filter(|candidate| candidate.context.height == height)
        } else {
            None
        };
        let carry_candidate = self
            .state
            .last_vote
            .as_ref()
            .filter(|last_vote| last_vote.height == height)
            .map(|last_vote| last_vote.candidate.clone())
            .or_else(|| {
                self.state
                    .reliable_delivery
                    .as_ref()
                    .and_then(|delivery| delivery.delivered_candidate.clone())
            })
            .or(inherited_carry);
        let mut vote = TimeoutVote {
            lease_index: self.epoch_context.lease_index(height)?,
            timed_out_proposer: self
                .epoch_context
                .authorized_proposer(height, round)?
                .clone(),
            highest_qc: self.state.highest_qc.clone(),
            previous_tc_id,
            last_voted_candidate: carry_candidate,
            validator_id: validator_id.clone(),
            key_id: key_id.clone(),
            context,
            signature: AegisPqSignature {
                algorithm: String::new(),
                signature_bytes: Vec::new(),
            },
        };
        let timeout_subject_root =
            Hash::from_domain_bytes(POSY_SIMPLIFIED_TIMEOUT_VOTE_DOMAIN, &vote.signing_bytes()?);
        signing_authority.authorize_before_signature(&ConsensusSigningAuthorization {
            chain_id: vote.context.chain_id,
            network_id: vote.context.network_id.clone(),
            protocol_version: vote.context.protocol_version.clone(),
            epoch: vote.context.epoch,
            height: vote.context.height,
            round: vote.context.round,
            height_context_root: vote.context.epoch_context_root,
            validator_id,
            key_id: key_id.clone(),
            phase: ConsensusSigningPhase::Timeout,
            candidate_id: Some(BlockId(format!(
                "posy-v3-timeout:{}",
                timeout_subject_root.to_hex()
            ))),
            highest_prepared_vc_root: Some(vote.highest_qc.qc_id),
            conflict_unlock_tc_id: None,
        })?;
        vote.signature = signer
            .sign_domain(
                POSY_SIMPLIFIED_TIMEOUT_VOTE_DOMAIN,
                &vote.signing_bytes()?,
                &key_id,
            )
            .map_err(|error| error.to_string())?;
        Ok(vote)
    }

    pub fn accept_timeout_certificate<V: ConsensusSignatureVerifier>(
        &mut self,
        certificate: SimplifiedTimeoutCertificate,
        verifier: &V,
    ) -> Result<(), String> {
        if self.state.safety_halt.is_some() {
            return Err("CONSENSUS_SAFETY_HALT: TC processing is disabled".to_string());
        }
        let verification_started = Instant::now();
        certificate.verify(&self.epoch_context, &self.validator_set, verifier)?;
        let recovery_latency = verification_started.elapsed();
        self.metrics.record_duration(
            SimplifiedMetricKind::PqcVerificationMicros,
            recovery_latency,
        );
        self.metrics.record_duration(
            SimplifiedMetricKind::TimeoutCertificateRecoveryMicros,
            recovery_latency,
        );
        self.metrics
            .record_duration(SimplifiedMetricKind::LeaderTakeoverMicros, recovery_latency);
        self.metrics.record_value(
            SimplifiedMetricKind::CertificateSizeBytes,
            u64::try_from(certificate.canonical_bytes()?.len()).unwrap_or(u64::MAX),
        );
        let expected_height = self.state.next_height()?;
        let (expected_round, expected_previous) = self
            .state
            .takeover_for_height(&self.epoch_context, expected_height)?;
        if certificate.context.height != expected_height
            || certificate.context.round.0 != expected_round
            || certificate.previous_tc_id != expected_previous
            || certificate.highest_qc()? != self.state.highest_qc
        {
            return Err("stale, skipped, or non-sequential timeout certificate".to_string());
        }
        let lease_index = self.epoch_context.lease_index(expected_height)?;
        let mut staged_state = self.state.clone();
        let mut takeover = match staged_state.takeover.take() {
            Some(existing) if existing.lease_index == lease_index => existing,
            _ => LeaseTakeoverState {
                lease_index,
                effective_height: expected_height,
                takeover_offset: 0,
                certificates: Vec::new(),
            },
        };
        takeover.certificates.push(certificate.clone());
        takeover.takeover_offset = takeover
            .takeover_offset
            .checked_add(1)
            .ok_or_else(|| "lease takeover offset overflow".to_string())?;
        staged_state
            .certified_tcs
            .entry(expected_height.0)
            .or_default()
            .push(certificate);
        staged_state.takeover = Some(takeover);
        Self::clear_reliable_delivery(&mut staged_state);
        self.store.persist(&self.epoch_context, &staged_state)?;
        self.state = staged_state;
        Ok(())
    }

    pub fn accept_quorum_certificate<V: ConsensusSignatureVerifier>(
        &mut self,
        certificate: SimplifiedQuorumCertificate,
        verifier: &V,
        signing_authority: &DurableConsensusSigningAuthority,
    ) -> Result<Option<FinalizedBlockRecord>, String> {
        if self.state.safety_halt.is_some() {
            return Err("CONSENSUS_SAFETY_HALT: QC processing is disabled".to_string());
        }
        let verification_started = Instant::now();
        certificate.verify(&self.epoch_context, &self.validator_set, verifier)?;
        self.metrics.record_duration(
            SimplifiedMetricKind::PqcVerificationMicros,
            verification_started.elapsed(),
        );
        self.metrics.record_value(
            SimplifiedMetricKind::CertificateSizeBytes,
            u64::try_from(certificate.canonical_bytes()?.len()).unwrap_or(u64::MAX),
        );
        if let Some(existing) = self.state.certified_qcs.get(&certificate.context.height.0) {
            if existing.id()? != certificate.id()? {
                let incident = SafetyHaltIncident {
                    incident_version: 1,
                    kind: SafetyHaltKind::ConflictingQuorumCertificates,
                    chain_id: certificate.context.chain_id,
                    network_id: certificate.context.network_id.clone(),
                    protocol_version: certificate.context.protocol_version.clone(),
                    epoch: certificate.context.epoch,
                    height: certificate.context.height,
                    context_root: certificate.context.epoch_context_root,
                    first_evidence_root: existing.id()?,
                    second_evidence_root: certificate.id()?,
                };
                signing_authority.enter_safety_halt(&incident)?;
                let mut staged_state = self.state.clone();
                staged_state.safety_halt = Some(incident);
                self.store.persist(&self.epoch_context, &staged_state)?;
                self.state = staged_state;
                return Err("CONSENSUS_SAFETY_HALT: conflicting valid QCs".to_string());
            }
            return Ok(None);
        }
        let (expected_round, expected_tc_id) = self
            .state
            .takeover_for_height(&self.epoch_context, certificate.context.height)?;
        if certificate.context.round.0 < expected_round {
            let latest_tc = self
                .state
                .takeover
                .as_ref()
                .and_then(|takeover| takeover.certificates.last())
                .filter(|tc| tc.context.height == certificate.context.height)
                .ok_or_else(|| {
                    "older-round QC has no active same-height TC evidence".to_string()
                })?;
            let carried = latest_tc.mandatory_carry_candidate()?;
            if carried
                .as_ref()
                .map(CertifiedCandidateSubject::id)
                .transpose()?
                != Some(certificate.id()?)
            {
                let incident = SafetyHaltIncident {
                    incident_version: 1,
                    kind: SafetyHaltKind::ConflictingTimeoutAndQuorumEvidence,
                    chain_id: certificate.context.chain_id,
                    network_id: certificate.context.network_id.clone(),
                    protocol_version: certificate.context.protocol_version.clone(),
                    epoch: certificate.context.epoch,
                    height: certificate.context.height,
                    context_root: certificate.context.epoch_context_root,
                    first_evidence_root: latest_tc.id()?,
                    second_evidence_root: certificate.id()?,
                };
                signing_authority.enter_safety_halt(&incident)?;
                let mut staged_state = self.state.clone();
                staged_state.safety_halt = Some(incident);
                self.store.persist(&self.epoch_context, &staged_state)?;
                self.state = staged_state;
                return Err(
                    "CONSENSUS_SAFETY_HALT: older-round QC contradicts no-carry/other-carry TC"
                        .to_string(),
                );
            }
        } else if certificate.context.round.0 > expected_round
            || certificate.takeover_tc_id != expected_tc_id
        {
            return Err("QC does not match the active lease takeover state".to_string());
        }
        if !self.state.known_qc(&certificate.parent_qc)? {
            return Err("QC parent is not verified local safety state".to_string());
        }
        let reference = certificate.reference()?;
        let mut staged_state = self.state.clone();
        staged_state
            .certified_qcs
            .insert(certificate.context.height.0, certificate.clone());
        if qc_order(&reference) > qc_order(&staged_state.highest_qc) {
            staged_state.highest_qc = reference.clone();
        }

        // A certified child proves its parent remains on the safe chain. The
        // lock advances monotonically to that parent; it is never cleared by a
        // timeout, restart, or operator action.
        let parent = certificate.parent_qc.clone();
        if staged_state
            .locked_qc
            .as_ref()
            .is_none_or(|lock| qc_order(&parent) > qc_order(lock))
        {
            staged_state.locked_qc = Some(parent.clone());
        }

        let finalized = Self::try_three_chain_commit(&mut staged_state, &certificate)?;
        Self::clear_reliable_delivery(&mut staged_state);
        self.store.persist(&self.epoch_context, &staged_state)?;
        self.state = staged_state;
        Ok(finalized)
    }

    fn try_three_chain_commit(
        state: &mut SimplifiedSafetyState,
        newest: &SimplifiedQuorumCertificate,
    ) -> Result<Option<FinalizedBlockRecord>, String> {
        let Some(parent) = state.certificate_at(newest.parent_qc.height) else {
            return Ok(None);
        };
        if parent.reference()? != newest.parent_qc {
            return Err("newest QC does not extend its claimed certified parent".to_string());
        }
        let Some(grandparent) = state.certificate_at(parent.parent_qc.height) else {
            return Ok(None);
        };
        if grandparent.reference()? != parent.parent_qc
            || grandparent.context.height.0.checked_add(1) != Some(parent.context.height.0)
            || parent.context.height.0.checked_add(1) != Some(newest.context.height.0)
        {
            return Err("certified blocks do not form a consecutive three-chain".to_string());
        }
        if grandparent.context.height.0 <= state.finalized.height.0 {
            return Ok(None);
        }
        let committed = FinalizedBlockRecord {
            height: grandparent.context.height,
            block_id: grandparent.block_id.clone(),
            qc_id: grandparent.id()?,
        };
        state.finalized = committed.clone();
        Ok(Some(committed))
    }
}

fn qc_order(reference: &QuorumCertificateReference) -> (u64, [u8; 32]) {
    (reference.height.0, reference.qc_id.0)
}

fn simplified_vote_authorization_candidate(
    candidate: &CertifiedCandidateSubject,
) -> Result<BlockId, String> {
    Ok(BlockId(format!("posy-v3:{}", candidate.id()?.to_hex())))
}

fn signing_authorization_root(
    authorization: &ConsensusSigningAuthorization,
) -> Result<Hash, String> {
    let bytes = serde_json::to_vec(authorization)
        .map_err(|error| format!("serialize signing authorization: {error}"))?;
    Ok(Hash::from_domain_bytes(
        "SYNERGY_CONSENSUS_SIGNING_AUTHORIZATION_V1",
        &bytes,
    ))
}

fn state_root(state: &SimplifiedSafetyState) -> Result<Hash, String> {
    Ok(Hash::from_domain_bytes(
        "SYNERGY_POSY_SIMPLIFIED_SAFETY_STATE_V1",
        &state.canonical_bytes()?,
    ))
}

fn current_unix_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default()
}
