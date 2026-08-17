//! Bounded, authenticated evidence streaming for simplified PoSy state sync.
//!
//! The wire never carries a monolithic epoch bundle. Evidence is ordered as
//! the state machine consumes it (zero or more TCs for a height, then its QC),
//! hash chained into deterministic chunks, and staged under strict resource
//! and time limits. Only a complete final-marked transcript can be converted
//! back into the bundle consumed by full signature/ancestry verification.

use super::{
    FinalizedBlockRecord, QuorumCertificateReference, SimplifiedEpochContext,
    SimplifiedQuorumCertificate, SimplifiedStateSyncBundle, SimplifiedTimeoutCertificate,
    POSY_SIMPLIFIED_STATE_SYNC_FORMAT,
};
use crate::synergy_types::{CanonicalSerialize, Hash, ValidatorId};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, VecDeque};
use std::time::{Duration, Instant};

pub const POSY_SIMPLIFIED_STATE_SYNC_CHUNK_FORMAT: &str =
    "synergy-posy-simplified-state-sync-chunk-v1";
pub const MAX_SIMPLIFIED_STATE_SYNC_CHUNK_PAYLOAD_BYTES: usize = 192 * 1024;
pub const MAX_SIMPLIFIED_STATE_SYNC_SESSION_STAGED_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_SIMPLIFIED_STATE_SYNC_PEER_STAGED_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_SIMPLIFIED_STATE_SYNC_GLOBAL_STAGED_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_SIMPLIFIED_STATE_SYNC_EVIDENCE: usize = 16_384;
pub const MAX_SIMPLIFIED_STATE_SYNC_CHUNKS: u32 = 4_096;
pub const MAX_SIMPLIFIED_STATE_SYNC_COMPLETED_SESSIONS: usize = 32;
pub const MAX_SIMPLIFIED_STATE_SYNC_SESSIONS_PER_PEER: usize = 2;
pub const MAX_SIMPLIFIED_STATE_SYNC_OUTSTANDING_REQUESTS: usize = 4;
pub const SIMPLIFIED_STATE_SYNC_SESSION_TTL: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub enum SimplifiedStateSyncEvidence {
    QuorumCertificate(SimplifiedQuorumCertificate),
    TimeoutCertificate(SimplifiedTimeoutCertificate),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SimplifiedStateSyncChunk {
    pub format: String,
    pub request_id: Hash,
    pub session_root: Hash,
    pub epoch_context_root: Hash,
    pub anchor_qc: QuorumCertificateReference,
    pub sequence: u32,
    pub previous_chunk_root: Option<Hash>,
    pub evidence: Vec<SimplifiedStateSyncEvidence>,
    pub final_chunk: bool,
    pub claimed_finalized: Option<FinalizedBlockRecord>,
    pub chunk_root: Hash,
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ChunkSubject {
    format: String,
    request_id: Hash,
    session_root: Hash,
    epoch_context_root: Hash,
    anchor_qc: QuorumCertificateReference,
    sequence: u32,
    previous_chunk_root: Option<Hash>,
    evidence: Vec<SimplifiedStateSyncEvidence>,
    final_chunk: bool,
    claimed_finalized: Option<FinalizedBlockRecord>,
}

impl SimplifiedStateSyncChunk {
    fn subject(&self) -> ChunkSubject {
        ChunkSubject {
            format: self.format.clone(),
            request_id: self.request_id,
            session_root: self.session_root,
            epoch_context_root: self.epoch_context_root,
            anchor_qc: self.anchor_qc.clone(),
            sequence: self.sequence,
            previous_chunk_root: self.previous_chunk_root,
            evidence: self.evidence.clone(),
            final_chunk: self.final_chunk,
            claimed_finalized: self.claimed_finalized.clone(),
        }
    }

    pub fn computed_root(&self) -> Result<Hash, String> {
        Ok(Hash::from_domain_bytes(
            "SYNERGY_POSY_SIMPLIFIED_STATE_SYNC_CHUNK_V1",
            &self.subject().canonical_bytes()?,
        ))
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.format != POSY_SIMPLIFIED_STATE_SYNC_CHUNK_FORMAT
            || self.request_id.is_zero()
            || self.session_root.is_zero()
            || self.epoch_context_root.is_zero()
            || self.sequence >= MAX_SIMPLIFIED_STATE_SYNC_CHUNKS
            || self.evidence.len() > MAX_SIMPLIFIED_STATE_SYNC_EVIDENCE
            || self.chunk_root != self.computed_root()?
        {
            return Err("invalid simplified state-sync chunk envelope".to_string());
        }
        self.anchor_qc.validate()?;
        if self.sequence == 0 && self.previous_chunk_root.is_some()
            || self.sequence > 0
                && self
                    .previous_chunk_root
                    .is_none_or(crate::synergy_types::Hash::is_zero)
        {
            return Err("state-sync chunk predecessor root is invalid".to_string());
        }
        if self.final_chunk != self.claimed_finalized.is_some() {
            return Err("state-sync final marker and finalized claim disagree".to_string());
        }
        if !self.final_chunk && self.evidence.is_empty() {
            return Err("non-final state-sync chunk cannot be empty".to_string());
        }
        if !self.final_chunk && self.sequence + 1 == MAX_SIMPLIFIED_STATE_SYNC_CHUNKS {
            return Err("last permitted state-sync chunk must be final".to_string());
        }
        let encoded = self.canonical_bytes()?.len();
        if encoded > MAX_SIMPLIFIED_STATE_SYNC_CHUNK_PAYLOAD_BYTES {
            return Err(format!(
                "state-sync chunk payload {encoded} exceeds {} bytes",
                MAX_SIMPLIFIED_STATE_SYNC_CHUNK_PAYLOAD_BYTES
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct EvidenceSequence {
    next_height: u64,
    expected_parent_qc: QuorumCertificateReference,
    next_timeout_round: u64,
    previous_tc_id: Option<Hash>,
}

impl EvidenceSequence {
    fn new(anchor_qc: QuorumCertificateReference) -> Result<Self, String> {
        let next_height = anchor_qc
            .height
            .0
            .checked_add(1)
            .ok_or_else(|| "state-sync anchor height overflows".to_string())?;
        Ok(Self {
            next_height,
            expected_parent_qc: anchor_qc,
            next_timeout_round: 0,
            previous_tc_id: None,
        })
    }

    fn observe(
        &mut self,
        epoch_context: &SimplifiedEpochContext,
        item: &SimplifiedStateSyncEvidence,
    ) -> Result<(), String> {
        match item {
            SimplifiedStateSyncEvidence::QuorumCertificate(qc) => {
                qc.context.validate_against(epoch_context)?;
                let certified_lease = epoch_context.lease_index(qc.context.height)?;
                if qc.context.height.0 != self.next_height
                    || qc.context.round.0 != self.next_timeout_round
                    || qc.parent_qc != self.expected_parent_qc
                    || qc.takeover_tc_id != self.previous_tc_id
                {
                    return Err(
                        "state-sync QC evidence is not consecutive or lacks TC authority"
                            .to_string(),
                    );
                }
                self.expected_parent_qc = qc.reference()?;
                self.next_height = self
                    .next_height
                    .checked_add(1)
                    .ok_or_else(|| "state-sync evidence height overflows".to_string())?;
                let crossed_lease_boundary = if self.next_height <= epoch_context.epoch_end_height.0
                {
                    epoch_context.lease_index(crate::synergy_types::Height(self.next_height))?
                        != certified_lease
                } else {
                    true
                };
                if crossed_lease_boundary {
                    self.next_timeout_round = 0;
                    self.previous_tc_id = None;
                }
            }
            SimplifiedStateSyncEvidence::TimeoutCertificate(tc) => {
                tc.context.validate_against(epoch_context)?;
                if tc.context.height.0 != self.next_height
                    || tc.context.round.0 != self.next_timeout_round
                    || tc.previous_tc_id != self.previous_tc_id
                {
                    return Err("state-sync TC evidence is not sequential".to_string());
                }
                self.previous_tc_id = Some(tc.id()?);
                self.next_timeout_round = self
                    .next_timeout_round
                    .checked_add(1)
                    .ok_or_else(|| "state-sync timeout round overflows".to_string())?;
            }
        }
        Ok(())
    }

    fn observe_all(
        &mut self,
        epoch_context: &SimplifiedEpochContext,
        evidence: &[SimplifiedStateSyncEvidence],
    ) -> Result<(), String> {
        for item in evidence {
            self.observe(epoch_context, item)?;
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct SessionSubject {
    request_id: Hash,
    epoch_context_root: Hash,
    anchor_qc: QuorumCertificateReference,
    evidence_transcript_root: Hash,
    evidence_count: u64,
    claimed_finalized: FinalizedBlockRecord,
}

fn evidence_transcript_root(
    epoch_context_root: Hash,
    anchor_qc: &QuorumCertificateReference,
    evidence: &[SimplifiedStateSyncEvidence],
) -> Result<Hash, String> {
    let mut root = Hash::from_domain_bytes(
        "SYNERGY_POSY_SIMPLIFIED_STATE_SYNC_TRANSCRIPT_START_V1",
        &(epoch_context_root, anchor_qc.clone()).canonical_bytes()?,
    );
    for item in evidence {
        root = Hash::from_domain_bytes(
            "SYNERGY_POSY_SIMPLIFIED_STATE_SYNC_TRANSCRIPT_STEP_V1",
            &(root, item.clone()).canonical_bytes()?,
        );
    }
    Ok(root)
}

fn session_root(
    request_id: Hash,
    epoch_context_root: Hash,
    anchor_qc: &QuorumCertificateReference,
    evidence: &[SimplifiedStateSyncEvidence],
    claimed_finalized: &FinalizedBlockRecord,
) -> Result<Hash, String> {
    let evidence_count = u64::try_from(evidence.len())
        .map_err(|_| "state-sync evidence count exceeds u64".to_string())?;
    Ok(Hash::from_domain_bytes(
        "SYNERGY_POSY_SIMPLIFIED_STATE_SYNC_SESSION_V1",
        &SessionSubject {
            request_id,
            epoch_context_root,
            anchor_qc: anchor_qc.clone(),
            evidence_transcript_root: evidence_transcript_root(
                epoch_context_root,
                anchor_qc,
                evidence,
            )?,
            evidence_count,
            claimed_finalized: claimed_finalized.clone(),
        }
        .canonical_bytes()?,
    ))
}

fn ordered_evidence(
    bundle: &SimplifiedStateSyncBundle,
) -> Result<Vec<SimplifiedStateSyncEvidence>, String> {
    let mut qcs = bundle.certified_qcs.clone();
    qcs.sort_by_key(|qc| qc.context.height.0);
    if qcs
        .windows(2)
        .any(|pair| pair[0].context.height == pair[1].context.height)
    {
        return Err("state-sync export contains duplicate QC heights".to_string());
    }
    let mut evidence = Vec::new();
    for qc in qcs {
        if let Some(tcs) = bundle.certified_tcs.get(&qc.context.height.0) {
            evidence.extend(
                tcs.iter()
                    .cloned()
                    .map(SimplifiedStateSyncEvidence::TimeoutCertificate),
            );
        }
        evidence.push(SimplifiedStateSyncEvidence::QuorumCertificate(qc));
    }
    let next_height = bundle
        .certified_qcs
        .iter()
        .map(|qc| qc.context.height.0)
        .max()
        .unwrap_or(bundle.anchor_qc.height.0)
        .checked_add(1)
        .ok_or_else(|| "state-sync export height overflows".to_string())?;
    if let Some(tcs) = bundle.certified_tcs.get(&next_height) {
        evidence.extend(
            tcs.iter()
                .cloned()
                .map(SimplifiedStateSyncEvidence::TimeoutCertificate),
        );
    }
    let consumed_tc_heights = evidence
        .iter()
        .filter_map(|item| match item {
            SimplifiedStateSyncEvidence::TimeoutCertificate(tc) => Some(tc.context.height.0),
            SimplifiedStateSyncEvidence::QuorumCertificate(_) => None,
        })
        .collect::<std::collections::BTreeSet<_>>();
    if consumed_tc_heights
        != bundle
            .certified_tcs
            .keys()
            .copied()
            .collect::<std::collections::BTreeSet<_>>()
    {
        return Err("state-sync export contains out-of-chain TC evidence".to_string());
    }
    if evidence.len() > MAX_SIMPLIFIED_STATE_SYNC_EVIDENCE {
        return Err("state-sync export evidence limit exceeded".to_string());
    }
    let mut sequence = EvidenceSequence::new(bundle.anchor_qc.clone())?;
    sequence.observe_all(&bundle.epoch_context, &evidence)?;
    Ok(evidence)
}

fn validate_export_envelope(bundle: &SimplifiedStateSyncBundle) -> Result<(), String> {
    bundle.epoch_context.validate()?;
    bundle.anchor_qc.validate()?;
    if bundle.anchor_qc.height.0.checked_add(1) != Some(bundle.epoch_context.epoch_start_height.0) {
        return Err("state-sync export anchor does not precede the epoch".to_string());
    }
    if let Some(expected) = &bundle.epoch_context.v2_boundary_anchor {
        if bundle.anchor_qc.height != expected.height
            || bundle.anchor_qc.block_id != expected.block_id
            || bundle.anchor_qc.qc_id != expected.qc_finality_context_root
        {
            return Err("state-sync export substituted the pinned v2 boundary anchor".to_string());
        }
    }
    let transition_seed = if let Some(expected) = &bundle.epoch_context.v3_transition_anchor {
        if bundle.anchor_qc.height != expected.certified_parent_height
            || bundle.anchor_qc.block_id != expected.certified_parent_block_id
            || bundle.anchor_qc.qc_id != expected.certified_parent_qc_id
        {
            return Err("state-sync export substituted the pinned v3 certified parent".to_string());
        }
        Some(FinalizedBlockRecord {
            height: expected.finalized_seed_height,
            block_id: expected.finalized_seed_block_id.clone(),
            qc_id: expected.finalized_seed_qc_id,
        })
    } else {
        None
    };
    let minimum_finalized_height = transition_seed
        .as_ref()
        .map_or(bundle.anchor_qc.height.0, |seed| seed.height.0);
    if bundle.claimed_finalized.block_id.0.trim().is_empty()
        || bundle.claimed_finalized.qc_id.is_zero()
        || bundle.claimed_finalized.height.0 < minimum_finalized_height
    {
        return Err("state-sync export finalized claim is invalid".to_string());
    }
    let finalized_is_anchor = bundle.claimed_finalized.height == bundle.anchor_qc.height
        && bundle.claimed_finalized.block_id == bundle.anchor_qc.block_id
        && bundle.claimed_finalized.qc_id == bundle.anchor_qc.qc_id;
    let finalized_is_supplied_qc = bundle.certified_qcs.iter().any(|qc| {
        qc.context.height == bundle.claimed_finalized.height
            && qc.block_id == bundle.claimed_finalized.block_id
            && qc.id().ok() == Some(bundle.claimed_finalized.qc_id)
    });
    // Intermediate previous-epoch tail claims cannot be authenticated from
    // the context alone. The proof-aware receiver checks their exact IDs
    // against its independently verified transition tail before install.
    let finalized_is_transition_tail = transition_seed.as_ref().is_some_and(|seed| {
        (seed.height.0..=bundle.anchor_qc.height.0).contains(&bundle.claimed_finalized.height.0)
    });
    if !finalized_is_anchor && !finalized_is_transition_tail && !finalized_is_supplied_qc {
        return Err("state-sync finalized claim names no supplied certificate".to_string());
    }
    Ok(())
}

pub fn build_state_sync_chunks(
    bundle: &SimplifiedStateSyncBundle,
    request_id: Hash,
) -> Result<Vec<SimplifiedStateSyncChunk>, String> {
    if bundle.format != POSY_SIMPLIFIED_STATE_SYNC_FORMAT {
        return Err("cannot chunk an unsupported state-sync bundle".to_string());
    }
    if request_id.is_zero() {
        return Err("state-sync request id must be nonzero".to_string());
    }
    validate_export_envelope(bundle)?;
    let epoch_context_root = bundle.epoch_context.root()?;
    let evidence = ordered_evidence(bundle)?;
    let session_root = session_root(
        request_id,
        epoch_context_root,
        &bundle.anchor_qc,
        &evidence,
        &bundle.claimed_finalized,
    )?;
    let group_fits = |group: &[SimplifiedStateSyncEvidence]| -> Result<bool, String> {
        // Measure the exact canonical wire object with the largest envelope
        // shape (predecessor plus finalized claim), rather than rejecting a
        // legitimate ML-DSA certificate at an arbitrary fraction of the cap.
        let mut probe = SimplifiedStateSyncChunk {
            format: POSY_SIMPLIFIED_STATE_SYNC_CHUNK_FORMAT.to_string(),
            request_id,
            session_root,
            epoch_context_root,
            anchor_qc: bundle.anchor_qc.clone(),
            sequence: MAX_SIMPLIFIED_STATE_SYNC_CHUNKS - 1,
            previous_chunk_root: Some(Hash::from_domain_bytes(
                "SYNERGY_POSY_SIMPLIFIED_STATE_SYNC_SIZE_PROBE_V1",
                b"predecessor",
            )),
            evidence: group.to_vec(),
            final_chunk: true,
            claimed_finalized: Some(bundle.claimed_finalized.clone()),
            chunk_root: Hash::zero(),
        };
        probe.chunk_root = probe.computed_root()?;
        Ok(probe.canonical_bytes()?.len() <= MAX_SIMPLIFIED_STATE_SYNC_CHUNK_PAYLOAD_BYTES)
    };
    let mut groups = vec![Vec::<SimplifiedStateSyncEvidence>::new()];
    for item in evidence {
        if !group_fits(std::slice::from_ref(&item))? {
            return Err("one state-sync certificate is too large to chunk safely".to_string());
        }
        let current = groups
            .last_mut()
            .ok_or_else(|| "state-sync chunk planner lost its current group".to_string())?;
        let mut projected = current.clone();
        projected.push(item.clone());
        if !current.is_empty() && !group_fits(&projected)? {
            groups.push(vec![item]);
        } else {
            current.push(item);
        }
    }
    if groups.len() > MAX_SIMPLIFIED_STATE_SYNC_CHUNKS as usize {
        return Err("state-sync export requires too many chunks".to_string());
    }
    let group_count = groups.len();
    let mut chunks = Vec::with_capacity(group_count);
    let mut previous = None;
    for (index, group) in groups.into_iter().enumerate() {
        let final_chunk = index + 1 == group_count;
        let mut chunk = SimplifiedStateSyncChunk {
            format: POSY_SIMPLIFIED_STATE_SYNC_CHUNK_FORMAT.to_string(),
            request_id,
            session_root,
            epoch_context_root,
            anchor_qc: bundle.anchor_qc.clone(),
            sequence: u32::try_from(index)
                .map_err(|_| "state-sync chunk sequence exceeds u32".to_string())?,
            previous_chunk_root: previous,
            evidence: group,
            final_chunk,
            claimed_finalized: final_chunk.then(|| bundle.claimed_finalized.clone()),
            chunk_root: Hash::zero(),
        };
        chunk.chunk_root = chunk.computed_root()?;
        chunk.validate()?;
        previous = Some(chunk.chunk_root);
        chunks.push(chunk);
    }
    Ok(chunks)
}

struct StagedSession {
    request_id: Hash,
    session_root: Hash,
    epoch_context_root: Hash,
    anchor_qc: QuorumCertificateReference,
    next_sequence: u32,
    previous_chunk_root: Option<Hash>,
    evidence: Vec<SimplifiedStateSyncEvidence>,
    evidence_sequence: EvidenceSequence,
    staged_bytes: usize,
    expires_at: Instant,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompletedSimplifiedStateSync {
    pub request_id: Hash,
    pub peer: ValidatorId,
    pub bundle: SimplifiedStateSyncBundle,
}

pub struct SimplifiedStateSyncStager {
    expected_epoch_context: SimplifiedEpochContext,
    expected_epoch_context_root: Hash,
    expected_anchor_qc: QuorumCertificateReference,
    transition_finality_records: BTreeMap<u64, FinalizedBlockRecord>,
    max_active_sessions: usize,
    outstanding_requests: BTreeMap<Hash, Instant>,
    active: BTreeMap<(ValidatorId, Hash), StagedSession>,
    completed: VecDeque<(ValidatorId, Hash, Hash, Instant)>,
}

impl SimplifiedStateSyncStager {
    pub fn new(
        expected_epoch_context: SimplifiedEpochContext,
        expected_anchor_qc: QuorumCertificateReference,
    ) -> Result<Self, String> {
        if expected_epoch_context.v3_transition_anchor.is_some() {
            return Err(
                "v3-to-v3 state-sync staging requires an independently verified transition proof"
                    .to_string(),
            );
        }
        Self::new_internal(expected_epoch_context, expected_anchor_qc, BTreeMap::new())
    }

    pub fn new_from_verified_v3_transition(
        transition: &super::VerifiedSimplifiedEpochTransition,
    ) -> Result<Self, String> {
        let transition_finality_records = transition
            .transition_tail()
            .iter()
            .map(|certificate| {
                Ok((
                    certificate.context.height.0,
                    FinalizedBlockRecord {
                        height: certificate.context.height,
                        block_id: certificate.block_id.clone(),
                        qc_id: certificate.id()?,
                    },
                ))
            })
            .collect::<Result<BTreeMap<_, _>, String>>()?;
        Self::new_internal(
            transition.next_epoch_context().clone(),
            transition.certified_parent().clone(),
            transition_finality_records,
        )
    }

    fn new_internal(
        expected_epoch_context: SimplifiedEpochContext,
        expected_anchor_qc: QuorumCertificateReference,
        transition_finality_records: BTreeMap<u64, FinalizedBlockRecord>,
    ) -> Result<Self, String> {
        expected_epoch_context.validate()?;
        expected_anchor_qc.validate()?;
        if expected_anchor_qc.height.0.checked_add(1)
            != Some(expected_epoch_context.epoch_start_height.0)
        {
            return Err("state-sync stager anchor does not precede the epoch".to_string());
        }
        if let Some(expected) = &expected_epoch_context.v2_boundary_anchor {
            if expected_anchor_qc.height != expected.height
                || expected_anchor_qc.block_id != expected.block_id
                || expected_anchor_qc.qc_id != expected.qc_finality_context_root
            {
                return Err("state-sync stager anchor differs from the pinned boundary".to_string());
            }
        }
        if let Some(expected) = &expected_epoch_context.v3_transition_anchor {
            if expected_anchor_qc.height != expected.certified_parent_height
                || expected_anchor_qc.block_id != expected.certified_parent_block_id
                || expected_anchor_qc.qc_id != expected.certified_parent_qc_id
            {
                return Err(
                    "state-sync stager anchor differs from the pinned v3 certified parent"
                        .to_string(),
                );
            }
        }
        let max_active_sessions = expected_epoch_context
            .leader_ring
            .len()
            .checked_mul(MAX_SIMPLIFIED_STATE_SYNC_SESSIONS_PER_PEER)
            .ok_or_else(|| "state-sync active-session limit overflows".to_string())?;
        Ok(Self {
            expected_epoch_context_root: expected_epoch_context.root()?,
            expected_epoch_context,
            expected_anchor_qc,
            transition_finality_records,
            max_active_sessions,
            outstanding_requests: BTreeMap::new(),
            active: BTreeMap::new(),
            completed: VecDeque::new(),
        })
    }

    pub fn register_request(&mut self, request_id: Hash, now: Instant) -> Result<(), String> {
        if request_id.is_zero() {
            return Err("state-sync request id must be nonzero".to_string());
        }
        self.prune(now);
        if self.outstanding_requests.contains_key(&request_id) {
            return Ok(());
        }
        if self.outstanding_requests.len() >= MAX_SIMPLIFIED_STATE_SYNC_OUTSTANDING_REQUESTS {
            return Err("state-sync outstanding request limit reached".to_string());
        }
        let expires_at = now
            .checked_add(SIMPLIFIED_STATE_SYNC_SESSION_TTL)
            .ok_or_else(|| "state-sync request expiry overflows Instant".to_string())?;
        self.outstanding_requests.insert(request_id, expires_at);
        Ok(())
    }

    pub fn finish_request(&mut self, request_id: Hash, now: Instant) {
        self.prune(now);
        self.outstanding_requests.remove(&request_id);
        self.active
            .retain(|(_, active_request_id), _| *active_request_id != request_id);
    }

    fn prune(&mut self, now: Instant) {
        self.outstanding_requests
            .retain(|_, expires_at| *expires_at > now);
        self.active.retain(|(_, request_id), session| {
            session.expires_at > now && self.outstanding_requests.contains_key(request_id)
        });
        self.completed
            .retain(|(_, _, _, expires_at)| *expires_at > now);
    }

    pub fn accept(
        &mut self,
        peer: &ValidatorId,
        chunk: SimplifiedStateSyncChunk,
        now: Instant,
    ) -> Result<Option<CompletedSimplifiedStateSync>, String> {
        chunk.validate()?;
        self.prune(now);
        if !self.outstanding_requests.contains_key(&chunk.request_id) {
            return Err("state-sync chunk is not correlated to an outstanding request".to_string());
        }
        if self
            .completed
            .iter()
            .any(|(completed_peer, request_id, root, _)| {
                completed_peer == peer
                    && *request_id == chunk.request_id
                    && *root == chunk.session_root
            })
        {
            return Err("completed state-sync session replay rejected".to_string());
        }
        if chunk.epoch_context_root != self.expected_epoch_context_root
            || chunk.anchor_qc != self.expected_anchor_qc
        {
            return Err("state-sync chunk names another epoch or anchor".to_string());
        }
        let key = (peer.clone(), chunk.request_id);
        if !self.active.contains_key(&key) {
            if chunk.sequence != 0 {
                return Err("state-sync session must begin at sequence zero".to_string());
            }
            let peer_sessions = self
                .active
                .keys()
                .filter(|(active_peer, _)| active_peer == peer)
                .count();
            if peer_sessions >= MAX_SIMPLIFIED_STATE_SYNC_SESSIONS_PER_PEER {
                return Err("state-sync peer active-session limit reached".to_string());
            }
            if self.active.len() >= self.max_active_sessions {
                return Err("state-sync global active-session limit reached".to_string());
            }
            let expires_at = now
                .checked_add(SIMPLIFIED_STATE_SYNC_SESSION_TTL)
                .ok_or_else(|| "state-sync session expiry overflows Instant".to_string())?;
            self.active.insert(
                key.clone(),
                StagedSession {
                    request_id: chunk.request_id,
                    session_root: chunk.session_root,
                    epoch_context_root: chunk.epoch_context_root,
                    anchor_qc: chunk.anchor_qc.clone(),
                    next_sequence: 0,
                    previous_chunk_root: None,
                    evidence: Vec::new(),
                    evidence_sequence: EvidenceSequence::new(chunk.anchor_qc.clone())?,
                    staged_bytes: 0,
                    expires_at,
                },
            );
        }
        let staged = self
            .active
            .get(&key)
            .ok_or_else(|| "state-sync session was not installed".to_string())?;
        if staged.request_id != chunk.request_id
            || staged.session_root != chunk.session_root
            || staged.epoch_context_root != chunk.epoch_context_root
            || staged.anchor_qc != chunk.anchor_qc
        {
            return Err("state-sync session peer or immutable identity equivocated".to_string());
        }
        if chunk.sequence != staged.next_sequence
            || chunk.previous_chunk_root != staged.previous_chunk_root
        {
            self.active.remove(&key);
            return Err("state-sync chunk replay, gap, or out-of-order predecessor".to_string());
        }
        let chunk_bytes = chunk.canonical_bytes()?.len();
        let staged_bytes = staged
            .staged_bytes
            .checked_add(chunk_bytes)
            .ok_or_else(|| "state-sync staged byte count overflows".to_string())?;
        let staged_evidence_count = staged
            .evidence
            .len()
            .checked_add(chunk.evidence.len())
            .ok_or_else(|| "state-sync staged evidence count overflows".to_string())?;
        let peer_staged_bytes = self
            .active
            .iter()
            .filter(|((active_peer, _), _)| active_peer == peer)
            .try_fold(0usize, |sum, (_, session)| {
                sum.checked_add(session.staged_bytes)
                    .ok_or_else(|| "state-sync peer staged byte count overflows".to_string())
            })?;
        let global_staged_bytes = self.active.values().try_fold(0usize, |sum, session| {
            sum.checked_add(session.staged_bytes)
                .ok_or_else(|| "state-sync global staged byte count overflows".to_string())
        })?;
        if staged_bytes > MAX_SIMPLIFIED_STATE_SYNC_SESSION_STAGED_BYTES
            || peer_staged_bytes
                .checked_add(chunk_bytes)
                .is_none_or(|bytes| bytes > MAX_SIMPLIFIED_STATE_SYNC_PEER_STAGED_BYTES)
            || global_staged_bytes
                .checked_add(chunk_bytes)
                .is_none_or(|bytes| bytes > MAX_SIMPLIFIED_STATE_SYNC_GLOBAL_STAGED_BYTES)
            || staged_evidence_count > MAX_SIMPLIFIED_STATE_SYNC_EVIDENCE
        {
            self.active.remove(&key);
            return Err("state-sync session exceeded staging bounds".to_string());
        }
        let mut evidence_sequence = staged.evidence_sequence.clone();
        if let Err(error) =
            evidence_sequence.observe_all(&self.expected_epoch_context, &chunk.evidence)
        {
            self.active.remove(&key);
            return Err(error);
        }
        let next_sequence = staged
            .next_sequence
            .checked_add(1)
            .ok_or_else(|| "state-sync sequence overflows".to_string())?;
        let is_final = chunk.final_chunk;
        let claimed_finalized = chunk.claimed_finalized.clone();
        let chunk_root = chunk.chunk_root;
        let chunk_evidence = chunk.evidence;

        let staged = self
            .active
            .get_mut(&key)
            .ok_or_else(|| "state-sync session disappeared before staging".to_string())?;
        staged.staged_bytes = staged_bytes;
        staged.evidence_sequence = evidence_sequence;
        staged.evidence.extend(chunk_evidence);
        staged.next_sequence = next_sequence;
        staged.previous_chunk_root = Some(chunk_root);
        if !is_final {
            return Ok(None);
        }
        let claimed_finalized = claimed_finalized
            .ok_or_else(|| "final state-sync chunk omits finalized claim".to_string())?;
        if claimed_finalized.height.0 <= self.expected_anchor_qc.height.0
            && !self.transition_finality_records.is_empty()
            && self
                .transition_finality_records
                .get(&claimed_finalized.height.0)
                != Some(&claimed_finalized)
        {
            self.active.remove(&key);
            return Err(
                "state-sync finalized claim is not in the receiver's verified transition tail"
                    .to_string(),
            );
        }
        let completed = self
            .active
            .remove(&key)
            .ok_or_else(|| "completed state-sync session disappeared".to_string())?;
        let expected_session_root = session_root(
            completed.request_id,
            completed.epoch_context_root,
            &completed.anchor_qc,
            &completed.evidence,
            &claimed_finalized,
        )?;
        if expected_session_root != completed.session_root {
            return Err("state-sync session transcript root mismatch".to_string());
        }
        let mut qcs = Vec::new();
        let mut tcs = BTreeMap::<u64, Vec<SimplifiedTimeoutCertificate>>::new();
        for item in completed.evidence {
            match item {
                SimplifiedStateSyncEvidence::QuorumCertificate(qc) => qcs.push(qc),
                SimplifiedStateSyncEvidence::TimeoutCertificate(tc) => {
                    tcs.entry(tc.context.height.0).or_default().push(tc);
                }
            }
        }
        let bundle = SimplifiedStateSyncBundle {
            format: POSY_SIMPLIFIED_STATE_SYNC_FORMAT.to_string(),
            epoch_context: self.expected_epoch_context.clone(),
            anchor_qc: self.expected_anchor_qc.clone(),
            certified_qcs: qcs,
            certified_tcs: tcs,
            claimed_finalized,
        };
        validate_export_envelope(&bundle)?;
        let replay_expires_at = now
            .checked_add(SIMPLIFIED_STATE_SYNC_SESSION_TTL)
            .ok_or_else(|| "state-sync replay expiry overflows Instant".to_string())?;
        self.completed.push_back((
            peer.clone(),
            completed.request_id,
            completed.session_root,
            replay_expires_at,
        ));
        while self.completed.len() > MAX_SIMPLIFIED_STATE_SYNC_COMPLETED_SESSIONS {
            self.completed.pop_front();
        }
        Ok(Some(CompletedSimplifiedStateSync {
            request_id: completed.request_id,
            peer: peer.clone(),
            bundle,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::simplified_posy::ParticipantSignature;
    use crate::consensus_parameters::ConsensusParameterRoot;
    use crate::synergy_types::{
        AegisPqKeyId, AegisPqPublicKey, AegisPqSignature, BlockId, ClusterId, Epoch, Height, UmaId,
        ValidatorRecord, ValidatorSet, ValidatorStatus, TESTNET_V3_CONSENSUS_SIGNATURE_ALGORITHM,
        TESTNET_V3_MLDSA65_PUBLIC_KEY_BYTES,
    };

    fn validator_set() -> ValidatorSet {
        ValidatorSet {
            epoch: Epoch(7),
            validators: (0..5)
                .map(|index| {
                    let public_key = AegisPqPublicKey {
                        key_id: AegisPqKeyId(format!("state-sync-key-{index}")),
                        algorithm: TESTNET_V3_CONSENSUS_SIGNATURE_ALGORITHM.to_string(),
                        key_bytes: vec![index as u8 + 1; TESTNET_V3_MLDSA65_PUBLIC_KEY_BYTES],
                    };
                    ValidatorRecord {
                        validator_id: ValidatorId(format!("state-sync-validator-{index}")),
                        validator_uma_id: UmaId(format!("uma:state-sync-validator-{index}")),
                        consensus_public_key: public_key.clone(),
                        peer_public_key: public_key.clone(),
                        operator_public_key: public_key,
                        voting_weight: 1,
                        status: ValidatorStatus::Active,
                        cluster_id: ClusterId(0),
                        activation_epoch: Epoch(7),
                    }
                })
                .collect(),
        }
    }

    fn epoch_context() -> SimplifiedEpochContext {
        SimplifiedEpochContext::derive(
            Epoch(7),
            Height(1_000),
            Height(1_999),
            Hash::from_domain_bytes("state-sync-test-seed", b"epoch-7"),
            ConsensusParameterRoot::from_canonical_manifest_bytes(b"state-sync-test-parameters"),
            &validator_set(),
        )
        .expect("test epoch context should be valid")
    }

    fn anchor_qc() -> QuorumCertificateReference {
        QuorumCertificateReference {
            height: Height(999),
            block_id: BlockId("state-sync-anchor".to_string()),
            qc_id: Hash::from_domain_bytes("state-sync-test-anchor", b"height-999"),
        }
    }

    fn anchor_finalized() -> FinalizedBlockRecord {
        let anchor = anchor_qc();
        FinalizedBlockRecord {
            height: anchor.height,
            block_id: anchor.block_id,
            qc_id: anchor.qc_id,
        }
    }

    fn empty_bundle() -> SimplifiedStateSyncBundle {
        SimplifiedStateSyncBundle {
            format: POSY_SIMPLIFIED_STATE_SYNC_FORMAT.to_string(),
            epoch_context: epoch_context(),
            anchor_qc: anchor_qc(),
            certified_qcs: Vec::new(),
            certified_tcs: BTreeMap::new(),
            claimed_finalized: anchor_finalized(),
        }
    }

    fn test_request_id() -> Hash {
        Hash::from_domain_bytes("state-sync-test-request", b"request-1")
    }

    fn register_test_request(stager: &mut SimplifiedStateSyncStager, now: Instant) {
        stager
            .register_request(test_request_id(), now)
            .expect("test request should register");
    }

    fn uncertified_qc(
        context: &SimplifiedEpochContext,
        height: u64,
        parent_qc: QuorumCertificateReference,
    ) -> SimplifiedQuorumCertificate {
        SimplifiedQuorumCertificate {
            context: super::super::ConsensusObjectContext::for_height(
                context,
                Height(height),
                crate::synergy_types::Round(0),
            )
            .expect("test QC context should be valid"),
            block_id: BlockId(format!("state-sync-block-{height}")),
            parent_block_id: parent_qc.block_id.clone(),
            parent_qc,
            takeover_tc_id: None,
            protected_execution_root: Hash::from_domain_bytes(
                "state-sync-test-execution",
                &height.to_le_bytes(),
            ),
            participants: Vec::new(),
        }
    }

    fn two_chunk_stream() -> (
        SimplifiedEpochContext,
        QuorumCertificateReference,
        Vec<SimplifiedStateSyncChunk>,
    ) {
        let context = epoch_context();
        let anchor = anchor_qc();
        let evidence = vec![SimplifiedStateSyncEvidence::QuorumCertificate(
            uncertified_qc(&context, 1_000, anchor.clone()),
        )];
        let context_root = context.root().expect("test context should hash");
        let request_id = test_request_id();
        let session_root = session_root(
            request_id,
            context_root,
            &anchor,
            &evidence,
            &anchor_finalized(),
        )
        .expect("test session should hash");
        let mut first = SimplifiedStateSyncChunk {
            format: POSY_SIMPLIFIED_STATE_SYNC_CHUNK_FORMAT.to_string(),
            request_id,
            session_root,
            epoch_context_root: context_root,
            anchor_qc: anchor.clone(),
            sequence: 0,
            previous_chunk_root: None,
            evidence,
            final_chunk: false,
            claimed_finalized: None,
            chunk_root: Hash::zero(),
        };
        first.chunk_root = first.computed_root().expect("first chunk should hash");
        let mut final_chunk = SimplifiedStateSyncChunk {
            format: POSY_SIMPLIFIED_STATE_SYNC_CHUNK_FORMAT.to_string(),
            request_id,
            session_root,
            epoch_context_root: context_root,
            anchor_qc: anchor.clone(),
            sequence: 1,
            previous_chunk_root: Some(first.chunk_root),
            evidence: Vec::new(),
            final_chunk: true,
            claimed_finalized: Some(anchor_finalized()),
            chunk_root: Hash::zero(),
        };
        final_chunk.chunk_root = final_chunk
            .computed_root()
            .expect("final chunk should hash");
        (context, anchor, vec![first, final_chunk])
    }

    #[test]
    fn empty_bundle_should_round_trip_through_one_final_chunk() {
        let bundle = empty_bundle();
        let chunks =
            build_state_sync_chunks(&bundle, test_request_id()).expect("empty bundle should chunk");
        let mut stager = SimplifiedStateSyncStager::new(epoch_context(), anchor_qc())
            .expect("stager should initialize");
        let now = Instant::now();
        register_test_request(&mut stager, now);
        let result = stager
            .accept(
                &ValidatorId("state-sync-peer".to_string()),
                chunks.into_iter().next().expect("one chunk should exist"),
                now,
            )
            .expect("complete chunk should stage");

        assert_eq!(result.expect("completed state sync").bundle, bundle);
    }

    #[test]
    fn takeover_authority_persists_across_certified_heights_in_one_lease() {
        let context = epoch_context();
        let timeout_context = super::super::ConsensusObjectContext::for_height(
            &context,
            crate::synergy_types::Height(1_000),
            crate::synergy_types::Round(0),
        )
        .unwrap();
        let timeout = SimplifiedTimeoutCertificate {
            context: timeout_context,
            lease_index: context
                .lease_index(crate::synergy_types::Height(1_000))
                .unwrap(),
            timed_out_proposer: context
                .authorized_proposer(crate::synergy_types::Height(1_000), 0)
                .unwrap()
                .clone(),
            previous_tc_id: None,
            reports: Vec::new(),
            highest_qc_proofs: Vec::new(),
        };
        let timeout_id = timeout.id().unwrap();
        let mut first = uncertified_qc(&context, 1_000, anchor_qc());
        first.context.round = crate::synergy_types::Round(1);
        first.takeover_tc_id = Some(timeout_id);
        let mut second = uncertified_qc(&context, 1_001, first.reference().unwrap());
        second.context.round = crate::synergy_types::Round(1);
        second.takeover_tc_id = Some(timeout_id);
        let bundle = SimplifiedStateSyncBundle {
            format: POSY_SIMPLIFIED_STATE_SYNC_FORMAT.to_string(),
            epoch_context: context,
            anchor_qc: anchor_qc(),
            certified_qcs: vec![first, second],
            certified_tcs: BTreeMap::from([(1_000, vec![timeout])]),
            claimed_finalized: anchor_finalized(),
        };
        let chunks = build_state_sync_chunks(&bundle, test_request_id()).unwrap();
        assert!(!chunks.is_empty());
    }

    #[test]
    fn final_claim_tamper_should_fail_the_session_transcript() {
        let bundle = empty_bundle();
        let mut chunk = build_state_sync_chunks(&bundle, test_request_id())
            .expect("empty bundle should chunk")
            .remove(0);
        chunk
            .claimed_finalized
            .as_mut()
            .expect("final claim should exist")
            .block_id = BlockId("tampered-finalized-block".to_string());
        chunk.chunk_root = chunk.computed_root().expect("tampered chunk should hash");
        let mut stager = SimplifiedStateSyncStager::new(epoch_context(), anchor_qc())
            .expect("stager should initialize");
        let now = Instant::now();
        register_test_request(&mut stager, now);
        let error = stager
            .accept(&ValidatorId("state-sync-peer".to_string()), chunk, now)
            .expect_err("tampered transcript must fail");

        assert!(error.contains("transcript root mismatch"), "{error}");
    }

    #[test]
    fn completed_session_should_reject_immediate_replay() {
        let chunk = build_state_sync_chunks(&empty_bundle(), test_request_id())
            .expect("empty bundle should chunk")
            .remove(0);
        let mut stager = SimplifiedStateSyncStager::new(epoch_context(), anchor_qc())
            .expect("stager should initialize");
        let peer = ValidatorId("state-sync-peer".to_string());
        let now = Instant::now();
        register_test_request(&mut stager, now);
        stager
            .accept(&peer, chunk.clone(), now)
            .expect("first transcript should complete");
        let error = stager
            .accept(&peer, chunk, now)
            .expect_err("completed transcript replay must fail");

        assert!(error.contains("replay rejected"), "{error}");
    }

    #[test]
    fn completed_session_should_allow_replay_after_cache_expiry() {
        let chunk = build_state_sync_chunks(&empty_bundle(), test_request_id())
            .expect("empty bundle should chunk")
            .remove(0);
        let mut stager = SimplifiedStateSyncStager::new(epoch_context(), anchor_qc())
            .expect("stager should initialize");
        let peer = ValidatorId("state-sync-peer".to_string());
        let now = Instant::now();
        register_test_request(&mut stager, now);
        stager
            .accept(&peer, chunk.clone(), now)
            .expect("first transcript should complete");
        let after_expiry = now
            .checked_add(SIMPLIFIED_STATE_SYNC_SESSION_TTL)
            .expect("test Instant should support TTL");
        register_test_request(&mut stager, after_expiry);
        let replay = stager
            .accept(&peer, chunk, after_expiry)
            .expect("expired replay-cache entry should be removed");

        assert!(replay.is_some());
    }

    #[test]
    fn non_final_empty_chunk_should_be_rejected() {
        let mut chunk = build_state_sync_chunks(&empty_bundle(), test_request_id())
            .expect("empty bundle should chunk")
            .remove(0);
        chunk.final_chunk = false;
        chunk.claimed_finalized = None;
        chunk.chunk_root = chunk.computed_root().expect("modified chunk should hash");
        let error = chunk
            .validate()
            .expect_err("empty intermediate chunk must fail");

        assert!(error.contains("cannot be empty"), "{error}");
    }

    #[test]
    fn chunk_should_reject_an_oversized_canonical_payload() {
        let context = epoch_context();
        let anchor = anchor_qc();
        let mut qc = uncertified_qc(&context, 1_000, anchor.clone());
        qc.block_id = BlockId("x".repeat(MAX_SIMPLIFIED_STATE_SYNC_CHUNK_PAYLOAD_BYTES));
        let mut chunk = SimplifiedStateSyncChunk {
            format: POSY_SIMPLIFIED_STATE_SYNC_CHUNK_FORMAT.to_string(),
            request_id: test_request_id(),
            session_root: Hash::from_domain_bytes("state-sync-large-session", b"large"),
            epoch_context_root: context.root().expect("test context should hash"),
            anchor_qc: anchor,
            sequence: 0,
            previous_chunk_root: None,
            evidence: vec![SimplifiedStateSyncEvidence::QuorumCertificate(qc)],
            final_chunk: false,
            claimed_finalized: None,
            chunk_root: Hash::zero(),
        };
        chunk.chunk_root = chunk.computed_root().expect("large chunk should hash");
        let error = chunk
            .validate()
            .expect_err("oversized canonical chunk must fail");

        assert!(error.contains("exceeds"), "{error}");
    }

    #[test]
    fn exporter_should_accept_one_certificate_above_the_old_half_chunk_limit() {
        let context = epoch_context();
        let anchor = anchor_qc();
        let mut qc = uncertified_qc(&context, 1_000, anchor.clone());
        qc.participants.push(ParticipantSignature {
            validator_id: ValidatorId("state-sync-large-proof-validator".to_string()),
            key_id: AegisPqKeyId("state-sync-large-proof-key".to_string()),
            signature: AegisPqSignature {
                algorithm: TESTNET_V3_CONSENSUS_SIGNATURE_ALGORITHM.to_string(),
                // JSON's canonical byte-array representation makes this
                // evidence larger than 96 KiB but still below the real
                // 192 KiB state-sync chunk cap.
                signature_bytes: vec![1; 55_000],
            },
        });
        let item = SimplifiedStateSyncEvidence::QuorumCertificate(qc.clone());
        let item_len = item.canonical_bytes().unwrap().len();
        assert!(item_len > MAX_SIMPLIFIED_STATE_SYNC_CHUNK_PAYLOAD_BYTES / 2);
        let bundle = SimplifiedStateSyncBundle {
            format: POSY_SIMPLIFIED_STATE_SYNC_FORMAT.to_string(),
            epoch_context: context,
            anchor_qc: anchor,
            certified_qcs: vec![qc],
            certified_tcs: BTreeMap::new(),
            claimed_finalized: anchor_finalized(),
        };

        let chunks = build_state_sync_chunks(&bundle, test_request_id())
            .expect("certificate below the exact chunk cap should be streamable");

        assert_eq!(chunks.len(), 1);
        assert!(
            chunks[0].canonical_bytes().unwrap().len()
                <= MAX_SIMPLIFIED_STATE_SYNC_CHUNK_PAYLOAD_BYTES
        );
    }

    #[test]
    fn session_should_reject_a_nonzero_start_sequence() {
        let (context, anchor, mut chunks) = two_chunk_stream();
        let mut stager =
            SimplifiedStateSyncStager::new(context, anchor).expect("stager should initialize");
        register_test_request(&mut stager, Instant::now());
        let error = stager
            .accept(
                &ValidatorId("state-sync-peer".to_string()),
                chunks.remove(1),
                Instant::now(),
            )
            .expect_err("sequence one cannot start a session");

        assert!(error.contains("sequence zero"), "{error}");
    }

    #[test]
    fn session_should_expire_before_accepting_the_next_chunk() {
        let (context, anchor, mut chunks) = two_chunk_stream();
        let mut stager =
            SimplifiedStateSyncStager::new(context, anchor).expect("stager should initialize");
        let peer = ValidatorId("state-sync-peer".to_string());
        let now = Instant::now();
        register_test_request(&mut stager, now);
        stager
            .accept(&peer, chunks.remove(0), now)
            .expect("first chunk should stage");
        let after_expiry = now
            .checked_add(SIMPLIFIED_STATE_SYNC_SESSION_TTL)
            .expect("test Instant should support TTL");
        let error = stager
            .accept(&peer, chunks.remove(0), after_expiry)
            .expect_err("expired session cannot resume");

        assert!(error.contains("outstanding request"), "{error}");
    }

    #[test]
    fn active_session_should_remain_bound_to_its_first_peer() {
        let (context, anchor, mut chunks) = two_chunk_stream();
        let mut stager =
            SimplifiedStateSyncStager::new(context, anchor).expect("stager should initialize");
        let now = Instant::now();
        register_test_request(&mut stager, now);
        stager
            .accept(
                &ValidatorId("state-sync-peer-a".to_string()),
                chunks.remove(0),
                now,
            )
            .expect("first chunk should stage");
        let error = stager
            .accept(
                &ValidatorId("state-sync-peer-b".to_string()),
                chunks.remove(0),
                now,
            )
            .expect_err("another peer cannot splice the session");

        assert!(error.contains("sequence zero"), "{error}");
    }

    #[test]
    fn active_session_should_reject_a_different_predecessor_root() {
        let (context, anchor, mut chunks) = two_chunk_stream();
        let mut stager =
            SimplifiedStateSyncStager::new(context, anchor).expect("stager should initialize");
        let peer = ValidatorId("state-sync-peer".to_string());
        let now = Instant::now();
        register_test_request(&mut stager, now);
        stager
            .accept(&peer, chunks.remove(0), now)
            .expect("first chunk should stage");
        let mut final_chunk = chunks.remove(0);
        final_chunk.previous_chunk_root = Some(Hash::from_domain_bytes(
            "state-sync-wrong-predecessor",
            b"wrong",
        ));
        final_chunk.chunk_root = final_chunk
            .computed_root()
            .expect("modified final chunk should hash");
        let error = stager
            .accept(&peer, final_chunk, now)
            .expect_err("wrong predecessor must fail");

        assert!(error.contains("out-of-order predecessor"), "{error}");
    }

    #[test]
    fn exporter_should_reject_a_qc_that_skips_the_next_height() {
        let mut bundle = empty_bundle();
        bundle.certified_qcs.push(uncertified_qc(
            &bundle.epoch_context,
            1_001,
            bundle.anchor_qc.clone(),
        ));
        let error = build_state_sync_chunks(&bundle, test_request_id())
            .expect_err("nonconsecutive QC evidence must not be chunked");

        assert!(error.contains("not consecutive"), "{error}");
    }

    #[test]
    fn self_consistent_session_should_reject_an_unanchored_finalized_claim() {
        let bundle = empty_bundle();
        let context_root = bundle
            .epoch_context
            .root()
            .expect("test context should hash");
        let bad_finalized = FinalizedBlockRecord {
            height: bundle.anchor_qc.height,
            block_id: BlockId("unanchored-finalized-block".to_string()),
            qc_id: bundle.anchor_qc.qc_id,
        };
        let request_id = test_request_id();
        let session_root = session_root(
            request_id,
            context_root,
            &bundle.anchor_qc,
            &[],
            &bad_finalized,
        )
        .expect("test session should hash");
        let mut chunk = SimplifiedStateSyncChunk {
            format: POSY_SIMPLIFIED_STATE_SYNC_CHUNK_FORMAT.to_string(),
            request_id,
            session_root,
            epoch_context_root: context_root,
            anchor_qc: bundle.anchor_qc.clone(),
            sequence: 0,
            previous_chunk_root: None,
            evidence: Vec::new(),
            final_chunk: true,
            claimed_finalized: Some(bad_finalized),
            chunk_root: Hash::zero(),
        };
        chunk.chunk_root = chunk.computed_root().expect("test chunk should hash");
        let mut stager = SimplifiedStateSyncStager::new(bundle.epoch_context, bundle.anchor_qc)
            .expect("stager should initialize");
        let now = Instant::now();
        register_test_request(&mut stager, now);
        let error = stager
            .accept(&ValidatorId("state-sync-peer".to_string()), chunk, now)
            .expect_err("unanchored finalized claim must fail");

        assert!(error.contains("names no supplied certificate"), "{error}");
    }
}
