//! Request-correlated bounded streaming for simplified proposal material.

use super::{VerifiedSimplifiedProposalMaterial, MAX_POSY_SIMPLIFIED_MATERIAL_RECORD_BYTES};
use crate::synergy_types::{CanonicalSerialize, Hash, ValidatorId};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, VecDeque};
use std::time::{Duration, Instant};

pub const POSY_SIMPLIFIED_MATERIAL_CHUNK_FORMAT: &str = "synergy-posy-simplified-material-chunk-v1";
pub const MAX_SIMPLIFIED_MATERIAL_CHUNK_PAYLOAD_BYTES: usize = 48 * 1024;
pub const MAX_SIMPLIFIED_MATERIAL_CHUNKS: u32 = 512;
pub const MAX_SIMPLIFIED_MATERIAL_SYNC_SESSIONS: usize = 8;
pub const MAX_SIMPLIFIED_MATERIAL_SYNC_SESSIONS_PER_PEER: usize = 2;
pub const MAX_SIMPLIFIED_MATERIAL_SYNC_OUTSTANDING_REQUESTS: usize = 4;
pub const MAX_SIMPLIFIED_MATERIAL_SYNC_GLOBAL_STAGED_BYTES: usize = 64 * 1024 * 1024;
pub const SIMPLIFIED_MATERIAL_SYNC_SESSION_TTL: Duration = Duration::from_secs(30);
const MAX_COMPLETED_MATERIAL_REQUESTS: usize = 32;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SimplifiedMaterialChunk {
    pub format: String,
    pub request_id: Hash,
    pub epoch_context_root: Hash,
    pub stable_candidate_id: Hash,
    pub record_root: Hash,
    pub sequence: u32,
    pub total_chunks: u32,
    pub previous_chunk_root: Option<Hash>,
    pub payload: Vec<u8>,
    pub chunk_root: Hash,
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct MaterialChunkSubject {
    format: String,
    request_id: Hash,
    epoch_context_root: Hash,
    stable_candidate_id: Hash,
    record_root: Hash,
    sequence: u32,
    total_chunks: u32,
    previous_chunk_root: Option<Hash>,
    payload: Vec<u8>,
}

impl SimplifiedMaterialChunk {
    fn subject(&self) -> MaterialChunkSubject {
        MaterialChunkSubject {
            format: self.format.clone(),
            request_id: self.request_id,
            epoch_context_root: self.epoch_context_root,
            stable_candidate_id: self.stable_candidate_id,
            record_root: self.record_root,
            sequence: self.sequence,
            total_chunks: self.total_chunks,
            previous_chunk_root: self.previous_chunk_root,
            payload: self.payload.clone(),
        }
    }

    pub fn computed_root(&self) -> Result<Hash, String> {
        Ok(Hash::from_domain_bytes(
            "SYNERGY_POSY_SIMPLIFIED_MATERIAL_CHUNK_V1",
            &self.subject().canonical_bytes()?,
        ))
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.format != POSY_SIMPLIFIED_MATERIAL_CHUNK_FORMAT
            || self.request_id.is_zero()
            || self.epoch_context_root.is_zero()
            || self.stable_candidate_id.is_zero()
            || self.record_root.is_zero()
            || self.total_chunks == 0
            || self.total_chunks > MAX_SIMPLIFIED_MATERIAL_CHUNKS
            || self.sequence >= self.total_chunks
            || self.payload.is_empty()
            || self.payload.len() > MAX_SIMPLIFIED_MATERIAL_CHUNK_PAYLOAD_BYTES
            || self.chunk_root != self.computed_root()?
        {
            return Err("invalid simplified proposal-material chunk".to_string());
        }
        if self.sequence == 0 && self.previous_chunk_root.is_some()
            || self.sequence > 0
                && self
                    .previous_chunk_root
                    .is_none_or(crate::synergy_types::Hash::is_zero)
        {
            return Err("proposal-material chunk predecessor is invalid".to_string());
        }
        Ok(())
    }
}

pub fn build_material_chunks(
    record: &VerifiedSimplifiedProposalMaterial,
    request_id: Hash,
) -> Result<Vec<SimplifiedMaterialChunk>, String> {
    record.validate(record.epoch_context_root)?;
    if request_id.is_zero() {
        return Err("proposal-material request id is zero".to_string());
    }
    let bytes = record.canonical_bytes()?;
    if bytes.is_empty() || bytes.len() > MAX_POSY_SIMPLIFIED_MATERIAL_RECORD_BYTES {
        return Err("proposal-material record violates its stream bound".to_string());
    }
    let chunk_count = bytes
        .len()
        .checked_add(MAX_SIMPLIFIED_MATERIAL_CHUNK_PAYLOAD_BYTES - 1)
        .ok_or_else(|| "proposal-material chunk count overflowed".to_string())?
        / MAX_SIMPLIFIED_MATERIAL_CHUNK_PAYLOAD_BYTES;
    let total_chunks = u32::try_from(chunk_count)
        .map_err(|_| "proposal-material chunk count exceeds u32".to_string())?;
    if total_chunks == 0 || total_chunks > MAX_SIMPLIFIED_MATERIAL_CHUNKS {
        return Err("proposal-material requires too many chunks".to_string());
    }
    let record_root = Hash::from_domain_bytes("SYNERGY_POSY_SIMPLIFIED_MATERIAL_RECORD_V1", &bytes);
    let mut chunks = Vec::with_capacity(chunk_count);
    let mut previous_chunk_root = None;
    for (index, payload) in bytes
        .chunks(MAX_SIMPLIFIED_MATERIAL_CHUNK_PAYLOAD_BYTES)
        .enumerate()
    {
        let sequence = u32::try_from(index)
            .map_err(|_| "proposal-material chunk index exceeds u32".to_string())?;
        let mut chunk = SimplifiedMaterialChunk {
            format: POSY_SIMPLIFIED_MATERIAL_CHUNK_FORMAT.to_string(),
            request_id,
            epoch_context_root: record.epoch_context_root,
            stable_candidate_id: record.stable_candidate_id,
            record_root,
            sequence,
            total_chunks,
            previous_chunk_root,
            payload: payload.to_vec(),
            chunk_root: Hash::zero(),
        };
        chunk.chunk_root = chunk.computed_root()?;
        previous_chunk_root = Some(chunk.chunk_root);
        chunks.push(chunk);
    }
    Ok(chunks)
}

#[derive(Debug, Clone)]
struct OutstandingMaterialRequest {
    stable_candidate_id: Hash,
    expected_peer: ValidatorId,
    registered_at: Instant,
}

#[derive(Debug, Clone)]
struct MaterialSession {
    peer: ValidatorId,
    epoch_context_root: Hash,
    stable_candidate_id: Hash,
    record_root: Hash,
    total_chunks: u32,
    next_sequence: u32,
    previous_chunk_root: Option<Hash>,
    bytes: Vec<u8>,
    last_activity: Instant,
}

#[derive(Debug, Clone)]
pub struct SimplifiedMaterialStager {
    epoch_context_root: Hash,
    outstanding: BTreeMap<Hash, OutstandingMaterialRequest>,
    sessions: BTreeMap<Hash, MaterialSession>,
    completed: BTreeMap<Hash, Instant>,
    completed_order: VecDeque<Hash>,
}

impl SimplifiedMaterialStager {
    pub fn new(epoch_context_root: Hash) -> Result<Self, String> {
        if epoch_context_root.is_zero() {
            return Err("proposal-material stager requires an epoch root".to_string());
        }
        Ok(Self {
            epoch_context_root,
            outstanding: BTreeMap::new(),
            sessions: BTreeMap::new(),
            completed: BTreeMap::new(),
            completed_order: VecDeque::new(),
        })
    }

    pub fn register_request(
        &mut self,
        request_id: Hash,
        stable_candidate_id: Hash,
        expected_peer: &ValidatorId,
        now: Instant,
    ) -> Result<(), String> {
        self.expire(now);
        if request_id.is_zero()
            || stable_candidate_id.is_zero()
            || expected_peer.0.trim().is_empty()
        {
            return Err("proposal-material request identity is zero".to_string());
        }
        if self.completed.contains_key(&request_id) {
            return Err("proposal-material request was already completed".to_string());
        }
        if let Some(existing) = self.outstanding.get(&request_id) {
            return if existing.stable_candidate_id == stable_candidate_id
                && &existing.expected_peer == expected_peer
            {
                Ok(())
            } else {
                Err("proposal-material request id was reused".to_string())
            };
        }
        if self.outstanding.len() >= MAX_SIMPLIFIED_MATERIAL_SYNC_OUTSTANDING_REQUESTS {
            return Err("proposal-material outstanding request limit reached".to_string());
        }
        self.outstanding.insert(
            request_id,
            OutstandingMaterialRequest {
                stable_candidate_id,
                expected_peer: expected_peer.clone(),
                registered_at: now,
            },
        );
        Ok(())
    }

    pub fn finish_request(&mut self, request_id: Hash) {
        self.outstanding.remove(&request_id);
        self.sessions.remove(&request_id);
    }

    pub fn has_outstanding(&mut self, request_id: Hash, now: Instant) -> bool {
        self.expire(now);
        self.outstanding.contains_key(&request_id)
    }

    pub fn accept(
        &mut self,
        peer: &ValidatorId,
        chunk: SimplifiedMaterialChunk,
        now: Instant,
    ) -> Result<Option<VerifiedSimplifiedProposalMaterial>, String> {
        self.expire(now);
        chunk.validate()?;
        if chunk.epoch_context_root != self.epoch_context_root {
            return Err("proposal-material chunk names another epoch".to_string());
        }
        let request = self
            .outstanding
            .get(&chunk.request_id)
            .ok_or_else(|| "unsolicited proposal-material chunk".to_string())?;
        if request.stable_candidate_id != chunk.stable_candidate_id {
            return Err("proposal-material response names another candidate".to_string());
        }
        if &request.expected_peer != peer {
            return Err("proposal-material response came from another peer".to_string());
        }
        if !self.sessions.contains_key(&chunk.request_id) {
            let peer_sessions = self
                .sessions
                .values()
                .filter(|session| &session.peer == peer)
                .count();
            if self.sessions.len() >= MAX_SIMPLIFIED_MATERIAL_SYNC_SESSIONS
                || peer_sessions >= MAX_SIMPLIFIED_MATERIAL_SYNC_SESSIONS_PER_PEER
                || chunk.sequence != 0
            {
                return Err("proposal-material session admission rejected".to_string());
            }
            self.sessions.insert(
                chunk.request_id,
                MaterialSession {
                    peer: peer.clone(),
                    epoch_context_root: chunk.epoch_context_root,
                    stable_candidate_id: chunk.stable_candidate_id,
                    record_root: chunk.record_root,
                    total_chunks: chunk.total_chunks,
                    next_sequence: 0,
                    previous_chunk_root: None,
                    bytes: Vec::new(),
                    last_activity: now,
                },
            );
        }
        let staged_without_current = self
            .sessions
            .iter()
            .filter(|(request_id, _)| **request_id != chunk.request_id)
            .try_fold(0usize, |total, (_, session)| {
                total.checked_add(session.bytes.len())
            })
            .ok_or_else(|| "proposal-material staged byte count overflowed".to_string())?;
        let session = self
            .sessions
            .get_mut(&chunk.request_id)
            .ok_or_else(|| "proposal-material session disappeared".to_string())?;
        if &session.peer != peer
            || session.epoch_context_root != chunk.epoch_context_root
            || session.stable_candidate_id != chunk.stable_candidate_id
            || session.record_root != chunk.record_root
            || session.total_chunks != chunk.total_chunks
            || session.next_sequence != chunk.sequence
            || session.previous_chunk_root != chunk.previous_chunk_root
        {
            return Err("proposal-material session transcript changed".to_string());
        }
        let next_session_bytes = session
            .bytes
            .len()
            .checked_add(chunk.payload.len())
            .ok_or_else(|| "proposal-material session byte count overflowed".to_string())?;
        let next_global_bytes = staged_without_current
            .checked_add(next_session_bytes)
            .ok_or_else(|| "proposal-material global byte count overflowed".to_string())?;
        if next_session_bytes > MAX_POSY_SIMPLIFIED_MATERIAL_RECORD_BYTES
            || next_global_bytes > MAX_SIMPLIFIED_MATERIAL_SYNC_GLOBAL_STAGED_BYTES
        {
            return Err("proposal-material staged byte budget exceeded".to_string());
        }
        session.bytes.extend_from_slice(&chunk.payload);
        session.next_sequence = session
            .next_sequence
            .checked_add(1)
            .ok_or_else(|| "proposal-material sequence overflowed".to_string())?;
        session.previous_chunk_root = Some(chunk.chunk_root);
        session.last_activity = now;
        if session.next_sequence != session.total_chunks {
            return Ok(None);
        }
        let session = self
            .sessions
            .remove(&chunk.request_id)
            .ok_or_else(|| "completed proposal-material session disappeared".to_string())?;
        let record_root =
            Hash::from_domain_bytes("SYNERGY_POSY_SIMPLIFIED_MATERIAL_RECORD_V1", &session.bytes);
        if record_root != session.record_root {
            return Err("proposal-material record transcript root mismatch".to_string());
        }
        let record = VerifiedSimplifiedProposalMaterial::from_canonical_bytes(
            &session.bytes,
            self.epoch_context_root,
        )?;
        if record.stable_candidate_id != session.stable_candidate_id {
            return Err("proposal-material record names another candidate".to_string());
        }
        self.outstanding.remove(&chunk.request_id);
        self.completed.insert(chunk.request_id, now);
        self.completed_order.push_back(chunk.request_id);
        while self.completed_order.len() > MAX_COMPLETED_MATERIAL_REQUESTS {
            if let Some(oldest) = self.completed_order.pop_front() {
                self.completed.remove(&oldest);
            }
        }
        Ok(Some(record))
    }

    fn expire(&mut self, now: Instant) {
        let expired = |timestamp: Instant| {
            now.saturating_duration_since(timestamp) >= SIMPLIFIED_MATERIAL_SYNC_SESSION_TTL
        };
        self.outstanding
            .retain(|_, request| !expired(request.registered_at));
        self.sessions.retain(|request_id, session| {
            self.outstanding.contains_key(request_id) && !expired(session.last_activity)
        });
        self.completed.retain(|_, timestamp| !expired(*timestamp));
        self.completed_order
            .retain(|request_id| self.completed.contains_key(request_id));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chunk(
        request_id: Hash,
        epoch_context_root: Hash,
        stable_candidate_id: Hash,
        record_root: Hash,
        sequence: u32,
        total_chunks: u32,
        previous_chunk_root: Option<Hash>,
        payload: &[u8],
    ) -> SimplifiedMaterialChunk {
        let mut chunk = SimplifiedMaterialChunk {
            format: POSY_SIMPLIFIED_MATERIAL_CHUNK_FORMAT.to_string(),
            request_id,
            epoch_context_root,
            stable_candidate_id,
            record_root,
            sequence,
            total_chunks,
            previous_chunk_root,
            payload: payload.to_vec(),
            chunk_root: Hash::zero(),
        };
        chunk.chunk_root = chunk.computed_root().expect("material chunk root");
        chunk
    }

    #[test]
    fn material_stager_rejects_first_chunk_from_an_unrequested_peer() {
        let epoch_root = Hash::from_domain_bytes("material-stager-test", b"epoch");
        let candidate_id = Hash::from_domain_bytes("material-stager-test", b"candidate");
        let request_id = Hash::from_domain_bytes("material-stager-test", b"request");
        let expected_peer = ValidatorId("expected-material-peer".to_string());
        let wrong_peer = ValidatorId("wrong-material-peer".to_string());
        let payload = b"first of two material chunks";
        let first = chunk(
            request_id,
            epoch_root,
            candidate_id,
            Hash::from_domain_bytes("material-stager-test", b"record"),
            0,
            2,
            None,
            payload,
        );
        let now = Instant::now();
        let mut stager = SimplifiedMaterialStager::new(epoch_root).expect("material stager");
        stager
            .register_request(request_id, candidate_id, &expected_peer, now)
            .expect("register expected peer");

        assert!(stager.accept(&wrong_peer, first.clone(), now).is_err());
        assert!(stager
            .accept(&expected_peer, first, now)
            .expect("expected peer remains admissible")
            .is_none());
    }

    #[test]
    fn material_stager_rejects_truncation_without_consuming_the_request() {
        let epoch_root = Hash::from_domain_bytes("material-truncation-test", b"epoch");
        let candidate_id = Hash::from_domain_bytes("material-truncation-test", b"candidate");
        let request_id = Hash::from_domain_bytes("material-truncation-test", b"request");
        let expected_peer = ValidatorId("truncation-material-peer".to_string());
        let first_payload = b"complete first half";
        let second_payload = b"complete second half";
        let mut complete = first_payload.to_vec();
        complete.extend_from_slice(second_payload);
        let record_root =
            Hash::from_domain_bytes("SYNERGY_POSY_SIMPLIFIED_MATERIAL_RECORD_V1", &complete);
        let first = chunk(
            request_id,
            epoch_root,
            candidate_id,
            record_root,
            0,
            2,
            None,
            first_payload,
        );
        let truncated = chunk(
            request_id,
            epoch_root,
            candidate_id,
            record_root,
            1,
            2,
            Some(first.chunk_root),
            &second_payload[..second_payload.len() - 1],
        );
        let now = Instant::now();
        let mut stager = SimplifiedMaterialStager::new(epoch_root).expect("material stager");
        stager
            .register_request(request_id, candidate_id, &expected_peer, now)
            .expect("register material request");
        assert!(stager
            .accept(&expected_peer, first.clone(), now)
            .expect("stage first chunk")
            .is_none());

        assert!(stager.accept(&expected_peer, truncated, now).is_err());
        assert!(stager.has_outstanding(request_id, now));
        assert!(stager
            .accept(&expected_peer, first, now)
            .expect("request remains retryable from sequence zero")
            .is_none());
    }

    #[test]
    fn material_chunk_rejects_payload_above_the_per_chunk_bound() {
        let request_id = Hash::from_domain_bytes("material-oversize-test", b"request");
        let epoch_root = Hash::from_domain_bytes("material-oversize-test", b"epoch");
        let candidate_id = Hash::from_domain_bytes("material-oversize-test", b"candidate");
        let oversized = vec![7; MAX_SIMPLIFIED_MATERIAL_CHUNK_PAYLOAD_BYTES + 1];
        let chunk = chunk(
            request_id,
            epoch_root,
            candidate_id,
            Hash::from_domain_bytes("material-oversize-test", b"record"),
            0,
            1,
            None,
            &oversized,
        );

        assert!(chunk.validate().is_err());
    }
}
