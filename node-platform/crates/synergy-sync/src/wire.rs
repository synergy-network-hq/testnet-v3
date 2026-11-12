use serde::{Deserialize, Serialize};
use synergy_crypto::Hash32;
use synergy_execution::ExecutionCandidate;

use crate::HeadClaim;

/// One-block bounded request anchored to the caller's local finalized tip.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalizedCandidateRequest {
    pub height: u64,
    pub expected_parent_id: String,
}

impl FinalizedCandidateRequest {
    pub fn validate(&self) -> bool {
        self.height > 0 && !self.expected_parent_id.trim().is_empty()
    }
}

/// Complete candidate data plus the three-QC witness that finalized it.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalizedCandidateResponse<W = synergy_state::WorldState> {
    pub request: FinalizedCandidateRequest,
    pub candidate: ExecutionCandidate<W>,
    pub finality_witness: Vec<u8>,
    /// Native asynchronous replay inputs and exact ECHO certificate. Legacy
    /// responses omit the field, preserving their existing wire encoding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub processing_replay: Option<Vec<u8>>,
}

/// Bounded request for one authenticated snapshot chunk. The first request
/// identifies a PoSy-verified finalized block; subsequent requests also pin the
/// signed snapshot root learned from the verified manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotChunkRequest {
    pub epoch: u64,
    pub height: u64,
    pub finalized_block_id: String,
    pub finality_evidence_id: String,
    pub expected_snapshot_root: Option<Hash32>,
    pub index: u64,
}

impl SnapshotChunkRequest {
    pub fn validate(&self) -> bool {
        self.epoch > 0
            && self.height > 0
            && !self.finalized_block_id.trim().is_empty()
            && self.finalized_block_id.len() <= 256
            && !self.finality_evidence_id.trim().is_empty()
            && self.finality_evidence_id.len() <= 256
    }
}

/// One authenticated snapshot chunk response. The complete manifest is
/// repeated on every response so a resumed transfer can validate its finalized
/// authority anchor before accepting any chunk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotChunkResponse {
    pub request: SnapshotChunkRequest,
    pub manifest: synergy_snapshot::SnapshotManifest,
    pub chunk: synergy_snapshot::SnapshotChunk,
}

impl SnapshotChunkResponse {
    pub fn validate(&self) -> Result<(), String> {
        if !self.request.validate()
            || self.manifest.epoch != self.request.epoch
            || self.manifest.height != self.request.height
            || self.manifest.finalized_block_id != self.request.finalized_block_id
            || self.manifest.finality_evidence_id != self.request.finality_evidence_id
            || self
                .request
                .expected_snapshot_root
                .is_some_and(|root| root != self.manifest.state_root)
            || self.chunk.index != self.request.index
            || self.chunk.index >= self.manifest.chunk_hashes.len() as u64
            || self.chunk.bytes.is_empty()
            || self.chunk.bytes.len() > self.manifest.chunk_size as usize
            || self.chunk.hash != self.manifest.chunk_hashes[self.chunk.index as usize]
        {
            return Err("snapshot chunk response is not bound to its request".into());
        }
        self.manifest.validate_shape()
    }
}

/// Request for the trust-root-signed authority binding that immediately follows
/// the caller's locally verified, epoch-closing PoSy finality record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EpochAuthorityRequest {
    pub current_epoch: u64,
    pub current_epoch_context_root: String,
    pub finalized_height: u64,
    pub finalized_block_id: String,
    pub finality_evidence_id: String,
}

impl EpochAuthorityRequest {
    pub fn validate(&self) -> bool {
        // PoSy v3 epoch roots and QC subject IDs are canonical 32-byte hashes.
        fn is_posy_hash(value: &str) -> bool {
            value.len() == 64
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        }

        self.current_epoch > 0
            && is_posy_hash(&self.current_epoch_context_root)
            && self.finalized_height > 0
            && !self.finalized_block_id.trim().is_empty()
            && self.finalized_block_id.len() <= 256
            && is_posy_hash(&self.finality_evidence_id)
    }
}

/// The next frozen authority binding. The authenticated transport identifies
/// the source; the binding still requires the configured Aegis trust-root
/// signature and an exact match to local epoch-closing PoSy finality.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EpochAuthorityResponse {
    pub request: EpochAuthorityRequest,
    pub next_authority_binding: Vec<u8>,
}

impl EpochAuthorityResponse {
    pub fn validate(&self) -> bool {
        self.request.validate()
            && !self.next_authority_binding.is_empty()
            && self.next_authority_binding.len() <= 1024 * 1024
    }
}

/// Authenticated Sync protocol messages. Semantic verification remains with
/// Sync, PoSy, and Execution owners rather than the transport adapter.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "body", rename_all = "snake_case")]
pub enum SyncWireMessage<W = synergy_state::WorldState> {
    Head(HeadClaim),
    FinalizedCandidateRequest(FinalizedCandidateRequest),
    /// Explicit capability: requester can assemble bounded multi-frame responses.
    FinalizedCandidateRequestV2(FinalizedCandidateRequest),
    FinalizedCandidateChunk(crate::CandidateResponseChunk),
    FinalizedCandidateResponse(FinalizedCandidateResponse<W>),
    SnapshotChunkRequest(SnapshotChunkRequest),
    SnapshotChunkResponse(SnapshotChunkResponse),
    EpochAuthorityRequest(EpochAuthorityRequest),
    EpochAuthorityResponse(EpochAuthorityResponse),
}

pub type BudgetedFinalizedCandidateResponse =
    FinalizedCandidateResponse<synergy_state::world_resources::BudgetedWorld>;
pub type BudgetedSyncWireMessage = SyncWireMessage<synergy_state::world_resources::BudgetedWorld>;
impl<W: Clone> Clone for FinalizedCandidateResponse<W> {
    fn clone(&self) -> Self {
        Self {
            request: self.request.clone(),
            candidate: self.candidate.clone(),
            finality_witness: self.finality_witness.clone(),
            processing_replay: self.processing_replay.clone(),
        }
    }
}
impl<W: Clone> Clone for SyncWireMessage<W> {
    fn clone(&self) -> Self {
        match self {
            Self::Head(v) => Self::Head(v.clone()),
            Self::FinalizedCandidateRequest(v) => Self::FinalizedCandidateRequest(v.clone()),
            Self::FinalizedCandidateRequestV2(v) => Self::FinalizedCandidateRequestV2(v.clone()),
            Self::FinalizedCandidateChunk(v) => Self::FinalizedCandidateChunk(v.clone()),
            Self::FinalizedCandidateResponse(v) => Self::FinalizedCandidateResponse(v.clone()),
            Self::SnapshotChunkRequest(v) => Self::SnapshotChunkRequest(v.clone()),
            Self::SnapshotChunkResponse(v) => Self::SnapshotChunkResponse(v.clone()),
            Self::EpochAuthorityRequest(v) => Self::EpochAuthorityRequest(v.clone()),
            Self::EpochAuthorityResponse(v) => Self::EpochAuthorityResponse(v.clone()),
        }
    }
}

use std::{fmt, ops::Deref, sync::Arc};
use synergy_execution::{decode_budgeted_candidate, CandidateResourceError};
use synergy_state::world_resources::{
    borrow_json_object_field, JsonObjectField, WorldResourceBudget, WorldResourceError,
    WorldResourcePermit,
};

/// An owned decoded message and the reservation covering its non-World envelope.
/// Keep this owner alive while using its contents. There is deliberately no
/// Clone or consuming bare-value accessor.
#[derive(Debug)]
pub struct DecodedBudgetedSync<T> {
    value: T,
    metadata: WorldResourcePermit,
}
impl<T> Deref for DecodedBudgetedSync<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.value
    }
}
impl<T: Serialize> Serialize for DecodedBudgetedSync<T> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.value.serialize(serializer)
    }
}
impl<T> DecodedBudgetedSync<T> {
    pub fn metadata_bytes(&self) -> usize {
        self.metadata.bytes()
    }
    /// A caller moving fields must carry the permit with the moved envelope.
    pub fn into_parts(self) -> (T, WorldResourcePermit) {
        (self.value, self.metadata)
    }
}
#[derive(Debug)]
pub enum SyncResourceError {
    Resource(WorldResourceError),
    Candidate(CandidateResourceError),
    Decode(String),
}
impl fmt::Display for SyncResourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Resource(e) => write!(f, "{e}"),
            Self::Candidate(e) => write!(f, "{e}"),
            Self::Decode(e) => write!(f, "invalid Sync envelope: {e}"),
        }
    }
}
impl std::error::Error for SyncResourceError {}
impl From<WorldResourceError> for SyncResourceError {
    fn from(e: WorldResourceError) -> Self {
        Self::Resource(e)
    }
}
impl From<CandidateResourceError> for SyncResourceError {
    fn from(e: CandidateResourceError) -> Self {
        match e {
            CandidateResourceError::Resource(e) => Self::Resource(e),
            other => Self::Candidate(other),
        }
    }
}
fn decode_error(e: impl fmt::Display) -> SyncResourceError {
    SyncResourceError::Decode(e.to_string())
}
fn checked_add(a: usize, b: usize) -> Result<usize, SyncResourceError> {
    a.checked_add(b)
        .ok_or(WorldResourceError::ArithmeticOverflow.into())
}
fn scanner_reservation(
    bytes: &[u8],
    budget: &Arc<WorldResourceBudget>,
) -> Result<WorldResourcePermit, SyncResourceError> {
    if bytes.len() > crate::MAX_CANDIDATE_RESPONSE_BYTES {
        return Err(WorldResourceError::Capacity {
            requested: bytes.len(),
            limit: crate::MAX_CANDIDATE_RESPONSE_BYTES,
        }
        .into());
    }
    let amount = bytes
        .len()
        .checked_mul(3)
        .and_then(|n| n.checked_add(4096))
        .ok_or(WorldResourceError::ArithmeticOverflow)?;
    Ok(budget.reserve(amount)?)
}

/// Conservative native Sync envelope allocation count. Scalars reserve twice
/// the fixed 32-byte hash-vector element plus growth/alignment allowance;
/// objects reserve their inline struct size and strings their owned capacity.
/// The scanner uses no retained JSON tree. Caller holds parser scratch first.
fn metadata_charge(bytes: &[u8]) -> Result<usize, SyncResourceError> {
    use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};
    struct Seed<'a>(&'a mut usize);
    impl Seed<'_> {
        fn add<E: serde::de::Error>(&mut self, n: usize) -> Result<(), E> {
            *self.0 = self
                .0
                .checked_add(n)
                .ok_or_else(|| E::custom("Sync resource overflow"))?;
            Ok(())
        }
    }
    impl<'de> DeserializeSeed<'de> for Seed<'_> {
        type Value = ();
        fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
            d.deserialize_any(self)
        }
    }
    impl<'de> Visitor<'de> for Seed<'_> {
        type Value = ();
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("Sync metadata")
        }
        fn visit_map<A: MapAccess<'de>>(mut self, mut map: A) -> Result<(), A::Error> {
            self.add(4096)?;
            while map.next_key::<serde::de::IgnoredAny>()?.is_some() {
                map.next_value_seed(Seed(self.0))?;
            }
            Ok(())
        }
        fn visit_seq<A: SeqAccess<'de>>(mut self, mut seq: A) -> Result<(), A::Error> {
            self.add(128)?;
            while seq.next_element_seed(Seed(self.0))?.is_some() {}
            Ok(())
        }
        fn visit_str<E: serde::de::Error>(mut self, v: &str) -> Result<(), E> {
            self.add(
                v.len()
                    .checked_mul(2)
                    .and_then(|n| n.checked_add(128))
                    .ok_or_else(|| E::custom("Sync string resource overflow"))?,
            )
        }
        fn visit_u64<E: serde::de::Error>(mut self, _: u64) -> Result<(), E> {
            self.add(128)
        }
        fn visit_i64<E: serde::de::Error>(mut self, _: i64) -> Result<(), E> {
            self.add(128)
        }
        fn visit_f64<E: serde::de::Error>(mut self, _: f64) -> Result<(), E> {
            self.add(128)
        }
        fn visit_bool<E: serde::de::Error>(mut self, _: bool) -> Result<(), E> {
            self.add(128)
        }
        fn visit_unit<E: serde::de::Error>(mut self) -> Result<(), E> {
            self.add(128)
        }
    }
    let mut count = 4096;
    let mut de = serde_json::Deserializer::from_slice(bytes);
    Seed(&mut count)
        .deserialize(&mut de)
        .map_err(decode_error)?;
    de.end().map_err(decode_error)?;
    Ok(count)
}
fn required_field<'a>(
    bytes: &'a [u8],
    field: JsonObjectField,
    budget: &Arc<WorldResourceBudget>,
) -> Result<&'a [u8], SyncResourceError> {
    borrow_json_object_field(bytes, field, budget)?
        .ok_or_else(|| decode_error("missing envelope field"))
}

/// These fields decode to Vec<u8>, not arbitrary JSON trees. Each decoded
/// element occupies one byte; geometric Vec growth is bounded by twice the
/// element count. The encoded length is an upper bound on that count, even
/// for whitespace-heavy input. Reserve before serde allocates the vector.
fn byte_vector_charge(bytes: &[u8]) -> Result<usize, SyncResourceError> {
    checked_add(checked_add(bytes.len(), bytes.len())?, 128)
}

/// Decode exact candidate bytes through Execution's authenticated budgeted
/// decoder. Input bytes themselves remain the caller's separately owned charge.
/// Candidate non-World retained fields retain their existing transport limits;
/// this permit covers only the outer request/witness envelope.
pub fn decode_budgeted_candidate_response(
    bytes: &[u8],
    budget: &Arc<WorldResourceBudget>,
) -> Result<DecodedBudgetedSync<BudgetedFinalizedCandidateResponse>, SyncResourceError> {
    let mut metadata = scanner_reservation(bytes, budget)?;
    let candidate = required_field(bytes, JsonObjectField::Candidate, budget)?;
    let request = required_field(bytes, JsonObjectField::Request, budget)?;
    let witness = required_field(bytes, JsonObjectField::FinalityWitness, budget)?;
    let replay = borrow_json_object_field(bytes, JsonObjectField::ProcessingReplay, budget)?;
    let owned = checked_add(
        checked_add(metadata_charge(request)?, byte_vector_charge(witness)?)?,
        replay.map(byte_vector_charge).transpose()?.unwrap_or(0),
    )?;
    metadata.resize(checked_add(metadata.bytes(), owned)?)?;
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Envelope {
        request: FinalizedCandidateRequest,
        candidate: serde::de::IgnoredAny,
        finality_witness: Vec<u8>,
        #[serde(default)]
        processing_replay: Option<Vec<u8>>,
    }
    let envelope: Envelope = serde_json::from_slice(bytes).map_err(decode_error)?;
    let _ = envelope.candidate;
    // Native witness/transport bounds are unchanged, checked before native
    // verification as in the existing chunk assembly boundary.
    if envelope.finality_witness.len() > crate::MAX_CANDIDATE_WITNESS_BYTES {
        return Err(decode_error(
            "candidate finality witness exceeds transport bound",
        ));
    }
    if envelope
        .processing_replay
        .as_ref()
        .is_some_and(|v| v.len() > 16 * 1024 * 1024)
    {
        return Err(decode_error("processing replay exceeds transport bound"));
    }
    let candidate = decode_budgeted_candidate(candidate, budget)?;
    metadata.resize(owned)?;
    Ok(DecodedBudgetedSync {
        value: FinalizedCandidateResponse {
            request: envelope.request,
            candidate,
            finality_witness: envelope.finality_witness,
            processing_replay: envelope.processing_replay,
        },
        metadata,
    })
}

// Head witnesses are opaque byte vectors, not retained JSON value trees.
// Validate their native shape and the existing 1 MiB owner limit without
// materializing the vector, then reserve the actual typed envelope allocation.
fn preflight_head(bytes: &[u8]) -> Result<(), SyncResourceError> {
    use serde::de::{SeqAccess, Visitor};
    struct Witness;
    impl<'de> Deserialize<'de> for Witness {
        fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            struct Bytes;
            impl<'de> Visitor<'de> for Bytes {
                type Value = Witness;
                fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                    f.write_str("a bounded array of witness bytes")
                }
                fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Witness, A::Error> {
                    let mut count = 0usize;
                    while seq.next_element::<u8>()?.is_some() {
                        count += 1;
                        if count > 1024 * 1024 {
                            return Err(serde::de::Error::custom(
                                "head finality witness exceeds transport bound",
                            ));
                        }
                    }
                    Ok(Witness)
                }
            }
            d.deserialize_seq(Bytes)
        }
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "snake_case")]
    enum HeadKind {
        Head,
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    #[allow(dead_code)]
    struct Head {
        peer_id: serde::de::IgnoredAny,
        chain_id: serde::de::IgnoredAny,
        genesis_hash: serde::de::IgnoredAny,
        finalized_height: serde::de::IgnoredAny,
        finalized_hash: serde::de::IgnoredAny,
        finality_evidence_id: serde::de::IgnoredAny,
        #[serde(default)]
        finality_witness: Option<Witness>,
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    #[allow(dead_code)]
    struct Envelope {
        kind: HeadKind,
        body: Head,
    }
    serde_json::from_slice::<Envelope>(bytes).map_err(decode_error)?;
    Ok(())
}

/// Native adjacent-tag validation runs before any nested candidate decoding.
/// Every non-candidate variant is decoded only after a full metadata reservation.
pub fn decode_budgeted_sync_wire(
    bytes: &[u8],
    budget: &Arc<WorldResourceBudget>,
) -> Result<DecodedBudgetedSync<BudgetedSyncWireMessage>, SyncResourceError> {
    let mut metadata = scanner_reservation(bytes, budget)?;
    #[derive(Deserialize)]
    #[serde(rename_all = "snake_case")]
    enum Kind {
        Head,
        FinalizedCandidateRequest,
        FinalizedCandidateRequestV2,
        FinalizedCandidateChunk,
        FinalizedCandidateResponse,
        SnapshotChunkRequest,
        SnapshotChunkResponse,
        EpochAuthorityRequest,
        EpochAuthorityResponse,
    }
    // A struct streams IgnoredAny even when body precedes kind. Deserializing
    // an adjacently tagged enum here could buffer the entire body before kind.
    #[derive(Deserialize)]
    struct Tag {
        kind: Kind,
        body: serde::de::IgnoredAny,
    }
    let tag: Tag = serde_json::from_slice(bytes).map_err(decode_error)?;
    let _ = tag.body;
    if matches!(tag.kind, Kind::FinalizedCandidateResponse) {
        let body = required_field(bytes, JsonObjectField::Body, budget)?;
        // No parsed envelope allocation survives this tag walk.
        drop(metadata);
        let response = decode_budgeted_candidate_response(body, budget)?;
        let (value, metadata) = response.into_parts();
        return Ok(DecodedBudgetedSync {
            value: SyncWireMessage::FinalizedCandidateResponse(value),
            metadata,
        });
    }
    if matches!(tag.kind, Kind::Head) {
        preflight_head(bytes)?;
        let body = required_field(bytes, JsonObjectField::Body, budget)?;
        // Deserialize the typed body directly. An adjacent-tag enum may buffer
        // body-before-kind input into a generic serde Content tree, whose per-
        // scalar allocation would invalidate the byte-vector reservation.
        let owned = checked_add(byte_vector_charge(bytes)?, 4096)?;
        metadata.resize(checked_add(metadata.bytes(), owned)?)?;
        let claim: HeadClaim = serde_json::from_slice(body).map_err(decode_error)?;
        metadata.resize(owned)?;
        return Ok(DecodedBudgetedSync {
            value: SyncWireMessage::Head(claim),
            metadata,
        });
    }
    let owned = metadata_charge(bytes)?;
    metadata.resize(checked_add(metadata.bytes(), owned)?)?;
    let plain: SyncWireMessage = serde_json::from_slice(bytes).map_err(decode_error)?;
    let value = match plain {
        SyncWireMessage::Head(v) => SyncWireMessage::Head(v),
        SyncWireMessage::FinalizedCandidateRequest(v) => {
            SyncWireMessage::FinalizedCandidateRequest(v)
        }
        SyncWireMessage::FinalizedCandidateRequestV2(v) => {
            SyncWireMessage::FinalizedCandidateRequestV2(v)
        }
        SyncWireMessage::FinalizedCandidateChunk(v) => SyncWireMessage::FinalizedCandidateChunk(v),
        SyncWireMessage::SnapshotChunkRequest(v) => SyncWireMessage::SnapshotChunkRequest(v),
        SyncWireMessage::SnapshotChunkResponse(v) => SyncWireMessage::SnapshotChunkResponse(v),
        SyncWireMessage::EpochAuthorityRequest(v) => SyncWireMessage::EpochAuthorityRequest(v),
        SyncWireMessage::EpochAuthorityResponse(v) => SyncWireMessage::EpochAuthorityResponse(v),
        SyncWireMessage::FinalizedCandidateResponse(_) => {
            unreachable!("tag schema already checked")
        }
    };
    metadata.resize(owned)?;
    Ok(DecodedBudgetedSync { value, metadata })
}

#[cfg(test)]
mod budgeted_wire_tests {
    use super::*;
    use sha3::{Digest, Sha3_256};
    fn candidate_response() -> FinalizedCandidateResponse {
        let mut world = synergy_state::WorldState::default();
        world.protocol.insert("large".into(), vec![255; 8192]);
        let value = serde_json::json!({
            "height":1,"block_id":"placeholder","parent_block_id":"parent",
            "protected_execution_root":"placeholder",
            "protected_material":{"material_version":2,"height":1,
                "execution_root":"11".repeat(64),"next_batch_root":"22".repeat(64),
                "cutoff_boundary_root":"33".repeat(64)},
            "state_root":synergy_state::state_root(&world).unwrap(),
            "transactions":[],"receipts":[],"state":world
        });
        let mut candidate: ExecutionCandidate = serde_json::from_value(value).unwrap();
        let proof = candidate.protected_material.commitment_bytes().unwrap();
        let mut hash = Sha3_256::new();
        hash.update(b"SYNERGY_BLOCK_ID_V1");
        hash.update((proof.len() as u64).to_be_bytes());
        hash.update(proof);
        candidate.protected_execution_root = format!("{:x}", hash.finalize());
        candidate.block_id = candidate.commitment_id().unwrap();
        candidate.validate().unwrap();
        FinalizedCandidateResponse {
            request: FinalizedCandidateRequest {
                height: 1,
                expected_parent_id: "parent".into(),
            },
            candidate,
            finality_witness: vec![7; 1024],
            processing_replay: None,
        }
    }
    #[test]
    fn budgeted_sync_exact_wire_and_retained_permit_lifetime() {
        let response = candidate_response();
        let bytes = serde_json::to_vec(&response).unwrap();
        let budget = WorldResourceBudget::new(16 * 1024 * 1024);
        let decoded = decode_budgeted_candidate_response(&bytes, &budget).unwrap();
        assert_eq!(serde_json::to_vec(&decoded).unwrap(), bytes);
        decoded.candidate.validate().unwrap();
        assert_eq!(
            budget.used(),
            decoded.metadata_bytes()
                + decoded.candidate.state.charged_bytes()
                + decoded.candidate.resource_permit.as_ref().unwrap().bytes()
        );
        // Arc handoffs share the charged World; outer metadata has a distinct lifetime.
        let state = Arc::clone(&decoded.candidate.state);
        drop(decoded);
        assert_eq!(budget.used(), state.charged_bytes());
        drop(state);
        assert_eq!(budget.used(), 0);

        let body_first = format!(
            "{{\"body\":{},\"kind\":\"finalized_candidate_response\"}}",
            String::from_utf8(bytes).unwrap()
        );
        let tagged = decode_budgeted_sync_wire(body_first.as_bytes(), &budget).unwrap();
        let SyncWireMessage::FinalizedCandidateResponse(inner) = &*tagged else {
            panic!("wrong variant")
        };
        inner.candidate.validate().unwrap();
        assert_eq!(
            serde_json::to_vec(&*tagged).unwrap(),
            serde_json::to_vec(&SyncWireMessage::FinalizedCandidateResponse(response)).unwrap()
        );
        drop(tagged);
        assert_eq!(budget.used(), 0);
    }
    #[test]
    fn processing_sync_sideband_is_charged_and_legacy_encoding_stays_unchanged() {
        let mut response = candidate_response();
        let legacy = serde_json::to_vec(&response).unwrap();
        assert!(!String::from_utf8(legacy.clone())
            .unwrap()
            .contains("processing_replay"));
        let budget = WorldResourceBudget::new(16 * 1024 * 1024);
        let old = decode_budgeted_candidate_response(&legacy, &budget).unwrap();
        let legacy_metadata = old.metadata_bytes();
        drop(old);
        response.processing_replay = Some(vec![37; 64 * 1024]);
        let bytes = serde_json::to_vec(&response).unwrap();
        let decoded = decode_budgeted_candidate_response(&bytes, &budget).unwrap();
        assert_eq!(serde_json::to_vec(&decoded).unwrap(), bytes);
        assert!(decoded.metadata_bytes() >= legacy_metadata + 64 * 1024);
        drop(decoded);
        assert_eq!(budget.used(), 0);
        let tiny = WorldResourceBudget::new(1024);
        assert!(decode_budgeted_candidate_response(&bytes, &tiny).is_err());
        assert_eq!(tiny.used(), 0);

        // A byte sideband must fit its actual Vec allocation plus parser and
        // candidate charges, rather than 128 bytes per JSON numeric element.
        let constrained = WorldResourceBudget::new(4 * 1024 * 1024);
        drop(decode_budgeted_candidate_response(&legacy, &constrained).unwrap());
        assert_eq!(constrained.used(), 0);
        drop(decode_budgeted_candidate_response(&bytes, &constrained).unwrap());
        assert_eq!(constrained.used(), 0);

        // The reservation precedes native Vec validation; malformed byte
        // values still fail closed when sufficient memory is available.
        let mut malformed = serde_json::to_value(&response).unwrap();
        malformed["processing_replay"][0] = 256.into();
        let malformed = serde_json::to_vec(&malformed).unwrap();
        assert!(matches!(
            decode_budgeted_candidate_response(&malformed, &tiny),
            Err(SyncResourceError::Resource(
                WorldResourceError::Capacity { .. }
            ))
        ));
        assert_eq!(constrained.used(), 0);
        assert!(matches!(
            decode_budgeted_candidate_response(&malformed, &budget),
            Err(SyncResourceError::Decode(_))
        ));
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn budgeted_sync_pressure_corruption_and_duplicate_fields_release() {
        let tiny = WorldResourceBudget::new(1);
        assert!(matches!(
            decode_budgeted_sync_wire(b"not JSON", &tiny),
            Err(SyncResourceError::Resource(
                WorldResourceError::Capacity { .. }
            ))
        ));
        assert_eq!(tiny.used(), 0);
        let budget = WorldResourceBudget::new(16 * 1024 * 1024);
        let response = candidate_response();
        let bytes = serde_json::to_vec(&response).unwrap();
        let mut corrupt: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        corrupt["candidate"]["state_root"] = "bad".into();
        assert!(matches!(
            decode_budgeted_candidate_response(&serde_json::to_vec(&corrupt).unwrap(), &budget),
            Err(SyncResourceError::Candidate(
                CandidateResourceError::Invalid(_)
            ))
        ));
        assert_eq!(budget.used(), 0);
        for bytes in [
            br#"{"kind":"head","kind":"finalized_candidate_response","body":{}}"#.as_slice(),
            br#"{"kind":"head","body":{},"body":{}}"#,
            br#"{"kind":"unknown","body":{}}"#,
            br#"{"request":{},"candidate":{},"candidate":{},"finality_witness":[]}"#,
            br#"{"kind":"finalized_candidate_response","body":{}}"#,
        ] {
            assert!(decode_budgeted_sync_wire(bytes, &budget).is_err());
            assert_eq!(budget.used(), 0);
        }
    }
    #[test]
    fn epoch_boundary_authority_request_accepts_canonical_posy_digests_only() {
        let request = EpochAuthorityRequest {
            current_epoch: 1,
            current_epoch_context_root: "a".repeat(64),
            finalized_height: 9_998,
            finalized_block_id: "boundary-block".into(),
            finality_evidence_id: "b".repeat(64),
        };
        assert!(request.validate());
        for invalid in [
            "a".repeat(128),
            "a".repeat(63),
            "A".repeat(64),
            "g".repeat(64),
        ] {
            let mut bad = request.clone();
            bad.current_epoch_context_root = invalid.clone();
            assert!(!bad.validate());
            let mut bad = request.clone();
            bad.finality_evidence_id = invalid;
            assert!(!bad.validate());
        }
        assert!(EpochAuthorityResponse {
            request,
            next_authority_binding: vec![1],
        }
        .validate());
    }

    fn assert_head_decode_under_native_memory_pressure(bytes: &[u8]) {
        const LIMIT: usize = 64 * 1024 * 1024;
        let budget = WorldResourceBudget::new(LIMIT);
        // A native owner retains charged certified state/proofs. Leave bounded
        // scratch for this exact opaque witness, without increasing its budget.
        let typed_owned = byte_vector_charge(bytes).unwrap() + 4096;
        let scanner = bytes.len() * 3 + 4096;
        // Borrowing the body performs one additional transient scanner pass;
        // it ends before typed materialization begins.
        let available = (typed_owned + scanner).max(scanner + bytes.len() * 3 + 256) + 4096;
        assert!(available < LIMIT);
        let _retained_native_state = budget.reserve(LIMIT - available).unwrap();
        let baseline = budget.used();
        let old_owned = metadata_charge(bytes).unwrap();
        assert!(
            old_owned + scanner > available,
            "fixture must reach old scalar-accounting capacity failure"
        );
        let decoded = decode_budgeted_sync_wire(bytes, &budget).unwrap();
        let SyncWireMessage::Head(claim) = &*decoded else {
            panic!("native fixture is not a head")
        };
        assert!(claim
            .finality_witness
            .as_ref()
            .is_some_and(|proof| !proof.is_empty()));
        let original: SyncWireMessage = serde_json::from_slice(bytes).unwrap();
        assert_eq!(
            serde_json::to_vec(&decoded).unwrap(),
            serde_json::to_vec(&original).unwrap()
        );
        assert!(decoded.metadata_bytes() >= claim.finality_witness.as_ref().unwrap().len());
        assert_eq!(budget.used(), baseline + decoded.metadata_bytes());
        eprintln!("SYNC_TYPED_HEAD_ACCOUNTING encoded={} old_owned={} typed_owned={} available={} limit={LIMIT}", bytes.len(), old_owned, decoded.metadata_bytes(), available);
        drop(decoded);
        assert_eq!(budget.used(), baseline);
    }

    fn opaque_head(proof: Vec<u8>) -> SyncWireMessage {
        SyncWireMessage::Head(HeadClaim {
            peer_id: "native-donor".into(),
            chain_id: 99999,
            genesis_hash: "a".repeat(64),
            finalized_height: 18,
            finalized_hash: "b".repeat(64),
            finality_evidence_id: "c".repeat(64),
            finality_witness: Some(proof),
        })
    }

    fn body_before_kind(bytes: &[u8]) -> Vec<u8> {
        let value: serde_json::Value = serde_json::from_slice(bytes).unwrap();
        format!("{{\"body\":{},\"kind\":\"head\"}}", value["body"]).into_bytes()
    }

    #[test]
    fn budgeted_head_byte_witness_progresses_under_memory_pressure() {
        let bytes = serde_json::to_vec(&opaque_head(vec![173; 146_079])).unwrap();
        assert_head_decode_under_native_memory_pressure(&bytes);
        assert_head_decode_under_native_memory_pressure(&body_before_kind(&bytes));
    }

    #[test]
    #[ignore = "requires public native three-QC Head fixture from retained qualification"]
    fn budgeted_head_actual_native_witness_progresses_under_memory_pressure() {
        let bytes =
            std::fs::read(std::env::var("SYNERGY_SYNC_NATIVE_HEAD_FIXTURE").unwrap()).unwrap();
        assert_head_decode_under_native_memory_pressure(&bytes);
        assert_head_decode_under_native_memory_pressure(&body_before_kind(&bytes));
    }

    #[test]
    fn budgeted_head_preflight_rejects_malformed_unknown_and_oversized_vectors() {
        let valid = serde_json::to_value(opaque_head(vec![1, 2, 3])).unwrap();
        let mut cases = Vec::new();
        for witness in [
            serde_json::json!([-1]),
            serde_json::json!([256]),
            serde_json::json!([[1]]),
            serde_json::json!(["1"]),
            serde_json::json!("bytes"),
        ] {
            let mut bad = valid.clone();
            bad["body"]["finality_witness"] = witness;
            cases.push(bad);
        }
        let mut unknown = valid.clone();
        unknown["body"]["unrecognized"] = serde_json::json!(1);
        cases.push(unknown);
        let mut unknown = valid.clone();
        unknown["unrecognized"] = serde_json::json!(1);
        cases.push(unknown);
        let mut missing = valid.clone();
        missing["body"]
            .as_object_mut()
            .unwrap()
            .remove("finalized_hash");
        cases.push(missing);
        for case in cases {
            let bytes = serde_json::to_vec(&case).unwrap();
            let budget = WorldResourceBudget::new(64 * 1024 * 1024);
            assert!(decode_budgeted_sync_wire(&bytes, &budget).is_err());
            assert_eq!(budget.used(), 0);
        }
        let bytes = serde_json::to_vec(&opaque_head(vec![0; 1024 * 1024 + 1])).unwrap();
        let budget = WorldResourceBudget::new(64 * 1024 * 1024);
        assert!(decode_budgeted_sync_wire(&bytes, &budget)
            .unwrap_err()
            .to_string()
            .contains("head finality witness exceeds transport bound"));
        assert_eq!(budget.used(), 0);
        let compact: SyncWireMessage = SyncWireMessage::Head(HeadClaim {
            finality_witness: None,
            ..match opaque_head(vec![]) {
                SyncWireMessage::Head(claim) => claim,
                _ => unreachable!(),
            }
        });
        let bytes = serde_json::to_vec(&compact).unwrap();
        assert_eq!(
            serde_json::to_vec(&decode_budgeted_sync_wire(&bytes, &budget).unwrap()).unwrap(),
            bytes
        );
    }

    #[test]
    fn budgeted_sync_non_candidate_metadata_remains_charged() {
        let message: SyncWireMessage =
            SyncWireMessage::EpochAuthorityResponse(EpochAuthorityResponse {
                request: EpochAuthorityRequest {
                    current_epoch: 1,
                    current_epoch_context_root: "a".repeat(64),
                    finalized_height: 1,
                    finalized_block_id: "block".into(),
                    finality_evidence_id: "b".repeat(64),
                },
                next_authority_binding: vec![9; 16384],
            });
        let bytes = serde_json::to_vec(&message).unwrap();
        let budget = WorldResourceBudget::new(16 * 1024 * 1024);
        let decoded = decode_budgeted_sync_wire(&bytes, &budget).unwrap();
        assert!(decoded.metadata_bytes() >= 16384);
        assert_eq!(budget.used(), decoded.metadata_bytes());
        assert_eq!(serde_json::to_vec(&decoded).unwrap(), bytes);
        drop(decoded);
        assert_eq!(budget.used(), 0);
        let tight = WorldResourceBudget::new(bytes.len() * 3 + 4096);
        assert!(matches!(
            decode_budgeted_sync_wire(&bytes, &tight),
            Err(SyncResourceError::Resource(
                WorldResourceError::Capacity { .. }
            ))
        ));
        assert_eq!(tight.used(), 0);
    }
}
