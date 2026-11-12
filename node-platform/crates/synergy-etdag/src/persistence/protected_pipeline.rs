use crate::crypto::SignatureVerifier;
use crate::execution::{ParentProposalRevealEvidence, PreparedProtectedBatch};
use crate::ordering::{derive_target_order_seed, CutoffMembers, ProtectedCutMarker};
use crate::reveal::{RevealAuthorizationVerifier, VerifiedRevealAuthorization};
use crate::{
    AvailabilityCertificate, AvailabilityVote, DeterministicProtectedBatch, EtdagDigest,
    EtdagError, EtdagGraph, EtdagParameters, ProtectedCutProof, TargetAdmissionContextV3,
};
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::Arc;

/// Exact PoSy-authorized replacement of an uncommitted close generation.
/// Serialized evidence is reverified by the PoSy owner, never trusted from disk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CutRecoveryGeneration {
    pub original_cutoff_context_root: EtdagDigest,
    pub previous_cutoff_context_root: EtdagDigest,
    pub cutoff_context_root: EtdagDigest,
    pub timeout_id: String,
    pub timeout_round: u64,
    pub authorization: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RetainedMarker {
    cutoff_context_root: EtdagDigest,
    marker: ProtectedCutMarker,
}

#[derive(Debug, Clone, Default)]
struct GenerationIndex {
    ids: BTreeMap<String, usize>,
    roots: BTreeMap<EtdagDigest, usize>,
}

impl GenerationIndex {
    fn insert(&mut self, generation: &CutRecoveryGeneration, position: usize) {
        self.ids.insert(generation.timeout_id.clone(), position);
        self.roots
            .insert(generation.cutoff_context_root.clone(), position);
    }
}

/// In-memory index into immutable, already authenticated journal bytes.
#[derive(Debug, Clone)]
struct JournalLocation {
    offset: u64,
    length: usize,
    digest: EtdagDigest,
    initial: bool,
}
#[derive(Debug, Clone)]
struct ProofLocation {
    frame: Arc<JournalLocation>,
    index: usize,
}
impl JournalLocation {
    fn read(&self, file: &mut std::fs::File) -> Result<StoredPipeline, EtdagError> {
        if self.length > JOURNAL_LIMIT {
            return Err(EtdagError::InvalidCapacity);
        }
        file.seek(SeekFrom::Start(self.offset))
            .map_err(journal_error)?;
        let mut payload = vec![0; self.length];
        file.read_exact(&mut payload).map_err(journal_error)?;
        if journal_digest(&payload) != self.digest {
            return Err(journal_error("indexed original changed"));
        }
        if self.initial {
            return serde_json::from_slice(&payload).map_err(journal_error);
        }
        let mut delta: JournalDelta = serde_json::from_slice(&payload).map_err(journal_error)?;
        delta.state.cut_recovery_generations = delta.generations;
        delta.state.retained_markers = delta.markers;
        Ok(delta.state)
    }
}

/// Authenticated history retains identities/digests, not historical proof payloads.
/// Originals remain in the hash-chained journal and are read individually on demand.
#[derive(Debug, Clone, Default)]
struct VerifiedHistory {
    generations: Vec<EtdagDigest>,
    markers: Vec<(EtdagDigest, EtdagDigest)>,
    index: GenerationIndex,
    generation_locations: Vec<ProofLocation>,
    marker_locations: Vec<ProofLocation>,
    last: Option<CutRecoveryGeneration>,
}
impl VerifiedHistory {
    // Index strings are validated fixed64/128-byte IDs and cloned into compact
    // allocations. Charge whole BTree nodes per entry, twice each Vec slot for
    // growth, separate Arc/frame allocations, and the retained original's actual
    // capacities. This is O(1), independent of the proof-history length.
    fn projected_resource_bytes(
        &self,
        generations: usize,
        markers: usize,
        last: Option<&CutRecoveryGeneration>,
    ) -> usize {
        let generations = self.generations.len().saturating_add(generations);
        let markers = self.markers.len().saturating_add(markers);
        if generations == 0 && markers == 0 && last.is_none() {
            return 0;
        }
        let frame = std::mem::size_of::<JournalLocation>() + 2 * std::mem::size_of::<usize>() + 128;
        let generation = 2 * std::mem::size_of::<EtdagDigest>()
            + 2 * std::mem::size_of::<ProofLocation>()
            + 2 * (12 * std::mem::size_of::<(String, usize)>() + 256)
            + 128
            + 64
            + 128
            + frame;
        let marker = 2 * std::mem::size_of::<(EtdagDigest, EtdagDigest)>()
            + 2 * std::mem::size_of::<ProofLocation>()
            + 256
            + frame;
        let last = last.or(self.last.as_ref()).map_or(0, |last| {
            std::mem::size_of::<CutRecoveryGeneration>()
                .saturating_add(last.original_cutoff_context_root.0.capacity())
                .saturating_add(last.previous_cutoff_context_root.0.capacity())
                .saturating_add(last.cutoff_context_root.0.capacity())
                .saturating_add(last.timeout_id.capacity())
                .saturating_add(last.authorization.capacity())
        });
        8192usize
            .saturating_add(generations.saturating_mul(generation))
            .saturating_add(markers.saturating_mul(marker))
            .saturating_add(last)
    }
    fn resource_bytes(&self) -> usize {
        self.projected_resource_bytes(0, 0, None)
    }
    fn absorb(&mut self, state: &mut StoredPipeline) -> Result<(), EtdagError> {
        let original = state
            .original_cutoff_context_root
            .as_ref()
            .or(state.cutoff_context_root.as_ref());
        let mut previous = self
            .last
            .as_ref()
            .map(|g| &g.cutoff_context_root)
            .or(original)
            .cloned();
        // Metadata-only transitions introduce no proof locations. Existing
        // indexes must continue to address the original full-state frames.
        if state.pending_location.is_none()
            && state.cut_recovery_generations.is_empty()
            && state.retained_markers.is_empty()
        {
            return if previous == state.cutoff_context_root {
                Ok(())
            } else {
                Err(EtdagError::ContextMismatch)
            };
        }
        let location = state
            .pending_location
            .take()
            .ok_or_else(|| journal_error("missing history byte location"))?;
        for (position, generation) in state.cut_recovery_generations.iter().enumerate() {
            validate_generation(generation, original, previous.as_ref(), &[])?;
            if self.generations.len() >= 4096
                || self
                    .last
                    .as_ref()
                    .is_some_and(|g| generation.timeout_round <= g.timeout_round)
                || self.index.ids.contains_key(&generation.timeout_id)
                || self
                    .index
                    .roots
                    .contains_key(&generation.cutoff_context_root)
            {
                return Err(EtdagError::ContextMismatch);
            }
            self.index.insert(generation, self.generations.len());
            self.generations.push(EtdagDigest::from_canonical(
                "SYNERGY_PROTECTED_GENERATION_RECORD_V1",
                generation,
            )?);
            self.generation_locations.push(ProofLocation {
                frame: Arc::clone(&location),
                index: position,
            });
            previous = Some(generation.cutoff_context_root.clone());
            self.last = Some(generation.clone());
        }
        if previous != state.cutoff_context_root {
            return Err(EtdagError::ContextMismatch);
        }
        for (position, retained) in state.retained_markers.iter().enumerate() {
            if self.markers.len() >= 4096
                || Some(&retained.cutoff_context_root) == state.cutoff_context_root.as_ref()
                || (Some(&retained.cutoff_context_root) != original
                    && !self.index.roots.contains_key(&retained.cutoff_context_root))
                || self
                    .markers
                    .iter()
                    .any(|(root, _)| root == &retained.cutoff_context_root)
            {
                return Err(EtdagError::ContextMismatch);
            }
            self.marker_locations.push(ProofLocation {
                frame: Arc::clone(&location),
                index: position,
            });
            self.markers.push((
                retained.cutoff_context_root.clone(),
                EtdagDigest::from_canonical(
                    "SYNERGY_PROTECTED_MARKER_RECORD_V1",
                    &retained.marker,
                )?,
            ));
        }
        state.cut_recovery_generations.clear();
        state.retained_markers.clear();
        Ok(())
    }
}

fn validate_generation(
    generation: &CutRecoveryGeneration,
    original: Option<&EtdagDigest>,
    previous: Option<&EtdagDigest>,
    history: &[CutRecoveryGeneration],
) -> Result<(), EtdagError> {
    for root in [
        &generation.original_cutoff_context_root,
        &generation.previous_cutoff_context_root,
        &generation.cutoff_context_root,
    ] {
        root.validate()?;
        if root.is_zero() {
            return Err(EtdagError::ContextMismatch);
        }
    }
    if original != Some(&generation.original_cutoff_context_root)
        || previous != Some(&generation.previous_cutoff_context_root)
        || generation.cutoff_context_root == generation.previous_cutoff_context_root
        || generation.cutoff_context_root == generation.original_cutoff_context_root
        || generation.timeout_id.len() != 64
        || !generation
            .timeout_id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || generation.authorization.is_empty()
        || generation.authorization.len() > 1024 * 1024
        || history.len() >= 4096
        || history
            .last()
            .is_some_and(|g| generation.timeout_round <= g.timeout_round)
        || history.iter().any(|g| {
            g.timeout_id == generation.timeout_id
                || g.cutoff_context_root == generation.cutoff_context_root
        })
    {
        return Err(EtdagError::ContextMismatch);
    }
    Ok(())
}

/// One bounded atomic record per target. Evidence never becomes authority
/// merely by surviving a restart; open re-verifies the cut and parent proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u32,
    context: TargetAdmissionContextV3,
    parameters: EtdagParameters,
    cut: ProtectedCutProof,
    graph: EtdagGraph,
    availability: BTreeMap<EtdagDigest, AvailabilityCertificate>,
    batch: DeterministicProtectedBatch,
    prepared: Option<PreparedProtectedBatch>,
    #[serde(default)]
    reveal_transcripts: BTreeMap<EtdagDigest, crate::reveal::RevealTranscript>,
    consumed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CollectingEvidence {
    graph: EtdagGraph,
    local_votes: BTreeMap<EtdagDigest, AvailabilityVote>,
    votes: BTreeMap<EtdagDigest, BTreeMap<String, AvailabilityVote>>,
    certificates: BTreeMap<EtdagDigest, AvailabilityCertificate>,
}

// Charge an entire B-tree node per entry, including spare key/value slots,
// edges and allocator overhead. This deliberately overcharges sparse maps.
fn map_slot<T>() -> usize {
    std::mem::size_of::<T>()
        .saturating_mul(12)
        .saturating_add(256)
}
fn add_bytes(values: impl IntoIterator<Item = usize>) -> usize {
    values.into_iter().fold(0usize, usize::saturating_add)
}
fn digest_bytes(digest: &EtdagDigest) -> usize {
    digest.0.capacity()
}
fn digests_bytes(values: &Vec<EtdagDigest>) -> usize {
    values
        .capacity()
        .saturating_mul(std::mem::size_of::<EtdagDigest>())
        .saturating_add(add_bytes(values.iter().map(digest_bytes)))
}
fn envelope_heap_bytes(envelope: &crate::EncryptedTransactionEnvelope) -> usize {
    let aad = &envelope.aad;
    add_bytes([
        digest_bytes(&envelope.envelope_id),
        digest_bytes(&envelope.target_context_root),
        digest_bytes(&envelope.key_commitment),
        digest_bytes(&envelope.share_commitment_root),
        digest_bytes(&envelope.share_capsule_root),
        digest_bytes(&envelope.content_blind_order_key),
        envelope.ciphertext.capacity(),
        aad.profile_id.capacity(),
        aad.network_id.capacity(),
        aad.protocol_version.capacity(),
        digest_bytes(&aad.target_context_root),
        aad.lane_id.capacity(),
        aad.sender_id.capacity(),
        envelope
            .share_capsules
            .capacity()
            .saturating_mul(std::mem::size_of::<crate::ShareCapsule>()),
        add_bytes(envelope.share_capsules.iter().map(|capsule| {
            add_bytes([
                capsule.validator_id.capacity(),
                capsule.ingress_kem_key_id.capacity(),
                digest_bytes(&capsule.share_commitment),
                capsule.kem_ciphertext.capacity(),
                capsule.encrypted_share.capacity(),
            ])
        })),
    ])
}
fn wallet_heap_bytes(admission: &crate::WalletAdmission) -> usize {
    let request = &admission.request;
    let carrier = &admission.identity_authorization;
    let binding = &carrier.binding;
    add_bytes([
        request.network_id.capacity(),
        digest_bytes(&request.context_root),
        request.sender_wallet.capacity(),
        request.signature_algorithm.capacity(),
        request.signer_public_key.capacity(),
        request.signature.capacity(),
        envelope_heap_bytes(&request.envelope),
        carrier.signature_domain.capacity(),
        binding.schema_version.capacity(),
        binding.binary_encoding.capacity(),
        binding.identity_id.capacity(),
        binding.identity_address.capacity(),
        binding.identity_root.algorithm.capacity(),
        binding.identity_root.public_key.capacity(),
        binding.identity_root.public_key_sha3_256.capacity(),
        binding
            .authorization_policy
            .principals
            .capacity()
            .saturating_mul(std::mem::size_of::<
                synergy_identity::authorization::AuthorizationPrincipal,
            >()),
        add_bytes(
            binding
                .authorization_policy
                .principals
                .iter()
                .map(|principal| {
                    add_bytes([
                        principal.principal_id.capacity(),
                        principal.algorithm.as_ref().map_or(0, String::capacity),
                        principal.public_key.as_ref().map_or(0, String::capacity),
                        principal
                            .public_key_sha3_256
                            .as_ref()
                            .map_or(0, String::capacity),
                        principal
                            .identity_reference
                            .as_ref()
                            .map_or(0, String::capacity),
                        principal
                            .purposes
                            .capacity()
                            .saturating_mul(std::mem::size_of::<String>()),
                        add_bytes(principal.purposes.iter().map(String::capacity)),
                    ])
                }),
        ),
        binding
            .authorization_scopes
            .capacity()
            .saturating_mul(std::mem::size_of::<
                synergy_identity::authorization::AuthorizationScope,
            >()),
        add_bytes(binding.authorization_scopes.iter().map(|scope| {
            add_bytes([
                scope.signature_domain.capacity(),
                scope.network_id.capacity(),
                scope.purpose.capacity(),
            ])
        })),
        binding
            .current_auth_key_hash
            .as_ref()
            .map_or(0, String::capacity),
        binding
            .auth_key_history
            .capacity()
            .saturating_mul(std::mem::size_of::<
                synergy_identity::authorization::AuthKeyHistoryEntry,
            >()),
        add_bytes(binding.auth_key_history.iter().map(|entry| {
            add_bytes([
                entry.principal_id.capacity(),
                entry.algorithm.capacity(),
                entry.public_key_sha3_256.capacity(),
                entry.retired_at.capacity(),
                entry.reason.capacity(),
            ])
        })),
        binding
            .supersession_history
            .capacity()
            .saturating_mul(std::mem::size_of::<
                synergy_identity::authorization::SupersessionEntry,
            >()),
        add_bytes(binding.supersession_history.iter().map(|entry| {
            add_bytes([
                entry.address.capacity(),
                entry.derivation_standard.capacity(),
                entry.reason.capacity(),
            ])
        })),
        binding.effective_at.capacity(),
        binding.binding_payload_sha3_256.capacity(),
        binding.proofs.identity_root.algorithm.capacity(),
        binding.proofs.identity_root.signature.capacity(),
        binding
            .proofs
            .authorization_key_possession
            .capacity()
            .saturating_mul(std::mem::size_of::<
                synergy_identity::authorization::AuthorizationKeyPossessionProof,
            >()),
        add_bytes(
            binding
                .proofs
                .authorization_key_possession
                .iter()
                .map(|proof| {
                    add_bytes([
                        proof.principal_id.capacity(),
                        proof.algorithm.capacity(),
                        proof.signature.capacity(),
                    ])
                }),
        ),
    ])
}
fn vertex_heap_bytes(vertex: &crate::TransactionVertex) -> usize {
    add_bytes([
        digest_bytes(&vertex.vertex_id),
        digest_bytes(&vertex.target_context_root),
        envelope_heap_bytes(&vertex.envelope),
        digest_bytes(&vertex.envelope_ref.tx_commitment),
        vertex.envelope_ref.sender_id.capacity(),
        digests_bytes(&vertex.envelope_ref.protocol_dependencies),
        digests_bytes(&vertex.parents),
        vertex.author_id.capacity(),
        vertex.author_signature.capacity(),
        vertex
            .wallet_admission
            .as_ref()
            .map_or(0, wallet_heap_bytes),
    ])
}
fn vote_heap_bytes(vote: &AvailabilityVote) -> usize {
    add_bytes([
        digest_bytes(&vote.context_root),
        digest_bytes(&vote.vertex_id),
        vote.validator_id.capacity(),
        vote.key_id.capacity(),
        vote.signature.capacity(),
    ])
}
fn certificate_heap_bytes(certificate: &AvailabilityCertificate) -> usize {
    add_bytes([
        digest_bytes(&certificate.context_root),
        digest_bytes(&certificate.vertex_id),
        certificate
            .votes
            .capacity()
            .saturating_mul(std::mem::size_of::<AvailabilityVote>()),
        add_bytes(certificate.votes.iter().map(vote_heap_bytes)),
    ])
}
fn collecting_bytes(evidence: &CollectingEvidence) -> usize {
    add_bytes([
        std::mem::size_of::<CollectingEvidence>(),
        digest_bytes(evidence.graph.context_root()),
        add_bytes(evidence.graph.vertices().map(|vertex| {
            add_bytes([
                map_slot::<(EtdagDigest, crate::TransactionVertex)>(),
                digest_bytes(&vertex.vertex_id),
                vertex_heap_bytes(vertex),
            ])
        })),
        add_bytes(evidence.local_votes.iter().map(|(key, vote)| {
            add_bytes([
                map_slot::<(EtdagDigest, AvailabilityVote)>(),
                digest_bytes(key),
                vote_heap_bytes(vote),
            ])
        })),
        add_bytes(evidence.votes.iter().map(|(key, votes)| {
            add_bytes([
                map_slot::<(EtdagDigest, BTreeMap<String, AvailabilityVote>)>(),
                digest_bytes(key),
                add_bytes(votes.iter().map(|(validator, vote)| {
                    add_bytes([
                        map_slot::<(String, AvailabilityVote)>(),
                        validator.capacity(),
                        vote_heap_bytes(vote),
                    ])
                })),
            ])
        })),
        add_bytes(evidence.certificates.iter().map(|(key, certificate)| {
            add_bytes([
                map_slot::<(EtdagDigest, AvailabilityCertificate)>(),
                digest_bytes(key),
                certificate_heap_bytes(certificate),
            ])
        })),
    ])
}

fn encoded_len(value: &impl Serialize) -> Result<usize, EtdagError> {
    struct Counter(usize);
    impl std::io::Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self.0.saturating_add(bytes.len());
            if self.0 > JOURNAL_LIMIT {
                return Err(std::io::Error::other("protected collecting capacity"));
            }
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut counter = Counter(0);
    serde_json::to_writer(&mut counter, value).map_err(|error| {
        if error.is_io() {
            EtdagError::ResourcePressure(
                "protected collecting serialized reservation exhausted".into(),
            )
        } else {
            journal_error(error)
        }
    })?;
    Ok(counter.0)
}

const JOURNAL_MAGIC: &[u8; 8] = b"SNPGJ001";
const JOURNAL_END: &[u8; 8] = b"SNPGEND1";
const JOURNAL_HEADER: usize = 8 + 8 + 128 + 128;
const JOURNAL_LIMIT: usize = 16 * 1024 * 1024;
#[derive(Debug, Clone)]
struct JournalCursor {
    length: u64,
    head: EtdagDigest,
    generations: usize,
    markers: usize,
    appended: bool,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct JournalDelta {
    version: u32,
    state: StoredPipeline,
    generations: Vec<CutRecoveryGeneration>,
    markers: Vec<RetainedMarker>,
}
#[derive(Deserialize)]
struct JournalVersion {
    version: u32,
}

/// Internal storage transitions preserve the original native signed carriers.
/// They confer no authority until their native verifier has accepted them.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CollectingDelta {
    version: u32,
    prior_head: EtdagDigest,
    context_root: EtdagDigest,
    target_height: u64,
    local_validator_id: String,
    action: CollectingAction,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", content = "original", deny_unknown_fields)]
enum CollectingAction {
    Vertex(Box<crate::TransactionVertex>),
    LocalVote(AvailabilityVote),
    PeerVote(AvailabilityVote),
    Availability(AvailabilityCertificate),
    BindCutoff(EtdagDigest),
}

impl CollectingAction {
    fn authenticate(
        &self,
        context: &TargetAdmissionContextV3,
        members: &CutoffMembers,
        verifier: &impl SignatureVerifier,
    ) -> Result<(), EtdagError> {
        match self {
            Self::Vertex(vertex) => verify_vertex(vertex, context, members, verifier),
            Self::LocalVote(vote) | Self::PeerVote(vote) => {
                verify_vote(vote, context, members, verifier)
            }
            Self::Availability(certificate) => {
                verify_certificate(certificate, context, members, verifier)
            }
            Self::BindCutoff(cutoff) => {
                cutoff.validate()?;
                if cutoff.is_zero() {
                    Err(EtdagError::ContextMismatch)
                } else {
                    Ok(())
                }
            }
        }
    }

    fn check(
        &self,
        evidence: &CollectingEvidence,
        local: &str,
        closed: bool,
        committed: bool,
    ) -> Result<(), EtdagError> {
        if committed {
            return Err(EtdagError::AdmissionClosed);
        }
        match self {
            Self::Vertex(vertex) => {
                if evidence.graph.len() >= 4096 {
                    return Err(EtdagError::InvalidCapacity);
                }
                if evidence.graph.contains(&vertex.vertex_id) {
                    return Err(EtdagError::DuplicateVertex(vertex.vertex_id.0.clone()));
                }
                if vertex.target_context_root != *evidence.graph.context_root()
                    || vertex.target_height != evidence.graph.target_height()
                {
                    return Err(EtdagError::ContextMismatch);
                }
                if let Some(parent) = vertex
                    .parents
                    .iter()
                    .find(|parent| !evidence.graph.contains(parent))
                {
                    return Err(EtdagError::UnknownParent(parent.0.clone()));
                }
            }
            Self::LocalVote(vote) | Self::PeerVote(vote) => {
                if !evidence.graph.contains(&vote.vertex_id) {
                    return Err(EtdagError::MissingArtifact(vote.vertex_id.0.clone()));
                }
                if vote.context_root != *evidence.graph.context_root() {
                    return Err(EtdagError::ContextMismatch);
                }
                if matches!(self, Self::LocalVote(_))
                    && (closed
                        || vote.validator_id != local
                        || evidence.local_votes.contains_key(&vote.vertex_id))
                {
                    return Err(EtdagError::AdmissionClosed);
                }
                if let Some(previous) = evidence
                    .votes
                    .get(&vote.vertex_id)
                    .and_then(|votes| votes.get(&vote.validator_id))
                {
                    // A local-signature transition may retain an already observed
                    // identical statement. Preserve the first peer signature.
                    if !matches!(self, Self::LocalVote(_))
                        || previous.context_root != vote.context_root
                        || previous.vertex_id != vote.vertex_id
                        || previous.key_id != vote.key_id
                    {
                        return Err(EtdagError::ConflictingArtifact(
                            "duplicate collecting vote".into(),
                        ));
                    }
                }
            }
            Self::Availability(certificate) => {
                if !evidence.graph.contains(&certificate.vertex_id) {
                    return Err(EtdagError::MissingArtifact(certificate.vertex_id.0.clone()));
                }
                if certificate.context_root != *evidence.graph.context_root()
                    || evidence.certificates.contains_key(&certificate.vertex_id)
                {
                    return Err(EtdagError::ConflictingArtifact(
                        "duplicate collecting certificate".into(),
                    ));
                }
            }
            Self::BindCutoff(_) => {
                if closed {
                    return Err(EtdagError::AdmissionClosed);
                }
            }
        }
        Ok(())
    }

    /// Called only after native authentication and check, on the sole owner.
    fn apply(self, evidence: &mut CollectingEvidence) {
        match self {
            Self::Vertex(vertex) => evidence
                .graph
                .insert(*vertex)
                .expect("prevalidated collecting vertex"),
            Self::LocalVote(vote) => {
                evidence
                    .votes
                    .entry(vote.vertex_id.clone())
                    .or_default()
                    .entry(vote.validator_id.clone())
                    .or_insert_with(|| vote.clone());
                evidence.local_votes.insert(vote.vertex_id.clone(), vote);
            }
            Self::PeerVote(vote) => {
                evidence
                    .votes
                    .entry(vote.vertex_id.clone())
                    .or_default()
                    .insert(vote.validator_id.clone(), vote);
            }
            Self::Availability(certificate) => {
                evidence
                    .certificates
                    .insert(certificate.vertex_id.clone(), certificate);
            }
            Self::BindCutoff(_) => unreachable!("cutoff transition has no collecting mutation"),
        }
    }
}

fn action_resource_bytes(action: &CollectingAction) -> Result<usize, EtdagError> {
    Ok(match action {
        CollectingAction::Vertex(vertex) => ProtectedPipeline::vertex_resource_bytes(vertex)?,
        CollectingAction::LocalVote(vote) => ProtectedPipeline::vote_resource_bytes(vote)
            .saturating_add(add_bytes([
                map_slot::<(EtdagDigest, AvailabilityVote)>(),
                digest_bytes(&vote.vertex_id),
                vote_heap_bytes(vote),
            ])),
        CollectingAction::PeerVote(vote) => ProtectedPipeline::vote_resource_bytes(vote),
        CollectingAction::Availability(certificate) => {
            ProtectedPipeline::certificate_resource_bytes(certificate)
        }
        CollectingAction::BindCutoff(_) => 1024,
    })
}
fn stored_resident_bytes(state: &StoredPipeline) -> Result<usize, EtdagError> {
    // Collecting uses actual deep capacities; the decoded remaining proof data
    // has bounded wire-derived allocations, reserved with a conservative factor.
    Ok(state
        .collecting
        .as_ref()
        .map_or(0, collecting_bytes)
        .saturating_add(
            encoded_len(&(
                &state.context,
                &state.parameters,
                &state.local_validator_id,
                &state.local_marker,
                &state.committed,
                &state.cut_recovery_generations,
                &state.retained_markers,
            ))?
            .saturating_mul(8),
        )
        .saturating_add(state.history.resource_bytes())
        .saturating_add(4096))
}

impl CollectingDelta {
    fn check(&self, state: &StoredPipeline, head: &EtdagDigest) -> Result<(), EtdagError> {
        if self.version != 3
            || &self.prior_head != head
            || self.context_root != state.context.root()?
            || self.target_height != state.context.target_height
            || self.local_validator_id != state.local_validator_id
        {
            return Err(journal_error("collecting transition binding mismatch"));
        }
        let evidence = state
            .collecting
            .as_ref()
            .ok_or_else(|| journal_error("collecting transition without collecting phase"))?;
        self.action.check(
            evidence,
            &state.local_validator_id,
            state.cutoff_context_root.is_some(),
            state.committed.is_some(),
        )
    }
    fn apply(self, state: &mut StoredPipeline) {
        match self.action {
            CollectingAction::BindCutoff(cutoff) => {
                state.cutoff_context_root = Some(cutoff.clone());
                state.original_cutoff_context_root = Some(cutoff);
            }
            action => action.apply(state.collecting.as_mut().expect("checked collecting phase")),
        }
    }
}

/// Local monotonic bookkeeping, never an authority or a replacement proof.
/// The preceding authenticated frame binds the exact prepared material.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConsumedDelta {
    version: u32,
    prior_head: EtdagDigest,
    context_root: EtdagDigest,
    target_height: u64,
    batch_root: EtdagDigest,
}

impl ConsumedDelta {
    fn apply(&self, state: &mut StoredPipeline, head: &EtdagDigest) -> Result<(), EtdagError> {
        if self.version != 2
            || &self.prior_head != head
            || self.context_root != state.context.root()?
            || self.target_height != state.context.target_height
        {
            return Err(journal_error("consumed transition binding mismatch"));
        }
        let committed = state
            .committed
            .as_mut()
            .ok_or_else(|| journal_error("consumed transition without committed batch"))?;
        if committed.prepared.is_none()
            || committed.consumed
            || committed.batch.protected_batch_root != self.batch_root
        {
            return Err(journal_error(
                "consumed transition requires exact prepared phase",
            ));
        }
        committed.consumed = true;
        Ok(())
    }
}
fn bounded_json(value: &impl Serialize) -> Result<Vec<u8>, EtdagError> {
    struct Bounded(Vec<u8>);
    impl std::io::Write for Bounded {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if bytes.len() > (JOURNAL_LIMIT - JOURNAL_HEADER - 8).saturating_sub(self.0.len()) {
                return Err(std::io::Error::other(
                    "protected transition exceeds journal capacity",
                ));
            }
            self.0.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut output = Bounded(Vec::with_capacity(encoded_len(value)?));
    serde_json::to_writer(&mut output, value).map_err(|error| {
        if error.is_io() {
            EtdagError::ResourcePressure("protected collecting frame reservation exhausted".into())
        } else {
            journal_error(error)
        }
    })?;
    Ok(output.0)
}

fn journal_digest(bytes: &[u8]) -> EtdagDigest {
    EtdagDigest::from_domain_bytes("SYNERGY_PROTECTED_SINGLE_JOURNAL_V1", bytes)
}
fn journal_error(error: impl std::fmt::Display) -> EtdagError {
    EtdagError::Corrupt(format!("protected journal: {error}"))
}
fn read_journal(
    file: &mut std::fs::File,
    authenticate: impl FnMut(
        &StoredPipeline,
        &[CutRecoveryGeneration],
        &[RetainedMarker],
        Option<&CollectingAction>,
    ) -> Result<(), EtdagError>,
) -> Result<(StoredPipeline, JournalCursor, Option<u64>), EtdagError> {
    let (state, cursor, tail, _) =
        read_journal_step(file, None, usize::MAX, true, usize::MAX, authenticate)?;
    Ok((state, cursor, tail))
}

fn read_journal_step(
    file: &mut std::fs::File,
    resume: Option<(StoredPipeline, JournalCursor)>,
    maximum_frames: usize,
    verified: bool,
    scratch_limit: usize,
    mut authenticate: impl FnMut(
        &StoredPipeline,
        &[CutRecoveryGeneration],
        &[RetainedMarker],
        Option<&CollectingAction>,
    ) -> Result<(), EtdagError>,
) -> Result<(StoredPipeline, JournalCursor, Option<u64>, bool), EtdagError> {
    let physical_length = file.metadata().map_err(journal_error)?.len();
    let (mut state, mut cursor) = if let Some((state, cursor)) = resume {
        if physical_length < cursor.length {
            return Err(journal_error("recovery journal regressed"));
        }
        file.seek(SeekFrom::Start(cursor.length))
            .map_err(journal_error)?;
        (state, cursor)
    } else {
        let (mut state, mut position) = {
            let mut decoded = serde_json::Deserializer::from_reader(BufReader::new(
                (&mut *file).take((JOURNAL_LIMIT + 1).min(scratch_limit / 8) as u64),
            ))
            .into_iter::<StoredPipeline>();
            let state = decoded
                .next()
                .ok_or_else(|| journal_error("missing initial JSON snapshot"))?
                .map_err(|error| {
                    if error.is_eof() && physical_length > (scratch_limit / 8) as u64 {
                        EtdagError::ResourcePressure(
                            "protected recovery snapshot exceeds scratch reservation".into(),
                        )
                    } else {
                        journal_error(error)
                    }
                })?;
            (state, decoded.byte_offset() as u64)
        };
        if position > JOURNAL_LIMIT as u64 {
            return Err(EtdagError::InvalidCapacity);
        }
        authenticate(
            &state,
            &state.cut_recovery_generations,
            &state.retained_markers,
            None,
        )?;
        state.authenticated = verified;
        state.collecting_encoded_bytes = state
            .collecting
            .as_ref()
            .map(encoded_len)
            .transpose()?
            .unwrap_or(0)
            .saturating_add(
                encoded_len(&(&state.context, &state.parameters, &state.local_validator_id))?
                    .saturating_add(4096),
            );
        if state.collecting_encoded_bytes > JOURNAL_LIMIT {
            return Err(EtdagError::InvalidCapacity);
        }
        state.resident_resource_bytes = stored_resident_bytes(&state)?;
        let generations = state.cut_recovery_generations.len();
        let markers = state.retained_markers.len();
        file.seek(SeekFrom::Start(position))
            .map_err(journal_error)?;
        while position < physical_length {
            let mut byte = [0];
            file.read_exact(&mut byte).map_err(journal_error)?;
            if !byte[0].is_ascii_whitespace() {
                file.seek(SeekFrom::Start(position))
                    .map_err(journal_error)?;
                break;
            }
            position += 1;
        }
        if position > JOURNAL_LIMIT as u64 {
            return Err(EtdagError::InvalidCapacity);
        }
        file.seek(SeekFrom::Start(0)).map_err(journal_error)?;
        let mut legacy = vec![0; position as usize];
        file.read_exact(&mut legacy).map_err(journal_error)?;
        let cursor = JournalCursor {
            length: position,
            head: journal_digest(&legacy),
            generations,
            markers,
            appended: false,
        };
        state.pending_location = Some(Arc::new(JournalLocation {
            offset: 0,
            length: position as usize,
            digest: cursor.head.clone(),
            initial: true,
        }));
        drop(legacy);
        if verified {
            let mut history = std::mem::take(&mut state.history);
            history.absorb(&mut state)?;
            state.history = history;
        }
        (state, cursor)
    };
    let mut frames = 0;
    loop {
        if cursor.length == physical_length {
            return Ok((state, cursor, None, true));
        }
        if frames >= maximum_frames {
            return Ok((state, cursor, None, false));
        }
        let remaining = physical_length - cursor.length;
        let mut header = vec![0; remaining.min(JOURNAL_HEADER as u64) as usize];
        file.read_exact(&mut header).map_err(journal_error)?;
        if header.len() < JOURNAL_HEADER {
            if !JOURNAL_MAGIC.starts_with(&header[..header.len().min(8)]) {
                return Err(journal_error("invalid incomplete-frame magic"));
            }
            return Ok((state, cursor, Some(physical_length), true));
        }
        if &header[..8] != JOURNAL_MAGIC {
            return Err(journal_error("frame magic mismatch"));
        }
        let length = u64::from_le_bytes(header[8..16].try_into().unwrap());
        if length == 0 || length > (JOURNAL_LIMIT - JOURNAL_HEADER - 8) as u64 {
            return Err(EtdagError::InvalidCapacity);
        }
        let previous = std::str::from_utf8(&header[16..144]).map_err(journal_error)?;
        let expected = EtdagDigest(
            std::str::from_utf8(&header[144..272])
                .map_err(journal_error)?
                .into(),
        );
        expected.validate()?;
        if previous != cursor.head.0 {
            return Err(journal_error("frame hash-chain mismatch"));
        }
        let frame_length = JOURNAL_HEADER as u64 + length + 8;
        if remaining < frame_length {
            return Ok((state, cursor, Some(physical_length), true));
        }
        // Decoded objects, payload, frame scratch and serde buffers all fit
        // a conservative reservation before any payload allocation occurs.
        if (length as usize)
            .saturating_mul(8)
            .saturating_add(JOURNAL_HEADER)
            .saturating_add(state.resident_resource_bytes)
            > scratch_limit
        {
            return Err(EtdagError::ResourcePressure(
                "protected recovery frame exceeds scratch reservation".into(),
            ));
        }
        let mut payload = vec![0; length as usize];
        file.read_exact(&mut payload).map_err(journal_error)?;
        let mut footer = [0; 8];
        file.read_exact(&mut footer).map_err(journal_error)?;
        if &footer != JOURNAL_END || journal_digest(&payload) != expected {
            return Err(journal_error("complete frame integrity mismatch"));
        }
        // A version probe skips unknown fields without materializing another
        // copy of large legacy proofs (an untagged enum would buffer them).
        let version: JournalVersion = serde_json::from_slice(&payload).map_err(journal_error)?;
        if version.version == 2 {
            let delta: ConsumedDelta = serde_json::from_slice(&payload).map_err(journal_error)?;
            delta.apply(&mut state, &cursor.head)?;
            cursor.length += frame_length;
            cursor.head = expected;
            cursor.appended = true;
            frames += 1;
            continue;
        }
        if version.version == 3 {
            let delta: CollectingDelta = serde_json::from_slice(&payload).map_err(journal_error)?;
            delta.check(&state, &cursor.head)?;
            let charge = encoded_len(&delta.action)?
                .saturating_mul(if matches!(delta.action, CollectingAction::LocalVote(_)) {
                    2
                } else {
                    1
                })
                .saturating_add(512);
            let next_encoded = state.collecting_encoded_bytes.saturating_add(charge);
            if next_encoded > JOURNAL_LIMIT {
                return Err(EtdagError::ResourcePressure(
                    "protected collecting replay reservation exhausted".into(),
                ));
            }
            authenticate(&state, &[], &[], Some(&delta.action))?;
            state.collecting_encoded_bytes = next_encoded;
            state.resident_resource_bytes = state
                .resident_resource_bytes
                .saturating_add(action_resource_bytes(&delta.action)?);
            delta.apply(&mut state);
            cursor.length += frame_length;
            cursor.head = expected;
            cursor.appended = true;
            frames += 1;
            continue;
        }
        let mut delta: JournalDelta = serde_json::from_slice(&payload).map_err(journal_error)?;
        if delta.version != 1
            || !delta.state.cut_recovery_generations.is_empty()
            || !delta.state.retained_markers.is_empty()
            || delta.state.context != state.context
            || delta.state.parameters != state.parameters
            || delta.state.local_validator_id != state.local_validator_id
            || delta
                .state
                .original_cutoff_context_root
                .as_ref()
                .or(delta.state.cutoff_context_root.as_ref())
                != state
                    .original_cutoff_context_root
                    .as_ref()
                    .or(state.cutoff_context_root.as_ref())
            || state.history.generations.len() + delta.generations.len() > 4096
            || state.history.markers.len() + delta.markers.len() > 4096
        {
            return Err(journal_error(
                "frame changes protected authority or exceeds existing horizon",
            ));
        }
        if delta.generations.is_empty() {
            if delta.state.cutoff_context_root != state.cutoff_context_root
                || !delta.markers.is_empty()
            {
                return Err(journal_error(
                    "frame changes cutoff without recovery evidence",
                ));
            }
            if let Some(marker) = &state.local_marker {
                if delta
                    .state
                    .local_marker
                    .as_ref()
                    .map(|next| next.signing_bytes())
                    .transpose()?
                    != Some(marker.signing_bytes()?)
                {
                    return Err(journal_error("frame replaces durable close signature"));
                }
            }
        } else {
            if delta.generations.last().map(|g| &g.cutoff_context_root)
                != delta.state.cutoff_context_root.as_ref()
            {
                return Err(journal_error("frame cutoff differs from recovery evidence"));
            }
            if let Some(marker) = &state.local_marker {
                if !delta.markers.iter().any(|retained| {
                    retained.marker == *marker
                        && Some(&retained.cutoff_context_root) == state.cutoff_context_root.as_ref()
                }) {
                    return Err(journal_error("frame loses prior durable marker"));
                }
            }
        }
        if let Some(committed) = &state.committed {
            if !delta.generations.is_empty()
                || delta.state.committed.as_ref().is_none_or(|next| {
                    next.batch != committed.batch
                        || next.cut != committed.cut
                        || (committed.consumed && !next.consumed)
                        || (committed.prepared.is_some() && next.prepared != committed.prepared)
                })
            {
                return Err(journal_error("frame replaces durable committed material"));
            }
        }
        authenticate(&delta.state, &delta.generations, &delta.markers, None)?;
        delta.state.authenticated = verified;
        delta.state.collecting_encoded_bytes = delta
            .state
            .collecting
            .as_ref()
            .map(encoded_len)
            .transpose()?
            .unwrap_or(0)
            .saturating_add(
                encoded_len(&(
                    &delta.state.context,
                    &delta.state.parameters,
                    &delta.state.local_validator_id,
                ))?
                .saturating_add(4096),
            );
        if delta.state.collecting_encoded_bytes > JOURNAL_LIMIT {
            return Err(EtdagError::InvalidCapacity);
        }
        delta.state.resident_resource_bytes = stored_resident_bytes(&delta.state)?;
        delta.state.pending_location = Some(Arc::new(JournalLocation {
            offset: cursor.length + JOURNAL_HEADER as u64,
            length: length as usize,
            digest: expected.clone(),
            initial: false,
        }));
        delta.state.history = std::mem::take(&mut state.history);
        delta.state.cut_recovery_generations = delta.generations;
        delta.state.retained_markers = delta.markers;
        if verified {
            let mut history = std::mem::take(&mut delta.state.history);
            history.absorb(&mut delta.state)?;
            delta.state.history = history;
        }
        state = delta.state;
        cursor.length += frame_length;
        cursor.head = expected;
        cursor.generations = state.history.generations.len() + state.cut_recovery_generations.len();
        cursor.markers = state.history.markers.len() + state.retained_markers.len();
        cursor.appended = true;
        frames += 1;
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "verify the complete durable pipeline and its retained proof sets against explicit frozen authority"
)]
fn authenticate_journal_state(
    state: &StoredPipeline,
    generations: &[CutRecoveryGeneration],
    markers: &[RetainedMarker],
    context: &TargetAdmissionContextV3,
    parameters: &EtdagParameters,
    local_validator_id: &str,
    members: &CutoffMembers,
    verifier: &(impl SignatureVerifier + ProtectedRecoveryVerifier),
) -> Result<(), EtdagError> {
    if !matches!(state.version, 2 | 3)
        || &state.context != context
        || &state.parameters != parameters
        || state.local_validator_id != local_validator_id
    {
        return Err(EtdagError::ContextMismatch);
    }
    for generation in generations {
        verifier.verify_cut_recovery_generation(context, generation)?;
    }
    if let Some(generation) = generations.last() {
        verifier.verify_cut_recovery_batch_binding(
            context,
            generation,
            state.committed.as_ref().map(|record| &record.batch),
        )?;
    }
    for retained in markers {
        verify_local_marker(
            &retained.marker,
            context,
            &retained.cutoff_context_root,
            local_validator_id,
            members,
            verifier,
        )?;
    }
    if let Some(marker) = &state.local_marker {
        verify_local_marker(
            marker,
            context,
            state
                .cutoff_context_root
                .as_ref()
                .ok_or(EtdagError::ContextMismatch)?,
            local_validator_id,
            members,
            verifier,
        )?;
    }
    if let Some(evidence) = &state.collecting {
        validate_collecting(evidence, context, local_validator_id, members, verifier)?;
    }
    if let Some(record) = &state.committed {
        if record.version != 1 || &record.context != context || &record.parameters != parameters {
            return Err(EtdagError::ContextMismatch);
        }
        let cut = record.cut.verify(
            context,
            state
                .cutoff_context_root
                .as_ref()
                .ok_or(EtdagError::ContextMismatch)?,
            &record.graph,
            &record.availability,
            members,
            verifier,
        )?;
        let seed = derive_target_order_seed(context, &cut)?;
        if DeterministicProtectedBatch::derive(&cut, &seed, parameters)? != record.batch {
            return Err(EtdagError::ConflictingArtifact(
                "journal protected batch".into(),
            ));
        }
        if let Some(prepared) = &record.prepared {
            prepared.validate()?;
            if &prepared.context != context || prepared.parent_evidence.next_batch != record.batch {
                return Err(EtdagError::ContextMismatch);
            }
            VerifiedRevealAuthorization::verify(
                prepared.reveal_authorization.clone(),
                &prepared.parent_evidence,
                verifier,
            )?;
            verify_prepared_recovery(record, verifier)?;
        } else if record.consumed {
            return Err(journal_error("consumed protected input absent"));
        }
    }
    Ok(())
}

/// Collection and committed state share one atomic target record. A crash
/// between signing a close statement and deriving the cut must not erase it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredPipeline {
    version: u32,
    // Private in-process provenance, never decoded from storage.
    #[serde(skip)]
    authenticated: bool,
    #[serde(skip)]
    collecting_encoded_bytes: usize,
    #[serde(skip)]
    resident_resource_bytes: usize,
    #[serde(skip)]
    history: VerifiedHistory,
    #[serde(skip)]
    pending_location: Option<Arc<JournalLocation>>,
    context: TargetAdmissionContextV3,
    parameters: EtdagParameters,
    cutoff_context_root: Option<EtdagDigest>,
    local_validator_id: String,
    local_marker: Option<ProtectedCutMarker>,
    committed: Option<Record>,
    #[serde(default)]
    collecting: Option<CollectingEvidence>,
    #[serde(default)]
    original_cutoff_context_root: Option<EtdagDigest>,
    #[serde(default)]
    cut_recovery_generations: Vec<CutRecoveryGeneration>,
    #[serde(default)]
    retained_markers: Vec<RetainedMarker>,
}

/// Reauthenticates nonempty persisted execution from signed reveal witnesses.
/// Implementations must verify every transcript against governed custody and
/// consensus keys, decrypt the retained envelopes, and compare exact plaintext.
pub trait ProtectedRecoveryVerifier: RevealAuthorizationVerifier {
    fn verify_cut_recovery_generation(
        &self,
        _context: &TargetAdmissionContextV3,
        _generation: &CutRecoveryGeneration,
    ) -> Result<(), EtdagError> {
        Err(EtdagError::UnauthorizedReveal)
    }
    /// Later certified material must bind the selected recovery generation.
    /// Absence checks at issuance cannot be substituted for this restart gate.
    fn verify_cut_recovery_batch_binding(
        &self,
        _context: &TargetAdmissionContextV3,
        _generation: &CutRecoveryGeneration,
        _batch: Option<&DeterministicProtectedBatch>,
    ) -> Result<(), EtdagError> {
        Err(EtdagError::ContextMismatch)
    }

    fn verify_nonempty_prepared(
        &self,
        context: &TargetAdmissionContextV3,
        prepared: &PreparedProtectedBatch,
        transcripts: &BTreeMap<EtdagDigest, crate::reveal::RevealTranscript>,
        envelopes: &BTreeMap<EtdagDigest, crate::EncryptedTransactionEnvelope>,
    ) -> Result<(), EtdagError>;
}

#[derive(Debug)]
pub struct ProtectedPipeline {
    store: synergy_storage::AtomicStore,
    key: String,
    context: TargetAdmissionContextV3,
    parameters: EtdagParameters,
    cutoff_context_root: Option<EtdagDigest>,
    local_validator_id: String,
    local_marker: Option<ProtectedCutMarker>,
    record: Option<Record>,
    collecting: CollectingEvidence,
    collecting_resource_bytes: usize,
    collecting_encoded_bytes: usize,
    transition_resource_budget: usize,
    history_resource_budget: usize,
    original_cutoff_context_root: Option<EtdagDigest>,
    cut_recovery_generations: Vec<CutRecoveryGeneration>,
    history: VerifiedHistory,
    retained_markers: Vec<RetainedMarker>,
    journal_cursor: RefCell<Option<JournalCursor>>,
}

/// Private recovery projection held by the existing ETDAG owner. No evidence
/// here can authorize admission or signing until poll returns a verified owner.
pub struct ProtectedPipelineRecovery {
    root: std::path::PathBuf,
    store: synergy_storage::AtomicStore,
    key: String,
    context: TargetAdmissionContextV3,
    parameters: EtdagParameters,
    cutoff: Option<EtdagDigest>,
    validator: String,
    state: Option<(StoredPipeline, JournalCursor)>,
    generation_next: usize,
    marker_next: usize,
    complete: bool,
    tail: Option<u64>,
}

impl ProtectedPipelineRecovery {
    pub fn retained_history_resource_bytes(&self) -> usize {
        self.state
            .as_ref()
            .map_or(0, |(state, _)| state.history.resource_bytes())
    }
    /// Performs at most four generation and four marker authentications or one
    /// bounded append-frame decode. Call only on the sole ETDAG owner thread.
    pub fn poll(
        &mut self,
        members: &CutoffMembers,
        verifier: &(impl SignatureVerifier + ProtectedRecoveryVerifier),
        cancelled: bool,
    ) -> Result<Option<ProtectedPipeline>, EtdagError> {
        self.poll_with_resource_budget(members, verifier, cancelled, usize::MAX)
    }

    /// Enforces the caller's transient decode reservation before allocating a
    /// snapshot/frame. Pressure retains the immutable journal for later retry.
    pub fn poll_with_resource_budget(
        &mut self,
        members: &CutoffMembers,
        verifier: &(impl SignatureVerifier + ProtectedRecoveryVerifier),
        cancelled: bool,
        scratch_bytes: usize,
    ) -> Result<Option<ProtectedPipeline>, EtdagError> {
        self.poll_with_resource_budgets(members, verifier, cancelled, scratch_bytes, usize::MAX)
    }

    /// The history ceiling is the caller's remaining aggregate retained pool,
    /// including this staged owner; decoded proof scratch remains independent.
    pub fn poll_with_resource_budgets(
        &mut self,
        members: &CutoffMembers,
        verifier: &(impl SignatureVerifier + ProtectedRecoveryVerifier),
        cancelled: bool,
        scratch_bytes: usize,
        history_bytes: usize,
    ) -> Result<Option<ProtectedPipeline>, EtdagError> {
        if self.retained_history_resource_bytes() > history_bytes {
            return Err(EtdagError::ResourcePressure(
                "protected retained history capacity exhausted".into(),
            ));
        }
        if cancelled {
            return Err(journal_error("protected recovery cancelled"));
        }
        if self.state.is_none() {
            let (state, cursor, tail, complete) = self
                .store
                .inspect_append_journal(&self.key, |file| {
                    read_journal_step(file, None, 0, false, scratch_bytes, |_, _, _, _| Ok(()))
                })
                .map_err(storage_error)??;
            self.state = Some((state, cursor));
            self.tail = tail;
            self.complete = complete;
            return Ok(None);
        }
        let (state, _) = self
            .state
            .as_ref()
            .ok_or_else(|| journal_error("recovery state missing"))?;
        if !matches!(state.version, 2 | 3)
            || state.context != self.context
            || state.parameters != self.parameters
            || state.local_validator_id != self.validator
        {
            return Err(EtdagError::ContextMismatch);
        }
        let end = (self.generation_next + 4).min(state.cut_recovery_generations.len());
        for generation in &state.cut_recovery_generations[self.generation_next..end] {
            verifier.verify_cut_recovery_generation(&self.context, generation)?;
        }
        self.generation_next = end;
        let end = (self.marker_next + 4).min(state.retained_markers.len());
        for retained in &state.retained_markers[self.marker_next..end] {
            verify_local_marker(
                &retained.marker,
                &self.context,
                &retained.cutoff_context_root,
                &self.validator,
                members,
                verifier,
            )?;
        }
        self.marker_next = end;
        if self.generation_next < state.cut_recovery_generations.len()
            || self.marker_next < state.retained_markers.len()
        {
            return Ok(None);
        }
        if !state.authenticated {
            authenticate_journal_state(
                state,
                &[],
                &[],
                &self.context,
                &self.parameters,
                &self.validator,
                members,
                verifier,
            )?;
        }
        if let Some(generation) = state
            .cut_recovery_generations
            .last()
            .or(state.history.last.as_ref())
        {
            verifier.verify_cut_recovery_batch_binding(
                &self.context,
                generation,
                state.committed.as_ref().map(|record| &record.batch),
            )?;
        }
        let (state, _) = self
            .state
            .as_mut()
            .ok_or_else(|| journal_error("recovery state missing"))?;
        let refresh_resident = !state.authenticated;
        let required_history = state.history.projected_resource_bytes(
            state.cut_recovery_generations.len(),
            state.retained_markers.len(),
            state.cut_recovery_generations.last(),
        );
        if required_history > history_bytes {
            return Err(EtdagError::ResourcePressure(format!(
                "protected retained history capacity: requested={required_history} limit={history_bytes}"
            )));
        }
        state.authenticated = true;
        let mut history = std::mem::take(&mut state.history);
        history.absorb(state)?;
        state.history = history;
        if refresh_resident || required_history != 0 {
            state.resident_resource_bytes = stored_resident_bytes(state)?;
        }
        self.generation_next = 0;
        self.marker_next = 0;
        if self.complete {
            let (state, cursor) = self
                .state
                .take()
                .ok_or_else(|| journal_error("recovery state missing"))?;
            let mut pipeline = ProtectedPipeline::open_inner_loaded(
                &self.root,
                self.context.clone(),
                self.parameters.clone(),
                self.cutoff.clone(),
                self.validator.clone(),
                members,
                verifier,
                Some((state, cursor, self.tail)),
            )?;
            pipeline.set_transition_resource_budget(scratch_bytes);
            pipeline.set_history_resource_budget(history_bytes);
            return Ok(Some(pipeline));
        }
        let previous = self
            .state
            .take()
            .ok_or_else(|| journal_error("recovery state missing"))?;
        let (state, cursor, tail, complete) = self
            .store
            .inspect_append_journal(&self.key, |file| {
                read_journal_step(
                    file,
                    Some(previous),
                    1,
                    false,
                    scratch_bytes,
                    |_, _, _, action| {
                        if let Some(action) = action {
                            action.authenticate(&self.context, members, verifier)?;
                        }
                        Ok(())
                    },
                )
            })
            .map_err(storage_error)??;
        self.state = Some((state, cursor));
        self.tail = tail;
        self.complete = complete;
        Ok(None)
    }
}

impl ProtectedPipeline {
    /// Stage only existing durable history. A missing journal has no recovery
    /// work and may be opened normally on its owner without a background signer.
    pub fn begin_recovery(
        root: impl AsRef<Path>,
        context: TargetAdmissionContextV3,
        parameters: EtdagParameters,
        cutoff: Option<EtdagDigest>,
        validator: String,
    ) -> Result<Option<ProtectedPipelineRecovery>, EtdagError> {
        context.validate_with_parameters(&parameters)?;
        let store = synergy_storage::AtomicStore::new(root.as_ref(), JOURNAL_LIMIT)
            .map_err(storage_error)?;
        let key = format!("protected-h{}.json", context.target_height);
        if !store.exists(&key).map_err(storage_error)? {
            return Ok(None);
        }
        Ok(Some(ProtectedPipelineRecovery {
            root: root.as_ref().into(),
            store,
            key,
            context,
            parameters,
            cutoff,
            validator,
            state: None,
            generation_next: 0,
            marker_next: 0,
            complete: false,
            tail: None,
        }))
    }
    /// Read-only, checksum-checked storage evidence for audit/qualification.
    /// This is NOT verified consensus authority; only open reauthenticates it.
    /// Incomplete tails are reported through the last complete state, never trimmed here.
    pub fn read_durable_evidence(
        root: impl AsRef<Path>,
        target: u64,
    ) -> Result<Option<serde_json::Value>, EtdagError> {
        if !root.as_ref().is_dir() {
            return Ok(None);
        }
        let store = synergy_storage::AtomicStore::new(root.as_ref(), JOURNAL_LIMIT)
            .map_err(storage_error)?;
        let key = format!("protected-h{target}.json");
        if !store.exists(&key).map_err(storage_error)? {
            return Ok(None);
        }
        let mut generations = Vec::new();
        let mut markers = Vec::new();
        let mut bytes = 0usize;
        let (mut state, _, _) = store
            .inspect_append_journal(&key, |file| {
                read_journal(file, |_, gs, ms, _| {
                    // Cap before retaining each additional decoded proof set.
                    bytes = bytes.saturating_add(
                        serde_json::to_vec(&(gs, ms)).map_err(journal_error)?.len(),
                    );
                    if bytes > JOURNAL_LIMIT {
                        return Err(EtdagError::InvalidCapacity);
                    }
                    generations.extend_from_slice(gs);
                    markers.extend_from_slice(ms);
                    Ok(())
                })
            })
            .map_err(storage_error)??;
        state.cut_recovery_generations = generations;
        state.retained_markers = markers;
        if serde_json::to_vec(&state).map_err(journal_error)?.len() > JOURNAL_LIMIT {
            return Err(EtdagError::InvalidCapacity);
        }
        serde_json::to_value(state).map(Some).map_err(journal_error)
    }
    /// The caller supplies the cutoff commitment from verified chain authority;
    /// persisted evidence must never choose its own expected authority.
    pub fn open(
        root: impl AsRef<Path>,
        context: TargetAdmissionContextV3,
        parameters: EtdagParameters,
        cutoff_context_root: EtdagDigest,
        local_validator_id: String,
        members: &CutoffMembers,
        verifier: &(impl SignatureVerifier + ProtectedRecoveryVerifier),
    ) -> Result<Self, EtdagError> {
        Self::open_inner(
            root,
            context,
            parameters,
            Some(cutoff_context_root),
            local_validator_id,
            members,
            verifier,
        )
    }

    /// Opens admission before the consensus cutoff event is available. A
    /// previously closed record requires the caller to supply its verified
    /// cutoff authority through `open`, never authority chosen by disk bytes.
    pub fn open_collecting(
        root: impl AsRef<Path>,
        context: TargetAdmissionContextV3,
        parameters: EtdagParameters,
        local_validator_id: String,
        members: &CutoffMembers,
        verifier: &(impl SignatureVerifier + ProtectedRecoveryVerifier),
    ) -> Result<Self, EtdagError> {
        Self::open_inner(
            root,
            context,
            parameters,
            None,
            local_validator_id,
            members,
            verifier,
        )
    }

    fn open_inner(
        root: impl AsRef<Path>,
        context: TargetAdmissionContextV3,
        parameters: EtdagParameters,
        cutoff_context_root: Option<EtdagDigest>,
        local_validator_id: String,
        members: &CutoffMembers,
        verifier: &(impl SignatureVerifier + ProtectedRecoveryVerifier),
    ) -> Result<Self, EtdagError> {
        Self::open_inner_loaded(
            root,
            context,
            parameters,
            cutoff_context_root,
            local_validator_id,
            members,
            verifier,
            None,
        )
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "completed native recovery retains all original explicit authority inputs"
    )]
    fn open_inner_loaded(
        root: impl AsRef<Path>,
        context: TargetAdmissionContextV3,
        parameters: EtdagParameters,
        cutoff_context_root: Option<EtdagDigest>,
        local_validator_id: String,
        members: &CutoffMembers,
        verifier: &(impl SignatureVerifier + ProtectedRecoveryVerifier),
        loaded: Option<(StoredPipeline, JournalCursor, Option<u64>)>,
    ) -> Result<Self, EtdagError> {
        context.validate_with_parameters(&parameters)?;
        if let Some(cutoff) = &cutoff_context_root {
            cutoff.validate()?;
            if cutoff.is_zero() {
                return Err(EtdagError::ContextMismatch);
            }
        }
        if !members.contains_key(&local_validator_id) {
            return Err(EtdagError::ContextMismatch);
        }
        let store = synergy_storage::AtomicStore::new(root.as_ref(), 16 * 1024 * 1024)
            .map_err(storage_error)?;
        let key = format!("protected-h{}.json", context.target_height);
        let original_cutoff_context_root = cutoff_context_root.clone();
        let mut cutoff_context_root = cutoff_context_root;
        let cut_recovery_generations = Vec::new();
        let retained_markers = Vec::new();
        let mut history = VerifiedHistory::default();
        let mut local_marker = None;
        let mut collecting = CollectingEvidence {
            graph: EtdagGraph::new(context.root()?, context.target_height)?,
            local_votes: BTreeMap::new(),
            votes: BTreeMap::new(),
            certificates: BTreeMap::new(),
        };
        let mut journal_cursor = None;
        let mut incomplete_tail = None;
        let record = if store.exists(&key).map_err(storage_error)? {
            let (stored, cursor, tail) = if let Some(loaded) = loaded {
                loaded
            } else {
                store
                    .inspect_append_journal(&key, |file| {
                        read_journal(file, |state, generations, markers, action| {
                            if let Some(action) = action {
                                return action.authenticate(&context, members, verifier);
                            }
                            authenticate_journal_state(
                                state,
                                generations,
                                markers,
                                &context,
                                &parameters,
                                &local_validator_id,
                                members,
                                verifier,
                            )
                        })
                    })
                    .map_err(storage_error)??
            };
            journal_cursor = Some(cursor);
            incomplete_tail = tail;
            if !matches!(stored.version, 2 | 3)
                || stored.context != context
                || stored.parameters != parameters
                || stored
                    .original_cutoff_context_root
                    .as_ref()
                    .or(stored.cutoff_context_root.as_ref())
                    .is_some_and(|stored| Some(stored) != original_cutoff_context_root.as_ref())
                || stored.local_validator_id != local_validator_id
            {
                return Err(EtdagError::ContextMismatch);
            }
            // The reader admits only authenticated, structurally linked history.
            // Pending payload vectors must have been drained before owner handoff.
            if !stored.cut_recovery_generations.is_empty() || !stored.retained_markers.is_empty() {
                return Err(journal_error("unverified pending history at owner handoff"));
            }
            cutoff_context_root = stored.cutoff_context_root;
            history = stored.history;
            let has_collecting = stored.collecting.is_some();
            if let Some(evidence) = stored.collecting {
                if !stored.authenticated {
                    validate_collecting(
                        &evidence,
                        &context,
                        &local_validator_id,
                        members,
                        verifier,
                    )?;
                }
                collecting = evidence;
            }
            if let Some(marker) = &stored.local_marker {
                verify_local_marker(
                    marker,
                    &context,
                    cutoff_context_root
                        .as_ref()
                        .ok_or(EtdagError::ContextMismatch)?,
                    &local_validator_id,
                    members,
                    verifier,
                )?;
            }
            local_marker = stored.local_marker;
            if let Some(record) = stored.committed {
                if record.version != 1
                    || record.context != context
                    || record.parameters != parameters
                {
                    return Err(EtdagError::ContextMismatch);
                }
                let cut = record.cut.verify(
                    &context,
                    cutoff_context_root
                        .as_ref()
                        .ok_or(EtdagError::ContextMismatch)?,
                    &record.graph,
                    &record.availability,
                    members,
                    verifier,
                )?;
                let seed = derive_target_order_seed(&context, &cut)?;
                if DeterministicProtectedBatch::derive(&cut, &seed, &parameters)? != record.batch {
                    return Err(EtdagError::ConflictingArtifact(
                        "persisted protected batch".into(),
                    ));
                }
                if let Some(prepared) = &record.prepared {
                    prepared.validate()?;
                    if prepared.context != context
                        || prepared.parent_evidence.next_batch != record.batch
                    {
                        return Err(EtdagError::ContextMismatch);
                    }
                    VerifiedRevealAuthorization::verify(
                        prepared.reveal_authorization.clone(),
                        &prepared.parent_evidence,
                        verifier,
                    )?;
                    verify_prepared_recovery(&record, verifier)?;
                } else if record.consumed {
                    return Err(EtdagError::Corrupt(
                        "consumed protected input is absent".into(),
                    ));
                }
                if !has_collecting {
                    collecting.graph = record.graph.clone();
                    collecting.certificates = record.availability.clone();
                }
                Some(record)
            } else {
                None
            }
        } else {
            None
        };
        if let Some(generation) = history.last.as_ref() {
            verifier.verify_cut_recovery_batch_binding(
                &context,
                generation,
                record.as_ref().map(|r| &r.batch),
            )?;
        }
        // Only fully reauthenticated native evidence permits recovery of an
        // incomplete, never-acknowledged last frame. Complete corruption failed above.
        if let (Some(physical), Some(cursor)) = (incomplete_tail, journal_cursor.as_ref()) {
            store
                .trim_uncommitted_journal_tail(&key, physical, cursor.length)
                .map_err(storage_error)?;
        }
        let collecting_resource_bytes = collecting_bytes(&collecting);
        let collecting_encoded_bytes = encoded_len(&collecting)?.saturating_add(
            encoded_len(&(&context, &parameters, &local_validator_id))?.saturating_add(4096),
        );
        if collecting_encoded_bytes > JOURNAL_LIMIT {
            return Err(EtdagError::InvalidCapacity);
        }
        Ok(Self {
            transition_resource_budget: usize::MAX,
            history_resource_budget: usize::MAX,
            collecting_resource_bytes,
            collecting_encoded_bytes,
            store,
            key,
            journal_cursor: RefCell::new(journal_cursor),
            context,
            parameters,
            cutoff_context_root,
            local_validator_id,
            local_marker,
            record,
            collecting,
            original_cutoff_context_root,
            cut_recovery_generations,
            history,
            retained_markers,
        })
    }

    /// Durable cutoff binding closes VAC signing before marker production.
    pub fn bind_cutoff(&mut self, cutoff: EtdagDigest) -> Result<bool, EtdagError> {
        cutoff.validate()?;
        if cutoff.is_zero() {
            return Err(EtdagError::ContextMismatch);
        }
        if let Some(existing) = &self.cutoff_context_root {
            return if existing == &cutoff {
                Ok(false)
            } else {
                Err(EtdagError::ConflictingArtifact(
                    "protected cutoff authority changed".into(),
                ))
            };
        }
        self.persist_collecting_action(CollectingAction::BindCutoff(cutoff))?;
        Ok(true)
    }

    pub fn admission_closed(&self) -> bool {
        self.cutoff_context_root.is_some()
    }

    pub fn original_cutoff_context_root(&self) -> Option<&EtdagDigest> {
        self.original_cutoff_context_root.as_ref()
    }
    pub fn cutoff_context_root(&self) -> Option<&EtdagDigest> {
        self.cutoff_context_root.as_ref()
    }
    pub fn cut_recovery_generation_count(&self) -> usize {
        self.history.generations.len()
    }
    pub fn retained_local_marker_count(&self) -> usize {
        self.history.markers.len()
    }
    pub fn last_cut_recovery_generation(&self) -> Option<&CutRecoveryGeneration> {
        self.history.last.as_ref()
    }
    pub fn has_cutoff_context(&self, root: &EtdagDigest) -> bool {
        self.original_cutoff_context_root.as_ref() == Some(root)
            || self.history.index.roots.contains_key(root)
    }
    /// Bounded inspection of one original proof; no all-history payload API.
    /// Its exact remembered frame digest and authenticated record identity are checked.
    pub fn read_cut_recovery_generation(
        &self,
        position: usize,
    ) -> Result<Option<CutRecoveryGeneration>, EtdagError> {
        let Some(expected) = self.history.generations.get(position) else {
            return Ok(None);
        };
        let location = &self.history.generation_locations[position];
        let original = self
            .store
            .inspect_append_journal(&self.key, |file| location.frame.read(file))
            .map_err(storage_error)??;
        let found = original
            .cut_recovery_generations
            .into_iter()
            .nth(location.index);
        if found
            .as_ref()
            .map(|g| EtdagDigest::from_canonical("SYNERGY_PROTECTED_GENERATION_RECORD_V1", g))
            .transpose()?
            .as_ref()
            != Some(expected)
        {
            return Err(journal_error("original generation changed"));
        }
        Ok(found)
    }
    pub fn read_retained_local_marker(
        &self,
        position: usize,
    ) -> Result<Option<ProtectedCutMarker>, EtdagError> {
        let Some((root, expected)) = self.history.markers.get(position) else {
            return Ok(None);
        };
        let location = &self.history.marker_locations[position];
        let original = self
            .store
            .inspect_append_journal(&self.key, |file| location.frame.read(file))
            .map_err(storage_error)??;
        let found = original
            .retained_markers
            .into_iter()
            .nth(location.index)
            .filter(|m| &m.cutoff_context_root == root)
            .map(|m| m.marker);
        if found
            .as_ref()
            .map(|m| EtdagDigest::from_canonical("SYNERGY_PROTECTED_MARKER_RECORD_V1", m))
            .transpose()?
            .as_ref()
            != Some(expected)
        {
            return Err(journal_error("original marker changed or missing"));
        }
        Ok(found)
    }
    #[cfg(test)]
    fn cut_recovery_generations(&self) -> Vec<CutRecoveryGeneration> {
        (0..self.cut_recovery_generation_count())
            .map(|i| self.read_cut_recovery_generation(i).unwrap().unwrap())
            .collect()
    }
    #[cfg(test)]
    fn retained_local_markers(&self) -> impl Iterator<Item = ProtectedCutMarker> + '_ {
        (0..self.retained_local_marker_count())
            .map(|i| self.read_retained_local_marker(i).unwrap().unwrap())
    }

    /// Persist PoSy's verified replacement authority before any new signature.
    /// Ordinary bind_cutoff remains immutable; admission never reopens.
    pub fn apply_cut_recovery_generation(
        &mut self,
        generation: CutRecoveryGeneration,
        verifier: &impl ProtectedRecoveryVerifier,
    ) -> Result<bool, EtdagError> {
        verifier.verify_cut_recovery_generation(&self.context, &generation)?;
        verifier.verify_cut_recovery_batch_binding(&self.context, &generation, None)?;
        if self.record.is_some() {
            return Err(EtdagError::ConflictingArtifact(
                "committed protected cut cannot recover".into(),
            ));
        }
        let existing = self
            .history
            .index
            .roots
            .get(&generation.cutoff_context_root)
            .or_else(|| self.history.index.ids.get(&generation.timeout_id));
        if let Some(position) = existing {
            return if self.history.generations[*position]
                == EtdagDigest::from_canonical(
                    "SYNERGY_PROTECTED_GENERATION_RECORD_V1",
                    &generation,
                )? {
                Ok(false)
            } else {
                Err(EtdagError::ConflictingArtifact(
                    "conflicting recovery generation".into(),
                ))
            };
        }
        validate_generation(
            &generation,
            self.original_cutoff_context_root.as_ref(),
            self.cutoff_context_root.as_ref(),
            &[],
        )?;
        if self.history.generations.len() >= 4096
            || self
                .history
                .last
                .as_ref()
                .is_some_and(|g| generation.timeout_round <= g.timeout_round)
        {
            return Err(EtdagError::ContextMismatch);
        }
        let required_history = self.prospective_history_resource_bytes(&generation);
        if required_history > self.history_resource_budget {
            return Err(EtdagError::ResourcePressure(format!(
                "protected retained history capacity: requested={required_history} limit={}",
                self.history_resource_budget
            )));
        }
        let previous_cutoff = self.cutoff_context_root.clone();
        let previous_marker = self.local_marker.take();
        let retained_len = self.retained_markers.len();
        if let Some(marker) = &previous_marker {
            self.retained_markers.push(RetainedMarker {
                cutoff_context_root: generation.previous_cutoff_context_root.clone(),
                marker: marker.clone(),
            });
        }
        self.cutoff_context_root = Some(generation.cutoff_context_root.clone());
        self.cut_recovery_generations.push(generation);
        let previous_length = self
            .journal_cursor
            .borrow()
            .as_ref()
            .ok_or_else(|| journal_error("missing durable cutoff"))?
            .length;
        if let Err(error) = self.write_state(None, None) {
            self.cutoff_context_root = previous_cutoff;
            self.local_marker = previous_marker;
            self.cut_recovery_generations.pop();
            self.retained_markers.truncate(retained_len);
            return Err(error);
        }
        let cursor = self.journal_cursor.borrow();
        let cursor = cursor
            .as_ref()
            .ok_or_else(|| journal_error("missing appended frame"))?;
        let location = Arc::new(JournalLocation {
            offset: previous_length + JOURNAL_HEADER as u64,
            length: (cursor.length - previous_length - JOURNAL_HEADER as u64 - 8) as usize,
            digest: cursor.head.clone(),
            initial: false,
        });
        self.history.generation_locations.push(ProofLocation {
            frame: Arc::clone(&location),
            index: 0,
        });
        if !self.retained_markers.is_empty() {
            self.history.marker_locations.push(ProofLocation {
                frame: location,
                index: 0,
            });
        }
        let generation = self
            .cut_recovery_generations
            .pop()
            .ok_or(EtdagError::ContextMismatch)?;
        self.history
            .index
            .insert(&generation, self.history.generations.len());
        self.history.generations.push(EtdagDigest::from_canonical(
            "SYNERGY_PROTECTED_GENERATION_RECORD_V1",
            &generation,
        )?);
        self.history.last = Some(generation);
        for retained in self.retained_markers.drain(..) {
            self.history.markers.push((
                retained.cutoff_context_root,
                EtdagDigest::from_canonical(
                    "SYNERGY_PROTECTED_MARKER_RECORD_V1",
                    &retained.marker,
                )?,
            ));
        }
        Ok(true)
    }
    /// Local allocation reservation only; never changes protocol capacity or
    /// authority. Insufficient capacity preserves durable evidence for retry.
    pub fn set_transition_resource_budget(&mut self, bytes: usize) {
        self.transition_resource_budget = bytes;
    }
    pub fn set_history_resource_budget(&mut self, bytes: usize) {
        self.history_resource_budget = bytes;
    }
    pub fn retained_history_resource_bytes(&self) -> usize {
        self.history.resource_bytes()
    }
    pub fn prospective_history_resource_bytes(&self, generation: &CutRecoveryGeneration) -> usize {
        if self.history.index.ids.contains_key(&generation.timeout_id)
            || self
                .history
                .index
                .roots
                .contains_key(&generation.cutoff_context_root)
        {
            return self.history.resource_bytes();
        }
        self.history.projected_resource_bytes(
            1,
            usize::from(self.local_marker.is_some()),
            Some(generation),
        )
    }
    fn check_transition_resources(&self, encoded: usize, owned: usize) -> Result<(), EtdagError> {
        if encoded
            .saturating_mul(8)
            .saturating_add(owned)
            .saturating_add(4096)
            > self.transition_resource_budget
        {
            return Err(EtdagError::ResourcePressure(
                "protected transition scratch reservation exhausted".into(),
            ));
        }
        Ok(())
    }

    /// Conservative cached charge for collecting-owned allocations only.
    /// Record/reveal/history and runtime mirrors require separate reservations.
    pub fn collecting_resource_bytes(&self) -> usize {
        self.collecting_resource_bytes
    }

    pub fn envelope_resource_bytes(envelope: &crate::EncryptedTransactionEnvelope) -> usize {
        std::mem::size_of::<crate::EncryptedTransactionEnvelope>()
            .saturating_add(envelope_heap_bytes(envelope))
    }
    pub fn wallet_admission_resource_bytes(
        admission: &crate::WalletAdmission,
    ) -> Result<usize, EtdagError> {
        Ok(std::mem::size_of::<crate::WalletAdmission>()
            .saturating_add(wallet_heap_bytes(admission)))
    }
    pub fn vertex_resource_bytes(vertex: &crate::TransactionVertex) -> Result<usize, EtdagError> {
        Ok(add_bytes([
            map_slot::<(EtdagDigest, crate::TransactionVertex)>(),
            digest_bytes(&vertex.vertex_id),
            vertex_heap_bytes(vertex),
        ]))
    }
    pub fn vote_resource_bytes(vote: &AvailabilityVote) -> usize {
        add_bytes([
            map_slot::<(String, AvailabilityVote)>(),
            vote.validator_id.capacity(),
            vote_heap_bytes(vote),
            map_slot::<(EtdagDigest, BTreeMap<String, AvailabilityVote>)>(),
            digest_bytes(&vote.vertex_id),
        ])
    }
    pub fn certificate_resource_bytes(certificate: &AvailabilityCertificate) -> usize {
        add_bytes([
            map_slot::<(EtdagDigest, AvailabilityCertificate)>(),
            digest_bytes(&certificate.vertex_id),
            certificate_heap_bytes(certificate),
        ])
    }

    pub fn graph(&self) -> &EtdagGraph {
        &self.collecting.graph
    }
    pub fn availability(&self) -> &BTreeMap<EtdagDigest, AvailabilityCertificate> {
        &self.collecting.certificates
    }
    pub fn local_votes(&self) -> &BTreeMap<EtdagDigest, AvailabilityVote> {
        &self.collecting.local_votes
    }

    /// Authenticated graph data is retained before any local custody vote.
    pub fn persist_vertex(
        &mut self,
        vertex: crate::TransactionVertex,
        members: &CutoffMembers,
        verifier: &impl SignatureVerifier,
    ) -> Result<bool, EtdagError> {
        if self.collecting.graph.get(&vertex.vertex_id) == Some(&vertex) {
            return Ok(false);
        }
        verify_vertex(&vertex, &self.context, members, verifier)?;
        if self.collecting.graph.contains(&vertex.vertex_id) {
            return Ok(false);
        }
        if self.collecting.graph.len() >= 4096 {
            return Err(EtdagError::InvalidCapacity);
        }
        self.persist_collecting_action(CollectingAction::Vertex(Box::new(vertex)))?;
        Ok(true)
    }

    /// Called before broadcast; restart retries the original signed vote.
    pub fn persist_local_vote(
        &mut self,
        vote: AvailabilityVote,
        members: &CutoffMembers,
        verifier: &impl SignatureVerifier,
    ) -> Result<bool, EtdagError> {
        verify_vote(&vote, &self.context, members, verifier)?;
        if vote.validator_id != self.local_validator_id
            || !self.collecting.graph.contains(&vote.vertex_id)
        {
            return Err(EtdagError::ContextMismatch);
        }
        if self.collecting.local_votes.contains_key(&vote.vertex_id) {
            return Ok(false);
        }
        if self.admission_closed() {
            return Err(EtdagError::AdmissionClosed);
        }
        self.persist_collecting_action(CollectingAction::LocalVote(vote))?;
        Ok(true)
    }

    pub fn persist_vote(
        &mut self,
        vote: AvailabilityVote,
        members: &CutoffMembers,
        verifier: &impl SignatureVerifier,
    ) -> Result<bool, EtdagError> {
        verify_vote(&vote, &self.context, members, verifier)?;
        if !self.collecting.graph.contains(&vote.vertex_id) {
            return Err(EtdagError::MissingArtifact(vote.vertex_id.0));
        }
        if self
            .collecting
            .votes
            .get(&vote.vertex_id)
            .is_some_and(|votes| votes.contains_key(&vote.validator_id))
        {
            return Ok(false);
        }
        self.persist_collecting_action(CollectingAction::PeerVote(vote))?;
        Ok(true)
    }

    pub fn assembled_availability(
        &self,
        vertex: &EtdagDigest,
        members: &CutoffMembers,
        verifier: &impl SignatureVerifier,
    ) -> Result<AvailabilityCertificate, EtdagError> {
        let votes = self
            .collecting
            .votes
            .get(vertex)
            .map(|votes| votes.values().cloned().collect())
            .unwrap_or_default();
        let certificate = AvailabilityCertificate::from_votes(
            self.context.root()?,
            vertex.clone(),
            votes,
            members.len(),
        )?;
        verify_certificate(&certificate, &self.context, members, verifier)?;
        Ok(certificate)
    }

    pub fn persist_availability(
        &mut self,
        certificate: AvailabilityCertificate,
        members: &CutoffMembers,
        verifier: &impl SignatureVerifier,
    ) -> Result<bool, EtdagError> {
        verify_certificate(&certificate, &self.context, members, verifier)?;
        if !self.collecting.graph.contains(&certificate.vertex_id) {
            return Err(EtdagError::MissingArtifact(certificate.vertex_id.0));
        }
        if self
            .collecting
            .certificates
            .contains_key(&certificate.vertex_id)
        {
            return Ok(false);
        }
        self.persist_collecting_action(CollectingAction::Availability(certificate))?;
        Ok(true)
    }

    fn persist_collecting_action(&mut self, action: CollectingAction) -> Result<(), EtdagError> {
        action.check(
            &self.collecting,
            &self.local_validator_id,
            self.admission_closed(),
            self.record.is_some(),
        )?;
        // The original empty/legacy snapshot remains the immutable journal base.
        if self.journal_cursor.borrow().is_none() {
            self.write_state(self.local_marker.clone(), self.record.clone())?;
        }
        let previous = self
            .journal_cursor
            .borrow()
            .as_ref()
            .expect("initialized journal")
            .clone();
        let delta = CollectingDelta {
            version: 3,
            prior_head: previous.head.clone(),
            context_root: self.context.root()?,
            target_height: self.context.target_height,
            local_validator_id: self.local_validator_id.clone(),
            action,
        };
        let action_encoded = encoded_len(&delta.action)?;
        if action_encoded.saturating_add(1024).saturating_mul(8) > 32 * 1024 * 1024 {
            return Err(EtdagError::ResourcePressure(
                "protected collecting transition exceeds scratch reservation".into(),
            ));
        }
        let encoded_charge = action_encoded
            .saturating_mul(if matches!(delta.action, CollectingAction::LocalVote(_)) {
                2
            } else {
                1
            })
            .saturating_add(512);
        let next_encoded = self.collecting_encoded_bytes.saturating_add(encoded_charge);
        if next_encoded > JOURNAL_LIMIT {
            return Err(EtdagError::ResourcePressure(
                "protected collecting encoded-state reservation exhausted".into(),
            ));
        }
        let resource_charge = action_resource_bytes(&delta.action)?;
        self.check_transition_resources(action_encoded.saturating_add(1024), resource_charge)?;
        let payload = bounded_json(&delta)?;
        let head = journal_digest(&payload);
        let mut frame = Vec::with_capacity(JOURNAL_HEADER + payload.len() + 8);
        frame.extend_from_slice(JOURNAL_MAGIC);
        frame.extend_from_slice(&(payload.len() as u64).to_le_bytes());
        frame.extend_from_slice(previous.head.0.as_bytes());
        frame.extend_from_slice(head.0.as_bytes());
        frame.extend_from_slice(&payload);
        frame.extend_from_slice(JOURNAL_END);
        self.store
            .append_journal_frame(&self.key, previous.length, &frame)
            .map_err(storage_error)?;
        // No fallible validation or storage operation follows durable append.
        self.collecting_resource_bytes = self
            .collecting_resource_bytes
            .saturating_add(resource_charge);
        self.collecting_encoded_bytes = next_encoded;
        match delta.action {
            CollectingAction::BindCutoff(cutoff) => {
                self.cutoff_context_root = Some(cutoff.clone());
                self.original_cutoff_context_root = Some(cutoff);
            }
            action => action.apply(&mut self.collecting),
        }
        *self.journal_cursor.borrow_mut() = Some(JournalCursor {
            length: previous.length + frame.len() as u64,
            head,
            appended: true,
            ..previous
        });
        Ok(())
    }

    /// Retry the exact durable signature, including after a process restart.
    pub fn local_marker(&self) -> Option<&ProtectedCutMarker> {
        self.local_marker.as_ref()
    }

    /// Call before broadcasting. Changed close statements for the same target
    /// are rejected even if their signatures are individually valid.
    pub fn persist_local_marker(
        &mut self,
        marker: ProtectedCutMarker,
        members: &CutoffMembers,
        verifier: &impl SignatureVerifier,
    ) -> Result<bool, EtdagError> {
        verify_local_marker(
            &marker,
            &self.context,
            self.cutoff_context_root
                .as_ref()
                .ok_or(EtdagError::AdmissionClosed)?,
            &self.local_validator_id,
            members,
            verifier,
        )?;
        if let Some(existing) = &self.local_marker {
            return if existing.signing_bytes()? == marker.signing_bytes()? {
                Ok(false)
            } else {
                Err(EtdagError::ConflictingArtifact(
                    "local cutoff marker changed".into(),
                ))
            };
        }
        self.check_transition_resources(
            encoded_len(&(&self.record, &marker))?.saturating_add(self.collecting_encoded_bytes),
            self.collecting_resource_bytes,
        )?;
        self.write_state(Some(marker.clone()), self.record.clone())?;
        self.local_marker = Some(marker);
        Ok(true)
    }

    /// Freeze verified semantic material exactly once. Different valid signer
    /// subsets for the same cut are idempotent; a changed cut is a conflict.
    #[allow(clippy::too_many_arguments)]
    pub fn accept_cut(
        &mut self,
        markers: &[ProtectedCutMarker],
        graph: &EtdagGraph,
        availability: &BTreeMap<EtdagDigest, AvailabilityCertificate>,
        members: &CutoffMembers,
        verifier: &impl SignatureVerifier,
    ) -> Result<bool, EtdagError> {
        self.check_transition_resources(
            encoded_len(&(graph, availability, markers))?,
            self.collecting_resource_bytes,
        )?;
        let cut = ProtectedCutProof::derive(
            &self.context,
            self.cutoff_context_root
                .as_ref()
                .ok_or(EtdagError::AdmissionClosed)?,
            markers,
            graph,
            availability,
            members,
            verifier,
        )?;
        let seed = derive_target_order_seed(&self.context, &cut)?;
        let batch = DeterministicProtectedBatch::derive(&cut, &seed, &self.parameters)?;
        if let Some(current) = &self.record {
            return if current.batch == batch {
                Ok(false)
            } else {
                Err(EtdagError::ConflictingArtifact(
                    "protected cut changed after commitment".into(),
                ))
            };
        }
        // Persist only the certified causal closure, not unrelated local cache.
        let ids: std::collections::BTreeSet<_> = cut.vertices().iter().cloned().collect();
        let mut retained_graph = EtdagGraph::new(self.context.root()?, self.context.target_height)?;
        for id in crate::deterministic_topological_order(graph)? {
            if ids.contains(&id) {
                retained_graph.insert(
                    graph
                        .get(&id)
                        .ok_or_else(|| EtdagError::MissingArtifact(id.0.clone()))?
                        .clone(),
                )?;
            }
        }
        let retained = availability
            .iter()
            .filter(|(id, _)| ids.contains(*id))
            .map(|(id, cert)| (id.clone(), cert.clone()))
            .collect();
        self.commit(Record {
            version: 1,
            context: self.context.clone(),
            parameters: self.parameters.clone(),
            cut: cut.proof().clone(),
            graph: retained_graph,
            availability: retained,
            batch,
            prepared: None,
            reveal_transcripts: BTreeMap::new(),
            consumed: false,
        })?;
        Ok(true)
    }

    pub fn batch(&self) -> Option<&DeterministicProtectedBatch> {
        self.record.as_ref().map(|record| &record.batch)
    }
    pub fn prepared(&self) -> Option<&PreparedProtectedBatch> {
        self.record
            .as_ref()
            .and_then(|record| record.prepared.as_ref())
    }

    /// Empty execution is legal only after the authenticated cut selected no
    /// transactions and the ordinary parent PoSy proof fixed that exact batch.
    pub fn prepare_empty(
        &mut self,
        authorization: crate::ProtectedRevealAuthorization,
        evidence: ParentProposalRevealEvidence,
        verifier: &impl RevealAuthorizationVerifier,
    ) -> Result<bool, EtdagError> {
        let current = self
            .record
            .as_ref()
            .ok_or_else(|| EtdagError::MissingArtifact("protected cut".into()))?;
        if !current.batch.ordered_transaction_ids.is_empty() || evidence.next_batch != current.batch
        {
            return Err(EtdagError::InvalidExecutionInput);
        }
        self.check_transition_resources(
            encoded_len(&(current, &authorization, &evidence))?,
            self.collecting_resource_bytes,
        )?;
        let verified = VerifiedRevealAuthorization::verify(authorization, &evidence, verifier)?;
        let transcript = EtdagDigest::from_canonical(
            "SYNERGY_ETDAG_BATCH_REVEAL_TRANSCRIPTS_V1",
            &Vec::<(EtdagDigest, EtdagDigest)>::new(),
        )?;
        let input = crate::DeterministicProtectedExecutionInput::from_batch(
            &current.batch,
            &BTreeMap::new(),
            transcript,
        )?;
        let prepared = crate::execution::prepare_deterministic_batch(
            self.context.clone(),
            &input,
            &BTreeMap::new(),
            &[],
            &verified,
            evidence,
        )?;
        if let Some(existing) = &current.prepared {
            // Parent QC proof subsets may differ without changing authority.
            return if existing.reveal_authorization == prepared.reveal_authorization {
                Ok(false)
            } else {
                Err(EtdagError::ConflictingArtifact(
                    "protected reveal parent changed".into(),
                ))
            };
        }
        let mut next = current.clone();
        next.prepared = Some(prepared);
        next.reveal_transcripts.clear();
        self.commit(next)?;
        Ok(true)
    }

    /// Prepares only threshold-verified revealed inputs for the authenticated cut.
    /// Signed witnesses are persisted atomically and reverified after restart.
    pub fn prepare_revealed(
        &mut self,
        authorization: crate::ProtectedRevealAuthorization,
        evidence: ParentProposalRevealEvidence,
        revealed: &[crate::reveal::RevealedTransaction],
        transcripts: BTreeMap<EtdagDigest, crate::reveal::RevealTranscript>,
        verifier: &impl ProtectedRecoveryVerifier,
    ) -> Result<bool, EtdagError> {
        let current = self
            .record
            .as_ref()
            .ok_or_else(|| EtdagError::MissingArtifact("protected cut".into()))?;
        if current.batch.ordered_transaction_ids.is_empty() || evidence.next_batch != current.batch
        {
            return Err(EtdagError::InvalidExecutionInput);
        }
        self.check_transition_resources(
            encoded_len(&(current, &authorization, &evidence, &transcripts))?.saturating_add(
                revealed
                    .iter()
                    .map(|transaction| transaction.plaintext().len())
                    .fold(0usize, usize::saturating_add),
            ),
            self.collecting_resource_bytes,
        )?;
        let verified = VerifiedRevealAuthorization::verify(authorization, &evidence, verifier)?;
        let (vertex_envelopes, _) = selected_envelopes(current)?;
        let mut entries: Vec<_> = revealed
            .iter()
            .map(|transaction| {
                (
                    transaction.envelope_id().clone(),
                    transaction.transcript_root().clone(),
                )
            })
            .collect();
        entries.sort();
        let root =
            EtdagDigest::from_canonical("SYNERGY_ETDAG_BATCH_REVEAL_TRANSCRIPTS_V1", &entries)?;
        let input = crate::DeterministicProtectedExecutionInput::from_batch(
            &current.batch,
            &vertex_envelopes,
            root,
        )?;
        let prepared = crate::execution::prepare_deterministic_batch(
            self.context.clone(),
            &input,
            &vertex_envelopes,
            revealed,
            &verified,
            evidence,
        )?;
        let mut next = current.clone();
        next.prepared = Some(prepared.clone());
        next.reveal_transcripts = transcripts;
        verify_prepared_recovery(&next, verifier)?;
        if let Some(existing) = &current.prepared {
            return if existing.context == prepared.context
                && existing.context_root == prepared.context_root
                && existing.target_height == prepared.target_height
                && existing.protected_batch_root == prepared.protected_batch_root
                && existing.reveal_authorization == prepared.reveal_authorization
                && existing.transactions == prepared.transactions
            {
                Ok(false)
            } else {
                Err(EtdagError::ConflictingArtifact(
                    "protected revealed execution changed".into(),
                ))
            };
        }
        self.commit(next)?;
        Ok(true)
    }

    pub fn mark_consumed(&mut self, batch_root: &EtdagDigest) -> Result<bool, EtdagError> {
        let current = self
            .record
            .as_ref()
            .ok_or_else(|| EtdagError::MissingArtifact("protected cut".into()))?;
        if current.prepared.is_none() || &current.batch.protected_batch_root != batch_root {
            return Err(EtdagError::InvalidExecutionInput);
        }
        if current.consumed {
            return Ok(false);
        }
        let mut cursor = self.journal_cursor.borrow_mut();
        let previous = cursor
            .as_ref()
            .ok_or_else(|| journal_error("consumed transition without durable prepared state"))?;
        let payload = serde_json::to_vec(&ConsumedDelta {
            version: 2,
            prior_head: previous.head.clone(),
            context_root: self.context.root()?,
            target_height: self.context.target_height,
            batch_root: batch_root.clone(),
        })
        .map_err(journal_error)?;
        let head = journal_digest(&payload);
        let mut frame = Vec::with_capacity(payload.len() + JOURNAL_HEADER + 8);
        frame.extend_from_slice(JOURNAL_MAGIC);
        frame.extend_from_slice(&(payload.len() as u64).to_le_bytes());
        frame.extend_from_slice(previous.head.0.as_bytes());
        frame.extend_from_slice(head.0.as_bytes());
        frame.extend_from_slice(&payload);
        frame.extend_from_slice(JOURNAL_END);
        self.store
            .append_journal_frame(&self.key, previous.length, &frame)
            .map_err(storage_error)?;
        *cursor = Some(JournalCursor {
            length: previous.length + frame.len() as u64,
            head,
            generations: previous.generations,
            markers: previous.markers,
            appended: true,
        });
        // No proof is cloned or serialized, and failed durability leaves the
        // in-memory phase untouched.
        self.record
            .as_mut()
            .expect("validated prepared record")
            .consumed = true;
        Ok(true)
    }

    fn write_state(
        &self,
        local_marker: Option<ProtectedCutMarker>,
        committed: Option<Record>,
    ) -> Result<(), EtdagError> {
        self.check_transition_resources(
            encoded_len(&(
                &self.context,
                &self.parameters,
                &local_marker,
                &committed,
                &self.cut_recovery_generations,
                &self.retained_markers,
            ))?
            .saturating_add(if committed.is_none() {
                self.collecting_encoded_bytes
            } else {
                0
            }),
            self.collecting_resource_bytes,
        )?;
        // After commitment the authenticated retained closure and VACs in
        // Record are sufficient for recovery; the durable cutoff forbids new
        // local votes, so duplicate collecting copies are unnecessary.
        let collecting = if committed.is_none() {
            Some(self.collecting.clone())
        } else {
            None
        };
        let append_mode = self
            .journal_cursor
            .borrow()
            .as_ref()
            .is_some_and(|previous| {
                previous.appended
                    || !self.history.generations.is_empty()
                    || !self.cut_recovery_generations.is_empty()
            });
        let stored = StoredPipeline {
            authenticated: false,
            collecting_encoded_bytes: 0,
            resident_resource_bytes: 0,
            version: 3,
            history: VerifiedHistory::default(),
            pending_location: None,
            context: self.context.clone(),
            parameters: self.parameters.clone(),
            cutoff_context_root: self.cutoff_context_root.clone(),
            local_validator_id: self.local_validator_id.clone(),
            local_marker,
            committed,
            collecting,
            original_cutoff_context_root: self.original_cutoff_context_root.clone(),
            cut_recovery_generations: if append_mode {
                Vec::new()
            } else {
                self.cut_recovery_generations.clone()
            },
            retained_markers: if append_mode {
                Vec::new()
            } else {
                self.retained_markers.clone()
            },
        };
        let mut cursor = self.journal_cursor.borrow_mut();
        if let Some(previous) = cursor.as_ref().filter(|_| append_mode) {
            if previous.generations != self.history.generations.len()
                || previous.markers != self.history.markers.len()
            {
                return Err(journal_error("owner history rolled backward"));
            }
            let generations = self.cut_recovery_generations.clone();
            let markers = self.retained_markers.clone();
            let generation_count =
                self.history.generations.len() + self.cut_recovery_generations.len();
            let marker_count = self.history.markers.len() + self.retained_markers.len();
            let mut state = stored;
            state.cut_recovery_generations.clear();
            state.retained_markers.clear();
            let payload = bounded_json(&JournalDelta {
                version: 1,
                state,
                generations,
                markers,
            })?;
            if payload.len() + JOURNAL_HEADER + 8 > JOURNAL_LIMIT {
                return Err(EtdagError::InvalidCapacity);
            }
            let head = journal_digest(&payload);
            let mut frame = Vec::with_capacity(payload.len() + JOURNAL_HEADER + 8);
            frame.extend_from_slice(JOURNAL_MAGIC);
            frame.extend_from_slice(&(payload.len() as u64).to_le_bytes());
            frame.extend_from_slice(previous.head.0.as_bytes());
            frame.extend_from_slice(head.0.as_bytes());
            frame.extend_from_slice(&payload);
            frame.extend_from_slice(JOURNAL_END);
            self.store
                .append_journal_frame(&self.key, previous.length, &frame)
                .map_err(storage_error)?;
            *cursor = Some(JournalCursor {
                length: previous.length + frame.len() as u64,
                head,
                generations: generation_count,
                markers: marker_count,
                appended: true,
            });
            return Ok(());
        }
        let bytes = bounded_json(&stored)?;
        if bytes.len() > JOURNAL_LIMIT {
            return Err(EtdagError::InvalidCapacity);
        }
        self.store
            .write_atomic(&self.key, &bytes)
            .map_err(storage_error)?;
        *cursor = Some(JournalCursor {
            length: bytes.len() as u64,
            head: journal_digest(&bytes),
            generations: stored.cut_recovery_generations.len(),
            markers: stored.retained_markers.len(),
            appended: false,
        });
        Ok(())
    }

    fn commit(&mut self, next: Record) -> Result<(), EtdagError> {
        self.check_transition_resources(encoded_len(&next)?, self.collecting_resource_bytes)?;
        self.write_state(self.local_marker.clone(), Some(next.clone()))?;
        self.record = Some(next);
        Ok(())
    }
}
type SelectedEnvelopes = (
    BTreeMap<EtdagDigest, EtdagDigest>,
    BTreeMap<EtdagDigest, crate::EncryptedTransactionEnvelope>,
);

fn selected_envelopes(record: &Record) -> Result<SelectedEnvelopes, EtdagError> {
    let mut vertices = BTreeMap::new();
    let mut envelopes = BTreeMap::new();
    for vertex in record.graph.vertices() {
        if record
            .batch
            .ordered_transaction_ids
            .contains(&vertex.envelope.envelope_id)
        {
            if envelopes
                .insert(vertex.envelope.envelope_id.clone(), vertex.envelope.clone())
                .is_some()
            {
                return Err(EtdagError::DuplicateEnvelope);
            }
            vertices.insert(
                vertex.vertex_id.clone(),
                vertex.envelope.envelope_id.clone(),
            );
        }
    }
    if envelopes.len() != record.batch.ordered_transaction_ids.len() {
        return Err(EtdagError::InvalidExecutionInput);
    }
    Ok((vertices, envelopes))
}

fn verify_prepared_recovery(
    record: &Record,
    verifier: &impl ProtectedRecoveryVerifier,
) -> Result<(), EtdagError> {
    let prepared = record
        .prepared
        .as_ref()
        .ok_or(EtdagError::InvalidExecutionInput)?;
    if prepared.transactions.is_empty() {
        if !record.reveal_transcripts.is_empty() {
            return Err(EtdagError::UnauthorizedReveal);
        }
        return Ok(());
    }
    let (vertices, envelopes) = selected_envelopes(record)?;
    if prepared.transactions.len() != vertices.len()
        || prepared.transactions.iter().any(|transaction| {
            vertices.get(&transaction.vertex_id) != Some(&transaction.envelope_id)
        })
    {
        return Err(EtdagError::InvalidExecutionInput);
    }
    if record.reveal_transcripts.len() != envelopes.len()
        || record.reveal_transcripts.iter().any(|(id, transcript)| {
            !envelopes.contains_key(id)
                || transcript.authorization != prepared.reveal_authorization
                || transcript.shares.is_empty()
                || transcript
                    .shares
                    .iter()
                    .any(|share| &share.envelope_id != id)
        })
    {
        return Err(EtdagError::UnauthorizedReveal);
    }
    verifier.verify_nonempty_prepared(
        &record.context,
        prepared,
        &record.reveal_transcripts,
        &envelopes,
    )
}

fn storage_error(error: synergy_storage::StorageError) -> EtdagError {
    EtdagError::Storage(error.to_string())
}

fn verify_local_marker(
    marker: &ProtectedCutMarker,
    context: &TargetAdmissionContextV3,
    cutoff: &EtdagDigest,
    local_validator_id: &str,
    members: &CutoffMembers,
    verifier: &impl SignatureVerifier,
) -> Result<(), EtdagError> {
    marker.validate()?;
    let (key, _) = members
        .get(local_validator_id)
        .ok_or_else(|| EtdagError::UnauthorizedValidator(local_validator_id.into()))?;
    if marker.validator_id != local_validator_id
        || marker.key_id != *key
        || marker.context_root != context.root()?
        || marker.target_height != context.target_height
        || &marker.cutoff_context_root != cutoff
    {
        return Err(EtdagError::ContextMismatch);
    }
    verifier.verify(
        local_validator_id,
        key,
        &marker.signing_bytes()?,
        &marker.signature,
    )
}

fn verify_vertex(
    vertex: &crate::TransactionVertex,
    context: &TargetAdmissionContextV3,
    members: &CutoffMembers,
    verifier: &impl SignatureVerifier,
) -> Result<(), EtdagError> {
    vertex.validate()?;
    crate::dag::validate_vertex_identity(vertex)?;
    if vertex.target_context_root != context.root()?
        || vertex.target_height != context.target_height
    {
        return Err(EtdagError::ContextMismatch);
    }
    let (key, _) = members
        .get(&vertex.author_id)
        .ok_or_else(|| EtdagError::UnauthorizedValidator(vertex.author_id.clone()))?;
    verifier.verify(
        &vertex.author_id,
        key,
        vertex.vertex_id.0.as_bytes(),
        &vertex.author_signature,
    )
}

fn verify_vote(
    vote: &AvailabilityVote,
    context: &TargetAdmissionContextV3,
    members: &CutoffMembers,
    verifier: &impl SignatureVerifier,
) -> Result<(), EtdagError> {
    vote.validate()?;
    if vote.context_root != context.root()? {
        return Err(EtdagError::ContextMismatch);
    }
    let (key, _) = members
        .get(&vote.validator_id)
        .ok_or_else(|| EtdagError::UnauthorizedValidator(vote.validator_id.clone()))?;
    if &vote.key_id != key {
        return Err(EtdagError::InvalidSignature);
    }
    let bytes = crate::crypto::canonical_signing_bytes(
        "SYNERGY_ETDAG_AVAILABILITY_VOTE_V1",
        &(
            &vote.context_root,
            &vote.vertex_id,
            &vote.validator_id,
            &vote.key_id,
        ),
    )?;
    verifier.verify(&vote.validator_id, key, &bytes, &vote.signature)
}

fn verify_certificate(
    certificate: &AvailabilityCertificate,
    context: &TargetAdmissionContextV3,
    members: &CutoffMembers,
    verifier: &impl SignatureVerifier,
) -> Result<(), EtdagError> {
    crate::availability::verify_availability_certificate(
        certificate,
        &members.keys().cloned().collect(),
        verifier,
    )?;
    let mut signed = 0u128;
    for vote in &certificate.votes {
        verify_vote(vote, context, members, verifier)?;
        signed += u128::from(
            members
                .get(&vote.validator_id)
                .ok_or(EtdagError::ContextMismatch)?
                .1,
        );
    }
    let total: u128 = members
        .values()
        .map(|(_, weight)| u128::from(*weight))
        .sum();
    if total != u128::from(context.assigned_cluster_total_voting_weight)
        || members.len() as u64 != context.assigned_cluster_validator_count
    {
        return Err(EtdagError::ContextMismatch);
    }
    if signed * 3 <= total * 2 {
        return Err(EtdagError::InsufficientAvailability {
            signed: certificate.votes.len(),
            required: crate::certificate_quorum(members.len())?,
        });
    }
    Ok(())
}

fn validate_collecting(
    evidence: &CollectingEvidence,
    context: &TargetAdmissionContextV3,
    local_id: &str,
    members: &CutoffMembers,
    verifier: &impl SignatureVerifier,
) -> Result<(), EtdagError> {
    crate::validate_graph(&evidence.graph)?;
    if evidence.graph.context_root() != &context.root()?
        || evidence.graph.target_height() != context.target_height
        || evidence.graph.len() > 4096
    {
        return Err(EtdagError::ContextMismatch);
    }
    for vertex in evidence.graph.vertices() {
        verify_vertex(vertex, context, members, verifier)?;
    }
    for (vertex, votes) in &evidence.votes {
        if !evidence.graph.contains(vertex) || votes.len() > members.len() {
            return Err(EtdagError::ContextMismatch);
        }
        for (validator, vote) in votes {
            if &vote.vertex_id != vertex || &vote.validator_id != validator {
                return Err(EtdagError::ContextMismatch);
            }
            verify_vote(vote, context, members, verifier)?;
        }
    }
    for (vertex, vote) in &evidence.local_votes {
        if !evidence.graph.contains(vertex)
            || &vote.vertex_id != vertex
            || vote.validator_id != local_id
        {
            return Err(EtdagError::ContextMismatch);
        }
        verify_vote(vote, context, members, verifier)?;
    }
    for (vertex, certificate) in &evidence.certificates {
        if !evidence.graph.contains(vertex) || &certificate.vertex_id != vertex {
            return Err(EtdagError::ContextMismatch);
        }
        verify_certificate(certificate, context, members, verifier)?;
    }
    Ok(())
}

#[cfg(test)]
mod cut_recovery_tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct Verifier;
    struct LegacyVerifier;
    #[derive(Default)]
    struct CountingVerifier {
        generations: std::cell::Cell<usize>,
        signatures: std::cell::Cell<usize>,
    }
    impl SignatureVerifier for CountingVerifier {
        fn verify(
            &self,
            validator: &str,
            key: &str,
            message: &[u8],
            signature: &[u8],
        ) -> Result<(), EtdagError> {
            self.signatures.set(self.signatures.get() + 1);
            Verifier.verify(validator, key, message, signature)
        }
    }
    impl RevealAuthorizationVerifier for CountingVerifier {
        fn verify_parent_commitment(
            &self,
            _: &crate::ProtectedRevealAuthorization,
            _: &ParentProposalRevealEvidence,
        ) -> Result<(), EtdagError> {
            Err(EtdagError::UnauthorizedReveal)
        }
    }
    impl ProtectedRecoveryVerifier for CountingVerifier {
        fn verify_cut_recovery_generation(
            &self,
            context: &TargetAdmissionContextV3,
            generation: &CutRecoveryGeneration,
        ) -> Result<(), EtdagError> {
            self.generations.set(self.generations.get() + 1);
            Verifier.verify_cut_recovery_generation(context, generation)
        }
        fn verify_cut_recovery_batch_binding(
            &self,
            context: &TargetAdmissionContextV3,
            generation: &CutRecoveryGeneration,
            batch: Option<&DeterministicProtectedBatch>,
        ) -> Result<(), EtdagError> {
            Verifier.verify_cut_recovery_batch_binding(context, generation, batch)
        }
        fn verify_nonempty_prepared(
            &self,
            _: &TargetAdmissionContextV3,
            _: &PreparedProtectedBatch,
            _: &BTreeMap<EtdagDigest, crate::reveal::RevealTranscript>,
            _: &BTreeMap<EtdagDigest, crate::EncryptedTransactionEnvelope>,
        ) -> Result<(), EtdagError> {
            Err(EtdagError::UnauthorizedReveal)
        }
    }
    macro_rules! verifier_base {
        ($name:ty) => {
            impl SignatureVerifier for $name {
                fn verify(
                    &self,
                    _: &str,
                    _: &str,
                    _: &[u8],
                    signature: &[u8],
                ) -> Result<(), EtdagError> {
                    if !signature.is_empty() && signature.iter().all(|byte| *byte == 1) {
                        Ok(())
                    } else {
                        Err(EtdagError::InvalidSignature)
                    }
                }
            }
            impl RevealAuthorizationVerifier for $name {
                fn verify_parent_commitment(
                    &self,
                    _: &crate::ProtectedRevealAuthorization,
                    _: &ParentProposalRevealEvidence,
                ) -> Result<(), EtdagError> {
                    Err(EtdagError::UnauthorizedReveal)
                }
            }
        };
    }
    verifier_base!(Verifier);
    verifier_base!(LegacyVerifier);
    impl ProtectedRecoveryVerifier for Verifier {
        fn verify_cut_recovery_batch_binding(
            &self,
            _context: &TargetAdmissionContextV3,
            _generation: &CutRecoveryGeneration,
            _batch: Option<&DeterministicProtectedBatch>,
        ) -> Result<(), EtdagError> {
            Ok(())
        }
        fn verify_cut_recovery_generation(
            &self,
            _: &TargetAdmissionContextV3,
            generation: &CutRecoveryGeneration,
        ) -> Result<(), EtdagError> {
            if generation.authorization.starts_with(b"verified-test-path")
                && generation.authorization[b"verified-test-path".len()..]
                    .iter()
                    .all(|b| *b == 1)
            {
                Ok(())
            } else {
                Err(EtdagError::UnauthorizedReveal)
            }
        }
        fn verify_nonempty_prepared(
            &self,
            _: &TargetAdmissionContextV3,
            _: &PreparedProtectedBatch,
            _: &BTreeMap<EtdagDigest, crate::reveal::RevealTranscript>,
            _: &BTreeMap<EtdagDigest, crate::EncryptedTransactionEnvelope>,
        ) -> Result<(), EtdagError> {
            Err(EtdagError::UnauthorizedReveal)
        }
    }
    impl ProtectedRecoveryVerifier for LegacyVerifier {
        fn verify_nonempty_prepared(
            &self,
            _: &TargetAdmissionContextV3,
            _: &PreparedProtectedBatch,
            _: &BTreeMap<EtdagDigest, crate::reveal::RevealTranscript>,
            _: &BTreeMap<EtdagDigest, crate::EncryptedTransactionEnvelope>,
        ) -> Result<(), EtdagError> {
            Err(EtdagError::UnauthorizedReveal)
        }
    }
    fn digest(label: &str) -> EtdagDigest {
        EtdagDigest::from_domain_bytes("pipeline-test", label.as_bytes())
    }
    fn context() -> TargetAdmissionContextV3 {
        let root = digest("context").0;
        serde_json::from_value(serde_json::json!({
            "context_version":1,"chain_id":1266,"network_id":"pipeline-test","protocol_version":"posy/3.0","epoch":1,
            "target_height":5,"source_finalized_height":0,"source_finality_context_root":root,
            "active_validator_set_root":root,"validator_consensus_key_root":root,"frozen_voting_weight_root":root,
            "cluster_schedule_version":"1","finalized_epoch_seed_root":"a".repeat(64),"assigned_height_schedule_root":root,
            "cluster_map_root":root,"assigned_cluster_id":0,"assigned_cluster_membership_root":root,
            "assigned_cluster_validator_count":5,"assigned_cluster_total_voting_weight":500,
            "consensus_parameter_root":root,"cryptographic_profile_root":root,"ingress_kem_registry_root":root
        })).unwrap()
    }
    fn members() -> CutoffMembers {
        (0..5)
            .map(|i| (format!("node-{i}"), (format!("key-{i}"), 100)))
            .collect()
    }
    fn directory() -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "synergy-cut-generation-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        path
    }
    fn marker(cutoff: EtdagDigest, i: usize) -> ProtectedCutMarker {
        ProtectedCutMarker {
            marker_version: 1,
            context_root: context().root().unwrap(),
            target_height: 5,
            cutoff_context_root: cutoff,
            frontier: vec![],
            validator_id: format!("node-{i}"),
            key_id: format!("key-{i}"),
            signature: vec![1],
        }
    }
    fn generation(previous: EtdagDigest, round: u64) -> CutRecoveryGeneration {
        CutRecoveryGeneration {
            original_cutoff_context_root: digest("original"),
            previous_cutoff_context_root: previous,
            cutoff_context_root: digest(&format!("generation-{round}")),
            timeout_id: digest(&format!("timeout-{round}")).0[..64].to_owned(),
            timeout_round: round,
            authorization: b"verified-test-path".to_vec(),
        }
    }
    fn open(path: &Path) -> ProtectedPipeline {
        ProtectedPipeline::open(
            path,
            context(),
            EtdagParameters::default(),
            digest("original"),
            "node-0".into(),
            &members(),
            &Verifier,
        )
        .unwrap()
    }

    fn collecting_owner(
        path: &Path,
        verifier: &(impl SignatureVerifier + ProtectedRecoveryVerifier),
    ) -> ProtectedPipeline {
        ProtectedPipeline::open_collecting(
            path,
            context(),
            EtdagParameters::default(),
            "node-0".into(),
            &members(),
            verifier,
        )
        .unwrap()
    }
    fn collecting_vertex(index: usize, bytes: usize) -> crate::TransactionVertex {
        let root = context().root().unwrap();
        let mut envelope = crate::EncryptedTransactionEnvelope {
            envelope_version: 2,
            envelope_id: digest(&format!("envelope-{index}")),
            target_context_root: root.clone(),
            target_height: 5,
            aad: crate::EnvelopeAad {
                profile_id: crate::ETDAG_PROFILE_ID.into(),
                chain_id: 1266,
                network_id: "pipeline-test".into(),
                protocol_version: "posy/3.0".into(),
                epoch: 1,
                target_height: 5,
                target_context_root: root.clone(),
                assigned_cluster_id: 0,
                lane_id: "ordinary-user".into(),
                sender_id: "alice".into(),
                nonce_slot: index as u64,
            },
            aead_nonce: [0; 12],
            key_commitment: digest("key"),
            share_commitment_root: digest("pending"),
            share_capsule_root: digest("pending"),
            ciphertext: vec![7; bytes],
            content_blind_order_key: digest("order"),
            share_capsules: vec![crate::ShareCapsule {
                validator_id: "node-0".into(),
                ingress_kem_key_id: "ingress".into(),
                share_index: 1,
                share_commitment: digest("share"),
                kem_ciphertext: vec![1; crate::crypto::ML_KEM_1024_CIPHERTEXT_BYTES],
                aead_nonce: [0; 12],
                encrypted_share: vec![1; 16],
            }],
        };
        envelope.refresh_capsule_roots().unwrap();
        let mut vertex = crate::TransactionVertex {
            vertex_id: digest("pending"),
            target_context_root: root,
            target_height: 5,
            envelope_ref: crate::CertifiedEnvelopeRef {
                tx_commitment: envelope.envelope_id.clone(),
                sender_id: "alice".into(),
                nonce_slot: index as u64,
                certified_dag_round: 0,
                gas_class_units: 10,
                ciphertext_bytes: bytes as u64,
                fee_class: 1,
                protocol_dependencies: vec![],
            },
            envelope,
            parents: vec![],
            author_id: "node-0".into(),
            author_signature: vec![1],
            wallet_admission: None,
        };
        vertex.vertex_id = crate::dag::derive_vertex_id(&vertex).unwrap();
        vertex
    }
    fn collecting_vote(vertex: &crate::TransactionVertex, index: usize) -> AvailabilityVote {
        AvailabilityVote {
            context_root: context().root().unwrap(),
            vertex_id: vertex.vertex_id.clone(),
            validator_id: format!("node-{index}"),
            key_id: format!("key-{index}"),
            signature: vec![1],
        }
    }
    fn collecting_frame(delta: &CollectingDelta) -> Vec<u8> {
        let payload = serde_json::to_vec(delta).unwrap();
        let mut frame = Vec::new();
        frame.extend_from_slice(JOURNAL_MAGIC);
        frame.extend_from_slice(&(payload.len() as u64).to_le_bytes());
        frame.extend_from_slice(delta.prior_head.0.as_bytes());
        frame.extend_from_slice(journal_digest(&payload).0.as_bytes());
        frame.extend_from_slice(&payload);
        frame.extend_from_slice(JOURNAL_END);
        frame
    }

    #[test]
    fn collecting_delta_constant_append_and_linear_native_authentication() {
        let path = directory();
        let verifier = CountingVerifier::default();
        let mut owner = collecting_owner(&path, &verifier);
        let mut lengths = Vec::new();
        for index in 0..24 {
            let vertex = collecting_vertex(index, 4096);
            let vote = collecting_vote(&vertex, 1);
            owner.persist_vertex(vertex, &members(), &verifier).unwrap();
            let before = owner.journal_cursor.borrow().as_ref().unwrap().length;
            owner.persist_vote(vote, &members(), &verifier).unwrap();
            lengths.push(owner.journal_cursor.borrow().as_ref().unwrap().length - before);
        }
        assert!(lengths.iter().all(|length| *length == lengths[0]));
        assert!(lengths[0] < 2048);
        assert_eq!(verifier.signatures.get(), 48);
        let charge = owner.collecting_resource_bytes();
        assert!(charge >= collecting_bytes(&owner.collecting));
        drop(owner);
        let verifier = CountingVerifier::default();
        let owner = collecting_owner(&path, &verifier);
        assert_eq!(owner.graph().len(), 24);
        assert_eq!(verifier.signatures.get(), 48);
        drop(owner);
        let verifier = CountingVerifier::default();
        let mut recovery = ProtectedPipeline::begin_recovery(
            &path,
            context(),
            EtdagParameters::default(),
            None,
            "node-0".into(),
        )
        .unwrap()
        .unwrap();
        let mut recovered = None;
        for _ in 0..64 {
            if let Some(owner) = recovery
                .poll_with_resource_budget(&members(), &verifier, false, 32 * 1024 * 1024)
                .unwrap()
            {
                recovered = Some(owner);
                break;
            }
        }
        assert_eq!(recovered.unwrap().graph().len(), 24);
        assert_eq!(verifier.signatures.get(), 48);
        std::fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn collecting_delta_failed_append_and_capacity_leave_original_state() {
        use std::io::Write as _;
        let path = directory();
        let mut owner = collecting_owner(&path, &Verifier);
        let vertex = collecting_vertex(0, 512);
        owner
            .persist_vertex(vertex.clone(), &members(), &Verifier)
            .unwrap();
        let before = owner.journal_cursor.borrow().as_ref().unwrap().clone();
        let charge = owner.collecting_resource_bytes();
        let bytes = std::fs::read(path.join(&owner.key)).unwrap();
        std::fs::OpenOptions::new()
            .append(true)
            .open(path.join(&owner.key))
            .unwrap()
            .write_all(b"S")
            .unwrap();
        assert!(owner
            .persist_local_vote(collecting_vote(&vertex, 0), &members(), &Verifier)
            .is_err());
        assert!(owner.local_votes().is_empty());
        assert!(owner.collecting.votes.is_empty());
        assert_eq!(owner.collecting_resource_bytes(), charge);
        assert_eq!(
            owner.journal_cursor.borrow().as_ref().unwrap().head,
            before.head
        );
        std::fs::write(path.join(&owner.key), &bytes).unwrap();
        let mut large = collecting_vertex(1, 2 * 1024 * 1024);
        // Serialized u8 ciphertext alone exceeds the reserved transition scratch.
        large.author_signature.reserve(1000);
        assert!(matches!(
            owner.persist_vertex(large, &members(), &Verifier),
            Err(EtdagError::ResourcePressure(_))
        ));
        assert_eq!(owner.graph().len(), 1);
        assert_eq!(std::fs::read(path.join(&owner.key)).unwrap(), bytes);
        std::fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn collecting_delta_native_bindings_quorum_and_parent_checks_fail_closed() {
        for malformed in 0..5 {
            let path = directory();
            let mut owner = collecting_owner(&path, &Verifier);
            let vertex = collecting_vertex(0, 512);
            owner
                .persist_vertex(vertex.clone(), &members(), &Verifier)
                .unwrap();
            let cursor = owner.journal_cursor.borrow().as_ref().unwrap().clone();
            let mut vote = collecting_vote(&vertex, 1);
            let action = match malformed {
                0 => {
                    vote.signature = vec![0];
                    CollectingAction::PeerVote(vote)
                }
                1 => CollectingAction::Availability(AvailabilityCertificate {
                    context_root: context().root().unwrap(),
                    vertex_id: vertex.vertex_id.clone(),
                    votes: vec![vote],
                }),
                2 => {
                    vote.vertex_id = digest("missing");
                    CollectingAction::PeerVote(vote)
                }
                3 => {
                    let mut next = collecting_vertex(1, 512);
                    next.parents = vec![digest("missing-parent")];
                    next.vertex_id = crate::dag::derive_vertex_id(&next).unwrap();
                    CollectingAction::Vertex(Box::new(next))
                }
                _ => CollectingAction::PeerVote(vote),
            };
            let mut delta = CollectingDelta {
                version: 3,
                prior_head: cursor.head.clone(),
                context_root: context().root().unwrap(),
                target_height: 5,
                local_validator_id: "node-0".into(),
                action,
            };
            if malformed == 4 {
                delta.target_height += 1;
            }
            let frame = collecting_frame(&delta);
            owner
                .store
                .append_journal_frame(&owner.key, cursor.length, &frame)
                .unwrap();
            let before = std::fs::read(path.join(&owner.key)).unwrap();
            assert!(ProtectedPipeline::open_collecting(
                &path,
                context(),
                EtdagParameters::default(),
                "node-0".into(),
                &members(),
                &Verifier
            )
            .is_err());
            assert_eq!(std::fs::read(path.join(&owner.key)).unwrap(), before);
            assert_eq!(owner.graph().len(), 1);
            assert!(owner.collecting.votes.is_empty());
            std::fs::remove_dir_all(path).unwrap();
        }
    }

    #[test]
    fn collecting_delta_torn_tail_and_mixed_full_frames_preserve_native_originals() {
        use std::io::Write as _;
        let path = directory();
        let mut owner = collecting_owner(&path, &Verifier);
        let vertex = collecting_vertex(0, 512);
        let vote = collecting_vote(&vertex, 0);
        owner
            .persist_vertex(vertex.clone(), &members(), &Verifier)
            .unwrap();
        owner
            .persist_local_vote(vote.clone(), &members(), &Verifier)
            .unwrap();
        owner.bind_cutoff(digest("original")).unwrap();
        owner
            .persist_local_marker(marker(digest("original"), 0), &members(), &Verifier)
            .unwrap();
        // A v1 full frame following v3 actions authenticates the same originals.
        owner
            .apply_cut_recovery_generation(generation(digest("original"), 1), &Verifier)
            .unwrap();
        let cursor = owner.journal_cursor.borrow().as_ref().unwrap().clone();
        let mut journal = std::fs::OpenOptions::new()
            .append(true)
            .open(path.join(&owner.key))
            .unwrap();
        journal.write_all(JOURNAL_MAGIC).unwrap();
        drop(journal);
        drop(owner);
        let owner = open(&path);
        assert_eq!(owner.graph().get(&vertex.vertex_id), Some(&vertex));
        assert_eq!(owner.local_votes().get(&vertex.vertex_id), Some(&vote));
        assert_eq!(owner.cut_recovery_generation_count(), 1);
        assert_eq!(
            std::fs::metadata(path.join(&owner.key)).unwrap().len(),
            cursor.length
        );
        std::fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn collecting_resource_accounting_charges_spare_nested_capacities_and_decode_budget() {
        let mut vertex = collecting_vertex(0, 512);
        let before = ProtectedPipeline::vertex_resource_bytes(&vertex).unwrap();
        vertex.envelope.ciphertext.reserve(8192);
        vertex.envelope.share_capsules[0].validator_id.reserve(2048);
        vertex.parents.reserve(64);
        let after = ProtectedPipeline::vertex_resource_bytes(&vertex).unwrap();
        assert!(after >= before + 8192);
        let path = directory();
        let mut owner = collecting_owner(&path, &Verifier);
        owner.persist_vertex(vertex, &members(), &Verifier).unwrap();
        let original = std::fs::read(path.join(&owner.key)).unwrap();
        let mut recovery = ProtectedPipeline::begin_recovery(
            &path,
            context(),
            EtdagParameters::default(),
            None,
            "node-0".into(),
        )
        .unwrap()
        .unwrap();
        assert!(matches!(
            recovery.poll_with_resource_budget(&members(), &Verifier, false, 64),
            Err(EtdagError::ResourcePressure(_))
        ));
        assert_eq!(std::fs::read(path.join(&owner.key)).unwrap(), original);
        std::fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn collecting_transition_budget_rejects_cut_and_new_proof_before_mutation() {
        let path = directory();
        let mut owner = open(&path);
        owner
            .persist_local_marker(marker(digest("original"), 0), &members(), &Verifier)
            .unwrap();
        let before = std::fs::read(path.join(&owner.key)).unwrap();
        owner.set_transition_resource_budget(64);
        let markers = (0..4)
            .map(|i| marker(digest("original"), i))
            .collect::<Vec<_>>();
        assert!(matches!(
            owner.accept_cut(
                &markers,
                &owner.graph().clone(),
                &owner.availability().clone(),
                &members(),
                &Verifier
            ),
            Err(EtdagError::ResourcePressure(_))
        ));
        assert!(owner.batch().is_none());
        assert_eq!(std::fs::read(path.join(&owner.key)).unwrap(), before);
        owner.set_transition_resource_budget(usize::MAX);
        owner
            .accept_cut(
                &markers,
                &owner.graph().clone(),
                &owner.availability().clone(),
                &members(),
                &Verifier,
            )
            .unwrap();
        let batch = owner.batch().unwrap().clone();
        let before = std::fs::read(path.join(&owner.key)).unwrap();
        owner.set_transition_resource_budget(64);
        assert!(matches!(
            owner.prepare_empty(
                crate::ProtectedRevealAuthorization {
                    authorization_version: 1,
                    context_root: context().root().unwrap(),
                    target_height: 5,
                    protected_batch_root: batch.protected_batch_root.clone(),
                    finality_reference: digest("parent"),
                },
                ParentProposalRevealEvidence {
                    material: crate::execution::ProtectedProposalMaterial {
                        material_version: 2,
                        height: 4,
                        execution_root: digest("execution"),
                        next_batch_root: batch.protected_batch_root.clone(),
                        cutoff_boundary_root: digest("boundary"),
                    },
                    next_batch: batch,
                    validation_proof: vec![1; 1024 * 1024],
                },
                &PreparedVerifier
            ),
            Err(EtdagError::ResourcePressure(_))
        ));
        assert!(owner.prepared().is_none());
        assert_eq!(std::fs::read(path.join(&owner.key)).unwrap(), before);
        std::fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn collecting_recovery_scratch_counts_prior_decoded_resident_before_next_frame() {
        let path = directory();
        let mut owner = collecting_owner(&path, &Verifier);
        for index in 0..8 {
            owner
                .persist_vertex(collecting_vertex(index, 4096), &members(), &Verifier)
                .unwrap();
        }
        let original = std::fs::read(path.join(&owner.key)).unwrap();
        let mut recovery = ProtectedPipeline::begin_recovery(
            &path,
            context(),
            EtdagParameters::default(),
            None,
            "node-0".into(),
        )
        .unwrap()
        .unwrap();
        // Decode/authenticate the base and one action with a generous budget.
        recovery
            .poll_with_resource_budget(&members(), &Verifier, false, 32 * 1024 * 1024)
            .unwrap();
        recovery
            .poll_with_resource_budget(&members(), &Verifier, false, 32 * 1024 * 1024)
            .unwrap();
        let retained = recovery.state.as_ref().unwrap().0.resident_resource_bytes;
        assert!(retained > 4096);
        assert!(matches!(
            recovery.poll_with_resource_budget(&members(), &Verifier, false, retained),
            Err(EtdagError::ResourcePressure(_))
        ));
        assert_eq!(std::fs::read(path.join(&owner.key)).unwrap(), original);
        std::fs::remove_dir_all(path).unwrap();
    }

    struct PreparedVerifier;
    impl SignatureVerifier for PreparedVerifier {
        fn verify(
            &self,
            validator: &str,
            key: &str,
            bytes: &[u8],
            signature: &[u8],
        ) -> Result<(), EtdagError> {
            Verifier.verify(validator, key, bytes, signature)
        }
    }
    impl RevealAuthorizationVerifier for PreparedVerifier {
        fn verify_parent_commitment(
            &self,
            _: &crate::ProtectedRevealAuthorization,
            evidence: &ParentProposalRevealEvidence,
        ) -> Result<(), EtdagError> {
            if !evidence.validation_proof.is_empty()
                && evidence.validation_proof.iter().all(|b| *b == 1)
            {
                Ok(())
            } else {
                Err(EtdagError::UnauthorizedReveal)
            }
        }
    }
    impl ProtectedRecoveryVerifier for PreparedVerifier {
        fn verify_cut_recovery_generation(
            &self,
            context: &TargetAdmissionContextV3,
            generation: &CutRecoveryGeneration,
        ) -> Result<(), EtdagError> {
            Verifier.verify_cut_recovery_generation(context, generation)
        }
        fn verify_cut_recovery_batch_binding(
            &self,
            context: &TargetAdmissionContextV3,
            generation: &CutRecoveryGeneration,
            batch: Option<&DeterministicProtectedBatch>,
        ) -> Result<(), EtdagError> {
            Verifier.verify_cut_recovery_batch_binding(context, generation, batch)
        }
        fn verify_nonempty_prepared(
            &self,
            _: &TargetAdmissionContextV3,
            _: &PreparedProtectedBatch,
            _: &BTreeMap<EtdagDigest, crate::reveal::RevealTranscript>,
            _: &BTreeMap<EtdagDigest, crate::EncryptedTransactionEnvelope>,
        ) -> Result<(), EtdagError> {
            Err(EtdagError::UnauthorizedReveal)
        }
    }
    fn prepared_owner(path: &Path, proof_bytes: usize, history: bool) -> ProtectedPipeline {
        let mut owner = open(path);
        if history {
            for round in 1..=2 {
                let previous = owner.cutoff_context_root().unwrap().clone();
                owner
                    .persist_local_marker(marker(previous.clone(), 0), &members(), &Verifier)
                    .unwrap();
                owner
                    .apply_cut_recovery_generation(generation(previous, round), &Verifier)
                    .unwrap();
            }
        }
        let cutoff = owner.cutoff_context_root().unwrap().clone();
        let markers = (0..4)
            .map(|i| marker(cutoff.clone(), i))
            .collect::<Vec<_>>();
        owner
            .accept_cut(
                &markers,
                &owner.graph().clone(),
                &owner.availability().clone(),
                &members(),
                &Verifier,
            )
            .unwrap();
        let batch = owner.batch().unwrap().clone();
        owner
            .prepare_empty(
                crate::ProtectedRevealAuthorization {
                    authorization_version: 1,
                    context_root: context().root().unwrap(),
                    target_height: 5,
                    protected_batch_root: batch.protected_batch_root.clone(),
                    finality_reference: digest("parent"),
                },
                ParentProposalRevealEvidence {
                    material: crate::execution::ProtectedProposalMaterial {
                        material_version: 2,
                        height: 4,
                        execution_root: digest("execution"),
                        next_batch_root: batch.protected_batch_root.clone(),
                        cutoff_boundary_root: digest("boundary"),
                    },
                    next_batch: batch,
                    validation_proof: vec![1; proof_bytes],
                },
                &PreparedVerifier,
            )
            .unwrap();
        owner
    }
    fn reopen_prepared(path: &Path) -> Result<ProtectedPipeline, EtdagError> {
        ProtectedPipeline::open(
            path,
            context(),
            EtdagParameters::default(),
            digest("original"),
            "node-0".into(),
            &members(),
            &PreparedVerifier,
        )
    }
    fn consumed_frame(delta: &ConsumedDelta, prior: &EtdagDigest) -> Vec<u8> {
        let payload = serde_json::to_vec(delta).unwrap();
        let mut frame = Vec::new();
        frame.extend_from_slice(JOURNAL_MAGIC);
        frame.extend_from_slice(&(payload.len() as u64).to_le_bytes());
        frame.extend_from_slice(prior.0.as_bytes());
        frame.extend_from_slice(journal_digest(&payload).0.as_bytes());
        frame.extend_from_slice(&payload);
        frame.extend_from_slice(JOURNAL_END);
        frame
    }

    #[test]
    fn consumed_delta_constant_bytes_preserves_prepared_and_indexed_originals() {
        let mut lengths = Vec::new();
        for (proof_bytes, history) in [(32, false), (1024 * 1024, false), (1024 * 1024, true)] {
            let path = directory();
            let mut owner = prepared_owner(&path, proof_bytes, history);
            let file = path.join("protected-h5.json");
            let before = std::fs::read(&file).unwrap();
            let batch = owner.batch().unwrap().protected_batch_root.clone();
            let proof_pointer = owner
                .prepared()
                .unwrap()
                .parent_evidence
                .validation_proof
                .as_ptr();
            assert!(owner.mark_consumed(&batch).unwrap());
            assert_eq!(
                owner
                    .prepared()
                    .unwrap()
                    .parent_evidence
                    .validation_proof
                    .as_ptr(),
                proof_pointer,
                "consumption must not clone retained proof"
            );
            let after = std::fs::read(&file).unwrap();
            assert_eq!(&after[..before.len()], before);
            lengths.push(after.len() - before.len());
            assert!(lengths.last().unwrap() < &1024);
            assert!(!owner.mark_consumed(&batch).unwrap());
            assert_eq!(std::fs::read(&file).unwrap(), after);
            drop(owner);
            let recovered = reopen_prepared(&path).unwrap();
            assert!(recovered.record.as_ref().unwrap().consumed);
            assert_eq!(
                recovered
                    .prepared()
                    .unwrap()
                    .parent_evidence
                    .validation_proof
                    .len(),
                proof_bytes
            );
            if history {
                for position in 0..2 {
                    assert_eq!(
                        recovered
                            .read_cut_recovery_generation(position)
                            .unwrap()
                            .unwrap()
                            .timeout_round,
                        position as u64 + 1
                    );
                    assert_eq!(
                        recovered
                            .read_retained_local_marker(position)
                            .unwrap()
                            .unwrap()
                            .validator_id,
                        "node-0"
                    );
                }
            }
            assert_eq!(std::fs::read(&file).unwrap(), after);
            drop(recovered);
            let mut staged = ProtectedPipeline::begin_recovery(
                &path,
                context(),
                EtdagParameters::default(),
                Some(digest("original")),
                "node-0".into(),
            )
            .unwrap()
            .unwrap();
            let mut completed = false;
            for _ in 0..32 {
                if let Some(recovered) = staged.poll(&members(), &PreparedVerifier, false).unwrap()
                {
                    assert!(recovered.record.as_ref().unwrap().consumed);
                    completed = true;
                    break;
                }
            }
            assert!(
                completed,
                "metadata-only frame completes bounded staged recovery"
            );
            assert_eq!(std::fs::read(&file).unwrap(), after);
            std::fs::remove_dir_all(path).unwrap();
        }
        assert!(lengths.iter().all(|length| *length == lengths[0]));
    }

    #[test]
    fn consumed_delta_torn_corrupt_duplicate_and_wrong_phase_fail_closed() {
        let path = directory();
        let mut owner = prepared_owner(&path, 32, false);
        let file = path.join("protected-h5.json");
        let before = std::fs::read(&file).unwrap();
        let prior = owner.journal_cursor.borrow().as_ref().unwrap().head.clone();
        let batch = owner.batch().unwrap().protected_batch_root.clone();
        assert!(owner.mark_consumed(&batch).unwrap());
        let complete = std::fs::read(&file).unwrap();
        drop(owner);
        let delta = ConsumedDelta {
            version: 2,
            prior_head: prior.clone(),
            context_root: context().root().unwrap(),
            target_height: 5,
            batch_root: batch.clone(),
        };
        for prefix in [1, JOURNAL_HEADER - 1, complete.len() - before.len() - 1] {
            std::fs::write(&file, &complete[..before.len() + prefix]).unwrap();
            let recovered = reopen_prepared(&path).unwrap();
            assert!(!recovered.record.as_ref().unwrap().consumed);
            drop(recovered);
            assert_eq!(std::fs::read(&file).unwrap(), before);
        }
        for changed in [
            "batch",
            "context",
            "target",
            "prior",
            "duplicate",
            "integrity",
            "unprepared",
            "rollback",
        ] {
            let mut altered: ConsumedDelta =
                serde_json::from_slice(&serde_json::to_vec(&delta).unwrap()).unwrap();
            match changed {
                "batch" => altered.batch_root = digest("wrong"),
                "context" => altered.context_root = digest("wrong"),
                "target" => altered.target_height += 1,
                "prior" => altered.prior_head = digest("wrong"),
                _ => (),
            }
            let mut bytes = before.clone();
            let mut previous = prior.clone();
            if changed == "unprepared" {
                let mut state: StoredPipeline = serde_json::from_slice(&before).unwrap();
                state.committed.as_mut().unwrap().prepared = None;
                bytes = serde_json::to_vec(&state).unwrap();
                previous = journal_digest(&bytes);
                altered.prior_head = previous.clone();
            }
            if changed == "duplicate" || changed == "rollback" {
                bytes = complete.clone();
                previous =
                    journal_digest(&complete[before.len() + JOURNAL_HEADER..complete.len() - 8]);
                altered.prior_head = previous.clone();
            }
            if changed == "rollback" {
                let state: StoredPipeline = serde_json::from_slice(&before).unwrap();
                let payload = serde_json::to_vec(&JournalDelta {
                    version: 1,
                    state,
                    generations: vec![],
                    markers: vec![],
                })
                .unwrap();
                bytes.extend_from_slice(JOURNAL_MAGIC);
                bytes.extend_from_slice(&(payload.len() as u64).to_le_bytes());
                bytes.extend_from_slice(previous.0.as_bytes());
                bytes.extend_from_slice(journal_digest(&payload).0.as_bytes());
                bytes.extend_from_slice(&payload);
                bytes.extend_from_slice(JOURNAL_END);
            } else {
                bytes.extend_from_slice(&consumed_frame(&altered, &previous));
            }
            if changed == "integrity" {
                let last = bytes.len() - 9;
                bytes[last] ^= 1;
            }
            std::fs::write(&file, &bytes).unwrap();
            assert!(reopen_prepared(&path).is_err(), "must reject {changed}");
            assert_eq!(std::fs::read(&file).unwrap(), bytes);
        }
        std::fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn consumed_delta_failed_append_preserves_memory_and_cursor() {
        let path = directory();
        let mut owner = prepared_owner(&path, 32, false);
        let batch = owner.batch().unwrap().protected_batch_root.clone();
        let previous = owner.journal_cursor.borrow().as_ref().unwrap().clone();
        assert!(owner.mark_consumed(&digest("wrong")).is_err());
        let file = path.join("protected-h5.json");
        // A competing length change violates the atomic append precondition.
        use std::io::Write;
        std::fs::OpenOptions::new()
            .append(true)
            .open(&file)
            .unwrap()
            .write_all(b"x")
            .unwrap();
        assert!(owner.mark_consumed(&batch).is_err());
        assert!(!owner.record.as_ref().unwrap().consumed);
        assert_eq!(
            owner.journal_cursor.borrow().as_ref().unwrap().length,
            previous.length
        );
        assert_eq!(
            owner.journal_cursor.borrow().as_ref().unwrap().head,
            previous.head
        );
        std::fs::remove_dir_all(path).unwrap();
    }
    #[test]
    fn r3_retains_markers_and_reverifies_restart_generation() {
        let path = directory();
        let mut pipeline = open(&path);
        pipeline
            .persist_local_marker(marker(digest("original"), 0), &members(), &Verifier)
            .unwrap();
        let first = generation(digest("original"), 1);
        assert!(pipeline
            .apply_cut_recovery_generation(first.clone(), &Verifier)
            .unwrap());
        assert!(pipeline.admission_closed());
        assert!(pipeline.local_marker().is_none());
        assert!(!pipeline
            .apply_cut_recovery_generation(first.clone(), &Verifier)
            .unwrap());
        pipeline
            .persist_local_marker(
                marker(first.cutoff_context_root.clone(), 0),
                &members(),
                &Verifier,
            )
            .unwrap();
        let second = generation(first.cutoff_context_root.clone(), 2);
        pipeline
            .apply_cut_recovery_generation(second.clone(), &Verifier)
            .unwrap();
        pipeline
            .persist_local_marker(
                marker(second.cutoff_context_root.clone(), 0),
                &members(),
                &Verifier,
            )
            .unwrap();
        drop(pipeline);
        let recovered = open(&path);
        assert_eq!(
            recovered.cutoff_context_root(),
            Some(&second.cutoff_context_root)
        );
        assert_eq!(recovered.retained_local_markers().count(), 2);
        assert_eq!(recovered.cut_recovery_generations(), &[first, second]);
        assert!(ProtectedPipeline::open(
            &path,
            context(),
            EtdagParameters::default(),
            digest("original"),
            "node-0".into(),
            &members(),
            &LegacyVerifier
        )
        .is_err());
        std::fs::remove_dir_all(path).unwrap();
    }
    #[test]
    fn r3_default_denies_invalid_and_committed_transitions_without_mutation() {
        let path = directory();
        let mut pipeline = open(&path);
        pipeline
            .persist_local_marker(marker(digest("original"), 0), &members(), &Verifier)
            .unwrap();
        let first = generation(digest("original"), 1);
        assert!(pipeline
            .apply_cut_recovery_generation(first.clone(), &LegacyVerifier)
            .is_err());
        let mut invalid = first.clone();
        invalid.previous_cutoff_context_root = digest("wrong");
        assert!(pipeline
            .apply_cut_recovery_generation(invalid, &Verifier)
            .is_err());
        assert!(pipeline.local_marker().is_some());
        assert!(pipeline.cut_recovery_generations().is_empty());
        let markers = (0..4)
            .map(|i| marker(digest("original"), i))
            .collect::<Vec<_>>();
        let graph = pipeline.graph().clone();
        let certificates = pipeline.availability().clone();
        pipeline
            .accept_cut(&markers, &graph, &certificates, &members(), &Verifier)
            .unwrap();
        assert!(pipeline
            .apply_cut_recovery_generation(first, &Verifier)
            .is_err());
        std::fs::remove_dir_all(path).unwrap();
    }
    #[test]
    fn single_journal_preserves_near_limit_legacy_and_appends_1136th_recovery() {
        let path = directory();
        let pipeline = open(&path);
        let mut stored = StoredPipeline {
            authenticated: false,
            collecting_encoded_bytes: 0,
            resident_resource_bytes: 0,
            version: 3,
            history: VerifiedHistory::default(),
            pending_location: None,
            context: context(),
            parameters: EtdagParameters::default(),
            cutoff_context_root: Some(digest("original")),
            local_validator_id: "node-0".into(),
            local_marker: None,
            committed: None,
            collecting: Some(pipeline.collecting.clone()),
            original_cutoff_context_root: Some(digest("original")),
            cut_recovery_generations: Vec::new(),
            retained_markers: Vec::new(),
        };
        let mut previous = digest("original");
        for round in 1..=1135 {
            stored.retained_markers.push(RetainedMarker {
                cutoff_context_root: previous.clone(),
                marker: marker(previous.clone(), 0),
            });
            let next = generation(previous, round);
            previous = next.cutoff_context_root.clone();
            stored.cut_recovery_generations.push(next);
        }
        stored.cutoff_context_root = Some(previous.clone());
        let base = serde_json::to_vec(&stored).unwrap().len();
        let mut remaining = (JOURNAL_LIMIT - 7680 - base) / 2;
        for retained in &mut stored.retained_markers {
            let added = remaining.min(16000 - 1);
            retained.marker.signature.resize(1 + added, 1);
            remaining -= added;
        }
        assert_eq!(remaining, 0);
        let legacy = serde_json::to_vec(&stored).unwrap();
        assert!(legacy.len() < JOURNAL_LIMIT && JOURNAL_LIMIT - legacy.len() < 8000);
        let record_path = path.join("protected-h5.json");
        std::fs::write(&record_path, &legacy).unwrap();
        drop(pipeline);
        let mut migrated = open(&path);
        let mut next_marker = marker(previous.clone(), 0);
        next_marker.signature = vec![1; 12000];
        migrated
            .persist_local_marker(next_marker.clone(), &members(), &Verifier)
            .unwrap();
        let next = generation(previous, 1136);
        migrated
            .apply_cut_recovery_generation(next.clone(), &Verifier)
            .unwrap();
        drop(migrated);
        let verifier = CountingVerifier::default();
        let recovered = ProtectedPipeline::open(
            &path,
            context(),
            EtdagParameters::default(),
            digest("original"),
            "node-0".into(),
            &members(),
            &verifier,
        )
        .unwrap();
        assert_eq!(
            verifier.generations.get(),
            1136,
            "authenticate every original once, not twice"
        );
        assert!(
            verifier.signatures.get() <= 1140,
            "retained marker authentication must not repeat during reconstruction"
        );
        assert_eq!(recovered.cut_recovery_generation_count(), 1136);
        assert_eq!(recovered.retained_local_marker_count(), 1136);
        assert_eq!(
            recovered.read_retained_local_marker(1135).unwrap().unwrap(),
            next_marker
        );
        assert_eq!(
            recovered.cutoff_context_root(),
            Some(&next.cutoff_context_root)
        );
        let bytes = std::fs::read(&record_path).unwrap();
        assert_eq!(&bytes[..legacy.len()], legacy.as_slice());
        assert!(
            bytes.len() - legacy.len() < 128 * 1024,
            "append must contain only new bounded evidence, not old history"
        );
        let extra = std::fs::read_dir(&path)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name.starts_with("protected-"))
            .collect::<Vec<_>>();
        assert_eq!(extra, vec!["protected-h5.json"]);
        let verifier = CountingVerifier::default();
        let mut staged = ProtectedPipeline::begin_recovery(
            &path,
            context(),
            EtdagParameters::default(),
            Some(digest("original")),
            "node-0".into(),
        )
        .unwrap()
        .unwrap();
        let before = std::fs::read(&record_path).unwrap();
        assert!(staged.poll(&members(), &verifier, true).is_err());
        assert_eq!(
            std::fs::read(&record_path).unwrap(),
            before,
            "cancelled recovery cannot mutate history"
        );
        let mut steps = 0;
        let incrementally_recovered = loop {
            let previous = verifier.generations.get();
            let recovered = staged.poll(&members(), &verifier, false).unwrap();
            assert!(
                verifier.generations.get() - previous <= 4,
                "one recovery step has a bounded native proof batch"
            );
            steps += 1;
            if let Some(recovered) = recovered {
                break recovered;
            }
            assert!(
                steps < 400,
                "recovery advances without restarting the retained prefix"
            );
        };
        assert_eq!(verifier.generations.get(), 1136);
        assert_eq!(
            incrementally_recovered.history.generations,
            recovered.history.generations
        );
        assert_eq!(
            incrementally_recovered.history.markers,
            recovered.history.markers
        );
        assert_eq!(
            incrementally_recovered.cutoff_context_root,
            recovered.cutoff_context_root
        );
        assert_eq!(
            std::fs::read(&record_path).unwrap(),
            before,
            "completed recovery preserves originals exactly"
        );
        std::fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn shared_history_budget_preserves_originals_and_resumes_after_owner_retirement() {
        use sha3::{Digest, Sha3_256};
        fn original(path: &Path) -> (u64, Vec<u8>) {
            let mut file = std::fs::File::open(path).unwrap();
            let length = file.metadata().unwrap().len();
            let mut hash = Sha3_256::new();
            let mut bytes = [0; 8192];
            loop {
                let count = file.read(&mut bytes).unwrap();
                if count == 0 {
                    break;
                }
                hash.update(&bytes[..count]);
            }
            (length, hash.finalize().to_vec())
        }
        let count = std::env::var("SYNERGY_RECOVERY_QUAL_GENERATIONS")
            .map_or(96, |v| v.parse::<usize>().unwrap());
        assert!((96..=4096).contains(&count));
        let mut paths = Vec::new();
        let mut originals = Vec::new();
        let mut charges = Vec::new();
        for _ in 0..3 {
            let path = directory();
            let mut owner = open(&path);
            let mut previous = digest("original");
            for round in 1..=count {
                owner
                    .persist_local_marker(marker(previous.clone(), 0), &members(), &Verifier)
                    .unwrap();
                let mut next = generation(previous, round as u64);
                // Historical payload size does not affect retained history.
                // Keep the latest maximum proof on every concurrent owner.
                if round == count {
                    next.authorization.resize(1024 * 1024, 1);
                }
                previous = next.cutoff_context_root.clone();
                owner
                    .apply_cut_recovery_generation(next, &Verifier)
                    .unwrap();
            }
            charges.push(owner.retained_history_resource_bytes());
            originals.push(original(&path.join(&owner.key)));
            paths.push(path);
        }
        let limit = charges[0] + charges[1] + 8192;
        assert!(charges.iter().sum::<usize>() > limit);
        let mut recoveries: Vec<_> = paths
            .iter()
            .map(|path| {
                Some(
                    ProtectedPipeline::begin_recovery(
                        path,
                        context(),
                        EtdagParameters::default(),
                        Some(digest("original")),
                        "node-0".into(),
                    )
                    .unwrap()
                    .unwrap(),
                )
            })
            .collect();
        let mut owners: Vec<Option<ProtectedPipeline>> = (0..3).map(|_| None).collect();
        let mut reserved = [0usize; 3];
        let mut blocked = None;
        // Runtime drives the earliest pending owner to completion before
        // decoding another owner. Waiting cursors hold no decoded history;
        // round-robin decoding would needlessly fill the pool with partial
        // indexes before any owner could install and later retire.
        for _ in 0..count * 12 + 96 {
            let Some(index) = recoveries.iter().position(Option::is_some) else {
                break;
            };
            for (waiting, recovery) in recoveries.iter().enumerate().skip(index + 1) {
                if let Some(recovery) = recovery {
                    assert_eq!(recovery.retained_history_resource_bytes(), 0);
                    assert_eq!(reserved[waiting], 0);
                }
            }
            let other = reserved
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != index)
                .map(|(_, n)| *n)
                .sum::<usize>();
            let recovery = recoveries[index].as_mut().unwrap();
            match recovery.poll_with_resource_budgets(
                &members(),
                &Verifier,
                false,
                40 * 1024 * 1024,
                limit.saturating_sub(other),
            ) {
                Ok(Some(owner)) => {
                    reserved[index] = owner.retained_history_resource_bytes();
                    owners[index] = Some(owner);
                    recoveries[index] = None;
                }
                Ok(None) => {
                    reserved[index] = recovery.retained_history_resource_bytes();
                }
                Err(EtdagError::ResourcePressure(_)) => {
                    blocked = Some(index);
                    break;
                }
                Err(error) => panic!("unexpected recovery failure: {error:?}"),
            }
            assert!(reserved.iter().sum::<usize>() <= limit);
        }
        assert_eq!(owners.iter().filter(|owner| owner.is_some()).count(), 2);
        let blocked = blocked.expect("shared history pool must reject the third maximum owner");
        for index in 0..3 {
            assert_eq!(
                original(&paths[index].join("protected-h5.json")),
                originals[index]
            );
        }
        // Retire one installed owner. The staged owner keeps its existing
        // reservation; retry must subtract only OTHER owners, not charge itself twice.
        let retired = owners
            .iter()
            .position(Option::is_some)
            .expect("at least one owner must install before pressure");
        owners[retired] = None;
        reserved[retired] = 0;
        for _ in 0..count * 4 + 32 {
            let other = reserved
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != blocked)
                .map(|(_, n)| *n)
                .sum::<usize>();
            let recovery = recoveries[blocked].as_mut().unwrap();
            match recovery
                .poll_with_resource_budgets(
                    &members(),
                    &Verifier,
                    false,
                    40 * 1024 * 1024,
                    limit - other,
                )
                .unwrap()
            {
                Some(owner) => {
                    owners[blocked] = Some(owner);
                    break;
                }
                None => {
                    reserved[blocked] = recovery.retained_history_resource_bytes();
                }
            }
        }
        let owner = owners[blocked]
            .as_mut()
            .expect("staged recovery must resume after retirement");
        assert_eq!(owner.cut_recovery_generation_count(), count);
        assert_eq!(
            owner
                .read_cut_recovery_generation(count - 1)
                .unwrap()
                .unwrap()
                .authorization
                .len(),
            1024 * 1024
        );
        let journal = paths[blocked].join("protected-h5.json");
        assert_eq!(original(&journal), originals[blocked]);
        if count < 4096 {
            let mut next = generation(
                owner.cutoff_context_root().unwrap().clone(),
                count as u64 + 1,
            );
            next.authorization.resize(1024 * 1024, 1);
            next.authorization.reserve_exact(1024 * 1024);
            let prior = owner.retained_history_resource_bytes();
            assert!(owner.prospective_history_resource_bytes(&next) > prior);
            owner.set_history_resource_budget(prior);
            assert!(matches!(
                owner.apply_cut_recovery_generation(next.clone(), &Verifier),
                Err(EtdagError::ResourcePressure(_))
            ));
            assert_eq!(owner.retained_history_resource_bytes(), prior);
            assert_eq!(original(&journal), originals[blocked]);
            // A raised LOCAL reservation permits the identical, previously rejected
            // generation; this does not change authority or signed protocol limits.
            owner.set_history_resource_budget(owner.prospective_history_resource_bytes(&next));
            owner
                .apply_cut_recovery_generation(next, &Verifier)
                .unwrap();
            assert_eq!(owner.cut_recovery_generation_count(), count + 1);
        }
        drop(owners);
        drop(recoveries);
        for path in paths {
            std::fs::remove_dir_all(path).unwrap();
        }
    }

    #[test]
    fn appended_history_keeps_only_latest_payload_and_reads_originals_with_bounded_recovery() {
        let path = directory();
        let mut owner = open(&path);
        let mut previous = digest("original");
        let count = std::env::var("SYNERGY_RECOVERY_QUAL_GENERATIONS")
            .map_or(96, |v| v.parse::<usize>().unwrap());
        assert!((96..=4096).contains(&count));
        let proof_bytes = std::env::var("SYNERGY_RECOVERY_QUAL_AUTH_BYTES")
            .map_or(256 * 1024, |v| v.parse::<usize>().unwrap());
        assert!((256 * 1024..=1024 * 1024).contains(&proof_bytes));
        for round in 1..=count {
            let mut close = marker(previous.clone(), 0);
            close.signature.resize(16 * 1024, 1);
            owner
                .persist_local_marker(close, &members(), &Verifier)
                .unwrap();
            let mut next = generation(previous, round as u64);
            next.authorization.resize(proof_bytes, 1);
            previous = next.cutoff_context_root.clone();
            owner
                .apply_cut_recovery_generation(next, &Verifier)
                .unwrap();
            assert!(owner.cut_recovery_generations.is_empty());
            assert!(owner.retained_markers.is_empty());
            assert_eq!(
                owner.history.last.as_ref().unwrap().authorization.len(),
                proof_bytes
            );
        }
        assert_eq!(owner.cut_recovery_generation_count(), count);
        assert_eq!(owner.retained_local_marker_count(), count);
        let record_path = path.join("protected-h5.json");
        let original_len = std::fs::metadata(&record_path).unwrap().len();
        assert!(
            original_len > (2 * JOURNAL_LIMIT) as u64,
            "aggregate journal crosses per-frame limit"
        );
        for position in [0, count / 2, count - 1] {
            let original = owner
                .read_cut_recovery_generation(position)
                .unwrap()
                .unwrap();
            assert_eq!(original.timeout_round, position as u64 + 1);
            assert_eq!(original.authorization.len(), proof_bytes);
            assert_eq!(
                owner
                    .read_retained_local_marker(position)
                    .unwrap()
                    .unwrap()
                    .signature
                    .len(),
                16 * 1024
            );
        }
        // A bulk diagnostic export must not reintroduce all-history allocation.
        assert_eq!(
            ProtectedPipeline::read_durable_evidence(&path, 5),
            Err(EtdagError::InvalidCapacity)
        );
        drop(owner);
        let verifier = CountingVerifier::default();
        let mut recovery = ProtectedPipeline::begin_recovery(
            &path,
            context(),
            EtdagParameters::default(),
            Some(digest("original")),
            "node-0".into(),
        )
        .unwrap()
        .unwrap();
        let mut steps = 0;
        let owner = loop {
            let before = verifier.generations.get();
            let result = recovery.poll(&members(), &verifier, false).unwrap();
            assert!(verifier.generations.get() - before <= 4);
            if let Some((state, _)) = recovery.state.as_ref() {
                assert!(state.cut_recovery_generations.len() <= 1);
                assert!(state.retained_markers.len() <= 1);
                assert!(
                    state
                        .history
                        .last
                        .as_ref()
                        .map_or(0, |g| g.authorization.len())
                        <= proof_bytes
                );
            }
            steps += 1;
            if let Some(owner) = result {
                break owner;
            }
            assert!(steps <= 2 * count + 4);
        };
        assert_eq!(verifier.generations.get(), count);
        assert_eq!(owner.cut_recovery_generation_count(), count);
        assert_eq!(owner.cutoff_context_root(), Some(&previous));
        assert!(owner.cut_recovery_generations.is_empty() && owner.retained_markers.is_empty());
        assert_eq!(std::fs::metadata(&record_path).unwrap().len(), original_len);
        eprintln!("protected_recovery_resource generations={count} authorization_bytes={proof_bytes} journal_bytes={original_len} verified_generations={} pending_payloads={}", verifier.generations.get(), owner.cut_recovery_generations.len());
        std::fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn incomplete_unacknowledged_tail_recovers_only_after_native_authentication() {
        use std::io::Write;
        let path = directory();
        let mut pipeline = open(&path);
        pipeline
            .persist_local_marker(marker(digest("original"), 0), &members(), &Verifier)
            .unwrap();
        pipeline
            .apply_cut_recovery_generation(generation(digest("original"), 1), &Verifier)
            .unwrap();
        drop(pipeline);
        let record_path = path.join("protected-h5.json");
        let committed = std::fs::read(&record_path).unwrap();
        std::fs::OpenOptions::new()
            .append(true)
            .open(&record_path)
            .unwrap()
            .write_all(&JOURNAL_MAGIC[..4])
            .unwrap();
        let full_len = std::fs::metadata(&record_path).unwrap().len();
        assert!(ProtectedPipeline::open(
            &path,
            context(),
            EtdagParameters::default(),
            digest("original"),
            "node-0".into(),
            &members(),
            &LegacyVerifier
        )
        .is_err());
        assert_eq!(
            std::fs::metadata(&record_path).unwrap().len(),
            full_len,
            "unauthenticated restart must not trim"
        );
        let recovered = open(&path);
        assert_eq!(recovered.cut_recovery_generation_count(), 1);
        assert_eq!(std::fs::read(&record_path).unwrap(), committed);
        std::fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn complete_corrupt_frame_and_stale_append_position_fail_closed_without_trimming() {
        use std::io::Write;
        let path = directory();
        let mut pipeline = open(&path);
        pipeline
            .persist_local_marker(marker(digest("original"), 0), &members(), &Verifier)
            .unwrap();
        pipeline
            .apply_cut_recovery_generation(generation(digest("original"), 1), &Verifier)
            .unwrap();
        let record_path = path.join("protected-h5.json");
        let mut bytes = std::fs::read(&record_path).unwrap();
        let original = bytes.clone();
        *bytes.last_mut().unwrap() ^= 1;
        std::fs::write(&record_path, &bytes).unwrap();
        drop(pipeline);
        assert!(ProtectedPipeline::open(
            &path,
            context(),
            EtdagParameters::default(),
            digest("original"),
            "node-0".into(),
            &members(),
            &Verifier
        )
        .is_err());
        assert_eq!(
            std::fs::read(&record_path).unwrap(),
            bytes,
            "complete corruption cannot be truncated"
        );
        std::fs::write(&record_path, &original).unwrap();
        let mut pipeline = open(&path);
        std::fs::OpenOptions::new()
            .append(true)
            .open(&record_path)
            .unwrap()
            .write_all(b"external")
            .unwrap();
        assert!(pipeline
            .persist_local_marker(marker(digest("generation-1"), 0), &members(), &Verifier)
            .is_err());
        assert!(pipeline.local_marker().is_none());
        assert!(std::fs::read(&record_path).unwrap().ends_with(b"external"));
        std::fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn indexed_original_reads_reject_modified_payload_without_changing_active_authority() {
        use std::io::Write;
        let path = directory();
        let mut pipeline = open(&path);
        pipeline
            .persist_local_marker(marker(digest("original"), 0), &members(), &Verifier)
            .unwrap();
        let next = generation(digest("original"), 1);
        pipeline
            .apply_cut_recovery_generation(next.clone(), &Verifier)
            .unwrap();
        assert_eq!(
            pipeline.read_cut_recovery_generation(0).unwrap(),
            Some(next.clone())
        );
        assert!(pipeline.read_retained_local_marker(0).unwrap().is_some());
        let location = &pipeline.history.generation_locations[0].frame;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .open(path.join("protected-h5.json"))
            .unwrap();
        file.seek(SeekFrom::Start(location.offset)).unwrap();
        file.write_all(b"!").unwrap();
        file.sync_all().unwrap();
        assert!(pipeline.read_cut_recovery_generation(0).is_err());
        assert!(pipeline.read_retained_local_marker(0).is_err());
        assert_eq!(
            pipeline.cutoff_context_root(),
            Some(&next.cutoff_context_root)
        );
        assert_eq!(pipeline.last_cut_recovery_generation(), Some(&next));
        assert!(pipeline.read_cut_recovery_generation(1).unwrap().is_none());
        std::fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn r3_failed_atomic_generation_write_restores_original_marker() {
        let path = directory();
        let mut pipeline = open(&path);
        let original = marker(digest("original"), 0);
        pipeline
            .persist_local_marker(original.clone(), &members(), &Verifier)
            .unwrap();
        // A directory at the record destination makes atomic replacement fail.
        let record = path.join("protected-h5.json");
        std::fs::remove_file(&record).unwrap();
        std::fs::create_dir(&record).unwrap();
        assert!(pipeline
            .apply_cut_recovery_generation(generation(digest("original"), 1), &Verifier)
            .is_err());
        assert_eq!(pipeline.local_marker(), Some(&original));
        assert_eq!(pipeline.cutoff_context_root(), Some(&digest("original")));
        assert!(pipeline.cut_recovery_generations().is_empty());
        assert_eq!(pipeline.retained_local_markers().count(), 0);
        assert!(pipeline.admission_closed());
        std::fs::remove_dir_all(path).unwrap();
    }
}
