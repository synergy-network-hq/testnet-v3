#[path = "etdag_processing.rs"]
mod processing;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs;
use std::io::Read;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
#[cfg(test)]
use synergy_aegis::PqvmSigner;

use synergy_aegis::{
    AegisPolicy, AegisSigner, AegisVerifier, KeyId, SignatureAlgorithm, SigningContext,
};
use synergy_config::NodeConfiguration;
use synergy_data_availability::{serve::serve_custody, FilesystemShardStore, ShardStore};
use synergy_etdag::availability::{accept_vertex_shard, verify_availability_certificate};
use synergy_etdag::certificates::CanonicalCertificate;
use synergy_etdag::crypto::canonical_signing_bytes;
use synergy_etdag::crypto::SignatureVerifier;
use synergy_etdag::crypto::{
    decrypt_share_capsule, verify_ingress_key_possession, GovernedThresholdDecryptor,
    ML_KEM_1024_SECRET_KEY_BYTES,
};
use synergy_etdag::network::verify_network_message;
use synergy_etdag::ordering::{CutoffMembers, ProtectedCutMarker};
use synergy_etdag::persistence::{ProtectedPipeline, ProtectedPipelineRecovery};
use synergy_etdag::reveal::{
    decrypt_authorized_envelope, verify_decrypt_share, RevealTranscript,
    VerifiedRevealAuthorization, VerifiedShareCollector,
};
use synergy_etdag::{
    AuthenticatedEtdagMessage, AvailabilityCertificate, AvailabilityVote, EtdagDigest, EtdagError,
    EtdagGraph, EtdagMetrics, EtdagNetworkMessage, EtdagParameters, RecoveredShardCustody,
    ShardCustodyMessage, TargetAdmissionContextV3,
};
use synergy_etdag::{DecryptShareMessage, EncryptedTransactionEnvelope, TransactionVertex};
use synergy_identity::PublicNodeIdentity;
use synergy_node_core::{
    CancellationToken, Criticality, ManagedService, RestartPolicy, ServiceHealth, ServiceId,
    ServiceReadiness, ServiceSpec,
};
use synergy_p2p_protocols::{AdapterEnvelope, EtdagAdapter, EtdagMessageSink};
use synergy_protocol_types::{AuthenticatedPeer, ProtocolKind};
use synergy_storage::NodeStorageLayout;

use super::authority::{self, VerifiedAuthority};
use super::ingress::{AuthenticatedIngress, EtdagControlAction, OutboundFrame};

const MAX_MESSAGES_PER_POLL: usize = 64;
const MAX_IDENTITY_BYTES: u64 = 64 * 1024;
const MAX_SIGNING_KEY_BYTES: u64 = 8 * 1024;
const MAX_ETDAG_SIGNING_BYTES: usize = 1024 * 1024;
// Enumerate borrowed payload/peer pairs in the original deterministic order.
// Only the bounded attempted slice reaches the publisher and can allocate frames.
fn deliver_retry_slice<'a>(
    payloads: impl Iterator<Item = &'a [u8]> + Clone,
    peers: impl Iterator<Item = &'a str> + Clone,
    cursor: &mut usize,
    mut publish: impl FnMut(&str, &[u8]) -> Result<bool, String>,
) -> Result<bool, String> {
    let total = payloads
        .clone()
        .count()
        .checked_mul(peers.clone().count())
        .ok_or("ETDAG retry pair count overflow")?;
    if total == 0 {
        return Ok(false);
    }
    let start = *cursor % total;
    let pairs = payloads.flat_map(move |payload| peers.clone().map(move |peer| (peer, payload)));
    for (peer, payload) in pairs
        .clone()
        .skip(start)
        .chain(pairs.take(start))
        .take(total.min(MAX_MESSAGES_PER_POLL))
    {
        if !publish(peer, payload)? {
            return Ok(false);
        }
        *cursor = (*cursor % total + 1) % total;
    }
    Ok(true)
}

// Local operational limits, independent of signed protected parameters. The pool
// reserves completion before intake; it is not a claim that all process memory,
// ingress queues, finalized worlds or historical cut proofs fit in this pool.
const LIVE_ETDAG_RESERVATION_BYTES: usize = 32 * 1024 * 1024;
// The genuine maximum131072-byte fresh-wallet carrier reserves32.72MiB
// with native completion witnesses.40MiB is the next8MiB allocation envelope;
// retained collecting reservations remain independently bounded at32MiB.
const ETDAG_TRANSITION_SCRATCH_BYTES: usize = 40 * 1024 * 1024;
// The frozen native validator algorithm is ML-DSA-65. The native regression
// asserts this wire length against the provider; production needs no dev crate.
const ML_DSA_65_SIGNATURE_BYTES: usize = 3309;
const ETDAG_OUTBOUND_SLOTS: usize = 16; // ingress::outbound_limit(Etdag)
const MAX_DURABLE_REVEAL_FRAME_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug)]
struct VertexResourceReservation {
    retained: usize,
    largest_frame: usize,
    collecting_encoded: usize,
    transition_bytes: usize,
}

struct LiveEtdagResources {
    vertices: BTreeMap<(u64, EtdagDigest), VertexResourceReservation>,
    history_bytes: BTreeMap<u64, usize>,
    base_bytes: usize,
    base_frame: usize,
    target_transition_base: usize,
    vote_bytes: usize,
    certificate_frame: usize,
    vote_wire: usize,
    member_count: usize,
    network_header: usize,
    share_bytes: usize,
    share_message_wire: usize,
    // Rejected prospective intake is normal backpressure. Only inability to
    // complete/recover already durable work degrades service health.
    intake_pressure: Option<String>,
    pressure: Option<String>,
}

fn local_resource_pressure(message: &str) -> EtdagError {
    EtdagError::ResourcePressure(message.into())
}

// Count canonical JSON without constructing a second encoded payload buffer.
fn encoded_resource_bytes(value: &impl serde::Serialize) -> Result<usize, EtdagError> {
    struct Counter(usize);
    impl std::io::Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self
                .0
                .checked_add(bytes.len())
                .ok_or_else(|| std::io::Error::other("ETDAG encoded resource count overflow"))?;
            if self.0 > ETDAG_TRANSITION_SCRATCH_BYTES {
                return Err(std::io::Error::other("ETDAG transition scratch pressure"));
            }
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut counter = Counter(0);
    serde_json::to_writer(&mut counter, value)
        .map_err(|_| local_resource_pressure("local ETDAG serialization scratch unavailable"))?;
    Ok(counter.0)
}

impl LiveEtdagResources {
    fn new(
        members: &CutoffMembers,
        lookahead: u64,
        context: &TargetAdmissionContextV3,
    ) -> Result<Self, EtdagError> {
        let signature = ML_DSA_65_SIGNATURE_BYTES;
        let identifiers = members
            .iter()
            .map(|(id, (key, _))| id.capacity().saturating_add(key.capacity()))
            .max()
            .unwrap_or(0);
        let vote = signature.saturating_add(identifiers).saturating_add(4096);
        let vote_bytes = members.len().saturating_mul(vote);
        // JSON escaping <=6 bytes per input byte; byte arrays <=4 per byte.
        let network_header = signature
            .saturating_mul(4)
            .saturating_add(identifiers.saturating_mul(6))
            .saturating_add(2048);
        let vote_wire = signature
            .saturating_mul(4)
            .saturating_add(identifiers.saturating_mul(6))
            .saturating_add(2048);
        let certificate_frame = members
            .len()
            .saturating_mul(vote_wire)
            .saturating_add(network_header)
            .saturating_add(2048);
        let marker = signature
            .saturating_add(identifiers)
            .saturating_add(2048)
            .saturating_add(synergy_etdag::dag::MAX_VERTEX_PARENTS.saturating_mul(192));
        let context_wire = encoded_resource_bytes(context)?;
        // A native VC contains at most one ECHO per frozen member. Each ECHO
        // contains two consensus contexts (the target context is larger), native
        // signature, frozen identifiers and fixed-size native block/hash roots.
        // Parent evidence stores these JSON bytes as Vec<u8>: its next encoding
        // can expand each byte to four characters. Runtime prepares only an
        // unprepared Record, so no phase encodes two parent proofs. Generic
        // duplicate prepare calls retain the pipeline exact allocation guard.
        // No protocol cap is changed.
        let parent_proof = members
            .len()
            .saturating_mul(
                signature
                    .saturating_mul(4)
                    .saturating_add(identifiers.saturating_mul(6))
                    .saturating_add(context_wire.saturating_mul(2))
                    .saturating_add(4096),
            )
            .saturating_add(context_wire.saturating_mul(2))
            .saturating_add(4096);
        let marker_wire = network_header
            .saturating_add(synergy_etdag::dag::MAX_VERTEX_PARENTS.saturating_mul(80));
        let target_transition_base = context_wire
            .saturating_mul(2)
            .saturating_add(members.len().saturating_mul(marker_wire).saturating_mul(2))
            .saturating_add(parent_proof.saturating_mul(4))
            .saturating_add(16384)
            .saturating_mul(8)
            .saturating_add(members.len().saturating_mul(marker).saturating_mul(4));
        let base_bytes = (lookahead as usize).saturating_mul(
            context_wire
                .saturating_mul(8)
                .saturating_add(members.len().saturating_mul(marker).saturating_mul(4))
                .saturating_add(parent_proof.saturating_mul(4)),
        );
        let base_frame = network_header
            .saturating_add(signature.saturating_mul(4))
            .saturating_add(synergy_etdag::dag::MAX_VERTEX_PARENTS.saturating_mul(80))
            .saturating_add(2048);
        // Count native reveal wire separately from retained heap/map padding.
        // Canonical Shamir is an index plus exactly32 bytes. Count its largest
        // canonical representation, then bound each outer JSON byte by255.
        let digest = EtdagDigest("f".repeat(128));
        let authorization = synergy_etdag::ProtectedRevealAuthorization {
            authorization_version: u32::MAX,
            context_root: digest.clone(),
            target_height: u64::MAX,
            protected_batch_root: digest.clone(),
            finality_reference: digest.clone(),
        };
        let maximum_share_bytes = synergy_etdag::crypto::ShamirShare {
            index: u8::MAX,
            value: vec![u8::MAX; 32],
        }
        .canonical_bytes()?
        .len();
        let mut share_message_wire = 0;
        for (validator, (key, _)) in members {
            let share = DecryptShareMessage {
                share_version: u32::MAX,
                authorization: authorization.clone(),
                envelope_id: digest.clone(),
                validator_id: validator.clone(),
                key_id: key.clone(),
                ingress_kem_key_id: String::new(),
                share_index: u8::MAX,
                share_commitment: digest.clone(),
                encrypted_share: vec![255; maximum_share_bytes],
                signature: vec![255; ML_DSA_65_SIGNATURE_BYTES],
            };
            share_message_wire = share_message_wire.max(encoded_resource_bytes(&share)?);
        }
        let result = Self {
            vertices: BTreeMap::new(),
            history_bytes: BTreeMap::new(),
            base_bytes,
            base_frame,
            target_transition_base,
            vote_bytes,
            certificate_frame,
            vote_wire,
            share_message_wire,
            member_count: members.len(),
            network_header,
            // Share::from_canonical_bytes rejects >1024; include authorization,
            // member/key/ingress identifiers, signature and whole-map-node charge.
            share_bytes: members.len().saturating_mul(
                signature
                    .saturating_add(identifiers.saturating_mul(2))
                    .saturating_add(4096),
            ),
            intake_pressure: None,
            pressure: None,
        };
        if result.total_with(None) > LIVE_ETDAG_RESERVATION_BYTES {
            return Err(local_resource_pressure(
                "local ETDAG base reservation requires more capacity",
            ));
        }
        Ok(result)
    }

    fn reservation(
        &self,
        vertex: usize,
        encoded: usize,
        reference_encoded: usize,
        share_encoded: usize,
        plaintext: usize,
    ) -> VertexResourceReservation {
        let vertex_frame = encoded.saturating_add(self.network_header);
        let retained = vertex
            .saturating_mul(8)
            .saturating_add(self.vote_bytes.saturating_mul(8))
            .saturating_add(self.share_bytes.saturating_mul(4))
            .saturating_add(plaintext.saturating_mul(2))
            .saturating_add(vertex_frame)
            .saturating_add(self.network_header.saturating_mul(2))
            .saturating_add(self.certificate_frame)
            .saturating_add(MAX_DURABLE_REVEAL_FRAME_BYTES)
            .saturating_add(8192);
        let collecting_encoded = encoded
            .saturating_add(
                self.vote_wire
                    .saturating_mul(self.member_count.saturating_mul(2).saturating_add(1)),
            )
            .saturating_add(8192);
        // Match the owner's pre-clone guard: encoded state ×8 plus existing
        // collecting allocations. Reserve future VACs, native share transcripts,
        // byte-array plaintext, closure/batch IDs, and selected-envelope scratch.
        // Collecting retains peer/local votes and VACs. Committed Record keeps
        // only VACs; plaintext/transcripts exist only in that latter phase.
        // Bound the larger encoded phase instead of adding mutually exclusive
        // serialized states. Existing collecting-owned allocations stay charged.
        let committed_encoded = encoded
            .saturating_add(self.vote_wire.saturating_mul(self.member_count))
            .saturating_add(reference_encoded)
            .saturating_add(share_encoded)
            .saturating_add(plaintext.saturating_mul(4))
            .saturating_add(16384);
        let transition_bytes = collecting_encoded
            .saturating_add(16384)
            .max(committed_encoded)
            .saturating_mul(8)
            .saturating_add(vertex.saturating_mul(2))
            .saturating_add(self.vote_bytes.saturating_mul(4));
        VertexResourceReservation {
            retained,
            transition_bytes,
            // Initial vertex plus every governed peer vote, the duplicated
            // local vote and a full-member VAC. A target retains1MiB headroom
            // for context/base fields; this is independent of resident charge.
            collecting_encoded,
            largest_frame: vertex_frame
                .max(self.certificate_frame)
                .max(MAX_DURABLE_REVEAL_FRAME_BYTES),
        }
    }

    fn share_wire(&self, envelope: &EncryptedTransactionEnvelope) -> usize {
        // Five digest fields and all frozen consensus identifiers were counted
        // in the typed message. Ingress key IDs come from the actual capsules,
        // including arbitrary JSON escaping, rather than a guessed key length.
        envelope.share_capsules.iter().fold(
            self.share_message_wire
                .saturating_mul(self.member_count)
                .saturating_add(1024), // transcript authorization/map framing
            |sum, capsule| {
                sum.saturating_add(
                    encoded_resource_bytes(&capsule.ingress_kem_key_id)
                        .unwrap_or(usize::MAX)
                        .saturating_sub(2), // replace synthetic empty JSON string
                )
            },
        )
    }

    fn total_with(&self, extra: Option<VertexResourceReservation>) -> usize {
        let mut bytes = self
            .history_bytes
            .values()
            .fold(self.base_bytes, |sum, bytes| sum.saturating_add(*bytes));
        let mut largest_frame = self.base_frame;
        for charge in self.vertices.values().copied().chain(extra) {
            bytes = bytes.saturating_add(charge.retained);
            largest_frame = largest_frame.max(charge.largest_frame);
        }
        // Repeated polls may fill ALL16 slots with the same frame. Reserving
        // only one frame per peer would not bound a stalled outbound queue.
        bytes.saturating_add(largest_frame.saturating_mul(ETDAG_OUTBOUND_SLOTS))
    }

    fn record_intake_pressure(&mut self, reason: String) -> EtdagError {
        #[cfg(test)]
        if self.intake_pressure.as_ref() != Some(&reason) {
            eprintln!("ETDAG intake reservation: {reason}");
        }
        self.intake_pressure = Some(reason.clone());
        local_resource_pressure(&reason)
    }

    fn check(
        &mut self,
        height: u64,
        envelope: &EtdagDigest,
        charge: VertexResourceReservation,
    ) -> Result<(), EtdagError> {
        let previous = self.vertices.get(&(height, envelope.clone())).copied();
        if previous.is_some_and(|old| {
            old.retained >= charge.retained
                && old.largest_frame >= charge.largest_frame
                && old.collecting_encoded >= charge.collecting_encoded
                && old.transition_bytes >= charge.transition_bytes
        }) {
            self.intake_pressure = None;
            return Ok(());
        }
        let charge = previous.map_or(charge, |old| VertexResourceReservation {
            retained: old.retained.max(charge.retained),
            largest_frame: old.largest_frame.max(charge.largest_frame),
            collecting_encoded: old.collecting_encoded.max(charge.collecting_encoded),
            transition_bytes: old.transition_bytes.max(charge.transition_bytes),
        });
        let target_encoded = self
            .vertices
            .iter()
            .filter(|((target, id), _)| *target == height && id != envelope)
            .fold(charge.collecting_encoded, |sum, (_, value)| {
                sum.saturating_add(value.collecting_encoded)
            });
        if target_encoded > 15 * 1024 * 1024 {
            let reason = format!(
                "local ETDAG encoded completion pressure: requested={target_encoded} limit={}",
                15 * 1024 * 1024
            );
            return Err(self.record_intake_pressure(reason));
        }
        let target_transition = self
            .vertices
            .iter()
            .filter(|((target, id), _)| *target == height && id != envelope)
            .fold(
                self.target_transition_base
                    .saturating_add(charge.transition_bytes),
                |sum, (_, value)| sum.saturating_add(value.transition_bytes),
            );
        if target_transition > ETDAG_TRANSITION_SCRATCH_BYTES {
            let count = self
                .vertices
                .keys()
                .filter(|(target, _)| *target == height)
                .count();
            let reason = format!("local ETDAG transition completion pressure: target={height} requested={target_transition} limit={ETDAG_TRANSITION_SCRATCH_BYTES} entries={count} base={} incoming={} previous={} retained_incoming={} encoded_incoming={}", self.target_transition_base, charge.transition_bytes, previous.map_or(0, |old| old.transition_bytes), charge.retained, charge.collecting_encoded);
            return Err(self.record_intake_pressure(reason));
        }
        // Subtract only the old retained charge; old largest-frame queue reserve
        // stays conservative while considering a replacement.
        if self
            .total_with(Some(charge))
            .saturating_sub(previous.map_or(0, |old| old.retained))
            > LIVE_ETDAG_RESERVATION_BYTES
        {
            let used = self.total_with(None);
            let requested = self
                .total_with(Some(charge))
                .saturating_sub(previous.map_or(0, |old| old.retained));
            let reason = format!("local ETDAG completion pressure: used={used} requested={requested} limit={LIVE_ETDAG_RESERVATION_BYTES}; intake remains queued");
            return Err(self.record_intake_pressure(reason));
        }
        self.intake_pressure = None;
        Ok(())
    }

    fn reserve(
        &mut self,
        height: u64,
        envelope: &EtdagDigest,
        charge: VertexResourceReservation,
    ) -> Result<(), EtdagError> {
        self.check(height, envelope, charge)?;
        self.vertices
            .entry((height, envelope.clone()))
            .and_modify(|old| {
                old.retained = old.retained.max(charge.retained);
                old.largest_frame = old.largest_frame.max(charge.largest_frame);
                old.collecting_encoded = old.collecting_encoded.max(charge.collecting_encoded);
                old.transition_bytes = old.transition_bytes.max(charge.transition_bytes);
            })
            .or_insert(charge);
        Ok(())
    }

    fn restore_uncommitted(
        &mut self,
        height: u64,
        envelope: EtdagDigest,
        previous: Option<VertexResourceReservation>,
    ) {
        let key = (height, envelope);
        match previous {
            Some(previous) => {
                self.vertices.insert(key, previous);
            }
            None => {
                self.vertices.remove(&key);
            }
        }
    }

    fn history_limit(&self, height: u64) -> usize {
        LIVE_ETDAG_RESERVATION_BYTES.saturating_sub(
            self.total_with(None)
                .saturating_sub(self.history_bytes.get(&height).copied().unwrap_or(0)),
        )
    }

    fn reserve_history(&mut self, height: u64, bytes: usize) -> Result<(), EtdagError> {
        let limit = self.history_limit(height);
        if bytes > limit {
            return Err(local_resource_pressure(&format!(
                "local ETDAG retained history pressure: target={height} requested={bytes} limit={limit}; originals retained"
            )));
        }
        if bytes != 0 {
            self.history_bytes.insert(height, bytes);
        } else {
            self.history_bytes.remove(&height);
        }
        Ok(())
    }

    fn retire(&mut self, finalized: u64) -> bool {
        let before = self.total_with(None);
        self.history_bytes.retain(|height, _| *height > finalized);
        self.vertices.retain(|(height, _), _| *height > finalized);
        let released = self.total_with(None) < before;
        if released {
            self.intake_pressure = None;
            self.pressure = None;
        }
        released
    }
}

const MAX_PROTECTED_RETIREMENTS_PER_POLL: u64 = 32;
const PROTECTED_RETIREMENT_INTERVAL: Duration = Duration::from_millis(200);
const PROTECTED_RETIREMENT_BACKOFF: Duration = Duration::from_secs(30);

// Only successfully authenticated/applied immutable announcements enter this
// cache. Keep fingerprints, never the large encrypted payloads. A miss always
// takes the full validation path; requests must always produce their response.
const MAX_PROCESSED_ETDAG_FRAMES: usize = 512;
type ProcessedEtdagFrame = (String, synergy_protocol_types::SessionId, String);

#[derive(Default)]
struct ProcessedEtdagFrames {
    entries: BTreeSet<ProcessedEtdagFrame>,
    order: VecDeque<ProcessedEtdagFrame>,
}

impl ProcessedEtdagFrames {
    fn identity(peer: &AuthenticatedPeer, payload: &[u8]) -> ProcessedEtdagFrame {
        (
            peer.node_address.to_string(),
            peer.session_id,
            synergy_block::hash_block_bytes(payload),
        )
    }

    fn remember(&mut self, identity: ProcessedEtdagFrame) {
        if !self.entries.insert(identity.clone()) {
            return;
        }
        self.order.push_back(identity);
        while self.order.len() > MAX_PROCESSED_ETDAG_FRAMES {
            if let Some(oldest) = self.order.pop_front() {
                self.entries.remove(&oldest);
            }
        }
    }
}

#[derive(Default)]
struct ProtectedRetirement {
    next_height: u64,
    through_height: u64,
    verified_execution: Option<synergy_state::FinalizedState>,
    verified_finalized_height: u64,
    last_check: Option<Instant>,
    defer_until: Option<Instant>,
}

impl ProtectedRetirement {
    fn complete_cleanup(&mut self, result: Result<u64, String>, now: Instant) {
        if let Err(error) = result {
            // Obsolete raw records grant no authority. Refuse unsafe deletion,
            // report once per backoff and keep consensus/protected work running.
            self.defer_until = Some(now + PROTECTED_RETIREMENT_BACKOFF);
            eprintln!("ETDAG protected retirement deferred: {error}");
        } else {
            self.defer_until = None;
        }
    }
}

fn protected_retirement_boundary(
    finalized: &synergy_posy::FinalizedBlockRecord,
    executed_finality: &synergy_posy::FinalizedBlockRecord,
    executed: &synergy_state::FinalizedState,
    candidate: &synergy_execution::ExecutionCandidate,
    lookahead: u64,
) -> Result<u64, String> {
    candidate.validate()?;
    if executed.finalized_height != executed_finality.height
        || candidate.height != executed.finalized_height
        || executed.finalized_block_id != executed_finality.block_id
        || candidate.block_id != executed.finalized_block_id
        || candidate.state_root != executed.state_root
        || candidate.protected_execution_root != executed_finality.protected_execution_root
        || (finalized.height == executed_finality.height && finalized != executed_finality)
    {
        return Err("R4 execution commitment differs from verified finalized candidate".into());
    }
    let retained = lookahead
        .checked_add(2)
        .ok_or("R4 retention height overflow")?
        .max(8);
    Ok(finalized
        .height
        .min(executed.finalized_height)
        .saturating_sub(retained))
}

// StoredPipeline puts context before its growing evidence arrays. Stop after
// that bounded field; obsolete history is neither decoded nor reauthenticated.
fn retired_journal_context(file: &mut fs::File) -> Result<TargetAdmissionContextV3, String> {
    let mut reader = std::io::BufReader::new(file.take(64 * 1024));
    let mut prefix = Vec::new();
    let mut byte = [0];
    loop {
        reader
            .read_exact(&mut byte)
            .map_err(|e| format!("R4 journal context prefix: {e}"))?;
        prefix.push(byte[0]);
        // Canonical StoredPipeline serialization uses this exact field token.
        // Deserialize its value alone so the large outer evidence arrays remain unread.
        if prefix.ends_with(b"\"context\":") {
            break;
        }
    }
    let header = std::str::from_utf8(&prefix[..prefix.len() - b"\"context\":".len()])
        .map_err(|e| format!("R4 journal header: {e}"))?;
    if !matches!(header.trim(), "{\"version\":2," | "{\"version\":3,") {
        return Err("R4 journal lacks canonical supported context header".into());
    }
    let mut decoder = serde_json::Deserializer::from_reader(reader);
    serde::Deserialize::deserialize(&mut decoder).map_err(|e| format!("R4 journal context: {e}"))
}

fn retire_protected_records(
    root: &std::path::Path,
    next_height: &mut u64,
    through: u64,
    verify_context: impl Fn(&TargetAdmissionContextV3, u64) -> Result<(), String>,
) -> Result<u64, String> {
    use std::os::unix::fs::MetadataExt;
    let metadata = fs::symlink_metadata(root).map_err(|e| format!("R4 journal root: {e}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("R4 journal root is not a real directory".into());
    }
    let store =
        synergy_storage::AtomicStore::new(root, 16 * 1024 * 1024).map_err(|e| e.to_string())?;
    *next_height = (*next_height).max(3);
    let mut removed = 0;
    let result = (|| -> Result<(), String> {
        for _ in 0..MAX_PROTECTED_RETIREMENTS_PER_POLL {
            let height = *next_height;
            if height > through {
                break;
            }
            let key = format!("protected-h{height}.json");
            if store
                .exists(&key)
                .map_err(|e| format!("R4 journal path: {e}"))?
            {
                store
                    .inspect_append_journal(&key, |file| -> Result<(), String> {
                        let context = retired_journal_context(file)?;
                        verify_context(&context, height)?;
                        let current =
                            fs::symlink_metadata(root.join(&key)).map_err(|e| e.to_string())?;
                        let opened = file.metadata().map_err(|e| e.to_string())?;
                        if current.file_type().is_symlink()
                            || !current.is_file()
                            || current.dev() != opened.dev()
                            || current.ino() != opened.ino()
                        {
                            return Err("R4 journal changed during retirement".into());
                        }
                        fs::remove_file(root.join(&key))
                            .map_err(|e| format!("R4 retire journal: {e}"))
                    })
                    .map_err(|e| e.to_string())??;
                removed += 1;
            }
            *next_height = height
                .checked_add(1)
                .ok_or("R4 retirement cursor overflow")?;
        }
        Ok(())
    })();
    if removed > 0 {
        fs::File::open(root)
            .and_then(|directory| directory.sync_all())
            .map_err(|e| format!("R4 persist retirement: {e}"))?;
    }
    result?;
    Ok(removed)
}

// True gives public context preparation first access; false gives wallets.
// No successful dispatch means the preferred producer keeps its turn.
fn next_admission_dispatch_turn(
    previous: bool,
    context_dispatched: bool,
    wallet_dispatched: bool,
) -> bool {
    if wallet_dispatched {
        true
    } else if context_dispatched {
        false
    } else {
        previous
    }
}

fn cacheable_context_target(newest: &[u64], unavailable: impl Fn(u64) -> bool) -> Option<u64> {
    newest
        .iter()
        .copied()
        .take(2)
        .find(|height| !unavailable(*height))
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum VertexAdmissionFailure {
    Rejected(String),
    ResourcePressure(String),
    Safety(String),
}

impl From<String> for VertexAdmissionFailure {
    fn from(message: String) -> Self {
        Self::Rejected(message)
    }
}
impl From<&str> for VertexAdmissionFailure {
    fn from(message: &str) -> Self {
        Self::Rejected(message.into())
    }
}
impl std::fmt::Display for VertexAdmissionFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rejected(message) | Self::ResourcePressure(message) | Self::Safety(message) => {
                f.write_str(message)
            }
        }
    }
}

fn classify_world_read(error: synergy_state::StateError) -> VertexAdmissionFailure {
    match error {
        synergy_state::StateError::ResourcePressure { .. } => {
            VertexAdmissionFailure::ResourcePressure(format!(
                "admission source state capacity: {error:?}"
            ))
        }
        _ => VertexAdmissionFailure::Safety(format!("read admission source state: {error:?}")),
    }
}

fn classify_vertex_persistence(error: EtdagError) -> VertexAdmissionFailure {
    match error {
        EtdagError::ResourcePressure(message) => VertexAdmissionFailure::ResourcePressure(message),
        EtdagError::Storage(_) | EtdagError::Corrupt(_) => VertexAdmissionFailure::Safety(format!(
            "persist authenticated custody vertex: {error:?}"
        )),
        _ => VertexAdmissionFailure::Rejected(format!("reject custody vertex: {error:?}")),
    }
}

fn complete_local_vertex_admission(
    result: Result<(), VertexAdmissionFailure>,
    response: std::sync::mpsc::Sender<Result<(), String>>,
) -> Result<(), String> {
    match result {
        Ok(()) => {
            let _ = response.send(Ok(()));
            Ok(())
        }
        Err(
            VertexAdmissionFailure::Rejected(message)
            | VertexAdmissionFailure::ResourcePressure(message),
        ) => {
            let _ = response.send(Err(message));
            Ok(())
        }
        Err(VertexAdmissionFailure::Safety(message)) => {
            let _ = response.send(Err(message.clone()));
            Err(message)
        }
    }
}

struct LocalEtdagSigner {
    validator_id: String,
    key_id: KeyId,
    signer: Arc<dyn AegisSigner>,
    chain_id: u64,
    epoch: u64,
}

impl LocalEtdagSigner {
    fn sign_share(&self, mut share: DecryptShareMessage) -> Result<DecryptShareMessage, String> {
        share.signature = self
            .signer
            .sign(
                &self.key_id,
                &SigningContext {
                    domain: "SYNERGY-ETDAG-SIGNATURE-V1".into(),
                    chain_id: self.chain_id,
                    epoch: Some(self.epoch),
                    height: None,
                },
                &share
                    .signing_bytes()
                    .map_err(|e| format!("encode reveal share: {e:?}"))?,
            )
            .map_err(|e| format!("sign authorized reveal share: {e}"))?
            .bytes;
        Ok(share)
    }

    fn sign_availability_vote(
        &self,
        context_root: EtdagDigest,
        vertex_id: EtdagDigest,
    ) -> Result<AvailabilityVote, String> {
        let mut vote = AvailabilityVote {
            context_root,
            vertex_id,
            validator_id: self.validator_id.clone(),
            key_id: self.key_id.as_str().to_owned(),
            signature: Vec::new(),
        };
        let bytes = canonical_signing_bytes(
            "SYNERGY_ETDAG_AVAILABILITY_VOTE_V1",
            &(
                &vote.context_root,
                &vote.vertex_id,
                &vote.validator_id,
                &vote.key_id,
            ),
        )
        .map_err(|e| format!("encode availability vote: {e:?}"))?;
        vote.signature = self
            .signer
            .sign(
                &self.key_id,
                &SigningContext {
                    domain: "SYNERGY-ETDAG-SIGNATURE-V1".into(),
                    chain_id: self.chain_id,
                    epoch: Some(self.epoch),
                    height: None,
                },
                &bytes,
            )
            .map_err(|e| format!("sign availability custody vote: {e}"))?
            .bytes;
        Ok(vote)
    }

    fn sign_cutoff_marker(
        &self,
        context_root: EtdagDigest,
        target_height: u64,
        cutoff_context_root: EtdagDigest,
        frontier: Vec<EtdagDigest>,
    ) -> Result<ProtectedCutMarker, String> {
        let mut marker = ProtectedCutMarker {
            marker_version: 1,
            context_root,
            target_height,
            cutoff_context_root,
            frontier,
            validator_id: self.validator_id.clone(),
            key_id: self.key_id.as_str().to_owned(),
            signature: Vec::new(),
        };
        let bytes = marker
            .signing_bytes()
            .map_err(|error| format!("encode protected cutoff statement: {error:?}"))?;
        marker.signature = self
            .signer
            .sign(
                &self.key_id,
                &SigningContext {
                    domain: "SYNERGY-ETDAG-SIGNATURE-V1".into(),
                    chain_id: self.chain_id,
                    epoch: Some(self.epoch),
                    height: None,
                },
                &bytes,
            )
            .map_err(|error| format!("sign protected cutoff statement: {error}"))?
            .bytes;
        Ok(marker)
    }

    fn sign_message(
        &self,
        message: EtdagNetworkMessage,
    ) -> Result<AuthenticatedEtdagMessage, String> {
        let message_id = EtdagDigest::from_canonical(
            "SYNERGY_ETDAG_NETWORK_MESSAGE_V1",
            &(
                1u32,
                self.validator_id.trim(),
                self.key_id.as_str(),
                &message,
            ),
        )
        .map_err(|error| format!("derive outbound ETDAG message id: {error:?}"))?;
        let signing_bytes = canonical_signing_bytes(
            "SYNERGY_ETDAG_NETWORK_MESSAGE_SIGNATURE_V1",
            &(
                1u32,
                &message_id,
                &self.validator_id,
                self.key_id.as_str(),
                &message,
            ),
        )
        .map_err(|error| format!("encode outbound ETDAG signature transcript: {error:?}"))?;
        let signature = self
            .signer
            .sign(
                &self.key_id,
                &SigningContext {
                    domain: "SYNERGY-ETDAG-SIGNATURE-V1".into(),
                    chain_id: self.chain_id,
                    epoch: Some(self.epoch),
                    height: None,
                },
                &signing_bytes,
            )
            .map_err(|error| format!("sign outbound ETDAG message with Aegis: {error}"))?;
        Ok(AuthenticatedEtdagMessage {
            message_version: 1,
            message_id,
            sender_id: self.validator_id.clone(),
            key_id: self.key_id.as_str().to_owned(),
            message,
            signature: signature.bytes,
        })
    }
}

fn load_local_signer(
    configuration: &NodeConfiguration,
    authority: &VerifiedAuthority,
) -> Result<LocalEtdagSigner, String> {
    let identity_metadata = fs::symlink_metadata(&configuration.public_identity_path)
        .map_err(|error| format!("inspect ETDAG public identity: {error}"))?;
    if identity_metadata.file_type().is_symlink()
        || !identity_metadata.is_file()
        || identity_metadata.len() == 0
        || identity_metadata.len() > MAX_IDENTITY_BYTES
    {
        return Err("ETDAG public identity must be a bounded regular file".into());
    }
    let identity = serde_json::from_slice::<PublicNodeIdentity>(
        &fs::read(&configuration.public_identity_path)
            .map_err(|error| format!("read ETDAG public identity: {error}"))?,
    )
    .map_err(|error| format!("decode ETDAG public identity: {error}"))?
    .validate()
    .map_err(|error| format!("validate ETDAG public identity: {error:?}"))?;
    let (key_id_text, public_key) = authority.consensus_binding(identity.node_address.as_str())?;
    let key_id = KeyId::new(key_id_text.to_owned()).map_err(|error| error.to_string())?;
    if configuration.apqe_transport.is_some() {
        let signer = super::apqe_provider::consensus_signer(
            configuration,
            authority,
            identity.node_address.as_str(),
            AegisPolicy {
                allowed_algorithms: vec![SignatureAlgorithm::MlDsa65],
                maximum_message_bytes: MAX_ETDAG_SIGNING_BYTES,
                maximum_signature_bytes: 16 * 1024,
            },
        )?;
        return Ok(LocalEtdagSigner {
            validator_id: identity.node_address.to_string(),
            key_id,
            signer,
            chain_id: configuration.chain_id,
            epoch: authority.epoch.epoch,
        });
    }
    let signing_key_path = configuration
        .consensus
        .signing_key_path
        .as_ref()
        .ok_or("ETDAG artifact serving requires consensus.signing_key_path")?;
    let key_metadata = fs::symlink_metadata(signing_key_path)
        .map_err(|error| format!("inspect ETDAG signing key: {error}"))?;
    if key_metadata.file_type().is_symlink()
        || !key_metadata.is_file()
        || key_metadata.len() == 0
        || key_metadata.len() > MAX_SIGNING_KEY_BYTES
    {
        return Err("ETDAG signing key must be a bounded regular file".into());
    }
    let policy = AegisPolicy {
        allowed_algorithms: vec![SignatureAlgorithm::MlDsa65],
        maximum_message_bytes: MAX_ETDAG_SIGNING_BYTES,
        maximum_signature_bytes: 16 * 1024,
    };
    let signer = super::apqe_provider::signer(
        configuration,
        policy.clone(),
        key_id.clone(),
        public_key,
        fs::read(signing_key_path).map_err(|error| format!("read ETDAG signing key: {error}"))?,
    )
    .map_err(|error| format!("load Aegis ETDAG signer: {error}"))?;
    let verifier = super::apqe_provider::verifier(configuration, policy)?;
    let proof = b"SYNERGY-ETDAG-CONSENSUS-KEY-POSSESSION-V1";
    let context = SigningContext {
        domain: "SYNERGY-ETDAG-CONSENSUS-KEY-POSSESSION-V1".into(),
        chain_id: configuration.chain_id,
        epoch: Some(authority.epoch.epoch),
        height: None,
    };
    let signature = signer
        .sign(&key_id, &context, proof)
        .map_err(|error| format!("prove ETDAG key possession: {error}"))?;
    verifier
        .verify(&context, proof, &signature, public_key)
        .map_err(|_| "ETDAG signing key differs from frozen authority binding".to_string())?;
    Ok(LocalEtdagSigner {
        validator_id: identity.node_address.to_string(),
        key_id,
        signer: Arc::new(signer),
        chain_id: configuration.chain_id,
        epoch: authority.epoch.epoch,
    })
}

struct LocalIngressCustody {
    secret: Vec<u8>,
    kem: Option<Arc<dyn synergy_aegis::AegisKem>>,
}
impl Drop for LocalIngressCustody {
    fn drop(&mut self) {
        self.secret.fill(0);
    }
}
fn load_ingress_custody(
    configuration: &NodeConfiguration,
    authority: &VerifiedAuthority,
    validator: &str,
) -> Result<LocalIngressCustody, String> {
    if configuration.apqe_transport.is_some() {
        return Ok(LocalIngressCustody {
            secret: Vec::new(),
            kem: Some(super::apqe_provider::ingress_kem(
                configuration,
                authority,
                validator,
            )?),
        });
    }
    let path = configuration
        .etdag
        .ingress_kem_secret_key_path
        .as_ref()
        .ok_or("ETDAG validator requires etdag.ingress_kem_secret_key_path")?;
    let before =
        fs::symlink_metadata(path).map_err(|e| format!("inspect ingress custody key: {e}"))?;
    if !before.is_file()
        || before.file_type().is_symlink()
        || before.len() != ML_KEM_1024_SECRET_KEY_BYTES as u64
    {
        return Err(
            "ingress custody key must be an exact bounded regular non-symlink ML-KEM-1024 secret"
                .into(),
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if before.permissions().mode() & 0o077 != 0 {
            return Err("ingress custody key must be owner-only".into());
        }
    }
    let file = fs::File::open(path).map_err(|e| format!("open ingress custody key: {e}"))?;
    let after = file
        .metadata()
        .map_err(|e| format!("inspect opened custody key: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.dev() != after.dev() || before.ino() != after.ino() {
            return Err("ingress custody key changed while opening".into());
        }
    }
    if after.len() != before.len() || !after.is_file() {
        return Err("ingress custody key changed shape".into());
    }
    let kem = if cfg!(test) && configuration.aegis_provider.is_none() {
        None
    } else {
        Some(Arc::new(
            synergy_aegis::ApqeKem::mlkem1024(super::apqe_provider::load(configuration)?)
                .map_err(|e| format!("construct APQE ingress KEM: {e:?}"))?,
        ) as Arc<dyn synergy_aegis::AegisKem>)
    };
    let mut custody = LocalIngressCustody {
        secret: Vec::new(),
        kem,
    };
    file.take(ML_KEM_1024_SECRET_KEY_BYTES as u64 + 1)
        .read_to_end(&mut custody.secret)
        .map_err(|e| format!("read bounded ingress custody key: {e}"))?;
    if custody.secret.len() != ML_KEM_1024_SECRET_KEY_BYTES {
        return Err("ingress custody key changed length".into());
    }
    let registry = authority.protected_ingress_registry()?;
    registry
        .validate_protected_profile()
        .map_err(|e| format!("validate governed custody registry: {e:?}"))?;
    if !registry
        .records
        .iter()
        .filter(|r| r.validator_id == validator)
        .any(|r| match custody.kem.as_ref() {
            Some(kem) => synergy_etdag::crypto::verify_ingress_key_possession_with_kem(
                r,
                &custody.secret,
                kem.as_ref(),
            )
            .is_ok(),
            None => verify_ingress_key_possession(r, &custody.secret).is_ok(),
        })
    {
        return Err("ingress custody key differs from governed validator binding".into());
    }
    Ok(custody)
}

// The same verified finalized retention boundary used for custody controls
// released-share evidence. Active target namespaces are never removed.
fn prune_reveal_records(root: &std::path::Path, through: u64) -> Result<(), String> {
    if through == 0 {
        return Ok(());
    }
    for entry in fs::read_dir(root).map_err(|e| format!("inspect reveal retention: {e}"))? {
        let entry = entry.map_err(|e| format!("inspect reveal namespace: {e}"))?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let Some((height, context)) = name.split_once('-') else {
            continue;
        };
        let Ok(height) = height.parse::<u64>() else {
            continue;
        };
        if height.to_string() != name.split_once('-').map(|p| p.0).unwrap_or_default()
            || height == 0
            || EtdagDigest(context.into()).validate().is_err()
        {
            continue;
        }
        if height > through {
            continue;
        }
        let kind = entry
            .file_type()
            .map_err(|e| format!("inspect retained reveal directory: {e}"))?;
        if !kind.is_dir() || kind.is_symlink() {
            return Err("reveal retention namespace has invalid shape".into());
        }
        for file in fs::read_dir(entry.path())
            .map_err(|e| format!("inspect finalized reveal records: {e}"))?
        {
            let file = file.map_err(|e| format!("inspect finalized reveal record: {e}"))?;
            let kind = file
                .file_type()
                .map_err(|e| format!("inspect finalized reveal shape: {e}"))?;
            let name = file.file_name();
            let id = name
                .to_str()
                .and_then(|n| n.strip_suffix(".json"))
                .ok_or("unexpected file in finalized reveal namespace")?;
            if !kind.is_file() || kind.is_symlink() || EtdagDigest(id.into()).validate().is_err() {
                return Err("finalized reveal record has invalid shape".into());
            }
            fs::remove_file(file.path())
                .map_err(|e| format!("prune finalized reveal record: {e}"))?;
        }
        fs::remove_dir(entry.path())
            .map_err(|e| format!("prune finalized reveal namespace: {e}"))?;
    }
    Ok(())
}

// Synchronous fixture adapter; production uses the preparation-aware owner.
#[cfg(test)]
pub fn registration_with_admission(
    configuration: &NodeConfiguration,
    authority: Arc<VerifiedAuthority>,
    ingress: AuthenticatedIngress,
    wallet_admission: Option<super::protected_admission::AdmissionHandle>,
) -> Result<(ServiceSpec, Box<dyn ManagedService>), String> {
    registration_with_preparation(configuration, authority, ingress, wallet_admission, None)
}

// Resource sizing must use a real admission context without granting any
// target authority. Genesis has its governed bootstrap context; successors
// require the already verified transition's actual finalized source record.
pub(super) fn resource_sizing_context(
    configuration: &NodeConfiguration,
    authority: &VerifiedAuthority,
) -> Result<TargetAdmissionContextV3, String> {
    if authority.epoch.epoch == 1 {
        return authority
            .protected_target(None, 3)
            .map(|(context, _)| context);
    }
    let (source, _) = authority::load_transition_finality_prefix(configuration, authority)?
        .ok_or("successor ETDAG sizing lacks verified transition finality")?;
    let target = authority
        .protected_parameters()?
        .protected_target_height(source.height)
        .map_err(|error| format!("successor ETDAG sizing target: {error:?}"))?;
    authority
        .protected_target(Some(&source), target)
        .map(|(context, _)| context)
}

pub fn registration_with_preparation(
    configuration: &NodeConfiguration,
    authority: Arc<VerifiedAuthority>,
    ingress: AuthenticatedIngress,
    wallet_admission: Option<super::protected_admission::AdmissionHandle>,
    preparation: Option<super::preparation::Handle>,
) -> Result<(ServiceSpec, Box<dyn ManagedService>), String> {
    if !configuration.etdag.enabled {
        return Err("ETDAG service cannot be registered when ETDAG is disabled".into());
    }
    if let Some(handle) = &wallet_admission {
        handle.bind_ingress(ingress.clone())?;
    }
    let parameters = authority.protected_parameters()?;
    parameters
        .validate()
        .map_err(|error| format!("validate governed ETDAG parameters: {error:?}"))?;
    if configuration.etdag.protected_lookahead != parameters.target_height_offset {
        return Err("ETDAG configuration does not preserve governed protected lookahead".into());
    }
    let members = authority
        .registry
        .active()
        .map(|validator| validator.validator_id.clone())
        .collect::<BTreeSet<_>>();
    let layout = NodeStorageLayout::new(configuration.storage.data_directory.clone())
        .map_err(|error| format!("construct canonical storage layout: {error}"))?;
    let shard_store = FilesystemShardStore::open(layout.etdag().join("availability-shards"))?;
    let local_signer = load_local_signer(configuration, authority.as_ref())?;
    if authority.processing_profile_enabled() {
        ingress.set_processing_local_validator(&local_signer.validator_id)?;
    }
    if let Some(handle) = &wallet_admission {
        let namespace = EtdagDigest::from_canonical(
            "SYNERGY_ADMISSION_OBSERVATION_AUTHORITY_V1",
            &(authority.binding_bytes(), &local_signer.validator_id),
        )
        .map_err(|e| format!("receipt authority namespace: {e:?}"))?
        .0;
        handle.bind_receipt_journal(&layout.etdag().join("admission-receipts"), namespace)?;
    }
    let ingress_custody = load_ingress_custody(
        configuration,
        authority.as_ref(),
        &local_signer.validator_id,
    )?;
    let reveal_store = synergy_storage::AtomicStore::new(
        layout.etdag().join("protected-pipeline/reveal-shares"),
        64 * 1024,
    )
    .map_err(|e| format!("open durable reveal share store: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(
            layout.etdag().join("protected-pipeline/reveal-shares"),
            fs::Permissions::from_mode(0o700),
        )
        .map_err(|e| format!("protect durable reveal namespace: {e}"))?;
    }
    let cutoff_members = authority
        .registry
        .active()
        .map(|validator| {
            let weight = u64::try_from(validator.frozen_voting_weight)
                .map_err(|_| "ETDAG frozen weight exceeds governed u64 capacity".to_string())?;
            Ok((
                validator.validator_id.clone(),
                (validator.consensus_key_id.clone(), weight),
            ))
        })
        .collect::<Result<CutoffMembers, String>>()?;
    let resources = LiveEtdagResources::new(
        &cutoff_members,
        parameters.target_height_offset,
        &resource_sizing_context(configuration, authority.as_ref())?,
    )
    .map_err(|e| format!("ETDAG local resource provisioning: {e:?}"))?;
    Ok((
        ServiceSpec {
            id: ServiceId::new("etdag")?,
            dependencies: vec![ServiceId::new("sync")?, ServiceId::new("storage")?],
            criticality: Criticality::Critical,
            restart_policy: RestartPolicy::OnFailure { max_attempts: 3 },
        },
        super::owned_service::production(
            Box::new(EtdagService {
                processing_transition: authority::load_transition_context(
                    configuration,
                    authority.as_ref(),
                )?,
                processing: authority
                    .processing_profile_enabled()
                    .then(processing::ProcessingOwner::default),
                parameters,
                pipeline_root: layout.etdag().join("protected-pipeline"),
                cut_recovery_verifier: super::cut_recovery::CutRecoveryVerifier::new(
                    authority.clone(),
                    layout.consensus().join("posy"),
                ),
                finalized_state_root: layout.state().join("execution"),
                processing_candidate_root: layout.blocks().join("execution-candidates"),
                processing_consensus_root: layout.consensus().join("posy"),
                wallet_admission,
                preparation_handle: preparation,
                context_preparation: None,
                wallet_preparation: None,
                wallet_jobs: BTreeMap::new(),
                initial_wallet_world: Arc::new(
                    authority.initial_world_state_budgeted(ingress.world_budget())?,
                ),
                context_jobs: BTreeMap::new(),
                prepared_contexts: BTreeMap::new(),
                context_dispatch_turn: false,
                cutoff_members,
                targets: BTreeMap::new(),
                recovering_targets: BTreeMap::new(),
                recovery_capacity_blocked: false,
                owner_cancellation: None,
                certificates: BTreeMap::new(),
                marker_frames: BTreeMap::new(),
                vertex_frames: BTreeMap::new(),
                availability_frames: BTreeMap::new(),
                certificate_frames: BTreeMap::new(),
                reveal_frames: BTreeMap::new(),
                reveal_shares: BTreeMap::new(),
                reveal_store,
                ingress_custody,
                processed_frames: ProcessedEtdagFrames::default(),
                resources,
                retry_cursor: 0,
                last_retry: None,
                authority,
                members: members.clone(),

                ingress,
                shard_store,
                local_signer,
                retention_blocks: configuration.storage.prune_finalized_history_after_blocks,
                last_pruned_finalized_height: 0,
                protected_retirement: (configuration.role
                    == synergy_protocol_types::NodeRole::Validator)
                    .then(ProtectedRetirement::default),
                graphs: BTreeMap::new(),
                available: BTreeSet::new(),
                metrics: EtdagMetrics::default(),
                started: false,
                ingress_paused: false,
                failure: None,
            }),
            "etdag",
        ),
    ))
}

struct PreparedWalletAdmission {
    pending: super::protected_admission::PendingAdmission,
    context_root: EtdagDigest,
    verified: Result<(), VertexAdmissionFailure>,
}
struct PreparedWalletContext {
    context_root: EtdagDigest,
    // Raw bounded bytes keep heap-expanded JSON outside the result mailbox.
    response: Vec<u8>,
}
struct PublishedWalletContext {
    context_root: EtdagDigest,
    response: serde_json::Value,
}

// Signatures/frontiers belong only to the active cutoff. Compact authenticated
// identities preserve historical equivocation checks without retaining payloads.
#[derive(Default)]
struct CutMarkerCache {
    fingerprints: BTreeMap<(EtdagDigest, String), EtdagDigest>,
    payloads: BTreeMap<(EtdagDigest, String), ProtectedCutMarker>,
}
impl CutMarkerCache {
    fn select(&mut self, cutoff: &EtdagDigest) {
        self.payloads.retain(|(root, _), _| root == cutoff);
    }
    // Call only after frozen membership and native signature verification, or
    // for the locally signed marker authenticated by the durable pipeline.
    fn remember(&mut self, marker: ProtectedCutMarker, cutoff: &EtdagDigest) -> Result<(), String> {
        let key = (
            marker.cutoff_context_root.clone(),
            marker.validator_id.clone(),
        );
        let fingerprint = EtdagDigest::from_domain_bytes(
            "SYNERGY_ETDAG_AUTHENTICATED_MARKER_CACHE_V1",
            &marker
                .signing_bytes()
                .map_err(|e| format!("encode cutoff: {e:?}"))?,
        );
        if let Some(previous) = self.fingerprints.get(&key) {
            if previous != &fingerprint {
                return Err("cutoff signer equivocated in one target".into());
            }
        } else {
            self.fingerprints.insert(key.clone(), fingerprint);
        }
        self.select(cutoff);
        if &marker.cutoff_context_root == cutoff {
            self.payloads.entry(key).or_insert(marker);
        }
        Ok(())
    }
}

struct ProtectedTarget {
    context: TargetAdmissionContextV3,
    pipeline: Option<ProtectedPipeline>,
    markers: CutMarkerCache,
    handed_off: bool,
}

struct EtdagService {
    processing_transition: Option<authority::VerifiedTransitionContext>,
    processing: Option<processing::ProcessingOwner>,
    finalized_state_root: PathBuf,
    processing_candidate_root: PathBuf,
    processing_consensus_root: PathBuf,
    wallet_admission: Option<super::protected_admission::AdmissionHandle>,
    preparation_handle: Option<super::preparation::Handle>,
    context_preparation: Option<super::preparation::Owner<PreparedWalletContext>>,
    wallet_preparation: Option<super::preparation::Owner<PreparedWalletAdmission>>,
    wallet_jobs: BTreeMap<String, super::preparation::JobTag>,
    initial_wallet_world: Arc<synergy_state::world_resources::BudgetedWorld>,
    context_jobs: BTreeMap<u64, super::preparation::JobTag>,
    prepared_contexts: BTreeMap<u64, PublishedWalletContext>,
    context_dispatch_turn: bool,
    parameters: EtdagParameters,
    pipeline_root: PathBuf,
    cut_recovery_verifier: super::cut_recovery::CutRecoveryVerifier,
    cutoff_members: CutoffMembers,
    targets: BTreeMap<u64, ProtectedTarget>,
    recovering_targets: BTreeMap<u64, ProtectedPipelineRecovery>,
    recovery_capacity_blocked: bool,
    owner_cancellation: Option<CancellationToken>,
    certificates: BTreeMap<(EtdagDigest, u64), BTreeMap<EtdagDigest, AvailabilityCertificate>>,
    marker_frames: BTreeMap<(u64, EtdagDigest), Vec<u8>>,
    vertex_frames: BTreeMap<(u64, EtdagDigest), Vec<u8>>,
    availability_frames: BTreeMap<(u64, EtdagDigest), Vec<u8>>,
    certificate_frames: BTreeMap<(u64, EtdagDigest), Vec<u8>>,
    reveal_frames: BTreeMap<(u64, EtdagDigest), Vec<u8>>,
    reveal_shares: BTreeMap<(u64, EtdagDigest), BTreeMap<String, DecryptShareMessage>>,
    reveal_store: synergy_storage::AtomicStore,
    ingress_custody: LocalIngressCustody,
    processed_frames: ProcessedEtdagFrames,
    resources: LiveEtdagResources,
    retry_cursor: usize,
    last_retry: Option<Instant>,
    authority: Arc<VerifiedAuthority>,
    members: BTreeSet<String>,
    ingress: AuthenticatedIngress,
    shard_store: FilesystemShardStore,
    local_signer: LocalEtdagSigner,
    retention_blocks: Option<u64>,
    last_pruned_finalized_height: u64,
    protected_retirement: Option<ProtectedRetirement>,
    graphs: BTreeMap<(EtdagDigest, u64), EtdagGraph>,
    available: BTreeSet<(EtdagDigest, EtdagDigest)>,
    metrics: EtdagMetrics,
    started: bool,
    ingress_paused: bool,
    failure: Option<String>,
}

/// Batch transaction IDs are envelope commitments, never graph vertex IDs.
/// Reject ambiguity rather than opening custody for a different vertex.
pub(super) fn selected_envelope<'a>(
    graph: &'a EtdagGraph,
    batch: &synergy_etdag::DeterministicProtectedBatch,
    envelope_id: &EtdagDigest,
) -> Result<&'a EncryptedTransactionEnvelope, String> {
    if !batch.ordered_transaction_ids.contains(envelope_id)
        || graph.context_root() != &batch.context_root
        || graph.target_height() != batch.target_height
    {
        return Err("reveal envelope is outside selected protected cut".into());
    }
    let mut matches = graph
        .vertices()
        .filter(|vertex| &vertex.envelope.envelope_id == envelope_id);
    let selected = matches
        .next()
        .ok_or("selected reveal envelope vertex missing")?;
    if matches.next().is_some() {
        return Err("selected reveal envelope maps to multiple vertices".into());
    }
    Ok(&selected.envelope)
}

impl EtdagService {
    /// Verify account authority at the exact finalized source frozen by this
    /// target, so peers cannot disagree because one has already executed ahead.
    fn verify_admission(
        &self,
        admission: &synergy_etdag::WalletAdmission,
    ) -> Result<(), VertexAdmissionFailure> {
        let target = self
            .targets
            .get(&admission.request.target_height)
            .ok_or("protected admission target is unavailable")?;
        let world = if target.context.source_finalized_height == 0 {
            Arc::clone(&self.initial_wallet_world)
        } else {
            let store = synergy_state::FinalizedStateStore::load_budgeted(
                &self.finalized_state_root,
                Arc::clone(self.ingress.world_budget()),
            )
            .map_err(|e| {
                VertexAdmissionFailure::Safety(format!("load admission source state: {e:?}"))
            })?;
            store
                .world_state_at_budgeted(
                    target.context.source_finalized_height,
                    self.ingress.world_budget(),
                )
                .map_err(classify_world_read)?
                .map(Arc::new)
                .ok_or_else(|| {
                    VertexAdmissionFailure::Safety(
                        "verified target lacks finalized source state".into(),
                    )
                })?
        };
        let timestamp = self
            .authority
            .consensus_timestamp_unix(target.context.target_height)
            .map_err(VertexAdmissionFailure::Safety)?;
        super::protected_admission::verify_wallet_admission_with_authority(
            admission,
            &world,
            target.context.chain_id,
            &target.context.network_id,
            timestamp,
            Some(self.authority.as_ref()),
        )
        .map_err(VertexAdmissionFailure::Rejected)?;
        let nonce = world
            .accounts
            .get(&admission.request.sender_wallet)
            .ok_or("admission sender has no governed account")?
            .nonce;
        if admission.request.sender_nonce < nonce
            || admission.request.sender_nonce.saturating_sub(nonce)
                >= self.parameters.max_outstanding_nonce_slots as u64
            || admission.request.gas_class_units > self.parameters.max_protected_gas
        {
            return Err("admission nonce window or gas class exceeds governed bounds".into());
        }
        Ok(())
    }

    fn wallet_resource_reservation(
        &self,
        admission: &synergy_etdag::WalletAdmission,
    ) -> Result<VertexResourceReservation, EtdagError> {
        let request = &admission.request;
        // Vertex owns both envelope and wallet admission. Parent/key metadata and
        // signature are bounded before their first local allocation/signature.
        let vertex = ProtectedPipeline::wallet_admission_resource_bytes(admission)?
            .saturating_add(ProtectedPipeline::envelope_resource_bytes(
                &request.envelope,
            ))
            .saturating_add(self.local_signer.validator_id.capacity())
            .saturating_add(ML_DSA_65_SIGNATURE_BYTES)
            .saturating_add(synergy_etdag::dag::MAX_VERTEX_PARENTS * 192)
            .saturating_add(std::mem::size_of::<(EtdagDigest, TransactionVertex)>() * 12 + 256)
            .saturating_add(8192);
        let encoded = encoded_resource_bytes(admission)?
            .saturating_add(encoded_resource_bytes(&request.envelope)?)
            .saturating_add(self.resources.network_header)
            .saturating_add(synergy_etdag::dag::MAX_VERTEX_PARENTS * 80)
            .saturating_add(8192);
        let reference = synergy_etdag::CertifiedEnvelopeRef {
            tx_commitment: request.envelope.envelope_id.clone(),
            sender_id: request.sender_wallet.clone(),
            nonce_slot: request.sender_nonce,
            certified_dag_round: u64::MAX,
            gas_class_units: request.gas_class_units,
            ciphertext_bytes: request.envelope.ciphertext.len() as u64,
            fee_class: request.fee_class,
            protocol_dependencies: Vec::new(),
        };
        Ok(self.resources.reservation(
            vertex,
            encoded,
            encoded_resource_bytes(&reference)?,
            self.resources.share_wire(&request.envelope),
            request.envelope.ciphertext.len(),
        ))
    }

    fn check_target_transition_scratch(&mut self, height: u64) -> bool {
        let Some(target) = self.targets.get(&height) else {
            return false;
        };
        let Some(owner) = target.pipeline.as_ref() else {
            return false;
        };
        let _ = owner; // Pipeline retains its exact preallocation guard as well.
        let required = self
            .resources
            .vertices
            .iter()
            .filter(|((target, _), _)| *target == height)
            .fold(self.resources.target_transition_base, |sum, (_, value)| {
                sum.saturating_add(value.transition_bytes)
            });
        if required <= ETDAG_TRANSITION_SCRATCH_BYTES {
            true
        } else {
            self.resources.pressure = Some(format!(
                "local ETDAG transition pressure: requested={required} limit={ETDAG_TRANSITION_SCRATCH_BYTES}; durable evidence retained"
            ));
            false
        }
    }

    fn check_wallet_resources(
        &mut self,
        admission: &synergy_etdag::WalletAdmission,
    ) -> Result<(), EtdagError> {
        let charge = self.wallet_resource_reservation(admission)?;
        self.resources.check(
            admission.request.target_height,
            &admission.request.envelope.envelope_id,
            charge,
        )
    }

    fn author_admission(
        &mut self,
        admission: synergy_etdag::WalletAdmission,
    ) -> Result<serde_json::Value, VertexAdmissionFailure> {
        self.verify_admission(&admission)?;
        self.author_verified_admission(admission)
    }

    // Only a matching immutable worker result or synchronous native verification enters here.
    fn rollback_undurable_reservation(
        &mut self,
        height: u64,
        envelope: EtdagDigest,
        previous: Option<VertexResourceReservation>,
    ) {
        let durable = self
            .targets
            .get(&height)
            .and_then(|target| target.pipeline.as_ref())
            .is_some_and(|owner| {
                owner
                    .graph()
                    .vertices()
                    .any(|vertex| vertex.envelope.envelope_id == envelope)
            });
        if !durable {
            self.resources
                .restore_uncommitted(height, envelope, previous);
        }
    }

    fn author_verified_admission(
        &mut self,
        admission: synergy_etdag::WalletAdmission,
    ) -> Result<serde_json::Value, VertexAdmissionFailure> {
        #[cfg(feature = "qualification-timing")]
        let _author_timing = super::protected_admission::AdmissionTimingSpan::start(
            &admission,
            "owner-wallet-authoring",
        );
        let height = admission.request.target_height;
        let envelope = admission.request.envelope.envelope_id.clone();
        let previous = self
            .resources
            .vertices
            .get(&(height, envelope.clone()))
            .copied();
        let result = self.author_verified_admission_inner(admission);
        // Safety/storage errors can have an uncertain append outcome; retain
        // their reservation even when in-memory insertion has not occurred.
        if matches!(
            &result,
            Err(VertexAdmissionFailure::Rejected(_) | VertexAdmissionFailure::ResourcePressure(_))
        ) {
            self.rollback_undurable_reservation(height, envelope, previous);
        }
        result
    }

    fn author_verified_admission_inner(
        &mut self,
        admission: synergy_etdag::WalletAdmission,
    ) -> Result<serde_json::Value, VertexAdmissionFailure> {
        let charge = self
            .wallet_resource_reservation(&admission)
            .map_err(classify_vertex_persistence)?;
        let request = &admission.request;
        let key = (request.context_root.clone(), request.target_height);
        let graph = self
            .graphs
            .get(&key)
            .ok_or("wallet target graph is unavailable")?;
        if let Some(existing) = graph
            .vertices()
            .find(|vertex| vertex.envelope.envelope_id == request.envelope.envelope_id)
        {
            if existing.wallet_admission.as_ref() != Some(&admission) {
                return Err("wallet envelope conflicts with admitted authorization".into());
            }
            // A persisted vertex may only be staging if VC arrived during its disk acknowledgement.
            if self
                .ingress
                .protected_cutoff_authority(request.target_height)
                .map_err(VertexAdmissionFailure::Safety)?
                .is_some()
                && !self
                    .certificates
                    .get(&key)
                    .is_some_and(|c| c.contains_key(&existing.vertex_id))
                && !self
                    .wallet_admission
                    .as_ref()
                    .map(|h| h.was_durably_admitted(&admission))
                    .transpose()
                    .map_err(VertexAdmissionFailure::Safety)?
                    .unwrap_or(false)
            {
                return Err("fresh local protected admission is closed".into());
            }
            return Ok(
                serde_json::json!({"vertex_id":existing.vertex_id,"envelope_id":existing.envelope.envelope_id,
                "target_height":existing.target_height,"newly_admitted":false,"finalized":false}),
            );
        }
        let mut frontier = graph
            .vertices()
            .map(|v| v.vertex_id.clone())
            .collect::<BTreeSet<_>>();
        for vertex in graph.vertices() {
            for parent in &vertex.parents {
                frontier.remove(parent);
            }
        }
        let certificates = self
            .certificates
            .get(&key)
            .ok_or("wallet target certificates unavailable")?;
        let quorum = self.members.len() * 2 / 3 + 1;
        let certified_frontier = frontier
            .iter()
            .filter(|id| certificates.contains_key(*id))
            .cloned()
            .collect::<Vec<_>>();
        let parents = if certified_frontier.len() >= quorum {
            certified_frontier
                .into_iter()
                .take(quorum)
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        if frontier
            .len()
            .saturating_sub(parents.len())
            .saturating_add(1)
            > synergy_etdag::dag::MAX_VERTEX_PARENTS
        {
            return Err("wallet authoring is waiting for certified frontier capacity".into());
        }
        let round = if parents.is_empty() {
            0
        } else {
            parents
                .iter()
                .filter_map(|id| graph.get(id).map(|v| v.envelope_ref.certified_dag_round))
                .max()
                .unwrap_or(0)
                .checked_add(1)
                .ok_or("wallet DAG round overflow")?
        };
        self.resources
            .reserve(
                admission.request.target_height,
                &admission.request.envelope.envelope_id,
                charge,
            )
            .map_err(classify_vertex_persistence)?;
        let reference = synergy_etdag::CertifiedEnvelopeRef {
            tx_commitment: request.envelope.envelope_id.clone(),
            sender_id: request.sender_wallet.clone(),
            nonce_slot: request.sender_nonce,
            // Only locally verified certified ancestry selects the DAG round.
            certified_dag_round: round,
            gas_class_units: request.gas_class_units,
            ciphertext_bytes: request.envelope.ciphertext.len() as u64,
            fee_class: request.fee_class,
            protocol_dependencies: Vec::new(),
        };
        let mut vertex = TransactionVertex {
            vertex_id: EtdagDigest::from_domain_bytes("pending", b"wallet-vertex"),
            target_context_root: request.context_root.clone(),
            target_height: request.target_height,
            envelope: request.envelope.clone(),
            envelope_ref: reference,
            parents,
            author_id: self.local_signer.validator_id.clone(),
            author_signature: vec![],
            wallet_admission: Some(admission),
        };
        vertex.vertex_id = synergy_etdag::dag::derive_vertex_id(&vertex)
            .map_err(|e| format!("derive admission vertex: {e:?}"))?;
        vertex.author_signature = self
            .local_signer
            .signer
            .sign(
                &self.local_signer.key_id,
                &SigningContext {
                    domain: "SYNERGY-ETDAG-SIGNATURE-V1".into(),
                    chain_id: self.local_signer.chain_id,
                    epoch: Some(self.local_signer.epoch),
                    height: None,
                },
                vertex.vertex_id.0.as_bytes(),
            )
            .map_err(|e| VertexAdmissionFailure::Safety(format!("sign admission vertex: {e}")))?
            .bytes;
        let newly_admitted = self
            .graphs
            .get(&(vertex.target_context_root.clone(), vertex.target_height))
            .is_none_or(|graph| !graph.contains(&vertex.vertex_id));
        let evidence = serde_json::json!({"vertex_id":vertex.vertex_id,"envelope_id":vertex.envelope.envelope_id,
            "target_height":vertex.target_height,"newly_admitted":newly_admitted,"finalized":false});
        self.admit_verified_wallet_vertex(vertex, true, true)?;
        Ok(evidence)
    }

    fn poll_wallet_admission(&mut self) -> Result<(), String> {
        let Some(handle) = self.wallet_admission.clone() else {
            return Ok(());
        };
        if self.wallet_preparation.is_some() {
            return self.dispatch_prepared_wallet_admission(&handle);
        }
        // Bound costly account authorization work so load cannot starve PoSy.
        for _ in 0..2 {
            let Some(pending) = handle.take()? else {
                break;
            };
            if handle.finish_observed_duplicate(&pending.id)? {
                continue;
            }
            // Closing a target remains terminal even while intake is full;
            // never requeue closed work waiting for unrelated reservations.
            if self
                .ingress
                .protected_cutoff_authority(pending.admission.request.target_height)?
                .is_some()
            {
                handle.complete(
                    &pending.id,
                    Err("fresh local protected admission is closed".into()),
                )?;
                continue;
            }
            if let Err(error) = self.check_wallet_resources(&pending.admission) {
                if matches!(error, EtdagError::ResourcePressure(_)) {
                    handle.return_pending(pending)?;
                    break;
                }
                return Err(format!("wallet resource accounting: {error:?}"));
            }
            let result = self.author_admission(pending.admission);
            match result {
                Ok(evidence) => handle.complete(&pending.id, Ok(evidence))?,
                Err(
                    VertexAdmissionFailure::Rejected(reason)
                    | VertexAdmissionFailure::ResourcePressure(reason),
                ) => handle.complete(&pending.id, Err(reason))?,
                Err(VertexAdmissionFailure::Safety(reason)) => {
                    handle.complete(
                        &pending.id,
                        Err("local admission persistence unavailable".into()),
                    )?;
                    return Err(reason);
                }
            }
        }
        Ok(())
    }

    fn drain_prepared_wallet_admission(
        &mut self,
        handle: &super::protected_admission::AdmissionHandle,
    ) -> Result<(), String> {
        for _ in 0..2 {
            let Some(completion) = self.wallet_preparation.as_ref().unwrap().take()? else {
                break;
            };
            let id = completion.tag.input_digest.clone();
            if self.wallet_jobs.remove(&id).as_ref() != Some(&completion.tag) {
                continue;
            }
            let prepared = completion.result?;
            #[cfg(feature = "qualification-timing")]
            let _completion_timing = super::protected_admission::AdmissionTimingSpan::start(
                &prepared.pending.admission,
                "owner-prepared-completion",
            );
            if prepared.pending.id != id {
                return Err("prepared wallet receipt identity mismatch".into());
            }
            if handle.finish_observed_duplicate(&id)? {
                continue;
            }
            if self
                .ingress
                .protected_cutoff_authority(prepared.pending.admission.request.target_height)?
                .is_some()
            {
                handle.complete(&id, Err("fresh local protected admission is closed".into()))?;
                continue;
            }
            if let Err(error) = self.check_wallet_resources(&prepared.pending.admission) {
                match error {
                    EtdagError::ResourcePressure(_) => {
                        handle.return_pending(prepared.pending)?;
                        continue;
                    }
                    error => return Err(format!("wallet resource accounting: {error:?}")),
                }
            }
            let target = prepared.pending.admission.request.target_height;
            let matching = self.targets.get(&target).is_some_and(|owner| {
                owner
                    .context
                    .root()
                    .is_ok_and(|root| root == prepared.context_root)
                    && owner.context.source_finalized_height == completion.tag.height
            });
            let result = if !matching {
                Err(VertexAdmissionFailure::Rejected(
                    "protected admission context unavailable after preparation".into(),
                ))
            } else if self.ingress.protected_cutoff_authority(target)?.is_some() {
                Err(VertexAdmissionFailure::Rejected(
                    "fresh local protected admission is closed".into(),
                ))
            } else {
                prepared
                    .verified
                    .and_then(|_| self.author_verified_admission(prepared.pending.admission))
            };
            match result {
                Ok(evidence) => handle.complete(&id, Ok(evidence))?,
                Err(
                    VertexAdmissionFailure::Rejected(reason)
                    | VertexAdmissionFailure::ResourcePressure(reason),
                ) => handle.complete(&id, Err(reason))?,
                Err(VertexAdmissionFailure::Safety(reason)) => {
                    handle.complete(&id, Err("local admission persistence unavailable".into()))?;
                    return Err(reason);
                }
            }
        }
        Ok(())
    }

    fn dispatch_prepared_wallet_admission(
        &mut self,
        handle: &super::protected_admission::AdmissionHandle,
    ) -> Result<(), String> {
        for _ in 0..2 {
            let Some(pending) = handle.take()? else {
                break;
            };
            #[cfg(feature = "qualification-timing")]
            let _dispatch_timing = super::protected_admission::AdmissionTimingSpan::start(
                &pending.admission,
                "owner-wallet-dispatch",
            );
            if handle.finish_observed_duplicate(&pending.id)? {
                continue;
            }
            // Closing a target remains terminal even while intake is full;
            // never requeue closed work waiting for unrelated reservations.
            if self
                .ingress
                .protected_cutoff_authority(pending.admission.request.target_height)?
                .is_some()
            {
                handle.complete(
                    &pending.id,
                    Err("fresh local protected admission is closed".into()),
                )?;
                continue;
            }
            if let Err(error) = self.check_wallet_resources(&pending.admission) {
                if matches!(error, EtdagError::ResourcePressure(_)) {
                    handle.return_pending(pending)?;
                    break;
                }
                return Err(format!("wallet resource accounting: {error:?}"));
            }
            let target = pending.admission.request.target_height;
            let Some(context) = self.targets.get(&target).map(|t| t.context.clone()) else {
                handle.complete(
                    &pending.id,
                    Err("protected admission context unavailable".into()),
                )?;
                continue;
            };
            if self.ingress.protected_cutoff_authority(target)?.is_some() {
                handle.complete(
                    &pending.id,
                    Err("fresh local protected admission is closed".into()),
                )?;
                continue;
            }
            let id = pending.id.clone();
            let bytes = pending.owned_byte_charge();
            let slot = Arc::new(std::sync::Mutex::new(Some(pending)));
            let worker_slot = slot.clone();
            let verification_authority = Arc::clone(&self.authority);
            let initial = self.initial_wallet_world.clone();
            let state_root = self.finalized_state_root.clone();
            let timestamp = self.authority.consensus_timestamp_unix(target)?;
            let nonce_limit = self.parameters.max_outstanding_nonce_slots as u64;
            let gas_limit = self.parameters.max_protected_gas;
            let source = context.source_finalized_height;
            let context_root = context
                .root()
                .map_err(|e| format!("wallet preparation context: {e:?}"))?;
            let submitted = self.wallet_preparation.as_ref().unwrap().submit(
                super::preparation::Lane::Admission,
                source,
                0,
                target,
                id.clone(),
                bytes,
                move || {
                    let verification_authority =
                        VerifiedAuthority::worker_context(&verification_authority)?;
                    let pending = worker_slot
                        .lock()
                        .map_err(|_| "wallet preparation input poisoned")?
                        .take()
                        .ok_or("wallet preparation input missing")?;
                    #[cfg(feature = "qualification-timing")]
                    let verification_timing =
                        super::protected_admission::AdmissionTimingSpan::start(
                            &pending.admission,
                            "worker-wallet-verification",
                        );
                    #[cfg(feature = "qualification-timing")]
                    let state_timing = super::protected_admission::AdmissionTimingSpan::start(
                        &pending.admission,
                        "worker-wallet-state-read",
                    );
                    // Worker and owner reads reserve from the same process-wide World pool.
                    let world = if source == 0 {
                        Ok(initial)
                    } else {
                        synergy_state::FinalizedStateStore::load_budgeted(
                            &state_root,
                            Arc::clone(initial.budget()),
                        )
                        .map_err(|e| {
                            VertexAdmissionFailure::Safety(format!(
                                "load admission source state: {e:?}"
                            ))
                        })
                        .and_then(|store| {
                            store
                                .world_state_at_budgeted(source, initial.budget())
                                .map_err(classify_world_read)?
                                .map(Arc::new)
                                .ok_or_else(|| {
                                    VertexAdmissionFailure::Safety(
                                        "verified target lacks finalized source state".into(),
                                    )
                                })
                        })
                    };
                    #[cfg(feature = "qualification-timing")]
                    drop(state_timing);
                    let verified = world.and_then(|world| {
                        super::protected_admission::verify_wallet_admission_with_authority(
                            &pending.admission,
                            &world,
                            context.chain_id,
                            &context.network_id,
                            timestamp,
                            Some(verification_authority.as_ref()),
                        )
                        .map_err(VertexAdmissionFailure::Rejected)?;
                        let request = &pending.admission.request;
                        let nonce = world
                            .accounts
                            .get(&request.sender_wallet)
                            .ok_or_else(|| {
                                VertexAdmissionFailure::Rejected(
                                    "admission sender has no governed account".into(),
                                )
                            })?
                            .nonce;
                        if request.context_root != context_root
                            || request.sender_nonce < nonce
                            || request.sender_nonce.saturating_sub(nonce) >= nonce_limit
                            || request.gas_class_units > gas_limit
                        {
                            return Err(VertexAdmissionFailure::Rejected(
                                "admission context, nonce window or gas exceeds governed bounds"
                                    .into(),
                            ));
                        }
                        Ok(())
                    });
                    #[cfg(feature = "qualification-timing")]
                    drop(verification_timing);
                    Ok(PreparedWalletAdmission {
                        pending,
                        context_root,
                        verified,
                    })
                },
            );
            match submitted {
                Ok(tag) => {
                    self.wallet_jobs.insert(id, tag);
                }
                Err(reason) => {
                    let pending = slot
                        .lock()
                        .map_err(|_| "wallet preparation input poisoned")?
                        .take()
                        .ok_or("wallet preparation rejected input missing")?;
                    handle.return_pending(pending)?;
                    if reason == "preparation backpressure" {
                        break;
                    }
                    return Err(reason);
                }
            }
        }
        Ok(())
    }

    fn drain_context_preparation(&mut self) -> Result<(), String> {
        let Some(owner) = &self.context_preparation else {
            return Ok(());
        };
        for _ in 0..16 {
            let Some(completion) = owner.take()? else {
                break;
            };
            let height = completion.tag.target;
            if self.context_jobs.remove(&height).as_ref() != Some(&completion.tag) {
                continue;
            }
            let Some(target) = self.targets.get(&height) else {
                continue;
            };
            let root = target
                .context
                .root()
                .map_err(|e| format!("prepared context identity: {e:?}"))?;
            if root.0 != completion.tag.input_digest
                || self.ingress.protected_cutoff_authority(height)?.is_some()
            {
                continue;
            }
            let prepared = completion.result?;
            if prepared.context_root != root {
                return Err("prepared source proof context mismatch".into());
            }
            let response = serde_json::from_slice(&prepared.response)
                .map_err(|e| format!("decode prepared immutable context: {e}"))?;
            self.prepared_contexts.insert(
                height,
                PublishedWalletContext {
                    context_root: prepared.context_root,
                    response,
                },
            );
        }
        self.prepared_contexts.retain(|height, _| {
            self.targets.get(height).is_some_and(|target| {
                target
                    .pipeline
                    .as_ref()
                    .is_some_and(|pipeline| !pipeline.admission_closed())
            })
        });
        // These are public observation caches, never safety journals. Retain
        // only the newest two responses rather than every finalized height.
        while self.prepared_contexts.len() > 2 {
            self.prepared_contexts.pop_first();
        }
        Ok(())
    }

    fn dispatch_context_preparation(&mut self) -> Result<bool, String> {
        let Some(owner) = &self.context_preparation else {
            return Ok(false);
        };
        // Select only cache-retainable contexts before filtering completed jobs.
        // Older open targets must not regenerate responses immediately evicted
        // by the two-response cache and monopolize the live admission lane.
        let mut newest = Vec::new();
        for (&height, target) in self.targets.iter().rev() {
            if target
                .pipeline
                .as_ref()
                .is_some_and(|p| !p.admission_closed())
                && self.ingress.protected_cutoff_authority(height)?.is_none()
            {
                newest.push(height);
                if newest.len() == 2 {
                    break;
                }
            }
        }
        let candidate = cacheable_context_target(&newest, |height| {
            self.context_jobs.contains_key(&height) || self.prepared_contexts.contains_key(&height)
        });
        let candidate = candidate.and_then(|height| self.targets.get_key_value(&height));
        let Some((&height, target)) = candidate else {
            return Ok(false);
        };
        if self.ingress.protected_cutoff_authority(height)?.is_some() {
            return Ok(false);
        }
        let registry = self.authority.protected_ingress_registry()?;
        let context = synergy_etdag::WalletAdmissionContext {
            context: target.context.clone(),
            parameters: self.parameters.clone(),
            ingress_keys: self
                .members
                .iter()
                .map(|member| {
                    synergy_etdag::crypto::active_key_for_validator(registry, member, height)
                        .cloned()
                        .map_err(|e| format!("prepare admission ingress key: {e:?}"))
                })
                .collect::<Result<Vec<_>, _>>()?,
        };
        let context_root = context
            .context
            .root()
            .map_err(|e| format!("prepare context root: {e:?}"))?;
        let authority = self.authority.clone();
        let ingress = self.ingress.clone();
        let input_digest = context_root.0.clone();
        match owner.submit(
            super::preparation::Lane::Admission,
            height,
            0,
            height,
            input_digest,
            8 * 1024 * 1024,
            move || {
                let authority = VerifiedAuthority::worker_context(&authority)?;
                let response = super::source_finality_evidence::context_response(
                    &authority, &ingress, &context,
                )?;
                let response = serde_json::to_vec(&response).map_err(|e| e.to_string())?;
                if response.capacity() > 1024 * 1024 {
                    return Err(
                        "prepared source proof response exceeds bounded context size".into(),
                    );
                }
                Ok(PreparedWalletContext {
                    context_root,
                    response,
                })
            },
        ) {
            Ok(tag) => {
                self.context_jobs.insert(height, tag);
            }
            Err(reason) if reason == "preparation backpressure" => {}
            Err(reason) => return Err(reason),
        }
        Ok(true)
    }

    fn poll_admission_preparation(&mut self) -> Result<(), String> {
        // Completion consumption releases retained mailbox reservations. Neither
        // producer may replenish the full lane before both owners drain results.
        self.drain_context_preparation()?;
        if let Some(handle) = self.wallet_admission.clone() {
            if self.wallet_preparation.is_some() {
                self.drain_prepared_wallet_admission(&handle)?;
            }
        }
        // A busy poll must not rotate priority: asynchronous completions can
        // consistently arrive on one parity of polls. Hold the next producer's
        // turn until actual dispatch, retaining full outstanding byte charges.
        let context_jobs_before = self.context_jobs.len();
        let wallet_jobs_before = self.wallet_jobs.len();
        if self.context_dispatch_turn {
            let context_waiting = self.dispatch_context_preparation()?;
            // Once refresh needs its full bounded reservation, let existing
            // wallet jobs drain instead of refilling them forever under load.
            if !context_waiting {
                self.poll_wallet_admission()?;
            }
        } else {
            self.poll_wallet_admission()?;
            self.dispatch_context_preparation()?;
        }
        self.context_dispatch_turn = next_admission_dispatch_turn(
            self.context_dispatch_turn,
            self.context_jobs.len() > context_jobs_before,
            self.wallet_jobs.len() > wallet_jobs_before,
        );
        Ok(())
    }

    fn publish_wallet_context(&self) -> Result<(), String> {
        let Some(handle) = &self.wallet_admission else {
            return Ok(());
        };
        if !self.started || self.ingress_paused {
            return handle.publish_context(None);
        }
        for (&height, target) in self.targets.iter().rev() {
            if target
                .pipeline
                .as_ref()
                .is_none_or(|p| p.admission_closed())
                || self.ingress.protected_cutoff_authority(height)?.is_some()
            {
                continue;
            }
            let registry = self.authority.protected_ingress_registry()?;
            let ingress_keys = self
                .members
                .iter()
                .map(|member| {
                    synergy_etdag::crypto::active_key_for_validator(registry, member, height)
                        .cloned()
                        .map_err(|e| format!("resolve admission ingress key: {e:?}"))
                })
                .collect::<Result<Vec<_>, _>>()?;
            let context = synergy_etdag::WalletAdmissionContext {
                context: target.context.clone(),
                parameters: self.parameters.clone(),
                ingress_keys,
            };
            let root = context
                .context
                .root()
                .map_err(|e| format!("publish context identity: {e:?}"))?;
            handle.publish_context_v2(
                self.prepared_contexts
                    .get(&height)
                    .filter(|prepared| prepared.context_root == root)
                    .map(|prepared| prepared.response.clone()),
            )?;
            return handle.publish_context(Some(
                serde_json::to_value(context)
                    .map_err(|e| format!("encode governed admission context: {e}"))?,
            ));
        }
        handle.publish_context(None)
    }

    fn encode_local_vertex_frame(
        &self,
        vertex: &TransactionVertex,
    ) -> Result<Vec<u8>, VertexAdmissionFailure> {
        let message = self
            .local_signer
            .sign_message(EtdagNetworkMessage::Vertex(vertex.clone()))
            .map_err(VertexAdmissionFailure::Safety)?;
        let bytes = serde_json::to_vec(&message).map_err(|e| {
            VertexAdmissionFailure::Safety(format!("encode durable local vertex: {e}"))
        })?;
        if bytes.len() > synergy_network::protocol::DEFAULT_MAX_FRAME_BYTES {
            return Err("signed local vertex exceeds authenticated frame bound".into());
        }
        Ok(bytes)
    }

    fn retain_local_vertex_frame(&mut self, vertex: TransactionVertex) -> Result<(), String> {
        let slot = (vertex.target_height, vertex.vertex_id.clone());
        if !self.vertex_frames.contains_key(&slot) {
            let bytes = self
                .encode_local_vertex_frame(&vertex)
                .map_err(|e| e.to_string())?;
            self.vertex_frames.insert(slot, bytes);
        }
        Ok(())
    }

    fn admit_vertex(
        &mut self,
        vertex: TransactionVertex,
        local: bool,
    ) -> Result<(), VertexAdmissionFailure> {
        self.admit_verified_wallet_vertex(vertex, local, false)
    }

    fn admit_verified_wallet_vertex(
        &mut self,
        vertex: TransactionVertex,
        local: bool,
        wallet_verified: bool,
    ) -> Result<(), VertexAdmissionFailure> {
        let height = vertex.target_height;
        let envelope = vertex.envelope.envelope_id.clone();
        let previous = self
            .resources
            .vertices
            .get(&(height, envelope.clone()))
            .copied();
        let result = self.admit_verified_wallet_vertex_inner(vertex, local, wallet_verified);
        // Safety/storage errors can have an uncertain append outcome; retain
        // their reservation even when in-memory insertion has not occurred.
        if matches!(
            &result,
            Err(VertexAdmissionFailure::Rejected(_) | VertexAdmissionFailure::ResourcePressure(_))
        ) {
            self.rollback_undurable_reservation(height, envelope, previous);
        }
        result
    }

    fn admit_verified_wallet_vertex_inner(
        &mut self,
        vertex: TransactionVertex,
        local: bool,
        wallet_verified: bool,
    ) -> Result<(), VertexAdmissionFailure> {
        if local && vertex.author_id != self.local_signer.validator_id {
            return Err("local protected vertex author differs from local validator".into());
        }
        let target = self
            .targets
            .get(&vertex.target_height)
            .ok_or("ETDAG vertex target is not opened by verified finality")?;
        if target
            .context
            .root()
            .map_err(|e| VertexAdmissionFailure::Safety(format!("derive target root: {e:?}")))?
            != vertex.target_context_root
        {
            return Err("ETDAG vertex is bound to the wrong target context".into());
        }
        if !local
            && self
                .graphs
                .get(&(vertex.target_context_root.clone(), vertex.target_height))
                .and_then(|graph| graph.get(&vertex.vertex_id))
                == Some(&vertex)
        {
            return Ok(());
        }
        let (author_key, _) = self
            .cutoff_members
            .get(&vertex.author_id)
            .ok_or("ETDAG vertex author is not assigned")?;
        SignatureVerifier::verify(
            self.authority.as_ref(),
            &vertex.author_id,
            author_key,
            vertex.vertex_id.0.as_bytes(),
            &vertex.author_signature,
        )
        .map_err(|e| format!("verify vertex author signature: {e:?}"))?;
        if let Some(admission) = &vertex.wallet_admission {
            if !wallet_verified {
                self.verify_admission(admission)?;
            }
        } else if self.wallet_admission.is_some() {
            return Err("fresh protected vertex lacks wallet authorization".into());
        }
        let key = (vertex.target_context_root.clone(), vertex.target_height);
        if self.graphs.get(&key).is_some_and(|graph| {
            graph.vertices().any(|existing| {
                existing.envelope_ref.sender_id == vertex.envelope_ref.sender_id
                    && existing.envelope_ref.nonce_slot == vertex.envelope_ref.nonce_slot
                    && existing.envelope.envelope_id != vertex.envelope.envelope_id
            })
        }) {
            return Err(
                "protected target already has a different envelope for sender nonce".into(),
            );
        }
        self.validate_outer_custody(&vertex)
            .map_err(VertexAdmissionFailure::Rejected)?;
        let charge = self.resources.reservation(
            ProtectedPipeline::vertex_resource_bytes(&vertex)
                .map_err(classify_vertex_persistence)?,
            encoded_resource_bytes(&vertex).map_err(classify_vertex_persistence)?,
            encoded_resource_bytes(&vertex.envelope_ref).map_err(classify_vertex_persistence)?,
            self.resources.share_wire(&vertex.envelope),
            vertex.envelope.ciphertext.len(),
        );
        self.resources
            .reserve(vertex.target_height, &vertex.envelope.envelope_id, charge)
            .map_err(classify_vertex_persistence)?;
        // Validate the complete signed network size before durable admission.
        let local_frame = if local
            && !self
                .vertex_frames
                .contains_key(&(vertex.target_height, vertex.vertex_id.clone()))
        {
            Some(self.encode_local_vertex_frame(&vertex)?)
        } else {
            None
        };
        let cutoff = if local {
            self.ingress
                .protected_cutoff_authority(vertex.target_height)
                .map_err(VertexAdmissionFailure::Safety)?
        } else {
            None
        };
        let owner = self
            .targets
            .get_mut(&vertex.target_height)
            .and_then(|target| target.pipeline.as_mut())
            .ok_or_else(|| {
                VertexAdmissionFailure::Safety("protected availability owner absent".into())
            })?;
        if let Some(cutoff) = cutoff {
            if owner
                .original_cutoff_context_root()
                .is_some_and(|original| original != &cutoff)
            {
                return Err(VertexAdmissionFailure::Safety(
                    "original cutoff authority changed".into(),
                ));
            }
            if owner.original_cutoff_context_root().is_none() {
                owner.bind_cutoff(cutoff).map_err(|e| match e {
                    EtdagError::ResourcePressure(_) => classify_vertex_persistence(e),
                    _ => VertexAdmissionFailure::Safety(format!(
                        "close local admission at verified VC: {e:?}"
                    )),
                })?;
            }
        }
        if local
            && owner
                .graph()
                .get(&vertex.vertex_id)
                .is_some_and(|existing| existing != &vertex)
        {
            return Err("local vertex differs from its exact durable predecessor".into());
        }
        if local && owner.admission_closed() {
            return Err("fresh local protected admission is closed".into());
        }
        owner
            .persist_vertex(
                vertex.clone(),
                &self.cutoff_members,
                self.authority.as_ref(),
            )
            .map_err(classify_vertex_persistence)?;
        // This snapshot linearizes native durable admission against immediate VC publication.
        // No shared lock spans storage, cryptography or network work. Closed staging is retained,
        // but cannot become fresh acceptance or freshly broadcast evidence.
        if let Some(cutoff) = self
            .ingress
            .protected_cutoff_authority(vertex.target_height)
            .map_err(VertexAdmissionFailure::Safety)?
        {
            if owner
                .original_cutoff_context_root()
                .is_some_and(|original| original != &cutoff)
            {
                return Err(VertexAdmissionFailure::Safety(
                    "original cutoff authority changed".into(),
                ));
            }
            if owner.original_cutoff_context_root().is_none() {
                owner.bind_cutoff(cutoff).map_err(|e| match e {
                    EtdagError::ResourcePressure(_) => classify_vertex_persistence(e),
                    _ => VertexAdmissionFailure::Safety(format!("close post-ack admission: {e:?}")),
                })?;
            }
            self.graphs.insert(key.clone(), owner.graph().clone());
            if local {
                return Err("fresh local protected admission is closed".into());
            }
        } else if !local {
            if let Some(handle) = &self.wallet_admission {
                handle
                    .recover_verified_vertex(&vertex)
                    .map_err(VertexAdmissionFailure::Safety)?;
            }
        }
        #[cfg(feature = "qualification-timing")]
        observe_admission(
            super::qualification_timing::Phase::DurableAdmission,
            vertex.target_height,
            &vertex.envelope.envelope_id.0,
        );
        self.graphs.insert(key, owner.graph().clone());
        let count = self.graphs.values().map(EtdagGraph::len).sum();
        self.metrics.set_dag_vertices(count).map_err(|error| {
            VertexAdmissionFailure::Safety(format!("update ETDAG metrics: {error:?}"))
        })?;
        if let Some(bytes) = local_frame {
            self.vertex_frames
                .insert((vertex.target_height, vertex.vertex_id), bytes);
        }
        Ok(())
    }

    fn open_target(
        &mut self,
        source: Option<&synergy_posy::FinalizedBlockRecord>,
        height: u64,
    ) -> Result<(), String> {
        if self.targets.contains_key(&height) {
            return Ok(());
        }
        let (context, _) = self.authority.protected_target(source, height)?;
        let root = context
            .root()
            .map_err(|e| format!("derive governed target root: {e:?}"))?;
        let cutoff = self.ingress.protected_cutoff_authority(height)?;
        if let Some(recovery) = ProtectedPipeline::begin_recovery(
            &self.pipeline_root,
            context.clone(),
            self.parameters.clone(),
            cutoff,
            self.local_signer.validator_id.clone(),
        )
        .map_err(|e| format!("stage protected recovery: {e:?}"))?
        {
            self.recovering_targets.insert(height, recovery);
            self.targets.insert(
                height,
                ProtectedTarget {
                    context,
                    pipeline: None,
                    markers: CutMarkerCache::default(),
                    handed_off: false,
                },
            );
            return Ok(());
        }
        let pipeline = if let Some(cutoff) = self.ingress.protected_cutoff_authority(height)? {
            ProtectedPipeline::open(
                &self.pipeline_root,
                context.clone(),
                self.parameters.clone(),
                cutoff,
                self.local_signer.validator_id.clone(),
                &self.cutoff_members,
                &self.cut_recovery_verifier,
            )
        } else {
            ProtectedPipeline::open_collecting(
                &self.pipeline_root,
                context.clone(),
                self.parameters.clone(),
                self.local_signer.validator_id.clone(),
                &self.cutoff_members,
                &self.cut_recovery_verifier,
            )
        }
        .map_err(|e| format!("recover protected admission owner: {e:?}"))?;
        self.install_verified_target(context, root, pipeline)
    }

    fn install_verified_target(
        &mut self,
        context: TargetAdmissionContextV3,
        root: EtdagDigest,
        mut pipeline: ProtectedPipeline,
    ) -> Result<(), String> {
        pipeline.set_transition_resource_budget(ETDAG_TRANSITION_SCRATCH_BYTES);
        let height = context.target_height;
        self.resources
            .reserve_history(height, pipeline.retained_history_resource_bytes())
            .map_err(|e| format!("install bounded protected history: {e:?}"))?;
        pipeline.set_history_resource_budget(self.resources.history_limit(height));
        let recovered_wallet_vertices = pipeline
            .graph()
            .vertices()
            .filter(|vertex| vertex.wallet_admission.is_some())
            .cloned()
            .collect::<Vec<_>>();
        let local_vertices = pipeline
            .graph()
            .vertices()
            .filter(|v| v.author_id == self.local_signer.validator_id)
            .cloned()
            .collect::<Vec<_>>();
        for vertex in local_vertices {
            self.retain_local_vertex_frame(vertex)?;
        }
        #[cfg(feature = "qualification-timing")]
        if !pipeline.admission_closed() {
            use super::qualification_timing::{self as timing, Classification, Kind, Phase, Role};
            timing::emit_once(
                Kind::Window,
                Phase::TargetOpen,
                height,
                0,
                0,
                Role::Participant,
                Classification::Observed,
                None,
                None,
            );
        }
        self.graphs
            .insert((root.clone(), height), pipeline.graph().clone());
        self.certificates
            .insert((root, height), pipeline.availability().clone());
        self.targets.insert(
            height,
            ProtectedTarget {
                context,
                pipeline: Some(pipeline),
                markers: CutMarkerCache::default(),
                handed_off: false,
            },
        );
        if let Some(handle) = &self.wallet_admission {
            for vertex in recovered_wallet_vertices {
                self.verify_admission(vertex.wallet_admission.as_ref().unwrap())
                    .map_err(|e| format!("durable wallet receipt authority: {e}"))?;
                let owner = self
                    .targets
                    .get(&height)
                    .and_then(|t| t.pipeline.as_ref())
                    .ok_or("recovered pipeline absent")?;
                let proven = !owner.admission_closed()
                    || owner.availability().contains_key(&vertex.vertex_id)
                    || handle.was_durably_admitted(vertex.wallet_admission.as_ref().unwrap())?;
                if proven {
                    handle.recover_verified_vertex(&vertex)?;
                } else {
                    self.vertex_frames
                        .remove(&(height, vertex.vertex_id.clone()));
                }
            }
        }
        Ok(())
    }

    fn poll_target_recovery(&mut self) -> Result<(), String> {
        if self.recovery_capacity_blocked {
            return Ok(());
        }
        let Some(height) = self.recovering_targets.keys().next().copied() else {
            return Ok(());
        };
        let cancelled = self
            .owner_cancellation
            .as_ref()
            .is_some_and(CancellationToken::is_cancelled);
        let history_limit = self.resources.history_limit(height);
        let verified = self
            .recovering_targets
            .get_mut(&height)
            .ok_or("protected recovery cursor missing")?
            .poll_with_resource_budgets(
                &self.cutoff_members,
                &self.cut_recovery_verifier,
                cancelled,
                ETDAG_TRANSITION_SCRATCH_BYTES,
                history_limit,
            );
        let verified = match verified {
            Ok(verified) => verified,
            Err(EtdagError::ResourcePressure(reason)) => {
                self.resources.pressure = Some(format!("protected recovery requires additional local capacity: {reason}; durable originals retained"));
                self.recovery_capacity_blocked = true;
                return Ok(());
            }
            Err(error) => return Err(format!("verify bounded protected recovery: {error:?}")),
        };
        let staged_history = verified.as_ref().map_or_else(
            || {
                self.recovering_targets.get(&height).map_or(
                    0,
                    ProtectedPipelineRecovery::retained_history_resource_bytes,
                )
            },
            ProtectedPipeline::retained_history_resource_bytes,
        );
        if let Err(error) = self.resources.reserve_history(height, staged_history) {
            self.resources.pressure = Some(format!("protected recovery requires additional local capacity: {error:?}; durable originals retained"));
            self.recovery_capacity_blocked = true;
            return Ok(());
        }
        if let Some(pipeline) = verified {
            if self
                .owner_cancellation
                .as_ref()
                .is_some_and(CancellationToken::is_cancelled)
            {
                return Err("protected recovery cancelled before owner installation".into());
            }
            let context = self
                .targets
                .get(&height)
                .ok_or("protected recovery context missing")?
                .context
                .clone();
            let root = context
                .root()
                .map_err(|e| format!("recovered target root: {e:?}"))?;
            for vertex in pipeline.graph().vertices() {
                let charge = self.resources.reservation(
                    ProtectedPipeline::vertex_resource_bytes(vertex)
                        .map_err(|e| format!("recovered vertex resource accounting: {e:?}"))?,
                    encoded_resource_bytes(vertex)
                        .map_err(|e| format!("recovered vertex scratch accounting: {e:?}"))?,
                    encoded_resource_bytes(&vertex.envelope_ref)
                        .map_err(|e| format!("recovered reference scratch accounting: {e:?}"))?,
                    self.resources.share_wire(&vertex.envelope),
                    vertex.envelope.ciphertext.len(),
                );
                if let Err(error) =
                    self.resources
                        .reserve(height, &vertex.envelope.envelope_id, charge)
                {
                    self.resources.pressure = Some(format!("protected recovery requires additional local capacity: {error:?}; durable originals retained; operator capacity qualification required"));
                    self.recovery_capacity_blocked = true;
                    // Keep the immutable originals on disk. No mirror/frame is
                    // installed and no additional owner is decoded in this run.
                    return Ok(());
                }
            }
            self.install_verified_target(context, root, pipeline)?;
            self.recovering_targets.remove(&height);
        }
        Ok(())
    }

    fn open_authorized_targets(&mut self) -> Result<(), String> {
        let latest = self.ingress.latest_finality()?;
        let finalized = latest.as_ref().map(|r| r.height).unwrap_or(0);
        let offset = self.parameters.target_height_offset;
        self.parameters
            .validate()
            .map_err(|e| format!("governed protected parameters: {e:?}"))?;
        for height in 3..=offset {
            if height > finalized {
                self.open_target(None, height)?;
            }
        }
        // Only the governed still-live successors are reconstructed. Their source
        // records come from independently verified durable PoSy finality.
        for source_height in finalized.saturating_sub(offset - 1).max(1)..=finalized {
            let source = if latest.as_ref().is_some_and(|r| r.height == source_height) {
                latest.clone()
            } else {
                self.ingress.finalized_record(source_height)?
            };
            let source = source.ok_or("verified protected target source is unavailable")?;
            let target = self
                .parameters
                .protected_target_height(source_height)
                .map_err(|e| format!("protected target height: {e:?}"))?;
            if target > finalized {
                self.open_target(Some(&source), target)?;
            }
        }
        for (_, target) in self.targets.range_mut(..=finalized) {
            if let Some(pipeline) = target.pipeline.as_mut() {
                if pipeline.prepared().is_some() {
                    let root = pipeline
                        .batch()
                        .ok_or("consumed protected batch missing")?
                        .protected_batch_root
                        .clone();
                    pipeline
                        .mark_consumed(&root)
                        .map_err(|e| format!("persist finalized protected consumption: {e:?}"))?;
                }
            }
        }
        let prior_recovery = self.recovering_targets.keys().next().copied();
        let released = self.resources.retire(finalized);
        self.targets.retain(|height, _| *height > finalized);
        self.recovering_targets
            .retain(|height, _| *height > finalized);
        if released || prior_recovery != self.recovering_targets.keys().next().copied() {
            // A capacity refusal is retryable when finalization retires another
            // owner or the blocked target itself. Do not repeatedly decode an
            // unchanged over-capacity journal, or latch a now-free pool forever.
            self.recovery_capacity_blocked = false;
            self.resources.pressure = None;
        }
        self.graphs.retain(|(_, height), _| *height > finalized);
        self.certificates
            .retain(|(_, height), _| *height > finalized);
        self.reveal_frames
            .retain(|(height, _), _| *height > finalized);
        self.reveal_shares
            .retain(|(height, _), _| *height > finalized);
        self.marker_frames
            .retain(|(height, _), _| *height > finalized);
        self.vertex_frames
            .retain(|(height, _), _| *height > finalized);
        self.availability_frames
            .retain(|(height, _), _| *height > finalized);
        self.certificate_frames
            .retain(|(height, _), _| *height > finalized);
        let roots = self
            .graphs
            .keys()
            .map(|(root, _)| root.clone())
            .collect::<BTreeSet<_>>();
        self.available.retain(|(root, _)| roots.contains(root));
        Ok(())
    }

    fn retain_availability(&mut self, certificate: AvailabilityCertificate) -> Result<(), String> {
        let target = self
            .targets
            .iter()
            .find(|(_, target)| {
                target.context.root().ok().as_ref() == Some(&certificate.context_root)
            })
            .map(|(height, _)| *height)
            .ok_or("availability certificate has no governed target")?;
        let owner = self
            .targets
            .get_mut(&target)
            .and_then(|target| target.pipeline.as_mut())
            .ok_or("governed availability owner absent")?;
        owner
            .persist_availability(
                certificate.clone(),
                &self.cutoff_members,
                self.authority.as_ref(),
            )
            .map_err(|e| format!("persist verified availability certificate: {e:?}"))?;
        #[cfg(feature = "qualification-timing")]
        if let Some(vertex) = owner.graph().get(&certificate.vertex_id) {
            observe_admission(
                super::qualification_timing::Phase::DurableAvailability,
                target,
                &vertex.envelope.envelope_id.0,
            );
        }
        let key = (certificate.context_root.clone(), target);
        let certificates = self.certificates.entry(key).or_default();
        if certificates.len() >= 4096 && !certificates.contains_key(&certificate.vertex_id) {
            return Err("ETDAG governed availability capacity reached".into());
        }
        certificates
            .entry(certificate.vertex_id.clone())
            .or_insert(certificate);
        Ok(())
    }

    fn validate_outer_custody(
        &self,
        vertex: &synergy_etdag::TransactionVertex,
    ) -> Result<(), String> {
        vertex
            .validate()
            .map_err(|e| format!("validate custody envelope: {e:?}"))?;
        if !self
            .parameters
            .ciphertext_size_classes
            .contains(&vertex.envelope.ciphertext.len())
        {
            return Err("protected ciphertext is outside governed size classes".into());
        }
        let target = self
            .targets
            .get(&vertex.target_height)
            .ok_or("protected envelope has no governed admission target")?;
        let aad = &vertex.envelope.aad;
        if aad.chain_id != target.context.chain_id
            || aad.network_id != target.context.network_id
            || aad.protocol_version != target.context.protocol_version
            || aad.epoch != target.context.epoch
            || aad.assigned_cluster_id != target.context.assigned_cluster_id
            || aad.sender_id != vertex.envelope_ref.sender_id
            || aad.nonce_slot != vertex.envelope_ref.nonce_slot
        {
            return Err(
                "protected envelope AAD differs from governed target or outer reference".into(),
            );
        }
        if vertex.wallet_admission.is_some() {
            if vertex.envelope_ref.certified_dag_round == 0 {
                if !vertex.parents.is_empty() {
                    return Err("first-round wallet vertex has parents".into());
                }
            } else {
                let quorum = self.members.len() * 2 / 3 + 1;
                let graph = self
                    .graphs
                    .get(&(vertex.target_context_root.clone(), vertex.target_height))
                    .ok_or("wallet vertex graph is unavailable")?;
                let certificates = self
                    .certificates
                    .get(&(vertex.target_context_root.clone(), vertex.target_height))
                    .ok_or("wallet vertex certificate map is unavailable")?;
                if vertex.parents.len() < quorum
                    || vertex.parents.iter().any(|id| {
                        !certificates.contains_key(id)
                            || graph.get(id).is_none_or(|parent| {
                                parent.envelope_ref.certified_dag_round
                                    >= vertex.envelope_ref.certified_dag_round
                            })
                    })
                {
                    return Err(
                        "wallet vertex lacks governed certified earlier-round parents".into(),
                    );
                }
            }
        }
        let registry = self.authority.protected_ingress_registry()?;
        let mut recipients = BTreeSet::new();
        for capsule in &vertex.envelope.share_capsules {
            if !self.members.contains(&capsule.validator_id)
                || !recipients.insert(&capsule.validator_id)
            {
                return Err("protected share capsules have wrong or duplicate recipients".into());
            }
            let key = synergy_etdag::crypto::active_key_for_validator(
                registry,
                &capsule.validator_id,
                vertex.target_height,
            )
            .map_err(|e| format!("resolve governed ingress KEM key: {e:?}"))?;
            if key.key_id != capsule.ingress_kem_key_id
                || key.public_key.algorithm != "ML-KEM-1024"
                || capsule.kem_ciphertext.len()
                    != synergy_etdag::crypto::ML_KEM_1024_CIPHERTEXT_BYTES
                || capsule.encrypted_share.len() > 64 * 1024
            {
                return Err("protected capsule differs from bounded governed KEM binding".into());
            }
        }
        if recipients.len() != self.members.len() {
            return Err("protected capsule recipient set is incomplete".into());
        }
        Ok(())
    }

    fn reconcile_availability(&mut self) -> Result<(), String> {
        for (height, target) in &mut self.targets {
            let owner = target
                .pipeline
                .as_mut()
                .ok_or("protected availability owner absent")?;
            // Consensus cutoff closes signing immediately, even if marker
            // derivation awaits missing availability evidence later in this poll.
            if let Some(cutoff) = self.ingress.protected_cutoff_authority(*height)? {
                if owner
                    .original_cutoff_context_root()
                    .is_some_and(|original| original != &cutoff)
                {
                    return Err("original cutoff authority changed".into());
                }
                if owner.original_cutoff_context_root().is_none() {
                    owner.bind_cutoff(cutoff).map_err(|e| {
                        format!("close VAC signing at accepted validation event: {e:?}")
                    })?;
                }
            }
            let ids = owner
                .graph()
                .vertices()
                .map(|vertex| vertex.vertex_id.clone())
                .collect::<Vec<_>>();
            for id in ids {
                if !owner.admission_closed()
                    && self.ingress.protected_cutoff_authority(*height)?.is_none()
                    && !owner.local_votes().contains_key(&id)
                {
                    let vote = self.local_signer.sign_availability_vote(
                        target
                            .context
                            .root()
                            .map_err(|e| format!("derive availability context: {e:?}"))?,
                        id.clone(),
                    )?;
                    owner
                        .persist_local_vote(vote, &self.cutoff_members, self.authority.as_ref())
                        .map_err(|e| {
                            format!("persist availability vote before broadcast: {e:?}")
                        })?;
                }
                // A signed vote is safety history even when its disk ack loses to VC.
                // Retain it, close the owner, and suppress newly created network frames.
                if let Some(cutoff) = self.ingress.protected_cutoff_authority(*height)? {
                    if owner
                        .original_cutoff_context_root()
                        .is_some_and(|original| original != &cutoff)
                    {
                        return Err("original cutoff authority changed".into());
                    }
                    if owner.original_cutoff_context_root().is_none() {
                        owner
                            .bind_cutoff(cutoff)
                            .map_err(|e| format!("close post-ack availability signing: {e:?}"))?;
                    }
                }
                if !owner.admission_closed()
                    && self.ingress.protected_cutoff_authority(*height)?.is_none()
                {
                    if let Some(vote) = owner.local_votes().get(&id) {
                        if !self
                            .availability_frames
                            .contains_key(&(*height, id.clone()))
                        {
                            let message = self.local_signer.sign_message(
                                EtdagNetworkMessage::AvailabilityVote(vote.clone()),
                            )?;
                            let bytes = serde_json::to_vec(&message)
                                .map_err(|e| format!("encode durable availability vote: {e}"))?;
                            if self.ingress.protected_cutoff_authority(*height)?.is_none() {
                                self.availability_frames
                                    .insert((*height, id.clone()), bytes);
                            }
                        }
                    }
                }
                if !owner.availability().contains_key(&id) {
                    match owner.assembled_availability(
                        &id,
                        &self.cutoff_members,
                        self.authority.as_ref(),
                    ) {
                        Ok(certificate) => {
                            owner
                                .persist_availability(
                                    certificate,
                                    &self.cutoff_members,
                                    self.authority.as_ref(),
                                )
                                .map_err(|e| {
                                    format!("persist assembled availability quorum: {e:?}")
                                })?;
                        }
                        Err(EtdagError::InsufficientAvailability { .. }) => {}
                        Err(error) => {
                            return Err(format!("assemble availability quorum: {error:?}"))
                        }
                    }
                }
                #[cfg(feature = "qualification-timing")]
                if owner.availability().contains_key(&id) {
                    if let Some(vertex) = owner.graph().get(&id) {
                        observe_admission(
                            super::qualification_timing::Phase::DurableAvailability,
                            *height,
                            &vertex.envelope.envelope_id.0,
                        );
                    }
                }
                if let Some(cutoff) = self.ingress.protected_cutoff_authority(*height)? {
                    if owner
                        .original_cutoff_context_root()
                        .is_some_and(|original| original != &cutoff)
                    {
                        return Err("original cutoff authority changed".into());
                    }
                    if owner.original_cutoff_context_root().is_none() {
                        owner.bind_cutoff(cutoff).map_err(|e| {
                            format!("close post-ack certificate publication: {e:?}")
                        })?;
                    }
                }
                if let Some(certificate) = owner.availability().get(&id) {
                    if let (Some(handle), Some(vertex)) =
                        (&self.wallet_admission, owner.graph().get(&id))
                    {
                        // Native verified quorum evidence independently proves availability, even
                        // when the local vertex remained staging when its acknowledgement completed.
                        handle.recover_verified_vertex(vertex)?;
                        handle.record_verified_stage(&vertex.envelope.envelope_id, "certified", serde_json::json!({
                            "target_height":height,"vertex_id":id,"context_root":certificate.context_root,
                            "verified_vote_count":certificate.votes.len(),"finalized":false}))?;
                    }
                    if !owner.admission_closed()
                        && self.ingress.protected_cutoff_authority(*height)?.is_none()
                        && !self.certificate_frames.contains_key(&(*height, id.clone()))
                    {
                        let message = self.local_signer.sign_message(
                            EtdagNetworkMessage::AvailabilityCertificate(certificate.clone()),
                        )?;
                        let bytes = serde_json::to_vec(&message)
                            .map_err(|e| format!("encode durable availability certificate: {e}"))?;
                        if self.ingress.protected_cutoff_authority(*height)?.is_none() {
                            self.certificate_frames.insert((*height, id.clone()), bytes);
                            self.metrics
                                .record_availability_certificate()
                                .map_err(|e| format!("record available custody: {e:?}"))?;
                        }
                    }
                    self.available
                        .insert((certificate.context_root.clone(), id.clone()));
                }
            }
            let key = (
                target
                    .context
                    .root()
                    .map_err(|e| format!("derive availability cache key: {e:?}"))?,
                *height,
            );
            self.certificates.insert(key, owner.availability().clone());
        }
        Ok(())
    }

    fn accept_marker(&mut self, marker: ProtectedCutMarker) -> Result<(), String> {
        marker
            .validate()
            .map_err(|e| format!("validate cutoff statement: {e:?}"))?;
        let target = self
            .targets
            .get_mut(&marker.target_height)
            .ok_or("cutoff target is not governed")?;
        let pipeline = target.pipeline.as_ref().ok_or("cutoff owner missing")?;
        let known_cutoff = pipeline.has_cutoff_context(&marker.cutoff_context_root);
        if !known_cutoff {
            return Err("cutoff generation lacks verified PoSy authority".into());
        }
        let cutoff = marker.cutoff_context_root.clone();
        if marker.context_root
            != target
                .context
                .root()
                .map_err(|e| format!("derive cutoff target: {e:?}"))?
            || marker.cutoff_context_root != cutoff
        {
            return Err("cutoff context differs from accepted PoSy authority".into());
        }
        let (key, _) = self
            .cutoff_members
            .get(&marker.validator_id)
            .ok_or("cutoff signer is not assigned")?;
        if key != &marker.key_id {
            return Err("cutoff key differs from frozen binding".into());
        }
        SignatureVerifier::verify(
            self.authority.as_ref(),
            &marker.validator_id,
            key,
            &marker
                .signing_bytes()
                .map_err(|e| format!("encode cutoff statement: {e:?}"))?,
            &marker.signature,
        )
        .map_err(|e| format!("verify cutoff signature: {e:?}"))?;
        let active = pipeline
            .cutoff_context_root()
            .ok_or("cutoff owner lacks active authority")?;
        target.markers.remember(marker, active)
    }

    fn reconcile_protected_targets(&mut self) -> Result<(), String> {
        let heights = self.targets.keys().copied().collect::<Vec<_>>();
        'targets: for height in heights {
            if !self.check_target_transition_scratch(height) {
                continue;
            }
            let Some(cutoff) = self.ingress.protected_cutoff_authority(height)? else {
                continue;
            };
            let target = self
                .targets
                .get_mut(&height)
                .ok_or("protected target disappeared")?;
            let root = target
                .context
                .root()
                .map_err(|e| format!("derive protected context: {e:?}"))?;
            let key = (root.clone(), height);
            let graph = self
                .graphs
                .get(&key)
                .ok_or("protected target graph missing")?;
            let availability = self.certificates.entry(key).or_default();
            let pipeline = target
                .pipeline
                .as_mut()
                .ok_or("protected target owner absent")?;
            if pipeline.original_cutoff_context_root().is_none() {
                match pipeline.bind_cutoff(cutoff.clone()) {
                    Ok(_) => {}
                    Err(EtdagError::ResourcePressure(reason)) => {
                        self.resources.pressure = Some(reason);
                        continue 'targets;
                    }
                    Err(error) => {
                        return Err(format!("durably close availability signing: {error:?}"))
                    }
                }
            } else if pipeline.original_cutoff_context_root() != Some(&cutoff) {
                return Err("original cutoff authority changed".into());
            }
            if pipeline.batch().is_none() {
                for generation in self.ingress.cut_recovery_generations(height)? {
                    let required = pipeline.prospective_history_resource_bytes(&generation);
                    let previous = self.resources.history_bytes.get(&height).copied();
                    if let Err(error) = self.resources.reserve_history(height, required) {
                        self.resources.pressure =
                            Some(format!("protected cut recovery capacity: {error:?}"));
                        continue 'targets;
                    }
                    pipeline.set_history_resource_budget(self.resources.history_limit(height));
                    match pipeline
                        .apply_cut_recovery_generation(generation, &self.cut_recovery_verifier)
                    {
                        Ok(_) => {}
                        Err(EtdagError::ResourcePressure(reason)) => {
                            // Capacity guards precede append; restore this uncommitted
                            // reservation while keeping every previously durable index.
                            match previous {
                                Some(bytes) => {
                                    self.resources.history_bytes.insert(height, bytes);
                                }
                                None => {
                                    self.resources.history_bytes.remove(&height);
                                }
                            }
                            self.resources.pressure = Some(reason);
                            continue 'targets;
                        }
                        Err(error) => {
                            return Err(format!("persist PoSy-authorized cut recovery: {error:?}"))
                        }
                    }
                    // A later generation may encounter capacity pressure. Ack
                    // each durable prefix now so retry never retains/clones the
                    // already installed originals in the shared handoff queue.
                    self.ingress.report_cut_recovery_state(
                        height,
                        super::ingress::CutRecoveryState {
                            cutoff: pipeline
                                .cutoff_context_root()
                                .cloned()
                                .ok_or("recovered cutoff absent")?,
                            committed: false,
                            last_timeout_id: pipeline
                                .last_cut_recovery_generation()
                                .map(|g| g.timeout_id.clone()),
                        },
                    )?;
                }
            }
            let cutoff = pipeline
                .cutoff_context_root()
                .cloned()
                .ok_or("closed cutoff missing")?;
            target.markers.select(&cutoff);
            // Retain signed history on disk; prioritize delivery of the selected
            // generation so obsolete retry frames cannot starve its markers.
            self.marker_frames
                .retain(|(target, root), _| *target != height || root == &cutoff);
            self.ingress.report_cut_recovery_state(
                height,
                super::ingress::CutRecoveryState {
                    cutoff: cutoff.clone(),
                    committed: pipeline.batch().is_some(),
                    last_timeout_id: pipeline
                        .last_cut_recovery_generation()
                        .map(|g| g.timeout_id.clone()),
                },
            )?;
            if pipeline.local_marker().is_none() {
                // Close evidence covers every certified local ancestor. Missing
                // certificates delay closure rather than manufacturing an empty cut.
                if availability.keys().any(|id| !graph.contains(id)) {
                    continue;
                }
                let mut frontier = BTreeSet::new();
                let mut parents = BTreeSet::new();
                for vertex in graph.vertices() {
                    if !availability.contains_key(&vertex.vertex_id) {
                        continue;
                    }
                    let ancestors =
                        synergy_etdag::dag::ancestors(graph, &vertex.vertex_id, 4096)
                            .map_err(|e| format!("derive complete protected frontier: {e:?}"))?;
                    if ancestors.iter().any(|id| !availability.contains_key(id)) {
                        continue 'targets;
                    }
                    frontier.insert(vertex.vertex_id.clone());
                    parents.extend(ancestors);
                }
                frontier.retain(|id| !parents.contains(id));
                if frontier.len() > synergy_etdag::dag::MAX_VERTEX_PARENTS {
                    continue;
                }
                let marker = self.local_signer.sign_cutoff_marker(
                    root,
                    height,
                    cutoff.clone(),
                    frontier.into_iter().collect(),
                )?;
                match pipeline.persist_local_marker(
                    marker,
                    &self.cutoff_members,
                    self.authority.as_ref(),
                ) {
                    Ok(_) => {}
                    Err(EtdagError::ResourcePressure(reason)) => {
                        self.resources.pressure = Some(reason);
                        continue 'targets;
                    }
                    Err(error) => {
                        return Err(format!(
                            "persist protected admission close before broadcast: {error:?}"
                        ))
                    }
                }
            }
            if let Some(marker) = pipeline.local_marker() {
                target.markers.remember(marker.clone(), &cutoff)?;
                if !self.marker_frames.contains_key(&(height, cutoff.clone())) {
                    let message = self
                        .local_signer
                        .sign_message(EtdagNetworkMessage::CutoffMarker(marker.clone()))?;
                    let bytes = serde_json::to_vec(&message)
                        .map_err(|e| format!("encode cutoff delivery: {e}"))?;
                    self.marker_frames.insert((height, cutoff.clone()), bytes);
                }
            }
            if pipeline.batch().is_none() {
                // A Byzantine marker with a different frontier must not poison
                // an otherwise complete quorum. Group by semantic ancestry,
                // never by signatures or incidental redundant frontier IDs.
                let mut groups: BTreeMap<Vec<EtdagDigest>, Vec<ProtectedCutMarker>> =
                    BTreeMap::new();
                for marker in target
                    .markers
                    .payloads
                    .values()
                    .filter(|m| m.cutoff_context_root == cutoff)
                {
                    let mut closure = BTreeSet::new();
                    let mut complete = true;
                    for id in &marker.frontier {
                        match synergy_etdag::dag::ancestors(graph, id, 4096) {
                            Ok(ancestors) => {
                                closure.insert(id.clone());
                                closure.extend(ancestors);
                            }
                            Err(_) => {
                                complete = false;
                                break;
                            }
                        }
                    }
                    if complete {
                        groups
                            .entry(closure.into_iter().collect())
                            .or_default()
                            .push(marker.clone());
                    }
                }
                for markers in groups.values() {
                    match pipeline.accept_cut(
                        markers,
                        graph,
                        availability,
                        &self.cutoff_members,
                        self.authority.as_ref(),
                    ) {
                        Ok(_) => break,
                        Err(
                            EtdagError::InsufficientAvailability { .. }
                            | EtdagError::MissingArtifact(_),
                        ) => {}
                        Err(EtdagError::ResourcePressure(reason)) => {
                            self.resources.pressure = Some(reason);
                            continue 'targets;
                        }
                        Err(error) => return Err(format!("derive protected cut: {error:?}")),
                    }
                }
            }
            let Some(batch) = pipeline.batch().cloned() else {
                continue;
            };
            self.ingress
                .submit_protected_commitments(height, batch.clone(), cutoff)?;
            if let Some(handle) = &self.wallet_admission {
                handle.record_ordered(
                    height,
                    batch.protected_batch_root.clone(),
                    batch.ordered_transaction_ids.len(),
                )?;
                for envelope in &batch.ordered_transaction_ids {
                    handle.record_verified_stage(
                        envelope,
                        "ordered",
                        serde_json::json!({
                        "target_height":height,"protected_batch_root":batch.protected_batch_root,
                        "finalized":false}),
                    )?;
                }
            }
            if pipeline.prepared().is_none() && batch.ordered_transaction_ids.is_empty() {
                if let Some((authorization, evidence)) =
                    self.ingress.accepted_protected_parent(height)?
                {
                    match pipeline.prepare_empty(authorization, evidence, self.authority.as_ref()) {
                        Ok(_) => {}
                        Err(EtdagError::ResourcePressure(reason)) => {
                            self.resources.pressure = Some(reason);
                            continue 'targets;
                        }
                        Err(error) => {
                            return Err(format!(
                                "prepare quorum-authorized empty protected execution: {error:?}"
                            ))
                        }
                    }
                }
            }
            if !target.handed_off {
                if let Some(prepared) = pipeline.prepared() {
                    self.ingress.submit_protected_batch(prepared.clone())?;
                    target.handed_off = true;
                    self.metrics
                        .record_completed_reveal()
                        .and_then(|_| self.metrics.record_execution_handoff())
                        .map_err(|e| format!("record protected handoff: {e:?}"))?;
                }
            }
        }
        Ok(())
    }

    fn reveal_authority(
        &self,
        height: u64,
    ) -> Result<
        Option<(
            synergy_etdag::ProtectedRevealAuthorization,
            synergy_etdag::execution::ParentProposalRevealEvidence,
        )>,
        String,
    > {
        let pipeline = self
            .targets
            .get(&height)
            .and_then(|t| t.pipeline.as_ref())
            .ok_or("reveal owner absent")?;
        let accepted = self.ingress.accepted_protected_parent(height)?.or_else(|| {
            pipeline
                .prepared()
                .map(|p| (p.reveal_authorization.clone(), p.parent_evidence.clone()))
        });
        if let Some((authorization, evidence)) = &accepted {
            let batch = pipeline
                .batch()
                .ok_or("reveal parent arrived before verified cut")?;
            if authorization.protected_batch_root != batch.protected_batch_root
                || evidence.next_batch != *batch
            {
                return Err(
                    "accepted reveal parent differs from local selected protected batch".into(),
                );
            }
        }
        Ok(accepted)
    }

    fn selected_reveal_envelope(
        &self,
        height: u64,
        envelope_id: &EtdagDigest,
    ) -> Result<EncryptedTransactionEnvelope, String> {
        let target = self
            .targets
            .get(&height)
            .ok_or("reveal target is not active")?;
        let pipeline = target.pipeline.as_ref().ok_or("reveal owner missing")?;
        let batch = pipeline
            .batch()
            .ok_or("reveal target has no verified cut")?;
        selected_envelope(pipeline.graph(), batch, envelope_id).cloned()
    }

    fn accept_reveal_share(&mut self, share: DecryptShareMessage) -> Result<(), String> {
        let height = share.authorization.target_height;
        let envelope = self.selected_reveal_envelope(height, &share.envelope_id)?;
        let (authorization, evidence) = self
            .reveal_authority(height)?
            .ok_or("reveal has no locally accepted parent authority")?;
        VerifiedRevealAuthorization::verify(
            authorization.clone(),
            &evidence,
            self.authority.as_ref(),
        )
        .map_err(|e| format!("verify parent before share collection: {e:?}"))?;
        let target = self
            .targets
            .get(&height)
            .ok_or("reveal target disappeared")?;
        verify_decrypt_share(
            &share,
            &authorization,
            &self.members,
            &envelope,
            self.authority.protected_ingress_registry()?,
            &target.context,
            self.authority.as_ref(),
        )
        .map_err(|e| format!("verify protected reveal share: {e:?}"))?;
        let slot = (height, share.envelope_id.clone());
        if !self.reveal_shares.contains_key(&slot) && self.reveal_shares.len() >= 5 * 4096 {
            return Err("protected reveal envelope capacity reached".into());
        }
        let shares = self.reveal_shares.entry(slot).or_default();
        if let Some(previous) = shares.get(&share.validator_id) {
            if previous
                .signing_bytes()
                .map_err(|e| format!("encode previous reveal: {e:?}"))?
                != share
                    .signing_bytes()
                    .map_err(|e| format!("encode reveal: {e:?}"))?
            {
                return Err("protected reveal signer changed one committed share".into());
            }
            return Ok(());
        }
        if shares.len() >= self.members.len()
            || shares.values().any(|s| s.share_index == share.share_index)
        {
            return Err("protected reveal share count or index invalid".into());
        }
        #[cfg(test)]
        eprintln!(
            "protected reveal: owner={} H{} accepted signer={} shares={}",
            self.local_signer.validator_id,
            height,
            share.validator_id,
            shares.len() + 1
        );
        shares.insert(share.validator_id.clone(), share);
        Ok(())
    }

    fn reconcile_reveals(&mut self) -> Result<(), String> {
        let heights = self.targets.keys().copied().collect::<Vec<_>>();
        let registry = self.authority.protected_ingress_registry()?.clone();
        let quorum = synergy_etdag::certificate_quorum(self.members.len())
            .map_err(|e| format!("derive governed reveal quorum: {e:?}"))?;
        let decryptor = GovernedThresholdDecryptor::new(self.members.len(), quorum)
            .map_err(|e| format!("construct governed reveal provider: {e:?}"))?;
        for height in heights {
            if !self.check_target_transition_scratch(height) {
                continue;
            }
            let (context, batch, prepared) = {
                let target = self
                    .targets
                    .get(&height)
                    .ok_or("reveal target disappeared")?;
                let pipeline = target.pipeline.as_ref().ok_or("reveal owner absent")?;
                let Some(batch) = pipeline.batch() else {
                    continue;
                };
                (
                    target.context.clone(),
                    batch.clone(),
                    pipeline.prepared().is_some(),
                )
            };
            if batch.ordered_transaction_ids.is_empty() {
                continue;
            }
            let Some((authorization, evidence)) = self.reveal_authority(height)? else {
                continue;
            };
            let verified = VerifiedRevealAuthorization::verify(
                authorization.clone(),
                &evidence,
                self.authority.as_ref(),
            )
            .map_err(|e| format!("verify parent before custody opening: {e:?}"))?;
            #[cfg(test)]
            if !prepared
                && !self
                    .reveal_frames
                    .keys()
                    .any(|(target, _)| *target == height)
            {
                eprintln!(
                    "protected reveal: owner={} H{} parent accepted envelopes={}",
                    self.local_signer.validator_id,
                    height,
                    batch.ordered_transaction_ids.len()
                );
            }
            let envelopes = batch
                .ordered_transaction_ids
                .iter()
                .map(|id| self.selected_reveal_envelope(height, id))
                .collect::<Result<Vec<_>, _>>()?;
            for envelope in &envelopes {
                let slot = (height, envelope.envelope_id.clone());
                if !self.reveal_frames.contains_key(&slot) {
                    let key = format!(
                        "{}-{}/{}.json",
                        height, envelope.target_context_root.0, envelope.envelope_id.0
                    );
                    let bytes = if self
                        .reveal_store
                        .exists(&key)
                        .map_err(|e| format!("inspect durable reveal share: {e}"))?
                    {
                        self.reveal_store
                            .read_bounded(&key)
                            .map_err(|e| format!("read durable reveal share: {e}"))?
                    } else {
                        let capsule = envelope
                            .share_capsules
                            .iter()
                            .find(|c| c.validator_id == self.local_signer.validator_id)
                            .ok_or("local validator has no governed reveal capsule")?;
                        let record = synergy_etdag::crypto::active_key_for_validator(
                            &registry,
                            &self.local_signer.validator_id,
                            height,
                        )
                        .map_err(|e| format!("resolve governed local custody key: {e:?}"))?;
                        let mut share = match self.ingress_custody.kem.as_ref() {
                            Some(kem) => {
                                synergy_etdag::crypto::decrypt_share_capsule_with_kem_diagnostic(
                                    envelope,
                                    capsule,
                                    record,
                                    &self.ingress_custody.secret,
                                    false,
                                    kem.as_ref(),
                                )
                                .map_err(|failure| failure.into_error())
                            }
                            None => decrypt_share_capsule(
                                envelope,
                                capsule,
                                record,
                                &self.ingress_custody.secret,
                            ),
                        }
                        .map_err(|e| format!("open authorized local capsule: {e:?}"))?;
                        let released = share
                            .canonical_bytes()
                            .map_err(|e| format!("encode authorized local share: {e:?}"));
                        share.value.fill(0);
                        let message = self.local_signer.sign_share(DecryptShareMessage {
                            share_version: 2,
                            authorization: authorization.clone(),
                            envelope_id: envelope.envelope_id.clone(),
                            validator_id: self.local_signer.validator_id.clone(),
                            key_id: self.local_signer.key_id.as_str().into(),
                            ingress_kem_key_id: capsule.ingress_kem_key_id.clone(),
                            share_index: capsule.share_index,
                            share_commitment: capsule.share_commitment.clone(),
                            encrypted_share: released?,
                            signature: Vec::new(),
                        })?;
                        verify_decrypt_share(
                            &message,
                            &authorization,
                            &self.members,
                            envelope,
                            &registry,
                            &context,
                            self.authority.as_ref(),
                        )
                        .map_err(|e| {
                            format!("verify local share before durable publication: {e:?}")
                        })?;
                        let signed = self
                            .local_signer
                            .sign_message(EtdagNetworkMessage::DecryptShare(message))?;
                        let bytes = serde_json::to_vec(&signed)
                            .map_err(|e| format!("encode durable reveal frame: {e}"))?;
                        if bytes.len() > 64 * 1024 {
                            return Err("reveal frame exceeds durable bound".into());
                        }
                        self.reveal_store
                            .put_once_atomic(&[synergy_storage::StorageWrite {
                                relative_path: PathBuf::from(&key),
                                bytes: bytes.clone(),
                            }])
                            .map_err(|e| format!("persist exact reveal before broadcast: {e}"))?;
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::PermissionsExt;
                            let path = self.pipeline_root.join("reveal-shares").join(&key);
                            fs::set_permissions(path, fs::Permissions::from_mode(0o600))
                                .map_err(|e| format!("protect durable reveal share: {e}"))?;
                        }
                        bytes
                    };
                    let signed: AuthenticatedEtdagMessage = serde_json::from_slice(&bytes)
                        .map_err(|e| format!("decode durable reveal frame: {e}"))?;
                    verify_network_message(&signed, &self.members, self.authority.as_ref())
                        .map_err(|e| format!("reverify durable reveal frame: {e:?}"))?;
                    if signed.sender_id != self.local_signer.validator_id
                        || signed.key_id != self.local_signer.key_id.as_str()
                    {
                        return Err("durable reveal signer differs from local authority".into());
                    }
                    let EtdagNetworkMessage::DecryptShare(share) = signed.message else {
                        return Err("durable reveal record has wrong message kind".into());
                    };
                    if share.envelope_id != envelope.envelope_id
                        || share.validator_id != self.local_signer.validator_id
                    {
                        return Err("durable reveal record differs from selected envelope".into());
                    }
                    self.accept_reveal_share(share)?;
                    self.reveal_frames.insert(slot, bytes);
                }
            }
            if !prepared {
                let mut revealed = Vec::with_capacity(envelopes.len());
                let mut transcripts = BTreeMap::new();
                let mut sufficient = true;
                for envelope in &envelopes {
                    let mut collector = VerifiedShareCollector::new(
                        verified.clone(),
                        envelope.envelope_id.clone(),
                        quorum,
                        self.members.len(),
                    )
                    .map_err(|e| format!("construct authorized reveal collection: {e:?}"))?;
                    let messages = self
                        .reveal_shares
                        .get(&(height, envelope.envelope_id.clone()))
                        .ok_or("local reveal share missing")?;
                    for share in messages.values() {
                        let share = verify_decrypt_share(
                            share,
                            &authorization,
                            &self.members,
                            envelope,
                            &registry,
                            &context,
                            self.authority.as_ref(),
                        )
                        .map_err(|e| format!("reverify share before threshold decrypt: {e:?}"))?;
                        collector
                            .insert(share)
                            .map_err(|e| format!("collect verified reveal: {e:?}"))?;
                    }
                    let threshold = match collector.into_threshold_shares() {
                        Ok(threshold) => threshold,
                        Err(EtdagError::RevealThreshold { .. }) => {
                            sufficient = false;
                            break;
                        }
                        Err(e) => return Err(format!("assemble governed reveal threshold: {e:?}")),
                    };
                    revealed.push(
                        decrypt_authorized_envelope(envelope, &threshold, &decryptor).map_err(
                            |e| format!("decrypt authorized protected transaction: {e:?}"),
                        )?,
                    );
                    transcripts.insert(
                        envelope.envelope_id.clone(),
                        RevealTranscript {
                            transcript_version: 1,
                            authorization: authorization.clone(),
                            shares: messages.values().cloned().collect(),
                        },
                    );
                }
                if sufficient {
                    let prepared = self
                        .targets
                        .get_mut(&height)
                        .and_then(|t| t.pipeline.as_mut())
                        .ok_or("reveal owner disappeared")?
                        .prepare_revealed(
                            authorization,
                            evidence,
                            &revealed,
                            transcripts,
                            self.authority.as_ref(),
                        );
                    match prepared {
                        Ok(_) => {}
                        Err(EtdagError::ResourcePressure(reason)) => {
                            self.resources.pressure = Some(reason);
                            continue;
                        }
                        Err(error) => {
                            return Err(format!(
                                "persist authenticated nonempty protected execution: {error:?}"
                            ))
                        }
                    }
                }
            }
            let target = self
                .targets
                .get_mut(&height)
                .ok_or("reveal target disappeared")?;
            if !target.handed_off {
                if let Some(prepared) = target.pipeline.as_ref().and_then(|p| p.prepared()) {
                    self.ingress.submit_protected_batch(prepared.clone())?;
                    target.handed_off = true;
                    self.metrics
                        .record_completed_reveal()
                        .and_then(|_| self.metrics.record_execution_handoff())
                        .map_err(|e| format!("record nonempty protected handoff: {e:?}"))?;
                }
            }
        }
        Ok(())
    }

    fn retry_cutoff_delivery(&mut self) -> Result<(), String> {
        if self
            .last_retry
            .is_some_and(|last| last.elapsed() < Duration::from_millis(250))
        {
            return Ok(());
        }
        let payloads = self
            .vertex_frames
            .values()
            .chain(self.marker_frames.values())
            .chain(self.availability_frames.values())
            .chain(self.certificate_frames.values())
            .chain(self.reveal_frames.values())
            .map(Vec::as_slice);
        let peers = self
            .members
            .iter()
            .filter(|peer| *peer != &self.local_signer.validator_id)
            .map(String::as_str);
        if deliver_retry_slice(payloads, peers, &mut self.retry_cursor, |peer, payload| {
            self.ingress.try_publish_outbound(OutboundFrame {
                peer_id: peer.to_owned(),
                protocol: ProtocolKind::Etdag,
                payload: payload.to_vec(),
            })
        })? {
            self.last_retry = Some(Instant::now());
        }
        Ok(())
    }

    fn handle_network_message(
        &mut self,
        peer: &AuthenticatedPeer,
        message: AuthenticatedEtdagMessage,
    ) -> Result<(), String> {
        if peer.node_address.as_str() != message.sender_id.as_str() {
            return Err("ETDAG signed sender differs from authenticated transport peer".into());
        }
        verify_network_message(&message, &self.members, self.authority.as_ref())
            .map_err(|error| format!("verify Aegis ETDAG network message: {error:?}"))?;
        match message.message {
            EtdagNetworkMessage::ProcessingProposalInputsV1(bytes) => {
                #[cfg(feature = "qualification-timing")]
                super::qualification_timing::processing_input_arrival(&bytes, &message.sender_id);
                if !self.authority.processing_profile_enabled() {
                    return Err("processing inputs require governed profile".into());
                }
                if !self
                    .ingress
                    .queue_processing_inputs(&message.sender_id, &bytes, false)?
                {
                    return Err("processing replay input backpressure".into());
                }
            }
            EtdagNetworkMessage::ProcessingVertexV1(vertex) => self.processing_vertex(vertex)?,
            EtdagNetworkMessage::ProcessingAvailabilityVoteV1(vote) => {
                if vote.validator_id != message.sender_id || vote.key_id != message.key_id {
                    return Err(
                        "processing availability voter differs from authenticated sender".into(),
                    );
                }
                self.processing_availability_vote(peer, vote)?;
            }
            EtdagNetworkMessage::ProcessingAvailabilityCertificateV1(certificate) => {
                self.processing_availability_certificate(certificate)?
            }
            EtdagNetworkMessage::ProcessingDecryptShareV1(share) => {
                self.processing_reveal_share(share)?
            }
            EtdagNetworkMessage::Vertex(vertex) => {
                if vertex.author_id != message.sender_id {
                    return Err("ETDAG vertex author differs from signed network sender".into());
                }
                self.admit_vertex(vertex, false)
                    .map_err(|e| e.to_string())?;
            }
            EtdagNetworkMessage::AvailabilityVote(vote) => {
                if vote.validator_id != message.sender_id || vote.key_id != message.key_id {
                    return Err("availability voter differs from authenticated sender".into());
                }
                let height = self
                    .targets
                    .iter()
                    .find(|(_, target)| {
                        target.context.root().ok().as_ref() == Some(&vote.context_root)
                    })
                    .map(|(height, _)| *height)
                    .ok_or("availability vote target is not governed")?;
                let owner = self
                    .targets
                    .get_mut(&height)
                    .and_then(|target| target.pipeline.as_mut())
                    .ok_or("availability owner missing")?;
                owner
                    .persist_vote(vote, &self.cutoff_members, self.authority.as_ref())
                    .map_err(|e| format!("admit verified availability vote: {e:?}"))?;
            }
            EtdagNetworkMessage::AvailabilityCertificate(certificate) => {
                verify_availability_certificate(
                    &certificate,
                    &self.members,
                    self.authority.as_ref(),
                )
                .map_err(|error| format!("verify availability certificate: {error:?}"))?;
                self.retain_availability(certificate.clone())?;
                self.available.insert((
                    certificate.context_root.clone(),
                    certificate.vertex_id.clone(),
                ));
                self.metrics
                    .record_availability_certificate()
                    .map_err(|error| format!("update ETDAG metrics: {error:?}"))?;
            }
            EtdagNetworkMessage::ShardCustody(custody) => {
                if custody.proof.custodian_id != message.sender_id
                    || custody.proof.key_id != message.key_id
                    || custody.proof.chain_id != self.authority.epoch.chain_id
                    || custody.proof.network_id != self.authority.epoch.network_id
                {
                    return Err(
                        "availability shard custody differs from authenticated authority".into(),
                    );
                }
                let current_height = self
                    .ingress
                    .latest_finality()?
                    .map(|record| record.height)
                    .unwrap_or_else(|| self.authority.anchor_parent.height());
                accept_vertex_shard(
                    self.authority.as_ref(),
                    &self.shard_store,
                    &custody.vertex_id,
                    &custody.proof,
                    &custody.shard,
                    current_height,
                )
                .map_err(|error| format!("admit authenticated ETDAG shard custody: {error:?}"))?;
            }
            EtdagNetworkMessage::Certificate(certificate) => {
                self.handle_certificate(certificate)?;
            }
            EtdagNetworkMessage::DecryptShare(share) => {
                if share.validator_id != message.sender_id {
                    return Err("ETDAG decrypt-share owner differs from signed sender".into());
                }
                if share.key_id != message.key_id {
                    return Err("reveal consensus key differs from signed sender".into());
                }
                self.accept_reveal_share(share)?;
            }
            EtdagNetworkMessage::CertifiedExecutionHandoff(_) => {
                return Err(
                    "legacy batch-validation certificates cannot authorize protected execution"
                        .into(),
                );
            }
            EtdagNetworkMessage::CutoffMarker(marker) => {
                if marker.validator_id != message.sender_id || marker.key_id != message.key_id {
                    return Err("cutoff statement differs from authenticated sender".into());
                }
                self.accept_marker(marker)?;
            }
            EtdagNetworkMessage::RequestMissingArtifact(request) => {
                request
                    .validate()
                    .map_err(|error| format!("validate ETDAG artifact request: {error:?}"))?;
                let custody = serve_custody(
                    &self.shard_store,
                    &request.artifact_id.0,
                    request.shard_index,
                )?;
                let response =
                    self.local_signer
                        .sign_message(EtdagNetworkMessage::RecoveredShardCustody(
                            RecoveredShardCustody {
                                custody: ShardCustodyMessage {
                                    vertex_id: request.artifact_id.clone(),
                                    proof: custody.proof,
                                    shard: custody.shard,
                                },
                                request,
                            },
                        ))?;
                let payload = serde_json::to_vec(&response)
                    .map_err(|error| format!("encode recovered ETDAG shard: {error}"))?;
                if payload.len() > synergy_network::protocol::DEFAULT_MAX_FRAME_BYTES {
                    return Err("recovered ETDAG shard exceeds authenticated frame bound".into());
                }
                self.ingress.publish_outbound(OutboundFrame {
                    peer_id: peer.node_address.to_string(),
                    protocol: ProtocolKind::Etdag,
                    payload,
                })?;
                self.metrics
                    .record_recovery_request()
                    .map_err(|error| format!("update ETDAG recovery metric: {error:?}"))?;
            }
            EtdagNetworkMessage::RecoveredShardCustody(recovered) => {
                recovered
                    .validate_shape()
                    .map_err(|error| format!("validate recovered ETDAG custody: {error:?}"))?;
                let current_height = self
                    .ingress
                    .latest_finality()?
                    .map(|record| record.height)
                    .unwrap_or_else(|| self.authority.anchor_parent.height());
                accept_vertex_shard(
                    self.authority.as_ref(),
                    &self.shard_store,
                    &recovered.custody.vertex_id,
                    &recovered.custody.proof,
                    &recovered.custody.shard,
                    current_height,
                )
                .map_err(|error| format!("admit recovered ETDAG shard custody: {error:?}"))?;
            }
        }
        Ok(())
    }

    fn apply_finalized_retention(&mut self) -> Result<(), String> {
        self.apply_protected_retirement()?;
        let Some(retain_blocks) = self.retention_blocks else {
            return Ok(());
        };
        if retain_blocks == 0 {
            return Err("data-availability retention window must be nonzero".into());
        }
        let Some(finality) = self.ingress.latest_finality()? else {
            return Ok(());
        };
        if finality.height <= self.last_pruned_finalized_height {
            return Ok(());
        }
        let retain_from_height = finality.height.saturating_sub(retain_blocks).max(1);
        self.shard_store
            .remove_below(retain_from_height)
            .map_err(|error| format!("apply finalized shard retention: {error}"))?;
        prune_reveal_records(
            &self.pipeline_root.join("reveal-shares"),
            retain_from_height.saturating_sub(1),
        )?;
        self.last_pruned_finalized_height = finality.height;
        Ok(())
    }

    fn apply_protected_retirement(&mut self) -> Result<(), String> {
        let Some(retirement) = self.protected_retirement.as_mut() else {
            return Ok(());
        };
        let now = Instant::now();
        if retirement
            .defer_until
            .is_some_and(|deadline| now < deadline)
        {
            return Ok(());
        }
        if retirement
            .last_check
            .is_some_and(|last| now.duration_since(last) < PROTECTED_RETIREMENT_INTERVAL)
        {
            return Ok(());
        }
        retirement.last_check = Some(now);
        let Some(finalized) = self.ingress.latest_finality()? else {
            return Ok(());
        };
        let state = synergy_state::FinalizedStateStore::load_budgeted(
            &self.finalized_state_root,
            Arc::clone(self.ingress.world_budget()),
        )
        .map_err(|e| format!("R4 load durable execution commitment: {e:?}"))?;
        let Some(executed) = state.current() else {
            return Ok(());
        };
        if let Some(previous) = &retirement.verified_execution {
            if executed.finalized_height < previous.finalized_height
                || (executed.finalized_height == previous.finalized_height && executed != previous)
                || finalized.height < retirement.verified_finalized_height
            {
                return Err("R4 verified retirement watermark regressed or conflicted".into());
            }
        }
        // Coalesce anchor verification; draining an existing verified horizon
        // needs no repeated candidate/world decoding or PQC verification.
        let refresh = retirement.verified_execution.is_none()
            || (retirement.next_height.max(3) > retirement.through_height
                && retirement
                    .verified_execution
                    .as_ref()
                    .is_some_and(|previous| {
                        finalized.height.min(executed.finalized_height)
                            >= previous
                                .finalized_height
                                .saturating_add(MAX_PROTECTED_RETIREMENTS_PER_POLL)
                    }));
        if refresh {
            let Some((executed_finality, _)) = self
                .ingress
                .finalized_record_with_witness(executed.finalized_height)?
            else {
                return Ok(());
            };
            let Some(world) = state
                .current_world_state()
                .map_err(|e| format!("R4 committed account state: {e:?}"))?
            else {
                return Ok(());
            };
            if synergy_state::state_root(&world)
                .map_err(|e| format!("R4 committed account root: {e:?}"))?
                != executed.state_root
            {
                return Err(
                    "R4 committed account state differs from durable execution root".into(),
                );
            }
            drop(world);
            let data_root = self
                .pipeline_root
                .parent()
                .and_then(|root| root.parent())
                .ok_or("R4 canonical storage layout mismatch")?;
            let candidates = synergy_execution::CandidateStore::new(
                data_root.join("blocks/execution-candidates"),
            )?;
            let Some(candidate) = candidates.get(executed.finalized_height)? else {
                return Ok(());
            };
            retirement.through_height = protected_retirement_boundary(
                &finalized,
                &executed_finality,
                executed,
                &candidate,
                self.parameters.target_height_offset,
            )?;
            retirement.verified_execution = Some(executed.clone());
            retirement.verified_finalized_height = finalized.height;
        }
        if retirement.next_height.max(3) > retirement.through_height {
            return Ok(());
        }
        let authority = self.authority.as_ref();
        let cleanup = retire_protected_records(
            &self.pipeline_root,
            &mut retirement.next_height,
            retirement.through_height,
            |context, height| {
                context
                    .validate_with_parameters(&self.parameters)
                    .map_err(|e| format!("R4 retired target context: {e:?}"))?;
                if context.target_height != height
                    || context.chain_id != authority.epoch.chain_id
                    || context.network_id != authority.epoch.network_id
                    || context.protocol_version != authority.epoch.protocol_version
                    || context.epoch != authority.epoch.epoch
                    || context.active_validator_set_root
                        != authority.epoch.active_validator_set_root
                    || context.validator_consensus_key_root
                        != authority.epoch.validator_consensus_key_root
                    || context.frozen_voting_weight_root
                        != authority.epoch.frozen_voting_weight_root
                    || context.consensus_parameter_root != authority.epoch.consensus_parameter_root
                    || self.targets.contains_key(&height)
                {
                    return Err(
                        "R4 retirement target differs from frozen authority or remains live".into(),
                    );
                }
                Ok(())
            },
        );
        retirement.complete_cleanup(cleanup, now);
        Ok(())
    }

    fn handle_certificate(&mut self, certificate: CanonicalCertificate) -> Result<(), String> {
        match certificate {
            CanonicalCertificate::Availability(value) => {
                verify_availability_certificate(&value, &self.members, self.authority.as_ref())
                    .map_err(|error| {
                        format!("verify canonical availability certificate: {error:?}")
                    })?;
                self.retain_availability(value.clone())?;
                self.available.insert((value.context_root, value.vertex_id));
                Ok(())
            }
            _ => Err(
                "legacy ETDAG consensus certificates do not authorize the protected pipeline"
                    .into(),
            ),
        }
    }
}

impl EtdagMessageSink for EtdagService {
    fn receive_etdag(&mut self, peer: AuthenticatedPeer, payload: Vec<u8>) -> Result<(), String> {
        let identity = ProcessedEtdagFrames::identity(&peer, &payload);
        if self.processed_frames.entries.contains(&identity) {
            return Ok(());
        }
        let message: AuthenticatedEtdagMessage = serde_json::from_slice(&payload)
            .map_err(|error| format!("decode authenticated ETDAG message: {error}"))?;
        let immutable_announcement = matches!(
            &message.message,
            EtdagNetworkMessage::Vertex(_)
                | EtdagNetworkMessage::AvailabilityVote(_)
                | EtdagNetworkMessage::AvailabilityCertificate(_)
                | EtdagNetworkMessage::Certificate(_)
                | EtdagNetworkMessage::DecryptShare(_)
                | EtdagNetworkMessage::CutoffMarker(_)
                | EtdagNetworkMessage::ProcessingVertexV1(_)
                | EtdagNetworkMessage::ProcessingAvailabilityVoteV1(_)
                | EtdagNetworkMessage::ProcessingAvailabilityCertificateV1(_)
                | EtdagNetworkMessage::ProcessingDecryptShareV1(_)
        );
        self.handle_network_message(&peer, message)?;
        if immutable_announcement {
            self.processed_frames.remember(identity);
        }
        Ok(())
    }
}

impl ManagedService for EtdagService {
    fn start(&mut self, cancellation: &CancellationToken) -> Result<(), String> {
        if cancellation.is_cancelled() {
            return Err("ETDAG service start was cancelled".into());
        }
        // Production owners must not share the supervisor's nonblocking crypto
        // engines with PoSy/execution. This runs on the sole ETDAG thread before
        // any pending recovery or author verification is initialized.
        self.authority = VerifiedAuthority::worker_context(&self.authority)?;
        self.cut_recovery_verifier.authority = self.authority.clone();
        self.owner_cancellation = Some(cancellation.clone());
        if self.processing.is_some() {
            self.started = true;
            self.failure = None;
            return self.start_processing_owner();
        }
        self.parameters
            .validate()
            .map_err(|error| format!("validate ETDAG service parameters: {error:?}"))?;
        self.authority
            .epoch
            .validate_against(&self.authority.registry)
            .map_err(|error| format!("validate ETDAG frozen authority: {error}"))?;
        if let Some(handle) = &self.preparation_handle {
            self.context_preparation = Some(
                handle.owner(super::preparation::AuthorityTag {
                    incarnation: self.authority.epoch.network_id.clone(),
                    epoch: self.authority.epoch.epoch,
                    authority_digest: EtdagDigest::from_domain_bytes(
                        "SYNERGY_PREPARATION_AUTHORITY_V1",
                        self.authority.binding_bytes(),
                    )
                    .0,
                })?,
            );
            self.wallet_preparation = Some(
                handle.owner(super::preparation::AuthorityTag {
                    incarnation: self.authority.epoch.network_id.clone(),
                    epoch: self.authority.epoch.epoch,
                    authority_digest: EtdagDigest::from_domain_bytes(
                        "SYNERGY_PREPARATION_AUTHORITY_V1",
                        self.authority.binding_bytes(),
                    )
                    .0,
                })?,
            );
        }
        self.open_authorized_targets()?;
        if !self.recovering_targets.is_empty() {
            self.started = true;
            self.failure = None;
            if let Some(handle) = &self.wallet_admission {
                handle.publish_context(None)?;
            }
            return Ok(());
        }
        self.poll_admission_preparation()?;
        self.started = true;
        self.failure = None;
        self.publish_wallet_context()
    }

    fn poll(&mut self) -> Result<(), String> {
        if !self.started {
            return Err("ETDAG service is not started".into());
        }
        if self.processing.is_some() {
            return self.poll_processing_owner();
        }
        for _ in 0..MAX_MESSAGES_PER_POLL {
            let Some(request) = self.ingress.take_etdag_control()? else {
                break;
            };
            self.ingress_paused = match request.action {
                EtdagControlAction::PauseIngress => true,
                EtdagControlAction::ResumeIngress => false,
            };
            let _ = request.response.send(Ok(()));
        }
        self.parameters
            .validate()
            .map_err(|e| format!("ETDAG service lost governed admission policy: {e:?}"))?;
        if self.parameters != self.authority.protected_parameters()? {
            return Err("ETDAG parameters differ from signed authority".into());
        }
        self.open_authorized_targets()?;
        self.poll_target_recovery()?;
        if !self.recovering_targets.is_empty() {
            if let Some(handle) = &self.wallet_admission {
                handle.publish_context(None)?;
            }
            return Ok(());
        }
        if self.ingress_paused {
            self.publish_wallet_context()?;
            return self.apply_finalized_retention();
        }
        self.poll_admission_preparation()?;
        // Peer recovery remains admissible after close. Fresh local authoring
        // receives an explicit rejection and cannot reopen VAC signing.
        for _ in 0..MAX_MESSAGES_PER_POLL {
            let Some(request) = self.ingress.take_local_protected_vertex()? else {
                break;
            };
            let result = self.admit_vertex(request.vertex, true);
            complete_local_vertex_admission(result, request.response)?;
        }
        for _ in 0..MAX_MESSAGES_PER_POLL {
            let Some(frame) = self.ingress.take(ProtocolKind::Etdag)? else {
                break;
            };
            if let Err(error) = EtdagAdapter.deliver(AdapterEnvelope::from(frame), self) {
                #[cfg(test)]
                {
                    static REJECT_DIAGNOSTICS: std::sync::atomic::AtomicUsize =
                        std::sync::atomic::AtomicUsize::new(0);
                    if REJECT_DIAGNOSTICS.fetch_add(1, std::sync::atomic::Ordering::Relaxed) < 20 {
                        eprintln!(
                            "protected input rejected: owner={} error={error:?}",
                            self.local_signer.validator_id
                        );
                    }
                }
                #[cfg(not(test))]
                let _ = error;
                // Peer data cannot terminate the local protected owner. Verified
                // local persistence and reconciliation errors remain fatal below.
                self.metrics
                    .record_admission(false)
                    .map_err(|error| format!("record rejected ETDAG input: {error:?}"))?;
            }
        }
        self.reconcile_availability()?;
        self.reconcile_protected_targets()?;
        self.reconcile_reveals()?;
        self.retry_cutoff_delivery()?;
        self.apply_finalized_retention()?;
        self.publish_wallet_context()
    }

    fn stop(&mut self) -> Result<(), String> {
        if let Some(owner) = self.context_preparation.take() {
            owner.cancel();
        }
        if let Some(owner) = self.wallet_preparation.take() {
            owner.cancel();
        }
        self.wallet_jobs.clear();
        self.context_jobs.clear();
        self.prepared_contexts.clear();
        self.context_dispatch_turn = false;
        if let Some(handle) = &self.wallet_admission {
            handle.publish_context(None)?;
            handle.publish_processing_context(&self.authority, None)?;
            handle.cancel_uncommitted()?;
        }
        if self.processing.is_some() {
            self.processing = Some(processing::ProcessingOwner::default());
        }
        self.ingress.clear(ProtocolKind::Etdag)?;
        self.graphs.clear();
        self.available.clear();
        self.targets.clear();
        self.recovering_targets.clear();
        self.recovery_capacity_blocked = false;
        self.resources.vertices.clear();
        self.resources.pressure = None;
        self.owner_cancellation = None;
        self.certificates.clear();
        self.reveal_frames.clear();
        self.reveal_shares.clear();
        self.marker_frames.clear();
        self.vertex_frames.clear();
        self.availability_frames.clear();
        self.certificate_frames.clear();
        self.last_retry = None;
        self.processed_frames = ProcessedEtdagFrames::default();
        self.retry_cursor = 0;
        self.started = false;
        self.ingress_paused = false;
        Ok(())
    }

    fn health(&self) -> ServiceHealth {
        if !self.started {
            return ServiceHealth::Unhealthy {
                reason: "ETDAG service is stopped".into(),
            };
        }
        if let Some(reason) = &self.failure {
            return ServiceHealth::Unhealthy {
                reason: reason.clone(),
            };
        }
        if let Some(reason) = &self.resources.pressure {
            return ServiceHealth::Degraded {
                reason: reason.clone(),
            };
        }
        if self.ingress_paused {
            return ServiceHealth::Degraded {
                reason: "ETDAG ingress is paused by an authorized operator".into(),
            };
        }
        if !self.recovering_targets.is_empty() {
            return ServiceHealth::Degraded {
                reason: "protected journals are being verified in bounded recovery steps".into(),
            };
        }
        ServiceHealth::Healthy
    }

    fn readiness(&self) -> ServiceReadiness {
        if !self.started {
            return ServiceReadiness::Blocked {
                reason: "ETDAG service is stopped".into(),
            };
        }
        if self.ingress_paused {
            return ServiceReadiness::Pending {
                reason: "ETDAG ingress is paused by an authorized operator".into(),
            };
        }
        if !self.recovering_targets.is_empty() {
            return ServiceReadiness::Pending { reason:"protected recovery is not yet authenticated; admission and signing remain closed".into() };
        }
        ServiceReadiness::Ready
    }
}

#[cfg(feature = "qualification-timing")]
fn observe_admission(phase: super::qualification_timing::Phase, target: u64, envelope: &str) {
    use super::qualification_timing::{self as timing, Classification, Kind, Role};
    timing::emit_subject_once(
        Kind::Admission,
        phase,
        target,
        0,
        0,
        envelope,
        Role::Participant,
        Classification::Observed,
        None,
        None,
    );
}

#[cfg(test)]
mod qualification {
    use super::*;
    use crate::services::posy::qualification::Fleet;

    fn retirement_record(context: &TargetAdmissionContextV3) -> Vec<u8> {
        #[derive(serde::Serialize)]
        struct Journal<'a> {
            version: u32,
            context: &'a TargetAdmissionContextV3,
            unused_history: &'a str,
        }
        serde_json::to_vec(&Journal {
            version: 3,
            context,
            unused_history: "not needed for retirement",
        })
        .unwrap()
    }

    fn retirement_candidate(height: u64) -> synergy_execution::ExecutionCandidate {
        let material = synergy_etdag::execution::ProtectedProposalMaterial {
            material_version: 2,
            height,
            execution_root: EtdagDigest::from_domain_bytes("retirement", b"execution"),
            next_batch_root: EtdagDigest::from_domain_bytes("retirement", b"batch"),
            cutoff_boundary_root: EtdagDigest::from_domain_bytes("retirement", b"cutoff"),
        };
        let state = synergy_state::WorldState::default();
        let mut candidate = synergy_execution::ExecutionCandidate {
            resource_permit: None,
            height,
            block_id: String::new(),
            parent_block_id: "a".repeat(64),
            protected_execution_root: synergy_block::hash_block_bytes(
                &material.commitment_bytes().unwrap(),
            ),
            protected_material: material.into(),
            state_root: synergy_state::state_root(&state).unwrap(),
            transactions: Vec::new(),
            receipts: Vec::new(),
            state: std::sync::Arc::new(state),
        };
        candidate.block_id = candidate.commitment_id().unwrap();
        candidate
    }

    #[test]
    fn processed_announcements_are_exact_peer_session_bound_and_memory_bounded() {
        let peer = AuthenticatedPeer::new(
            "synv11lrh6jcxaejkj4zv994j7qwn2rk6u3ar4emn",
            synergy_protocol_types::SessionId(17),
            vec![],
        )
        .unwrap();
        let mut cache = ProcessedEtdagFrames::default();
        let original = ProcessedEtdagFrames::identity(&peer, b"verified announcement");
        assert!(!cache.entries.contains(&original));
        cache.remember(original.clone());
        assert!(cache.entries.contains(&original));
        assert!(!cache.entries.contains(&ProcessedEtdagFrames::identity(
            &peer,
            b"altered announcement"
        )));
        let mut reconnected = peer.clone();
        reconnected.session_id = synergy_protocol_types::SessionId(18);
        assert!(!cache.entries.contains(&ProcessedEtdagFrames::identity(
            &reconnected,
            b"verified announcement"
        )));
        cache.remember(original.clone());
        assert_eq!(cache.order.len(), 1);
        for sequence in 0..MAX_PROCESSED_ETDAG_FRAMES {
            cache.remember(ProcessedEtdagFrames::identity(
                &peer,
                &sequence.to_be_bytes(),
            ));
        }
        assert_eq!(cache.entries.len(), MAX_PROCESSED_ETDAG_FRAMES);
        assert_eq!(cache.order.len(), MAX_PROCESSED_ETDAG_FRAMES);
        assert!(!cache.entries.contains(&original));
    }

    #[test]
    fn r4_requires_matching_execution_and_finality_before_bounded_exact_journal_retirement() {
        let fleet = Fleet::new();
        let root = fleet.root.join("r4-protected-pipeline");
        fs::create_dir(&root).unwrap();
        let context = crate::services::etdag_qualification::context(&fleet);
        for height in 3..=100 {
            let mut context = context.clone();
            context.target_height = height;
            context.source_finalized_height = height.saturating_sub(context.target_height_offset);
            fs::write(
                root.join(format!("protected-h{height}.json")),
                retirement_record(&context),
            )
            .unwrap();
        }
        fs::write(root.join("sign-once.json"), b"preserved").unwrap();
        let candidate = retirement_candidate(80);
        let executed = synergy_state::FinalizedState {
            finalized_height: 80,
            finalized_block_id: candidate.block_id.clone(),
            state_root: candidate.state_root.clone(),
        };
        let proof = synergy_posy::FinalizedBlockRecord {
            height: 80,
            block_id: candidate.block_id.clone(),
            finality_certificate_id: "d".repeat(64),
            protected_execution_root: candidate.protected_execution_root.clone(),
        };
        let mut tip = proof.clone();
        tip.height = 100;
        let mut corrupt = executed.clone();
        corrupt.state_root = "f".repeat(64);
        assert!(protected_retirement_boundary(&tip, &proof, &corrupt, &candidate, 5).is_err());
        assert!(
            root.join("protected-h3.json").exists(),
            "failed authorization deletes nothing"
        );
        let through =
            protected_retirement_boundary(&tip, &proof, &executed, &candidate, 5).unwrap();
        assert_eq!(through, 72, "durable execution lag limits retirement");
        assert_eq!(
            protected_retirement_boundary(&tip, &proof, &executed, &candidate, 16).unwrap(),
            62
        );
        let check = |context: &TargetAdmissionContextV3, height| {
            if context.target_height != height || context.chain_id != fleet.authority.epoch.chain_id
            {
                return Err("retired journal domain mismatch".to_string());
            }
            Ok(())
        };
        let mut cursor = 3;
        assert_eq!(
            retire_protected_records(&root, &mut cursor, through, check).unwrap(),
            MAX_PROTECTED_RETIREMENTS_PER_POLL
        );
        assert_eq!(cursor, 35);
        assert!(
            root.join("protected-h35.json").exists(),
            "one tick is bounded"
        );
        while cursor <= through {
            retire_protected_records(&root, &mut cursor, through, check).unwrap();
        }
        assert!(!root.join("protected-h72.json").exists());
        for height in 73..=100 {
            assert!(root.join(format!("protected-h{height}.json")).exists());
        }
        assert_eq!(fs::read(root.join("sign-once.json")).unwrap(), b"preserved");
        // A restart rechecks exact missing slots, preserving the same tail.
        let mut restarted_cursor = 3;
        retire_protected_records(&root, &mut restarted_cursor, through, check).unwrap();
        assert_eq!(restarted_cursor, 35);
        assert!(root.join("protected-h73.json").exists());
    }

    #[test]
    fn r4_rejects_symlinks_and_wrong_target_without_deleting_original() {
        use std::os::unix::fs::symlink;
        let fleet = Fleet::new();
        let root = fleet.root.join("r4-invalid-record");
        fs::create_dir(&root).unwrap();
        let outside = fleet.root.join("must-remain.json");
        fs::write(&outside, b"outside").unwrap();
        symlink(&outside, root.join("protected-h3.json")).unwrap();
        let mut cursor = 3;
        assert!(retire_protected_records(&root, &mut cursor, 3, |_, _| Ok(())).is_err());
        let now = Instant::now();
        let mut retirement = ProtectedRetirement::default();
        retirement.complete_cleanup(Err("unsafe obsolete symlink".into()), now);
        assert_eq!(
            retirement.defer_until,
            Some(now + PROTECTED_RETIREMENT_BACKOFF)
        );
        retirement.complete_cleanup(Ok(0), now + PROTECTED_RETIREMENT_BACKOFF);
        assert!(retirement.defer_until.is_none());
        assert_eq!(fs::read(&outside).unwrap(), b"outside");
        fs::remove_file(root.join("protected-h3.json")).unwrap();
        let mut context = crate::services::etdag_qualification::context(&fleet);
        context.target_height = 4;
        fs::write(root.join("protected-h3.json"), retirement_record(&context)).unwrap();
        assert!(
            retire_protected_records(&root, &mut cursor, 3, |context, height| {
                if context.target_height == height {
                    Ok(())
                } else {
                    Err("wrong target".into())
                }
            })
            .is_err()
        );
        assert!(root.join("protected-h3.json").exists());
        assert_eq!(cursor, 3);
    }

    #[test]
    fn cutoff_wire_preserves_real_pqc_identity_and_exact_close_statement() {
        let fleet = Fleet::new();
        let key_id = KeyId::new("key-0".to_owned()).unwrap();
        let signer = LocalEtdagSigner {
            validator_id: "qualification-0".into(),
            key_id: key_id.clone(),
            signer: Arc::new(
                PqvmSigner::from_secret_key_bytes(
                    AegisPolicy {
                        allowed_algorithms: vec![SignatureAlgorithm::MlDsa65],
                        maximum_message_bytes: MAX_ETDAG_SIGNING_BYTES,
                        maximum_signature_bytes: 16 * 1024,
                    },
                    key_id,
                    fleet.secrets[0].clone(),
                )
                .unwrap(),
            ),
            chain_id: 1266,
            epoch: 1,
        };
        let marker = signer
            .sign_cutoff_marker(
                EtdagDigest::from_domain_bytes("test", b"context"),
                3,
                EtdagDigest::from_domain_bytes("test", b"accepted-vc1"),
                Vec::new(),
            )
            .unwrap();
        SignatureVerifier::verify(
            fleet.authority.as_ref(),
            &marker.validator_id,
            &marker.key_id,
            &marker.signing_bytes().unwrap(),
            &marker.signature,
        )
        .unwrap();
        let message = signer
            .sign_message(EtdagNetworkMessage::CutoffMarker(marker.clone()))
            .unwrap();
        let wire = serde_json::to_vec(&message).unwrap();
        let decoded: AuthenticatedEtdagMessage = serde_json::from_slice(&wire).unwrap();
        let members = fleet
            .authority
            .registry
            .active()
            .map(|member| member.validator_id.clone())
            .collect();
        verify_network_message(&decoded, &members, fleet.authority.as_ref()).unwrap();
        assert_eq!(decoded, message);
        let mut changed = marker;
        changed.target_height = 4;
        assert!(SignatureVerifier::verify(
            fleet.authority.as_ref(),
            &changed.validator_id,
            &changed.key_id,
            &changed.signing_bytes().unwrap(),
            &changed.signature
        )
        .is_err());
    }
}

#[cfg(test)]
mod local_admission_failure_tests {
    use super::*;
    #[test]
    fn invalid_caller_data_is_receipt_only_but_durable_fault_stops_service() {
        let (response, receipt) = std::sync::mpsc::channel();
        assert!(complete_local_vertex_admission(
            Err(VertexAdmissionFailure::Rejected("closed".into())),
            response
        )
        .is_ok());
        assert_eq!(receipt.recv().unwrap(), Err("closed".into()));
        let (response, receipt) = std::sync::mpsc::channel();
        assert_eq!(
            complete_local_vertex_admission(
                Err(VertexAdmissionFailure::Safety("disk failure".into())),
                response
            ),
            Err("disk failure".into())
        );
        assert_eq!(receipt.recv().unwrap(), Err("disk failure".into()));
        let (response, receipt) = std::sync::mpsc::channel();
        complete_local_vertex_admission(Ok(()), response).unwrap();
        assert_eq!(receipt.recv().unwrap(), Ok(()));
    }
    #[test]
    fn persistence_classification_uses_typed_errors_not_message_text() {
        assert!(matches!(
            classify_vertex_persistence(EtdagError::Storage("closed".into())),
            VertexAdmissionFailure::Safety(_)
        ));
        assert!(matches!(
            classify_vertex_persistence(EtdagError::Corrupt("bad encoding".into())),
            VertexAdmissionFailure::Safety(_)
        ));
        assert!(matches!(
            classify_vertex_persistence(EtdagError::UnknownParent("disk failure".into())),
            VertexAdmissionFailure::Rejected(_)
        ));
        assert!(matches!(
            classify_vertex_persistence(EtdagError::InvalidCapacity),
            VertexAdmissionFailure::Rejected(_)
        ));
    }
}

#[cfg(test)]
mod admission_scheduling_tests {
    use super::{cacheable_context_target, next_admission_dispatch_turn};
    use crate::services::preparation::{AuthorityTag, Lane, Pool};
    use std::time::{Duration, Instant};

    #[test]
    fn cached_newest_two_never_regenerate_evicted_open_contexts() {
        assert_eq!(
            cacheable_context_target(&[12, 11, 10, 9], |height| height >= 11),
            None
        );
        assert_eq!(
            cacheable_context_target(&[13, 12, 11, 10], |height| height == 12),
            Some(13)
        );
    }

    #[test]
    fn full_context_completion_cannot_recapture_lane_ahead_of_waiting_wallet() {
        let mut pool = Pool::new().unwrap();
        let tag = AuthorityTag {
            incarnation: "scheduling-regression".into(),
            epoch: 1,
            authority_digest: "authority".into(),
        };
        let context = pool.handle().owner::<u64>(tag.clone()).unwrap();
        let wallet = pool.handle().owner::<u64>(tag).unwrap();
        context
            .submit(
                Lane::Admission,
                1,
                0,
                8,
                "context".into(),
                8 * 1024 * 1024,
                || Ok(1),
            )
            .unwrap();
        let mut turn = next_admission_dispatch_turn(true, true, false);
        // Adversarially poll many times while the completed context mailbox
        // still holds all8MiB. Priority must remain wallet-first, not toggle.
        for _ in 0..17 {
            assert_eq!(
                wallet
                    .submit(Lane::Admission, 1, 0, 8, "wallet".into(), 1, || Ok(2))
                    .unwrap_err(),
                "preparation backpressure"
            );
            turn = next_admission_dispatch_turn(turn, false, false);
            assert!(!turn);
        }
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            if let Some(completion) = context.take().unwrap() {
                drop(completion);
                break;
            }
            assert!(Instant::now() < deadline);
            std::thread::yield_now();
        }
        // The old context-first loop would immediately reserve all8MiB again.
        // The held wallet turn instead commits dispatch before refresh.
        wallet
            .submit(Lane::Admission, 1, 0, 8, "wallet".into(), 1, || Ok(2))
            .unwrap();
        assert_eq!(
            context
                .submit(
                    Lane::Admission,
                    2,
                    0,
                    9,
                    "new-context".into(),
                    8 * 1024 * 1024,
                    || Ok(3)
                )
                .unwrap_err(),
            "preparation backpressure"
        );
        turn = next_admission_dispatch_turn(turn, false, true);
        assert!(turn);
        // Reverse load cannot rotate away the context's next opportunity.
        for _ in 0..17 {
            turn = next_admission_dispatch_turn(turn, false, false);
            assert!(turn);
        }
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            if let Some(completion) = wallet.take().unwrap() {
                drop(completion);
                break;
            }
            assert!(Instant::now() < deadline);
            std::thread::yield_now();
        }
        context
            .submit(
                Lane::Admission,
                2,
                0,
                9,
                "new-context".into(),
                8 * 1024 * 1024,
                || Ok(3),
            )
            .unwrap();
        assert!(!next_admission_dispatch_turn(turn, true, false));
        context.cancel();
        wallet.cancel();
        pool.shutdown().unwrap();
    }
}

#[cfg(test)]
mod marker_cache_tests {
    use super::*;
    #[test]
    fn historical_payloads_retire_but_equivocation_checks_survive() {
        let root = |round: usize| {
            EtdagDigest::from_domain_bytes("marker-cache-test", &round.to_le_bytes())
        };
        let make = |round, signer| ProtectedCutMarker {
            marker_version: 1,
            context_root: root(0),
            target_height: 5,
            cutoff_context_root: root(round),
            frontier: vec![],
            validator_id: format!("validator-{signer}"),
            key_id: format!("key-{signer}"),
            signature: vec![1; 16 * 1024],
        };
        let mut cache = CutMarkerCache::default();
        for round in 0..=4096 {
            for signer in 0..5 {
                cache.remember(make(round, signer), &root(round)).unwrap();
            }
            assert_eq!(cache.payloads.len(), 5);
            assert!(cache
                .payloads
                .values()
                .all(|m| m.cutoff_context_root == root(round)));
        }
        assert_eq!(cache.fingerprints.len(), 4097 * 5);
        cache.remember(make(0, 0), &root(4096)).unwrap();
        assert_eq!(cache.payloads.len(), 5);
        let mut conflict = make(0, 0);
        conflict.frontier.push(root(99));
        assert!(cache
            .remember(conflict, &root(4096))
            .unwrap_err()
            .contains("equivocated"));
        assert_eq!(cache.payloads.len(), 5);
        let mut equivalent_signature = make(4096, 0);
        equivalent_signature.signature[0] = 2;
        cache.remember(equivalent_signature, &root(4096)).unwrap();
        assert_eq!(cache.payloads.len(), 5);
    }
}

#[cfg(test)]
mod bounded_retry_tests {
    use super::{deliver_retry_slice, MAX_MESSAGES_PER_POLL};

    #[test]
    fn many_payloads_and_peers_copy_only_attempted_bounded_slice() {
        let payloads = (0u32..4096).map(|id| id.to_le_bytes()).collect::<Vec<_>>();
        let peers = (0..31)
            .map(|id| format!("peer-{id:02}"))
            .collect::<Vec<_>>();
        let mut cursor = 0;
        let mut copied = Vec::new();
        assert!(deliver_retry_slice(
            payloads.iter().map(|p| p.as_slice()),
            peers.iter().map(String::as_str),
            &mut cursor,
            |peer, payload| {
                copied.push((peer.to_owned(), payload.to_vec()));
                Ok(true)
            },
        )
        .unwrap());
        assert_eq!(copied.len(), MAX_MESSAGES_PER_POLL);
        assert_eq!(cursor, MAX_MESSAGES_PER_POLL);
        for (index, (peer, payload)) in copied.iter().enumerate() {
            assert_eq!(peer, &peers[index % peers.len()]);
            assert_eq!(payload.as_slice(), payloads[index / peers.len()].as_slice());
        }
    }

    #[test]
    fn backpressure_retries_exact_pair_and_wraps_without_skipping() {
        let payloads = [b"first".as_slice(), b"second".as_slice()];
        let peers = ["a", "b", "c"];
        let mut cursor = 5;
        let mut attempted = Vec::new();
        let mut run = |cursor: &mut usize, accept: usize| {
            let mut calls = 0;
            deliver_retry_slice(
                payloads.into_iter(),
                peers.into_iter(),
                cursor,
                |peer, payload| {
                    attempted.push((peer.to_owned(), payload.to_vec()));
                    calls += 1;
                    Ok(calls <= accept)
                },
            )
            .unwrap()
        };
        assert!(!run(&mut cursor, 2));
        assert_eq!(cursor, 1);
        assert!(!run(&mut cursor, 0));
        assert_eq!(cursor, 1);
        assert!(run(&mut cursor, 6));
        assert_eq!(cursor, 1);
        assert_eq!(attempted[0], ("c".into(), b"second".to_vec()));
        assert_eq!(attempted[1], ("a".into(), b"first".to_vec()));
        assert_eq!(attempted[2], attempted[3]);
        assert_eq!(attempted[3], attempted[4]);
        let successful_round = &attempted[4..];
        assert_eq!(successful_round.len(), 6);
        assert_eq!(successful_round[0], ("b".into(), b"first".to_vec()));
        assert_eq!(successful_round[5], ("a".into(), b"first".to_vec()));
    }

    #[test]
    fn empty_retry_set_and_publish_error_preserve_cursor() {
        let mut cursor = 19;
        assert!(!deliver_retry_slice(
            std::iter::empty(),
            ["peer"].into_iter(),
            &mut cursor,
            |_, _| panic!("empty retry set must not publish")
        )
        .unwrap());
        assert_eq!(cursor, 19);
        assert!(deliver_retry_slice(
            [b"original".as_slice()].into_iter(),
            ["peer"].into_iter(),
            &mut cursor,
            |_, _| Err("queue unavailable".into())
        )
        .is_err());
        assert_eq!(cursor, 19);
    }
}

#[cfg(test)]
mod resource_budget_tests {
    use super::*;
    use crate::services::posy::qualification::Fleet;

    fn sign(fleet: &Fleet, index: usize, bytes: &[u8]) -> Vec<u8> {
        let key = KeyId::new(format!("key-{index}")).unwrap();
        PqvmSigner::from_secret_key_bytes(
            AegisPolicy {
                allowed_algorithms: vec![SignatureAlgorithm::MlDsa65],
                maximum_message_bytes: 1024 * 1024,
                maximum_signature_bytes: 16 * 1024,
            },
            key.clone(),
            fleet.secrets[index].clone(),
        )
        .unwrap()
        .sign(
            &key,
            &SigningContext {
                domain: "SYNERGY-ETDAG-SIGNATURE-V1".into(),
                chain_id: 1266,
                epoch: Some(1),
                height: None,
            },
            bytes,
        )
        .unwrap()
        .bytes
    }

    fn maximum_vertex(
        fleet: &Fleet,
        context: &TargetAdmissionContextV3,
        nonce: u64,
    ) -> TransactionVertex {
        let digest =
            |label: &str| EtdagDigest::from_domain_bytes("resource-budget-test", label.as_bytes());
        let root = context.root().unwrap();
        let mut envelope = EncryptedTransactionEnvelope {
            envelope_version: 2,
            envelope_id: digest("pending"),
            target_context_root: root.clone(),
            target_height: context.target_height,
            aad: synergy_etdag::EnvelopeAad {
                profile_id: synergy_etdag::ETDAG_EXPERIMENTAL_PROFILE_ID.into(),
                chain_id: context.chain_id,
                network_id: context.network_id.clone(),
                protocol_version: context.protocol_version.clone(),
                epoch: context.epoch,
                target_height: context.target_height,
                target_context_root: root.clone(),
                assigned_cluster_id: context.assigned_cluster_id,
                lane_id: "ordinary-user".into(),
                sender_id: "resource-wallet".into(),
                nonce_slot: nonce,
            },
            aead_nonce: [0; 12],
            key_commitment: digest("key"),
            share_commitment_root: digest("pending"),
            share_capsule_root: digest("pending"),
            ciphertext: vec![42; 131072],
            content_blind_order_key: digest(&format!("order-{nonce}")),
            share_capsules: (0..5)
                .map(|index| synergy_etdag::ShareCapsule {
                    validator_id: format!("qualification-{index}"),
                    ingress_kem_key_id: format!("ingress-{index}"),
                    share_index: index + 1,
                    share_commitment: digest(&format!("share-{index}")),
                    kem_ciphertext: vec![1; synergy_etdag::crypto::ML_KEM_1024_CIPHERTEXT_BYTES],
                    aead_nonce: [0; 12],
                    encrypted_share: vec![2; 48],
                })
                .collect(),
        };
        envelope.refresh_capsule_roots().unwrap();
        envelope.envelope_id = synergy_etdag::envelope_commitment(&envelope).unwrap();
        let mut vertex = TransactionVertex {
            vertex_id: digest("pending"),
            target_context_root: root,
            target_height: context.target_height,
            envelope_ref: synergy_etdag::CertifiedEnvelopeRef {
                tx_commitment: envelope.envelope_id.clone(),
                sender_id: envelope.aad.sender_id.clone(),
                nonce_slot: nonce,
                certified_dag_round: 0,
                gas_class_units: 21000,
                ciphertext_bytes: 131072,
                fee_class: 1,
                protocol_dependencies: vec![],
            },
            envelope,
            parents: vec![],
            author_id: "qualification-0".into(),
            author_signature: vec![],
            wallet_admission: None,
        };
        vertex.vertex_id = synergy_etdag::dag::derive_vertex_id(&vertex).unwrap();
        vertex.author_signature = sign(fleet, 0, vertex.vertex_id.0.as_bytes());
        vertex
    }

    #[test]
    fn maximum_ciphertext_many_targets_reserve_quorum_completion_before_pressure() {
        let fleet = Fleet::new();
        let members = fleet
            .authority
            .registry
            .active()
            .map(|v| {
                (
                    v.validator_id.clone(),
                    (
                        v.consensus_key_id.clone(),
                        u64::try_from(v.frozen_voting_weight).unwrap(),
                    ),
                )
            })
            .collect::<CutoffMembers>();
        let parameters = EtdagParameters {
            profile_id: synergy_etdag::ETDAG_EXPERIMENTAL_PROFILE_ID.into(),
            target_height_offset: 16,
            ..EtdagParameters::default()
        };
        let mut context = crate::services::etdag_qualification::context(&fleet);
        context.target_height_offset = 16;
        let mut ledger = LiveEtdagResources::new(&members, 16, &context).unwrap();
        let base = ledger.total_with(None);
        let mut accepted = Vec::new();
        let mut pressured = false;
        for height in 3..=16 {
            context.target_height = height;
            let vertex = maximum_vertex(&fleet, &context, height);
            let charge = ledger.reservation(
                ProtectedPipeline::vertex_resource_bytes(&vertex).unwrap(),
                encoded_resource_bytes(&vertex).unwrap(),
                encoded_resource_bytes(&vertex.envelope_ref).unwrap(),
                ledger.share_wire(&vertex.envelope),
                vertex.envelope.ciphertext.len(),
            );
            match ledger.reserve(height, &vertex.envelope.envelope_id, charge) {
                Ok(()) => {
                    let mut owner = ProtectedPipeline::open_collecting(
                        fleet.root.join(format!("resource-{height}")),
                        context.clone(),
                        parameters.clone(),
                        "qualification-0".into(),
                        &members,
                        fleet.authority.as_ref(),
                    )
                    .unwrap();
                    owner.set_transition_resource_budget(ETDAG_TRANSITION_SCRATCH_BYTES);
                    owner
                        .persist_vertex(vertex.clone(), &members, fleet.authority.as_ref())
                        .unwrap();
                    accepted.push((owner, vertex, charge));
                }
                Err(EtdagError::ResourcePressure(_)) => {
                    pressured = true;
                    break;
                }
                Err(error) => panic!("unexpected admission failure: {error:?}"),
            }
        }
        assert!(pressured && !accepted.is_empty());
        assert!(ledger.total_with(None) <= LIVE_ETDAG_RESERVATION_BYTES);
        let exhausted = ledger.total_with(None);
        // Reservation is retained while native votes/certificates complete: no
        // new budget demand or capacity release merely because collection closes.
        for (owner, vertex, charge) in &mut accepted {
            let mut votes = Vec::new();
            for index in 0..5 {
                let mut vote = AvailabilityVote {
                    context_root: vertex.target_context_root.clone(),
                    vertex_id: vertex.vertex_id.clone(),
                    validator_id: format!("qualification-{index}"),
                    key_id: format!("key-{index}"),
                    signature: vec![],
                };
                let bytes = canonical_signing_bytes(
                    "SYNERGY_ETDAG_AVAILABILITY_VOTE_V1",
                    &(
                        &vote.context_root,
                        &vote.vertex_id,
                        &vote.validator_id,
                        &vote.key_id,
                    ),
                )
                .unwrap();
                vote.signature = sign(&fleet, index, &bytes);
                assert_eq!(
                    vote.signature.len(),
                    aegis_pqvm::pqc::signatures::mldsa::mldsa65::signature_bytes()
                );
                if index == 0 {
                    owner
                        .persist_local_vote(vote.clone(), &members, fleet.authority.as_ref())
                        .unwrap();
                } else {
                    owner
                        .persist_vote(vote.clone(), &members, fleet.authority.as_ref())
                        .unwrap();
                }
                votes.push(vote);
            }
            let certificate = owner
                .assembled_availability(&vertex.vertex_id, &members, fleet.authority.as_ref())
                .unwrap();
            owner
                .persist_availability(certificate.clone(), &members, fleet.authority.as_ref())
                .unwrap();
            assert_eq!(owner.availability().len(), 1);
            assert!(owner.collecting_resource_bytes().saturating_mul(2) < charge.retained);
            assert!(ProtectedPipeline::certificate_resource_bytes(&certificate) < charge.retained);
            // Exact original retry bytes survive a completely stalled16-slot queue.
            let original = serde_json::to_vec(vertex).unwrap();
            let ingress = AuthenticatedIngress::default();
            for _ in 0..ETDAG_OUTBOUND_SLOTS {
                assert!(ingress
                    .try_publish_outbound(OutboundFrame {
                        peer_id: "qualification-1".into(),
                        protocol: ProtocolKind::Etdag,
                        payload: original.clone()
                    })
                    .unwrap());
            }
            assert!(!ingress
                .try_publish_outbound(OutboundFrame {
                    peer_id: "qualification-1".into(),
                    protocol: ProtocolKind::Etdag,
                    payload: original.clone()
                })
                .unwrap());
            for _ in 0..ETDAG_OUTBOUND_SLOTS {
                assert_eq!(ingress.take_outbound().unwrap().unwrap().payload, original);
            }
        }
        assert_eq!(ledger.total_with(None), exhausted);
        ledger.retire(2);
        assert_eq!(ledger.total_with(None), exhausted);
        ledger.retire(16);
        assert_eq!(ledger.total_with(None), base);
    }

    #[test]
    fn same_target_maximum_vertices_complete_native_cut_after_phase_pressure() {
        let fleet = Fleet::new();
        let mut context = crate::services::etdag_qualification::context(&fleet);
        context.target_height_offset = 16;
        let members = fleet
            .authority
            .registry
            .active()
            .map(|v| (v.validator_id.clone(), (v.consensus_key_id.clone(), 1)))
            .collect::<CutoffMembers>();
        let mut ledger = LiveEtdagResources::new(&members, 16, &context).unwrap();
        let mut owner = ProtectedPipeline::open_collecting(
            fleet.root.join("same-target-resources"),
            context.clone(),
            EtdagParameters {
                profile_id: synergy_etdag::ETDAG_EXPERIMENTAL_PROFILE_ID.into(),
                target_height_offset: 16,
                ..EtdagParameters::default()
            },
            "qualification-0".into(),
            &members,
            fleet.authority.as_ref(),
        )
        .unwrap();
        owner.set_transition_resource_budget(ETDAG_TRANSITION_SCRATCH_BYTES);
        let mut accepted = Vec::new();
        let mut phase_pressure = false;
        for nonce in 0..64 {
            let vertex = maximum_vertex(&fleet, &context, nonce);
            let charge = ledger.reservation(
                ProtectedPipeline::vertex_resource_bytes(&vertex).unwrap(),
                encoded_resource_bytes(&vertex).unwrap(),
                encoded_resource_bytes(&vertex.envelope_ref).unwrap(),
                ledger.share_wire(&vertex.envelope),
                vertex.envelope.ciphertext.len(),
            );
            match ledger.reserve(context.target_height, &vertex.envelope.envelope_id, charge) {
                Ok(()) => {
                    owner
                        .persist_vertex(vertex.clone(), &members, fleet.authority.as_ref())
                        .unwrap();
                    accepted.push(vertex);
                }
                Err(EtdagError::ResourcePressure(reason)) => {
                    phase_pressure = reason.contains("transition completion pressure");
                    break;
                }
                Err(error) => panic!("unexpected resource failure: {error:?}"),
            }
        }
        assert!(
            phase_pressure,
            "{}",
            ledger.intake_pressure.as_deref().unwrap_or("no pressure")
        );
        assert!(accepted.len() > 1);
        let reserved = ledger.total_with(None);
        let mut certificates = BTreeMap::new();
        for vertex in &accepted {
            let mut votes = Vec::new();
            for index in 0..5 {
                let mut vote = AvailabilityVote {
                    context_root: vertex.target_context_root.clone(),
                    vertex_id: vertex.vertex_id.clone(),
                    validator_id: format!("qualification-{index}"),
                    key_id: format!("key-{index}"),
                    signature: vec![],
                };
                vote.signature = sign(
                    &fleet,
                    index,
                    &canonical_signing_bytes(
                        "SYNERGY_ETDAG_AVAILABILITY_VOTE_V1",
                        &(
                            &vote.context_root,
                            &vote.vertex_id,
                            &vote.validator_id,
                            &vote.key_id,
                        ),
                    )
                    .unwrap(),
                );
                if index == 0 {
                    owner
                        .persist_local_vote(vote.clone(), &members, fleet.authority.as_ref())
                        .unwrap();
                } else {
                    owner
                        .persist_vote(vote.clone(), &members, fleet.authority.as_ref())
                        .unwrap();
                }
                votes.push(vote);
            }
            let certificate = AvailabilityCertificate::from_votes(
                vertex.target_context_root.clone(),
                vertex.vertex_id.clone(),
                votes,
                5,
            )
            .unwrap();
            owner
                .persist_availability(certificate.clone(), &members, fleet.authority.as_ref())
                .unwrap();
            certificates.insert(vertex.vertex_id.clone(), certificate);
        }
        let cutoff = EtdagDigest::from_domain_bytes("resource-budget-test", b"same-target-cutoff");
        owner.bind_cutoff(cutoff.clone()).unwrap();
        let mut frontier = accepted
            .iter()
            .map(|v| v.vertex_id.clone())
            .collect::<Vec<_>>();
        frontier.sort();
        let markers = (0..5)
            .map(|index| {
                let mut marker = ProtectedCutMarker {
                    marker_version: 1,
                    context_root: context.root().unwrap(),
                    target_height: context.target_height,
                    cutoff_context_root: cutoff.clone(),
                    frontier: frontier.clone(),
                    validator_id: format!("qualification-{index}"),
                    key_id: format!("key-{index}"),
                    signature: vec![],
                };
                marker.signature = sign(&fleet, index, &marker.signing_bytes().unwrap());
                marker
            })
            .collect::<Vec<_>>();
        owner
            .persist_local_marker(markers[0].clone(), &members, fleet.authority.as_ref())
            .unwrap();
        let graph = owner.graph().clone();
        assert!(owner
            .accept_cut(
                &markers,
                &graph,
                &certificates,
                &members,
                fleet.authority.as_ref()
            )
            .unwrap());
        assert_eq!(
            owner.batch().unwrap().ordered_transaction_ids.len(),
            accepted.len()
        );
        assert_eq!(ledger.total_with(None), reserved);
    }

    #[test]
    fn rejected_undurable_reservations_restore_previous_pool_and_frame_maximum() {
        let fleet = Fleet::new();
        let mut context = crate::services::etdag_qualification::context(&fleet);
        context.target_height_offset = 16;
        let members = fleet
            .authority
            .registry
            .active()
            .map(|v| (v.validator_id.clone(), (v.consensus_key_id.clone(), 1)))
            .collect();
        let mut ledger = LiveEtdagResources::new(&members, 16, &context).unwrap();
        assert_eq!(
            ML_DSA_65_SIGNATURE_BYTES,
            aegis_pqvm::pqc::signatures::mldsa::mldsa65::signature_bytes()
        );
        let baseline = ledger.total_with(None);
        for nonce in 0..64 {
            let vertex = maximum_vertex(&fleet, &context, nonce);
            let charge = ledger.reservation(
                ProtectedPipeline::vertex_resource_bytes(&vertex).unwrap(),
                encoded_resource_bytes(&vertex).unwrap(),
                encoded_resource_bytes(&vertex.envelope_ref).unwrap(),
                ledger.share_wire(&vertex.envelope),
                vertex.envelope.ciphertext.len(),
            );
            ledger
                .reserve(3, &vertex.envelope.envelope_id, charge)
                .unwrap();
            ledger.restore_uncommitted(3, vertex.envelope.envelope_id, None);
            assert_eq!(ledger.total_with(None), baseline);
            assert!(ledger.vertices.is_empty());
        }
        let envelope = EtdagDigest::from_domain_bytes("reservation", b"prior");
        let previous = VertexResourceReservation {
            retained: 4096,
            largest_frame: 16384,
            collecting_encoded: 1024,
            transition_bytes: 8192,
        };
        ledger.reserve(3, &envelope, previous).unwrap();
        let before = ledger.total_with(None);
        ledger
            .reserve(
                3,
                &envelope,
                VertexResourceReservation {
                    retained: 8192,
                    largest_frame: 131072,
                    ..previous
                },
            )
            .unwrap();
        ledger.restore_uncommitted(3, envelope, Some(previous));
        assert_eq!(ledger.total_with(None), before);
    }

    #[test]
    fn phase_reservation_counts_exact_cut_reference_and_variable_dependencies() {
        let fleet = Fleet::new();
        let mut context = crate::services::etdag_qualification::context(&fleet);
        context.target_height_offset = 16;
        let vertex = maximum_vertex(&fleet, &context, 1);
        let members = fleet
            .authority
            .registry
            .active()
            .map(|v| (v.validator_id.clone(), (v.consensus_key_id.clone(), 1)))
            .collect();
        let ledger = LiveEtdagResources::new(&members, 16, &context).unwrap();
        let encoded = encoded_resource_bytes(&vertex).unwrap();
        let reference = encoded_resource_bytes(&vertex.envelope_ref).unwrap();
        assert!(encoded > reference * 100);
        let deep = ProtectedPipeline::vertex_resource_bytes(&vertex).unwrap();
        let exact = ledger.reservation(
            deep,
            encoded,
            reference,
            ledger.share_wire(&vertex.envelope),
            131072,
        );
        let duplicated = ledger.reservation(
            deep,
            encoded,
            encoded,
            ledger.share_wire(&vertex.envelope),
            131072,
        );
        assert_eq!(
            duplicated.transition_bytes - exact.transition_bytes,
            8 * (encoded - reference)
        );
        let mut extended = vertex.envelope_ref.clone();
        extended.protocol_dependencies = (0u64..4096)
            .map(|i| EtdagDigest::from_domain_bytes("resource-reference", &i.to_le_bytes()))
            .collect();
        let extended_bytes = encoded_resource_bytes(&extended).unwrap();
        let extended_charge = ledger.reservation(
            deep,
            encoded,
            extended_bytes,
            ledger.share_wire(&vertex.envelope),
            131072,
        );
        assert_eq!(
            extended_charge.transition_bytes - exact.transition_bytes,
            8 * (extended_bytes - reference)
        );
        assert_eq!(extended_charge.retained, exact.retained);

        // Check the independent wire estimator against real typed canonical
        // shares, including every frozen member and escaped capsule key ID.
        let digest = EtdagDigest("f".repeat(128));
        let authorization = synergy_etdag::ProtectedRevealAuthorization {
            authorization_version: 1,
            context_root: digest.clone(),
            target_height: u64::MAX,
            protected_batch_root: digest.clone(),
            finality_reference: digest.clone(),
        };
        let canonical_share = synergy_etdag::crypto::ShamirShare {
            index: u8::MAX,
            value: vec![u8::MAX; 32],
        }
        .canonical_bytes()
        .unwrap();
        assert!(canonical_share.len() <= 160);
        let mut envelope = vertex.envelope.clone();
        for capsule in &mut envelope.share_capsules {
            capsule.ingress_kem_key_id.push_str("\"\\\n");
        }
        let mut shares = Vec::new();
        for capsule in &envelope.share_capsules {
            let (key, _) = members.get(&capsule.validator_id).unwrap();
            shares.push(DecryptShareMessage {
                share_version: 2,
                authorization: authorization.clone(),
                envelope_id: digest.clone(),
                validator_id: capsule.validator_id.clone(),
                key_id: key.clone(),
                ingress_kem_key_id: capsule.ingress_kem_key_id.clone(),
                share_index: u8::MAX,
                share_commitment: digest.clone(),
                encrypted_share: canonical_share.clone(),
                signature: vec![u8::MAX; ML_DSA_65_SIGNATURE_BYTES],
            });
        }
        let transcript = RevealTranscript {
            transcript_version: 1,
            authorization,
            shares,
        };
        assert!(encoded_resource_bytes(&transcript).unwrap() <= ledger.share_wire(&envelope));
        assert!(ledger.share_wire(&envelope) < ledger.share_bytes.saturating_mul(4));
    }

    #[test]
    fn spare_payload_capacities_and_existing_reservation_upgrade_are_charged() {
        let fleet = Fleet::new();
        let mut context = crate::services::etdag_qualification::context(&fleet);
        context.target_height_offset = 16;
        let vertex = maximum_vertex(&fleet, &context, 1);
        let mut inflated = vertex.clone();
        inflated.envelope.ciphertext.reserve_exact(4 * 1024 * 1024);
        inflated.author_id.reserve_exact(1024 * 1024);
        assert_eq!(vertex, inflated);
        assert!(
            ProtectedPipeline::vertex_resource_bytes(&inflated).unwrap()
                > ProtectedPipeline::vertex_resource_bytes(&vertex).unwrap() + 4 * 1024 * 1024
        );
        let members = fleet
            .authority
            .registry
            .active()
            .map(|v| (v.validator_id.clone(), (v.consensus_key_id.clone(), 1)))
            .collect();
        let mut ledger = LiveEtdagResources::new(&members, 16, &context).unwrap();
        let charge = ledger.reservation(
            ProtectedPipeline::vertex_resource_bytes(&vertex).unwrap(),
            encoded_resource_bytes(&vertex).unwrap(),
            encoded_resource_bytes(&vertex.envelope_ref).unwrap(),
            ledger.share_wire(&vertex.envelope),
            131072,
        );
        ledger
            .reserve(3, &vertex.envelope.envelope_id, charge)
            .unwrap();
        let before = ledger.total_with(None);
        let encoded_upgrade = VertexResourceReservation {
            collecting_encoded: 16 * 1024 * 1024,
            ..charge
        };
        assert!(matches!(
            ledger.reserve(3, &vertex.envelope.envelope_id, encoded_upgrade),
            Err(EtdagError::ResourcePressure(_))
        ));
        assert_eq!(ledger.total_with(None), before);
        assert_eq!(
            ledger.vertices[&(3, vertex.envelope.envelope_id.clone())].collecting_encoded,
            charge.collecting_encoded
        );
        let phase_upgrade = VertexResourceReservation {
            transition_bytes: ETDAG_TRANSITION_SCRATCH_BYTES,
            ..charge
        };
        assert!(matches!(
            ledger.reserve(3, &vertex.envelope.envelope_id, phase_upgrade),
            Err(EtdagError::ResourcePressure(_))
        ));
        assert_eq!(ledger.total_with(None), before);
        let huge = ledger.reservation(
            ProtectedPipeline::vertex_resource_bytes(&inflated).unwrap(),
            encoded_resource_bytes(&inflated).unwrap(),
            encoded_resource_bytes(&inflated.envelope_ref).unwrap(),
            ledger.share_wire(&inflated.envelope),
            131072,
        );
        assert!(matches!(
            ledger.reserve(3, &vertex.envelope.envelope_id, huge),
            Err(EtdagError::ResourcePressure(_))
        ));
        assert_eq!(ledger.total_with(None), before);
        assert!(ledger.intake_pressure.is_some());
        assert!(
            ledger.pressure.is_none(),
            "prospective intake must not poison node readiness"
        );
        assert!(matches!(
            classify_vertex_persistence(EtdagError::ResourcePressure("capacity".into())),
            VertexAdmissionFailure::ResourcePressure(_)
        ));
    }

    #[test]
    fn shared_history_pool_retries_exclude_own_reservation_and_retire_exact_heights() {
        let fleet = Fleet::new();
        let mut context = crate::services::etdag_qualification::context(&fleet);
        context.target_height_offset = 16;
        let members = fleet
            .authority
            .registry
            .active()
            .map(|v| (v.validator_id.clone(), (v.consensus_key_id.clone(), 1)))
            .collect();
        let mut ledger = LiveEtdagResources::new(&members, 16, &context).unwrap();
        let baseline = ledger.total_with(None);
        let available = ledger.history_limit(3);
        let first = available / 2;
        ledger.reserve_history(3, first).unwrap();
        let second = ledger.history_limit(4);
        ledger.reserve_history(4, second).unwrap();
        assert_eq!(ledger.total_with(None), LIVE_ETDAG_RESERVATION_BYTES);
        // A staged owner must be able to retry at its current charge even when
        // another owner has filled every other byte of the shared pool.
        ledger.reserve_history(3, first).unwrap();
        ledger.reserve_history(4, second).unwrap();
        let prior = ledger.history_bytes.clone();
        assert!(matches!(
            ledger.reserve_history(3, first + 1),
            Err(EtdagError::ResourcePressure(_))
        ));
        assert_eq!(ledger.history_bytes, prior);
        assert!(ledger.retire(3));
        assert!(!ledger.history_bytes.contains_key(&3));
        assert_eq!(ledger.history_bytes.get(&4), Some(&second));
        ledger.reserve_history(4, available).unwrap();
        ledger.reserve_history(4, 0).unwrap();
        assert_eq!(ledger.total_with(None), baseline);
        ledger.reserve_history(5, available).unwrap();
        assert!(!ledger.retire(4));
        assert_eq!(ledger.history_bytes.get(&5), Some(&available));
        assert!(ledger.retire(5));
        assert_eq!(ledger.total_with(None), baseline);
    }
}
