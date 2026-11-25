//! Read-only transport of existing commitments, without a new state-root format.
use super::*;
use serde::{Deserialize, Serialize};
use synergy_address_engine::apqe::{HashAlgorithm, HashStream, Primitives};
use crate::services::protected_accounts::{PublicWalletRecords, validate_public_wallet_record};

#[path = "rpc_public_processing.rs"]
mod public_processing;
#[path = "rpc_public_ethereum.rs"]
mod public_ethereum;

const MAX_PAGE: usize = 64 * 1024;
// A proof is a bounded transport of the existing commitment preimage, not a
// claim of a Merkle path for the current flat canonical state hash.
pub(super) const MAX_DOCUMENT: usize = 1024 * 1024;
// Streaming disclosure validation retains only one entry, not an entire typed
// table. Charge parser scratch plus page/base64/JSON response simultaneously.
pub(crate) const PROOF_SCRATCH: usize = MAX_DOCUMENT * 2 + MAX_PAGE * 4;

#[derive(Default)]
pub(super) struct ProofThrottle {
    window: Option<Instant>,
    requests: u32,
}
impl ProofThrottle {
    pub fn admit(&mut self) -> Result<(), RpcError> {
        let now = Instant::now();
        if self
            .window
            .is_none_or(|at| now.duration_since(at) >= Duration::from_secs(1))
        {
            self.window = Some(now);
            self.requests = 0;
        }
        if self.requests >= 4 {
            return Err(RpcError::unavailable(
                "proof verification capacity exhausted; retry later",
            ));
        }
        self.requests += 1;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum ProofKind {
    BlockCommitment,
    WorldState,
    Finality,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProofQuery {
    pub height: u64,
    pub kind: ProofKind,
    #[serde(default)]
    pub offset: usize,
    #[serde(default = "page_limit")]
    pub limit: usize,
    #[serde(default)]
    pub expected_sha256: Option<String>,
}
fn page_limit() -> usize {
    MAX_PAGE
}
impl ProofQuery {
    pub fn decode(value: Value) -> Result<Self, RpcError> {
        let query: Self = decode_params(value)?;
        if query.height == 0
            || query.limit == 0
            || query.limit > MAX_PAGE
            || query.offset > MAX_DOCUMENT
            || query.offset.checked_add(query.limit).is_none()
            || query.offset > 0 && query.expected_sha256.is_none()
            || query.expected_sha256.as_ref().is_some_and(|pin| {
                pin.len() != 64
                    || !pin
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            })
        {
            return Err(RpcError::invalid_params(
                "invalid bounded/pinned proof page query",
            ));
        }
        Ok(query)
    }
}

struct PageWriter {
    offset: usize,
    limit: usize,
    total: usize,
    bytes: Vec<u8>,
    hash: HashStream,
}
impl PageWriter {
    fn new(offset: usize, limit: usize) -> Result<Self, String> {
        Ok(Self {
            offset,
            limit,
            total: 0,
            bytes: Vec::with_capacity(limit),
            hash: Primitives
                .hash_stream(HashAlgorithm::Sha256)
                .map_err(|error| format!("APQE disclosure digest unavailable: {error:?}"))?,
        })
    }
}
impl Write for PageWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let end = self
            .total
            .checked_add(bytes.len())
            .filter(|end| *end <= MAX_DOCUMENT)
            .ok_or_else(|| std::io::Error::other("proof document exceeds 1 MiB"))?;
        let first = self.offset.max(self.total);
        let last = (self.offset + self.limit).min(end);
        if first < last {
            self.bytes
                .extend_from_slice(&bytes[first - self.total..last - self.total]);
        }
        self.hash.update(bytes);
        self.total = end;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

// Preflight typed evidence before allocating an owned JSON Value. This writer
// retains no document bytes and enforces the same complete-document ceiling.
pub(crate) fn bounded_document(value: &impl Serialize) -> Result<(), String> {
    let mut writer = PageWriter::new(0, 0)?;
    serde_json::to_writer(&mut writer, value).map_err(|error| error.to_string())
}

pub(super) fn page(query: &ProofQuery, value: &impl Serialize) -> Result<Value, RpcError> {
    let mut output = PageWriter::new(query.offset, query.limit).map_err(RpcError::unavailable)?;
    serde_json::to_writer(&mut output, value)
        .map_err(|error| RpcError::unavailable(format!("serialize proof evidence: {error}")))?;
    if query.offset >= output.total {
        return Err(RpcError::invalid_params("proof offset outside document"));
    }
    let digest: String = output
        .hash
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    if query
        .expected_sha256
        .as_ref()
        .is_some_and(|expected| expected != &digest)
    {
        return Err(RpcError::unavailable(
            "proof document differs from pinned digest",
        ));
    }
    let end = query.offset + output.bytes.len();
    Ok(json!({"version":1,"height":query.height,"kind":query.kind,
        "encoding":"base64","bytes_base64":BASE64.encode(&output.bytes),
        "sha256":digest,"total_bytes":output.total,"offset":query.offset,
        "next_offset":if end < output.total { Some(end) } else { None },
        "authentication":"verify complete original bytes against independently authenticated PoSy commitments"}))
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ClientFinalityEvidence {
    version: u8,
    finalized: synergy_posy::FinalizedBlockRecord,
    witness: synergy_posy::FinalitySyncWitness,
}

struct VerifiedFinalityProof {
    record: FinalizedBlockRecord,
    parent_block_id: String,
    following_block_id: String,
}

/// Verify against caller-selected authenticated history, never a public key or
/// authority selected by the proof. The returned record is what clients match
/// against their independently recomputed block/preimage commitments.
fn verify_finality_bytes(
    bytes: &[u8],
    authority: &Arc<super::super::authority::VerifiedAuthority>,
) -> Result<VerifiedFinalityProof, String> {
    if bytes.is_empty() || bytes.len() > MAX_DOCUMENT {
        return Err("bounded finality document required".into());
    }
    let evidence: ClientFinalityEvidence =
        serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
    if serde_json::to_vec(&evidence).map_err(|e| e.to_string())? != bytes {
        return Err(
            "exact canonical finality document required (no hidden or unknown fields)".into(),
        );
    }
    if evidence.version != 1 || evidence.witness.timeout_certificates.len() > 128 {
        return Err("unsupported or excessive finality witness".into());
    }
    let mut finality = synergy_posy::ThreeQcFinality::default();
    let mut used = BTreeSet::new();
    let mut by_id = std::collections::BTreeMap::new();
    for tc in &evidence.witness.timeout_certificates {
        if by_id
            .insert(tc.id().map_err(|e| e.to_string())?, tc)
            .is_some()
        {
            return Err("duplicate finality timeout".into());
        }
    }
    for qc in &evidence.witness.quorum_certificates {
        let original = authority
            .authenticated_history_at(qc.context.height)
            .ok_or("proof lies outside independently authenticated authority history")?;
        let owner = super::super::authority::VerifiedAuthority::worker_context(original)?;
        qc.verify(&owner.epoch, &owner.registry, owner.as_ref())
            .map_err(|e| e.to_string())?;
        // Reuse the native verifier under each original epoch; foreign-epoch
        // timeouts are verified when their own QC is processed, never relabeled.
        let scoped = synergy_posy::FinalitySyncWitness {
            quorum_certificates: [qc.clone(), qc.clone(), qc.clone()],
            timeout_certificates: evidence
                .witness
                .timeout_certificates
                .iter()
                .filter(|tc| tc.context.epoch == qc.context.epoch)
                .cloned()
                .collect(),
        };
        scoped
            .verified_timeout_closure(&owner.epoch, &owner.registry, owner.as_ref())
            .map_err(|e| e.to_string())?;
        let mut expected = qc.takeover_tc_id.as_ref();
        for _ in 0..qc.context.round {
            let id = expected.ok_or("missing finality timeout predecessor")?;
            let tc = by_id.get(id).ok_or("missing finality timeout")?;
            used.insert(id.clone());
            expected = tc.previous_tc_id.as_ref();
        }
        finality.accept(qc.clone()).map_err(|e| e.to_string())?;
    }
    if used.len() != by_id.len() || finality.last_finalized() != Some(&evidence.finalized) {
        return Err("finality record or exact timeout closure mismatch".into());
    }
    let [first, second, _] = evidence.witness.quorum_certificates;
    Ok(VerifiedFinalityProof {
        record: evidence.finalized,
        parent_block_id: first.parent_block_id,
        following_block_id: second.block_id,
    })
}

struct VerifiedBlockCommitment<'a> {
    parent_block_id: &'a str,
    state_root: &'a str,
}

fn verify_block_commitment<'a>(
    bytes: &'a [u8],
    finalized: &FinalizedBlockRecord,
) -> Result<VerifiedBlockCommitment<'a>, String> {
    if bytes.is_empty()
        || bytes.len() > MAX_DOCUMENT
        || synergy_block::hash_block_bytes(bytes) != finalized.block_id
    {
        return Err("block preimage does not match verified finality".into());
    }
    use serde::de::IgnoredAny;
    // Decode only the committed header, without reconstructing transaction or
    // receipt values. The hash authenticates their original bytes as well.
    let (height, parent_block_id, protected_root, state_root, _, _): (
        u64,
        &str,
        &str,
        &str,
        IgnoredAny,
        IgnoredAny,
    ) = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
    if height != finalized.height
        || protected_root != finalized.protected_execution_root
        || !canonical_digest(state_root)
    {
        return Err("block preimage header differs from verified finality".into());
    }
    Ok(VerifiedBlockCommitment {
        parent_block_id,
        state_root,
    })
}

fn verified_consensus_position(
    finalized: &FinalizedBlockRecord,
    authority: &Arc<super::super::authority::VerifiedAuthority>,
) -> Result<(u64, String, u64), String> {
    // A tail block may be finalized by QCs from its successor epoch.
    // Always derive time from the authority that certified this height.
    let owner = authority
        .authenticated_history_at(finalized.height)
        .ok_or("verified height has no authenticated consensus time authority")?;
    Ok((
        owner.epoch.epoch,
        owner.epoch.root().map_err(|error| error.to_string())?,
        owner.consensus_timestamp_unix(finalized.height)?,
    ))
}

/// An independently selected expectation for an exact finalized governance
/// write. The proof source cannot select these fields or approve this record.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActivationRecordExpectation {
    chain_id: u64,
    network_id: String,
    genesis_hash: String,
    activation_height: u64,
    finalized_block_id: String,
    state_root: String,
    record_key: String,
    record_sha256: String,
}

fn inspect_expected_activation_record(
    world: &synergy_state::WorldState,
    finalized: &synergy_posy::FinalizedBlockRecord,
    state_root: &str,
    chain_id: u64,
    network_id: &str,
    genesis_hash: &str,
    expected: &ActivationRecordExpectation,
) -> Result<Value, String> {
    let valid_hash = |value: &str| canonical_digest(value) && value.bytes().any(|b| b != b'0');
    let key = expected
        .record_key
        .strip_prefix("governance/")
        .and_then(|key| key.split_once('/'));
    let valid_segment = |segment: &str, limit| {
        !segment.is_empty()
            && segment.len() <= limit
            && segment != "."
            && segment != ".."
            && segment
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
    };
    if !key.is_some_and(|(action, target)| valid_segment(action, 128) && valid_segment(target, 256))
        || !valid_hash(&expected.record_sha256)
        || !valid_hash(&expected.genesis_hash)
        || !valid_hash(&expected.finalized_block_id)
        || !valid_hash(&expected.state_root)
        || expected.activation_height == 0
        || expected.chain_id == 0
        || expected.network_id.is_empty()
        || expected.chain_id != chain_id
        || expected.network_id != network_id
        || expected.genesis_hash != genesis_hash
        || expected.activation_height != finalized.height
        || expected.finalized_block_id != finalized.block_id
        || expected.state_root != state_root
        || synergy_state::state_root(world).map_err(|error| format!("{error:?}"))? != state_root
    {
        return Err(
            "expected activation record does not match the verified scope and boundary".into(),
        );
    }
    let Some(bytes) = world.protocol.get(&expected.record_key) else {
        return Ok(json!({"status":"expected_record_absent", "record_key":expected.record_key}));
    };
    if bytes.is_empty() || bytes.len() > MAX_DOCUMENT {
        return Err("activation record exceeds proof resource bounds".into());
    }
    let digest: String = Primitives
        .hash(HashAlgorithm::Sha256, bytes)
        .map_err(|error| format!("APQE activation record digest: {error:?}"))?
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    if digest != expected.record_sha256 {
        return Err("finalized governance record differs from independently expected bytes".into());
    }
    Ok(
        json!({"status":"exact_expected_record_finalized", "record_key":expected.record_key,
        "record_sha256":expected.record_sha256, "activation_height":expected.activation_height}),
    )
}

struct ActivationBoundaryEvidence<'a> {
    finality: &'a VerifiedFinalityProof,
    block: &'a VerifiedBlockCommitment<'a>,
    world: &'a synergy_state::WorldState,
}

fn links_finalized_predecessor(
    before: &VerifiedFinalityProof,
    after: &VerifiedFinalityProof,
    after_block: &VerifiedBlockCommitment<'_>,
) -> bool {
    before.record.height != 0
        && before.record.height.checked_add(1) == Some(after.record.height)
        && after_block.parent_block_id == before.record.block_id
        && after.parent_block_id == before.record.block_id
        && before.following_block_id == after.record.block_id
}

fn inspect_activation_transition(
    before: ActivationBoundaryEvidence<'_>,
    after: ActivationBoundaryEvidence<'_>,
    chain_id: u64,
    network_id: &str,
    genesis_hash: &str,
    expected: &ActivationRecordExpectation,
) -> Result<Value, String> {
    if !links_finalized_predecessor(before.finality, after.finality, after.block) {
        return Err("activation proofs do not link adjacent certified blocks".into());
    }
    if synergy_state::state_root(before.world).map_err(|error| format!("{error:?}"))?
        != before.block.state_root
    {
        return Err("activation predecessor World differs from its verified state root".into());
    }
    let record = inspect_expected_activation_record(
        after.world,
        &after.finality.record,
        after.block.state_root,
        chain_id,
        network_id,
        genesis_hash,
        expected,
    )?;
    if before.world.protocol.contains_key(&expected.record_key) {
        return Err(
            "expected activation record already existed in the finalized predecessor".into(),
        );
    }
    if !after.world.protocol.contains_key(&expected.record_key) {
        return Err("expected activation record is absent at the verified boundary".into());
    }
    Ok(json!({
        "status":"expected_record_introduced_at_finalized_boundary",
        "predecessor":{"height":before.finality.record.height,"block_id":before.finality.record.block_id,
            "state_root":before.block.state_root, "finality_certificate_id":before.finality.record.finality_certificate_id},
        "boundary_record":record,
    }))
}

fn read_canonical_world(path: &str) -> Result<synergy_state::WorldState, String> {
    let original =
        super::super::apqe_transport::read(std::path::Path::new(path), MAX_DOCUMENT as u64, false)?;
    let world = serde_json::from_slice(&original).map_err(|error| error.to_string())?;
    if serde_json::to_vec(&world).map_err(|error| error.to_string())? != original {
        return Err("exact canonical World preimage required".into());
    }
    Ok(world)
}

pub(crate) fn verify_finality_proof_cli(args: impl Iterator<Item = String>) -> Result<(), String> {
    let args: Vec<_> = args.collect();
    let (config, proof, block, inspection, predecessor) = match args.as_slice() {
        [action, config, proof] if action == "verify" => (config, proof, None, None, None),
        [action, config, proof, block] if action == "verify" => (config, proof, Some(block), None, None),
        [action, config, proof, block, world, query]
            if matches!(action.as_str(), "verify-candidate-state" | "verify-activation-record") => {
            (config, proof, Some(block), Some((action, world, query)), None)
        }
        [action, config, proof, block, world, query, previous_proof, previous_block, previous_world]
            if matches!(action.as_str(), "verify-activation-transition" | "verify-candidate-settlement") => {
            (config, proof, Some(block), Some((action, world, query)),
                Some((previous_proof, previous_block, previous_world)))
        }
        _ => return Err(
            "usage: finality-proof verify CONFIG FINALITY_JSON [BLOCK_COMMITMENT_JSON], finality-proof {verify-candidate-state|verify-activation-record} CONFIG FINALITY_JSON BLOCK_COMMITMENT_JSON WORLD_JSON QUERY_JSON, or finality-proof {verify-activation-transition|verify-candidate-settlement} CONFIG FINALITY_JSON BLOCK_COMMITMENT_JSON WORLD_JSON QUERY_JSON PREVIOUS_FINALITY_JSON PREVIOUS_BLOCK_JSON PREVIOUS_WORLD_JSON".into(),
        ),
    };
    let configuration =
        synergy_config::load(std::path::Path::new(config)).map_err(|e| e.to_string())?;
    let genesis_hash = crate::commands::selected_network::verify(&configuration)?;
    let authority = super::super::authority::load(&configuration)?
        .ok_or("independently pinned signed authority required")?;
    let bytes = super::super::apqe_transport::read(
        std::path::Path::new(proof),
        MAX_DOCUMENT as u64,
        false,
    )?;
    let finality = verify_finality_bytes(&bytes, &authority)?;
    let verified = &finality.record;
    let mut result = json!({"version":1,"verified":true,"chain_id":configuration.chain_id,
        "network_id":configuration.network_id,"genesis_hash":genesis_hash,"finalized":verified});
    if let Some(block) = block {
        let block_bytes = super::super::apqe_transport::read(
            std::path::Path::new(block),
            MAX_DOCUMENT as u64,
            false,
        )?;
        let header = verify_block_commitment(&block_bytes, verified)?;
        let state_root = header.state_root;
        let (epoch, epoch_context_root, timestamp_unix) =
            verified_consensus_position(verified, &authority)?;
        result["state_root"] = json!(state_root);
        result["epoch"] = json!(epoch);
        result["epoch_context_root"] = json!(epoch_context_root);
        result["consensus_timestamp_unix"] = json!(timestamp_unix);
        if let Some((action, world, query)) = inspection {
            use super::super::protected_accounts::inspection::{
                inspect, inspect_settlement_inclusion, CandidateReadQuery, CandidateWorld,
            };
            let query =
                super::super::apqe_transport::read(std::path::Path::new(query), 8 * 1024, false)?;
            let world = read_canonical_world(world)?;
            if let Some((previous_proof, previous_block, previous_world)) = predecessor {
                let read = |path: &str| {
                    super::super::apqe_transport::read(
                        std::path::Path::new(path),
                        MAX_DOCUMENT as u64,
                        false,
                    )
                };
                let prior = verify_finality_bytes(&read(previous_proof)?, &authority)?;
                let prior_block_bytes = read(previous_block)?;
                let prior_header = verify_block_commitment(&prior_block_bytes, &prior.record)?;
                let prior_world = read_canonical_world(previous_world)?;
                if action == "verify-activation-transition" {
                    let expectation: ActivationRecordExpectation =
                        serde_json::from_slice(&query).map_err(|error| error.to_string())?;
                    result["activation_transition"] = inspect_activation_transition(
                        ActivationBoundaryEvidence {
                            finality: &prior,
                            block: &prior_header,
                            world: &prior_world,
                        },
                        ActivationBoundaryEvidence {
                            finality: &finality,
                            block: &header,
                            world: &world,
                        },
                        configuration.chain_id,
                        &configuration.network_id,
                        &genesis_hash,
                        &expectation,
                    )?;
                } else {
                    if !links_finalized_predecessor(&prior, &finality, &header) {
                        return Err("settlement proofs do not link adjacent certified blocks".into());
                    }
                    let (_, _, previous_timestamp) =
                        verified_consensus_position(&prior.record, &authority)?;
                    let query: CandidateReadQuery =
                        serde_json::from_slice(&query).map_err(|error| error.to_string())?;
                    result["candidate_settlement"] = inspect_settlement_inclusion(
                        CandidateWorld {
                            world: &prior_world,
                            finality: &prior.record,
                            state_root: prior_header.state_root,
                            consensus_time: previous_timestamp,
                        },
                        CandidateWorld {
                            world: &world,
                            finality: verified,
                            state_root,
                            consensus_time: timestamp_unix,
                        },
                        configuration.chain_id,
                        &genesis_hash,
                        query,
                    )?;
                }
            } else if action == "verify-activation-record" {
                let expectation: ActivationRecordExpectation =
                    serde_json::from_slice(&query).map_err(|error| error.to_string())?;
                result["activation_record"] = inspect_expected_activation_record(
                    &world,
                    verified,
                    state_root,
                    configuration.chain_id,
                    &configuration.network_id,
                    &genesis_hash,
                    &expectation,
                )?;
            } else {
                let query: CandidateReadQuery =
                    serde_json::from_slice(&query).map_err(|error| error.to_string())?;
                result["candidate_state"] = inspect(
                    &world,
                    verified,
                    state_root,
                    timestamp_unix,
                    configuration.chain_id,
                    &genesis_hash,
                    query,
                )?;
            }
        }
    }
    println!("{result}");
    Ok(())
}

impl CanonicalQueryStore {
    fn wallet_world_scope(&self, finalized: &FinalizedBlockRecord) -> Result<Option<PublicWalletRecords>, RpcError> {
        let Some((genesis, owner)) = self.wallet_finalized_authority.as_ref() else { return Ok(None); };
        let selected = owner.read().map_err(|_| RpcError::unavailable("Wallet proof authority unavailable"))?.clone();
        let Some(authority) = selected.as_ref().and_then(|current| current.autonomous_authority_at(finalized.height))
            else { return Ok(None); };
        if authority.wallet_dispatch_policy().is_none() {
            return Ok(None);
        }
        let approved = authority.native_wallet_release().map_err(RpcError::unavailable)?;
        PublicWalletRecords::new(approved.verified.policy(), genesis, finalized)
            .map(Some).map_err(RpcError::unavailable)
    }

    pub(super) fn canonical_proof_page(&self, value: &Value) -> Result<Value, RpcError> {
        let query = ProofQuery::decode(value.clone())?;
        // Charge retained response scratch separately from the budgeted World.
        let _permit = self
            .world_budget
            .reserve(PROOF_SCRATCH)
            .map_err(|error| RpcError::unavailable(error.to_string()))?;
        let (candidate, finalized) = self
            .finalized_at(query.height)?
            .ok_or_else(|| RpcError::unavailable("requested finalized evidence is not retained"))?;
        let mut result = match query.kind {
            ProofKind::BlockCommitment => page(
                &query,
                &(
                    candidate.height,
                    &candidate.parent_block_id,
                    &candidate.protected_execution_root,
                    &candidate.state_root,
                    &candidate.transactions,
                    &candidate.receipts,
                ),
            )?,
            ProofKind::WorldState => {
                let scope = self.wallet_world_scope(&finalized)?;
                require_public_world(&candidate.state, scope.as_ref())?;
                page(&query, &candidate.state)?
            }
            ProofKind::Finality => {
                return Err(RpcError::unavailable(
                    "finality requires authenticated ingress",
                ))
            }
        };
        if query.kind == ProofKind::WorldState {
            result["commitment"] = json!({"type":"full_canonical_world_preimage",
                "algorithm":"sha3-256", "domain_utf8":"SYNERGY_WORLD_STATE_ROOT_V1",
                "framing":"domain || canonical_json_length_be_u64 || canonical_json_bytes"});
        }
        result["block_id"] = json!(candidate.block_id);
        result["state_root"] = json!(candidate.state_root);
        result["protected_execution_root"] = json!(candidate.protected_execution_root);
        Ok(result)
    }
}

// The root commits the complete World. Redacting opaque records would produce
// a different preimage; disclosing them could expose private application data.
// Only these typed, explicitly public consensus records may be transported.
// New protocol consumers must qualify disclosure before extending this list.
pub(in crate::services) fn require_public_world(world: &synergy_state::WorldState, wallet: Option<&PublicWalletRecords>) -> Result<(), RpcError> {
    use synergy_identity::authorization::IDENTITY_AUTHORIZATION_BINDINGS_STATE_KEY;
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ReadyMetadata {
        namespace_root: synergy_etdag::EtdagDigest,
        generation: u64,
        count: usize,
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct GroupMetadata {
        namespace_root: synergy_etdag::EtdagDigest,
        last_number: u64,
        last_root: synergy_etdag::EtdagDigest,
        groups: usize,
        claims: usize,
    }
    let invalid = || {
        RpcError::unavailable("World contains records without a qualified public disclosure schema")
    };
    for (key, bytes) in &world.protocol {
        if bytes.len() > MAX_DOCUMENT {
            return Err(invalid());
        }
        match key.as_str() {
            IDENTITY_AUTHORIZATION_BINDINGS_STATE_KEY => {
                validate_public_bindings(bytes).map_err(|_| invalid())?;
            }
            synergy_identity::registration::AUTHORIZATION_UPDATED_HEIGHT_STATE_KEY => {
                serde_json::from_slice::<u64>(bytes).map_err(|_| invalid())?;
            }
            "etdag-processing-ready-v1/meta" => {
                let v: ReadyMetadata = serde_json::from_slice(bytes).map_err(|_| invalid())?;
                v.namespace_root.validate().map_err(|_| invalid())?;
                let _public_counters = (v.generation, v.count);
            }
            "etdag-processing-groups-v1/meta" => {
                let v: GroupMetadata = serde_json::from_slice(bytes).map_err(|_| invalid())?;
                v.namespace_root.validate().map_err(|_| invalid())?;
                v.last_root.validate().map_err(|_| invalid())?;
                let _public_counters = (v.last_number, v.groups, v.claims);
            }
            synergy_naming::WALLET_PROTOCOL_STATE_KEY => {
                // The canonical registry contains only public aliases, addresses
                // and registration heights. Keep the proof's working set bounded.
                if bytes.len() > 64 * 1024 { return Err(invalid()); }
                let names = synergy_naming::WalletSynIdRegistry::decode(Some(bytes)).map_err(|_| invalid())?;
                if names.encode().map_err(|_| invalid())? != *bytes { return Err(invalid()); }
            }
            _ => {
                if crate::services::validator_admission::validate_public_record(world,key,bytes).map_err(|_|invalid())?
                    || crate::services::membership_retirement::validate_public_record(key,bytes).map_err(|_|invalid())?
                    || public_ethereum::validate_record(world,key,bytes).map_err(|_|invalid())?
                    || public_processing::validate_record(key,bytes).map_err(|_|invalid())? {continue;}
                let Some(scope) = wallet else { return Err(invalid()); };
                if !validate_public_wallet_record(scope, world, key, bytes).map_err(|_| invalid())? {
                    return Err(invalid());
                }
            }
        }
    }
    Ok(())
}

// Keep this disclosure schema local and closed even if the internal identity
// type gains additional fields. Borrowed entries avoid retaining a decoded map.
fn validate_public_bindings(bytes: &[u8]) -> Result<(), serde_json::Error> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct PublicBinding<'a> {
        #[serde(borrow)]
        binding_payload_sha3_256: &'a str,
        #[serde(borrow)]
        identity_root_public_key_sha3_256: &'a str,
        effective_at_unix: u64,
    }
    struct Bindings;
    impl<'de> serde::de::Visitor<'de> for Bindings {
        type Value = ();
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("a map of closed public identity commitments")
        }
        fn visit_map<M: serde::de::MapAccess<'de>>(self, mut map: M) -> Result<(), M::Error> {
            while let Some((_address, value)) = map.next_entry::<&str, PublicBinding<'de>>()? {
                if !canonical_digest(value.binding_payload_sha3_256)
                    || !canonical_digest(value.identity_root_public_key_sha3_256)
                {
                    return Err(serde::de::Error::custom("invalid public commitment digest"));
                }
                let _public_time = value.effective_at_unix;
            }
            Ok(())
        }
    }
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    serde::de::Deserializer::deserialize_map(&mut decoder, Bindings)?;
    decoder.end()
}

fn canonical_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[cfg(test)]
pub(crate) fn qualify_wallet_world_disclosure(
    active: &Arc<super::super::authority::VerifiedAuthority>,
    finalized: &FinalizedBlockRecord,
    genesis: &str,
) {
    let approved = active.native_wallet_release().unwrap();
    let scope = PublicWalletRecords::new(approved.verified.policy(), genesis, finalized).unwrap();
    let (key, bytes) = scope.fixture_commit([7; 32]);
    let mut world = synergy_state::WorldState::default();
    world.protocol.insert(key.clone(), bytes.clone());
    let group = synergy_execution::ProcessingGroupState {
        namespace_root: synergy_etdag::EtdagDigest("a".repeat(128)),
        group_number: 1,
        group_root: synergy_etdag::EtdagDigest("b".repeat(128)),
        remaining: 1,
        next_position: 0,
        closed_by_successor: Some(synergy_etdag::EtdagDigest("c".repeat(128))),
    };
    let group_key = "etdag-processing-groups-v1/group/00000000000000000001";
    world.protocol.insert(group_key.into(), serde_json::to_vec(&group).unwrap());
    assert!(require_public_world(&world, None).is_err());
    require_public_world(&world, Some(&scope)).unwrap();
    let query = ProofQuery::decode(json!({"height": finalized.height, "kind": "world_state"})).unwrap();
    let observed = page(&query, &world).unwrap();
    let raw = BASE64.decode(observed["bytes_base64"].as_str().unwrap()).unwrap();
    assert_eq!(raw, serde_json::to_vec(&world).unwrap());
    assert_eq!(synergy_state::state_root(&serde_json::from_slice(&raw).unwrap()).unwrap(),
               synergy_state::state_root(&world).unwrap());
    assert!(PublicWalletRecords::new(approved.verified.policy(), &"e".repeat(64), finalized).is_err());
    let mut early = finalized.clone();
    early.height -= 1;
    assert!(PublicWalletRecords::new(approved.verified.policy(), genesis, &early).is_err());

    for (foreign_key, field) in [(key.as_str(), "salt"), (group_key, "encrypted_payload")] {
        let mut poisoned = world.clone();
        let target = poisoned.protocol.get_mut(foreign_key).unwrap();
        let mut decoded: Value = serde_json::from_slice(target).unwrap();
        decoded[field] = json!("private");
        *target = serde_json::to_vec(&decoded).unwrap();
        assert!(require_public_world(&poisoned, Some(&scope)).is_err());
    }
    world.protocol.insert("apqe-protected-account-candidate/v1/private".into(), b"{}".to_vec());
    assert!(require_public_world(&world, Some(&scope)).is_err());
}

#[cfg(test)]
pub(crate) fn qualify_first_epoch_timeout(
    active: Arc<super::super::authority::VerifiedAuthority>,
    previous: &synergy_posy::SimplifiedQuorumCertificate,
    validators: &[synergy_posy::ValidatorRecord],
    keys: &[synergy_address_engine::apqe::crypto_engine::EncodedKeyPair],
    engine: &Arc<Mutex<synergy_address_engine::apqe::crypto_engine::CryptoEngine>>,
) {
    use synergy_address_engine::{apqe::provider::SignOptions, types::Algorithm};
    use synergy_posy::{
        block_vote_signing_bytes, timeout_vote_signing_bytes, BlockVote, ConsensusObjectContext,
        SimplifiedFinalityParent, SimplifiedQuorumCertificate, SimplifiedTimeoutCertificate,
        ThreeQcFinality, TimeoutVote, VerifiedQuorumCertificateStore,
        VerifiedTimeoutCertificateStore,
    };
    let first = active.epoch.epoch_start_height;
    assert_eq!(previous.context.height.checked_add(1), Some(first));
    // A predecessor QC is never verified by relabeling it into successor context.
    assert!(previous
        .verify(&active.epoch, &active.registry, active.as_ref())
        .is_err());
    let reports = validators
        .iter()
        .zip(keys)
        .take(4)
        .map(|(record, key)| {
            let mut report = TimeoutVote {
                context: ConsensusObjectContext::for_height(&active.epoch, first, 0).unwrap(),
                lease_index: active.epoch.lease_index(first).unwrap(),
                timed_out_proposer: active.epoch.authorized_proposer(first, 0).unwrap().into(),
                highest_parent: active.anchor_parent.clone(),
                previous_tc_id: None,
                last_voted_candidate: None,
                validator_id: record.validator_id.clone(),
                key_id: record.consensus_key_id.clone(),
                signature: Vec::new(),
            };
            report.signature = engine
                .lock()
                .unwrap()
                .sign(
                    Algorithm::MlDsa65,
                    key.private_key.as_bytes(),
                    &timeout_vote_signing_bytes(&report).unwrap(),
                    SignOptions::default(),
                )
                .unwrap();
            report
        })
        .collect();
    let tc =
        SimplifiedTimeoutCertificate::from_votes_with_qc_proofs(reports, vec![previous.clone()])
            .unwrap();
    tc.verify(&active.epoch, &active.registry, active.as_ref())
        .unwrap();
    struct WithoutHistory<'a>(&'a super::super::authority::VerifiedAuthority);
    impl synergy_posy::ConsensusSignatureVerifier for WithoutHistory<'_> {
        fn verify_consensus_signature(
            &self,
            domain: &str,
            payload: &[u8],
            validator: &synergy_posy::ValidatorRecord,
            key_id: &str,
            epoch: u64,
            signature: &[u8],
        ) -> synergy_posy::PosyResult<()> {
            synergy_posy::ConsensusSignatureVerifier::verify_consensus_signature(
                self.0, domain, payload, validator, key_id, epoch, signature,
            )
        }
        // No authenticated predecessor: inherited callback must fail closed.
    }
    assert!(tc
        .verify(
            &active.epoch,
            &active.registry,
            &WithoutHistory(active.as_ref())
        )
        .is_err());
    let mut bad = tc.clone();
    bad.highest_qc_proofs[0].participants[0].signature[0] ^= 1;
    assert!(bad
        .verify(&active.epoch, &active.registry, active.as_ref())
        .is_err());
    let mut substituted = tc.clone();
    substituted.highest_qc_proofs[0].block_id = "unapproved-boundary".into();
    assert!(substituted
        .verify(&active.epoch, &active.registry, active.as_ref())
        .is_err());
    struct Cleanup(PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    let scratch = Cleanup(std::env::temp_dir().join(format!(
            "native-boundary-proof-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        )));
    let qcs = VerifiedQuorumCertificateStore::new(&scratch.0).unwrap();
    let tcs = VerifiedTimeoutCertificateStore::new(&scratch.0).unwrap();
    tcs.put_verified(&tc, &active.epoch, &active.registry, active.as_ref())
        .unwrap();
    let mut parent = active.anchor_parent.clone();
    let mut finality = ThreeQcFinality::default();
    finality.accept(previous.clone()).unwrap();
    let mut previous_finalized = None;
    for height in first..=first + 2 {
        let votes = validators
            .iter()
            .zip(keys)
            .take(4)
            .map(|(record, key)| {
                let mut vote = BlockVote {
                    context: ConsensusObjectContext::for_height(&active.epoch, height, 1).unwrap(),
                    block_id: format!("boundary-proof-{height}"),
                    parent_block_id: parent.block_id().into(),
                    parent: parent.clone(),
                    takeover_tc_id: Some(tc.id().unwrap()),
                    protected_execution_root: "e".repeat(64),
                    validator_id: record.validator_id.clone(),
                    key_id: record.consensus_key_id.clone(),
                    signature: Vec::new(),
                };
                vote.signature = engine
                    .lock()
                    .unwrap()
                    .sign(
                        Algorithm::MlDsa65,
                        key.private_key.as_bytes(),
                        &block_vote_signing_bytes(&vote).unwrap(),
                        SignOptions::default(),
                    )
                    .unwrap();
                vote
            })
            .collect();
        let qc = SimplifiedQuorumCertificate::from_votes(votes).unwrap();
        qcs.put_verified(&qc, &active.epoch, &active.registry, active.as_ref())
            .unwrap();
        // Exact producer path: store lookup + generic TC verification must invoke
        // the authenticated original-predecessor callback.
        let collected = synergy_posy::FinalitySyncWitness::collect_verified_timeouts(
            &qc,
            &tcs,
            &active.epoch,
            &active.registry,
            active.as_ref(),
        )
        .unwrap();
        assert_eq!(collected, vec![tc.clone()]);
        parent = SimplifiedFinalityParent::QuorumCertificate {
            height,
            block_id: qc.block_id.clone(),
            qc_id: qc.id().unwrap(),
        };
        finality.accept(qc).unwrap();
        if height == first + 1 {
            // Actual three-QC cross-epoch evidence finalizes the immediately
            // preceding record; do not fabricate a contiguous-history token.
            previous_finalized = finality.last_finalized().cloned();
        }
    }
    let expected = finality.last_finalized().unwrap().clone();
    synergy_posy::persistence::FinalityStore::new(&scratch.0)
        .unwrap()
        .commit_exactly_once(&expected, previous_finalized.as_ref())
        .unwrap();
    let ingress = super::super::ingress::AuthenticatedIngress::default();
    ingress
        .install_finality_history(scratch.0.clone(), active.clone())
        .unwrap();
    let proof = ingress.finality_proof(first).unwrap();
    let exact = serde_json::to_vec(&proof).unwrap();
    assert_eq!(
        verify_finality_bytes(&exact, &active).unwrap().record,
        expected
    );
    let mut invalid: ClientFinalityEvidence = serde_json::from_slice(&exact).unwrap();
    invalid.witness.timeout_certificates[0].highest_qc_proofs[0].participants[0].signature[0] ^= 1;
    assert!(verify_finality_bytes(&serde_json::to_vec(&invalid).unwrap(), &active).is_err());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verified_block_preimage_binds_the_state_root_to_the_finalized_height() {
        let protected_root = "a".repeat(64);
        let state_root = "b".repeat(64);
        let preimage = |height, root: &str, protected: &str| {
            serde_json::to_vec(&(
                height,
                "parent",
                protected,
                root,
                Vec::<Value>::new(),
                Vec::<Value>::new(),
            ))
            .unwrap()
        };
        let original = preimage(7, &state_root, &protected_root);
        let record = FinalizedBlockRecord {
            height: 7,
            block_id: synergy_block::hash_block_bytes(&original),
            protected_execution_root: protected_root.clone(),
            finality_certificate_id: "c".repeat(64),
        };
        assert_eq!(
            verify_block_commitment(&original, &record)
                .unwrap()
                .state_root,
            state_root
        );
        let substituted = preimage(7, &"d".repeat(64), &protected_root);
        assert!(verify_block_commitment(&substituted, &record).is_err());
        let stale = preimage(6, &state_root, &protected_root);
        let mut incorrect = record.clone();
        incorrect.block_id = synergy_block::hash_block_bytes(&stale);
        assert!(verify_block_commitment(&stale, &incorrect).is_err());
        let wrong_protected_root = preimage(7, &state_root, &"e".repeat(64));
        incorrect.block_id = synergy_block::hash_block_bytes(&wrong_protected_root);
        assert!(verify_block_commitment(&wrong_protected_root, &incorrect).is_err());
    }

    #[test]
    fn proof_pages_preserve_original_integer_bytes_and_require_pinned_continuation() {
        let original = (u128::MAX, "large\"integer", vec![u64::MAX; 35]);
        let expected = serde_json::to_vec(&original).unwrap();
        let mut query =
            ProofQuery::decode(json!({"height":7,"kind":"block_commitment","limit":37})).unwrap();
        let mut bytes = Vec::new();
        loop {
            let response = page(&query, &original).unwrap();
            bytes.extend(
                BASE64
                    .decode(response["bytes_base64"].as_str().unwrap())
                    .unwrap(),
            );
            query.expected_sha256 = Some(response["sha256"].as_str().unwrap().into());
            let Some(next) = response["next_offset"].as_u64() else {
                break;
            };
            query.offset = next as usize;
        }
        assert_eq!(bytes, expected);
        query.expected_sha256 = Some("0".repeat(64));
        assert!(page(&query, &original).is_err());
        for bad in [
            json!({"height":7,"kind":"world_state","offset":1}),
            json!({"height":7,"kind":"world_state","limit":65537}),
            json!({"height":0,"kind":"world_state"}),
            json!({"height":7,"kind":"world_state","unknown":1}),
        ] {
            assert!(ProofQuery::decode(bad).is_err());
        }
    }
    #[test]
    fn apqe_disclosure_stream_preserves_exact_sha256_across_pages() {
        use sha2::{Digest, Sha256};
        for size in [0, 1, 1024, MAX_PAGE + 37] {
            let value = json!({"disclosure": "x".repeat(size)});
            let bytes = serde_json::to_vec(&value).unwrap();
            let expected = format!("{:x}", Sha256::digest(&bytes));
            for offset in [0, bytes.len() / 2, bytes.len() - 1] {
                let query = ProofQuery {
                    height: 7,
                    kind: ProofKind::WorldState,
                    offset,
                    limit: 31,
                    expected_sha256: Some(expected.clone()),
                };
                let response = page(&query, &value).unwrap();
                assert_eq!(response["sha256"], expected);
                assert_eq!(response["total_bytes"], bytes.len());
                assert_eq!(
                    BASE64
                        .decode(response["bytes_base64"].as_str().unwrap())
                        .unwrap(),
                    bytes[offset..(offset + 31).min(bytes.len())]
                );
                let wrong = ProofQuery {
                    expected_sha256: Some("0".repeat(64)),
                    ..query
                };
                assert!(page(&wrong, &value).is_err());
            }
        }
    }

    #[test]
    fn streaming_writer_bounds_retained_memory_and_rejects_document_overflow() {
        let mut writer = PageWriter::new(2, 3).unwrap();
        writer.write_all(b"ab").unwrap();
        writer.write_all(b"cdefgh").unwrap();
        assert_eq!(writer.bytes, b"cde");
        writer.total = MAX_DOCUMENT;
        assert!(writer.write_all(b"x").is_err());
        assert_eq!(writer.bytes, b"cde");
    }
    #[test]
    fn world_disclosure_rejects_unknown_records_and_hidden_metadata_fields() {
        let mut world = synergy_state::WorldState::default();
        world.accounts.insert(
            "public-account".into(),
            synergy_state::AccountState {
                balance_nwei: u128::MAX,
                nonce: 7,
                code_hash: None,
            },
        );
        assert!(require_public_world(&world, None).is_ok());
        world
            .protocol
            .insert("private-application-state".into(), b"secret".to_vec());
        assert!(require_public_world(&world, None).is_err());
        world.protocol.clear();
        let key = "etdag-processing-ready-v1/meta";
        let mut metadata = json!({"namespace_root":"a".repeat(128),"generation":0,"count":0});
        world
            .protocol
            .insert(key.into(), serde_json::to_vec(&metadata).unwrap());
        assert!(require_public_world(&world, None).is_ok());
        metadata["secret"] = json!("must not be disclosed");
        world
            .protocol
            .insert(key.into(), serde_json::to_vec(&metadata).unwrap());
        assert!(require_public_world(&world, None).is_err());
    }
    #[test]
    fn identity_disclosure_rejects_hidden_duplicate_and_trailing_fields() {
        let entry = format!(
            r#"{{"binding_payload_sha3_256":"{}","identity_root_public_key_sha3_256":"{}","effective_at_unix":0}}"#,
            "a".repeat(64),
            "b".repeat(64)
        );
        let valid = format!("{{\"account\":{entry}}}");
        assert!(validate_public_bindings(valid.as_bytes()).is_ok());
        for extra in [r#", "secret":"never expose""#, r#", "effective_at_unix":1"#] {
            let changed = entry.trim_end_matches('}').to_owned() + extra + "}";
            assert!(
                validate_public_bindings(format!("{{\"account\":{changed}}}").as_bytes()).is_err()
            );
        }
        assert!(validate_public_bindings((valid + " {}").as_bytes()).is_err());
    }
    #[test]
    fn complete_world_pages_reproduce_the_actual_flat_commitment() {
        use synergy_aegis::{AegisHashEngine, AegisSha3_256};
        let mut world = synergy_state::WorldState::default();
        world.accounts.insert(
            "account".into(),
            synergy_state::AccountState {
                balance_nwei: u128::MAX,
                nonce: u64::MAX,
                code_hash: None,
            },
        );
        require_public_world(&world, None).unwrap();
        let query = ProofQuery::decode(json!({"height":1,"kind":"world_state"})).unwrap();
        let response = page(&query, &world).unwrap();
        let bytes = BASE64
            .decode(response["bytes_base64"].as_str().unwrap())
            .unwrap();
        let independent = AegisSha3_256
            .sha3_256_segments(&[
                b"SYNERGY_WORLD_STATE_ROOT_V1",
                &(bytes.len() as u64).to_be_bytes(),
                &bytes,
            ])
            .unwrap();
        assert_eq!(
            independent
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
            synergy_state::state_root(&world).unwrap()
        );
    }
    #[test]
    #[ignore = "requires explicitly authenticated immutable APQE native artifacts"]
    fn native_finality_pages_are_independently_verifiable_and_retain_their_charge() {
        use synergy_address_engine::{apqe::provider::SignOptions, types::Algorithm};
        use synergy_posy::{
            block_vote_signing_bytes, BlockVote, ConsensusObjectContext, SimplifiedFinalityParent,
            SimplifiedQuorumCertificate, ThreeQcFinality, ValidatorRecord, ValidatorStatus,
            VerifiedQuorumCertificateStore,
        };
        let selected = synergy_config::ApqeProviderConfiguration {
            report_path: std::env::var("APQE_TRUSTED_NATIVE_REPORT").unwrap().into(),
            authenticated_report_sha256: std::env::var("APQE_AUTHENTICATED_REPORT_SHA256").unwrap(),
        };
        let engine = super::super::super::apqe_provider::load_selected(&selected).unwrap();
        let pairs = (0..5)
            .map(|_| {
                engine
                    .lock()
                    .unwrap()
                    .generate_keypair(Algorithm::MlDsa65)
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let entries = pairs
            .iter()
            .enumerate()
            .map(|(i, pair)| {
                (
                    ValidatorRecord {
                        validator_id: format!("proof-validator-{i}"),
                        consensus_key_id: format!("proof-key-{i}"),
                        frozen_voting_weight: 1,
                        status: ValidatorStatus::Active,
                    },
                    pair.public_key.clone(),
                )
            })
            .collect::<Vec<_>>();
        let authority = super::super::super::authority::qualification_authority_with_provider(
            entries.clone(),
            Some(engine.clone()),
        );
        struct Cleanup(PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let scratch = Cleanup(std::env::temp_dir().join(format!(
                "native-public-proof-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            )));
        let store = VerifiedQuorumCertificateStore::new(&scratch.0).unwrap();
        let mut parent = authority.anchor_parent.clone();
        let mut finality = ThreeQcFinality::default();
        let preceding_world = synergy_state::WorldState::default();
        let mut world = preceding_world.clone();
        let fixture_record = b"test-only externally pinned decision bytes";
        let mutation = synergy_governance::GovernedStateMutation {
            action_kind: "qualification".into(),
            target: "fixture-activation".into(),
            expected_value: None,
            value: fixture_record.to_vec(),
        };
        let record_key = mutation.state_key().unwrap();
        world.protocol.insert(record_key.clone(), mutation.value);
        let preceding_root = synergy_state::state_root(&preceding_world).unwrap();
        let root = synergy_state::state_root(&world).unwrap();
        let protected_root = "e".repeat(64);
        let mut preimages = Vec::new();
        let mut expected = None;
        for height in 1..=4 {
            let block = serde_json::to_vec(&(
                height,
                parent.block_id(),
                &protected_root,
                if height == 1 { &preceding_root } else { &root },
                Vec::<Value>::new(),
                Vec::<Value>::new(),
            ))
            .unwrap();
            let id = synergy_block::hash_block_bytes(&block);
            preimages.push(block);
            let votes = pairs
                .iter()
                .take(4)
                .enumerate()
                .map(|(i, pair)| {
                    let mut vote = BlockVote {
                        context: ConsensusObjectContext::for_height(&authority.epoch, height, 0)
                            .unwrap(),
                        block_id: id.clone(),
                        parent_block_id: parent.block_id().into(),
                        parent: parent.clone(),
                        takeover_tc_id: None,
                        protected_execution_root: protected_root.clone(),
                        validator_id: format!("proof-validator-{i}"),
                        key_id: format!("proof-key-{i}"),
                        signature: Vec::new(),
                    };
                    vote.signature = engine
                        .lock()
                        .unwrap()
                        .sign(
                            Algorithm::MlDsa65,
                            pair.private_key.as_bytes(),
                            &block_vote_signing_bytes(&vote).unwrap(),
                            SignOptions::default(),
                        )
                        .unwrap();
                    vote
                })
                .collect();
            let qc = SimplifiedQuorumCertificate::from_votes(votes).unwrap();
            store
                .put_verified(
                    &qc,
                    &authority.epoch,
                    &authority.registry,
                    authority.as_ref(),
                )
                .unwrap();
            parent = SimplifiedFinalityParent::QuorumCertificate {
                height,
                block_id: qc.block_id.clone(),
                qc_id: qc.id().unwrap(),
            };
            finality.accept(qc).unwrap();
            if height == 3 {
                expected = finality.last_finalized().cloned();
            }
        }
        let expected = expected.unwrap();
        let expected_boundary = finality.last_finalized().unwrap();
        assert_eq!((expected.height, expected_boundary.height), (1, 2));
        let records = synergy_posy::persistence::FinalityStore::new(&scratch.0).unwrap();
        records.commit_exactly_once(&expected, None).unwrap();
        records
            .commit_exactly_once(expected_boundary, Some(&expected))
            .unwrap();
        let budget = WorldResourceBudget::new(PROOF_SCRATCH * 2);
        let ingress =
            super::super::super::ingress::AuthenticatedIngress::with_world_budget(budget.clone());
        ingress
            .install_finality_history(scratch.0.clone(), authority)
            .unwrap();
        let evidence = ingress.finality_proof(1).unwrap();
        assert_eq!(budget.used(), PROOF_SCRATCH);
        let mut query =
            ProofQuery::decode(json!({"height":1,"kind":"finality","limit":17000})).unwrap();
        let mut exact = Vec::new();
        loop {
            let response = page(&query, &evidence).unwrap();
            exact.extend(
                BASE64
                    .decode(response["bytes_base64"].as_str().unwrap())
                    .unwrap(),
            );
            query.expected_sha256 = Some(response["sha256"].as_str().unwrap().into());
            let Some(next) = response["next_offset"].as_u64() else {
                break;
            };
            query.offset = next as usize;
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct ClientEvidence {
            version: u8,
            finalized: synergy_posy::FinalizedBlockRecord,
            witness: synergy_posy::FinalitySyncWitness,
        }
        let mut decoded: ClientEvidence = serde_json::from_slice(&exact).unwrap();
        assert_eq!(decoded.version, 1);
        // Independent, empty verification cache: original authority is not
        // obtained from the RPC response and its assertions grant no trust.
        let trusted = super::super::super::authority::qualification_authority_with_provider(
            entries,
            Some(engine),
        );
        let verified = verify_finality_bytes(&exact, &trusted).unwrap();
        assert_eq!(verified.record, expected);
        let activation_evidence = serde_json::to_vec(&ingress.finality_proof(2).unwrap()).unwrap();
        let boundary = verify_finality_bytes(&activation_evidence, &trusted).unwrap();
        assert_eq!(&boundary.record, expected_boundary);
        let before = verify_block_commitment(&preimages[0], &verified.record).unwrap();
        let after = verify_block_commitment(&preimages[1], &boundary.record).unwrap();
        let verified_root = after.state_root;
        let genesis = "1".repeat(64);
        let pinned = ActivationRecordExpectation {
            chain_id: 23,
            network_id: "qualification-network".into(),
            genesis_hash: genesis.clone(),
            activation_height: 2,
            finalized_block_id: boundary.record.block_id.clone(),
            state_root: verified_root.into(),
            record_key: record_key.clone(),
            record_sha256: Primitives
                .hash(HashAlgorithm::Sha256, fixture_record)
                .unwrap()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
        };
        let observe = |world: &synergy_state::WorldState,
                       expectation: ActivationRecordExpectation| {
            inspect_expected_activation_record(
                world,
                &boundary.record,
                verified_root,
                23,
                "qualification-network",
                &genesis,
                &expectation,
            )
        };
        let transition = |prior_header: &VerifiedBlockCommitment<'_>,
                          prior_world: &synergy_state::WorldState,
                          next_header: &VerifiedBlockCommitment<'_>,
                          expectation: &ActivationRecordExpectation| {
            inspect_activation_transition(
                ActivationBoundaryEvidence {
                    finality: &verified,
                    block: prior_header,
                    world: prior_world,
                },
                ActivationBoundaryEvidence {
                    finality: &boundary,
                    block: next_header,
                    world: &world,
                },
                23,
                "qualification-network",
                &genesis,
                expectation,
            )
        };
        let introduced = transition(&before, &preceding_world, &after, &pinned).unwrap();
        assert_eq!(
            introduced["status"],
            "expected_record_introduced_at_finalized_boundary"
        );
        assert_eq!(introduced["predecessor"]["height"], 1);
        assert_eq!(
            introduced["predecessor"]["block_id"],
            verified.record.block_id
        );
        assert_eq!(introduced["boundary_record"]["activation_height"], 2);
        let unrelated_parent = VerifiedBlockCommitment {
            parent_block_id: "another-parent",
            state_root: after.state_root,
        };
        assert_eq!(
            transition(&before, &preceding_world, &unrelated_parent, &pinned).unwrap_err(),
            "activation proofs do not link adjacent certified blocks",
        );
        assert_eq!(
            transition(&before, &world, &after, &pinned).unwrap_err(),
            "activation predecessor World differs from its verified state root",
        );
        assert_eq!(
            transition(
                &VerifiedBlockCommitment {
                    parent_block_id: before.parent_block_id,
                    state_root: after.state_root
                },
                &world,
                &after,
                &pinned
            )
            .unwrap_err(),
            "expected activation record already existed in the finalized predecessor",
        );
        assert_eq!(
            transition(
                &before,
                &preceding_world,
                &after,
                &ActivationRecordExpectation {
                    record_key: "governance/qualification/absent".into(),
                    ..pinned.clone()
                }
            )
            .unwrap_err(),
            "expected activation record is absent at the verified boundary",
        );
        assert_eq!(
            observe(&world, pinned.clone()).unwrap()["status"],
            "exact_expected_record_finalized"
        );
        let mut altered = world.clone();
        altered.protocol.insert(record_key, vec![0xff]);
        assert!(observe(&altered, pinned.clone()).is_err());
        for wrong in [
            ActivationRecordExpectation {
                genesis_hash: "2".repeat(64),
                ..pinned.clone()
            },
            ActivationRecordExpectation {
                chain_id: 24,
                ..pinned.clone()
            },
            ActivationRecordExpectation {
                network_id: "other-network".into(),
                ..pinned.clone()
            },
            ActivationRecordExpectation {
                activation_height: 3,
                ..pinned.clone()
            },
            ActivationRecordExpectation {
                record_sha256: "3".repeat(64),
                ..pinned.clone()
            },
            ActivationRecordExpectation {
                record_key: "governance/qualification/../fixture-activation".into(),
                ..pinned.clone()
            },
        ] {
            assert!(observe(&world, wrong).is_err());
        }
        assert_eq!(
            observe(
                &world,
                ActivationRecordExpectation {
                    record_key: "governance/qualification/absent".into(),
                    ..pinned
                }
            )
            .unwrap()["status"],
            "expected_record_absent",
        );
        assert!(verified_consensus_position(&verified.record, &trusted).is_err());
        let timed = Arc::new(trusted.qualification_with_ingress(
            synergy_etdag::IngressKemKeyRegistry {
                context_root: synergy_etdag::EtdagDigest::from_domain_bytes(
                    "proof-test-registry",
                    b"",
                ),
                records: Vec::new(),
            },
        ));
        let (epoch, context, consensus_time) = verified_consensus_position(
            &verify_finality_bytes(&exact, &timed).unwrap().record,
            &timed,
        )
        .unwrap();
        assert_eq!(
            (epoch, context, consensus_time),
            (1, timed.epoch.root().unwrap(), 1000)
        );
        let mut future = verified.record.clone();
        future.height = timed.epoch.epoch_end_height + 1;
        assert!(verified_consensus_position(&future, &timed).is_err());
        let mut forged_clock: ClientFinalityEvidence = serde_json::from_slice(&exact).unwrap();
        forged_clock.finalized.height += 1;
        assert!(
            verify_finality_bytes(&serde_json::to_vec(&forged_clock).unwrap(), &timed).is_err()
        );
        let mut mismatched = serde_json::from_slice::<Value>(&exact).unwrap();
        mismatched["finalized"]["block_id"] = json!("substituted");
        assert!(
            verify_finality_bytes(&serde_json::to_vec(&mismatched).unwrap(), &trusted).is_err()
        );
        let mut verified = ThreeQcFinality::default();
        for qc in &decoded.witness.quorum_certificates {
            qc.verify(&trusted.epoch, &trusted.registry, trusted.as_ref())
                .unwrap();
            verified.accept(qc.clone()).unwrap();
        }
        assert!(decoded.witness.timeout_certificates.is_empty());
        assert_eq!(verified.last_finalized(), Some(&decoded.finalized));
        assert_eq!(decoded.finalized, expected);
        decoded.witness.quorum_certificates[0].participants[0].signature[0] ^= 1;
        assert!(decoded.witness.quorum_certificates[0]
            .verify(&trusted.epoch, &trusted.registry, trusted.as_ref())
            .is_err());
        if let Ok(directory) = std::env::var("SYNERGY_PUBLIC_PROOF_FIXTURES") {
            let directory = PathBuf::from(directory);
            // Explicit opt-in public outputs only, never overwrite evidence.
            std::fs::create_dir(&directory).unwrap();
            let mut negative_record: ClientFinalityEvidence =
                serde_json::from_slice(&exact).unwrap();
            negative_record.finalized.block_id = "substituted".into();
            let mut negative_signature: ClientFinalityEvidence =
                serde_json::from_slice(&exact).unwrap();
            negative_signature.witness.quorum_certificates[0].participants[0].signature[0] ^= 1;
            let public_trust = json!({"fixture_only":true,"epoch":trusted.epoch,
                "validators": pairs.iter().enumerate().map(|(i,p)| json!({
                    "validator_id":format!("proof-validator-{i}"),"key_id":format!("proof-key-{i}"),
                    "ml_dsa65_public_key_base64":BASE64.encode(&p.public_key)
                })).collect::<Vec<_>>()});
            for (name, bytes) in [
                ("proof-positive.json", exact.clone()),
                (
                    "proof-negative-record.json",
                    serde_json::to_vec(&negative_record).unwrap(),
                ),
                (
                    "proof-negative-signature.json",
                    serde_json::to_vec(&negative_signature).unwrap(),
                ),
                (
                    "fixture-public-trust.json",
                    serde_json::to_vec(&public_trust).unwrap(),
                ),
            ] {
                std::fs::write(directory.join(name), bytes).unwrap();
            }
        }
        drop(evidence);
        assert_eq!(budget.used(), 0);
    }
    #[test]
    fn proof_work_has_a_separate_bounded_request_budget() {
        let mut throttle = ProofThrottle::default();
        for _ in 0..4 {
            assert!(throttle.admit().is_ok());
        }
        assert!(throttle.admit().is_err());
        throttle.window = Some(Instant::now() - Duration::from_secs(2));
        assert!(throttle.admit().is_ok());
    }
}
