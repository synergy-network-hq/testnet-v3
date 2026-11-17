//! Read-only transport of existing commitments, without a new state-root format.
use super::*;
use serde::{Deserialize, Serialize};
use synergy_address_engine::apqe::{HashAlgorithm, HashStream, Primitives};

const MAX_PAGE: usize = 64 * 1024;
// A proof is a bounded transport of the existing commitment preimage, not a
// claim of a Merkle path for the current flat canonical state hash.
pub(super) const MAX_DOCUMENT: usize = 1024 * 1024;
// Streaming disclosure validation retains only one entry, not an entire typed
// table. Charge parser scratch plus page/base64/JSON response simultaneously.
pub(crate) const PROOF_SCRATCH: usize = MAX_DOCUMENT * 2 + MAX_PAGE * 4;

// Endpoint policy only: refuse expensive retained timeout searches rather than
// changing consensus validation or silently returning an incomplete witness.
pub(crate) fn charge_timeout_search(
    remaining: &mut u64,
    rounds: u64,
    lease: u64,
) -> Result<(), String> {
    let work = rounds
        .checked_mul(lease)
        .ok_or("proof timeout work overflow")?;
    *remaining = remaining
        .checked_sub(work)
        .ok_or("proof timeout verification capacity exhausted")?;
    Ok(())
}

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

/// Verify against caller-selected authenticated history, never a public key or
/// authority selected by the proof. The returned record is what clients match
/// against their independently recomputed block/preimage commitments.
fn verify_finality_bytes(
    bytes: &[u8],
    authority: &Arc<super::super::authority::VerifiedAuthority>,
) -> Result<synergy_posy::FinalizedBlockRecord, String> {
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
    Ok(evidence.finalized)
}

pub(crate) fn verify_finality_proof_cli(args: impl Iterator<Item = String>) -> Result<(), String> {
    let args: Vec<_> = args.collect();
    let [action, config, proof] = args.as_slice() else {
        return Err("usage: finality-proof verify CONFIG REASSEMBLED_PROOF_JSON".into());
    };
    if action != "verify" {
        return Err("finality-proof supports verify only".into());
    }
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
    let verified = verify_finality_bytes(&bytes, &authority)?;
    println!(
        "{}",
        json!({"version":1,"verified":true,"chain_id":configuration.chain_id,
        "network_id":configuration.network_id,"genesis_hash":genesis_hash,"finalized":verified})
    );
    Ok(())
}

impl CanonicalQueryStore {
    pub(super) fn canonical_proof_page(&self, value: &Value) -> Result<Value, RpcError> {
        let query = ProofQuery::decode(value.clone())?;
        // Charge retained response scratch separately from the budgeted World.
        let _permit = self
            .world_budget
            .reserve(PROOF_SCRATCH)
            .map_err(|error| RpcError::unavailable(error.to_string()))?;
        let (candidate, _) = self
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
                require_public_world(&candidate.state)?;
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
fn require_public_world(world: &synergy_state::WorldState) -> Result<(), RpcError> {
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
            _ => return Err(invalid()),
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
    assert_eq!(verify_finality_bytes(&exact, &active).unwrap(), expected);
    let mut invalid: ClientFinalityEvidence = serde_json::from_slice(&exact).unwrap();
    invalid.witness.timeout_certificates[0].highest_qc_proofs[0].participants[0].signature[0] ^= 1;
    assert!(verify_finality_bytes(&serde_json::to_vec(&invalid).unwrap(), &active).is_err());
}

#[cfg(test)]
mod tests {
    use super::*;
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
        assert!(require_public_world(&world).is_ok());
        world
            .protocol
            .insert("private-application-state".into(), b"secret".to_vec());
        assert!(require_public_world(&world).is_err());
        world.protocol.clear();
        let key = "etdag-processing-ready-v1/meta";
        let mut metadata = json!({"namespace_root":"a".repeat(128),"generation":0,"count":0});
        world
            .protocol
            .insert(key.into(), serde_json::to_vec(&metadata).unwrap());
        assert!(require_public_world(&world).is_ok());
        metadata["secret"] = json!("must not be disclosed");
        world
            .protocol
            .insert(key.into(), serde_json::to_vec(&metadata).unwrap());
        assert!(require_public_world(&world).is_err());
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
        require_public_world(&world).unwrap();
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
    fn proof_timeout_work_is_aggregate_checked_and_fail_closed() {
        let mut remaining = 128;
        charge_timeout_search(&mut remaining, 3, 10).unwrap();
        assert_eq!(remaining, 98);
        assert!(charge_timeout_search(&mut remaining, 10, 10).is_err());
        assert_eq!(remaining, 98);
        assert!(charge_timeout_search(&mut remaining, u64::MAX, 2).is_err());
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
        for height in 1..=3 {
            let votes = pairs
                .iter()
                .take(4)
                .enumerate()
                .map(|(i, pair)| {
                    let mut vote = BlockVote {
                        context: ConsensusObjectContext::for_height(&authority.epoch, height, 0)
                            .unwrap(),
                        block_id: format!("proof-block-{height}"),
                        parent_block_id: parent.block_id().into(),
                        parent: parent.clone(),
                        takeover_tc_id: None,
                        protected_execution_root: "e".repeat(64),
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
        }
        let expected = finality.last_finalized().unwrap().clone();
        synergy_posy::persistence::FinalityStore::new(&scratch.0)
            .unwrap()
            .commit_exactly_once(&expected, None)
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
        assert_eq!(verify_finality_bytes(&exact, &trusted).unwrap(), expected);
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
