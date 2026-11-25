//! Native execution recovery inputs carried by the existing certified replay.
//! Every capability is reconstructed from original authentication, old three-QC
//! source, weighted availability, VC and threshold shares. No donor flag grants
//! membership, execution or finality authority.
use super::{
    authority::VerifiedAuthority,
    etdag_wallet_admission::RuntimeProcessingAdmission,
    ingress::AuthenticatedIngress,
    processing_pipeline::*,
    processing_store::{ProcessingAdmissionAuthenticator, ProcessingAdmissionRecord},
};
use serde::{Deserialize, Serialize};
use std::{path::Path, sync::Arc};
use synergy_etdag::{execution::ProcessingVertex, EtdagDigest, ProcessingContext};
use synergy_execution::{decode_budgeted_candidate, BudgetedCandidateStore};
const MAX: usize = 8 * 1024 * 1024;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Witness {
    version: u8,
    context: ProcessingContext,
    admission: String,
    progress: ProcessingProgressEvidence,
    completion: Option<ProcessingCompletionEvidence>,
    source_candidate: Option<String>,
    source_finality: Option<[synergy_posy::SimplifiedQuorumCertificate; 3]>,
    reveal_parent: Option<String>,
}
pub(super) struct Export {
    pub vertex_id: EtdagDigest,
    pub bytes: String,
    pub completion: bool,
    pub _permit: synergy_state::world_resources::WorldResourcePermit,
}
pub(super) fn capture(
    context: &ProcessingContext,
    admission: &RuntimeProcessingAdmission,
    progress: &ProcessingProgressEvidence,
    completion: Option<&ProcessingCompletionEvidence>,
    candidate_root: &Path,
    ingress: &AuthenticatedIngress,
    budget: &Arc<synergy_state::world_resources::WorldResourceBudget>,
) -> Result<Export, String> {
    let store = BudgetedCandidateStore::new_budgeted(candidate_root, budget.clone())?;
    let (source_candidate, source_finality) = if context.authority.source_finalized_height == 0 {
        (None, None)
    } else {
        let h = context.authority.source_finalized_height;
        let (_, witness) = ingress
            .finalized_record_with_witness(h)?
            .ok_or("handoff original source finality unavailable")?;
        let candidate = store
            .get_budgeted(h)
            .map_err(|e| e.to_string())?
            .ok_or("handoff original source World unavailable")?;
        (
            Some(serde_json::to_string(&candidate).map_err(|e| e.to_string())?),
            Some(witness),
        )
    };
    let reveal_parent = completion
        .map(|e| -> Result<String, String> {
            store
                .get_budgeted(e.reveal_validation.context.height)
                .map_err(|e| e.to_string())?
                .ok_or("handoff reveal parent unavailable".to_string())
                .and_then(|v| serde_json::to_string(&v).map_err(|e| e.to_string()))
        })
        .transpose()?;
    let vertex = ProcessingVertex {
        vertex_version: progress.vertex_version,
        admission: admission.clone(),
        envelope_ref: progress.envelope_ref.clone(),
        parents: progress.parents.clone(),
        author_id: progress.author_id.clone(),
        key_id: progress.key_id.clone(),
        author_signature: progress.author_signature.clone(),
    };
    let vertex_id = vertex.id().map_err(|e| format!("{e:?}"))?;
    let mut progress = progress.clone();
    progress.shares.clear();
    progress.reveal_validation = None;
    let witness = Witness {
        version: 1,
        context: context.clone(),
        admission: serde_json::to_string(admission).map_err(|e| e.to_string())?,
        progress,
        completion: completion.cloned(),
        source_candidate,
        source_finality,
        reveal_parent,
    };
    let bytes = serde_json::to_string(&witness).map_err(|e| e.to_string())?;
    if bytes.len() > MAX {
        return Err("native recovery witness exceeds existing replay bound".into());
    }
    let permit = budget
        .reserve(bytes.len() + 4096)
        .map_err(|e| e.to_string())?;
    Ok(Export {
        vertex_id,
        bytes,
        completion: completion.is_some(),
        _permit: permit,
    })
}
pub(super) fn recover(
    bytes: &str,
    lineage: &Arc<VerifiedAuthority>,
    ingress: &AuthenticatedIngress,
) -> Result<(), String> {
    if bytes.is_empty() || bytes.len() > MAX {
        return Err("native recovery witness exceeds bound".into());
    }
    if bytes.starts_with("{\"bootstrap_candidate\":") {
        return recover_bootstrap(bytes, lineage, ingress);
    }

    let budget = ingress.world_budget();
    let _decode = budget
        .reserve(bytes.len().checked_mul(6).ok_or("handoff size overflow")?)
        .map_err(|e| e.to_string())?;
    let w: Witness = serde_json::from_str(bytes).map_err(|e| e.to_string())?;
    if w.version != 1 {
        return Err("unknown native recovery witness".into());
    }
    let authority = lineage
        .autonomous_authority_at(w.context.authority.target_height)
        .ok_or("handoff lacks authenticated original authority")?;
    let admission = RuntimeProcessingAdmission::decode_original(&w.admission, &w.context)
        .map_err(|e| e.to_string())?;
    admission
        .validate_context(&w.context)
        .map_err(|e| format!("{e:?}"))?;
    let genesis = if w.context.authority.source_finalized_height == 0 {
        Some(authority.initial_world_state_budgeted(budget)?)
    } else {
        None
    };
    let source = if w.context.authority.source_finalized_height == 0 {
        if w.source_candidate.is_some() || w.source_finality.is_some() {
            return Err("Genesis handoff has unrelated source".into());
        }
        NativeProcessingContext::verify_in(
            authority,
            &w.context,
            ProcessingSource::Genesis(genesis.as_ref().unwrap()),
            budget,
        )?
    } else {
        let candidate = decode_budgeted_candidate(
            w.source_candidate
                .as_deref()
                .ok_or("handoff source World missing")?
                .as_bytes(),
            budget,
        )
        .map_err(|e| e.to_string())?;
        let witness = w
            .source_finality
            .as_ref()
            .ok_or("handoff source three-QC missing")?;
        if is_pw13_context(&w.context) {
            NativeProcessingContext::verify_owned_wallet_source(
                authority, &w.context, candidate, witness, budget,
            )?
        } else {
            NativeProcessingContext::verify_owned_finalized_with_transition(
                authority, &w.context, candidate, witness, budget, None,
            )?
        }
    }
    .with_lineage(lineage)?;
    let snapshot = ingress
        .processing_snapshot()?
        .ok_or("native recovery budget unavailable")?;
    let parents = w
        .progress
        .parents
        .iter()
        .map(|id| {
            snapshot
                .members
                .iter()
                .find(|m| m.vertex_id() == id)
                .map(AsRef::as_ref)
                .ok_or("native recovery DAG parent missing")
        })
        .collect::<Result<Vec<_>, _>>()?;
    let vertex = ProcessingVertex {
        vertex_version: w.progress.vertex_version,
        admission: admission.clone(),
        envelope_ref: w.progress.envelope_ref.clone(),
        parents: w.progress.parents.clone(),
        author_id: w.progress.author_id.clone(),
        key_id: w.progress.key_id.clone(),
        author_signature: w.progress.author_signature.clone(),
    };
    let authenticate = |value: &RuntimeProcessingAdmission| match value {
        RuntimeProcessingAdmission::Ordinary(value) => source.verify(
            &w.context,
            source.persisted_authorization_timestamp()?,
            value,
        ),
        RuntimeProcessingAdmission::Ethereum(value) => source.authenticate_ethereum(value),
        RuntimeProcessingAdmission::Protected(value) => {
            super::protected_accounts::processing_execution::with_native_protected_intake(
                &source,
                |intake| intake.authorize(value).map(drop),
            )
        }
    };
    let native = NativeProcessingVertex::verify_authenticated(
        &source,
        &vertex,
        w.progress.availability.as_ref(),
        &parents,
        budget,
        authenticate,
    )?;
    let member = Arc::new(native.retain_member(budget)?);
    if let Some(evidence) = &w.completion {
        let parent = decode_budgeted_candidate(
            w.reveal_parent
                .as_deref()
                .ok_or("native recovery reveal parent missing")?
                .as_bytes(),
            budget,
        )
        .map_err(|e| e.to_string())?;
        let recovery = NativeProcessingRecovery {
            source: &source,
            reveal_parent: &parent,
            dag_parents: &parents,
        };
        match &admission {
            RuntimeProcessingAdmission::Ordinary(value) => ingress.publish_processing_completion(
                Arc::new(recovery.recover(value, evidence, budget)?),
            )?,
            RuntimeProcessingAdmission::Ethereum(value) => ingress.publish_processing_completion(
                Arc::new(recovery.recover_ethereum(value, evidence, budget)?),
            )?,
            RuntimeProcessingAdmission::Protected(value) => {
                let (opened, _) =
                    super::protected_accounts::processing_execution::with_native_protected_intake(
                        &source,
                        |intake| {
                            recovery.recover_pw13(value, evidence, budget, |original| {
                                intake.authorize(original)
                            })
                        },
                    )?;
                let completion=super::protected_accounts::processing_execution::NativeProtectedCompletion::retain(&source,value,&parent.state,opened,budget)?;
                ingress.publish_processing_wallet_completion(Arc::new(completion))?;
            }
        }
    } else if w.reveal_parent.is_some() {
        return Err("member handoff has unrelated reveal World".into());
    }
    let export = Export {
        vertex_id: member.vertex_id().clone(),
        bytes: bytes.to_owned(),
        completion: w.completion.is_some(),
        _permit: budget
            .reserve(bytes.len() + 4096)
            .map_err(|e| e.to_string())?,
    };
    ingress.publish_processing_handoff(admission.identity().envelope_id, export)?;
    ingress.publish_processing_member(member)
}
#[cfg(test)]
pub(super) fn qualify_genesis(
    context: &ProcessingContext,
    admission: &synergy_etdag::WalletProcessingAdmission,
    progress: &ProcessingProgressEvidence,
    completion: &ProcessingCompletionEvidence,
    parent: &synergy_execution::BudgetedExecutionCandidate,
    lineage: &Arc<VerifiedAuthority>,
) {
    let recipient = AuthenticatedIngress::with_world_budget(
        synergy_state::world_resources::WorldResourceBudget::new(256 * 1024 * 1024),
    );
    let w = Witness {
        version: 1,
        context: context.clone(),
        admission: serde_json::to_string(admission).unwrap(),
        progress: progress.clone(),
        completion: Some(completion.clone()),
        source_candidate: None,
        source_finality: None,
        reveal_parent: Some(serde_json::to_string(parent).unwrap()),
    };
    let bytes = serde_json::to_string(&w).unwrap();
    recover(&bytes, lineage, &recipient).unwrap();
    let snapshot = recipient.processing_snapshot().unwrap().unwrap();
    assert_eq!(snapshot.members.len(), 1);
    assert_eq!(snapshot.completions.len(), 1);
    assert_eq!(snapshot.completions[0].record, completion.record);
    let fresh = AuthenticatedIngress::with_world_budget(
        synergy_state::world_resources::WorldResourceBudget::new(256 * 1024 * 1024),
    );
    let mut bad: serde_json::Value = serde_json::from_str(&bytes).unwrap();
    bad["completion"]["shares"][0]["signature"][0] = serde_json::json!(255);
    assert!(recover(&serde_json::to_string(&bad).unwrap(), lineage, &fresh).is_err());
    assert!(fresh
        .processing_snapshot()
        .unwrap()
        .unwrap()
        .completions
        .is_empty());
    let mut bad: serde_json::Value = serde_json::from_str(&bytes).unwrap();
    bad["progress"]["author_signature"][0] = serde_json::json!(255);
    assert!(recover(&serde_json::to_string(&bad).unwrap(), lineage, &fresh).is_err());
    // A cold restart reconstructs the same capabilities from original public
    // witness bytes, without a pending ledger, old private ingress key or donor
    // finality/completion flag.
    recover(&bytes, lineage, &fresh).unwrap();
    assert_eq!(
        fresh.processing_snapshot().unwrap().unwrap().completions[0].record,
        completion.record
    );
    // Exercise the actual closed authenticated Sync chunk decoder and durable
    // recovery owner, rather than giving the receiver a full frame bypass.
    let wire_recipient = AuthenticatedIngress::with_world_budget(
        synergy_state::world_resources::WorldResourceBudget::new(256 * 1024 * 1024),
    );
    let id = completion.record.item.envelope_id.clone();
    wire_recipient
        .request_processing_handoff(id.clone(), true)
        .unwrap();
    let peer = synergy_protocol_types::AuthenticatedPeer::new(
        lineage
            .registry
            .active()
            .next()
            .unwrap()
            .validator_id
            .clone(),
        synergy_protocol_types::SessionId(411),
        vec![],
    )
    .unwrap();
    wire_recipient
        .admit_session(peer.node_address.to_string(), peer.session_id)
        .unwrap();
    let mut transport = Transport::default();
    use base64::Engine;
    let response = |offset: usize| synergy_network::protocol::InboundFrame {
        peer: peer.clone(),
        protocol: synergy_protocol_types::ProtocolKind::Sync,
        payload: serde_json::to_vec(&Wire {
            profile: "synergy-native-processing-handoff-v1".into(),
            id: id.clone(),
            completion: true,
            anchor_height: None,
            offset,
            total: bytes.len(),
            sha256: super::apqe_transport::sha256(bytes.as_bytes()),
            chunk: base64::engine::general_purpose::STANDARD
                .encode(&bytes.as_bytes()[offset..bytes.len().min(offset + CHUNK)]),
        })
        .unwrap(),
    };
    transport.route(&response(CHUNK), &wire_recipient).unwrap();
    assert!(transport.incoming.is_empty());
    for offset in (0..bytes.len()).step_by(CHUNK) {
        assert!(transport.route(&response(offset), &wire_recipient).unwrap());
    }
    let root = std::env::temp_dir().join(format!(
        "synergy-native-handoff-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    struct Clean(std::path::PathBuf);
    impl Drop for Clean {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let _clean = Clean(root.clone());
    transport.poll(lineage, &wire_recipient, &root).unwrap();
    assert!(wire_recipient
        .processing_handoff_requests()
        .unwrap()
        .is_empty());
    assert_eq!(
        wire_recipient
            .processing_snapshot()
            .unwrap()
            .unwrap()
            .completions[0]
            .record,
        completion.record
    );
    let restarted = AuthenticatedIngress::with_world_budget(
        synergy_state::world_resources::WorldResourceBudget::new(256 * 1024 * 1024),
    );
    restarted.request_processing_handoff(id, true).unwrap();
    Transport::default()
        .poll(lineage, &restarted, &root)
        .unwrap();
    assert_eq!(
        restarted
            .processing_snapshot()
            .unwrap()
            .unwrap()
            .completions[0]
            .record,
        completion.record
    );
    assert!(restarted.authenticated_peers().unwrap().is_empty());
    eprintln!("Actual native cold execution handoff {}B: original author/availability/VC/threshold verification, no old private key; tamper denied, restart replay identical",bytes.len());
}

// Bounded pull over the existing authenticated Sync channel. The responder
// supplies one requested chunk at a time; replay never expands a block or its
// consensus message by the sum of all witnesses in a full ordering group.
const CHUNK: usize = 48 * 1024;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Wire {
    profile: String,
    id: EtdagDigest,
    completion: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    anchor_height: Option<u64>,
    offset: usize,
    total: usize,
    sha256: String,
    chunk: String,
}
struct Incoming {
    started: std::time::Instant,
    peer: String,
    total: usize,
    sha256: String,
    bytes: Vec<u8>,
    _permit: synergy_state::world_resources::WorldResourcePermit,
}
#[derive(Default)]
pub(super) struct Transport {
    incoming: std::collections::BTreeMap<EtdagDigest, Incoming>,
    last: Option<std::time::Instant>,
    cursor: usize,
    prune_cursor: usize,
}
impl Transport {
    pub(super) fn route(
        &mut self,
        frame: &synergy_network::protocol::InboundFrame,
        ingress: &AuthenticatedIngress,
    ) -> Result<bool, String> {
        // A fixed leading field distinguishes this closed native extension before
        // the ordinary Sync decoder; no new remote authority is selected from it.
        if !frame
            .payload
            .starts_with(b"{\"profile\":\"synergy-native-processing-handoff-v1\"")
        {
            return Ok(false);
        }
        if frame.payload.len() > CHUNK * 2 || !ingress.is_current_session(&frame.peer)? {
            return Ok(true);
        }
        let w: Wire = match serde_json::from_slice(&frame.payload) {
            Ok(v) => v,
            Err(_) => return Ok(true),
        };
        if w.id.validate().is_err() || w.profile != "synergy-native-processing-handoff-v1" {
            return Ok(true);
        }
        if w.total == 0 {
            if !w.chunk.is_empty() || !w.sha256.is_empty() {
                return Ok(true);
            }
            if let Some(bytes) = ingress.processing_handoff_bytes(&w.id, w.completion)? {
                if w.offset >= bytes.len() || w.offset % CHUNK != 0 {
                    return Ok(true);
                }
                use base64::Engine;
                let response = Wire {
                    profile: w.profile,
                    id: w.id,
                    completion: w.completion,
                    anchor_height: w.anchor_height,
                    offset: w.offset,
                    total: bytes.len(),
                    sha256: super::apqe_transport::sha256(bytes.as_bytes()),
                    chunk: base64::engine::general_purpose::STANDARD
                        .encode(&bytes.as_bytes()[w.offset..bytes.len().min(w.offset + CHUNK)]),
                };
                let _ = ingress.try_publish_outbound(super::ingress::OutboundFrame {
                    peer_id: frame.peer.node_address.to_string(),
                    protocol: synergy_protocol_types::ProtocolKind::Sync,
                    payload: serde_json::to_vec(&response).map_err(|e| e.to_string())?,
                })?;
            } else if let Some(height) = w.anchor_height {
                ingress.request_processing_bootstrap_export(w.id, height)?;
            } else {
                ingress.request_processing_handoff_export(w.id)?;
            }
            return Ok(true);
        }
        let wants = ingress.processing_handoff_requests()?;
        if !wants
            .iter()
            .any(|(id, complete)| id == &w.id && (!complete || w.completion))
            || w.total > MAX
            || w.offset % CHUNK != 0
            || !synergy_posy::is_hash(&w.sha256)
        {
            return Ok(true);
        }
        use base64::Engine;
        let chunk = match base64::engine::general_purpose::STANDARD.decode(&w.chunk) {
            Ok(v) => v,
            Err(_) => return Ok(true),
        };
        if chunk.len() != CHUNK.min(w.total.saturating_sub(w.offset))
            || chunk.is_empty()
            || base64::engine::general_purpose::STANDARD.encode(&chunk) != w.chunk
        {
            return Ok(true);
        }
        if !self.incoming.contains_key(&w.id) {
            if w.offset != 0 || self.incoming.len() >= 4 {
                return Ok(true);
            }
            let permit = match ingress
                .world_budget()
                .reserve(w.total.saturating_mul(2) + 65536)
            {
                Ok(p) => p,
                Err(_) => return Ok(true),
            };
            self.incoming.insert(
                w.id.clone(),
                Incoming {
                    started: std::time::Instant::now(),
                    peer: frame.peer.node_address.to_string(),
                    total: w.total,
                    sha256: w.sha256.clone(),
                    bytes: Vec::with_capacity(w.total),
                    _permit: permit,
                },
            );
        }
        let entry = self.incoming.get_mut(&w.id).unwrap();
        if entry.peer != frame.peer.node_address.to_string()
            || entry.total != w.total
            || entry.sha256 != w.sha256
            || entry.bytes.len() != w.offset
        {
            return Ok(true);
        }
        entry.bytes.extend_from_slice(&chunk);
        Ok(true)
    }
    pub(super) fn poll(
        &mut self,
        authority: &Arc<VerifiedAuthority>,
        ingress: &AuthenticatedIngress,
        root: &Path,
    ) -> Result<(), String> {
        let now = std::time::Instant::now();
        if self
            .last
            .is_some_and(|v| now.duration_since(v) < std::time::Duration::from_millis(250))
        {
            return Ok(());
        }
        self.last = Some(now);
        let complete = self
            .incoming
            .iter()
            .filter(|(_, v)| v.bytes.len() == v.total)
            .map(|(id, _)| id.clone())
            .collect::<Vec<_>>();
        for id in complete {
            let entry = &self.incoming[&id];
            if super::apqe_transport::sha256(&entry.bytes) != entry.sha256 {
                self.incoming.remove(&id);
                continue;
            }
            let Ok(bytes) = std::str::from_utf8(&entry.bytes) else {
                self.incoming.remove(&id);
                continue;
            };
            if recover(bytes, authority, ingress).is_ok()
                && ingress
                    .processing_handoff_bytes(
                        &id,
                        ingress
                            .processing_handoff_requests()?
                            .iter()
                            .find(|(key, _)| key == &id)
                            .is_some_and(|(_, complete)| *complete),
                    )?
                    .is_some()
            {
                if !bytes.starts_with("{\"bootstrap_candidate\":") {
                    let store =
                        synergy_storage::AtomicStore::new(root, MAX).map_err(|e| e.to_string())?;
                    let witness: Witness =
                        serde_json::from_str(bytes).map_err(|e| e.to_string())?;
                    let admission = RuntimeProcessingAdmission::decode_original(
                        &witness.admission,
                        &witness.context,
                    )
                    .map_err(|e| e.to_string())?;
                    let vertex = ProcessingVertex {
                        vertex_version: witness.progress.vertex_version,
                        admission,
                        envelope_ref: witness.progress.envelope_ref.clone(),
                        parents: witness.progress.parents,
                        author_id: witness.progress.author_id,
                        key_id: witness.progress.key_id,
                        author_signature: witness.progress.author_signature,
                    };
                    let vertex_id = vertex.id().map_err(|e| format!("{e:?}"))?;
                    let envelope = witness.progress.envelope_ref.tx_commitment;
                    let path = format!(
                        "{}-{}.json",
                        envelope.0,
                        if witness.completion.is_some() {
                            "complete"
                        } else {
                            "member"
                        }
                    );
                    if !root.join(&path).try_exists().map_err(|e| e.to_string())? {
                        store
                            .put_once_atomic(&[synergy_storage::StorageWrite {
                                relative_path: path.into(),
                                bytes: entry.bytes.clone(),
                            }])
                            .map_err(|e| e.to_string())?;
                    }
                    store
                        .put_once_atomic(&[synergy_storage::StorageWrite {
                            relative_path: format!("{}.link", vertex_id.0).into(),
                            bytes: envelope.0.as_bytes().to_vec(),
                        }])
                        .map_err(|e| e.to_string())?;
                }
                ingress.complete_processing_handoff(&id)?;
                self.incoming.remove(&id);
            } else if let Ok(w) = serde_json::from_str::<Witness>(bytes) {
                // Closed DAG ancestry is itself independently checked by native recovery.
                // A bounded request only obtains bytes; it cannot create a parent token.
                for parent in w.progress.parents {
                    ingress.request_processing_handoff(parent, false)?;
                }
                self.incoming.remove(&id);
            } else {
                self.incoming.remove(&id);
            }
        }
        self.incoming
            .retain(|_, v| now.duration_since(v.started) < std::time::Duration::from_secs(10));
        prune_orphan_link(root, &mut self.prune_cursor)?;
        let requests = ingress.processing_handoff_requests()?;
        for (id, complete) in requests.iter().take(2) {
            if load_local(root, id, *complete, authority, ingress)? {
                ingress.complete_processing_handoff(id)?;
            }
        }
        let requests = ingress.processing_handoff_requests()?;
        if requests.is_empty() {
            return Ok(());
        }
        let peers = ingress.authenticated_peers()?;
        if peers.is_empty() {
            return Ok(());
        }
        for _ in 0..2 {
            let (id, completion) = &requests[self.cursor % requests.len()];
            let peer = &peers[(self.cursor / requests.len()) % peers.len()];
            self.cursor = self.cursor.wrapping_add(1);
            if load_local(root, id, *completion, authority, ingress)? {
                ingress.complete_processing_handoff(id)?;
                continue;
            }
            let offset = self.incoming.get(id).map_or(0, |v| v.bytes.len());
            if self.incoming.get(id).is_some_and(|v| offset == v.total) {
                continue;
            }
            let peer = self
                .incoming
                .get(id)
                .map_or(peer.as_str(), |v| v.peer.as_str());
            let request = Wire {
                profile: "synergy-native-processing-handoff-v1".into(),
                id: id.clone(),
                completion: *completion,
                anchor_height: ingress.processing_bootstrap_height(id)?,
                offset,
                total: 0,
                sha256: String::new(),
                chunk: String::new(),
            };
            let _ = ingress.try_publish_outbound(super::ingress::OutboundFrame {
                peer_id: peer.into(),
                protocol: synergy_protocol_types::ProtocolKind::Sync,
                payload: serde_json::to_vec(&request).map_err(|e| e.to_string())?,
            })?;
        }
        Ok(())
    }
}
pub(super) fn load_local(
    root: &Path,
    id: &EtdagDigest,
    completion: bool,
    authority: &Arc<VerifiedAuthority>,
    ingress: &AuthenticatedIngress,
) -> Result<bool, String> {
    let link = root.join(format!("{}.link", id.0));
    let linked = if link.try_exists().map_err(|e| e.to_string())? {
        let raw = super::apqe_transport::read(&link, 256, false)?;
        let value = EtdagDigest(std::str::from_utf8(&raw).map_err(|e| e.to_string())?.into());
        value.validate().map_err(|e| format!("{e:?}"))?;
        Some(value)
    } else {
        None
    };
    let id = linked.as_ref().unwrap_or(id);
    let complete = root.join(format!("{}-complete.json", id.0));
    let path = if completion || complete.try_exists().map_err(|e| e.to_string())? {
        complete
    } else {
        root.join(format!("{}-member.json", id.0))
    };
    if !path.try_exists().map_err(|e| e.to_string())? {
        return Ok(false);
    }
    let bytes = super::apqe_transport::read(&path, MAX as u64, false)?;
    let bytes = std::str::from_utf8(&bytes).map_err(|e| e.to_string())?;
    let recovered = recover(bytes, authority, ingress).is_ok();
    if !recovered {
        if let Ok(w) = serde_json::from_str::<Witness>(bytes) {
            for id in w.progress.parents {
                ingress.request_processing_handoff(id, false)?;
            }
        }
    }
    Ok(recovered)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Bootstrap {
    bootstrap_candidate: String,
    processing_replay: String,
}
pub(super) fn bootstrap_id(block_id: &str) -> EtdagDigest {
    EtdagDigest::from_domain_bytes(
        "SYNERGY_NATIVE_PROCESSING_BOOTSTRAP_V1",
        block_id.as_bytes(),
    )
}
pub(super) fn publish_bootstrap(
    candidate: &synergy_execution::BudgetedExecutionCandidate,
    replay: &[u8],
    ingress: &AuthenticatedIngress,
) -> Result<(), String> {
    let id = bootstrap_id(&candidate.block_id);
    let bytes = serde_json::to_string(&Bootstrap {
        bootstrap_candidate: serde_json::to_string(candidate).map_err(|e| e.to_string())?,
        processing_replay: std::str::from_utf8(replay)
            .map_err(|e| e.to_string())?
            .into(),
    })
    .map_err(|e| e.to_string())?;
    if bytes.len() > MAX {
        return Err("bootstrap candidate exceeds existing native Sync bound".into());
    }
    let permit = ingress
        .world_budget()
        .reserve(bytes.len() + 4096)
        .map_err(|e| e.to_string())?;
    ingress.publish_processing_handoff(
        id.clone(),
        Export {
            vertex_id: id,
            bytes,
            completion: false,
            _permit: permit,
        },
    )
}
fn recover_bootstrap(
    bytes: &str,
    lineage: &Arc<VerifiedAuthority>,
    ingress: &AuthenticatedIngress,
) -> Result<(), String> {
    let _decode = ingress
        .world_budget()
        .reserve(bytes.len().saturating_mul(4))
        .map_err(|e| e.to_string())?;
    let payload: Bootstrap = serde_json::from_str(bytes).map_err(|e| e.to_string())?;
    let candidate = decode_budgeted_candidate(
        payload.bootstrap_candidate.as_bytes(),
        ingress.world_budget(),
    )
    .map_err(|e| e.to_string())?;
    let authority = lineage
        .autonomous_authority_at(candidate.height)
        .ok_or("bootstrap lacks original authenticated authority")?;
    authority.verify_processing_candidate(&candidate)?;
    let (record, _) = ingress
        .finalized_record_with_witness(candidate.height)?
        .ok_or("bootstrap lacks locally verified original three-QC finality")?;
    if candidate.block_id != record.block_id
        || candidate.protected_execution_root != record.protected_execution_root
    {
        return Err("bootstrap candidate differs from old-authority finality".into());
    }
    publish_bootstrap(&candidate, payload.processing_replay.as_bytes(), ingress)?;
    ingress.submit_verified_sync_candidate(Arc::new(candidate), record)
}
pub(super) fn bootstrap_replay(
    block_id: &str,
    ingress: &AuthenticatedIngress,
) -> Result<Option<String>, String> {
    ingress
        .processing_handoff_bytes(&bootstrap_id(block_id), false)?
        .map(|bytes| {
            serde_json::from_str::<Bootstrap>(&bytes)
                .map(|v| v.processing_replay)
                .map_err(|e| e.to_string())
        })
        .transpose()
}
#[cfg(test)]
pub(super) fn qualify_bootstrap(
    candidate: &synergy_execution::BudgetedExecutionCandidate,
    qcs: [synergy_posy::SimplifiedQuorumCertificate; 3],
    vc: &synergy_posy::ProposalValidationCertificate,
    lineage: &Arc<VerifiedAuthority>,
    root: &Path,
) {
    let mut driver = synergy_posy::ThreeQcFinality::default();
    for qc in &qcs {
        driver.accept(qc.clone()).unwrap();
    }
    let finalized = driver.last_finalized().unwrap().clone();
    let witness = synergy_posy::FinalitySyncWitness {
        quorum_certificates: qcs.clone(),
        timeout_certificates: vec![],
    };
    let posy = root.join("handoff-bootstrap-posy");
    synergy_posy::persistence::AtomicConsensusTransitionStore::new(&posy)
        .unwrap()
        .commit_verified_snapshot_anchor(
            &finalized,
            &witness,
            &lineage.epoch,
            &lineage.registry,
            lineage.as_ref(),
        )
        .unwrap();
    let recipient = AuthenticatedIngress::with_world_budget(
        synergy_state::world_resources::WorldResourceBudget::new(128 * 1024 * 1024),
    );
    recipient
        .install_finality_history(posy, lineage.clone())
        .unwrap();
    let inputs = super::processing_proposals::ProcessingProposalInputs {
        context: qcs[0].context.clone(),
        parent: qcs[0].parent.clone(),
        takeover_id: None,
        block_id: candidate.block_id.clone(),
        state_root: candidate.state_root.clone(),
        protected_execution_root: candidate.protected_execution_root.clone(),
        ordered_group: None,
        publications: vec![],
        certified_ancestors: vec![],
    };
    let replay = serde_json::to_vec(&(1u32, &inputs, vc)).unwrap();
    let payload = serde_json::to_string(&Bootstrap {
        bootstrap_candidate: serde_json::to_string(candidate).unwrap(),
        processing_replay: String::from_utf8(replay.clone()).unwrap(),
    })
    .unwrap();
    recover(&payload, lineage, &recipient).unwrap();
    let (restored, record) = recipient.take_verified_sync_candidate().unwrap().unwrap();
    assert_eq!(record, finalized);
    assert_eq!(restored.block_id, candidate.block_id);
    assert_eq!(restored.state_root, candidate.state_root);
    let mut journal = super::processing_proposals::ProcessingProposalStore::open(
        &root.join("handoff-bootstrap-replay"),
        processing_namespace(lineage, recipient.world_budget()).unwrap(),
        recipient.world_budget(),
        lineage.clone(),
    )
    .unwrap();
    journal
        .try_import_certified(
            bootstrap_replay(&candidate.block_id, &recipient)
                .unwrap()
                .unwrap()
                .as_bytes(),
            &qcs[0],
        )
        .unwrap();
    assert!(journal.has_validation(&candidate.block_id));
    let empty = AuthenticatedIngress::with_world_budget(
        synergy_state::world_resources::WorldResourceBudget::new(128 * 1024 * 1024),
    );
    assert!(recover(&payload, lineage, &empty).is_err());
    assert!(empty.take_verified_sync_candidate().unwrap().is_none());
    let mut corrupted: serde_json::Value = serde_json::from_str(&payload).unwrap();
    let mut changed: serde_json::Value =
        serde_json::from_str(corrupted["bootstrap_candidate"].as_str().unwrap()).unwrap();
    changed["state_root"] = serde_json::json!("ff".repeat(32));
    corrupted["bootstrap_candidate"] = serde_json::json!(serde_json::to_string(&changed).unwrap());
    assert!(recover(
        &serde_json::to_string(&corrupted).unwrap(),
        lineage,
        &recipient
    )
    .is_err());
    eprintln!("Actual native bootstrap parent + exact replay VC authenticated under old three-QC; absent proof/tampered state denied; finalized height preserved{}",candidate.height);
}
fn prune_orphan_link(root: &Path, cursor: &mut usize) -> Result<(), String> {
    if !root.try_exists().map_err(|e| e.to_string())? {
        return Ok(());
    }
    let next = std::fs::read_dir(root)
        .map_err(|e| e.to_string())?
        .filter_map(Result::ok)
        .filter(|e| e.path().extension().is_some_and(|s| s == "link"))
        .nth(*cursor);
    let Some(entry) = next else {
        *cursor = 0;
        return Ok(());
    };
    *cursor = cursor.saturating_add(1).min(4096);
    let bytes = super::apqe_transport::read(&entry.path(), 256, false)?;
    let id = EtdagDigest(
        std::str::from_utf8(&bytes)
            .map_err(|e| e.to_string())?
            .into(),
    );
    id.validate().map_err(|e| format!("{e:?}"))?;
    if !root
        .join(format!("{}-member.json", id.0))
        .try_exists()
        .map_err(|e| e.to_string())?
        && !root
            .join(format!("{}-complete.json", id.0))
            .try_exists()
            .map_err(|e| e.to_string())?
    {
        std::fs::remove_file(entry.path()).map_err(|e| e.to_string())?;
    }
    Ok(())
}
