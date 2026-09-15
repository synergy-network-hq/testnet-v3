use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::sync::Arc;

use synergy_aegis::{
    AegisPolicy, AegisSigner, AegisVerifier, KeyId, PqvmSigner, PqvmVerifier, SignatureAlgorithm,
    SigningContext,
};
use synergy_config::NodeConfiguration;
use synergy_data_availability::{serve::serve_custody, FilesystemShardStore, ShardStore};
use synergy_etdag::availability::{accept_vertex_shard, verify_availability_certificate};
use synergy_etdag::certificates::{
    canonical_certificate_root, verify_certificate_signatures, CanonicalCertificate,
    CertificateQuorum,
};
use synergy_etdag::crypto::canonical_signing_bytes;
use synergy_etdag::network::verify_network_message;
use synergy_etdag::{
    certificate_quorum, AuthenticatedEtdagMessage, EtdagDigest, EtdagGraph, EtdagMetrics,
    EtdagNetworkMessage, EtdagParameters, RecoveredShardCustody, ShardCustodyMessage,
};
use synergy_identity::PublicNodeIdentity;
use synergy_node_core::{
    CancellationToken, Criticality, ManagedService, RestartPolicy, ServiceHealth, ServiceId,
    ServiceReadiness, ServiceSpec,
};
use synergy_p2p_protocols::{AdapterEnvelope, EtdagAdapter, EtdagMessageSink};
use synergy_protocol_types::{AuthenticatedPeer, ProtocolKind};
use synergy_storage::NodeStorageLayout;

use super::authority::VerifiedAuthority;
use super::ingress::{AuthenticatedIngress, OutboundFrame};

const MAX_MESSAGES_PER_POLL: usize = 64;
const MAX_IDENTITY_BYTES: u64 = 64 * 1024;
const MAX_SIGNING_KEY_BYTES: u64 = 8 * 1024;
const MAX_ETDAG_SIGNING_BYTES: usize = 1024 * 1024;

struct LocalEtdagSigner {
    validator_id: String,
    key_id: KeyId,
    signer: PqvmSigner,
    chain_id: u64,
    epoch: u64,
}

impl LocalEtdagSigner {
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
    let signer = PqvmSigner::from_secret_key_bytes(
        policy.clone(),
        key_id.clone(),
        fs::read(signing_key_path).map_err(|error| format!("read ETDAG signing key: {error}"))?,
    )
    .map_err(|error| format!("load Aegis ETDAG signer: {error}"))?;
    let verifier = PqvmVerifier::new(policy).map_err(|error| error.to_string())?;
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
        signer,
        chain_id: configuration.chain_id,
        epoch: authority.epoch.epoch,
    })
}

pub fn registration(
    configuration: &NodeConfiguration,
    authority: Arc<VerifiedAuthority>,
    ingress: AuthenticatedIngress,
) -> Result<(ServiceSpec, Box<dyn ManagedService>), String> {
    if !configuration.etdag.enabled {
        return Err("ETDAG service cannot be registered when ETDAG is disabled".into());
    }
    let parameters = EtdagParameters::default();
    parameters
        .validate()
        .map_err(|error| format!("validate governed ETDAG parameters: {error:?}"))?;
    if configuration.etdag.protected_lookahead != parameters.target_height_offset {
        return Err("ETDAG configuration does not preserve governed H+5 admission".into());
    }
    let members = authority
        .registry
        .active()
        .map(|validator| validator.validator_id.clone())
        .collect::<BTreeSet<_>>();
    let required_signers = certificate_quorum(members.len())
        .map_err(|error| format!("derive ETDAG authority quorum: {error:?}"))?;
    let layout = NodeStorageLayout::new(configuration.storage.data_directory.clone())
        .map_err(|error| format!("construct canonical storage layout: {error}"))?;
    let shard_store = FilesystemShardStore::open(layout.etdag().join("availability-shards"))?;
    let local_signer = load_local_signer(configuration, authority.as_ref())?;
    Ok((
        ServiceSpec {
            id: ServiceId::new("etdag")?,
            dependencies: vec![ServiceId::new("sync")?, ServiceId::new("storage")?],
            criticality: Criticality::Critical,
            restart_policy: RestartPolicy::OnFailure { max_attempts: 3 },
        },
        Box::new(EtdagService {
            parameters,
            authority,
            members: members.clone(),
            quorum: CertificateQuorum {
                members,
                required_signers,
            },
            ingress,
            shard_store,
            local_signer,
            retention_blocks: configuration.storage.prune_finalized_history_after_blocks,
            last_pruned_finalized_height: 0,
            graphs: BTreeMap::new(),
            available: BTreeSet::new(),
            ordered: BTreeMap::new(),
            metrics: EtdagMetrics::default(),
            started: false,
            failure: None,
        }),
    ))
}

struct EtdagService {
    parameters: EtdagParameters,
    authority: Arc<VerifiedAuthority>,
    members: BTreeSet<String>,
    quorum: CertificateQuorum,
    ingress: AuthenticatedIngress,
    shard_store: FilesystemShardStore,
    local_signer: LocalEtdagSigner,
    retention_blocks: Option<u64>,
    last_pruned_finalized_height: u64,
    graphs: BTreeMap<(EtdagDigest, u64), EtdagGraph>,
    available: BTreeSet<(EtdagDigest, EtdagDigest)>,
    ordered: BTreeMap<(EtdagDigest, u64), Vec<EtdagDigest>>,
    metrics: EtdagMetrics,
    started: bool,
    failure: Option<String>,
}

impl EtdagService {
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
            EtdagNetworkMessage::Vertex(vertex) => {
                if vertex.author_id != message.sender_id {
                    return Err("ETDAG vertex author differs from signed network sender".into());
                }
                let key = (vertex.target_context_root.clone(), vertex.target_height);
                let graph = match self.graphs.entry(key) {
                    std::collections::btree_map::Entry::Occupied(entry) => entry.into_mut(),
                    std::collections::btree_map::Entry::Vacant(entry) => entry.insert(
                        EtdagGraph::new(vertex.target_context_root.clone(), vertex.target_height)
                            .map_err(|error| format!("open ETDAG graph: {error:?}"))?,
                    ),
                };
                graph
                    .insert(vertex)
                    .map_err(|error| format!("insert authenticated ETDAG vertex: {error:?}"))?;
                synergy_etdag::validate_graph(graph)
                    .map_err(|error| format!("validate ETDAG graph: {error:?}"))?;
                let count = self.graphs.values().map(EtdagGraph::len).sum();
                self.metrics
                    .set_dag_vertices(count)
                    .map_err(|error| format!("update ETDAG metrics: {error:?}"))?;
            }
            EtdagNetworkMessage::AvailabilityVote(vote) => {
                if vote.validator_id != message.sender_id {
                    return Err("ETDAG availability voter differs from signed sender".into());
                }
                vote.validate()
                    .map_err(|error| format!("validate availability vote: {error:?}"))?;
            }
            EtdagNetworkMessage::AvailabilityCertificate(certificate) => {
                verify_availability_certificate(
                    &certificate,
                    &self.members,
                    self.authority.as_ref(),
                )
                .map_err(|error| format!("verify availability certificate: {error:?}"))?;
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
                share
                    .validate()
                    .map_err(|error| format!("validate decrypt share: {error:?}"))?;
            }
            EtdagNetworkMessage::CertifiedExecutionHandoff(handoff) => {
                handoff
                    .validate_shape()
                    .map_err(|error| format!("validate ETDAG execution handoff: {error:?}"))?;
                let context = &handoff.prepared_batch.context;
                let expected_source_height = self
                    .ingress
                    .latest_finality()?
                    .map(|record| record.height)
                    .unwrap_or_else(|| self.authority.anchor_parent.height());
                if context.source_finalized_height != expected_source_height
                    || context.target_height
                        != expected_source_height
                            .saturating_add(self.parameters.target_height_offset)
                    || context.chain_id != self.authority.epoch.chain_id
                    || context.network_id != self.authority.epoch.network_id
                    || context.epoch != self.authority.epoch.epoch
                    || context.active_validator_set_root
                        != self.authority.epoch.active_validator_set_root
                    || context.validator_consensus_key_root
                        != self.authority.epoch.validator_consensus_key_root
                    || context.frozen_voting_weight_root
                        != self.authority.epoch.frozen_voting_weight_root
                    || context.finalized_epoch_seed_root
                        != self.authority.epoch.finalized_epoch_seed_root
                    || context.consensus_parameter_root
                        != self.authority.epoch.consensus_parameter_root
                {
                    return Err(
                        "ETDAG handoff is not bound to current finalized H+5 authority".into(),
                    );
                }
                let root = handoff
                    .certificate
                    .certificate_root()
                    .map_err(|error| format!("derive ETDAG batch certificate root: {error:?}"))?;
                verify_certificate_signatures(
                    "SYNERGY_ETDAG_BATCH_VALIDATION_CERTIFICATE_V1",
                    &root,
                    &handoff.certificate.signatures,
                    &self.quorum,
                    self.authority.as_ref(),
                )
                .map_err(|error| format!("verify ETDAG execution quorum: {error:?}"))?;
                let key = (
                    handoff.prepared_batch.context_root.clone(),
                    handoff.prepared_batch.target_height,
                );
                let expected = self
                    .ordered
                    .get(&key)
                    .ok_or("ETDAG execution handoff has no verified ordering certificate")?;
                if expected.len() != handoff.prepared_batch.transactions.len()
                    || expected
                        .iter()
                        .zip(&handoff.prepared_batch.transactions)
                        .any(|(vertex, transaction)| vertex != &transaction.vertex_id)
                    || expected
                        .iter()
                        .any(|vertex| !self.available.contains(&(key.0.clone(), vertex.clone())))
                {
                    return Err(
                        "ETDAG execution handoff differs from certified available order".into(),
                    );
                }
                self.ingress
                    .submit_protected_batch(handoff.prepared_batch)?;
                self.metrics
                    .record_completed_reveal()
                    .and_then(|_| self.metrics.record_execution_handoff())
                    .map_err(|error| format!("update ETDAG metrics: {error:?}"))?;
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
        self.last_pruned_finalized_height = finality.height;
        Ok(())
    }

    fn handle_certificate(&mut self, certificate: CanonicalCertificate) -> Result<(), String> {
        match &certificate {
            CanonicalCertificate::Availability(value) => {
                verify_availability_certificate(value, &self.members, self.authority.as_ref())
                    .map_err(|error| {
                        format!("verify canonical availability certificate: {error:?}")
                    })?;
                self.available
                    .insert((value.context_root.clone(), value.vertex_id.clone()));
            }
            CanonicalCertificate::Ordering(value) => {
                let root = value
                    .certificate_root()
                    .map_err(|error| format!("derive ordering certificate root: {error:?}"))?;
                verify_certificate_signatures(
                    "SYNERGY_ETDAG_ORDERING_CERTIFICATE_V1",
                    &root,
                    &value.signatures,
                    &self.quorum,
                    self.authority.as_ref(),
                )
                .map_err(|error| format!("verify ordering certificate quorum: {error:?}"))?;
                let key = (value.proof.context_root.clone(), value.proof.target_height);
                let graph = self
                    .graphs
                    .get(&key)
                    .ok_or("ordering certificate has no matching ETDAG graph")?;
                synergy_etdag::validate_graph(graph)
                    .map_err(|error| format!("validate ordered ETDAG graph: {error:?}"))?;
                if value.proof.ordered_vertex_ids.iter().any(|vertex| {
                    graph.get(vertex).is_none()
                        || !self.available.contains(&(key.0.clone(), vertex.clone()))
                }) {
                    return Err(
                        "ordering certificate contains missing or unavailable vertex".into(),
                    );
                }
                self.ordered
                    .insert(key, value.proof.ordered_vertex_ids.clone());
            }
            CanonicalCertificate::BatchValidation(value) => {
                let root = value
                    .certificate_root()
                    .map_err(|error| format!("derive validation certificate root: {error:?}"))?;
                verify_certificate_signatures(
                    "SYNERGY_ETDAG_BATCH_VALIDATION_CERTIFICATE_V1",
                    &root,
                    &value.signatures,
                    &self.quorum,
                    self.authority.as_ref(),
                )
                .map_err(|error| format!("verify validation certificate quorum: {error:?}"))?;
            }
            CanonicalCertificate::TargetAdmission(_)
            | CanonicalCertificate::BatchFinality(_)
            | CanonicalCertificate::BatchTimeout(_) => {
                canonical_certificate_root(&certificate)
                    .map_err(|error| format!("validate canonical ETDAG certificate: {error:?}"))?;
            }
        }
        Ok(())
    }
}

impl EtdagMessageSink for EtdagService {
    fn receive_etdag(&mut self, peer: AuthenticatedPeer, payload: Vec<u8>) -> Result<(), String> {
        let message: AuthenticatedEtdagMessage = serde_json::from_slice(&payload)
            .map_err(|error| format!("decode authenticated ETDAG message: {error}"))?;
        self.handle_network_message(&peer, message)
    }
}

impl ManagedService for EtdagService {
    fn start(&mut self, cancellation: &CancellationToken) -> Result<(), String> {
        if cancellation.is_cancelled() {
            return Err("ETDAG service start was cancelled".into());
        }
        self.parameters
            .validate()
            .map_err(|error| format!("validate ETDAG service parameters: {error:?}"))?;
        self.authority
            .epoch
            .validate_against(&self.authority.registry)
            .map_err(|error| format!("validate ETDAG frozen authority: {error}"))?;
        self.started = true;
        self.failure = None;
        Ok(())
    }

    fn poll(&mut self) -> Result<(), String> {
        if !self.started {
            return Err("ETDAG service is not started".into());
        }
        if self.parameters.target_height_offset != 5 {
            return Err("ETDAG service lost governed H+5 admission policy".into());
        }
        for _ in 0..MAX_MESSAGES_PER_POLL {
            let Some(frame) = self.ingress.take(ProtocolKind::Etdag)? else {
                break;
            };
            EtdagAdapter
                .deliver(AdapterEnvelope::from(frame), self)
                .map_err(|error| format!("route authenticated ETDAG frame: {error:?}"))?;
        }
        self.apply_finalized_retention()
    }

    fn stop(&mut self) -> Result<(), String> {
        self.ingress.clear(ProtocolKind::Etdag)?;
        self.graphs.clear();
        self.available.clear();
        self.ordered.clear();
        self.started = false;
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
        ServiceHealth::Healthy
    }

    fn readiness(&self) -> ServiceReadiness {
        if self.started {
            ServiceReadiness::Ready
        } else {
            ServiceReadiness::Blocked {
                reason: "ETDAG service is stopped".into(),
            }
        }
    }
}
