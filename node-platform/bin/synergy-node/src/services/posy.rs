use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::Read;
use std::sync::Arc;
use std::time::{Duration, Instant};

use synergy_aegis::{
    AegisPolicy, AegisSigner, AegisVerifier, KeyId, PqvmSigner, PqvmVerifier, SignatureAlgorithm,
    SigningContext,
};
use synergy_config::{ConsensusMode, NodeConfiguration};
use synergy_execution::ExecutionCandidate;
use synergy_identity::PublicNodeIdentity;
use synergy_node_core::{
    CancellationToken, Criticality, ManagedService, RestartPolicy, ServiceHealth, ServiceId,
    ServiceReadiness, ServiceSpec,
};
use synergy_p2p_protocols::{AdapterEnvelope, PosyAdapter, PosyMessageSink};
use synergy_posy::persistence::{
    AtomicConsensusTransitionStore, ConsensusSigner, DurableSigningAuthority, FinalityStore,
    VerifiedQuorumCertificateStore, VerifiedTimeoutCertificateStore,
};
use synergy_posy::{
    block_vote_signing_bytes, timeout_vote_signing_bytes, validate_proposal, BlockVote,
    ConsensusEvent, ConsensusObjectContext, ConsensusTransition, FinalitySyncWitness, PosyMetrics,
    PosyRecoveryJournal, SignOnceJournal, SigningSlot, SimplifiedConsensusStateMachine,
    SimplifiedPosyDriver, SimplifiedProposal, SimplifiedQuorumCertificate, ThreeQcFinality,
    TimeoutVote, POSY_SIMPLIFIED_BLOCK_VOTE_DOMAIN, POSY_SIMPLIFIED_PROPOSAL_DOMAIN,
    POSY_SIMPLIFIED_TIMEOUT_VOTE_DOMAIN,
};
use synergy_protocol_types::{AuthenticatedPeer, ProtocolKind};
use synergy_storage::NodeStorageLayout;
use synergy_sync::VerifiedHead;

use super::authority::{self, VerifiedAuthority};
use super::ingress::{AuthenticatedIngress, OutboundFrame};

const MAX_AUTHORITY_BINDING_BYTES: u64 = 1024 * 1024;
const MAX_SIGNING_KEY_BYTES: u64 = 8 * 1024;
const MAX_IDENTITY_BYTES: u64 = 64 * 1024;
const MAX_MESSAGES_PER_POLL: usize = 64;

struct LocalConsensusSigner {
    validator_id: String,
    key_id: KeyId,
    signer: PqvmSigner,
    chain_id: u64,
    epoch: u64,
}

impl ConsensusSigner for LocalConsensusSigner {
    fn validator_id(&self) -> &str {
        &self.validator_id
    }

    fn key_id(&self) -> &str {
        self.key_id.as_str()
    }

    fn sign(&self, domain: &str, height: u64, transcript: &[u8]) -> Result<Vec<u8>, String> {
        self.signer
            .sign(
                &self.key_id,
                &SigningContext {
                    domain: domain.into(),
                    chain_id: self.chain_id,
                    epoch: Some(self.epoch),
                    height: Some(height),
                },
                transcript,
            )
            .map(|signature| signature.bytes)
            .map_err(|error| format!("Aegis PoSy signature failed: {error}"))
    }
}

pub fn registration(
    configuration: &NodeConfiguration,
    authority: Arc<VerifiedAuthority>,
    ingress: AuthenticatedIngress,
) -> Result<(ServiceSpec, Box<dyn ManagedService>), String> {
    let consensus = &configuration.consensus;
    if consensus.mode == ConsensusMode::Disabled {
        return Err("PoSy service cannot be registered when consensus is disabled".into());
    }
    let authority_binding = consensus
        .authority_binding
        .clone()
        .ok_or_else(|| "PoSy service requires an explicit authority binding".to_string())?;
    inspect_bounded_regular(
        &authority_binding,
        MAX_AUTHORITY_BINDING_BYTES,
        "PoSy authority binding",
        false,
    )?;
    let mut state_machine = SimplifiedConsensusStateMachine::new(
        authority.epoch.clone(),
        authority.registry.clone(),
        authority.anchor_parent.clone(),
    )
    .map_err(|error| format!("construct single PoSy state machine: {error}"))?;
    let layout = NodeStorageLayout::new(configuration.storage.data_directory.clone())
        .map_err(|error| format!("construct canonical storage layout: {error}"))?;
    let root = layout.consensus().join("posy");
    let recovery = PosyRecoveryJournal::load(root.join("recovery.json"))
        .map_err(|error| format!("load PoSy recovery journal: {error:?}"))?;
    let finality = FinalityStore::new(&root)
        .map_err(|error| format!("open PoSy finality store: {error:?}"))?;
    if let Some((finalized, certificates)) =
        authority::load_transition_finality_prefix(configuration, authority.as_ref())?
    {
        let committed = finality
            .get(finalized.height)
            .map_err(|error| format!("load transition finality commit: {error}"))?
            .ok_or("epoch transition finality is not durably committed")?;
        if committed != finalized {
            return Err("epoch transition witness conflicts with durable PoSy finality".into());
        }
        state_machine
            .seed_epoch_transition_finality(finalized, certificates)
            .map_err(|error| format!("seed successor epoch finality: {error}"))?;
    }
    let certificates = VerifiedQuorumCertificateStore::new(&root)
        .map_err(|error| format!("open PoSy verified-QC store: {error:?}"))?;
    let atomic_transitions = AtomicConsensusTransitionStore::new(&root)
        .map_err(|error| format!("open atomic PoSy transition store: {error:?}"))?;
    let timeout_certificates = VerifiedTimeoutCertificateStore::new(&root)
        .map_err(|error| format!("open PoSy verified-timeout store: {error:?}"))?;
    let sign_once = SignOnceJournal::load(root.join("sign-once.json"))
        .map_err(|error| format!("load PoSy sign-once journal: {error:?}"))?;
    let last_finalized = replay_verified_safety_state(
        &mut state_machine,
        &authority,
        &certificates,
        &timeout_certificates,
        &finality,
    )?;
    if let Some(record) = last_finalized.as_ref() {
        if let Some(witness) = state_machine.finality_witness(record.height) {
            ingress.submit_finality(
                record.clone(),
                serde_json::to_vec(&witness)
                    .map_err(|error| format!("encode recovered three-QC witness: {error}"))?,
            )?;
        }
    }
    let local_signer = match consensus.mode {
        ConsensusMode::Observe => None,
        ConsensusMode::ValidateAndVote => Some(DurableSigningAuthority::new(
            sign_once,
            load_local_signer(configuration, &authority)?,
        )),
        ConsensusMode::Disabled => None,
    };
    Ok((
        ServiceSpec {
            id: ServiceId::new("posy")?,
            dependencies: vec![
                ServiceId::new("sync")?,
                ServiceId::new("etdag")?,
                ServiceId::new("execution")?,
            ],
            criticality: Criticality::Critical,
            restart_policy: RestartPolicy::OnFailure { max_attempts: 3 },
        },
        Box::new(PosyService {
            mode: consensus.mode,
            authority_binding,
            authority,
            driver: SimplifiedPosyDriver::new(state_machine),
            recovery: Some(recovery),
            finality: Some(finality),
            certificates,
            atomic_transitions,
            timeout_certificates,
            local_signer,
            last_finalized,
            candidates: BTreeMap::new(),
            pending_proposals: BTreeMap::new(),
            metrics: PosyMetrics::default(),
            emitted_slots: BTreeSet::new(),
            last_voted_candidate: None,
            ingress,
            round_timeout: Duration::from_millis(consensus.round_timeout_ms),
            round_deadline: Instant::now() + Duration::from_millis(consensus.round_timeout_ms),
            started: false,
            failure: None,
        }),
    ))
}

/// Reconstructs the one PoSy state machine from authority-verified, immutable
/// QC and timeout records. Missing or conflicting finalized commits fail closed.
fn replay_verified_safety_state(
    state_machine: &mut SimplifiedConsensusStateMachine,
    authority: &VerifiedAuthority,
    certificates: &VerifiedQuorumCertificateStore,
    timeout_certificates: &VerifiedTimeoutCertificateStore,
    finality: &FinalityStore,
) -> Result<Option<synergy_posy::FinalizedBlockRecord>, String> {
    let mut last_finalized = state_machine.last_finalized().cloned();
    loop {
        if state_machine.epoch_complete() {
            break;
        }
        let height = state_machine.active_slot().0;
        loop {
            let (slot_height, round) = state_machine.active_slot();
            let Some(timeout) = timeout_certificates
                .get_verified(
                    slot_height,
                    round,
                    &authority.epoch,
                    &authority.registry,
                    authority,
                )
                .map_err(|error| format!("load verified PoSy timeout for recovery: {error}"))?
            else {
                break;
            };
            state_machine
                .accept_timeout_certificate(timeout, authority)
                .map_err(|error| {
                    format!("replay PoSy timeout at {slot_height}/{round}: {error}")
                })?;
        }
        let Some(certificate) = certificates
            .get_verified(height, &authority.epoch, &authority.registry, authority)
            .map_err(|error| format!("load verified PoSy QC for recovery: {error}"))?
        else {
            break;
        };
        let transitions = state_machine
            .accept_quorum_certificate(certificate, authority)
            .map_err(|error| format!("replay PoSy QC at height {height}: {error}"))?;
        for transition in transitions {
            if let ConsensusTransition::Finalized(record) = transition {
                let committed = finality
                    .get(record.height)
                    .map_err(|error| format!("load committed PoSy finality: {error}"))?
                    .ok_or_else(|| {
                        format!(
                            "verified QC replay reached H{} without a durable finalized commit",
                            record.height
                        )
                    })?;
                if committed != record {
                    return Err(format!(
                        "durable PoSy finality conflicts with verified QC replay at H{}",
                        record.height
                    ));
                }
                last_finalized = Some(record);
            }
        }
    }
    let next_unproven = last_finalized
        .as_ref()
        .map(|record| record.height.saturating_add(1))
        .unwrap_or(authority.epoch.epoch_start_height);
    if finality
        .get(next_unproven)
        .map_err(|error| format!("check orphan PoSy finality: {error}"))?
        .is_some()
    {
        return Err(format!(
            "durable PoSy finality at H{next_unproven} lacks replayed three-QC authority"
        ));
    }
    Ok(last_finalized)
}

fn inspect_bounded_regular(
    path: &std::path::Path,
    maximum: u64,
    label: &str,
    private: bool,
) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("inspect {label} {}: {error}", path.display()))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > maximum
    {
        return Err(format!(
            "{label} must be a bounded regular non-symlink file"
        ));
    }
    #[cfg(unix)]
    if private {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(format!("{label} must not be accessible to group or others"));
        }
    }
    Ok(())
}

fn read_bounded(path: &std::path::Path, maximum: u64, label: &str) -> Result<Vec<u8>, String> {
    inspect_bounded_regular(path, maximum, label, false)?;
    let mut bytes = Vec::new();
    File::open(path)
        .and_then(|file| file.take(maximum + 1).read_to_end(&mut bytes))
        .map_err(|error| format!("read {label}: {error}"))?;
    if bytes.is_empty() || bytes.len() as u64 > maximum {
        return Err(format!("{label} changed shape while loading"));
    }
    Ok(bytes)
}

fn load_local_signer(
    configuration: &NodeConfiguration,
    authority: &VerifiedAuthority,
) -> Result<LocalConsensusSigner, String> {
    let identity_bytes = read_bounded(
        &configuration.public_identity_path,
        MAX_IDENTITY_BYTES,
        "public node identity",
    )?;
    let identity = serde_json::from_slice::<PublicNodeIdentity>(&identity_bytes)
        .map_err(|error| format!("decode public node identity: {error}"))?
        .validate()
        .map_err(|error| format!("validate public node identity: {error:?}"))?;
    let (key_id_text, public_key) = authority.consensus_binding(identity.node_address.as_str())?;
    let key_id = KeyId::new(key_id_text.to_string())
        .map_err(|error| format!("invalid frozen consensus key id: {error}"))?;
    let path = configuration
        .consensus
        .signing_key_path
        .as_ref()
        .ok_or("ValidateAndVote requires consensus.signing_key_path")?;
    inspect_bounded_regular(
        path,
        MAX_SIGNING_KEY_BYTES,
        "PoSy consensus signing key",
        true,
    )?;
    let secret_key = read_bounded(path, MAX_SIGNING_KEY_BYTES, "PoSy consensus signing key")?;
    let policy = AegisPolicy {
        allowed_algorithms: vec![SignatureAlgorithm::MlDsa65],
        maximum_message_bytes: 1024 * 1024,
        maximum_signature_bytes: 16 * 1024,
    };
    let signer = PqvmSigner::from_secret_key_bytes(policy.clone(), key_id.clone(), secret_key)
        .map_err(|error| format!("load PQVM consensus signer: {error}"))?;
    let verifier = PqvmVerifier::new(policy).map_err(|error| error.to_string())?;
    let proof = b"SYNERGY-POSY-CONSENSUS-KEY-POSSESSION-V1";
    let context = SigningContext {
        domain: "SYNERGY-POSY-CONSENSUS-KEY-POSSESSION-V1".into(),
        chain_id: configuration.chain_id,
        epoch: Some(authority.epoch.epoch),
        height: None,
    };
    let signature = signer
        .sign(&key_id, &context, proof)
        .map_err(|error| format!("prove consensus-key possession: {error}"))?;
    verifier
        .verify(&context, proof, &signature, public_key)
        .map_err(|_| "provisioned consensus key differs from frozen authority binding")?;
    Ok(LocalConsensusSigner {
        validator_id: identity.node_address.to_string(),
        key_id,
        signer,
        chain_id: configuration.chain_id,
        epoch: authority.epoch.epoch,
    })
}

struct PosyService {
    mode: ConsensusMode,
    authority_binding: std::path::PathBuf,
    authority: Arc<VerifiedAuthority>,
    driver: SimplifiedPosyDriver,
    recovery: Option<PosyRecoveryJournal>,
    finality: Option<FinalityStore>,
    certificates: VerifiedQuorumCertificateStore,
    atomic_transitions: AtomicConsensusTransitionStore,
    timeout_certificates: VerifiedTimeoutCertificateStore,
    local_signer: Option<DurableSigningAuthority<LocalConsensusSigner>>,
    last_finalized: Option<synergy_posy::FinalizedBlockRecord>,
    candidates: BTreeMap<u64, ExecutionCandidate>,
    pending_proposals: BTreeMap<(u64, u64), SimplifiedProposal>,
    metrics: PosyMetrics,
    emitted_slots: BTreeSet<SigningSlot>,
    last_voted_candidate: Option<synergy_posy::CertifiedCandidateSubject>,
    ingress: AuthenticatedIngress,
    round_timeout: Duration,
    round_deadline: Instant,
    started: bool,
    failure: Option<String>,
}

impl PosyService {
    fn broadcast(&self, event: &ConsensusEvent) -> Result<(), String> {
        let payload = serde_json::to_vec(event)
            .map_err(|error| format!("encode PoSy network event: {error}"))?;
        for peer_id in self.ingress.authenticated_peers()? {
            self.ingress.publish_outbound(OutboundFrame {
                peer_id,
                protocol: ProtocolKind::Posy,
                payload: payload.clone(),
            })?;
        }
        Ok(())
    }

    fn handle_transitions(&mut self, transitions: Vec<ConsensusTransition>) -> Result<(), String> {
        let mut transitions = transitions.into_iter().peekable();
        while let Some(transition) = transitions.next() {
            match transition {
                ConsensusTransition::QuorumCertified(certificate) => {
                    if let Some(ConsensusTransition::Finalized(record)) = transitions.peek() {
                        let record = record.clone();
                        transitions.next();
                        self.atomic_transitions
                            .commit_verified_qc_and_finality(
                                &certificate,
                                &record,
                                self.last_finalized.as_ref(),
                                &self.authority.epoch,
                                &self.authority.registry,
                                self.authority.as_ref(),
                            )
                            .map_err(|error| {
                                format!("persist crash-atomic PoSy QC/finality: {error}")
                            })?;
                        self.metrics.record_verified_qc();
                        self.metrics.record_finality();
                        self.broadcast(&ConsensusEvent::QuorumCertificate(certificate))?;
                        let witness = self
                            .driver
                            .state_machine()
                            .finality_witness(record.height)
                            .ok_or("PoSy finalized without a retained three-QC witness")?;
                        let witness = serde_json::to_vec(&witness)
                            .map_err(|error| format!("encode PoSy finality witness: {error}"))?;
                        self.last_finalized = Some(record.clone());
                        self.ingress.submit_finality(record, witness)?;
                    } else {
                        self.certificates
                            .put_verified(
                                &certificate,
                                &self.authority.epoch,
                                &self.authority.registry,
                                self.authority.as_ref(),
                            )
                            .map_err(|error| format!("persist verified PoSy QC: {error}"))?;
                        self.metrics.record_verified_qc();
                        self.broadcast(&ConsensusEvent::QuorumCertificate(certificate))?;
                    }
                }
                ConsensusTransition::TimeoutCertified(certificate) => {
                    self.timeout_certificates
                        .put_verified(
                            &certificate,
                            &self.authority.epoch,
                            &self.authority.registry,
                            self.authority.as_ref(),
                        )
                        .map_err(|error| {
                            format!("persist verified PoSy timeout certificate: {error}")
                        })?;
                    self.broadcast(&ConsensusEvent::TimeoutCertificate(certificate))?;
                }
                ConsensusTransition::Finalized(_) => {
                    return Err(
                        "PoSy emitted finality without its paired quorum certificate transition"
                            .into(),
                    );
                }
                ConsensusTransition::HeightAdvanced { .. }
                | ConsensusTransition::RoundAdvanced { .. } => {
                    self.round_deadline = Instant::now() + self.round_timeout;
                    let active = self.driver.state_machine().active_slot();
                    self.pending_proposals.retain(|slot, _| *slot == active);
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn apply_event(&mut self, event: ConsensusEvent) -> Result<(), String> {
        if let ConsensusEvent::Proposal(proposal) = &event {
            validate_proposal(
                proposal,
                &self.authority.epoch,
                &self.authority.registry,
                self.authority.as_ref(),
            )
            .map_err(|error| format!("verify PoSy proposal before execution admission: {error}"))?;
            let slot = (proposal.context.height, proposal.context.round);
            if slot != self.driver.state_machine().active_slot() {
                self.metrics.record_rejection();
                return Ok(());
            }
            if self.mode == ConsensusMode::ValidateAndVote {
                if let Some(candidate) = self.candidates.get(&proposal.context.height) {
                    if !candidate_matches_proposal(candidate, proposal) {
                        self.metrics.record_rejection();
                        return Ok(());
                    }
                } else {
                    match self.pending_proposals.get(&slot) {
                        Some(existing) if existing != proposal => {
                            self.metrics.record_rejection();
                            return Ok(());
                        }
                        Some(_) => return Ok(()),
                        None => {
                            self.pending_proposals.insert(slot, proposal.clone());
                            return Ok(());
                        }
                    }
                }
            }
        }
        let accepted_proposal = match &event {
            ConsensusEvent::Proposal(proposal) => Some(proposal.clone()),
            _ => None,
        };
        let observed_kind = match &event {
            ConsensusEvent::Proposal(_) => 0u8,
            ConsensusEvent::BlockVote(_) | ConsensusEvent::TimeoutVote(_) => 1u8,
            ConsensusEvent::QuorumCertificate(_) | ConsensusEvent::TimeoutCertificate(_) => 2u8,
        };
        let transitions = self
            .driver
            .handle(event, self.authority.as_ref())
            .map_err(|error| {
                self.metrics.record_rejection();
                format!("PoSy rejected authenticated consensus event: {error}")
            })?;
        match observed_kind {
            0 => self.metrics.record_proposal(),
            1 => self.metrics.record_vote(),
            _ => {}
        }
        let proposal_accepted = transitions
            .iter()
            .any(|transition| matches!(transition, ConsensusTransition::ProposalAccepted { .. }));
        self.handle_transitions(transitions)?;
        if proposal_accepted && self.mode == ConsensusMode::ValidateAndVote {
            if let Some(proposal) = accepted_proposal {
                self.emit_vote(&proposal)?;
            }
        }
        Ok(())
    }

    fn sign_once(
        &mut self,
        slot: SigningSlot,
        signing_domain: &str,
        subject: &str,
        bytes: &[u8],
    ) -> Result<Option<Vec<u8>>, String> {
        if self.emitted_slots.contains(&slot)
            && self
                .local_signer
                .as_ref()
                .and_then(|authority| authority.journal().subject(&slot))
                == Some(subject)
        {
            return Ok(None);
        }
        let signature = self
            .local_signer
            .as_mut()
            .ok_or("PoSy signer unavailable")?
            .sign_once(slot.clone(), signing_domain, subject, bytes)
            .map_err(|error| format!("durable PoSy signing refused: {error}"))?;
        self.emitted_slots.insert(slot);
        Ok(Some(signature))
    }

    fn emit_proposal(&mut self, candidate: &ExecutionCandidate) -> Result<(), String> {
        let (height, round) = self.driver.state_machine().active_slot();
        let (local_validator_id, local_key_id) = {
            let local = self
                .local_signer
                .as_ref()
                .ok_or("PoSy signer unavailable")?;
            (local.validator_id().to_string(), local.key_id().to_string())
        };
        if candidate.height != height
            || candidate.parent_block_id != self.driver.state_machine().highest_parent().block_id()
            || self
                .authority
                .epoch
                .authorized_proposer(height, round)
                .map_err(|error| error.to_string())?
                != local_validator_id
        {
            return Ok(());
        }
        let context = ConsensusObjectContext::for_height(&self.authority.epoch, height, round)
            .map_err(|error| error.to_string())?;
        let mut proposal = SimplifiedProposal {
            context,
            proposer_id: local_validator_id,
            block_id: candidate.block_id.clone(),
            parent_block_id: candidate.parent_block_id.clone(),
            parent: self.driver.state_machine().highest_parent().clone(),
            takeover_tc_id: self
                .driver
                .state_machine()
                .active_takeover_tc_id()
                .map(str::to_string),
            protected_execution_root: candidate.protected_execution_root.clone(),
            proposer_key_id: local_key_id,
            proposer_signature: Vec::new(),
        };
        let subject = proposal
            .candidate_subject()
            .map_err(|error| error.to_string())?
            .id()
            .map_err(|error| error.to_string())?;
        let slot = SigningSlot {
            height,
            round,
            domain: "proposal".into(),
        };
        let signing_bytes = proposal
            .signing_bytes()
            .map_err(|error| error.to_string())?;
        let Some(signature) = self.sign_once(
            slot,
            POSY_SIMPLIFIED_PROPOSAL_DOMAIN,
            &subject,
            &signing_bytes,
        )?
        else {
            return Ok(());
        };
        proposal.proposer_signature = signature;
        let event = ConsensusEvent::Proposal(proposal);
        self.broadcast(&event)?;
        self.apply_event(event)
    }

    fn emit_vote(&mut self, proposal: &SimplifiedProposal) -> Result<(), String> {
        let candidate = self
            .candidates
            .get(&proposal.context.height)
            .ok_or("PoSy vote requires locally executed ETDAG candidate")?;
        if !candidate_matches_proposal(candidate, proposal) {
            return Err("PoSy vote conflicts with locally executed ETDAG candidate".into());
        }
        let (local_validator_id, local_key_id) = {
            let local = self
                .local_signer
                .as_ref()
                .ok_or("PoSy signer unavailable")?;
            (local.validator_id().to_string(), local.key_id().to_string())
        };
        let mut vote = BlockVote {
            context: proposal.context.clone(),
            block_id: proposal.block_id.clone(),
            parent_block_id: proposal.parent_block_id.clone(),
            parent: proposal.parent.clone(),
            takeover_tc_id: proposal.takeover_tc_id.clone(),
            protected_execution_root: proposal.protected_execution_root.clone(),
            validator_id: local_validator_id,
            key_id: local_key_id,
            signature: Vec::new(),
        };
        let candidate = proposal
            .candidate_subject()
            .map_err(|error| error.to_string())?;
        let slot = SigningSlot {
            height: vote.context.height,
            round: vote.context.round,
            domain: "block-vote".into(),
        };
        let subject = candidate.id().map_err(|error| error.to_string())?;
        let signing_bytes = block_vote_signing_bytes(&vote).map_err(|error| error.to_string())?;
        let Some(signature) = self.sign_once(
            slot,
            POSY_SIMPLIFIED_BLOCK_VOTE_DOMAIN,
            &subject,
            &signing_bytes,
        )?
        else {
            return Ok(());
        };
        vote.signature = signature;
        self.last_voted_candidate = Some(candidate);
        let event = ConsensusEvent::BlockVote(vote);
        self.broadcast(&event)?;
        let transitions = self
            .driver
            .handle(event, self.authority.as_ref())
            .map_err(|error| format!("PoSy rejected local block vote: {error}"))?;
        self.handle_transitions(transitions)
    }

    fn emit_timeout_vote(&mut self) -> Result<(), String> {
        if self.mode != ConsensusMode::ValidateAndVote || Instant::now() < self.round_deadline {
            return Ok(());
        }
        let (height, round) = self.driver.state_machine().active_slot();
        let (local_validator_id, local_key_id) = {
            let local = self
                .local_signer
                .as_ref()
                .ok_or("PoSy signer unavailable")?;
            (local.validator_id().to_string(), local.key_id().to_string())
        };
        let mut vote = TimeoutVote {
            context: ConsensusObjectContext::for_height(&self.authority.epoch, height, round)
                .map_err(|error| error.to_string())?,
            lease_index: self
                .authority
                .epoch
                .lease_index(height)
                .map_err(|error| error.to_string())?,
            timed_out_proposer: self
                .authority
                .epoch
                .authorized_proposer(height, round)
                .map_err(|error| error.to_string())?
                .to_string(),
            highest_parent: self.driver.state_machine().highest_parent().clone(),
            previous_tc_id: self
                .driver
                .state_machine()
                .active_takeover_tc_id()
                .map(str::to_string),
            last_voted_candidate: self.last_voted_candidate.clone(),
            validator_id: local_validator_id,
            key_id: local_key_id,
            signature: Vec::new(),
        };
        let subject = synergy_posy::canonical_hash(
            "SYNERGY_POSY_TIMEOUT_VOTE_SUBJECT_V1",
            &(
                &vote.context,
                &vote.highest_parent,
                &vote.previous_tc_id,
                &vote.last_voted_candidate,
            ),
        )
        .map_err(|error| error.to_string())?;
        let slot = SigningSlot {
            height,
            round,
            domain: "timeout-vote".into(),
        };
        let signing_bytes = timeout_vote_signing_bytes(&vote).map_err(|error| error.to_string())?;
        let Some(signature) = self.sign_once(
            slot,
            POSY_SIMPLIFIED_TIMEOUT_VOTE_DOMAIN,
            &subject,
            &signing_bytes,
        )?
        else {
            self.round_deadline = Instant::now() + self.round_timeout;
            return Ok(());
        };
        vote.signature = signature;
        let event = ConsensusEvent::TimeoutVote(vote);
        self.broadcast(&event)?;
        let transitions = self
            .driver
            .handle(event, self.authority.as_ref())
            .map_err(|error| format!("PoSy rejected local timeout vote: {error}"))?;
        self.handle_transitions(transitions)?;
        self.round_deadline = Instant::now() + self.round_timeout;
        Ok(())
    }

    fn collect_candidates(&mut self) -> Result<(), String> {
        for _ in 0..MAX_MESSAGES_PER_POLL {
            let Some(candidate) = self.ingress.take_execution_candidate()? else {
                break;
            };
            match self.candidates.get(&candidate.height) {
                Some(current) if current.block_id == candidate.block_id => {}
                Some(_) => return Err("conflicting execution candidates for PoSy height".into()),
                None => {
                    self.candidates.insert(candidate.height, candidate);
                }
            }
        }
        if self.mode == ConsensusMode::ValidateAndVote {
            let slot = self.driver.state_machine().active_slot();
            if let Some(candidate) = self.candidates.get(&slot.0).cloned() {
                if let Some(proposal) = self.pending_proposals.remove(&slot) {
                    self.apply_event(ConsensusEvent::Proposal(proposal))?;
                }
                self.emit_proposal(&candidate)?;
            }
        }
        Ok(())
    }

    fn verify_external_finality_witness(
        &self,
        bytes: &[u8],
    ) -> Result<synergy_posy::FinalizedBlockRecord, String> {
        if bytes.is_empty() || bytes.len() > 1024 * 1024 {
            return Err("Sync three-QC witness is missing or oversized".into());
        }
        let certificates: [SimplifiedQuorumCertificate; 3] = serde_json::from_slice(bytes)
            .map_err(|error| format!("decode Sync three-QC witness: {error}"))?;
        let mut finality = ThreeQcFinality::default();
        for certificate in certificates {
            certificate
                .verify(
                    &self.authority.epoch,
                    &self.authority.registry,
                    self.authority.as_ref(),
                )
                .map_err(|error| format!("verify Sync QC authority: {error}"))?;
            finality
                .accept(certificate)
                .map_err(|error| format!("verify Sync three-QC ancestry: {error}"))?;
        }
        finality
            .last_finalized()
            .cloned()
            .ok_or_else(|| "Sync witness does not establish three-QC finality".into())
    }

    fn admit_sync_candidates(&mut self) -> Result<(), String> {
        for _ in 0..MAX_MESSAGES_PER_POLL {
            let Some((_peer, response)) = self.ingress.take_sync_candidate_response()? else {
                break;
            };
            let witness: FinalitySyncWitness =
                serde_json::from_slice(&response.finality_witness)
                    .map_err(|error| format!("decode Sync safety witness: {error}"))?;
            let mut finality = ThreeQcFinality::default();
            let mut timeouts = BTreeMap::new();
            for timeout in witness.timeout_certificates {
                timeout
                    .verify(
                        &self.authority.epoch,
                        &self.authority.registry,
                        self.authority.as_ref(),
                    )
                    .map_err(|error| format!("verify Sync timeout authority: {error}"))?;
                let slot = (timeout.context.height, timeout.context.round);
                if timeouts.insert(slot, timeout).is_some() {
                    return Err("Sync safety witness repeats a timeout slot".into());
                }
            }
            for certificate in &witness.quorum_certificates {
                certificate
                    .verify(
                        &self.authority.epoch,
                        &self.authority.registry,
                        self.authority.as_ref(),
                    )
                    .map_err(|error| format!("verify Sync QC authority: {error}"))?;
                for round in 0..certificate.context.round {
                    if !timeouts.contains_key(&(certificate.context.height, round)) {
                        return Err("Sync safety witness omits a required timeout closure".into());
                    }
                }
                finality
                    .accept(certificate.clone())
                    .map_err(|error| format!("verify Sync three-QC ancestry: {error}"))?;
            }
            let record = finality
                .last_finalized()
                .cloned()
                .ok_or("Sync safety witness does not establish finality")?;
            if record.height != response.candidate.height
                || record.block_id != response.candidate.block_id
                || record.protected_execution_root != response.candidate.protected_execution_root
            {
                return Err("Sync execution candidate differs from three-QC finality".into());
            }
            for certificate in witness.quorum_certificates {
                let height = certificate.context.height;
                if height >= self.driver.state_machine().active_slot().0 {
                    while self.driver.state_machine().active_slot().1 < certificate.context.round {
                        let slot = self.driver.state_machine().active_slot();
                        let timeout = timeouts
                            .remove(&slot)
                            .ok_or("Sync safety replay lacks the next timeout closure")?;
                        self.apply_event(ConsensusEvent::TimeoutCertificate(timeout))?;
                    }
                }
                self.apply_event(ConsensusEvent::QuorumCertificate(certificate))?;
            }
            self.ingress
                .submit_verified_sync_candidate(response.candidate, record)?;
        }
        Ok(())
    }

    fn verify_sync_claims(&mut self) -> Result<(), String> {
        for _ in 0..MAX_MESSAGES_PER_POLL {
            let Some((peer, claim)) = self.ingress.take_head_claim()? else {
                break;
            };
            if peer.node_address.as_str() != claim.peer_id.as_str()
                || claim.chain_id != self.authority.epoch.chain_id
            {
                self.metrics.record_rejection();
                continue;
            }
            let local = self
                .finality
                .as_ref()
                .ok_or("PoSy finality store unavailable")?
                .get(claim.finalized_height)
                .map_err(|error| format!("load PoSy finality evidence: {error}"))?;
            let verified = if let Some(local) = local {
                local
            } else {
                let Some(witness) = claim.finality_witness.as_deref() else {
                    continue;
                };
                match self.verify_external_finality_witness(witness) {
                    Ok(record) => record,
                    Err(_) => {
                        self.metrics.record_rejection();
                        continue;
                    }
                }
            };
            if verified.height != claim.finalized_height
                || verified.block_id != claim.finalized_hash
                || verified.finality_certificate_id != claim.finality_evidence_id
            {
                self.metrics.record_rejection();
                continue;
            }
            self.ingress.submit_verified_head(VerifiedHead {
                peer_id: peer.node_address.to_string(),
                finalized_height: verified.height,
                finalized_hash: verified.block_id,
                finality_evidence_id: verified.finality_certificate_id,
            })?;
        }
        Ok(())
    }
}

fn candidate_matches_proposal(
    candidate: &ExecutionCandidate,
    proposal: &SimplifiedProposal,
) -> bool {
    candidate.height == proposal.context.height
        && candidate.block_id == proposal.block_id
        && candidate.parent_block_id == proposal.parent_block_id
        && candidate.protected_execution_root == proposal.protected_execution_root
}

impl PosyMessageSink for PosyService {
    fn receive_posy(&mut self, peer: AuthenticatedPeer, payload: Vec<u8>) -> Result<(), String> {
        let event: ConsensusEvent = serde_json::from_slice(&payload)
            .map_err(|error| format!("decode authenticated PoSy event: {error}"))?;
        let direct_sender = match &event {
            ConsensusEvent::Proposal(proposal) => Some(proposal.proposer_id.as_str()),
            ConsensusEvent::BlockVote(vote) => Some(vote.validator_id.as_str()),
            ConsensusEvent::TimeoutVote(vote) => Some(vote.validator_id.as_str()),
            ConsensusEvent::QuorumCertificate(_) | ConsensusEvent::TimeoutCertificate(_) => None,
        };
        if direct_sender.is_some_and(|sender| sender != peer.node_address.as_str()) {
            return Err("PoSy message signer differs from authenticated transport peer".into());
        }
        self.apply_event(event)
    }
}

impl ManagedService for PosyService {
    fn start(&mut self, cancellation: &CancellationToken) -> Result<(), String> {
        if cancellation.is_cancelled() {
            return Err("PoSy service start was cancelled".into());
        }
        if self.recovery.is_none() || self.finality.is_none() {
            return Err("PoSy durable safety owners are unavailable".into());
        }
        if self.mode == ConsensusMode::ValidateAndVote && self.local_signer.is_none() {
            return Err("PoSy voting is configured without a verified signer".into());
        }
        self.authority
            .epoch
            .validate_against(&self.authority.registry)
            .map_err(|error| format!("revalidate frozen PoSy authority: {error}"))?;
        self.round_deadline = Instant::now() + self.round_timeout;
        self.started = true;
        self.failure = None;
        Ok(())
    }

    fn poll(&mut self) -> Result<(), String> {
        if !self.started {
            return Err("PoSy service is not started".into());
        }
        inspect_bounded_regular(
            &self.authority_binding,
            MAX_AUTHORITY_BINDING_BYTES,
            "PoSy authority binding",
            false,
        )?;
        for _ in 0..MAX_MESSAGES_PER_POLL {
            let Some(frame) = self.ingress.take(ProtocolKind::Posy)? else {
                break;
            };
            PosyAdapter
                .deliver(AdapterEnvelope::from(frame), self)
                .map_err(|error| format!("route authenticated PoSy frame: {error:?}"))?;
        }
        for _ in 0..MAX_MESSAGES_PER_POLL {
            let Some((_peer, event)) = self.ingress.take_consensus_event()? else {
                break;
            };
            self.apply_event(event)?;
        }
        self.collect_candidates()?;
        self.verify_sync_claims()?;
        self.admit_sync_candidates()?;
        self.emit_timeout_vote()
    }

    fn stop(&mut self) -> Result<(), String> {
        self.ingress.clear(ProtocolKind::Posy)?;
        self.started = false;
        self.recovery = None;
        self.finality = None;
        self.emitted_slots.clear();
        self.pending_proposals.clear();
        self.local_signer = None;
        Ok(())
    }

    fn health(&self) -> ServiceHealth {
        if !self.started
            || self.recovery.is_none()
            || self.finality.is_none()
            || (self.mode == ConsensusMode::ValidateAndVote && self.local_signer.is_none())
        {
            return ServiceHealth::Unhealthy {
                reason: "PoSy durability or single-driver boundary is stopped".into(),
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
        if !self.started {
            return ServiceReadiness::Blocked {
                reason: "PoSy service is stopped".into(),
            };
        }
        if self.mode == ConsensusMode::ValidateAndVote && self.local_signer.is_none() {
            return ServiceReadiness::Blocked {
                reason: "PoSy validator signer is unavailable".into(),
            };
        }
        ServiceReadiness::Ready
    }
}
