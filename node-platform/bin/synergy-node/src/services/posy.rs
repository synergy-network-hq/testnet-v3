use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::Read;
use std::sync::Arc;
#[cfg(test)]
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use synergy_aegis::{
    AegisPolicy, AegisSigner, AegisVerifier, KeyId, SignatureAlgorithm, SigningContext,
};
use synergy_config::{ConsensusMode, NodeConfiguration};
use synergy_execution::BudgetedExecutionCandidate as ExecutionCandidate;
use synergy_identity::PublicNodeIdentity;
use synergy_node_core::{
    CancellationToken, Criticality, ManagedService, RestartPolicy, ServiceHealth, ServiceId,
    ServiceReadiness, ServiceSpec,
};
use synergy_p2p_protocols::{AdapterEnvelope, PosyAdapter, PosyMessageSink};
use synergy_posy::persistence::{
    AtomicConsensusTransitionStore, ConsensusSigner, DurableSigningAuthority, FinalityStore,
    TimeoutSlotCursor, VerifiedQuorumCertificateStore, VerifiedTimeoutCertificateStore,
};
use synergy_posy::{
    timeout_vote_signing_bytes, validate_block_vote, validate_proposal, validate_timeout_vote,
    AcceptedTimeoutSummary, BlockVote, ConsensusEvent, ConsensusObjectContext, ConsensusTransition,
    FinalitySyncWitness, FinalizedBlockRecord, PosyError, PosyMetrics, PosyRecoveryJournal,
    ProposalDelivery, ProposalDeliveryEnvelope, ProposalDeliveryPhase, ProposalDeliveryStatement,
    SignOnceJournal, SigningSlot, SimplifiedConsensusStateMachine, SimplifiedPosyDriver,
    SimplifiedProposal, SimplifiedQuorumCertificate, ThreeQcFinality, TimeoutVote,
    POSY_SIMPLIFIED_PROPOSAL_DOMAIN, POSY_SIMPLIFIED_TIMEOUT_VOTE_DOMAIN,
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
const MAX_DEFERRED_QCS: usize = 64;
const MAX_DEFERRED_SYNC: usize = 8;

#[cfg(test)]
use synergy_aegis::PqvmSigner;

struct LocalConsensusSigner {
    validator_id: String,
    key_id: KeyId,
    signer: Arc<dyn AegisSigner>,
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

pub fn registration_with_preparation(
    configuration: &NodeConfiguration,
    authority: Arc<VerifiedAuthority>,
    ingress: AuthenticatedIngress,
    preparation: Option<super::preparation::Handle>,
) -> Result<(ServiceSpec, Box<dyn ManagedService>), String> {
    let authority = VerifiedAuthority::owner_context(&authority)?;
    let preparation = preparation
        .map(|handle| {
            handle.owner::<PreparedConsensus>(super::preparation::AuthorityTag {
                incarnation: authority.epoch.network_id.clone(),
                epoch: authority.epoch.epoch,
                authority_digest: synergy_etdag::EtdagDigest::from_domain_bytes(
                    "SYNERGY_PREPARATION_AUTHORITY_V1",
                    authority.binding_bytes(),
                )
                .0,
            })
        })
        .transpose()?;
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
    let last_finalized = replay_verified_safety_state_from_floor(
        &mut state_machine,
        &authority,
        &certificates,
        &timeout_certificates,
        &finality,
        Some(sign_once.finalized_floor()),
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
    let delivery_transition =
        authority::load_transition_context(configuration, authority.as_ref())?;
    let mut delivery = if let Some(transition) = delivery_transition.as_ref() {
        transition.verify_current(authority.as_ref())?;
        let previous = transition.previous_authority();
        ProposalDelivery::open_after_verified_epoch_transition(
            &root,
            (&authority.epoch, &authority.registry, authority.as_ref()),
            (&previous.epoch, &previous.registry, previous.as_ref()),
        )
    } else {
        ProposalDelivery::open(
            &root,
            &authority.epoch,
            &authority.registry,
            authority.as_ref(),
        )
    }
    .map_err(|e| format!("load authenticated proposal delivery: {e}"))?;
    delivery
        .activate(state_machine.active_slot())
        .map_err(|e| e.to_string())?;
    let mut local_signer = match consensus.mode {
        ConsensusMode::Observe => None,
        ConsensusMode::ValidateAndVote => Some(DurableSigningAuthority::new(
            sign_once,
            load_local_signer(configuration, &authority)?,
        )),
        ConsensusMode::Disabled => None,
    };
    if let (Some(local), Some(finalized)) = (local_signer.as_mut(), last_finalized.as_ref()) {
        local
            .record_verified_finalized_floor(finalized.height)
            .map_err(|e| e.to_string())?;
    }
    let last_voted_candidate = if let Some(local) = local_signer.as_ref() {
        if let Some(vote) = local
            .journal()
            .recover_last_block_vote(state_machine.active_slot().0)
            .map_err(|e| format!("recover last vote: {e:?}"))?
        {
            validate_block_vote(
                &vote,
                &authority.epoch,
                &authority.registry,
                authority.as_ref(),
            )
            .map_err(|e| e.to_string())?;
            Some(
                synergy_posy::CertifiedCandidateSubject::new(
                    vote.context,
                    vote.block_id,
                    vote.parent_block_id,
                    vote.parent,
                    vote.protected_execution_root,
                )
                .map_err(|e| e.to_string())?,
            )
        } else {
            None
        }
    } else {
        None
    };
    // ETDAG starts before PoSy. Restore authority evidence during registration,
    // before any service can reopen a durable closed protected target.
    republish_verified_validation_history(
        &delivery,
        state_machine.active_slot().0,
        authority.as_ref(),
        &ingress,
    )?;
    let mut retry_frames = BTreeMap::new();
    if !state_machine.epoch_complete() {
        for certificate in state_machine.accepted_timeout_certificates() {
            retry_frames.insert(
                (certificate.context().height, certificate.context().round, 4),
                RetryFrame::Timeout {
                    summary: Box::new(certificate.clone()),
                    fingerprint: None,
                },
            );
        }
    }
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
        super::owned_service::production(
            Box::new(PosyService {
                mode: consensus.mode,
                preparation,
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
                processing_candidate_rounds: BTreeMap::new(),
                pending_proposals: BTreeMap::new(),
                deferred_qcs: BTreeMap::new(),
                deferred_sync: BTreeMap::new(),
                pending_verified_sync: None,
                delivery,
                delivery_proposal: None,
                delivery_validation_retry: false,
                metrics: PosyMetrics::default(),
                emitted_slots: BTreeSet::new(),
                retry_frames,
                historical_timeouts: HistoricalTimeoutRetry::default(),
                retry_at: Instant::now(),
                retry_cursor: 0,
                last_voted_candidate,
                ingress,
                round_timeout: Duration::from_millis(consensus.round_timeout_ms),
                round_deadline: Instant::now() + Duration::from_millis(consensus.round_timeout_ms),
                started: false,
                failure: None,
            }),
            "posy",
        ),
    ))
}

/// Reconstructs the one PoSy state machine from authority-verified, immutable
/// QC and timeout records. Missing or conflicting finalized commits fail closed.
#[cfg(test)]
pub(super) fn replay_verified_safety_state(
    state_machine: &mut SimplifiedConsensusStateMachine,
    authority: &VerifiedAuthority,
    certificates: &VerifiedQuorumCertificateStore,
    timeout_certificates: &VerifiedTimeoutCertificateStore,
    finality: &FinalityStore,
) -> Result<Option<synergy_posy::FinalizedBlockRecord>, String> {
    replay_verified_safety_state_from_floor(
        state_machine,
        authority,
        certificates,
        timeout_certificates,
        finality,
        None,
    )
}

/// A durable signer floor is an index into existing committed evidence, never
/// authority by itself. Authenticate that floor and seed only its lease anchor.
pub(super) fn replay_verified_safety_state_from_floor(
    state_machine: &mut SimplifiedConsensusStateMachine,
    authority: &VerifiedAuthority,
    certificates: &VerifiedQuorumCertificateStore,
    timeout_certificates: &VerifiedTimeoutCertificateStore,
    finality: &FinalityStore,
    finalized_floor: Option<u64>,
) -> Result<Option<synergy_posy::FinalizedBlockRecord>, String> {
    // Recovery is staged: a failed proof must not leave partially restored
    // control state available to a caller, and never writes signing evidence.
    let mut recovered = SimplifiedConsensusStateMachine::new(
        authority.epoch.clone(),
        authority.registry.clone(),
        authority.anchor_parent.clone(),
    )
    .map_err(|error| format!("construct staged PoSy recovery: {error}"))?;
    if authority.epoch.epoch > 1 {
        let record = state_machine
            .last_finalized()
            .cloned()
            .ok_or("successor recovery lacks verified transition finality")?;
        let tail = state_machine
            .finality_witness(record.height)
            .ok_or("successor recovery lacks verified transition QC tail")?;
        recovered
            .seed_epoch_transition_finality(record, tail)
            .map_err(|error| format!("seed staged PoSy transition recovery: {error}"))?;
    }
    seed_committed_recovery_anchor(
        &mut recovered,
        authority,
        certificates,
        timeout_certificates,
        finality,
        finalized_floor,
    )?;
    let finalized = replay_verified_safety_state_into(
        &mut recovered,
        authority,
        certificates,
        timeout_certificates,
        finality,
    )?;
    reconcile_retained_lease_timeouts(
        &mut recovered,
        authority,
        certificates,
        timeout_certificates,
        finality,
    )?;
    *state_machine = recovered;
    Ok(finalized)
}

/// Authenticate an existing local finality commit and its exact three-QC
/// witness. Direct height reads preserve old conflict detection without loading
/// the historical prefix into the reconstructed owner.
fn committed_recovery_witness(
    height: u64,
    authority: &VerifiedAuthority,
    certificates: &VerifiedQuorumCertificateStore,
    timeouts: &VerifiedTimeoutCertificateStore,
    durable: &FinalityStore,
) -> Result<(synergy_posy::FinalizedBlockRecord, FinalitySyncWitness), String> {
    let committed = durable
        .get(height)
        .map_err(|e| e.to_string())?
        .ok_or("bounded recovery lacks its committed finalized record")?;
    let mut qcs = Vec::with_capacity(3);
    let mut verified = ThreeQcFinality::default();
    for offset in 0..3 {
        let covered = height
            .checked_add(offset)
            .ok_or("bounded recovery height overflow")?;
        let qc = certificates
            .get_verified(covered, &authority.epoch, &authority.registry, authority)
            .map_err(|e| format!("verify bounded recovery anchor QC: {e}"))?
            .ok_or("bounded recovery finalized commit lacks its three-QC witness")?;
        verified.accept(qc.clone()).map_err(|e| e.to_string())?;
        qcs.push(qc);
    }
    if verified.last_finalized() != Some(&committed) {
        return Err("bounded recovery witness conflicts with committed finality".into());
    }
    let witness = FinalitySyncWitness::from_verified_certificates(
        qcs.try_into()
            .map_err(|_| "bounded recovery requires three QCs")?,
        timeouts,
        &authority.epoch,
        &authority.registry,
        authority,
    )
    .map_err(|e| format!("verify bounded recovery timeout ancestry: {e}"))?;
    witness
        .verified_timeout_closure(&authority.epoch, &authority.registry, authority)
        .map_err(|e| e.to_string())?;
    Ok((committed, witness))
}

fn seed_committed_recovery_anchor(
    state: &mut SimplifiedConsensusStateMachine,
    authority: &VerifiedAuthority,
    certificates: &VerifiedQuorumCertificateStore,
    timeouts: &VerifiedTimeoutCertificateStore,
    durable: &FinalityStore,
    finalized_floor: Option<u64>,
) -> Result<(), String> {
    // Successor-epoch and Genesis bootstrap recovery retain their existing
    // verified transition procedure.
    let Some(floor) = finalized_floor.filter(|floor| *floor > 0) else {
        return Ok(());
    };
    if authority.epoch.epoch != 1 {
        return Ok(());
    }
    committed_recovery_witness(floor, authority, certificates, timeouts, durable)?;
    let end = floor
        .checked_add(3)
        .ok_or("bounded recovery safety floor overflow")?
        .min(authority.epoch.epoch_end_height);
    if !authority.epoch.contains_height(end) {
        return Err("bounded recovery floor is outside current authority".into());
    }
    let lease = authority
        .epoch
        .lease_index(end)
        .map_err(|e| e.to_string())?;
    let boundary = authority
        .epoch
        .epoch_start_height
        .checked_add(
            lease
                .checked_mul(authority.epoch.leader_lease_blocks)
                .ok_or("bounded recovery lease overflow")?,
        )
        .ok_or("bounded recovery boundary overflow")?;
    let Some(anchor) = boundary
        .checked_sub(3)
        .filter(|anchor| *anchor >= authority.epoch.epoch_start_height)
    else {
        return Ok(());
    };
    if anchor > floor {
        return Err("bounded recovery anchor exceeds committed safety floor".into());
    }
    let (committed, witness) =
        committed_recovery_witness(anchor, authority, certificates, timeouts, durable)?;
    state
        .seed_committed_lease_boundary(committed, witness, authority)
        .map_err(|e| format!("seed verified committed lease anchor: {e}"))
}

/// R2 restores late carried timeouts after the immutable certified prefix.
/// R1-superseded alternate carries stay in storage and cannot supply live authority.
fn reconcile_retained_lease_timeouts(
    state: &mut SimplifiedConsensusStateMachine,
    authority: &VerifiedAuthority,
    certificates: &VerifiedQuorumCertificateStore,
    timeouts: &VerifiedTimeoutCertificateStore,
    finality: &FinalityStore,
) -> Result<(), String> {
    if state.epoch_complete() {
        return Ok(());
    }
    let active = state.active_slot().0;
    for (height, round) in timeouts
        .get_slots_for_lease_before(active, active, &authority.epoch, &authority.registry)
        .map_err(|e| format!("load retained R2 lease timeouts: {e}"))?
    {
        let timeout = timeouts
            .get_verified(
                height,
                round,
                &authority.epoch,
                &authority.registry,
                authority,
            )
            .map_err(|e| format!("load retained R2 original timeout: {e}"))?
            .ok_or("retained R2 timeout disappeared")?;
        if timeout.context.height >= active {
            continue;
        }
        let Some(qc) = certificates
            .get_verified(
                timeout.context.height,
                &authority.epoch,
                &authority.registry,
                authority,
            )
            .map_err(|e| format!("load R2 carried QC: {e}"))?
        else {
            continue;
        };
        let retained_limit =
            verify_unused_recovery_timeouts(&qc, authority, certificates, timeouts, finality)?;
        if timeout.context.round >= retained_limit {
            // R1 has independently verified three-QC supersession and its
            // durable finalized commit. R2 must not reactivate that branch.
            continue;
        }
        if timeout.highest_parent().map_err(|e| e.to_string())? != qc.parent
            || timeout
                .mandatory_carry_candidate()
                .map_err(|e| e.to_string())?
                != Some(qc.subject().map_err(|e| e.to_string())?)
        {
            continue;
        }
        state
            .accept_timeout_certificate(timeout, authority)
            .map_err(|e| format!("restore retained R2 lease authority: {e}"))?;
    }
    Ok(())
}

fn replay_verified_safety_state_into(
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
        let certificate = certificates
            .get_verified(height, &authority.epoch, &authority.registry, authority)
            .map_err(|error| format!("load verified PoSy QC for recovery: {error}"))?;
        let replay_round_limit = if let Some(qc) = certificate.as_ref() {
            verify_unused_recovery_timeouts(
                qc,
                authority,
                certificates,
                timeout_certificates,
                finality,
            )?
        } else {
            u64::MAX
        };
        loop {
            let (slot_height, round) = state_machine.active_slot();
            if certificate.is_some() && round >= replay_round_limit {
                break;
            }
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
                if certificate
                    .as_ref()
                    .is_some_and(|qc| round < qc.context.round)
                {
                    return Err(format!(
                        "certified PoSy recovery lacks timeout at {slot_height}/{round}"
                    ));
                }
                break;
            };
            state_machine
                .accept_timeout_certificate(timeout, authority)
                .map_err(|error| {
                    format!("replay PoSy timeout at {slot_height}/{round}: {error}")
                })?;
        }
        let Some(certificate) = certificate else {
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

/// R1 permits only a three-QC-backed compatible local timeout tail to be
/// omitted from certified-history projection. Every original record stays put.
fn verify_unused_recovery_timeouts(
    qc: &SimplifiedQuorumCertificate,
    authority: &VerifiedAuthority,
    certificates: &VerifiedQuorumCertificateStore,
    timeouts: &VerifiedTimeoutCertificateStore,
    finality: &FinalityStore,
) -> Result<u64, String> {
    let height = qc.context.height;
    let mut round = qc.context.round;
    let mut previous = qc.takeover_tc_id.clone();
    let mut witness = None;
    let mut replay_round_limit = round;
    // A timeout after the last stored QC is still outstanding lease control.
    // A backward covering witness cannot authorize rolling the active tip back.
    let next = height.checked_add(1).ok_or("R1 QC height overflow")?;
    if certificates
        .get_verified(next, &authority.epoch, &authority.registry, authority)
        .map_err(|error| format!("load R1 descendant authority: {error}"))?
        .is_none()
    {
        return Ok(u64::MAX);
    }
    while let Some(timeout) = timeouts
        .get_verified(
            height,
            round,
            &authority.epoch,
            &authority.registry,
            authority,
        )
        .map_err(|error| format!("load local R1 timeout tail: {error}"))?
    {
        if timeout.previous_tc_id != previous {
            return Err("R1 local timeout tail has a missing or different predecessor".into());
        }
        if witness.is_none() {
            let mut covering_chain = None;
            for backwards in 0..=2 {
                let Some(first) = height.checked_sub(backwards) else {
                    continue;
                };
                if first < authority.epoch.epoch_start_height {
                    continue;
                }
                let mut chain = Vec::with_capacity(3);
                for offset in 0..3 {
                    let covered = first
                        .checked_add(offset)
                        .ok_or("R1 witness height overflow")?;
                    let proof = certificates
                        .get_verified(covered, &authority.epoch, &authority.registry, authority)
                        .map_err(|error| format!("load R1 covering QC: {error}"))?;
                    let Some(proof) = proof else { break };
                    chain.push(proof);
                }
                if chain.len() == 3 {
                    covering_chain = Some(chain);
                    break;
                }
            }
            let Some(chain) = covering_chain else {
                // Without finality authority, retain ordinary TC-first replay.
                return Ok(u64::MAX);
            };
            let chain = chain
                .try_into()
                .map_err(|_| "R1 requires exactly three QCs")?;
            witness = Some(
                FinalitySyncWitness::from_verified_certificates(
                    chain,
                    timeouts,
                    &authority.epoch,
                    &authority.registry,
                    authority,
                )
                .map_err(|error| format!("load R1 certified timeout closure: {error}"))?,
            );
        }
        let proof = witness.as_ref().ok_or("R1 witness unavailable")?;
        let timeout_id = timeout.id().map_err(|error| error.to_string())?;
        let retained = proof
            .timeout_certificates
            .iter()
            .any(|tc| tc.id().is_ok_and(|id| id == timeout_id));
        if retained {
            replay_round_limit = round.checked_add(1).ok_or("R1 timeout round overflow")?;
        } else {
            let record = proof
                .verify_superseded_timeout(
                    &timeout,
                    &authority.epoch,
                    &authority.registry,
                    authority,
                )
                .map_err(|error| format!("verify R1 local timeout supersession: {error}"))?;
            let committed = finality
                .get(record.height)
                .map_err(|error| format!("load R1 durable finalized authority: {error}"))?
                .ok_or("R1 three-QC authority is not durably committed")?;
            if committed != record {
                return Err("R1 witness conflicts with durable finalized authority".into());
            }
        }
        previous = Some(timeout.id().map_err(|error| error.to_string())?);
        round = round.checked_add(1).ok_or("R1 timeout round overflow")?;
    }
    Ok(replay_round_limit)
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
    if configuration.apqe_transport.is_some() {
        let signer = super::apqe_provider::consensus_signer(
            configuration,
            authority,
            identity.node_address.as_str(),
            AegisPolicy {
                allowed_algorithms: vec![SignatureAlgorithm::MlDsa65],
                maximum_message_bytes: 1024 * 1024,
                maximum_signature_bytes: 16 * 1024,
            },
        )?;
        return Ok(LocalConsensusSigner {
            validator_id: identity.node_address.to_string(),
            key_id,
            signer,
            chain_id: configuration.chain_id,
            epoch: authority.epoch.epoch,
        });
    }
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
    let signer = super::apqe_provider::signer(
        configuration,
        policy.clone(),
        key_id.clone(),
        public_key,
        secret_key,
    )
    .map_err(|error| format!("load PQVM consensus signer: {error}"))?;
    let verifier = super::apqe_provider::verifier(configuration, policy)?;
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
        signer: Arc::new(signer),
        chain_id: configuration.chain_id,
        epoch: authority.epoch.epoch,
    })
}

struct PreparedConsensus {
    peer: AuthenticatedPeer,
    event: ConsensusEvent,
}

struct PosyService {
    preparation: Option<super::preparation::Owner<PreparedConsensus>>,
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
    candidates: BTreeMap<u64, Arc<ExecutionCandidate>>,
    processing_candidate_rounds: BTreeMap<u64, u64>,
    pending_proposals: BTreeMap<(u64, u64), SimplifiedProposal>,
    deferred_qcs: BTreeMap<u64, synergy_posy::SimplifiedQuorumCertificate>,
    deferred_sync: BTreeMap<u64, super::ingress::FinalizedCandidateResponse>,
    pending_verified_sync: Option<(Arc<ExecutionCandidate>, FinalizedBlockRecord)>,
    delivery: ProposalDelivery,
    delivery_proposal: Option<SimplifiedProposal>,
    delivery_validation_retry: bool,
    metrics: PosyMetrics,
    emitted_slots: BTreeSet<SigningSlot>,
    retry_frames: BTreeMap<(u64, u64, u8), RetryFrame>,
    historical_timeouts: HistoricalTimeoutRetry,
    retry_at: Instant,
    retry_cursor: usize,
    last_voted_candidate: Option<synergy_posy::CertifiedCandidateSubject>,
    ingress: AuthenticatedIngress,
    round_timeout: Duration,
    round_deadline: Instant,
    started: bool,
    failure: Option<String>,
}

/// Transport-only bounded scan of immutable originals. At most one historical
/// lease and 4096 slot locators are retained. Larger legacy histories are paged
/// through repeated incremental scans, never omitted or loaded as proof vectors.
#[derive(Default)]
struct HistoricalTimeoutRetry {
    scan: Option<TimeoutSlotCursor>,
    selected: BTreeSet<(u64, u64, u64)>, // lease, round, height
    after: Option<(u64, u64, u64)>,
    ready: bool,
    pending: Option<(Vec<u8>, usize)>,
    first: bool,
}

impl HistoricalTimeoutRetry {
    fn select(&mut self, key: (u64, u64, u64)) {
        if self.after.is_some_and(|after| key <= after) {
            return;
        }
        if let Some(first) = self.selected.first() {
            if key.0 > first.0 {
                return;
            }
            if key.0 < first.0 {
                self.selected.clear();
            }
        }
        self.selected.insert(key);
        if self.selected.len() > 4096 {
            self.selected.pop_last();
        }
    }
}

/// Historical TCs retain authenticated metadata only. Native originals are
/// immutable and loaded one at a time; ordinary current-slot frames remain bytes.
#[derive(Clone)]
enum RetryFrame {
    Bytes(Vec<u8>),
    Timeout {
        summary: Box<AcceptedTimeoutSummary>,
        fingerprint: Option<synergy_etdag::EtdagDigest>,
    },
}

impl PosyService {
    fn retry_payload(&mut self, slot: (u64, u64, u8)) -> Result<Vec<u8>, String> {
        let (summary, fingerprint) = match self.retry_frames.get(&slot) {
            Some(RetryFrame::Bytes(bytes)) => return Ok(bytes.clone()),
            Some(RetryFrame::Timeout {
                summary,
                fingerprint,
            }) => (summary.clone(), fingerprint.clone()),
            None => return Err("missing PoSy retry reference".into()),
        };
        let certificate = self
            .timeout_certificates
            .get_verified(
                slot.0,
                slot.1,
                &self.authority.epoch,
                &self.authority.registry,
                self.authority.as_ref(),
            )
            .map_err(|e| format!("load native PoSy retry original: {e}"))?
            .ok_or("PoSy retry original is missing")?;
        if !summary
            .matches_certificate(&certificate)
            .map_err(|e| e.to_string())?
        {
            return Err("PoSy retry original conflicts with accepted timeout authority".into());
        }
        let payload = serde_json::to_vec(&ConsensusEvent::TimeoutCertificate(certificate))
            .map_err(|e| e.to_string())?;
        let digest = synergy_etdag::EtdagDigest::from_domain_bytes(
            "Synergy/PoSy/v3/timeout-retry-bytes",
            &payload,
        );
        if fingerprint
            .as_ref()
            .is_some_and(|expected| expected != &digest)
        {
            return Err("PoSy immutable timeout retry bytes changed".into());
        }
        if let Some(RetryFrame::Timeout { fingerprint, .. }) = self.retry_frames.get_mut(&slot) {
            *fingerprint = Some(digest);
        }
        Ok(payload)
    }

    fn broadcast(&mut self, event: &ConsensusEvent) -> Result<(), String> {
        let slot = event_slot(event);
        let payload = if let ConsensusEvent::TimeoutCertificate(certificate) = event {
            let id = certificate.id().map_err(|e| e.to_string())?;
            let summary = self
                .driver
                .state_machine()
                .accepted_timeout_certificate(&id)
                .ok_or("outbound PoSy timeout has no accepted authority")?
                .clone();
            if !summary
                .matches_certificate(certificate)
                .map_err(|e| e.to_string())?
            {
                return Err("outbound timeout conflicts with accepted authority".into());
            }
            match self.retry_frames.entry(slot) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(RetryFrame::Timeout {
                        summary: Box::new(summary),
                        fingerprint: None,
                    });
                }
                std::collections::btree_map::Entry::Occupied(mut entry) => {
                    let RetryFrame::Timeout {
                        summary: retained, ..
                    } = entry.get_mut()
                    else {
                        return Err("PoSy timeout retry slot contains another event".into());
                    };
                    // A newly admitted equivalent variant may strengthen a
                    // projection. Compare the original against current authority.
                    **retained = summary;
                }
            }
            // Select the immutable verified original before the first send, so
            // retries preserve its exact signed bytes even for proof variants.
            self.retry_payload(slot)?
        } else {
            serde_json::to_vec(event)
                .map_err(|error| format!("encode PoSy network event: {error}"))?
        };
        if let ConsensusEvent::ProposalDelivery(envelope) = event {
            if envelope.statement.phase == ProposalDeliveryPhase::Ready {
                self.delivery
                    .persist_ready_envelope(
                        envelope,
                        &self.authority.epoch,
                        &self.authority.registry,
                        self.authority.as_ref(),
                    )
                    .map_err(|e| e.to_string())?;
            }
        }
        if slot.2 == 6 {
            self.retry_frames
                .insert(slot, RetryFrame::Bytes(payload.clone()));
        } else if slot.2 != 4 {
            self.retry_frames
                .entry(slot)
                .or_insert(RetryFrame::Bytes(payload.clone()));
        }
        self.prune_retry_frames()?;
        self.send_payload(&payload)
    }

    fn send_payload(&self, payload: &[u8]) -> Result<(), String> {
        for peer_id in self.ingress.authenticated_peers()? {
            // A full queue leaves the exact signed bytes in retry_frames.
            // Never re-sign, advance rounds, or fail the node for backpressure.
            if !self.ingress.try_publish_outbound(OutboundFrame {
                peer_id,
                protocol: ProtocolKind::Posy,
                payload: payload.to_vec(),
            })? {
                break;
            }
        }
        Ok(())
    }

    fn prune_retry_frames(&mut self) -> Result<(), String> {
        let active = self.driver.state_machine().active_slot();
        let epoch = &self.authority.epoch;
        let active_lease = epoch.lease_index(active.0).map_err(|e| e.to_string())?;
        let local_validator = self
            .local_signer
            .as_ref()
            .map(|signer| signer.validator_id().to_string());
        let validator_peers: Vec<String> = epoch
            .leader_ring
            .iter()
            .filter(|validator| Some(validator.as_str()) != local_validator.as_deref())
            .cloned()
            .collect();
        let verified_peer_heights = self.ingress.verified_peer_heights()?;
        self.retry_frames.retain(|slot, _| {
            if slot.2 == 4 {
                // R2: a QC can arrive before its carried timeout. Keep the
                // exact predecessor chain across proposer leases while any
                // validator may still need it. Unknown progress is lagging;
                // only verified peer progress permits transport pruning.
                epoch
                    .lease_index(slot.0)
                    .is_ok_and(|lease| lease == active_lease)
                    && timeout_retry_is_needed(
                        *slot,
                        active,
                        &validator_peers,
                        &verified_peer_heights,
                    )
            } else {
                retry_slot_is_live(*slot, active)
            }
        });
        Ok(())
    }

    fn retry_historical_timeouts(&mut self, peers: &[String]) -> Result<(), String> {
        if peers.is_empty() {
            return Ok(());
        }
        let active = self.driver.state_machine().active_slot();
        let epoch = &self.authority.epoch;
        let active_lease = epoch.lease_index(active.0).map_err(|e| e.to_string())?;
        if active_lease == 0 {
            return Ok(());
        }
        let progress = self.ingress.verified_peer_heights()?;
        let local = self.local_signer.as_ref().map(|s| s.validator_id());
        let validators: Vec<String> = epoch
            .leader_ring
            .iter()
            .filter(|id| Some(id.as_str()) != local)
            .cloned()
            .collect();
        let history = &mut self.historical_timeouts;
        if !history.ready {
            if history.scan.is_none() {
                history.scan = Some(
                    self.timeout_certificates
                        .slot_cursor()
                        .map_err(|e| e.to_string())?,
                );
            }
            let mut scan = history.scan.take().expect("timeout scan initialized");
            for (height, round) in scan.next_slots(64).map_err(|e| e.to_string())? {
                if !epoch.contains_height(height) {
                    continue;
                }
                let lease = epoch.lease_index(height).map_err(|e| e.to_string())?;
                let key = (lease, round, height);
                if lease >= active_lease
                    || !timeout_retry_is_needed((height, round, 4), active, &validators, &progress)
                {
                    continue;
                }
                history.select(key);
            }
            if !scan.is_complete() {
                history.scan = Some(scan);
                return Ok(());
            }
            if history.selected.is_empty() {
                history.after = None; // Complete sweep; unknown peers get another fair cycle.
                return Ok(());
            }
            history.ready = true;
        }
        if history.pending.is_none() {
            let Some(key @ (_, round, height)) = history.selected.pop_first() else {
                history.ready = false;
                return Ok(());
            };
            history.after = Some(key);
            let original = self
                .timeout_certificates
                .get_verified(
                    height,
                    round,
                    epoch,
                    &self.authority.registry,
                    self.authority.as_ref(),
                )
                .map_err(|e| e.to_string())?
                .ok_or("historical PoSy timeout original disappeared")?;
            history.pending = Some((
                serde_json::to_vec(&ConsensusEvent::TimeoutCertificate(original))
                    .map_err(|e| e.to_string())?,
                0,
            ));
        }
        let (payload, next_peer) = history.pending.as_mut().expect("historical retry loaded");
        while *next_peer < peers.len() {
            if !self.ingress.try_publish_outbound(OutboundFrame {
                peer_id: peers[*next_peer].clone(),
                protocol: ProtocolKind::Posy,
                payload: payload.clone(),
            })? {
                return Ok(());
            }
            *next_peer += 1;
        }
        history.pending = None;
        if history.selected.is_empty() {
            history.ready = false;
        }
        Ok(())
    }

    fn retry_delivery(&mut self) -> Result<(), String> {
        if Instant::now() < self.retry_at {
            return Ok(());
        }
        self.prune_retry_frames()?;
        let peers = self.ingress.authenticated_peers()?;
        self.historical_timeouts.first = !self.historical_timeouts.first;
        let historical_first = self.historical_timeouts.first;
        if historical_first {
            self.retry_historical_timeouts(&peers)?;
        }
        let slots: Vec<_> = self.retry_frames.keys().copied().collect();
        let verified_peer_heights = self.ingress.verified_peer_heights()?;
        let deliveries = peers.len().saturating_mul(slots.len());
        let mut loaded_timeout_frames = 0usize;
        let mut current_payload: Option<((u64, u64, u8), Vec<u8>)> = None;
        #[cfg(test)]
        let mut r3_timeout_published = 0usize;
        if deliveries != 0 {
            // Resume after the last accepted delivery. Starting at the first
            // frame/peer each tick starves the tail under sustained backpressure.
            self.retry_cursor %= deliveries;
            for _ in 0..deliveries.min(MAX_MESSAGES_PER_POLL) {
                let index = self.retry_cursor;
                let slot = slots[index / peers.len()];
                let peer = &peers[index % peers.len()];
                if !certificate_retry_is_needed(slot, verified_peer_heights.get(peer).copied()) {
                    // This session has already supplied verified three-QC
                    // finality whose certified tail covers this height. Keep
                    // the original for Sync and
                    // lagging/reconnected peers, but do not re-sign/re-send it
                    // to this peer. Skips must not starve later delivery pairs.
                    self.retry_cursor = (index + 1) % deliveries;
                    continue;
                }
                if current_payload
                    .as_ref()
                    .is_none_or(|(loaded, _)| *loaded != slot)
                {
                    if slot.2 == 4 {
                        if loaded_timeout_frames >= 4 {
                            break;
                        }
                        loaded_timeout_frames += 1;
                    }
                    current_payload = Some((slot, self.retry_payload(slot)?));
                }
                let payload = &current_payload
                    .as_ref()
                    .expect("retry payload was loaded")
                    .1;
                if !self.ingress.try_publish_outbound(OutboundFrame {
                    peer_id: peer.clone(),
                    protocol: ProtocolKind::Posy,
                    payload: payload.clone(),
                })? {
                    break;
                }
                #[cfg(test)]
                if serde_json::from_slice::<ConsensusEvent>(payload)
                    .is_ok_and(|event| matches!(event, ConsensusEvent::TimeoutCertificate(tc) if tc.context.height == 50))
                {
                    r3_timeout_published += 1;
                }
                self.retry_cursor = (index + 1) % deliveries;
            }
        }
        #[cfg(test)]
        if std::env::var_os("SYNERGY_SOCKET_QUALIFICATION_R3_DIAGNOSTICS").is_some()
            && self.driver.state_machine().active_slot().0 >= 50
        {
            static LAST_RETRY_REPORT: OnceLock<Mutex<BTreeMap<String, Instant>>> = OnceLock::new();
            let validator = self
                .local_signer
                .as_ref()
                .map(|s| s.validator_id())
                .unwrap_or("observer");
            if let Ok(mut last) = LAST_RETRY_REPORT
                .get_or_init(|| Mutex::new(BTreeMap::new()))
                .lock()
            {
                let now = Instant::now();
                if last
                    .get(validator)
                    .is_none_or(|at| now.duration_since(*at) >= Duration::from_secs(10))
                {
                    last.insert(validator.to_owned(), now);
                    let slots: Vec<_> = self
                        .retry_frames
                        .keys()
                        .filter(|slot| slot.0 == 50 && slot.2 == 4)
                        .collect();
                    eprintln!("R3 TC retry: validator={validator} active={:?} slots={slots:?} peers={peers:?} verified_heads={:?} published={r3_timeout_published}",
                        self.driver.state_machine().active_slot(), self.ingress.verified_peer_heights()?);
                }
            }
        }
        if !historical_first {
            self.retry_historical_timeouts(&peers)?;
        }
        self.retry_at = Instant::now() + Duration::from_millis(250);
        Ok(())
    }

    fn handle_transitions(&mut self, transitions: Vec<ConsensusTransition>) -> Result<(), String> {
        let mut transitions = transitions.into_iter().peekable();
        while let Some(transition) = transitions.next() {
            match transition {
                ConsensusTransition::QuorumCertified(certificate) => {
                    #[cfg(feature = "qualification-timing")]
                    let measured_slot = (certificate.context.height, certificate.context.round);
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
                        #[cfg(feature = "qualification-timing")]
                        qualification_qc(measured_slot.0, measured_slot.1);
                        #[cfg(feature = "qualification-timing")]
                        qualification_finality(record.height);
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
                        if let Some(local) = self.local_signer.as_mut() {
                            local
                                .record_verified_finalized_floor(record.height)
                                .map_err(|e| e.to_string())?;
                        }
                        self.delivery
                            .retire_finalized_evidence(record.height)
                            .map_err(|error| {
                                format!("retire finalized READY working evidence: {error}")
                            })?;
                        self.last_finalized = Some(record.clone());
                        retire_finalized_candidates(&mut self.candidates, record.height);
                        self.processing_candidate_rounds
                            .retain(|height, _| *height > record.height);
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
                        #[cfg(feature = "qualification-timing")]
                        qualification_qc(measured_slot.0, measured_slot.1);
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
                    self.delivery.activate(active).map_err(|e| e.to_string())?;
                    self.delivery_proposal = None;
                    self.delivery_validation_retry = false;
                    self.emitted_slots
                        .retain(|slot| (slot.height, slot.round) == active);
                    if self
                        .last_voted_candidate
                        .as_ref()
                        .is_some_and(|candidate| candidate.context.height != active.0)
                    {
                        self.last_voted_candidate = None;
                    }
                    self.prune_retry_frames()?;
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn apply_event(&mut self, event: ConsensusEvent) -> Result<(), String> {
        self.apply_event_from(event, false)
    }

    fn persist_and_publish_validation(
        &self,
        certificate: &synergy_posy::ProposalValidationCertificate,
    ) -> Result<bool, String> {
        let machine = self.driver.state_machine();
        let takeover =
            if machine.active_slot() == (certificate.context.height, certificate.context.round) {
                machine
                    .active_takeover_tc_id()
                    .and_then(|id| machine.accepted_timeout_certificate(id))
            } else {
                None
            };
        let durable = if self.authority.processing_profile_enabled() {
            let store = self
                .ingress
                .processing_proposal_store()?
                .ok_or("native processing proposal store is unavailable")?;
            match store
                .lock()
                .map_err(|_| "processing proposal store lock poisoned")?
                .try_persist_validation(&certificate.candidate.block_id, certificate)
            {
                Ok(()) => {}
                Err(error) if error.is_capacity() => return Ok(false),
                Err(error) => return Err(error.to_string()),
            }
            self.delivery.persist_processing_validation(
                certificate,
                takeover,
                &self.authority.epoch,
                &self.authority.registry,
                self.authority.as_ref(),
            )
        } else {
            self.delivery.persist_validation(
                certificate,
                &self.authority.epoch,
                &self.authority.registry,
                self.authority.as_ref(),
            )
        }
        .map_err(|e| e.to_string())?;
        if self.authority.processing_profile_enabled() {
            self.ingress
                .submit_processing_proposal_validation(durable, takeover)?;
        } else {
            self.ingress.submit_proposal_validation(durable)?;
        }
        Ok(true)
    }

    fn apply_event_from(&mut self, event: ConsensusEvent, from_peer: bool) -> Result<(), String> {
        #[cfg(test)]
        let r3_timeout_diagnostic = match &event {
            ConsensusEvent::TimeoutCertificate(certificate)
                if from_peer && certificate.context.height == 50 =>
            {
                Some(certificate.clone())
            }
            _ => None,
        };
        #[cfg(test)]
        if let Some(certificate) = &r3_timeout_diagnostic {
            self.r3_timeout_diagnostic(certificate, "received");
        }
        if let ConsensusEvent::ProposalDelivery(envelope) = event {
            if let Some(certificate) = envelope.validation_certificate {
                if certificate.candidate != envelope.statement.candidate
                    || certificate.context.height != envelope.statement.context.height
                {
                    self.metrics.record_rejection();
                    return Ok(());
                }
                let active = self.driver.state_machine().active_slot().0;
                if certificate.context.height > active || active - certificate.context.height > 8 {
                    self.metrics.record_rejection();
                    return Ok(());
                }
                match self.persist_and_publish_validation(&certificate) {
                    Ok(true) => {}
                    // The sender retains the exact signed delivery for retry.
                    // Capacity does not authorize READY or invalidate its VC.
                    Ok(false) => return Ok(()),
                    Err(_) if from_peer => {
                        self.metrics.record_rejection();
                        return Ok(());
                    }
                    Err(e) => return Err(format!("persist piggyback VC: {e}")),
                }
            }
            let statement = envelope.statement;
            let processing_echo = (self.authority.processing_profile_enabled()
                && from_peer
                && statement.phase == ProposalDeliveryPhase::Echo)
                .then(|| {
                    (
                        statement.validator_id.clone(),
                        statement.context.height,
                        statement.context.round,
                        statement.candidate.block_id.clone(),
                    )
                });
            match self.delivery.admit(
                statement,
                self.driver.state_machine().active_slot(),
                &self.authority.epoch,
                &self.authority.registry,
                self.authority.as_ref(),
            ) {
                Ok(true) => {
                    if let Some((peer, height, round, block)) = processing_echo {
                        self.ingress
                            .record_processing_input_echo(&peer, height, round, &block)?;
                    }
                    return self.advance_delivery();
                }
                Ok(false) => return Ok(()),
                Err(_) if from_peer => {
                    self.metrics.record_rejection();
                    return Ok(());
                }
                Err(e) => return Err(format!("local proposal delivery: {e}")),
            }
        }
        if let ConsensusEvent::QuorumCertificate(certificate) = &event {
            let active = self.driver.state_machine().active_slot();
            if certificate.context.height > active.0 {
                certificate
                    .verify(
                        &self.authority.epoch,
                        &self.authority.registry,
                        self.authority.as_ref(),
                    )
                    .map_err(|e| format!("verify deferred PoSy QC: {e}"))?;
                if let Some(previous) = self.deferred_qcs.get(&certificate.context.height) {
                    if previous.id().map_err(|e| e.to_string())?
                        != certificate.id().map_err(|e| e.to_string())?
                    {
                        return Err(
                            "conflicting authenticated future PoSy quorum certificates".into()
                        );
                    }
                } else if self.deferred_qcs.len() < MAX_DEFERRED_QCS {
                    self.deferred_qcs
                        .insert(certificate.context.height, certificate.clone());
                }
                return Ok(());
            }
            if certificate.context.height < active.0 {
                let durable = self
                    .certificates
                    .get_verified(
                        certificate.context.height,
                        &self.authority.epoch,
                        &self.authority.registry,
                        self.authority.as_ref(),
                    )
                    .map_err(|e| format!("verify historical PoSy QC: {e}"))?;
                if let Some(durable) = durable {
                    if durable.id().map_err(|e| e.to_string())?
                        != certificate.id().map_err(|e| e.to_string())?
                    {
                        return Err(
                            "conflicting authenticated historical PoSy quorum certificate".into(),
                        );
                    }
                    return Ok(());
                }
                // No historical authority is inferred from an old signature.
                // The driver checks any retained epoch-prefix evidence.
            }
        }
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
                let ready = self
                    .candidates
                    .get(&proposal.context.height)
                    .is_some_and(|candidate| candidate_matches_proposal(candidate, proposal))
                    && (!self.authority.processing_profile_enabled()
                        || self.processing_candidate_rounds.get(&slot.0) == Some(&slot.1));
                if !ready {
                    if !self.authority.processing_profile_enabled()
                        && self.candidates.contains_key(&proposal.context.height)
                    {
                        self.metrics.record_rejection();
                        return Ok(());
                    }
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
            ConsensusEvent::ProposalDelivery(_) => unreachable!(),
            ConsensusEvent::BlockVote(_) | ConsensusEvent::TimeoutVote(_) => 1u8,
            ConsensusEvent::QuorumCertificate(_) | ConsensusEvent::TimeoutCertificate(_) => 2u8,
        };
        let certified = matches!(
            &event,
            ConsensusEvent::QuorumCertificate(_) | ConsensusEvent::TimeoutCertificate(_)
        );
        let transitions = match self.driver.handle(event, self.authority.as_ref()) {
            Ok(transitions) => transitions,
            Err(error) if from_peer && !peer_error_is_fatal(certified, &error) => {
                #[cfg(test)]
                if let Some(certificate) = &r3_timeout_diagnostic {
                    self.r3_timeout_diagnostic(certificate, &format!("rejected:{error}"));
                }
                self.metrics.record_rejection();
                return Ok(());
            }
            Err(PosyError::ResourcePressure(_)) => return Ok(()),
            Err(error) => return Err(format!("PoSy consensus admission failed: {error}")),
        };
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
                self.delivery_proposal = Some(proposal.clone());
                self.emit_delivery(&proposal, ProposalDeliveryPhase::Echo)?;
                self.advance_delivery()?;
            }
        }
        Ok(())
    }

    fn republish_validation_history(&self) -> Result<(), String> {
        republish_verified_validation_history(
            &self.delivery,
            self.driver.state_machine().active_slot().0,
            self.authority.as_ref(),
            &self.ingress,
        )
    }

    fn delivery_envelope(
        &self,
        statement: ProposalDeliveryStatement,
    ) -> Result<ProposalDeliveryEnvelope, String> {
        let validation_certificate = if statement.phase == ProposalDeliveryPhase::Ready {
            self.delivery
                .stored_validation_for(
                    &statement.candidate,
                    &self.authority.epoch,
                    &self.authority.registry,
                    self.authority.as_ref(),
                )
                .map_err(|e| e.to_string())?
        } else {
            None
        };
        Ok(ProposalDeliveryEnvelope {
            statement,
            validation_certificate,
        })
    }

    fn emit_delivery(
        &mut self,
        proposal: &SimplifiedProposal,
        phase: ProposalDeliveryPhase,
    ) -> Result<(), String> {
        let local = self
            .local_signer
            .as_ref()
            .ok_or("PoSy signer unavailable")?;
        let candidate = proposal.candidate_subject().map_err(|e| e.to_string())?;
        if let Some(previous) = self.delivery.local_statement(local.validator_id(), phase) {
            // Sign-once is round scoped; a different Byzantine proposal is never re-signed.
            if previous.candidate != candidate {
                return Ok(());
            }
            let event = ConsensusEvent::ProposalDelivery(self.delivery_envelope(previous.clone())?);
            let payload = serde_json::to_vec(&event).map_err(|e| e.to_string())?;
            if !matches!(self.retry_frames.get(&event_slot(&event)), Some(RetryFrame::Bytes(bytes)) if bytes == &payload)
            {
                self.broadcast(&event)?;
            }
            return Ok(());
        }
        let mut statement = ProposalDeliveryStatement {
            context: proposal.context.clone(),
            phase,
            candidate,
            validator_id: local.validator_id().to_string(),
            key_id: local.key_id().to_string(),
            signature: Vec::new(),
        };
        let slot = SigningSlot {
            height: statement.context.height,
            round: statement.context.round,
            domain: phase.slot_domain().into(),
        };
        let subject = statement.candidate.id().map_err(|e| e.to_string())?;
        let transcript = statement.signing_bytes().map_err(|e| e.to_string())?;
        // The durable exact statement is written before any network publication.
        statement.signature = self
            .local_signer
            .as_mut()
            .ok_or("PoSy signer unavailable")?
            .sign_once(slot, phase.domain(), &subject, &transcript)
            .map_err(|e| e.to_string())?;
        self.delivery
            .admit(
                statement.clone(),
                self.driver.state_machine().active_slot(),
                &self.authority.epoch,
                &self.authority.registry,
                self.authority.as_ref(),
            )
            .map_err(|e| e.to_string())?;
        self.broadcast(&ConsensusEvent::ProposalDelivery(
            self.delivery_envelope(statement)?,
        ))?;
        #[cfg(feature = "qualification-timing")]
        if phase == ProposalDeliveryPhase::Echo {
            super::qualification_timing::processing_boundary(
                "own_echo",
                proposal.context.height,
                proposal.context.round,
                &proposal.block_id,
                self.local_signer
                    .as_ref()
                    .map(|s| s.validator_id())
                    .unwrap_or("observer"),
            );
        }
        Ok(())
    }

    fn advance_delivery(&mut self) -> Result<(), String> {
        if self.mode != ConsensusMode::ValidateAndVote {
            return Ok(());
        }
        let Some(proposal) = self.delivery_proposal.clone() else {
            return Ok(());
        };
        let candidate = proposal.candidate_subject().map_err(|e| e.to_string())?;
        let certificate = self
            .delivery
            .validation_certificate(&candidate, self.authority.registry.active_count());
        if let Some(certificate) = certificate.as_ref() {
            if !self.persist_and_publish_validation(certificate)? {
                // The authenticated ECHO statements remain in delivery. Retry
                // persistence from them before publishing READY or voting.
                self.delivery_validation_retry = true;
                return Ok(());
            }
            self.delivery_validation_retry = false;
        }
        if certificate.is_some()
            || self
                .delivery
                .count(&candidate, ProposalDeliveryPhase::Ready)
                >= 2
        {
            self.emit_delivery(&proposal, ProposalDeliveryPhase::Ready)?;
        }
        if self
            .delivery
            .deliver(&candidate)
            .map_err(|e| e.to_string())?
        {
            self.emit_vote(&proposal)?;
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
        // A speculative candidate retained at this height belongs to its
        // assembly round. A native takeover must obtain a fresh handoff (or
        // explicit carry replay) before signing its replacement envelope.
        if self.authority.processing_profile_enabled()
            && self.processing_candidate_rounds.get(&height) != Some(&round)
        {
            return Ok(());
        }
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
        if self.authority.processing_profile_enabled()
            && ((proposal.context.height, proposal.context.round)
                != self.driver.state_machine().active_slot()
                || self
                    .processing_candidate_rounds
                    .get(&proposal.context.height)
                    != Some(&proposal.context.round))
        {
            return Ok(());
        }
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
        if self.emitted_slots.contains(&slot) {
            return Ok(());
        }
        if self.local_signer.as_ref().is_some_and(|local| {
            local
                .journal()
                .subject(&SigningSlot {
                    domain: "timeout-vote".into(),
                    ..slot.clone()
                })
                .is_some()
        }) {
            return Ok(());
        }
        let unlock = if vote.context.round > 0 {
            self.timeout_certificates
                .get_verified(
                    vote.context.height,
                    vote.context.round - 1,
                    &self.authority.epoch,
                    &self.authority.registry,
                    self.authority.as_ref(),
                )
                .map_err(|e| e.to_string())?
        } else {
            None
        };
        let signature = self
            .local_signer
            .as_mut()
            .ok_or("PoSy signer unavailable")?
            .sign_block_vote_verified(
                &vote,
                &self.authority.epoch,
                &self.authority.registry,
                self.authority.as_ref(),
                unlock.as_ref(),
            )
            .map_err(|e| format!("durable PoSy block-vote refused: {e}"))?;
        self.emitted_slots.insert(slot);
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

    #[cfg(test)]
    fn r3_timeout_diagnostic(
        &self,
        certificate: &synergy_posy::SimplifiedTimeoutCertificate,
        outcome: &str,
    ) {
        if std::env::var_os("SYNERGY_SOCKET_QUALIFICATION_R3_DIAGNOSTICS").is_none()
            || certificate.context.height != 50
        {
            return;
        }
        static COUNTS: OnceLock<Mutex<BTreeMap<(String, bool), usize>>> = OnceLock::new();
        let validator = self
            .local_signer
            .as_ref()
            .map(|signer| signer.validator_id())
            .unwrap_or("observer");
        let Ok(mut counts) = COUNTS.get_or_init(|| Mutex::new(BTreeMap::new())).lock() else {
            return;
        };
        let count = counts
            .entry((validator.to_owned(), outcome != "received"))
            .or_default();
        if *count >= 12 {
            return;
        }
        *count += 1;
        let machine = self.driver.state_machine();
        eprintln!(
            "R3 TC ingress: validator={validator} outcome={outcome} tc={}/{} predecessor={:?} parent={:?} active={:?} active_tc={:?} active_parent={:?}",
            certificate.context.height, certificate.context.round,
            certificate.previous_tc_id, certificate.highest_parent(),
            machine.active_slot(), machine.active_takeover_tc_id(), machine.highest_parent(),
        );
    }

    #[cfg(test)]
    fn r3_recovery_diagnostic(&self, target: u64, height: u64, round: u64, reason: &str) {
        if target < 49 {
            return;
        }
        static LAST: OnceLock<Mutex<BTreeMap<String, Instant>>> = OnceLock::new();
        let validator = self
            .local_signer
            .as_ref()
            .map(|signer| signer.validator_id())
            .unwrap_or("observer");
        let now = Instant::now();
        let Ok(mut last) = LAST.get_or_init(|| Mutex::new(BTreeMap::new())).lock() else {
            return;
        };
        if last
            .get(validator)
            .is_some_and(|previous| now.duration_since(*previous) < Duration::from_secs(10))
        {
            return;
        }
        last.insert(validator.to_owned(), now);
        eprintln!(
            "R3 recovery gate: validator={validator} target={target} active={height}/{round} active_tc={:?} prior_timeout={:?} finalized={:?} blocker={reason}",
            self.driver.state_machine().active_takeover_tc_id(),
            self.ingress.cut_recovery_state(target).ok().flatten().and_then(|state| state.last_timeout_id),
            self.last_finalized.as_ref().map(|record| record.height),
        );
    }

    fn authorize_cut_recovery(&mut self) -> Result<(), String> {
        let machine = self.driver.state_machine();
        let (height, _round) = machine.active_slot();
        let Some(target) = height.checked_add(1) else {
            return Ok(());
        };
        let Some(state) = self.ingress.cut_recovery_state(target)? else {
            return Ok(());
        };
        let active_tc = machine.active_takeover_tc_id();
        let mut blockers = Vec::new();
        if state.committed {
            blockers.push("already-committed");
        }
        if self.candidates.contains_key(&height) {
            blockers.push("candidate");
        }
        if self.deferred_qcs.contains_key(&height) {
            blockers.push("deferred-qc");
        }
        if self.pending_proposals.keys().any(|(h, _)| *h == height) {
            blockers.push("pending-proposal");
        }
        if self
            .delivery_proposal
            .as_ref()
            .is_some_and(|p| p.context.height == height)
        {
            blockers.push("delivery-proposal");
        }
        if self
            .last_voted_candidate
            .as_ref()
            .is_some_and(|p| p.context.height == height)
        {
            blockers.push("last-vote");
        }
        if active_tc == state.last_timeout_id.as_deref() {
            blockers.push("unchanged-timeout");
        }
        if active_tc.is_none() {
            blockers.push("no-active-timeout");
        }
        if !blockers.is_empty() {
            #[cfg(test)]
            self.r3_recovery_diagnostic(target, height, _round, &blockers.join(","));
            return Ok(());
        }
        // RAM caches cannot prove absence of a durable certificate.
        if self
            .delivery
            .stored_validation(
                height,
                &self.authority.epoch,
                &self.authority.registry,
                self.authority.as_ref(),
            )
            .map_err(|e| format!("R3 check durable VC: {e}"))?
            .is_some()
        {
            #[cfg(test)]
            self.r3_recovery_diagnostic(target, height, _round, "durable-vc");
            return Ok(());
        }
        if self
            .delivery
            .stored_ready_envelope(
                height,
                &self.authority.epoch,
                &self.authority.registry,
                self.authority.as_ref(),
            )
            .map_err(|e| format!("R3 check retained READY: {e}"))?
            .is_some()
        {
            #[cfg(test)]
            self.r3_recovery_diagnostic(target, height, _round, "retained-ready");
            return Ok(());
        }
        if self
            .certificates
            .get_verified(
                height,
                &self.authority.epoch,
                &self.authority.registry,
                self.authority.as_ref(),
            )
            .map_err(|e| format!("R3 check durable QC: {e}"))?
            .is_some()
        {
            #[cfg(test)]
            self.r3_recovery_diagnostic(target, height, _round, "durable-qc");
            return Ok(());
        }
        if self.ingress.protected_commitments(target)?.is_some() {
            #[cfg(test)]
            self.r3_recovery_diagnostic(target, height, _round, "target-commitment");
            return Ok(());
        }
        if self.ingress.proposal_validation(height)?.is_some() {
            #[cfg(test)]
            self.r3_recovery_diagnostic(target, height, _round, "proposal-validation");
            return Ok(());
        }
        if self
            .last_finalized
            .as_ref()
            .is_some_and(|f| f.height >= height)
        {
            #[cfg(test)]
            self.r3_recovery_diagnostic(target, height, _round, "finalized-active-height");
            return Ok(());
        }
        let path = match machine.verified_cut_recovery_timeout_path(
            target,
            state.last_timeout_id.as_deref(),
            self.authority.as_ref(),
        ) {
            Ok(path) => path,
            Err(_error) => {
                #[cfg(test)]
                self.r3_recovery_diagnostic(
                    target,
                    height,
                    _round,
                    &format!("timeout-path:{_error}"),
                );
                return Ok(()); // A missing/blocked proof grants no authority.
            }
        };
        if path
            .iter()
            .filter(|tc| tc.context().height == height)
            .any(|tc| tc.mandatory_carry_candidate().is_some())
        {
            #[cfg(test)]
            self.r3_recovery_diagnostic(target, height, _round, "mandatory-carry");
            return Ok(());
        }
        let Some(original_height) = target.checked_sub(2) else {
            return Ok(());
        };
        let Some(original) = self
            .delivery
            .stored_validation(
                original_height,
                &self.authority.epoch,
                &self.authority.registry,
                self.authority.as_ref(),
            )
            .map_err(|e| format!("R3 original cutoff VC: {e}"))?
        else {
            #[cfg(test)]
            self.r3_recovery_diagnostic(target, height, _round, "missing-original-cutoff-vc");
            return Ok(());
        };
        let generation = super::cut_recovery::generation(target, &original, state.cutoff, &path)?;
        self.ingress
            .try_submit_cut_recovery_generation(target, generation)
            // Queue pressure does not reject the verified timeout or alter the
            // PoSy slot. The next owner poll derives it again from durable proof.
            .map(|_| ())
    }

    fn emit_timeout_vote(&mut self) -> Result<(), String> {
        // A terminal epoch retains its certified last slot as a boundary,
        // not as another live voting slot. Its highest parent is already the
        // terminal QC; signing a timeout here would be invalid and would burn
        // a durable slot before the ordinary future-parent check rejects it.
        if self.driver.state_machine().epoch_complete()
            || self.mode != ConsensusMode::ValidateAndVote
            || Instant::now() < self.round_deadline
        {
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
        let transitions = match self.driver.handle(event, self.authority.as_ref()) {
            Ok(transitions) => transitions,
            Err(PosyError::ResourcePressure(_)) => {
                self.round_deadline = Instant::now() + self.round_timeout;
                return Ok(());
            }
            Err(error) => return Err(format!("PoSy rejected local timeout vote: {error}")),
        };
        self.handle_transitions(transitions)?;
        self.round_deadline = Instant::now() + self.round_timeout;
        Ok(())
    }

    fn collect_candidates(&mut self) -> Result<(), String> {
        if self.authority.processing_profile_enabled() {
            for _ in 0..MAX_MESSAGES_PER_POLL {
                let Some(handoff) = self.ingress.take_processing_candidate()? else {
                    break;
                };
                retain_processing_execution_candidate(
                    &mut self.candidates,
                    &mut self.processing_candidate_rounds,
                    handoff,
                    self.driver.state_machine(),
                )?;
            }
        } else {
            for _ in 0..MAX_MESSAGES_PER_POLL {
                let Some(candidate) = self.ingress.take_execution_candidate()? else {
                    break;
                };
                retain_execution_candidate(
                    &mut self.candidates,
                    candidate,
                    self.last_finalized.as_ref().map(|record| record.height),
                )?;
            }
        }
        if self.mode == ConsensusMode::ValidateAndVote {
            let slot = self.driver.state_machine().active_slot();
            let candidate_round = self.processing_candidate_rounds.get(&slot.0).copied();
            let candidate_height = self
                .candidates
                .get(&slot.0)
                .map(|candidate| candidate.height);
            let stage =
                if self.authority.processing_profile_enabled() && candidate_round != Some(slot.1) {
                    "awaiting_current_round_handoff"
                } else if candidate_height.is_none() {
                    "awaiting_execution_candidate"
                } else {
                    "candidate_available"
                };
            self.ingress.observe_candidate_stage(
                slot.0,
                slot.1,
                candidate_height,
                candidate_round,
                stage,
            )?;
            if self.authority.processing_profile_enabled()
                && self.processing_candidate_rounds.get(&slot.0) != Some(&slot.1)
            {
                return Ok(());
            }
            if let Some(candidate) = self.candidates.get(&slot.0).cloned() {
                if let Some(proposal) = self.pending_proposals.remove(&slot) {
                    self.apply_event_from(ConsensusEvent::Proposal(proposal), true)?;
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

    fn drain_deferred_qcs(&mut self) -> Result<(), String> {
        for _ in 0..64 {
            let active = self.driver.state_machine().active_slot();
            let Some(certificate) = self.deferred_qcs.get(&active.0) else {
                break;
            };
            if certificate.context.round > active.1 {
                break;
            }
            let certificate = self
                .deferred_qcs
                .remove(&active.0)
                .ok_or("deferred QC disappeared")?;
            self.apply_event(ConsensusEvent::QuorumCertificate(certificate))?;
        }
        let historical = self
            .deferred_qcs
            .range(..self.driver.state_machine().active_slot().0)
            .map(|(h, _)| *h)
            .collect::<Vec<_>>();
        for height in historical {
            let certificate = self
                .deferred_qcs
                .remove(&height)
                .ok_or("deferred historical QC disappeared")?;
            self.apply_event(ConsensusEvent::QuorumCertificate(certificate))?;
        }
        Ok(())
    }

    fn drain_deferred_sync(&mut self) -> Result<(), String> {
        if !self.flush_verified_sync_delivery()? {
            return Ok(());
        }
        let active = self.driver.state_machine().active_slot().0;
        let ready = self
            .deferred_sync
            .keys()
            .filter(|h| **h <= active)
            .copied()
            .collect::<Vec<_>>();
        for height in ready {
            let response = self
                .deferred_sync
                .remove(&height)
                .ok_or("deferred Sync witness disappeared")?;
            self.admit_sync_candidate(response)?;
            if self.pending_verified_sync.is_some() {
                break;
            }
        }
        Ok(())
    }

    fn admit_sync_candidates(&mut self) -> Result<(), String> {
        if !self.flush_verified_sync_delivery()? {
            return Ok(());
        }
        for _ in 0..MAX_MESSAGES_PER_POLL {
            let Some((_peer, response)) = self.ingress.take_sync_candidate_response()? else {
                break;
            };
            self.admit_sync_candidate(response)?;
            if self.pending_verified_sync.is_some() {
                break;
            }
        }
        Ok(())
    }

    fn flush_verified_sync_delivery(&mut self) -> Result<bool, String> {
        let Some((candidate, record)) = self.pending_verified_sync.take() else {
            return Ok(true);
        };
        if self
            .ingress
            .try_submit_verified_sync_candidate(Arc::clone(&candidate), record.clone())?
        {
            Ok(true)
        } else {
            self.pending_verified_sync = Some((candidate, record));
            Ok(false)
        }
    }

    fn deliver_verified_sync_candidate(
        &mut self,
        candidate: Arc<ExecutionCandidate>,
        record: FinalizedBlockRecord,
    ) -> Result<(), String> {
        if self.pending_verified_sync.is_some() {
            return Err("verified Sync delivery consumed beyond retained bound".into());
        }
        self.pending_verified_sync = Some((candidate, record));
        self.flush_verified_sync_delivery().map(|_| ())
    }

    fn admit_sync_candidate(
        &mut self,
        response: super::ingress::FinalizedCandidateResponse,
    ) -> Result<(), String> {
        let witness: FinalitySyncWitness = serde_json::from_slice(&response.finality_witness)
            .map_err(|error| format!("decode Sync safety witness: {error}"))?;
        let mut finality = ThreeQcFinality::default();
        let mut timeouts = witness
            .verified_timeout_closure(
                &self.authority.epoch,
                &self.authority.registry,
                self.authority.as_ref(),
            )
            .map_err(|error| format!("verify Sync lease timeout witness: {error}"))?;
        for certificate in &witness.quorum_certificates {
            certificate
                .verify(
                    &self.authority.epoch,
                    &self.authority.registry,
                    self.authority.as_ref(),
                )
                .map_err(|error| format!("verify Sync QC authority: {error}"))?;
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
        if self.authority.processing_profile_enabled() {
            let bytes = response
                .processing_replay
                .as_ref()
                .ok_or("processing Sync lacks native replay inputs and ECHO proof")?;
            let store = self
                .ingress
                .processing_proposal_store()?
                .ok_or("processing Sync journal unavailable")?;
            store
                .lock()
                .map_err(|_| "processing proposal journal lock poisoned")?
                .import_sync(bytes, &response.candidate, &witness.quorum_certificates[0])?;
        } else if response.processing_replay.is_some() {
            return Err("legacy Sync cannot activate processing replay".into());
        }
        // A snapshot or reordered response may be ahead of the canonical safety
        // prefix. Keep its authenticated witness bounded until predecessors are
        // admitted; never skip history merely because execution moved ahead.
        if witness.quorum_certificates[0].context.height
            > self.driver.state_machine().active_slot().0
        {
            for certificate in &witness.quorum_certificates {
                self.apply_event(ConsensusEvent::QuorumCertificate(certificate.clone()))?;
            }
            let height = response.candidate.height;
            if let Some(previous) = self.deferred_sync.get(&height) {
                if previous.candidate != response.candidate {
                    return Err("conflicting authenticated future Sync execution candidate".into());
                }
            } else if self.deferred_sync.len() < MAX_DEFERRED_SYNC {
                self.deferred_sync.insert(height, response);
            }
            return Ok(());
        }
        if self.reconcile_sync_projection(&witness, &record)? {
            self.deliver_verified_sync_candidate(Arc::new(response.response.candidate), record)?;
            return Ok(());
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
        self.deliver_verified_sync_candidate(Arc::new(response.response.candidate), record)?;
        Ok(())
    }

    /// Stage certified recovery first, commit existing atomic transitions, then
    /// install only after exact durable finality has been read back. No signer
    /// journal, lock authorization or immutable timeout evidence is discarded.
    fn reconcile_sync_projection(
        &mut self,
        witness: &FinalitySyncWitness,
        record: &synergy_posy::FinalizedBlockRecord,
    ) -> Result<bool, String> {
        if witness.quorum_certificates[2].context.height
            < self.driver.state_machine().active_slot().0
        {
            let committed = self
                .finality
                .as_ref()
                .ok_or("PoSy finality unavailable")?
                .get(record.height)
                .map_err(|e| e.to_string())?;
            if let Some(committed) = committed {
                if &committed != record {
                    return Err("historical R1 Sync finality conflicts".into());
                }
                for qc in &witness.quorum_certificates {
                    let stored = self
                        .certificates
                        .get_verified(
                            qc.context.height,
                            &self.authority.epoch,
                            &self.authority.registry,
                            self.authority.as_ref(),
                        )
                        .map_err(|e| e.to_string())?
                        .ok_or("historical R1 Sync QC missing")?;
                    if stored.id().map_err(|e| e.to_string())?
                        != qc.id().map_err(|e| e.to_string())?
                    {
                        return Err("historical R1 Sync QC conflicts".into());
                    }
                }
                return Ok(false);
            }
        }
        let canonical = witness
            .verified_timeout_closure(
                &self.authority.epoch,
                &self.authority.registry,
                self.authority.as_ref(),
            )
            .map_err(|e| e.to_string())?;
        let diverged = verify_sync_local_omissions(
            &self.authority,
            &self.timeout_certificates,
            witness,
            record,
        )?;
        let active = self.driver.state_machine().active_slot();
        let projected_reference_differs = sync_projection_reference_differs(
            &self.authority.epoch,
            active,
            self.driver.state_machine().active_takeover_tc_id(),
            witness,
            &canonical,
        )?;
        if !diverged && !projected_reference_differs {
            return Ok(false);
        }
        if witness.quorum_certificates[2]
            .context
            .height
            .checked_add(1)
            .is_none_or(|next| next < self.driver.state_machine().active_slot().0)
        {
            return Err("R1 Sync witness cannot regress the current certified prefix".into());
        }
        let (mut staged, transitions) = stage_sync_projection_from_floor(
            &self.authority,
            &self.certificates,
            &self.timeout_certificates,
            self.finality.as_ref().ok_or("PoSy finality unavailable")?,
            witness,
            self.last_finalized.as_ref().map(|record| record.height),
        )?;
        // Retain every required canonical TC as immutable recovery evidence.
        for tc in canonical.values() {
            self.timeout_certificates
                .put_verified(
                    tc,
                    &self.authority.epoch,
                    &self.authority.registry,
                    self.authority.as_ref(),
                )
                .map_err(|e| e.to_string())?;
        }
        let mut previous = self.last_finalized.clone();
        for (qc, finalized) in &transitions {
            if let Some(finalized) = finalized {
                self.atomic_transitions
                    .commit_verified_qc_and_finality(
                        qc,
                        finalized,
                        previous.as_ref(),
                        &self.authority.epoch,
                        &self.authority.registry,
                        self.authority.as_ref(),
                    )
                    .map_err(|e| e.to_string())?;
                previous = Some(finalized.clone());
            } else {
                self.certificates
                    .put_verified(
                        qc,
                        &self.authority.epoch,
                        &self.authority.registry,
                        self.authority.as_ref(),
                    )
                    .map_err(|e| e.to_string())?;
            }
        }
        let durable = self
            .finality
            .as_ref()
            .ok_or("PoSy finality unavailable")?
            .get(record.height)
            .map_err(|e| e.to_string())?
            .ok_or("R1 Sync finality commit missing")?;
        if &durable != record {
            return Err("R1 Sync finality commit conflicts".into());
        }
        for (_, finalized) in &transitions {
            if let Some(finalized) = finalized {
                let committed = self
                    .finality
                    .as_ref()
                    .ok_or("PoSy finality unavailable")?
                    .get(finalized.height)
                    .map_err(|e| e.to_string())?
                    .ok_or("R1 Sync intermediate finalized commit missing")?;
                if &committed != finalized {
                    return Err("R1 Sync intermediate finality conflicts".into());
                }
            }
        }
        if let Some(local) = self.local_signer.as_mut() {
            local
                .record_verified_finalized_floor(record.height)
                .map_err(|e| e.to_string())?;
        }
        reconcile_retained_lease_timeouts(
            &mut staged,
            self.authority.as_ref(),
            &self.certificates,
            &self.timeout_certificates,
            self.finality.as_ref().ok_or("PoSy finality unavailable")?,
        )?;
        for certificate in staged.accepted_timeout_certificates() {
            self.retry_frames.insert(
                (certificate.context().height, certificate.context().round, 4),
                RetryFrame::Timeout {
                    summary: Box::new(certificate.clone()),
                    fingerprint: None,
                },
            );
        }
        self.driver = SimplifiedPosyDriver::new(staged);
        self.last_finalized = previous;
        if let Some(record) = &self.last_finalized {
            retire_finalized_candidates(&mut self.candidates, record.height);
            self.processing_candidate_rounds
                .retain(|height, _| *height > record.height);
        }
        let active = self.driver.state_machine().active_slot();
        self.delivery.activate(active).map_err(|e| e.to_string())?;
        self.pending_proposals.retain(|slot, _| *slot == active);
        self.delivery_proposal = None;
        self.emitted_slots
            .retain(|slot| (slot.height, slot.round) == active);
        if self
            .last_voted_candidate
            .as_ref()
            .is_some_and(|v| v.context.height != active.0)
        {
            self.last_voted_candidate = None;
        }
        self.round_deadline = Instant::now() + self.round_timeout;
        self.prune_retry_frames()?;
        for (_, finalized) in transitions {
            if let Some(finalized) = finalized {
                let chain = self
                    .driver
                    .state_machine()
                    .finality_witness(finalized.height)
                    .ok_or("R1 Sync installed without finality witness")?;
                self.ingress.submit_finality(
                    finalized,
                    serde_json::to_vec(&chain).map_err(|e| e.to_string())?,
                )?;
            }
        }
        Ok(true)
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
            self.ingress.submit_verified_head(
                VerifiedHead {
                    peer_id: peer.node_address.to_string(),
                    finalized_height: verified.height,
                    finalized_hash: verified.block_id,
                    finality_evidence_id: verified.finality_certificate_id,
                },
                peer.session_id,
            )?;
        }
        Ok(())
    }
}

/// Call only after independently verifying the witness and its exact timeout
/// closure. Older predecessors of the current terminal TC are ordinary proof
/// ancestry, not a different active lease projection.
pub(super) fn sync_projection_reference_differs(
    epoch: &synergy_posy::SimplifiedEpochContext,
    active: (u64, u64),
    active_takeover: Option<&str>,
    witness: &FinalitySyncWitness,
    canonical: &BTreeMap<(u64, u64), synergy_posy::SimplifiedTimeoutCertificate>,
) -> Result<bool, String> {
    if witness.quorum_certificates.iter().any(|qc| {
        qc.context.height == active.0
            && active.1 >= qc.context.round
            && qc.takeover_tc_id.as_deref() != active_takeover
    }) {
        return Ok(true);
    }
    let active_lease = epoch.lease_index(active.0).map_err(|e| e.to_string())?;
    for tc in canonical.values() {
        if tc.context.height >= active.0
            || epoch
                .lease_index(tc.context.height)
                .map_err(|e| e.to_string())?
                != active_lease
        {
            continue;
        }
        // A not-yet-applied TC originating at an older height must still be
        // restored at its original slot through the staged recovery boundary.
        if tc.context.round >= active.1 {
            return Ok(true);
        }
        if tc.context.round.checked_add(1) == Some(active.1)
            && tc.id().map_err(|e| e.to_string())?.as_str() != active_takeover.unwrap_or("")
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn verify_sync_local_omissions(
    authority: &VerifiedAuthority,
    timeouts: &VerifiedTimeoutCertificateStore,
    witness: &FinalitySyncWitness,
    record: &synergy_posy::FinalizedBlockRecord,
) -> Result<bool, String> {
    let canonical = witness
        .verified_timeout_closure(&authority.epoch, &authority.registry, authority)
        .map_err(|e| e.to_string())?;
    let mut diverged = false;
    for qc in &witness.quorum_certificates {
        let mut round = qc.context.round;
        let mut previous = qc.takeover_tc_id.clone();
        while let Some(tc) = timeouts
            .get_verified(
                qc.context.height,
                round,
                &authority.epoch,
                &authority.registry,
                authority,
            )
            .map_err(|e| e.to_string())?
        {
            if tc.previous_tc_id != previous {
                return Err("R1 Sync local timeout predecessor mismatch".into());
            }
            if !canonical.values().any(|v| v.id().ok() == tc.id().ok()) {
                let proven = witness
                    .verify_superseded_timeout(
                        &tc,
                        &authority.epoch,
                        &authority.registry,
                        authority,
                    )
                    .map_err(|e| format!("R1 Sync supersession refused: {e}"))?;
                if &proven != record {
                    return Err("R1 Sync supersession finality mismatch".into());
                }
                diverged = true;
            }
            previous = Some(tc.id().map_err(|e| e.to_string())?);
            round = round.checked_add(1).ok_or("R1 Sync round overflow")?;
        }
    }
    Ok(diverged)
}

type RecoveredQcTransition = (
    SimplifiedQuorumCertificate,
    Option<synergy_posy::FinalizedBlockRecord>,
);

#[cfg(test)]
thread_local! {
    static SYNC_PROJECTION_STAGES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(super) fn sync_projection_stages() -> usize {
    SYNC_PROJECTION_STAGES.with(std::cell::Cell::get)
}

/// Pure staging boundary shared by live Sync recovery and its causal tests.
#[cfg(test)]
pub(super) fn stage_sync_projection(
    authority: &VerifiedAuthority,
    certificates: &VerifiedQuorumCertificateStore,
    timeouts: &VerifiedTimeoutCertificateStore,
    durable: &FinalityStore,
    witness: &FinalitySyncWitness,
) -> Result<(SimplifiedConsensusStateMachine, Vec<RecoveredQcTransition>), String> {
    stage_sync_projection_from_floor(authority, certificates, timeouts, durable, witness, None)
}

pub(super) fn stage_sync_projection_from_floor(
    authority: &VerifiedAuthority,
    certificates: &VerifiedQuorumCertificateStore,
    timeouts: &VerifiedTimeoutCertificateStore,
    durable: &FinalityStore,
    witness: &FinalitySyncWitness,
    finalized_floor: Option<u64>,
) -> Result<(SimplifiedConsensusStateMachine, Vec<RecoveredQcTransition>), String> {
    stage_checkpoint_projection_from_floor(
        authority,
        certificates,
        timeouts,
        durable,
        std::slice::from_ref(witness),
        finalized_floor,
    )
}

/// Offline checkpoint recovery uses the same staged PoSy projection as live
/// Sync, with an overlapping three-QC witness for every intervening height.
/// This function does not persist certificates, modify journals, or sign.
pub(super) fn stage_checkpoint_projection_from_floor(
    authority: &VerifiedAuthority,
    certificates: &VerifiedQuorumCertificateStore,
    timeouts: &VerifiedTimeoutCertificateStore,
    durable: &FinalityStore,
    witnesses: &[FinalitySyncWitness],
    finalized_floor: Option<u64>,
) -> Result<(SimplifiedConsensusStateMachine, Vec<RecoveredQcTransition>), String> {
    let staged =
        begin_checkpoint_projection(authority, certificates, timeouts, durable, finalized_floor)?;
    let (staged, fresh) = stage_checkpoint_page(
        authority,
        certificates,
        timeouts,
        durable,
        witnesses,
        staged,
        witnesses
            .last()
            .ok_or("checkpoint lacks certified prefix")?
            .quorum_certificates[2]
            .context
            .height,
    )?;
    let staged = finish_checkpoint_projection(authority, timeouts, staged)?;
    Ok((staged, fresh))
}

/// Start a pure recovery projection at the independently committed local floor.
/// The caller can replay a long prefix in bounded complete-lease pages. No
/// journal, certificate or finality record is changed by this projection.
pub(super) fn begin_checkpoint_projection(
    authority: &VerifiedAuthority,
    certificates: &VerifiedQuorumCertificateStore,
    timeouts: &VerifiedTimeoutCertificateStore,
    durable: &FinalityStore,
    finalized_floor: Option<u64>,
) -> Result<SimplifiedConsensusStateMachine, String> {
    let mut staged = SimplifiedConsensusStateMachine::new(
        authority.epoch.clone(),
        authority.registry.clone(),
        authority.anchor_parent.clone(),
    )
    .map_err(|e| e.to_string())?;
    seed_committed_recovery_anchor(
        &mut staged,
        authority,
        certificates,
        timeouts,
        durable,
        finalized_floor,
    )?;
    Ok(staged)
}

/// Advance the ordinary PoSy state machine through one bounded proof page.
/// Intermediate pages must end their QC prefix at a leader-lease boundary;
/// all same-lease carried timeout paths must be visible before admitting its
/// QCs. The final page may end at the actual certified checkpoint. Ownership
/// moves through this function so no second live control plane is cloned.
pub(super) fn stage_checkpoint_page(
    authority: &VerifiedAuthority,
    certificates: &VerifiedQuorumCertificateStore,
    timeouts: &VerifiedTimeoutCertificateStore,
    durable: &FinalityStore,
    witnesses: &[FinalitySyncWitness],
    staged: SimplifiedConsensusStateMachine,
    apply_through: u64,
) -> Result<(SimplifiedConsensusStateMachine, Vec<RecoveredQcTransition>), String> {
    stage_offline_checkpoint_page(
        authority,
        certificates,
        timeouts,
        durable,
        witnesses,
        staged,
        CheckpointPageApplication {
            through: apply_through,
            initial_anchor: None,
        },
    )
}

pub(super) struct CheckpointPageApplication<'a> {
    pub through: u64,
    // Only the first nonterminal page of a stopped checkpoint can supply this.
    pub initial_anchor: Option<&'a FinalizedBlockRecord>,
}

pub(super) fn stage_offline_checkpoint_page(
    authority: &VerifiedAuthority,
    certificates: &VerifiedQuorumCertificateStore,
    timeouts: &VerifiedTimeoutCertificateStore,
    durable: &FinalityStore,
    witnesses: &[FinalitySyncWitness],
    mut staged: SimplifiedConsensusStateMachine,
    application: CheckpointPageApplication<'_>,
) -> Result<(SimplifiedConsensusStateMachine, Vec<RecoveredQcTransition>), String> {
    let witness = witnesses
        .last()
        .ok_or("checkpoint lacks certified prefix")?;
    #[cfg(test)]
    SYNC_PROJECTION_STAGES.with(|stages| stages.set(stages.get() + 1));
    if authority.epoch.epoch != 1 {
        return Err("R1 Sync successor epoch staging unsupported".into());
    }
    let mut incoming = BTreeMap::new();
    let mut closure = BTreeMap::new();
    let mut previous_height: Option<u64> = None;
    let mut first_finalized = None;
    for part in witnesses {
        let height = part.quorum_certificates[0].context.height;
        if previous_height.is_some_and(|previous| previous.checked_add(1) != Some(height)) {
            return Err("checkpoint certified prefix is not contiguous".into());
        }
        previous_height = Some(height);
        let mut proof = ThreeQcFinality::default();
        for qc in &part.quorum_certificates {
            qc.verify(&authority.epoch, &authority.registry, authority)
                .map_err(|e| e.to_string())?;
            proof.accept(qc.clone()).map_err(|e| e.to_string())?;
            if let Some(old) = incoming.insert(qc.context.height, qc.clone()) {
                if old != *qc {
                    return Err("checkpoint overlapping QCs conflict".into());
                }
            }
        }
        let record = proof
            .last_finalized()
            .ok_or("checkpoint lacks three-QC finality")?;
        if first_finalized.is_none() {
            first_finalized = Some(record.clone());
        }
        verify_sync_local_omissions(authority, timeouts, part, record)?;
        for (slot, tc) in part
            .verified_timeout_closure(&authority.epoch, &authority.registry, authority)
            .map_err(|e| e.to_string())?
        {
            if let Some(old) = closure.insert(slot, tc.clone()) {
                if old != tc {
                    return Err("checkpoint timeout closures conflict".into());
                }
            }
        }
    }
    let apply_through = application.through;
    let certified_end = witness.quorum_certificates[2].context.height;
    if apply_through > certified_end
        || apply_through < witnesses[0].quorum_certificates[0].context.height
    {
        return Err("checkpoint application bound is outside its certified page".into());
    }
    let end = apply_through;
    // A previous pure page is not yet durable during the verification pass.
    // Its overlapping QCs therefore must also be compared with the staged
    // machine, rather than relying only on the local immutable store below.
    if let Some(record) = staged.last_finalized() {
        if let Some(previous) = staged.finality_witness(record.height) {
            for qc in previous {
                if let Some(next) = incoming.get(&qc.context.height) {
                    if next != &qc {
                        return Err("checkpoint page conflicts with staged QC overlap".into());
                    }
                }
            }
        }
    }
    // A bounded seed omits old heights from the replay loop, not from conflict
    // checks. Compare every incoming proof against its immutable height record.
    for qc in incoming.values() {
        if let Some(stored) = certificates
            .get_verified(
                qc.context.height,
                &authority.epoch,
                &authority.registry,
                authority,
            )
            .map_err(|e| e.to_string())?
        {
            if stored.id().map_err(|e| e.to_string())? != qc.id().map_err(|e| e.to_string())? {
                return Err(format!(
                    "R1 Sync conflicts with durable QC at H{}",
                    qc.context.height
                ));
            }
        }
    }
    let covered = end < staged.active_slot().0;
    if covered && application.initial_anchor.is_none() {
        return Err("R1 Sync witness ends below the committed recovery anchor".into());
    }
    let mut all = BTreeMap::new();
    let mut canonical = BTreeMap::<(u64, u64), synergy_posy::SimplifiedTimeoutCertificate>::new();
    for height in staged.active_slot().0..=end {
        let stored = certificates
            .get_verified(height, &authority.epoch, &authority.registry, authority)
            .map_err(|e| e.to_string())?;
        let qc = match (stored.as_ref(), incoming.get(&height)) {
            (Some(old), Some(new))
                if old.id().map_err(|e| e.to_string())?
                    != new.id().map_err(|e| e.to_string())? =>
            {
                return Err("R1 Sync conflicts with durable QC".into())
            }
            (_, Some(new)) => new.clone(),
            (Some(old), None) => old.clone(),
            (None, None) => return Err("R1 Sync immutable certified prefix has a gap".into()),
        };
        all.insert(height, (qc, stored.is_some()));
    }
    // Resolve the union of ALL certified timeout paths before replaying any
    // height. A later QC may reference a carried timeout at an earlier height.
    let mut proof_qcs = all
        .iter()
        .map(|(height, (qc, _))| (*height, qc.clone()))
        .collect::<BTreeMap<_, _>>();
    for (height, qc) in &incoming {
        proof_qcs.entry(*height).or_insert_with(|| qc.clone());
    }
    for (height, qc) in &proof_qcs {
        let first = authority.epoch.epoch_start_height
            + authority
                .epoch
                .lease_index(*height)
                .map_err(|e| e.to_string())?
                * authority.epoch.leader_lease_blocks;
        let mut expected = qc.takeover_tc_id.clone();
        let mut last = *height;
        for round in (0..qc.context.round).rev() {
            let mut found = None;
            for slot in (first..=last).rev() {
                let tc = if let Some(tc) = closure.get(&(slot, round)) {
                    Some(tc.clone())
                } else {
                    timeouts
                        .get_verified(
                            slot,
                            round,
                            &authority.epoch,
                            &authority.registry,
                            authority,
                        )
                        .map_err(|e| e.to_string())?
                };
                if let Some(tc) = tc {
                    if Some(tc.id().map_err(|e| e.to_string())?) == expected {
                        found = Some(tc);
                        break;
                    }
                }
            }
            let tc = found.ok_or("R1 Sync canonical predecessor missing")?;
            last = tc.context.height;
            expected = tc.previous_tc_id.clone();
            if let Some(previous) = canonical.insert((tc.context.height, round), tc.clone()) {
                if previous.id().map_err(|e| e.to_string())?
                    != tc.id().map_err(|e| e.to_string())?
                {
                    return Err("R1 Sync certified timeout paths conflict".into());
                }
            }
        }
        if expected.is_some() {
            return Err("R1 Sync canonical predecessor closure incomplete".into());
        }
    }
    if covered {
        let anchor = application
            .initial_anchor
            .expect("covered page must have initial anchor");
        let seed = staged
            .last_finalized()
            .ok_or("covered checkpoint page lacks a verified lease seed")?;
        // A seed at a lease boundary already applied this first page's tail.
        // Accept it only as evidence: never advance, persist, or replace facts.
        // The durable execution anchor can be any of the three heights covered
        // by the seed's witness, including the final height of the old lease.
        if end.checked_add(1) != Some(staged.active_slot().0)
            || seed.height.checked_add(2) != Some(end)
            || !(seed.height..=end).contains(&anchor.height)
            || first_finalized.as_ref() != Some(anchor)
            || durable
                .get(anchor.height)
                .map_err(|e| e.to_string())?
                .as_ref()
                != Some(anchor)
        {
            return Err(
                "checkpoint covered page does not match the committed recovery anchor".into(),
            );
        }
        for height in anchor.height..=end {
            let exact = certificates
                .get_verified(height, &authority.epoch, &authority.registry, authority)
                .map_err(|e| e.to_string())?;
            if exact.is_none() || exact.as_ref() != incoming.get(&height) {
                return Err(format!(
                    "checkpoint covered page differs from durable QC at H{height}"
                ));
            }
        }
        return Ok((staged, Vec::new()));
    }
    let mut fresh = Vec::new();
    for (height, (qc, stored)) in all {
        if !incoming.contains_key(&height) {
            verify_unused_recovery_timeouts(&qc, authority, certificates, timeouts, durable)?;
        }
        let limit = canonical
            .range((height, 0)..=(height, u64::MAX))
            .map(|((_, round), _)| round.checked_add(1).ok_or("R1 Sync timeout round overflow"))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .max()
            .unwrap_or(qc.context.round)
            .max(qc.context.round);
        while staged.active_slot().1 < limit {
            let slot = staged.active_slot();
            let tc = canonical
                .get(&slot)
                .ok_or("R1 Sync required original-slot timeout missing")?;
            staged
                .accept_timeout_certificate(tc.clone(), authority)
                .map_err(|e| format!("R1 Sync staged timeout: {e}"))?;
        }
        let events = staged
            .accept_quorum_certificate(qc.clone(), authority)
            .map_err(|e| format!("R1 Sync staged QC: {e}"))?;
        let finalized = events.into_iter().find_map(|event| {
            if let ConsensusTransition::Finalized(record) = event {
                Some(record)
            } else {
                None
            }
        });
        if let Some(record) = &finalized {
            let existing = durable.get(record.height).map_err(|e| e.to_string())?;
            if let Some(existing) = existing {
                if &existing != record {
                    return Err("R1 Sync staged proof conflicts with durable finality".into());
                }
            } else if stored {
                return Err("R1 Sync durable QC prefix lacks finalized commit".into());
            }
        }
        if !stored {
            fresh.push((qc, finalized));
        }
    }
    Ok((staged, fresh))
}

/// Apply retained uncertified-tip timeouts only after the complete prefix.
/// Doing this between pages could let a superseded local tip block a later
/// authenticated page before its covering finality proof has been considered.
pub(super) fn finish_checkpoint_projection(
    authority: &VerifiedAuthority,
    timeouts: &VerifiedTimeoutCertificateStore,
    mut staged: SimplifiedConsensusStateMachine,
) -> Result<SimplifiedConsensusStateMachine, String> {
    // Outstanding uncertified-tip timeouts remain active. Preserve their exact
    // predecessor authority rather than treating incoming finality as a reset.
    loop {
        let (height, round) = staged.active_slot();
        let Some(tc) = timeouts
            .get_verified(
                height,
                round,
                &authority.epoch,
                &authority.registry,
                authority,
            )
            .map_err(|e| e.to_string())?
        else {
            break;
        };
        staged
            .accept_timeout_certificate(tc, authority)
            .map_err(|e| format!("R1 Sync uncertified timeout tail: {e}"))?;
    }
    Ok(staged)
}

fn republish_verified_validation_history(
    delivery: &ProposalDelivery,
    active_height: u64,
    authority: &VerifiedAuthority,
    ingress: &AuthenticatedIngress,
) -> Result<(), String> {
    for certificate in delivery
        .stored_validation_window(
            active_height,
            &authority.epoch,
            &authority.registry,
            authority,
        )
        .map_err(|e| e.to_string())?
    {
        ingress.submit_proposal_validation(certificate)?;
    }
    Ok(())
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

fn verify_prepared_consensus(
    authority: &VerifiedAuthority,
    peer: &AuthenticatedPeer,
    event: &ConsensusEvent,
) -> Result<(), String> {
    let validation = match event {
        ConsensusEvent::Proposal(value) => {
            validate_proposal(value, &authority.epoch, &authority.registry, authority)
        }
        ConsensusEvent::ProposalDelivery(value) => {
            value
                .statement
                .verify(&authority.epoch, &authority.registry, authority)
        }
        ConsensusEvent::BlockVote(value) => {
            validate_block_vote(value, &authority.epoch, &authority.registry, authority)
        }
        ConsensusEvent::TimeoutVote(value) => {
            validate_timeout_vote(value, &authority.epoch, &authority.registry, authority)
        }
        ConsensusEvent::QuorumCertificate(value) => {
            value.verify(&authority.epoch, &authority.registry, authority)
        }
        ConsensusEvent::TimeoutCertificate(value) => {
            value.verify(&authority.epoch, &authority.registry, authority)
        }
    };
    if let Err(error) = validation {
        let _ = error;
        return Err("invalid authenticated consensus evidence".into());
    }
    let direct_sender = match event {
        ConsensusEvent::Proposal(proposal) => Some(proposal.proposer_id.as_str()),
        ConsensusEvent::BlockVote(vote) => Some(vote.validator_id.as_str()),
        ConsensusEvent::ProposalDelivery(statement) => {
            Some(statement.statement.validator_id.as_str())
        }
        ConsensusEvent::TimeoutVote(vote) => Some(vote.validator_id.as_str()),
        ConsensusEvent::QuorumCertificate(_) | ConsensusEvent::TimeoutCertificate(_) => None,
    };
    if direct_sender.is_some_and(|sender| sender != peer.node_address.as_str()) {
        return Err("invalid authenticated consensus evidence".into());
    }
    Ok(())
}

impl PosyMessageSink for PosyService {
    fn receive_posy(&mut self, peer: AuthenticatedPeer, payload: Vec<u8>) -> Result<(), String> {
        if payload.len() > 1024 * 1024 {
            self.metrics.record_rejection();
            return Ok(());
        }
        let event: ConsensusEvent = match serde_json::from_slice(&payload) {
            Ok(event) => event,
            Err(_) => {
                self.metrics.record_rejection();
                return Ok(());
            }
        };
        if let Some(preparation) = &self.preparation {
            let (height, round, _) = event_slot(&event);
            let digest = synergy_etdag::EtdagDigest::from_domain_bytes(
                "SYNERGY_PREPARATION_INPUT_V1",
                &payload,
            )
            .0;
            let charge = payload
                .len()
                .checked_mul(2)
                .and_then(|n| n.checked_add(2048))
                .ok_or("consensus preparation byte overflow")?;
            let authority = self.authority.clone();
            match preparation.submit(
                super::preparation::Lane::Consensus,
                height,
                round,
                height,
                digest,
                charge,
                move || {
                    let authority = VerifiedAuthority::worker_context(&authority)?;
                    verify_prepared_consensus(authority.as_ref(), &peer, &event)?;
                    Ok(PreparedConsensus { peer, event })
                },
            ) {
                Ok(_) => return Ok(()),
                Err(reason) if reason == "preparation backpressure" => {
                    self.metrics.record_rejection();
                    return Ok(());
                }
                Err(reason) => return Err(reason),
            }
        }
        let validation = match &event {
            ConsensusEvent::Proposal(value) => validate_proposal(
                value,
                &self.authority.epoch,
                &self.authority.registry,
                self.authority.as_ref(),
            ),
            ConsensusEvent::ProposalDelivery(value) => value.statement.verify(
                &self.authority.epoch,
                &self.authority.registry,
                self.authority.as_ref(),
            ),
            ConsensusEvent::BlockVote(value) => validate_block_vote(
                value,
                &self.authority.epoch,
                &self.authority.registry,
                self.authority.as_ref(),
            ),
            ConsensusEvent::TimeoutVote(value) => validate_timeout_vote(
                value,
                &self.authority.epoch,
                &self.authority.registry,
                self.authority.as_ref(),
            ),
            ConsensusEvent::QuorumCertificate(value) => value.verify(
                &self.authority.epoch,
                &self.authority.registry,
                self.authority.as_ref(),
            ),
            ConsensusEvent::TimeoutCertificate(value) => value.verify(
                &self.authority.epoch,
                &self.authority.registry,
                self.authority.as_ref(),
            ),
        };
        if let Err(error) = validation {
            #[cfg(test)]
            if let ConsensusEvent::TimeoutCertificate(certificate) = &event {
                self.r3_timeout_diagnostic(certificate, &format!("native-rejected:{error}"));
            }
            #[cfg(not(test))]
            let _ = error;
            self.metrics.record_rejection();
            return Ok(());
        }
        let direct_sender = match &event {
            ConsensusEvent::Proposal(proposal) => Some(proposal.proposer_id.as_str()),
            ConsensusEvent::BlockVote(vote) => Some(vote.validator_id.as_str()),
            ConsensusEvent::ProposalDelivery(statement) => {
                Some(statement.statement.validator_id.as_str())
            }
            ConsensusEvent::TimeoutVote(vote) => Some(vote.validator_id.as_str()),
            ConsensusEvent::QuorumCertificate(_) | ConsensusEvent::TimeoutCertificate(_) => None,
        };
        if direct_sender.is_some_and(|sender| sender != peer.node_address.as_str()) {
            self.metrics.record_rejection();
            return Ok(());
        }
        self.apply_event_from(event, true)
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
        if self.authority.processing_profile_enabled() {
            self.ingress.initialize_processing_build_requests()?;
            self.ingress
                .publish_processing_build_request(self.driver.state_machine())?;
        }
        self.republish_validation_history()?;
        let height = self.driver.state_machine().active_slot().0;
        for envelope in self
            .delivery
            .stored_ready_window(
                height,
                &self.authority.epoch,
                &self.authority.registry,
                self.authority.as_ref(),
            )
            .map_err(|e| e.to_string())?
        {
            self.broadcast(&ConsensusEvent::ProposalDelivery(envelope))?;
        }
        if let Some(local) = self.local_signer.as_ref() {
            let statements = self.delivery.local_statements(local.validator_id());
            for statement in statements {
                self.broadcast(&ConsensusEvent::ProposalDelivery(
                    self.delivery_envelope(statement)?,
                ))?;
            }
        }
        self.started = true;
        self.failure = None;
        Ok(())
    }

    fn poll(&mut self) -> Result<(), String> {
        if !self.started {
            return Err("PoSy service is not started".into());
        }
        #[cfg(feature = "qualification-timing")]
        {
            use super::qualification_timing::{self as timing, Classification, Kind, Phase, Role};
            if timing::enabled() {
                let (height, round) = self.driver.state_machine().active_slot();
                // Round zero alone cannot prove absence of historical catch-up.
                // Until fixture provenance identifies a healthy cohort, retain
                // these observations conservatively outside healthy budgets.
                let classification = Classification::Recovered;
                timing::emit_once(
                    Kind::Proposal,
                    Phase::ProposalStart,
                    height,
                    round,
                    0,
                    Role::Participant,
                    classification,
                    Some(false),
                    None,
                );
            }
        }
        #[cfg(any(test, feature = "qualification-timing"))]
        let mut operation_trace = super::owner_poll_diagnostic::PollTrace::new("posy");
        inspect_bounded_regular(
            &self.authority_binding,
            MAX_AUTHORITY_BINDING_BYTES,
            "PoSy authority binding",
            false,
        )?;
        #[cfg(any(test, feature = "qualification-timing"))]
        operation_trace.completed("authority-binding");
        for _ in 0..MAX_MESSAGES_PER_POLL {
            let Some(frame) = self.ingress.take(ProtocolKind::Posy)? else {
                break;
            };
            PosyAdapter
                .deliver(AdapterEnvelope::from(frame), self)
                .map_err(|error| format!("route authenticated PoSy frame: {error:?}"))?;
        }
        #[cfg(any(test, feature = "qualification-timing"))]
        operation_trace.completed("network-intake");
        loop {
            let prepared = match &self.preparation {
                Some(owner) => owner.take()?,
                None => None,
            };
            let Some(prepared) = prepared else {
                break;
            };
            match prepared.result {
                Ok(verified) => {
                    // Authentication was checked when queued; reconnect may replace
                    // the session while immutable cryptography runs off-thread.
                    if self.ingress.is_current_session(&verified.peer)? {
                        self.apply_event_from(verified.event, true)?;
                    } else {
                        self.metrics.record_rejection();
                    }
                }
                Err(_) => self.metrics.record_rejection(),
            }
        }
        #[cfg(any(test, feature = "qualification-timing"))]
        operation_trace.completed("preparation-completions");
        self.collect_candidates()?;
        #[cfg(any(test, feature = "qualification-timing"))]
        operation_trace.completed("collect-candidates");
        self.verify_sync_claims()?;
        #[cfg(any(test, feature = "qualification-timing"))]
        operation_trace.completed("verify-sync-claims");
        self.admit_sync_candidates()?;
        #[cfg(any(test, feature = "qualification-timing"))]
        operation_trace.completed("admit-sync-candidates");
        self.drain_deferred_qcs()?;
        #[cfg(any(test, feature = "qualification-timing"))]
        operation_trace.completed("deferred-qcs");
        self.drain_deferred_sync()?;
        #[cfg(any(test, feature = "qualification-timing"))]
        operation_trace.completed("deferred-sync");
        self.retry_delivery()?;
        #[cfg(any(test, feature = "qualification-timing"))]
        operation_trace.completed("retry-delivery");
        if self.delivery_validation_retry {
            self.advance_delivery()?;
        }
        #[cfg(any(test, feature = "qualification-timing"))]
        operation_trace.completed("advance-delivery");
        self.authorize_cut_recovery()?;
        #[cfg(any(test, feature = "qualification-timing"))]
        operation_trace.completed("cut-recovery");
        self.emit_timeout_vote()?;
        #[cfg(any(test, feature = "qualification-timing"))]
        operation_trace.completed("timeout-vote");
        if self.authority.processing_profile_enabled() {
            self.ingress
                .publish_processing_build_request(self.driver.state_machine())?;
        }
        #[cfg(any(test, feature = "qualification-timing"))]
        operation_trace.completed("processing-build-request");
        let (height, round) = self.driver.state_machine().active_slot();
        self.ingress.publish_consensus_observation(
            height,
            round,
            self.authority.epoch.root().map_err(|e| e.to_string())?,
        )?;
        Ok(())
    }

    fn stop(&mut self) -> Result<(), String> {
        if let Some(owner) = self.preparation.take() {
            owner.cancel();
        }
        self.ingress.clear(ProtocolKind::Posy)?;
        if self.authority.processing_profile_enabled() {
            self.ingress.clear_processing_build_requests()?;
        }
        self.started = false;
        self.recovery = None;
        self.finality = None;
        self.emitted_slots.clear();
        self.retry_frames.clear();
        self.historical_timeouts = HistoricalTimeoutRetry::default();
        self.pending_proposals.clear();
        self.candidates.clear();
        self.processing_candidate_rounds.clear();
        self.deferred_qcs.clear();
        self.deferred_sync.clear();
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

// Call only after the verified finality commit is durable. Current candidates
// and the unfinalized three-QC tail remain available to the sole PoSy driver;
// historical authenticated commitments remain in the immutable finality store.
fn retire_finalized_candidates(
    candidates: &mut BTreeMap<u64, Arc<ExecutionCandidate>>,
    finalized: u64,
) {
    candidates.retain(|height, _| *height > finalized);
}

/// Native-slot processing handoff. The original height-only legacy path stays
/// immutable; only a later PoSy-admitted takeover can replace an async candidate.
pub(super) fn retain_processing_execution_candidate(
    candidates: &mut BTreeMap<u64, Arc<ExecutionCandidate>>,
    rounds: &mut BTreeMap<u64, u64>,
    handoff: super::ingress::ProcessingCandidateHandoff,
    machine: &synergy_posy::SimplifiedConsensusStateMachine,
) -> Result<(), String> {
    let request = &handoff.request;
    let slot = (request.context.height, request.context.round);
    if slot != machine.active_slot() || request.parent != *machine.highest_parent() {
        return Ok(());
    }
    if request.mandatory_carry.as_ref() != machine.active_mandatory_carry() {
        return Err("processing candidate carries obsolete native carry authority".into());
    }
    request
        .context
        .validate_against(machine.epoch())
        .map_err(|e| e.to_string())?;
    if request.proposer
        != machine
            .epoch()
            .authorized_proposer(slot.0, slot.1)
            .map_err(|e| e.to_string())?
    {
        return Err("processing candidate carries another proposer instruction".into());
    }
    let candidate = handoff.candidate;
    if candidate.height != slot.0 || candidate.parent_block_id != request.parent.block_id() {
        return Err("processing candidate differs from native slot parent".into());
    }
    if let Some(takeover) = request.takeover.as_ref() {
        if machine.active_takeover_tc_id() != Some(takeover.id())
            || machine.accepted_timeout_certificate(takeover.id()) != Some(takeover)
            || takeover.context().height > slot.0
            || takeover.lease_index()
                != machine
                    .epoch()
                    .lease_index(slot.0)
                    .map_err(|e| e.to_string())?
            || takeover.context().round.checked_add(1) != Some(slot.1)
            || request.mandatory_carry.as_ref().is_some_and(|carry| {
                carry.block_id != candidate.block_id
                    || carry.protected_execution_root != candidate.protected_execution_root
                    || carry.parent != request.parent
            })
        {
            return Err("processing candidate violates native takeover/carry".into());
        }
    } else if slot.1 != 0 {
        return Err("processing candidate lacks native takeover".into());
    }
    if candidates
        .get(&slot.0)
        .is_some_and(|old| old.block_id != candidate.block_id)
        && (request.takeover.is_none() || rounds.get(&slot.0).is_none_or(|old| *old >= slot.1))
    {
        return Err("conflicting processing candidates within one native slot".into());
    }
    rounds.insert(slot.0, slot.1);
    candidates.insert(slot.0, candidate);
    Ok(())
}

// Execution ingress validates candidates before handoff. A retired internal
// handoff grants no authority and must not repin its historical world. Active
// candidate conflicts retain the existing fail-closed behavior.
fn retain_execution_candidate(
    candidates: &mut BTreeMap<u64, Arc<ExecutionCandidate>>,
    candidate: Arc<ExecutionCandidate>,
    finalized: Option<u64>,
) -> Result<(), String> {
    if finalized.is_some_and(|height| candidate.height <= height) {
        return Ok(());
    }
    match candidates.get(&candidate.height) {
        Some(current) if current.block_id == candidate.block_id => Ok(()),
        Some(_) => Err("conflicting execution candidates for PoSy height".into()),
        None => {
            candidates.insert(candidate.height, candidate);
            Ok(())
        }
    }
}

// Retransmission retains active signed messages and a small certificate tail.
// It owns no consensus state and never grants authority to a queued message.
fn event_slot(event: &ConsensusEvent) -> (u64, u64, u8) {
    let (context, kind) = match event {
        ConsensusEvent::Proposal(v) => (&v.context, 0),
        ConsensusEvent::ProposalDelivery(v) => (
            &v.statement.context,
            match v.statement.phase {
                ProposalDeliveryPhase::Echo => 5,
                ProposalDeliveryPhase::Ready => 6,
            },
        ),
        ConsensusEvent::BlockVote(v) => (&v.context, 1),
        ConsensusEvent::TimeoutVote(v) => (&v.context, 2),
        ConsensusEvent::QuorumCertificate(v) => (&v.context, 3),
        ConsensusEvent::TimeoutCertificate(v) => (&v.context, 4),
    };
    (
        context.height,
        if kind == 3 || kind == 6 {
            0
        } else {
            context.round
        },
        kind,
    )
}

fn retry_slot_is_live(slot: (u64, u64, u8), active: (u64, u64)) -> bool {
    match slot.2 {
        0..=2 | 5 => (slot.0, slot.1) == active,
        6 => slot.1 == 0 && slot.0 <= active.0 && active.0 - slot.0 <= 8,
        3 => slot.1 == 0 && slot.0 < active.0 && active.0 - slot.0 <= 3,
        4 => slot.0 == active.0 && slot.1 < active.1 && active.1 - slot.1 <= 3,
        _ => false,
    }
}

// Verified peer progress is scoped to the current authenticated session and
// native three-QC finality. Finality at H authenticates the contiguous QCs at
// H, H+1 and H+2: its finality_certificate_id is the H+2 QC identifier, whose
// parent references bind the other two. Retrying READY/QC at those certified
// heights to the same session cannot advance its consensus prefix. This is
// retransmission routing only: it neither
// retires proof bytes nor claims that the peer has executed the finalized state.
fn certificate_retry_is_needed(
    slot: (u64, u64, u8),
    verified_finalized_height: Option<u64>,
) -> bool {
    !matches!(slot.2, 3 | 6)
        || verified_finalized_height
            .and_then(|height| height.checked_add(2))
            .is_none_or(|certified_height| certified_height < slot.0)
}

fn timeout_retry_is_needed(
    slot: (u64, u64, u8),
    active: (u64, u64),
    validator_peers: &[String],
    verified_peer_heights: &BTreeMap<String, u64>,
) -> bool {
    slot.2 == 4
        && (slot.0 < active.0 || (slot.0 == active.0 && slot.1 < active.1))
        && validator_peers.iter().any(|peer| {
            verified_peer_heights
                .get(peer)
                .is_none_or(|height| *height <= slot.0)
        })
}

fn peer_error_is_fatal(certified: bool, error: &PosyError) -> bool {
    // Only independently verified contradictory quorum evidence signals a
    // safety failure. Invalid, stale, reordered or premature peer messages
    // are rejected without converting them into a local service failure.
    certified && matches!(error, PosyError::Conflict(_))
}

#[cfg(test)]
mod delivery_tests {
    use super::*;

    #[test]
    fn stale_and_premature_peer_messages_are_nonfatal_but_certified_conflict_is_fatal() {
        assert!(!peer_error_is_fatal(
            false,
            &PosyError::NotReady("proposal pending".into())
        ));
        assert!(!peer_error_is_fatal(
            true,
            &PosyError::invalid("future height")
        ));
        assert!(!peer_error_is_fatal(
            false,
            &PosyError::Conflict("peer equivocation".into())
        ));
        assert!(peer_error_is_fatal(
            true,
            &PosyError::Conflict("conflicting verified QC".into())
        ));
    }

    #[test]
    fn delivery_tail_is_bounded_and_drops_stale_signed_votes() {
        let active = (1000, 50);
        let live: Vec<_> = (0..=1001)
            .flat_map(|h| (0..=51).flat_map(move |r| (0..=6).map(move |k| (h, r, k))))
            .filter(|slot| retry_slot_is_live(*slot, active))
            .collect();
        assert!(!live.contains(&(999, 50, 1)));
        assert!(!live.contains(&(1000, 49, 1)));
        assert!(live.contains(&(1000, 50, 1)));
        assert!(live.contains(&(999, 0, 3)));
        assert!(live.contains(&(1000, 49, 4)));
        // QC entries must be keyed by height, not signer subset or round.
        assert_eq!(live.len(), 19);
    }

    #[test]
    fn certificate_retry_requires_current_peer_finality_and_preserves_other_messages() {
        for kind in [3, 6] {
            let slot = (50, 0, kind);
            assert!(certificate_retry_is_needed(slot, None));
            assert!(certificate_retry_is_needed(slot, Some(47)));
            assert!(!certificate_retry_is_needed(slot, Some(48)));
            assert!(!certificate_retry_is_needed(slot, Some(49)));
            assert!(!certificate_retry_is_needed(slot, Some(50)));
            assert!(!certificate_retry_is_needed(slot, Some(51)));
            assert!(certificate_retry_is_needed(slot, Some(u64::MAX - 1)));
        }
        for kind in [0, 1, 2, 4, 5] {
            assert!(certificate_retry_is_needed((50, 0, kind), Some(99)));
        }
    }

    #[test]
    fn timeout_retry_waits_for_every_validator_to_verify_progress_past_its_height() {
        let slot = (50, 1, 4);
        let active = (51, 0);
        let peers = vec!["val2".to_string(), "val3".to_string()];
        let mut heads = BTreeMap::from([("val2".to_string(), 51)]);

        assert!(timeout_retry_is_needed(slot, active, &peers, &heads));
        heads.insert("val3".to_string(), 50);
        assert!(timeout_retry_is_needed(slot, active, &peers, &heads));
        heads.insert("val3".to_string(), 51);
        assert!(!timeout_retry_is_needed(slot, active, &peers, &heads));
        // Crossing the proposer lease boundary must not strand an offline
        // validator that still needs this exact verified timeout authority.
        let later_lease = (63, 0);
        heads.insert("val3".to_string(), 50);
        assert!(timeout_retry_is_needed(slot, later_lease, &peers, &heads));
        heads.remove("val3");
        assert!(timeout_retry_is_needed(slot, later_lease, &peers, &heads));
        heads.insert("val3".to_string(), 51);
        assert!(!timeout_retry_is_needed(slot, later_lease, &peers, &heads));
    }
}

#[cfg(test)]
#[path = "posy_qualification.rs"]
pub(super) mod qualification;

#[cfg(feature = "qualification-timing")]
fn qualification_qc(height: u64, round: u64) {
    use super::qualification_timing::{self as timing, Classification, Kind, Phase, Role};
    timing::emit_once(
        Kind::Proposal,
        Phase::QcVerified,
        height,
        round,
        0,
        Role::Participant,
        Classification::Recovered,
        Some(false),
        None,
    );
}

#[cfg(feature = "qualification-timing")]
fn qualification_finality(height: u64) {
    use super::qualification_timing::{self as timing, Classification, Kind, Phase, Role};
    // Cadence is between consecutive local durable finality acknowledgements;
    // no historical timestamp is reconstructed after restart.
    timing::emit_once(
        Kind::Cadence,
        Phase::End,
        height,
        0,
        0,
        Role::Participant,
        Classification::Recovered,
        None,
        None,
    );
    if let Some(next) = height.checked_add(1) {
        timing::emit_once(
            Kind::Cadence,
            Phase::Start,
            next,
            0,
            0,
            Role::Participant,
            Classification::Recovered,
            None,
            None,
        );
    }
}

#[cfg(test)]
mod candidate_retention_tests {
    use super::*;

    fn budget_world(
        world: &synergy_state::WorldState,
    ) -> synergy_state::world_resources::BudgetedWorld {
        synergy_state::world_resources::BudgetedWorld::try_clone_world(
            world,
            &synergy_state::world_resources::WorldResourceBudget::new(64 * 1024 * 1024),
        )
        .unwrap()
    }
    fn candidate(
        height: u64,
        state: Arc<synergy_state::world_resources::BudgetedWorld>,
    ) -> Arc<ExecutionCandidate> {
        let root = synergy_etdag::EtdagDigest::from_domain_bytes(
            "candidate-retention",
            &height.to_le_bytes(),
        );
        Arc::new(ExecutionCandidate {
            resource_permit: None,
            height,
            block_id: format!("block-{height}"),
            parent_block_id: format!("block-{}", height - 1),
            protected_execution_root: format!("protected-{height}"),
            state_root: format!("world-{height}"),
            protected_material: synergy_etdag::execution::ProtectedProposalMaterial {
                material_version: 2,
                height,
                execution_root: root.clone(),
                next_batch_root: root.clone(),
                cutoff_boundary_root: root,
            }
            .into(),
            transactions: vec![],
            receipts: vec![],
            state,
        })
    }

    #[test]
    fn finalized_candidate_retirement_releases_changing_worlds_and_preserves_live_tail() {
        let mut candidates = BTreeMap::new();
        let mut worlds = Vec::new();
        for height in 1u64..=128 {
            let mut world = synergy_state::WorldState::default();
            world
                .protocol
                .insert(format!("height-{height}"), vec![height as u8; 64 * 1024]);
            let world = Arc::new(budget_world(&world));
            worlds.push(Arc::downgrade(&world));
            candidates.insert(height, candidate(height, world));
            // Persisted finality trails the active executed candidate by three.
            retire_finalized_candidates(&mut candidates, height.saturating_sub(3));
            retire_finalized_candidates(&mut candidates, height.saturating_sub(3));
            assert!(candidates.len() <= 3);
        }
        assert!(worlds[..125].iter().all(|world| world.upgrade().is_none()));
        assert!(worlds[125..].iter().all(|world| world.upgrade().is_some()));
        assert_eq!(
            candidates.keys().copied().collect::<Vec<_>>(),
            vec![126, 127, 128]
        );
        // An unfinalized pending/current candidate retains exactly its shared world.
        assert_eq!(Arc::strong_count(&candidates[&128].state), 1);
        candidates.clear();
        assert!(worlds.iter().all(|world| world.upgrade().is_none()));
    }

    #[test]
    fn delayed_finalized_candidate_replay_drops_world_and_preserves_active_conflicts() {
        let mut candidates = BTreeMap::new();
        for _ in 0..2 {
            let world = Arc::new(budget_world(&synergy_state::WorldState::default()));
            let weak = Arc::downgrade(&world);
            retain_execution_candidate(&mut candidates, candidate(7, world), Some(7)).unwrap();
            assert!(candidates.is_empty());
            assert!(weak.upgrade().is_none());
        }
        let pending = Arc::new(budget_world(&synergy_state::WorldState::default()));
        let weak_pending = Arc::downgrade(&pending);
        retain_execution_candidate(&mut candidates, candidate(8, pending), Some(7)).unwrap();
        let duplicate = Arc::new(budget_world(&synergy_state::WorldState::default()));
        let weak_duplicate = Arc::downgrade(&duplicate);
        retain_execution_candidate(&mut candidates, candidate(8, duplicate), Some(7)).unwrap();
        assert!(weak_duplicate.upgrade().is_none());
        assert!(weak_pending.upgrade().is_some());
        let mut conflicting = candidate(
            8,
            Arc::new(budget_world(&synergy_state::WorldState::default())),
        );
        Arc::get_mut(&mut conflicting)
            .unwrap()
            .block_id
            .push_str("-conflict");
        assert!(retain_execution_candidate(&mut candidates, conflicting, Some(7)).is_err());
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[&8].block_id, "block-8");
        retire_finalized_candidates(&mut candidates, 7);
        assert!(weak_pending.upgrade().is_some());
        retire_finalized_candidates(&mut candidates, 8);
        retire_finalized_candidates(&mut candidates, 8);
        assert!(weak_pending.upgrade().is_none());
    }
}

#[cfg(test)]
#[path = "posy_epoch_boundary_qualification.rs"]
pub(super) mod epoch_boundary_qualification;
