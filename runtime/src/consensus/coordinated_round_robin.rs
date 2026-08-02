//! Temporary, coordinator-driven consensus for Testnet-v3 stabilization.
//!
//! This module intentionally contains no vote, validation-certificate, quorum
//! certificate, timeout-certificate, aggregator, or coordinator-election
//! machinery.  It owns only the durable producer cursor and the single
//! coordinator commitment allowed for each height.  The role-runtime adapter
//! is responsible for authenticating messages with the canonical validator
//! consensus keys, persisting this state before broadcast, and passing the
//! canonical block execution result to this state machine.

use crate::crypto::aegis_pqvm::{AegisPqvmVerifier, SYNERGY_BLOCK_V1};
use crate::dag_mempool::compute_tx_order_root;
use crate::p2p::messages::{
    validate_coordinated_consensus_message_size, CoordinatedCommittedBlockPackage,
    CoordinatedConsensusMessage,
};
use crate::synergy_types::{
    AegisPqKeyId, AegisPqKeyRole, AegisPqSignature, Block as TypedBlock, CanonicalSerialize, Epoch,
    Hash, TxId, UmaId, ValidatorId, ValidatorRecord, ValidatorSet,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

pub const COORDINATED_ROUND_ROBIN_V1: &str = "coordinated_round_robin_v1";
pub const COORDINATED_ASSIGNMENT_DOMAIN: &str = "SYNERGY_COORDINATED_ASSIGNMENT_V1";
pub const COORDINATED_COMMIT_DOMAIN: &str = "SYNERGY_COORDINATED_COMMIT_V1";
const COORDINATOR_STATE_VERSION: u32 = 1;

/// The exact validator identity established by the canonical Testnet-v3
/// handshake.  This is deliberately a distinct type from the retired typed
/// PoSy peer envelope, even though both begin with the same authenticated
/// Genesis identity proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedCoordinatedConsensusPeer {
    pub validator_id: ValidatorId,
    pub validator_uma_id: UmaId,
    pub consensus_key_id: AegisPqKeyId,
}

/// A bounded P2P delivery envelope.  The runtime verifies that the authenticated
/// session identity has the authority required for the contained assignment,
/// proposal, commit, or sync request before it mutates consensus state.
#[derive(Debug, Clone)]
pub struct CoordinatedConsensusEnvelope {
    pub peer_address: String,
    pub authenticated_peer: AuthenticatedCoordinatedConsensusPeer,
    pub message: CoordinatedConsensusMessage,
}

static COORDINATED_CONSENSUS_INGRESS: OnceLock<
    Mutex<Option<mpsc::SyncSender<CoordinatedConsensusEnvelope>>>,
> = OnceLock::new();

fn coordinated_ingress_slot(
) -> &'static Mutex<Option<mpsc::SyncSender<CoordinatedConsensusEnvelope>>> {
    COORDINATED_CONSENSUS_INGRESS.get_or_init(|| Mutex::new(None))
}

/// Installs the only coordinated-mode mailbox for this process.  Replacing a
/// live mailbox is forbidden because it could split the coordinator signing
/// journal from the worker that owns it.
pub fn install_coordinated_consensus_ingress(
    queue_capacity: usize,
) -> Result<mpsc::Receiver<CoordinatedConsensusEnvelope>, String> {
    if queue_capacity == 0 {
        return Err("coordinated consensus ingress queue capacity must be non-zero".to_string());
    }
    let (sender, receiver) = mpsc::sync_channel(queue_capacity);
    let mut slot = coordinated_ingress_slot()
        .lock()
        .map_err(|_| "coordinated consensus ingress lock is poisoned".to_string())?;
    if slot.is_some() {
        return Err("coordinated consensus ingress is already installed".to_string());
    }
    *slot = Some(sender);
    Ok(receiver)
}

/// Removes coordinated ingress after its worker has stopped.  Only the role
/// runtime should call this; P2P traffic cannot install or replace a worker.
pub fn remove_coordinated_consensus_ingress() -> Result<(), String> {
    let mut slot = coordinated_ingress_slot()
        .lock()
        .map_err(|_| "coordinated consensus ingress lock is poisoned".to_string())?;
    *slot = None;
    Ok(())
}

/// Delivers a coordinated-consensus message to its dedicated mailbox.  There
/// is no legacy or typed-PoSy fallback: an absent worker, an unauthenticated
/// peer, a saturated queue, and an oversized frame all fail closed.
pub fn dispatch_coordinated_consensus_message(
    peer_address: &str,
    authenticated_peer: Option<AuthenticatedCoordinatedConsensusPeer>,
    message: CoordinatedConsensusMessage,
) -> Result<(), String> {
    validate_coordinated_consensus_message_size(&message)?;
    let authenticated_peer = authenticated_peer.ok_or_else(|| {
        "coordinated consensus refuses a message without authenticated validator identity"
            .to_string()
    })?;
    let sender = coordinated_ingress_slot()
        .lock()
        .map_err(|_| "coordinated consensus ingress lock is poisoned".to_string())?
        .clone()
        .ok_or_else(|| {
            "coordinated consensus coordinator is not running; refusing consensus message"
                .to_string()
        })?;
    sender
        .try_send(CoordinatedConsensusEnvelope {
            peer_address: peer_address.to_string(),
            authenticated_peer,
            message,
        })
        .map_err(|error| match error {
            mpsc::TrySendError::Full(_) => {
                "coordinated consensus ingress is saturated; refusing consensus message".to_string()
            }
            mpsc::TrySendError::Disconnected(_) => {
                "coordinated consensus ingress is disconnected; refusing consensus message"
                    .to_string()
            }
        })
}

/// Verification authority built exclusively from the finalized active
/// validator set.  It rejects a configuration that is not exactly Val1 as
/// coordinator plus Val2--Val6 as producers, and it never derives identities
/// from a P2P address, connection order, or an unverified message field.
#[derive(Debug, Clone)]
pub struct CoordinatedConsensusVerifier {
    config: CoordinatedRoundRobinConfig,
    active_validators: BTreeMap<String, ValidatorRecord>,
    verifier: AegisPqvmVerifier,
    epoch: Epoch,
}

impl CoordinatedConsensusVerifier {
    pub fn new(
        config: CoordinatedRoundRobinConfig,
        validator_set: &ValidatorSet,
        verifier: AegisPqvmVerifier,
    ) -> Result<Self, String> {
        config.validate()?;
        let epoch = validator_set.epoch;
        let active_set = validator_set.active_for_epoch(epoch);
        active_set.validate_unique_validator_and_key_ids()?;
        let configured = std::iter::once(config.coordinator_id.clone())
            .chain(config.producer_ids.iter().cloned())
            .collect::<BTreeSet<_>>();
        let active = active_set
            .validators
            .iter()
            .map(|validator| validator.validator_id.0.clone())
            .collect::<BTreeSet<_>>();
        if configured != active {
            return Err(
                "coordinated mode must bind exactly the finalized active six-validator set"
                    .to_string(),
            );
        }
        if active_set.validators.len() != 6 {
            return Err(
                "coordinated mode requires exactly six active finalized validators".to_string(),
            );
        }
        let active_validators = active_set
            .validators
            .into_iter()
            .map(|validator| (validator.validator_id.0.clone(), validator))
            .collect();
        Ok(Self {
            config,
            active_validators,
            verifier,
            epoch,
        })
    }

    pub fn config(&self) -> &CoordinatedRoundRobinConfig {
        &self.config
    }

    pub fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// Checks that the TLS/P2P-session identity is exactly the finalized
    /// validator identity and consensus key claimed by the peer.  Packet
    /// content is verified separately so session authentication cannot be
    /// substituted for a signature.
    pub fn verify_authenticated_peer(
        &self,
        peer: &AuthenticatedCoordinatedConsensusPeer,
    ) -> Result<(), String> {
        let validator = self.validator(&peer.validator_id.0)?;
        if validator.validator_uma_id != peer.validator_uma_id
            || validator.consensus_public_key.key_id != peer.consensus_key_id
        {
            return Err(
                "coordinated consensus peer identity does not match finalized validator keys"
                    .to_string(),
            );
        }
        Ok(())
    }

    /// Verifies Val1's signed producer assignment.  The signature covers the
    /// exact chain, epoch, height, parent, ordered producer turn, and intended
    /// timestamp through [`ProducerAssignment::signing_hash`].
    pub fn verify_assignment(&self, assignment: &ProducerAssignment) -> Result<(), String> {
        assignment.validate_shape(&self.config)?;
        if assignment.epoch != self.epoch.0 {
            return Err(
                "coordinated assignment epoch does not match finalized validator set".to_string(),
            );
        }
        let coordinator = self.validator(&self.config.coordinator_id)?;
        self.verifier
            .verify_domain_signature(
                COORDINATED_ASSIGNMENT_DOMAIN,
                &assignment.signing_hash()?.0,
                &coordinator.validator_uma_id.0,
                &coordinator.consensus_public_key.key_id,
                self.epoch,
                AegisPqKeyRole::ConsensusProposer,
                &assignment.coordinator_signature,
            )
            .map_err(|error| format!("verify coordinated producer assignment: {error}"))
    }

    /// Verifies the producer's canonical block signature and every binding
    /// between the signed Val1 assignment and the announced block.  It does
    /// not perform execution; callers must execute deterministically before
    /// accepting a coordinator commit.
    pub fn verify_producer_block(
        &self,
        assignment: &ProducerAssignment,
        proposal: &CoordinatedProposal,
        block: &TypedBlock,
    ) -> Result<(), String> {
        self.verify_assignment(assignment)?;
        proposal.validate_shape()?;
        let producer = self.validator(&assignment.assigned_producer_id)?;
        let block_hash = Hash::from_hex(&block.block_id()?.0)
            .map_err(|error| format!("coordinated block ID is not a hash: {error}"))?;
        let transaction_ids = block
            .transactions
            .iter()
            .map(|transaction| {
                Ok(TxId::from_hash(Hash::from_domain_bytes(
                    "SYNERGY_EXECUTION_TX_ID_V1",
                    &transaction.canonical_bytes()?,
                )))
            })
            .collect::<Result<Vec<_>, String>>()?;
        let transaction_count = u64::try_from(transaction_ids.len())
            .map_err(|_| "coordinated block transaction count exceeds u64".to_string())?;
        if proposal.epoch != assignment.epoch
            || proposal.height != assignment.height
            || proposal.producer_round != assignment.producer_round
            || proposal.parent_block_hash != assignment.parent_block_hash
            || proposal.prior_finality_reference != assignment.prior_finality_reference
            || proposal.block_hash != block_hash
            || proposal.producer_id != assignment.assigned_producer_id
            || proposal.assignment_hash != assignment.signing_hash()?
            || block.header.chain_id.0 != assignment.chain_id
            || block.header.network_id.0 != assignment.network_id
            || block.header.epoch.0 != assignment.epoch
            || block.header.height.0 != assignment.height
            || block.header.round.0 != assignment.producer_round
            || block.header.protocol_version != assignment.consensus_version
            || block.header.parent_block_hash != assignment.parent_block_hash
            || block.header.parent_state_root != block.header.state_root_before
            || block.header.evidence_root != assignment.prior_finality_reference
            || !block.header.last_finalized_qc_hash.is_zero()
            || block.header.proposer_validator_id != producer.validator_id
            || block.header.proposer_uma_id != producer.validator_uma_id
            || block.header.proposer_key_id != producer.consensus_public_key.key_id
            || block.header.tx_count != transaction_count
            || block.header.tx_order_root != compute_tx_order_root(&transaction_ids)?
            || block.header.tx_order_root != proposal.transaction_root
            || block.header.receipt_root != proposal.receipt_root
            || block.header.state_root_after != proposal.state_root
            || block.proposer_signature != proposal.producer_signature
        {
            return Err(
                "coordinated producer block does not match its signed assignment".to_string(),
            );
        }
        for transaction in &block.transactions {
            self.verifier
                .verify_transaction_signature_checked(transaction)
                .map_err(|error| format!("verify coordinated transaction signature: {error}"))?;
        }
        self.verifier
            .verify_domain_signature(
                SYNERGY_BLOCK_V1,
                &block.header.canonical_bytes()?,
                &producer.validator_uma_id.0,
                &producer.consensus_public_key.key_id,
                self.epoch,
                AegisPqKeyRole::ConsensusProposer,
                &block.proposer_signature,
            )
            .map_err(|error| format!("verify coordinated producer block: {error}"))
    }

    /// Verifies Val1's sole coordinator commitment.  This is not a QC or a
    /// certificate: it is one consensus-key signature over the fully bound,
    /// already-executed producer block subject.
    pub fn verify_commit(&self, commit: &CoordinatorCommit) -> Result<(), String> {
        commit.validate_shape(&self.config)?;
        if commit.epoch != self.epoch.0 {
            return Err(
                "coordinated commit epoch does not match finalized validator set".to_string(),
            );
        }
        let coordinator = self.validator(&self.config.coordinator_id)?;
        self.verifier
            .verify_domain_signature(
                COORDINATED_COMMIT_DOMAIN,
                &commit.signing_hash()?.0,
                &coordinator.validator_uma_id.0,
                &coordinator.consensus_public_key.key_id,
                self.epoch,
                AegisPqKeyRole::ConsensusProposer,
                &commit.coordinator_signature,
            )
            .map_err(|error| format!("verify coordinated coordinator commit: {error}"))
    }

    /// Verifies every cryptographic and structural binding in a relayable
    /// finalized package.  Execution and durable storage remain separate,
    /// mandatory steps performed by the runtime adapter.
    pub fn verify_committed_block_package(
        &self,
        package: &CoordinatedCommittedBlockPackage,
    ) -> Result<(), String> {
        package.validate_against(&self.config)?;
        self.verify_producer_block(&package.assignment, &package.proposal, &package.block)?;
        self.verify_commit(&package.coordinator_commit)
    }

    /// Ensures the session identity is authorized to originate the wire item
    /// that it sends. Finalized packages may be relayed by any authenticated
    /// member of the six-validator set, but first-hop assignments, proposals,
    /// and commits must originate from the accountable signer.
    pub fn verify_message_sender(
        &self,
        peer: &AuthenticatedCoordinatedConsensusPeer,
        message: &CoordinatedConsensusMessage,
    ) -> Result<(), String> {
        self.verify_authenticated_peer(peer)?;
        let expected_signer = match message {
            CoordinatedConsensusMessage::ProducerAssignment { assignment } => {
                Some(&assignment.coordinator_id)
            }
            CoordinatedConsensusMessage::ProposedBlock { assignment, .. } => {
                Some(&assignment.assigned_producer_id)
            }
            CoordinatedConsensusMessage::CoordinatorCommit { package } => {
                Some(&package.coordinator_commit.coordinator_id)
            }
            CoordinatedConsensusMessage::GetCommittedBlock { .. }
            | CoordinatedConsensusMessage::GetCommittedBlockRange { .. }
            | CoordinatedConsensusMessage::CommittedBlock { .. }
            | CoordinatedConsensusMessage::CommittedBlockRange { .. } => None,
        };
        if expected_signer.is_some_and(|validator_id| validator_id != &peer.validator_id.0) {
            return Err(
                "coordinated consensus message sender is not its accountable validator".to_string(),
            );
        }
        Ok(())
    }

    fn validator(&self, validator_id: &str) -> Result<&ValidatorRecord, String> {
        self.active_validators.get(validator_id).ok_or_else(|| {
            format!(
                "coordinated consensus validator {validator_id} is not in the finalized active set"
            )
        })
    }

    /// Returns an active canonical validator record after the constructor has
    /// proven that the configured six-validator membership is exact.
    pub fn validator_record(&self, validator_id: &str) -> Result<&ValidatorRecord, String> {
        self.validator(validator_id)
    }

    /// Returns the exact active six-validator set that the constructor bound
    /// to this coordinated session. Callers receive a value, never mutable
    /// access to the verifier's canonical membership map.
    pub fn validator_set(&self) -> ValidatorSet {
        ValidatorSet {
            epoch: self.epoch,
            validators: self.active_validators.values().cloned().collect(),
        }
    }
}

/// Immutable configuration for the temporary testnet-only consensus mode.
///
/// Identities are canonical validator identities, never peer addresses, DNS
/// names, or positions in a runtime peer list.  The production loader must
/// derive these values from the finalized validator configuration before it
/// constructs a coordinator or producer worker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoordinatedRoundRobinConfig {
    pub chain_id: u64,
    pub network_id: String,
    pub consensus_version: String,
    pub coordinator_id: String,
    pub producer_ids: Vec<String>,
    pub target_block_interval_ms: u64,
    pub producer_turn_timeout_ms: u64,
}

impl CoordinatedRoundRobinConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.chain_id != 1266 {
            return Err(format!(
                "coordinated mode is restricted to Testnet-v3 chain 1266, found {}",
                self.chain_id
            ));
        }
        if self.network_id != "synergy-testnet-v3" {
            return Err(format!(
                "coordinated mode requires network_id synergy-testnet-v3, found {}",
                self.network_id
            ));
        }
        if self.consensus_version != COORDINATED_ROUND_ROBIN_V1 {
            return Err(format!(
                "unsupported coordinated consensus version {}",
                self.consensus_version
            ));
        }
        if self.coordinator_id.trim().is_empty() {
            return Err("coordinated mode coordinator identity is empty".to_string());
        }
        if self.producer_ids.len() != 5 {
            return Err(format!(
                "coordinated mode requires exactly five producer identities, found {}",
                self.producer_ids.len()
            ));
        }
        if self.target_block_interval_ms == 0 {
            return Err("coordinated mode target block interval must be positive".to_string());
        }
        if self.producer_turn_timeout_ms < self.target_block_interval_ms {
            return Err(
                "coordinated mode producer turn timeout must not be shorter than the target block interval"
                    .to_string(),
            );
        }

        let mut identities = self.producer_ids.clone();
        identities.push(self.coordinator_id.clone());
        if identities.iter().any(|identity| identity.trim().is_empty()) {
            return Err("coordinated mode contains an empty validator identity".to_string());
        }
        identities.sort();
        if identities.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(
                "coordinator and producer identities must be unique in coordinated mode"
                    .to_string(),
            );
        }
        Ok(())
    }

    pub fn producer_at(&self, cursor: usize) -> Result<&str, String> {
        self.producer_ids
            .get(cursor)
            .map(String::as_str)
            .ok_or_else(|| format!("coordinated mode producer cursor {cursor} is out of range"))
    }

    fn successor_cursor(&self, cursor: usize) -> usize {
        (cursor + 1) % self.producer_ids.len()
    }
}

/// The coordinator's one-time authorization for a producer to build one block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProducerAssignment {
    pub chain_id: u64,
    pub network_id: String,
    pub consensus_version: String,
    /// The finalized consensus epoch whose canonical validator keys authorize
    /// this assignment.  This prevents a valid prior-epoch assignment from
    /// being replayed after a validator-set transition.
    pub epoch: u64,
    pub height: u64,
    pub producer_round: u64,
    pub parent_block_hash: Hash,
    /// The prior finalized coordinated commit hash, or the immutable migration
    /// anchor for the first coordinated height. This is carried in the block's
    /// generic evidence root; the legacy QC header field remains zero.
    pub prior_finality_reference: Hash,
    pub assigned_producer_id: String,
    pub coordinator_id: String,
    pub assignment_sequence: u64,
    pub intended_block_timestamp_ms: u64,
    pub coordinator_signature: AegisPqSignature,
}

impl ProducerAssignment {
    pub fn signing_hash(&self) -> Result<Hash, String> {
        let payload = ProducerAssignmentPayload {
            chain_id: self.chain_id,
            network_id: self.network_id.clone(),
            consensus_version: self.consensus_version.clone(),
            epoch: self.epoch,
            height: self.height,
            producer_round: self.producer_round,
            parent_block_hash: self.parent_block_hash,
            prior_finality_reference: self.prior_finality_reference,
            assigned_producer_id: self.assigned_producer_id.clone(),
            coordinator_id: self.coordinator_id.clone(),
            assignment_sequence: self.assignment_sequence,
            intended_block_timestamp_ms: self.intended_block_timestamp_ms,
        };
        Ok(Hash::from_domain_bytes(
            COORDINATED_ASSIGNMENT_DOMAIN,
            &payload.canonical_bytes()?,
        ))
    }

    pub fn validate_shape(&self, config: &CoordinatedRoundRobinConfig) -> Result<(), String> {
        config.validate()?;
        if self.chain_id != config.chain_id
            || self.network_id != config.network_id
            || self.consensus_version != config.consensus_version
            || self.coordinator_id != config.coordinator_id
        {
            return Err(
                "producer assignment is bound to a different coordinated network".to_string(),
            );
        }
        if self.height == 0 {
            return Err("producer assignment cannot target genesis height zero".to_string());
        }
        if !config
            .producer_ids
            .iter()
            .any(|producer| producer == &self.assigned_producer_id)
        {
            return Err("producer assignment names a non-producer identity".to_string());
        }
        if !self.coordinator_signature.is_present() {
            return Err("producer assignment lacks a coordinator signature".to_string());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ProducerAssignmentPayload {
    chain_id: u64,
    network_id: String,
    consensus_version: String,
    epoch: u64,
    height: u64,
    producer_round: u64,
    parent_block_hash: Hash,
    prior_finality_reference: Hash,
    assigned_producer_id: String,
    coordinator_id: String,
    assignment_sequence: u64,
    intended_block_timestamp_ms: u64,
}

/// A producer-signed proposal after the caller has validated its signature.
/// The coordinator state machine verifies the assignment and all deterministic
/// bindings; the runtime performs canonical block execution before creating a
/// [`CoordinatorCommit`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoordinatedProposal {
    pub epoch: u64,
    pub height: u64,
    pub producer_round: u64,
    pub parent_block_hash: Hash,
    pub prior_finality_reference: Hash,
    pub block_hash: Hash,
    pub transaction_root: Hash,
    pub receipt_root: Hash,
    pub state_root: Hash,
    pub producer_id: String,
    pub assignment_hash: Hash,
    pub producer_signature: AegisPqSignature,
}

impl CoordinatedProposal {
    pub fn validate_shape(&self) -> Result<(), String> {
        if self.height == 0 {
            return Err("coordinated proposal cannot target genesis height zero".to_string());
        }
        if self.producer_id.trim().is_empty() {
            return Err("coordinated proposal producer identity is empty".to_string());
        }
        if !self.producer_signature.is_present() {
            return Err("coordinated proposal lacks a producer signature".to_string());
        }
        Ok(())
    }
}

/// The sole finality proof in coordinated mode.  It is a coordinator signature
/// over one producer-authorized, fully executed block -- not a QC and not a
/// substitute certificate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoordinatorCommit {
    pub chain_id: u64,
    pub network_id: String,
    pub consensus_version: String,
    pub epoch: u64,
    pub height: u64,
    pub producer_round: u64,
    pub parent_block_hash: Hash,
    pub prior_finality_reference: Hash,
    pub block_hash: Hash,
    pub transaction_root: Hash,
    pub receipt_root: Hash,
    pub state_root: Hash,
    pub producer_id: String,
    pub coordinator_id: String,
    pub assignment_hash: Hash,
    pub coordinator_signature: AegisPqSignature,
}

impl CoordinatorCommit {
    pub fn signing_hash(&self) -> Result<Hash, String> {
        let payload = CoordinatorCommitPayload {
            chain_id: self.chain_id,
            network_id: self.network_id.clone(),
            consensus_version: self.consensus_version.clone(),
            epoch: self.epoch,
            height: self.height,
            producer_round: self.producer_round,
            parent_block_hash: self.parent_block_hash,
            prior_finality_reference: self.prior_finality_reference,
            block_hash: self.block_hash,
            transaction_root: self.transaction_root,
            receipt_root: self.receipt_root,
            state_root: self.state_root,
            producer_id: self.producer_id.clone(),
            coordinator_id: self.coordinator_id.clone(),
            assignment_hash: self.assignment_hash,
        };
        Ok(Hash::from_domain_bytes(
            COORDINATED_COMMIT_DOMAIN,
            &payload.canonical_bytes()?,
        ))
    }

    pub fn validate_shape(&self, config: &CoordinatedRoundRobinConfig) -> Result<(), String> {
        config.validate()?;
        if self.chain_id != config.chain_id
            || self.network_id != config.network_id
            || self.consensus_version != config.consensus_version
            || self.coordinator_id != config.coordinator_id
        {
            return Err(
                "coordinator commit is bound to a different coordinated network".to_string(),
            );
        }
        if self.height == 0 {
            return Err("coordinator commit cannot target genesis height zero".to_string());
        }
        if !config
            .producer_ids
            .iter()
            .any(|producer| producer == &self.producer_id)
        {
            return Err("coordinator commit names a non-producer identity".to_string());
        }
        if !self.coordinator_signature.is_present() {
            return Err("coordinator commit lacks a coordinator signature".to_string());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CoordinatorCommitPayload {
    chain_id: u64,
    network_id: String,
    consensus_version: String,
    epoch: u64,
    height: u64,
    producer_round: u64,
    parent_block_hash: Hash,
    prior_finality_reference: Hash,
    block_hash: Hash,
    transaction_root: Hash,
    receipt_root: Hash,
    state_root: Hash,
    producer_id: String,
    coordinator_id: String,
    assignment_hash: Hash,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProducerTurnMissed {
    pub height: u64,
    pub producer_round: u64,
    pub producer_id: String,
    pub reason: String,
}

/// Crash-recoverable coordinator state.  The caller must atomically persist
/// this object before sending assignments or commits; [`CoordinatorStateStore`]
/// provides that persistence boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoordinatorState {
    pub state_version: u32,
    pub last_finalized_height: u64,
    pub last_finalized_block_hash: Hash,
    pub last_finality_reference: Hash,
    pub pending_height: Option<u64>,
    pub pending_round: u64,
    pub pending_producer_id: Option<String>,
    pub producer_cursor: usize,
    pub pending_assignment_hash: Option<Hash>,
    pub pending_assignment: Option<ProducerAssignment>,
    pub committed_block_hash_for_pending_height: Option<Hash>,
    pub last_commit: Option<CoordinatorCommit>,
    pub assignment_sequence: u64,
    /// A durable single-subject journal.  A height can map to exactly one block
    /// hash; replays of that exact hash are idempotent and alternates are
    /// rejected before a second coordinator signature can be broadcast.
    pub signer_journal: BTreeMap<u64, Hash>,
    pub missed_turns: Vec<ProducerTurnMissed>,
}

impl CoordinatorState {
    pub fn new(last_finalized_height: u64, last_finalized_block_hash: Hash) -> Self {
        Self {
            state_version: COORDINATOR_STATE_VERSION,
            last_finalized_height,
            last_finalized_block_hash,
            last_finality_reference: Hash::from_domain_bytes(
                "SYNERGY_COORDINATED_MIGRATION_ANCHOR_V1",
                &last_finalized_block_hash.0,
            ),
            pending_height: None,
            pending_round: 0,
            pending_producer_id: None,
            producer_cursor: 0,
            pending_assignment_hash: None,
            pending_assignment: None,
            committed_block_hash_for_pending_height: None,
            last_commit: None,
            assignment_sequence: 0,
            signer_journal: BTreeMap::new(),
            missed_turns: Vec::new(),
        }
    }

    pub fn next_height(&self) -> u64 {
        self.last_finalized_height.saturating_add(1)
    }

    /// Constructs state from the exact verified predecessor at activation.
    /// The supplied reference is the migration proof anchor, not a synthetic
    /// QC; every successor is then bound to the prior coordinator commit.
    pub fn from_migration_anchor(
        last_finalized_height: u64,
        last_finalized_block_hash: Hash,
        last_finality_reference: Hash,
    ) -> Result<Self, String> {
        if last_finality_reference.is_zero() {
            return Err("coordinated migration finality reference cannot be zero".to_string());
        }
        let mut state = Self::new(last_finalized_height, last_finalized_block_hash);
        state.last_finality_reference = last_finality_reference;
        Ok(state)
    }

    pub fn issue_assignment(
        &mut self,
        config: &CoordinatedRoundRobinConfig,
        epoch: u64,
        intended_block_timestamp_ms: u64,
        coordinator_signature: AegisPqSignature,
    ) -> Result<ProducerAssignment, String> {
        config.validate()?;
        if let Some(assignment) = &self.pending_assignment {
            if self.committed_block_hash_for_pending_height.is_none() {
                return Ok(assignment.clone());
            }
        }
        if !coordinator_signature.is_present() {
            return Err(
                "cannot issue a producer assignment without a coordinator signature".to_string(),
            );
        }
        let mut assignment =
            self.assignment_template(config, epoch, intended_block_timestamp_ms)?;
        let height = assignment.height;
        let producer_id = assignment.assigned_producer_id.clone();
        assignment.coordinator_signature = coordinator_signature;
        assignment.validate_shape(config)?;
        let assignment_hash = assignment.signing_hash()?;
        self.pending_height = Some(height);
        self.pending_producer_id = Some(producer_id);
        self.pending_assignment_hash = Some(assignment_hash);
        self.pending_assignment = Some(assignment.clone());
        self.committed_block_hash_for_pending_height = None;
        self.assignment_sequence = assignment.assignment_sequence;
        Ok(assignment)
    }

    /// Returns the exact next assignment subject before it is signed.  The
    /// timestamp is supplied by the deterministic block-context provider, not
    /// by a wall clock, so a restart can recover the same durable subject.
    pub fn assignment_template(
        &self,
        config: &CoordinatedRoundRobinConfig,
        epoch: u64,
        intended_block_timestamp_ms: u64,
    ) -> Result<ProducerAssignment, String> {
        config.validate()?;
        if let Some(assignment) = &self.pending_assignment {
            if self.committed_block_hash_for_pending_height.is_none() {
                if assignment.epoch != epoch
                    || assignment.intended_block_timestamp_ms != intended_block_timestamp_ms
                {
                    return Err(
                        "pending coordinated assignment does not match the deterministic signing context"
                            .to_string(),
                    );
                }
                return Ok(assignment.clone());
            }
        }
        Ok(ProducerAssignment {
            chain_id: config.chain_id,
            network_id: config.network_id.clone(),
            consensus_version: config.consensus_version.clone(),
            epoch,
            height: self.next_height(),
            producer_round: self.pending_round,
            parent_block_hash: self.last_finalized_block_hash,
            prior_finality_reference: self.last_finality_reference,
            assigned_producer_id: config.producer_at(self.producer_cursor)?.to_string(),
            coordinator_id: config.coordinator_id.clone(),
            assignment_sequence: self.assignment_sequence.saturating_add(1),
            intended_block_timestamp_ms,
            coordinator_signature: AegisPqSignature {
                algorithm: String::new(),
                signature_bytes: Vec::new(),
            },
        })
    }

    /// Records a timeout or an invalid proposal.  This never advances the
    /// block height; it only advances the persistent producer cursor and round
    /// for a replacement assignment at the same height.
    pub fn mark_producer_turn_missed(
        &mut self,
        config: &CoordinatedRoundRobinConfig,
        reason: impl Into<String>,
    ) -> Result<ProducerTurnMissed, String> {
        config.validate()?;
        let assignment = self.pending_assignment.as_ref().ok_or_else(|| {
            "cannot miss a producer turn without a pending assignment".to_string()
        })?;
        if self.committed_block_hash_for_pending_height.is_some() {
            return Err("cannot skip a producer after its block was committed".to_string());
        }
        let missed = ProducerTurnMissed {
            height: assignment.height,
            producer_round: assignment.producer_round,
            producer_id: assignment.assigned_producer_id.clone(),
            reason: reason.into(),
        };
        self.missed_turns.push(missed.clone());
        self.producer_cursor = config.successor_cursor(self.producer_cursor);
        self.pending_round = self.pending_round.saturating_add(1);
        self.pending_height = None;
        self.pending_producer_id = None;
        self.pending_assignment_hash = None;
        self.pending_assignment = None;
        Ok(missed)
    }

    pub fn prepare_commit(
        &self,
        config: &CoordinatedRoundRobinConfig,
        proposal: &CoordinatedProposal,
        coordinator_signature: AegisPqSignature,
    ) -> Result<CoordinatorCommit, String> {
        config.validate()?;
        proposal.validate_shape()?;
        if !coordinator_signature.is_present() {
            return Err("cannot commit a block without a coordinator signature".to_string());
        }
        let mut commit = self.commit_template(config, proposal)?;
        commit.coordinator_signature = coordinator_signature;
        commit.validate_shape(config)?;
        Ok(commit)
    }

    /// Returns the exact coordinator-commit subject before its single Val1
    /// signature is created and durably journaled.
    pub fn commit_template(
        &self,
        config: &CoordinatedRoundRobinConfig,
        proposal: &CoordinatedProposal,
    ) -> Result<CoordinatorCommit, String> {
        config.validate()?;
        proposal.validate_shape()?;
        let assignment = self.current_assignment(config)?;
        let assignment_hash = assignment.signing_hash()?;
        if proposal.epoch != assignment.epoch
            || proposal.height != assignment.height
            || proposal.producer_round != assignment.producer_round
            || proposal.parent_block_hash != assignment.parent_block_hash
            || proposal.prior_finality_reference != assignment.prior_finality_reference
            || proposal.producer_id != assignment.assigned_producer_id
            || proposal.assignment_hash != assignment_hash
        {
            return Err(
                "proposal does not match the current signed producer assignment".to_string(),
            );
        }
        if let Some(recorded_hash) = self.signer_journal.get(&proposal.height) {
            if *recorded_hash != proposal.block_hash {
                return Err(
                    "coordinator signer journal refuses a conflicting block hash at this height"
                        .to_string(),
                );
            }
        }
        Ok(CoordinatorCommit {
            chain_id: config.chain_id,
            network_id: config.network_id.clone(),
            consensus_version: config.consensus_version.clone(),
            epoch: proposal.epoch,
            height: proposal.height,
            producer_round: proposal.producer_round,
            parent_block_hash: proposal.parent_block_hash,
            prior_finality_reference: proposal.prior_finality_reference,
            block_hash: proposal.block_hash,
            transaction_root: proposal.transaction_root,
            receipt_root: proposal.receipt_root,
            state_root: proposal.state_root,
            producer_id: proposal.producer_id.clone(),
            coordinator_id: config.coordinator_id.clone(),
            assignment_hash,
            coordinator_signature: AegisPqSignature {
                algorithm: String::new(),
                signature_bytes: Vec::new(),
            },
        })
    }

    /// Persists the one allowed commitment subject in memory.  Callers must
    /// atomically write the updated state before broadcasting this commit.
    pub fn record_commit(
        &mut self,
        config: &CoordinatedRoundRobinConfig,
        commit: CoordinatorCommit,
    ) -> Result<bool, String> {
        commit.validate_shape(config)?;
        if let Some(existing) = self.signer_journal.get(&commit.height) {
            if *existing == commit.block_hash {
                return Ok(false);
            }
            return Err(
                "coordinator signer journal refuses a second block hash at one height".to_string(),
            );
        }
        let assignment = self.current_assignment(config)?;
        let assignment_hash = assignment.signing_hash()?;
        if commit.epoch != assignment.epoch
            || commit.height != assignment.height
            || commit.producer_round != assignment.producer_round
            || commit.parent_block_hash != assignment.parent_block_hash
            || commit.prior_finality_reference != assignment.prior_finality_reference
            || commit.producer_id != assignment.assigned_producer_id
            || commit.assignment_hash != assignment_hash
        {
            return Err("coordinator commit does not match the current assignment".to_string());
        }

        let finality_reference = commit.signing_hash()?;
        self.signer_journal.insert(commit.height, commit.block_hash);
        self.committed_block_hash_for_pending_height = Some(commit.block_hash);
        self.last_finalized_height = commit.height;
        self.last_finalized_block_hash = commit.block_hash;
        self.last_finality_reference = finality_reference;
        self.last_commit = Some(commit);
        self.producer_cursor = config.successor_cursor(self.producer_cursor);
        self.pending_height = None;
        self.pending_round = 0;
        self.pending_producer_id = None;
        self.pending_assignment_hash = None;
        self.pending_assignment = None;
        self.committed_block_hash_for_pending_height = None;
        Ok(true)
    }

    pub fn validate(&self, config: &CoordinatedRoundRobinConfig) -> Result<(), String> {
        config.validate()?;
        if self.state_version != COORDINATOR_STATE_VERSION {
            return Err(format!(
                "unsupported coordinated coordinator state version {}",
                self.state_version
            ));
        }
        if self.producer_cursor >= config.producer_ids.len() {
            return Err("coordinated coordinator state has an invalid producer cursor".to_string());
        }
        if self.last_finality_reference.is_zero() {
            return Err("coordinated coordinator state has no finality reference".to_string());
        }
        match &self.pending_assignment {
            Some(assignment) => {
                assignment.validate_shape(config)?;
                if self.pending_height != Some(assignment.height)
                    || self.pending_round != assignment.producer_round
                    || self.pending_producer_id.as_deref()
                        != Some(assignment.assigned_producer_id.as_str())
                    || self.pending_assignment_hash != Some(assignment.signing_hash()?)
                    || assignment.height != self.next_height()
                {
                    return Err(
                        "coordinated coordinator pending state is internally inconsistent"
                            .to_string(),
                    );
                }
            }
            None => {
                if self.pending_height.is_some()
                    || self.pending_producer_id.is_some()
                    || self.pending_assignment_hash.is_some()
                {
                    return Err("coordinated coordinator has incomplete pending state".to_string());
                }
            }
        }
        if let Some(commit) = &self.last_commit {
            commit.validate_shape(config)?;
            if commit.height != self.last_finalized_height
                || commit.block_hash != self.last_finalized_block_hash
                || self.signer_journal.get(&commit.height) != Some(&commit.block_hash)
            {
                return Err(
                    "coordinated coordinator last commit is inconsistent with its signer journal"
                        .to_string(),
                );
            }
        }
        Ok(())
    }

    fn current_assignment(
        &self,
        config: &CoordinatedRoundRobinConfig,
    ) -> Result<&ProducerAssignment, String> {
        let assignment = self
            .pending_assignment
            .as_ref()
            .ok_or_else(|| "no producer assignment is pending".to_string())?;
        assignment.validate_shape(config)?;
        if self.pending_height != Some(assignment.height)
            || self.pending_round != assignment.producer_round
            || self.pending_producer_id.as_deref() != Some(assignment.assigned_producer_id.as_str())
            || self.pending_assignment_hash != Some(assignment.signing_hash()?)
            || assignment.height != self.next_height()
        {
            return Err(
                "coordinated producer assignment does not match persisted state".to_string(),
            );
        }
        Ok(assignment)
    }
}

/// File-backed, atomically replaced coordinator state.  It is separate from
/// the typed PoSy finality/QC store so coordinated mode never treats a QC as a
/// finality proof or imports old certificate state on restart.
#[derive(Debug, Clone)]
pub struct CoordinatorStateStore {
    path: PathBuf,
}

impl CoordinatorStateStore {
    pub fn at_path(path: impl Into<PathBuf>) -> Result<Self, String> {
        let path = path.into();
        if path.as_os_str().is_empty() {
            return Err("coordinator state path is empty".to_string());
        }
        Ok(Self { path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn load(
        &self,
        config: &CoordinatedRoundRobinConfig,
    ) -> Result<Option<CoordinatorState>, String> {
        match fs::read(&self.path) {
            Ok(bytes) => {
                let state: CoordinatorState = serde_json::from_slice(&bytes)
                    .map_err(|error| format!("decode coordinated coordinator state: {error}"))?;
                state.validate(config)?;
                Ok(Some(state))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(format!(
                "read coordinated coordinator state {}: {error}",
                self.path.display()
            )),
        }
    }

    pub fn persist(
        &self,
        config: &CoordinatedRoundRobinConfig,
        state: &CoordinatorState,
    ) -> Result<(), String> {
        state.validate(config)?;
        let parent = self.path.parent().ok_or_else(|| {
            format!(
                "coordinated coordinator state path has no parent: {}",
                self.path.display()
            )
        })?;
        fs::create_dir_all(parent).map_err(|error| {
            format!(
                "create coordinated coordinator state directory {}: {error}",
                parent.display()
            )
        })?;
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| format!("read clock for coordinated state persistence: {error}"))?
            .as_nanos();
        let temporary = parent.join(format!(
            ".{}.{}.tmp",
            self.path
                .file_name()
                .and_then(|value| value.to_str())
                .unwrap_or("coordinator-state"),
            nonce
        ));
        let bytes = serde_json::to_vec(state)
            .map_err(|error| format!("encode coordinated coordinator state: {error}"))?;
        let write_result = (|| -> Result<(), String> {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temporary)
                .map_err(|error| {
                    format!(
                        "create temporary coordinated coordinator state {}: {error}",
                        temporary.display()
                    )
                })?;
            file.write_all(&bytes).map_err(|error| {
                format!(
                    "write temporary coordinated coordinator state {}: {error}",
                    temporary.display()
                )
            })?;
            file.sync_all().map_err(|error| {
                format!(
                    "sync temporary coordinated coordinator state {}: {error}",
                    temporary.display()
                )
            })?;
            fs::rename(&temporary, &self.path).map_err(|error| {
                format!(
                    "replace coordinated coordinator state {}: {error}",
                    self.path.display()
                )
            })?;
            File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(|error| {
                    format!(
                        "sync coordinated coordinator state directory {}: {error}",
                        parent.display()
                    )
                })?;
            Ok(())
        })();
        if write_result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        write_result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::aegis_pqvm::AegisPqvmSigner;
    use crate::synergy_types::{AegisPqKeyRole, ClusterId, Epoch, ValidatorStatus};
    use std::env;

    fn hash(label: &str) -> Hash {
        Hash::from_domain_bytes("COORDINATED_ROUND_ROBIN_TEST", label.as_bytes())
    }

    fn signature(label: &str) -> AegisPqSignature {
        AegisPqSignature {
            algorithm: "ML-DSA-65".to_string(),
            signature_bytes: label.as_bytes().to_vec(),
        }
    }

    fn config() -> CoordinatedRoundRobinConfig {
        CoordinatedRoundRobinConfig {
            chain_id: 1266,
            network_id: "synergy-testnet-v3".to_string(),
            consensus_version: COORDINATED_ROUND_ROBIN_V1.to_string(),
            coordinator_id: "validator-1".to_string(),
            producer_ids: vec![
                "validator-2".to_string(),
                "validator-3".to_string(),
                "validator-4".to_string(),
                "validator-5".to_string(),
                "validator-6".to_string(),
            ],
            target_block_interval_ms: 2_000,
            producer_turn_timeout_ms: 4_000,
        }
    }

    fn authenticated_peer() -> AuthenticatedCoordinatedConsensusPeer {
        AuthenticatedCoordinatedConsensusPeer {
            validator_id: ValidatorId("validator-2".to_string()),
            validator_uma_id: UmaId("uma-validator-2".to_string()),
            consensus_key_id: AegisPqKeyId("validator-2-consensus-key".to_string()),
        }
    }

    fn assignment_message() -> CoordinatedConsensusMessage {
        CoordinatedConsensusMessage::ProducerAssignment {
            assignment: ProducerAssignment {
                chain_id: 1266,
                network_id: "synergy-testnet-v3".to_string(),
                consensus_version: COORDINATED_ROUND_ROBIN_V1.to_string(),
                epoch: 0,
                height: 1,
                producer_round: 0,
                parent_block_hash: hash("genesis"),
                prior_finality_reference: hash("migration-anchor"),
                assigned_producer_id: "validator-2".to_string(),
                coordinator_id: "validator-1".to_string(),
                assignment_sequence: 1,
                intended_block_timestamp_ms: 1_000,
                coordinator_signature: signature("assignment"),
            },
        }
    }

    fn cryptographic_verifier_fixture() -> (
        AegisPqvmSigner,
        CoordinatedConsensusVerifier,
        AegisPqKeyId,
        AuthenticatedCoordinatedConsensusPeer,
        AuthenticatedCoordinatedConsensusPeer,
    ) {
        let mut signer = AegisPqvmSigner::initialize_required().expect("Aegis signer");
        let mut validators = Vec::new();
        let mut coordinator_key_id = None;
        let mut coordinator_peer = None;
        let mut producer_peer = None;
        for index in 1..=6 {
            let validator_id = ValidatorId(format!("validator-{index}"));
            let uma_id = UmaId(format!("uma-validator-{index}"));
            let key_id = signer
                .generate_and_register_key(
                    &uma_id.0,
                    vec![AegisPqKeyRole::ConsensusProposer],
                    Epoch(0),
                )
                .expect("register test consensus key");
            let public_key = signer
                .public_key_record(&key_id)
                .expect("registered public consensus key");
            let peer = AuthenticatedCoordinatedConsensusPeer {
                validator_id: validator_id.clone(),
                validator_uma_id: uma_id.clone(),
                consensus_key_id: key_id.clone(),
            };
            if index == 1 {
                coordinator_key_id = Some(key_id.clone());
                coordinator_peer = Some(peer.clone());
            }
            if index == 2 {
                producer_peer = Some(peer.clone());
            }
            validators.push(ValidatorRecord {
                validator_id,
                validator_uma_id: uma_id,
                consensus_public_key: public_key.clone(),
                peer_public_key: public_key.clone(),
                operator_public_key: public_key,
                voting_weight: 1,
                status: ValidatorStatus::Active,
                cluster_id: ClusterId(0),
                activation_epoch: Epoch(0),
            });
        }
        let verifier = CoordinatedConsensusVerifier::new(
            config(),
            &ValidatorSet {
                epoch: Epoch(0),
                validators,
            },
            signer.verifier(),
        )
        .expect("coordinated verifier from canonical active set");
        (
            signer,
            verifier,
            coordinator_key_id.expect("coordinator key"),
            coordinator_peer.expect("coordinator peer"),
            producer_peer.expect("producer peer"),
        )
    }

    #[test]
    fn assignments_require_the_canonical_coordinator_key_and_epoch() {
        let (mut signer, verifier, coordinator_key_id, coordinator_peer, producer_peer) =
            cryptographic_verifier_fixture();
        let CoordinatedConsensusMessage::ProducerAssignment { mut assignment } =
            assignment_message()
        else {
            unreachable!("fixture creates an assignment")
        };
        assignment.coordinator_signature = signer
            .sign_domain(
                COORDINATED_ASSIGNMENT_DOMAIN,
                &assignment.signing_hash().expect("assignment hash").0,
                &coordinator_key_id,
            )
            .expect("sign assignment with Val1 consensus key");

        verifier
            .verify_assignment(&assignment)
            .expect("Val1 assignment verifies against finalized keys");
        verifier
            .verify_message_sender(
                &coordinator_peer,
                &CoordinatedConsensusMessage::ProducerAssignment {
                    assignment: assignment.clone(),
                },
            )
            .expect("Val1 is the accountable assignment sender");
        assert!(verifier
            .verify_message_sender(
                &producer_peer,
                &CoordinatedConsensusMessage::ProducerAssignment {
                    assignment: assignment.clone(),
                },
            )
            .is_err());

        assignment.epoch = 1;
        assert!(verifier.verify_assignment(&assignment).is_err());
    }

    #[test]
    fn coordinated_messages_fail_closed_without_a_running_worker() {
        let _ = remove_coordinated_consensus_ingress();
        let error = dispatch_coordinated_consensus_message(
            "validator-2-peer",
            Some(authenticated_peer()),
            assignment_message(),
        )
        .expect_err("a coordinated message must not use a legacy fallback");
        assert!(error.contains("coordinator is not running"));
    }

    #[test]
    fn coordinated_messages_require_an_authenticated_session_and_dedicated_mailbox() {
        let _ = remove_coordinated_consensus_ingress();
        let receiver = install_coordinated_consensus_ingress(1).expect("install mailbox");
        let unauthenticated =
            dispatch_coordinated_consensus_message("unknown-peer", None, assignment_message())
                .expect_err("unauthenticated P2P traffic must not reach the worker");
        assert!(unauthenticated.contains("authenticated validator identity"));

        dispatch_coordinated_consensus_message(
            "validator-2-peer",
            Some(authenticated_peer()),
            assignment_message(),
        )
        .expect("authenticated traffic reaches the dedicated mailbox");
        let envelope = receiver.try_recv().expect("mailbox delivery");
        assert_eq!(envelope.peer_address, "validator-2-peer");
        assert_eq!(envelope.authenticated_peer.validator_id.0, "validator-2");
        assert!(matches!(
            envelope.message,
            CoordinatedConsensusMessage::ProducerAssignment { .. }
        ));
        remove_coordinated_consensus_ingress().expect("remove mailbox");
    }

    fn commit_current(
        state: &mut CoordinatorState,
        config: &CoordinatedRoundRobinConfig,
        block: &str,
    ) -> CoordinatorCommit {
        let assignment = state
            .issue_assignment(config, 0, 1_000, signature("assignment"))
            .expect("assignment should issue");
        let proposal = CoordinatedProposal {
            epoch: assignment.epoch,
            height: assignment.height,
            producer_round: assignment.producer_round,
            parent_block_hash: assignment.parent_block_hash,
            prior_finality_reference: assignment.prior_finality_reference,
            block_hash: hash(block),
            transaction_root: hash("tx"),
            receipt_root: hash("receipt"),
            state_root: hash("state"),
            producer_id: assignment.assigned_producer_id.clone(),
            assignment_hash: assignment.signing_hash().expect("assignment hashes"),
            producer_signature: signature("producer"),
        };
        let commit = state
            .prepare_commit(config, &proposal, signature("commit"))
            .expect("commit should prepare");
        assert!(state
            .record_commit(config, commit.clone())
            .expect("commit should record"));
        commit
    }

    #[test]
    fn five_producers_rotate_strictly_after_successful_blocks() {
        let config = config();
        let mut state = CoordinatorState::new(0, hash("genesis"));
        let mut producers = Vec::new();
        for index in 0..10 {
            let commit = commit_current(&mut state, &config, &format!("block-{index}"));
            producers.push(commit.producer_id);
        }
        assert_eq!(
            producers,
            vec![
                "validator-2",
                "validator-3",
                "validator-4",
                "validator-5",
                "validator-6",
                "validator-2",
                "validator-3",
                "validator-4",
                "validator-5",
                "validator-6",
            ]
        );
        assert_eq!(state.last_finalized_height, 10);
    }

    #[test]
    fn missed_turn_advances_producer_not_block_height() {
        let config = config();
        let mut state = CoordinatorState::new(99, hash("parent"));
        let first = state
            .issue_assignment(&config, 0, 100, signature("assignment-1"))
            .expect("first assignment");
        assert_eq!(first.height, 100);
        assert_eq!(first.assigned_producer_id, "validator-2");
        let missed = state
            .mark_producer_turn_missed(&config, "timeout")
            .expect("turn can be missed");
        assert_eq!(missed.height, 100);
        assert_eq!(state.last_finalized_height, 99);
        let replacement = state
            .issue_assignment(&config, 0, 200, signature("assignment-2"))
            .expect("replacement assignment");
        assert_eq!(replacement.height, 100);
        assert_eq!(replacement.producer_round, 1);
        assert_eq!(replacement.assigned_producer_id, "validator-3");

        let proposal = CoordinatedProposal {
            epoch: replacement.epoch,
            height: replacement.height,
            producer_round: replacement.producer_round,
            parent_block_hash: replacement.parent_block_hash,
            prior_finality_reference: replacement.prior_finality_reference,
            block_hash: hash("height-100"),
            transaction_root: hash("tx"),
            receipt_root: hash("receipt"),
            state_root: hash("state"),
            producer_id: replacement.assigned_producer_id.clone(),
            assignment_hash: replacement.signing_hash().expect("assignment hashes"),
            producer_signature: signature("producer"),
        };
        let commit = state
            .prepare_commit(&config, &proposal, signature("commit"))
            .expect("replacement proposal should commit");
        state
            .record_commit(&config, commit)
            .expect("replacement commit records");
        let next = state
            .issue_assignment(&config, 0, 300, signature("assignment-3"))
            .expect("next assignment");
        assert_eq!(next.height, 101);
        assert_eq!(next.assigned_producer_id, "validator-4");
    }

    #[test]
    fn coordinator_cannot_commit_two_hashes_at_one_height() {
        let config = config();
        let mut state = CoordinatorState::new(0, hash("genesis"));
        let commit = commit_current(&mut state, &config, "canonical");
        assert!(!state
            .record_commit(&config, commit.clone())
            .expect("exact duplicate is idempotent"));

        let mut conflict = commit;
        conflict.block_hash = hash("conflict");
        assert!(state.record_commit(&config, conflict).is_err());
    }

    #[test]
    fn stale_producer_round_is_rejected_after_missed_turn() {
        let config = config();
        let mut state = CoordinatorState::new(20, hash("parent"));
        let stale = state
            .issue_assignment(&config, 0, 100, signature("assignment-1"))
            .expect("assignment issues");
        state
            .mark_producer_turn_missed(&config, "producer offline")
            .expect("turn can be missed");
        let _replacement = state
            .issue_assignment(&config, 0, 200, signature("assignment-2"))
            .expect("replacement issues");
        let stale_proposal = CoordinatedProposal {
            epoch: stale.epoch,
            height: stale.height,
            producer_round: stale.producer_round,
            parent_block_hash: stale.parent_block_hash,
            prior_finality_reference: stale.prior_finality_reference,
            block_hash: hash("stale"),
            transaction_root: hash("tx"),
            receipt_root: hash("receipt"),
            state_root: hash("state"),
            producer_id: stale.assigned_producer_id.clone(),
            assignment_hash: stale.signing_hash().expect("assignment hashes"),
            producer_signature: signature("producer"),
        };
        assert!(state
            .prepare_commit(&config, &stale_proposal, signature("commit"))
            .is_err());
    }

    #[test]
    fn state_persists_and_recovers_pending_assignment_without_resetting_cursor() {
        let config = config();
        let unique = format!(
            "synergy-coordinated-state-{}-{}.json",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        );
        let path = env::temp_dir().join(unique);
        let store = CoordinatorStateStore::at_path(&path).expect("store path");
        let mut state = CoordinatorState::new(40, hash("parent"));
        let assignment = state
            .issue_assignment(&config, 0, 123, signature("assignment"))
            .expect("assignment issues");
        store.persist(&config, &state).expect("state persists");
        let recovered = store
            .load(&config)
            .expect("state reloads")
            .expect("state exists");
        assert_eq!(recovered.pending_assignment, Some(assignment));
        assert_eq!(recovered.producer_cursor, 0);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn configuration_requires_one_coordinator_and_five_distinct_producers() {
        let mut invalid = config();
        invalid.producer_ids.pop();
        assert!(invalid.validate().is_err());
        let mut duplicate = config();
        duplicate.producer_ids[0] = duplicate.coordinator_id.clone();
        assert!(duplicate.validate().is_err());
    }
}
