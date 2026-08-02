use serde::{Deserialize, Serialize};

use crate::block::{Block, BlockHeader};
use crate::consensus::coordinated_admission::{
    coordinated_dag_frontier_root, coordinated_transaction_admission_root,
};
use crate::consensus::coordinated_round_robin::{
    CoordinatedProposal, CoordinatedRoundRobinConfig, CoordinatorCommit, ProducerAssignment,
};
use crate::consensus::dual_quorum::{QuorumCertificate, Vote};
use crate::consensus::typed_finality_store::TypedFinalityRecord;
use crate::dag_mempool::compute_tx_order_root;
use crate::etdag::{CertifiedProtectedInputArtifact, ProtectedBlockInput, TargetAdmissionContext};
use crate::synergy_types::AegisPqSignature;
use crate::synergy_types::{
    Block as TypedBlock, CanonicalSerialize, Hash, HeightConsensusContext,
    QuorumCertificate as TypedQuorumCertificate, TimeoutCertificate, TxId, ValidationCertificate,
    Vote as TypedVote,
};
use crate::transaction::Transaction;

/// Testnet-v3 bounds for a complete canonical typed-consensus P2P frame.
///
/// These are transport and verification budgets, not PoSy timeouts or Genesis
/// consensus parameters.  The frame calculation includes the typed envelope
/// and four-byte P2P length prefix, so the caps apply to exactly what a peer
/// sends rather than to a partial in-memory field.
pub const MAX_TYPED_CONSENSUS_CERTIFICATE_FRAME_BYTES: usize = 128 * 1024;
pub const MAX_TYPED_CONSENSUS_PROPOSAL_FRAME_BYTES: usize = 8 * 1024 * 1024;
/// A recovery response carries both a full ML-DSA-65 VC and TC plus the core
/// block. It is still tightly bounded, but necessarily larger than one
/// certificate frame.
pub const MAX_TYPED_PREPARED_RECOVERY_FRAME_BYTES: usize = 256 * 1024;
/// Bounded replay of already-verified typed finality. Recipients replay each
/// record through normal core-proposal and QC verification before persistence.
pub const MAX_TYPED_FINALITY_CHECKPOINT_FRAME_BYTES: usize = 4 * 1024 * 1024;
/// Core-only proposals are deterministic empty blocks while ETDAG is deferred,
/// so they receive the tighter certificate-sized transport budget rather than
/// the ETDAG package allowance.
pub const MAX_TYPED_CONSENSUS_CORE_PROPOSAL_FRAME_BYTES: usize = 128 * 1024;
/// Coordinated-mode packages contain the canonical block plus one assignment
/// and one coordinator commit. They must remain bounded independently from
/// the retired PoSy certificate transport budgets.
pub const MAX_COORDINATED_CONSENSUS_ASSIGNMENT_FRAME_BYTES: usize = 128 * 1024;
pub const MAX_COORDINATED_CONSENSUS_BLOCK_PACKAGE_FRAME_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_COORDINATED_CONSENSUS_SYNC_RANGE_FRAME_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_COORDINATED_CONSENSUS_SYNC_RANGE_BLOCKS: usize = 64;

/// The only wire representation for the typed PoSy v2.2 state machine.
///
/// This is deliberately separate from the inherited `Block`/`Vote` variants
/// below. A peer must not be able to reinterpret legacy messages as typed
/// certificates, and every typed proposal carries the exact immutable context
/// it will be checked against before any vote or finality action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TypedConsensusMessage {
    /// The only typed proposal accepted before ETDAG activation.  The block
    /// itself must be a deterministic empty core block; coordinator validation
    /// rejects any transaction payload, protected batch, or ETDAG commitment.
    CoreProposal {
        height_context: HeightConsensusContext,
        block: TypedBlock,
    },
    Proposal {
        height_context: HeightConsensusContext,
        target_context: TargetAdmissionContext,
        protected_block: ProtectedBlockInput,
        block: TypedBlock,
    },
    Vote {
        vote: TypedVote,
    },
    ValidationCertificate {
        certificate: ValidationCertificate,
    },
    QuorumCertificate {
        certificate: TypedQuorumCertificate,
    },
    TimeoutCertificate {
        certificate: TimeoutCertificate,
    },
    /// Requests the exact verified proposal and VC named by a live TC.  The TC
    /// is included so responders never select recovery material from an
    /// unauthenticated candidate identifier.
    PreparedCertificateRequest {
        timeout_certificate: TimeoutCertificate,
    },
    /// Returns the bounded core-only proposal/VC pair required by the supplied
    /// TC. Every field is independently verified before it becomes live or
    /// durable state.
    PreparedCertificateResponse {
        timeout_certificate: TimeoutCertificate,
        block: TypedBlock,
        validation_certificate: ValidationCertificate,
    },
    /// Requests a bounded segment beginning at the caller's next missing
    /// height. Only authenticated finalized-Genesis validators may request it.
    FinalityCheckpointRequest {
        next_height: crate::synergy_types::Height,
    },
    /// A bounded sequence of certified core-only finality records.
    FinalityCheckpoint {
        records: Vec<TypedFinalityRecord>,
    },
}

/// Non-signing, finalized-only typed-finality replication for relayers and
/// public service observers. This is deliberately a separate wire protocol
/// from [`TypedConsensusMessage`]: it never carries a proposal, vote, timeout,
/// or authority to participate in validator consensus.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TypedFinalityObserverMessage {
    /// Requests the first bounded certified segment at `next_height`.
    Request {
        next_height: crate::synergy_types::Height,
    },
    /// A bounded consecutive sequence of finalized typed records.
    Records { records: Vec<TypedFinalityRecord> },
}

/// The temporary coordinator-driven wire protocol.  It deliberately has no
/// vote, validation certificate, quorum certificate, timeout certificate, or
/// aggregator object.  Message signatures are verified against canonical
/// validator consensus keys by the coordinated runtime adapter before any
/// state or block installation changes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CoordinatedConsensusMessage {
    ProducerAssignment {
        assignment: ProducerAssignment,
    },
    ProposedBlock {
        assignment: ProducerAssignment,
        proposal: CoordinatedProposal,
        block: TypedBlock,
    },
    CoordinatorCommit {
        package: CoordinatedCommittedBlockPackage,
    },
    GetCommittedBlock {
        height: u64,
    },
    GetCommittedBlockRange {
        start_height: u64,
        end_height: u64,
    },
    CommittedBlock {
        package: CoordinatedCommittedBlockPackage,
    },
    CommittedBlockRange {
        packages: Vec<CoordinatedCommittedBlockPackage>,
    },
}

/// A relayable, independently verifiable finalized-block package.  The packet
/// carries everything needed to prove coordinated finality without recreating
/// a certificate or contacting the original coordinator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoordinatedCommittedBlockPackage {
    pub block: TypedBlock,
    pub assignment: ProducerAssignment,
    pub proposal: CoordinatedProposal,
    pub coordinator_commit: CoordinatorCommit,
}

impl CoordinatedCommittedBlockPackage {
    pub fn validate_against(&self, config: &CoordinatedRoundRobinConfig) -> Result<(), String> {
        self.assignment.validate_shape(config)?;
        self.proposal.validate_shape()?;
        self.coordinator_commit.validate_shape(config)?;
        let assignment_hash = self.assignment.signing_hash()?;
        let transaction_ids = self
            .block
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
            .map_err(|_| "coordinated package transaction count exceeds u64".to_string())?;
        let transaction_admission_root =
            coordinated_transaction_admission_root(&self.proposal.transaction_admissions)?;
        let block_hash = Hash::from_hex(&self.block.block_id()?.0)
            .map_err(|error| format!("coordinated package block ID is not a hash: {error}"))?;
        if self.block.header.epoch.0 != self.assignment.epoch
            || self.block.header.height.0 != self.assignment.height
            || self.block.header.round.0 != self.assignment.producer_round
            || self.block.header.protocol_version != self.assignment.consensus_version
            || self.block.header.parent_block_hash != self.assignment.parent_block_hash
            || self.block.header.parent_state_root != self.block.header.state_root_before
            || self.block.header.evidence_root != self.assignment.prior_finality_reference
            || !self.block.header.last_finalized_qc_hash.is_zero()
            || self.block.header.proposer_validator_id.0 != self.assignment.assigned_producer_id
            || self.block.header.tx_count != transaction_count
            || self.block.header.tx_order_root != compute_tx_order_root(&transaction_ids)?
            || self.proposal.transaction_admission_root != transaction_admission_root
            || self.block.header.dag_frontier_root
                != coordinated_dag_frontier_root(
                    self.block.header.parent_block_hash,
                    self.block.header.tx_order_root,
                    transaction_admission_root,
                )
            || self.block.header.state_root_after != self.proposal.state_root
            || self.block.header.receipt_root != self.proposal.receipt_root
            || self.block.proposer_signature != self.proposal.producer_signature
        {
            return Err(
                "coordinated package block does not match its producer assignment".to_string(),
            );
        }
        if self.proposal.epoch != self.assignment.epoch
            || self.proposal.height != self.assignment.height
            || self.proposal.producer_round != self.assignment.producer_round
            || self.proposal.parent_block_hash != self.assignment.parent_block_hash
            || self.proposal.prior_finality_reference != self.assignment.prior_finality_reference
            || self.proposal.block_hash != block_hash
            || self.proposal.producer_id != self.assignment.assigned_producer_id
            || self.proposal.assignment_hash != assignment_hash
        {
            return Err(
                "coordinated package proposal does not match its assignment and block".to_string(),
            );
        }
        if self.coordinator_commit.epoch != self.proposal.epoch
            || self.coordinator_commit.height != self.proposal.height
            || self.coordinator_commit.producer_round != self.proposal.producer_round
            || self.coordinator_commit.parent_block_hash != self.proposal.parent_block_hash
            || self.coordinator_commit.prior_finality_reference
                != self.proposal.prior_finality_reference
            || self.coordinator_commit.block_hash != self.proposal.block_hash
            || self.coordinator_commit.transaction_root != self.proposal.transaction_root
            || self.coordinator_commit.transaction_admission_root
                != self.proposal.transaction_admission_root
            || self.coordinator_commit.receipt_root != self.proposal.receipt_root
            || self.coordinator_commit.state_root != self.proposal.state_root
            || self.coordinator_commit.producer_id != self.proposal.producer_id
            || self.coordinator_commit.assignment_hash != assignment_hash
        {
            return Err("coordinated package commit does not match its proposal".to_string());
        }
        Ok(())
    }
}

/// Rejects typed consensus wire artifacts that exceed the Testnet-v3 resource
/// budget before they reach the coordinator mailbox or are fanned out to peers.
///
/// Certificates are independently bounded because an authenticated relay is
/// allowed to forward them; proposals receive the larger cap because their
/// protected ETDAG payload is part of the same canonical P2P frame.
pub fn validate_typed_consensus_message_size(
    message: &TypedConsensusMessage,
) -> Result<(), String> {
    let (kind, maximum) = match message {
        TypedConsensusMessage::CoreProposal { .. } => (
            "typed consensus core-only proposal",
            MAX_TYPED_CONSENSUS_CORE_PROPOSAL_FRAME_BYTES,
        ),
        TypedConsensusMessage::Proposal { .. } => (
            "typed consensus proposal",
            MAX_TYPED_CONSENSUS_PROPOSAL_FRAME_BYTES,
        ),
        TypedConsensusMessage::ValidationCertificate { .. }
        | TypedConsensusMessage::QuorumCertificate { .. }
        | TypedConsensusMessage::TimeoutCertificate { .. }
        | TypedConsensusMessage::PreparedCertificateRequest { .. } => (
            "typed consensus certificate",
            MAX_TYPED_CONSENSUS_CERTIFICATE_FRAME_BYTES,
        ),
        TypedConsensusMessage::PreparedCertificateResponse { .. } => (
            "typed prepared-certificate recovery",
            MAX_TYPED_PREPARED_RECOVERY_FRAME_BYTES,
        ),
        TypedConsensusMessage::FinalityCheckpointRequest { .. } => return Ok(()),
        TypedConsensusMessage::FinalityCheckpoint { .. } => (
            "typed finality checkpoint",
            MAX_TYPED_FINALITY_CHECKPOINT_FRAME_BYTES,
        ),
        TypedConsensusMessage::Vote { .. } => return Ok(()),
    };
    let encoded = NetworkMessage::TypedConsensus {
        chain_incarnation: crate::synergy_types::TESTNET_V3_CHAIN_INCARNATION,
        genesis_hash: crate::genesis::canonical_genesis()?.hash().to_string(),
        message: message.clone(),
    };
    let frame_bytes = serde_json::to_vec(&encoded)
        .map_err(|error| format!("serialize {kind} frame: {error}"))?
        .len()
        .checked_add(4)
        .ok_or_else(|| format!("{kind} frame length overflow"))?;
    validate_typed_consensus_frame_length(kind, frame_bytes, maximum)
}

/// Applies the same bounded-frame policy to finalized-only observer traffic.
/// The recipient must still independently replay every record before durable
/// persistence; this guard only limits untrusted transport work.
pub fn validate_typed_finality_observer_message_size(
    message: &TypedFinalityObserverMessage,
) -> Result<(), String> {
    let TypedFinalityObserverMessage::Records { records } = message else {
        return Ok(());
    };
    if records.is_empty() {
        return Err("typed finality observer record segment cannot be empty".to_string());
    }
    let encoded = NetworkMessage::TypedFinalityObserver {
        chain_incarnation: crate::synergy_types::TESTNET_V3_CHAIN_INCARNATION,
        genesis_hash: crate::genesis::canonical_genesis()?.hash().to_string(),
        message: message.clone(),
    };
    let frame_bytes = serde_json::to_vec(&encoded)
        .map_err(|error| format!("serialize typed finality observer frame: {error}"))?
        .len()
        .checked_add(4)
        .ok_or_else(|| "typed finality observer frame length overflow".to_string())?;
    validate_typed_consensus_frame_length(
        "typed finality observer record segment",
        frame_bytes,
        MAX_TYPED_FINALITY_CHECKPOINT_FRAME_BYTES,
    )
}

/// Applies a resource budget before a coordinated-mode message reaches its
/// coordinator or block-sync handler.  Structural and signature validation is
/// performed by the mode-specific receiver because it requires the local
/// canonical validator configuration and consensus key registry.
pub fn validate_coordinated_consensus_message_size(
    message: &CoordinatedConsensusMessage,
) -> Result<(), String> {
    let (kind, maximum) = match message {
        CoordinatedConsensusMessage::ProducerAssignment { .. }
        | CoordinatedConsensusMessage::GetCommittedBlock { .. }
        | CoordinatedConsensusMessage::GetCommittedBlockRange { .. } => (
            "coordinated consensus control message",
            MAX_COORDINATED_CONSENSUS_ASSIGNMENT_FRAME_BYTES,
        ),
        CoordinatedConsensusMessage::ProposedBlock { .. }
        | CoordinatedConsensusMessage::CoordinatorCommit { .. }
        | CoordinatedConsensusMessage::CommittedBlock { .. } => (
            "coordinated consensus block package",
            MAX_COORDINATED_CONSENSUS_BLOCK_PACKAGE_FRAME_BYTES,
        ),
        CoordinatedConsensusMessage::CommittedBlockRange { packages } => {
            if packages.is_empty() {
                return Err("coordinated committed-block range cannot be empty".to_string());
            }
            if packages.len() > MAX_COORDINATED_CONSENSUS_SYNC_RANGE_BLOCKS {
                return Err(format!(
                    "coordinated committed-block range has {} packages, exceeding limit {}",
                    packages.len(),
                    MAX_COORDINATED_CONSENSUS_SYNC_RANGE_BLOCKS
                ));
            }
            (
                "coordinated committed-block range",
                MAX_COORDINATED_CONSENSUS_SYNC_RANGE_FRAME_BYTES,
            )
        }
    };
    let encoded = NetworkMessage::CoordinatedConsensus {
        chain_incarnation: crate::synergy_types::TESTNET_V3_CHAIN_INCARNATION,
        genesis_hash: crate::genesis::canonical_genesis()?.hash().to_string(),
        message: message.clone(),
    };
    let frame_bytes = serde_json::to_vec(&encoded)
        .map_err(|error| format!("serialize {kind} frame: {error}"))?
        .len()
        .checked_add(4)
        .ok_or_else(|| format!("{kind} frame length overflow"))?;
    validate_typed_consensus_frame_length(kind, frame_bytes, maximum)
}

fn validate_typed_consensus_frame_length(
    kind: &str,
    actual: usize,
    maximum: usize,
) -> Result<(), String> {
    if actual > maximum {
        return Err(format!(
            "{kind} frame is {actual} bytes, exceeding Testnet-v3 limit {maximum} bytes"
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkMessage {
    Handshake {
        node_id: String,
        version: String,
        capabilities: Vec<String>,
        #[serde(default)]
        chain_id: Option<u64>,
        #[serde(default)]
        chain_incarnation: Option<u64>,
        #[serde(default)]
        consensus_state_schema_version: Option<u32>,
        #[serde(default)]
        network_id: Option<u64>,
        #[serde(default)]
        network_id_text: Option<String>,
        #[serde(default)]
        genesis_hash: String,
        #[serde(default)]
        network_magic_bytes: String,
        #[serde(default)]
        protocol_version: Option<String>,
        #[serde(default)]
        consensus_version: Option<String>,
        #[serde(default)]
        native_caip2: Option<String>,
        #[serde(default)]
        reserved_eip155: Option<String>,
        #[serde(default)]
        public_address: Option<String>,
        #[serde(default)]
        validator_address: Option<String>,
        #[serde(default)]
        role: Option<String>,
        #[serde(default)]
        active_validator_set_hash: Option<String>,
        #[serde(default)]
        cluster_map_hash: Option<String>,
        #[serde(default)]
        protocol_config_hash: Option<String>,
        #[serde(default)]
        aegis_pqvm_version: Option<String>,
        #[serde(default)]
        aegis_pq_public_key_id: Option<String>,
        #[serde(default)]
        aegis_pq_public_key_algorithm: Option<String>,
        #[serde(default)]
        aegis_pq_public_key: Vec<u8>,
        #[serde(default)]
        aegis_pq_handshake_signature: Option<AegisPqSignature>,
    },
    Block {
        block_data: Block,
        #[serde(default)]
        quorum_certificate: Option<QuorumCertificate>,
    },
    VoteRequest {
        block_data: Block,
        epoch_number: u64,
        round_number: u64,
    },
    Vote {
        vote: Vote,
    },
    /// Typed PoSy v2.2 messages. These are dispatched through the dedicated
    /// coordinator mailbox and never through inherited consensus handlers.
    TypedConsensus {
        chain_incarnation: u64,
        genesis_hash: String,
        message: TypedConsensusMessage,
    },
    /// Temporary coordinator-driven messages. They have their own protocol
    /// variant so no legacy or typed-PoSy handler can reinterpret them.
    CoordinatedConsensus {
        chain_incarnation: u64,
        genesis_hash: String,
        message: CoordinatedConsensusMessage,
    },
    /// Verified, non-signing finalized-chain replication between the
    /// validator-VPN relayer tier and public RPC/indexer observer roles.
    TypedFinalityObserver {
        chain_incarnation: u64,
        genesis_hash: String,
        message: TypedFinalityObserverMessage,
    },
    /// A complete, already-certified ETDAG proof package. The P2P receiver
    /// binds it to local height/finality authority before durable admission;
    /// no consensus context is accepted from this wire message.
    EtdagCertifiedInput {
        artifact: CertifiedProtectedInputArtifact,
    },
    Transaction {
        transaction_data: Transaction,
    },
    GetBlocks {
        from_height: u64,
        count: u32,
    },
    Blocks {
        blocks: Vec<Block>,
        #[serde(default)]
        quorum_certificates: Vec<QuorumCertificate>,
    },
    GetPeers,
    Peers {
        peer_addresses: Vec<String>,
    },
    Ping,
    Pong,
    Error {
        message: String,
    },
    GetStatus,
    Status {
        block_height: u64,
        best_block_hash: String,
        genesis_hash: String,
        #[serde(default)]
        status_timestamp: Option<u64>,
        #[serde(default)]
        validator_address: Option<String>,
        #[serde(default)]
        source_session_id: Option<String>,
        #[serde(default)]
        active_validator_set_hash: Option<String>,
        #[serde(default)]
        quarantined: bool,
        #[serde(default)]
        consensus_duties_disabled: bool,
        #[serde(default)]
        recovery_state: Option<String>,
    },
    GetBlockHeaders {
        start_height: u64,
        count: u64,
    },
    BlockHeaders {
        headers: Vec<BlockHeader>,
    },
    GetBlockBodies {
        hashes: Vec<String>,
    },
    BlockBodies {
        blocks: Vec<Block>,
        #[serde(default)]
        quorum_certificates: Vec<QuorumCertificate>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::synergy_types::{
        AegisPqKeyId, AegisPqSignature, BlockId, ChainId, ClusterId, Epoch, Hash, Height,
        NetworkId, Round, UmaId, ValidatorId, VotePhase,
    };

    #[test]
    fn typed_consensus_vote_round_trips_without_legacy_reinterpretation() {
        let message = NetworkMessage::TypedConsensus {
            chain_incarnation: crate::synergy_types::TESTNET_V3_CHAIN_INCARNATION,
            genesis_hash: crate::genesis::canonical_genesis()
                .unwrap()
                .hash()
                .to_string(),
            message: TypedConsensusMessage::Vote {
                vote: TypedVote {
                    chain_id: ChainId::synergy_testnet_v3(),
                    network_id: NetworkId::synergy_testnet_v3(),
                    protocol_version: "posy-v2.2".to_string(),
                    height: Height(1),
                    round: Round(0),
                    epoch: Epoch(0),
                    cluster_id: ClusterId(0),
                    height_context_root: Hash::from_domain_bytes("test", b"context"),
                    phase: VotePhase::Validate,
                    block_id: BlockId("candidate".to_string()),
                    highest_prepared_vc_root: None,
                    validator_id: ValidatorId("validator-1".to_string()),
                    validator_uma_id: UmaId("uma-1".to_string()),
                    key_id: AegisPqKeyId("key-1".to_string()),
                    active_validator_set_hash: Hash::from_domain_bytes("test", b"set"),
                    cluster_map_hash: Hash::from_domain_bytes("test", b"cluster"),
                    aegis_pq_signature: AegisPqSignature {
                        algorithm: "mldsa65".to_string(),
                        signature_bytes: vec![1],
                    },
                },
            },
        };

        let encoded = serde_json::to_vec(&message).expect("serialize typed wire message");
        let decoded: NetworkMessage =
            serde_json::from_slice(&encoded).expect("deserialize typed wire message");
        assert!(matches!(
            decoded,
            NetworkMessage::TypedConsensus {
                message: TypedConsensusMessage::Vote { .. },
                ..
            }
        ));
    }

    #[test]
    fn oversized_typed_certificate_is_rejected_before_coordinator_delivery() {
        let certificate = TypedQuorumCertificate {
            qc_version: 1,
            chain_id: ChainId::synergy_testnet_v3(),
            network_id: NetworkId::synergy_testnet_v3(),
            protocol_version: "posy/2.2".to_string(),
            height: Height(1),
            round: Round(0),
            epoch: Epoch(0),
            cluster_id: ClusterId(0),
            height_context_root: Hash::from_domain_bytes("test", b"context"),
            phase: VotePhase::Finality,
            block_id: BlockId("candidate".to_string()),
            highest_prepared_vc_root: None,
            active_validator_set_hash: Hash::from_domain_bytes("test", b"set"),
            cluster_map_hash: Hash::from_domain_bytes("test", b"cluster"),
            threshold_weight_required: 5,
            signed_weight: 5,
            signer_bitmap: vec![0b00_0111_11],
            aegis_pq_signatures: vec![AegisPqSignature {
                algorithm: "mldsa65".to_string(),
                signature_bytes: vec![0; MAX_TYPED_CONSENSUS_CERTIFICATE_FRAME_BYTES],
            }],
            aegis_pq_key_ids: vec![AegisPqKeyId("key-1".to_string())],
        };

        let error =
            validate_typed_consensus_message_size(&TypedConsensusMessage::QuorumCertificate {
                certificate,
            })
            .expect_err("certificate frame above the 128 KiB cap must fail closed");

        assert!(error.contains("typed consensus certificate frame"));
        assert!(error.contains("131072"));
    }

    #[test]
    fn proposal_frame_limit_is_exactly_eight_mebibytes() {
        validate_typed_consensus_frame_length(
            "typed consensus proposal",
            MAX_TYPED_CONSENSUS_PROPOSAL_FRAME_BYTES,
            MAX_TYPED_CONSENSUS_PROPOSAL_FRAME_BYTES,
        )
        .expect("the exact proposal cap is accepted");
        let error = validate_typed_consensus_frame_length(
            "typed consensus proposal",
            MAX_TYPED_CONSENSUS_PROPOSAL_FRAME_BYTES + 1,
            MAX_TYPED_CONSENSUS_PROPOSAL_FRAME_BYTES,
        )
        .expect_err("proposal frame above the 8 MiB cap must fail closed");

        assert!(error.contains("8388608"));
    }

    #[test]
    fn coordinated_assignment_round_trips_as_its_own_message_family() {
        let assignment = ProducerAssignment {
            chain_id: 1266,
            network_id: "synergy-testnet-v3".to_string(),
            consensus_version:
                crate::consensus::coordinated_round_robin::COORDINATED_ROUND_ROBIN_V1.to_string(),
            epoch: 0,
            height: 1,
            producer_round: 0,
            parent_block_hash: Hash::zero(),
            prior_finality_reference: Hash::zero(),
            assigned_producer_id: "validator-2".to_string(),
            coordinator_id: "validator-1".to_string(),
            assignment_sequence: 1,
            intended_block_timestamp_ms: 2_000,
            coordinator_signature: AegisPqSignature {
                algorithm: "ML-DSA-65".to_string(),
                signature_bytes: vec![7; 32],
            },
        };
        let message = NetworkMessage::CoordinatedConsensus {
            chain_incarnation: crate::synergy_types::TESTNET_V3_CHAIN_INCARNATION,
            genesis_hash: crate::genesis::canonical_genesis()
                .expect("canonical Genesis should load")
                .hash()
                .to_string(),
            message: CoordinatedConsensusMessage::ProducerAssignment {
                assignment: assignment.clone(),
            },
        };
        let decoded: NetworkMessage =
            serde_json::from_slice(&serde_json::to_vec(&message).expect("wire message serializes"))
                .expect("wire message deserializes");
        match decoded {
            NetworkMessage::CoordinatedConsensus {
                message: CoordinatedConsensusMessage::ProducerAssignment { assignment: actual },
                ..
            } => assert_eq!(actual, assignment),
            _ => panic!("coordinated assignment was reinterpreted as another message family"),
        }
    }

    #[test]
    fn coordinated_sync_range_rejects_an_empty_response_before_delivery() {
        let error = validate_coordinated_consensus_message_size(
            &CoordinatedConsensusMessage::CommittedBlockRange { packages: vec![] },
        )
        .expect_err("an empty coordinated sync range is invalid");
        assert!(error.contains("cannot be empty"));
    }

    #[test]
    fn oversized_coordinated_assignment_is_rejected_before_delivery() {
        let assignment = ProducerAssignment {
            chain_id: 1266,
            network_id: "synergy-testnet-v3".to_string(),
            consensus_version:
                crate::consensus::coordinated_round_robin::COORDINATED_ROUND_ROBIN_V1.to_string(),
            epoch: 0,
            height: 1,
            producer_round: 0,
            parent_block_hash: Hash::zero(),
            prior_finality_reference: Hash::zero(),
            assigned_producer_id: "validator-2".to_string(),
            coordinator_id: "validator-1".to_string(),
            assignment_sequence: 1,
            intended_block_timestamp_ms: 2_000,
            coordinator_signature: AegisPqSignature {
                algorithm: "ML-DSA-65".to_string(),
                signature_bytes: vec![9; MAX_COORDINATED_CONSENSUS_ASSIGNMENT_FRAME_BYTES],
            },
        };
        let error = validate_coordinated_consensus_message_size(
            &CoordinatedConsensusMessage::ProducerAssignment { assignment },
        )
        .expect_err("oversized coordinated assignment must be rejected");
        assert!(error.contains("131072"));
    }
}
