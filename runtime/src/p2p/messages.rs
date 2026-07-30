use serde::{Deserialize, Serialize};

use crate::block::{Block, BlockHeader};
use crate::consensus::dual_quorum::{QuorumCertificate, Vote};
use crate::consensus::typed_finality_store::TypedFinalityRecord;
use crate::etdag::{CertifiedProtectedInputArtifact, ProtectedBlockInput, TargetAdmissionContext};
use crate::synergy_types::AegisPqSignature;
use crate::synergy_types::{
    Block as TypedBlock, HeightConsensusContext, QuorumCertificate as TypedQuorumCertificate,
    TimeoutCertificate, ValidationCertificate, Vote as TypedVote,
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
        message: TypedConsensusMessage,
    },
    /// Verified, non-signing finalized-chain replication between the
    /// validator-VPN relayer tier and public RPC/indexer observer roles.
    TypedFinalityObserver {
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
                message: TypedConsensusMessage::Vote { .. }
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
}
