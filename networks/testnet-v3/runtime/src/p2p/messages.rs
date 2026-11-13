use serde::{Deserialize, Serialize};

use crate::block::{Block, BlockHeader};
use crate::consensus::coordinated_admission::{
    coordinated_dag_frontier_root, coordinated_transaction_admission_root,
};
use crate::consensus::coordinated_finality_store::CoordinatedFinalityRecord;
use crate::consensus::coordinated_round_robin::{
    CoordinatedProposal, CoordinatedRoundRobinConfig, CoordinatorCommit, ProducerAssignment,
};
use crate::consensus::dual_quorum::{QuorumCertificate, Vote};
use crate::consensus::simplified_posy::{
    SimplifiedConsensusMessage, SimplifiedTargetAdmissionVoteRequest,
};
use crate::consensus::typed_finality_store::TypedFinalityRecord;
use crate::dag_mempool::compute_tx_order_root;
use crate::etdag::{
    CertifiedProtectedInputArtifact, CertifiedVertex, EtdagDigest, EtdagSubmissionEnvelope,
    ProtectedBlockInput, ProtectedRevealAuthorization, ProtectedRevealShareMessage,
    TargetAdmissionContext, TargetAdmissionPackage, VertexKind, ETDAG_PROFILE_ID,
    PROTECTED_PIPELINE_VERSION,
};
use crate::synergy_types::AegisPqSignature;
use crate::synergy_types::{
    Block as TypedBlock, CanonicalSerialize, ChainId, Hash, Height, HeightConsensusContext,
    NetworkId, QuorumCertificate as TypedQuorumCertificate, TimeoutCertificate, TxId,
    ValidationCertificate, Vote as TypedVote,
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
/// Finalized-only P1 observer traffic has its own bounded wire variant so
/// relayers/RPC/indexers cannot be routed through coordinator consensus.
pub const MAX_COORDINATED_FINALITY_OBSERVER_FRAME_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_SIMPLIFIED_CONSENSUS_CERTIFICATE_FRAME_BYTES: usize = 256 * 1024;
pub const MAX_SIMPLIFIED_CONSENSUS_PROPOSAL_FRAME_BYTES: usize = 512 * 1024;
pub const MAX_SIMPLIFIED_CONSENSUS_STATE_SYNC_FRAME_BYTES: usize = 256 * 1024;
pub const MAX_SIMPLIFIED_CONSENSUS_VOTE_FRAME_BYTES: usize = 64 * 1024;
pub const MAX_SIMPLIFIED_CONSENSUS_CONTROL_FRAME_BYTES: usize = 16 * 1024;
/// One target-admission vote repeats the exact public ML-KEM registry committed
/// by its signed context. The cap is independent from normal block votes.
pub const MAX_SIMPLIFIED_TARGET_ADMISSION_VOTE_FRAME_BYTES: usize = 128 * 1024;
/// A certified package carries the same registry plus a dynamic strict-quorum
/// set of ML-DSA-65 signatures. It remains bounded independently of the 64 MiB
/// generic transport ceiling.
pub const MAX_SIMPLIFIED_TARGET_ADMISSION_PACKAGE_FRAME_BYTES: usize = 512 * 1024;
/// A single semantic protected-pipeline object is bounded independently from
/// proposals and from the retired whole-input artifact.
pub const MAX_PROTECTED_PIPELINE_EVIDENCE_FRAME_BYTES: usize = 2 * 1024 * 1024;
/// Missing-object requests carry only fixed-width semantic identifiers.
pub const MAX_PROTECTED_PIPELINE_REQUEST_FRAME_BYTES: usize = 32 * 1024;
/// A response may return several independently verifiable semantic objects,
/// but never an unbounded graph or complete DCC/BVC/BOC protected input.
pub const MAX_PROTECTED_PIPELINE_RESPONSE_FRAME_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_PROTECTED_PIPELINE_REQUEST_IDS: usize = 64;
pub const MAX_PROTECTED_PIPELINE_RESPONSE_OBJECTS: usize = 32;
pub const DOMAIN_PROTECTED_PIPELINE_EVIDENCE_ID: &str = "PoSy/ProtectedPipeline/WireEvidenceId/v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub enum SimplifiedTargetAdmissionMessage {
    Vote {
        request: SimplifiedTargetAdmissionVoteRequest,
    },
    CertifiedPackage {
        package: TargetAdmissionPackage,
    },
}

/// One independently identifiable object consumed by ProtectedPipeline.
/// Transaction vertices and cutoff markers are distinct variants so a marker
/// cannot be reinterpreted as encrypted transaction availability evidence.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum ProtectedPipelineSemanticObject {
    /// The exact wallet-authenticated encrypted material referenced by a
    /// transaction vertex. The semantic ID is the envelope's canonical
    /// transaction commitment, allowing a vertex reference to request the
    /// concrete ciphertext, share capsules, and sender key proof directly.
    EncryptedMaterial {
        semantic_id: EtdagDigest,
        submission: EtdagSubmissionEnvelope,
    },
    CertifiedVertex {
        semantic_id: EtdagDigest,
        certified_vertex: CertifiedVertex,
    },
    CutoffMarker {
        semantic_id: EtdagDigest,
        certified_vertex: CertifiedVertex,
    },
    RevealAuthorization {
        semantic_id: EtdagDigest,
        authorization: ProtectedRevealAuthorization,
    },
    RevealShare {
        semantic_id: EtdagDigest,
        authorization_id: EtdagDigest,
        share: ProtectedRevealShareMessage,
    },
}

impl ProtectedPipelineSemanticObject {
    pub fn declared_semantic_id(&self) -> &EtdagDigest {
        match self {
            Self::EncryptedMaterial { semantic_id, .. }
            | Self::CertifiedVertex { semantic_id, .. }
            | Self::CutoffMarker { semantic_id, .. }
            | Self::RevealAuthorization { semantic_id, .. }
            | Self::RevealShare { semantic_id, .. } => semantic_id,
        }
    }

    pub fn computed_semantic_id(&self) -> Result<EtdagDigest, String> {
        match self {
            Self::EncryptedMaterial { submission, .. } => {
                Ok(submission.sealed_bundle.envelope.tx_commitment.clone())
            }
            Self::CertifiedVertex {
                certified_vertex, ..
            }
            | Self::CutoffMarker {
                certified_vertex, ..
            } => certified_vertex.vertex.digest(),
            Self::RevealAuthorization { authorization, .. } => authorization.root(),
            Self::RevealShare { share, .. } => {
                EtdagDigest::from_canonical(DOMAIN_PROTECTED_PIPELINE_EVIDENCE_ID, share)
            }
        }
    }

    pub fn validate_shape(&self) -> Result<(), String> {
        self.declared_semantic_id()
            .validate("protected evidence semantic id")?;
        let expected = self.computed_semantic_id()?;
        if self.declared_semantic_id() != &expected || expected.is_zero() {
            return Err("protected evidence semantic id mismatch".to_string());
        }
        match self {
            Self::EncryptedMaterial { submission, .. } => {
                validate_encrypted_material_shape(submission)
            }
            Self::CertifiedVertex {
                certified_vertex, ..
            } if certified_vertex.vertex.kind != VertexKind::Transactions => Err(
                "protected certified-vertex object does not contain a transaction vertex"
                    .to_string(),
            ),
            Self::CutoffMarker {
                certified_vertex, ..
            } if certified_vertex.vertex.kind != VertexKind::CutoffMarker => {
                Err("protected cutoff-marker object does not contain a cutoff marker".to_string())
            }
            Self::RevealAuthorization { authorization, .. } => {
                validate_reveal_authorization_shape(authorization)
            }
            Self::RevealShare {
                authorization_id,
                share,
                ..
            } => {
                authorization_id.validate("protected reveal authorization id")?;
                if share.share_version != PROTECTED_PIPELINE_VERSION
                    || authorization_id != &share.authorization_root
                    || authorization_id.is_zero()
                    || share.target_height.0 == 0
                    || share.target_context_root.is_zero()
                    || share.next_commitment_root.is_zero()
                    || share.protected_batch_root.is_zero()
                    || share.tx_commitment.is_zero()
                    || share.parameter_root.is_zero()
                    || share.protocol_version.trim().is_empty()
                    || share.profile_id.trim().is_empty()
                    || share.validator_id.0.trim().is_empty()
                    || share.key_id.0.trim().is_empty()
                    || share.signature.signature_bytes.is_empty()
                {
                    return Err(
                        "protected reveal share has invalid authenticated shape".to_string()
                    );
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    pub fn target_binding(&self) -> (Height, Hash) {
        match self {
            Self::EncryptedMaterial { submission, .. } => {
                let envelope = &submission.sealed_bundle.envelope;
                (envelope.target_height, envelope.target_context_root)
            }
            Self::CertifiedVertex {
                certified_vertex, ..
            }
            | Self::CutoffMarker {
                certified_vertex, ..
            } => (
                certified_vertex.vertex.target_height,
                certified_vertex.vertex.target_context_root,
            ),
            Self::RevealAuthorization { authorization, .. } => (
                authorization.target_height,
                authorization.target_context_root,
            ),
            Self::RevealShare { share, .. } => (share.target_height, share.target_context_root),
        }
    }

    pub fn chain_binding(&self) -> (ChainId, &NetworkId) {
        match self {
            Self::EncryptedMaterial { submission, .. } => {
                let envelope = &submission.sealed_bundle.envelope;
                (envelope.chain_id, &envelope.network_id)
            }
            Self::CertifiedVertex {
                certified_vertex, ..
            }
            | Self::CutoffMarker {
                certified_vertex, ..
            } => (
                certified_vertex.vertex.chain_id,
                &certified_vertex.vertex.network_id,
            ),
            Self::RevealAuthorization { authorization, .. } => {
                (authorization.chain_id, &authorization.network_id)
            }
            Self::RevealShare { share, .. } => (share.chain_id, &share.network_id),
        }
    }

    pub fn encrypted_submission(&self) -> Option<&EtdagSubmissionEnvelope> {
        match self {
            Self::EncryptedMaterial { submission, .. } => Some(submission),
            _ => None,
        }
    }
}

fn validate_encrypted_material_shape(submission: &EtdagSubmissionEnvelope) -> Result<(), String> {
    let envelope = &submission.sealed_bundle.envelope;
    envelope.chain_id.require_testnet_v3()?;
    envelope.network_id.require_fresh_posy_testnet_v3()?;
    if envelope.envelope_version != 2
        || envelope.profile_id != ETDAG_PROFILE_ID
        || envelope.protocol_version
            != crate::consensus::simplified_posy::POSY_SIMPLIFIED_PROTOCOL_VERSION
        || envelope.target_height.0 == 0
        || envelope.target_context_root.is_zero()
        || envelope.expiry_height != envelope.target_height
        || envelope.sender_id.trim().is_empty()
        || envelope.aead_nonce.len() != 12
        || envelope.ciphertext.len() < 16
        || !crate::etdag::EtdagParameters::default()
            .ciphertext_size_classes
            .contains(&envelope.ciphertext_size_class)
        || envelope.ciphertext.len() > envelope.ciphertext_size_class as usize
        || envelope.outer_key_id.0.trim().is_empty()
        || !envelope.outer_signature.is_present()
    {
        return Err("protected encrypted material has invalid target-bound shape".to_string());
    }
    for (name, digest) in [
        (
            "protected encrypted key commitment",
            &envelope.key_commitment,
        ),
        (
            "protected encrypted share commitment root",
            &envelope.share_commitment_root,
        ),
        (
            "protected encrypted share capsule root",
            &envelope.share_capsule_root,
        ),
        (
            "protected encrypted transaction commitment",
            &envelope.tx_commitment,
        ),
    ] {
        digest.validate(name)?;
        if digest.is_zero() {
            return Err(format!("{name} is zero"));
        }
    }
    if envelope.recompute_commitment()? != envelope.tx_commitment {
        return Err("protected encrypted transaction commitment mismatch".to_string());
    }
    submission.sealed_bundle.validate_roots()?;
    if submission.outer_public_key.key_id != envelope.outer_key_id
        || submission.outer_public_key.algorithm.trim().is_empty()
        || submission.outer_public_key.key_bytes.is_empty()
        || submission.outer_key_lifecycle.key_id != envelope.outer_key_id
        || submission.outer_key_lifecycle.uma_id != envelope.sender_id
        || !submission
            .outer_key_lifecycle
            .roles
            .contains(&crate::synergy_types::AegisPqKeyRole::Transaction)
        || submission.outer_key_lifecycle.active_from_epoch.0 > envelope.epoch.0
        || submission
            .outer_key_lifecycle
            .active_until_epoch
            .is_some_and(|until| envelope.epoch.0 > until.0)
        || submission
            .outer_key_lifecycle
            .revoked_from_epoch
            .is_some_and(|revoked| envelope.epoch.0 >= revoked.0)
    {
        return Err("protected encrypted material sender key is not authorized".to_string());
    }
    let verifier =
        crate::crypto::aegis_pqvm::AegisPqvmVerifier::initialize_required_for_public_key(
            submission.outer_public_key.clone(),
            submission.outer_key_lifecycle.clone(),
        )
        .map_err(|error| format!("initialize protected envelope verifier: {error}"))?;
    envelope
        .verify_outer_signature(&verifier)
        .map_err(|error| format!("verify protected envelope origin: {error}"))
}

fn validate_reveal_authorization_shape(
    authorization: &ProtectedRevealAuthorization,
) -> Result<(), String> {
    if authorization.authorization_version != PROTECTED_PIPELINE_VERSION
        || authorization.target_height.0 == 0
        || authorization.target_context_root.is_zero()
        || authorization.validator_set_commitment.is_zero()
        || authorization.parameter_root.is_zero()
        || authorization.protocol_version.trim().is_empty()
        || authorization.parent_proposal_id.0.trim().is_empty()
        || authorization.parent_block_id.0.trim().is_empty()
        || authorization.next_commitment_root.is_zero()
        || authorization.protected_batch_root.is_zero()
        || authorization.proposal_validation_certificate_root.is_zero()
        || authorization.certificate_evidence_root.is_zero()
    {
        return Err("protected reveal authorization has invalid authenticated shape".to_string());
    }
    authorization
        .root()?
        .validate("protected reveal authorization root")
}

/// One bounded semantic evidence propagation family. Missing-object recovery
/// refers only to canonical semantic IDs; responses are validated object by
/// object and may arrive in any order.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum ProtectedPipelineEvidenceMessage {
    Evidence {
        object: ProtectedPipelineSemanticObject,
    },
    MissingObjectsRequest {
        target_height: Height,
        target_context_root: Hash,
        semantic_ids: Vec<EtdagDigest>,
    },
    MissingObjectsResponse {
        target_height: Height,
        target_context_root: Hash,
        objects: Vec<ProtectedPipelineSemanticObject>,
    },
}

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

/// Non-signing P1 finality replication for the validator-VPN relayer and
/// public service tiers. This never carries an assignment, proposal, commit
/// request, or any authority to enter the coordinator mailbox.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CoordinatedFinalityObserverMessage {
    Request {
        next_height: crate::synergy_types::Height,
    },
    Records {
        records: Vec<CoordinatedFinalityRecord>,
    },
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
        chain_incarnation: crate::genesis::canonical_genesis()?.chain_incarnation(),
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
        chain_incarnation: crate::genesis::canonical_genesis()?.chain_incarnation(),
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

/// Applies the P1 support-tier record-count and exact-frame budget before an
/// untrusted relayer or public peer reaches finality replay.
pub fn validate_coordinated_finality_observer_message_size(
    message: &CoordinatedFinalityObserverMessage,
) -> Result<(), String> {
    let CoordinatedFinalityObserverMessage::Records { records } = message else {
        return Ok(());
    };
    if records.is_empty()
        || records.len()
            > crate::consensus::coordinated_finality_observer::MAX_COORDINATED_FINALITY_OBSERVER_RECORDS
    {
        return Err("coordinated finality observer record segment has an invalid record count".to_string());
    }
    let encoded = NetworkMessage::CoordinatedFinalityObserver {
        chain_incarnation: crate::genesis::canonical_genesis()?.chain_incarnation(),
        genesis_hash: crate::genesis::canonical_genesis()?.hash().to_string(),
        message: message.clone(),
    };
    let frame_bytes = serde_json::to_vec(&encoded)
        .map_err(|error| format!("serialize coordinated finality observer frame: {error}"))?
        .len()
        .checked_add(4)
        .ok_or_else(|| "coordinated finality observer frame length overflow".to_string())?;
    validate_typed_consensus_frame_length(
        "coordinated finality observer record segment",
        frame_bytes,
        MAX_COORDINATED_FINALITY_OBSERVER_FRAME_BYTES,
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
        chain_incarnation: crate::genesis::canonical_genesis()?.chain_incarnation(),
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
    /// PoSy v3 simplified consensus is intentionally a distinct wire family;
    /// it cannot be decoded by the v2.2 coordinator or inherited handlers.
    SimplifiedConsensus {
        /// First in canonical JSON so the predecode allocation gate can apply
        /// the exact inner-message cap before allocating the full frame.
        message: SimplifiedConsensusMessage,
        chain_incarnation: u64,
        genesis_hash: String,
    },
    /// Schedule-neutral H+3 target-admission traffic is separated from block
    /// consensus so it receives its own predecode and signature-verification
    /// budget before reaching the process-wide producer.
    SimplifiedTargetAdmission {
        /// First in canonical JSON for the same predecode allocation gate.
        message: SimplifiedTargetAdmissionMessage,
        chain_incarnation: u64,
        genesis_hash: String,
    },
    /// Canonical PoSy v3 protected-pipeline evidence and semantic-object
    /// recovery. This is the only active ETDAG progression carrier.
    ProtectedPipelineEvidence {
        /// First in canonical JSON so the predecode allocation gate can apply
        /// the exact per-kind cap before allocating the full frame.
        message: ProtectedPipelineEvidenceMessage,
        chain_incarnation: u64,
        genesis_hash: String,
    },
    /// Verified, non-signing finalized-chain replication between the
    /// validator-VPN relayer tier and public RPC/indexer observer roles.
    TypedFinalityObserver {
        chain_incarnation: u64,
        genesis_hash: String,
        message: TypedFinalityObserverMessage,
    },
    /// Finalized-only `coordinated_round_robin_v1` evidence replication.
    /// This is intentionally distinct from [`Self::CoordinatedConsensus`].
    CoordinatedFinalityObserver {
        chain_incarnation: u64,
        genesis_hash: String,
        message: CoordinatedFinalityObserverMessage,
    },
    /// Compatibility-only decoder for the retired whole DCC/BVC/BOC carrier.
    /// Networking must never route this variant into active progression.
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

pub fn validate_simplified_consensus_message_size(
    message: &SimplifiedConsensusMessage,
) -> Result<(), String> {
    let (kind, maximum) = match message {
        SimplifiedConsensusMessage::Proposal { .. } => (
            "simplified consensus proposal",
            MAX_SIMPLIFIED_CONSENSUS_PROPOSAL_FRAME_BYTES,
        ),
        SimplifiedConsensusMessage::ReliableDelivery { .. }
        | SimplifiedConsensusMessage::Vote { .. }
        | SimplifiedConsensusMessage::TimeoutVote { .. } => (
            "simplified consensus vote",
            MAX_SIMPLIFIED_CONSENSUS_VOTE_FRAME_BYTES,
        ),
        SimplifiedConsensusMessage::QuorumCertificate { .. }
        | SimplifiedConsensusMessage::TimeoutCertificate { .. } => (
            "simplified consensus certificate",
            MAX_SIMPLIFIED_CONSENSUS_CERTIFICATE_FRAME_BYTES,
        ),
        SimplifiedConsensusMessage::StateSyncRequest { .. }
        | SimplifiedConsensusMessage::MaterialRequest { .. } => (
            "simplified consensus state-sync request",
            MAX_SIMPLIFIED_CONSENSUS_CONTROL_FRAME_BYTES,
        ),
        SimplifiedConsensusMessage::StateSyncChunk { .. }
        | SimplifiedConsensusMessage::MaterialChunk { .. } => (
            "simplified consensus state-sync chunk",
            MAX_SIMPLIFIED_CONSENSUS_STATE_SYNC_FRAME_BYTES,
        ),
    };
    let encoded = NetworkMessage::SimplifiedConsensus {
        chain_incarnation: crate::genesis::canonical_genesis()?.chain_incarnation(),
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

pub fn validate_simplified_target_admission_message_size(
    message: &SimplifiedTargetAdmissionMessage,
) -> Result<(), String> {
    let (kind, maximum) = match message {
        SimplifiedTargetAdmissionMessage::Vote { .. } => (
            "simplified target-admission vote",
            MAX_SIMPLIFIED_TARGET_ADMISSION_VOTE_FRAME_BYTES,
        ),
        SimplifiedTargetAdmissionMessage::CertifiedPackage { .. } => (
            "simplified target-admission certified package",
            MAX_SIMPLIFIED_TARGET_ADMISSION_PACKAGE_FRAME_BYTES,
        ),
    };
    let encoded = NetworkMessage::SimplifiedTargetAdmission {
        chain_incarnation: crate::genesis::canonical_genesis()?.chain_incarnation(),
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

pub fn validate_protected_pipeline_evidence_message(
    message: &ProtectedPipelineEvidenceMessage,
) -> Result<(), String> {
    let (kind, maximum) = match message {
        ProtectedPipelineEvidenceMessage::Evidence { object } => {
            object.validate_shape()?;
            (
                "protected-pipeline semantic evidence",
                MAX_PROTECTED_PIPELINE_EVIDENCE_FRAME_BYTES,
            )
        }
        ProtectedPipelineEvidenceMessage::MissingObjectsRequest {
            target_height,
            target_context_root,
            semantic_ids,
        } => {
            validate_protected_target_binding(*target_height, target_context_root)?;
            if semantic_ids.is_empty() || semantic_ids.len() > MAX_PROTECTED_PIPELINE_REQUEST_IDS {
                return Err(
                    "protected-pipeline missing-object request has invalid count".to_string(),
                );
            }
            let mut unique = std::collections::BTreeSet::new();
            for semantic_id in semantic_ids {
                semantic_id.validate("protected requested semantic id")?;
                if semantic_id.is_zero() || !unique.insert(semantic_id) {
                    return Err(
                        "protected-pipeline missing-object request has duplicate or zero id"
                            .to_string(),
                    );
                }
            }
            (
                "protected-pipeline missing-object request",
                MAX_PROTECTED_PIPELINE_REQUEST_FRAME_BYTES,
            )
        }
        ProtectedPipelineEvidenceMessage::MissingObjectsResponse {
            target_height,
            target_context_root,
            objects,
        } => {
            validate_protected_target_binding(*target_height, target_context_root)?;
            if objects.is_empty() || objects.len() > MAX_PROTECTED_PIPELINE_RESPONSE_OBJECTS {
                return Err(
                    "protected-pipeline missing-object response has invalid count".to_string(),
                );
            }
            let mut unique = std::collections::BTreeMap::new();
            for object in objects {
                object.validate_shape()?;
                if object.target_binding() != (*target_height, *target_context_root) {
                    return Err(
                        "protected-pipeline response object target binding mismatch".to_string()
                    );
                }
                if let Some(prior) = unique.insert(object.declared_semantic_id(), object) {
                    if prior != object {
                        return Err(
                            "protected-pipeline response has conflicting semantic objects"
                                .to_string(),
                        );
                    }
                }
            }
            (
                "protected-pipeline missing-object response",
                MAX_PROTECTED_PIPELINE_RESPONSE_FRAME_BYTES,
            )
        }
    };
    let encoded = NetworkMessage::ProtectedPipelineEvidence {
        message: message.clone(),
        chain_incarnation: crate::genesis::canonical_genesis()?.chain_incarnation(),
        genesis_hash: crate::genesis::canonical_genesis()?.hash().to_string(),
    };
    let frame_bytes = serde_json::to_vec(&encoded)
        .map_err(|error| format!("serialize {kind} frame: {error}"))?
        .len()
        .checked_add(4)
        .ok_or_else(|| format!("{kind} frame length overflow"))?;
    validate_typed_consensus_frame_length(kind, frame_bytes, maximum)
}

fn validate_protected_target_binding(
    target_height: Height,
    target_context_root: &Hash,
) -> Result<(), String> {
    if target_height.0 == 0 || target_context_root.is_zero() {
        return Err("protected-pipeline message has invalid target binding".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::etdag::tests::{complete_protected_input, fixture, target_admission_package};
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
    fn coordinated_sync_range_accepts_an_empty_terminal_response() {
        validate_coordinated_consensus_message_size(
            &CoordinatedConsensusMessage::CommittedBlockRange { packages: vec![] },
        )
        .expect("an empty coordinated sync range is a valid terminal response");
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

    #[test]
    fn target_admission_vote_and_package_have_independent_exact_wire_caps() {
        let mut fixture = fixture(5, None);
        let context = fixture.context.clone();
        let package = target_admission_package(&mut fixture, context.clone());
        let request = SimplifiedTargetAdmissionVoteRequest {
            context,
            ingress_kem_registry: package.ingress_kem_registry.clone(),
            vote: package.certificate.votes[0].clone(),
        };
        validate_simplified_target_admission_message_size(
            &SimplifiedTargetAdmissionMessage::Vote {
                request: request.clone(),
            },
        )
        .expect("ordinary target-admission vote must fit its wire budget");
        validate_simplified_target_admission_message_size(
            &SimplifiedTargetAdmissionMessage::CertifiedPackage {
                package: package.clone(),
            },
        )
        .expect("ordinary target-admission package must fit its wire budget");

        let mut oversized_vote = request;
        oversized_vote.vote.signature.signature_bytes =
            vec![0; MAX_SIMPLIFIED_TARGET_ADMISSION_VOTE_FRAME_BYTES];
        let error = validate_simplified_target_admission_message_size(
            &SimplifiedTargetAdmissionMessage::Vote {
                request: oversized_vote,
            },
        )
        .expect_err("oversized target-admission vote must fail closed");
        assert!(error.contains("target-admission vote frame"));

        let mut oversized_package = package;
        oversized_package.certificate.votes[0]
            .signature
            .signature_bytes = vec![0; MAX_SIMPLIFIED_TARGET_ADMISSION_PACKAGE_FRAME_BYTES];
        let error = validate_simplified_target_admission_message_size(
            &SimplifiedTargetAdmissionMessage::CertifiedPackage {
                package: oversized_package,
            },
        )
        .expect_err("oversized target-admission package must fail closed");
        assert!(error.contains("target-admission certified package frame"));
    }

    fn protected_evidence_fixture() -> (
        ProtectedPipelineSemanticObject,
        ProtectedPipelineSemanticObject,
        ProtectedPipelineSemanticObject,
    ) {
        let mut fixture = fixture(5, None);
        let input = complete_protected_input(&mut fixture);
        let transaction = input
            .certified_vertices
            .values()
            .find(|certified| certified.vertex.kind == VertexKind::Transactions)
            .expect("fixture has transaction vertex")
            .clone();
        let transaction_id = transaction.vertex.digest().unwrap();
        let transaction = ProtectedPipelineSemanticObject::CertifiedVertex {
            semantic_id: transaction_id,
            certified_vertex: transaction,
        };

        let authorization = ProtectedRevealAuthorization {
            authorization_version: PROTECTED_PIPELINE_VERSION,
            chain_id: fixture.context.chain_id,
            network_id: fixture.context.network_id.clone(),
            protocol_version: fixture.context.protocol_version.clone(),
            epoch: fixture.context.epoch,
            target_height: fixture.context.target_height,
            cluster_id: fixture.context.assigned_cluster_id,
            target_context_root: fixture.context.root().unwrap(),
            validator_set_commitment: fixture.context.active_validator_set_root,
            parameter_root: fixture.context.consensus_parameter_root,
            parent_proposal_id: BlockId::from("test-parent-proposal"),
            parent_block_id: BlockId::from("test-parent-block"),
            next_commitment_root: EtdagDigest::from_domain_bytes("test-commitment", b"commitment"),
            protected_batch_root: EtdagDigest::from_domain_bytes("test-batch", b"batch"),
            proposal_validation_certificate_root: Hash::from_domain_bytes("test-vc", b"vc"),
            certificate_evidence_root: EtdagDigest::from_domain_bytes("test-evidence", b"evidence"),
        };
        let authorization_id = authorization.root().unwrap();
        let next_commitment_root = authorization.next_commitment_root.clone();
        let protected_batch_root = authorization.protected_batch_root.clone();
        let authorization_object = ProtectedPipelineSemanticObject::RevealAuthorization {
            semantic_id: authorization_id.clone(),
            authorization,
        };
        let legacy_share = input
            .decrypt_shares
            .values()
            .flat_map(|shares| shares.iter())
            .next()
            .expect("fixture has decrypt share")
            .clone();
        let share = ProtectedRevealShareMessage {
            share_version: PROTECTED_PIPELINE_VERSION,
            chain_id: legacy_share.chain_id,
            network_id: legacy_share.network_id,
            protocol_version: fixture.context.protocol_version.clone(),
            profile_id: legacy_share.profile_id,
            epoch: legacy_share.epoch,
            target_height: legacy_share.target_height,
            target_context_root: legacy_share.target_context_root,
            cluster_id: legacy_share.cluster_id,
            authorization_root: authorization_id.clone(),
            next_commitment_root,
            protected_batch_root,
            tx_commitment: legacy_share.tx_commitment,
            validator_id: legacy_share.validator_id,
            share: legacy_share.share,
            share_commitment: legacy_share.share_commitment,
            parameter_root: fixture.context.consensus_parameter_root,
            key_id: legacy_share.key_id,
            signature: legacy_share.signature,
        };
        let mut share_object = ProtectedPipelineSemanticObject::RevealShare {
            semantic_id: EtdagDigest::from_domain_bytes("placeholder", b"placeholder"),
            authorization_id,
            share,
        };
        let share_id = share_object.computed_semantic_id().unwrap();
        if let ProtectedPipelineSemanticObject::RevealShare { semantic_id, .. } = &mut share_object
        {
            *semantic_id = share_id;
        }
        (transaction, authorization_object, share_object)
    }

    #[test]
    fn protected_semantic_ids_and_exact_object_bounds_fail_closed() {
        let (transaction, _authorization, mut share) = protected_evidence_fixture();
        validate_protected_pipeline_evidence_message(&ProtectedPipelineEvidenceMessage::Evidence {
            object: transaction.clone(),
        })
        .expect("ordinary certified vertex evidence fits bounded frame");

        let mut mismatched = transaction;
        if let ProtectedPipelineSemanticObject::CertifiedVertex { semantic_id, .. } =
            &mut mismatched
        {
            *semantic_id = EtdagDigest::from_domain_bytes("wrong", b"semantic-id");
        }
        assert!(validate_protected_pipeline_evidence_message(
            &ProtectedPipelineEvidenceMessage::Evidence { object: mismatched }
        )
        .unwrap_err()
        .contains("semantic id mismatch"));

        if let ProtectedPipelineSemanticObject::RevealShare { share, .. } = &mut share {
            share.signature.signature_bytes = vec![7; MAX_PROTECTED_PIPELINE_EVIDENCE_FRAME_BYTES];
        }
        let oversized_share_id = share.computed_semantic_id().unwrap();
        if let ProtectedPipelineSemanticObject::RevealShare { semantic_id, .. } = &mut share {
            *semantic_id = oversized_share_id;
        }
        assert!(validate_protected_pipeline_evidence_message(
            &ProtectedPipelineEvidenceMessage::Evidence { object: share }
        )
        .unwrap_err()
        .contains("semantic evidence frame"));
    }

    #[test]
    fn protected_missing_object_counts_and_target_bindings_are_bounded() {
        let ids = (0..=MAX_PROTECTED_PIPELINE_REQUEST_IDS)
            .map(|index| EtdagDigest::from_domain_bytes("request-id", &index.to_be_bytes()))
            .collect();
        let error = validate_protected_pipeline_evidence_message(
            &ProtectedPipelineEvidenceMessage::MissingObjectsRequest {
                target_height: Height(8),
                target_context_root: Hash::from_domain_bytes("target", b"height-8"),
                semantic_ids: ids,
            },
        )
        .expect_err("request above semantic-ID count must fail closed");
        assert!(error.contains("invalid count"));

        let (object, _, _) = protected_evidence_fixture();
        let (height, root) = object.target_binding();
        validate_protected_pipeline_evidence_message(
            &ProtectedPipelineEvidenceMessage::MissingObjectsResponse {
                target_height: height,
                target_context_root: root,
                objects: vec![object.clone(), object],
            },
        )
        .expect("exact duplicate response evidence is idempotent");
    }

    #[test]
    fn protected_evidence_is_a_distinct_wire_family_from_legacy_carriers() {
        let (object, _, _) = protected_evidence_fixture();
        let message = NetworkMessage::ProtectedPipelineEvidence {
            message: ProtectedPipelineEvidenceMessage::Evidence { object },
            chain_incarnation: crate::synergy_types::TESTNET_V3_CHAIN_INCARNATION,
            genesis_hash: crate::genesis::canonical_genesis()
                .unwrap()
                .hash()
                .to_string(),
        };
        let encoded = serde_json::to_vec(&message).unwrap();
        assert!(String::from_utf8_lossy(&encoded).contains("ProtectedPipelineEvidence"));
        assert!(matches!(
            serde_json::from_slice::<NetworkMessage>(&encoded).unwrap(),
            NetworkMessage::ProtectedPipelineEvidence { .. }
        ));
    }
}
