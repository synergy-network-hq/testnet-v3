use serde::{Deserialize, Serialize};
use synergy_data_availability::{AvailabilityProof, DataShard};

use crate::{
    certificates::{BatchValidationCertificate, CanonicalCertificate},
    execution::PreparedProtectedBatch,
    AvailabilityCertificate, AvailabilityVote, DecryptShareMessage, EtdagDigest, EtdagError,
    TransactionVertex,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShardCustodyMessage {
    pub vertex_id: EtdagDigest,
    pub proof: AvailabilityProof,
    pub shard: DataShard,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MissingArtifactRequest {
    pub artifact_id: EtdagDigest,
    pub shard_index: u32,
}

impl MissingArtifactRequest {
    pub fn validate(&self) -> Result<(), EtdagError> {
        self.artifact_id.validate()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveredShardCustody {
    pub request: MissingArtifactRequest,
    pub custody: ShardCustodyMessage,
}

impl RecoveredShardCustody {
    pub fn validate_shape(&self) -> Result<(), EtdagError> {
        self.request.validate()?;
        self.custody
            .proof
            .validate()
            .map_err(EtdagError::InvalidEnvelope)?;
        self.custody
            .shard
            .validate(synergy_data_availability::serve::MAX_SHARD_BYTES)
            .map_err(EtdagError::InvalidEnvelope)?;
        if self.custody.vertex_id != self.request.artifact_id
            || self.custody.proof.object_root != self.request.artifact_id.0
            || self.custody.proof.shard_index != self.request.shard_index
            || self.custody.shard.object_root != self.request.artifact_id.0
            || self.custody.shard.index != self.request.shard_index
            || self.custody.proof.shard_root != self.custody.shard.payload_root
        {
            return Err(EtdagError::InvalidEnvelope(
                "recovered shard custody differs from request".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertifiedExecutionHandoff {
    pub certificate: BatchValidationCertificate,
    pub prepared_batch: PreparedProtectedBatch,
}

impl CertifiedExecutionHandoff {
    pub fn validate_shape(&self) -> Result<(), EtdagError> {
        self.certificate.validate_shape()?;
        self.prepared_batch.validate()?;
        let protected = &self.certificate.execution_input;
        let context_root = self.prepared_batch.context.root()?;
        if context_root != self.prepared_batch.context_root
            || self.prepared_batch.context.target_height != self.prepared_batch.target_height
            || self.prepared_batch.context_root != protected.context_root
            || self.prepared_batch.target_height != protected.target_height
            || self.prepared_batch.protected_batch_root != protected.protected_batch_root
            || self.prepared_batch.reveal_transcript_root != protected.reveal_transcript_root
            || self.prepared_batch.transactions.len() != protected.ordered_vertex_ids.len()
            || self
                .prepared_batch
                .transactions
                .iter()
                .zip(&protected.ordered_vertex_ids)
                .any(|(transaction, vertex)| {
                    &transaction.vertex_id != vertex
                        || transaction.content_blind_order_key.validate().is_err()
                        || transaction.reveal_authorization.validate().is_err()
                        || transaction.reveal_authorization.context_root
                            != self.prepared_batch.context_root
                        || transaction.reveal_authorization.target_height
                            != self.prepared_batch.target_height
                        || transaction.reveal_authorization.protected_batch_root
                            != self.prepared_batch.protected_batch_root
                        || transaction.plaintext.is_empty()
                })
        {
            return Err(EtdagError::InvalidExecutionInput);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EtdagNetworkMessage {
    Vertex(TransactionVertex),
    AvailabilityVote(AvailabilityVote),
    AvailabilityCertificate(AvailabilityCertificate),
    ShardCustody(ShardCustodyMessage),
    DecryptShare(DecryptShareMessage),
    Certificate(CanonicalCertificate),
    CertifiedExecutionHandoff(CertifiedExecutionHandoff),
    RequestMissingArtifact(MissingArtifactRequest),
    RecoveredShardCustody(RecoveredShardCustody),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthenticatedEtdagMessage {
    pub message_version: u32,
    pub message_id: EtdagDigest,
    pub sender_id: String,
    pub key_id: String,
    pub message: EtdagNetworkMessage,
    pub signature: Vec<u8>,
}

impl AuthenticatedEtdagMessage {
    pub fn validate_shape(&self) -> Result<(), EtdagError> {
        self.message_id.validate()?;
        if self.message_version != 1
            || self.sender_id.trim().is_empty()
            || self.key_id.trim().is_empty()
            || self.signature.is_empty()
        {
            return Err(EtdagError::InvalidSignature);
        }
        let expected = EtdagDigest::from_canonical(
            "SYNERGY_ETDAG_NETWORK_MESSAGE_V1",
            &(
                self.message_version,
                self.sender_id.trim(),
                &self.key_id,
                &self.message,
            ),
        )?;
        if expected != self.message_id {
            return Err(EtdagError::ConflictingArtifact(
                "network message identifier mismatch".into(),
            ));
        }
        Ok(())
    }
}
