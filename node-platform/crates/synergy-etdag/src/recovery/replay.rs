use crate::{
    certificates::{canonical_certificate_root, CanonicalCertificate},
    EncryptedTransactionEnvelope, EtdagError, TransactionVertex,
};

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RecoveryArtifact {
    ProtectedInput(EncryptedTransactionEnvelope),
    Vertex(TransactionVertex),
    Certificate(CanonicalCertificate),
}

impl RecoveryArtifact {
    pub fn validate(&self) -> Result<(), EtdagError> {
        match self {
            Self::ProtectedInput(envelope) => envelope.validate(),
            Self::Vertex(vertex) => {
                vertex.validate()?;
                crate::dag::validate_vertex_identity(vertex)
            }
            Self::Certificate(certificate) => canonical_certificate_root(certificate).map(|_| ()),
        }
    }
}

pub trait RecoveryTarget {
    fn apply_protected_input(
        &mut self,
        envelope: EncryptedTransactionEnvelope,
    ) -> Result<(), EtdagError>;

    fn apply_vertex(&mut self, vertex: TransactionVertex) -> Result<(), EtdagError>;

    fn apply_certificate(&mut self, certificate: CanonicalCertificate) -> Result<(), EtdagError>;
}

pub fn replay_artifacts(
    artifacts: Vec<RecoveryArtifact>,
    target: &mut impl RecoveryTarget,
) -> Result<(), EtdagError> {
    for artifact in &artifacts {
        artifact.validate()?;
    }
    for artifact in artifacts {
        match artifact {
            RecoveryArtifact::ProtectedInput(envelope) => target.apply_protected_input(envelope)?,
            RecoveryArtifact::Vertex(vertex) => target.apply_vertex(vertex)?,
            RecoveryArtifact::Certificate(certificate) => target.apply_certificate(certificate)?,
        }
    }
    Ok(())
}
