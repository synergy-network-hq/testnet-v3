use crate::{SynqArtifact, SynqError, SynqExecutionReceipt};

pub trait SynqStorage {
    fn put_artifact(&mut self, artifact: &SynqArtifact) -> Result<(), SynqError>;
    fn artifact(&self, code_hash: &str) -> Result<Option<SynqArtifact>, SynqError>;
    fn put_receipt(&mut self, receipt: &SynqExecutionReceipt) -> Result<(), SynqError>;
}

pub fn store_verified_artifact(
    storage: &mut impl SynqStorage,
    artifact: &SynqArtifact,
) -> Result<(), SynqError> {
    artifact.validate()?;
    storage.put_artifact(artifact)
}

pub fn load_verified_artifact(
    storage: &impl SynqStorage,
    code_hash: &str,
) -> Result<SynqArtifact, SynqError> {
    let artifact = storage
        .artifact(code_hash)?
        .ok_or(SynqError::ArtifactHashMismatch)?;
    artifact.validate()?;
    if artifact.code_hash != code_hash {
        return Err(SynqError::ArtifactHashMismatch);
    }
    Ok(artifact)
}
