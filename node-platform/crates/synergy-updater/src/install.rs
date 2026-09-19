use crate::StagedArtifact;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallReceipt {
    pub release_id: String,
    pub previous_release_id: String,
}

pub trait InstallCoordinator: Send + Sync {
    fn install(&self, artifact: &StagedArtifact) -> Result<InstallReceipt, String>;
}
