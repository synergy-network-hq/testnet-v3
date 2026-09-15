mod blocks;
mod consensus;
mod etdag;
mod metadata;
mod peers;
mod state;

pub use blocks::BlocksColumn;
pub use consensus::ConsensusColumn;
pub use etdag::EtdagColumn;
pub use metadata::MetadataColumn;
pub use peers::PeersColumn;
pub use state::StateColumn;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeStorageLayout {
    root: std::path::PathBuf,
}

impl NodeStorageLayout {
    pub fn new(root: impl Into<std::path::PathBuf>) -> Result<Self, crate::StorageError> {
        let root = root.into();
        if root.as_os_str().is_empty() || !root.is_absolute() {
            return Err(crate::StorageError::InvalidPath);
        }
        Ok(Self { root })
    }

    pub fn root(&self) -> &std::path::Path {
        &self.root
    }

    pub fn blocks(&self) -> std::path::PathBuf {
        self.root.join(BlocksColumn::NAME)
    }

    pub fn state(&self) -> std::path::PathBuf {
        self.root.join(StateColumn::NAME)
    }

    pub fn consensus(&self) -> std::path::PathBuf {
        self.root.join(ConsensusColumn::NAME)
    }

    pub fn etdag(&self) -> std::path::PathBuf {
        self.root.join(EtdagColumn::NAME)
    }

    pub fn peers(&self) -> std::path::PathBuf {
        self.root.join(PeersColumn::NAME)
    }

    pub fn metadata(&self) -> std::path::PathBuf {
        self.root.join(MetadataColumn::NAME)
    }

    pub fn columns(&self) -> [std::path::PathBuf; 6] {
        [
            self.blocks(),
            self.state(),
            self.consensus(),
            self.etdag(),
            self.peers(),
            self.metadata(),
        ]
    }
}

pub trait StorageColumn {
    const NAME: &'static str;

    fn record(key: &str) -> Result<String, crate::StorageError> {
        if key.is_empty() || key.len() > 240 || key.contains('/') || key == "." || key == ".." {
            return Err(crate::StorageError::InvalidPath);
        }
        Ok(format!("{}/{}", Self::NAME, key))
    }
}
