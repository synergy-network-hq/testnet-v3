use std::{
    fs,
    path::{Path, PathBuf},
};
pub struct SnapshotStorage {
    root: PathBuf,
}
impl SnapshotStorage {
    pub fn new(root: impl Into<PathBuf>) -> Result<Self, String> {
        let root = root.into();
        fs::create_dir_all(&root).map_err(|e| e.to_string())?;
        Ok(Self { root })
    }
    pub fn publish(&self, id: &str, bytes: &[u8]) -> Result<PathBuf, String> {
        if id.is_empty()
            || !id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err("invalid snapshot id".into());
        }
        let path = self.root.join(id);
        let tmp = self.root.join(format!(".{id}.tmp"));
        fs::write(&tmp, bytes).map_err(|e| e.to_string())?;
        fs::rename(&tmp, &path).map_err(|e| e.to_string())?;
        Ok(path)
    }
    pub fn root(&self) -> &Path {
        &self.root
    }
}
