use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatabaseEntry {
    pub relative_path: PathBuf,
    pub bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatabaseInventory {
    pub root: PathBuf,
    pub entries: Vec<DatabaseEntry>,
    pub total_bytes: u64,
}

pub fn inspect(root: &Path) -> Result<DatabaseInventory, String> {
    let metadata = fs::symlink_metadata(root)
        .map_err(|error| format!("inspect database root {}: {error}", root.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("database root must be a regular directory, not a symlink".into());
    }
    let mut entries = Vec::new();
    walk(root, root, &mut entries)?;
    entries.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    let total_bytes = entries.iter().try_fold(0u64, |total, entry| {
        total
            .checked_add(entry.bytes)
            .ok_or("database byte count overflow")
    })?;
    Ok(DatabaseInventory {
        root: root.to_path_buf(),
        entries,
        total_bytes,
    })
}

fn walk(root: &Path, directory: &Path, output: &mut Vec<DatabaseEntry>) -> Result<(), String> {
    let mut entries = fs::read_dir(directory)
        .map_err(|error| format!("read database directory {}: {error}", directory.display()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("read database entry: {error}"))?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("inspect database entry {}: {error}", path.display()))?;
        if metadata.file_type().is_symlink() {
            return Err(format!(
                "database contains forbidden symlink {}",
                path.display()
            ));
        }
        if metadata.is_dir() {
            walk(root, &path, output)?;
        } else if metadata.is_file() {
            let relative_path = path
                .strip_prefix(root)
                .map_err(|_| "database traversal escaped its root")?
                .to_path_buf();
            output.push(DatabaseEntry {
                relative_path,
                bytes: metadata.len(),
            });
        } else {
            return Err(format!(
                "database contains unsupported entry {}",
                path.display()
            ));
        }
    }
    Ok(())
}
