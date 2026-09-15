use std::fs;
use std::path::{Path, PathBuf};

use crate::inspect::inspect;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepairPlan {
    pub stale_temporary_files: Vec<PathBuf>,
}

pub fn plan(root: &Path) -> Result<RepairPlan, String> {
    let inventory = inspect(root)?;
    let stale_temporary_files = inventory
        .entries
        .into_iter()
        .filter(|entry| {
            let name = entry
                .relative_path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or_default();
            name.contains(".tmp-") || name.ends_with(".export-tmp")
        })
        .map(|entry| entry.relative_path)
        .collect();
    Ok(RepairPlan {
        stale_temporary_files,
    })
}

pub fn apply(root: &Path, repair: &RepairPlan) -> Result<usize, String> {
    let canonical = root
        .canonicalize()
        .map_err(|error| format!("canonicalize database root: {error}"))?;
    let mut removed = 0usize;
    for relative in &repair.stale_temporary_files {
        if relative.is_absolute()
            || relative
                .components()
                .any(|component| matches!(component, std::path::Component::ParentDir))
        {
            return Err("repair plan contains an unsafe path".into());
        }
        let path = canonical.join(relative);
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("reinspect repair target {}: {error}", path.display()))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(format!(
                "repair target is not a regular file: {}",
                path.display()
            ));
        }
        fs::remove_file(&path)
            .map_err(|error| format!("remove stale temporary {}: {error}", path.display()))?;
        removed += 1;
    }
    Ok(removed)
}
