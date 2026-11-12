use std::{fs, path::Path};
pub fn enforce(root: &Path, keep: usize) -> Result<usize, String> {
    if keep == 0 {
        return Err("retention must be nonzero".into());
    }
    let mut entries = fs::read_dir(root)
        .map_err(|e| e.to_string())?
        .filter_map(Result::ok)
        .filter(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
        .collect::<Vec<_>>();
    entries.sort_by_key(|e| e.metadata().and_then(|m| m.modified()).ok());
    let remove = entries.len().saturating_sub(keep);
    for e in entries.into_iter().take(remove) {
        fs::remove_file(e.path()).map_err(|x| x.to_string())?;
    }
    Ok(remove)
}
