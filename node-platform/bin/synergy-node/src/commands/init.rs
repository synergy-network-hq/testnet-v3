use std::path::PathBuf;

use serde::Serialize;

use super::{absolute_path, nonempty};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InitializationRequest {
    pub node_name: String,
    pub role: String,
    pub configuration_path: PathBuf,
    pub data_directory: PathBuf,
}

pub fn request(
    node_name: &str,
    role: &str,
    configuration_path: &str,
    data_directory: &str,
) -> Result<InitializationRequest, String> {
    let configuration_path = absolute_path(configuration_path, "configuration path")?;
    let data_directory = absolute_path(data_directory, "data directory")?;
    if configuration_path == data_directory || configuration_path.starts_with(&data_directory) {
        return Err("configuration path and data directory must be distinct".into());
    }
    Ok(InitializationRequest {
        node_name: nonempty(node_name, "node name", 128)?,
        role: nonempty(role, "role", 64)?,
        configuration_path,
        data_directory,
    })
}

/// Initializes only a fresh local storage root. It neither joins a network nor
/// starts PoSy; signed genesis and the final authority are installed afterward.
pub fn initialize(request: &InitializationRequest) -> Result<serde_json::Value, String> {
    use std::fs;
    use synergy_storage::{write_schema_version, AtomicStore, NodeStorageLayout, SchemaVersion};

    if request.role != "validator" {
        return Err("only the validator installation role is implemented".into());
    }
    let root = &request.data_directory;
    if root
        .components()
        .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        return Err("storage initialization refuses parent-directory traversal".into());
    }
    for parent in root.ancestors().skip(1) {
        if fs::symlink_metadata(parent)
            .map_err(|error| format!("inspect storage parent: {error}"))?
            .file_type()
            .is_symlink()
        {
            return Err("storage initialization refuses symlink parents".into());
        }
    }
    // create_dir is exclusive, including for an existing empty or symlink root.
    fs::create_dir(root).map_err(|error| format!("create fresh storage root: {error}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(root, fs::Permissions::from_mode(0o700))
            .map_err(|error| format!("secure storage root: {error}"))?;
    }
    let layout = NodeStorageLayout::new(root.clone()).map_err(|error| error.to_string())?;
    for path in layout.columns() {
        fs::create_dir(&path).map_err(|error| format!("create storage column: {error}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .map_err(|error| format!("secure storage column: {error}"))?;
        }
    }
    let store = AtomicStore::new(root, 1024 * 1024).map_err(|error| error.to_string())?;
    write_schema_version(
        &store,
        &SchemaVersion {
            name: "synergy-node-storage".into(),
            version: 1,
        },
    )
    .map_err(|error| error.to_string())?;
    fs::File::open(root)
        .and_then(|file| file.sync_all())
        .map_err(|error| format!("sync fresh storage layout: {error}"))?;
    Ok(serde_json::json!({
        "node_name": request.node_name,
        "role": request.role,
        "data_directory": root,
        "storage_schema": "synergy-node-storage:1",
        "fresh_storage_initialized": true,
        "consensus_started": false,
        "signed_genesis_required": true,
        "safety_journal": "empty; native signer creates records only for actual operations"
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_initialization_is_fresh_durable_and_never_overwrites_state() {
        let parent =
            std::env::temp_dir().join(format!("synergy-native-init-{}", std::process::id()));
        std::fs::create_dir(&parent).unwrap();
        // macOS /var and /tmp are aliases; production intentionally rejects
        // aliases, so the fixture must supply its actual canonical parent.
        let parent = std::fs::canonicalize(parent).unwrap();
        let root = parent.join("data");
        let request = request(
            "fresh",
            "validator",
            parent.join("node.json").to_str().unwrap(),
            root.to_str().unwrap(),
        )
        .unwrap();
        let report = initialize(&request).unwrap();
        assert_eq!(report["consensus_started"], false);
        assert_eq!(
            std::fs::read(root.join("metadata/schema-version")).unwrap(),
            b"synergy-node-storage:1"
        );
        assert_eq!(
            std::fs::read_dir(root.join("consensus")).unwrap().count(),
            0
        );
        assert!(initialize(&request).is_err());
        std::fs::write(root.join("consensus/safety-sentinel"), b"must remain").unwrap();
        assert!(initialize(&request).is_err());
        assert_eq!(
            std::fs::read(root.join("consensus/safety-sentinel")).unwrap(),
            b"must remain"
        );
        std::fs::remove_dir_all(parent).unwrap();
    }
}
