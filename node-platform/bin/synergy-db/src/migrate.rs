use std::fs;
use std::path::Path;

use synergy_storage::{write_schema_version, AtomicStore, SchemaVersion};

pub fn migrate(root: &Path, schema_name: &str, target_version: u32) -> Result<(), String> {
    if schema_name.trim().is_empty() || target_version == 0 {
        return Err("migration requires a schema name and nonzero target version".into());
    }
    let marker = root.join("metadata/schema-version");
    let current = if marker.exists() {
        let text = fs::read_to_string(&marker)
            .map_err(|error| format!("read current schema marker: {error}"))?;
        let (name, version) = text
            .trim()
            .split_once(':')
            .ok_or("invalid current schema marker")?;
        if name != schema_name {
            return Err("schema name differs from current database".into());
        }
        version
            .parse::<u32>()
            .map_err(|_| "invalid current schema version")?
    } else {
        0
    };
    if target_version < current {
        return Err("schema downgrade is forbidden".into());
    }
    if target_version > current.saturating_add(1) {
        return Err("schema migration must advance exactly one version at a time".into());
    }
    if target_version == current {
        return Ok(());
    }
    let store = AtomicStore::new(root, 1024).map_err(|error| error.to_string())?;
    write_schema_version(
        &store,
        &SchemaVersion {
            name: schema_name.to_string(),
            version: target_version,
        },
    )
    .map_err(|error| error.to_string())
}
