use std::fs;
use std::io::Read;
use std::path::Path;

use synergy_storage::IntegrityDigest;

use crate::inspect::{inspect, DatabaseInventory};

const MAX_RECORD_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct VerifiedDatabase {
    pub inventory: DatabaseInventory,
    pub digest: IntegrityDigest,
    pub schema: Option<(String, u32)>,
}

pub fn verify(root: &Path) -> Result<VerifiedDatabase, String> {
    let inventory = inspect(root)?;
    let mut commitment = Vec::new();
    for entry in &inventory.entries {
        if entry.bytes > MAX_RECORD_BYTES {
            return Err(format!(
                "database record {} exceeds the offline verifier bound",
                entry.relative_path.display()
            ));
        }
        let path = root.join(&entry.relative_path);
        let mut bytes = Vec::with_capacity(entry.bytes as usize);
        fs::File::open(&path)
            .and_then(|file| file.take(MAX_RECORD_BYTES + 1).read_to_end(&mut bytes))
            .map_err(|error| format!("read database record {}: {error}", path.display()))?;
        if bytes.len() as u64 != entry.bytes {
            return Err(format!(
                "database record changed during verification: {}",
                path.display()
            ));
        }
        let digest = IntegrityDigest::of("SYNERGY_DB_RECORD_V1", &bytes);
        append(
            &mut commitment,
            entry.relative_path.to_string_lossy().as_bytes(),
        );
        append(&mut commitment, digest.0.as_bytes());
    }
    let schema_path = root.join("metadata/schema-version");
    let schema = if schema_path.exists() {
        let value = fs::read_to_string(&schema_path)
            .map_err(|error| format!("read schema version: {error}"))?;
        let (name, version) = value
            .trim()
            .split_once(':')
            .ok_or("invalid schema-version record")?;
        let version = version
            .parse::<u32>()
            .map_err(|_| "invalid schema version number")?;
        if name.trim().is_empty() || version == 0 {
            return Err("invalid schema-version record".into());
        }
        Some((name.to_string(), version))
    } else {
        None
    };
    Ok(VerifiedDatabase {
        inventory,
        digest: IntegrityDigest::of("SYNERGY_DB_EXPORT_SET_V1", &commitment),
        schema,
    })
}

fn append(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u64).to_be_bytes());
    output.extend_from_slice(value);
}
