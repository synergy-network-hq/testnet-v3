use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{Read, Take};
use std::path::Path;

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use synergy_aegis::KeyId;
use synergy_storage::AtomicStore;

pub const MAX_MANIFEST_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_KEY_BYTES: u64 = 64 * 1024;
const MAX_BOOTSEEDS: usize = 64;
const MAX_VERSION_BINDINGS: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnsignedManifest {
    pub format_version: u32,
    pub chain_id: u64,
    pub network_id: String,
    pub genesis_hash: String,
    pub release_version: String,
    pub protocol_versions: BTreeMap<String, String>,
    pub schema_versions: BTreeMap<String, u64>,
    pub validator_set_root: String,
    pub validator_consensus_key_root: String,
    pub posy_parameter_root: String,
    pub etdag_parameter_root: String,
    pub role_profile_root: String,
    pub transport_registry_root: String,
    pub bootseeds: Vec<String>,
    pub manifest_authority_key_id: String,
}

impl UnsignedManifest {
    pub fn validate(&self) -> Result<(), String> {
        if self.format_version != 1
            || self.chain_id != 1266
            || !bounded_text(&self.network_id, 128)
            || !bounded_text(&self.release_version, 128)
            || !bounded_text(&self.manifest_authority_key_id, 128)
            || KeyId::new(self.manifest_authority_key_id.clone()).is_err()
        {
            return Err("invalid manifest identity or authority binding".into());
        }
        for (label, root) in [
            ("genesis", &self.genesis_hash),
            ("validator set", &self.validator_set_root),
            (
                "validator consensus key",
                &self.validator_consensus_key_root,
            ),
            ("PoSy parameter", &self.posy_parameter_root),
            ("ETDAG parameter", &self.etdag_parameter_root),
            ("role profile", &self.role_profile_root),
            ("transport registry", &self.transport_registry_root),
        ] {
            if !hex64(root) {
                return Err(format!("{label} root must be canonical lowercase SHA3-256"));
            }
        }
        if self.protocol_versions.is_empty()
            || self.protocol_versions.len() > MAX_VERSION_BINDINGS
            || self.protocol_versions.iter().any(|(component, version)| {
                !bounded_text(component, 64) || !bounded_text(version, 128)
            })
        {
            return Err("invalid protocol-version bindings".into());
        }
        if self.schema_versions.is_empty()
            || self.schema_versions.len() > MAX_VERSION_BINDINGS
            || self
                .schema_versions
                .iter()
                .any(|(schema, version)| !bounded_text(schema, 64) || *version == 0)
        {
            return Err("invalid schema-version bindings".into());
        }
        let mut bootseeds = BTreeSet::new();
        if self.bootseeds.is_empty()
            || self.bootseeds.len() > MAX_BOOTSEEDS
            || self.bootseeds.iter().any(|bootseed| {
                !bounded_text(bootseed, 512) || !bootseeds.insert(bootseed.as_str())
            })
        {
            return Err("invalid or duplicate bootseed binding".into());
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|error| format!("encode canonical manifest: {error}"))
    }

    pub fn manifest_hash(&self) -> Result<String, String> {
        let bytes = self.canonical_bytes()?;
        let mut hasher = Sha3_256::new();
        hasher.update(b"SYNERGY_CHAIN1266_NETWORK_MANIFEST_V1");
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(bytes);
        Ok(format!("{:x}", hasher.finalize()))
    }
}

pub fn decode<T: DeserializeOwned>(path: &Path, maximum: u64) -> Result<T, String> {
    serde_json::from_slice(&read_bounded(path, maximum)?)
        .map_err(|error| format!("decode {}: {error}", path.display()))
}

pub fn read_bounded(path: &Path, maximum: u64) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("inspect {}: {error}", path.display()))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > maximum
    {
        return Err(format!(
            "{} must be a bounded regular non-symlink file",
            path.display()
        ));
    }
    let file = File::open(path).map_err(|error| format!("open {}: {error}", path.display()))?;
    let mut reader: Take<File> = file.take(maximum.saturating_add(1));
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    reader
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read {}: {error}", path.display()))?;
    if bytes.is_empty() || bytes.len() as u64 > maximum {
        return Err(format!("{} changed size while reading", path.display()));
    }
    Ok(bytes)
}

pub fn ensure_private(path: &Path) -> Result<(), String> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| format!("inspect private key: {error}"))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_KEY_BYTES
    {
        return Err("private key must be a bounded regular non-symlink file".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err("private key is accessible to group or others".into());
        }
    }
    Ok(())
}

pub fn write_new(path: &Path, value: &impl Serialize) -> Result<(), String> {
    if path.exists() {
        return Err(format!("refusing to overwrite {}", path.display()));
    }
    let bytes =
        serde_json::to_vec_pretty(value).map_err(|error| format!("encode output: {error}"))?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_MANIFEST_BYTES {
        return Err("manifest output exceeds the bounded size".into());
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or("output must have an explicit parent directory")?;
    let metadata = fs::symlink_metadata(parent)
        .map_err(|error| format!("inspect output directory: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("output parent must be a pre-existing non-symlink directory".into());
    }
    let file_name = path.file_name().ok_or("output has no file name")?;
    let store =
        AtomicStore::new(parent, MAX_MANIFEST_BYTES as usize).map_err(|error| error.to_string())?;
    store
        .write_atomic(file_name, &bytes)
        .map_err(|error| error.to_string())
}

pub fn hex64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn bounded_text(value: &str, maximum: usize) -> bool {
    !value.trim().is_empty() && value.len() <= maximum && !value.contains(char::is_control)
}
