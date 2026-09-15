use std::fs::{self, File, OpenOptions};
use std::io::{Read, Take, Write};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use synergy_aegis::{KeyId, KeyPurpose, KeyRecord, KeyState};
use synergy_identity::{NodeAddress, NodeClass};

pub const MAX_KEY_BYTES: u64 = 64 * 1024;
pub const MAX_METADATA_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyMetadata {
    pub format_version: u32,
    #[serde(alias = "node_id")]
    pub node_address: NodeAddress,
    pub record: KeyRecord,
    pub algorithm: String,
    pub public_key_fingerprint: String,
}

impl KeyMetadata {
    pub fn new(
        node_address: NodeAddress,
        record: KeyRecord,
        algorithm: &str,
    ) -> Result<Self, String> {
        let metadata = Self {
            format_version: 1,
            node_address,
            public_key_fingerprint: fingerprint(&record.public_key),
            record,
            algorithm: algorithm.into(),
        };
        metadata.validate()?;
        Ok(metadata)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.format_version != 1
            || self.algorithm.trim().is_empty()
            || self.record.public_key.is_empty()
            || self.public_key_fingerprint != fingerprint(&self.record.public_key)
        {
            return Err("invalid key metadata".into());
        }
        KeyId::new(self.record.id.as_str().to_string()).map_err(|error| error.to_string())?;
        match self.record.purpose {
            KeyPurpose::P2pIdentity
            | KeyPurpose::PosyConsensus
            | KeyPurpose::Manifest
            | KeyPurpose::Snapshot => {
                if self.algorithm != "ML-DSA-65" {
                    return Err("signing key metadata must use ML-DSA-65".into());
                }
            }
            KeyPurpose::EtdagDecryption => {
                if self.algorithm != "ML-KEM-768" {
                    return Err("ETDAG key metadata must use ML-KEM-768".into());
                }
            }
            KeyPurpose::NodeIdentity => {
                return Err("node identity metadata must describe its P2P possession key".into());
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrittenBundle {
    pub secret_key_path: PathBuf,
    pub public_key_path: PathBuf,
    pub metadata_path: PathBuf,
}

pub fn fingerprint(bytes: &[u8]) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update(b"SYNERGY_KEY_FINGERPRINT_V1");
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

pub fn valid_consensus_node_address(value: &str) -> bool {
    NodeAddress::parse(value)
        .is_ok_and(|address| address.class() == NodeClass::ConsensusAndChainIntegrity)
}

pub fn file_stem(key_id: &KeyId) -> String {
    key_id
        .as_str()
        .bytes()
        .map(|byte| match byte {
            b':' | b'/' => '_',
            value => value as char,
        })
        .collect()
}

pub fn write_bundle(
    output_directory: &Path,
    metadata: &KeyMetadata,
    public_key: &[u8],
    secret_key: &mut [u8],
) -> Result<WrittenBundle, String> {
    metadata.validate()?;
    if metadata.record.public_key != public_key {
        return Err("metadata public key does not match generated public key".into());
    }
    let directory = validate_output_directory(output_directory)?;
    let stem = file_stem(&metadata.record.id);
    let result = WrittenBundle {
        secret_key_path: directory.join(format!("{stem}.secret.key")),
        public_key_path: directory.join(format!("{stem}.public.key")),
        metadata_path: directory.join(format!("{stem}.metadata.json")),
    };
    for path in [
        &result.secret_key_path,
        &result.public_key_path,
        &result.metadata_path,
    ] {
        if path.exists() {
            return Err(format!("refusing to overwrite {}", path.display()));
        }
    }

    let metadata_bytes =
        serde_json::to_vec_pretty(metadata).map_err(|error| format!("encode metadata: {error}"))?;
    let mut created = Vec::new();
    let write_result = (|| {
        write_new(&result.secret_key_path, secret_key, true)?;
        created.push(result.secret_key_path.clone());
        write_new(&result.public_key_path, public_key, false)?;
        created.push(result.public_key_path.clone());
        write_new(&result.metadata_path, &metadata_bytes, false)?;
        created.push(result.metadata_path.clone());
        sync_directory(&directory)?;
        Ok(())
    })();
    wipe(secret_key);
    if let Err(error) = write_result {
        for path in created.into_iter().rev() {
            let _ = fs::remove_file(path);
        }
        return Err(error);
    }
    Ok(result)
}

pub fn read_bounded(path: &Path, maximum: u64, label: &str) -> Result<Vec<u8>, String> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| format!("inspect {label}: {error}"))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > maximum
    {
        return Err(format!(
            "{label} must be a bounded regular non-symlink file"
        ));
    }
    let file = File::open(path).map_err(|error| format!("open {label}: {error}"))?;
    let mut reader: Take<File> = file.take(maximum.saturating_add(1));
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    reader
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read {label}: {error}"))?;
    if bytes.is_empty() || bytes.len() as u64 > maximum {
        return Err(format!(
            "{label} changed outside its permitted size while reading"
        ));
    }
    Ok(bytes)
}

pub fn read_metadata(path: &Path) -> Result<KeyMetadata, String> {
    let bytes = read_bounded(path, MAX_METADATA_BYTES, "key metadata")?;
    let metadata = serde_json::from_slice::<KeyMetadata>(&bytes)
        .map_err(|error| format!("decode key metadata: {error}"))?;
    metadata.validate()?;
    Ok(metadata)
}

pub fn write_public_json(path: &Path, value: &impl Serialize) -> Result<(), String> {
    if path.exists() {
        return Err(format!("refusing to overwrite {}", path.display()));
    }
    let bytes =
        serde_json::to_vec_pretty(value).map_err(|error| format!("encode JSON output: {error}"))?;
    if bytes.len() as u64 > MAX_METADATA_BYTES {
        return Err("JSON output exceeds the keytool limit".into());
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or("output must have an explicit parent directory")?;
    validate_output_directory(parent)?;
    write_new(path, &bytes, false)?;
    if let Err(error) = sync_directory(parent) {
        let _ = fs::remove_file(path);
        return Err(error);
    }
    Ok(())
}

fn validate_output_directory(path: &Path) -> Result<PathBuf, String> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| format!("inspect output directory: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("output directory must be a pre-existing non-symlink directory".into());
    }
    fs::canonicalize(path).map_err(|error| format!("resolve output directory: {error}"))
}

fn write_new(path: &Path, bytes: &[u8], private: bool) -> Result<(), String> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(if private { 0o600 } else { 0o644 });
    let mut file = options
        .open(path)
        .map_err(|error| format!("create {}: {error}", path.display()))?;
    if let Err(error) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(format!("persist {}: {error}", path.display()));
    }
    Ok(())
}

fn sync_directory(path: &Path) -> Result<(), String> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("sync output directory: {error}"))
}

pub fn wipe(bytes: &mut [u8]) {
    for byte in bytes {
        unsafe { std::ptr::write_volatile(byte, 0) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}
