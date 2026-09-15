use std::path::Path;

use serde::Serialize;
use synergy_identity::NodeAddress;

use crate::aegis_keys::{fingerprint, read_bounded, read_metadata, MAX_KEY_BYTES};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Inspection {
    pub node_address: NodeAddress,
    pub key_id: String,
    pub purpose: String,
    pub state: String,
    pub algorithm: String,
    pub public_key_bytes: usize,
    pub public_key_fingerprint: String,
}

pub fn inspect(metadata_path: &Path, public_key_path: &Path) -> Result<Inspection, String> {
    let metadata = read_metadata(metadata_path)?;
    let public_key = read_bounded(public_key_path, MAX_KEY_BYTES, "public key")?;
    if public_key != metadata.record.public_key
        || fingerprint(&public_key) != metadata.public_key_fingerprint
    {
        return Err("public key does not match governed metadata".into());
    }
    Ok(Inspection {
        node_address: metadata.node_address,
        key_id: metadata.record.id.as_str().into(),
        purpose: format!("{:?}", metadata.record.purpose),
        state: format!("{:?}", metadata.record.state),
        algorithm: metadata.algorithm,
        public_key_bytes: public_key.len(),
        public_key_fingerprint: fingerprint(&public_key),
    })
}
