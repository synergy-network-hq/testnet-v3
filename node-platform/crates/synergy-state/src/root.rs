use sha3::{Digest, Sha3_256};

use crate::{StateError, WorldState};

pub fn state_root(state: &WorldState) -> Result<String, StateError> {
    let canonical =
        serde_json::to_vec(state).map_err(|error| StateError::Corrupt(error.to_string()))?;
    let mut hasher = Sha3_256::new();
    hasher.update(b"SYNERGY_WORLD_STATE_ROOT_V1");
    hasher.update((canonical.len() as u64).to_be_bytes());
    hasher.update(canonical);
    Ok(format!("{:x}", hasher.finalize()))
}
