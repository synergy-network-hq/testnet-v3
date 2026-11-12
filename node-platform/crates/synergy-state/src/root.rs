use sha3::{Digest, Sha3_256};

use crate::{StateError, WorldState};

pub fn state_root(state: &WorldState) -> Result<String, StateError> {
    state_root_with_size(state).map(|(root, _)| root)
}

/// Return the unchanged canonical root and JSON length without retaining a
/// full serialized World. The length-prefixed commitment requires two passes;
/// both serialize the same immutable state and use bounded writer scratch.
pub fn state_root_with_size(state: &WorldState) -> Result<(String, usize), StateError> {
    use std::io::Write;
    let encoded_bytes = world_encoded_size(state)?;
    let mut hasher = Sha3_256::new();
    hasher.update(b"SYNERGY_WORLD_STATE_ROOT_V1");
    hasher.update((encoded_bytes as u64).to_be_bytes());
    {
        let mut writer = std::io::BufWriter::with_capacity(8192, HashWriter(&mut hasher));
        serde_json::to_writer(&mut writer, state)
            .map_err(|error| StateError::Corrupt(error.to_string()))?;
        writer
            .flush()
            .map_err(|error| StateError::Corrupt(error.to_string()))?;
    }
    Ok((format!("{:x}", hasher.finalize()), encoded_bytes))
}

/// Exact canonical JSON size with bounded scratch. Resource accounting needs
/// the length only; computing and discarding a cryptographic root would repeat
/// serialization and SHA3 across both the current and parent worlds per write.
pub(crate) fn world_encoded_size(state: &WorldState) -> Result<usize, StateError> {
    let mut counter = CountWriter(0);
    serde_json::to_writer(&mut counter, state)
        .map_err(|error| StateError::Corrupt(error.to_string()))?;
    Ok(counter.0)
}

struct CountWriter(usize);
impl std::io::Write for CountWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0 = self
            .0
            .checked_add(bytes.len())
            .ok_or_else(|| std::io::Error::other("canonical World length overflow"))?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct HashWriter<'a>(&'a mut Sha3_256);
impl std::io::Write for HashWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn root_and_size_preserve_the_existing_canonical_commitment() {
        let mut world = WorldState::default();
        world.accounts.insert(
            "account-α".into(),
            crate::AccountState {
                balance_nwei: u128::MAX,
                nonce: u64::MAX,
                code_hash: Some("quoted\"hash".into()),
            },
        );
        world.protocol.insert("bytes".into(), vec![0, 127, 255]);
        world
            .protocol
            .insert("large-buffer-boundary".into(), vec![255; 1024 * 1024]);
        let bytes = serde_json::to_vec(&world).unwrap();
        let mut reference = Sha3_256::new();
        reference.update(b"SYNERGY_WORLD_STATE_ROOT_V1");
        reference.update((bytes.len() as u64).to_be_bytes());
        reference.update(&bytes);
        let expected = format!("{:x}", reference.finalize());
        assert_eq!(
            state_root_with_size(&world).unwrap(),
            (expected.clone(), bytes.len())
        );
        assert_eq!(state_root(&world).unwrap(), expected);
    }
}
