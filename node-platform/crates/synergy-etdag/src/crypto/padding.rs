use crate::{EtdagError, CIPHERTEXT_SIZE_CLASSES};

const LENGTH_PREFIX_BYTES: usize = 4;
/// AES-256-GCM authentication tag included in the governed ciphertext classes.
const AEAD_TAG_BYTES: usize = 16;

pub fn pad_plaintext(plaintext: &[u8]) -> Result<Vec<u8>, EtdagError> {
    let required = plaintext
        .len()
        .checked_add(LENGTH_PREFIX_BYTES)
        .ok_or(EtdagError::InvalidCapacity)?;
    let size = CIPHERTEXT_SIZE_CLASSES
        .iter()
        .copied()
        .find(|size| *size >= required + AEAD_TAG_BYTES)
        .ok_or(EtdagError::InvalidCiphertextClasses)?;
    let length = u32::try_from(plaintext.len()).map_err(|_| EtdagError::InvalidCapacity)?;
    let mut padded = vec![0_u8; size - AEAD_TAG_BYTES];
    padded[..LENGTH_PREFIX_BYTES].copy_from_slice(&length.to_be_bytes());
    padded[LENGTH_PREFIX_BYTES..required].copy_from_slice(plaintext);
    Ok(padded)
}

pub fn unpad_plaintext(padded: &[u8]) -> Result<Vec<u8>, EtdagError> {
    if !padded
        .len()
        .checked_add(AEAD_TAG_BYTES)
        .is_some_and(|size| CIPHERTEXT_SIZE_CLASSES.contains(&size))
        || padded.len() < LENGTH_PREFIX_BYTES
    {
        return Err(EtdagError::InvalidCiphertextClasses);
    }
    let length = u32::from_be_bytes(
        padded[..LENGTH_PREFIX_BYTES]
            .try_into()
            .map_err(|_| EtdagError::Corrupt("invalid padding prefix".into()))?,
    ) as usize;
    let end = length
        .checked_add(LENGTH_PREFIX_BYTES)
        .ok_or(EtdagError::InvalidCapacity)?;
    if end > padded.len() || padded[end..].iter().any(|byte| *byte != 0) {
        return Err(EtdagError::Corrupt("non-canonical ETDAG padding".into()));
    }
    Ok(padded[LENGTH_PREFIX_BYTES..end].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn padding_reserves_authenticated_ciphertext_tag_and_round_trips_boundaries() {
        for &class in CIPHERTEXT_SIZE_CLASSES {
            let plaintext = vec![9; class - LENGTH_PREFIX_BYTES - AEAD_TAG_BYTES];
            let padded = pad_plaintext(&plaintext).unwrap();
            assert_eq!(padded.len() + AEAD_TAG_BYTES, class);
            assert_eq!(unpad_plaintext(&padded).unwrap(), plaintext);
        }
        let mut padded = pad_plaintext(b"transaction").unwrap();
        *padded.last_mut().unwrap() = 1;
        assert!(unpad_plaintext(&padded).is_err());
    }
}
