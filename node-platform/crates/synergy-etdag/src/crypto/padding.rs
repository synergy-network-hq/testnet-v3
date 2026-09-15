use crate::{EtdagError, CIPHERTEXT_SIZE_CLASSES};

const LENGTH_PREFIX_BYTES: usize = 4;

pub fn pad_plaintext(plaintext: &[u8]) -> Result<Vec<u8>, EtdagError> {
    let required = plaintext
        .len()
        .checked_add(LENGTH_PREFIX_BYTES)
        .ok_or(EtdagError::InvalidCapacity)?;
    let size = CIPHERTEXT_SIZE_CLASSES
        .iter()
        .copied()
        .find(|size| *size >= required)
        .ok_or(EtdagError::InvalidCiphertextClasses)?;
    let length = u32::try_from(plaintext.len()).map_err(|_| EtdagError::InvalidCapacity)?;
    let mut padded = vec![0_u8; size];
    padded[..LENGTH_PREFIX_BYTES].copy_from_slice(&length.to_be_bytes());
    padded[LENGTH_PREFIX_BYTES..required].copy_from_slice(plaintext);
    Ok(padded)
}

pub fn unpad_plaintext(padded: &[u8]) -> Result<Vec<u8>, EtdagError> {
    if !CIPHERTEXT_SIZE_CLASSES.contains(&padded.len()) || padded.len() < LENGTH_PREFIX_BYTES {
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
