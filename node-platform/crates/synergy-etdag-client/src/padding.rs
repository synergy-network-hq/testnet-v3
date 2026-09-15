use synergy_etdag::CIPHERTEXT_SIZE_CLASSES;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PaddingError {
    EmptyPlaintext,
    OversizePlaintext,
}

pub fn pad_plaintext(plaintext: &[u8]) -> Result<Vec<u8>, PaddingError> {
    if plaintext.is_empty() {
        return Err(PaddingError::EmptyPlaintext);
    }
    let size = CIPHERTEXT_SIZE_CLASSES
        .iter()
        .copied()
        .find(|size| plaintext.len() <= *size)
        .ok_or(PaddingError::OversizePlaintext)?;
    let mut padded = Vec::with_capacity(size);
    padded.extend_from_slice(plaintext);
    padded.resize(size, 0);
    Ok(padded)
}
