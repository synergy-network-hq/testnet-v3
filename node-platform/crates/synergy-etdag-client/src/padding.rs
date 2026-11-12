#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PaddingError {
    EmptyPlaintext,
    OversizePlaintext,
}

pub fn pad_plaintext(plaintext: &[u8]) -> Result<Vec<u8>, PaddingError> {
    if plaintext.is_empty() {
        return Err(PaddingError::EmptyPlaintext);
    }
    synergy_etdag::crypto::pad_plaintext(plaintext).map_err(|_| PaddingError::OversizePlaintext)
}
