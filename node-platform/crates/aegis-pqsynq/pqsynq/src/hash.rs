//! Canonical SHA256 ownership delegated to APQE without changing transcripts.
use synergy_address_engine::apqe::{HashAlgorithm, HashStream, Primitives};
pub(crate) struct Sha256(HashStream);
impl Sha256 {
    pub(crate) fn new() -> Self {
        Self(
            Primitives
                .hash_stream(HashAlgorithm::Sha256)
                .expect("fixed SHA256 supported"),
        )
    }
    pub(crate) fn update(&mut self, bytes: impl AsRef<[u8]>) {
        self.0.update(bytes.as_ref());
    }
    pub(crate) fn finalize(self) -> [u8; 32] {
        self.0.finalize().try_into().expect("fixed SHA256 length")
    }
    pub(crate) fn digest(bytes: impl AsRef<[u8]>) -> [u8; 32] {
        let mut hash = Self::new();
        hash.update(bytes);
        hash.finalize()
    }
}
