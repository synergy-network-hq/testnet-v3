use crate::{SynqArtifact, SynqError};
use synergy_aegis::AegisVerifier;
/// SynQ artifact verification is supplied by the canonical Aegis engine.
pub trait SynqArtifactVerifier: AegisVerifier {
    fn verify(&self, artifact: &SynqArtifact) -> Result<(), SynqError>;
}
