use synergy_etdag::{EtdagError, TargetAdmissionContextV3};

#[derive(Debug, Clone)]
pub struct VerifiedTargetContext(TargetAdmissionContextV3);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetContextError {
    Invalid(EtdagError),
}

impl VerifiedTargetContext {
    pub fn new(context: TargetAdmissionContextV3) -> Result<Self, TargetContextError> {
        context.validate().map_err(TargetContextError::Invalid)?;
        Ok(Self(context))
    }

    pub fn inner(&self) -> &TargetAdmissionContextV3 {
        &self.0
    }

    pub fn target_height(&self) -> u64 {
        self.0.target_height
    }

    pub fn context_root(&self) -> Result<synergy_etdag::EtdagDigest, TargetContextError> {
        self.0.root().map_err(TargetContextError::Invalid)
    }
}
