use super::VerifiedRevealAuthorization;
use crate::{EtdagDigest, EtdagError};

#[derive(Debug, Clone)]
pub struct RevealGate {
    context_root: EtdagDigest,
    target_height: u64,
    protected_batch_root: EtdagDigest,
    authorization: Option<VerifiedRevealAuthorization>,
}

impl RevealGate {
    pub fn new(
        context_root: EtdagDigest,
        target_height: u64,
        protected_batch_root: EtdagDigest,
    ) -> Result<Self, EtdagError> {
        context_root.validate()?;
        protected_batch_root.validate()?;
        if target_height == 0 {
            return Err(EtdagError::ContextMismatch);
        }
        Ok(Self {
            context_root,
            target_height,
            protected_batch_root,
            authorization: None,
        })
    }
    pub fn authorize(&mut self, verified: VerifiedRevealAuthorization) -> Result<(), EtdagError> {
        let authorization = verified.authorization();
        authorization.validate()?;
        if authorization.context_root != self.context_root
            || authorization.target_height != self.target_height
            || authorization.protected_batch_root != self.protected_batch_root
        {
            return Err(EtdagError::UnauthorizedReveal);
        }
        if self
            .authorization
            .as_ref()
            .is_some_and(|existing| existing != &verified)
        {
            return Err(EtdagError::ConflictingArtifact(
                "reveal authorization".into(),
            ));
        }
        self.authorization = Some(verified);
        Ok(())
    }
    pub fn authorization(&self) -> Result<&VerifiedRevealAuthorization, EtdagError> {
        self.authorization
            .as_ref()
            .ok_or(EtdagError::UnauthorizedReveal)
    }
}
