use synergy_version::ReleaseVersion;

use crate::VerifiedRelease;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivationDecision {
    SoftwareOnly,
    ProtocolAlreadyActive,
    ProtocolPending,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActivationGate;

impl ActivationGate {
    pub fn evaluate(
        &self,
        release: &VerifiedRelease,
        _installed: ReleaseVersion,
        governed_commitment: Option<&str>,
    ) -> Result<ActivationDecision, &'static str> {
        match release
            .signed
            .release
            .protocol_activation_commitment
            .as_deref()
        {
            None => Ok(ActivationDecision::SoftwareOnly),
            Some(required) if governed_commitment == Some(required) => {
                Ok(ActivationDecision::ProtocolAlreadyActive)
            }
            Some(_) => Ok(ActivationDecision::ProtocolPending),
        }
    }
}
