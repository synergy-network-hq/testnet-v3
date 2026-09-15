use synergy_governance::{
    ActivationPoint, GovernanceAuthorization, GovernanceProposal, GovernedActivation,
};

/// Governance authorization is verified by its dedicated subsystem before any
/// operation enters execution. Ingress has no authority to interpret it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GovernanceIngress;

impl GovernanceIngress {
    /// Validates the proposal/authorization binding and returns the governed
    /// activation record consumed by the activation caller.
    pub fn authorize_activation(
        self,
        proposal: &GovernanceProposal,
        authorization: &GovernanceAuthorization,
        point: ActivationPoint,
    ) -> Result<GovernedActivation, String> {
        GovernedActivation::new(proposal, authorization, point)
    }

    pub const fn may_determine_finality(self) -> bool {
        false
    }
}
