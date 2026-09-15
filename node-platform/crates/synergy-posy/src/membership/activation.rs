use crate::{FrozenValidatorRegistry, PosyError, PosyResult, SimplifiedEpochContext};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenesisBoundActivation {
    pub activation_epoch: u64,
    pub activation_height: u64,
    pub governance_decision_id: String,
    pub parameter_root: String,
}

impl GenesisBoundActivation {
    pub fn validate_for(
        &self,
        context: &SimplifiedEpochContext,
        registry: &FrozenValidatorRegistry,
    ) -> PosyResult<()> {
        if self.activation_epoch != context.epoch
            || self.activation_height != context.epoch_start_height
            || self.parameter_root != context.consensus_parameter_root
            || self.governance_decision_id.trim().is_empty()
            || registry.epoch() != context.epoch
        {
            return Err(PosyError::invalid(
                "activation is not bound to frozen genesis epoch authority",
            ));
        }
        Ok(())
    }
}
