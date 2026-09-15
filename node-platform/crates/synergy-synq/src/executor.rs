use synergy_transaction::TransactionId;

use crate::{DeterministicContext, GasMeter, SynqArtifact, SynqError, SynqHost, SynqVm};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SynqExecutionReceipt {
    pub transaction_id: TransactionId,
    pub artifact_hash: String,
    pub gas_used: u64,
    pub events: u32,
}

pub struct SynqExecutor;

impl SynqExecutor {
    pub fn execute<V: SynqVm, H: SynqHost>(
        artifact: &SynqArtifact,
        transaction_id: TransactionId,
        context: DeterministicContext,
        input: &[u8],
        gas_limit: u64,
        vm: &V,
        host: &mut H,
    ) -> Result<SynqExecutionReceipt, SynqError> {
        artifact.validate()?;
        transaction_id
            .validate()
            .map_err(|error| SynqError::Transaction(error.to_string()))?;
        if context.block_height == 0 {
            return Err(SynqError::InvalidContext);
        }
        let mut gas = GasMeter::new(gas_limit)?;
        let events = vm.execute(artifact, context, input, &mut gas, host)?;
        Ok(SynqExecutionReceipt {
            transaction_id,
            artifact_hash: artifact.code_hash.clone(),
            gas_used: gas.used(),
            events,
        })
    }

    pub const fn may_determine_finality(&self) -> bool {
        false
    }
}
