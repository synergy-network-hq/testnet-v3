use synergy_synq::{DeterministicContext, GasMeter, SynqArtifact, SynqError, SynqHost, SynqVm};

use crate::quantum::QuantumVM;

/// Concrete deterministic SynQ bytecode engine owned by AIVM.
///
/// The VM executes the established QVM bytecode format with bounded gas. PQ
/// opcodes fail closed here because cryptographic authorization is performed by
/// the injected Aegis PQSynQ provider before execution.
#[derive(Debug, Clone, Copy, Default)]
pub struct CanonicalAivmSynqVm;

impl SynqVm for CanonicalAivmSynqVm {
    fn execute<H: SynqHost>(
        &self,
        artifact: &SynqArtifact,
        context: DeterministicContext,
        input: &[u8],
        gas: &mut GasMeter,
        _host: &mut H,
    ) -> Result<u32, SynqError> {
        artifact.validate()?;
        if context.block_height == 0 {
            return Err(SynqError::InvalidContext);
        }
        let mut vm = QuantumVM::with_gas(gas.remaining(), 0);
        vm.push_input(input)
            .map_err(|error| SynqError::Vm(error.to_string()))?;
        vm.load_bytecode(&artifact.bytes)
            .map_err(|error| SynqError::Vm(error.to_string()))?;
        vm.execute()
            .map_err(|error| SynqError::Vm(error.to_string()))?;
        gas.charge(vm.consumed_gas())?;
        Ok(0)
    }
}
