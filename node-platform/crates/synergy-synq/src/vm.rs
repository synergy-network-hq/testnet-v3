use crate::{DeterministicContext, GasMeter, SynqArtifact, SynqError, SynqHost};

/// AIVM/SynQ concrete engines implement this deterministic contract. The
/// platform shell provides no fallback interpreter and never fabricates output.
pub trait SynqVm {
    fn execute<H: SynqHost>(
        &self,
        artifact: &SynqArtifact,
        context: DeterministicContext,
        input: &[u8],
        gas: &mut GasMeter,
        host: &mut H,
    ) -> Result<u32, SynqError>;
}
