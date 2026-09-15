use crate::{validation::validate_request, ResourceBudget, ResourceUsage, SandboxPolicy};
use serde::{Deserialize, Serialize};
use synergy_ai::AiJob;
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AivmRequest {
    pub job: AiJob,
    pub module: Vec<u8>,
    pub input: Vec<u8>,
    pub budget: ResourceBudget,
    pub sandbox: SandboxPolicy,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AivmResult {
    pub output: Vec<u8>,
    pub output_root: String,
    pub usage: ResourceUsage,
}
pub trait AivmEngine {
    fn execute(
        &self,
        module: &[u8],
        input: &[u8],
        budget: ResourceBudget,
    ) -> Result<AivmResult, String>;
}
pub fn execute(request: &AivmRequest, engine: &impl AivmEngine) -> Result<AivmResult, String> {
    validate_request(request)?;
    let result = engine.execute(&request.module, &request.input, request.budget)?;
    if result.output.len() as u64 != result.usage.output_bytes
        || !request.budget.accepts(result.usage)
        || crate::validation::output_root(&result.output) != result.output_root
    {
        return Err("AIVM result violated deterministic resource or commitment contract".into());
    }
    Ok(result)
}
