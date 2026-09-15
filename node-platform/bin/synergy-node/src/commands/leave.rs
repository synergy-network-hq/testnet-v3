use synergy_admin_api::operations::{AdminOperation, LifecycleAction, LifecycleOperation};

use super::parse_u64;

pub fn operation(timeout_ms: &str) -> Result<AdminOperation, String> {
    let operation = LifecycleOperation {
        action: LifecycleAction::Drain,
        timeout_ms: parse_u64(timeout_ms, "leave timeout", false)?,
    };
    operation.validate().map_err(|error| error.message)?;
    Ok(AdminOperation::Lifecycle(operation))
}
