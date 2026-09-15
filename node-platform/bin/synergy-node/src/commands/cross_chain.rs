use synergy_admin_api::operations::{AdminOperation, CrossChainOperation};

use super::nonempty;

pub fn operation(action: &str, package_id: Option<&str>) -> Result<AdminOperation, String> {
    let operation = match action {
        "pause" => CrossChainOperation::Pause,
        "resume" => CrossChainOperation::Resume,
        "retry" => CrossChainOperation::RetryPackage {
            package_id: nonempty(
                package_id.ok_or("retry requires a package ID")?,
                "package ID",
                256,
            )?,
        },
        _ => return Err("cross-chain action must be pause, resume, or retry".into()),
    };
    operation.validate().map_err(|error| error.message)?;
    Ok(AdminOperation::CrossChain(operation))
}
