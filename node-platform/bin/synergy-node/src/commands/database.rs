use synergy_admin_api::operations::{AdminOperation, StorageOperation};

use super::parse_u64;

pub fn operation(action: &str, height: Option<&str>) -> Result<AdminOperation, String> {
    let operation = match action {
        "verify" => StorageOperation::Verify,
        "prune" => StorageOperation::Prune {
            retain_from_height: parse_u64(
                height.ok_or("prune requires a retained height")?,
                "retained height",
                false,
            )?,
        },
        _ => return Err("database action must be verify or prune".into()),
    };
    operation.validate().map_err(|error| error.message)?;
    Ok(AdminOperation::Storage(operation))
}
