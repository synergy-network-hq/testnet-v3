use synergy_admin_api::operations::{AdminOperation, StorageOperation};

use super::parse_u64;

pub fn operation(finalized_height: &str) -> Result<AdminOperation, String> {
    let operation = StorageOperation::CreateSnapshot {
        finalized_height: parse_u64(finalized_height, "finalized height", false)?,
    };
    operation.validate().map_err(|error| error.message)?;
    Ok(AdminOperation::Storage(operation))
}
