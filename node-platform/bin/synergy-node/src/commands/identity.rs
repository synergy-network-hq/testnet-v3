use synergy_admin_api::operations::{AdminOperation, IdentityOperation};

use super::nonempty;

pub fn operation(action: &str, key_id: &str) -> Result<AdminOperation, String> {
    let key_id = nonempty(key_id, "identity key ID", 128)?;
    let operation = match action {
        "rotate" => IdentityOperation::Rotate {
            next_key_id: key_id,
        },
        "retire" => IdentityOperation::Retire { key_id },
        _ => return Err("identity action must be rotate or retire".into()),
    };
    operation.validate().map_err(|error| error.message)?;
    Ok(AdminOperation::Identity(operation))
}
