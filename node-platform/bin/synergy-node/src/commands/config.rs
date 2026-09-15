use synergy_admin_api::operations::{AdminOperation, ConfigOperation};

use super::absolute_path;

pub fn operation(action: &str, path: &str) -> Result<AdminOperation, String> {
    let path = absolute_path(path, "configuration path")?
        .to_str()
        .ok_or("configuration path is not valid UTF-8")?
        .to_string();
    let operation = match action {
        "validate" => ConfigOperation::Validate { path },
        "reload" => ConfigOperation::Reload { path },
        _ => return Err("config action must be validate or reload".into()),
    };
    operation.validate().map_err(|error| error.message)?;
    Ok(AdminOperation::Config(operation))
}
