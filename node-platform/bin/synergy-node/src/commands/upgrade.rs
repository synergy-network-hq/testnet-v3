use synergy_admin_api::operations::{AdminOperation, UpgradeOperation};

use super::{absolute_path, nonempty};

pub fn operation(
    action: &str,
    release_id: &str,
    artifact_path: Option<&str>,
) -> Result<AdminOperation, String> {
    let release_id = nonempty(release_id, "release ID", 256)?;
    let operation = match action {
        "stage" => UpgradeOperation::Stage {
            release_id,
            artifact_path: absolute_path(
                artifact_path.ok_or("stage requires an artifact path")?,
                "upgrade artifact path",
            )?
            .to_str()
            .ok_or("upgrade artifact path is not valid UTF-8")?
            .to_string(),
        },
        "apply" => UpgradeOperation::Apply { release_id },
        "rollback" => UpgradeOperation::Rollback { release_id },
        _ => return Err("upgrade action must be stage, apply, or rollback".into()),
    };
    operation.validate().map_err(|error| error.message)?;
    Ok(AdminOperation::Upgrade(operation))
}
