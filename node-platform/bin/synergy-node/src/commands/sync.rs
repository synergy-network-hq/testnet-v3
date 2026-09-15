use synergy_admin_api::operations::{AdminOperation, SyncOperation};

use super::nonempty;

pub fn operation(action: &str, peer_id: Option<&str>) -> Result<AdminOperation, String> {
    let operation = match action {
        "pause" => SyncOperation::Pause,
        "resume" => SyncOperation::Resume,
        "retry-source" => SyncOperation::RetrySource {
            peer_id: nonempty(
                peer_id.ok_or("retry-source requires a peer ID")?,
                "peer ID",
                256,
            )?,
        },
        _ => return Err("sync action must be pause, resume, or retry-source".into()),
    };
    operation.validate().map_err(|error| error.message)?;
    Ok(AdminOperation::Sync(operation))
}
