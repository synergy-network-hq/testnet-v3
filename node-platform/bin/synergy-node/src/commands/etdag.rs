use synergy_admin_api::operations::{AdminOperation, EtdagOperation};

use super::nonempty;

pub fn operation(action: &str, artifact_id: Option<&str>) -> Result<AdminOperation, String> {
    let operation = match action {
        "pause-ingress" => EtdagOperation::PauseIngress,
        "resume-ingress" => EtdagOperation::ResumeIngress,
        "recover" => EtdagOperation::RecoverArtifact {
            artifact_id: nonempty(
                artifact_id.ok_or("recover requires an artifact ID")?,
                "artifact ID",
                256,
            )?,
        },
        _ => return Err("ETDAG action must be pause-ingress, resume-ingress, or recover".into()),
    };
    operation.validate().map_err(|error| error.message)?;
    Ok(AdminOperation::Etdag(operation))
}
