use synergy_admin_api::operations::{AdminOperation, AiOperation};

use super::nonempty;

pub fn operation(action: &str, workload_id: Option<&str>) -> Result<AdminOperation, String> {
    let operation = match action {
        "pause" => AiOperation::PauseWorkloads,
        "resume" => AiOperation::ResumeWorkloads,
        "cancel" => AiOperation::CancelWorkload {
            workload_id: nonempty(
                workload_id.ok_or("cancel requires a workload ID")?,
                "workload ID",
                256,
            )?,
        },
        _ => return Err("AI action must be pause, resume, or cancel".into()),
    };
    operation.validate().map_err(|error| error.message)?;
    Ok(AdminOperation::Ai(operation))
}
