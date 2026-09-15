use synergy_admin_api::operations::{AdminOperation, PosyOperation};

use super::nonempty;

pub fn operation(action: &str, recovery_reference: Option<&str>) -> Result<AdminOperation, String> {
    let operation = match action {
        "drain-signing" => PosyOperation::DrainSigning,
        "resume-signing" => PosyOperation::ResumeSigning {
            recovery_reference: nonempty(
                recovery_reference.ok_or("resume-signing requires recovery evidence")?,
                "recovery reference",
                1024,
            )?,
        },
        _ => return Err("PoSy action must be drain-signing or resume-signing".into()),
    };
    operation.validate().map_err(|error| error.message)?;
    Ok(AdminOperation::Posy(operation))
}
