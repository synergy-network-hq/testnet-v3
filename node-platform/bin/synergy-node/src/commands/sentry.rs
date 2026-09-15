use synergy_admin_api::operations::{AdminOperation, SentryOperation};

use super::nonempty;

pub fn operation(action: &str, validator_id: Option<&str>) -> Result<AdminOperation, String> {
    let operation = match action {
        "drain-public" => SentryOperation::DrainPublic,
        "resume-public" => SentryOperation::ResumePublic,
        "reconnect-validator" => SentryOperation::ReconnectValidator {
            validator_id: nonempty(
                validator_id.ok_or("reconnect-validator requires a validator ID")?,
                "validator ID",
                256,
            )?,
        },
        _ => {
            return Err(
                "sentry action must be drain-public, resume-public, or reconnect-validator".into(),
            )
        }
    };
    operation.validate().map_err(|error| error.message)?;
    Ok(AdminOperation::Sentry(operation))
}
