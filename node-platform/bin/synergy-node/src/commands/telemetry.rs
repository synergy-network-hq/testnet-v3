use synergy_admin_api::operations::{AdminOperation, TelemetryOperation};

use super::nonempty;

pub fn operation(action: &str, filter: Option<&str>) -> Result<AdminOperation, String> {
    let operation = match action {
        "snapshot" => TelemetryOperation::Snapshot,
        "set-filter" => TelemetryOperation::SetFilter {
            filter: nonempty(
                filter.ok_or("set-filter requires a filter")?,
                "telemetry filter",
                1024,
            )?,
        },
        _ => return Err("telemetry action must be snapshot or set-filter".into()),
    };
    operation.validate().map_err(|error| error.message)?;
    Ok(AdminOperation::Telemetry(operation))
}
