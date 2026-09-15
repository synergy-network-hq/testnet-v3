use synergy_admin_api::operations::{AdminOperation, VpnOperation};

use super::nonempty;

pub fn operation(action: &str, authorization_id: Option<&str>) -> Result<AdminOperation, String> {
    let operation = match action {
        "enroll" => VpnOperation::Enroll {
            authorization_id: nonempty(
                authorization_id.ok_or("enroll requires an authorization ID")?,
                "authorization ID",
                256,
            )?,
        },
        "refresh" => VpnOperation::RefreshLease,
        "revoke" => VpnOperation::Revoke {
            authorization_id: nonempty(
                authorization_id.ok_or("revoke requires an authorization ID")?,
                "authorization ID",
                256,
            )?,
        },
        _ => return Err("VPN action must be enroll, refresh, or revoke".into()),
    };
    operation.validate().map_err(|error| error.message)?;
    Ok(AdminOperation::Vpn(operation))
}
