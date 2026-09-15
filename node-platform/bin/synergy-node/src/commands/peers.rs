use synergy_admin_api::operations::{AdminOperation, PeerOperation};

use super::{nonempty, parse_u64};

pub fn operation(
    action: &str,
    peer_id: &str,
    until: Option<&str>,
) -> Result<AdminOperation, String> {
    let peer_id = nonempty(peer_id, "peer ID", 256)?;
    let operation = match action {
        "disconnect" => PeerOperation::Disconnect { peer_id },
        "quarantine" => PeerOperation::Quarantine {
            peer_id,
            until: parse_u64(
                until.ok_or("quarantine requires an expiry timestamp")?,
                "quarantine expiry",
                false,
            )?,
        },
        "ban" => PeerOperation::Ban {
            peer_id,
            until: until
                .map(|value| parse_u64(value, "ban expiry", false))
                .transpose()?,
        },
        "unban" => PeerOperation::Unban { peer_id },
        _ => return Err("peers action must be disconnect, quarantine, ban, or unban".into()),
    };
    operation.validate().map_err(|error| error.message)?;
    Ok(AdminOperation::Peers(operation))
}
