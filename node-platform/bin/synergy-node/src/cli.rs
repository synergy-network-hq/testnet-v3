use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use synergy_admin_api::operations::AdminOperation;
use synergy_admin_api::AdminRequest;
use synergy_node_core::ManagementOperation;

use crate::commands::node_state::NodeStateArguments;
use crate::commands::validator::ValidatorArguments;

#[derive(Debug, Clone, PartialEq)]
pub enum Command {
    Help,
    Version,
    Start(PathBuf),
    Admin(AdminOperation),
}

#[derive(Debug, Clone, PartialEq)]
pub struct Cli {
    pub command: Command,
    pub admin_socket: Option<PathBuf>,
    pub request_id: Option<String>,
    pub idempotency_key: Option<String>,
}

impl Cli {
    pub fn parse(args: impl IntoIterator<Item = String>) -> Result<Self, String> {
        let mut args = args.into_iter();
        let command_text = args.next().unwrap_or_else(|| "help".into());
        let command_kind = match command_text.as_str() {
            "help" | "--help" | "-h" => CommandKind::Fixed(Command::Help),
            "version" | "--version" | "-V" => CommandKind::Fixed(Command::Version),
            "start" => CommandKind::Start,
            "status" => {
                CommandKind::Admin(AdminOperation::Read(crate::commands::status::operation()))
            }
            "health" => {
                CommandKind::Admin(AdminOperation::Read(crate::commands::health::operation()))
            }
            "readiness" => {
                CommandKind::Admin(AdminOperation::Read(crate::commands::readiness::operation()))
            }
            "doctor" => {
                CommandKind::Admin(AdminOperation::Read(crate::commands::doctor::operation()))
            }
            "validate-config" => CommandKind::Admin(AdminOperation::Read(
                ManagementOperation::ConfigurationValidation,
            )),
            "role" => CommandKind::Admin(AdminOperation::Read(crate::commands::role::operation())),
            "capabilities" => CommandKind::Admin(AdminOperation::Read(
                ManagementOperation::CapabilityDiscovery,
            )),
            subsystem @ ("ownership" | "naming" | "rewards") => CommandKind::NodeState {
                subsystem: subsystem.to_string(),
                action: args
                    .next()
                    .ok_or_else(|| format!("{subsystem} requires an action"))?,
            },
            "validator" => CommandKind::Validator(
                args.next()
                    .ok_or_else(|| "validator requires an action".to_string())?,
            ),
            other => return Err(format!("unknown command {other}")),
        };

        let mut admin_socket = None;
        let mut request_id = None;
        let mut idempotency_key = None;
        let mut config_path = None;
        let mut validator = ValidatorArguments::default();
        let mut node_state = NodeStateArguments::default();
        while let Some(option) = args.next() {
            let value = match option.as_str() {
                "--config"
                | "--admin-socket"
                | "--request-id"
                | "--idempotency-key"
                | "--consensus-key-id"
                | "--operator-identity"
                | "--target-epoch"
                | "--authorization-root"
                | "--required-shadow-blocks"
                | "--change-set-root"
                | "--frozen-voting-weight"
                | "--verified-blocks"
                | "--evidence-root"
                | "--effective-epoch"
                | "--release-epoch"
                | "--penalty-units"
                | "--node-address"
                | "--node-id"
                | "--current-node-id"
                | "--replacement-node-id"
                | "--nonce"
                | "--proof-file"
                | "--new-owner-wallet"
                | "--destination-wallet"
                | "--amount-nwei"
                | "--withdrawal-id" => args
                    .next()
                    .ok_or_else(|| format!("{option} requires a value"))?,
                other => return Err(format!("unknown option {other}")),
            };
            match option.as_str() {
                "--config" => set_once(&mut config_path, PathBuf::from(value), "--config")?,
                "--admin-socket" => {
                    let path = PathBuf::from(value);
                    if !path.is_absolute() {
                        return Err("--admin-socket requires an absolute path".into());
                    }
                    set_once(&mut admin_socket, path, "--admin-socket")?;
                }
                "--request-id" => {
                    require_safe_text(&value, "request ID")?;
                    set_once(&mut request_id, value, "--request-id")?;
                }
                "--idempotency-key" => {
                    require_safe_text(&value, "idempotency key")?;
                    set_once(&mut idempotency_key, value, "--idempotency-key")?;
                }
                "--consensus-key-id" => {
                    set_once(&mut validator.consensus_key_id, value, "--consensus-key-id")?
                }
                "--operator-identity" => set_once(
                    &mut validator.operator_identity,
                    value,
                    "--operator-identity",
                )?,
                "--target-epoch" => set_once(
                    &mut validator.target_epoch,
                    crate::commands::parse_u64(&value, "target epoch", false)?,
                    "--target-epoch",
                )?,
                "--authorization-root" => set_once(
                    &mut validator.authorization_root,
                    value,
                    "--authorization-root",
                )?,
                "--required-shadow-blocks" => set_once(
                    &mut validator.required_shadow_blocks,
                    crate::commands::parse_u64(&value, "required shadow blocks", false)?,
                    "--required-shadow-blocks",
                )?,
                "--change-set-root" => {
                    set_once(&mut validator.change_set_root, value, "--change-set-root")?
                }
                "--frozen-voting-weight" => set_once(
                    &mut validator.frozen_voting_weight,
                    parse_u128(&value, "frozen voting weight")?,
                    "--frozen-voting-weight",
                )?,
                "--verified-blocks" => set_once(
                    &mut validator.verified_blocks,
                    crate::commands::parse_u64(&value, "verified blocks", false)?,
                    "--verified-blocks",
                )?,
                "--evidence-root" => {
                    set_once(&mut validator.evidence_root, value, "--evidence-root")?
                }
                "--effective-epoch" => set_once(
                    &mut validator.effective_epoch,
                    crate::commands::parse_u64(&value, "effective epoch", false)?,
                    "--effective-epoch",
                )?,
                "--release-epoch" => set_once(
                    &mut validator.release_epoch,
                    crate::commands::parse_u64(&value, "release epoch", false)?,
                    "--release-epoch",
                )?,
                "--penalty-units" => set_once(
                    &mut validator.penalty_units,
                    parse_u128(&value, "penalty units")?,
                    "--penalty-units",
                )?,
                "--node-address" => {
                    if matches!(&command_kind, CommandKind::Validator(_)) {
                        set_once(&mut validator.node_address, value, "--node-address")?
                    } else {
                        set_once(&mut node_state.node_address, value, "--node-address")?
                    }
                }
                "--node-id" => set_once(&mut node_state.node_id, value, "--node-id")?,
                "--current-node-id" => {
                    set_once(&mut node_state.current_node_id, value, "--current-node-id")?
                }
                "--replacement-node-id" => set_once(
                    &mut node_state.replacement_node_id,
                    value,
                    "--replacement-node-id",
                )?,
                "--nonce" => set_once(
                    &mut node_state.nonce,
                    crate::commands::parse_u64(&value, "nonce", false)?,
                    "--nonce",
                )?,
                "--proof-file" => set_once(
                    &mut node_state.proof_file,
                    crate::commands::absolute_path(&value, "proof file")?,
                    "--proof-file",
                )?,
                "--new-owner-wallet" => set_once(
                    &mut node_state.new_owner_wallet,
                    value,
                    "--new-owner-wallet",
                )?,
                "--destination-wallet" => set_once(
                    &mut node_state.destination_wallet,
                    value,
                    "--destination-wallet",
                )?,
                "--amount-nwei" => set_once(
                    &mut node_state.amount_nwei,
                    parse_u128(&value, "reward withdrawal amount")?,
                    "--amount-nwei",
                )?,
                "--withdrawal-id" => {
                    set_once(&mut node_state.withdrawal_id, value, "--withdrawal-id")?
                }
                _ => return Err(format!("unknown option {option}")),
            }
        }

        let command = match command_kind {
            CommandKind::Start => {
                if admin_socket.is_some()
                    || request_id.is_some()
                    || idempotency_key.is_some()
                    || !validator.is_empty()
                    || !node_state.is_empty()
                {
                    return Err("start accepts only --config <absolute path>".into());
                }
                let path = config_path
                    .ok_or_else(|| "start requires --config <absolute path>".to_string())?;
                if !path.is_absolute() {
                    return Err("start requires an absolute configuration path".into());
                }
                Command::Start(path)
            }
            CommandKind::Fixed(command) => {
                if config_path.is_some()
                    || admin_socket.is_some()
                    || request_id.is_some()
                    || idempotency_key.is_some()
                    || !validator.is_empty()
                    || !node_state.is_empty()
                {
                    return Err("help and version do not accept management options".into());
                }
                command
            }
            CommandKind::Admin(operation) => {
                if config_path.is_some()
                    || idempotency_key.is_some()
                    || !validator.is_empty()
                    || !node_state.is_empty()
                {
                    return Err(
                        "read management commands accept only Admin socket/request options".into(),
                    );
                }
                Command::Admin(operation)
            }
            CommandKind::Validator(action) => {
                if config_path.is_some() || !node_state.is_empty() {
                    return Err("--config is accepted only by start".into());
                }
                let operation = crate::commands::validator::operation(&action, &validator)?;
                if operation.is_mutating() {
                    if request_id.is_none() {
                        return Err(
                            "mutating validator commands require an explicit --request-id".into(),
                        );
                    }
                    if idempotency_key.is_none() {
                        return Err("mutating validator commands require --idempotency-key".into());
                    }
                } else if idempotency_key.is_some() {
                    return Err("validator inspection does not accept --idempotency-key".into());
                }
                Command::Admin(operation)
            }
            CommandKind::NodeState { subsystem, action } => {
                if config_path.is_some() || idempotency_key.is_some() || !validator.is_empty() {
                    return Err(
                        "node-state queries and transaction preparation do not accept config, validator, or idempotency options"
                            .into(),
                    );
                }
                Command::Admin(crate::commands::node_state::operation(
                    &subsystem,
                    &action,
                    &node_state,
                )?)
            }
        };
        if matches!(command, Command::Admin(_)) && admin_socket.is_none() {
            return Err(
                "management commands require --admin-socket <absolute-path>; refusing to guess a node data directory"
                    .into(),
            );
        }
        Ok(Self {
            command,
            admin_socket,
            request_id,
            idempotency_key,
        })
    }

    pub fn request_id(&self) -> String {
        self.request_id.clone().unwrap_or_else(|| {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|duration| duration.as_nanos())
                .unwrap_or(0);
            format!("synergy-node-{}-{nanos}", std::process::id())
        })
    }

    pub fn admin_request(&self, operation: AdminOperation) -> Result<AdminRequest, String> {
        let request_id = self.request_id();
        if operation.is_mutating() {
            let idempotency_key = self.idempotency_key.as_ref().ok_or_else(|| {
                "mutating Admin command reached execution without an idempotency key".to_string()
            })?;
            Ok(AdminRequest::command(
                request_id,
                idempotency_key.clone(),
                operation,
            ))
        } else {
            Ok(AdminRequest::query(request_id, operation))
        }
    }
}

fn set_once<T>(slot: &mut Option<T>, value: T, option: &str) -> Result<(), String> {
    if slot.replace(value).is_some() {
        return Err(format!("{option} may be supplied only once"));
    }
    Ok(())
}

fn require_safe_text(value: &str, label: &str) -> Result<(), String> {
    if value.trim().is_empty() || value.len() > 256 || value.contains(char::is_control) {
        return Err(format!("{label} must contain 1..=256 safe characters"));
    }
    Ok(())
}

fn parse_u128(value: &str, label: &str) -> Result<u128, String> {
    let parsed = value
        .parse::<u128>()
        .map_err(|error| format!("invalid {label}: {error}"))?;
    if parsed == 0 {
        return Err(format!("{label} must be nonzero"));
    }
    Ok(parsed)
}

enum CommandKind {
    Start,
    Fixed(Command),
    Admin(AdminOperation),
    Validator(String),
    NodeState { subsystem: String, action: String },
}

pub const HELP: &str = "Synergy node runtime and management CLI

Usage:
  synergy-node start --config <absolute-path>
  synergy-node <status|health|readiness|doctor|validate-config|role|capabilities> --admin-socket <absolute-path> [--request-id <id>]
  synergy-node validator <action> --admin-socket <absolute-path> --request-id <id> --idempotency-key <key> [action fields]
  synergy-node validator inspect --node-address <synv-address> --admin-socket <absolute-path> [--request-id <id>]
  synergy-node ownership <inspect|prepare-claim|prepare-transfer> [action fields] --admin-socket <absolute-path>
  synergy-node naming <resolve|reverse-resolve|availability|prepare-register|prepare-rename> [action fields] --admin-socket <absolute-path>
  synergy-node rewards <inspect-account|inspect-withdrawal|prepare-withdrawal> [action fields] --admin-socket <absolute-path>
  synergy-node version

Validator actions:
  inspect, onboard, authorize, begin-synchronization, enter-shadow,
  record-shadow-progress, mark-ready, request-activation,
  confirm-frozen-authority, schedule-jailing, schedule-deactivation,
  schedule-removal, schedule-expulsion, schedule-slashing

Mutating validator commands require explicit request and idempotency keys.
The Admin service validates frozen PoSy authority; CLI arguments never grant it.";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_every_migrated_management_command() {
        let cases = [
            ("status", ManagementOperation::NodeStatus),
            ("health", ManagementOperation::Health),
            ("readiness", ManagementOperation::Readiness),
            ("doctor", ManagementOperation::Diagnostics),
            (
                "validate-config",
                ManagementOperation::ConfigurationValidation,
            ),
            ("role", ManagementOperation::RoleInspection),
            ("capabilities", ManagementOperation::CapabilityDiscovery),
        ];
        for (name, expected) in cases {
            let cli = Cli::parse([
                name.to_string(),
                "--admin-socket".into(),
                "/run/synergy/admin.sock".into(),
            ])
            .unwrap();
            assert_eq!(cli.command, Command::Admin(AdminOperation::Read(expected)));
        }
    }

    #[test]
    fn management_command_requires_explicit_socket_and_rejects_unknown_input() {
        assert!(Cli::parse(["status".into()]).is_err());
        assert!(Cli::parse(["status".into(), "--bogus".into()]).is_err());
        assert!(Cli::parse([
            "status".into(),
            "--admin-socket".into(),
            "/tmp/a".into(),
            "--admin-socket".into(),
            "/tmp/b".into(),
        ])
        .is_err());
    }

    #[test]
    fn help_and_version_do_not_require_a_running_node() {
        assert_eq!(Cli::parse(Vec::new()).unwrap().command, Command::Help);
        assert_eq!(
            Cli::parse(["--version".into()]).unwrap().command,
            Command::Version
        );
    }
}
