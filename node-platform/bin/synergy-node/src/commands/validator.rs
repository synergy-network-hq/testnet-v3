use synergy_admin_api::operations::{AdminOperation, ValidatorOperation};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ValidatorArguments {
    pub node_address: Option<String>,
    pub consensus_key_id: Option<String>,
    pub operator_identity: Option<String>,
    pub target_epoch: Option<u64>,
    pub authorization_root: Option<String>,
    pub required_shadow_blocks: Option<u64>,
    pub change_set_root: Option<String>,
    pub frozen_voting_weight: Option<u128>,
    pub verified_blocks: Option<u64>,
    pub evidence_root: Option<String>,
    pub effective_epoch: Option<u64>,
    pub release_epoch: Option<u64>,
    pub penalty_units: Option<u128>,
}

impl ValidatorArguments {
    pub fn is_empty(&self) -> bool {
        self.present_fields().is_empty()
    }

    fn ensure_only(&self, allowed: &[&str]) -> Result<(), String> {
        if let Some(unexpected) = self
            .present_fields()
            .into_iter()
            .find(|field| !allowed.contains(field))
        {
            return Err(format!(
                "--{unexpected} is not accepted by this validator action"
            ));
        }
        Ok(())
    }

    fn present_fields(&self) -> Vec<&'static str> {
        [
            ("node-address", self.node_address.is_some()),
            ("consensus-key-id", self.consensus_key_id.is_some()),
            ("operator-identity", self.operator_identity.is_some()),
            ("target-epoch", self.target_epoch.is_some()),
            ("authorization-root", self.authorization_root.is_some()),
            (
                "required-shadow-blocks",
                self.required_shadow_blocks.is_some(),
            ),
            ("change-set-root", self.change_set_root.is_some()),
            ("frozen-voting-weight", self.frozen_voting_weight.is_some()),
            ("verified-blocks", self.verified_blocks.is_some()),
            ("evidence-root", self.evidence_root.is_some()),
            ("effective-epoch", self.effective_epoch.is_some()),
            ("release-epoch", self.release_epoch.is_some()),
            ("penalty-units", self.penalty_units.is_some()),
        ]
        .into_iter()
        .filter_map(|(field, present)| present.then_some(field))
        .collect()
    }
}

pub fn operation(action: &str, arguments: &ValidatorArguments) -> Result<AdminOperation, String> {
    let node_address = || {
        let value = required_string(&arguments.node_address, "node address")?;
        synergy_protocol_types::NodeAddress::parse(value).map_err(|error| error.to_string())
    };
    let operation = match action {
        "inspect" => {
            arguments.ensure_only(&["node-address"])?;
            ValidatorOperation::Inspect {
                node_address: node_address()?,
            }
        }
        "onboard" => {
            arguments.ensure_only(&[
                "node-address",
                "consensus-key-id",
                "operator-identity",
                "target-epoch",
                "authorization-root",
                "required-shadow-blocks",
            ])?;
            ValidatorOperation::Onboard {
                node_address: node_address()?,
                consensus_key_id: required_string(
                    &arguments.consensus_key_id,
                    "consensus key ID",
                )?,
                operator_identity: required_string(
                    &arguments.operator_identity,
                    "operator identity",
                )?,
                target_epoch: required_u64(arguments.target_epoch, "target epoch")?,
                authorization_root: required_string(
                    &arguments.authorization_root,
                    "authorization root",
                )?,
                required_shadow_blocks: required_u64(
                    arguments.required_shadow_blocks,
                    "required shadow blocks",
                )?,
            }
        }
        "authorize" => {
            arguments.ensure_only(&["node-address"])?;
            ValidatorOperation::Authorize {
                node_address: node_address()?,
            }
        }
        "begin-synchronization" => {
            arguments.ensure_only(&["node-address"])?;
            ValidatorOperation::BeginSynchronization {
                node_address: node_address()?,
            }
        }
        "enter-shadow" => {
            arguments.ensure_only(&[
                "node-address",
                "change-set-root",
                "frozen-voting-weight",
            ])?;
            ValidatorOperation::EnterShadow {
                node_address: node_address()?,
                change_set_root: required_string(
                    &arguments.change_set_root,
                    "change-set root",
                )?,
                frozen_voting_weight: arguments
                    .frozen_voting_weight
                    .ok_or_else(|| "enter-shadow requires --frozen-voting-weight".to_string())?,
            }
        }
        "record-shadow-progress" => {
            arguments.ensure_only(&["node-address", "verified-blocks"])?;
            ValidatorOperation::RecordShadowProgress {
                node_address: node_address()?,
                verified_blocks: required_u64(arguments.verified_blocks, "verified blocks")?,
            }
        }
        "mark-ready" => {
            arguments.ensure_only(&["node-address"])?;
            ValidatorOperation::MarkReady {
                node_address: node_address()?,
            }
        }
        "request-activation" => {
            arguments.ensure_only(&["node-address", "change-set-root"])?;
            ValidatorOperation::RequestActivation {
                node_address: node_address()?,
                change_set_root: required_string(
                    &arguments.change_set_root,
                    "change-set root",
                )?,
            }
        }
        "confirm-frozen-authority" => {
            arguments.ensure_only(&["node-address"])?;
            ValidatorOperation::ConfirmFrozenAuthority {
                node_address: node_address()?,
            }
        }
        "schedule-jailing" => {
            arguments.ensure_only(&[
                "node-address",
                "evidence-root",
                "effective-epoch",
                "release-epoch",
                "authorization-root",
            ])?;
            ValidatorOperation::ScheduleJailing {
                node_address: node_address()?,
                evidence_root: required_string(&arguments.evidence_root, "evidence root")?,
                effective_epoch: required_u64(arguments.effective_epoch, "effective epoch")?,
                release_epoch: arguments.release_epoch,
                authorization_root: required_string(
                    &arguments.authorization_root,
                    "authorization root",
                )?,
            }
        }
        "schedule-deactivation" | "schedule-removal" => {
            arguments.ensure_only(&[
                "node-address",
                "effective-epoch",
                "authorization-root",
            ])?;
            ValidatorOperation::ScheduleDeactivation {
                node_address: node_address()?,
                effective_epoch: required_u64(arguments.effective_epoch, "effective epoch")?,
                authorization_root: required_string(
                    &arguments.authorization_root,
                    "authorization root",
                )?,
            }
        }
        "schedule-expulsion" => {
            arguments.ensure_only(&[
                "node-address",
                "evidence-root",
                "effective-epoch",
                "authorization-root",
            ])?;
            ValidatorOperation::ScheduleExpulsion {
                node_address: node_address()?,
                evidence_root: required_string(&arguments.evidence_root, "evidence root")?,
                effective_epoch: required_u64(arguments.effective_epoch, "effective epoch")?,
                authorization_root: required_string(
                    &arguments.authorization_root,
                    "authorization root",
                )?,
            }
        }
        "schedule-slashing" => {
            arguments.ensure_only(&[
                "node-address",
                "evidence-root",
                "penalty-units",
                "effective-epoch",
                "authorization-root",
            ])?;
            ValidatorOperation::ScheduleSlashing {
                node_address: node_address()?,
                evidence_root: required_string(&arguments.evidence_root, "evidence root")?,
                penalty_units: arguments
                    .penalty_units
                    .ok_or_else(|| "schedule-slashing requires --penalty-units".to_string())?,
                effective_epoch: required_u64(arguments.effective_epoch, "effective epoch")?,
                authorization_root: required_string(
                    &arguments.authorization_root,
                    "authorization root",
                )?,
            }
        }
        _ => {
            return Err(format!(
                "unknown validator action {action}; use inspect, onboard, authorize, begin-synchronization, enter-shadow, record-shadow-progress, mark-ready, request-activation, confirm-frozen-authority, schedule-jailing, schedule-deactivation, schedule-removal, schedule-expulsion, or schedule-slashing"
            ))
        }
    };
    operation.validate().map_err(|error| error.message)?;
    Ok(AdminOperation::Validator(operation))
}

fn required_string(value: &Option<String>, label: &str) -> Result<String, String> {
    value
        .clone()
        .ok_or_else(|| format!("validator action requires --{}", label.replace(' ', "-")))
}

fn required_u64(value: Option<u64>, label: &str) -> Result<u64, String> {
    value.ok_or_else(|| format!("validator action requires --{}", label.replace(' ', "-")))
}
