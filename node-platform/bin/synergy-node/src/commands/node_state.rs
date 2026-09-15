use std::path::{Path, PathBuf};

use synergy_admin_api::operations::{
    AdminOperation, NamingOperation, OwnershipOperation, RewardOperation,
};

const MAX_PROOF_BYTES: u64 = 65_536;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NodeStateArguments {
    pub node_address: Option<String>,
    pub node_id: Option<String>,
    pub current_node_id: Option<String>,
    pub replacement_node_id: Option<String>,
    pub nonce: Option<u64>,
    pub proof_file: Option<PathBuf>,
    pub new_owner_wallet: Option<String>,
    pub destination_wallet: Option<String>,
    pub amount_nwei: Option<u128>,
    pub withdrawal_id: Option<String>,
}

impl NodeStateArguments {
    pub fn is_empty(&self) -> bool {
        self.present_fields().is_empty()
    }

    fn present_fields(&self) -> Vec<&'static str> {
        [
            ("node-address", self.node_address.is_some()),
            ("node-id", self.node_id.is_some()),
            ("current-node-id", self.current_node_id.is_some()),
            ("replacement-node-id", self.replacement_node_id.is_some()),
            ("nonce", self.nonce.is_some()),
            ("proof-file", self.proof_file.is_some()),
            ("new-owner-wallet", self.new_owner_wallet.is_some()),
            ("destination-wallet", self.destination_wallet.is_some()),
            ("amount-nwei", self.amount_nwei.is_some()),
            ("withdrawal-id", self.withdrawal_id.is_some()),
        ]
        .into_iter()
        .filter_map(|(field, present)| present.then_some(field))
        .collect()
    }

    fn ensure_only(&self, allowed: &[&str]) -> Result<(), String> {
        if let Some(field) = self
            .present_fields()
            .into_iter()
            .find(|field| !allowed.contains(field))
        {
            return Err(format!("--{field} is not accepted by this action"));
        }
        Ok(())
    }
}

pub fn operation(
    subsystem: &str,
    action: &str,
    arguments: &NodeStateArguments,
) -> Result<AdminOperation, String> {
    let required = |value: &Option<String>, label: &str| {
        value
            .clone()
            .ok_or_else(|| format!("{action} requires --{label}"))
    };
    let node_address = || required(&arguments.node_address, "node-address");
    let operation = match (subsystem, action) {
        ("ownership", "inspect") => {
            arguments.ensure_only(&["node-address"])?;
            AdminOperation::Ownership(OwnershipOperation::Inspect {
                node_address: node_address()?,
            })
        }
        ("ownership", "prepare-claim") => {
            arguments.ensure_only(&["node-address", "nonce", "proof-file"])?;
            AdminOperation::Ownership(OwnershipOperation::PrepareClaim {
                node_address: node_address()?,
                nonce: required_u64(arguments.nonce, "nonce", action)?,
                node_possession_proof: read_proof(arguments.proof_file.as_deref(), action)?,
            })
        }
        ("ownership", "prepare-transfer") => {
            arguments.ensure_only(&["node-address", "nonce", "proof-file", "new-owner-wallet"])?;
            AdminOperation::Ownership(OwnershipOperation::PrepareTransfer {
                node_address: node_address()?,
                new_owner_wallet: required(&arguments.new_owner_wallet, "new-owner-wallet")?,
                nonce: required_u64(arguments.nonce, "nonce", action)?,
                new_owner_acceptance_proof: read_proof(arguments.proof_file.as_deref(), action)?,
            })
        }
        ("naming", "resolve") | ("naming", "availability") => {
            arguments.ensure_only(&["node-id"])?;
            let node_id = required(&arguments.node_id, "node-id")?;
            if action == "resolve" {
                AdminOperation::Naming(NamingOperation::Resolve { node_id })
            } else {
                AdminOperation::Naming(NamingOperation::Availability { node_id })
            }
        }
        ("naming", "reverse-resolve") => {
            arguments.ensure_only(&["node-address"])?;
            AdminOperation::Naming(NamingOperation::ReverseResolve {
                node_address: node_address()?,
            })
        }
        ("naming", "prepare-register") => {
            arguments.ensure_only(&["node-id", "node-address", "nonce"])?;
            AdminOperation::Naming(NamingOperation::PrepareRegister {
                node_id: required(&arguments.node_id, "node-id")?,
                node_address: node_address()?,
                nonce: required_u64(arguments.nonce, "nonce", action)?,
            })
        }
        ("naming", "prepare-rename") => {
            arguments.ensure_only(&[
                "current-node-id",
                "replacement-node-id",
                "node-address",
                "nonce",
            ])?;
            AdminOperation::Naming(NamingOperation::PrepareRename {
                current_node_id: required(&arguments.current_node_id, "current-node-id")?,
                replacement_node_id: required(
                    &arguments.replacement_node_id,
                    "replacement-node-id",
                )?,
                node_address: node_address()?,
                nonce: required_u64(arguments.nonce, "nonce", action)?,
            })
        }
        ("rewards", "inspect-account") => {
            arguments.ensure_only(&["node-address"])?;
            AdminOperation::Rewards(RewardOperation::InspectAccount {
                node_address: node_address()?,
            })
        }
        ("rewards", "inspect-withdrawal") => {
            arguments.ensure_only(&["withdrawal-id"])?;
            AdminOperation::Rewards(RewardOperation::InspectWithdrawal {
                withdrawal_id: required(&arguments.withdrawal_id, "withdrawal-id")?,
            })
        }
        ("rewards", "prepare-withdrawal") => {
            arguments.ensure_only(&[
                "withdrawal-id",
                "node-address",
                "destination-wallet",
                "amount-nwei",
                "nonce",
            ])?;
            AdminOperation::Rewards(RewardOperation::PrepareWithdrawal {
                withdrawal_id: required(&arguments.withdrawal_id, "withdrawal-id")?,
                node_address: node_address()?,
                destination_wallet: required(&arguments.destination_wallet, "destination-wallet")?,
                amount_nwei: arguments
                    .amount_nwei
                    .ok_or_else(|| format!("{action} requires --amount-nwei"))?,
                nonce: required_u64(arguments.nonce, "nonce", action)?,
            })
        }
        _ => return Err(format!("unknown {subsystem} action {action}")),
    };
    operation
        .validate()
        .map_err(|error| format!("invalid {subsystem} operation: {}", error.message))?;
    Ok(operation)
}

fn required_u64(value: Option<u64>, field: &str, action: &str) -> Result<u64, String> {
    value.ok_or_else(|| format!("{action} requires --{field}"))
}

fn read_proof(path: Option<&Path>, action: &str) -> Result<Vec<u8>, String> {
    let path = path.ok_or_else(|| format!("{action} requires --proof-file"))?;
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| format!("inspect proof file {}: {error}", path.display()))?;
    if !path.is_absolute()
        || metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_PROOF_BYTES
    {
        return Err("proof file must be an absolute, bounded regular file".into());
    }
    std::fs::read(path).map_err(|error| format!("read proof file {}: {error}", path.display()))
}
