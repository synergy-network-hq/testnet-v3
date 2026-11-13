//! Offline ordinary continuation under the root authenticated by the existing
//! lost-root recovery certificate. This does not replace that certificate or
//! grant authority from local state, mutable configuration, or a new key.
use super::*;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Proposal {
    version: u32,
    previous_authority_binding: Vec<u8>,
    witness: Witness,
    successor_authority_binding: Vec<u8>,
}

fn verify(
    config: &NodeConfiguration,
    proposal: &Proposal,
) -> Result<(Arc<VerifiedAuthority>, Arc<VerifiedAuthority>), String> {
    if proposal.version != 1 {
        return Err("unsupported authority successor proposal".into());
    }
    let (_, recovery) = configured_certificate(config)?;
    let previous = verify_binding_bytes(config, proposal.previous_authority_binding.clone())?;
    if previous.epoch.epoch < recovery.next.epoch.epoch {
        return Err("successor predecessor predates authenticated replacement root".into());
    }
    // The predecessor itself must have a durable, authenticated origin here,
    // including on a non-signing relay.
    load_transition_finality_prefix(config, &previous)?
        .ok_or("successor predecessor lacks its verified transition")?;
    let next = verify_binding_bytes(config, proposal.successor_authority_binding.clone())?;
    let [_, _, boundary] = verify_transition_witness(
        &previous,
        &proposal.witness.finalized,
        &serde_json::to_vec(&proposal.witness.certificates).map_err(|e| e.to_string())?,
    )?;
    if next.anchor_parent.quorum_certificate_reference()
        != Some(boundary.reference().map_err(|e| e.to_string())?)
    {
        return Err("successor anchor differs from certified boundary QC".into());
    }
    EpochTransitionAuthorization {
        previous_epoch: previous.epoch.epoch,
        previous_epoch_context_root: previous.epoch.root().map_err(|e| e.to_string())?,
        finalized_height: proposal.witness.finalized.height,
        next_epoch: next.epoch.epoch,
        next_epoch_start_height: next.epoch.epoch_start_height,
        next_epoch_end_height: next.epoch.epoch_end_height,
        next_consensus_parameter_root: next.epoch.consensus_parameter_root.clone(),
        next_active_validator_set_root: next.epoch.active_validator_set_root.clone(),
        next_validator_consensus_key_root: next.epoch.validator_consensus_key_root.clone(),
        next_frozen_voting_weight_root: next.epoch.frozen_voting_weight_root.clone(),
    }
    .validate(&previous.epoch, &next.epoch, &next.registry)
    .map_err(|e| e.to_string())?;
    let current = load(config)?.ok_or("current authority is missing")?;
    if current.binding_bytes() != previous.binding_bytes()
        && current.binding_bytes() != next.binding_bytes()
    {
        return Err("installed authority is not an exact endpoint of this successor".into());
    }
    Ok((previous, next))
}

pub(crate) fn cli(args: impl Iterator<Item = String>) -> Result<(), String> {
    let args: Vec<_> = args.take(6).collect();
    let [command, config, proposal_path, extra @ ..] = args.as_slice() else {
        return Err("usage: authority-successor check|activate|activate-observer CONFIG PROPOSAL; registry CONFIG PROPOSAL CUSTODY OUTPUT".into());
    };
    let config = Path::new(config);
    if !config.is_absolute() {
        return Err("successor configuration path must be absolute".into());
    }
    let lock = matches!(command.as_str(), "activate" | "activate-observer")
        .then(|| crate::services::checkpoint::lock_configuration(config))
        .transpose()?;
    let configuration = synergy_config::load(config).map_err(|e| e.to_string())?;
    if lock.is_some() {
        crate::services::checkpoint::require_stopped(config, &configuration.admin_socket_path)?;
    }
    let bytes = input(proposal_path, 8 * 1024 * 1024)?;
    let proposal: Proposal = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    let (previous, next) = verify(&configuration, &proposal)?;
    let result = match (command.as_str(), extra) {
        ("check", []) => serde_json::json!({
            "status":"successor-proof-verified",
            "successor_proposal_sha256": sha256(&bytes),
            "previous_authority_sha256": sha256(previous.binding_bytes()),
            "successor_authority_sha256": sha256(next.binding_bytes()),
            "epoch": next.epoch.epoch,
            "finalized_height": proposal.witness.finalized.height,
            "genesis_trust_pin_preserved": true,
        }),
        ("activate" | "activate-observer", []) => {
            activate_verified(&configuration, &previous, &next, &proposal.witness, command == "activate-observer")?
        }
        ("registry", [custody, output]) => {
            return registry::issue_successor(config, custody, output, Path::new(proposal_path), &previous, &next);
        }
        _ => return Err("invalid authority-successor arguments".into()),
    };
    println!("{}", crate::output::json::render(&result)?);
    Ok(())
}
