//! Explicit quorum-authorized lost-root recovery. The original Genesis pin is
//! immutable; a replacement key grants authority only through a frozen-validator
//! quorum certificate and the original certified epoch boundary.
use super::*;
use crate::services::apqe_transport::sha256;
use std::{collections::BTreeSet, path::Path};
use synergy_genesis::authority::AuthorityPayload;

const DOMAIN: &str = "SYNERGY-POSY-LOST-AUTHORITY-RECOVERY-V1";
const ML_DSA_65_PUBLIC_KEY_BYTES: usize = 1952;
const ML_DSA_65_SIGNATURE_BYTES: usize = 3309;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Witness {
    pub(super) finalized: FinalizedBlockRecord,
    pub(super) certificates: [SimplifiedQuorumCertificate; 3],
}

#[derive(Serialize)]
struct Transcript<'a> {
    chain_id: u64,
    network_id: &'a str,
    genesis_hash: &'a str,
    genesis_artifact_sha256: &'a str,
    original_root_sha256: &'a str,
    previous_authority_sha256: String,
    previous_epoch_context_root: String,
    finalized: &'a FinalizedBlockRecord,
    boundary_qc_id: String,
    successor_authority_sha256: String,
    replacement_root_sha256: String,
    replacement_signer_id: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Attestation {
    pub(super) validator_id: String,
    pub(super) key_id: String,
    pub(super) signature: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Certificate {
    pub(super) version: u32,
    pub(super) previous_authority_binding: Vec<u8>,
    pub(super) witness: Witness,
    pub(super) successor_authority_binding: Vec<u8>,
    pub(super) replacement_root: Vec<u8>,
    pub(super) attestations: Vec<Attestation>,
}

pub(super) struct VerifiedRecovery {
    pub(super) previous: Arc<VerifiedAuthority>,
    pub(super) next: Arc<VerifiedAuthority>,
    pub(super) witness: Witness,
    pub(super) signing_bytes: Vec<u8>,
    transcript: serde_json::Value,
}

fn exact_successor(
    previous: &AuthorityPayload,
    boundary: &SimplifiedQuorumCertificate,
    next: &AuthorityPayload,
) -> Result<(), String> {
    let start = previous
        .epoch_end_height
        .checked_add(1)
        .ok_or("epoch start overflow")?;
    let span = previous
        .epoch_end_height
        .checked_sub(previous.epoch_start_height)
        .ok_or("invalid prior epoch duration")?;
    if previous.epoch != 1
        || next.epoch != 2
        || next.epoch_start_height != start
        || Some(next.epoch_end_height) != start.checked_add(span)
        || next.anchor_parent.quorum_certificate_reference()
            != Some(boundary.reference().map_err(|e| e.to_string())?)
    {
        return Err("recovery must continue epoch 1 at its exact certified boundary".into());
    }
    // Preserve the full frozen roster, keys, voting weights and status, as well
    // as the ETDAG policy and ingress keys. Only the epoch clock advances.
    let records = |payload: &AuthorityPayload| -> Result<_, String> {
        let mut rows = payload.validators.clone();
        rows.sort_by(|a, b| a.record.validator_id.cmp(&b.record.validator_id));
        serde_json::to_vec(&rows).map_err(|e| e.to_string())
    };
    if previous.finalized_epoch_seed_root != next.finalized_epoch_seed_root {
        return Err("recovery cannot change the finalized epoch seed".into());
    }
    if records(previous)? != records(next)? {
        return Err("recovery cannot modify frozen membership, keys or weights".into());
    }
    let old_policy = previous
        .protected
        .as_ref()
        .ok_or("missing epoch 1 policy")?;
    let mut expected_policy = old_policy.clone();
    expected_policy.epoch_start_timestamp_ms = old_policy
        .timestamp_for_height_ms(
            previous.epoch_start_height,
            previous.epoch_end_height,
            previous.epoch_end_height,
        )?
        .checked_add(old_policy.target_block_time_ms)
        .ok_or("epoch clock overflow")?;
    if serde_json::to_vec(&Some(expected_policy)).map_err(|e| e.to_string())?
        != serde_json::to_vec(&next.protected).map_err(|e| e.to_string())?
    {
        return Err("recovery cannot modify protected policy or reset its clock".into());
    }
    Ok(())
}

fn verify_attestations(
    previous: &VerifiedAuthority,
    transcript: &[u8],
    attestations: &[Attestation],
) -> Result<(), String> {
    if attestations.len() > previous.registry.active_count() {
        return Err("recovery contains too many signatures".into());
    }
    let mut signers = BTreeSet::new();
    let mut public_keys = BTreeSet::new();
    // Key IDs alone do not establish independent signers.
    for validator in previous.registry.active() {
        if !public_keys.insert(previous.keys[&validator.validator_id].public_key.as_slice()) {
            return Err("recovery requires independent frozen validator keys".into());
        }
    }
    for attestation in attestations {
        if !signers.insert(attestation.validator_id.clone()) {
            return Err("recovery repeats a validator".into());
        }
        if attestation.signature.len() != ML_DSA_65_SIGNATURE_BYTES {
            return Err("invalid recovery ML-DSA-65 signature length".into());
        }
        let validator = previous
            .registry
            .active_validator(&attestation.validator_id)
            .map_err(|e| e.to_string())?;
        previous
            .verify_consensus_signature(
                DOMAIN,
                transcript,
                validator,
                &attestation.key_id,
                previous.epoch.epoch,
                &attestation.signature,
            )
            .map_err(|e| format!("invalid recovery approval: {e}"))?;
    }
    synergy_posy::verify_strict_dual_quorum(
        &previous.registry.quorum_validators(),
        &signers.into_iter().collect::<Vec<_>>(),
    )
    .map_err(|e| format!("recovery lacks frozen dual quorum: {e:?}"))
}

fn input(path: &str, limit: u64) -> Result<Vec<u8>, String> {
    if !Path::new(path).is_absolute() {
        return Err("recovery inputs must be absolute paths".into());
    }
    read_bounded(Path::new(path), limit, "public recovery input")
}

pub(super) fn prepare_verified(
    configuration: &NodeConfiguration,
    witness_bytes: Vec<u8>,
    candidate: Vec<u8>,
    replacement_root: Vec<u8>,
    previous_binding_bytes: Vec<u8>,
) -> Result<VerifiedRecovery, String> {
    if configuration.aegis_provider.is_none() {
        return Err("recovery requires an explicit authenticated APQE provider".into());
    }
    let (genesis_hash, genesis) =
        crate::commands::selected_network::verify_with_custody_binding(configuration)?;
    let root_path = configuration
        .consensus
        .authority_trust_key_path
        .as_deref()
        .ok_or("original authority root is required")?;
    let original_root = read_bounded(root_path, MAX_TRUST_KEY_BYTES, "original authority root")?;
    let previous =
        verify_binding_with_explicit_key(configuration, previous_binding_bytes, &original_root)?;
    let signed_genesis: synergy_genesis::signing::SignedGenesis =
        serde_json::from_slice(&read_bounded(
            configuration
                .genesis_path
                .as_deref()
                .ok_or("Genesis path required")?,
            16 * 1024 * 1024,
            "Genesis",
        )?)
        .map_err(|e| e.to_string())?;
    let initial: SignedAuthorityBinding =
        serde_json::from_slice(previous.binding_bytes()).map_err(|e| e.to_string())?;
    let genesis_verifier = super::super::apqe_provider::verifier(
        configuration,
        AegisPolicy {
            allowed_algorithms: vec![SignatureAlgorithm::MlDsa65],
            maximum_message_bytes: 16 * 1024 * 1024,
            maximum_signature_bytes: 16 * 1024,
        },
    )?;
    synergy_genesis::verify_binding_with_verifier(
        &signed_genesis,
        &original_root,
        &initial,
        &genesis_verifier,
    )?;
    if previous.epoch.epoch != 1 {
        return Err(
            "offline lost-root recovery only qualifies the Genesis authority boundary".into(),
        );
    }
    let witness: Witness = serde_json::from_slice(&witness_bytes)
        .map_err(|e| format!("invalid boundary witness: {e}"))?;
    let certificates = verify_transition_witness(
        &previous,
        &witness.finalized,
        &serde_json::to_vec(&witness.certificates).map_err(|e| e.to_string())?,
    )?;
    let boundary = &certificates[2];
    let boundary_qc_id = boundary.id().map_err(|e| e.to_string())?;
    if replacement_root.len() != ML_DSA_65_PUBLIC_KEY_BYTES
        || original_root.len() != ML_DSA_65_PUBLIC_KEY_BYTES
        || replacement_root == original_root
        || previous
            .keys
            .values()
            .any(|k| k.public_key == replacement_root)
    {
        return Err("replacement must use an independent ML-DSA-65 authority root".into());
    }
    let previous_binding: SignedAuthorityBinding =
        serde_json::from_slice(previous.binding_bytes()).map_err(|e| e.to_string())?;
    let next_binding: SignedAuthorityBinding =
        serde_json::from_slice(&candidate).map_err(|e| e.to_string())?;
    if previous_binding.signer_key_id == next_binding.signer_key_id
        || previous
            .keys
            .values()
            .any(|k| k.validator.consensus_key_id == next_binding.signer_key_id)
    {
        return Err(
            "replacement signer ID must differ from existing authority and validator IDs".into(),
        );
    }
    next_binding.payload.validate()?;
    exact_successor(&previous_binding.payload, boundary, &next_binding.payload)?;
    let next = verify_binding_with_explicit_key(configuration, candidate, &replacement_root)?;
    EpochTransitionAuthorization {
        previous_epoch: previous.epoch.epoch,
        previous_epoch_context_root: previous.epoch.root().map_err(|e| e.to_string())?,
        finalized_height: witness.finalized.height,
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
    let transcript = Transcript {
        chain_id: configuration.chain_id,
        network_id: &configuration.network_id,
        genesis_hash: &genesis_hash,
        genesis_artifact_sha256: &genesis.genesis_sha256,
        original_root_sha256: &sha256(&original_root),
        previous_authority_sha256: sha256(previous.binding_bytes()),
        previous_epoch_context_root: previous.epoch.root().map_err(|e| e.to_string())?,
        finalized: &witness.finalized,
        boundary_qc_id,
        successor_authority_sha256: sha256(next.binding_bytes()),
        replacement_root_sha256: sha256(&replacement_root),
        replacement_signer_id: next_binding.signer_key_id,
    };
    let bytes = signing_bytes(&transcript)?;
    let transcript = serde_json::to_value(&transcript).map_err(|e| e.to_string())?;
    Ok(VerifiedRecovery {
        previous,
        next,
        witness,
        signing_bytes: bytes,
        transcript,
    })
}

fn verify_certificate(
    configuration: &NodeConfiguration,
    certificate: &Certificate,
) -> Result<VerifiedRecovery, String> {
    if certificate.version != 1 {
        return Err("unsupported recovery certificate version".into());
    }
    let verified = prepare_verified(
        configuration,
        serde_json::to_vec(&certificate.witness).map_err(|e| e.to_string())?,
        certificate.successor_authority_binding.clone(),
        certificate.replacement_root.clone(),
        certificate.previous_authority_binding.clone(),
    )?;
    verify_attestations(
        &verified.previous,
        &verified.signing_bytes,
        &certificate.attestations,
    )?;
    Ok(verified)
}

fn configured_certificate(
    configuration: &NodeConfiguration,
) -> Result<(Certificate, VerifiedRecovery), String> {
    let path = configuration
        .consensus
        .authority_recovery_certificate_path
        .as_deref()
        .ok_or("explicit authority recovery certificate path is required")?;
    if !path.is_absolute() {
        return Err("recovery certificate path must be absolute".into());
    }
    let certificate: Certificate = serde_json::from_slice(&read_bounded(
        path,
        8 * 1024 * 1024,
        "recovery certificate",
    )?)
    .map_err(|e| format!("decode recovery certificate: {e}"))?;
    let verified = verify_certificate(configuration, &certificate)?;
    Ok((certificate, verified))
}

pub(super) fn verify_recovered_binding(
    configuration: &NodeConfiguration,
    bytes: Vec<u8>,
) -> Result<Arc<VerifiedAuthority>, String> {
    let (certificate, verified) = configured_certificate(configuration)?;
    let candidate: SignedAuthorityBinding =
        serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    if candidate.payload.epoch == verified.next.epoch.epoch {
        if bytes != certificate.successor_authority_binding {
            return Err("recovery successor differs from quorum-authorized exact binding".into());
        }
        return Ok(verified.next);
    }
    // Future epochs still require their normal sequential durable transition
    // witnesses. Recovery does not authorize arbitrary membership or anchors.
    if candidate.payload.epoch <= verified.next.epoch.epoch {
        return Err("recovered authority epoch precedes its certificate".into());
    }
    verify_binding_with_explicit_key(configuration, bytes, &certificate.replacement_root)
}

fn require_observer(configuration: &NodeConfiguration) -> Result<(), String> {
    if configuration.role != synergy_protocol_types::NodeRole::RpcGateway
        || !matches!(
            configuration.consensus.mode,
            synergy_config::ConsensusMode::Disabled | synergy_config::ConsensusMode::Observe
        )
        || configuration.consensus.signing_key_path.is_some()
    {
        return Err("observer activation is restricted to non-signing RPC gateways; validators require recovered durable finality".into());
    }
    Ok(())
}

fn activate_observer(configuration: &NodeConfiguration) -> Result<serde_json::Value, String> {
    require_observer(configuration)?;
    let (certificate, verified) = configured_certificate(configuration)?;
    let current = load(configuration)?.ok_or("gateway current authority is missing")?;
    let repeated = current.binding_bytes() == verified.next.binding_bytes();
    if repeated {
        load_transition_finality_prefix(configuration, &current)?
            .ok_or("gateway recovery lacks its durable transition")?;
    } else {
        if current.binding_bytes() != verified.previous.binding_bytes() {
            return Err("gateway current authority differs from certified predecessor".into());
        }
        // This installs public verified trust and its boundary proof only. It
        // creates no execution/finality records and cannot enable validator votes.
        verify_and_persist_transition(
            configuration,
            &verified.previous,
            &verified.witness.finalized,
            &serde_json::to_vec(&verified.witness.certificates).map_err(|e| e.to_string())?,
            certificate.successor_authority_binding,
            &AuthorityTransitionSignal::default(),
        )?;
    }
    Ok(
        serde_json::json!({"status":"observer-trust-activated", "epoch":verified.next.epoch.epoch,
        "repeated":repeated,"validator_finality_imported":false,"genesis_trust_pin_preserved":true}),
    )
}

fn activate(configuration: &NodeConfiguration) -> Result<serde_json::Value, String> {
    let (certificate, verified) = configured_certificate(configuration)?;
    let current = load(configuration)?.ok_or("current authority is missing")?;
    let repeated = current.binding_bytes() == verified.next.binding_bytes();
    if !repeated && current.binding_bytes() != verified.previous.binding_bytes() {
        return Err("activation current authority differs from certified predecessor".into());
    }
    let layout = NodeStorageLayout::new(configuration.storage.data_directory.clone())
        .map_err(|e| e.to_string())?;
    // Open the canonical owners before reading the anchor: AtomicStore recovery
    // must complete before inspecting any latest state captured in memory.
    let budget = synergy_state::world_resources::WorldResourceBudget::new(
        configuration.storage.world_memory_budget_bytes,
    );
    let state = synergy_state::FinalizedStateStore::load_budgeted(
        layout.state().join("execution"),
        budget.clone(),
    )
    .map_err(|e| format!("recover durable execution state: {e:?}"))?;
    let root = layout.consensus().join("posy");
    let _atomic = synergy_posy::persistence::AtomicConsensusTransitionStore::new(&root)
        .map_err(|e| e.to_string())?;
    let finality =
        synergy_posy::persistence::FinalityStore::new(&root).map_err(|e| e.to_string())?;
    let anchor = &verified.witness.finalized;
    let tip = state
        .current()
        .ok_or("activation requires existing recovered execution state")?;
    if tip.finalized_height != anchor.height
        || tip.finalized_block_id != anchor.block_id
        || finality
            .get(anchor.height)
            .map_err(|e| e.to_string())?
            .as_ref()
            != Some(anchor)
    {
        return Err(
            "activation requires the exact recovered durable certified boundary; catch up first"
                .into(),
        );
    }
    if state
        .current_world_state_budgeted(&budget)
        .map_err(|e| format!("verify recovered world: {e:?}"))?
        .is_none()
    {
        return Err("activation lacks authenticated recovered execution dependencies".into());
    }
    let candidates = synergy_execution::CandidateStore::new_budgeted(
        layout.blocks().join("execution-candidates"),
        budget,
    )?;
    let candidate = candidates
        .get_budgeted(anchor.height)
        .map_err(|e| e.to_string())?
        .ok_or("activation lacks the finalized execution candidate")?;
    candidate.validate()?;
    if candidate.height != anchor.height
        || candidate.block_id != anchor.block_id
        || candidate.protected_execution_root != anchor.protected_execution_root
        || candidate.state_root != tip.state_root
    {
        return Err("activation execution candidate differs from certified anchor".into());
    }
    if repeated {
        load_transition_finality_prefix(configuration, &current)?
            .ok_or("activation restart lacks its durable transition")?;
    } else {
        verify_and_persist_transition(
            configuration,
            &verified.previous,
            anchor,
            &serde_json::to_vec(&verified.witness.certificates).map_err(|e| e.to_string())?,
            certificate.successor_authority_binding,
            &AuthorityTransitionSignal::default(),
        )?;
    }
    Ok(
        serde_json::json!({"status":"activated", "epoch":verified.next.epoch.epoch,
        "finalized_height":anchor.height, "repeated":repeated, "genesis_trust_pin_preserved":true}),
    )
}

#[path = "authority_recovery_approval.rs"]
mod approval;
#[path = "authority_recovery_registry.rs"]
mod registry;

pub(crate) fn cli(args: impl Iterator<Item = String>) -> Result<(), String> {
    let args = args.take(9).collect::<Vec<_>>();
    if let [action, config, custody, output] = args.as_slice() {
        if action == "registry" {
            return registry::cli(config, custody, output);
        }
    }
    if let [action, config, certificate_path] = args.as_slice() {
        if action == "check" {
            if !Path::new(config).is_absolute() {
                return Err("recovery configuration path must be absolute".into());
            }
            let configuration =
                synergy_config::load(Path::new(config)).map_err(|e| e.to_string())?;
            let bytes = input(certificate_path, 8 * 1024 * 1024)?;
            let certificate: Certificate =
                serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
            let verified = verify_certificate(&configuration, &certificate)?;
            println!(
                "{}",
                crate::output::json::render(
                    &serde_json::json!({"status":"quorum-certificate-verified",
                "certificate_sha256":sha256(&bytes),"epoch":verified.next.epoch.epoch,
                "finalized_height":verified.witness.finalized.height,"successor_authority_sha256":sha256(verified.next.binding_bytes()),
                "replacement_root_sha256":sha256(&certificate.replacement_root),"genesis_trust_pin_preserved":true})
                )?
            );
            return Ok(());
        }
    }
    if let [action, config, witness, candidate, root] = args.as_slice() {
        if action == "approve" {
            return approval::approve(config, witness, candidate, root);
        }
    }
    if let [action, config] = args.as_slice() {
        if action == "activate" || action == "activate-observer" {
            let config = Path::new(config);
            let _exclusive = crate::services::checkpoint::lock_configuration(config)?;
            let configuration = synergy_config::load(config).map_err(|e| e.to_string())?;
            crate::services::checkpoint::require_stopped(config, &configuration.admin_socket_path)?;
            let result = if action == "activate-observer" {
                activate_observer(&configuration)?
            } else {
                activate(&configuration)?
            };
            println!("{}", crate::output::json::render(&result)?);
            return Ok(());
        }
    }
    let (config, witness_path, candidate) = match args.as_slice() {
        [action, config, witness] if action == "boundary" => (config, witness, None),
        [action, config, witness, binding, root] if action == "prepare" => (config, witness, Some((binding, root, None, None))),
        [action, config, witness, binding, root, approvals] if action == "verify" => (config, witness, Some((binding, root, Some(approvals), None))),
        [action, config, witness, binding, root, approvals, output] if action == "assemble" => (config, witness, Some((binding, root, Some(approvals), Some(output)))),
        _ => return Err("usage: authority-recovery boundary CONFIG WITNESS | prepare CONFIG WITNESS SUCCESSOR ROOT | verify CONFIG WITNESS SUCCESSOR ROOT APPROVALS | assemble CONFIG WITNESS SUCCESSOR ROOT APPROVALS OUTPUT | check CONFIG CERTIFICATE | activate CONFIG | activate-observer CONFIG".into()),
    };
    if !Path::new(config).is_absolute() {
        return Err("recovery configuration path must be absolute".into());
    }
    let configuration = synergy_config::load(Path::new(config)).map_err(|e| e.to_string())?;
    let witness_bytes = input(witness_path, MAX_CONSENSUS_MESSAGE_BYTES as u64)?;
    let previous = load(&configuration)?.ok_or("previous authority binding is required")?;
    if let Some((binding_path, root_path, approvals_path, output)) = candidate {
        let candidate = input(binding_path, MAX_AUTHORITY_BYTES)?;
        let replacement_root = input(root_path, MAX_TRUST_KEY_BYTES)?;
        let verified = prepare_verified(
            &configuration,
            witness_bytes,
            candidate.clone(),
            replacement_root.clone(),
            previous.binding_bytes().to_vec(),
        )?;
        let mut status = "requires-validator-quorum";
        if let Some(path) = approvals_path {
            let attestations: Vec<Attestation> =
                serde_json::from_slice(&input(path, MAX_CONSENSUS_MESSAGE_BYTES as u64)?)
                    .map_err(|e| format!("invalid approvals: {e}"))?;
            verify_attestations(&verified.previous, &verified.signing_bytes, &attestations)?;
            status = "verified-offline";
            if let Some(output) = output {
                let certificate = Certificate {
                    version: 1,
                    previous_authority_binding: previous.binding_bytes().to_vec(),
                    witness: verified.witness.clone(),
                    successor_authority_binding: candidate,
                    replacement_root,
                    attestations,
                };
                let bytes = serde_json::to_vec_pretty(&certificate).map_err(|e| e.to_string())?;
                if !Path::new(output).is_absolute() {
                    return Err("certificate output must be absolute".into());
                }
                let mut file = OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .open(output)
                    .map_err(|e| e.to_string())?;
                file.write_all(&bytes)
                    .and_then(|_| file.sync_all())
                    .map_err(|e| e.to_string())?;
            }
        }
        println!(
            "{}",
            crate::output::json::render(&serde_json::json!({"status":status,"domain":DOMAIN,
            "transcript":verified.transcript,"signing_bytes_sha256":sha256(&verified.signing_bytes)}))?
        );
    } else {
        crate::commands::selected_network::verify_with_custody_binding(&configuration)?;
        let witness: Witness = serde_json::from_slice(&witness_bytes).map_err(|e| e.to_string())?;
        let certificates = verify_transition_witness(
            &previous,
            &witness.finalized,
            &serde_json::to_vec(&witness.certificates).map_err(|e| e.to_string())?,
        )?;
        println!(
            "{}",
            crate::output::json::render(&serde_json::json!({"status":"boundary-verified",
            "epoch":previous.epoch.epoch,"finalized":witness.finalized,"boundary_height":certificates[2].context.height,
            "boundary_qc_id":certificates[2].id().map_err(|e| e.to_string())?}))?
        );
    }
    Ok(())
}

fn signing_bytes(transcript: &Transcript<'_>) -> Result<Vec<u8>, String> {
    let mut bytes = DOMAIN.as_bytes().to_vec();
    bytes.push(0);
    bytes.extend(serde_json::to_vec(transcript).map_err(|e| e.to_string())?);
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use synergy_address_engine::{apqe::provider::SignOptions, types::Algorithm};
    use synergy_aegis::{AegisSigner, PqvmSigner};
    use synergy_posy::ValidatorStatus;

    #[test]
    #[ignore = "requires pinned native APQE and captured public Canary boundary"]
    fn native_canary_boundary_and_replacement_candidate_are_read_only() {
        let (fixture_root, mut config) =
            crate::services::socket_qualification::sync_poll_native_test_configuration();
        struct Cleanup(std::path::PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        let _cleanup = Cleanup(fixture_root.clone());
        let public = std::path::PathBuf::from(std::env::var("APQE_CANARY_BOUNDARY_DIR").unwrap());
        config.chain_id = 99999;
        config.network_id = "posy-apqe-canary-process-49028".into();
        config.genesis_path = Some(public.join("genesis.json"));
        config.manifest_path = public.join("network-manifest.json");
        config.consensus.authority_binding = Some(public.join("authority.json"));
        config.consensus.authority_trust_key_path = Some(public.join("authority-root.pub"));
        config.consensus.mode = synergy_config::ConsensusMode::Observe;
        config.apqe_transport = None;
        config.vpn = synergy_config::VpnConfiguration::default();
        let cfg = fixture_root.join("recovery-test.json");
        fs::write(&cfg, serde_json::to_vec(&config).unwrap()).unwrap();
        let witness_file = public.join("synergy-val2-witness.json");
        let witness_bytes = fs::read(&witness_file).unwrap();
        assert_eq!(
            witness_bytes,
            fs::read(public.join("synergy-val3-witness.json")).unwrap()
        );
        let command = |action: &str, witness: &Path, extra: &[&Path]| {
            cli(std::iter::once(action.to_owned()).chain(
                [cfg.as_path(), witness]
                    .into_iter()
                    .chain(extra.iter().copied())
                    .map(|p| p.to_string_lossy().into_owned()),
            ))
        };
        command("boundary", &witness_file, &[]).unwrap();
        let witness: Witness = serde_json::from_slice(&witness_bytes).unwrap();
        let mut corrupt: serde_json::Value = serde_json::from_slice(&witness_bytes).unwrap();
        corrupt["finalized"]["protected_execution_root"] = serde_json::json!("0".repeat(64));
        let corrupt_path = fixture_root.join("corrupt.json");
        fs::write(&corrupt_path, serde_json::to_vec(&corrupt).unwrap()).unwrap();
        assert!(command("boundary", &corrupt_path, &[])
            .unwrap_err()
            .contains("differs from local finalized"));
        let mut candidate: SignedAuthorityBinding =
            serde_json::from_slice(&fs::read(public.join("authority.json")).unwrap()).unwrap();
        let previous_payload = candidate.payload.clone();
        let qc = &witness.certificates[2];
        let payload = &mut candidate.payload;
        payload.epoch = 2;
        payload.epoch_start_height = 10001;
        payload.epoch_end_height = 20000;
        payload.anchor_parent = SimplifiedFinalityParent::QuorumCertificate {
            height: qc.context.height,
            block_id: qc.block_id.clone(),
            qc_id: qc.id().unwrap(),
        };
        let protected = payload.protected.as_mut().unwrap();
        protected.epoch_start_timestamp_ms += protected.target_block_time_ms * 10000;
        payload.consensus_parameter_root = protected.commitment().unwrap();
        // The candidate policy check rejects otherwise admissible policy changes.
        let mut altered = payload.clone();
        altered.protected.as_mut().unwrap().epoch_start_timestamp_ms += 1;
        assert!(exact_successor(&previous_payload, qc, &altered).is_err());
        altered = payload.clone();
        altered.validators[0].record.frozen_voting_weight += 1;
        assert!(exact_successor(&previous_payload, qc, &altered).is_err());
        let engine = crate::services::apqe_provider::load(&config).unwrap();
        let pair = engine
            .lock()
            .unwrap()
            .generate_keypair(Algorithm::MlDsa65)
            .unwrap();
        let key_id = KeyId::new("disposable-authority-recovery-test").unwrap();
        let signer = PqvmSigner::with_apqe(
            AegisPolicy {
                allowed_algorithms: vec![SignatureAlgorithm::MlDsa65],
                maximum_message_bytes: MAX_CONSENSUS_MESSAGE_BYTES,
                maximum_signature_bytes: 16 * 1024,
            },
            key_id.clone(),
            &pair.public_key,
            pair.private_key.as_bytes().to_vec(),
            engine.clone(),
        )
        .unwrap();
        candidate.signature = signer
            .sign(
                &key_id,
                &SigningContext {
                    domain: synergy_genesis::authority::AUTHORITY_SIGNING_DOMAIN.into(),
                    chain_id: payload.chain_id,
                    epoch: Some(payload.epoch),
                    height: None,
                },
                &payload.signing_bytes().unwrap(),
            )
            .unwrap()
            .bytes;
        candidate.signer_key_id = key_id.as_str().into();
        let candidate_bytes = serde_json::to_vec(&candidate).unwrap();
        let candidate_path = fixture_root.join("disposable-candidate.json");
        let root_path = fixture_root.join("disposable-root.pub");
        let approvals_path = fixture_root.join("no-approvals.json");
        fs::write(&candidate_path, &candidate_bytes).unwrap();
        fs::write(&root_path, &pair.public_key).unwrap();
        fs::write(&approvals_path, b"[]").unwrap();
        assert!(verify_binding_bytes(&config, candidate_bytes).is_err());
        command("prepare", &witness_file, &[&candidate_path, &root_path]).unwrap();
        assert!(command(
            "verify",
            &witness_file,
            &[&candidate_path, &root_path, &approvals_path]
        )
        .unwrap_err()
        .contains("lacks frozen dual quorum"));
        assert!(!config.storage.data_directory.exists());

        // A distinct five-key fixture demonstrates the approval gate without
        // using or copying any live validator's signing material.
        let pairs = (0..5)
            .map(|_| {
                engine
                    .lock()
                    .unwrap()
                    .generate_keypair(Algorithm::MlDsa65)
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let test_records = pairs
            .iter()
            .enumerate()
            .map(|(i, pair)| {
                (
                    ValidatorRecord {
                        validator_id: format!("recovery-v{i}"),
                        consensus_key_id: format!("recovery-k{i}"),
                        frozen_voting_weight: 1,
                        status: ValidatorStatus::Active,
                    },
                    pair.public_key.clone(),
                )
            })
            .collect();
        let test_authority =
            qualification_authority_with_provider(test_records, Some(engine.clone()));
        let raw = b"SYNERGY-POSY-LOST-AUTHORITY-RECOVERY-V1\0disposable-quorum-transcript";
        let mut approvals: Vec<_> = pairs
            .iter()
            .take(4)
            .enumerate()
            .map(|(i, pair)| Attestation {
                validator_id: format!("recovery-v{i}"),
                key_id: format!("recovery-k{i}"),
                signature: engine
                    .lock()
                    .unwrap()
                    .sign(
                        Algorithm::MlDsa65,
                        pair.private_key.as_bytes(),
                        raw,
                        SignOptions::default(),
                    )
                    .unwrap(),
            })
            .collect();
        verify_attestations(&test_authority, raw, &approvals).unwrap();
        assert!(verify_attestations(&test_authority, raw, &approvals[..3]).is_err());
        assert!(
            verify_attestations(&test_authority, b"different root or witness", &approvals).is_err()
        );
        approvals[3].validator_id = approvals[0].validator_id.clone();
        assert!(verify_attestations(&test_authority, raw, &approvals).is_err());
    }
}

#[cfg(test)]
#[path = "authority_recovery_tests.rs"]
pub(in crate::services) mod native_activation_tests;
