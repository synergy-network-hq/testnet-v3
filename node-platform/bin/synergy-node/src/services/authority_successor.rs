//! Offline ordinary continuation under the root authenticated by the existing
//! lost-root recovery certificate. This does not replace that certificate or
//! grant authority from local state, mutable configuration, or a new key.
use super::*;
use crate::services::{
    apqe_rpc::Admission,
    apqe_transport::{self, Snapshot, Stamp},
    processing_pipeline::{processing_namespace, NativeProcessingParent},
    processing_proposals::{epoch_store_path, ProcessingProposalStore},
};
use std::path::PathBuf;
use synergy_posy::persistence::{FinalityStore, VerifiedQuorumCertificateStore};

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
    let predecessor_proof = transition_witness_path(config, &previous)?
        .ok_or("successor predecessor lacks its verified transition")?;
    let stored = apqe_transport::read(&predecessor_proof, 4 * 1024 * 1024, false)?;
    verify_stored_transition(config, &previous, &stored)?;
    if config.chain_id != 99999 {
        return Err("offline successor is scoped to Canary 99999".into());
    }
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
    let established: SignedAuthorityBinding =
        serde_json::from_slice(previous.binding_bytes()).map_err(|e| e.to_string())?;
    let proposed: SignedAuthorityBinding =
        serde_json::from_slice(next.binding_bytes()).map_err(|e| e.to_string())?;
    if established.signer_key_id != proposed.signer_key_id
        || serde_json::to_vec(&successor_payload(established.payload, &boundary)?)
            .map_err(|e| e.to_string())?
            != serde_json::to_vec(&proposed.payload).map_err(|e| e.to_string())?
    {
        return Err("binding differs from exact authorized 1,000-block continuation".into());
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

const CANARY_EPOCH_BLOCKS: u64 = 1_000;

fn canary_successor_range(chain: u64, epoch: u64, first: u64, last: u64) -> Option<(u64, u64, u64)> {
    if chain != 99999 {
        return None;
    }
    let expected_first = if epoch == 2 {
        10_001
    } else {
        epoch.checked_sub(3)?.checked_mul(CANARY_EPOCH_BLOCKS)?.checked_add(20_001)?
    };
    let expected_last = if epoch == 2 {
        20_000
    } else {
        expected_first.checked_add(CANARY_EPOCH_BLOCKS - 1)?
    };
    if (first, last) != (expected_first, expected_last) {
        return None;
    }
    Some((epoch.checked_add(1)?, last.checked_add(1)?, last.checked_add(CANARY_EPOCH_BLOCKS)?))
}

fn successor_payload(
    mut payload: AuthorityPayload,
    boundary: &SimplifiedQuorumCertificate,
) -> Result<AuthorityPayload, String> {
    let (epoch, first, last) = canary_successor_range(
        payload.chain_id,
        payload.epoch,
        payload.epoch_start_height,
        payload.epoch_end_height,
    )
    .ok_or("predecessor is outside the established 1,000-block Canary continuation schedule")?;
    if boundary.context.height != payload.epoch_end_height {
        return Err("successor requires the certified last height of the predecessor".into());
    }
    let policy = payload
        .protected
        .as_mut()
        .ok_or("predecessor lacks ETDAG policy")?;
    policy.epoch_start_timestamp_ms = policy
        .timestamp_for_height_ms(
            payload.epoch_start_height,
            payload.epoch_end_height,
            payload.epoch_end_height,
        )?
        .checked_add(policy.target_block_time_ms)
        .ok_or("successor epoch clock overflow")?;
    payload.consensus_parameter_root = policy.commitment()?;
    payload.epoch = epoch;
    payload.epoch_start_height = first;
    payload.epoch_end_height = last;
    payload.anchor_parent = SimplifiedFinalityParent::QuorumCertificate {
        height: boundary.context.height,
        block_id: boundary.block_id.clone(),
        qc_id: boundary.id().map_err(|e| e.to_string())?,
    };
    payload.validate()?;
    Ok(payload)
}

#[cfg(test)]
#[test]
fn canary_schedule_preserves_the_signed_bridge_and_continues_in_exact_windows() {
    assert_eq!(canary_successor_range(99999, 2, 10001, 20000), Some((3, 20001, 21000)));
    assert_eq!(canary_successor_range(99999, 3, 20001, 21000), Some((4, 21001, 22000)));
    assert_eq!(canary_successor_range(99999, 4, 21001, 22000), Some((5, 22001, 23000)));
    assert_eq!(canary_successor_range(99999, 3, 20002, 21001), None);
    assert_eq!(canary_successor_range(99999, 3, 20001, 22000), None);
    assert_eq!(canary_successor_range(1266, 3, 20001, 21000), None);
    assert_eq!(canary_successor_range(99999, 1, 1, 10000), None);
    assert_eq!(canary_successor_range(99999, u64::MAX, 20001, 21000), None);
}

fn stored_transition(
    previous: &VerifiedAuthority,
    next: &VerifiedAuthority,
    witness: &Witness,
) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&StoredEpochTransition {
        version: 1,
        next_epoch: next.epoch.epoch,
        previous_authority_binding: previous.binding_bytes().to_vec(),
        finalized: witness.finalized.clone(),
        finality_witness: serde_json::to_vec(&witness.certificates).map_err(|e| e.to_string())?,
    })
    .map_err(|e| e.to_string())
}

fn verify_processing_boundary(
    config: &NodeConfiguration,
    previous: &Arc<VerifiedAuthority>,
    next: &VerifiedAuthority,
    witness: &Witness,
) -> Result<(), String> {
    if !previous.processing_profile_enabled() || !next.processing_profile_enabled() {
        return Err("Canary successor requires the existing processing profile".into());
    }
    let layout =
        NodeStorageLayout::new(config.storage.data_directory.clone()).map_err(|e| e.to_string())?;
    let budget = synergy_state::world_resources::WorldResourceBudget::new(
        config.storage.world_memory_budget_bytes,
    );
    let boundary = &witness.certificates[2];
    let candidates = synergy_execution::CandidateStore::new_budgeted(
        layout.blocks().join("execution-candidates"),
        budget.clone(),
    )?;
    let candidate = candidates
        .get_budgeted(boundary.context.height)
        .map_err(|e| e.to_string())?
        .ok_or("certified terminal execution candidate is unavailable")?;
    let transition =
        verify_stored_transition(config, next, &stored_transition(previous, next, witness)?)?;
    let path = epoch_store_path(&layout.blocks(), previous.epoch.epoch);
    if !fs::symlink_metadata(&path).is_ok_and(|m| m.is_dir() && !m.file_type().is_symlink()) {
        return Err("certified terminal proposal journal is unavailable".into());
    }
    let store = ProcessingProposalStore::open(
        &path,
        processing_namespace(previous, &budget)?,
        &budget,
        previous.clone(),
    )?;
    store.with_validation(&candidate.block_id, |certificate| {
        NativeProcessingParent::verify_transition(
            &candidate,
            certificate,
            previous,
            next,
            &transition,
        )
        .map(|_| ())
    })
}

fn export_boundary(config: &NodeConfiguration, output: &Path) -> Result<(), String> {
    let authority = load(config)?.ok_or("missing installed authenticated authority")?;
    let root = NodeStorageLayout::new(config.storage.data_directory.clone())
        .map_err(|e| e.to_string())?
        .consensus()
        .join("posy");
    let end = authority.epoch.epoch_end_height;
    let height = end
        .checked_sub(2)
        .filter(|height| *height != 0)
        .ok_or("invalid epoch end")?;
    let finality = FinalityStore::new(&root).map_err(|e| e.to_string())?;
    let finalized = finality
        .get(height)
        .map_err(|e| e.to_string())?
        .ok_or("certified terminal finality record is not yet durable")?;
    let qcs = VerifiedQuorumCertificateStore::new(&root).map_err(|e| e.to_string())?;
    let [a, b, c] = [height, end - 1, end].map(|height| {
        qcs.get_verified(
            height,
            &authority.epoch,
            &authority.registry,
            authority.as_ref(),
        )
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("terminal QC H{height} is not durable"))
    });
    let certificates = [a?, b?, c?];
    verify_transition_witness(
        &authority,
        &finalized,
        &serde_json::to_vec(&certificates).map_err(|e| e.to_string())?,
    )?;
    write_public(
        output,
        &serde_json::to_vec(&Witness {
            finalized,
            certificates,
        })
        .map_err(|e| e.to_string())?,
    )
}

fn write_public(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if !path.is_absolute() {
        return Err("public successor output must be absolute".into());
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|e| e.to_string())?;
    if let Err(error) = file.write_all(bytes).and_then(|_| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(error.to_string());
    }
    File::open(path.parent().ok_or("public output parent required")?)
        .and_then(|directory| directory.sync_all())
        .map_err(|e| e.to_string())
}

fn with_staged_network<T>(
    config: &NodeConfiguration,
    previous: &VerifiedAuthority,
    next: &VerifiedAuthority,
    witness: &Witness,
    registry: &Path,
    workspace: &Path,
    f: impl FnOnce(&NodeConfiguration, &[String; 2]) -> Result<T, String>,
) -> Result<T, String> {
    if !workspace.is_absolute() {
        return Err("staged public verification workspace must be absolute".into());
    }
    fs::create_dir(workspace).map_err(|e| e.to_string())?;
    struct Cleanup(PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    let _cleanup = Cleanup(workspace.to_owned());
    let mut staged = config.clone();
    let authority_path = workspace.join("authority.json");
    write_public(&authority_path, next.binding_bytes())?;
    staged.consensus.authority_binding = Some(authority_path);
    staged.storage.data_directory = workspace.join("data");
    let path = transition_witness_path(&staged, next)?
        .ok_or("staged successor requires its exact witness")?;
    fs::create_dir_all(path.parent().ok_or("staged transition parent missing")?)
        .map_err(|e| e.to_string())?;
    write_public(&path, &stored_transition(previous, next, witness)?)?;
    let transport = staged
        .apqe_transport
        .as_mut()
        .ok_or("missing APQE transport")?;
    transport.registry_path = registry.to_owned();
    let anchors = [
        transport.registry_trust_key_sha256.clone(),
        transport.genesis_trust_key_sha256.clone(),
    ];
    f(&staged, &anchors)
}

fn check_staged_network(
    config: &NodeConfiguration,
    previous: &VerifiedAuthority,
    next: &VerifiedAuthority,
    witness: &Witness,
    registry: &Path,
    admission: Option<&Path>,
    workspace: &Path,
) -> Result<serde_json::Value, String> {
    with_staged_network(
        config,
        previous,
        next,
        witness,
        registry,
        workspace,
        |staged, anchors| {
            let (registry_sha256, admission_sha256) = if let Some(path) = admission {
                let before = Stamp::capture(path)?;
                let admission = Admission::load(staged, path)?;
                let digest = sha256(&apqe_transport::read(path, 128 * 1024, false)?);
                if !before.unchanged() {
                    return Err("staged RPC admission changed".into());
                }
                (sha256(&admission.base.registry_bytes), Some(digest))
            } else {
                (
                    sha256(&Snapshot::load(staged, anchors)?.registry_bytes),
                    None,
                )
            };
            Ok(serde_json::json!({
                "status":"successor-network-verified",
                "registry_sha256":registry_sha256,
                "admission_sha256":admission_sha256,
            }))
        },
    )
}

pub(crate) fn cli(args: impl Iterator<Item = String>) -> Result<(), String> {
    let args: Vec<_> = args.take(10).collect();
    let [command, config, proposal_path, extra @ ..] = args.as_slice() else {
        return Err("usage: authority-successor check|activate|activate-observer CONFIG PROPOSAL; export-boundary CONFIG WITNESS; prepare-payload CONFIG WITNESS OUTPUT; bundle CONFIG WITNESS SIGNED_AUTHORITY OUTPUT; check-local CONFIG PROPOSAL; registry CONFIG PROPOSAL CUSTODY OUTPUT; check-network CONFIG PROPOSAL REGISTRY WORKSPACE [ADMISSION]; issue-admission CONFIG PROPOSAL REGISTRY WORKSPACE ENROLLMENT CUSTODY UNLOCK OUTPUT".into());
    };
    let config = Path::new(config);
    if !config.is_absolute() {
        return Err("successor configuration path must be absolute".into());
    }
    let lock = matches!(
        command.as_str(),
        "activate" | "activate-observer" | "export-boundary" | "check-local"
    )
    .then(|| crate::services::checkpoint::lock_configuration(config))
    .transpose()?;
    let configuration = synergy_config::load(config).map_err(|e| e.to_string())?;
    if lock.is_some() {
        crate::services::checkpoint::require_stopped(config, &configuration.admin_socket_path)?;
    }
    if command == "export-boundary" && extra.is_empty() {
        return export_boundary(&configuration, Path::new(proposal_path));
    }
    if command == "prepare-payload" && extra.len() == 1 {
        let previous = load(&configuration)?.ok_or("missing installed predecessor")?;
        let bytes = apqe_transport::read(
            Path::new(proposal_path),
            MAX_CONSENSUS_MESSAGE_BYTES as u64,
            false,
        )?;
        let witness: Witness = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
        let [_, _, boundary] = verify_transition_witness(
            &previous,
            &witness.finalized,
            &serde_json::to_vec(&witness.certificates).map_err(|e| e.to_string())?,
        )?;
        let binding: SignedAuthorityBinding =
            serde_json::from_slice(previous.binding_bytes()).map_err(|e| e.to_string())?;
        return write_public(
            Path::new(&extra[0]),
            &serde_json::to_vec(&successor_payload(binding.payload, &boundary)?)
                .map_err(|e| e.to_string())?,
        );
    }
    if command == "bundle" && extra.len() == 2 {
        let previous = load(&configuration)?.ok_or("missing installed predecessor")?;
        let witness: Witness = serde_json::from_slice(&apqe_transport::read(
            Path::new(proposal_path),
            MAX_CONSENSUS_MESSAGE_BYTES as u64,
            false,
        )?)
        .map_err(|e| e.to_string())?;
        let proposal = Proposal {
            version: 1,
            previous_authority_binding: previous.binding_bytes().to_vec(),
            witness,
            successor_authority_binding: apqe_transport::read(
                Path::new(&extra[0]),
                MAX_AUTHORITY_BYTES,
                false,
            )?,
        };
        verify(&configuration, &proposal)?;
        return write_public(
            Path::new(&extra[1]),
            &serde_json::to_vec(&proposal).map_err(|e| e.to_string())?,
        );
    }
    let stamp = Stamp::capture(Path::new(proposal_path))?;
    let bytes = apqe_transport::read(Path::new(proposal_path), 8 * 1024 * 1024, false)?;
    let proposal: Proposal = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    let (previous, next) = verify(&configuration, &proposal)?;
    if !stamp.unchanged() {
        return Err("successor proposal changed during verification".into());
    }
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
        ("check-local", []) => {
            require_validator_boundary(&configuration, &proposal.witness)?;
            verify_processing_boundary(&configuration, &previous, &next, &proposal.witness)?;
            serde_json::json!({
                "status":"successor-local-boundary-verified",
                "successor_proposal_sha256":sha256(&bytes),
            })
        }
        ("activate" | "activate-observer", []) => {
            if command == "activate" {
                require_validator_boundary(&configuration, &proposal.witness)?;
                verify_processing_boundary(&configuration, &previous, &next, &proposal.witness)?;
            }
            activate_verified(
                &configuration,
                &previous,
                &next,
                &proposal.witness,
                command == "activate-observer",
            )?
        }
        ("check-network", [registry, workspace] | [registry, workspace, _]) => {
            let mut result = check_staged_network(
                &configuration,
                &previous,
                &next,
                &proposal.witness,
                Path::new(registry),
                extra.get(2).map(Path::new),
                Path::new(workspace),
            )?;
            result["successor_proposal_sha256"] = sha256(&bytes).into();
            result
        }
        ("issue-admission", [registry, workspace, enrollment, custody, unlock, output]) => {
            return with_staged_network(
                &configuration,
                &previous,
                &next,
                &proposal.witness,
                Path::new(registry),
                Path::new(workspace),
                |staged, _| {
                    crate::services::apqe_rpc::issue(
                        staged,
                        Path::new(enrollment),
                        Path::new(custody),
                        Path::new(unlock),
                        Path::new(output),
                    )
                },
            );
        }
        ("registry", [custody, output]) => {
            return registry::issue_successor(
                config,
                custody,
                output,
                Path::new(proposal_path),
                &previous,
                &next,
            );
        }
        _ => return Err("invalid authority-successor arguments".into()),
    };
    println!("{}", crate::output::json::render(&result)?);
    Ok(())
}

#[cfg(test)]
pub(super) fn qualify_offline_successor(
    config: &NodeConfiguration,
    previous: &VerifiedAuthority,
    signed_previous: &SignedAuthorityBinding,
    keys: &[synergy_address_engine::apqe::crypto_engine::EncodedKeyPair],
    signer: &synergy_aegis::PqvmSigner,
    engine: &Arc<Mutex<synergy_address_engine::apqe::crypto_engine::CryptoEngine>>,
) {
    use synergy_address_engine::{apqe::provider::SignOptions, types::Algorithm};
    use synergy_aegis::AegisSigner;
    use synergy_posy::{block_vote_signing_bytes, BlockVote, ConsensusObjectContext};
    let mut parent = SimplifiedFinalityParent::QuorumCertificate {
        height: 19997,
        block_id: "d".repeat(64),
        qc_id: "e".repeat(64),
    };
    let mut finality = ThreeQcFinality::default();
    let mut certificates = Vec::new();
    for height in 19998..=20000 {
        let votes = keys
            .iter()
            .take(4)
            .enumerate()
            .map(|(index, key)| {
                let record = &signed_previous.payload.validators[index].record;
                let mut vote = BlockVote {
                    context: ConsensusObjectContext::for_height(&previous.epoch, height, 0)
                        .unwrap(),
                    block_id: format!("{height:064x}"),
                    parent_block_id: parent.block_id().into(),
                    parent: parent.clone(),
                    takeover_tc_id: None,
                    protected_execution_root: "f".repeat(64),
                    validator_id: record.validator_id.clone(),
                    key_id: record.consensus_key_id.clone(),
                    signature: vec![],
                };
                vote.signature = engine
                    .lock()
                    .unwrap()
                    .sign(
                        Algorithm::MlDsa65,
                        key.private_key.as_bytes(),
                        &block_vote_signing_bytes(&vote).unwrap(),
                        SignOptions::default(),
                    )
                    .unwrap();
                vote
            })
            .collect();
        let qc = SimplifiedQuorumCertificate::from_votes(votes).unwrap();
        finality.accept(qc.clone()).unwrap();
        parent = SimplifiedFinalityParent::QuorumCertificate {
            height,
            block_id: qc.block_id.clone(),
            qc_id: qc.id().unwrap(),
        };
        certificates.push(qc);
    }
    let mut candidate = signed_previous.clone();
    candidate.payload =
        successor_payload(signed_previous.payload.clone(), &certificates[2]).unwrap();
    let sign = |payload: &AuthorityPayload| {
        signer
            .sign(
                &KeyId::new(candidate.signer_key_id.clone()).unwrap(),
                &SigningContext {
                    domain: synergy_genesis::authority::AUTHORITY_SIGNING_DOMAIN.into(),
                    chain_id: config.chain_id,
                    epoch: Some(3),
                    height: None,
                },
                &payload.signing_bytes().unwrap(),
            )
            .unwrap()
            .bytes
    };
    candidate.signature = sign(&candidate.payload);
    let mut proposal = Proposal {
        version: 1,
        previous_authority_binding: previous.binding_bytes().to_vec(),
        witness: Witness {
            finalized: finality.last_finalized().unwrap().clone(),
            certificates: certificates.try_into().unwrap(),
        },
        successor_authority_binding: serde_json::to_vec(&candidate).unwrap(),
    };
    let (_, next) = verify(config, &proposal).unwrap();
    assert_eq!(
        (next.epoch.epoch_start_height, next.epoch.epoch_end_height),
        (20001, 21000)
    );
    let correct = proposal.successor_authority_binding.clone();
    candidate.payload.epoch_end_height += 1;
    candidate.signature = sign(&candidate.payload);
    proposal.successor_authority_binding = serde_json::to_vec(&candidate).unwrap();
    assert!(verify(config, &proposal)
        .err()
        .unwrap()
        .contains("1,000-block"));
    proposal.successor_authority_binding = correct;
    proposal.witness.certificates[2].participants[0].signature[0] ^= 1;
    assert!(verify(config, &proposal)
        .err()
        .unwrap()
        .contains("verify authority transition QC"));
}
