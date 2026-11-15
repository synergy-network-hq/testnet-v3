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

/// Compact public inputs for offline proof qualification. Decoding this
/// structure never activates a successor or authorizes peer membership.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DerivedEpochProof {
    authorization: EpochTransitionAuthorization,
    finalized: FinalizedBlockRecord,
    witness: synergy_posy::FinalitySyncWitness,
    closing_material: synergy_etdag::execution::CandidateProtectedMaterial,
    next_validators: Vec<ValidatorRecord>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DerivedEpochProofChain {
    version: u32,
    origin_context_root: String,
    transitions: Vec<DerivedEpochProof>,
}

struct VerifiedDerivedEpoch {
    context: SimplifiedEpochContext,
    parent: SimplifiedFinalityParent,
    registry: FrozenValidatorRegistry,
    policy: ProtectedEpochPolicy,
}

/// Read-only proof cursor. It cannot return a live authority binding, peer
/// registry or signing capability. Only a verified closure can advance it.
struct DerivedEpochVerifier<'a> {
    origin: &'a VerifiedAuthority,
    context: SimplifiedEpochContext,
    registry: FrozenValidatorRegistry,
    policy: Arc<ProtectedEpochPolicy>,
}

impl<'a> DerivedEpochVerifier<'a> {
    fn new(origin: &'a VerifiedAuthority) -> Result<Self, String> {
        Ok(Self {
            origin,
            context: origin.epoch.clone(),
            registry: origin.registry.clone(),
            policy: origin
                .protected
                .clone()
                .ok_or("previous authority lacks ETDAG policy")?,
        })
    }

    fn advance(
        &mut self,
        proof: &DerivedEpochProof,
    ) -> Result<SimplifiedFinalityParent, String> {
        let verified = verify_derived_epoch_in_scope(
            &self.context, &self.registry, &self.policy, self, proof,
        )?;
        self.context = verified.context;
        self.registry = verified.registry;
        self.policy = Arc::new(verified.policy);
        Ok(verified.parent)
    }
}

impl ConsensusSignatureVerifier for DerivedEpochVerifier<'_> {
    fn verify_consensus_signature(
        &self,
        domain: &str,
        payload: &[u8],
        validator: &ValidatorRecord,
        key_id: &str,
        epoch: u64,
        signature: &[u8],
    ) -> PosyResult<()> {
        self.origin.verify_consensus_signature_in_epoch(
            domain, payload, validator, key_id, self.context.epoch, epoch, signature,
        )
    }

    fn verify_timeout_boundary_parent(
        &self,
        successor: &SimplifiedEpochContext,
        proof: &SimplifiedQuorumCertificate,
    ) -> PosyResult<()> {
        // Closing proofs for derived 1,000-block epochs are confined to the
        // last lease. They cannot include a first-lease boundary parent.
        if self.context != self.origin.epoch || successor != &self.context {
            return Err(PosyError::invalid("closing proof references another epoch's boundary"));
        }
        self.origin.verify_timeout_boundary_parent(successor, proof)
    }
}

#[cfg(test)]
fn verify_derived_epoch(
    previous: &VerifiedAuthority,
    proof: &DerivedEpochProof,
) -> Result<(SimplifiedEpochContext, SimplifiedFinalityParent), String> {
    let mut cursor = DerivedEpochVerifier::new(previous)?;
    let parent = cursor.advance(proof)?;
    Ok((cursor.context, parent))
}

fn verify_derived_epoch_in_scope(
    previous: &SimplifiedEpochContext,
    previous_registry: &FrozenValidatorRegistry,
    policy: &ProtectedEpochPolicy,
    verifier: &impl ConsensusSignatureVerifier,
    proof: &DerivedEpochProof,
) -> Result<VerifiedDerivedEpoch, String> {
    if proof.next_validators.iter().any(|validator| !validator.may_sign_consensus()) {
        return Err("derived epoch proof includes a validator outside the active set".into());
    }
    let next_registry = FrozenValidatorRegistry::new(
        proof.authorization.next_epoch,
        proof.next_validators.clone(),
    )
    .map_err(|e| e.to_string())?;
    // Until this consumer can reconstruct an on-chain membership or policy
    // change, qualify only the unchanged governed set. A proof is not an
    // independent source of validator eligibility or consensus parameters.
    let (expected, next_policy) =
        unchanged_successor_subject(previous, previous_registry, policy)?;
    if proof.authorization != expected {
        return Err("epoch subject differs from independently derived rollover policy".into());
    }
    let subject = proof
        .closing_material
        .epoch_subject_from_commitment(
            proof.finalized.height,
            &proof.finalized.protected_execution_root,
            synergy_block::hash_block_bytes,
        )
        .map_err(|e| format!("epoch closure lacks its exact protected transition subject: {e:?}"))?;
    let (context, parent) = proof
        .authorization
        .derive_from_finalized_subject(
            previous,
            previous_registry,
            &next_registry,
            &proof.finalized,
            &proof.witness,
            subject,
            verifier,
        )
        .map_err(|e| format!("authenticate consensus-derived epoch: {e}"))?;
    Ok(VerifiedDerivedEpoch {
        context,
        parent,
        registry: next_registry,
        policy: next_policy,
    })
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

fn unchanged_successor_subject(
    previous: &SimplifiedEpochContext,
    previous_registry: &FrozenValidatorRegistry,
    policy: &ProtectedEpochPolicy,
) -> Result<(EpochTransitionAuthorization, ProtectedEpochPolicy), String> {
    let next_epoch = previous.epoch.checked_add(1).ok_or("epoch overflow")?;
    let next_policy = successor_time_policy(
        policy,
        previous.epoch_start_height,
        previous.epoch_end_height,
    )?;
    let registry =
        FrozenValidatorRegistry::new(next_epoch, previous_registry.active().cloned().collect())
            .map_err(|e| e.to_string())?;
    let subject = EpochTransitionAuthorization::for_governed_successor(
        previous,
        &registry,
        next_policy.commitment()?,
    )
    .map_err(|e| e.to_string())?;
    Ok((subject, next_policy))
}

fn successor_time_policy(
    policy: &ProtectedEpochPolicy,
    first: u64,
    last: u64,
) -> Result<ProtectedEpochPolicy, String> {
    let mut next = policy.clone();
    next.epoch_start_timestamp_ms = policy
        .timestamp_for_height_ms(first, last, last)?
        .checked_add(policy.target_block_time_ms)
        .ok_or("successor epoch clock overflow")?;
    Ok(next)
}

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
        .as_ref()
        .ok_or("predecessor lacks ETDAG policy")?;
    let next_policy =
        successor_time_policy(policy, payload.epoch_start_height, payload.epoch_end_height)?;
    payload.consensus_parameter_root = next_policy.commitment()?;
    payload.protected = Some(next_policy);
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

// A single offline execution owner, with no signer, network service, or node
// process. Input is an explicitly supplied scratch copy of a certified
// boundary (public authority, Worlds, replay inputs and validation proofs).
#[cfg(test)]
#[test]
#[ignore = "requires an authenticated Canary boundary export and scratch storage"]
fn native_terminal_replay_checks_exact_successor_on_existing_canary_evidence() {
    use crate::services::{execution, ingress::AuthenticatedIngress};
    use synergy_node_core::CancellationToken;

    let path = |key| PathBuf::from(std::env::var_os(key).expect(key));
    let config = synergy_config::load(&path("SYNERGY_TEST_TERMINAL_CONFIG")).unwrap();
    let decode = |file: &Path| fs::read(file).unwrap();
    let proposal: Proposal =
        serde_json::from_slice(&decode(&path("SYNERGY_TEST_TERMINAL_PROPOSAL"))).unwrap();
    let preceding: Witness =
        serde_json::from_slice(&decode(&path("SYNERGY_TEST_TERMINAL_PRECEDING"))).unwrap();
    let expected = &proposal.witness;
    let (previous, next) = verify(&config, &proposal).unwrap();
    let mut prior_finality = synergy_posy::ThreeQcFinality::default();
    for qc in preceding.certificates {
        qc.verify(&previous.epoch, &previous.registry, previous.as_ref())
            .unwrap();
        prior_finality.accept(qc).unwrap();
    }
    assert_eq!(prior_finality.last_finalized(), Some(&preceding.finalized));
    let layout = NodeStorageLayout::new(config.storage.data_directory.clone()).unwrap();
    let root = layout.consensus().join("posy");
    let certificates = VerifiedQuorumCertificateStore::new(&root).unwrap();
    for qc in &expected.certificates {
        certificates
            .put_verified(qc, &previous.epoch, &previous.registry, previous.as_ref())
            .unwrap();
    }
    let finality = FinalityStore::new(&root).unwrap();
    finality
        .commit_exactly_once(&expected.finalized, Some(&preceding.finalized))
        .unwrap();
    require_validator_boundary(&config, expected).unwrap();
    assert_eq!(
        verify_processing_boundary(&config, &previous, &next, expected).unwrap_err(),
        "certified terminal execution candidate is unavailable"
    );
    let ingress = AuthenticatedIngress::with_world_budget(
        synergy_state::world_resources::WorldResourceBudget::new(
            config.storage.world_memory_budget_bytes,
        ),
    );
    let (_, mut owner) = execution::registration(&config, previous.clone(), ingress.clone())
        .unwrap();
    ingress
        .submit_finality(
            expected.finalized.clone(),
            serde_json::to_vec(&expected.certificates).unwrap(),
        )
        .unwrap();
    owner.start(&CancellationToken::default()).unwrap();
    owner.poll().unwrap();
    owner.stop().unwrap();
    require_validator_boundary(&config, expected).unwrap();
    verify_processing_boundary(&config, &previous, &next, expected).unwrap();
    assert_eq!(
        finality.get(expected.finalized.height).unwrap().as_ref(),
        Some(&expected.finalized)
    );
    assert!(finality.get(expected.finalized.height + 1).unwrap().is_none());
    assert!(finality.get(expected.finalized.height + 2).unwrap().is_none());
    assert!(!root.join("sign-once.json").exists());
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
        return Err("usage: authority-successor check|activate|activate-observer CONFIG PROPOSAL; check-derived|check-derived-chain CONFIG PROOF; export-boundary CONFIG WITNESS; prepare-payload CONFIG WITNESS OUTPUT; bundle CONFIG WITNESS SIGNED_AUTHORITY OUTPUT; check-local CONFIG PROPOSAL; registry CONFIG PROPOSAL CUSTODY OUTPUT; check-network CONFIG PROPOSAL REGISTRY WORKSPACE [ADMISSION]; issue-admission CONFIG PROPOSAL REGISTRY WORKSPACE ENROLLMENT CUSTODY UNLOCK OUTPUT".into());
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
    if matches!(command.as_str(), "check-derived" | "check-derived-chain") && extra.is_empty() {
        let previous = load(&configuration)?.ok_or("missing authenticated predecessor")?;
        let bytes = apqe_transport::read(Path::new(proposal_path), 4 * 1024 * 1024, false)?;
        let mut cursor = DerivedEpochVerifier::new(&previous)?;
        let proofs = if command == "check-derived-chain" {
            let chain: DerivedEpochProofChain = serde_json::from_slice(&bytes)
                .map_err(|e| format!("decode derived epoch proof chain: {e}"))?;
            if chain.version != 1
                || chain.origin_context_root != cursor.context.root().map_err(|e| e.to_string())?
                || !(1..=16).contains(&chain.transitions.len())
            {
                return Err("invalid proof-chain version, origin or length".into());
            }
            chain.transitions
        } else {
            vec![serde_json::from_slice(&bytes)
                .map_err(|e| format!("decode derived epoch proof: {e}"))?]
        };
        let mut certified_parent = None;
        for proof in &proofs {
            certified_parent = Some(cursor.advance(proof)?);
        }
        println!("{}", serde_json::json!({
            "status": "consensus-derived-context-verified",
            "context_root": cursor.context.root().map_err(|e| e.to_string())?,
            "context": cursor.context,
            "certified_parent": certified_parent,
            "verified_transitions": proofs.len(),
            "activated": false,
        }));
        return Ok(());
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
fn signed_derived_test_proof(
    previous: &SimplifiedEpochContext,
    authorization: EpochTransitionAuthorization,
    next_validators: Vec<ValidatorRecord>,
    keys: &[synergy_address_engine::apqe::crypto_engine::EncodedKeyPair],
    engine: &Arc<Mutex<synergy_address_engine::apqe::crypto_engine::CryptoEngine>>,
) -> DerivedEpochProof {
    use synergy_address_engine::{apqe::provider::SignOptions, types::Algorithm};
    use synergy_posy::{block_vote_signing_bytes, BlockVote, ConsensusObjectContext};
    let root = synergy_etdag::EtdagDigest::from_domain_bytes("epoch-closure-test", b"namespace");
    let (closing_material, commitment) = synergy_etdag::execution::ProcessingProposalMaterial {
        material_version: 1,
        profile_id: synergy_etdag::PROCESSING_PROFILE_ID.into(),
        height: authorization.finalized_height,
        namespace_root: root.clone(),
        selection: synergy_etdag::execution::ProcessingReadyView {
            namespace_root: root.clone(),
            items: Vec::new(),
        }
        .select(21_000, 128 * 1024)
        .unwrap(),
        transition_root: root,
        ordered_group: None,
        epoch_transition_subject_root: None,
    }
    .with_epoch_close_subject(authorization.subject_root_v2().unwrap())
    .unwrap();
    let protected_root = synergy_block::hash_block_bytes(&commitment);
    let mut parent = SimplifiedFinalityParent::QuorumCertificate {
        height: authorization.finalized_height - 1,
        block_id: "d".repeat(64),
        qc_id: "e".repeat(64),
    };
    let mut finality = ThreeQcFinality::default();
    let mut certificates = Vec::new();
    for height in authorization.finalized_height..=previous.epoch_end_height {
        let votes = keys
            .iter()
            .take(4)
            .enumerate()
            .map(|(index, key)| {
                let record = &next_validators[index];
                let mut vote = BlockVote {
                    context: ConsensusObjectContext::for_height(previous, height, 0)
                        .unwrap(),
                    block_id: format!("{height:064x}"),
                    parent_block_id: parent.block_id().into(),
                    parent: parent.clone(),
                    takeover_tc_id: None,
                    protected_execution_root: if height == authorization.finalized_height {
                        protected_root.clone()
                    } else {
                        "f".repeat(64)
                    },
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
    DerivedEpochProof {
        authorization,
        finalized: finality.last_finalized().unwrap().clone(),
        witness: synergy_posy::FinalitySyncWitness {
            quorum_certificates: certificates.try_into().unwrap(),
            timeout_certificates: Vec::new(),
        },
        closing_material: closing_material.into(),
        next_validators,
    }
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
    use synergy_aegis::AegisSigner;
    // The old validator keys certify each closing subject; no successor
    // authority signature is used for this consecutive-epoch verification.
    let mut cursor = DerivedEpochVerifier::new(previous).unwrap();
    let validators = signed_previous.payload.validators.iter()
        .map(|validator| validator.record.clone())
        .collect::<Vec<_>>();
    let next_subject = |cursor: &DerivedEpochVerifier<'_>| {
        unchanged_successor_subject(&cursor.context, &cursor.registry, &cursor.policy)
            .unwrap().0
    };
    let mut derived = signed_derived_test_proof(
        &cursor.context, next_subject(&cursor), validators.clone(), keys, engine,
    );
    cursor.advance(&derived).unwrap();
    let second = signed_derived_test_proof(
        &cursor.context, next_subject(&cursor), validators, keys, engine,
    );
    assert!(verify_derived_epoch(previous, &second).is_err());
    cursor.advance(&second).unwrap();
    assert_eq!(cursor.context.epoch_start_height, 21001);
    let final_root = cursor.context.root().unwrap();
    assert!(cursor.advance(&derived).is_err());
    assert_eq!(cursor.context.root().unwrap(), final_root);

    let certificates = derived.witness.quorum_certificates.clone();
    let finalized = derived.finalized.clone();
    let (next_context, parent) = verify_derived_epoch(previous, &derived).unwrap();
    assert_ne!(next_context.consensus_parameter_root, previous.epoch.consensus_parameter_root);
    assert_eq!(next_context.finalized_epoch_seed_root, certificates[0].id().unwrap());
    assert_eq!(parent.quorum_certificate_reference().unwrap(), certificates[2].reference().unwrap());

    let closing_material = derived.closing_material.clone();
    let synergy_etdag::execution::CandidateProtectedMaterial::Processing(foreign_material) =
        &mut derived.closing_material
    else {
        panic!("derived fixture requires processing material");
    };
    foreign_material.epoch_transition_subject_root = Some("a".repeat(64));
    assert!(verify_derived_epoch(previous, &derived)
        .unwrap_err()
        .contains("protected transition subject"));
    derived.closing_material = closing_material;
    derived.next_validators[0].frozen_voting_weight += 1;
    assert!(verify_derived_epoch(previous, &derived).is_err());
    derived.next_validators[0].frozen_voting_weight -= 1;

    let saved_root = derived.authorization.next_consensus_parameter_root.clone();
    derived.authorization.next_consensus_parameter_root = previous.epoch.consensus_parameter_root.clone();
    assert!(verify_derived_epoch(previous, &derived)
        .unwrap_err()
        .contains("independently derived rollover policy"));
    derived.authorization.next_consensus_parameter_root = saved_root;

    // Change a signature without changing the QC subject/ID.
    derived.witness.quorum_certificates[2].participants[0].signature[0] ^= 1;
    assert!(verify_derived_epoch(previous, &derived).is_err());

    let mut candidate = signed_previous.clone();
    candidate.payload =
        successor_payload(signed_previous.payload.clone(), &certificates[2]).unwrap();
    assert_eq!(candidate.payload.consensus_parameter_root, next_context.consensus_parameter_root);
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
            finalized,
            certificates,
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
