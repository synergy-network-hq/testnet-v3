//! Recovery uses only actual native socket-produced QCs, candidates and ECHOs.
use super::*;
use crate::commands::checkpoint::{Action, Request};
use std::collections::BTreeSet;

use synergy_posy::persistence::{AtomicConsensusTransitionStore, FinalityStore};
use synergy_posy::{
    FinalitySyncWitness, ThreeQcFinality, VerifiedQuorumCertificateStore,
    VerifiedTimeoutCertificateStore,
};
use synergy_state::{FinalizedState, FinalizedStateStore};
use synergy_storage::NodeStorageLayout;

// Build an offline target from exact immutable proof/world facts of the fresh
// socket fixture, while all five original owners keep producing. Read only the
// atomic journal, never copy an open database or reuse this as a live backup.
fn preserve_test_anchor(
    source: &NodeConfiguration,
    target: &NodeConfiguration,
    authority: &authority::VerifiedAuthority,
    height: u64,
) -> FinalizedState {
    let original = NodeStorageLayout::new(source.storage.data_directory.clone()).unwrap();
    let saved = NodeStorageLayout::new(target.storage.data_directory.clone()).unwrap();
    let original_posy = original.consensus().join("posy");
    let saved_posy = saved.consensus().join("posy");
    fs::create_dir_all(&saved_posy).unwrap();
    fs::write(
        saved_posy.join("sign-once.json"),
        fs::read(original_posy.join("sign-once.json")).unwrap(),
    )
    .unwrap();
    let execution = FinalizedStateStore::load(original.state().join("execution")).unwrap();
    let anchor = execution.history_at(height).unwrap().unwrap();
    let world = execution.world_state_at(height).unwrap().unwrap();
    let mut target_execution = FinalizedStateStore::load(saved.state().join("execution")).unwrap();
    assert!(target_execution
        .commit_verified_snapshot(anchor.clone(), &world)
        .unwrap());

    let original_qcs = VerifiedQuorumCertificateStore::new(&original_posy).unwrap();
    let original_tcs = VerifiedTimeoutCertificateStore::new(&original_posy).unwrap();
    let original_finality = FinalityStore::new(&original_posy).unwrap();
    let saved_qcs = VerifiedQuorumCertificateStore::new(&saved_posy).unwrap();
    let saved_tcs = VerifiedTimeoutCertificateStore::new(&saved_posy).unwrap();
    let saved_atomic = AtomicConsensusTransitionStore::new(saved_posy).unwrap();
    let mut previous = None;
    for h in authority.epoch.epoch_start_height..=height {
        let qcs = [h, h + 1, h + 2].map(|index| {
            original_qcs
                .get_verified(index, &authority.epoch, &authority.registry, authority)
                .unwrap()
                .unwrap()
        });
        let witness = FinalitySyncWitness::from_verified_certificates(
            qcs,
            &original_tcs,
            &authority.epoch,
            &authority.registry,
            authority,
        )
        .unwrap();
        let mut finality = ThreeQcFinality::default();
        for qc in &witness.quorum_certificates {
            finality.accept(qc.clone()).unwrap();
        }
        let record = finality.last_finalized().unwrap();
        assert_eq!(original_finality.get(h).unwrap().as_ref(), Some(record));
        for tc in &witness.timeout_certificates {
            saved_tcs
                .put_verified(tc, &authority.epoch, &authority.registry, authority)
                .unwrap();
        }
        for qc in &witness.quorum_certificates[..2] {
            saved_qcs
                .put_verified(qc, &authority.epoch, &authority.registry, authority)
                .unwrap();
        }
        saved_atomic
            .commit_verified_qc_and_finality(
                &witness.quorum_certificates[2],
                record,
                previous.as_ref(),
                &authority.epoch,
                &authority.registry,
                authority,
            )
            .unwrap();
        previous = Some(record.clone());
    }
    assert_eq!(previous.unwrap().block_id, anchor.finalized_block_id);
    anchor
}

#[test]
#[ignore = "requires explicitly authenticated immutable APQE native artifacts"]
fn native_checkpoint_rejects_bad_proofs_resumes_interruption_and_restarts_after_pruning() {
    let provider = trusted_apqe_provider();
    let mut prepared = prepare_socket_fixture_profile_mode(
        synergy_state::WorldState::default(),
        None,
        true,
        None,
        Some(&provider),
        true,
    );
    let open = |configuration: NodeConfiguration, listeners: &FixtureListeners| {
        let capacity = configuration.storage.world_memory_budget_bytes;
        Node::open_with_wallet_budget(
            configuration,
            None,
            listeners,
            synergy_state::world_resources::WorldResourceBudget::new(capacity),
            true,
            None,
        )
    };
    for configuration in &mut prepared.configurations {
        configuration.storage.prune_finalized_history_after_blocks = Some(4);
    }
    let mut fleet = SocketFleet {
        root: prepared.root,
        nodes: prepared
            .configurations
            .iter()
            .cloned()
            .zip(&prepared.listeners)
            .map(|(configuration, listeners)| Some(open(configuration, listeners)))
            .collect(),
        ids: prepared.ids,
        listeners: prepared.listeners,
    };
    fleet.dial_mesh();
    let authenticated = authority::load(&fleet.nodes[0].as_ref().unwrap().configuration)
        .unwrap()
        .unwrap();
    let epoch = &authenticated.epoch;
    // Select a nonproposer for the eventual standalone restart, outside
    // the scheduled lease turns covered by the test proof.
    let boundary = epoch.epoch_start_height + epoch.leader_lease_blocks;
    let anchor_height = boundary - 3;
    let target_height = boundary + 3;
    let scheduled = (epoch.epoch_start_height..=target_height + 2)
        .map(|height| epoch.authorized_proposer(height, 0).unwrap())
        .collect::<BTreeSet<_>>();
    let lagging_index = fleet
        .ids
        .iter()
        .position(|id| !scheduled.contains(id.as_str()))
        .unwrap();
    fleet.advance(anchor_height);
    let original = &fleet.nodes[lagging_index].as_ref().unwrap().configuration;
    let mut target = original.clone();
    target.storage.data_directory = fleet.root.join("offline-checkpoint-target");
    let anchor = preserve_test_anchor(original, &target, &authenticated, anchor_height);
    let target_layout = NodeStorageLayout::new(target.storage.data_directory.clone()).unwrap();
    fleet.advance(target_height);
    let source = fleet
        .nodes
        .iter()
        .flatten()
        .next()
        .unwrap()
        .configuration
        .clone();
    let mut restart_configs = fleet
        .nodes
        .iter()
        .map(|node| node.as_ref().unwrap().configuration.clone())
        .collect::<Vec<_>>();
    for node in &mut fleet.nodes {
        if let Some(mut node) = node.take() {
            node.stop();
        }
    }
    let source_layout =
        synergy_storage::NodeStorageLayout::new(source.storage.data_directory.clone()).unwrap();
    let source_candidates =
        synergy_execution::CandidateStore::new(source_layout.blocks().join("execution-candidates"))
            .unwrap();
    assert!(
        source_candidates
            .get(anchor.finalized_height + 1)
            .unwrap()
            .is_none(),
        "test must exercise a genuine retired replay gap"
    );
    drop(source_candidates);
    let bundle = fleet.root.join("checkpoint-transfer");
    let export = Request {
        action: Action::Export,
        config: fleet.root.join("unused-fixture-config"),
        bundle: bundle.clone(),
        from: Some((anchor.finalized_height, anchor.finalized_block_id.clone())),
    };
    let exported = super::super::checkpoint::fixture_run(&export, &source, None).unwrap();
    let head = exported["checkpoint_height"].as_u64().unwrap();
    assert!(head >= target_height);
    assert!(exported["pages"].as_u64().unwrap() >= 2);
    let import = Request {
        action: Action::Import,
        from: None,
        ..export
    };
    let manifest_path = bundle.join("manifest.json");
    let original_manifest = fs::read(&manifest_path).unwrap();
    let original_prefix = fs::read(bundle.join("prefix.bin")).unwrap();
    let first_len = u64::from_le_bytes(original_prefix[..8].try_into().unwrap()) as usize;
    let first: serde_json::Value =
        serde_json::from_slice(&original_prefix[8..8 + first_len]).unwrap();
    assert_eq!(first["first_height"], anchor_height);
    assert_eq!(first["apply_through"], boundary - 1);
    let journal = target_layout.consensus().join("posy/sign-once.json");
    let before = fs::read(&journal).unwrap();
    let unchanged = || {
        assert_eq!(fs::read(&journal).unwrap(), before);
        assert_eq!(
            synergy_state::FinalizedStateStore::load(target_layout.state().join("execution"))
                .unwrap()
                .current()
                .unwrap(),
            &anchor
        );
        assert!(synergy_posy::persistence::FinalityStore::new(
            target_layout.consensus().join("posy")
        )
        .unwrap()
        .get(head)
        .unwrap()
        .is_none());
    };
    // An unsigned manifest cannot select another network or escape its folder.
    let mut manifest: serde_json::Value = serde_json::from_slice(&original_manifest).unwrap();
    manifest["network_id"] = serde_json::json!("untrusted-other-network");
    write_json(&manifest_path, &manifest);
    assert!(
        super::super::checkpoint::fixture_run(&import, &target, None)
            .unwrap_err()
            .contains("scope")
    );
    unchanged();
    manifest = serde_json::from_slice(&original_manifest).unwrap();
    manifest["files"]["../outside"] = serde_json::json!("0".repeat(64));
    write_json(&manifest_path, &manifest);
    assert!(super::super::checkpoint::fixture_run(&import, &target, None).is_err());
    unchanged();
    fs::write(&manifest_path, &original_manifest).unwrap();
    // Corrupt a later lease page: the earlier valid pages MUST NOT commit.
    let mut corrupt = original_prefix.clone();
    let offset = corrupt.len() - 2;
    corrupt[offset] ^= 1;
    fs::write(bundle.join("prefix.bin"), corrupt).unwrap();
    assert!(super::super::checkpoint::fixture_run(&import, &target, None).is_err());
    unchanged();
    fs::write(bundle.join("prefix.bin"), &original_prefix).unwrap();
    // Remove a certified height and update the outer hash chain. Native prefix
    // validation, rather than merely an unsigned file hash, must reject it.
    let mut rebuilt = Vec::new();
    let mut offset = 0;
    let mut index = 0;
    let mut chain = synergy_block::hash_block_bytes(b"SYNERGY-OFFLINE-CHECKPOINT-PREFIX-V2");
    while offset < original_prefix.len() {
        let length =
            u64::from_le_bytes(original_prefix[offset..offset + 8].try_into().unwrap()) as usize;
        let mut page: serde_json::Value =
            serde_json::from_slice(&original_prefix[offset + 8..offset + 8 + length]).unwrap();
        if index == 0 {
            page["certificates"].as_array_mut().unwrap().remove(1);
        }
        let bytes = serde_json::to_vec(&page).unwrap();
        rebuilt.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
        rebuilt.extend_from_slice(&bytes);
        let hash = synergy_block::hash_block_bytes(&bytes);
        chain = synergy_block::hash_block_bytes(format!("{chain}{hash}").as_bytes());
        offset += 8 + length;
        index += 1;
    }
    manifest = serde_json::from_slice(&original_manifest).unwrap();
    manifest["prefix_chain"] = serde_json::json!(chain);
    write_json(&manifest_path, &manifest);
    fs::write(bundle.join("prefix.bin"), rebuilt).unwrap();
    assert!(super::super::checkpoint::fixture_run(&import, &target, None).is_err());
    unchanged();
    fs::write(&manifest_path, &original_manifest).unwrap();
    fs::write(bundle.join("prefix.bin"), &original_prefix).unwrap();
    // Rehash a corrupted native ECHO, so rejection exercises the governed
    // signature verifier rather than the unsigned bundle integrity layer.
    let replay_path = bundle.join("processing-replay.json");
    let original_replay = fs::read(&replay_path).unwrap();
    let mut replay: serde_json::Value = serde_json::from_slice(&original_replay).unwrap();
    let signature = &mut replay[2]["echoes"][0]["signature"][0];
    *signature = serde_json::json!(signature.as_u64().unwrap() ^ 1);
    let bad_replay = serde_json::to_vec(&replay).unwrap();
    manifest = serde_json::from_slice(&original_manifest).unwrap();
    manifest["files"]["processing-replay.json"] =
        serde_json::json!(synergy_block::hash_block_bytes(&bad_replay));
    write_json(&manifest_path, &manifest);
    fs::write(&replay_path, bad_replay).unwrap();
    assert!(super::super::checkpoint::fixture_run(&import, &target, None).is_err());
    unchanged();
    fs::write(&manifest_path, &original_manifest).unwrap();
    fs::write(&replay_path, original_replay).unwrap();
    // Simulate interruption at each durable recovery boundary, then retry the
    // same bundle. Consensus may lead Execution; a world never lacks its parent.
    for stage in ["consensus", "candidate", "world"] {
        assert!(
            super::super::checkpoint::fixture_run(&import, &target, Some(stage))
                .unwrap_err()
                .contains(stage)
        );
        assert_eq!(
            fs::read(&journal).unwrap(),
            before,
            "journal must not advance before completed checkpoint"
        );
    }
    let report = super::super::checkpoint::fixture_run(&import, &target, None).unwrap();
    assert_eq!(report["checkpoint_height"], head);
    assert_eq!(
        synergy_posy::SignOnceJournal::load(&journal)
            .unwrap()
            .finalized_floor(),
        head
    );
    super::super::checkpoint::fixture_run(&import, &target, None).unwrap(); // exact idempotent replay
    let started = Instant::now();
    restart_configs[lagging_index] = target;
    fleet.nodes = restart_configs
        .into_iter()
        .zip(&fleet.listeners)
        .map(|(configuration, listeners)| Some(open(configuration, listeners)))
        .collect();
    let recovered = fleet.nodes[lagging_index].as_ref().unwrap();
    let restored = recovered.ingress.latest_finality().unwrap().unwrap();
    assert_eq!(restored.height, head);
    assert_eq!(restored.block_id, report["block_id"].as_str().unwrap());
    eprintln!(
        "native checkpoint restart restored H{head} in {:?}",
        started.elapsed()
    );
    fleet.dial_mesh();
    fleet.advance(head + 1);
    let recovered = fleet.nodes[lagging_index].as_ref().unwrap();
    assert_eq!(recovered.ingress.authenticated_peers().unwrap().len(), 4);
    assert!(
        synergy_posy::SignOnceJournal::load(&journal)
            .unwrap()
            .finalized_floor()
            > head
    );
}

/// Uses the already authenticated native first-use wallet fixture, with an
/// actual authorization-changing transaction at H5 and native QCs through H8.
pub(super) fn qualify_authorization_bundle(
    prepared: &PreparedSocketFixture,
    authority: &Arc<authority::VerifiedAuthority>,
    candidates: [&synergy_execution::BudgetedExecutionCandidate; 3],
    chain: [&synergy_posy::SimplifiedQuorumCertificate; 8],
    validation: &synergy_posy::ProposalValidationCertificate,
) {
    use super::super::processing_proposals::{ProcessingProposalInputs, ProcessingProposalStore};
    use synergy_execution::CandidateStore;
    use synergy_posy::SignOnceJournal;

    let budget = &synergy_state::world_resources::WorldResourceBudget::new(512 * 1024 * 1024);
    let cases = candidates.map(|candidate| {
        let wire = serde_json::to_vec(candidate).unwrap();
        synergy_execution::decode_budgeted_candidate(&wire, budget).unwrap()
    });
    let [anchor, dependency, head] = &cases;
    let commitment = |candidate: &synergy_execution::BudgetedExecutionCandidate| FinalizedState {
        finalized_height: candidate.height,
        finalized_block_id: candidate.block_id.clone(),
        state_root: candidate.state_root.clone(),
    };
    let install_fixture =
        |index: usize, label: &str, tip: &synergy_execution::BudgetedExecutionCandidate| {
            let mut config = prepared.configurations[index].clone();
            config.storage.data_directory = prepared.root.join(label);
            config.storage.world_memory_budget_bytes = budget.limit();
            let layout = NodeStorageLayout::new(config.storage.data_directory.clone()).unwrap();
            let root = layout.consensus().join("posy");
            let qcs = VerifiedQuorumCertificateStore::new(&root).unwrap();
            let atomic = AtomicConsensusTransitionStore::new(&root).unwrap();
            let mut proof = ThreeQcFinality::default();
            for qc in chain.iter().copied().take(tip.height as usize + 2) {
                let previous = proof.last_finalized().cloned();
                if let Some(record) = proof.accept(qc.clone()).unwrap() {
                    atomic
                        .commit_verified_qc_and_finality(
                            qc,
                            &record,
                            previous.as_ref(),
                            &authority.epoch,
                            &authority.registry,
                            authority.as_ref(),
                        )
                        .unwrap();
                } else {
                    qcs.put_verified(
                        qc,
                        &authority.epoch,
                        &authority.registry,
                        authority.as_ref(),
                    )
                    .unwrap();
                }
            }
            assert_eq!(proof.last_finalized().unwrap().block_id, tip.block_id);
            SignOnceJournal::load(root.join("sign-once.json"))
                .unwrap()
                .advance_finalized_floor(tip.height)
                .unwrap();
            FinalizedStateStore::load_budgeted(layout.state().join("execution"), budget.clone())
                .unwrap()
                .commit_verified_snapshot(commitment(tip), &tip.state)
                .unwrap();
            CandidateStore::new_budgeted(
                layout.blocks().join("execution-candidates"),
                budget.clone(),
            )
            .unwrap()
            .put_budgeted(tip, &tip.state)
            .unwrap();
            (config, layout)
        };
    let (provider, provider_layout) = install_fixture(0, "dependency-provider", head);
    let head_qc = chain[(head.height - 1) as usize];
    let namespace =
        super::super::processing_pipeline::processing_namespace(authority, budget).unwrap();
    let input = ProcessingProposalInputs {
        context: head_qc.context.clone(),
        parent: head_qc.parent.clone(),
        takeover_id: head_qc.takeover_tc_id.clone(),
        block_id: head.block_id.clone(),
        state_root: head.state_root.clone(),
        protected_execution_root: head.protected_execution_root.clone(),
        ordered_group: None,
        publications: Vec::new(),
        certified_ancestors: Vec::new(),
    };
    ProcessingProposalStore::open(
        &provider_layout
            .blocks()
            .join("processing-proposal-inputs-v1"),
        namespace,
        budget,
        authority.clone(),
    )
    .unwrap()
    .import_checkpoint(
        &serde_json::to_vec(&(1u32, input, validation)).unwrap(),
        head,
        head_qc,
    )
    .unwrap();
    use super::super::checkpoint::fixture_run as run;
    for (index, start) in [(1, anchor), (2, dependency)] {
        let (target, layout) = install_fixture(index, &format!("dependency-target-{index}"), start);
        let export = Request {
            action: Action::Export,
            config: prepared.root.join("unused-test-config"),
            bundle: prepared.root.join(format!("dependency-bundle-{index}")),
            from: Some((start.height, start.block_id.clone())),
        };
        if index == 1 {
            assert!(run(&export, &provider, None)
                .unwrap_err()
                .contains("missing required authorization source"));
            assert!(!export.bundle.exists());
            CandidateStore::new_budgeted(
                provider_layout.blocks().join("execution-candidates"),
                budget.clone(),
            )
            .unwrap()
            .pin_budgeted(dependency)
            .unwrap();
        }
        assert_eq!(
            run(&export, &provider, None).unwrap()["checkpoint_height"],
            head.height
        );
        let import = Request {
            action: Action::Import,
            from: None,
            ..export
        };
        let source_path = import.bundle.join("authorization-source.json");
        let source_bytes = fs::read(&source_path).unwrap();
        let manifest_path = import.bundle.join("manifest.json");
        let original_manifest = fs::read(&manifest_path).unwrap();
        let journal = layout.consensus().join("posy/sign-once.json");
        let old_journal = fs::read(&journal).unwrap();
        let state_path = layout.state().join("execution");
        let assert_untouched = || {
            assert_eq!(fs::read(&journal).unwrap(), old_journal);
            assert_eq!(
                FinalizedStateStore::load(&state_path).unwrap().current(),
                Some(&commitment(start))
            );
            assert!(FinalityStore::new(layout.consensus().join("posy"))
                .unwrap()
                .get(head.height)
                .unwrap()
                .is_none());
        };
        fs::remove_file(&source_path).unwrap();
        assert!(run(&import, &target, None).is_err());
        assert_untouched();
        let mut corrupted = source_bytes.clone();
        corrupted[0] ^= 1;
        fs::write(&source_path, corrupted).unwrap();
        assert!(run(&import, &target, None)
            .unwrap_err()
            .contains("hash mismatch"));
        assert_untouched();
        let mut manifest: serde_json::Value = serde_json::from_slice(&original_manifest).unwrap();
        write_json(&source_path, head);
        // Rehash the wrong candidate's exact bytes so cryptographic/scope
        // checking, rather than the unsigned catalog hash, must reject it.
        manifest["files"]["authorization-source.json"] =
            synergy_block::hash_block_bytes(&fs::read(&source_path).unwrap()).into();
        write_json(&manifest_path, &manifest);
        assert!(run(&import, &target, None).is_err());
        assert_untouched();
        fs::write(&source_path, &source_bytes).unwrap();
        fs::write(&manifest_path, &original_manifest).unwrap();
        for stage in ["consensus", "candidate", "world"] {
            assert!(run(&import, &target, Some(stage))
                .unwrap_err()
                .contains(stage));
            assert_eq!(fs::read(&journal).unwrap(), old_journal);
        }
        let imported = run(&import, &target, None).unwrap();
        assert_eq!(imported["authorization_source_height"], dependency.height);
        assert_eq!(run(&import, &target, None).unwrap(), imported);
        let state = FinalizedStateStore::load(&state_path).unwrap();
        assert_eq!(state.current(), Some(&commitment(head)));
        assert_eq!(
            state.history_at(dependency.height).unwrap(),
            Some(commitment(dependency))
        );
        let candidates = CandidateStore::new_budgeted(
            layout.blocks().join("execution-candidates"),
            budget.clone(),
        )
        .unwrap();
        assert_eq!(
            candidates.get_budgeted(dependency.height).unwrap().as_ref(),
            Some(dependency)
        );
        assert_eq!(candidates.pinned_descriptors().len(), 1);
        assert_eq!(
            SignOnceJournal::load(&journal).unwrap().finalized_floor(),
            head.height
        );
    }
}
