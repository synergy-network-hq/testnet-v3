//! Qualification of the real PoSy service, PQC verification, and durable
//! journals. Execution material is a deterministic fixture: this test does
//! not qualify ETDAG, socket transport, or a deployed chain.
use super::*;
use aegis_pqvm::pqc::signatures::mldsa::mldsa65;
use pqrust_traits::sign::{PublicKey as _, SecretKey as _};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use synergy_posy::{ValidatorRecord, ValidatorStatus};
use synergy_protocol_types::SessionId;

#[path = "posy_storage_qualification.rs"]
mod storage_growth;

pub(in crate::services) struct Fleet {
    pub(in crate::services) root: PathBuf,
    pub(in crate::services) authority: Arc<VerifiedAuthority>,
    pub(in crate::services) secrets: Vec<Vec<u8>>,
    nodes: Vec<PosyService>,
    dropped_votes: BTreeSet<(usize, usize, u64)>,
}

impl Drop for Fleet {
    fn drop(&mut self) {
        for secret in &mut self.secrets {
            secret.fill(0);
        }
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

impl Fleet {
    pub(in crate::services) fn new() -> Self {
        static NEXT_FLEET: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "posy-real-service-{}-{}-{}",
            std::process::id(),
            NEXT_FLEET.fetch_add(1, Ordering::Relaxed),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        let mut entries = Vec::new();
        let mut secrets = Vec::new();
        for index in 0..5 {
            let (public, secret) = mldsa65::keypair();
            entries.push((
                ValidatorRecord {
                    validator_id: format!("qualification-{index}"),
                    consensus_key_id: format!("key-{index}"),
                    frozen_voting_weight: 1,
                    status: ValidatorStatus::Active,
                },
                public.as_bytes().to_vec(),
            ));
            secrets.push(secret.as_bytes().to_vec());
        }
        let authority = authority::qualification_authority(entries);
        let mut fleet = Self {
            root,
            authority,
            secrets,
            nodes: Vec::new(),
            dropped_votes: BTreeSet::new(),
        };
        for i in 0..5 {
            let node = fleet.make_node(i);
            fleet.nodes.push(node);
        }
        fleet
    }

    fn make_node(&self, index: usize) -> PosyService {
        let root = self.root.join(format!("node-{index}"));
        let key_id = KeyId::new(format!("key-{index}")).unwrap();
        let signer = LocalConsensusSigner {
            validator_id: format!("qualification-{index}"),
            key_id: key_id.clone(),
            signer: Arc::new(
                PqvmSigner::from_secret_key_bytes(
                    AegisPolicy {
                        allowed_algorithms: vec![SignatureAlgorithm::MlDsa65],
                        maximum_message_bytes: 1024 * 1024,
                        maximum_signature_bytes: 16 * 1024,
                    },
                    key_id,
                    self.secrets[index].clone(),
                )
                .unwrap(),
            ),
            chain_id: 1266,
            epoch: 1,
        };
        let mut machine = SimplifiedConsensusStateMachine::new(
            self.authority.epoch.clone(),
            self.authority.registry.clone(),
            self.authority.anchor_parent.clone(),
        )
        .unwrap();
        let certificates = VerifiedQuorumCertificateStore::new(&root).unwrap();
        let timeouts = VerifiedTimeoutCertificateStore::new(&root).unwrap();
        let finality = FinalityStore::new(&root).unwrap();
        let last_finalized = replay_verified_safety_state(
            &mut machine,
            &self.authority,
            &certificates,
            &timeouts,
            &finality,
        )
        .unwrap();
        let ingress = AuthenticatedIngress::default();
        for peer in 0..5 {
            if peer != index {
                ingress
                    .admit_session(format!("qualification-{peer}"), SessionId(peer as u64 + 1))
                    .unwrap();
            }
        }
        let mut delivery = ProposalDelivery::open(
            &root,
            &self.authority.epoch,
            &self.authority.registry,
            self.authority.as_ref(),
        )
        .unwrap();
        delivery.activate(machine.active_slot()).unwrap();
        let journal = SignOnceJournal::load(root.join("sign-once.json")).unwrap();
        let last_voted_candidate = journal
            .recover_last_block_vote(machine.active_slot().0)
            .unwrap()
            .map(|vote| {
                validate_block_vote(
                    &vote,
                    &self.authority.epoch,
                    &self.authority.registry,
                    self.authority.as_ref(),
                )
                .unwrap();
                synergy_posy::CertifiedCandidateSubject::new(
                    vote.context,
                    vote.block_id,
                    vote.parent_block_id,
                    vote.parent,
                    vote.protected_execution_root,
                )
                .unwrap()
            });
        for height in machine.active_slot().0.saturating_sub(8)..=machine.active_slot().0 {
            if let Some(certificate) = delivery
                .stored_validation(
                    height,
                    &self.authority.epoch,
                    &self.authority.registry,
                    self.authority.as_ref(),
                )
                .unwrap()
            {
                ingress.submit_proposal_validation(certificate).unwrap();
            }
        }
        PosyService {
            preparation: None,
            mode: ConsensusMode::ValidateAndVote,
            authority_binding: root.join("unused-test-binding"),
            authority: self.authority.clone(),
            driver: SimplifiedPosyDriver::new(machine),
            recovery: Some(PosyRecoveryJournal::load(root.join("recovery.json")).unwrap()),
            finality: Some(finality),
            certificates,
            timeout_certificates: timeouts,
            atomic_transitions: AtomicConsensusTransitionStore::new(&root).unwrap(),
            local_signer: Some(DurableSigningAuthority::new(journal, signer)),
            last_finalized,
            candidates: BTreeMap::new(),
            processing_candidate_rounds: BTreeMap::new(),
            delivery,
            delivery_proposal: None,
            delivery_validation_retry: false,
            pending_proposals: BTreeMap::new(),
            deferred_qcs: BTreeMap::new(),
            deferred_sync: BTreeMap::new(),
            pending_verified_sync: None,
            metrics: PosyMetrics::default(),
            emitted_slots: BTreeSet::new(),
            retry_frames: BTreeMap::new(),
            historical_timeouts: HistoricalTimeoutRetry::default(),
            retry_at: Instant::now(),
            retry_cursor: 0,
            last_voted_candidate,
            ingress,
            round_timeout: Duration::from_secs(5),
            round_deadline: Instant::now() + Duration::from_secs(5),
            started: true,
            failure: None,
        }
    }

    fn provide_material(&mut self) {
        self.provide_material_except(None);
    }

    fn provide_material_except(&mut self, excluded: Option<usize>) {
        self.provide_material_with_root(excluded, None);
    }

    fn provide_material_with_root(
        &mut self,
        excluded: Option<usize>,
        supplied: Option<&synergy_etdag::execution::ProtectedProposalMaterial>,
    ) {
        for (index, node) in self.nodes.iter_mut().enumerate() {
            if excluded == Some(index) {
                continue;
            }
            let height = node.driver.state_machine().active_slot().0;
            let state = synergy_state::WorldState::default();
            let fixture_root = |label: &str| {
                synergy_etdag::EtdagDigest::from_domain_bytes(
                    "qualification-material",
                    format!("{label}:{height}").as_bytes(),
                )
            };
            let material = supplied
                .filter(|material| material.height == height)
                .cloned()
                .unwrap_or(synergy_etdag::execution::ProtectedProposalMaterial {
                    material_version: 2,
                    height,
                    execution_root: fixture_root("execution"),
                    next_batch_root: fixture_root("next-batch"),
                    cutoff_boundary_root: fixture_root("cutoff-boundary"),
                });
            let mut candidate = ExecutionCandidate {
                resource_permit: None,
                height,
                block_id: String::new(),
                parent_block_id: node
                    .driver
                    .state_machine()
                    .highest_parent()
                    .block_id()
                    .into(),
                protected_execution_root: synergy_block::hash_block_bytes(
                    &material.commitment_bytes().unwrap(),
                ),
                protected_material: material.into(),
                state_root: synergy_state::state_root(&state).unwrap(),
                transactions: Vec::new(),
                receipts: Vec::new(),
                state: std::sync::Arc::new(
                    synergy_state::world_resources::BudgetedWorld::try_clone_world(
                        &state,
                        node.ingress.world_budget(),
                    )
                    .unwrap(),
                ),
            };
            candidate.block_id = candidate.commitment_id().unwrap();
            candidate.validate().unwrap();
            let candidate = Arc::new(candidate);
            node.ingress.submit_execution_candidate(candidate).unwrap();
            node.collect_candidates().unwrap();
        }
    }

    pub(in crate::services) fn validate_protected_parent(
        &mut self,
        material: &synergy_etdag::execution::ProtectedProposalMaterial,
    ) -> synergy_posy::ProposalValidationCertificate {
        for height in 1..=material.height {
            if self
                .nodes
                .iter()
                .all(|node| node.driver.state_machine().active_slot().0 > height)
            {
                continue;
            }
            for _ in 0..30 {
                self.provide_material_with_root(None, Some(material));
                self.drain(false, None);
                self.retry();
                self.drain(false, None);
                if self
                    .nodes
                    .iter()
                    .all(|node| node.driver.state_machine().active_slot().0 > height)
                {
                    break;
                }
            }
        }
        self.nodes[0]
            .ingress
            .proposal_validation(material.height)
            .unwrap()
            .unwrap()
    }

    pub(in crate::services) fn qualification_ingress(&self) -> AuthenticatedIngress {
        self.nodes[0].ingress.clone()
    }

    pub(in crate::services) fn restore_registration_validation(
        &self,
        ingress: &AuthenticatedIngress,
    ) {
        let delivery = ProposalDelivery::open(
            &self.root.join("node-0"),
            &self.authority.epoch,
            &self.authority.registry,
            self.authority.as_ref(),
        )
        .unwrap();
        republish_verified_validation_history(
            &delivery,
            self.nodes[0].driver.state_machine().active_slot().0,
            self.authority.as_ref(),
            ingress,
        )
        .unwrap();
    }

    fn drain(&mut self, drop_first_votes: bool, isolated: Option<usize>) {
        let mut messages = Vec::new();
        for (sender, node) in self.nodes.iter().enumerate() {
            while let Some(frame) = node.ingress.take_outbound().unwrap() {
                let receiver: usize = frame
                    .peer_id
                    .strip_prefix("qualification-")
                    .unwrap()
                    .parse()
                    .unwrap();
                if isolated == Some(sender) || isolated == Some(receiver) {
                    continue;
                }
                let event: ConsensusEvent = serde_json::from_slice(&frame.payload).unwrap();
                if let ConsensusEvent::BlockVote(vote) = &event {
                    if drop_first_votes
                        && self
                            .dropped_votes
                            .insert((sender, receiver, vote.context.height))
                    {
                        continue;
                    }
                }
                messages.push((receiver, event));
            }
        }
        // Reverse delivery creates votes-before-proposal and old-vote-after-QC cases.
        for (receiver, event) in messages.into_iter().rev() {
            self.nodes[receiver].apply_event_from(event, true).unwrap();
        }
        // Model the execution consumer draining finalized notifications.
        for node in &self.nodes {
            while node.ingress.take_finality().unwrap().is_some() {}
        }
    }

    fn retry(&mut self) {
        for node in &mut self.nodes {
            node.retry_at = Instant::now();
            node.retry_delivery().unwrap();
        }
    }

    fn assert_same_finality(&self, minimum: u64) {
        let first = self.nodes[0].last_finalized.as_ref().unwrap();
        assert!(
            first.height >= minimum,
            "finality stalled at {}",
            first.height
        );
        for node in &self.nodes {
            assert_eq!(node.last_finalized.as_ref().unwrap(), first);
        }
    }
}

#[test]
#[ignore = "requires authenticated native APQE provider fixtures"]
fn verified_sync_delivery_retains_exact_candidate_under_execution_backpressure() {
    let (root, configuration) =
        super::super::socket_qualification::sync_poll_native_test_configuration();
    struct Cleanup(PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    let _cleanup = Cleanup(root);
    let authority = authority::load(&configuration).unwrap().unwrap();
    let layout = NodeStorageLayout::new(configuration.storage.data_directory.clone()).unwrap();
    let root = layout.consensus().join("posy");
    let machine = SimplifiedConsensusStateMachine::new(
        authority.epoch.clone(),
        authority.registry.clone(),
        authority.anchor_parent.clone(),
    )
    .unwrap();
    let delivery = ProposalDelivery::open(
        &root,
        &authority.epoch,
        &authority.registry,
        authority.as_ref(),
    )
    .unwrap();
    // A real native-authority observer needs no signing key to deliver an
    // already verified candidate. No embedded verifier/signer is constructed.
    let mut node = PosyService {
        preparation: None,
        mode: ConsensusMode::Observe,
        authority_binding: configuration.consensus.authority_binding.clone().unwrap(),
        authority,
        driver: SimplifiedPosyDriver::new(machine),
        recovery: Some(PosyRecoveryJournal::load(root.join("recovery.json")).unwrap()),
        finality: Some(FinalityStore::new(&root).unwrap()),
        certificates: VerifiedQuorumCertificateStore::new(&root).unwrap(),
        atomic_transitions: AtomicConsensusTransitionStore::new(&root).unwrap(),
        timeout_certificates: VerifiedTimeoutCertificateStore::new(&root).unwrap(),
        local_signer: None,
        last_finalized: None,
        candidates: BTreeMap::new(),
        processing_candidate_rounds: BTreeMap::new(),
        pending_proposals: BTreeMap::new(),
        deferred_qcs: BTreeMap::new(),
        deferred_sync: BTreeMap::new(),
        pending_verified_sync: None,
        delivery,
        delivery_proposal: None,
        delivery_validation_retry: false,
        metrics: PosyMetrics::default(),
        emitted_slots: BTreeSet::new(),
        retry_frames: BTreeMap::new(),
        historical_timeouts: HistoricalTimeoutRetry::default(),
        retry_at: Instant::now(),
        retry_cursor: 0,
        last_voted_candidate: None,
        ingress: AuthenticatedIngress::default(),
        round_timeout: Duration::from_secs(30),
        round_deadline: Instant::now() + Duration::from_secs(30),
        started: true,
        failure: None,
    };
    let world = synergy_state::WorldState::default();
    let world = Arc::new(
        synergy_state::world_resources::BudgetedWorld::try_clone_world(
            &world,
            node.ingress.world_budget(),
        )
        .unwrap(),
    );
    let candidate = |height| {
        let root = |label: &str| {
            synergy_etdag::EtdagDigest::from_domain_bytes(
                "handoff-native-fixture",
                label.as_bytes(),
            )
        };
        let material = synergy_etdag::execution::ProtectedProposalMaterial {
            material_version: 2,
            height,
            execution_root: root("execution"),
            next_batch_root: root("batch"),
            cutoff_boundary_root: root("cutoff"),
        };
        let mut candidate = ExecutionCandidate {
            resource_permit: None,
            height,
            block_id: String::new(),
            parent_block_id: "a".repeat(64),
            protected_execution_root: synergy_block::hash_block_bytes(
                &material.commitment_bytes().unwrap(),
            ),
            protected_material: material.into(),
            state_root: synergy_state::state_root(&world).unwrap(),
            transactions: Vec::new(),
            receipts: Vec::new(),
            state: Arc::clone(&world),
        };
        candidate.block_id = candidate.commitment_id().unwrap();
        let record = FinalizedBlockRecord {
            height,
            block_id: candidate.block_id.clone(),
            protected_execution_root: candidate.protected_execution_root.clone(),
            finality_certificate_id: format!("{height:064x}"),
        };
        (Arc::new(candidate), record)
    };
    // Exercise the real PoSy producer boundary, not cryptographic admission.
    // The separate native integration test verifies authenticated replay inputs.
    for height in 1..=63 {
        let (candidate, record) = candidate(height);
        node.deliver_verified_sync_candidate(candidate, record)
            .unwrap();
        assert!(node.pending_verified_sync.is_none());
    }
    let (retained, record) = candidate(64);
    node.deliver_verified_sync_candidate(Arc::clone(&retained), record.clone())
        .unwrap();
    for _ in 0..3 {
        assert!(!node.flush_verified_sync_delivery().unwrap());
        let pending = node.pending_verified_sync.as_ref().unwrap();
        assert!(Arc::ptr_eq(&pending.0, &retained));
        assert_eq!(pending.1, record);
        node.admit_sync_candidates().unwrap();
        node.drain_deferred_sync().unwrap();
    }
    node.ingress
        .take_verified_sync_candidate()
        .unwrap()
        .unwrap();
    assert!(node.flush_verified_sync_delivery().unwrap());
    assert!(node.pending_verified_sync.is_none());
    let mut last = None;
    while let Some(item) = node.ingress.take_verified_sync_candidate().unwrap() {
        last = Some(item);
    }
    let last = last.unwrap();
    assert!(Arc::ptr_eq(&last.0, &retained));
    assert_eq!(last.1, record);
}

#[test]
fn five_real_signers_recover_dropped_votes_reordering_and_durable_restart() {
    let mut fleet = Fleet::new();
    for height in 1..=30 {
        for _step in 0..30 {
            fleet.provide_material();
            fleet.drain(true, None);
            fleet.retry();
            fleet.drain(true, None);
            if fleet
                .nodes
                .iter()
                .all(|n| n.driver.state_machine().active_slot().0 > height)
            {
                break;
            }
        }
        assert!(
            fleet
                .nodes
                .iter()
                .all(|n| n.driver.state_machine().active_slot().0 > height),
            "stalled at {height}"
        );
        if height == 15 {
            fleet.nodes[2] = fleet.make_node(2);
        }
    }
    // Let lagging notification delivery settle without producing new heights.
    for _ in 0..5 {
        fleet.retry();
        fleet.drain(false, None);
    }
    fleet.assert_same_finality(28);
    assert!(fleet.nodes.iter().all(|node| node.retry_frames.len() <= 19));
}

#[test]
fn missing_proposer_times_out_with_four_signers_and_rejoins_after_partition() {
    let mut fleet = Fleet::new();
    let missing: usize = fleet
        .authority
        .epoch
        .authorized_proposer(1, 0)
        .unwrap()
        .strip_prefix("qualification-")
        .unwrap()
        .parse()
        .unwrap();
    // The absent proposer sends neither a proposal nor a timeout report.
    for (index, node) in fleet.nodes.iter_mut().enumerate() {
        if index != missing {
            node.round_deadline = Instant::now();
            node.emit_timeout_vote().unwrap();
        }
    }
    for _ in 0..8 {
        fleet.drain(false, Some(missing));
        fleet.retry();
    }
    for (index, node) in fleet.nodes.iter().enumerate() {
        if index != missing {
            assert_eq!(node.driver.state_machine().active_slot(), (1, 1));
        }
    }
    // Heal before leaving H1; the retained verified TC must bring the isolated
    // node into the same round without deleting any safety state.
    for _ in 0..8 {
        fleet.retry();
        fleet.drain(false, None);
    }
    assert!(fleet
        .nodes
        .iter()
        .all(|n| n.driver.state_machine().active_slot() == (1, 1)));
    for height in 1..=12 {
        for _ in 0..30 {
            fleet.provide_material();
            fleet.drain(false, None);
            fleet.retry();
            fleet.drain(false, None);
            if fleet
                .nodes
                .iter()
                .all(|n| n.driver.state_machine().active_slot().0 > height)
            {
                break;
            }
        }
        assert!(
            fleet
                .nodes
                .iter()
                .all(|n| n.driver.state_machine().active_slot().0 > height),
            "stalled at {height}"
        );
    }
    fleet.assert_same_finality(10);
    let node = &mut fleet.nodes[0];
    node.prune_retry_frames().unwrap();
    assert!(node.retry_frames.keys().all(|slot| slot.2 != 4));
    assert!(node.ingress.verified_peer_heights().unwrap().is_empty());
    while node.ingress.take_outbound().unwrap().is_some() {}
    let peers = node.ingress.authenticated_peers().unwrap();
    let mut original = None;
    for _ in 0..8 {
        node.retry_historical_timeouts(&peers).unwrap();
        while let Some(frame) = node.ingress.take_outbound().unwrap() {
            if let ConsensusEvent::TimeoutCertificate(tc) =
                serde_json::from_slice(&frame.payload).unwrap()
            {
                original = Some(tc);
            }
        }
        if original.is_some() {
            break;
        }
    }
    let original = original.expect("unknown peer must still receive old-lease original TC");
    assert_eq!((original.context.height, original.context.round), (1, 0));
    let mut delayed = SimplifiedConsensusStateMachine::new(
        fleet.authority.epoch.clone(),
        fleet.authority.registry.clone(),
        fleet.authority.anchor_parent.clone(),
    )
    .unwrap();
    delayed
        .accept_timeout_certificate(original, fleet.authority.as_ref())
        .unwrap();
    assert_eq!(delayed.active_slot(), (1, 1));
    // One available queue position must alternate historical recovery and
    // current-slot traffic; a permanently lagging peer cannot starve either.
    let mut historical_sends = 0;
    let mut current_sends = 0;
    for _ in 0..16 {
        for _ in 0..15 {
            node.ingress
                .publish_outbound(OutboundFrame {
                    peer_id: "occupied".into(),
                    protocol: ProtocolKind::Posy,
                    payload: vec![0],
                })
                .unwrap();
        }
        node.retry_at = Instant::now();
        node.retry_delivery().unwrap();
        while let Some(frame) = node.ingress.take_outbound().unwrap() {
            if frame.peer_id == "occupied" {
                continue;
            }
            match serde_json::from_slice::<ConsensusEvent>(&frame.payload).unwrap() {
                ConsensusEvent::TimeoutCertificate(tc) if tc.context.height == 1 => {
                    historical_sends += 1
                }
                _ => current_sends += 1,
            }
        }
    }
    assert!(historical_sends > 0 && current_sends > 0);

    fleet.nodes[missing] = fleet.make_node(missing);
    fleet.assert_same_finality(10);
}

#[test]
fn three_signers_cannot_advance_timeout_round() {
    let mut fleet = Fleet::new();
    for index in 0..3 {
        fleet.nodes[index].round_deadline = Instant::now();
        fleet.nodes[index].emit_timeout_vote().unwrap();
    }
    for _ in 0..4 {
        fleet.drain(false, None);
        fleet.retry();
    }
    assert!(fleet
        .nodes
        .iter()
        .all(|n| n.driver.state_machine().active_slot() == (1, 0)));
    assert!(fleet.nodes.iter().all(|n| n.last_finalized.is_none()));
}

#[test]
fn four_signers_sustain_finality_across_leases_with_one_validator_offline() {
    let mut fleet = Fleet::new();
    let missing: usize = fleet
        .authority
        .epoch
        .authorized_proposer(1, 0)
        .unwrap()
        .strip_prefix("qualification-")
        .unwrap()
        .parse()
        .unwrap();
    let source = (missing + 1) % 5;
    let mut retained_candidates = BTreeMap::new();
    for height in 1..=22 {
        for step in 0..80 {
            fleet.provide_material_except(Some(missing));
            fleet.drain(true, Some(missing));
            fleet.retry();
            fleet.drain(true, Some(missing));
            if fleet
                .nodes
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != missing)
                .all(|(_, n)| n.driver.state_machine().active_slot().0 > height)
            {
                break;
            }
            if step % 10 == 9 {
                for (index, node) in fleet.nodes.iter_mut().enumerate() {
                    if index != missing && node.driver.state_machine().active_slot().0 == height {
                        node.round_deadline = Instant::now();
                        node.emit_timeout_vote().unwrap();
                    }
                }
            }
        }
        assert!(
            fleet
                .nodes
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != missing)
                .all(|(_, n)| n.driver.state_machine().active_slot().0 > height),
            "four-validator progression stalled at {height}"
        );
        if height <= 20 {
            // Retain the original fixture inputs while live. The production
            // owner correctly retires finalized candidates before catch-up.
            retained_candidates.insert(height, fleet.nodes[source].candidates[&height].clone());
        }
    }
    let records: Vec<_> = fleet
        .nodes
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != missing)
        .map(|(_, n)| n.last_finalized.as_ref().unwrap())
        .collect();
    assert!(records[0].height >= 20);
    assert!(records.iter().all(|record| *record == records[0]));
    assert!(fleet.nodes[missing].last_finalized.is_none());
    // Real authenticated future QC and Sync witness arrive before a restarted
    // node's canonical predecessor prefix. Neither may advance it across gaps.
    fleet.nodes[missing] = fleet.make_node(missing);
    let future_qc = fleet.nodes[source]
        .certificates
        .get_verified(
            4,
            &fleet.authority.epoch,
            &fleet.authority.registry,
            fleet.authority.as_ref(),
        )
        .unwrap()
        .unwrap();
    fleet.nodes[missing]
        .apply_event_from(ConsensusEvent::QuorumCertificate(future_qc), true)
        .unwrap();
    assert_eq!(
        fleet.nodes[missing].driver.state_machine().active_slot().0,
        1
    );
    assert_eq!(fleet.nodes[missing].deferred_qcs.len(), 1);
    let future_certificates = [5, 6, 7].map(|height| {
        fleet.nodes[source]
            .certificates
            .get_verified(
                height,
                &fleet.authority.epoch,
                &fleet.authority.registry,
                fleet.authority.as_ref(),
            )
            .unwrap()
            .unwrap()
    });
    let future_witness = FinalitySyncWitness::from_verified_certificates(
        future_certificates,
        &fleet.nodes[source].timeout_certificates,
        &fleet.authority.epoch,
        &fleet.authority.registry,
        fleet.authority.as_ref(),
    )
    .unwrap();
    let future_candidate = retained_candidates[&5].clone();
    let future_response = crate::services::ingress::FinalizedCandidateResponse::decode_test(
        &synergy_sync::FinalizedCandidateResponse {
            request: synergy_sync::FinalizedCandidateRequest {
                height: 5,
                expected_parent_id: future_candidate.parent_block_id.clone(),
            },
            candidate: serde_json::from_slice::<synergy_execution::ExecutionCandidate>(
                &serde_json::to_vec(&future_candidate).unwrap(),
            )
            .unwrap(),
            finality_witness: serde_json::to_vec(&future_witness).unwrap(),
            processing_replay: None,
        },
        &fleet.nodes[missing].ingress,
    );
    fleet.nodes[missing]
        .admit_sync_candidate(future_response)
        .unwrap();
    assert_eq!(
        fleet.nodes[missing].driver.state_machine().active_slot().0,
        1
    );
    assert_eq!(fleet.nodes[missing].deferred_sync.len(), 1);
    for height in 1..=20 {
        let node = &fleet.nodes[source];
        let certificates = [height, height + 1, height + 2].map(|h| {
            node.certificates
                .get_verified(
                    h,
                    &fleet.authority.epoch,
                    &fleet.authority.registry,
                    fleet.authority.as_ref(),
                )
                .unwrap()
                .unwrap()
        });
        let witness = FinalitySyncWitness::from_verified_certificates(
            certificates,
            &node.timeout_certificates,
            &fleet.authority.epoch,
            &fleet.authority.registry,
            fleet.authority.as_ref(),
        )
        .unwrap();
        witness
            .verified_timeout_closure(
                &fleet.authority.epoch,
                &fleet.authority.registry,
                fleet.authority.as_ref(),
            )
            .unwrap();
        if height == 1 {
            // One genuine H1 timeout authorizes the takeover throughout the
            // lease; H2 and H3 must not need fabricated per-height timeouts.
            assert_eq!(witness.timeout_certificates.len(), 1);
            let mut incomplete = witness.clone();
            incomplete.timeout_certificates.clear();
            assert!(incomplete
                .verified_timeout_closure(
                    &fleet.authority.epoch,
                    &fleet.authority.registry,
                    fleet.authority.as_ref()
                )
                .is_err());
        }
        let candidate = retained_candidates[&height].clone();
        let response = synergy_sync::FinalizedCandidateResponse {
            request: synergy_sync::FinalizedCandidateRequest {
                height,
                expected_parent_id: candidate.parent_block_id.clone(),
            },
            candidate: serde_json::from_slice::<synergy_execution::ExecutionCandidate>(
                &serde_json::to_vec(&candidate).unwrap(),
            )
            .unwrap(),
            finality_witness: serde_json::to_vec(&witness).unwrap(),
            processing_replay: None,
        };
        let response = crate::services::ingress::FinalizedCandidateResponse::decode_test(
            &response,
            &fleet.nodes[missing].ingress,
        );
        fleet.nodes[missing].admit_sync_candidate(response).unwrap();
        fleet.nodes[missing].drain_deferred_qcs().unwrap();
        fleet.nodes[missing].drain_deferred_sync().unwrap();
        while fleet.nodes[missing]
            .ingress
            .take_finality()
            .unwrap()
            .is_some()
        {}
        while fleet.nodes[missing]
            .ingress
            .take_verified_sync_candidate()
            .unwrap()
            .is_some()
        {}
    }
    assert!(fleet.nodes[missing].deferred_qcs.is_empty());
    assert!(fleet.nodes[missing].deferred_sync.is_empty());
    fleet.assert_same_finality(20);
    fleet.nodes[missing] = fleet.make_node(missing);
    fleet.assert_same_finality(20);
}

#[test]
fn outbound_backpressure_does_not_starve_later_peers_or_messages() {
    let mut fleet = Fleet::new();
    fleet.provide_material();
    let proposer = fleet.authority.epoch.authorized_proposer(1, 0).unwrap();
    let index: usize = proposer
        .strip_prefix("qualification-")
        .unwrap()
        .parse()
        .unwrap();
    let node = &mut fleet.nodes[index];
    node.round_deadline = Instant::now();
    node.emit_timeout_vote().unwrap();
    while node.ingress.take_outbound().unwrap().is_some() {}
    let expected: BTreeSet<_> = node
        .retry_frames
        .keys()
        .flat_map(|slot| {
            node.ingress
                .authenticated_peers()
                .unwrap()
                .into_iter()
                .map(move |peer| (*slot, peer))
        })
        .collect();
    assert!(expected.len() >= 8);
    let mut delivered = BTreeSet::new();
    // Competing PoSy traffic consumes 15 of its 16 reserved positions,
    // leaving exactly one PoSy delivery per retry tick.
    for _ in 0..expected.len() * 2 {
        for _ in 0..15 {
            node.ingress
                .publish_outbound(OutboundFrame {
                    peer_id: "occupied".into(),
                    protocol: ProtocolKind::Posy,
                    payload: vec![0],
                })
                .unwrap();
        }
        node.retry_at = Instant::now();
        node.retry_delivery().unwrap();
        let mut tick_deliveries = 0;
        while let Some(frame) = node.ingress.take_outbound().unwrap() {
            if frame.peer_id != "occupied" {
                tick_deliveries += 1;
                let event: ConsensusEvent = serde_json::from_slice(&frame.payload).unwrap();
                let slot = event_slot(&event);
                assert_eq!(frame.payload, node.retry_payload(slot).unwrap());
                delivered.insert((slot, frame.peer_id));
            }
        }
        assert_eq!(
            tick_deliveries, 1,
            "PoSy quota must leave one retry position"
        );
    }
    assert_eq!(delivered, expected);
}

#[test]
fn certificate_retries_follow_verified_session_progress_without_losing_retained_proofs() {
    let mut fleet = Fleet::new();
    // Generate the retained READY/QC with real signatures and native finality.
    for height in 1..=4 {
        for _ in 0..30 {
            fleet.provide_material();
            fleet.drain(false, None);
            fleet.retry();
            fleet.drain(false, None);
            if fleet
                .nodes
                .iter()
                .all(|node| node.driver.state_machine().active_slot().0 > height)
            {
                break;
            }
        }
        assert!(fleet
            .nodes
            .iter()
            .all(|node| node.driver.state_machine().active_slot().0 > height));
    }
    fleet.assert_same_finality(2);
    let node = &mut fleet.nodes[0];
    let finalized = node.last_finalized.clone().unwrap();
    let behind = node
        .finality
        .as_ref()
        .unwrap()
        .get(finalized.height - 1)
        .unwrap()
        .unwrap();
    let certified_height = finalized.height.checked_add(2).unwrap();
    let witness = node
        .driver
        .state_machine()
        .finality_witness(finalized.height)
        .unwrap();
    assert_eq!(
        witness.map(|qc| qc.context.height),
        [finalized.height, finalized.height + 1, certified_height]
    );
    let latest_qc = node
        .certificates
        .get_verified(
            certified_height,
            &node.authority.epoch,
            &node.authority.registry,
            node.authority.as_ref(),
        )
        .unwrap()
        .unwrap();
    assert_eq!(latest_qc.id().unwrap(), finalized.finality_certificate_id);
    node.retry_frames
        .retain(|slot, _| slot.0 == certified_height && matches!(slot.2, 3 | 6));
    assert_eq!(
        node.retry_frames.len(),
        2,
        "native certified-tail READY and QC must both remain live"
    );
    let slots: Vec<_> = node.retry_frames.keys().copied().collect();
    let originals: BTreeMap<_, _> = slots
        .iter()
        .map(|slot| (*slot, node.retry_payload(*slot).unwrap()))
        .collect();
    let peers = node.ingress.authenticated_peers().unwrap();
    assert_eq!(peers.len(), 4);
    let session = |peer: &str| {
        SessionId(
            peer.strip_prefix("qualification-")
                .unwrap()
                .parse::<u64>()
                .unwrap()
                + 1,
        )
    };
    let head = |peer: &str, record: &synergy_posy::FinalizedBlockRecord| VerifiedHead {
        peer_id: peer.to_owned(),
        finalized_height: record.height,
        finalized_hash: record.block_id.clone(),
        finality_evidence_id: record.finality_certificate_id.clone(),
    };
    // These are trusted PoSy-verifier boundary notifications, not raw network claims.
    for index in [0, 3] {
        node.ingress
            .submit_verified_head(head(&peers[index], &finalized), session(&peers[index]))
            .unwrap();
    }
    node.ingress
        .submit_verified_head(head(&peers[1], &behind), session(&peers[1]))
        .unwrap();
    assert!(!node
        .ingress
        .verified_peer_heights()
        .unwrap()
        .contains_key(&peers[2]));
    while node.ingress.take_outbound().unwrap().is_some() {}
    let expected: BTreeSet<_> = slots
        .iter()
        .flat_map(|slot| [(*slot, peers[1].clone()), (*slot, peers[2].clone())])
        .collect();
    node.retry_cursor = 0;
    node.retry_at = Instant::now();
    node.retry_delivery().unwrap();
    let mut received = BTreeSet::new();
    while let Some(frame) = node.ingress.take_outbound().unwrap() {
        let event: ConsensusEvent = serde_json::from_slice(&frame.payload).unwrap();
        let slot = event_slot(&event);
        assert_eq!(frame.payload, originals[&slot]);
        received.insert((slot, frame.peer_id));
    }
    assert_eq!(
        received, expected,
        "verified tail peers skip, unknown and below-tail peers retry"
    );

    // A skip advances past the first peer, but a full queue retains the next
    // exact eligible pair. Draining one position per tick must reach the tail.
    node.retry_cursor = 0;
    for _ in 0..16 {
        node.ingress
            .publish_outbound(OutboundFrame {
                peer_id: "occupied".into(),
                protocol: ProtocolKind::Posy,
                payload: vec![0],
            })
            .unwrap();
    }
    node.retry_at = Instant::now();
    node.retry_delivery().unwrap();
    assert_eq!(
        node.retry_cursor, 1,
        "skip advances; blocked eligible publish does not"
    );
    let mut occupied = 0;
    while let Some(frame) = node.ingress.take_outbound().unwrap() {
        assert_eq!(frame.peer_id, "occupied");
        occupied += 1;
    }
    assert_eq!(occupied, 16);
    received.clear();
    for _ in 0..expected.len() * 2 {
        for _ in 0..15 {
            node.ingress
                .publish_outbound(OutboundFrame {
                    peer_id: "occupied".into(),
                    protocol: ProtocolKind::Posy,
                    payload: vec![0],
                })
                .unwrap();
        }
        node.retry_at = Instant::now();
        node.retry_delivery().unwrap();
        let mut delivered = 0;
        while let Some(frame) = node.ingress.take_outbound().unwrap() {
            if frame.peer_id == "occupied" {
                continue;
            }
            delivered += 1;
            let event: ConsensusEvent = serde_json::from_slice(&frame.payload).unwrap();
            let slot = event_slot(&event);
            assert_eq!(frame.payload, originals[&slot]);
            received.insert((slot, frame.peer_id));
        }
        assert_eq!(delivered, 1);
    }
    assert_eq!(
        received, expected,
        "skipped peers cannot starve either retained certificate"
    );

    // A replacement session cannot inherit the prior session's finalized head.
    let replacement = SessionId(1000);
    node.ingress
        .admit_session(peers[0].clone(), replacement)
        .unwrap();
    node.ingress
        .submit_verified_head(head(&peers[0], &finalized), session(&peers[0]))
        .unwrap();
    assert!(!node
        .ingress
        .verified_peer_heights()
        .unwrap()
        .contains_key(&peers[0]));
    node.retry_cursor = 0;
    node.retry_at = Instant::now();
    node.retry_delivery().unwrap();
    let mut resumed = BTreeSet::new();
    while let Some(frame) = node.ingress.take_outbound().unwrap() {
        let event: ConsensusEvent = serde_json::from_slice(&frame.payload).unwrap();
        let slot = event_slot(&event);
        assert_eq!(frame.payload, originals[&slot]);
        assert_ne!(frame.peer_id, peers[3]);
        if frame.peer_id == peers[0] {
            resumed.insert(slot);
        }
    }
    assert_eq!(resumed, slots.iter().copied().collect());
    for (index, peer) in peers.iter().enumerate() {
        node.ingress
            .submit_verified_head(
                head(peer, &finalized),
                if index == 0 {
                    replacement
                } else {
                    session(peer)
                },
            )
            .unwrap();
    }
    node.retry_at = Instant::now();
    node.retry_delivery().unwrap();
    assert!(
        node.ingress.take_outbound().unwrap().is_none(),
        "all current sessions prove both certificate heights through three-QC finality"
    );
    assert_eq!(node.retry_frames.keys().copied().collect::<Vec<_>>(), slots);
    for (slot, original) in originals {
        assert_eq!(
            node.retry_payload(slot).unwrap(),
            original,
            "suppression must never delete or rewrite retained proof bytes"
        );
    }
}

#[test]
fn byzantine_equivocation_cannot_deliver_split_candidates_or_mutate_stale_slot() {
    let fleet = Fleet::new();
    let epoch = &fleet.authority.epoch;
    let context = ConsensusObjectContext::for_height(epoch, 1, 0).unwrap();
    let make_candidate = |block: &str| {
        synergy_posy::CertifiedCandidateSubject::new(
            context.clone(),
            block.into(),
            fleet.authority.anchor_parent.block_id().into(),
            fleet.authority.anchor_parent.clone(),
            "a".repeat(64),
        )
        .unwrap()
    };
    let a = make_candidate("byzantine-a");
    let b = make_candidate("byzantine-b");
    let sign = |index: usize, candidate: &synergy_posy::CertifiedCandidateSubject, phase| {
        let mut value = ProposalDeliveryStatement {
            context: context.clone(),
            phase,
            candidate: candidate.clone(),
            validator_id: format!("qualification-{index}"),
            key_id: format!("key-{index}"),
            signature: Vec::new(),
        };
        let key = KeyId::new(format!("key-{index}")).unwrap();
        let signer = PqvmSigner::from_secret_key_bytes(
            AegisPolicy {
                allowed_algorithms: vec![SignatureAlgorithm::MlDsa65],
                maximum_message_bytes: 1024 * 1024,
                maximum_signature_bytes: 16 * 1024,
            },
            key.clone(),
            fleet.secrets[index].clone(),
        )
        .unwrap();
        value.signature = signer
            .sign(
                &key,
                &SigningContext {
                    domain: phase.domain().into(),
                    chain_id: 1266,
                    epoch: Some(1),
                    height: Some(1),
                },
                &value.signing_bytes().unwrap(),
            )
            .unwrap()
            .bytes;
        value
    };
    let root = fleet.root.join("byzantine-delivery");
    let mut delivery = ProposalDelivery::open(
        &root,
        epoch,
        &fleet.authority.registry,
        fleet.authority.as_ref(),
    )
    .unwrap();
    delivery.activate((1, 0)).unwrap();
    // Two honest nodes echo A, two echo B; the Byzantine node can equivocate,
    // but neither honest partition has n-1 ECHOs and neither can send READY.
    for (index, candidate) in [(0, &a), (1, &a), (2, &b), (3, &b), (4, &a)] {
        delivery
            .admit(
                sign(index, candidate, ProposalDeliveryPhase::Echo),
                (1, 0),
                epoch,
                &fleet.authority.registry,
                fleet.authority.as_ref(),
            )
            .unwrap();
    }
    assert!(delivery.validation_certificate(&a, 5).is_none());
    assert!(delivery.validation_certificate(&b, 5).is_none());
    assert!(delivery
        .admit(
            sign(4, &b, ProposalDeliveryPhase::Echo),
            (1, 0),
            epoch,
            &fleet.authority.registry,
            fleet.authority.as_ref()
        )
        .is_err());
    assert!(!delivery.deliver(&a).unwrap());
    delivery.activate((1, 1)).unwrap();
    assert!(delivery
        .admit(
            sign(0, &a, ProposalDeliveryPhase::Ready),
            (1, 1),
            epoch,
            &fleet.authority.registry,
            fleet.authority.as_ref()
        )
        .is_err());
    drop(delivery);
    let recovered = ProposalDelivery::open(
        &root,
        epoch,
        &fleet.authority.registry,
        fleet.authority.as_ref(),
    )
    .unwrap();
    assert_eq!(recovered.count(&a, ProposalDeliveryPhase::Echo), 0);
}

#[test]
fn historical_ready_proof_recovers_missing_vc_without_mutating_active_slot() {
    let mut fleet = Fleet::new();
    for height in 1..=3 {
        for _ in 0..30 {
            fleet.provide_material();
            fleet.drain(false, None);
            fleet.retry();
            fleet.drain(false, None);
            if fleet
                .nodes
                .iter()
                .all(|n| n.driver.state_machine().active_slot().0 > height)
            {
                break;
            }
        }
    }
    let envelope = fleet.nodes[0]
        .delivery
        .stored_ready_envelope(
            2,
            &fleet.authority.epoch,
            &fleet.authority.registry,
            fleet.authority.as_ref(),
        )
        .unwrap()
        .unwrap();
    assert!(envelope.validation_certificate.is_some());
    // Simulate a lagging node that installed QCs but never received this VC.
    replace_archive_fixture_bytes(
        &fleet.root.join("node-4"),
        b"validation-h2.json",
        b"validation-h2.jsox",
    );
    fleet.nodes[4] = fleet.make_node(4);
    assert!(fleet.nodes[4]
        .ingress
        .proposal_validation(2)
        .unwrap()
        .is_none());
    let before = fleet.nodes[4].driver.state_machine().active_slot();
    fleet.nodes[4]
        .apply_event_from(ConsensusEvent::ProposalDelivery(envelope.clone()), true)
        .unwrap();
    assert_eq!(fleet.nodes[4].driver.state_machine().active_slot(), before);
    assert_eq!(
        fleet.nodes[4]
            .delivery
            .count(&envelope.statement.candidate, ProposalDeliveryPhase::Ready),
        0
    );
    assert!(fleet.nodes[4]
        .ingress
        .proposal_validation(2)
        .unwrap()
        .is_some());
    let recovered = ProposalDelivery::open(
        &fleet.root.join("node-0"),
        &fleet.authority.epoch,
        &fleet.authority.registry,
        fleet.authority.as_ref(),
    )
    .unwrap();
    assert_eq!(
        recovered
            .stored_ready_envelope(
                2,
                &fleet.authority.epoch,
                &fleet.authority.registry,
                fleet.authority.as_ref()
            )
            .unwrap()
            .unwrap(),
        envelope
    );
}

#[test]
fn durable_finality_history_recovers_cache_loss_and_rejects_missing_or_tampered_qc() {
    let mut fleet = Fleet::new();
    for height in 1..=3 {
        for _ in 0..30 {
            fleet.provide_material();
            fleet.drain(false, None);
            fleet.retry();
            fleet.drain(false, None);
            if fleet
                .nodes
                .iter()
                .all(|n| n.driver.state_machine().active_slot().0 > height)
            {
                break;
            }
        }
    }
    let root = fleet.root.join("node-0");
    let expected = fleet.nodes[0]
        .finality
        .as_ref()
        .unwrap()
        .get(1)
        .unwrap()
        .unwrap();
    let fresh = || {
        let ingress = AuthenticatedIngress::default();
        ingress
            .install_finality_history(root.clone(), fleet.authority.clone())
            .unwrap();
        ingress
    };
    assert_eq!(fresh().finalized_record(1).unwrap(), Some(expected));
    let qc_key = "verified-qcs/qc/00000000000000000002.json";
    let original = synergy_posy::persistence::ConsensusEvidenceReader::open(&root)
        .unwrap()
        .read_exact(qc_key)
        .unwrap()
        .unwrap();
    let mut value: serde_json::Value = serde_json::from_slice(&original).unwrap();
    let byte = value["certificate"]["participants"][0]["signature"][0]
        .as_u64()
        .unwrap();
    value["certificate"]["participants"][0]["signature"][0] = serde_json::json!(byte ^ 1);
    // SQLite overflow pages frame large BLOBs. Corrupt a short unique signed
    // prefix inside one page, rather than assuming the entire JSON is contiguous.
    let original_value: serde_json::Value = serde_json::from_slice(&original).unwrap();
    let prefix = |v: &serde_json::Value| {
        let array = v["certificate"]["participants"][0]["signature"]
            .as_array()
            .unwrap();
        let mut prefix = serde_json::to_string(&array[..16]).unwrap();
        prefix.pop();
        format!("\"signature\":{prefix}").into_bytes()
    };
    replace_archive_fixture_bytes(&root, &prefix(&original_value), &prefix(&value));
    assert!(fresh().finalized_record(1).is_err());
    replace_archive_fixture_bytes(
        &root,
        qc_key.as_bytes(),
        b"verified-qcs/qc/00000000000000000002.jsox",
    );
    assert!(fresh().finalized_record(1).is_err());
}

#[test]
fn timeout_retry_references_keep_exact_native_original_bytes_without_history_payloads() {
    let mut fleet = Fleet::new();
    let mut reports = Vec::new();
    for node in &mut fleet.nodes {
        node.round_deadline = Instant::now();
        node.emit_timeout_vote().unwrap();
        let RetryFrame::Bytes(bytes) = node.retry_frames.get(&(1, 0, 2)).unwrap() else {
            panic!("local timeout vote must retain exact signed bytes");
        };
        let ConsensusEvent::TimeoutVote(report) = serde_json::from_slice(bytes).unwrap() else {
            panic!("expected signed timeout vote");
        };
        reports.push(report);
    }
    fleet.drain(false, None);
    let variant =
        synergy_posy::SimplifiedTimeoutCertificate::from_votes_with_qc_proofs(reports, vec![])
            .unwrap();
    let node = &mut fleet.nodes[0];
    let original = node
        .timeout_certificates
        .get_verified(
            1,
            0,
            &node.authority.epoch,
            &node.authority.registry,
            node.authority.as_ref(),
        )
        .unwrap()
        .unwrap();
    assert_eq!(variant.id().unwrap(), original.id().unwrap());
    assert_eq!(variant.reports.len(), 5);
    assert_eq!(original.reports.len(), 4);
    while node.ingress.take_outbound().unwrap().is_some() {}
    node.broadcast(&ConsensusEvent::TimeoutCertificate(variant.clone()))
        .unwrap();
    let expected =
        serde_json::to_vec(&ConsensusEvent::TimeoutCertificate(original.clone())).unwrap();
    let mut first_sends = 0;
    while let Some(frame) = node.ingress.take_outbound().unwrap() {
        assert_eq!(frame.payload, expected);
        first_sends += 1;
    }
    assert_eq!(first_sends, 4);
    assert_eq!(node.retry_payload((1, 0, 4)).unwrap(), expected);
    node.retry_frames.retain(|slot, _| slot.2 == 4);
    node.retry_at = Instant::now();
    node.retry_delivery().unwrap();
    let mut retries = 0;
    while let Some(frame) = node.ingress.take_outbound().unwrap() {
        assert_eq!(frame.payload, expected);
        retries += 1;
    }
    assert_eq!(retries, 4);
    let summary = node
        .driver
        .state_machine()
        .accepted_timeout_certificate(&original.id().unwrap())
        .unwrap()
        .clone();
    let mut changed = variant;
    changed.reports[0].key_id.push_str("-contradiction");
    assert!(!summary.matches_certificate(&changed).unwrap());
    assert!(node
        .broadcast(&ConsensusEvent::TimeoutCertificate(changed))
        .is_err());
    let reference = node.retry_frames.get(&(1, 0, 4)).unwrap().clone();
    for round in 1..4096 {
        node.retry_frames.insert((1, round, 4), reference.clone());
    }
    assert_eq!(node.retry_frames.len(), 4096);
    assert!(node
        .retry_frames
        .values()
        .all(|frame| matches!(frame, RetryFrame::Timeout { .. })));
    let summary_bytes = serde_json::to_vec(&summary).unwrap().len() * node.retry_frames.len();
    assert!(summary_bytes < 8 * 1024 * 1024);
    eprintln!("timeout_retry_resource references=4096 summary_bytes={summary_bytes} retained_payload_bytes=0");
}

#[test]
fn historical_timeout_locator_pages_bound_multiple_leases_and_do_not_omit_ancestry() {
    let mut history = HistoricalTimeoutRetry::default();
    let slots: Vec<_> = (0..3)
        .flat_map(|lease| (0..5000).map(move |round| (lease, round, lease * 10 + 1)))
        .collect();
    let mut delivered = Vec::new();
    loop {
        for key in slots.iter().rev() {
            history.select(*key);
        }
        assert!(history.selected.len() <= 4096);
        if history.selected.is_empty() {
            break;
        }
        let lease = history.selected.first().unwrap().0;
        assert!(history.selected.iter().all(|key| key.0 == lease));
        while let Some(key) = history.selected.pop_first() {
            history.after = Some(key);
            delivered.push(key);
        }
    }
    assert_eq!(delivered, slots);
}

/// Corrupt only an isolated test archive, with an equal-length replacement so
/// SQLite framing remains intact and protocol integrity/missing-proof checks
/// are exercised. No production storage API permits rewriting immutable rows.
fn replace_archive_fixture_bytes(root: &std::path::Path, original: &[u8], replacement: &[u8]) {
    assert_eq!(original.len(), replacement.len());
    let path = root.join("consensus-evidence-v1.sqlite3");
    let mut bytes = std::fs::read(&path).unwrap();
    let offsets = bytes
        .windows(original.len())
        .enumerate()
        .filter_map(|(i, b)| (b == original).then_some(i))
        .collect::<Vec<_>>();
    assert_eq!(
        offsets.len(),
        1,
        "fixture needle must identify exactly one archived record"
    );
    bytes[offsets[0]..offsets[0] + original.len()].copy_from_slice(replacement);
    // Signal an external generation change to already-open SQLite readers.
    let counter = u32::from_be_bytes(bytes[24..28].try_into().unwrap())
        .wrapping_add(1)
        .to_be_bytes();
    bytes[24..28].copy_from_slice(&counter);
    bytes[92..96].copy_from_slice(&counter);
    std::fs::write(path, bytes).unwrap();
}

/// Run explicitly against a bounded public-only capture from stopped storage.
/// Never opens a signer, starts a node, or changes the captured source.
#[test]
#[ignore = "requires explicit stopped public-history capture and new disposable fixture path"]
fn offline_existing_history_legacy_mixed_import_and_rollback_rehearsal() {
    use synergy_posy::persistence::ConsensusEvidenceReader;
    let source = PathBuf::from(
        std::env::var_os("SYNERGY_STORAGE_LEGACY_SOURCE").expect("public capture path required"),
    );
    let fixture = PathBuf::from(
        std::env::var_os("SYNERGY_STORAGE_MIGRATION_FIXTURE")
            .expect("new disposable path required"),
    );
    assert!(
        !fixture.exists(),
        "rehearsal must never overwrite an existing directory"
    );
    assert_ne!(source.canonicalize().unwrap(), fixture);
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(source.join("manifest.json")).unwrap()).unwrap();
    let records = manifest["records"].as_object().unwrap();
    assert!(!records.is_empty() && records.len() <= 128);
    let mut originals = BTreeMap::new();
    let mut total = 0;
    for (name, metadata) in records {
        let relative = std::path::Path::new(name);
        assert!(relative
            .components()
            .all(|c| matches!(c, std::path::Component::Normal(_))));
        let path = source.join("records").join(relative);
        let file = std::fs::symlink_metadata(&path).unwrap();
        assert!(file.is_file() && !file.file_type().is_symlink());
        assert!(file.len() <= 16 * 1024 * 1024);
        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(bytes.len() as u64, metadata["size"].as_u64().unwrap());
        total += bytes.len();
        assert!(total <= 32 * 1024 * 1024);
        originals.insert(name.clone(), bytes);
    }
    std::fs::create_dir_all(&fixture).unwrap();
    for (name, bytes) in &originals {
        let path = fixture.join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, bytes).unwrap();
    }
    let binding_bytes = std::fs::read(source.join("public/authority.json")).unwrap();
    let binding: serde_json::Value = serde_json::from_slice(&binding_bytes).unwrap();
    let configuration:NodeConfiguration=serde_json::from_value(serde_json::json!({
        "schema_version":1,"node_name":"offline-public-history-rehearsal","role":"validator",
        "chain_id":binding["payload"]["chain_id"],"network_id":binding["payload"]["network_id"],
        "manifest_path":source.join("public/network-manifest.json"),"public_identity_path":"unused-offline-public-identity",
        "admin_socket_path":"unused-offline-admin-socket",
        "storage":{"data_directory":fixture,"wal_sync":"every_commit","max_open_files":64,"prune_finalized_history_after_blocks":null}
    })).unwrap();
    let mut configuration = configuration;
    configuration.consensus.authority_trust_key_path =
        Some(source.join("public/authority-root.pub"));
    let auth = authority::verify_binding_bytes(&configuration, binding_bytes).unwrap();
    let verify_stage = |label: &str| {
        let certificates = VerifiedQuorumCertificateStore::new(&fixture).unwrap();
        let finality = FinalityStore::new(&fixture).unwrap();
        let timeouts = VerifiedTimeoutCertificateStore::new(&fixture).unwrap();
        let delivery =
            ProposalDelivery::open(&fixture, &auth.epoch, &auth.registry, auth.as_ref()).unwrap();
        let mut journal = SignOnceJournal::load(fixture.join("sign-once.json")).unwrap();
        let journal_value: serde_json::Value =
            serde_json::from_slice(&originals["sign-once.json"]).unwrap();
        assert_eq!(
            journal.finalized_floor(),
            journal_value["finalized_floor"].as_u64().unwrap()
        );
        for reservation in journal_value["records"].as_array().unwrap() {
            let slot: SigningSlot = serde_json::from_value(reservation["slot"].clone()).unwrap();
            assert_eq!(journal.subject(&slot), reservation["subject"].as_str());
        }
        assert!(journal
            .record(
                SigningSlot {
                    height: journal.finalized_floor(),
                    round: 0,
                    domain: "block-vote".into()
                },
                "must-not-sign".into()
            )
            .is_err());
        let reader = ConsensusEvidenceReader::open(&fixture).unwrap();
        let mut counts = BTreeMap::<String, u64>::new();
        for (name, original) in &originals {
            assert_eq!(
                std::fs::read(fixture.join(name)).unwrap(),
                *original,
                "legacy file changed: {name}"
            );
            if name == "sign-once.json" || name == "delivery.json" {
                continue;
            }
            assert_eq!(
                reader.read_exact(name).unwrap().unwrap(),
                *original,
                "exact historical bytes differ: {name}"
            );
            let category = if let Some(height) = name
                .strip_prefix("verified-qcs/qc/")
                .and_then(|s| s.strip_suffix(".json"))
            {
                certificates
                    .get_verified(
                        height.parse().unwrap(),
                        &auth.epoch,
                        &auth.registry,
                        auth.as_ref(),
                    )
                    .unwrap()
                    .unwrap();
                "qc"
            } else if let Some(height) = name
                .strip_prefix("finality/h")
                .and_then(|s| s.strip_suffix(".json"))
            {
                let height: u64 = height.parse().unwrap();
                let record = finality.get(height).unwrap().unwrap();
                let mut witness = synergy_posy::ThreeQcFinality::default();
                for h in height..=height + 2 {
                    witness
                        .accept(
                            certificates
                                .get_verified(h, &auth.epoch, &auth.registry, auth.as_ref())
                                .unwrap()
                                .unwrap(),
                        )
                        .unwrap();
                }
                assert_eq!(witness.last_finalized(), Some(&record));
                "finality_three_qc"
            } else if let Some(height) = name
                .strip_prefix("ready-h")
                .and_then(|s| s.strip_suffix(".json"))
            {
                delivery
                    .stored_ready_envelope(
                        height.parse().unwrap(),
                        &auth.epoch,
                        &auth.registry,
                        auth.as_ref(),
                    )
                    .unwrap()
                    .unwrap();
                "ready"
            } else if let Some(height) = name
                .strip_prefix("validation-h")
                .and_then(|s| s.strip_suffix(".json"))
            {
                delivery
                    .stored_validation(
                        height.parse().unwrap(),
                        &auth.epoch,
                        &auth.registry,
                        auth.as_ref(),
                    )
                    .unwrap()
                    .unwrap();
                "validation"
            } else if let Some(slot) = name
                .strip_prefix("verified-timeouts/h")
                .and_then(|s| s.strip_suffix(".json"))
            {
                let (height, round) = slot.split_once('r').unwrap();
                timeouts
                    .get_verified(
                        height.parse().unwrap(),
                        round.parse().unwrap(),
                        &auth.epoch,
                        &auth.registry,
                        auth.as_ref(),
                    )
                    .unwrap()
                    .unwrap();
                "timeout"
            } else if name.starts_with("signature-") {
                let (slot, domain, transcript, signature): (SigningSlot, String, Vec<u8>, Vec<u8>) =
                    serde_json::from_slice(original).unwrap();
                assert_eq!(
                    name,
                    &format!(
                        "signature-{}.json",
                        synergy_posy::canonical_hash("SYNERGY_POSY_SIGNED_SLOT_V1", &slot).unwrap()
                    )
                );
                assert_eq!(
                    journal.signed_bytes(&slot, &domain, &transcript).unwrap(),
                    Some(signature.clone())
                );
                let value: serde_json::Value = serde_json::from_slice(&transcript).unwrap();
                let (context, validator, key) = if value.is_array() {
                    (
                        &value[0],
                        value[3].as_str().unwrap(),
                        value[4].as_str().unwrap(),
                    )
                } else {
                    (
                        &value["context"],
                        value["validator_id"].as_str().unwrap(),
                        value["key_id"].as_str().unwrap(),
                    )
                };
                let context: synergy_posy::ConsensusObjectContext =
                    serde_json::from_value(context.clone()).unwrap();
                context.validate_against(&auth.epoch).unwrap();
                assert_eq!((context.height, context.round), (slot.height, slot.round));
                synergy_posy::ConsensusSignatureVerifier::verify_consensus_signature(
                    auth.as_ref(),
                    &domain,
                    &transcript,
                    auth.registry.validator(validator).unwrap(),
                    key,
                    context.epoch,
                    &signature,
                )
                .unwrap();
                "exact_signature_pq"
            } else {
                panic!("unexpected captured historical record {name}");
            };
            *counts.entry(category.into()).or_default() += 1;
        }
        serde_json::json!({"stage":label,"verified_records":counts,"sign_once_floor":journal.finalized_floor(),"legacy_originals_unchanged":true})
    };
    let mut stages = vec![verify_stage("legacy_only")];
    let historical = originals
        .keys()
        .filter(|name| name.as_str() != "delivery.json" && name.as_str() != "sign-once.json")
        .map(PathBuf::from)
        .collect::<Vec<_>>();
    let split = historical.len() / 2;
    let archive = ConsensusEvidenceReader::open(&fixture).unwrap();
    archive.import_legacy_records(&historical[..split]).unwrap();
    stages.push(verify_stage("mixed_legacy_indexed"));
    archive.import_legacy_records(&historical[..split]).unwrap();
    archive.import_legacy_records(&historical[split..]).unwrap();
    stages.push(verify_stage("fully_indexed_restart"));
    drop(archive);
    // Reversible before any new consensus work: removing only the disposable
    // archive leaves the entire untouched legacy history available to old code.
    std::fs::remove_file(fixture.join("consensus-evidence-v1.sqlite3")).unwrap();
    // Dispose only this test's newly generated cold segments too: a missing
    // index beside cold data now correctly requires explicit offline reindex.
    // Every original legacy path remains untouched in this disposable copy.
    std::fs::remove_dir_all(fixture.join("archive")).unwrap();
    stages.push(verify_stage("rollback_legacy_only"));
    for (name, bytes) in &originals {
        assert_eq!(
            std::fs::read(source.join("records").join(name)).unwrap(),
            *bytes,
            "captured source changed"
        );
    }
    let report = serde_json::json!({"format":"posy-existing-public-history-rehearsal-v1","captured_records":originals.len(),"historical_records":historical.len(),
        "exact_original_bytes":total,"stages":stages,"captured_source_unchanged":true,"node_started":false,"signer_opened":false,
        "rollback_boundary":"Rollback proved only before any new consensus records. Downgrade after further consensus writes requires explicit verified export; never delete archive history."});
    std::fs::write(
        fixture.join("rehearsal-report.json"),
        serde_json::to_vec_pretty(&report).unwrap(),
    )
    .unwrap();
    println!("{}", serde_json::to_string(&report).unwrap());
}

/// A bounded-memory checkpoint of every public PoSy file. The chunk tree uses
/// domain-separated SHA3 digests, so large SQLite files need no whole-file RAM.
fn offline_public_checkpoint(
    root: &std::path::Path,
    copy_to: Option<&std::path::Path>,
) -> BTreeMap<PathBuf, (u64, String)> {
    use std::io::{Read, Write};
    assert!(root.is_dir() && !root.is_symlink());
    let mut pending = vec![root.to_path_buf()];
    let mut records = BTreeMap::new();
    let mut total = 0u64;
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(directory).unwrap() {
            let path = entry.unwrap().path();
            let metadata = std::fs::symlink_metadata(&path).unwrap();
            assert!(!metadata.file_type().is_symlink(), "public source symlink");
            if metadata.is_dir() {
                pending.push(path);
                assert!(pending.len() <= 1_000_000);
                continue;
            }
            assert!(metadata.is_file(), "public source special file");
            let relative = path.strip_prefix(root).unwrap().to_path_buf();
            assert!(!relative.components().any(|part| part.as_os_str() == "keys"));
            assert!(!relative.to_string_lossy().contains("secret.key"));
            assert!(
                !relative
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("._"),
                "exclude AppleDouble before capture"
            );
            total = total.checked_add(metadata.len()).unwrap();
            assert!(
                total <= 32 * 1024 * 1024 * 1024,
                "public capture exceeds 32GiB"
            );
            let mut input = std::fs::File::open(&path).unwrap();
            let mut output = copy_to.map(|destination| {
                let destination = destination.join(&relative);
                std::fs::create_dir_all(destination.parent().unwrap()).unwrap();
                std::fs::OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .open(destination)
                    .unwrap()
            });
            let mut buffer = vec![0; 1024 * 1024];
            let mut chunks = Vec::new();
            let mut bytes = 0u64;
            loop {
                let mut count = 0;
                while count < buffer.len() {
                    let read = input.read(&mut buffer[count..]).unwrap();
                    if read == 0 {
                        break;
                    }
                    count += read;
                }
                if count == 0 {
                    break;
                }
                bytes += count as u64;
                chunks.push(
                    synergy_storage::IntegrityDigest::of(
                        "POSY_OFFLINE_PUBLIC_CHUNK_V1",
                        &buffer[..count],
                    )
                    .0,
                );
                if let Some(output) = output.as_mut() {
                    output.write_all(&buffer[..count]).unwrap();
                }
            }
            assert_eq!(bytes, metadata.len(), "public file changed during copy");
            if let Some(output) = output {
                output.sync_all().unwrap();
            }
            records.insert(
                relative,
                (
                    bytes,
                    synergy_posy::canonical_hash("POSY_OFFLINE_PUBLIC_FILE_V1", &(bytes, chunks))
                        .unwrap(),
                ),
            );
            assert!(records.len() <= 1_000_000, "public capture record limit");
        }
    }
    records
}

fn offline_replay_stopped_copy(
    root: &std::path::Path,
    auth: &VerifiedAuthority,
) -> serde_json::Value {
    let _recovery = PosyRecoveryJournal::load(root.join("recovery.json")).unwrap();
    let certificates = VerifiedQuorumCertificateStore::new(root).unwrap();
    let finality = FinalityStore::new(root).unwrap();
    let timeouts = VerifiedTimeoutCertificateStore::new(root).unwrap();
    let mut journal = SignOnceJournal::load(root.join("sign-once.json")).unwrap();
    let floor = journal.finalized_floor();
    let mut state = SimplifiedConsensusStateMachine::new(
        auth.epoch.clone(),
        auth.registry.clone(),
        auth.anchor_parent.clone(),
    )
    .unwrap();
    assert_eq!(auth.epoch.epoch, 1, "successor capture requires its signed transition package; do not improvise transition state");
    let finalized = replay_verified_safety_state_from_floor(
        &mut state,
        auth,
        &certificates,
        &timeouts,
        &finality,
        Some(floor),
    )
    .unwrap();
    assert!(finalized
        .as_ref()
        .is_some_and(|record| record.height >= floor));
    let mut delivery = ProposalDelivery::open(root, &auth.epoch, &auth.registry, auth).unwrap();
    delivery.activate(state.active_slot()).unwrap();
    let last_vote = journal
        .recover_last_block_vote(state.active_slot().0)
        .unwrap();
    if let Some(vote) = &last_vote {
        validate_block_vote(vote, &auth.epoch, &auth.registry, auth).unwrap();
    }
    assert!(journal
        .record(
            SigningSlot {
                height: floor,
                round: 0,
                domain: "block-vote".into()
            },
            "offline-must-not-sign".into()
        )
        .is_err());
    serde_json::json!({"sign_once_floor":floor,"verified_finality":finalized,"active_slot":state.active_slot(),"last_vote_verified":last_vote.is_some(),"signer_opened":false,"node_started":false})
}

/// Stream every captured public path into an explicit accounting receipt.
/// Historical records must be retrievable from cold storage WITHOUT legacy
/// fallback. Journals/locks/index containers remain with their existing owner.
fn offline_import_all_public_history(
    root: &std::path::Path,
    original_root: &std::path::Path,
    originals: &BTreeMap<PathBuf, (u64, String)>,
) -> serde_json::Value {
    use sha2::{Digest, Sha256};
    use std::io::{Read, Write};
    let reader = synergy_posy::persistence::ConsensusEvidenceReader::open(root).unwrap();
    let historical = |path: &std::path::Path| {
        let name = path.to_str().unwrap();
        if matches!(
            name,
            "sign-once.json" | "delivery.json" | "recovery.json" | ".synergy-writer.lock"
        ) {
            return "local_safety_or_control";
        }
        if name == "consensus-evidence-v1.sqlite3"
            || name == "consensus-evidence-v1.sqlite3-journal"
            || name.starts_with("archive/")
        {
            return "existing_index_or_archive_container";
        }
        if name.starts_with(".transactions/") {
            return "preserved_atomic_recovery_work";
        }
        if (name.starts_with("signature-")
            || name.starts_with("ready-h")
            || name.starts_with("validation-h")
            || name.starts_with("verified-qcs/qc/")
            || name.starts_with("finality/h")
            || name.starts_with("verified-timeouts/h")
            || name.starts_with("proposals/")
            || name.starts_with("votes/"))
            && name.ends_with(".json")
        {
            return "lossless_cold_history";
        }
        panic!("unclassified original public record: {name}");
    };
    let mut batch = Vec::new();
    let mut batch_bytes = 0u64;
    let mut imported = 0u64;
    for (path, (size, _)) in originals {
        if historical(path) != "lossless_cold_history" {
            continue;
        }
        assert!(
            *size <= 16 * 1024 * 1024,
            "legacy record exceeds native bound"
        );
        if !batch.is_empty() && (batch.len() == 16 || batch_bytes + size > 8 * 1024 * 1024) {
            reader.import_legacy_records(&batch).unwrap();
            batch.clear();
            batch_bytes = 0;
        }
        batch.push(path.clone());
        batch_bytes += size;
        imported += 1;
    }
    if !batch.is_empty() {
        reader.import_legacy_records(&batch).unwrap();
    }
    let first = reader.inspection_statistics().unwrap();
    // Identical second pass must not append frames or logical objects.
    batch.clear();
    batch_bytes = 0;
    for (path, (size, _)) in originals {
        if historical(path) != "lossless_cold_history" {
            continue;
        }
        if !batch.is_empty() && (batch.len() == 16 || batch_bytes + size > 8 * 1024 * 1024) {
            reader.import_legacy_records(&batch).unwrap();
            batch.clear();
            batch_bytes = 0;
        }
        batch.push(path.clone());
        batch_bytes += size;
    }
    if !batch.is_empty() {
        reader.import_legacy_records(&batch).unwrap();
    }
    let second = reader.inspection_statistics().unwrap();
    for field in [
        "archive_objects",
        "archive_records",
        "archive_revisions",
        "segments",
    ] {
        assert_eq!(
            first[field], second[field],
            "idempotent import grew {field}"
        );
    }
    drop(reader);
    let reader =
        synergy_posy::persistence::ConsensusEvidenceReader::rebuild_archive_index(root).unwrap();
    let mut receipt = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(root.join("legacy-mapping-sha256.jsonl"))
        .unwrap();
    let mut categories = BTreeMap::<String, u64>::new();
    let mut buffer = vec![0; 1024 * 1024];
    for (path, (size, _)) in originals {
        let category = historical(path);
        *categories.entry(category.into()).or_default() += 1;
        let mut input = std::fs::File::open(original_root.join(path)).unwrap();
        let mut digest = Sha256::new();
        let mut count = 0u64;
        loop {
            let n = input.read(&mut buffer).unwrap();
            if n == 0 {
                break;
            }
            digest.update(&buffer[..n]);
            count += n as u64;
        }
        assert_eq!(count, *size);
        let original_sha = format!("{:x}", digest.finalize());
        let archived_sha = if category == "lossless_cold_history" {
            let archived = reader
                .read_archived_exact(path)
                .unwrap()
                .expect("legacy fallback cannot prove import");
            assert_eq!(archived.len() as u64, *size);
            let digest = format!("{:x}", Sha256::digest(&archived));
            assert_eq!(digest, original_sha);
            Some(digest)
        } else {
            None
        };
        serde_json::to_writer(&mut receipt,&serde_json::json!({"path":path,"classification":category,"bytes":size,"original_sha256":original_sha,"archived_sha256":archived_sha})).unwrap();
        receipt.write_all(b"\n").unwrap();
    }
    receipt.sync_all().unwrap();
    assert_eq!(categories.values().sum::<u64>(), originals.len() as u64);
    let stats = reader.inspection_statistics().unwrap();
    drop(reader);
    serde_json::json!({"source_paths_accounted":originals.len(),"historical_records_imported":imported,"categories":categories,"idempotent_logical_objects":true,
        "offline_reindex_exact_bytes_verified":true,"per_path_sha256_map":"legacy-mapping-sha256.jsonl","statistics":stats,
        "reindex_scope":"Cold segment bindings only. Does not reconstruct missingv1-only rows, transient hotREADY/lifecycle, local signing journals or execution state; native typed startup replay remains mandatory."})
}

/// Resolve every input and reject aliasing before any disposable file is made.
fn offline_full_input_paths(
    source: &std::path::Path,
    records_override: Option<&std::path::Path>,
    fixture: &std::path::Path,
) -> (PathBuf, PathBuf, PathBuf) {
    assert!(fixture.is_absolute() && !fixture.exists() && !fixture.is_symlink());
    assert!(!fixture
        .components()
        .any(|part| matches!(part, std::path::Component::ParentDir)));
    assert!(source.is_absolute() && !source.is_symlink());
    let source = source.canonicalize().unwrap();
    let records = records_override
        .map(PathBuf::from)
        .unwrap_or_else(|| source.join("records"));
    assert!(records.is_absolute() && !records.is_symlink());
    let records = records.canonicalize().unwrap();
    assert!(records.is_dir());
    let parent = fixture.parent().unwrap().canonicalize().unwrap();
    let fixture = parent.join(fixture.file_name().unwrap());
    for input in [&source, &records] {
        assert!(
            !fixture.starts_with(input) && !input.starts_with(&fixture),
            "output must be outside immutable source and actual records"
        );
    }
    for name in ["sign-once.json", "delivery.json"] {
        let path = records.join(name);
        assert!(
            path.is_file() && !path.is_symlink(),
            "missing active safety journal: {name}"
        );
    }
    for name in [
        "genesis.json",
        "authority.json",
        "authority-root.pub",
        "network-manifest.json",
        "p2p-bindings.json",
        "transport-registry.json",
    ] {
        let path = source.join("public").join(name);
        assert!(
            path.is_file() && !path.is_symlink(),
            "missing public network input: {name}"
        );
    }
    (source, records, fixture)
}

/// Full actual stopped public PoSy state, copied before recovery can mutate it.
/// SOURCE/records is the entire PoSy tree; SOURCE/public has six signed inputs.
/// This is deliberately separate from the bounded 50-record migration sample.
#[test]
#[ignore = "requires a full stopped public consensus capture and fresh disposable destination"]
fn offline_full_existing_history_startup_safety_replay() {
    let source = PathBuf::from(
        std::env::var_os("SYNERGY_STORAGE_FULL_SOURCE")
            .expect("full stopped public source required"),
    );
    let fixture = PathBuf::from(
        std::env::var_os("SYNERGY_STORAGE_FULL_FIXTURE")
            .expect("fresh disposable destination required"),
    );
    let records_override = std::env::var_os("SYNERGY_STORAGE_FULL_RECORDS").map(PathBuf::from);
    let (source, records_source, fixture) =
        offline_full_input_paths(&source, records_override.as_deref(), &fixture);
    std::fs::create_dir(&fixture).unwrap();
    let originals = offline_public_checkpoint(&records_source, Some(&fixture));
    let public_before = offline_public_checkpoint(&source.join("public"), None);
    let binding_bytes = std::fs::read(source.join("public/authority.json")).unwrap();
    let binding: serde_json::Value = serde_json::from_slice(&binding_bytes).unwrap();
    let mut configuration:NodeConfiguration=serde_json::from_value(serde_json::json!({
        "schema_version":1,"node_name":"offline-full-stopped-public-replay","role":"validator",
        "chain_id":binding["payload"]["chain_id"],"network_id":binding["payload"]["network_id"],
        "manifest_path":source.join("public/network-manifest.json"),"public_identity_path":"unused-public-identity", "admin_socket_path":"unused-admin-socket",
        "storage":{"data_directory":fixture,"wal_sync":"every_commit","max_open_files":64,"prune_finalized_history_after_blocks":null}
    })).unwrap();
    configuration.consensus.authority_trust_key_path =
        Some(source.join("public/authority-root.pub"));
    let auth = authority::verify_binding_bytes(&configuration, binding_bytes).unwrap();
    let first = offline_replay_stopped_copy(&fixture, auth.as_ref());
    let migration = offline_import_all_public_history(&fixture, &records_source, &originals);
    // All owner handles are dropped, including the pooled SQLite connection.
    // Reconstruct again and require the exact finalized record and active slot.
    let second = offline_replay_stopped_copy(&fixture, auth.as_ref());
    assert_eq!(first, second, "closed-handle startup replay differs");
    assert_eq!(
        offline_public_checkpoint(&records_source, None),
        originals,
        "immutable stopped source changed"
    );
    assert_eq!(
        offline_public_checkpoint(&source.join("public"), None),
        public_before,
        "public network artifacts changed"
    );
    for name in ["sign-once.json", "recovery.json"] {
        if originals.contains_key(std::path::Path::new(name)) {
            assert_eq!(
                std::fs::read(records_source.join(name)).unwrap(),
                std::fs::read(fixture.join(name)).unwrap(),
                "safety journal changed during offline replay"
            );
        }
    }
    let report = serde_json::json!({"format":"posy-full-stopped-startup-replay-v2","source_records":originals.len(),"source_bytes":originals.values().map(|value|value.0).sum::<u64>(),"source_checkpoint_root":synergy_posy::canonical_hash("POSY_FULL_STOPPED_SOURCE_V1",&originals).unwrap(),"source_unchanged":true,"public_unchanged":true,"copy_only_recovery":true,"closed_handle_replay_identical":true,"migration":migration,"recovered":second,"limits":{"maximum_source_bytes":34359738368u64,"maximum_files":1000000,"chunk_bytes":1048576},"scope":"full byte checkpoint,100%per-path lossless import/reindex accounting and exact native startup safety tail; not an all-historical-signature sweep or full execution-state boot"});
    std::fs::write(
        fixture.join("full-startup-replay-report.json"),
        serde_json::to_vec_pretty(&report).unwrap(),
    )
    .unwrap();
    println!("{}", serde_json::to_string(&report).unwrap());
}

#[test]
fn offline_stopped_copy_replay_matches_finality_without_signer() {
    let mut fleet = Fleet::new();
    for height in 1..=8 {
        for _ in 0..30 {
            fleet.provide_material();
            fleet.drain(false, None);
            if fleet
                .nodes
                .iter()
                .all(|node| node.driver.state_machine().active_slot().0 > height)
            {
                break;
            }
        }
    }
    fleet.assert_same_finality(6);
    let expected = fleet.nodes[0].last_finalized.clone().unwrap();
    let source = fleet.root.join("node-0");
    let destination = fleet.root.join("offline-no-signer-copy");
    std::fs::create_dir(&destination).unwrap();
    let before = offline_public_checkpoint(&source, Some(&destination));
    let first = offline_replay_stopped_copy(&destination, fleet.authority.as_ref());
    let migration = offline_import_all_public_history(&destination, &source, &before);
    assert_eq!(migration["source_paths_accounted"], before.len());
    let second = offline_replay_stopped_copy(&destination, fleet.authority.as_ref());
    assert_eq!(first, second);
    assert_eq!(
        first["verified_finality"],
        serde_json::to_value(expected).unwrap()
    );
    assert_eq!(offline_public_checkpoint(&source, None), before);
}

#[test]
fn offline_full_input_override_uses_actual_journals_and_external_sibling() {
    let base = std::env::temp_dir().join(format!(
        "posy-full-input-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let source = base.join("public-source");
    let records = base.join("actual-posy");
    std::fs::create_dir_all(source.join("public")).unwrap();
    std::fs::create_dir(&records).unwrap();
    for name in [
        "genesis.json",
        "authority.json",
        "authority-root.pub",
        "network-manifest.json",
        "p2p-bindings.json",
        "transport-registry.json",
    ] {
        std::fs::write(source.join("public").join(name), b"public-only").unwrap();
    }
    for name in ["sign-once.json", "delivery.json"] {
        std::fs::write(records.join(name), b"actual-journal").unwrap();
    }
    assert!(!source.join("records").exists());
    let destination = base.join("external-replay-copy");
    let (resolved_source, resolved_records, resolved_destination) =
        offline_full_input_paths(&source, Some(&records), &destination);
    assert_eq!(resolved_source, source.canonicalize().unwrap());
    assert_eq!(resolved_records, records.canonicalize().unwrap());
    assert_eq!(
        resolved_destination,
        base.canonicalize().unwrap().join("external-replay-copy")
    );
    assert!(!destination.exists(), "resolver must not create output");
    for bad in [source.join("nested-output"), records.join("nested-output")] {
        assert!(std::panic::catch_unwind(|| offline_full_input_paths(
            &source,
            Some(&records),
            &bad
        ))
        .is_err());
        assert!(!bad.exists(), "invalid output was created");
    }
    assert!(
        std::panic::catch_unwind(|| offline_full_input_paths(&source, None, &destination)).is_err(),
        "absent default records must not bypass override validation"
    );
    assert!(!destination.exists());
    std::fs::remove_file(records.join("sign-once.json")).unwrap();
    assert!(
        std::panic::catch_unwind(|| offline_full_input_paths(
            &source,
            Some(&records),
            &destination
        ))
        .is_err(),
        "actual journal is mandatory"
    );
    assert!(!destination.exists());
    std::fs::remove_dir_all(base).unwrap();
}
