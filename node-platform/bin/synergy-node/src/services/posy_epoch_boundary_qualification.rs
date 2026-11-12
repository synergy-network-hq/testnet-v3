//! Real native-APQE replay/timeout owner regression for terminal epochs.
use super::*;

pub(in crate::services) fn qualify_terminal_epoch_timeout(
    configuration: &NodeConfiguration,
    authority: Arc<VerifiedAuthority>,
    signer: Arc<dyn AegisSigner>,
    validator_id: &str,
    key_id: &str,
) {
    let layout = NodeStorageLayout::new(configuration.storage.data_directory.clone()).unwrap();
    let root = layout.consensus().join("posy");
    let journal_path = root.join("sign-once.json");
    let before_journal = fs::read(&journal_path).ok();
    let before_finality = FinalityStore::new(&root)
        .unwrap()
        .get(authority.epoch.epoch_end_height - 2)
        .unwrap()
        .unwrap();
    let make_service = |mut machine: SimplifiedConsensusStateMachine, replay: bool| {
        let certificates = VerifiedQuorumCertificateStore::new(&root).unwrap();
        let timeout_certificates = VerifiedTimeoutCertificateStore::new(&root).unwrap();
        let finality = FinalityStore::new(&root).unwrap();
        let last_finalized = if replay {
            replay_verified_safety_state(
                &mut machine,
                &authority,
                &certificates,
                &timeout_certificates,
                &finality,
            )
            .unwrap()
        } else {
            None
        };
        let local = LocalConsensusSigner {
            validator_id: validator_id.into(),
            key_id: KeyId::new(key_id).unwrap(),
            signer: signer.clone(),
            chain_id: authority.epoch.chain_id,
            epoch: authority.epoch.epoch,
        };
        let delivery = ProposalDelivery::open(
            &root,
            &authority.epoch,
            &authority.registry,
            authority.as_ref(),
        )
        .unwrap();
        PosyService {
            preparation: None,
            mode: ConsensusMode::ValidateAndVote,
            authority_binding: configuration.consensus.authority_binding.clone().unwrap(),
            authority: authority.clone(),
            driver: SimplifiedPosyDriver::new(machine),
            recovery: Some(PosyRecoveryJournal::load(root.join("recovery.json")).unwrap()),
            finality: Some(finality),
            certificates,
            atomic_transitions: AtomicConsensusTransitionStore::new(&root).unwrap(),
            timeout_certificates,
            local_signer: Some(DurableSigningAuthority::new(
                SignOnceJournal::load(&journal_path).unwrap(),
                local,
            )),
            last_finalized,
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
            round_deadline: Instant::now() - Duration::from_secs(1),
            started: true,
            failure: None,
        }
    };
    let fresh_machine = || {
        SimplifiedConsensusStateMachine::new(
            authority.epoch.clone(),
            authority.registry.clone(),
            authority.anchor_parent.clone(),
        )
        .unwrap()
    };
    // Reopening from durable genuine QC/finality evidence must restore the
    // terminal marker. Repeat expired deadlines across two independent owners.
    for _restart in 0..2 {
        let mut service = make_service(fresh_machine(), true);
        let state = service.driver.state_machine();
        assert!(state.epoch_complete());
        assert_eq!(state.active_slot().0, authority.epoch.epoch_end_height);
        assert_eq!(
            state.highest_parent().height(),
            authority.epoch.epoch_end_height
        );
        let active = state.active_slot();
        let invalid = TimeoutVote {
            context: ConsensusObjectContext::for_height(&authority.epoch, active.0, active.1)
                .unwrap(),
            lease_index: authority.epoch.lease_index(active.0).unwrap(),
            timed_out_proposer: authority
                .epoch
                .authorized_proposer(active.0, active.1)
                .unwrap()
                .into(),
            highest_parent: state.highest_parent().clone(),
            previous_tc_id: None,
            last_voted_candidate: None,
            validator_id: validator_id.into(),
            key_id: key_id.into(),
            signature: Vec::new(),
        };
        assert!(validate_timeout_vote(
            &invalid,
            &authority.epoch,
            &authority.registry,
            authority.as_ref()
        )
        .unwrap_err()
        .to_string()
        .contains("future highest finality parent"));
        for _deadline in 0..3 {
            service.round_deadline = Instant::now() - Duration::from_secs(1);
            service.emit_timeout_vote().unwrap();
        }
        assert_eq!(service.driver.state_machine().active_slot(), active);
        assert!(service.emitted_slots.is_empty());
        assert!(service.retry_frames.is_empty());
        assert!(service.ingress.take_outbound().unwrap().is_none());
        assert_eq!(fs::read(&journal_path).ok(), before_journal);
        assert_eq!(service.last_finalized.as_ref(), Some(&before_finality));
    }
    // A live slot still emits an actual APQE-signed, locally validated timeout.
    // The correction cannot disable ordinary timeout progress inside an epoch.
    let mut ordinary = make_service(fresh_machine(), false);
    assert!(!ordinary.driver.state_machine().epoch_complete());
    ordinary.emit_timeout_vote().unwrap();
    assert!(ordinary.emitted_slots.contains(&SigningSlot {
        height: authority.epoch.epoch_start_height,
        round: 0,
        domain: "timeout-vote".into()
    }));
}
