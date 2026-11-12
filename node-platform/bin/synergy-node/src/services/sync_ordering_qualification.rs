//! Transport-only reproducer. No candidate is granted finality by this test.
use super::*;

#[test]
#[ignore = "requires explicitly authenticated immutable APQE native artifacts"]
fn queued_initial_chunk_is_overtaken_by_mailbox_fallback() {
    let entries = (0..synergy_posy::POSY_MIN_VALIDATOR_COUNT)
        .map(|i| {
            (
                synergy_posy::ValidatorRecord {
                    validator_id: format!("ordering-validator-{i}"),
                    consensus_key_id: format!("ordering-key-{i}"),
                    frozen_voting_weight: 1,
                    status: synergy_posy::ValidatorStatus::Active,
                },
                vec![0; 1952],
            )
        })
        .collect();
    // No signature operation occurs: this exercises decoding and assembly.
    let engine = synergy_aegis::load_authenticated_native_engine(
        std::path::Path::new(&std::env::var("APQE_TRUSTED_NATIVE_REPORT").unwrap()),
        &std::env::var("APQE_AUTHENTICATED_REPORT_SHA256").unwrap(),
    )
    .unwrap();
    let authority = authority::qualification_authority_with_provider(entries, Some(engine));
    let budget = synergy_state::world_resources::WorldResourceBudget::new(512 * 1024 * 1024);
    let mut pool = preparation::Pool::new().unwrap();
    let tag = preparation::AuthorityTag {
        incarnation: "ordered-wire-reproduction".into(),
        epoch: 1,
        authority_digest: "unchanged".into(),
    };
    let blocker = pool.handle().owner::<()>(tag.clone()).unwrap();
    let owner = pool.handle().owner::<PreparedSync>(tag).unwrap();
    let peer = AuthenticatedPeer::new(
        "synv11lrh6jcxaejkj4zv994j7qwn2rk6u3ar4emn",
        SessionId(1),
        vec![],
    )
    .unwrap();
    let request = FinalizedCandidateRequest {
        height: 11,
        expected_parent_id: "certified-parent".into(),
    };
    let bytes = vec![255; synergy_sync::CANDIDATE_CHUNK_BYTES + 1];
    let wire = |offset| {
        serde_json::to_vec(&SyncWireMessage::FinalizedCandidateChunk(
            CandidateResponseChunk {
                request: request.clone(),
                total_bytes: bytes.len(),
                digest: synergy_sync::candidate_response_digest(&bytes),
                offset,
                bytes: bytes
                    [offset..(offset + synergy_sync::CANDIDATE_CHUNK_BYTES).min(bytes.len())]
                    .to_vec(),
            },
        ))
        .unwrap()
    };
    let first = wire(0);
    let first_charge = preparation_charge(&first, first.capacity()).unwrap();
    let (release, wait) = std::sync::mpsc::channel();
    blocker
        .submit(
            preparation::Lane::Background,
            11,
            0,
            11,
            "busy".into(),
            BACKGROUND_MAILBOX_BYTES - first_charge - 1,
            move || {
                wait.recv_timeout(Duration::from_secs(5))
                    .map_err(|e| e.to_string())
            },
        )
        .unwrap();
    assert!(prepare_sync_wire(
        &owner,
        10,
        peer.clone(),
        first,
        authority.clone(),
        budget.clone()
    )
    .unwrap()
    .is_none());
    let tail = prepare_sync_wire(
        &owner,
        10,
        peer.clone(),
        wire(synergy_sync::CANDIDATE_CHUNK_BYTES),
        authority,
        budget.clone(),
    )
    .unwrap()
    .expect("newer tail takes the owner fallback while offset zero is queued");
    let decoded = synergy_sync::decode_budgeted_sync_wire(&tail.1, &budget).unwrap();
    let (SyncWireMessage::FinalizedCandidateChunk(chunk), _) = decoded.into_parts() else {
        panic!("expected candidate tail");
    };
    let mut assemblies = BTreeMap::new();
    assert!(push_candidate_chunk(&mut assemblies, &peer, chunk)
        .unwrap_err()
        .contains("awaits initial"));
    assert!(assemblies.is_empty());
    release.send(()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    let completion = loop {
        if let Some(completion) = owner.take().unwrap() {
            break completion;
        }
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(1));
    };
    let PreparedSync::Wire { message, .. } = completion.result.unwrap() else {
        panic!("expected initial chunk decode");
    };
    let (SyncWireMessage::FinalizedCandidateChunk(chunk), _) = message.into_parts() else {
        panic!("expected initial chunk");
    };
    assert_eq!(
        push_candidate_chunk(&mut assemblies, &peer, chunk).unwrap(),
        (true, None)
    );
    assert_eq!(assemblies.len(), 1, "received tail was discarded locally");
    pool.shutdown().unwrap();
}
