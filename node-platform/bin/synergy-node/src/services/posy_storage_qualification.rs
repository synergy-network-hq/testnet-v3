//! Real ML-DSA-65 proof/storage growth qualification. No sockets, encrypted
//! execution, deployed chain, TPS or wall-clock consensus performance claim.
use super::*;
use synergy_aegis::PqvmVerifier;
use synergy_posy::persistence::ConsensusEvidenceReader;
use synergy_posy::{
    block_vote_signing_bytes, CertifiedCandidateSubject, FinalizedBlockRecord,
    ProposalValidationCertificate, SimplifiedEpochContext, SimplifiedFinalityParent,
};

fn bounded_env(name: &str, default: u64, maximum: u64) -> u64 {
    let value = std::env::var(name).unwrap_or_else(|_| default.to_string());
    assert!(
        !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()),
        "{name}: decimal required"
    );
    let number = value.parse::<u64>().expect("bounded height count overflow");
    assert!(
        (1..=maximum).contains(&number),
        "{name}: outside1..={maximum}"
    );
    number
}
fn inventory(root: &std::path::Path) -> serde_json::Value {
    let mut pending = vec![root.to_path_buf()];
    let mut files = 0u64;
    let mut logical = 0u64;
    let mut allocated = 0u64;
    let mut segments = 0u64;
    while let Some(root) = pending.pop() {
        for entry in std::fs::read_dir(root).unwrap() {
            let path = entry.unwrap().path();
            let metadata = std::fs::symlink_metadata(&path).unwrap();
            assert!(!metadata.is_symlink());
            if metadata.is_dir() {
                pending.push(path);
                continue;
            }
            assert!(metadata.is_file());
            files += 1;
            logical += metadata.len();
            if path.extension().is_some_and(|value| value == "sya") {
                segments += 1;
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                allocated += metadata.blocks() * 512;
            }
        }
    }
    serde_json::json!({"files":files,"logical_bytes":logical,"allocated_bytes":allocated,"segment_files":segments})
}
fn process_io() -> Option<String> {
    std::fs::read_to_string("/proc/self/io").ok()
}
fn process_memory() -> Option<String> {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .map(|status| {
            status
                .lines()
                .filter(|line| line.starts_with("VmRSS:") || line.starts_with("VmHWM:"))
                .collect::<Vec<_>>()
                .join("; ")
        })
}
fn append_sample(value: &serde_json::Value) {
    println!(
        "POSY_REAL_GROWTH_SAMPLE {}",
        serde_json::to_string(value).unwrap()
    );
}
#[test]
#[ignore = "real PQ signatures and durable disk writes; explicit isolated qualification only"]
fn real_signed_finality_storage_growth() {
    qualify_real_signed_finality_storage_growth(false);
}
#[test]
#[ignore = "explicit authenticated APQE native report and isolated durable disk qualification"]
fn real_apqe_signed_finality_storage_growth() {
    qualify_real_signed_finality_storage_growth(true);
}
fn qualify_real_signed_finality_storage_growth(apqe: bool) {
    let heights = bounded_env("SYNERGY_POSY_GROWTH_HEIGHTS", 32, 100000);
    let maximum_seconds = bounded_env("SYNERGY_POSY_GROWTH_MAX_SECONDS", 43200, 86400);
    let root = PathBuf::from(
        std::env::var_os("SYNERGY_POSY_GROWTH_ROOT").expect("new disposable growth root required"),
    );
    assert!(root.is_absolute() && !root.exists() && !root.is_symlink());
    std::fs::create_dir(&root).unwrap();
    struct Cleanup(PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let _cleanup = Cleanup(root.clone());
    let data = root.join("posy");
    let fleet = Fleet::new();
    let mut authority = (*fleet.authority).clone();
    let engine = if apqe {
        let report =
            std::env::var("APQE_TRUSTED_NATIVE_REPORT").expect("explicit trusted report path");
        let digest = std::env::var("APQE_AUTHENTICATED_REPORT_SHA256")
            .expect("explicit authenticated report digest");
        assert!(
            digest.len() == 64
                && digest
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        );
        let mut hash = [0; 32];
        for (i, byte) in hash.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&digest[2 * i..2 * i + 2], 16).unwrap();
        }
        // Explicit isolated-test operator authenticates and protects these artifacts.
        let engine = Arc::new(std::sync::Mutex::new(
            unsafe {
                synergy_address_engine::apqe::native_manifest::validator_engine(
                    std::path::Path::new(&report),
                    hash,
                )
            }
            .unwrap(),
        ));
        authority.qualification_verifier(
            PqvmVerifier::with_apqe(
                AegisPolicy {
                    allowed_algorithms: vec![SignatureAlgorithm::MlDsa65],
                    maximum_message_bytes: 1024 * 1024,
                    maximum_signature_bytes: 16 * 1024,
                },
                engine.clone(),
            )
            .unwrap(),
        );
        Some(engine)
    } else {
        None
    };

    authority.epoch = SimplifiedEpochContext::from_frozen_registry(
        1266,
        "qualification".into(),
        1,
        1,
        heights + 2,
        "a".repeat(64),
        "b".repeat(64),
        &authority.registry,
    )
    .unwrap();
    let mut signers = Vec::new();
    for index in 0..5 {
        let key_id = KeyId::new(format!("key-{index}")).unwrap();
        signers.push(LocalConsensusSigner {
            validator_id: format!("qualification-{index}"),
            key_id: key_id.clone(),
            signer: Arc::new({
                let policy = AegisPolicy {
                    allowed_algorithms: vec![SignatureAlgorithm::MlDsa65],
                    maximum_message_bytes: 1024 * 1024,
                    maximum_signature_bytes: 16 * 1024,
                };
                match engine.as_ref() {
                    Some(engine) => PqvmSigner::with_apqe(
                        policy,
                        key_id,
                        authority
                            .consensus_binding(&format!("qualification-{index}"))
                            .unwrap()
                            .1,
                        fleet.secrets[index].clone(),
                        engine.clone(),
                    )
                    .unwrap(),
                    None => PqvmSigner::from_secret_key_bytes(
                        policy,
                        key_id,
                        fleet.secrets[index].clone(),
                    )
                    .unwrap(),
                }
            }),
            chain_id: 1266,
            epoch: 1,
        });
    }
    let mut local = DurableSigningAuthority::new(
        SignOnceJournal::load(data.join("sign-once.json")).unwrap(),
        signers.remove(0),
    );
    let qcs = VerifiedQuorumCertificateStore::new(&data).unwrap();
    let transitions = AtomicConsensusTransitionStore::new(&data).unwrap();
    let delivery =
        ProposalDelivery::open(&data, &authority.epoch, &authority.registry, &authority).unwrap();
    let reader = ConsensusEvidenceReader::open(&data).unwrap();
    let mut finality = ThreeQcFinality::default();
    let mut previous = None;
    let mut parent = authority.anchor_parent.clone();
    let start = Instant::now();
    let io_before = process_io();
    let mut raw_signatures = 0u64;
    let mut expected = BTreeMap::<u64, FinalizedBlockRecord>::new();
    for height in 1..=heights + 2 {
        assert!(
            start.elapsed().as_secs() < maximum_seconds,
            "qualification deadline reached; disposable fixture will be removed"
        );
        let context = ConsensusObjectContext::for_height(&authority.epoch, height, 0).unwrap();
        let subject = CertifiedCandidateSubject::new(
            context.clone(),
            synergy_posy::canonical_hash("GROWTH_TEST_BLOCK_V1", &height).unwrap(),
            parent.block_id().into(),
            parent.clone(),
            synergy_posy::canonical_hash("GROWTH_TEST_EXECUTION_V1", &height).unwrap(),
        )
        .unwrap();
        let subject_id = subject.id().unwrap();
        let mut votes = Vec::new();
        let mut echoes = Vec::new();
        if authority.epoch.authorized_proposer(height, 0).unwrap() == "qualification-0" {
            let proposal = SimplifiedProposal {
                context: context.clone(),
                proposer_id: "qualification-0".into(),
                block_id: subject.block_id.clone(),
                parent_block_id: subject.parent_block_id.clone(),
                parent: parent.clone(),
                takeover_tc_id: None,
                protected_execution_root: subject.protected_execution_root.clone(),
                proposer_key_id: "key-0".into(),
                proposer_signature: Vec::new(),
            };
            let signature = local
                .sign_once(
                    SigningSlot {
                        height,
                        round: 0,
                        domain: "proposal".into(),
                    },
                    synergy_posy::POSY_SIMPLIFIED_PROPOSAL_DOMAIN,
                    &subject_id,
                    &proposal.signing_bytes().unwrap(),
                )
                .unwrap();
            assert_eq!(signature.len(), 3309);
            raw_signatures += 3309;
        }
        for index in 0..4 {
            let mut vote = BlockVote {
                context: context.clone(),
                block_id: subject.block_id.clone(),
                parent_block_id: subject.parent_block_id.clone(),
                parent: parent.clone(),
                takeover_tc_id: None,
                protected_execution_root: subject.protected_execution_root.clone(),
                validator_id: format!("qualification-{index}"),
                key_id: format!("key-{index}"),
                signature: Vec::new(),
            };
            let transcript = block_vote_signing_bytes(&vote).unwrap();
            vote.signature = if index == 0 {
                local
                    .sign_once(
                        SigningSlot {
                            height,
                            round: 0,
                            domain: "block-vote".into(),
                        },
                        synergy_posy::POSY_SIMPLIFIED_BLOCK_VOTE_DOMAIN,
                        &subject_id,
                        &transcript,
                    )
                    .unwrap()
            } else {
                signers[index - 1]
                    .sign(
                        synergy_posy::POSY_SIMPLIFIED_BLOCK_VOTE_DOMAIN,
                        height,
                        &transcript,
                    )
                    .unwrap()
            };
            assert_eq!(vote.signature.len(), 3309);
            raw_signatures += 3309;
            votes.push(vote);
            let mut echo = ProposalDeliveryStatement {
                context: context.clone(),
                phase: ProposalDeliveryPhase::Echo,
                candidate: subject.clone(),
                validator_id: format!("qualification-{index}"),
                key_id: format!("key-{index}"),
                signature: Vec::new(),
            };
            let transcript = echo.signing_bytes().unwrap();
            echo.signature = if index == 0 {
                local
                    .sign_once(
                        SigningSlot {
                            height,
                            round: 0,
                            domain: "proposal-echo".into(),
                        },
                        synergy_posy::PROPOSAL_ECHO_DOMAIN,
                        &subject_id,
                        &transcript,
                    )
                    .unwrap()
            } else {
                signers[index - 1]
                    .sign(synergy_posy::PROPOSAL_ECHO_DOMAIN, height, &transcript)
                    .unwrap()
            };
            assert_eq!(echo.signature.len(), 3309);
            raw_signatures += 3309;
            echoes.push(echo);
        }
        let vc = ProposalValidationCertificate {
            context: context.clone(),
            candidate: subject.clone(),
            echoes,
        };
        delivery
            .persist_validation(&vc, &authority.epoch, &authority.registry, &authority)
            .unwrap();
        let mut ready = ProposalDeliveryStatement {
            context: context.clone(),
            phase: ProposalDeliveryPhase::Ready,
            candidate: subject.clone(),
            validator_id: "qualification-0".into(),
            key_id: "key-0".into(),
            signature: Vec::new(),
        };
        ready.signature = local
            .sign_once(
                SigningSlot {
                    height,
                    round: 0,
                    domain: "proposal-ready".into(),
                },
                synergy_posy::PROPOSAL_READY_DOMAIN,
                &subject_id,
                &ready.signing_bytes().unwrap(),
            )
            .unwrap();
        assert_eq!(ready.signature.len(), 3309);
        raw_signatures += 3309;
        delivery
            .persist_ready_envelope(
                &ProposalDeliveryEnvelope {
                    statement: ready,
                    validation_certificate: Some(vc),
                },
                &authority.epoch,
                &authority.registry,
                &authority,
            )
            .unwrap();
        let qc = SimplifiedQuorumCertificate::from_votes(votes).unwrap();
        qc.verify(&authority.epoch, &authority.registry, &authority)
            .unwrap();
        if let Some(record) = finality.accept(qc.clone()).unwrap() {
            transitions
                .commit_verified_qc_and_finality(
                    &qc,
                    &record,
                    previous.as_ref(),
                    &authority.epoch,
                    &authority.registry,
                    &authority,
                )
                .unwrap();
            local
                .record_verified_finalized_floor(record.height)
                .unwrap();
            delivery.retire_finalized_evidence(record.height).unwrap();
            if [1, heights / 2, heights].contains(&record.height) {
                expected.insert(record.height, record.clone());
            }
            previous = Some(record);
        } else {
            qcs.put_verified(&qc, &authority.epoch, &authority.registry, &authority)
                .unwrap();
        }
        parent = SimplifiedFinalityParent::QuorumCertificate {
            height,
            block_id: qc.block_id.clone(),
            qc_id: qc.id().unwrap(),
        };
        if height % 1000 == 0 || height == heights + 2 {
            let statistics = reader.inspection_statistics().unwrap();
            assert!(
                statistics["hot_ready_rows"].as_u64().unwrap() <= 11,
                "hot READY failed to plateau"
            );
            append_sample(
                &serde_json::json!({"certified_height":height,"finalized_height":previous.as_ref().map(|r|r.height),"elapsed_seconds":start.elapsed().as_secs_f64(),"inventory":inventory(&data),"statistics":statistics,"process_io":process_io(),"process_memory":process_memory()}),
            );
        }
    }
    assert_eq!(previous.as_ref().unwrap().height, heights);
    let statistics = reader.inspection_statistics().unwrap();
    assert_eq!(statistics["archive_finality"], heights);
    assert_eq!(
        statistics["raw_3309_byte_array_bytes"], raw_signatures,
        "duplicate PQ blobs or missing unique signatures"
    );
    drop((reader, delivery, transitions, qcs, local, signers));
    let restart = Instant::now();
    let replay = offline_replay_stopped_copy(&data, &authority);
    let restart_seconds = restart.elapsed().as_secs_f64();
    assert_eq!(
        replay["verified_finality"],
        serde_json::to_value(previous.as_ref().unwrap()).unwrap()
    );
    let reader = ConsensusEvidenceReader::open(&data).unwrap();
    let finality_store = FinalityStore::new(&data).unwrap();
    let qcs = VerifiedQuorumCertificateStore::new(&data).unwrap();
    for (height, record) in expected {
        assert_eq!(finality_store.get(height).unwrap().unwrap(), record);
        let mut proof = ThreeQcFinality::default();
        for h in height..=height + 2 {
            proof
                .accept(
                    qcs.get_verified(h, &authority.epoch, &authority.registry, &authority)
                        .unwrap()
                        .unwrap(),
                )
                .unwrap();
        }
        assert_eq!(proof.last_finalized(), Some(&record));
        assert!(reader
            .read_archived_exact(format!("validation-h{height}.json"))
            .unwrap()
            .is_some());
    }
    let result = serde_json::json!({"format":"posy-real-signed-storage-growth-v1","finalized_heights":heights,"certified_heights":heights+2,"seconds":start.elapsed().as_secs_f64(),"restart_seconds":restart_seconds,"inventory":inventory(&data),"statistics":statistics,"unique_signature_bytes":raw_signatures,"signature_algorithm":"ML-DSA-65","provider_owner":if apqe {"APQE"} else {"legacy-fixture"},"bytes_per_signature":3309,"count_threshold":"strict4/5 plus frozenweight","process_io_before":io_before,"process_io_after":process_io(),"process_memory":process_memory(),"recovered":replay,
        "scope":"RealPQ signed QC+VC+localECHO/READY/vote and native3QC/floor persistence. No encrypted execution, sockets, state-world history, livechain, TPS or fsynccount claim. Inventoryallocatedbytes arest_blocks*512 notcumulativewrites. /procIO isprocesswide; warmOS-cache reopen."});
    println!(
        "POSY_REAL_GROWTH {}",
        serde_json::to_string(&result).unwrap()
    );
}
