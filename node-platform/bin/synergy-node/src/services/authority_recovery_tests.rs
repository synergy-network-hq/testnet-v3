//! Native, independently signed recovery/activation/restart matrix.
use super::*;
use synergy_address_engine::{apqe::provider::SignOptions, types::Algorithm};
use synergy_aegis::{AegisSigner, PqvmSigner};
use synergy_posy::{block_vote_signing_bytes, BlockVote, ConsensusObjectContext};

#[test]
#[ignore = "requires pinned native APQE artifacts"]
fn native_quorum_recovery_activation_restart_and_interrupted_witness() {
    exercise_native_recovery(false);
}

#[test]
#[ignore = "requires pinned native APQE artifacts"]
fn native_transport_verifies_published_transition_without_writer() {
    exercise_native_recovery(true);
}

fn exercise_native_recovery(read_only_transport: bool) {
    for end in [10_u64, 20] {
        let (root, mut config) =
            crate::services::socket_qualification::sync_poll_native_test_configuration();
        struct Cleanup(std::path::PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        let _cleanup = Cleanup(root.clone());
        config.consensus.mode = synergy_config::ConsensusMode::Observe;
        config.apqe_transport = None;
        config.vpn = synergy_config::VpnConfiguration::default();
        let engine = crate::services::apqe_provider::load(&config).unwrap();
        let pair = || {
            engine
                .lock()
                .unwrap()
                .generate_keypair(Algorithm::MlDsa65)
                .unwrap()
        };
        let original = pair();
        let replacement = pair();
        let keys = (0..5).map(|_| pair()).collect::<Vec<_>>();
        let make_signer = |id: &str, public: &[u8], secret: &[u8]| {
            PqvmSigner::with_apqe(
                AegisPolicy {
                    allowed_algorithms: vec![SignatureAlgorithm::MlDsa65],
                    maximum_message_bytes: 16 * 1024 * 1024,
                    maximum_signature_bytes: 16 * 1024,
                },
                KeyId::new(id).unwrap(),
                public,
                secret.to_vec(),
                engine.clone(),
            )
            .unwrap()
        };
        let old_signer = make_signer(
            "socket-qualification-root",
            &original.public_key,
            original.private_key.as_bytes(),
        );
        let new_signer = make_signer(
            "recovery-test-replacement",
            &replacement.public_key,
            replacement.private_key.as_bytes(),
        );
        let mut binding: SignedAuthorityBinding = serde_json::from_slice(
            &fs::read(config.consensus.authority_binding.as_ref().unwrap()).unwrap(),
        )
        .unwrap();
        // The shared poll fixture has signed authority/provider inputs but no
        // signed Genesis. Construct the exact format-2 artifact here rather
        // than assuming that an optional fixture Genesis path exists.
        for (validator, pair) in binding.payload.validators.iter_mut().zip(&keys) {
            validator.public_key = pair.public_key.clone();
        }
        let policy = binding
            .payload
            .protected
            .as_ref()
            .expect("processing fixture policy");
        let unsigned = synergy_genesis::builder::UnsignedGenesis {
            format_version: 2,
            network: synergy_genesis::network::GenesisNetwork {
                chain_id: config.chain_id,
                network_id: config.network_id.clone(),
                protocol_version: synergy_posy::POSY_SIMPLIFIED_PROTOCOL_VERSION.into(),
                activation_unix: policy.epoch_start_timestamp_ms / 1000,
            },
            validators: binding
                .payload
                .validators
                .iter()
                .map(
                    |validator| synergy_genesis::validator_set::GenesisValidator {
                        record: validator.record.clone(),
                        algorithm: validator.algorithm,
                        public_key: validator.public_key.clone(),
                    },
                )
                .collect(),
            etdag: synergy_genesis::etdag::GenesisEtdag {
                parameters: policy.parameters.clone(),
                cryptographic_profile_root: policy.cryptographic_profile_root.clone(),
                ingress_kem_registry_root: policy.ingress_kem_registry.root().unwrap(),
            },
            initial_state_root: synergy_genesis::state_root(&policy.initial_world_state).unwrap(),
            authority_trust_key_id: "socket-qualification-root".into(),
        };
        let genesis = synergy_genesis::signing::sign(
            unsigned,
            &old_signer,
            KeyId::new("socket-qualification-root").unwrap(),
        )
        .unwrap();
        config.genesis_path = Some(root.join("recovery-genesis.sgen"));
        binding.payload.epoch_end_height = end;
        binding.payload.anchor_parent = SimplifiedFinalityParent::Genesis {
            genesis_hash: genesis.genesis_hash.clone(),
            block_id: genesis.genesis_hash.clone(),
            reference_id: synergy_posy::canonical_hash(
                "SYNERGY_FRESH_GENESIS_REFERENCE_V1",
                &(
                    config.chain_id,
                    &config.network_id,
                    1_u64,
                    &genesis.genesis_hash,
                    &genesis.unsigned.initial_state_root,
                ),
            )
            .unwrap(),
        };
        binding.payload.finalized_epoch_seed_root = synergy_posy::canonical_hash(
            "SYNERGY_FRESH_GENESIS_EPOCH_SEED_V1",
            &(
                config.chain_id,
                &config.network_id,
                1_u64,
                &genesis.genesis_hash,
            ),
        )
        .unwrap();
        binding.signature = old_signer
            .sign(
                &KeyId::new("socket-qualification-root").unwrap(),
                &SigningContext {
                    domain: synergy_genesis::authority::AUTHORITY_SIGNING_DOMAIN.into(),
                    chain_id: config.chain_id,
                    epoch: Some(1),
                    height: None,
                },
                &binding.payload.signing_bytes().unwrap(),
            )
            .unwrap()
            .bytes;
        let prior_bytes = serde_json::to_vec(&binding).unwrap();
        fs::write(
            config.consensus.authority_binding.as_ref().unwrap(),
            &prior_bytes,
        )
        .unwrap();
        fs::write(
            config.consensus.authority_trust_key_path.as_ref().unwrap(),
            &original.public_key,
        )
        .unwrap();
        fs::write(
            config.genesis_path.as_ref().unwrap(),
            serde_json::to_vec(&genesis).unwrap(),
        )
        .unwrap();
        let mut manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(&config.manifest_path).unwrap()).unwrap();
        manifest["genesis_hash"] = serde_json::json!(genesis.genesis_hash);
        fs::write(
            &config.manifest_path,
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        let previous = load(&config).unwrap().unwrap();
        let world = binding
            .payload
            .protected
            .as_ref()
            .unwrap()
            .initial_world_state
            .clone();
        let world_root = synergy_state::state_root(&world).unwrap();
        let layout = NodeStorageLayout::new(config.storage.data_directory.clone()).unwrap();
        let posy = layout.consensus().join("posy");
        let qcs = synergy_posy::VerifiedQuorumCertificateStore::new(&posy).unwrap();
        let atomic = synergy_posy::persistence::AtomicConsensusTransitionStore::new(&posy).unwrap();
        let mut parent = previous.anchor_parent.clone();
        let mut finality = ThreeQcFinality::default();
        let mut final_records = Vec::new();
        let mut certificates = Vec::new();
        let mut anchor_candidate = None;
        for height in 1..=end {
            let material = synergy_etdag::execution::ProtectedProposalMaterial {
                material_version: 2,
                height,
                execution_root: synergy_etdag::EtdagDigest::from_domain_bytes(
                    "recovery-fixture",
                    b"execution",
                ),
                next_batch_root: synergy_etdag::EtdagDigest::from_domain_bytes(
                    "recovery-fixture",
                    b"next",
                ),
                cutoff_boundary_root: synergy_etdag::EtdagDigest::from_domain_bytes(
                    "recovery-fixture",
                    b"cutoff",
                ),
            };
            let mut candidate = synergy_execution::ExecutionCandidate {
                resource_permit: None,
                height,
                block_id: String::new(),
                parent_block_id: parent.block_id().into(),
                protected_execution_root: synergy_block::hash_block_bytes(
                    &material.commitment_bytes().unwrap(),
                ),
                protected_material: material.into(),
                state_root: world_root.clone(),
                transactions: vec![],
                receipts: vec![],
                state: Arc::new(world.clone()),
            };
            candidate.block_id = candidate.commitment_id().unwrap();
            candidate.validate().unwrap();
            let votes = keys
                .iter()
                .enumerate()
                .take(4)
                .map(|(index, key)| {
                    let record = &binding.payload.validators[index].record;
                    let mut vote = BlockVote {
                        context: ConsensusObjectContext::for_height(&previous.epoch, height, 0)
                            .unwrap(),
                        block_id: candidate.block_id.clone(),
                        parent_block_id: parent.block_id().into(),
                        parent: parent.clone(),
                        takeover_tc_id: None,
                        protected_execution_root: candidate.protected_execution_root.clone(),
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
            qc.verify(&previous.epoch, &previous.registry, previous.as_ref())
                .unwrap();
            finality.accept(qc.clone()).unwrap();
            if let Some(record) = finality.last_finalized() {
                atomic
                    .commit_verified_qc_and_finality(
                        &qc,
                        record,
                        final_records.last(),
                        &previous.epoch,
                        &previous.registry,
                        previous.as_ref(),
                    )
                    .unwrap();
                final_records.push(record.clone());
            } else {
                qcs.put_verified(&qc, &previous.epoch, &previous.registry, previous.as_ref())
                    .unwrap();
            }
            parent = SimplifiedFinalityParent::QuorumCertificate {
                height,
                block_id: qc.block_id.clone(),
                qc_id: qc.id().unwrap(),
            };
            certificates.push(qc);
            if height == end - 2 {
                anchor_candidate = Some(candidate);
            }
        }
        let witness = Witness {
            finalized: final_records.last().unwrap().clone(),
            certificates: certificates[certificates.len() - 3..]
                .to_vec()
                .try_into()
                .unwrap(),
        };
        let record = &binding.payload.validators[0].record;
        crate::services::posy::epoch_boundary_qualification::qualify_terminal_epoch_timeout(
            &config,
            previous.clone(),
            Arc::new(make_signer(
                &record.consensus_key_id,
                &keys[0].public_key,
                keys[0].private_key.as_bytes(),
            )),
            &record.validator_id,
            &record.consensus_key_id,
        );
        let mut next = binding.clone();
        next.signer_key_id = "recovery-test-replacement".into();
        next.payload.epoch = 2;
        next.payload.epoch_start_height = end + 1;
        next.payload.epoch_end_height = end * 2;
        next.payload.anchor_parent = parent;
        next.payload
            .protected
            .as_mut()
            .unwrap()
            .epoch_start_timestamp_ms += next
            .payload
            .protected
            .as_ref()
            .unwrap()
            .target_block_time_ms
            * end;
        next.payload.consensus_parameter_root = next
            .payload
            .protected
            .as_ref()
            .unwrap()
            .commitment()
            .unwrap();
        next.signature = new_signer
            .sign(
                &KeyId::new(next.signer_key_id.clone()).unwrap(),
                &SigningContext {
                    domain: synergy_genesis::authority::AUTHORITY_SIGNING_DOMAIN.into(),
                    chain_id: config.chain_id,
                    epoch: Some(2),
                    height: None,
                },
                &next.payload.signing_bytes().unwrap(),
            )
            .unwrap()
            .bytes;
        let next_bytes = serde_json::to_vec(&next).unwrap();
        let verified = prepare_verified(
            &config,
            serde_json::to_vec(&witness).unwrap(),
            next_bytes.clone(),
            replacement.public_key.clone(),
            prior_bytes.clone(),
        )
        .unwrap();
        let approvals = keys
            .iter()
            .enumerate()
            .take(4)
            .map(|(i, key)| Attestation {
                validator_id: binding.payload.validators[i].record.validator_id.clone(),
                key_id: binding.payload.validators[i]
                    .record
                    .consensus_key_id
                    .clone(),
                signature: engine
                    .lock()
                    .unwrap()
                    .sign(
                        Algorithm::MlDsa65,
                        key.private_key.as_bytes(),
                        &verified.signing_bytes,
                        SignOptions::default(),
                    )
                    .unwrap(),
            })
            .collect();
        let mut certificate = Certificate {
            version: 1,
            previous_authority_binding: prior_bytes.clone(),
            witness: witness.clone(),
            successor_authority_binding: next_bytes.clone(),
            replacement_root: replacement.public_key.clone(),
            attestations: approvals,
        };
        verify_certificate(&config, &certificate).unwrap();
        let fourth = certificate.attestations.pop().unwrap();
        assert!(verify_certificate(&config, &certificate)
            .err()
            .unwrap()
            .contains("lacks frozen dual quorum"));
        certificate.attestations.push(fourth);
        let certificate_path = root.join("recovery-certificate.json");
        fs::write(&certificate_path, serde_json::to_vec(&certificate).unwrap()).unwrap();
        config.consensus.authority_recovery_certificate_path = Some(certificate_path.clone());
        assert!(activate_observer(&config)
            .unwrap_err()
            .contains("restricted to non-signing RPC"));
        let mut observer = config.clone();
        observer.role = synergy_protocol_types::NodeRole::RpcGateway;
        observer.consensus.signing_key_path = None;
        observer.storage.data_directory = root.join("observer-data");
        observer.consensus.authority_binding = Some(root.join("observer-authority.json"));
        fs::write(
            observer.consensus.authority_binding.as_ref().unwrap(),
            &prior_bytes,
        )
        .unwrap();
        assert_eq!(
            activate_observer(&observer).unwrap()["validator_finality_imported"],
            false
        );
        assert_eq!(activate_observer(&observer).unwrap()["repeated"], true);
        assert_eq!(load(&observer).unwrap().unwrap().epoch.epoch, 2);
        assert!(
            !NodeStorageLayout::new(observer.storage.data_directory.clone())
                .unwrap()
                .state()
                .exists()
        );
        observer.consensus.mode = synergy_config::ConsensusMode::ValidateAndVote;
        assert!(activate_observer(&observer)
            .unwrap_err()
            .contains("restricted to non-signing RPC"));
        // The certificate cannot install state or leap over an unrecovered node.
        assert!(activate(&config)
            .unwrap_err()
            .contains("existing recovered execution"));
        let mut execution =
            synergy_state::FinalizedStateStore::load(layout.state().join("execution")).unwrap();
        let candidate = anchor_candidate.unwrap();
        execution
            .commit_verified_snapshot(
                synergy_state::FinalizedState {
                    finalized_height: end - 3,
                    finalized_block_id: "stale-anchor".into(),
                    state_root: world_root.clone(),
                },
                &world,
            )
            .unwrap();
        assert!(activate(&config)
            .unwrap_err()
            .contains("exact recovered durable"));
        execution
            .commit_verified_snapshot(
                synergy_state::FinalizedState {
                    finalized_height: end - 2,
                    finalized_block_id: candidate.block_id.clone(),
                    state_root: world_root.clone(),
                },
                &world,
            )
            .unwrap();
        drop(execution);
        assert!(activate(&config)
            .unwrap_err()
            .contains("execution candidate"));
        synergy_execution::CandidateStore::new(layout.blocks().join("execution-candidates"))
            .unwrap()
            .put_once(&candidate, &world)
            .unwrap();
        // Populate the real epoch-one owner namespace before activation, so
        // registration cannot accidentally qualify only an empty new store.
        let old_ingress = crate::services::ingress::AuthenticatedIngress::default();
        let (_, old_execution_owner) =
            crate::services::execution::registration(&config, previous.clone(), old_ingress)
                .unwrap();
        drop(old_execution_owner);
        let signing_path = config.consensus.signing_key_path.as_ref().unwrap();
        fs::write(signing_path, keys[0].private_key.as_bytes()).unwrap();
        let journal = posy.join("sign-once.json");
        synergy_posy::persistence::SignOnceJournal::load(&journal)
            .unwrap()
            .advance_finalized_floor(witness.finalized.height)
            .unwrap();
        let journal_before = fs::read(&journal).unwrap();
        let transition_store = AtomicStore::new(
            layout.consensus().join("authority-transitions"),
            4 * 1024 * 1024,
        )
        .unwrap();
        let transition = StoredEpochTransition {
            version: 1,
            next_epoch: 2,
            previous_authority_binding: prior_bytes.clone(),
            finalized: witness.finalized.clone(),
            finality_witness: serde_json::to_vec(&witness.certificates).unwrap(),
        };
        let transition_path = "epoch-00000000000000000002.json";
        // Crash after witness commit but before authority rename: restart must
        // retain the exact witnessed transition and finish idempotently.
        transition_store
            .write_atomic(transition_path, &serde_json::to_vec(&transition).unwrap())
            .unwrap();
        assert_eq!(activate(&config).unwrap()["repeated"], false);
        assert_eq!(activate(&config).unwrap()["repeated"], true);
        let restarted = load(&config).unwrap().unwrap();
        assert_eq!(restarted.epoch.epoch, 2);
        assert_eq!(
            load_transition_finality_prefix(&config, &restarted)
                .unwrap()
                .unwrap()
                .0,
            witness.finalized
        );
        if read_only_transport {
            verify_published_witness_without_writer(&config, &restarted, &witness.finalized);
            continue;
        }
        assert_eq!(fs::read(&journal).unwrap(), journal_before);
        assert_eq!(
            fs::read(config.consensus.authority_trust_key_path.as_ref().unwrap()).unwrap(),
            original.public_key
        );
        let genesis_after = fs::read(config.genesis_path.as_ref().unwrap()).unwrap();
        assert_eq!(
            serde_json::from_slice::<synergy_genesis::signing::SignedGenesis>(&genesis_after)
                .unwrap(),
            genesis
        );
        // Qualify the actual successor service registration boundary, not only
        // authority parsing. Initial shared ingress is intentionally empty, as
        // in real startup before the PoSy owner publishes recovered finality.
        let ingress = crate::services::ingress::AuthenticatedIngress::default();
        let (_, mut etdag_owner) = crate::services::etdag::registration_with_admission(
            &config,
            restarted.clone(),
            ingress.clone(),
            None,
        )
        .unwrap();
        let (_, mut execution_owner) =
            crate::services::execution::registration(&config, restarted.clone(), ingress.clone())
                .unwrap();
        let (_, mut posy_owner) = crate::services::posy::registration_with_preparation(
            &config,
            restarted.clone(),
            ingress.clone(),
            None,
        )
        .unwrap();
        let cancellation = synergy_node_core::CancellationToken::default();
        for owner in [&mut etdag_owner, &mut execution_owner, &mut posy_owner] {
            owner.start(&cancellation).unwrap();
        }
        for owner in [&mut etdag_owner, &mut execution_owner, &mut posy_owner] {
            owner.stop().unwrap();
        }
        assert_eq!(fs::read(&journal).unwrap(), journal_before);
        // No fallback when the configured certificate is damaged or absent.
        certificate.attestations[0].signature[0] ^= 1;
        fs::write(&certificate_path, serde_json::to_vec(&certificate).unwrap()).unwrap();
        assert!(load(&config).is_err());
        config.consensus.authority_recovery_certificate_path = None;
        assert!(load(&config).is_err());
        assert_eq!(
            fs::read(config.consensus.authority_binding.as_ref().unwrap()).unwrap(),
            next_bytes
        );
    }
}

fn verify_published_witness_without_writer(
    config: &NodeConfiguration,
    restarted: &VerifiedAuthority,
    finalized: &FinalizedBlockRecord,
) {
    // Verify the atomically published proof with the writer unavailable.
    let published_path = transition_witness_path(config, restarted).unwrap().unwrap();
    let writer_lock = published_path.with_file_name(".synergy-writer.lock");
    let saved_lock = writer_lock.with_extension("saved");
    fs::rename(&writer_lock, &saved_lock).unwrap();
    fs::create_dir(&writer_lock).unwrap();
    assert!(load_transition_finality_prefix(config, restarted).is_err());
    let published =
        crate::services::apqe_transport::read(&published_path, 4 * 1024 * 1024, false).unwrap();
    let authenticated = verify_stored_transition(config, restarted, &published).unwrap();
    assert_eq!(authenticated.finalized, *finalized);
    let mut altered: StoredEpochTransition = serde_json::from_slice(&published).unwrap();
    altered.next_epoch += 1;
    assert!(verify_stored_transition(
        config,
        restarted,
        &serde_json::to_vec(&altered).unwrap()
    ).is_err());
    fs::remove_dir(&writer_lock).unwrap();
    fs::rename(&saved_lock, &writer_lock).unwrap();
}

/// Native five-custody fixture transition. Reuses production recovery verifiers;
/// no test can construct an activated authority without genuine quorum approval.
pub(in crate::services) fn activate_real_socket_fixture(configurations: &mut [NodeConfiguration]) {
    assert_eq!(configurations.len(), 5);
    let configuration = &configurations[0];
    let previous = load(configuration).unwrap().unwrap();
    assert_eq!(previous.epoch.epoch_end_height, 20);
    let layout = NodeStorageLayout::new(configuration.storage.data_directory.clone()).unwrap();
    let qcs =
        synergy_posy::VerifiedQuorumCertificateStore::new(layout.consensus().join("posy")).unwrap();
    let certificates = (18..=20)
        .map(|height| {
            qcs.get_verified(
                height,
                &previous.epoch,
                &previous.registry,
                previous.as_ref(),
            )
            .unwrap()
            .unwrap()
        })
        .collect::<Vec<_>>();
    let finalized = synergy_posy::persistence::FinalityStore::new(layout.consensus().join("posy"))
        .unwrap()
        .get(18)
        .unwrap()
        .unwrap();
    let witness = Witness {
        finalized,
        certificates: certificates.try_into().unwrap(),
    };
    let prior_bytes = previous.binding_bytes().to_vec();
    let mut candidate: SignedAuthorityBinding = serde_json::from_slice(&prior_bytes).unwrap();
    let engine = crate::services::apqe_provider::load(configuration).unwrap();
    let replacement = engine
        .lock()
        .unwrap()
        .generate_keypair(Algorithm::MlDsa65)
        .unwrap();
    candidate.signer_key_id = "native-socket-recovery-replacement".into();
    candidate.payload.epoch = 2;
    candidate.payload.epoch_start_height = 21;
    candidate.payload.epoch_end_height = 40;
    candidate.payload.anchor_parent = SimplifiedFinalityParent::QuorumCertificate {
        height: 20,
        block_id: witness.certificates[2].block_id.clone(),
        qc_id: witness.certificates[2].id().unwrap(),
    };
    let policy = candidate.payload.protected.as_mut().unwrap();
    policy.epoch_start_timestamp_ms += policy.target_block_time_ms * 20;
    candidate.payload.consensus_parameter_root = policy.commitment().unwrap();
    let signer = PqvmSigner::with_apqe(
        AegisPolicy {
            allowed_algorithms: vec![SignatureAlgorithm::MlDsa65],
            maximum_message_bytes: 16 * 1024 * 1024,
            maximum_signature_bytes: 16 * 1024,
        },
        KeyId::new(candidate.signer_key_id.clone()).unwrap(),
        &replacement.public_key,
        replacement.private_key.as_bytes().to_vec(),
        engine.clone(),
    )
    .unwrap();
    candidate.signature = signer
        .sign(
            &KeyId::new(candidate.signer_key_id.clone()).unwrap(),
            &SigningContext {
                domain: synergy_genesis::authority::AUTHORITY_SIGNING_DOMAIN.into(),
                chain_id: configuration.chain_id,
                epoch: Some(2),
                height: None,
            },
            &candidate.payload.signing_bytes().unwrap(),
        )
        .unwrap()
        .bytes;
    let successor = serde_json::to_vec(&candidate).unwrap();
    let verified = prepare_verified(
        configuration,
        serde_json::to_vec(&witness).unwrap(),
        successor.clone(),
        replacement.public_key.clone(),
        prior_bytes.clone(),
    )
    .unwrap();
    let attestations = configurations
        .iter()
        .map(|config| {
            let inputs = crate::services::apqe_provider::custody_inputs(config, &previous).unwrap();
            let validator_id = inputs.request.payload.identity.address.clone();
            drop(inputs);
            let (key_id, _) = previous.consensus_binding(&validator_id).unwrap();
            let signer = crate::services::apqe_provider::consensus_signer(
                config,
                &previous,
                &validator_id,
                AegisPolicy {
                    allowed_algorithms: vec![SignatureAlgorithm::MlDsa65],
                    maximum_message_bytes: MAX_CONSENSUS_MESSAGE_BYTES,
                    maximum_signature_bytes: 16 * 1024,
                },
            )
            .unwrap();
            let signature = signer
                .sign(
                    &KeyId::new(key_id.to_owned()).unwrap(),
                    &SigningContext {
                        domain: DOMAIN.into(),
                        chain_id: config.chain_id,
                        epoch: Some(1),
                        height: None,
                    },
                    &verified.signing_bytes,
                )
                .unwrap()
                .bytes;
            Attestation {
                validator_id,
                key_id: key_id.to_owned(),
                signature,
            }
        })
        .collect();
    let certificate = Certificate {
        version: 1,
        previous_authority_binding: prior_bytes,
        witness,
        successor_authority_binding: successor,
        replacement_root: replacement.public_key,
        attestations,
    };
    verify_certificate(configuration, &certificate).unwrap();
    let certificate_path = configuration
        .genesis_path
        .as_ref()
        .unwrap()
        .parent()
        .unwrap()
        .join("native-socket-recovery-certificate.json");
    fs::write(&certificate_path, serde_json::to_vec(&certificate).unwrap()).unwrap();
    for config in configurations {
        let layout = NodeStorageLayout::new(config.storage.data_directory.clone()).unwrap();
        let journal = layout.consensus().join("posy/sign-once.json");
        let before = fs::read(&journal).ok();
        config.consensus.authority_recovery_certificate_path = Some(certificate_path.clone());
        assert_eq!(activate(config).unwrap()["status"], "activated");
        assert_eq!(activate(config).unwrap()["repeated"], true);
        assert_eq!(fs::read(&journal).ok(), before);
        assert_eq!(load(config).unwrap().unwrap().epoch.epoch, 2);
    }
}
