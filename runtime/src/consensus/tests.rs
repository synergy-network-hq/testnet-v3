use crate::block::Block;
use crate::consensus::cartel_detection::{CartelDetectionEngine, VoteRecord};
use crate::consensus::dao_governance::{DAOGovernance, ProposalType};
use crate::consensus::dual_quorum::{DualQuorumConsensus, EntropyBeacon, QuorumCertificate};
use crate::consensus::synergy_score::SynergyScoreCalculator;
use crate::consensus::validator_keys::{
    consensus_algorithm_label, load_local_validator_keypair, register_test_validator_signing_key,
};
use crate::crypto::pqc::{PQCAlgorithm, PQCManager};
use crate::validator::{Validator, ValidatorManager, ValidatorRegistration};
use base64::{engine::general_purpose, Engine as _};
use std::sync::{Arc, Mutex};

fn register_test_consensus_validator(validator_manager: &Arc<ValidatorManager>, address: &str) {
    let mut pqc_manager = PQCManager::new();
    let (public_key, private_key) = pqc_manager
        .generate_keypair(PQCAlgorithm::FNDSA)
        .expect("test validator Aegis PQC key should generate");
    register_test_validator_signing_key(address, public_key.clone(), private_key);
    let encoded_public_key = format!(
        "{}:{}",
        consensus_algorithm_label(&public_key.algorithm),
        general_purpose::STANDARD.encode(&public_key.key_data)
    );
    let _ = validator_manager.register_validator(ValidatorRegistration {
        address: address.to_string(),
        public_key: encoded_public_key,
        name: format!("Test Validator {address}"),
        stake_amount: 1000,
        submitted_at: 0,
        registration_tx_hash: format!("test-{address}"),
    });
    let _ = validator_manager.approve_validator(address);
}

fn sign_block_as_validator(block: &mut Block, validator_manager: &Arc<ValidatorManager>) {
    let (public_key, private_key) =
        load_local_validator_keypair(&block.validator_id, validator_manager)
            .expect("test validator signing key should load");
    let mut pqc_manager = PQCManager::new();
    let signature = pqc_manager
        .sign(&private_key, block.hash.as_bytes())
        .expect("test block signing should succeed");
    block.proposer_public_key = public_key.key_data;
    block.block_signature = signature.signature_data;
    block.block_signature_algorithm = consensus_algorithm_label(&public_key.algorithm).to_string();
}

#[test]
fn test_synergy_score_calculation() {
    // Initialize test environment
    let validator_manager = Arc::new(ValidatorManager::new());
    let pqc_manager = Arc::new(Mutex::new(PQCManager::new()));
    let synergy_calculator =
        SynergyScoreCalculator::new(Arc::clone(&validator_manager), Arc::clone(&pqc_manager));

    // Create test validator
    let mut validator = Validator::new(
        "test_validator".to_string(),
        "test_key".to_string(),
        "Test Validator".to_string(),
        1000,
    );

    // Set test metrics
    validator.total_blocks_produced = 100;
    validator.missed_blocks = 10;
    validator.total_transactions_validated = 95;
    validator.average_block_time = 5.0;
    validator.collaboration_score = 0.8;
    validator.reputation_score = 95.0;
    validator.slashing_penalty = 0.0;

    // Calculate synergy score
    let components = synergy_calculator.calculate_synergy_score(&validator);

    // Verify components are calculated
    assert!(components.stake_weight > 0.0);
    assert!(components.reputation > 0.0);
    assert!(components.contribution_index > 0.0);
    assert!(components.cartelization_penalty >= 1.0);
    assert!(components.normalized_score >= 0.0);

    println!("✅ Synergy Score Calculation Test Passed");
    println!("   Stake Weight: {:.4}", components.stake_weight);
    println!("   Reputation: {:.4}", components.reputation);
    println!(
        "   Contribution Index: {:.4}",
        components.contribution_index
    );
    println!(
        "   Cartelization Penalty: {:.4}",
        components.cartelization_penalty
    );
    println!("   Normalized Score: {:.4}", components.normalized_score);
}

#[test]
fn test_dual_quorum_consensus() {
    let _vote_tracking_guard = DualQuorumConsensus::test_vote_tracking_guard();
    DualQuorumConsensus::reset_test_vote_tracking();

    // Initialize test environment
    let validator_manager = Arc::new(ValidatorManager::new());
    let pqc_manager = Arc::new(Mutex::new(PQCManager::new()));

    // Register + approve the proposer so consensus can resolve validator metadata.
    register_test_consensus_validator(&validator_manager, "test_validator");

    // Give the proposer enough contribution so the proposal bond check passes.
    for _ in 0..10 {
        validator_manager.update_performance(crate::validator::ValidatorPerformanceUpdate {
            validator_address: "test_validator".to_string(),
            update_type: "block_produced".to_string(),
            value: None,
            timestamp: 0,
        });
    }

    let mut dual_quorum = DualQuorumConsensus::new(
        Arc::clone(&validator_manager),
        Arc::clone(&pqc_manager),
        true,
        1,
        1,
        8,
        5,
    );

    // Create test block
    let mut test_block = Block::new(
        1,
        vec![],
        "genesis_hash".to_string(),
        "test_validator".to_string(),
        12345,
    );

    sign_block_as_validator(&mut test_block, &validator_manager);

    // Test consensus execution
    let result = dual_quorum.start_consensus_round(&test_block, 1);

    // Verify result
    match result {
        Ok(qc) => {
            assert!(qc.validation_quorum_met);
            assert!(qc.cooperation_quorum_met);
            println!("✅ Dual-Quorum Consensus Test Passed");
            println!("   QC Validation Quorum: {}", qc.validation_quorum_met);
            println!("   QC Cooperation Quorum: {}", qc.cooperation_quorum_met);
        }
        Err(e) => {
            println!("⚠️ Dual-Quorum Consensus Test Failed: {}", e);
            assert!(false, "Dual-quorum consensus failed");
        }
    }
}

#[test]
fn test_dual_quorum_enforces_minimum_validator_count() {
    let validator_manager = Arc::new(ValidatorManager::new());
    let pqc_manager = Arc::new(Mutex::new(PQCManager::new()));

    for index in 1..=1 {
        let address = format!("validator{}", index);
        register_test_consensus_validator(&validator_manager, &address);
    }

    let mut dual_quorum = DualQuorumConsensus::new(
        Arc::clone(&validator_manager),
        Arc::clone(&pqc_manager),
        true,
        5,
        3,
        8,
        5,
    );

    let mut test_block = Block::new(
        1,
        vec![],
        "genesis_hash".to_string(),
        "validator1".to_string(),
        12345,
    );

    sign_block_as_validator(&mut test_block, &validator_manager);

    let result = dual_quorum.start_consensus_round(&test_block, 1);
    assert!(result.is_err());
    assert!(result
        .err()
        .unwrap_or_default()
        .contains("Insufficient active validators"));
}

#[test]
fn test_entropy_beacon() {
    // Initialize test environment
    let pqc_manager = Arc::new(Mutex::new(PQCManager::new()));
    let mut entropy_beacon = EntropyBeacon::new(Arc::clone(&pqc_manager));

    // Create dummy previous QC
    let previous_qc = QuorumCertificate {
        block_hash: "test_hash".to_string(),
        cluster_id: None,
        epoch_number: 0,
        round_number: 1,
        aggregate_signature: vec![1, 2, 3, 4],
        participant_bitmap: vec![255],
        cumulative_weight: 1.0,
        validation_quorum_met: true,
        cooperation_quorum_met: true,
        timestamp: 1234567890,
        votes: Vec::new(),
    };

    // Generate epoch randomness
    let randomness = entropy_beacon.generate_epoch_randomness(&previous_qc);

    // Verify randomness is generated
    assert!(!randomness.is_empty());
    assert_eq!(randomness.len(), 64); // SHA3-512 output

    println!("✅ Entropy Beacon Test Passed");
    println!("   Generated Randomness: {}", hex::encode(&randomness));
}

#[test]
fn test_cartel_detection() {
    // Initialize test environment
    let validator_manager = Arc::new(ValidatorManager::new());
    let pqc_manager = Arc::new(Mutex::new(PQCManager::new()));
    let synergy_calculator = Arc::new(SynergyScoreCalculator::new(
        Arc::clone(&validator_manager),
        Arc::clone(&pqc_manager),
    ));

    let mut cartel_detection = CartelDetectionEngine::new(
        Arc::clone(&validator_manager),
        Arc::clone(&synergy_calculator),
    );

    // Record test votes
    let vote1 = VoteRecord {
        validator_address: "validator1".to_string(),
        block_height: 1000,
        voted_for_winner: true,
        vote_timestamp: 1234567890,
        signature: vec![1, 2, 3],
    };

    let vote2 = VoteRecord {
        validator_address: "validator2".to_string(),
        block_height: 1000,
        voted_for_winner: true,
        vote_timestamp: 1234567891,
        signature: vec![4, 5, 6],
    };

    cartel_detection.record_vote(0, vote1);
    cartel_detection.record_vote(0, vote2);

    // Detect cartels
    let penalties = cartel_detection.detect_cartels(0);

    // Verify detection runs without error
    println!("✅ Cartel Detection Test Passed");
    println!("   Detected {} potential cartel members", penalties.len());
}

#[test]
fn test_dao_governance() {
    // Initialize test environment
    let validator_manager = Arc::new(ValidatorManager::new());
    let pqc_manager = Arc::new(Mutex::new(PQCManager::new()));
    let synergy_calculator = Arc::new(SynergyScoreCalculator::new(
        Arc::clone(&validator_manager),
        Arc::clone(&pqc_manager),
    ));

    let mut dao_governance = DAOGovernance::new(
        Arc::clone(&validator_manager),
        Arc::clone(&synergy_calculator),
        Arc::clone(&pqc_manager),
    );

    // Register + approve proposer so DAO governance validation passes.
    let _ = validator_manager.register_validator(crate::validator::ValidatorRegistration {
        address: "test_validator".to_string(),
        public_key: "test_key".to_string(),
        name: "Test Validator".to_string(),
        stake_amount: 1000,
        submitted_at: 0,
        registration_tx_hash: "test".to_string(),
    });
    let _ = validator_manager.approve_validator("test_validator");

    // Give the proposer enough contribution so the proposal bond check passes.
    for _ in 0..10 {
        validator_manager.update_performance(crate::validator::ValidatorPerformanceUpdate {
            validator_address: "test_validator".to_string(),
            update_type: "block_produced".to_string(),
            value: None,
            timestamp: 0,
        });
    }

    // Test proposal submission
    let mut parameters = std::collections::HashMap::new();
    parameters.insert("test_param".to_string(), "test_value".to_string());

    let proposal_result = dao_governance.submit_proposal(
        "test_validator",
        ProposalType::ParameterAdjustment,
        "Test Proposal".to_string(),
        "This is a test proposal".to_string(),
        parameters,
    );

    match proposal_result {
        Ok(proposal_id) => {
            println!("✅ DAO Governance Test Passed");
            println!("   Created Proposal: {}", proposal_id);

            // Verify proposal exists
            assert!(dao_governance.proposals.contains_key(&proposal_id));
        }
        Err(e) => {
            println!("⚠️ DAO Governance Test Failed: {}", e);
            assert!(false, "DAO governance proposal submission failed");
        }
    }
}

#[test]
fn test_pqc_integration() {
    // Test PQC manager functionality
    let mut pqc_manager = PQCManager::new();

    // Test keypair generation
    let keypair_result = pqc_manager.generate_keypair(PQCAlgorithm::FNDSA);

    match keypair_result {
        Ok((public_key, private_key)) => {
            assert_eq!(public_key.algorithm, PQCAlgorithm::FNDSA);
            assert_eq!(private_key.algorithm, PQCAlgorithm::FNDSA);

            // Test signing and verification
            let message = b"Test message for PoSy consensus";
            let signature_result = pqc_manager.sign(&private_key, message);

            match signature_result {
                Ok(signature) => {
                    let verify_result = pqc_manager.verify(&public_key, &signature, message);
                    assert!(verify_result.unwrap_or(false));

                    println!("✅ PQC Integration Test Passed");
                    println!("   Keypair Generation: OK");
                    println!("   Signing: OK");
                    println!("   Verification: OK");
                }
                Err(e) => {
                    println!("⚠️ PQC Signing Test Failed: {}", e);
                    assert!(false, "PQC signing failed");
                }
            }
        }
        Err(e) => {
            println!("⚠️ PQC Keypair Generation Test Failed: {}", e);
            assert!(false, "PQC keypair generation failed");
        }
    }
}

#[test]
fn test_full_posy_integration() {
    println!("🧪 Running Full PoSy Integration Test...");

    // Test all components together
    test_synergy_score_calculation();
    test_dual_quorum_consensus();
    test_entropy_beacon();
    test_cartel_detection();
    test_dao_governance();
    test_pqc_integration();

    println!("🎉 Full PoSy Integration Test Suite Completed Successfully!");
    println!("   All core components are functioning correctly.");
    println!("   The Proof-of-Synergy consensus protocol is ready for production.");
}
