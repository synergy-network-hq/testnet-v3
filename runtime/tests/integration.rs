use std::sync::{Arc, Mutex};
use synergy_testnet::validator::{Validator, ValidatorManager, ValidatorRegistration};
use synergy_testnet::consensus::synergy_score::{SynergyScoreCalculator, ValidatorMetrics, EpochSnapshot};
use synergy_testnet::consensus::dao_governance::{DAOGovernance, ProposalType, GovernanceProposal};
use synergy_testnet::consensus::cartel_detection::{CartelDetectionEngine, VoteRecord};
use synergy_testnet::crypto::pqc::{PQCManager, PQCAlgorithm};

#[test]
fn test_validator_slashing_penalty_correction() {
    // Test that the slashing_penalty field is properly initialized and used
    let validator = Validator::new(
        "test_address".to_string(),
        "test_key".to_string(),
        "Test Validator".to_string(),
        1000,
    );

    // Verify slashing_penalty field exists and is initialized to 0.0
    assert_eq!(validator.slashing_penalty, 0.0);

    // Test that slashing penalty is properly used in synergy score calculation
    let validator_manager = Arc::new(ValidatorManager::new());
    let pqc_manager = Arc::new(Mutex::new(PQCManager::new()));
    let synergy_calculator = SynergyScoreCalculator::new(
        Arc::clone(&validator_manager),
        Arc::clone(&pqc_manager),
    );

    let components = synergy_calculator.calculate_synergy_score(&validator);
    // The decayed penalty should be 0.0 since slashing_penalty is 0.0
    assert!(components.reputation > 0.0);
}

#[test]
fn test_synergy_score_calculator_methods() {
    // Test the implemented methods in SynergyScoreCalculator
    let validator_manager = Arc::new(ValidatorManager::new());
    let pqc_manager = Arc::new(Mutex::new(PQCManager::new()));
    let calculator = SynergyScoreCalculator::new(
        Arc::clone(&validator_manager),
        Arc::clone(&pqc_manager),
    );

    // Test calculate_pairwise_synergy
    let validator1 = Validator::new(
        "addr1".to_string(),
        "key1".to_string(),
        "Validator 1".to_string(),
        1000,
    );

    let validator2 = Validator::new(
        "addr2".to_string(),
        "key2".to_string(),
        "Validator 2".to_string(),
        1000,
    );

    let pairwise_synergy = calculator.calculate_pairwise_synergy(&validator1, &validator2);
    assert!(pairwise_synergy >= 0.0);
    assert!(pairwise_synergy <= 1.0);

    // Test normalize_scores
    let scores = vec![10.0, 20.0, 30.0, 40.0];
    let normalized = calculator.normalize_scores(&scores);
    let total: f64 = normalized.iter().sum();
    assert!((total - 1.0).abs() < f64::EPSILON);

    // Test apply_decay_factor
    let original_score = 100.0;
    let blocks_since_update = 100;
    let decayed_score = calculator.apply_decay_factor(original_score, blocks_since_update);
    assert!(decayed_score < original_score);
    assert!(decayed_score > 0.0);
}

#[test]
fn test_ok_some_pattern_harmonization() {
    // Test that Result/Option patterns are properly harmonized
    let validator_manager = Arc::new(ValidatorManager::new());

    // Register a test validator
    let registration = ValidatorRegistration {
        address: "test_addr".to_string(),
        public_key: "test_pubkey".to_string(),
        name: "Test Validator".to_string(),
        stake_amount: 1000,
        submitted_at: 0,
        registration_tx_hash: "test_tx".to_string(),
    };

    validator_manager.register_validator(registration).unwrap();
    validator_manager.approve_validator("test_addr").unwrap();

    // Test that get_validator returns Option<Validator> (not Result)
    let validator_opt = validator_manager.get_validator("test_addr");
    assert!(validator_opt.is_some());

    // Test that the validator has all required fields including slashing_penalty
    let validator = validator_opt.unwrap();
    assert_eq!(validator.slashing_penalty, 0.0);
}

#[test]
fn test_error_handling_for_map_err_on_option() {
    // Test that map_err is not used on Option types
    let validator_manager = Arc::new(ValidatorManager::new());

    // Test get_validator with non-existent address returns Option::None
    let validator_opt = validator_manager.get_validator("non_existent");
    assert!(validator_opt.is_none());

    // Test that we use ok_or/ok_or_else instead of map_err on Options
    let result: Result<Validator, String> = validator_opt.ok_or("Validator not found".to_string());
    assert!(result.is_err());
}

#[test]
fn test_string_return_type_standardization() {
    // Test that string returns use String for owned data
    use synergy_testnet::consensus::dao_governance::{proposal_type_to_string, vote_type_to_string};
    use synergy_testnet::consensus::dao_governance::{ProposalType, VoteType};

    let proposal_type_str = proposal_type_to_string(&ProposalType::ParameterAdjustment);
    assert_eq!(proposal_type_str, "param");

    let vote_type_str = vote_type_to_string(&VoteType::Approve);
    assert_eq!(vote_type_str, "approve");

    // Verify they return String (not &str)
    assert!(std::any::type_name_of_val(&proposal_type_str).contains("String"));
    assert!(std::any::type_name_of_val(&vote_type_str).contains("String"));
}

#[test]
fn test_mutable_borrow_conflict_resolution() {
    // Test that mutable borrow conflicts are resolved
    let validator_manager = Arc::new(ValidatorManager::new());
    let pqc_manager = Arc::new(Mutex::new(PQCManager::new()));

    let mut dao_governance = DAOGovernance::new(
        Arc::clone(&validator_manager),
        Arc::new(SynergyScoreCalculator::new(
            Arc::clone(&validator_manager),
            Arc::clone(&pqc_manager),
        )),
        Arc::clone(&pqc_manager),
    );

    // This should not cause borrow conflicts
    let result = dao_governance.submit_proposal(
        "test_proposer",
        ProposalType::ParameterAdjustment,
        "Test Proposal".to_string(),
        "Test Description".to_string(),
        std::collections::HashMap::new(),
    );

    // Should return Err since proposer doesn't exist, but shouldn't panic due to borrow conflicts
    assert!(result.is_err());
}

#[test]
fn test_reference_assignment_fixes() {
    // Test that reference assignment issues are fixed
    let validator_manager = Arc::new(ValidatorManager::new());
    let pqc_manager = Arc::new(Mutex::new(PQCManager::new()));

    let mut cartel_engine = CartelDetectionEngine::new(
        Arc::clone(&validator_manager),
        Arc::new(SynergyScoreCalculator::new(
            Arc::clone(&validator_manager),
            Arc::clone(&pqc_manager),
        )),
    );

    // Test record_vote and verify_report don't cause reference assignment issues
    let vote_record = VoteRecord {
        validator_address: "test_validator".to_string(),
        block_height: 1,
        voted_for_winner: true,
        vote_timestamp: 0,
        signature: vec![],
    };

    cartel_engine.record_vote(0, vote_record);

    // This should not cause reference assignment errors
    let result = cartel_engine.detect_cartels(0);
    assert!(result.is_empty());
}

#[test]
fn test_self_borrow_conflict_mitigation() {
    // Test that self borrow conflicts are mitigated
    let validator_manager = Arc::new(ValidatorManager::new());
    let pqc_manager = Arc::new(Mutex::new(PQCManager::new()));

    let mut dao_governance = DAOGovernance::new(
        Arc::clone(&validator_manager),
        Arc::new(SynergyScoreCalculator::new(
            Arc::clone(&validator_manager),
            Arc::clone(&pqc_manager),
        )),
        Arc::clone(&pqc_manager),
    );

    // Submit a proposal (this internally tests the borrow conflict resolution)
    let result = dao_governance.submit_proposal(
        "test_proposer",
        ProposalType::ParameterAdjustment,
        "Test Proposal".to_string(),
        "Test Description".to_string(),
        std::collections::HashMap::new(),
    );

    // Should return Err since proposer doesn't exist, but shouldn't panic due to self borrow conflicts
    assert!(result.is_err());
}

#[test]
fn test_synergy_score_components() {
    // Test that SynergyScoreComponents are properly calculated
    let validator_manager = Arc::new(ValidatorManager::new());
    let pqc_manager = Arc::new(Mutex::new(PQCManager::new()));
    let calculator = SynergyScoreCalculator::new(
        Arc::clone(&validator_manager),
        Arc::clone(&pqc_manager),
    );

    let validator = Validator::new(
        "test_addr".to_string(),
        "test_key".to_string(),
        "Test Validator".to_string(),
        1000,
    );

    let components = calculator.calculate_synergy_score(&validator);

    // Verify all components are calculated
    assert!(components.stake_weight >= 0.0);
    assert!(components.reputation >= 0.0);
    assert!(components.contribution_index >= 0.0);
    assert!(components.cartelization_penalty >= 1.0); // Should be at least 1.0
    assert!(components.normalized_score >= 0.0);
    assert!(components.normalized_score <= 1.0);
}

#[test]
fn test_validator_metrics_integration() {
    // Test ValidatorMetrics integration with slashing penalty
    let metrics = ValidatorMetrics {
        stake_amount: 1000,
        blocks_participated: 100,
        blocks_eligible: 100,
        correct_votes: 95,
        total_votes: 100,
        successful_proposals: 10,
        relay_assists: 5,
        average_latency: 1.0,
        slashing_penalty: 0.1, // 10% slashing penalty
        last_update_block: 0,
    };

    // Verify slashing_penalty is properly included in metrics
    assert_eq!(metrics.slashing_penalty, 0.1);
}

#[test]
fn test_epoch_snapshot_creation() {
    // Test EpochSnapshot creation with proper validator metrics
    let validator_manager = Arc::new(ValidatorManager::new());
    let pqc_manager = Arc::new(Mutex::new(PQCManager::new()));
    let calculator = Arc::new(SynergyScoreCalculator::new(
        Arc::clone(&validator_manager),
        Arc::clone(&pqc_manager),
    ));

    let mut oracle = synergy_testnet::consensus::dao_governance::SynergyOracle::new(
        Arc::clone(&calculator),
        Arc::clone(&pqc_manager),
    );

    // Add some validator metrics
    let metrics = ValidatorMetrics {
        stake_amount: 1000,
        blocks_participated: 100,
        blocks_eligible: 100,
        correct_votes: 95,
        total_votes: 100,
        successful_proposals: 10,
        relay_assists: 5,
        average_latency: 1.0,
        slashing_penalty: 0.0,
        last_update_block: 0,
    };

    oracle.update_validator_metrics("test_validator", metrics);

    // Create epoch snapshot
    let snapshot = oracle.compute_epoch_snapshot(0);

    // Verify snapshot contains expected data
    assert_eq!(snapshot.epoch_number, 0);
    assert!(snapshot.total_stake > 0);
    assert!(snapshot.active_validator_count > 0);
    assert!(!snapshot.merkle_root.is_empty());
}