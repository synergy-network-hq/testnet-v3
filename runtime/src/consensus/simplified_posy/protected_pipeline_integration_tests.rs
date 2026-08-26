use super::*;
use crate::consensus::simplified_posy::{
    ConsensusObjectContext, POSY_SIMPLIFIED_OBJECT_SCHEMA_VERSION,
};
use crate::etdag::{NextProtectedBatchCommitment, PROTECTED_PIPELINE_VERSION};
use crate::synergy_types::{ChainId, ClusterId, Epoch, NetworkId};

fn context(height: Height) -> ConsensusObjectContext {
    let parameter_root = ConsensusParameterRoot::from_canonical_manifest_bytes(b"r11-test");
    ConsensusObjectContext {
        schema_version: POSY_SIMPLIFIED_OBJECT_SCHEMA_VERSION,
        chain_id: ChainId::synergy_testnet_v3(),
        network_id: NetworkId::fresh_posy_testnet_v3(),
        protocol_version: POSY_SIMPLIFIED_PROTOCOL_VERSION.to_string(),
        epoch: Epoch(0),
        height,
        round: Round(0),
        epoch_context_root: Hash::from_domain_bytes("r11-test", b"epoch"),
        consensus_parameter_root: parameter_root.to_hex(),
        active_validator_set_root: Hash::from_domain_bytes("r11-test", b"validators"),
        validator_consensus_key_root: Hash::from_domain_bytes("r11-test", b"keys"),
        frozen_voting_weight_root: Hash::from_domain_bytes("r11-test", b"weights"),
    }
}

fn commitment(context: &ConsensusObjectContext) -> NextProtectedBatchCommitment {
    NextProtectedBatchCommitment {
        commitment_version: PROTECTED_PIPELINE_VERSION,
        chain_id: context.chain_id,
        network_id: context.network_id.clone(),
        protocol_version: context.protocol_version.clone(),
        epoch: context.epoch,
        target_height: context.height,
        cluster_id: ClusterId(0),
        target_context_root: Hash::from_domain_bytes("r11-test", b"target"),
        validator_set_commitment: context.active_validator_set_root,
        parameter_root: ConsensusParameterRoot::from_hex(&context.consensus_parameter_root)
            .unwrap(),
        cut_root: EtdagDigest::from_domain_bytes("r11-test", b"cut"),
        eligible_set_root: EtdagDigest::from_domain_bytes("r11-test", b"eligible"),
        order_seed: EtdagDigest::from_domain_bytes("r11-test", b"seed"),
        order_root: EtdagDigest::from_domain_bytes("r11-test", b"order"),
        protected_batch_root: EtdagDigest::from_domain_bytes("r11-test", b"batch"),
        protected_count: 0,
        protected_gas: 0,
        protected_bytes: 0,
    }
}

#[test]
fn h1_h2_commitments_are_exact_and_height_bound() {
    for height in [Height(1), Height(2)] {
        let context = context(height);
        let commitment = commitment(&context);
        validate_next_protected_batch_commitment(&commitment, &context, None, None).unwrap();
        validate_genesis_bootstrap_next_commitment(&commitment).unwrap();

        let mut wrong_height = commitment.clone();
        wrong_height.target_height = Height(height.0 + 1);
        assert!(
            validate_next_protected_batch_commitment(&wrong_height, &context, None, None,)
                .unwrap_err()
                .contains("exact PoSy proposal context")
        );
    }
}

#[test]
fn h3_and_later_have_no_empty_bootstrap_fallback() {
    for height in [Height(3), Height(4), Height(10_000)] {
        let context = context(height);
        let commitment = commitment(&context);
        assert!(validate_genesis_bootstrap_next_commitment(&commitment)
            .unwrap_err()
            .contains("H1/H2"));
    }
}

#[test]
fn commitment_mismatch_is_detected_independently() {
    let context = context(Height(2));
    let canonical = commitment(&context);
    validate_next_protected_batch_commitment(&canonical, &context, None, None).unwrap();

    let mut wrong_epoch = canonical.clone();
    wrong_epoch.epoch = Epoch(1);
    assert!(validate_next_protected_batch_commitment(&wrong_epoch, &context, None, None,).is_err());

    let mut wrong_validator_set = canonical;
    wrong_validator_set.validator_set_commitment =
        Hash::from_domain_bytes("r11-test", b"wrong-validators");
    assert!(
        validate_next_protected_batch_commitment(&wrong_validator_set, &context, None, None,)
            .is_err()
    );
}
