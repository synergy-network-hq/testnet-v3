use pqsynq::{AegisSynQVerifier, ContractDeployEnvelope, VerificationContext};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct DeployVector {
    schema_version: u32,
    case: String,
    expected_result: String,
    expected_error_variant: Option<String>,
    expected_error_code: Option<String>,
    context: VerificationContext,
    envelope: ContractDeployEnvelope,
}

fn vector(json: &str) -> DeployVector {
    let vector: DeployVector = serde_json::from_str(json).expect("vector JSON must parse");
    assert_eq!(vector.schema_version, 1);
    assert!(
        vector.case.starts_with("ml_dsa_65_"),
        "unexpected vector case {}",
        vector.case
    );
    vector
}

fn assert_vector_replays(vector: DeployVector) {
    let verifier = AegisSynQVerifier::new(vector.context.policy.clone());
    let result = verifier.verify_contract_deploy(&vector.envelope, &vector.context);

    match vector.expected_result.as_str() {
        "ok" => {
            let verified = result
                .unwrap_or_else(|error| panic!("{} should verify, got {error:?}", vector.case));
            assert_eq!(
                verified.deployer,
                vector.envelope.signing_payload.signer_address
            );
            assert_eq!(verified.bytecode_hash, vector.envelope.bytecode_hash);
            assert_eq!(verified.manifest_hash, vector.envelope.manifest_hash);
            assert_eq!(verified.abi_hash, vector.envelope.abi_hash);
        }
        "err" => {
            let error = result.expect_err("negative vector should fail");
            assert_eq!(
                format!("{error:?}"),
                vector.expected_error_variant.unwrap(),
                "{} error variant mismatch",
                vector.case
            );
            assert_eq!(
                error.code(),
                vector.expected_error_code.unwrap(),
                "{} error code mismatch",
                vector.case
            );
        }
        other => panic!("unsupported vector result {other}"),
    }
}

#[test]
fn ml_dsa_65_deploy_vectors_replay() {
    for json in [
        include_str!("vectors/ml_dsa_65_valid_deploy.json"),
        include_str!("vectors/ml_dsa_65_invalid_signature.json"),
        include_str!("vectors/ml_dsa_65_wrong_chain.json"),
        include_str!("vectors/ml_dsa_65_wrong_domain.json"),
    ] {
        assert_vector_replays(vector(json));
    }
}
