use compiler::ast::{ContractDefinition, SourceUnit};
use compiler::{analyze, parse, ArtifactBundle, ArtifactConfig, CodeGenerator};
use std::fs;
use std::path::PathBuf;

fn counter_bundle_from(relative_path: &str) -> ArtifactBundle {
    let source_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(relative_path);
    let source = fs::read_to_string(source_path).unwrap();
    let (_version, ast) = parse(&source).unwrap();
    analyze(&ast).unwrap();
    let bytecode = CodeGenerator::new().generate_stateful(&ast).unwrap();
    ArtifactBundle::generate(&source, &ast, bytecode).unwrap()
}

fn counter_bundle() -> ArtifactBundle {
    counter_bundle_from("../contracts/Counter.synq")
}

#[test]
fn counter_artifacts_are_deterministic_and_chain_bound() {
    let first = counter_bundle();
    let second = counter_bundle();

    assert_eq!(first, second);
    assert_eq!(first.abi_json().unwrap(), second.abi_json().unwrap());
    assert_eq!(
        first.manifest_json().unwrap(),
        second.manifest_json().unwrap()
    );
    assert_eq!(first.abi.contract, "Counter");
    assert_eq!(first.manifest.artifact_format, "synq-stateful-ir-v2");
    assert_eq!(first.manifest.required_chain_id, 1266);
    assert_eq!(first.manifest.required_network_id, "synergy-testnet");
    assert_eq!(first.manifest.required_signature_algorithm, "ML-DSA-87");
    assert!(!first.hashes.bytecode_hash.is_empty());
    assert!(!first.hashes.abi_hash.is_empty());
    assert!(!first.hashes.manifest_hash.is_empty());
}

#[test]
fn counter_abi_contains_increment_and_get() {
    let bundle = counter_bundle();

    assert_eq!(bundle.abi.state_schema.len(), 1);
    assert_eq!(bundle.abi.state_schema[0].name, "counter");
    assert_eq!(bundle.abi.state_schema[0].r#type, "u256");

    assert_eq!(bundle.abi.methods.len(), 2);
    assert_eq!(bundle.abi.methods[0].name, "increment");
    assert_eq!(bundle.abi.methods[0].mutability, "write");
    assert_eq!(bundle.abi.methods[1].name, "get");
    assert_eq!(bundle.abi.methods[1].mutability, "view");
}

#[test]
fn counter_artifacts_match_checked_in_canonical_fixtures() {
    let bundle = counter_bundle();
    let fixture_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../contracts");
    let expected_bytecode = fs::read(fixture_root.join("Counter.compiled.synq")).unwrap();
    let expected_abi = fs::read(fixture_root.join("Counter.abi.json")).unwrap();
    let expected_manifest = fs::read(fixture_root.join("Counter.manifest.json")).unwrap();

    assert_eq!(bundle.bytecode, expected_bytecode);
    assert_eq!(bundle.abi_json().unwrap(), expected_abi);
    assert_eq!(bundle.manifest_json().unwrap(), expected_manifest);
    assert_eq!(
        bundle.hashes.bytecode_hash,
        "9fe99c76286d6fab0cab50911d398b08723068beac8503d146a122bae635516a"
    );
    // ABI and manifest hashes changed on 2026-07-27 when the account-domain
    // signature algorithm moved ML-DSA-65 -> ML-DSA-87. Both artifacts carry
    // that label, so both digests move; `bytecode_hash` above is unchanged,
    // which is the proof that codegen was not affected.
    assert_eq!(
        bundle.hashes.abi_hash,
        "262bdaa8ec4af640710eceb059776c3b2d204e8aeb7e72d88d4bb2f8272e3784"
    );
    assert_eq!(
        bundle.hashes.manifest_hash,
        "7fd2d3b97ff6a0fc93221fcd99fd13fa066af558be44f851e2a8ac92aa03b3c3"
    );
}

#[test]
fn counter_manifest_references_generated_hashes_and_policy() {
    let bundle = counter_bundle();

    assert_eq!(bundle.manifest.bytecode_hash, bundle.hashes.bytecode_hash);
    assert_eq!(bundle.manifest.abi_hash, bundle.hashes.abi_hash);
    assert_eq!(
        bundle.manifest.storage_schema_hash,
        bundle.hashes.storage_schema_hash
    );
    assert_eq!(bundle.manifest.required_chain_id, 1266);
    assert_eq!(bundle.manifest.required_network_id, "synergy-testnet");
    assert_eq!(bundle.manifest.required_signature_algorithm, "ML-DSA-87");
    assert_eq!(
        bundle.abi.security_requirements.deploy_domain,
        "SYNQ_CONTRACT_DEPLOY_V1"
    );
    assert_eq!(
        bundle.abi.security_requirements.call_domain,
        "SYNQ_CONTRACT_CALL_V1"
    );
}

#[test]
fn manifest_generation_uses_explicit_artifact_config() {
    let source_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../contracts/Counter.synq");
    let source = fs::read_to_string(source_path).unwrap();
    let (_version, ast) = parse(&source).unwrap();
    analyze(&ast).unwrap();
    let bytecode = CodeGenerator::new().generate_stateful(&ast).unwrap();
    let mut config = ArtifactConfig::testnet_1266();
    config.required_network_id = "synergy-testnet-v3".to_string();

    let bundle = ArtifactBundle::generate_with_config(&source, &ast, bytecode, &config).unwrap();

    assert_eq!(bundle.manifest.required_chain_id, 1266);
    assert_eq!(bundle.manifest.required_network_id, "synergy-testnet-v3");
    assert_eq!(bundle.manifest.required_signature_algorithm, "ML-DSA-87");
}

#[test]
fn artifact_generation_fails_for_missing_or_ambiguous_contracts() {
    let no_contract = ArtifactBundle::generate("", &[], Vec::new()).unwrap_err();
    assert!(no_contract.contains("requires one contract"));

    let first = SourceUnit::Contract(ContractDefinition {
        name: "First".to_string(),
        annotations: Vec::new(),
        parts: Vec::new(),
    });
    let second = SourceUnit::Contract(ContractDefinition {
        name: "Second".to_string(),
        annotations: Vec::new(),
        parts: Vec::new(),
    });
    let ambiguous = ArtifactBundle::generate("", &[first, second], Vec::new()).unwrap_err();
    assert!(ambiguous.contains("exactly one contract"));
}
