use compiler::ast::{ContractDefinition, SourceUnit};
use compiler::{analyze, parse, ArtifactBundle, ArtifactConfig, CodeGenerator};
use std::fs;
use std::path::PathBuf;

fn counter_bundle_from(relative_path: &str) -> ArtifactBundle {
    let source_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(relative_path);
    let source = fs::read_to_string(source_path).unwrap();
    let (_version, ast) = parse(&source).unwrap();
    analyze(&ast).unwrap();
    let bytecode = CodeGenerator::new().generate(&ast).unwrap();
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
    assert_eq!(first.manifest.artifact_format, "synq-bytecode-v1");
    assert_eq!(first.manifest.required_chain_id, 1264);
    assert_eq!(first.manifest.required_network_id, "synergy-testnet");
    assert_eq!(first.manifest.required_signature_algorithm, "ML-DSA-65");
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
        "6b8b2d0d1433c0c4941bfc41054a58a004e9cc46e475926f0f70d3d309e92533"
    );
    assert_eq!(
        bundle.hashes.abi_hash,
        "ea9c1f48cad5f0d39d299d854ba578f6909a8475093aa8c616b1ee186c599b26"
    );
    assert_eq!(
        bundle.hashes.manifest_hash,
        "6334f5a98926f3c5eeb4f9337a9602841e5cc9b77b59f0e648203a296d290332"
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
    assert_eq!(bundle.manifest.required_chain_id, 1264);
    assert_eq!(bundle.manifest.required_network_id, "synergy-testnet");
    assert_eq!(bundle.manifest.required_signature_algorithm, "ML-DSA-65");
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
    let bytecode = CodeGenerator::new().generate(&ast).unwrap();
    let mut config = ArtifactConfig::testnet_1264();
    config.required_network_id = "synergy-testnet-v3".to_string();

    let bundle = ArtifactBundle::generate_with_config(&source, &ast, bytecode, &config).unwrap();

    assert_eq!(bundle.manifest.required_chain_id, 1264);
    assert_eq!(bundle.manifest.required_network_id, "synergy-testnet-v3");
    assert_eq!(bundle.manifest.required_signature_algorithm, "ML-DSA-65");
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
