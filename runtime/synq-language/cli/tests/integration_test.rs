use assert_cmd::prelude::*;
use predicates::prelude::*;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;
use tempfile::{tempdir, NamedTempFile, TempDir};

fn counter_source_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../contracts/Counter.synq")
}

fn write_counter_project(dir: &std::path::Path, config: &str) -> PathBuf {
    fs::create_dir_all(dir.join("contracts")).unwrap();
    fs::write(dir.join("synq.toml"), config).unwrap();
    let source_path = dir.join("contracts/Counter.synq");
    fs::write(
        &source_path,
        r#"
contract Counter {
    counter: UInt256 public;

    @public function increment() -> UInt256 {
        counter = counter + 1;
        return counter;
    }
}
"#,
    )
    .unwrap();
    source_path
}

fn valid_synq_toml(network_id: &str) -> String {
    format!(
        r#"[package]
name = "counter"
version = "0.1.0"

[compiler]
language_version = "0.1"
bytecode_version = 2
target_aivm_version = "0.1"

[network]
chain_id = 1266
network_id = "{network_id}"
address_hrp = "tsynq"

[security]
signature_algorithm = "ML-DSA-65"
deploy_domain = "SYNQ_CONTRACT_DEPLOY_V1"
call_domain = "SYNQ_CONTRACT_CALL_V1"
"#
    )
}

struct SignedCallProject {
    _dir: TempDir,
    call_envelope_path: PathBuf,
}

fn signed_call_project() -> SignedCallProject {
    let dir = tempdir().unwrap();
    let project_path = dir.path().join("counter-call");

    let mut init_cmd = Command::new(assert_cmd::cargo::cargo_bin!("cli"));
    init_cmd.arg("init").arg(&project_path);
    init_cmd.assert().success();

    let source_path = project_path.join("contracts/Counter.synq");
    let mut build_cmd = Command::new(assert_cmd::cargo::cargo_bin!("cli"));
    build_cmd.arg("build").arg(&source_path);
    build_cmd.assert().success();

    let key_dir = project_path.join("keys");
    let mut keygen_cmd = Command::new(assert_cmd::cargo::cargo_bin!("cli"));
    keygen_cmd.arg("keygen").arg("--out-dir").arg(&key_dir);
    keygen_cmd.assert().success();

    let private_key_path = key_dir.join("synq-testnet-mldsa65.private.json");
    let private_key_json: serde_json::Value =
        serde_json::from_slice(&fs::read(&private_key_path).unwrap()).unwrap();
    let contract_address = private_key_json["address"].as_str().unwrap();
    let call_envelope_path = project_path.join("contracts/Counter.increment.call.json");

    let mut sign_call_cmd = Command::new(assert_cmd::cargo::cargo_bin!("cli"));
    sign_call_cmd
        .arg("sign-call")
        .arg("--contract")
        .arg(contract_address)
        .arg("--method")
        .arg("increment")
        .arg("--abi")
        .arg(source_path.with_extension("abi.json"))
        .arg("--manifest")
        .arg(source_path.with_extension("manifest.json"))
        .arg("--private-key")
        .arg(&private_key_path)
        .arg("--output")
        .arg(&call_envelope_path)
        .arg("--nonce")
        .arg("43");
    sign_call_cmd.assert().success();

    SignedCallProject {
        _dir: dir,
        call_envelope_path,
    }
}

#[test]
fn test_compile_and_run() {
    let contract = r#"
        contract MyContract {
            function my_function() {}
        }
    "#;

    let mut file = NamedTempFile::new().unwrap();
    write!(file, "{}", contract).unwrap();

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("cli"));
    cmd.arg("compile").arg("--path").arg(file.path());

    cmd.assert().success();

    let bytecode_path = file.path().with_extension("synq");
    assert!(bytecode_path.exists());

    let mut run_cmd = Command::new(assert_cmd::cargo::cargo_bin!("cli"));
    run_cmd.arg("run").arg("--path").arg(&bytecode_path);

    run_cmd
        .assert()
        .success()
        .stdout(predicate::str::contains("Execution finished successfully"));
}

#[test]
fn test_verify_accepts_matching_bytecode_and_executes() {
    let contract = r#"
        contract VerifyContract {
            function noop() {}
        }
    "#;

    let mut file = NamedTempFile::new().unwrap();
    write!(file, "{}", contract).unwrap();

    let mut compile_cmd = Command::new(assert_cmd::cargo::cargo_bin!("cli"));
    compile_cmd.arg("compile").arg("--path").arg(file.path());
    compile_cmd.assert().success();

    let bytecode_path = file.path().with_extension("synq");
    assert!(bytecode_path.exists());

    let mut verify_cmd = Command::new(assert_cmd::cargo::cargo_bin!("cli"));
    verify_cmd
        .arg("verify")
        .arg("--source")
        .arg(file.path())
        .arg("--bytecode")
        .arg(&bytecode_path)
        .arg("--run");

    verify_cmd
        .assert()
        .success()
        .stdout(predicate::str::contains("Verification succeeded"))
        .stdout(predicate::str::contains("Execution finished successfully"));
}

#[test]
fn test_verify_rejects_mismatched_bytecode() {
    let contract = r#"
        contract VerifyContract {
            function noop() {}
        }
    "#;

    let mut file = NamedTempFile::new().unwrap();
    write!(file, "{}", contract).unwrap();

    let mut compile_cmd = Command::new(assert_cmd::cargo::cargo_bin!("cli"));
    compile_cmd.arg("compile").arg("--path").arg(file.path());
    compile_cmd.assert().success();

    let bytecode_path = file.path().with_extension("synq");
    assert!(bytecode_path.exists());

    let mut tampered = fs::read(&bytecode_path).unwrap();
    tampered[0] ^= 0xFF;
    fs::write(&bytecode_path, tampered).unwrap();

    let mut verify_cmd = Command::new(assert_cmd::cargo::cargo_bin!("cli"));
    verify_cmd
        .arg("verify")
        .arg("--source")
        .arg(file.path())
        .arg("--bytecode")
        .arg(&bytecode_path);

    verify_cmd
        .assert()
        .failure()
        .stderr(predicate::str::contains("Bytecode mismatch"));
}

#[test]
fn test_compile_does_not_overwrite_synq_source_extension() {
    let contract = r#"
        contract NoOverwrite {
            function noop() {}
        }
    "#;

    let dir = tempdir().unwrap();
    let source_path: PathBuf = dir.path().join("contract.synq");
    fs::write(&source_path, contract).unwrap();

    let mut compile_cmd = Command::new(assert_cmd::cargo::cargo_bin!("cli"));
    compile_cmd.arg("compile").arg("--path").arg(&source_path);
    compile_cmd.assert().success();

    let compiled_path = source_path.with_extension("compiled.synq");
    assert!(compiled_path.exists());
    assert!(source_path.exists());
    assert_eq!(fs::read_to_string(&source_path).unwrap(), contract);
}

#[test]
fn test_solidity_output_is_labeled_non_production() {
    let contract = r#"
        contract CompatibilityLabel {
            function noop() {}
        }
    "#;

    let dir = tempdir().unwrap();
    let source_path = dir.path().join("compatibility.synq");
    fs::write(&source_path, contract).unwrap();

    let mut compile_cmd = Command::new(assert_cmd::cargo::cargo_bin!("cli"));
    compile_cmd.arg("compile").arg("--path").arg(&source_path);
    compile_cmd
        .assert()
        .success()
        .stdout(predicate::str::contains(
            compiler::SOLIDITY_COMPATIBILITY_WARNING,
        ));

    let solidity = fs::read_to_string(source_path.with_extension("sol")).unwrap();
    assert!(solidity.contains(compiler::SOLIDITY_COMPATIBILITY_WARNING));
}

#[test]
fn test_compile_all_documented_examples() {
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..");
    let example_paths = [
        "docs/examples/1-ERC20-Token.synq",
        "docs/examples/2-MultiSig-Wallet.synq",
        "docs/examples/3-DAO-Voting.synq",
        "docs/examples/4-NFT-Contract.synq",
        "docs/examples/5-Escrow-Contract.synq",
        "docs/examples/6-Staking-Contract.synq",
    ];

    for relative_path in example_paths {
        let source_path = repo_root.join(relative_path);
        assert!(
            source_path.exists(),
            "Expected example source at {}",
            source_path.display()
        );

        let mut compile_cmd = Command::new(assert_cmd::cargo::cargo_bin!("cli"));
        compile_cmd.arg("compile").arg("--path").arg(&source_path);
        compile_cmd.assert().success();

        let compiled_path = source_path.with_extension("compiled.synq");
        let solidity_path = source_path.with_extension("sol");
        assert!(
            compiled_path.exists(),
            "Expected compiled artifact at {}",
            compiled_path.display()
        );
        assert!(
            solidity_path.exists(),
            "Expected Solidity artifact at {}",
            solidity_path.display()
        );
    }
}

#[test]
fn test_compile_counter_example() {
    let source_path = counter_source_path();
    assert!(
        source_path.exists(),
        "Expected Counter example at {}",
        source_path.display()
    );

    let mut build_cmd = Command::new(assert_cmd::cargo::cargo_bin!("cli"));
    build_cmd.arg("build").arg(&source_path);
    build_cmd
        .assert()
        .success()
        .stdout(predicate::str::contains("bytecode_hash="))
        .stdout(predicate::str::contains("abi_hash="))
        .stdout(predicate::str::contains("manifest_hash="));

    assert!(source_path.with_extension("compiled.synq").exists());
    assert!(source_path.with_extension("abi.json").exists());
    assert!(source_path.with_extension("manifest.json").exists());
    assert!(source_path.with_extension("sol").exists());

    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(source_path.with_extension("manifest.json")).unwrap())
            .unwrap();
    assert_eq!(manifest["required_chain_id"], 1266);
    assert_eq!(manifest["required_network_id"], "synergy-testnet");
    assert_eq!(manifest["required_signature_algorithm"], "ML-DSA-65");
}

#[test]
fn test_check_abi_manifest_and_simulate_counter() {
    let source_path = counter_source_path();

    let mut check_cmd = Command::new(assert_cmd::cargo::cargo_bin!("cli"));
    check_cmd.arg("check").arg(&source_path);
    check_cmd
        .assert()
        .success()
        .stdout(predicate::str::contains("Check succeeded"))
        .stdout(predicate::str::contains("bytecode_hash="))
        .stdout(predicate::str::contains("manifest_hash="));

    let mut abi_cmd = Command::new(assert_cmd::cargo::cargo_bin!("cli"));
    abi_cmd.arg("abi").arg(&source_path);
    abi_cmd
        .assert()
        .success()
        .stdout(predicate::str::contains(r#""contract":"Counter""#))
        .stdout(predicate::str::contains(r#""selector":"0x5842f1be""#));

    let mut manifest_cmd = Command::new(assert_cmd::cargo::cargo_bin!("cli"));
    manifest_cmd.arg("manifest").arg(&source_path);
    manifest_cmd
        .assert()
        .success()
        .stdout(predicate::str::contains(r#""required_chain_id":1266"#))
        .stdout(predicate::str::contains(
            r#""required_signature_algorithm":"ML-DSA-65""#,
        ));

    let mut simulate_source = NamedTempFile::new().unwrap();
    write!(
        simulate_source,
        "{}",
        r#"
        contract SimulateSmoke {
            function noop() {}
        }
    "#
    )
    .unwrap();

    let mut simulate_cmd = Command::new(assert_cmd::cargo::cargo_bin!("cli"));
    simulate_cmd.arg("simulate").arg(simulate_source.path());
    simulate_cmd
        .assert()
        .success()
        .stdout(predicate::str::contains("Simulation succeeded"))
        .stdout(predicate::str::contains("bytecode_hash="));
}

#[test]
fn test_abi_and_manifest_can_write_explicit_output_files() {
    let source_path = counter_source_path();
    let dir = tempdir().unwrap();
    let abi_path = dir.path().join("counter.abi.json");
    let manifest_path = dir.path().join("counter.manifest.json");

    let mut abi_cmd = Command::new(assert_cmd::cargo::cargo_bin!("cli"));
    abi_cmd
        .arg("abi")
        .arg(&source_path)
        .arg("--output")
        .arg(&abi_path);
    abi_cmd.assert().success();

    let mut manifest_cmd = Command::new(assert_cmd::cargo::cargo_bin!("cli"));
    manifest_cmd
        .arg("manifest")
        .arg(&source_path)
        .arg("--output")
        .arg(&manifest_path);
    manifest_cmd.assert().success();

    assert!(fs::read_to_string(abi_path)
        .unwrap()
        .contains(r#""contract":"Counter""#));
    assert!(fs::read_to_string(manifest_path)
        .unwrap()
        .contains(r#""required_network_id":"synergy-testnet""#));
}

#[test]
fn test_simulate_counter_reports_current_vm_state_limitation() {
    let source_path = counter_source_path();

    let mut simulate_cmd = Command::new(assert_cmd::cargo::cargo_bin!("cli"));
    simulate_cmd.arg("simulate").arg(&source_path);
    simulate_cmd
        .assert()
        .failure()
        .stderr(predicate::str::contains("VM execution failed"));
}

#[test]
fn test_init_creates_counter_project_template() {
    let dir = tempdir().unwrap();
    let project_path = dir.path().join("counter-demo");

    let mut init_cmd = Command::new(assert_cmd::cargo::cargo_bin!("cli"));
    init_cmd.arg("init").arg(&project_path);
    init_cmd
        .assert()
        .success()
        .stdout(predicate::str::contains("Created SynQ project"));

    assert!(project_path.join("synq.toml").exists());
    assert!(project_path.join("contracts/Counter.synq").exists());
    assert!(project_path.join("tests/.gitkeep").exists());
    assert!(project_path.join("scripts/deploy-local-demo.sh").exists());
    assert!(fs::read_to_string(project_path.join(".gitignore"))
        .unwrap()
        .contains("/keys/"));

    let mut build_cmd = Command::new(assert_cmd::cargo::cargo_bin!("cli"));
    build_cmd
        .arg("build")
        .arg(project_path.join("contracts/Counter.synq"));
    build_cmd.assert().success();
    assert!(project_path
        .join("contracts/Counter.manifest.json")
        .exists());

    let mut duplicate_init = Command::new(assert_cmd::cargo::cargo_bin!("cli"));
    duplicate_init.arg("init").arg(&project_path);
    duplicate_init
        .assert()
        .failure()
        .stderr(predicate::str::contains("Refusing to overwrite"));
}

#[test]
fn test_build_consumes_synq_toml_network_alias() {
    let dir = tempdir().unwrap();
    let source_path = write_counter_project(dir.path(), &valid_synq_toml("synergy-testnet-v3"));

    let mut build_cmd = Command::new(assert_cmd::cargo::cargo_bin!("cli"));
    build_cmd.arg("build").arg(&source_path);
    build_cmd.assert().success();

    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(source_path.with_extension("manifest.json")).unwrap())
            .unwrap();
    assert_eq!(manifest["required_network_id"], "synergy-testnet-v3");
}

#[test]
fn test_build_rejects_unsupported_synq_toml_chain() {
    let dir = tempdir().unwrap();
    let config = valid_synq_toml("synergy-testnet").replace("chain_id = 1266", "chain_id = 999");
    let source_path = write_counter_project(dir.path(), &config);

    let mut build_cmd = Command::new(assert_cmd::cargo::cargo_bin!("cli"));
    build_cmd.arg("build").arg(&source_path);
    build_cmd
        .assert()
        .failure()
        .stderr(predicate::str::contains("unsupported network.chain_id"));
}

#[test]
fn test_build_rejects_unsupported_synq_toml_signature_algorithm() {
    let dir = tempdir().unwrap();
    let config = valid_synq_toml("synergy-testnet").replace(
        "signature_algorithm = \"ML-DSA-65\"",
        "signature_algorithm = \"ML-DSA-87\"",
    );
    let source_path = write_counter_project(dir.path(), &config);

    let mut build_cmd = Command::new(assert_cmd::cargo::cargo_bin!("cli"));
    build_cmd.arg("build").arg(&source_path);
    build_cmd
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "unsupported security.signature_algorithm",
        ));
}

#[test]
fn test_keygen_sign_deploy_and_verify_deploy_use_pqsynq() {
    let dir = tempdir().unwrap();
    let project_path = dir.path().join("counter-signing");

    let mut init_cmd = Command::new(assert_cmd::cargo::cargo_bin!("cli"));
    init_cmd.arg("init").arg(&project_path);
    init_cmd.assert().success();

    let source_path = project_path.join("contracts/Counter.synq");
    let mut build_cmd = Command::new(assert_cmd::cargo::cargo_bin!("cli"));
    build_cmd.arg("build").arg(&source_path);
    build_cmd.assert().success();

    let key_dir = project_path.join("keys");
    let mut keygen_cmd = Command::new(assert_cmd::cargo::cargo_bin!("cli"));
    keygen_cmd
        .current_dir(&project_path)
        .arg("keygen")
        .arg("--algorithm")
        .arg("ml-dsa-65")
        .arg("--network")
        .arg("testnet")
        .arg("--out-dir")
        .arg(&key_dir);
    let keygen_output = keygen_cmd
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Generated ML-DSA-65 SynQ identity",
        ))
        .stdout(predicate::str::contains("network_id=synergy-testnet"))
        .get_output()
        .stdout
        .clone();

    let private_key_path = key_dir.join("synq-testnet-mldsa65.private.json");
    let public_key_path = key_dir.join("synq-testnet-mldsa65.public.json");
    assert!(private_key_path.exists());
    assert!(public_key_path.exists());
    let private_key_json: serde_json::Value =
        serde_json::from_slice(&fs::read(&private_key_path).unwrap()).unwrap();
    let private_key_hex = private_key_json["private_key_hex"].as_str().unwrap();
    assert!(!String::from_utf8(keygen_output)
        .unwrap()
        .contains(private_key_hex));

    let envelope_path = project_path.join("contracts/Counter.deploy.json");
    let mut sign_cmd = Command::new(assert_cmd::cargo::cargo_bin!("cli"));
    sign_cmd
        .arg("sign-deploy")
        .arg("--bytecode")
        .arg(source_path.with_extension("compiled.synq"))
        .arg("--manifest")
        .arg(source_path.with_extension("manifest.json"))
        .arg("--abi")
        .arg(source_path.with_extension("abi.json"))
        .arg("--private-key")
        .arg(&private_key_path)
        .arg("--output")
        .arg(&envelope_path)
        .arg("--nonce")
        .arg("42");
    sign_cmd
        .assert()
        .success()
        .stdout(predicate::str::contains("Signed SynQ deploy envelope"))
        .stdout(predicate::str::contains("domain=SYNQ_CONTRACT_DEPLOY_V1"))
        .stdout(predicate::str::contains("algorithm=ML-DSA-65"));

    let envelope: serde_json::Value =
        serde_json::from_slice(&fs::read(&envelope_path).unwrap()).unwrap();
    assert_eq!(envelope["signing_payload"]["chain_id"], 1266);
    assert_eq!(envelope["signing_payload"]["network_id"], "synergy-testnet");
    assert_eq!(envelope["signing_payload"]["nonce"], 42);

    let mut verify_cmd = Command::new(assert_cmd::cargo::cargo_bin!("cli"));
    verify_cmd.arg("verify-deploy").arg(&envelope_path);
    verify_cmd
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Deploy envelope verified through aegis-pqsynq",
        ))
        .stdout(predicate::str::contains("domain=SYNQ_CONTRACT_DEPLOY_V1"));

    let signer_address = private_key_json["address"].as_str().unwrap();
    let call_envelope_path = project_path.join("contracts/Counter.increment.call.json");
    let mut sign_call_cmd = Command::new(assert_cmd::cargo::cargo_bin!("cli"));
    sign_call_cmd
        .arg("sign-call")
        .arg("--contract")
        .arg(signer_address)
        .arg("--method")
        .arg("increment")
        .arg("--abi")
        .arg(source_path.with_extension("abi.json"))
        .arg("--manifest")
        .arg(source_path.with_extension("manifest.json"))
        .arg("--private-key")
        .arg(&private_key_path)
        .arg("--output")
        .arg(&call_envelope_path)
        .arg("--args")
        .arg("[]")
        .arg("--nonce")
        .arg("43");
    sign_call_cmd
        .assert()
        .success()
        .stdout(predicate::str::contains("Signed SynQ call envelope"))
        .stdout(predicate::str::contains("domain=SYNQ_CONTRACT_CALL_V1"))
        .stdout(predicate::str::contains("method_selector="));

    let call_envelope: serde_json::Value =
        serde_json::from_slice(&fs::read(&call_envelope_path).unwrap()).unwrap();
    assert_eq!(call_envelope["signing_payload"]["chain_id"], 1266);
    assert_eq!(
        call_envelope["signing_payload"]["network_id"],
        "synergy-testnet"
    );
    assert_eq!(call_envelope["signing_payload"]["nonce"], 43);

    let mut verify_call_cmd = Command::new(assert_cmd::cargo::cargo_bin!("cli"));
    verify_call_cmd.arg("verify-call").arg(&call_envelope_path);
    verify_call_cmd
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Call envelope verified through aegis-pqsynq",
        ))
        .stdout(predicate::str::contains("domain=SYNQ_CONTRACT_CALL_V1"));
}

#[test]
fn test_keygen_rejects_non_launch_signature_algorithm() {
    let dir = tempdir().unwrap();
    let mut keygen_cmd = Command::new(assert_cmd::cargo::cargo_bin!("cli"));
    keygen_cmd
        .arg("keygen")
        .arg("--algorithm")
        .arg("ml-dsa-87")
        .arg("--out-dir")
        .arg(dir.path());
    keygen_cmd
        .assert()
        .failure()
        .stderr(predicate::str::contains("launch policy requires ML-DSA-65"));
}

#[test]
fn test_verify_deploy_rejects_wrong_chain_before_pqsynq_context() {
    let dir = tempdir().unwrap();
    let source_path = write_counter_project(dir.path(), &valid_synq_toml("synergy-testnet"));

    let mut build_cmd = Command::new(assert_cmd::cargo::cargo_bin!("cli"));
    build_cmd.arg("build").arg(&source_path);
    build_cmd.assert().success();

    let key_dir = dir.path().join("keys");
    let mut keygen_cmd = Command::new(assert_cmd::cargo::cargo_bin!("cli"));
    keygen_cmd.arg("keygen").arg("--out-dir").arg(&key_dir);
    keygen_cmd.assert().success();

    let envelope_path = dir.path().join("Counter.deploy.json");
    let mut sign_cmd = Command::new(assert_cmd::cargo::cargo_bin!("cli"));
    sign_cmd
        .arg("sign-deploy")
        .arg("--bytecode")
        .arg(source_path.with_extension("compiled.synq"))
        .arg("--manifest")
        .arg(source_path.with_extension("manifest.json"))
        .arg("--abi")
        .arg(source_path.with_extension("abi.json"))
        .arg("--private-key")
        .arg(key_dir.join("synq-testnet-mldsa65.private.json"))
        .arg("--output")
        .arg(&envelope_path);
    sign_cmd.assert().success();

    let mut verify_cmd = Command::new(assert_cmd::cargo::cargo_bin!("cli"));
    verify_cmd
        .arg("verify-deploy")
        .arg(&envelope_path)
        .arg("--chain")
        .arg("999");
    verify_cmd
        .assert()
        .failure()
        .stderr(predicate::str::contains("Unsupported chain_id"));
}

#[test]
fn test_verify_call_rejects_wrong_domain_with_pqsynq_error_code() {
    let fixture = signed_call_project();
    let mut envelope: serde_json::Value =
        serde_json::from_slice(&fs::read(&fixture.call_envelope_path).unwrap()).unwrap();
    envelope["signing_payload"]["domain_tag"] =
        serde_json::Value::String("SynqContractDeployV1".to_string());
    let wrong_domain_path = fixture
        .call_envelope_path
        .with_file_name("Counter.increment.wrong-domain.call.json");
    fs::write(
        &wrong_domain_path,
        serde_json::to_vec_pretty(&envelope).unwrap(),
    )
    .unwrap();

    let mut verify_call_cmd = Command::new(assert_cmd::cargo::cargo_bin!("cli"));
    verify_call_cmd.arg("verify-call").arg(&wrong_domain_path);
    verify_call_cmd
        .assert()
        .failure()
        .stderr(predicate::str::contains("AEGIS-DOMAIN"));
}

#[test]
fn test_verify_call_rejects_invalid_signature_with_pqsynq_error_code() {
    let fixture = signed_call_project();
    let mut envelope: serde_json::Value =
        serde_json::from_slice(&fs::read(&fixture.call_envelope_path).unwrap()).unwrap();
    let first = envelope["signature"]["bytes"][0].as_u64().unwrap();
    envelope["signature"]["bytes"][0] = serde_json::Value::from(first ^ 1);
    let invalid_signature_path = fixture
        .call_envelope_path
        .with_file_name("Counter.increment.invalid-signature.call.json");
    fs::write(
        &invalid_signature_path,
        serde_json::to_vec_pretty(&envelope).unwrap(),
    )
    .unwrap();

    let mut verify_call_cmd = Command::new(assert_cmd::cargo::cargo_bin!("cli"));
    verify_call_cmd
        .arg("verify-call")
        .arg(&invalid_signature_path);
    verify_call_cmd
        .assert()
        .failure()
        .stderr(predicate::str::contains("AEGIS-SIG"));
}

#[test]
fn test_verify_call_rejects_method_selector_payload_mismatch() {
    let fixture = signed_call_project();
    let mut envelope: serde_json::Value =
        serde_json::from_slice(&fs::read(&fixture.call_envelope_path).unwrap()).unwrap();
    let first = envelope["method_selector"][0].as_u64().unwrap();
    envelope["method_selector"][0] = serde_json::Value::from(first ^ 1);
    let wrong_selector_path = fixture
        .call_envelope_path
        .with_file_name("Counter.increment.wrong-selector.call.json");
    fs::write(
        &wrong_selector_path,
        serde_json::to_vec_pretty(&envelope).unwrap(),
    )
    .unwrap();

    let mut verify_call_cmd = Command::new(assert_cmd::cargo::cargo_bin!("cli"));
    verify_call_cmd.arg("verify-call").arg(&wrong_selector_path);
    verify_call_cmd
        .assert()
        .failure()
        .stderr(predicate::str::contains("AEGIS-CANON"));
}

#[test]
fn test_sign_call_rejects_missing_method_in_abi() {
    let dir = tempdir().unwrap();
    let source_path = write_counter_project(dir.path(), &valid_synq_toml("synergy-testnet"));

    let mut build_cmd = Command::new(assert_cmd::cargo::cargo_bin!("cli"));
    build_cmd.arg("build").arg(&source_path);
    build_cmd.assert().success();

    let key_dir = dir.path().join("keys");
    let mut keygen_cmd = Command::new(assert_cmd::cargo::cargo_bin!("cli"));
    keygen_cmd.arg("keygen").arg("--out-dir").arg(&key_dir);
    keygen_cmd.assert().success();

    let key_json: serde_json::Value = serde_json::from_slice(
        &fs::read(key_dir.join("synq-testnet-mldsa65.private.json")).unwrap(),
    )
    .unwrap();
    let mut sign_call_cmd = Command::new(assert_cmd::cargo::cargo_bin!("cli"));
    sign_call_cmd
        .arg("sign-call")
        .arg("--contract")
        .arg(key_json["address"].as_str().unwrap())
        .arg("--method")
        .arg("missing")
        .arg("--abi")
        .arg(source_path.with_extension("abi.json"))
        .arg("--manifest")
        .arg(source_path.with_extension("manifest.json"))
        .arg("--private-key")
        .arg(key_dir.join("synq-testnet-mldsa65.private.json"))
        .arg("--output")
        .arg(dir.path().join("missing.call.json"));
    sign_call_cmd
        .assert()
        .failure()
        .stderr(predicate::str::contains("ABI does not contain method"));
}

#[test]
fn test_compile_fails_on_semantic_errors() {
    let invalid_contract = r#"
        contract InvalidSemantic {
            function break_it() {
                undefined_symbol = 42;
            }
        }
    "#;

    let mut file = NamedTempFile::new().unwrap();
    write!(file, "{}", invalid_contract).unwrap();

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("cli"));
    cmd.arg("compile").arg("--path").arg(file.path());

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Semantic analysis failed"));
}
