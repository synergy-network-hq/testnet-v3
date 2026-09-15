use assert_cmd::prelude::*;
use predicates::prelude::*;
use std::io::Write;
use std::process::Command;
use tempfile::NamedTempFile;

#[test]
fn test_compile_and_run() {
    let contract = r#"
        contract MyContract {
            function my_function() {}
        }
    "#;

    let mut file = NamedTempFile::new().unwrap();
    write!(file, "{}", contract).unwrap();

    let mut cmd = Command::cargo_bin("synq-cli").unwrap();
    cmd.arg("compile").arg("--path").arg(file.path());

    cmd.assert().success();

    let bytecode_path = file.path().with_extension("synq_bytecode");
    assert!(bytecode_path.exists());

    let mut run_cmd = Command::cargo_bin("synq-cli").unwrap();
    run_cmd.arg("run").arg("--path").arg(&bytecode_path);

    run_cmd
        .assert()
        .success()
        .stdout(predicate::str::contains("Execution finished successfully"));
}

#[test]
fn test_compile_produces_real_verifiable_signature() {
    let contract = r#"
        contract MyContract {
            function my_function() {}
        }
    "#;

    let mut file = NamedTempFile::new().unwrap();
    write!(file, "{}", contract).unwrap();

    Command::cargo_bin("synq-cli")
        .unwrap()
        .arg("compile")
        .arg("--path")
        .arg(file.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("Signed with real dilithium"));

    let bytecode_path = file.path().with_extension("synq_bytecode");
    let sig_path_str = format!("{}.sig.json", bytecode_path.display());
    let sig_path = std::path::PathBuf::from(&sig_path_str);
    assert!(
        sig_path.exists(),
        "signature sidecar file should be written"
    );

    let sig_content = std::fs::read_to_string(&sig_path).unwrap();
    let sig_json: serde_json::Value = serde_json::from_str(&sig_content).unwrap();
    assert_eq!(sig_json["algorithm"], "dilithium");
    assert!(sig_json["public_key"].as_str().unwrap().len() > 0);
    assert!(sig_json["signature"].as_str().unwrap().len() > 0);

    // A genuine, untampered bytecode file must verify successfully.
    Command::cargo_bin("synq-cli")
        .unwrap()
        .arg("verify")
        .arg("--path")
        .arg(&bytecode_path)
        .assert()
        .success()
        .stdout(predicate::str::contains("Signature valid"));
}

#[test]
fn test_verify_rejects_tampered_bytecode() {
    let contract = r#"
        contract MyContract {
            function my_function() {}
        }
    "#;

    let mut file = NamedTempFile::new().unwrap();
    write!(file, "{}", contract).unwrap();

    Command::cargo_bin("synq-cli")
        .unwrap()
        .arg("compile")
        .arg("--path")
        .arg(file.path())
        .assert()
        .success();

    let bytecode_path = file.path().with_extension("synq_bytecode");

    // Tamper with the compiled bytecode after signing.
    let mut bytes = std::fs::read(&bytecode_path).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0xFF;
    std::fs::write(&bytecode_path, &bytes).unwrap();

    Command::cargo_bin("synq-cli")
        .unwrap()
        .arg("verify")
        .arg("--path")
        .arg(&bytecode_path)
        .assert()
        .success()
        .stdout(predicate::str::contains("Signature INVALID"));
}
