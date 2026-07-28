//! Testnet-v3 genesis ceremony.
//!
//! Bridges the three encrypted production authority bundles into the completed
//! Track G deployment mechanism. It adds no cryptography of its own: decryption
//! is the Synergy Address Engine's approved reader, deployment is
//! `genesis_deployment::execute_genesis_deployment`.
//!
//! Secrets live in memory for exactly as long as the deployment needs them and
//! are zeroized on every exit path.

use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use synergy_testnet::address::derive_standard_account_address;
use synergy_testnet::execution::{ExecutionState, GenesisExecutionSnapshot};
use synergy_testnet::genesis_deployment::*;
use synergy_testnet::synq_execution::SynQContractArtifact;

const DEPLOYER: &str = "SNRG-TESTNET-V3-GENESIS-DEPLOYER";
const GOVERNANCE: &str = "SNRG-TESTNET-V3-GOVERNANCE-AUTHORITY";
const REGISTRY: &str = "SNRG-TESTNET-V3-VALIDATOR-REGISTRY-AUTHORITY";
const CONFIRMATION: &str = "EXECUTE TESTNET-V3 GENESIS";

/// Best-effort wipe. Rust may still move a `Vec` before this runs, so the real
/// guarantee is scope: nothing here is ever written to disk or printed.
fn zeroize(buf: &mut Vec<u8>) {
    for byte in buf.iter_mut() {
        *byte = 0;
    }
    buf.clear();
    buf.shrink_to_fit();
}

fn zeroize_string(s: &mut String) {
    unsafe {
        for byte in s.as_bytes_mut().iter_mut() {
            *byte = 0;
        }
    }
    s.clear();
    s.shrink_to_fit();
}

struct Secret(Vec<u8>);
impl Drop for Secret {
    fn drop(&mut self) {
        zeroize(&mut self.0);
    }
}
impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Secret([redacted {} bytes])", self.0.len())
    }
}

fn fail(message: &str) -> ! {
    eprintln!("\n  CEREMONY ABORTED: {message}");
    std::process::exit(1);
}

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(
        &std::fs::read(path).unwrap_or_else(|e| fail(&format!("read {}: {e}", path.display()))),
    )
    .unwrap_or_else(|e| fail(&format!("parse {}: {e}", path.display())))
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(bytes))
}

fn file_checksum(path: &Path) -> String {
    sha256_hex(
        &std::fs::read(path).unwrap_or_else(|e| fail(&format!("read {}: {e}", path.display()))),
    )
}

/// Rejects any attempt to supply a passphrase other than at the prompt.
fn reject_non_interactive_passphrases(args: &[String]) {
    for var in ["SYNERGY_PASSPHRASE", "SYNERGY_DECRYPT_PASSPHRASE"] {
        if std::env::var(var).is_ok() {
            fail(&format!(
                "{var} is set. Genesis ceremony passphrases must be entered interactively. Unset it and re-run."
            ));
        }
    }
    for arg in args {
        let lower = arg.to_ascii_lowercase();
        if lower.contains("passphrase") || lower.contains("password") {
            fail("passphrases must never be supplied as command arguments");
        }
    }
}

/// Checked immediately before the first prompt, so argument and mode errors
/// surface without needing a terminal.
fn require_terminal() {
    if !atty_stdin() {
        fail("a terminal is required: genesis ceremony passphrases are entered without echo");
    }
}

fn atty_stdin() -> bool {
    #[cfg(unix)]
    unsafe {
        extern "C" {
            fn isatty(fd: i32) -> i32;
        }
        isatty(0) == 1
    }
    #[cfg(not(unix))]
    {
        true
    }
}

/// Locates the Address Engine binary that owns the approved custody format.
fn engine_binary() -> PathBuf {
    if let Ok(explicit) = std::env::var("SYNERGY_KEYGEN_BIN") {
        return PathBuf::from(explicit);
    }
    PathBuf::from(
        "/Volumes/xcode/Synergy-Network-Projects/protocol-components/\
synergy-address-engine/target/release/synergy-keygen",
    )
}

/// Runs `synergy-keygen decrypt --stdout`, inheriting the terminal so the
/// passphrase prompt is the engine's own non-echoing prompt. Nothing secret is
/// written to disk and the passphrase never reaches this process.
fn decrypt_via_engine(enc_path: &Path, role: &str) -> Vec<u8> {
    use std::process::{Command, Stdio};
    let engine = engine_binary();
    if !engine.exists() {
        fail(&format!(
            "Address Engine binary not found at {}. Set SYNERGY_KEYGEN_BIN.",
            engine.display()
        ));
    }
    let output = Command::new(&engine)
        .arg("decrypt")
        .arg(enc_path)
        .arg("--stdout")
        .stdin(Stdio::inherit())
        .stderr(Stdio::inherit())
        .stdout(Stdio::piped())
        .output()
        .unwrap_or_else(|e| fail(&format!("{role}: could not run the Address Engine: {e}")));
    if !output.status.success() {
        fail(&format!(
            "{role}: decryption failed (wrong passphrase or damaged custody file)"
        ));
    }
    output.stdout
}

struct Authority {
    role: String,
    account_address: String,
    public_key: Vec<u8>,
    private_key: Secret,
}

/// Decrypts one bundle and refuses to return until every public check passes.
fn unlock(base: &Path, role: &str, frozen: &Value) -> Authority {
    let dir = base.join(role);
    let manifest = read_json(&dir.join("manifest.json"));
    let pubdoc = read_json(&dir.join("identity.pub.json"));
    let corr = read_json(&dir.join("correspondence.json"));

    if manifest["test_fixture"] != json!(false) {
        fail(&format!(
            "{role}: bundle is marked test_fixture and cannot sign a production genesis"
        ));
    }
    if manifest["role_id"] != json!(role) {
        fail(&format!("{role}: manifest role_id mismatch"));
    }
    if manifest["network_id"] != json!("synergy-testnet-v3")
        || manifest["chain_id"] != json!(1266)
        || manifest["environment"] != json!("testnet-v3")
    {
        fail(&format!("{role}: network / chain / environment mismatch"));
    }
    if manifest["algorithm"] != json!("ML-DSA-87") {
        fail(&format!("{role}: algorithm is not ML-DSA-87"));
    }

    // Checksums over the public bundle.
    let sums = std::fs::read_to_string(dir.join("SHA256SUMS"))
        .unwrap_or_else(|e| fail(&format!("{role}: read SHA256SUMS: {e}")));
    for line in sums.lines().filter(|l| !l.trim().is_empty()) {
        let (digest, name) = line
            .split_once("  ")
            .unwrap_or_else(|| fail(&format!("{role}: malformed SHA256SUMS")));
        if file_checksum(&dir.join(name)) != digest {
            fail(&format!("{role}: checksum mismatch for {name}"));
        }
    }

    let expected_account = frozen["authorities"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["role_id"] == json!(role))
        .unwrap_or_else(|| fail(&format!("{role}: absent from the frozen authority record")));
    let expected_address = expected_account["standard_account_address"]
        .as_str()
        .unwrap();
    let expected_fingerprint = expected_account["public_key_fingerprint"].as_str().unwrap();

    if expected_address.starts_with("tsynq") {
        fail(&format!(
            "{role}: frozen record uses the retired tsynq form"
        ));
    }

    let public_key = base64_decode(
        pubdoc["public_key"]
            .as_str()
            .unwrap_or_else(|| fail(&format!("{role}: identity.pub.json has no public_key"))),
    );
    if public_key.len() != 2592 {
        fail(&format!(
            "{role}: public key is not ML-DSA-87 (got {} bytes)",
            public_key.len()
        ));
    }
    let fingerprint = format!("sha256:{}", sha256_hex(&public_key));
    if fingerprint != expected_fingerprint
        || manifest["public_key_fingerprint"] != json!(fingerprint)
    {
        fail(&format!(
            "{role}: public-key fingerprint does not match the frozen record"
        ));
    }
    let derived = derive_standard_account_address(&public_key);
    if derived != expected_address || manifest["standard_account_address"] != json!(derived) {
        fail(&format!(
            "{role}: canonical syna address does not match the frozen record"
        ));
    }
    if corr["standard_account"]["recomputed_address"] != json!(derived)
        || corr["standard_account"]["verified"] != json!(true)
    {
        fail(&format!("{role}: correspondence proof does not agree"));
    }

    // Only now ask for the secret.
    let label = match role {
        DEPLOYER => "Genesis Deployer passphrase",
        GOVERNANCE => "Governance Authority passphrase",
        REGISTRY => "ValidatorRegistry Authority passphrase",
        other => other,
    };
    // The approved decryptor runs in its own process and prompts on the shared
    // terminal, so the passphrase never enters this process at all. Only the
    // decrypted payload crosses the pipe, in memory.
    println!("\n  {label} (entered in the Address Engine):");
    let plaintext = decrypt_via_engine(&dir.join("identity.enc.json"), role);

    let mut recovered = Secret(plaintext);
    let doc: Value = serde_json::from_slice(&recovered.0).unwrap_or_else(|_| {
        fail(&format!(
            "{role}: decrypted payload is not the expected record"
        ))
    });
    let mut private_key = base64_decode(
        doc["private_key"]
            .as_str()
            .unwrap_or_else(|| fail(&format!("{role}: no private key in payload"))),
    );
    zeroize(&mut recovered.0);

    if private_key.len() != 4896 {
        zeroize(&mut private_key);
        fail(&format!(
            "{role}: recovered key is not an ML-DSA-87 secret key"
        ));
    }
    // Prove the recovered secret belongs to the verified public key.
    if !signs_correctly(&private_key, &public_key) {
        zeroize(&mut private_key);
        fail(&format!(
            "{role}: recovered private key does not correspond to the bundle public key"
        ));
    }

    println!("    unlocked  {role}  {derived}");
    Authority {
        role: role.to_string(),
        account_address: derived,
        public_key,
        private_key: Secret(private_key),
    }
}

fn signs_correctly(private_key: &[u8], public_key: &[u8]) -> bool {
    use pqsynq::traits::{DetachedSignature, DigitalSignature};
    use pqsynq::Sign;
    let probe = b"synergy-genesis-ceremony-keypair-correspondence-probe";
    match Sign::mldsa87().detached_sign(probe, private_key) {
        // Argument order is (message, signature, public_key).
        Ok(sig) => Sign::mldsa87()
            .verify_detached(probe, &sig, public_key)
            .unwrap_or(false),
        Err(_) => false,
    }
}

fn base64_decode(input: &str) -> Vec<u8> {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    let (mut buf, mut bits) = (0u32, 0u32);
    for c in input
        .bytes()
        .filter(|c| *c != b'=' && !c.is_ascii_whitespace())
    {
        let v = match T.iter().position(|t| *t == c) {
            Some(v) => v as u32,
            None => fail("malformed base64 in bundle"),
        };
        buf = (buf << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    out
}

fn write_public(path: &Path, contents: &str) {
    std::fs::write(path, contents)
        .unwrap_or_else(|e| fail(&format!("write {}: {e}", path.display())));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
}

fn frozen_contract_address<'a>(contracts: &'a Value, contract_name: &str) -> &'a str {
    contracts["contracts"]
        .as_array()
        .and_then(|entries| {
            entries
                .iter()
                .find(|entry| entry.get("contract").and_then(Value::as_str) == Some(contract_name))
        })
        .and_then(|entry| entry.get("contract_address"))
        .and_then(Value::as_str)
        .filter(|address| !address.is_empty())
        .unwrap_or_else(|| {
            fail(&format!(
                "frozen contract record is missing {contract_name}"
            ))
        })
}

fn genesis_execution_state(repo: &Path, contracts: &Value) -> ExecutionState {
    let genesis_path = repo.join("genesis.testnet-v3.identity-assigned.json");
    let genesis = read_json(&genesis_path);
    let balances = genesis["balances"]
        .as_array()
        .unwrap_or_else(|| fail("source genesis balances must be an array"));
    let mut state = ExecutionState::new();
    let mut total = 0u128;
    for balance in balances {
        let source_address = balance["address"]
            .as_str()
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| fail("source genesis balance address is missing"));
        // TEM-A01 funds the deployed TeamVesting instance, not its separate
        // FN-DSA administrative/custody identity. SaleClaim is excluded, so
        // SAL-A01 remains at its custody identity.
        let address = if balance["account_id"] == "TEM-A01" {
            frozen_contract_address(contracts, "TeamVesting")
        } else {
            source_address
        };
        let amount = balance["balance_nwei"]
            .as_str()
            .unwrap_or_else(|| fail("source genesis balance_nwei must be a decimal string"))
            .parse::<u128>()
            .unwrap_or_else(|error| fail(&format!("parse source genesis balance_nwei: {error}")));
        if state
            .balances_nwei
            .insert(address.to_string(), amount)
            .is_some()
        {
            fail(&format!(
                "source genesis contains duplicate balance address {address}"
            ));
        }
        total = total
            .checked_add(amount)
            .unwrap_or_else(|| fail("source genesis balance sum overflowed u128"));
    }
    let declared_total = genesis["allocation_sum_check"]["grand_total_nwei"]
        .as_str()
        .unwrap_or_else(|| fail("source genesis allocation_sum_check.grand_total_nwei is missing"))
        .parse::<u128>()
        .unwrap_or_else(|error| fail(&format!("parse source genesis grand total: {error}")));
    if total != declared_total {
        fail(&format!(
            "source genesis balances sum to {total}, declared total is {declared_total}"
        ));
    }
    state
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    reject_non_interactive_passphrases(&args);

    let mut authorities_file = None;
    let mut contracts_file = None;
    let mut output_dir = None;
    let mut dry_run = false;
    let mut execute = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--authorities-file" => {
                authorities_file = args.get(i + 1).cloned();
                i += 2;
            }
            "--contracts-file" => {
                contracts_file = args.get(i + 1).cloned();
                i += 2;
            }
            "--output-dir" => {
                output_dir = args.get(i + 1).cloned();
                i += 2;
            }
            "--dry-run" => {
                dry_run = true;
                i += 1;
            }
            "--execute" => {
                execute = true;
                i += 1;
            }
            other => fail(&format!("unknown flag '{other}'")),
        }
    }
    if dry_run == execute {
        fail("choose exactly one of --dry-run or --execute (--dry-run is the safe default path)");
    }
    let (authorities_file, contracts_file, output_dir) =
        match (authorities_file, contracts_file, output_dir) {
            (Some(a), Some(c), Some(o)) => (PathBuf::from(a), PathBuf::from(c), PathBuf::from(o)),
            _ => fail("required: --authorities-file --contracts-file --output-dir"),
        };

    let repo = std::env::current_dir().unwrap_or_else(|e| fail(&format!("cwd: {e}")));
    let frozen = read_json(&authorities_file);
    let expected_contracts = read_json(&contracts_file);
    let source_genesis = repo.join("genesis.testnet-v3.identity-assigned.json");

    if frozen["test_fixture"] != json!(false) || frozen["status"] != json!("FROZEN") {
        fail("authority record is not a frozen production record");
    }
    if expected_contracts["canonical_synergy_address_model"] != json!(true) {
        fail("contract record was not produced under the canonical Synergy address model");
    }

    let input_manifest = json!({
        "authorities_file": authorities_file.display().to_string(),
        "authorities_file_sha256": file_checksum(&authorities_file),
        "contracts_file": contracts_file.display().to_string(),
        "contracts_file_sha256": file_checksum(&contracts_file),
        "source_genesis_file": source_genesis.display().to_string(),
        "source_genesis_file_sha256": file_checksum(&source_genesis),
        "mode": if execute { "execute" } else { "dry-run" },
    });
    let input_digest = sha256_hex(
        serde_json::to_string(&json!({
            "a": input_manifest["authorities_file_sha256"],
            "c": input_manifest["contracts_file_sha256"],
            "g": input_manifest["source_genesis_file_sha256"],
        }))
        .unwrap()
        .as_bytes(),
    );

    println!("\n  Synergy Testnet-v3 genesis ceremony");
    println!(
        "  mode              : {}",
        if execute { "EXECUTE" } else { "dry-run" }
    );
    println!(
        "  authorities sha256: {}",
        input_manifest["authorities_file_sha256"].as_str().unwrap()
    );
    println!(
        "  contracts   sha256: {}",
        input_manifest["contracts_file_sha256"].as_str().unwrap()
    );
    println!(
        "  genesis     sha256: {}",
        input_manifest["source_genesis_file_sha256"]
            .as_str()
            .unwrap()
    );
    println!("  candidate input id: {input_digest}");

    // Production mode requires prior matching dry-run evidence and an explicit phrase.
    if execute {
        let evidence = output_dir.join("dry-run-status.json");
        if !evidence.exists() {
            fail("no dry-run evidence in the output directory; run --dry-run first");
        }
        let prior = read_json(&evidence);
        if prior["status"] != json!("DRY_RUN_PASSED") {
            fail("prior dry run did not pass");
        }
        if prior["candidate_input_id"] != json!(input_digest.clone()) {
            fail("inputs changed since the dry run; re-run --dry-run");
        }
        println!("\n  Type the confirmation phrase to proceed:");
        println!("    {CONFIRMATION}");
        print!("  > ");
        let _ = std::io::stdout().flush();
        let mut typed = String::new();
        if std::io::stdin().read_line(&mut typed).is_err() {
            fail("could not read confirmation");
        }
        if typed.trim() != CONFIRMATION {
            fail("confirmation phrase did not match exactly");
        }
    }

    require_terminal();
    println!("\n  Unlocking three production authorities (three passphrase prompts).");
    let identities = repo.join("testnet-v3-identity-files");
    let deployer = unlock(&identities, DEPLOYER, &frozen);
    let governance = unlock(&identities, GOVERNANCE, &frozen);
    let registry = unlock(&identities, REGISTRY, &frozen);

    let frozen_addr = |role: &str| -> String {
        frozen["authorities"]
            .as_array()
            .unwrap()
            .iter()
            .find(|a| a["role_id"] == json!(role))
            .unwrap()["standard_account_address"]
            .as_str()
            .unwrap()
            .to_string()
    };

    let authorities = GenesisAuthorities {
        genesis_deployer: GenesisSigner {
            public_key: deployer.public_key.clone(),
            private_key: deployer.private_key.0.clone(),
        },
        governance: GenesisSigner {
            public_key: governance.public_key.clone(),
            private_key: governance.private_key.0.clone(),
        },
        emergency_slashing_authority: frozen_addr("SNRG-TESTNET-V3-EMERGENCY-SLASHING"),
        validator_registry_authority: registry.account_address.clone(),
        validator_registry_authority_key: GenesisSigner {
            public_key: registry.public_key.clone(),
            private_key: registry.private_key.0.clone(),
        },
        reward_distributor_authority: frozen_addr("SNRG-TESTNET-V3-REWARD-DISTRIBUTOR-AUTHORITY"),
        identity_fee_collector: "synf1pnchsrnyral0u9r65xusjrexuctfh465h06l".to_string(),
        team_vesting_admin: "synu18tmdavp9yskftz4lldshrxvzwyg0tpnu23n9".to_string(),
        oracle_publisher: frozen_addr("SNRG-TESTNET-V3-EMERGENCY-PAUSE-AUTHORITY"),
    };

    let artifacts: BTreeMap<GenesisContract, SynQContractArtifact> =
        GenesisContract::APPROVED_ORDER
            .iter()
            .map(|c| {
                let dir = repo.join("genesis-contracts/staged-governance-v1");
                let name = c.name();
                let read = |ext: &str| {
                    std::fs::read(dir.join(format!("{name}.{ext}")))
                        .unwrap_or_else(|e| fail(&format!("read staged {name}.{ext}: {e}")))
                };
                (
                    *c,
                    SynQContractArtifact::new(
                        read("compiled.synq"),
                        String::from_utf8(read("abi.json")).unwrap(),
                        String::from_utf8(read("manifest.json")).unwrap(),
                    ),
                )
            })
            .collect();
    let plan = GenesisDeploymentPlan::new(&artifacts).unwrap_or_else(|e| fail(&e));
    let parameters = production_parameters(&repo);

    println!("\n  Executing nine deployments and twenty-seven initialization calls…");
    let mut state = genesis_execution_state(&repo, &expected_contracts);
    let outcome = execute_genesis_deployment(&mut state, &plan, &authorities, &parameters);

    // Secrets are no longer needed regardless of outcome.
    let mut auth = authorities;
    zeroize(&mut auth.genesis_deployer.private_key);
    zeroize(&mut auth.governance.private_key);
    zeroize(&mut auth.validator_registry_authority_key.private_key);
    drop(deployer);
    drop(governance);
    drop(registry);

    let outcome = outcome.unwrap_or_else(|e| fail(&format!("genesis deployment failed: {e}")));
    let snapshot = GenesisExecutionSnapshot::capture_testnet_v3(&state)
        .unwrap_or_else(|e| fail(&format!("capture finalized execution state: {e}")));
    if snapshot.state_root != outcome.post_deployment_state_root.to_hex() {
        fail("captured execution-state root does not match deployment outcome");
    }
    let snapshot_name = if execute {
        "execution-state.json"
    } else {
        "dry-run-execution-state.json"
    };
    let snapshot_contents = serde_json::to_string_pretty(&snapshot).unwrap() + "\n";
    let snapshot_sha256 = sha256_hex(snapshot_contents.as_bytes());
    let snapshot_canonical_sha256 = sha256_hex(&serde_json::to_vec(&snapshot).unwrap());

    // Compare against the frozen Phase 3-4 derivation record.
    let mut mismatches = Vec::new();
    for entry in expected_contracts["contracts"].as_array().unwrap() {
        let name = entry["contract"].as_str().unwrap();
        let expected = entry["contract_address"].as_str().unwrap();
        let contract = GenesisContract::APPROVED_ORDER
            .iter()
            .find(|c| c.name() == name)
            .unwrap();
        let actual = outcome
            .addresses
            .get(contract)
            .map(String::as_str)
            .unwrap_or("<absent>");
        if actual != expected {
            mismatches.push(format!("{name}: expected {expected}, got {actual}"));
        }
    }

    std::fs::create_dir_all(&output_dir)
        .unwrap_or_else(|e| fail(&format!("create output dir: {e}")));
    let addresses: BTreeMap<String, String> = outcome
        .addresses
        .iter()
        .map(|(c, a)| (c.name().to_string(), a.clone()))
        .collect();
    let evidence = json!({
        "status": if mismatches.is_empty() {
            if execute { "EXECUTION_PASSED" } else { "DRY_RUN_PASSED" }
        } else {
            "ADDRESS_MISMATCH"
        },
        "mode": if execute { "execute" } else { "dry-run" },
        "candidate_input_id": input_digest,
        "inputs": input_manifest,
        "contract_addresses": addresses,
        "deployment_receipts": outcome.deployment_receipts.len(),
        "initialization_receipts": outcome.initialization_receipts.len(),
        "deployment_receipt_root": outcome.receipt_root.to_hex(),
        "post_deployment_execution_state_root": outcome.post_deployment_state_root.to_hex(),
        "post_deployment_aivm_state_root": snapshot.aivm_state_root,
        "execution_state_snapshot": snapshot_name,
        "execution_state_snapshot_sha256": snapshot_sha256,
        "execution_state_snapshot_canonical_sha256": snapshot_canonical_sha256,
        "execution_state_balance_count": snapshot.balances_nwei.len(),
        "execution_state_contract_count": snapshot.synq_contracts.len(),
        "execution_state_artifact_count": snapshot.synq_artifacts.len(),
        "deployment_manifest_hash": outcome.deployment_manifest_hash.to_hex(),
        "genesis_deployer_retirement": format!("{:?}", outcome.lifecycle),
        "address_mismatches": mismatches,
    });
    let name = if execute {
        "execution-status.json"
    } else {
        "dry-run-status.json"
    };
    write_public(&output_dir.join(snapshot_name), &snapshot_contents);
    write_public(
        &output_dir.join(name),
        &(serde_json::to_string_pretty(&evidence).unwrap() + "\n"),
    );
    write_public(
        &output_dir.join("deployment-receipts.json"),
        &(serde_json::to_string_pretty(&outcome.deployment_receipts).unwrap() + "\n"),
    );
    write_public(
        &output_dir.join("initialization-receipts.json"),
        &(serde_json::to_string_pretty(&outcome.initialization_receipts).unwrap() + "\n"),
    );

    if !mismatches.is_empty() {
        for m in &mismatches {
            eprintln!("    MISMATCH  {m}");
        }
        fail("derived addresses do not match the frozen record; no signable candidate produced");
    }

    println!("\n  All nine addresses match the frozen derivation record.");
    println!(
        "  deployments {} / initializations {}",
        outcome.deployment_receipts.len(),
        outcome.initialization_receipts.len()
    );
    println!(
        "  post-deployment execution root  : {}",
        outcome.post_deployment_state_root.to_hex()
    );
    println!(
        "  post-deployment AIVM state root : {}",
        snapshot.aivm_state_root
    );
    println!(
        "  deployment receipt root         : {}",
        outcome.receipt_root.to_hex()
    );
    println!(
        "  genesis deployer                : {:?}",
        outcome.lifecycle
    );
    println!("  evidence written to {}", output_dir.display());
    if !execute {
        println!("\n  Dry run only. Nothing was committed to the canonical genesis.");
    }
}

fn production_parameters(repo: &Path) -> GenesisParameters {
    let g: Value = read_json(&repo.join("genesis.testnet-v3.identity-assigned.json"));
    let c = &g["contracts"];
    let s = |v: &Value| v.as_str().unwrap().to_string();
    let n = |v: &Value| v.as_u64().unwrap().to_string();
    let validators = c["validator_registry"]["init_params"]["validators"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| GenesisValidator {
            id_hash: format!("0x{}", s(&v["validator_id_hash"])),
            operator_address: s(&v["operator_address"]),
            reward_address: s(&v["reward_address"]),
            voting_power: n(&v["voting_power"]),
            self_stake_nwei: s(&v["stake_nwei"]),
            metadata_hash: format!("0x{}", s(&v["metadata_hash"])),
            key_bundle_hash: format!("0x{}", s(&v["key_bundle_hash"])),
            activation_height: n(&v["activation_height"]),
        })
        .collect();
    GenesisParameters {
        identity_registration_fee_nwei: s(&c["identity"]["init_params"]["registration_fee_nwei"]),
        identity_reserved_names: c["identity"]["init_params"]["reserved_names"]
            .as_array()
            .unwrap()
            .iter()
            .map(s)
            .collect(),
        validator_max_count: n(&c["validator_registry"]["init_params"]["max_validator_count"]),
        validator_min_count: n(&c["validator_registry"]["init_params"]["min_validator_count"]),
        validator_min_self_stake_nwei: s(
            &c["validator_registry"]["init_params"]["min_self_stake_nwei"]
        ),
        validators,
        staking_min_stake_nwei: s(&c["staking"]["init_params"]["min_stake_nwei"]),
        staking_max_stake_nwei: s(&c["staking"]["init_params"]["max_stake_nwei"]),
        staking_unbonding_blocks: "302400".to_string(),
        governance_quorum_bps: "6000".to_string(),
        governance_approval_bps: "5000".to_string(),
        governance_veto_bps: "3300".to_string(),
        governance_min_deposit_nwei: s(&c["governance"]["init_params"]["min_deposit_nwei"]),
        governance_voting_blocks: "302400".to_string(),
        governance_timelock_blocks: "43200".to_string(),
        treasury_required_signers: n(&c["treasury"]["init_params"]["required_signers"]),
        treasury_signers: c["treasury"]["init_params"]["signers"]
            .as_array()
            .unwrap()
            .iter()
            .map(s)
            .collect(),
        slashing_double_sign_bps: "500".to_string(),
        slashing_downtime_bps: "100".to_string(),
        slashing_invalid_block_bps: "500".to_string(),
        slashing_missed_blocks_threshold: n(
            &c["slashing"]["init_params"]["downtime_missed_blocks_threshold"]
        ),
        slashing_jail_blocks: "43200".to_string(),
        oracle_quorum_threshold: n(&c["synergy_oracle"]["init_params"]["quorum_threshold"]),
        oracle_replay_protection: true,
        oracle_source_domains: c["synergy_oracle"]["init_params"]["accepted_source_domains"]
            .as_array()
            .unwrap()
            .iter()
            .map(s)
            .collect(),
        team_vesting_start_time: "1775044800".to_string(),
        team_allocation_nwei: s(&c["team_vesting"]["init_params"]["total_allocation_nwei"]),
        support_allocation_nwei: "200000000000000000".to_string(),
        team_count: "5".to_string(),
        support_count: "4".to_string(),
    }
}
