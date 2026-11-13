//! Key lifecycle manager example
//!
//! Demonstrates key registration, rotation scheduling, and retirement.

use aegis_pqvm::key_lifecycle::{AlgorithmFamily, KeyLifecycleManager, KeyState};

fn main() {
    println!("=== Key Lifecycle Manager Example ===\n");

    let mut klm = KeyLifecycleManager::new();

    // Register ML-KEM-768 key
    let id1 = klm
        .register_key(AlgorithmFamily::MLKEM768)
        .expect("register ML-KEM key");
    println!("1. Registered ML-KEM-768 key: id={}", id1);

    // Register ML-DSA-87 key
    let id2 = klm
        .register_key(AlgorithmFamily::MLDSA87)
        .expect("register ML-DSA key");
    println!("2. Registered ML-DSA-87 key: id={}", id2);

    // Touch key (update last_used)
    klm.touch_key(id1).expect("touch key");
    println!("3. Touched key {} (last_used updated)", id1);

    // Schedule rotation
    let at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 86400; // +1 day
    klm.schedule_rotation(id1, at).expect("schedule rotation");
    println!("4. Scheduled rotation for key {} at timestamp {}", id1, at);

    // Retire key
    klm.retire_key(id2, "End of validity period")
        .expect("retire key");
    println!("5. Retired key {} with reason", id2);

    // List keys
    let keys = klm.list_keys();
    println!("\n6. All keys:");
    for k in keys {
        let state_str: String = match &k.state {
            KeyState::Active => "Active".into(),
            KeyState::RotationScheduled { at_timestamp } => {
                format!("RotationScheduled@{}", at_timestamp)
            }
            KeyState::Retired { reason } => format!("Retired({})", reason),
            KeyState::Destroyed => "Destroyed".into(),
        };
        println!(
            "   - id={} alg={} state={}",
            k.id,
            k.algorithm.as_str(),
            state_str
        );
    }

    let audit_file = std::env::temp_dir().join("aegis_pqvm_key_lifecycle_audit.jsonl");
    klm.write_audit_log_jsonl(&audit_file)
        .expect("write audit log");
    println!("7. Audit log written to {}", audit_file.display());

    println!("\nKey lifecycle example completed successfully.");
}
