use super::protected_pipeline_lifecycle_store::{lifecycle_phase, test_atomic_round_trip};
use crate::etdag::ProtectedPipelinePhase;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

fn temp_path(label: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("test clock")
        .as_nanos();
    std::env::temp_dir()
        .join(format!(
            "synergy-lifecycle-{label}-{}-{nonce}",
            std::process::id()
        ))
        .join("lifecycle.json")
}

#[test]
fn restart_phase_is_derived_only_from_durable_evidence() {
    assert_eq!(
        lifecycle_phase(false, false, false, false),
        ProtectedPipelinePhase::CommittedInParent
    );
    assert_eq!(
        lifecycle_phase(true, false, false, false),
        ProtectedPipelinePhase::RevealAuthorized
    );
    assert_eq!(
        lifecycle_phase(true, true, false, false),
        ProtectedPipelinePhase::Revealing
    );
    assert_eq!(
        lifecycle_phase(true, true, true, false),
        ProtectedPipelinePhase::ReadyForExecution
    );
    assert_eq!(
        lifecycle_phase(true, true, true, true),
        ProtectedPipelinePhase::Consumed
    );
    assert_eq!(
        lifecycle_phase(false, false, false, true),
        ProtectedPipelinePhase::Consumed,
        "a durable consumed record remains monotonic after restart"
    );
}

#[test]
fn lifecycle_bytes_are_atomically_recoverable_after_reopen() {
    let path = temp_path("atomic-restart");
    let first = br#"{"sequence":1,"phase":"COMMITTED_IN_PARENT"}"#;
    let second = br#"{"sequence":2,"phase":"REVEAL_AUTHORIZED"}"#;

    assert_eq!(
        test_atomic_round_trip(&path, first).expect("persist first lifecycle record"),
        first
    );
    assert_eq!(
        test_atomic_round_trip(&path, second).expect("replace lifecycle record"),
        second
    );
    assert_eq!(fs::read(&path).expect("reopen lifecycle record"), second);

    let directory = path.parent().expect("store directory");
    let temporary_files = fs::read_dir(directory)
        .expect("read store directory")
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name().to_string_lossy().contains(".tmp-"))
        .count();
    assert_eq!(temporary_files, 0, "atomic persistence left a temp file");
    let _ = fs::remove_dir_all(directory);
}
