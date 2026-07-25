#![cfg(feature = "full")]

use serde::Deserialize;
use sha2::{Digest, Sha256};

#[derive(Debug, Deserialize)]
struct VectorManifest {
    schema_version: u32,
    vectors_file: String,
    sha256: String,
    source: String,
    generated_by: String,
    generated_at_utc: String,
    profile: String,
}

#[test]
fn test_vector_manifest_hash_matches_fixture() {
    let manifest: VectorManifest = serde_json::from_str(include_str!("vectors/manifest.json"))
        .expect("manifest.json must be valid JSON");

    assert_eq!(
        manifest.schema_version, 1,
        "unexpected manifest schema version"
    );
    assert_eq!(manifest.vectors_file, "pinned_vectors.json");
    assert!(
        !manifest.source.trim().is_empty(),
        "manifest source must not be empty"
    );
    assert!(
        !manifest.generated_by.trim().is_empty(),
        "manifest generated_by must not be empty"
    );
    assert!(
        !manifest.generated_at_utc.trim().is_empty(),
        "manifest generated_at_utc must not be empty"
    );
    assert_eq!(manifest.profile, "synq-pq-full");

    let fixture = include_bytes!("vectors/pinned_vectors.json");
    let actual_hash = format!("{:x}", Sha256::digest(fixture));
    assert_eq!(
        actual_hash, manifest.sha256,
        "fixture hash mismatch: regenerate vectors + manifest together"
    );
}
