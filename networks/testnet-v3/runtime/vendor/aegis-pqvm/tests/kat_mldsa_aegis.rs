mod common;

use common::hex_to_bytes;
use pqcrypto_traits::sign::{PublicKey as _, SignedMessage as _};
use serde_json::Value;
use std::path::PathBuf;

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn load_vec(name: &str) -> Value {
    let path = manifest_dir()
        .join("tests")
        .join("kats")
        .join("aegis")
        .join(name);
    let s = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
    serde_json::from_str(&s).unwrap_or_else(|e| panic!("bad json {}: {e}", path.display()))
}

#[cfg(feature = "mldsa")]
#[test]
fn kat_mldsa44_aegis_baseline_vector_opens() {
    use aegis_pqvm::mldsa::mldsa44::{open, PublicKey, SignedMessage};
    let v = load_vec("mldsa44.json");
    assert_eq!(v["version"].as_u64().unwrap(), 1);
    let msg = hex_to_bytes(v["msg_hex"].as_str().unwrap());
    let pk = PublicKey::from_bytes(&hex_to_bytes(v["pk_hex"].as_str().unwrap())).unwrap();
    let sm = SignedMessage::from_bytes(&hex_to_bytes(v["sm_hex"].as_str().unwrap())).unwrap();
    let opened = open(&sm, &pk).unwrap();
    assert_eq!(opened, msg);
}

#[cfg(feature = "mldsa")]
#[test]
fn kat_mldsa65_aegis_baseline_vector_opens() {
    use aegis_pqvm::mldsa::mldsa65::{open, PublicKey, SignedMessage};
    let v = load_vec("mldsa65.json");
    assert_eq!(v["version"].as_u64().unwrap(), 1);
    let msg = hex_to_bytes(v["msg_hex"].as_str().unwrap());
    let pk = PublicKey::from_bytes(&hex_to_bytes(v["pk_hex"].as_str().unwrap())).unwrap();
    let sm = SignedMessage::from_bytes(&hex_to_bytes(v["sm_hex"].as_str().unwrap())).unwrap();
    let opened = open(&sm, &pk).unwrap();
    assert_eq!(opened, msg);
}

#[cfg(feature = "mldsa")]
#[test]
fn kat_mldsa87_aegis_baseline_vector_opens() {
    use aegis_pqvm::mldsa::mldsa87::{open, PublicKey, SignedMessage};
    let v = load_vec("mldsa87.json");
    assert_eq!(v["version"].as_u64().unwrap(), 1);
    let msg = hex_to_bytes(v["msg_hex"].as_str().unwrap());
    let pk = PublicKey::from_bytes(&hex_to_bytes(v["pk_hex"].as_str().unwrap())).unwrap();
    let sm = SignedMessage::from_bytes(&hex_to_bytes(v["sm_hex"].as_str().unwrap())).unwrap();
    let opened = open(&sm, &pk).unwrap();
    assert_eq!(opened, msg);
}
