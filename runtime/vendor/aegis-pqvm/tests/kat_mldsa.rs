mod common;

use common::{kat_max_cases, parse_rsp};
use std::path::PathBuf;

#[cfg(feature = "mldsa")]
use pqcrypto_traits::sign::{PublicKey as _, SignedMessage as _};

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

#[cfg(feature = "mldsa")]
#[test]
#[ignore = "These .rsp files are Dilithium* KATs; ML-DSA (FIPS 204) uses different domain separation. Replace with official ML-DSA KAT vectors."]
fn kat_mldsa44_open_matches_nist_vectors() {
    use aegis_pqvm::mldsa::mldsa44::{open, PublicKey, SignedMessage};

    let rsp = manifest_dir().join("tests/kats/mldsa/reference/ml-dsa-44/PQCsignKAT_2544.rsp");
    let cases = parse_rsp(&rsp);
    let max = kat_max_cases(10);

    for case in cases.iter().take(max) {
        let mlen = case.get_usize("mlen");
        let msg = case.get_hex_bytes("msg");
        assert_eq!(
            msg.len(),
            mlen,
            "ml-dsa-44 msg length mismatch (count={})",
            case.count
        );

        let pk = PublicKey::from_bytes(&case.get_hex_bytes("pk")).unwrap();
        let sm = SignedMessage::from_bytes(&case.get_hex_bytes("sm")).unwrap();
        let opened = open(&sm, &pk).unwrap();
        assert_eq!(
            opened, msg,
            "ml-dsa-44 open mismatch (count={})",
            case.count
        );
    }
}

#[cfg(feature = "mldsa")]
#[test]
#[ignore = "These .rsp files are Dilithium* KATs; ML-DSA (FIPS 204) uses different domain separation. Replace with official ML-DSA KAT vectors."]
fn kat_mldsa65_open_matches_nist_vectors() {
    use aegis_pqvm::mldsa::mldsa65::{open, PublicKey, SignedMessage};

    let rsp = manifest_dir().join("tests/kats/mldsa/reference/ml-dsa-65/PQCsignKAT_4016.rsp");
    let cases = parse_rsp(&rsp);
    let max = kat_max_cases(10);

    for case in cases.iter().take(max) {
        let mlen = case.get_usize("mlen");
        let msg = case.get_hex_bytes("msg");
        assert_eq!(
            msg.len(),
            mlen,
            "ml-dsa-65 msg length mismatch (count={})",
            case.count
        );

        let pk = PublicKey::from_bytes(&case.get_hex_bytes("pk")).unwrap();
        let sm = SignedMessage::from_bytes(&case.get_hex_bytes("sm")).unwrap();
        let opened = open(&sm, &pk).unwrap();
        assert_eq!(
            opened, msg,
            "ml-dsa-65 open mismatch (count={})",
            case.count
        );
    }
}

#[cfg(feature = "mldsa")]
#[test]
#[ignore = "These .rsp files are Dilithium* KATs; ML-DSA (FIPS 204) uses different domain separation. Replace with official ML-DSA KAT vectors."]
fn kat_mldsa87_open_matches_nist_vectors() {
    use aegis_pqvm::mldsa::mldsa87::{open, PublicKey, SignedMessage};

    let rsp = manifest_dir().join("tests/kats/mldsa/reference/ml-dsa-87/PQCsignKAT_4880.rsp");
    let cases = parse_rsp(&rsp);
    let max = kat_max_cases(10);

    for case in cases.iter().take(max) {
        let mlen = case.get_usize("mlen");
        let msg = case.get_hex_bytes("msg");
        assert_eq!(
            msg.len(),
            mlen,
            "ml-dsa-87 msg length mismatch (count={})",
            case.count
        );

        let pk = PublicKey::from_bytes(&case.get_hex_bytes("pk")).unwrap();
        let sm = SignedMessage::from_bytes(&case.get_hex_bytes("sm")).unwrap();
        let opened = open(&sm, &pk).unwrap();
        assert_eq!(
            opened, msg,
            "ml-dsa-87 open mismatch (count={})",
            case.count
        );
    }
}
