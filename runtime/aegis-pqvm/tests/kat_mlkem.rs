mod common;

use common::{kat_max_cases, parse_rsp};
use std::path::PathBuf;

#[cfg(feature = "mlkem")]
use pqrust_traits::kem::{Ciphertext as _, SecretKey as _, SharedSecret as _};

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

#[cfg(feature = "mlkem")]
#[test]
fn kat_mlkem512_decaps_matches_nist_vectors() {
    use aegis_pqvm::mlkem::mlkem512::{decapsulate, Ciphertext, SecretKey, SharedSecret};

    let rsp = manifest_dir().join("tests/kats/mlkem/reference/ml-kem-512/PQCkemKAT_1632.rsp");
    let cases = parse_rsp(&rsp);
    let max = kat_max_cases(25);

    for case in cases.iter().take(max) {
        let sk = SecretKey::from_bytes(&case.get_hex_bytes("sk")).unwrap();
        let ct = Ciphertext::from_bytes(&case.get_hex_bytes("ct")).unwrap();
        let expected = SharedSecret::from_bytes(&case.get_hex_bytes("ss")).unwrap();
        let got = decapsulate(&ct, &sk);
        assert_eq!(
            got.as_bytes(),
            expected.as_bytes(),
            "ml-kem-512 KAT mismatch (count={})",
            case.count
        );
    }
}

#[cfg(feature = "mlkem")]
#[test]
fn kat_mlkem768_decaps_matches_nist_vectors() {
    use aegis_pqvm::mlkem::mlkem768::{decapsulate, Ciphertext, SecretKey, SharedSecret};

    let rsp = manifest_dir().join("tests/kats/mlkem/reference/ml-kem-768/PQCkemKAT_2400.rsp");
    let cases = parse_rsp(&rsp);
    let max = kat_max_cases(25);

    for case in cases.iter().take(max) {
        let sk = SecretKey::from_bytes(&case.get_hex_bytes("sk")).unwrap();
        let ct = Ciphertext::from_bytes(&case.get_hex_bytes("ct")).unwrap();
        let expected = SharedSecret::from_bytes(&case.get_hex_bytes("ss")).unwrap();
        let got = decapsulate(&ct, &sk);
        assert_eq!(
            got.as_bytes(),
            expected.as_bytes(),
            "ml-kem-768 KAT mismatch (count={})",
            case.count
        );
    }
}

#[cfg(feature = "mlkem")]
#[test]
fn kat_mlkem1024_decaps_matches_nist_vectors() {
    use aegis_pqvm::mlkem::mlkem1024::{decapsulate, Ciphertext, SecretKey, SharedSecret};

    let rsp = manifest_dir().join("tests/kats/mlkem/reference/ml-kem-1024/PQCkemKAT_3168.rsp");
    let cases = parse_rsp(&rsp);
    let max = kat_max_cases(25);

    for case in cases.iter().take(max) {
        let sk = SecretKey::from_bytes(&case.get_hex_bytes("sk")).unwrap();
        let ct = Ciphertext::from_bytes(&case.get_hex_bytes("ct")).unwrap();
        let expected = SharedSecret::from_bytes(&case.get_hex_bytes("ss")).unwrap();
        let got = decapsulate(&ct, &sk);
        assert_eq!(
            got.as_bytes(),
            expected.as_bytes(),
            "ml-kem-1024 KAT mismatch (count={})",
            case.count
        );
    }
}
