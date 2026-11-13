mod common;

use common::{kat_max_cases, parse_rsp};
use std::path::PathBuf;

#[cfg(feature = "fndsa")]
use pqcrypto_traits::sign::{PublicKey as _, SignedMessage as _};

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

#[cfg(feature = "fndsa")]
#[test]
fn kat_falcon512_open_matches_nist_vectors() {
    use aegis_pqvm::fndsa::fndsa512::{open, PublicKey, SignedMessage};

    let rsp = manifest_dir().join("tests/kats/fndsa/reference/falcon512-KAT.rsp");
    let cases = parse_rsp(&rsp);
    let max = kat_max_cases(10);

    for case in cases.iter().take(max) {
        let mlen = case.get_usize("mlen");
        let msg = case.get_hex_bytes("msg");
        assert_eq!(
            msg.len(),
            mlen,
            "falcon-512 msg length mismatch (count={})",
            case.count
        );

        let pk = PublicKey::from_bytes(&case.get_hex_bytes("pk")).unwrap();
        let sm = SignedMessage::from_bytes(&case.get_hex_bytes("sm")).unwrap();
        let opened = open(&sm, &pk).unwrap();
        assert_eq!(
            opened, msg,
            "falcon-512 open mismatch (count={})",
            case.count
        );
    }
}

#[cfg(feature = "fndsa")]
#[test]
fn kat_falcon1024_open_matches_nist_vectors() {
    use aegis_pqvm::fndsa::fndsa1024::{open, PublicKey, SignedMessage};

    let rsp = manifest_dir().join("tests/kats/fndsa/reference/falcon1024-KAT.rsp");
    let cases = parse_rsp(&rsp);
    let max = kat_max_cases(5);

    for case in cases.iter().take(max) {
        let mlen = case.get_usize("mlen");
        let msg = case.get_hex_bytes("msg");
        assert_eq!(
            msg.len(),
            mlen,
            "falcon-1024 msg length mismatch (count={})",
            case.count
        );

        let pk = PublicKey::from_bytes(&case.get_hex_bytes("pk")).unwrap();
        let sm = SignedMessage::from_bytes(&case.get_hex_bytes("sm")).unwrap();
        let opened = open(&sm, &pk).unwrap();
        assert_eq!(
            opened, msg,
            "falcon-1024 open mismatch (count={})",
            case.count
        );
    }
}
