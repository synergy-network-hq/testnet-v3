use std::fs;
use std::path::{Path, PathBuf};

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

fn write_json(path: &Path, msg: &[u8], pk: &[u8], sm: &[u8]) {
    let s = format!(
        "{{\n  \"version\": 1,\n  \"msg_hex\": \"{}\",\n  \"pk_hex\": \"{}\",\n  \"sm_hex\": \"{}\"\n}}\n",
        hex_encode(msg),
        hex_encode(pk),
        hex_encode(sm)
    );
    fs::write(path, s).expect("write vector json");
}

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn main() {
    let out_dir = manifest_dir().join("tests").join("kats").join("aegis");
    fs::create_dir_all(&out_dir).expect("create kats/aegis dir");

    // NOTE: These are "Aegis baseline" vectors used for regression testing.
    // They are not intended to replace official NIST/FIPS KAT vectors.
    let msg = b"aegis-pqvm mldsa kat v1";

    // ML-DSA-44
    {
        use aegis_pqvm::mldsa::mldsa44::{keypair, sign};
        use pqcrypto_traits::sign::{PublicKey as _, SignedMessage as _};
        let (pk, sk) = keypair();
        let sm = sign(msg, &sk);
        write_json(
            &out_dir.join("mldsa44.json"),
            msg,
            pk.as_bytes(),
            sm.as_bytes(),
        );
    }

    // ML-DSA-65
    {
        use aegis_pqvm::mldsa::mldsa65::{keypair, sign};
        use pqcrypto_traits::sign::{PublicKey as _, SignedMessage as _};
        let (pk, sk) = keypair();
        let sm = sign(msg, &sk);
        write_json(
            &out_dir.join("mldsa65.json"),
            msg,
            pk.as_bytes(),
            sm.as_bytes(),
        );
    }

    // ML-DSA-87
    {
        use aegis_pqvm::mldsa::mldsa87::{keypair, sign};
        use pqcrypto_traits::sign::{PublicKey as _, SignedMessage as _};
        let (pk, sk) = keypair();
        let sm = sign(msg, &sk);
        write_json(
            &out_dir.join("mldsa87.json"),
            msg,
            pk.as_bytes(),
            sm.as_bytes(),
        );
    }

    eprintln!("Wrote Aegis baseline KAT vectors to {}", out_dir.display());
}
