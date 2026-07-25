#[cfg(feature = "fndsa")]
use aegis_pqvm::fndsa;
#[cfg(feature = "mldsa")]
use aegis_pqvm::mldsa;
#[cfg(feature = "mlkem")]
use aegis_pqvm::mlkem;

#[cfg(feature = "mlkem")]
use pqcrypto_traits::kem::{Ciphertext as _, SharedSecret as _};
#[cfg(any(feature = "mldsa", feature = "fndsa"))]
use pqcrypto_traits::sign::DetachedSignature as _;

#[cfg(feature = "mlkem")]
#[test]
fn mlkem_smoke_tamper_ciphertext_changes_shared_secret() {
    use mlkem::mlkem512::{decapsulate, encapsulate, keypair, Ciphertext};

    let (pk, sk) = keypair();
    let (ss_ok, ct) = encapsulate(&pk);
    let ss2 = decapsulate(&ct, &sk);
    assert_eq!(ss_ok.as_bytes(), ss2.as_bytes());

    let mut ct_bytes = ct.as_bytes().to_vec();
    ct_bytes[0] ^= 0x01;
    let ct_bad = Ciphertext::from_bytes(&ct_bytes).unwrap();
    let ss_bad = decapsulate(&ct_bad, &sk);
    assert_ne!(
        ss_ok.as_bytes(),
        ss_bad.as_bytes(),
        "tampered ciphertext unexpectedly decapsulated to same secret"
    );
}

#[cfg(feature = "mldsa")]
#[test]
fn mldsa_smoke_tamper_message_or_signature_fails() {
    use mldsa::mldsa44::{detached_sign, keypair, verify_detached_signature};

    let (pk, sk) = keypair();
    let msg = b"aegis-pqvm smoke test message";
    let sig = detached_sign(msg, &sk);
    verify_detached_signature(&sig, msg, &pk).unwrap();

    let mut msg_bad = msg.to_vec();
    msg_bad[0] ^= 0x01;
    assert!(
        verify_detached_signature(&sig, &msg_bad, &pk).is_err(),
        "tampered message unexpectedly verified"
    );

    let mut sig_bytes = sig.as_bytes().to_vec();
    sig_bytes[0] ^= 0x01;
    let sig_bad = <mldsa::mldsa44::DetachedSignature as pqcrypto_traits::sign::DetachedSignature>::from_bytes(&sig_bytes).unwrap();
    assert!(
        verify_detached_signature(&sig_bad, msg, &pk).is_err(),
        "tampered signature unexpectedly verified"
    );
}

#[cfg(feature = "fndsa")]
#[test]
fn fndsa_smoke_tamper_message_or_signature_fails() {
    use fndsa::fndsa512::{detached_sign, keypair, verify_detached_signature};

    let (pk, sk) = keypair();
    let msg = b"aegis-pqvm smoke test message";
    let sig = detached_sign(msg, &sk);
    verify_detached_signature(&sig, msg, &pk).unwrap();

    let mut msg_bad = msg.to_vec();
    msg_bad[0] ^= 0x01;
    assert!(
        verify_detached_signature(&sig, &msg_bad, &pk).is_err(),
        "tampered message unexpectedly verified"
    );

    let mut sig_bytes = sig.as_bytes().to_vec();
    sig_bytes[0] ^= 0x01;
    let sig_bad = <fndsa::fndsa512::DetachedSignature as pqcrypto_traits::sign::DetachedSignature>::from_bytes(&sig_bytes).unwrap();
    assert!(
        verify_detached_signature(&sig_bad, msg, &pk).is_err(),
        "tampered signature unexpectedly verified"
    );
}
