//! FIPS 206 / Falcon FN-DSA wrappers backed by `pqrust-fndsa`.

use pqrust_fndsa::{fndsa1024, fndsa512};
use pqrust_traits::sign::{DetachedSignature as _, PublicKey as _, SecretKey as _};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FnDsaKeyPair {
    pk: Vec<u8>,
    sk: Vec<u8>,
}

impl FnDsaKeyPair {
    pub fn public_key(&self) -> Vec<u8> {
        self.pk.clone()
    }

    pub fn secret_key(&self) -> Vec<u8> {
        self.sk.clone()
    }
}

pub fn fndsa512_keygen() -> FnDsaKeyPair {
    let (pk, sk) = fndsa512::keypair().expect("FN-DSA-512 key generation failed");
    FnDsaKeyPair {
        pk: pk.as_bytes().to_vec(),
        sk: sk.as_bytes().to_vec(),
    }
}

pub fn fndsa512_sign(secret_key: &[u8], message: &[u8]) -> Result<Vec<u8>, String> {
    let sk = fndsa512::SecretKey::from_bytes(secret_key)
        .map_err(|_| "invalid FN-DSA-512 secret key".to_string())?;
    Ok(fndsa512::detached_sign(message, &sk)
        .map_err(|err| format!("FN-DSA-512 signing failed: {err:?}"))?
        .as_bytes()
        .to_vec())
}

pub fn fndsa512_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let Ok(pk) = fndsa512::PublicKey::from_bytes(public_key) else {
        return false;
    };
    let Ok(sig) = fndsa512::DetachedSignature::from_bytes(signature) else {
        return false;
    };
    fndsa512::verify_detached_signature(&sig, message, &pk).is_ok()
}

pub fn fndsa1024_keygen() -> FnDsaKeyPair {
    let (pk, sk) = fndsa1024::keypair().expect("FN-DSA-1024 key generation failed");
    FnDsaKeyPair {
        pk: pk.as_bytes().to_vec(),
        sk: sk.as_bytes().to_vec(),
    }
}

pub fn fndsa1024_sign(secret_key: &[u8], message: &[u8]) -> Result<Vec<u8>, String> {
    let sk = fndsa1024::SecretKey::from_bytes(secret_key)
        .map_err(|_| "invalid FN-DSA-1024 secret key".to_string())?;
    Ok(fndsa1024::detached_sign(message, &sk)
        .map_err(|err| format!("FN-DSA-1024 signing failed: {err:?}"))?
        .as_bytes()
        .to_vec())
}

pub fn fndsa1024_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let Ok(pk) = fndsa1024::PublicKey::from_bytes(public_key) else {
        return false;
    };
    let Ok(sig) = fndsa1024::DetachedSignature::from_bytes(signature) else {
        return false;
    };
    fndsa1024::verify_detached_signature(&sig, message, &pk).is_ok()
}

pub fn fndsa_keygen() -> FnDsaKeyPair {
    fndsa512_keygen()
}

pub fn fndsa_sign(secret_key: &[u8], message: &[u8]) -> Result<Vec<u8>, String> {
    fndsa512_sign(secret_key, message)
}

pub fn fndsa_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    fndsa512_verify(public_key, message, signature)
}
