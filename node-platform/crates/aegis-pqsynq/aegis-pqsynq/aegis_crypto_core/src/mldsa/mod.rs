//! FIPS 204 ML-DSA wrappers backed by `pqrust-mldsa`.

use pqrust_mldsa::{mldsa44, mldsa65, mldsa87};
use pqrust_traits::sign::{DetachedSignature as _, PublicKey as _, SecretKey as _};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlDsaKeyPair {
    pk: Vec<u8>,
    sk: Vec<u8>,
}

impl MlDsaKeyPair {
    pub fn public_key(&self) -> Vec<u8> {
        self.pk.clone()
    }

    pub fn secret_key(&self) -> Vec<u8> {
        self.sk.clone()
    }
}

pub fn mldsa44_keygen() -> MlDsaKeyPair {
    let (pk, sk) = mldsa44::keypair().expect("ML-DSA-44 key generation failed");
    MlDsaKeyPair {
        pk: pk.as_bytes().to_vec(),
        sk: sk.as_bytes().to_vec(),
    }
}

pub fn mldsa44_sign(secret_key: &[u8], message: &[u8]) -> Result<Vec<u8>, String> {
    let sk = mldsa44::SecretKey::from_bytes(secret_key)
        .map_err(|_| "invalid ML-DSA-44 secret key".to_string())?;
    Ok(mldsa44::detached_sign(message, &sk)
        .map_err(|err| format!("ML-DSA-44 signing failed: {err:?}"))?
        .as_bytes()
        .to_vec())
}

pub fn mldsa44_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let Ok(pk) = mldsa44::PublicKey::from_bytes(public_key) else {
        return false;
    };
    let Ok(sig) = mldsa44::DetachedSignature::from_bytes(signature) else {
        return false;
    };
    mldsa44::verify_detached_signature(&sig, message, &pk).is_ok()
}

pub fn mldsa65_keygen() -> MlDsaKeyPair {
    let (pk, sk) = mldsa65::keypair().expect("ML-DSA-65 key generation failed");
    MlDsaKeyPair {
        pk: pk.as_bytes().to_vec(),
        sk: sk.as_bytes().to_vec(),
    }
}

pub fn mldsa65_sign(secret_key: &[u8], message: &[u8]) -> Result<Vec<u8>, String> {
    let sk = mldsa65::SecretKey::from_bytes(secret_key)
        .map_err(|_| "invalid ML-DSA-65 secret key".to_string())?;
    Ok(mldsa65::detached_sign(message, &sk)
        .map_err(|err| format!("ML-DSA-65 signing failed: {err:?}"))?
        .as_bytes()
        .to_vec())
}

pub fn mldsa65_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let Ok(pk) = mldsa65::PublicKey::from_bytes(public_key) else {
        return false;
    };
    let Ok(sig) = mldsa65::DetachedSignature::from_bytes(signature) else {
        return false;
    };
    mldsa65::verify_detached_signature(&sig, message, &pk).is_ok()
}

pub fn mldsa87_keygen() -> MlDsaKeyPair {
    let (pk, sk) = mldsa87::keypair().expect("ML-DSA-87 key generation failed");
    MlDsaKeyPair {
        pk: pk.as_bytes().to_vec(),
        sk: sk.as_bytes().to_vec(),
    }
}

pub fn mldsa87_sign(secret_key: &[u8], message: &[u8]) -> Result<Vec<u8>, String> {
    let sk = mldsa87::SecretKey::from_bytes(secret_key)
        .map_err(|_| "invalid ML-DSA-87 secret key".to_string())?;
    Ok(mldsa87::detached_sign(message, &sk)
        .map_err(|err| format!("ML-DSA-87 signing failed: {err:?}"))?
        .as_bytes()
        .to_vec())
}

pub fn mldsa87_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let Ok(pk) = mldsa87::PublicKey::from_bytes(public_key) else {
        return false;
    };
    let Ok(sig) = mldsa87::DetachedSignature::from_bytes(signature) else {
        return false;
    };
    mldsa87::verify_detached_signature(&sig, message, &pk).is_ok()
}

pub fn mldsa_keygen() -> MlDsaKeyPair {
    mldsa65_keygen()
}

pub fn mldsa_sign(secret_key: &[u8], message: &[u8]) -> Result<Vec<u8>, String> {
    mldsa65_sign(secret_key, message)
}

pub fn mldsa_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    mldsa65_verify(public_key, message, signature)
}
