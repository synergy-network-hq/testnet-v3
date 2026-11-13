//! FIPS 203 ML-KEM wrappers backed by `pqrust-mlkem`.

use pqrust_mlkem::{mlkem1024, mlkem512, mlkem768};
use pqrust_traits::kem::{Ciphertext as _, PublicKey as _, SecretKey as _, SharedSecret as _};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlKemKeyPair {
    pk: Vec<u8>,
    sk: Vec<u8>,
}

impl MlKemKeyPair {
    pub fn public_key(&self) -> Vec<u8> {
        self.pk.clone()
    }

    pub fn secret_key(&self) -> Vec<u8> {
        self.sk.clone()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlKemEncapsulated {
    ciphertext: Vec<u8>,
    shared_secret: Vec<u8>,
}

impl MlKemEncapsulated {
    pub fn ciphertext(&self) -> Vec<u8> {
        self.ciphertext.clone()
    }

    pub fn shared_secret(&self) -> Vec<u8> {
        self.shared_secret.clone()
    }
}

pub fn mlkem512_keygen() -> MlKemKeyPair {
    let (pk, sk) = mlkem512::keypair().expect("ML-KEM-512 key generation failed");
    MlKemKeyPair {
        pk: pk.as_bytes().to_vec(),
        sk: sk.as_bytes().to_vec(),
    }
}

pub fn mlkem512_encapsulate(public_key: &[u8]) -> Result<MlKemEncapsulated, String> {
    let pk = mlkem512::PublicKey::from_bytes(public_key)
        .map_err(|_| "invalid ML-KEM-512 public key".to_string())?;
    let (shared_secret, ciphertext) = mlkem512::encapsulate(&pk)
        .map_err(|err| format!("ML-KEM-512 encapsulation failed: {err:?}"))?;
    Ok(MlKemEncapsulated {
        ciphertext: ciphertext.as_bytes().to_vec(),
        shared_secret: shared_secret.as_bytes().to_vec(),
    })
}

pub fn mlkem512_decapsulate(secret_key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    let sk = mlkem512::SecretKey::from_bytes(secret_key)
        .map_err(|_| "invalid ML-KEM-512 secret key".to_string())?;
    let ct = mlkem512::Ciphertext::from_bytes(ciphertext)
        .map_err(|_| "invalid ML-KEM-512 ciphertext".to_string())?;
    Ok(mlkem512::decapsulate(&ct, &sk)
        .map_err(|err| format!("ML-KEM-512 decapsulation failed: {err:?}"))?
        .as_bytes()
        .to_vec())
}

pub fn mlkem768_keygen() -> MlKemKeyPair {
    let (pk, sk) = mlkem768::keypair().expect("ML-KEM-768 key generation failed");
    MlKemKeyPair {
        pk: pk.as_bytes().to_vec(),
        sk: sk.as_bytes().to_vec(),
    }
}

pub fn mlkem768_encapsulate(public_key: &[u8]) -> Result<MlKemEncapsulated, String> {
    let pk = mlkem768::PublicKey::from_bytes(public_key)
        .map_err(|_| "invalid ML-KEM-768 public key".to_string())?;
    let (shared_secret, ciphertext) = mlkem768::encapsulate(&pk)
        .map_err(|err| format!("ML-KEM-768 encapsulation failed: {err:?}"))?;
    Ok(MlKemEncapsulated {
        ciphertext: ciphertext.as_bytes().to_vec(),
        shared_secret: shared_secret.as_bytes().to_vec(),
    })
}

pub fn mlkem768_decapsulate(secret_key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    let sk = mlkem768::SecretKey::from_bytes(secret_key)
        .map_err(|_| "invalid ML-KEM-768 secret key".to_string())?;
    let ct = mlkem768::Ciphertext::from_bytes(ciphertext)
        .map_err(|_| "invalid ML-KEM-768 ciphertext".to_string())?;
    Ok(mlkem768::decapsulate(&ct, &sk)
        .map_err(|err| format!("ML-KEM-768 decapsulation failed: {err:?}"))?
        .as_bytes()
        .to_vec())
}

pub fn mlkem1024_keygen() -> MlKemKeyPair {
    let (pk, sk) = mlkem1024::keypair().expect("ML-KEM-1024 key generation failed");
    MlKemKeyPair {
        pk: pk.as_bytes().to_vec(),
        sk: sk.as_bytes().to_vec(),
    }
}

pub fn mlkem1024_encapsulate(public_key: &[u8]) -> Result<MlKemEncapsulated, String> {
    let pk = mlkem1024::PublicKey::from_bytes(public_key)
        .map_err(|_| "invalid ML-KEM-1024 public key".to_string())?;
    let (shared_secret, ciphertext) = mlkem1024::encapsulate(&pk)
        .map_err(|err| format!("ML-KEM-1024 encapsulation failed: {err:?}"))?;
    Ok(MlKemEncapsulated {
        ciphertext: ciphertext.as_bytes().to_vec(),
        shared_secret: shared_secret.as_bytes().to_vec(),
    })
}

pub fn mlkem1024_decapsulate(secret_key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    let sk = mlkem1024::SecretKey::from_bytes(secret_key)
        .map_err(|_| "invalid ML-KEM-1024 secret key".to_string())?;
    let ct = mlkem1024::Ciphertext::from_bytes(ciphertext)
        .map_err(|_| "invalid ML-KEM-1024 ciphertext".to_string())?;
    Ok(mlkem1024::decapsulate(&ct, &sk)
        .map_err(|err| format!("ML-KEM-1024 decapsulation failed: {err:?}"))?
        .as_bytes()
        .to_vec())
}

pub fn mlkem_keygen() -> MlKemKeyPair {
    mlkem768_keygen()
}

pub fn mlkem_encapsulate(public_key: &[u8]) -> Result<MlKemEncapsulated, String> {
    mlkem768_encapsulate(public_key)
}

pub fn mlkem_decapsulate(secret_key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    mlkem768_decapsulate(secret_key, ciphertext)
}
