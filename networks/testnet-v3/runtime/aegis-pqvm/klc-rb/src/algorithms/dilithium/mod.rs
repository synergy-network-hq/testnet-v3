use pqrust_mldsa::{
    mldsa44::{keypair as keypair44, sign as sign44, verify_detached_signature as verify44, PublicKey as PublicKey44, SecretKey as SecretKey44, DetachedSignature as DetachedSignature44},
    mldsa65::{keypair as keypair65, sign as sign65, verify_detached_signature as verify65, PublicKey as PublicKey65, SecretKey as SecretKey65, DetachedSignature as DetachedSignature65},
    mldsa87::{keypair as keypair87, sign as sign87, verify_detached_signature as verify87, PublicKey as PublicKey87, SecretKey as SecretKey87, DetachedSignature as DetachedSignature87},
};
use pqrust_traits::sign::{ PublicKey as _, SecretKey as _, SignedMessage as _ };
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct mldsaKeyPair {
    pk: Vec<u8>,
    sk: Vec<u8>,
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl mldsaKeyPair {
    #[cfg_attr(feature = "wasm", wasm_bindgen(getter))]
    pub fn public_key(&self) -> Vec<u8> {
        self.pk.clone()
    }

    #[cfg_attr(feature = "wasm", wasm_bindgen(getter))]
    pub fn secret_key(&self) -> Vec<u8> {
        self.sk.clone()
    }
}

// ML-DSA-44 Functions
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub fn mldsa44_keygen() -> mldsaKeyPair {
    let (pk, sk) = keypair44();
    mldsaKeyPair {
        pk: pk.as_bytes().to_vec(),
        sk: sk.as_bytes().to_vec(),
    }
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub fn mldsa44_sign(secret_key: &[u8], message: &[u8]) -> Vec<u8> {
    let sk = SecretKey44::from_bytes(secret_key).expect("Invalid secret key");
    let signed_message = sign44(message, &sk);
    signed_message.as_bytes().to_vec()
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub fn mldsa44_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let pk = match PublicKey44::from_bytes(public_key) {
        Ok(pk) => pk,
        Err(_) => {
            return false;
        }
    };

    // Use the verify_detached_signature function directly with byte slices
    verify44(message, signature, &pk).is_ok()
}

// ML-DSA-65 Functions
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub fn mldsa65_keygen() -> mldsaKeyPair {
    let (pk, sk) = keypair65();
    mldsaKeyPair {
        pk: pk.as_bytes().to_vec(),
        sk: sk.as_bytes().to_vec(),
    }
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub fn mldsa65_sign(secret_key: &[u8], message: &[u8]) -> Vec<u8> {
    let sk = SecretKey65::from_bytes(secret_key).expect("Invalid secret key");
    let signed_message = sign65(message, &sk);
    signed_message.as_bytes().to_vec()
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub fn mldsa65_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let pk = match PublicKey65::from_bytes(public_key) {
        Ok(pk) => pk,
        Err(_) => {
            return false;
        }
    };

    verify65(message, signature, &pk).is_ok()
}

// ML-DSA-87 Functions
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub fn mldsa87_keygen() -> mldsaKeyPair {
    let (pk, sk) = keypair87();
    mldsaKeyPair {
        pk: pk.as_bytes().to_vec(),
        sk: sk.as_bytes().to_vec(),
    }
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub fn mldsa87_sign(secret_key: &[u8], message: &[u8]) -> Vec<u8> {
    let sk = SecretKey87::from_bytes(secret_key).expect("Invalid secret key");
    let signed_message = sign87(message, &sk);
    signed_message.as_bytes().to_vec()
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub fn mldsa87_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let pk = match PublicKey87::from_bytes(public_key) {
        Ok(pk) => pk,
        Err(_) => {
            return false;
        }
    };

    verify87(message, signature, &pk).is_ok()
}

// Legacy functions (for backward compatibility - default to ML-DSA-87)
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub fn mldsa_keygen() -> mldsaKeyPair {
    mldsa87_keygen()
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub fn mldsa_sign(secret_key: &[u8], message: &[u8]) -> Vec<u8> {
    mldsa87_sign(secret_key, message)
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub fn mldsa_verify(public_key: &[u8], signed_message: &[u8]) -> bool {
    mldsa87_verify(public_key, signed_message)
}
