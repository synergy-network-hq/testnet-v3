use pqrust_slhdsa::slhdsasha2128fsimple::{
    keypair as keypairSha2128f, open as openSha2128f, sign as signSha2128f,
    PublicKey as PublicKeySha2128f, SecretKey as SecretKeySha2128f,
    SignedMessage as SignedMessageSha2128f,
};
use pqrust_slhdsa::slhdsasha2192fsimple::{
    keypair as keypairSha2192f, open as openSha2192f, sign as signSha2192f,
    PublicKey as PublicKeySha2192f, SecretKey as SecretKeySha2192f,
    SignedMessage as SignedMessageSha2192f,
};
use pqrust_slhdsa::slhdsasha2256fsimple::{
    keypair as keypairSha2256f, open as openSha2256f, sign as signSha2256f,
    PublicKey as PublicKeySha2256f, SecretKey as SecretKeySha2256f,
    SignedMessage as SignedMessageSha2256f,
};
use pqrust_slhdsa::slhdsashake128fsimple::{
    keypair as keypairShake128f, open as openShake128f, sign as signShake128f,
    PublicKey as PublicKeyShake128f, SecretKey as SecretKeyShake128f,
    SignedMessage as SignedMessageShake128f,
};
use pqrust_slhdsa::slhdsashake192fsimple::{
    keypair as keypairShake192f, open as openShake192f, sign as signShake192f,
    PublicKey as PublicKeyShake192f, SecretKey as SecretKeyShake192f,
    SignedMessage as SignedMessageShake192f,
};
use pqrust_slhdsa::slhdsashake256fsimple::{
    keypair as keypairShake256f, open as openShake256f, sign as signShake256f,
    PublicKey as PublicKeyShake256f, SecretKey as SecretKeyShake256f,
    SignedMessage as SignedMessageShake256f,
};
use pqrust_traits::sign::{PublicKey as _, SecretKey as _, SignedMessage as _};
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct SphincsPlusKeyPair {
    pk: Vec<u8>,
    sk: Vec<u8>,
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl SphincsPlusKeyPair {
    #[cfg_attr(feature = "wasm", wasm_bindgen(getter))]
    pub fn public_key(&self) -> Vec<u8> {
        self.pk.clone()
    }

    #[cfg_attr(feature = "wasm", wasm_bindgen(getter))]
    pub fn secret_key(&self) -> Vec<u8> {
        self.sk.clone()
    }
}

// SPHINCS+-SHA2-128f Functions
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub fn sphincsplus_sha2_128f_keygen() -> SphincsPlusKeyPair {
    let (pk, sk) = keypairSha2128f();
    SphincsPlusKeyPair {
        pk: pk.as_bytes().to_vec(),
        sk: sk.as_bytes().to_vec(),
    }
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub fn sphincsplus_sha2_128f_sign(secret_key: &[u8], message: &[u8]) -> Vec<u8> {
    let sk = SecretKeySha2128f::from_bytes(secret_key).expect("Invalid secret key");
    let signed_message = signSha2128f(message, &sk);
    signed_message.as_bytes().to_vec()
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub fn sphincsplus_sha2_128f_verify(public_key: &[u8], signed_message: &[u8]) -> bool {
    let pk = match PublicKeySha2128f::from_bytes(public_key) {
        Ok(pk) => pk,
        Err(_) => {
            return false;
        }
    };
    let signed_message = match SignedMessageSha2128f::from_bytes(signed_message) {
        Ok(sm) => sm,
        Err(_) => {
            return false;
        }
    };
    openSha2128f(&signed_message, &pk).is_ok()
}

// SPHINCS+-SHA2-192f Functions
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub fn sphincsplus_sha2_192f_keygen() -> SphincsPlusKeyPair {
    let (pk, sk) = keypairSha2192f();
    SphincsPlusKeyPair {
        pk: pk.as_bytes().to_vec(),
        sk: sk.as_bytes().to_vec(),
    }
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub fn sphincsplus_sha2_192f_sign(secret_key: &[u8], message: &[u8]) -> Vec<u8> {
    let sk = SecretKeySha2192f::from_bytes(secret_key).expect("Invalid secret key");
    let signed_message = signSha2192f(message, &sk);
    signed_message.as_bytes().to_vec()
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub fn sphincsplus_sha2_192f_verify(public_key: &[u8], signed_message: &[u8]) -> bool {
    let pk = match PublicKeySha2192f::from_bytes(public_key) {
        Ok(pk) => pk,
        Err(_) => {
            return false;
        }
    };
    let signed_message = match SignedMessageSha2192f::from_bytes(signed_message) {
        Ok(sm) => sm,
        Err(_) => {
            return false;
        }
    };
    openSha2192f(&signed_message, &pk).is_ok()
}

// SPHINCS+-SHA2-256f Functions
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub fn sphincsplus_sha2_256f_keygen() -> SphincsPlusKeyPair {
    let (pk, sk) = keypairSha2256f();
    SphincsPlusKeyPair {
        pk: pk.as_bytes().to_vec(),
        sk: sk.as_bytes().to_vec(),
    }
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub fn sphincsplus_sha2_256f_sign(secret_key: &[u8], message: &[u8]) -> Vec<u8> {
    let sk = SecretKeySha2256f::from_bytes(secret_key).expect("Invalid secret key");
    let signed_message = signSha2256f(message, &sk);
    signed_message.as_bytes().to_vec()
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub fn sphincsplus_sha2_256f_verify(public_key: &[u8], signed_message: &[u8]) -> bool {
    let pk = match PublicKeySha2256f::from_bytes(public_key) {
        Ok(pk) => pk,
        Err(_) => {
            return false;
        }
    };
    let signed_message = match SignedMessageSha2256f::from_bytes(signed_message) {
        Ok(sm) => sm,
        Err(_) => {
            return false;
        }
    };
    openSha2256f(&signed_message, &pk).is_ok()
}

// SPHINCS+-SHAKE-128f Functions
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub fn sphincsplus_shake_128f_keygen() -> SphincsPlusKeyPair {
    let (pk, sk) = keypairShake128f();
    SphincsPlusKeyPair {
        pk: pk.as_bytes().to_vec(),
        sk: sk.as_bytes().to_vec(),
    }
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub fn sphincsplus_shake_128f_sign(secret_key: &[u8], message: &[u8]) -> Vec<u8> {
    let sk = SecretKeyShake128f::from_bytes(secret_key).expect("Invalid secret key");
    let signed_message = signShake128f(message, &sk);
    signed_message.as_bytes().to_vec()
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub fn sphincsplus_shake_128f_verify(public_key: &[u8], signed_message: &[u8]) -> bool {
    let pk = match PublicKeyShake128f::from_bytes(public_key) {
        Ok(pk) => pk,
        Err(_) => {
            return false;
        }
    };
    let signed_message = match SignedMessageShake128f::from_bytes(signed_message) {
        Ok(sm) => sm,
        Err(_) => {
            return false;
        }
    };
    openShake128f(&signed_message, &pk).is_ok()
}

// SPHINCS+-SHAKE-192f Functions
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub fn sphincsplus_shake_192f_keygen() -> SphincsPlusKeyPair {
    let (pk, sk) = keypairShake192f();
    SphincsPlusKeyPair {
        pk: pk.as_bytes().to_vec(),
        sk: sk.as_bytes().to_vec(),
    }
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub fn sphincsplus_shake_192f_sign(secret_key: &[u8], message: &[u8]) -> Vec<u8> {
    let sk = SecretKeyShake192f::from_bytes(secret_key).expect("Invalid secret key");
    let signed_message = signShake192f(message, &sk);
    signed_message.as_bytes().to_vec()
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub fn sphincsplus_shake_192f_verify(public_key: &[u8], signed_message: &[u8]) -> bool {
    let pk = match PublicKeyShake192f::from_bytes(public_key) {
        Ok(pk) => pk,
        Err(_) => {
            return false;
        }
    };
    let signed_message = match SignedMessageShake192f::from_bytes(signed_message) {
        Ok(sm) => sm,
        Err(_) => {
            return false;
        }
    };
    openShake192f(&signed_message, &pk).is_ok()
}

// SPHINCS+-SHAKE-256f Functions
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub fn sphincsplus_shake_256f_keygen() -> SphincsPlusKeyPair {
    let (pk, sk) = keypairShake256f();
    SphincsPlusKeyPair {
        pk: pk.as_bytes().to_vec(),
        sk: sk.as_bytes().to_vec(),
    }
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub fn sphincsplus_shake_256f_sign(secret_key: &[u8], message: &[u8]) -> Vec<u8> {
    let sk = SecretKeyShake256f::from_bytes(secret_key).expect("Invalid secret key");
    let signed_message = signShake256f(message, &sk);
    signed_message.as_bytes().to_vec()
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub fn sphincsplus_shake_256f_verify(public_key: &[u8], signed_message: &[u8]) -> bool {
    let pk = match PublicKeyShake256f::from_bytes(public_key) {
        Ok(pk) => pk,
        Err(_) => {
            return false;
        }
    };
    let signed_message = match SignedMessageShake256f::from_bytes(signed_message) {
        Ok(sm) => sm,
        Err(_) => {
            return false;
        }
    };
    openShake256f(&signed_message, &pk).is_ok()
}

// Legacy functions (for backward compatibility - default to SPHINCS+-SHA2-128f)
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub fn sphincsplus_keygen() -> SphincsPlusKeyPair {
    sphincsplus_sha2_128f_keygen()
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub fn sphincsplus_sign(secret_key: &[u8], message: &[u8]) -> Vec<u8> {
    sphincsplus_sha2_128f_sign(secret_key, message)
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub fn sphincsplus_verify(public_key: &[u8], signed_message: &[u8]) -> bool {
    sphincsplus_sha2_128f_verify(public_key, signed_message)
}
