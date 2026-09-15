#[cfg(feature = "classicmceliece")]
use pqrust_cmce::{
    cmce348864::{
        decapsulate as decapsulate348864, encapsulate as encapsulate348864,
        keypair as keypair348864, Ciphertext as Ciphertext348864, PublicKey as PublicKey348864,
        SecretKey as SecretKey348864,
    },
    cmce460896::{
        decapsulate as decapsulate460896, encapsulate as encapsulate460896,
        keypair as keypair460896, Ciphertext as Ciphertext460896, PublicKey as PublicKey460896,
        SecretKey as SecretKey460896,
    },
    cmce6688128::{
        decapsulate as decapsulate6688128, encapsulate as encapsulate6688128,
        keypair as keypair6688128, Ciphertext as Ciphertext6688128, PublicKey as PublicKey6688128,
        SecretKey as SecretKey6688128,
    },
};
use pqrust_traits::kem::{Ciphertext as _, PublicKey as _, SecretKey as _, SharedSecret as _};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct ClassicMcElieceKeyPair {
    pk: Vec<u8>,
    sk: Vec<u8>,
}

#[wasm_bindgen]
impl ClassicMcElieceKeyPair {
    #[wasm_bindgen(getter)]
    pub fn public_key(&self) -> Vec<u8> {
        self.pk.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn secret_key(&self) -> Vec<u8> {
        self.sk.clone()
    }
}

#[wasm_bindgen]
pub struct ClassicMcElieceEncapsulated {
    ciphertext: Vec<u8>,
    shared_secret: Vec<u8>,
}

#[wasm_bindgen]
impl ClassicMcElieceEncapsulated {
    #[wasm_bindgen(getter)]
    pub fn ciphertext(&self) -> Vec<u8> {
        self.ciphertext.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn shared_secret(&self) -> Vec<u8> {
        self.shared_secret.clone()
    }
}

// Classic McEliece-348864 Functions
#[wasm_bindgen]
pub fn classicmceliece348864_keygen() -> ClassicMcElieceKeyPair {
    let (pk, sk) = keypair348864();
    ClassicMcElieceKeyPair {
        pk: pk.as_bytes().to_vec(),
        sk: sk.as_bytes().to_vec(),
    }
}

#[wasm_bindgen]
pub fn classicmceliece348864_encapsulate(
    public_key: &[u8],
) -> Result<ClassicMcElieceEncapsulated, JsValue> {
    let pk = PublicKey348864::from_bytes(public_key)
        .map_err(|e| JsValue::from_str(&format!("Invalid public key: {:?}", e)))?;
    let (ss, ct) = encapsulate348864(&pk);
    Ok(ClassicMcElieceEncapsulated {
        ciphertext: ct.as_bytes().to_vec(),
        shared_secret: ss.as_bytes().to_vec(),
    })
}

#[wasm_bindgen]
pub fn classicmceliece348864_decapsulate(
    secret_key: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let sk = SecretKey348864::from_bytes(secret_key)
        .map_err(|e| JsValue::from_str(&format!("Invalid secret key: {:?}", e)))?;
    let ct = Ciphertext348864::from_bytes(ciphertext)
        .map_err(|e| JsValue::from_str(&format!("Invalid ciphertext: {:?}", e)))?;
    let ss = decapsulate348864(&ct, &sk);
    Ok(ss.as_bytes().to_vec())
}

// Classic McEliece-460896 Functions
#[wasm_bindgen]
pub fn classicmceliece460896_keygen() -> ClassicMcElieceKeyPair {
    let (pk, sk) = keypair460896();
    ClassicMcElieceKeyPair {
        pk: pk.as_bytes().to_vec(),
        sk: sk.as_bytes().to_vec(),
    }
}

#[wasm_bindgen]
pub fn classicmceliece460896_encapsulate(
    public_key: &[u8],
) -> Result<ClassicMcElieceEncapsulated, JsValue> {
    let pk = PublicKey460896::from_bytes(public_key)
        .map_err(|e| JsValue::from_str(&format!("Invalid public key: {:?}", e)))?;
    let (ss, ct) = encapsulate460896(&pk);
    Ok(ClassicMcElieceEncapsulated {
        ciphertext: ct.as_bytes().to_vec(),
        shared_secret: ss.as_bytes().to_vec(),
    })
}

#[wasm_bindgen]
pub fn classicmceliece460896_decapsulate(
    secret_key: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let sk = SecretKey460896::from_bytes(secret_key)
        .map_err(|e| JsValue::from_str(&format!("Invalid secret key: {:?}", e)))?;
    let ct = Ciphertext460896::from_bytes(ciphertext)
        .map_err(|e| JsValue::from_str(&format!("Invalid ciphertext: {:?}", e)))?;
    let ss = decapsulate460896(&ct, &sk);
    Ok(ss.as_bytes().to_vec())
}

// Classic McEliece-6688128 Functions
#[wasm_bindgen]
pub fn classicmceliece6688128_keygen() -> ClassicMcElieceKeyPair {
    let (pk, sk) = keypair6688128();
    ClassicMcElieceKeyPair {
        pk: pk.as_bytes().to_vec(),
        sk: sk.as_bytes().to_vec(),
    }
}

#[wasm_bindgen]
pub fn classicmceliece6688128_encapsulate(
    public_key: &[u8],
) -> Result<ClassicMcElieceEncapsulated, JsValue> {
    let pk = PublicKey6688128::from_bytes(public_key)
        .map_err(|e| JsValue::from_str(&format!("Invalid public key: {:?}", e)))?;
    let (ss, ct) = encapsulate6688128(&pk);
    Ok(ClassicMcElieceEncapsulated {
        ciphertext: ct.as_bytes().to_vec(),
        shared_secret: ss.as_bytes().to_vec(),
    })
}

#[wasm_bindgen]
pub fn classicmceliece6688128_decapsulate(
    secret_key: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let sk = SecretKey6688128::from_bytes(secret_key)
        .map_err(|e| JsValue::from_str(&format!("Invalid secret key: {:?}", e)))?;
    let ct = Ciphertext6688128::from_bytes(ciphertext)
        .map_err(|e| JsValue::from_str(&format!("Invalid ciphertext: {:?}", e)))?;
    let ss = decapsulate6688128(&ct, &sk);
    Ok(ss.as_bytes().to_vec())
}

// Legacy functions (for backward compatibility - default to McEliece-348864)
#[wasm_bindgen]
pub fn classicmceliece_keygen() -> ClassicMcElieceKeyPair {
    classicmceliece348864_keygen()
}

#[wasm_bindgen]
pub fn classicmceliece_encapsulate(
    public_key: &[u8],
) -> Result<ClassicMcElieceEncapsulated, JsValue> {
    classicmceliece348864_encapsulate(public_key)
}

#[wasm_bindgen]
pub fn classicmceliece_decapsulate(
    secret_key: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, JsValue> {
    classicmceliece348864_decapsulate(secret_key, ciphertext)
}

#[cfg(feature = "classicmceliece")]
pub fn mceliece348864_keypair() -> (ClassicMcElieceKeyPair, ClassicMcElieceKeyPair) {
    std::env::set_var("RUST_MIN_STACK", "800000000"); // Experimental stack increase
    let (pk, sk) = keypair348864();
    (
        ClassicMcElieceKeyPair {
            pk: pk.as_bytes().to_vec(),
            sk: sk.as_bytes().to_vec(),
        },
        ClassicMcElieceKeyPair {
            pk: pk.as_bytes().to_vec(),
            sk: sk.as_bytes().to_vec(),
        },
    )
}
