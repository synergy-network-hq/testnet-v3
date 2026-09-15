#[cfg(feature = "serialization")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "serialization")]
use serde_big_array::BigArray;

use crate::ffi;
use pqrust_traits::kem as primitive;
use pqrust_traits::{Error, Result};

macro_rules! simple_struct {
    ($type: ident, $size: expr) => {
        #[derive(Clone, Copy)]
        #[cfg_attr(feature = "serialization", derive(Serialize, Deserialize))]
        pub struct $type(
            #[cfg_attr(feature = "serialization", serde(with = "BigArray"))] [u8; $size],
        );

        impl $type {
            fn new() -> Self {
                $type([0u8; $size])
            }
        }

        impl primitive::$type for $type {
            #[inline]
            fn as_bytes(&self) -> &[u8] {
                &self.0
            }

            fn from_bytes(bytes: &[u8]) -> Result<Self> {
                if bytes.len() != $size {
                    Err(Error::BadLength {
                        name: stringify!($type),
                        actual: bytes.len(),
                        expected: $size,
                    })
                } else {
                    let mut array = [0u8; $size];
                    array.copy_from_slice(bytes);
                    Ok($type(array))
                }
            }
        }

        impl PartialEq for $type {
            fn eq(&self, other: &Self) -> bool {
                self.0
                    .iter()
                    .zip(other.0.iter())
                    .try_for_each(|(a, b)| if a == b { Ok(()) } else { Err(()) })
                    .is_ok()
            }
        }
    };
}

simple_struct!(PublicKey, ffi::PQCLEAN_HQC192_CLEAN_CRYPTO_PUBLICKEYBYTES);
simple_struct!(SecretKey, ffi::PQCLEAN_HQC192_CLEAN_CRYPTO_SECRETKEYBYTES);
simple_struct!(Ciphertext, ffi::PQCLEAN_HQC192_CLEAN_CRYPTO_CIPHERTEXTBYTES);
simple_struct!(SharedSecret, ffi::PQCLEAN_HQC192_CLEAN_CRYPTO_BYTES);

pub const fn public_key_bytes() -> usize {
    ffi::PQCLEAN_HQC192_CLEAN_CRYPTO_PUBLICKEYBYTES
}

pub const fn secret_key_bytes() -> usize {
    ffi::PQCLEAN_HQC192_CLEAN_CRYPTO_SECRETKEYBYTES
}

pub const fn ciphertext_bytes() -> usize {
    ffi::PQCLEAN_HQC192_CLEAN_CRYPTO_CIPHERTEXTBYTES
}

pub const fn shared_secret_bytes() -> usize {
    ffi::PQCLEAN_HQC192_CLEAN_CRYPTO_BYTES
}

#[inline]
fn ffi_result(operation: &'static str, code: i32) -> Result<()> {
    if code == 0 {
        Ok(())
    } else {
        Err(Error::FfiFailure { operation, code })
    }
}

macro_rules! gen_keypair {
    ($variant:ident) => {{
        let mut pk = PublicKey::new();
        let mut sk = SecretKey::new();
        ffi_result("hqc192_keypair", unsafe {
            ffi::$variant(pk.0.as_mut_ptr(), sk.0.as_mut_ptr())
        })
        .map(|_| (pk, sk))
    }};
}

pub fn keypair() -> Result<(PublicKey, SecretKey)> {
    gen_keypair!(PQCLEAN_HQC192_CLEAN_crypto_kem_keypair)
}

macro_rules! encap {
    ($variant:ident, $pk:ident) => {{
        let mut ss = SharedSecret::new();
        let mut ct = Ciphertext::new();
        ffi_result("hqc192_encapsulate", unsafe {
            ffi::$variant(ct.0.as_mut_ptr(), ss.0.as_mut_ptr(), $pk.0.as_ptr())
        })
        .map(|_| (ss, ct))
    }};
}

pub fn encapsulate(pk: &PublicKey) -> Result<(SharedSecret, Ciphertext)> {
    encap!(PQCLEAN_HQC192_CLEAN_crypto_kem_enc, pk)
}

macro_rules! decap {
    ($variant:ident, $ct:ident, $sk:ident) => {{
        let mut ss = SharedSecret::new();
        ffi_result("hqc192_decapsulate", unsafe {
            ffi::$variant(ss.0.as_mut_ptr(), $ct.0.as_ptr(), $sk.0.as_ptr())
        })
        .map(|_| ss)
    }};
}

pub fn decapsulate(ct: &Ciphertext, sk: &SecretKey) -> Result<SharedSecret> {
    decap!(PQCLEAN_HQC192_CLEAN_crypto_kem_dec, ct, sk)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    pub fn test_kem() {
        let (pk, sk) = keypair().expect("HQC-192 keypair should succeed");
        let (ss1, ct) = encapsulate(&pk).expect("HQC-192 encapsulation should succeed");
        let ss2 = decapsulate(&ct, &sk).expect("HQC-192 decapsulation should succeed");
        assert_eq!(&ss1.0[..], &ss2.0[..], "Difference in shared secrets!");
    }
}
