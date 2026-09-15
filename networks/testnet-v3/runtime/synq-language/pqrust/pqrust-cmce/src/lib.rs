
#![no_std]
#![allow(clippy::len_without_is_empty)]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub mod ffi;
pub mod cmce348864;
pub mod cmce348864f;
pub mod cmce460896;
pub mod cmce460896f;
pub mod cmce6688128;
pub mod cmce6688128f;
pub mod cmce6960119;
pub mod cmce6960119f;
pub mod cmce8192128;
pub mod cmce8192128f;

pub use crate::cmce348864::{
    ciphertext_bytes as mceliece348864_ciphertext_bytes, decapsulate as mceliece348864_decapsulate,
    encapsulate as mceliece348864_encapsulate, keypair as mceliece348864_keypair,
    public_key_bytes as mceliece348864_public_key_bytes,
    secret_key_bytes as mceliece348864_secret_key_bytes,
    shared_secret_bytes as mceliece348864_shared_secret_bytes,
};
pub use crate::cmce348864f::{
    ciphertext_bytes as mceliece348864f_ciphertext_bytes,
    decapsulate as mceliece348864f_decapsulate, encapsulate as mceliece348864f_encapsulate,
    keypair as mceliece348864f_keypair, public_key_bytes as mceliece348864f_public_key_bytes,
    secret_key_bytes as mceliece348864f_secret_key_bytes,
    shared_secret_bytes as mceliece348864f_shared_secret_bytes,
};
pub use crate::cmce460896::{
    ciphertext_bytes as mceliece460896_ciphertext_bytes, decapsulate as mceliece460896_decapsulate,
    encapsulate as mceliece460896_encapsulate, keypair as mceliece460896_keypair,
    public_key_bytes as mceliece460896_public_key_bytes,
    secret_key_bytes as mceliece460896_secret_key_bytes,
    shared_secret_bytes as mceliece460896_shared_secret_bytes,
};
pub use crate::cmce460896f::{
    ciphertext_bytes as mceliece460896f_ciphertext_bytes,
    decapsulate as mceliece460896f_decapsulate, encapsulate as mceliece460896f_encapsulate,
    keypair as mceliece460896f_keypair, public_key_bytes as mceliece460896f_public_key_bytes,
    secret_key_bytes as mceliece460896f_secret_key_bytes,
    shared_secret_bytes as mceliece460896f_shared_secret_bytes,
};
pub use crate::cmce6688128::{
    ciphertext_bytes as mceliece6688128_ciphertext_bytes,
    decapsulate as mceliece6688128_decapsulate, encapsulate as mceliece6688128_encapsulate,
    keypair as mceliece6688128_keypair, public_key_bytes as mceliece6688128_public_key_bytes,
    secret_key_bytes as mceliece6688128_secret_key_bytes,
    shared_secret_bytes as mceliece6688128_shared_secret_bytes,
};
pub use crate::cmce6688128f::{
    ciphertext_bytes as mceliece6688128f_ciphertext_bytes,
    decapsulate as mceliece6688128f_decapsulate, encapsulate as mceliece6688128f_encapsulate,
    keypair as mceliece6688128f_keypair, public_key_bytes as mceliece6688128f_public_key_bytes,
    secret_key_bytes as mceliece6688128f_secret_key_bytes,
    shared_secret_bytes as mceliece6688128f_shared_secret_bytes,
};
pub use crate::cmce6960119::{
    ciphertext_bytes as mceliece6960119_ciphertext_bytes,
    decapsulate as mceliece6960119_decapsulate, encapsulate as mceliece6960119_encapsulate,
    keypair as mceliece6960119_keypair, public_key_bytes as mceliece6960119_public_key_bytes,
    secret_key_bytes as mceliece6960119_secret_key_bytes,
    shared_secret_bytes as mceliece6960119_shared_secret_bytes,
};
pub use crate::cmce6960119f::{
    ciphertext_bytes as mceliece6960119f_ciphertext_bytes,
    decapsulate as mceliece6960119f_decapsulate, encapsulate as mceliece6960119f_encapsulate,
    keypair as mceliece6960119f_keypair, public_key_bytes as mceliece6960119f_public_key_bytes,
    secret_key_bytes as mceliece6960119f_secret_key_bytes,
    shared_secret_bytes as mceliece6960119f_shared_secret_bytes,
};
pub use crate::cmce8192128::{
    ciphertext_bytes as mceliece8192128_ciphertext_bytes,
    decapsulate as mceliece8192128_decapsulate, encapsulate as mceliece8192128_encapsulate,
    keypair as mceliece8192128_keypair, public_key_bytes as mceliece8192128_public_key_bytes,
    secret_key_bytes as mceliece8192128_secret_key_bytes,
    shared_secret_bytes as mceliece8192128_shared_secret_bytes,
};
pub use crate::cmce8192128f::{
    ciphertext_bytes as mceliece8192128f_ciphertext_bytes,
    decapsulate as mceliece8192128f_decapsulate, encapsulate as mceliece8192128f_encapsulate,
    keypair as mceliece8192128f_keypair, public_key_bytes as mceliece8192128f_public_key_bytes,
    secret_key_bytes as mceliece8192128f_secret_key_bytes,
    shared_secret_bytes as mceliece8192128f_shared_secret_bytes,
};