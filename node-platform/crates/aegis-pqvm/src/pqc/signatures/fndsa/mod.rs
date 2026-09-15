//! # FN-DSA
//!
//! This crate provides bindings to and wrappers around the following
//! implementations from [PQClean][pqc]:
//!
//! * FN-DSA-512 - clean
//! * FN-DSA-padded-512 - clean
//! * FN-DSA-1024 - clean
//! * FN-DSA-padded-1024 - clean
//!
//! [pqc]: https://github.com/pqclean/pqclean/
//!

pub mod ffi;
pub mod fndsa1024;
pub mod fndsa512;
pub mod fndsa_padded1024;
pub mod fndsa_padded512;

pub use self::fndsa1024::{
    detached_sign as fndsa1024_detached_sign, keypair as fndsa1024_keypair, open as fndsa1024_open,
    public_key_bytes as fndsa1024_public_key_bytes, secret_key_bytes as fndsa1024_secret_key_bytes,
    sign as fndsa1024_sign, signature_bytes as fndsa1024_signature_bytes,
    verify_detached_signature as fndsa1024_verify_detached_signature,
};
pub use self::fndsa512::{
    detached_sign as fndsa512_detached_sign, keypair as fndsa512_keypair, open as fndsa512_open,
    public_key_bytes as fndsa512_public_key_bytes, secret_key_bytes as fndsa512_secret_key_bytes,
    sign as fndsa512_sign, signature_bytes as fndsa512_signature_bytes,
    verify_detached_signature as fndsa512_verify_detached_signature,
};
pub use self::fndsa_padded1024::{
    detached_sign as fndsa_padded1024_detached_sign, keypair as fndsa_padded1024_keypair,
    open as fndsa_padded1024_open, public_key_bytes as fndsa_padded1024_public_key_bytes,
    secret_key_bytes as fndsa_padded1024_secret_key_bytes, sign as fndsa_padded1024_sign,
    signature_bytes as fndsa_padded1024_signature_bytes,
    verify_detached_signature as fndsa_padded1024_verify_detached_signature,
};
pub use self::fndsa_padded512::{
    detached_sign as fndsa_padded512_detached_sign, keypair as fndsa_padded512_keypair,
    open as fndsa_padded512_open, public_key_bytes as fndsa_padded512_public_key_bytes,
    secret_key_bytes as fndsa_padded512_secret_key_bytes, sign as fndsa_padded512_sign,
    signature_bytes as fndsa_padded512_signature_bytes,
    verify_detached_signature as fndsa_padded512_verify_detached_signature,
};
