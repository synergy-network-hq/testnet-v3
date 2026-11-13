//! # ML-KEM
//!
//! This crate provides bindings to and wrappers around the following
//! implementations from [PQClean][pqc]:
//!
//! * ML-KEM-512 - clean
//! * ML-KEM-768 - clean
//! * ML-KEM-1024 - clean
//!
//! [pqc]: https://github.com/pqclean/pqclean/
//!

pub mod ffi;
pub mod mlkem1024;
pub mod mlkem512;
pub mod mlkem768;

pub use self::mlkem1024::{
    ciphertext_bytes as mlkem1024_ciphertext_bytes, decapsulate as mlkem1024_decapsulate,
    encapsulate as mlkem1024_encapsulate, keypair as mlkem1024_keypair,
    public_key_bytes as mlkem1024_public_key_bytes, secret_key_bytes as mlkem1024_secret_key_bytes,
    shared_secret_bytes as mlkem1024_shared_secret_bytes,
};
pub use self::mlkem512::{
    ciphertext_bytes as mlkem512_ciphertext_bytes, decapsulate as mlkem512_decapsulate,
    encapsulate as mlkem512_encapsulate, keypair as mlkem512_keypair,
    public_key_bytes as mlkem512_public_key_bytes, secret_key_bytes as mlkem512_secret_key_bytes,
    shared_secret_bytes as mlkem512_shared_secret_bytes,
};
pub use self::mlkem768::{
    ciphertext_bytes as mlkem768_ciphertext_bytes, decapsulate as mlkem768_decapsulate,
    encapsulate as mlkem768_encapsulate, keypair as mlkem768_keypair,
    public_key_bytes as mlkem768_public_key_bytes, secret_key_bytes as mlkem768_secret_key_bytes,
    shared_secret_bytes as mlkem768_shared_secret_bytes,
};
