//! Shared cryptographic encodings and provider boundaries. Consensus authority remains with governed PoSy inputs.
pub mod constant_time;
pub mod domain;
pub mod encoding;
pub mod hash;
pub mod kem;
pub mod key_provider;
pub mod random;
pub mod signatures;
pub mod symmetric;
pub use domain::CryptoDomain;
pub use hash::{sha3_256, sha3_256_segments, sha3_512_segments, Hash32};
pub use synergy_aegis::{
    AegisDigest, AegisHashEngine, AegisSha3_256, AegisSigner, AegisVerifier, KeyId, Signature,
    SignatureAlgorithm, SigningContext,
};
