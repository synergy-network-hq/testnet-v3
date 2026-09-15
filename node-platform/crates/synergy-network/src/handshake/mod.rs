//! Nonce-bound identity authentication for new Synergy P2P sessions.

mod aegis;
mod chain;
mod challenge;
mod compatibility;
mod identity;
pub mod policy;
mod protocol;
mod rejection;
mod role;
mod signing;
mod verifier;

pub use aegis::{AegisHandshakeSigner, AegisHandshakeVerifier};
pub use chain::{ChainBinding, ChainBindingError};
pub use challenge::{ChallengeError, HandshakeChallenge, MAX_CHALLENGE_LIFETIME_SECS};
pub use compatibility::{verify_handshake_compatibility, HandshakeCompatibilityError};
pub use identity::{IdentityError, TransportIdentity};
pub use policy::{parse_peer_key_algorithm, HandshakeError, HandshakeMetadata, PeerKeyAlgorithm};
pub use protocol::{HandshakeOffer, HandshakeProof, OfferError};
pub use rejection::HandshakeRejection;
pub use role::AdvertisedNodeRole;
pub use signing::{
    build_handshake_proof, HandshakeSignError, HandshakeSigner, HandshakeTranscriptError,
};
pub use verifier::{
    verify_handshake, HandshakeSignatureVerifier, HandshakeVerificationError, VerifiedHandshake,
};
