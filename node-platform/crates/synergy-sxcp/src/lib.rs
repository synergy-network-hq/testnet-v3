//! Synergy Cross-Chain Protocol proof, finality, vault, and relay boundaries.
//!
//! External-chain evidence cannot create validator authority or PoSy finality.

pub mod adapters;
mod capability;
mod execution;
mod finality;
mod independence;
mod proof;
mod protocol;
mod receipt;
mod relay;
mod uma;
mod vault;
mod verifier;

pub use capability::SxcpCapability;
pub use execution::{
    FinalizedSxcpRelayIntent, SxcpAuthorizationSignature, SxcpExecutionAuthorizationVerifier,
    SxcpRelayExecution,
};
pub use finality::verify_external_finality;
pub use independence::SynergyFinalityAnchor;
pub use proof::{ExternalFinalityProof, ExternalProofAdapter, VerifiedExternalTransfer};
pub use protocol::{ExternalChain, SxcpTransfer};
pub use receipt::RelayReceipt;
pub use relay::{relay_verified_transfer, RelayDestination};
pub use uma::resolve_uma_destination;
pub use vault::{VaultKeyReference, VaultProvider};
pub use verifier::SxcpVerifierRegistry;
