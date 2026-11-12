//! Signed network-manifest bindings. Cryptographic verification is injected
//! through the canonical Aegis engine and is never implemented in this crate.

mod chain_identity;
mod consensus_binding;
mod etdag_binding;
mod genesis_binding;
mod hash;
mod network_manifest;
mod protocol_versions;
mod release_binding;
mod role_binding;
mod signature;
mod transport_binding;
mod verifier;

pub use chain_identity::ChainIdentityBinding;
pub use consensus_binding::ConsensusBinding;
pub use etdag_binding::EtdagBinding;
pub use genesis_binding::GenesisBinding;
pub use network_manifest::NetworkManifest;
pub use protocol_versions::ProtocolVersions;
pub use release_binding::ReleaseBinding;
pub use role_binding::RoleBinding;
pub use signature::{ManifestSignature, ManifestSignatureVerifier};
pub use transport_binding::TransportBinding;
pub use verifier::ManifestError;
