//! Discovery candidate parsing. Discovery is untrusted until handshake and peer admission.

mod bootseed;
mod cache;
mod dns;
mod peer_exchange;
mod seed_set;
mod transport_registry;
mod verifier;

pub use bootseed::{BootseedCandidate, BootseedSet};
pub use cache::{DiscoveryCache, DiscoveryRecord};
pub use dns::parse_dnsaddr_multiaddr_to_dial_address;
pub use peer_exchange::PeerExchange;
pub use seed_set::SeedSet;
pub use transport_registry::DiscoveryTransportRegistry;
pub use verifier::{verify_discovery_record, DiscoveryVerificationError};
