//! Authority-neutral AI workload, coordination, data, and assurance contracts. AI evidence never grants PoSy authority.
pub mod assurance;
pub mod capability;
pub mod compute;
pub mod coordination;
pub mod data;
pub mod job;
pub mod metrics;
pub mod policy;
pub mod provider;
pub mod receipt;
pub use capability::AiCapability;
pub use job::{AiJob, ResourceRequest};
pub use policy::AiPolicy;
pub use provider::ProviderAdvertisement;
pub use receipt::{AiReceipt, ReceiptOutcome};
pub(crate) fn valid(v: &str) -> bool {
    !v.trim().is_empty() && v.len() <= 1024 && !v.contains(char::is_control)
}
