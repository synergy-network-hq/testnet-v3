use serde::{Deserialize, Serialize};

pub const CHAIN_STATUS: &str = "synergy_chainStatus";

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainQuery {
    pub include_roots: bool,
}
