use serde::{Deserialize, Serialize};

pub const ETDAG_STATUS: &str = "synergy_etdagStatus";

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EtdagQuery {
    pub include_backlog: bool,
}
