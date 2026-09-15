use serde::{Deserialize, Serialize};

pub const GOVERNED_PROTECTED_LOOKAHEAD: u64 = 5;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EtdagConfiguration {
    pub enabled: bool,
    pub protected_lookahead: u64,
    pub admission_queue_capacity: usize,
    pub max_vertex_bytes: usize,
    pub proposal_material_wait_ms: u64,
}

impl Default for EtdagConfiguration {
    fn default() -> Self {
        Self {
            enabled: false,
            protected_lookahead: GOVERNED_PROTECTED_LOOKAHEAD,
            admission_queue_capacity: 4_096,
            max_vertex_bytes: 2 * 1024 * 1024,
            proposal_material_wait_ms: 1_500,
        }
    }
}
