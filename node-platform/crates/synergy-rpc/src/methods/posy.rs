use serde::{Deserialize, Serialize};

pub const POSY_STATUS: &str = "synergy_posyStatus";

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PosyQuery {
    pub include_certificate_roots: bool,
}
