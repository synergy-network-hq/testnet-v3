use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolVersions {
    pub p2p: u16,
    pub posy: u16,
    pub etdag: u16,
    pub sync: u16,
    pub snapshot: u16,
    pub admin: u16,
}
impl ProtocolVersions {
    pub fn validate(&self) -> Result<(), &'static str> {
        if [
            self.p2p,
            self.posy,
            self.etdag,
            self.sync,
            self.snapshot,
            self.admin,
        ]
        .into_iter()
        .all(|v| v > 0)
        {
            Ok(())
        } else {
            Err("protocol versions must be nonzero")
        }
    }
}
