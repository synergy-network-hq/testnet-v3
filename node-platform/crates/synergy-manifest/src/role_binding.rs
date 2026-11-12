use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleBinding {
    pub taxonomy_version: u16,
    pub profiles_hash: String,
}
impl RoleBinding {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.taxonomy_version > 0 && crate::hash::hex64(&self.profiles_hash) {
            Ok(())
        } else {
            Err("invalid role binding")
        }
    }
}
