use std::collections::BTreeSet;
#[derive(Default)]
pub struct RevocationSet {
    ids: BTreeSet<String>,
}
impl RevocationSet {
    pub fn revoke(&mut self, id: impl Into<String>) {
        self.ids.insert(id.into());
    }
    pub fn is_revoked(&self, id: &str) -> bool {
        self.ids.contains(id)
    }
}
