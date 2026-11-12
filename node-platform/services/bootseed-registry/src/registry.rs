use crate::{
    records::BootseedRecord,
    verification::{verify_record, BootseedVerifier},
};
use std::collections::BTreeMap;
#[derive(Default)]
pub struct BootseedRegistry {
    records: BTreeMap<String, BootseedRecord>,
}
impl BootseedRegistry {
    pub fn publish(
        &mut self,
        record: BootseedRecord,
        now: u64,
        verifier: &dyn BootseedVerifier,
    ) -> Result<(), String> {
        verify_record(&record, now, verifier)?;
        if self
            .records
            .get(&record.node_address)
            .is_some_and(|old| old.generation >= record.generation)
        {
            return Err("stale bootseed generation".into());
        }
        self.records.insert(record.node_address.clone(), record);
        Ok(())
    }
    pub fn live(&self, now: u64, limit: usize) -> Vec<BootseedRecord> {
        self.records
            .values()
            .filter(|r| r.expires_at > now)
            .take(limit.min(256))
            .cloned()
            .collect()
    }
}
