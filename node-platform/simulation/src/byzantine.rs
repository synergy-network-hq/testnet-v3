use std::collections::BTreeMap;
#[derive(Default)]
pub struct EquivocationDetector {
    seen: BTreeMap<(String, u64, u64), Vec<u8>>,
}
impl EquivocationDetector {
    pub fn observe(
        &mut self,
        validator: &str,
        height: u64,
        round: u64,
        digest: Vec<u8>,
    ) -> Result<(), String> {
        let key = (validator.into(), height, round);
        if let Some(old) = self.seen.get(&key) {
            if old != &digest {
                return Err("equivocation detected".into());
            }
            return Ok(());
        }
        self.seen.insert(key, digest);
        Ok(())
    }
}
