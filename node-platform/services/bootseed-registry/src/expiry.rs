use crate::records::BootseedRecord;
pub fn retain_live(records: &mut Vec<BootseedRecord>, now: u64) -> usize {
    let before = records.len();
    records.retain(|r| r.expires_at > now);
    before - records.len()
}
