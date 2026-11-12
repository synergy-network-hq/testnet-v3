use crate::records::BootseedRecord;
pub trait BootseedVerifier: Send + Sync {
    fn verify(&self, record: &BootseedRecord) -> Result<(), String>;
}
pub fn verify_record(
    record: &BootseedRecord,
    now: u64,
    verifier: &dyn BootseedVerifier,
) -> Result<(), String> {
    record.validate_shape().map_err(str::to_string)?;
    if record.expires_at <= now {
        return Err("bootseed record expired".into());
    }
    verifier.verify(record)
}
