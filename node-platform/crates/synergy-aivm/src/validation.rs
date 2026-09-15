use crate::AivmRequest;
use sha3::{Digest, Sha3_256};
pub const MAX_MODULE_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_INPUT_BYTES: usize = 64 * 1024 * 1024;
pub fn validate_request(r: &AivmRequest) -> Result<(), String> {
    r.job.validate()?;
    r.budget.validate()?;
    r.sandbox
        .validate()
        .map_err(|e| format!("sandbox violation: {e:?}"))?;
    if r.module.is_empty() || r.module.len() > MAX_MODULE_BYTES || r.input.len() > MAX_INPUT_BYTES {
        return Err("AIVM module or input exceeds bound".into());
    }
    Ok(())
}
pub fn output_root(bytes: &[u8]) -> String {
    let mut h = Sha3_256::new();
    h.update(b"SYNERGY_AIVM_OUTPUT_V1");
    h.update((bytes.len() as u64).to_be_bytes());
    h.update(bytes);
    format!("{:x}", h.finalize())
}
