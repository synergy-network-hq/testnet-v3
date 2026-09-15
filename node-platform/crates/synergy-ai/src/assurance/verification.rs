use crate::{assurance::independence::IndependenceEvidence, AiJob, AiReceipt};
pub trait ReceiptVerifier {
    fn verify(&self, provider: &str, receipt: &AiReceipt) -> Result<(), String>;
}
pub fn verify_receipt(
    j: &AiJob,
    r: &AiReceipt,
    i: &IndependenceEvidence,
    v: &impl ReceiptVerifier,
) -> Result<(), String> {
    j.validate()?;
    r.validate()?;
    i.validate()?;
    if j.job_id != r.job_id || i.provider_id != r.provider_id {
        return Err("assurance binding mismatch".into());
    }
    v.verify(&r.provider_id, r)
}
