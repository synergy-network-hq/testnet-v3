use synergy_etdag::ProtectedIngressReceipt;

#[derive(Debug, Clone)]
pub struct ClientSubmissionReceipt {
    pub receipt: ProtectedIngressReceipt,
}

impl ClientSubmissionReceipt {
    pub fn target_height(&self) -> u64 {
        self.receipt.target_height
    }

    pub fn may_determine_finality(&self) -> bool {
        false
    }
}
