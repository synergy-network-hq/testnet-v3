use super::{
    AdmissionQueue, IngressRateLimiter, IngressReplayProtection, ProtectedIngressReceipt,
};
use crate::admission::{
    AdmissionRequest, AdmissionResourceLimits, AdmissionSignatureVerifier, AdmissionValidator,
};
use crate::{EtdagDigest, EtdagError};

pub struct ProtectedIngressService<V> {
    validator: AdmissionValidator<V>,
    rate_limiter: IngressRateLimiter,
    replay: IngressReplayProtection,
    queue: AdmissionQueue,
    closed: bool,
}

impl<V: AdmissionSignatureVerifier> ProtectedIngressService<V> {
    pub fn new(
        chain_id: u64,
        network_id: String,
        context_root: EtdagDigest,
        target_height: u64,
        limits: AdmissionResourceLimits,
        verifier: V,
        rate_limiter: IngressRateLimiter,
        replay_capacity: usize,
    ) -> Result<Self, EtdagError> {
        let validator = AdmissionValidator::new(
            chain_id,
            network_id,
            context_root,
            target_height,
            limits,
            verifier,
        )?;
        Ok(Self {
            validator,
            rate_limiter,
            replay: IngressReplayProtection::new(replay_capacity)?,
            queue: AdmissionQueue::new(limits.maximum_envelopes)?,
            closed: false,
        })
    }

    pub fn submit(
        &mut self,
        request: AdmissionRequest,
        now_millis: u64,
    ) -> Result<ProtectedIngressReceipt, EtdagError> {
        if self.closed {
            return Err(EtdagError::AdmissionClosed);
        }
        self.validator.verify(&request)?;
        self.rate_limiter
            .check(&request.sender_wallet, now_millis)?;
        self.replay.check(&request)?;
        self.queue.check(&request)?;

        let receipt = ProtectedIngressReceipt {
            envelope_id: request.envelope.envelope_id.clone(),
            context_root: request.context_root.clone(),
            target_height: request.target_height,
            sender_nonce: request.sender_nonce,
            accepted_at_millis: now_millis,
        };
        self.rate_limiter
            .record(&request.sender_wallet, now_millis);
        self.replay.record(&request);
        self.queue.push(request);
        Ok(receipt)
    }

    pub fn next(&mut self) -> Option<AdmissionRequest> {
        self.queue.pop()
    }

    pub fn close(&mut self) {
        self.closed = true;
    }

    pub fn queued(&self) -> usize {
        self.queue.len()
    }

    pub const fn may_determine_finality(&self) -> bool {
        false
    }
}
