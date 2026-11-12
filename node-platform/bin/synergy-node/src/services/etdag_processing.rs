//! Versioned processing transport on the existing ETDAG owner thread. Native
//! PoSy alone supplies proposal slots; raw announcements never grant authority.
#[path = "etdag_processing_work.rs"]
mod work;
use super::*;
use crate::services::processing_proposals::ProcessingProposalInputs;
use synergy_state::world_resources::WorldResourcePermit;

#[derive(Default)]
pub(super) struct ProcessingOwner {
    work: Option<work::ProcessingWork>,
    announcement: Option<(u64, u64, String, Vec<u8>, WorldResourcePermit)>,
    retry: Option<Instant>,
}
impl EtdagService {
    pub(super) fn start_processing_owner(&mut self) -> Result<(), String> {
        if !self.authority.processing_profile_enabled() {
            return Err("processing owner lacks signed policy".into());
        }
        if let Some(handle) = &self.wallet_admission {
            handle.publish_context(None)?;
        }
        self.initialize_pending_work()
    }
    pub(super) fn poll_processing_owner(&mut self) -> Result<(), String> {
        for _ in 0..MAX_MESSAGES_PER_POLL {
            let Some(request) = self.ingress.take_etdag_control()? else {
                break;
            };
            self.ingress_paused = matches!(request.action, EtdagControlAction::PauseIngress);
            let _ = request.response.send(Ok(()));
        }
        // A certified recovery proposal can approach the existing 1 MiB frame
        // limit. Bound this owner quantum so sustained retries cannot keep it
        // inside one poll beyond its unchanged shutdown deadline.
        for _ in 0..4 {
            let Some(frame) = self.ingress.take(ProtocolKind::Etdag)? else {
                break;
            };
            if let Err(error) = EtdagAdapter.deliver(AdapterEnvelope::from(frame), self) {
                #[cfg(test)]
                {
                    static COUNT: std::sync::atomic::AtomicUsize =
                        std::sync::atomic::AtomicUsize::new(0);
                    if COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed) < 20 {
                        eprintln!(
                            "async ETDAG peer rejection: {} {error:?}",
                            self.local_signer.validator_id
                        );
                    }
                }
                #[cfg(not(test))]
                let _ = error;
                self.metrics
                    .record_admission(false)
                    .map_err(|e| format!("record processing peer rejection: {e:?}"))?;
            }
        }
        self.poll_pending_work()?;
        if let Some(reason) = self.failure.as_ref() {
            return Err(reason.clone());
        }
        for _ in 0..2 {
            let Some(frame) = self.ingress.take_processing_inputs(true)? else {
                break;
            };
            let inputs: ProcessingProposalInputs =
                serde_json::from_slice(&frame.payload).map_err(|e| e.to_string())?;
            let Some(request) = self.ingress.processing_build_request()? else {
                continue;
            };
            if frame.sender != self.local_signer.validator_id
                || request.proposer != self.local_signer.validator_id
                || inputs.context != request.context
                || inputs.parent != request.parent
                || inputs.takeover_id.as_deref() != request.takeover.as_ref().map(|tc| tc.id())
            {
                continue;
            }
            let permit = match self.ingress.world_budget().reserve(
                frame
                    .payload
                    .len()
                    .checked_mul(32)
                    .and_then(|n| n.checked_add(64 * 1024))
                    .ok_or("processing announcement size overflow")?,
            ) {
                Ok(p) => p,
                Err(synergy_state::world_resources::WorldResourceError::Capacity { .. }) => {
                    self.ingress
                        .queue_processing_inputs(&frame.sender, &frame.payload, true)?;
                    break;
                }
                Err(e) => return Err(e.to_string()),
            };
            let signed =
                self.local_signer
                    .sign_message(EtdagNetworkMessage::ProcessingProposalInputsV1(
                        frame.payload.clone(),
                    ))?;
            let bytes = serde_json::to_vec(&signed).map_err(|e| e.to_string())?;
            if bytes.len() > synergy_network::protocol::DEFAULT_MAX_FRAME_BYTES {
                return Err("processing announcement exceeds native transport frame".into());
            }
            let owner = self
                .processing
                .as_mut()
                .ok_or("processing owner unavailable")?;
            owner.announcement = Some((
                request.context.height,
                request.context.round,
                inputs.block_id,
                bytes,
                permit,
            ));
            owner.retry = None;
        }
        let slot = self
            .ingress
            .processing_build_request()?
            .map(|r| (r.context.height, r.context.round));
        let owner = self
            .processing
            .as_mut()
            .ok_or("processing owner unavailable")?;
        if owner
            .announcement
            .as_ref()
            .is_some_and(|(h, r, _, _, _)| Some((*h, *r)) != slot)
        {
            owner.announcement = None;
        }
        if owner
            .retry
            .is_none_or(|last| last.elapsed() >= Duration::from_millis(250))
        {
            if let Some((height, round, block_id, bytes, _)) = &owner.announcement {
                // Partial enqueue has already published frames. Pace that
                // attempt too, so a full queue cannot cause prefix resends at
                // every owner poll. Unknown peers still retry after 250ms.
                owner.retry = Some(Instant::now());
                for peer in &self.members {
                    if peer == &self.local_signer.validator_id {
                        continue;
                    }
                    // Native ECHO already attests replay of these exact inputs.
                    // This suppresses only redundant transport, never pending
                    // work, proof retention, quorum, or retries to other peers.
                    if self
                        .ingress
                        .processing_input_was_echoed(peer, *height, *round, block_id)?
                    {
                        continue;
                    }
                    if !self.ingress.try_publish_outbound(OutboundFrame {
                        peer_id: peer.clone(),
                        protocol: ProtocolKind::Etdag,
                        payload: bytes.clone(),
                    })? {
                        #[cfg(feature = "qualification-timing")]
                        crate::services::qualification_timing::processing_boundary(
                            "input_enqueue_partial",
                            *height,
                            *round,
                            block_id,
                            peer,
                        );
                        break;
                    }
                    #[cfg(feature = "qualification-timing")]
                    crate::services::qualification_timing::processing_boundary(
                        "input_enqueue",
                        *height,
                        *round,
                        block_id,
                        peer,
                    );
                }
            }
        }
        Ok(())
    }
}
