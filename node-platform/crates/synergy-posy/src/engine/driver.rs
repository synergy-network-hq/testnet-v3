use crate::{
    ConsensusEvent, ConsensusSignatureVerifier, ConsensusTransition, PosyResult,
    SimplifiedConsensusStateMachine,
};

/// The runtime/network adapter feeds authenticated envelopes here. This is
/// the single event driver; it owns no socket, authority source, signing key,
/// ETDAG orchestration, or finalization storage implementation.
#[derive(Debug)]
pub struct SimplifiedPosyDriver {
    state_machine: SimplifiedConsensusStateMachine,
}

impl SimplifiedPosyDriver {
    pub fn new(state_machine: SimplifiedConsensusStateMachine) -> Self {
        Self { state_machine }
    }

    pub fn state_machine(&self) -> &SimplifiedConsensusStateMachine {
        &self.state_machine
    }

    pub fn handle(
        &mut self,
        event: ConsensusEvent,
        verifier: &impl ConsensusSignatureVerifier,
    ) -> PosyResult<Vec<ConsensusTransition>> {
        match event {
            ConsensusEvent::Proposal(proposal) => self
                .state_machine
                .accept_proposal(&proposal, verifier)
                .map(|transition| vec![transition]),
            ConsensusEvent::BlockVote(vote) => self.state_machine.accept_block_vote(vote, verifier),
            ConsensusEvent::TimeoutVote(vote) => {
                self.state_machine.accept_timeout_vote(vote, verifier)
            }
            ConsensusEvent::QuorumCertificate(certificate) => self
                .state_machine
                .accept_quorum_certificate(certificate, verifier),
            ConsensusEvent::TimeoutCertificate(certificate) => self
                .state_machine
                .accept_timeout_certificate(certificate, verifier),
        }
    }
}
