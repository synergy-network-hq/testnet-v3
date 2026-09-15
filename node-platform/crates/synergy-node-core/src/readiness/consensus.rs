use serde::{Deserialize, Serialize};

use crate::DiagnosticCheck;

/// PoSy readiness evidence supplied by the consensus owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsensusReadiness {
    pub required_for_role: bool,
    pub active_membership_authorized: bool,
    pub recovery_reconciled: bool,
    pub signing_key_available: bool,
    pub protected_h_plus_five_ready: bool,
}

impl ConsensusReadiness {
    pub fn check(self) -> DiagnosticCheck {
        if !self.required_for_role {
            return DiagnosticCheck::passed(
                "consensus.not_required",
                "posy",
                "the selected role has no PoSy signing duty",
            );
        }
        if !(self.active_membership_authorized
            && self.recovery_reconciled
            && self.signing_key_available
            && self.protected_h_plus_five_ready)
        {
            return DiagnosticCheck::failed(
                "consensus.signing_gate",
                "posy",
                "PoSy signing prerequisites are incomplete",
                "restore governed membership, safe recovery, key custody, and protected H+5 material",
            );
        }
        DiagnosticCheck::passed(
            "consensus.signing_gate",
            "posy",
            "PoSy signing prerequisites are satisfied",
        )
    }
}
