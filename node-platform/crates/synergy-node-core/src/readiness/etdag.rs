use serde::{Deserialize, Serialize};

use crate::DiagnosticCheck;

/// Protected-transaction material readiness; it never decides finality.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EtdagReadiness {
    pub required_for_role: bool,
    pub governed_parameters_loaded: bool,
    pub ingress_keys_available: bool,
    pub recovery_complete: bool,
    pub proposal_material_ready: bool,
}

impl EtdagReadiness {
    pub fn check(self) -> DiagnosticCheck {
        if !self.required_for_role {
            return DiagnosticCheck::passed(
                "etdag.not_required",
                "etdag",
                "the selected role has no ETDAG production duty",
            );
        }
        if self.governed_parameters_loaded
            && self.ingress_keys_available
            && self.recovery_complete
            && self.proposal_material_ready
        {
            DiagnosticCheck::passed(
                "etdag.proposal_material",
                "etdag",
                "verified protected proposal material is ready",
            )
        } else {
            DiagnosticCheck::failed(
                "etdag.proposal_material",
                "etdag",
                "verified protected proposal material is not ready",
                "restore governed parameters, ingress keys, recovery state, and H+5 preparation",
            )
        }
    }
}
