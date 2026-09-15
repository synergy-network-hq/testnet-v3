use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::PreparedConsensusState;
use crate::{
    canonical_hash, verify_strict_dual_quorum, ConsensusSignatureVerifier, FrozenValidatorRegistry,
    PosyError, PosyResult, SimplifiedEpochContext,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
/// A validator-signed report of its prepared PoSy safety checkpoint.
pub struct PeerRecoveryReport {
    pub validator_id: String,
    pub key_id: String,
    pub prepared: PreparedConsensusState,
    pub signature: Vec<u8>,
}

#[derive(Serialize)]
struct PeerRecoverySigningPayload<'a> {
    validator_id: &'a str,
    key_id: &'a str,
    prepared: &'a PreparedConsensusState,
}

impl PeerRecoveryReport {
    /// Serializes the canonical recovery-report signature transcript.
    pub fn signing_bytes(&self) -> PosyResult<Vec<u8>> {
        serde_json::to_vec(&PeerRecoverySigningPayload {
            validator_id: &self.validator_id,
            key_id: &self.key_id,
            prepared: &self.prepared,
        })
        .map_err(|error| PosyError::invalid(format!("serialize recovery report: {error}")))
    }
}

/// Selects an identical restart checkpoint only when the reporting validators
/// independently satisfy strict count and frozen-weight quorum. Each report
/// is signature-checked against the frozen consensus key before counting.
pub fn select_quorum_recovery_state(
    reports: &[PeerRecoveryReport],
    epoch: &SimplifiedEpochContext,
    registry: &FrozenValidatorRegistry,
    verifier: &impl ConsensusSignatureVerifier,
) -> PosyResult<PreparedConsensusState> {
    let mut by_root = BTreeMap::<String, (PreparedConsensusState, Vec<String>)>::new();
    for report in reports {
        report.prepared.validate(epoch)?;
        let validator = registry.active_validator(&report.validator_id)?;
        if report.key_id != validator.consensus_key_id {
            return Err(PosyError::invalid(
                "recovery report does not use the frozen consensus key",
            ));
        }
        verifier.verify_consensus_signature(
            "Synergy/PoSy/v3/recovery-report",
            &report.signing_bytes()?,
            validator,
            &report.key_id,
            registry.epoch(),
            &report.signature,
        )?;
        let root = canonical_hash("Synergy/PoSy/v3/recovery-checkpoint", &report.prepared)?;
        let entry = by_root
            .entry(root)
            .or_insert_with(|| (report.prepared.clone(), Vec::new()));
        if !entry.1.contains(&report.validator_id) {
            entry.1.push(report.validator_id.clone());
        }
    }
    let mut selected = by_root
        .into_values()
        .filter(|(_, signers)| {
            verify_strict_dual_quorum(&registry.quorum_validators(), signers).is_ok()
        })
        .collect::<Vec<_>>();
    if selected.len() != 1 {
        return Err(PosyError::NotReady(
            "recovery requires one strict dual-quorum checkpoint".into(),
        ));
    }
    Ok(selected.remove(0).0)
}
