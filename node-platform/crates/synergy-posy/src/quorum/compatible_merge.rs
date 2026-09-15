use std::collections::BTreeMap;

use crate::{PosyError, PosyResult, SimplifiedQuorumCertificate};

/// Different valid signer subsets certify the same candidate. Merge proof
/// material by stable candidate identity without changing the candidate itself.
pub fn merge_compatible_quorum_certificates(
    left: SimplifiedQuorumCertificate,
    right: SimplifiedQuorumCertificate,
) -> PosyResult<SimplifiedQuorumCertificate> {
    if left.id()? != right.id()? {
        return Err(PosyError::Conflict(
            "cannot merge different certified candidates".into(),
        ));
    }

    // Stable candidate identity deliberately excludes proof-round and
    // takeover evidence. Signatures do not: they cover the complete vote
    // transcript. Never combine participant signatures that were produced
    // for different transcripts into an unverifiable synthetic proof.
    if left.context != right.context || left.takeover_tc_id != right.takeover_tc_id {
        return Ok(left);
    }

    let mut participants = BTreeMap::new();
    for participant in left
        .participants
        .into_iter()
        .chain(right.participants.iter().cloned())
    {
        participants
            .entry(participant.validator_id.clone())
            .or_insert(participant);
    }
    let mut merged = right;
    merged.participants = participants.into_values().collect();
    merged
        .participants
        .sort_by(|left, right| left.validator_id.cmp(&right.validator_id));
    Ok(merged)
}
