use crate::{EtdagError, EtdagParameters};

use super::GovernedEtdagManifest;

pub fn validate_manifest_activation(
    current: Option<&GovernedEtdagManifest>,
    next: &GovernedEtdagManifest,
    finalized_height: u64,
) -> Result<(), EtdagError> {
    next.validate()?;
    if next.activation_height <= finalized_height {
        return Err(EtdagError::Governance(
            "ETDAG manifest activation is not in the future".into(),
        ));
    }
    if let Some(current) = current {
        current.validate()?;
        if current.network_id != next.network_id
            || current.chain_id != next.chain_id
            || next.activation_height <= current.activation_height
        {
            return Err(EtdagError::Governance(
                "invalid ETDAG manifest succession".into(),
            ));
        }
        reject_frozen_parameter_change(&current.parameters, &next.parameters)?;
    }
    Ok(())
}

fn reject_frozen_parameter_change(
    current: &EtdagParameters,
    next: &EtdagParameters,
) -> Result<(), EtdagError> {
    if current.profile_id != next.profile_id
        || current.target_height_offset != next.target_height_offset
        || current.ciphertext_size_classes != next.ciphertext_size_classes
    {
        return Err(EtdagError::Governance(
            "frozen ETDAG parameter change requires protocol upgrade".into(),
        ));
    }
    Ok(())
}
