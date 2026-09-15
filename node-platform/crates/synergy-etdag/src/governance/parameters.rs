use crate::{EtdagError, EtdagParameters, MIN_TARGET_HEIGHT_OFFSET};

pub fn validate_governed_parameters(parameters: &EtdagParameters) -> Result<(), EtdagError> {
    parameters.validate()?;
    if parameters.target_height_offset != MIN_TARGET_HEIGHT_OFFSET {
        return Err(EtdagError::InvalidTargetOffset);
    }
    Ok(())
}
