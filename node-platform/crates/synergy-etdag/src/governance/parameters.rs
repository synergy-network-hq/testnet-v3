use crate::{EtdagError, EtdagParameters};

pub fn validate_governed_parameters(parameters: &EtdagParameters) -> Result<(), EtdagError> {
    parameters.validate()
}
