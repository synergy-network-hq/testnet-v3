use crate::{EtdagError, IngressKemKeyRegistry};

pub fn validate_governed_key_registry(
    registry: &IngressKemKeyRegistry,
    manifest_activation_height: u64,
) -> Result<(), EtdagError> {
    crate::crypto::validate_key_schedule(registry)?;
    if registry
        .records
        .iter()
        .any(|record| record.activation_height < manifest_activation_height)
    {
        return Err(EtdagError::Governance(
            "ingress key predates manifest activation".into(),
        ));
    }
    Ok(())
}
