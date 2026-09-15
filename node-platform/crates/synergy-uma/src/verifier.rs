use crate::AddressMapping;

pub trait MappingAuthorizationVerifier {
    fn verify_mapping(&self, mapping: &AddressMapping) -> Result<(), String>;
}

pub fn verify_mapping(
    verifier: &impl MappingAuthorizationVerifier,
    mapping: &AddressMapping,
) -> Result<(), String> {
    mapping.validate()?;
    verifier.verify_mapping(mapping)
}
