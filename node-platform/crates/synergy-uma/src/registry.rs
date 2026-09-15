use std::collections::BTreeMap;

use crate::{AddressMapping, AddressNamespace, MappingAuthorizationVerifier, UmaAddress};

#[derive(Default)]
pub struct UmaRegistry {
    mappings: BTreeMap<(UmaAddress, AddressNamespace), AddressMapping>,
}

impl UmaRegistry {
    pub fn apply(
        &mut self,
        verifier: &impl MappingAuthorizationVerifier,
        mapping: AddressMapping,
    ) -> Result<(), String> {
        crate::verify_mapping(verifier, &mapping)?;
        let key = (mapping.uma.clone(), mapping.namespace);
        if let Some(current) = self.mappings.get(&key) {
            if mapping.revision != current.revision.saturating_add(1) {
                return Err("UMA mapping revision is not sequential".into());
            }
        } else if mapping.revision != 0 {
            return Err("initial UMA mapping revision must be zero".into());
        }
        self.mappings.insert(key, mapping);
        Ok(())
    }

    pub fn resolve(
        &self,
        address: &UmaAddress,
        namespace: AddressNamespace,
    ) -> Option<&AddressMapping> {
        self.mappings.get(&(address.clone(), namespace))
    }
}
