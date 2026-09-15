use crate::{AddressMapping, MappingAuthorizationVerifier, UmaRegistry};

pub struct UmaCoordinator<V> {
    registry: UmaRegistry,
    verifier: V,
}

impl<V: MappingAuthorizationVerifier> UmaCoordinator<V> {
    pub fn new(verifier: V) -> Self {
        Self {
            registry: UmaRegistry::default(),
            verifier,
        }
    }

    pub fn apply(&mut self, mapping: AddressMapping) -> Result<(), String> {
        self.registry.apply(&self.verifier, mapping)
    }

    pub fn registry(&self) -> &UmaRegistry {
        &self.registry
    }
}
