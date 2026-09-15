use std::collections::BTreeMap;

use synergy_protocol_types::ProtocolKind;

use super::{protocol_id, ProtocolVersion};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtocolRegistration {
    pub kind: ProtocolKind,
    pub version: ProtocolVersion,
    pub max_payload_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolRegistryError {
    InvalidVersion,
    InvalidPayloadLimit,
    DuplicateProtocol(u8),
    UnknownProtocol(u8),
}

#[derive(Debug, Clone, Default)]
pub struct ProtocolRegistry {
    registrations: BTreeMap<u8, ProtocolRegistration>,
}

impl ProtocolRegistry {
    pub fn register(
        &mut self,
        registration: ProtocolRegistration,
    ) -> Result<(), ProtocolRegistryError> {
        if registration.version.major == 0 {
            return Err(ProtocolRegistryError::InvalidVersion);
        }
        if registration.max_payload_bytes == 0 || registration.max_payload_bytes > u32::MAX as usize
        {
            return Err(ProtocolRegistryError::InvalidPayloadLimit);
        }
        let id = protocol_id(registration.kind);
        if self.registrations.insert(id, registration).is_some() {
            return Err(ProtocolRegistryError::DuplicateProtocol(id));
        }
        Ok(())
    }

    pub fn get(&self, id: u8) -> Result<&ProtocolRegistration, ProtocolRegistryError> {
        self.registrations
            .get(&id)
            .ok_or(ProtocolRegistryError::UnknownProtocol(id))
    }

    pub fn supports(&self, kind: ProtocolKind) -> bool {
        self.registrations.contains_key(&protocol_id(kind))
    }
}
