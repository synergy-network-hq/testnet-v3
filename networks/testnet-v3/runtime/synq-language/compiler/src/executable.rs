use crate::ast::SourceUnit;
use serde::{Deserialize, Serialize};

pub const STATEFUL_SYNQ_EXECUTABLE_MAGIC: &[u8; 8] = b"SYNQIR2\0";
pub const STATEFUL_SYNQ_EXECUTABLE_VERSION: u16 = 2;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StatefulSynQExecutable {
    pub version: u16,
    pub source_units: Vec<SourceUnit>,
    pub legacy_quantum_vm_bytecode: Vec<u8>,
}

impl StatefulSynQExecutable {
    pub fn new(source_units: Vec<SourceUnit>, legacy_quantum_vm_bytecode: Vec<u8>) -> Self {
        Self {
            version: STATEFUL_SYNQ_EXECUTABLE_VERSION,
            source_units,
            legacy_quantum_vm_bytecode,
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, String> {
        let payload = serde_json::to_vec(self)
            .map_err(|error| format!("serialize stateful SynQ executable: {error}"))?;
        let payload_len = u32::try_from(payload.len())
            .map_err(|_| "stateful SynQ executable exceeds u32 payload length".to_string())?;
        let mut output =
            Vec::with_capacity(STATEFUL_SYNQ_EXECUTABLE_MAGIC.len() + 4 + payload.len());
        output.extend_from_slice(STATEFUL_SYNQ_EXECUTABLE_MAGIC);
        output.extend_from_slice(&payload_len.to_be_bytes());
        output.extend_from_slice(&payload);
        Ok(output)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < STATEFUL_SYNQ_EXECUTABLE_MAGIC.len() + 4
            || &bytes[..STATEFUL_SYNQ_EXECUTABLE_MAGIC.len()] != STATEFUL_SYNQ_EXECUTABLE_MAGIC
        {
            return Err("stateful SynQ executable magic is missing".to_string());
        }
        let length_offset = STATEFUL_SYNQ_EXECUTABLE_MAGIC.len();
        let payload_len = u32::from_be_bytes(
            bytes[length_offset..length_offset + 4]
                .try_into()
                .map_err(|_| "stateful SynQ length field is malformed".to_string())?,
        ) as usize;
        let payload = bytes
            .get(length_offset + 4..)
            .ok_or_else(|| "stateful SynQ payload is truncated".to_string())?;
        if payload.len() != payload_len {
            return Err(format!(
                "stateful SynQ payload length mismatch: declared {payload_len}, found {}",
                payload.len()
            ));
        }
        let executable: Self = serde_json::from_slice(payload)
            .map_err(|error| format!("decode stateful SynQ executable: {error}"))?;
        if executable.version != STATEFUL_SYNQ_EXECUTABLE_VERSION {
            return Err(format!(
                "unsupported stateful SynQ executable version {}",
                executable.version
            ));
        }
        Ok(executable)
    }

    pub fn is_stateful(bytes: &[u8]) -> bool {
        bytes.starts_with(STATEFUL_SYNQ_EXECUTABLE_MAGIC)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn executable_round_trip_is_byte_stable() {
        let executable = StatefulSynQExecutable::new(Vec::new(), vec![1, 2, 3]);
        let encoded = executable.encode().unwrap();
        assert_eq!(
            StatefulSynQExecutable::decode(&encoded).unwrap(),
            executable
        );
        assert_eq!(
            StatefulSynQExecutable::decode(&encoded)
                .unwrap()
                .encode()
                .unwrap(),
            encoded
        );
    }
}
