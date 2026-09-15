use serde::{Deserialize, Serialize};

use crate::TransactionError;

const ACTION_MAGIC: &[u8; 8] = b"SYNACT01";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransactionClass {
    User,
    System,
}

/// Canonical execution intent carried by a transaction. A plain transfer uses
/// an empty payload because its receiver and amount already live in the signed
/// transaction fields. Every richer action uses the versioned binary envelope
/// implemented here; no runtime-specific wire representation is accepted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TransactionAction {
    Transfer,
    Native {
        module: String,
        method: String,
        input: Vec<u8>,
    },
    Synq {
        artifact: Vec<u8>,
        input: Vec<u8>,
    },
    Sxcp {
        destination: String,
        message: Vec<u8>,
    },
    Governance {
        authorization_id: String,
        operation: Vec<u8>,
    },
    System {
        authorization_id: String,
        operation: Vec<u8>,
    },
}

impl TransactionAction {
    pub fn encode(&self) -> Result<Vec<u8>, TransactionError> {
        self.validate()?;
        let mut output = Vec::new();
        output.extend_from_slice(ACTION_MAGIC);
        match self {
            Self::Transfer => output.push(0),
            Self::Native {
                module,
                method,
                input,
            } => {
                output.push(1);
                append(&mut output, module.as_bytes())?;
                append(&mut output, method.as_bytes())?;
                append(&mut output, input)?;
            }
            Self::Synq { artifact, input } => {
                output.push(2);
                append(&mut output, artifact)?;
                append(&mut output, input)?;
            }
            Self::Sxcp {
                destination,
                message,
            } => {
                output.push(3);
                append(&mut output, destination.as_bytes())?;
                append(&mut output, message)?;
            }
            Self::Governance {
                authorization_id,
                operation,
            } => {
                output.push(4);
                append(&mut output, authorization_id.as_bytes())?;
                append(&mut output, operation)?;
            }
            Self::System {
                authorization_id,
                operation,
            } => {
                output.push(5);
                append(&mut output, authorization_id.as_bytes())?;
                append(&mut output, operation)?;
            }
        }
        Ok(output)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, TransactionError> {
        if bytes.is_empty() {
            return Ok(Self::Transfer);
        }
        if bytes.len() < ACTION_MAGIC.len() + 1 || &bytes[..ACTION_MAGIC.len()] != ACTION_MAGIC {
            return Err(TransactionError::InvalidPayload);
        }
        let tag = bytes[ACTION_MAGIC.len()];
        let mut cursor = ACTION_MAGIC.len() + 1;
        let action = match tag {
            0 => Self::Transfer,
            1 => Self::Native {
                module: read_string(bytes, &mut cursor)?,
                method: read_string(bytes, &mut cursor)?,
                input: read(bytes, &mut cursor)?,
            },
            2 => Self::Synq {
                artifact: read(bytes, &mut cursor)?,
                input: read(bytes, &mut cursor)?,
            },
            3 => Self::Sxcp {
                destination: read_string(bytes, &mut cursor)?,
                message: read(bytes, &mut cursor)?,
            },
            4 => Self::Governance {
                authorization_id: read_string(bytes, &mut cursor)?,
                operation: read(bytes, &mut cursor)?,
            },
            5 => Self::System {
                authorization_id: read_string(bytes, &mut cursor)?,
                operation: read(bytes, &mut cursor)?,
            },
            _ => return Err(TransactionError::InvalidPayload),
        };
        if cursor != bytes.len() {
            return Err(TransactionError::InvalidPayload);
        }
        action.validate()?;
        Ok(action)
    }

    pub fn validate(&self) -> Result<(), TransactionError> {
        let valid = match self {
            Self::Transfer => true,
            Self::Native { module, method, .. } => {
                !module.trim().is_empty() && !method.trim().is_empty()
            }
            Self::Synq { artifact, .. } => !artifact.is_empty(),
            Self::Sxcp {
                destination,
                message,
            } => !destination.trim().is_empty() && !message.is_empty(),
            Self::Governance {
                authorization_id,
                operation,
            }
            | Self::System {
                authorization_id,
                operation,
            } => !authorization_id.trim().is_empty() && !operation.is_empty(),
        };
        valid.then_some(()).ok_or(TransactionError::InvalidPayload)
    }

    pub const fn requires_system_authority(&self) -> bool {
        matches!(self, Self::Governance { .. } | Self::System { .. })
    }
}

impl TransactionClass {
    pub const fn may_determine_finality(self) -> bool {
        false
    }
}

fn append(output: &mut Vec<u8>, value: &[u8]) -> Result<(), TransactionError> {
    let len = u32::try_from(value.len()).map_err(|_| TransactionError::PayloadTooLarge)?;
    output.extend_from_slice(&len.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

fn read(bytes: &[u8], cursor: &mut usize) -> Result<Vec<u8>, TransactionError> {
    let end_len = cursor
        .checked_add(4)
        .ok_or(TransactionError::InvalidPayload)?;
    let encoded_len: [u8; 4] = bytes
        .get(*cursor..end_len)
        .ok_or(TransactionError::InvalidPayload)?
        .try_into()
        .map_err(|_| TransactionError::InvalidPayload)?;
    *cursor = end_len;
    let len = u32::from_be_bytes(encoded_len) as usize;
    let end = cursor
        .checked_add(len)
        .ok_or(TransactionError::InvalidPayload)?;
    let value = bytes
        .get(*cursor..end)
        .ok_or(TransactionError::InvalidPayload)?
        .to_vec();
    *cursor = end;
    Ok(value)
}

fn read_string(bytes: &[u8], cursor: &mut usize) -> Result<String, TransactionError> {
    String::from_utf8(read(bytes, cursor)?).map_err(|_| TransactionError::InvalidPayload)
}
