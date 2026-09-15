use std::fmt;
use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use crate::{ConfigError, NodeConfiguration};

pub const MAX_CONFIGURATION_BYTES: u64 = 1024 * 1024;

/// Loads one canonical new-platform JSON configuration with a strict size cap.
pub fn load(path: impl AsRef<Path>) -> Result<NodeConfiguration, ConfigLoadError> {
    let path = path.as_ref();
    let file = File::open(path).map_err(|source| ConfigLoadError::Open {
        path: path.to_path_buf(),
        source,
    })?;
    let mut bytes = Vec::new();
    file.take(MAX_CONFIGURATION_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| ConfigLoadError::Read {
            path: path.to_path_buf(),
            source,
        })?;
    if bytes.len() as u64 > MAX_CONFIGURATION_BYTES {
        return Err(ConfigLoadError::TooLarge {
            path: path.to_path_buf(),
            maximum: MAX_CONFIGURATION_BYTES,
        });
    }
    decode(path, &bytes)
}

pub fn decode(path: impl AsRef<Path>, bytes: &[u8]) -> Result<NodeConfiguration, ConfigLoadError> {
    let path = path.as_ref();
    let configuration: NodeConfiguration =
        serde_json::from_slice(bytes).map_err(|source| ConfigLoadError::Decode {
            path: path.to_path_buf(),
            source,
        })?;
    configuration
        .into_validated()
        .map_err(ConfigLoadError::Invalid)
}

#[derive(Debug)]
pub enum ConfigLoadError {
    Open {
        path: PathBuf,
        source: io::Error,
    },
    Read {
        path: PathBuf,
        source: io::Error,
    },
    TooLarge {
        path: PathBuf,
        maximum: u64,
    },
    Decode {
        path: PathBuf,
        source: serde_json::Error,
    },
    Invalid(ConfigError),
}

impl fmt::Display for ConfigLoadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Open { path, source } => {
                write!(formatter, "open configuration {}: {source}", path.display())
            }
            Self::Read { path, source } => {
                write!(formatter, "read configuration {}: {source}", path.display())
            }
            Self::TooLarge { path, maximum } => write!(
                formatter,
                "configuration {} exceeds the {maximum}-byte limit",
                path.display()
            ),
            Self::Decode { path, source } => write!(
                formatter,
                "decode canonical JSON configuration {}: {source}",
                path.display()
            ),
            Self::Invalid(source) => write!(formatter, "invalid configuration: {source}"),
        }
    }
}

impl std::error::Error for ConfigLoadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Open { source, .. } | Self::Read { source, .. } => Some(source),
            Self::Decode { source, .. } => Some(source),
            Self::Invalid(source) => Some(source),
            Self::TooLarge { .. } => None,
        }
    }
}
