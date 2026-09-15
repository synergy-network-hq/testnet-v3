use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PosyError {
    Invalid(String),
    UnknownValidator(String),
    Signature(String),
    Quorum(QuorumError),
    Conflict(String),
    NotReady(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuorumError {
    InsufficientDistinct { signed: usize, total: usize },
    InsufficientWeight { signed: u128, total: u128 },
    DuplicateSigner(String),
}

impl PosyError {
    pub fn invalid(message: impl Into<String>) -> Self {
        Self::Invalid(message.into())
    }
}

impl fmt::Display for PosyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(message)
            | Self::UnknownValidator(message)
            | Self::Signature(message)
            | Self::Conflict(message)
            | Self::NotReady(message) => formatter.write_str(message),
            Self::Quorum(error) => write!(formatter, "quorum error: {error:?}"),
        }
    }
}

impl std::error::Error for PosyError {}
