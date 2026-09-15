#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdapterError {
    WrongProtocol,
    EmptyPayload,
    Consumer(String),
}

impl std::fmt::Display for AdapterError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for AdapterError {}
