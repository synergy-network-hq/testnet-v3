#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransactionError {
    InvalidNetworkBinding,
    InvalidAddress,
    InvalidTimestamp,
    InvalidFeeLimit,
    FeeOverflow,
    InvalidNonceWindow,
    NonceOutOfWindow,
    DuplicateNonce,
    NonceNotReady,
    MissingSignatureMaterial,
    InvalidSignature,
    SignatureVerifier(String),
    InvalidTransactionId,
    InvalidPayload,
    PayloadTooLarge,
    UnauthorizedTransactionClass,
    NonceOverflow,
}

impl std::fmt::Display for TransactionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for TransactionError {}
