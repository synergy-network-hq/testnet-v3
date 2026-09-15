use synergy_transaction::TransactionError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockError {
    Transaction(TransactionError),
    InvalidHeader,
    InvalidCommitment,
    InvalidReceipt,
    DuplicateTransaction,
    TransactionRootMismatch,
    MissingProposerSignature,
    ParentMismatch,
    HeightMismatch,
    ReceiptCountMismatch,
    ReceiptRootMismatch,
    NetworkMismatch,
    TimestampRegression,
    InvalidSignature,
    SignatureVerifier(String),
    InvalidCodecLimit,
    UnsupportedFormat,
    BlockTooLarge { actual: usize, maximum: usize },
    Encoding(String),
}

pub trait BlockSignatureVerifier {
    type Error: std::fmt::Display;

    fn verify(
        &self,
        commitment: &[u8],
        proposer_public_key: &[u8],
        signature: &[u8],
        signature_algorithm: &str,
    ) -> Result<bool, Self::Error>;
}

impl std::fmt::Display for BlockError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for BlockError {}
