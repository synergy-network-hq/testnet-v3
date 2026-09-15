#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandshakeRejection {
    Malformed,
    ExpiredChallenge,
    Replay,
    IdentityMismatch,
    IncompatibleChain,
    IncompatibleProtocol,
    UnsupportedKeyAlgorithm,
    InvalidSignature,
    ConnectionLimit,
    Policy(String),
}
