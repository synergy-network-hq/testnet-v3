//! No approved authenticated PQ session profile has been selected.
//! Primitive availability and a signed plaintext handshake cannot waive this gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeSessionProfileError {
    UnapprovedPostQuantumSessionProfile,
}
impl std::fmt::Display for NativeSessionProfileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("native session unavailable: an approved role-bound APQE key-establishment, key-confirmation and authenticated-record profile has not been selected")
    }
}
impl std::error::Error for NativeSessionProfileError {}
pub fn require_native_session_profile() -> Result<(), NativeSessionProfileError> {
    Err(NativeSessionProfileError::UnapprovedPostQuantumSessionProfile)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn signed_tcp_or_overlay_cannot_authorize_native_sessions() {
        for _carrier in [
            "tcp+ml-dsa-65",
            "netbird",
            "wireguard",
            "tls",
            "unconfigured",
        ] {
            let mut accessed = false;
            let result = require_native_session_profile().map(|_| {
                accessed = true;
            });
            assert_eq!(
                result,
                Err(NativeSessionProfileError::UnapprovedPostQuantumSessionProfile)
            );
            assert!(!accessed);
        }
    }
}
