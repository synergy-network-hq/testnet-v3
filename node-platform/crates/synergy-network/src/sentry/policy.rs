use synergy_protocol_types::ProtocolKind;

/// Explicitly documents the Sentry trust boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SentryCapabilities {
    pub may_transport_posy: bool,
    pub owns_posy_engine: bool,
    pub may_sign_posy: bool,
    pub may_determine_finality: bool,
}
impl Default for SentryCapabilities {
    fn default() -> Self {
        Self {
            may_transport_posy: true,
            owns_posy_engine: false,
            may_sign_posy: false,
            may_determine_finality: false,
        }
    }
}
impl SentryCapabilities {
    pub fn allows(&self, protocol: ProtocolKind) -> bool {
        matches!(
            protocol,
            ProtocolKind::Status
                | ProtocolKind::Discovery
                | ProtocolKind::Sync
                | ProtocolKind::Posy
                | ProtocolKind::Etdag
                | ProtocolKind::Transaction
        )
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sentry_has_transport_but_no_consensus_authority() {
        let c = SentryCapabilities::default();
        assert!(c.may_transport_posy);
        assert!(!c.owns_posy_engine);
        assert!(!c.may_sign_posy);
        assert!(!c.may_determine_finality);
        assert!(c.allows(ProtocolKind::Posy));
        assert!(!c.allows(ProtocolKind::Snapshot));
    }
}
