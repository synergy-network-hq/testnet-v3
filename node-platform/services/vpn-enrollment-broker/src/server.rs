use crate::{
    authorization::EnrollmentAuthorization, chain_verifier::ChainAuthorityVerifier,
    challenge::EnrollmentChallenge, one_time_key::OneTimeEnrollmentKey, peer_binding::PeerBinding,
    providers::NetbirdProvider,
};
pub fn enroll(
    authorization: &EnrollmentAuthorization,
    challenge: &mut EnrollmentChallenge,
    proof: &[u8],
    material: String,
    now: u64,
    verifier: &dyn ChainAuthorityVerifier,
    provider: &dyn NetbirdProvider,
) -> Result<PeerBinding, String> {
    authorization.validate(now)?;
    challenge.validate(now)?;
    verifier.verify_finalized_authorization(authorization, challenge, proof)?;
    let key = OneTimeEnrollmentKey::new(material)?;
    // Authenticate and validate local inputs before irreversible consumption.
    // Once the provider is called, an uncertain outcome must remain consumed.
    challenge.consume(now)?;
    let enrolled = provider.enroll(key)?;
    let binding = PeerBinding {
        node_address: authorization.node_address.clone(),
        netbird_peer_id: enrolled.peer_id,
        overlay_address: enrolled.overlay_address,
    };
    binding.validate()?;
    Ok(binding)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::NetbirdEnrollment;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    #[derive(Default)]
    struct FixtureVerifier {
        calls: AtomicUsize,
        observed_used: AtomicBool,
    }

    impl ChainAuthorityVerifier for FixtureVerifier {
        fn verify_finalized_authorization(
            &self,
            _: &EnrollmentAuthorization,
            challenge: &EnrollmentChallenge,
            proof: &[u8],
        ) -> Result<(), String> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.observed_used.store(challenge.used, Ordering::SeqCst);
            if proof == b"isolated-verification-fixture" {
                Ok(())
            } else {
                Err("fixture proof rejected".into())
            }
        }
    }

    #[derive(Default)]
    struct FixtureProvider {
        calls: AtomicUsize,
        outcome_unknown: bool,
    }

    impl NetbirdProvider for FixtureProvider {
        fn enroll(&self, _: OneTimeEnrollmentKey) -> Result<NetbirdEnrollment, String> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.outcome_unknown {
                Err("fixture provider outcome unknown".into())
            } else {
                Ok(NetbirdEnrollment {
                    peer_id: "isolated-peer-fixture".into(),
                    overlay_address: "isolated-overlay-fixture".into(),
                })
            }
        }

        fn revoke(&self, _: &str) -> Result<(), String> {
            Err("not used by this fixture".into())
        }
    }

    fn inputs() -> (EnrollmentAuthorization, EnrollmentChallenge) {
        (
            EnrollmentAuthorization {
                id: "isolated-authorization-fixture".into(),
                node_address: "isolated-node-fixture".into(),
                role: "sentry".into(),
                expires_at: 100,
                revoked: false,
            },
            EnrollmentChallenge {
                id: "isolated-challenge-fixture".into(),
                nonce: vec![1; 32],
                expires_at: 100,
                used: false,
            },
        )
    }

    // These tests exercise the existing callback/provider ordering only. They do
    // not simulate qualified cryptography, issue credentials, or contact hosts.
    #[test]
    fn invalid_proof_cannot_burn_challenge_or_reach_provider() {
        let (authorization, mut challenge) = inputs();
        let verifier = FixtureVerifier::default();
        let provider = FixtureProvider::default();
        assert!(enroll(
            &authorization,
            &mut challenge,
            b"invalid",
            "isolated-material-fixture".into(),
            1,
            &verifier,
            &provider
        )
        .is_err());
        assert!(!challenge.used);
        assert_eq!(provider.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn expired_challenge_rejects_before_verification_or_provider() {
        let (authorization, mut challenge) = inputs();
        challenge.expires_at = 1;
        let verifier = FixtureVerifier::default();
        let provider = FixtureProvider::default();
        assert!(enroll(
            &authorization,
            &mut challenge,
            b"isolated-verification-fixture",
            "isolated-material-fixture".into(),
            1,
            &verifier,
            &provider
        )
        .is_err());
        assert!(!challenge.used);
        assert_eq!(verifier.calls.load(Ordering::SeqCst), 0);
        assert_eq!(provider.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn empty_material_cannot_burn_verified_challenge() {
        let (authorization, mut challenge) = inputs();
        let verifier = FixtureVerifier::default();
        let provider = FixtureProvider::default();
        assert!(enroll(
            &authorization,
            &mut challenge,
            b"isolated-verification-fixture",
            String::new(),
            1,
            &verifier,
            &provider
        )
        .is_err());
        assert!(!challenge.used);
        assert_eq!(provider.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn valid_proof_is_verified_before_challenge_consumption() {
        let (authorization, mut challenge) = inputs();
        let verifier = FixtureVerifier::default();
        let provider = FixtureProvider::default();
        enroll(
            &authorization,
            &mut challenge,
            b"isolated-verification-fixture",
            "isolated-material-fixture".into(),
            1,
            &verifier,
            &provider,
        )
        .unwrap();
        assert!(!verifier.observed_used.load(Ordering::SeqCst));
        assert!(challenge.used);
        assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn replay_cannot_reverify_or_issue_twice() {
        let (authorization, mut challenge) = inputs();
        let verifier = FixtureVerifier::default();
        let provider = FixtureProvider::default();
        enroll(
            &authorization,
            &mut challenge,
            b"isolated-verification-fixture",
            "isolated-material-fixture".into(),
            1,
            &verifier,
            &provider,
        )
        .unwrap();
        assert!(enroll(
            &authorization,
            &mut challenge,
            b"isolated-verification-fixture",
            "isolated-material-fixture".into(),
            2,
            &verifier,
            &provider
        )
        .is_err());
        assert_eq!(verifier.calls.load(Ordering::SeqCst), 1);
        assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn uncertain_provider_failure_keeps_challenge_consumed() {
        let (authorization, mut challenge) = inputs();
        let verifier = FixtureVerifier::default();
        let provider = FixtureProvider {
            outcome_unknown: true,
            ..FixtureProvider::default()
        };
        assert!(enroll(
            &authorization,
            &mut challenge,
            b"isolated-verification-fixture",
            "isolated-material-fixture".into(),
            1,
            &verifier,
            &provider
        )
        .is_err());
        assert!(challenge.used);
        assert!(enroll(
            &authorization,
            &mut challenge,
            b"isolated-verification-fixture",
            "isolated-material-fixture".into(),
            2,
            &verifier,
            &provider
        )
        .is_err());
        assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
    }
}
