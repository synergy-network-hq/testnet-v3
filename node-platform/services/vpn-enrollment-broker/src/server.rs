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
    challenge.consume(now)?;
    verifier.verify_finalized_authorization(authorization, challenge, proof)?;
    let enrolled = provider.enroll(OneTimeEnrollmentKey::new(material)?)?;
    let binding = PeerBinding {
        node_address: authorization.node_address.clone(),
        netbird_peer_id: enrolled.peer_id,
        overlay_address: enrolled.overlay_address,
    };
    binding.validate()?;
    Ok(binding)
}
