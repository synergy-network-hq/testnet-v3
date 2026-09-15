use std::collections::BTreeSet;

use crate::{
    crypto::{canonical_signing_bytes, SignatureVerifier},
    AuthenticatedEtdagMessage, EtdagError, EtdagNetworkMessage,
};

pub trait EtdagNetworkHandler {
    fn handle(&mut self, message: EtdagNetworkMessage) -> Result<(), EtdagError>;
}

pub trait AuthenticatedEtdagHandler {
    fn handle_authenticated(
        &mut self,
        message: AuthenticatedEtdagMessage,
    ) -> Result<(), EtdagError>;
}

pub fn verify_network_message(
    message: &AuthenticatedEtdagMessage,
    authorized_senders: &BTreeSet<String>,
    verifier: &impl SignatureVerifier,
) -> Result<(), EtdagError> {
    message.validate_shape()?;
    if !authorized_senders.contains(&message.sender_id) {
        return Err(EtdagError::UnauthorizedValidator(message.sender_id.clone()));
    }
    let signing_bytes = canonical_signing_bytes(
        "SYNERGY_ETDAG_NETWORK_MESSAGE_SIGNATURE_V1",
        &(
            message.message_version,
            &message.message_id,
            &message.sender_id,
            &message.key_id,
            &message.message,
        ),
    )?;
    verifier.verify(
        &message.sender_id,
        &message.key_id,
        &signing_bytes,
        &message.signature,
    )
}
