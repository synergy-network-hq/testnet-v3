use crate::{
    RelayReceipt, SynergyFinalityAnchor, VaultKeyReference, VaultProvider, VerifiedExternalTransfer,
};

pub trait RelayDestination {
    fn chain(&self) -> crate::ExternalChain;
    fn submit(
        &mut self,
        transfer: &VerifiedExternalTransfer,
        authorization: &[u8],
    ) -> Result<String, String>;
}

pub fn relay_verified_transfer(
    transfer: &VerifiedExternalTransfer,
    finality: SynergyFinalityAnchor,
    key: &VaultKeyReference,
    vault: &impl VaultProvider,
    destination: &mut impl RelayDestination,
) -> Result<RelayReceipt, String> {
    transfer.transfer.validate_shape()?;
    finality.validate()?;
    key.validate()?;
    let transcript = serde_json::to_vec(&(transfer, &finality))
        .map_err(|error| format!("serialize SXCP relay transcript: {error}"))?;
    let authorization = vault.authorize_relay(key, &transcript)?;
    let destination_transaction = destination.submit(transfer, &authorization)?;
    if destination_transaction.trim().is_empty() {
        return Err("SXCP destination returned an empty transaction reference".into());
    }
    Ok(RelayReceipt {
        transfer_id: transfer.transfer.transfer_id.clone(),
        destination_chain: destination.chain(),
        destination_transaction,
        synergy_finality: finality,
        authorization,
    })
}
