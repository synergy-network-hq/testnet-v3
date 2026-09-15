use serde::Serialize;

use crate::sign::SignedManifest;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ManifestInspection {
    pub manifest_hash: String,
    pub chain_id: u64,
    pub network_id: String,
    pub genesis_hash: String,
    pub release_version: String,
    pub protocol_components: usize,
    pub schema_domains: usize,
    pub validators_root: String,
    pub bootseed_count: usize,
    pub signer_key_id: String,
    pub signature_algorithm: String,
}

pub fn inspect(signed: &SignedManifest) -> Result<ManifestInspection, String> {
    signed.unsigned.validate()?;
    if signed.manifest_hash != signed.unsigned.manifest_hash()? {
        return Err("manifest hash does not match the unsigned body".into());
    }
    Ok(ManifestInspection {
        manifest_hash: signed.manifest_hash.clone(),
        chain_id: signed.unsigned.chain_id,
        network_id: signed.unsigned.network_id.clone(),
        genesis_hash: signed.unsigned.genesis_hash.clone(),
        release_version: signed.unsigned.release_version.clone(),
        protocol_components: signed.unsigned.protocol_versions.len(),
        schema_domains: signed.unsigned.schema_versions.len(),
        validators_root: signed.unsigned.validator_set_root.clone(),
        bootseed_count: signed.unsigned.bootseeds.len(),
        signer_key_id: signed.signer_key_id.clone(),
        signature_algorithm: format!("{:?}", signed.signature_algorithm),
    })
}
