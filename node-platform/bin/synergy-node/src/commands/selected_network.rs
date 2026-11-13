//! Read-only authentication of the operator-selected network before CLI startup.
use std::path::Path;

use synergy_config::NodeConfiguration;
use synergy_genesis::{authority::SignedAuthorityBinding, signing::SignedGenesis};
use synergy_manifest::NetworkManifest;

fn read(path: &Path, maximum: u64) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let metadata = std::fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !path.is_absolute()
        || !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() == 0
        || metadata.len() > maximum
    {
        return Err("selected network input must be a bounded absolute regular file".into());
    }
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .map_err(|e| e.to_string())?
        .take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.is_empty() || bytes.len() as u64 > maximum {
        return Err("selected network input changed size".into());
    }
    Ok(bytes)
}

/// Trust comes from the configured public key, never from the candidate Genesis.
/// No private keys, database, listeners or services are opened here.
pub(crate) fn verify(configuration: &NodeConfiguration) -> Result<String, String> {
    verify_with_custody_binding(configuration).map(|(hash, _)| hash)
}
pub(crate) fn verify_with_custody_binding(
    configuration: &NodeConfiguration,
) -> Result<
    (
        String,
        synergy_address_engine::validator_provisioning::NetworkBinding,
    ),
    String,
> {
    let genesis_path = configuration
        .genesis_path
        .as_deref()
        .ok_or("selected signed genesis_path is required")?;
    let trust_path = configuration
        .consensus
        .authority_trust_key_path
        .as_deref()
        .ok_or("selected Genesis requires a pinned authority_trust_key_path")?;
    let genesis_bytes = read(genesis_path, 16 * 1024 * 1024)?;
    let genesis: SignedGenesis = serde_json::from_slice(&genesis_bytes)
        .map_err(|e| format!("decode selected signed Genesis: {e}"))?;
    let trust = read(trust_path, 8 * 1024)?;
    let verifier = crate::services::apqe_provider::verifier(
        configuration,
        synergy_aegis::AegisPolicy {
            allowed_algorithms: vec![synergy_aegis::SignatureAlgorithm::MlDsa65],
            maximum_message_bytes: 16 * 1024 * 1024,
            maximum_signature_bytes: 16 * 1024,
        },
    )?;
    synergy_genesis::signing::verify(&genesis, &verifier, &trust)?;
    if genesis.unsigned.format_version != 2 {
        return Err("runtime initialization requires explicit network-neutral Genesis format 2; format 1 is historical verification only".into());
    }
    let network = &genesis.unsigned.network;
    if configuration.chain_id != network.chain_id || configuration.network_id != network.network_id
    {
        return Err("configuration differs from authenticated selected Genesis".into());
    }
    if configuration
        .vpn
        .transport_context
        .as_ref()
        .is_some_and(|context| context.protocol_version != network.protocol_version)
    {
        return Err("transport protocol differs from authenticated selected Genesis".into());
    }
    let manifest: NetworkManifest =
        serde_json::from_slice(&read(&configuration.manifest_path, 1024 * 1024)?)
            .map_err(|e| format!("decode selected network manifest: {e}"))?;
    let expected = NetworkManifest {
        chain_id: network.chain_id,
        network_id: network.network_id.clone(),
        genesis_hash: genesis.genesis_hash.clone(),
        protocol_version: network.protocol_version.clone(),
        manifest_hash: manifest.manifest_hash.clone(),
    };
    manifest
        .validate_against(&expected)
        .map_err(|e| format!("selected manifest mismatch: {e:?}"))?;
    if let Some(path) = configuration.consensus.authority_binding.as_deref() {
        let binding: SignedAuthorityBinding = serde_json::from_slice(&read(path, 1024 * 1024)?)
            .map_err(|e| format!("decode selected authority: {e}"))?;
        // Later epochs are verified by the existing durable transition owner.
        // The initial authority must be exactly the one committed by Genesis.
        if binding.payload.epoch == 1 {
            synergy_genesis::verify_binding_with_verifier(&genesis, &trust, &binding, &verifier)?;
        }
    }
    let digest = synergy_address_engine::apqe::fixed_digest(
        &synergy_address_engine::apqe::Primitives,
        synergy_address_engine::apqe::FixedDigest::Sha256,
        &genesis_bytes,
    );
    let digest = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Ok((
        genesis.genesis_hash,
        synergy_address_engine::validator_provisioning::NetworkBinding {
            chain_id_hex: format!("{:064x}", network.chain_id),
            genesis_sha256: digest,
        },
    ))
}
