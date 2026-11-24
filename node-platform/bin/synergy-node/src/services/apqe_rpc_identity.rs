//! Read-only verification of the retained Gateway identity at its exact
//! managed paths. This cannot provision, rewrite or export any custody.
use super::{apqe_rpc, transport, TargetEnrollment};
use serde_json::{json, Value};
use std::path::Path;
use synergy_address_engine::{
    apqe::gateway_transport::GatewayEnrollment, encrypt::EncryptedEnvelope,
};

pub(super) fn inspect(q: TargetEnrollment) -> Result<Value, String> {
    let config = &q.node_configuration;
    let genesis = config
        .genesis_path
        .as_ref()
        .ok_or("managed Gateway Genesis absent")?;
    let root = genesis
        .parent()
        .and_then(Path::parent)
        .ok_or("managed Gateway root absent")?;
    let keys = root.join("keys/apqe");
    if !root.is_absolute()
        || genesis != &root.join("network/genesis.json")
        || config.storage.data_directory != root.join("data")
        || root.canonicalize().map_err(|e| e.to_string())? != root
        || keys.canonicalize().map_err(|e| e.to_string())? != keys
    {
        return Err(
            "identity custody inspection requires the original canonical managed Gateway root"
                .into(),
        );
    }
    let scope = apqe_rpc::inspect_gateway_origin(config)?;
    let enrollment_path = keys.join("gateway-enrollment.json");
    let identity_path = keys.join("gateway-identity.encrypted.json");
    let unlock_path = keys.join("gateway-identity.unlock");
    let stamps = [
        transport::Stamp::capture(&enrollment_path)?,
        transport::Stamp::capture(&identity_path)?,
        transport::Stamp::capture(&unlock_path)?,
    ];
    let original = transport::read(&enrollment_path, 128 * 1024, false)?;
    if original != q.enrollment_json.as_bytes() {
        return Err("reviewed Gateway enrollment differs from retained custody scope".into());
    }
    let enrollment: GatewayEnrollment =
        serde_json::from_slice(&original).map_err(|_| "invalid retained Gateway enrollment")?;
    if Some(enrollment.payload.chain_id.to_string().as_str()) != scope["chain_id"].as_str()
        || Some(enrollment.payload.network_id.as_str()) != scope["network_id"].as_str()
        || Some(enrollment.payload.genesis_artifact_sha256.as_str())
            != scope["genesis_sha256"].as_str()
    {
        return Err("Gateway identity custody belongs to a different signed origin".into());
    }
    let encrypted: EncryptedEnvelope =
        serde_json::from_slice(&transport::read(&identity_path, 256 * 1024, true)?)
            .map_err(|_| "invalid retained Gateway identity envelope")?;
    let unlock = apqe_rpc::unlock(&unlock_path)?;
    let engine = crate::services::apqe_provider::load(config)?;
    let engine = engine
        .try_lock()
        .map_err(|_| "Gateway native provider unavailable")?;
    enrollment.verify_identity_custody(&engine, &encrypted, apqe_rpc::passphrase(&unlock)?)?;
    if !stamps.iter().all(transport::Stamp::unchanged) {
        return Err("Gateway custody changed during native inspection".into());
    }
    Ok(
        json!({"gateway_address":enrollment.payload.node_address,"enrollment_sha256":transport::sha256(&original),
        "identity_custody_verified":true,"mutation_performed":false}),
    )
}
