//! Canonical existing Canary gateway admission wire and signing transcript.
use serde::{Deserialize, Serialize};
use synergy_address_engine::{
    apqe::{HashAlgorithm, Primitives},
    canonical_json::to_canonical_json,
};
pub(crate) const PROTOCOL: &str = "synergy-rpc/1.0";
const DOMAIN: &[u8] = b"SYNERGY/CANARY-RPC-GATEWAY-ADMISSION/v1";
pub(crate) const SIGN_CONTEXT: &[u8] = b"SYNERGY.CANARY.RPC.GATEWAY.ADMISSION.V1";
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GatewayEntry {
    pub node_address: String,
    pub role: String,
    pub transport_key_id: String,
    pub transport_key_version: u64,
    pub transport_public_key: Vec<u8>,
    pub enrollment_sha256: String,
    pub revoked: bool,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AdmissionPayload {
    pub schema_version: u16,
    pub scope: String,
    pub protocol: String,
    pub chain_id: u64,
    pub network_id: String,
    pub genesis_artifact_sha256: String,
    pub authority_binding_sha256: String,
    pub validator_registry_sha256: String,
    pub epoch: u64,
    pub generation: u64,
    pub valid_from_unix: u64,
    pub expires_at_unix: u64,
    pub gateways: Vec<GatewayEntry>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SignedAdmission {
    pub payload: AdmissionPayload,
    pub signature: Vec<u8>,
}
pub(crate) fn signing_bytes(payload: &AdmissionPayload) -> Result<Vec<u8>, String> {
    let bytes = to_canonical_json(&serde_json::to_value(payload).map_err(|e| e.to_string())?)?;
    let mut hash = Primitives
        .hash_stream(HashAlgorithm::Sha3512)
        .map_err(|e| e.to_string())?;
    hash.update(DOMAIN);
    hash.update(&bytes);
    Ok(hash.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn gateway_admission_existing_transcript_golden() {
        // Frozen pre-extraction domain+canonical-json SHA3-512 transcript.
        let raw = r#"{"authority_binding_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","chain_id":99999,"epoch":1,"expires_at_unix":1700003600,"gateways":[{"enrollment_sha256":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","node_address":"synv5fixture","revoked":false,"role":"rpc_gateway","transport_key_id":"fixture:rpc-transport:1","transport_key_version":1,"transport_public_key":[1,2,3]}],"generation":2,"genesis_artifact_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","network_id":"gateway-wire-fixture","protocol":"synergy-rpc/1.0","schema_version":1,"scope":"isolated-development-canary","valid_from_unix":1700000000,"validator_registry_sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}"#;
        let payload: AdmissionPayload = serde_json::from_str(raw).unwrap();
        let actual = signing_bytes(&payload)
            .unwrap()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        assert_eq!(actual,"1a48f0c200bdb7482f75f9b63119299eee5f73eaa2a0754540525e72bc2f267d2247318e4bd6a74d87e759d3d6e57150de72705bfeee029cb7253c60bc48e4c9");
        assert_eq!(SIGN_CONTEXT, b"SYNERGY.CANARY.RPC.GATEWAY.ADMISSION.V1");
    }
}
