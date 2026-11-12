//! Disabled-by-default engineering RPC transport. Gateway admission never grants
//! PoSy membership, voting weight, ingress custody or validator protocol access.
use super::{
    apqe_transport::{self as transport, Snapshot, Stamp, TransportEntry},
    authority,
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, path::Path, sync::Arc};
use synergy_address_engine::{
    apqe::{
        crypto_engine::CryptoEngine,
        engineering_transport::{CurrentTransportTrust, SessionContext, SessionError},
        gateway_transport::{self, GatewayEnrollment},
        provider::{variants::Mldsa65, PublicKey, SignOptions},
        HashAlgorithm, Primitives, SecretBytes,
    },
    canonical_json::to_canonical_json,
    encrypt::{decrypt_with_passphrase, EncryptedEnvelope},
    types::Algorithm,
};
use synergy_config::NodeConfiguration;
use synergy_protocol_types::{NodeAddress, NodeClass};

pub(crate) const PROTOCOL: &str = "synergy-rpc/1.0";
const DOMAIN: &[u8] = b"SYNERGY/CANARY-RPC-GATEWAY-ADMISSION/v1";
const SIGN_CONTEXT: &[u8] = b"SYNERGY.CANARY.RPC.GATEWAY.ADMISSION.V1";
pub(crate) const MAX_BODY: usize = 1_000_000;
const HEADER: usize = 22;
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
fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn valid_gateway_address(value: &str) -> bool {
    NodeAddress::parse(value).is_ok_and(|address| address.class() == NodeClass::ServiceAndAccess)
}
fn validate_binding(
    p: &AdmissionPayload,
    base: &Snapshot,
    authority_sha: &str,
    consensus_keys: &[Vec<u8>],
    now: u64,
) -> Result<(), String> {
    if p.schema_version != 1
        || p.scope != "isolated-development-canary"
        || p.protocol != PROTOCOL
        || p.chain_id != 99999
        || p.chain_id != base.payload.chain_id
        || p.network_id != base.payload.network_id
        || p.genesis_artifact_sha256 != base.network.genesis_sha256
        || p.authority_binding_sha256 != authority_sha
        || p.validator_registry_sha256 != transport::sha256(&base.registry_bytes)
        || p.epoch != base.payload.epoch
        || p.generation != base.payload.generation
        || p.valid_from_unix > now
        || p.expires_at_unix <= now
        || p.expires_at_unix <= p.valid_from_unix
        || p.expires_at_unix > base.payload.expires_at_unix
        || p.gateways.is_empty()
        || p.gateways.len() > 16
    {
        return Err("RPC gateway admission differs from authenticated current canary".into());
    }
    let mut ids = BTreeSet::new();
    let mut keys = BTreeSet::new();
    let mut names = BTreeSet::new();
    for g in &p.gateways {
        if !valid_gateway_address(&g.node_address)
            || g.role != "rpc_gateway"
            || !transport::ascii(&g.transport_key_id, 128)
            || g.transport_key_version == 0
            || g.transport_public_key.len() != 1952
            || !digest(&g.enrollment_sha256)
            || !ids.insert(&g.node_address)
            || !keys.insert(&g.transport_public_key)
            || !names.insert(&g.transport_key_id)
            || base.entries.iter().any(|v| {
                v.node_address == g.node_address
                    || v.transport_key_id == g.transport_key_id
                    || v.transport_public_key == g.transport_public_key
            })
            || consensus_keys.contains(&g.transport_public_key)
        {
            return Err("RPC gateway role/key is duplicated, cross-role or malformed".into());
        }
    }
    Ok(())
}
pub(crate) struct Admission {
    pub base: Snapshot,
    pub payload: AdmissionPayload,
    bytes: Vec<u8>,
    pub authority_bytes: Vec<u8>,
    stamps: Vec<Stamp>,
}
impl Admission {
    pub(crate) fn load(config: &NodeConfiguration, path: &Path) -> Result<Self, String> {
        let before = Stamp::capture(path)?;
        let base = snapshot(config)?;
        let selected = config
            .apqe_transport
            .as_ref()
            .ok_or("missing APQE configuration")?;
        let bytes = transport::read(path, 128 * 1024, false)?;
        let signed: SignedAdmission =
            serde_json::from_slice(&bytes).map_err(|_| "invalid RPC admission encoding")?;
        let root = transport::read(&selected.registry_trust_key_path, 8192, false)?;
        if transport::sha256(&root) != selected.registry_trust_key_sha256 {
            return Err("RPC trust root changed".into());
        }
        let engine = super::apqe_provider::load(config)?;
        let engine = engine
            .try_lock()
            .map_err(|_| "RPC admission provider unavailable")?;
        verify_signature(&engine, &signed, &root)?;
        drop(engine);
        let (authority_bytes, consensus) = authority_material(config)?;
        validate_binding(
            &signed.payload,
            &base,
            &transport::sha256(&authority_bytes),
            &consensus,
            transport::clock()?,
        )?;
        if !before.unchanged() || !base.stamps.iter().all(Stamp::unchanged) {
            return Err("RPC authority artifacts changed".into());
        }
        Ok(Self {
            stamps: vec![before],
            base,
            bytes,
            authority_bytes,
            payload: signed.payload,
        })
    }
    pub(crate) fn check_current(&self) -> Result<(), String> {
        if transport::clock()? >= self.payload.expires_at_unix
            || !self
                .base
                .stamps
                .iter()
                .chain(&self.stamps)
                .all(Stamp::unchanged)
        {
            return Err("RPC admission expired or its pinned artifacts changed".into());
        }
        Ok(())
    }
    pub(crate) fn gateway(&self, id: &str) -> Result<&GatewayEntry, String> {
        self.payload
            .gateways
            .iter()
            .find(|g| g.node_address == id && !g.revoked)
            .ok_or_else(|| "unknown or revoked RPC gateway".into())
    }
    pub(crate) fn material_context(
        &self,
        gateway: &str,
        validator: &str,
    ) -> Result<(SessionContext, Arc<dyn CurrentTransportTrust + Send + Sync>), String> {
        let g = self.gateway(gateway)?;
        let v: &TransportEntry = self.base.entry(validator)?;
        let mut context = self.base.context(validator, validator)?;
        context.protocol = PROTOCOL.into();
        context.initiator_node = g.node_address.clone();
        context.initiator_transport_key_id = g.transport_key_id.clone();
        context.initiator_key_version = g.transport_key_version;
        context.registry_format = "synergy-canary-rpc-gateway-admission-v1-json".into();
        context.registry_commitment = transport::artifact_commitment(
            b"SYNERGY/RPC-RELAY/REGISTRY/v1",
            &context.registry_format,
            &self.bytes,
        )?;
        let mut stamps = self.base.stamps.clone();
        stamps.extend(self.stamps.clone());
        let trust = Arc::new(Trust {
            context: context.clone(),
            initiator: g.transport_public_key.clone(),
            responder: v.transport_public_key.clone(),
            stamps,
            expires: self.payload.expires_at_unix,
        });
        Ok((context, trust))
    }
}
fn snapshot(config: &NodeConfiguration) -> Result<Snapshot, String> {
    if config.chain_id != 99999 {
        return Err("RPC relay is restricted to isolated Canary 99999".into());
    }
    let selected = config
        .apqe_transport
        .as_ref()
        .ok_or("missing APQE configuration")?;
    Snapshot::load(
        config,
        &[
            selected.registry_trust_key_sha256.clone(),
            selected.genesis_trust_key_sha256.clone(),
        ],
    )
}

fn authority_material(config: &NodeConfiguration) -> Result<(Vec<u8>, Vec<Vec<u8>>), String> {
    let current = authority::load(config)?.ok_or("RPC requires authenticated frozen authority")?;
    let keys = current
        .registry
        .active()
        .map(|v| {
            current
                .consensus_binding(&v.validator_id)
                .map(|(_, key)| key.to_vec())
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok((current.binding_bytes().to_vec(), keys))
}

pub(crate) fn unlock(path: &Path) -> Result<SecretBytes, String> {
    let secret = SecretBytes::from_bytes(transport::read(path, 4096, true)?);
    if secret.as_bytes().len() < 32 {
        return Err("custody unlock must contain at least 32 bytes".into());
    }
    passphrase(&secret)?;
    Ok(secret)
}

pub(crate) fn passphrase(secret: &SecretBytes) -> Result<&str, String> {
    std::str::from_utf8(secret.as_bytes()).map_err(|_| "custody unlock is not UTF-8".into())
}

pub(crate) fn enrollment(path: &Path) -> Result<(GatewayEnrollment, String), String> {
    let bytes = transport::read(path, 128 * 1024, false)?;
    let document = serde_json::from_slice(&bytes).map_err(|_| "invalid gateway enrollment")?;
    Ok((document, transport::sha256(&bytes)))
}

pub(crate) fn provision(
    config: &NodeConfiguration,
    output: &Path,
    transport_unlock: &Path,
    identity_unlock: &Path,
) -> Result<(), String> {
    use std::os::unix::fs::DirBuilderExt;
    let base = snapshot(config)?;
    let transport_unlock = unlock(transport_unlock)?;
    let identity_unlock = unlock(identity_unlock)?;
    let engine = super::apqe_provider::load(config)?;
    let engine = engine
        .try_lock()
        .map_err(|_| "RPC provisioning provider unavailable")?;
    let generated = gateway_transport::provision(
        &engine,
        base.payload.chain_id,
        base.payload.network_id,
        base.network.genesis_sha256,
        passphrase(&transport_unlock)?,
        passphrase(&identity_unlock)?,
    )?;
    let files = [
        (
            "gateway-enrollment.json",
            serde_json::to_vec(&generated.enrollment),
        ),
        (
            "gateway-transport.encrypted.json",
            serde_json::to_vec(&generated.encrypted_transport),
        ),
        (
            "gateway-identity.encrypted.json",
            serde_json::to_vec(&generated.encrypted_identity),
        ),
    ];
    if !base.stamps.iter().all(Stamp::unchanged) {
        return Err("pinned canary artifacts changed during provisioning".into());
    }
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(output)
        .map_err(|e| e.to_string())?;
    let result = files
        .into_iter()
        .try_for_each(|(name, bytes)| {
            write_new(
                &output.join(name),
                &bytes.map_err(|_| "cannot encode gateway artifacts")?,
            )
        })
        .and_then(|()| sync_directory(output));
    if result.is_err() {
        for name in [
            "gateway-enrollment.json",
            "gateway-transport.encrypted.json",
            "gateway-identity.encrypted.json",
        ] {
            let _ = std::fs::remove_file(output.join(name));
        }
        let _ = std::fs::remove_dir(output);
    }
    result
}

pub(crate) fn issue(
    config: &NodeConfiguration,
    enrollment_path: &Path,
    root_custody: &Path,
    root_unlock: &Path,
    output: &Path,
) -> Result<(), String> {
    let base = snapshot(config)?;
    let (authority, consensus) = authority_material(config)?;
    let (enrollment, enrollment_sha256) = enrollment(enrollment_path)?;
    let selected = config
        .apqe_transport
        .as_ref()
        .ok_or("missing APQE configuration")?;
    let root = transport::read(&selected.registry_trust_key_path, 8192, false)?;
    if transport::sha256(&root) != selected.registry_trust_key_sha256 {
        return Err("RPC trust root changed".into());
    }
    let envelope: EncryptedEnvelope =
        serde_json::from_slice(&transport::read(root_custody, 256 * 1024, true)?)
            .map_err(|_| "invalid RPC registry-root custody")?;
    let unlock = unlock(root_unlock)?;
    let engine = super::apqe_provider::load(config)?;
    let engine = engine
        .try_lock()
        .map_err(|_| "RPC admission provider unavailable")?;
    enrollment.verify(&engine)?;
    let g = enrollment.payload;
    if g.chain_id != base.payload.chain_id
        || g.network_id != base.payload.network_id
        || g.genesis_artifact_sha256 != base.network.genesis_sha256
    {
        return Err("gateway enrollment is for a different canary".into());
    }
    let now = transport::clock()?;
    let payload = AdmissionPayload {
        schema_version: 1,
        scope: "isolated-development-canary".into(),
        protocol: PROTOCOL.into(),
        chain_id: g.chain_id,
        network_id: g.network_id,
        genesis_artifact_sha256: g.genesis_artifact_sha256,
        authority_binding_sha256: transport::sha256(&authority),
        validator_registry_sha256: transport::sha256(&base.registry_bytes),
        epoch: base.payload.epoch,
        generation: base.payload.generation,
        valid_from_unix: now.saturating_sub(5).max(base.payload.valid_from_unix),
        expires_at_unix: base.payload.expires_at_unix,
        gateways: vec![GatewayEntry {
            node_address: g.node_address,
            role: "rpc_gateway".into(),
            transport_key_id: g.transport_key_id,
            transport_key_version: g.transport_key_version,
            transport_public_key: g.transport_public_key,
            enrollment_sha256,
            revoked: false,
        }],
    };
    validate_binding(
        &payload,
        &base,
        &transport::sha256(&authority),
        &consensus,
        now,
    )?;
    let signer = SecretBytes::from_bytes(decrypt_with_passphrase(
        &engine,
        &Primitives,
        &envelope,
        passphrase(&unlock)?,
    )?);
    if !engine
        .keypair_corresponds(Algorithm::MlDsa87, &root, signer.as_bytes())
        .map_err(|e| e.to_string())?
    {
        return Err("RPC signing custody does not match the pinned registry root".into());
    }
    let signature = engine
        .sign(
            Algorithm::MlDsa87,
            signer.as_bytes(),
            &signing_bytes(&payload)?,
            SignOptions::Pure {
                context: SIGN_CONTEXT,
            },
        )
        .map_err(|e| e.to_string())?;
    let signed = SignedAdmission { payload, signature };
    verify_signature(&engine, &signed, &root)?;
    if !base.stamps.iter().all(Stamp::unchanged) {
        return Err("pinned canary artifacts changed during admission issuance".into());
    }
    write_new(
        output,
        &serde_json::to_vec(&signed).map_err(|_| "cannot encode gateway admission")?,
    )
}

fn sync_directory(path: &Path) -> Result<(), String> {
    std::fs::File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|e| e.to_string())
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::{io::Write, os::unix::fs::OpenOptionsExt};
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| e.to_string())?;
    if let Err(e) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = std::fs::remove_file(path);
        return Err(e.to_string());
    }
    Ok(())
}

fn verify_signature(
    engine: &CryptoEngine,
    signed: &SignedAdmission,
    root: &[u8],
) -> Result<(), String> {
    if root.len() != 2592
        || !engine
            .verify(
                Algorithm::MlDsa87,
                root,
                &signing_bytes(&signed.payload)?,
                &signed.signature,
                SignOptions::Pure {
                    context: SIGN_CONTEXT,
                },
            )
            .map_err(|e| e.to_string())?
    {
        return Err("invalid ML-DSA-87 RPC gateway admission signature".into());
    }
    Ok(())
}
struct Trust {
    context: SessionContext,
    initiator: Vec<u8>,
    responder: Vec<u8>,
    stamps: Vec<Stamp>,
    expires: u64,
}
impl CurrentTransportTrust for Trust {
    fn check(
        &self,
        c: &SessionContext,
        i: &PublicKey<Mldsa65>,
        r: &PublicKey<Mldsa65>,
    ) -> Result<(), SessionError> {
        if c == &self.context
            && Primitives.constant_time_equal(i.as_bytes(), &self.initiator)
            && Primitives.constant_time_equal(r.as_bytes(), &self.responder)
            && transport::clock().is_ok_and(|now| now < self.expires)
            && self.stamps.iter().all(Stamp::unchanged)
        {
            Ok(())
        } else {
            Err(SessionError::Rejected)
        }
    }
}
// One request and one response per session, no multiplexing or implicit retry.
// Opaque correlation is public metadata, not authentication or replay authority.
pub(crate) fn encode(kind: u8, id: &[u8; 16], body: &[u8]) -> Result<Vec<u8>, String> {
    if !matches!(kind, 1 | 2) || body.is_empty() || body.len() > MAX_BODY {
        return Err("invalid RPC relay record".into());
    }
    let mut out = Vec::with_capacity(HEADER + body.len());
    out.extend_from_slice(&[1, kind]);
    out.extend_from_slice(id);
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(body);
    Ok(out)
}
pub(crate) fn decode(record: &[u8], kind: u8) -> Result<([u8; 16], &[u8]), String> {
    if !matches!(kind, 1 | 2)
        || record.len() <= HEADER
        || record.len() > HEADER + MAX_BODY
        || record[..2] != [1, kind]
    {
        return Err("invalid RPC relay framing".into());
    }
    let length = u32::from_be_bytes(record[18..22].try_into().map_err(|_| "RPC length")?) as usize;
    if length != record.len() - HEADER {
        return Err("RPC relay body length mismatch".into());
    }
    Ok((
        record[2..18].try_into().map_err(|_| "RPC request id")?,
        &record[HEADER..],
    ))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn gateway_requires_canonical_service_and_access_address() {
        let service = "synv51lrh6jcxaejkj4zv994j7qwn2rk6u38z5nwn";
        let validator = "synv11lrh6jcxaejkj4zv994j7qwn2rk6u3ar4emn";
        assert!(valid_gateway_address(service));
        assert!(!valid_gateway_address(validator));
        assert!(!valid_gateway_address(&format!("{service}x")));
    }
    #[test]
    fn wire_rejects_wrong_direction_version_length_and_oversize() {
        let id = [7; 16];
        let good = encode(1, &id, b"{}").unwrap();
        assert_eq!(decode(&good, 1).unwrap(), (id, &b"{}"[..]));
        assert!(decode(&good, 2).is_err());
        let mut bad = good.clone();
        bad[0] = 2;
        assert!(decode(&bad, 1).is_err());
        let mut bad = good.clone();
        bad.push(0);
        assert!(decode(&bad, 1).is_err());
        for end in 0..good.len() {
            assert!(decode(&good[..end], 1).is_err());
        }
        assert!(encode(1, &id, &vec![0; MAX_BODY + 1]).is_err());
        assert!(encode(3, &id, b"{}").is_err());
    }
}
