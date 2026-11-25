//! A self-authenticated routing hint, never membership or consensus authority.
//! Endpoint changes preserve the original transport artifact/key context.
use super::{
    apqe_transport::{read, sha256},
    authority::VerifiedAuthority,
};
use serde::{Deserialize, Serialize};
#[cfg(test)]
use std::sync::Arc;
use std::{collections::BTreeMap, net::SocketAddr, path::Path};
use synergy_aegis::{AegisPolicy, AegisSigner, KeyId, SignatureAlgorithm, SigningContext};
use synergy_config::NodeConfiguration;
const DOMAIN: &str = "SYNERGY-VALIDATOR-TRANSPORT-ENDPOINT-V1";
const FILE: &str = "current.json";
const MAX: usize = 1024 * 1024;
pub(super) const MAGIC: &[u8] = b"SYNERGY/TRANSPORT-ENDPOINT/v1\0";
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Endpoint {
    pub schema_version: u32,
    pub chain_id: u64,
    pub genesis_hash: String,
    pub validator_id: String,
    pub consensus_key_id: String,
    pub signing_epoch: u64,
    pub generation: u64,
    pub dial_address: SocketAddr,
    pub vpn_binding_sha256: String,
    pub signature: Vec<u8>,
}
impl Endpoint {
    fn signing_bytes(&self) -> Result<Vec<u8>, String> {
        let mut value = self.clone();
        value.signature.clear();
        let mut bytes = MAGIC.to_vec();
        bytes.extend(serde_json::to_vec(&value).map_err(|e| e.to_string())?);
        Ok(bytes)
    }
    pub(super) fn verify(&self, authority: &VerifiedAuthority) -> Result<(), String> {
        let ip = self.dial_address.ip();
        let private = match ip {
            std::net::IpAddr::V4(v) => {
                v.is_private()
                    || (v.octets()[0] == 100 && (64..128).contains(&v.octets()[1]))
                    || (cfg!(test) && v.is_loopback())
            }
            std::net::IpAddr::V6(v) => v.is_unique_local() || (cfg!(test) && v.is_loopback()),
        };
        if self.schema_version != 1
            || self.chain_id != authority.epoch.chain_id
            || self.genesis_hash != authority.authenticated_genesis_hash()?
            || self.generation == 0
            || !private
            || self.dial_address.port() == 0
            || !synergy_posy::is_hash(&self.vpn_binding_sha256)
            || self.signature.len() != 3309
            || self.signing_epoch > authority.epoch.epoch
        {
            return Err("invalid scoped native endpoint".into());
        }
        // Current membership gates routing even for a genuine historical signature.
        authority
            .registry
            .active_validator(&self.validator_id)
            .map_err(|e| e.to_string())?;
        let (key_id, key) = authority.consensus_binding(&self.validator_id)?;
        if key_id != self.consensus_key_id {
            return Err("endpoint changed its authenticated identity key".into());
        }
        authority
            .native_identity_verifier()
            .ok_or("endpoint native verifier unavailable")?
            .verify_raw_classified("ML-DSA-65", key, &self.signing_bytes()?, &self.signature)
            .map_err(|e| format!("native endpoint signature: {e}"))
    }
}
fn store(config: &NodeConfiguration) -> Result<synergy_storage::AtomicStore, String> {
    synergy_storage::AtomicStore::new(
        config.storage.data_directory.join("peers/native-endpoints"),
        MAX,
    )
    .map_err(|e| e.to_string())
}
pub(super) fn load(config: &NodeConfiguration) -> Result<BTreeMap<String, Endpoint>, String> {
    let path = config
        .storage
        .data_directory
        .join("peers/native-endpoints")
        .join(FILE);
    if !path.try_exists().map_err(|e| e.to_string())? {
        return Ok(BTreeMap::new());
    }
    let records: BTreeMap<String, Endpoint> =
        serde_json::from_slice(&read(&path, MAX as u64, false)?)
            .map_err(|_| "invalid native endpoint cache")?;
    if records.len() > config.p2p.max_authenticated_peers {
        return Err("native endpoint cache exceeds peer bound".into());
    }
    if records.iter().any(|(id, r)| id != &r.validator_id) {
        return Err("native endpoint cache identity differs".into());
    }
    Ok(records)
}
pub(super) fn accept(
    config: &NodeConfiguration,
    authority: &VerifiedAuthority,
    record: Endpoint,
) -> Result<bool, String> {
    let mut records = load(config)?;
    if let Some(old) = records.get(&record.validator_id) {
        if old == &record {
            return Ok(false);
        }
        if old.generation >= record.generation {
            return Err("replayed or equivocal native endpoint".into());
        }
    }
    record.verify(authority)?;
    records.insert(record.validator_id.clone(), record);
    if records.len() > config.p2p.max_authenticated_peers {
        return Err("native endpoint cache exceeds peer bound".into());
    }
    store(config)?
        .write_atomic(
            FILE,
            &serde_json::to_vec(&records).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
    Ok(true)
}
pub(super) fn decode(bytes: &[u8]) -> Result<Option<Endpoint>, String> {
    if !bytes.starts_with(MAGIC) {
        return Ok(None);
    }
    if bytes.len() > 16 * 1024 {
        return Err("native endpoint announcement exceeds bound".into());
    }
    let record = serde_json::from_slice(&bytes[MAGIC.len()..])
        .map_err(|_| "invalid native endpoint announcement")?;
    Ok(Some(record))
}
pub(super) fn encode(record: &Endpoint) -> Result<Vec<u8>, String> {
    let mut bytes = MAGIC.to_vec();
    bytes.extend(serde_json::to_vec(record).map_err(|e| e.to_string())?);
    Ok(bytes)
}
fn public(root: &Path, name: &str) -> Result<serde_json::Value, String> {
    serde_json::from_slice(&read(&root.join("evidence").join(name), 128 * 1024, false)?)
        .map_err(|_| "invalid managed VPN evidence".into())
}
fn json_pin(value: &serde_json::Value) -> Result<String, String> {
    // Native controller public_hash is canonical sorted-key JSON with compact separators.
    Ok(sha256(
        &serde_json::to_vec(value).map_err(|e| e.to_string())?,
    ))
}
pub(crate) fn cli(args: impl Iterator<Item = String>) -> Result<(), String> {
    let mut args = args;
    let mut config = None;
    let mut root = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" => {
                config = Some(std::path::PathBuf::from(
                    args.next().ok_or("missing config")?,
                ))
            }
            "--root" => {
                root = Some(std::path::PathBuf::from(
                    args.next().ok_or("missing platform root")?,
                ))
            }
            _ => return Err("transport-endpoint accepts only --config and --root".into()),
        }
    }
    let path = config.ok_or("installed configuration required")?;
    let root = root.ok_or("platform root required")?;
    let root = root.canonicalize().map_err(|e| e.to_string())?;
    let _exclusive = super::checkpoint::lock_configuration(&path)?;
    let config = synergy_config::load(&path).map_err(|e| e.to_string())?;
    for path in [
        &path,
        &config.public_identity_path,
        &config.manifest_path,
        &config.storage.data_directory,
    ] {
        if !path.is_absolute()
            || !path
                .canonicalize()
                .map_err(|e| e.to_string())?
                .starts_with(&root)
        {
            return Err("endpoint authoring must remain inside installed platform root".into());
        }
    }
    let enrollment = public(&root, "vpn-enrollment.json")?;
    let binding = public(&root, "vpn-server-binding.json")?;
    let transition = public(&root, "vpn-reauthorization.json")?;
    if transition["format"] != "nodenetwork-vpn-reauthorization-v1"
        || transition["phase"] != "bound"
        || transition["new_enrollment"] != enrollment
        || transition["new_binding"] != binding
        || transition["new_binding_sha256"] != json_pin(&binding)?
        || binding["server_binding_verified"] != true
        || binding["wireguard_public_key"] != transition["old_enrollment"]["wireguard_public_key"]
        || binding["wireguard_public_key"] != enrollment["wireguard_public_key"]
        || binding["peer_name"] != enrollment["hostname"]
        || enrollment["native_enrollment_verified"] != true
    {
        return Err("exact completed same-key managed VPN binding required".into());
    }
    let (address, _binding_hash) = managed_endpoint(&config, &root)?;
    let identity: synergy_identity::PublicNodeIdentity =
        serde_json::from_slice(&read(&config.public_identity_path, 65536, false)?)
            .map_err(|_| "invalid installed identity")?;
    let identity = identity.validate().map_err(|e| format!("{e:?}"))?;
    let authority =
        super::authority::load(&config)?.ok_or("authenticated current authority unavailable")?;
    let id = identity.node_address.as_str();
    let (key_id, _) = authority.consensus_binding(id)?;
    let previous = load(&config)?.remove(id);
    let binding_hash = sha256(&read(
        &root.join("evidence/vpn-server-binding.json"),
        128 * 1024,
        false,
    )?);
    if let Some(old) = previous
        .as_ref()
        .filter(|old| old.dial_address == address && old.vpn_binding_sha256 == binding_hash)
    {
        old.verify(&authority)?;
        println!("{}",serde_json::to_string(&serde_json::json!({"schema":"synergy-native-transport-endpoint-v1","record":old,"record_sha256":sha256(&encode(old)?),"identity_preserved":true,"routing_complete":true,"consensus_started":false})).map_err(|e|e.to_string())?);
        return Ok(());
    }
    let signer = super::apqe_provider::consensus_signer(
        &config,
        &authority,
        id,
        AegisPolicy {
            allowed_algorithms: vec![SignatureAlgorithm::MlDsa65],
            maximum_message_bytes: 16384,
            maximum_signature_bytes: 16384,
        },
    )?;
    let mut record = Endpoint {
        schema_version: 1,
        chain_id: config.chain_id,
        genesis_hash: authority.authenticated_genesis_hash()?.into(),
        validator_id: id.into(),
        consensus_key_id: key_id.into(),
        signing_epoch: authority.epoch.epoch,
        generation: previous.map_or(Ok(1), |r| {
            r.generation
                .checked_add(1)
                .ok_or("endpoint generation overflow")
        })?,
        dial_address: address,
        vpn_binding_sha256: binding_hash,
        signature: vec![],
    };
    record.signature = signer
        .sign(
            &KeyId::new(key_id).map_err(|e| e.to_string())?,
            &SigningContext {
                domain: DOMAIN.into(),
                chain_id: config.chain_id,
                epoch: Some(authority.epoch.epoch),
                height: None,
            },
            &record.signing_bytes()?,
        )
        .map_err(|e| e.to_string())?
        .bytes;
    accept(&config, &authority, record.clone())?;
    println!("{}",serde_json::to_string(&serde_json::json!({"schema":"synergy-native-transport-endpoint-v1","record":record,"record_sha256":sha256(&encode(&record)?),"identity_preserved":true,"routing_complete":true,"consensus_started":false})).map_err(|e|e.to_string())?);
    Ok(())
}
#[cfg(test)]
pub(super) fn qualify(
    config: &NodeConfiguration,
    authority: Arc<VerifiedAuthority>,
    signers: &[Arc<dyn AegisSigner>],
) {
    let record = authority
        .registry
        .active()
        .find(|r| r.consensus_key_id == "consensus-1")
        .unwrap();
    let mut endpoint = Endpoint {
        schema_version: 1,
        chain_id: authority.epoch.chain_id,
        genesis_hash: authority.authenticated_genesis_hash().unwrap().into(),
        validator_id: record.validator_id.clone(),
        consensus_key_id: record.consensus_key_id.clone(),
        signing_epoch: authority.epoch.epoch,
        generation: 1,
        dial_address: "10.69.250.200:5622".parse().unwrap(),
        vpn_binding_sha256: "87".repeat(32),
        signature: vec![],
    };
    endpoint.signature = signers[1]
        .sign(
            &KeyId::new(&record.consensus_key_id).unwrap(),
            &SigningContext {
                domain: DOMAIN.into(),
                chain_id: authority.epoch.chain_id,
                epoch: Some(authority.epoch.epoch),
                height: None,
            },
            &endpoint.signing_bytes().unwrap(),
        )
        .unwrap()
        .bytes;
    endpoint.verify(&authority).unwrap();
    assert!(accept(config, &authority, endpoint.clone()).unwrap());
    assert!(!accept(config, &authority, endpoint.clone()).unwrap());
    let mut equivocal = endpoint.clone();
    equivocal.dial_address.set_port(5623);
    assert!(accept(config, &authority, equivocal).is_err());
    let mut forged = endpoint.clone();
    forged.generation = 2;
    forged.signature[0] ^= 1;
    assert!(accept(config, &authority, forged).is_err());
    let mut foreign = endpoint.clone();
    foreign.chain_id = 9969;
    assert!(foreign.verify(&authority).is_err());
    assert_eq!(load(config).unwrap()[&record.validator_id], endpoint);
    let decoded = decode(&encode(&endpoint).unwrap()).unwrap().unwrap();
    assert_eq!(decoded, endpoint);
    eprintln!("Real native ML65 same-identity endpoint signature/replay/equivocation/scope/restart decode passed");
}

pub(super) fn managed_endpoint(
    config: &NodeConfiguration,
    root: &Path,
) -> Result<(SocketAddr, String), String> {
    let binding = public(root, "vpn-server-binding.json")?;
    let enrollment = public(root, "vpn-enrollment.json")?;
    if binding["server_binding_verified"] != true
        || enrollment["native_enrollment_verified"] != true
        || binding["wireguard_public_key"] != enrollment["wireguard_public_key"]
        || binding["peer_name"] != enrollment["hostname"]
    {
        return Err("exact native managed VPN binding required".into());
    }
    let mut command = std::process::Command::new(root.join("tools/netbird-client"));
    command
        .args(["status", "--json"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null());
    let mut child = command
        .spawn()
        .map_err(|e| format!("observe installed NetBird: {e}"))?;
    let stdout = child.stdout.take().ok_or("NetBird output unavailable")?;
    let reader = std::thread::spawn(move || {
        use std::io::Read;
        let mut bytes = vec![];
        stdout
            .take(128 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map(|_| bytes)
    });
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let status = loop {
        if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
            break status;
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            let _ = reader.join();
            return Err("installed NetBird status deadline exceeded".into());
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    };
    let raw = reader
        .join()
        .map_err(|_| "NetBird reader failed")?
        .map_err(|e| e.to_string())?;
    if !status.success() || raw.len() > 128 * 1024 {
        return Err("installed NetBird status failed or exceeded bound".into());
    }
    let live: serde_json::Value =
        serde_json::from_slice(&raw).map_err(|_| "invalid installed NetBird status")?;
    if live["management"]["connected"] != true
        || live["signal"]["connected"] != true
        || live["publicKey"] != binding["wireguard_public_key"]
        || live["netbirdIp"].as_str().and_then(|v| v.split('/').next()) != binding["ip"].as_str()
    {
        return Err("current native VPN key/IP differs from managed binding".into());
    }
    let ip = binding["ip"]
        .as_str()
        .ok_or("new VPN IP missing")?
        .parse()
        .map_err(|_| "new VPN IP must be literal")?;
    let ports = config
        .network
        .listen_addresses
        .iter()
        .map(|a| a.port())
        .collect::<std::collections::BTreeSet<_>>();
    if ports.len() != 1 {
        return Err("endpoint authoring requires one unambiguous configured listen port".into());
    }
    let address = SocketAddr::new(ip, *ports.first().unwrap());
    Ok((
        address,
        sha256(&read(
            &root.join("evidence/vpn-server-binding.json"),
            128 * 1024,
            false,
        )?),
    ))
}
/// A verified self update changes the OS listener as well as peer dial hints.
/// The immutable installed configuration still owns the port and fallback route.
pub(crate) fn local_listeners(config: &NodeConfiguration) -> Result<Vec<SocketAddr>, String> {
    let identity =
        super::identity::load_public_identity(&config.public_identity_path, config.role)?;
    let Some(record) = load(config)?.remove(identity.node_address.as_str()) else {
        return Ok(config.network.listen_addresses.clone());
    };
    let authority = super::authority::load(config)?
        .ok_or("local endpoint requires original-root authenticated membership")?;
    record.verify(&authority)?;
    if config
        .network
        .listen_addresses
        .iter()
        .any(|a| a.port() != record.dial_address.port())
    {
        return Err("self endpoint changed configured listening port".into());
    }
    Ok(vec![record.dial_address])
}
