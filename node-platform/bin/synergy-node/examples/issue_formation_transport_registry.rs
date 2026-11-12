//! Offline generation-one transport registry for an independently approved
//! isolated formation. This tool cannot generate issuer or validator custody.
#[path = "../src/services/apqe_registry_wire.rs"]
mod registry;

use registry::{signing_bytes, RegistryPayload, SignedRegistry, TransportEntry, REGISTRY_CONTEXT};
use serde::{de::DeserializeOwned, Deserialize};
use std::{
    collections::BTreeSet,
    fs::{DirBuilder, File, OpenOptions},
    io::{self, IsTerminal, Read, Write},
    net::{IpAddr, SocketAddr},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use synergy_address_engine::{
    apqe::{
        crypto_engine::CryptoEngine, fixed_digest, provider::SignOptions, FixedDigest, Primitives,
        SecretBytes,
    },
    encrypt::{decrypt_with_passphrase, EncryptedEnvelope},
    snts07::decode_lower_hex,
    types::Algorithm,
    validator_provisioning::{verify_enrollment, EnrollmentRequest, NetworkBinding},
};
use synergy_aegis::{AegisPolicy, PqvmVerifier, SignatureAlgorithm};
use synergy_genesis::{authority::SignedAuthorityBinding, signing::SignedGenesis};

const SCOPE: &str = "isolated-development-canary";
const MAX_LIFETIME: u64 = 7 * 86400;
const ENROLLMENT_LIMIT: u64 = 128 * 1024;
const GENESIS_LIMIT: u64 = 4 * 1024 * 1024;
const AUTHORITY_LIMIT: u64 = 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    path: PathBuf,
    sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Member {
    enrollment: Input,
    dial_address: SocketAddr,
    transport_key_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    version: u16,
    scope: String,
    network_id: String,
    chain_id: u64,
    genesis: Input,
    authority: Input,
    authority_root: Input,
    issuer_root: Input,
    issuer_custody: Input,
    valid_from_unix: u64,
    expires_at_unix: u64,
    validators: [Member; 5],
}

fn sha256(bytes: &[u8]) -> String {
    fixed_digest(&Primitives, FixedDigest::Sha256, bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn read_exact_pin(path: &Path, pin: &str, limit: u64, private: bool) -> Result<Vec<u8>, String> {
    decode_lower_hex("approved SHA-256", pin, 32)?;
    let parent = path.parent().ok_or("input parent required")?;
    if !path.is_absolute() || parent.canonicalize().ok().as_deref() != Some(parent) {
        return Err("absolute input with direct parent required".into());
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| "approved input absent or unsafe")?;
    let metadata = file
        .metadata()
        .map_err(|_| "cannot inspect approved input")?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.len() == 0
        || metadata.len() > limit
        || (private
            && (metadata.mode() & 0o777 != 0o600 || metadata.uid() != unsafe { libc::geteuid() }))
    {
        return Err("approved input has unsafe type, size or private ownership".into());
    }
    let mut data = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut data)
        .map_err(|_| "cannot read approved input")?;
    if data.len() as u64 != metadata.len() || sha256(&data) != pin {
        return Err("approved input SHA-256 differs".into());
    }
    Ok(data)
}

impl Input {
    fn read(&self, limit: u64, private: bool) -> Result<Vec<u8>, String> {
        read_exact_pin(&self.path, &self.sha256, limit, private)
    }
}

fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, String> {
    serde_json::from_slice(bytes).map_err(|_| "invalid typed issuance JSON".into())
}

fn validate_plan(plan: &Plan, now: u64) -> Result<(), String> {
    if plan.version != 1
        || plan.scope != SCOPE
        || plan.chain_id == 0
        || plan.network_id.is_empty()
        || plan.network_id.len() > 128
        || plan.valid_from_unix > now
        || plan.expires_at_unix <= now
        || plan.expires_at_unix.saturating_sub(plan.valid_from_unix) > MAX_LIFETIME
    {
        return Err(
            "independently approved isolated scope and current bounded validity required".into(),
        );
    }
    Ok(())
}

fn isolated_dial(address: SocketAddr) -> bool {
    address.port() != 0
        && match address.ip() {
            IpAddr::V4(ip) => {
                let [first, second, _, _] = ip.octets();
                ip.is_loopback() || ip.is_private() || (first == 100 && (64..128).contains(&second))
            }
            IpAddr::V6(ip) => {
                let scope = match address {
                    SocketAddr::V6(addr) => addr.scope_id(),
                    _ => return false,
                };
                scope == 0 && (ip.is_loopback() || ip.is_unique_local())
            }
        }
}

struct Cohort<'a> {
    genesis_root: &'a [u8],
    authority: &'a synergy_genesis::authority::AuthorityPayload,
    network: &'a NetworkBinding,
}

fn transport_entries(
    engine: &CryptoEngine,
    cohort: &Cohort<'_>,
    inputs: &[Member; 5],
) -> Result<Vec<TransportEntry>, String> {
    let authority = cohort.authority;
    let policy = authority
        .protected
        .as_ref()
        .ok_or("initial protected policy required")?;
    policy
        .ingress_kem_registry
        .validate_protected_profile()
        .map_err(|_| "invalid governed ingress profile")?;
    let active: Vec<_> = authority
        .validators
        .iter()
        .filter(|v| v.record.may_sign_consensus())
        .collect();
    if active.len() != inputs.len() || authority.validators.len() != active.len() {
        return Err("exactly five active authenticated Genesis members required".into());
    }
    let (mut ids, mut addresses, mut key_ids, mut keys) = (
        BTreeSet::new(),
        BTreeSet::new(),
        BTreeSet::new(),
        BTreeSet::new(),
    );
    let mut entries = Vec::with_capacity(inputs.len());
    for input in inputs {
        let raw = input.enrollment.read(ENROLLMENT_LIMIT, false)?;
        let request: EnrollmentRequest = decode(&raw)?;
        verify_enrollment(engine, &request, cohort.network)?;
        let identity = request.payload.identity;
        let consensus =
            decode_lower_hex("consensus key", &identity.consensus_key.public_key, 1952)?;
        let transport = decode_lower_hex(
            "transport key",
            &identity.node_identity_key.public_key,
            1952,
        )?;
        let ingress =
            decode_lower_hex("ingress key", &request.payload.ingress_key.public_key, 1568)?;
        let member = active
            .iter()
            .find(|v| v.record.validator_id == identity.address)
            .ok_or("enrollment identity is not in authenticated active membership")?;
        let mut ingress_records = policy.ingress_kem_registry.records.iter().filter(|record| {
            record.validator_id == identity.address
                && record.activation_height <= authority.epoch_start_height
                && record
                    .retirement_height
                    .is_none_or(|h| authority.epoch_start_height < h)
        });
        if member.algorithm != SignatureAlgorithm::MlDsa65
            || member.public_key != consensus
            || !ingress_records
                .next()
                .is_some_and(|record| record.public_key.public_key == ingress)
            || ingress_records.next().is_some()
        {
            return Err("enrollment differs from governed consensus or ingress binding".into());
        }
        if !isolated_dial(input.dial_address)
            || !addresses.insert(input.dial_address)
            || !ids.insert(identity.address.clone())
            || !(1..=128).contains(&input.transport_key_id.len())
            || !input
                .transport_key_id
                .bytes()
                .all(|b| (0x21..=0x7e).contains(&b))
            || !key_ids.insert(input.transport_key_id.clone())
            || !keys.insert(transport.clone())
            || transport == cohort.genesis_root
            || active.iter().any(|v| {
                v.record.consensus_key_id == input.transport_key_id || v.public_key == transport
            })
        {
            return Err("nonisolated, duplicate or cross-role transport entry".into());
        }
        entries.push(TransportEntry {
            node_address: identity.address,
            dial_address: input.dial_address,
            transport_key_id: input.transport_key_id.clone(),
            transport_key_version: 1,
            transport_public_key: transport,
            enrollment_sha256: input.enrollment.sha256.clone(),
            revoked: false,
        });
    }
    entries.sort_by(|a, b| a.node_address.cmp(&b.node_address));
    Ok(entries)
}

fn unlock(input: impl Read) -> Result<SecretBytes, String> {
    let mut data = Vec::with_capacity(66);
    // Keep ownership of the partial buffer on read failure, and avoid a
    // resizing read that might leave a previous allocation unwiped.
    let mut input = input.take(66);
    let mut status = Ok(());
    while data.len() < 66 {
        let mut byte = vec![0; 1];
        match input.read(&mut byte) {
            Ok(0) => {
                drop(SecretBytes::from_bytes(byte));
                break;
            }
            Ok(_) => data.push(byte[0]),
            Err(_) => status = Err("issuer unlock input failed"),
        }
        drop(SecretBytes::from_bytes(byte));
        if status.is_err() {
            break;
        }
    }
    if data.len() == 65 && data.last() == Some(&b'\n') {
        data.pop();
    }
    let secret = SecretBytes::from_bytes(data);
    status?;
    if secret.as_bytes().len() != 64
        || !secret
            .as_bytes()
            .iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
    {
        return Err("issuer unlock requires 64 lowercase hex characters via private stdin".into());
    }
    Ok(secret)
}

fn sign_with_issuer(
    engine: &CryptoEngine,
    payload: RegistryPayload,
    root: &[u8],
    custody: &EncryptedEnvelope,
    unlock: &SecretBytes,
) -> Result<SignedRegistry, String> {
    let pass = std::str::from_utf8(unlock.as_bytes()).map_err(|_| "invalid issuer unlock")?;
    let secret =
        SecretBytes::from_bytes(decrypt_with_passphrase(engine, &Primitives, custody, pass)?);
    if root.len() != 2592
        || !engine
            .keypair_corresponds(Algorithm::MlDsa87, root, secret.as_bytes())
            .map_err(|_| "issuer custody cannot prove exact root ownership")?
    {
        return Err("encrypted issuer custody does not match approved ML-DSA-87 root".into());
    }
    let message = signing_bytes(&payload)?;
    let signature = engine
        .sign(
            Algorithm::MlDsa87,
            secret.as_bytes(),
            &message,
            SignOptions::Pure {
                context: REGISTRY_CONTEXT,
            },
        )
        .map_err(|_| "APQE registry signing failed")?;
    if !engine
        .verify(
            Algorithm::MlDsa87,
            root,
            &message,
            &signature,
            SignOptions::Pure {
                context: REGISTRY_CONTEXT,
            },
        )
        .map_err(|_| "APQE registry verification failed")?
    {
        return Err("registry signature refused under the independently pinned issuer root".into());
    }
    Ok(SignedRegistry { payload, signature })
}

fn publish(directory: &Path, registry: &SignedRegistry, root: &[u8]) -> Result<(), String> {
    let parent = directory.parent().ok_or("public output parent required")?;
    if !directory.is_absolute() || parent.canonicalize().ok().as_deref() != Some(parent) {
        return Err("absolute fresh output under a direct parent required".into());
    }
    let body = serde_json::to_vec(registry).map_err(|_| "cannot encode signed registry")?;
    DirBuilder::new()
        .mode(0o700)
        .create(directory)
        .map_err(|_| "public output directory must be fresh")?;
    for (name, bytes) in [
        ("transport-registry.json", body.as_slice()),
        ("transport-root.pub", root),
    ] {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .custom_flags(libc::O_NOFOLLOW)
            .open(directory.join(name))
            .map_err(|_| "cannot create fresh public registry output")?;
        file.write_all(bytes)
            .and_then(|_| file.sync_all())
            .map_err(|_| "cannot persist public registry output")?;
    }
    File::open(directory)
        .and_then(|f| f.sync_all())
        .and_then(|_| File::open(parent)?.sync_all())
        .map_err(|_| "cannot sync public registry output")?;
    println!(
        "generation=1 registry_sha256={} issuer_root_sha256={}",
        sha256(&body),
        sha256(root)
    );
    Ok(())
}

fn run() -> Result<(), String> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let [report, report_pin, plan, plan_pin, output] = args.as_slice() else {
        return Err("usage: issue_formation_transport_registry <native-report> <report-sha256> <approved-plan> <plan-sha256> <fresh-output-directory> (issuer unlock via private stdin)".into());
    };
    if io::stdin().is_terminal() {
        return Err("use a private stdin pipe for issuer unlock".into());
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "invalid clock")?
        .as_secs();
    let plan: Plan = decode(&read_exact_pin(
        Path::new(plan),
        plan_pin,
        32 * 1024,
        false,
    )?)?;
    validate_plan(&plan, now)?;
    let genesis: SignedGenesis = decode(&plan.genesis.read(GENESIS_LIMIT, false)?)?;
    let authority: SignedAuthorityBinding = decode(&plan.authority.read(AUTHORITY_LIMIT, false)?)?;
    let genesis_root = plan.authority_root.read(1952, false)?;
    if genesis.unsigned.format_version != 2
        || genesis.unsigned.network.chain_id != plan.chain_id
        || genesis.unsigned.network.network_id != plan.network_id
        || genesis_root.len() != 1952
    {
        return Err("signed Genesis differs from the independently approved formation".into());
    }
    let engine = synergy_aegis::load_authenticated_native_engine(Path::new(report), report_pin)?;
    let verifier = PqvmVerifier::with_apqe(
        AegisPolicy {
            allowed_algorithms: vec![SignatureAlgorithm::MlDsa65],
            maximum_message_bytes: GENESIS_LIMIT as usize,
            maximum_signature_bytes: 16 * 1024,
        },
        engine.clone(),
    )
    .map_err(|_| "authenticated Genesis verifier unavailable")?;
    synergy_genesis::verify_binding_with_verifier(&genesis, &genesis_root, &authority, &verifier)?;
    let network = NetworkBinding {
        chain_id_hex: format!("{:064x}", plan.chain_id),
        genesis_sha256: plan.genesis.sha256.clone(),
    };
    let guard = engine
        .lock()
        .map_err(|_| "authenticated APQE provider unavailable")?;
    let entries = transport_entries(
        &guard,
        &Cohort {
            genesis_root: &genesis_root,
            authority: &authority.payload,
            network: &network,
        },
        &plan.validators,
    )?;
    let payload = RegistryPayload {
        schema_version: 1,
        scope: plan.scope,
        chain_id: plan.chain_id,
        network_id: plan.network_id,
        protocol: genesis.unsigned.network.protocol_version,
        genesis_hash: genesis.genesis_hash,
        genesis_artifact_sha256: network.genesis_sha256,
        authority_binding_sha256: plan.authority.sha256,
        epoch: 1,
        generation: 1,
        valid_from_unix: plan.valid_from_unix,
        expires_at_unix: plan.expires_at_unix,
        validators: entries,
    };
    let root = plan.issuer_root.read(2592, false)?;
    let custody: EncryptedEnvelope = decode(&plan.issuer_custody.read(256 * 1024, true)?)?;
    let password = unlock(io::stdin().lock())?;
    let signed = sign_with_issuer(&guard, payload, &root, &custody, &password)?;
    publish(Path::new(output), &signed, &root)
}

fn main() {
    if let Err(error) = run() {
        eprintln!("initial transport registry: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use synergy_address_engine::{
        encrypt::encrypt_with_passphrase, types::AddressType, validator_provisioning::prepare,
    };
    use synergy_genesis::authority::AuthorityPayload;

    fn fixture_engine() -> std::sync::Arc<std::sync::Mutex<CryptoEngine>> {
        synergy_aegis::load_authenticated_native_engine(
            Path::new(&std::env::var("APQE_TRUSTED_NATIVE_REPORT").unwrap()),
            &std::env::var("APQE_AUTHENTICATED_REPORT_SHA256").unwrap(),
        )
        .unwrap()
    }

    #[test]
    #[ignore = "requires the independently authenticated native APQE provider"]
    fn exact_public_enrollments_and_existing_issuer_custody_are_required() {
        let engine = fixture_engine();
        let engine = engine.lock().unwrap();
        let root = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("formation-registry-{}", std::process::id()));
        DirBuilder::new().mode(0o700).create(&root).unwrap();
        struct Cleanup(PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        let _cleanup = Cleanup(root.clone());
        let network = NetworkBinding {
            chain_id_hex: format!("{:064x}", 999998),
            genesis_sha256: "ab".repeat(32),
        };
        // Use the historical public shape only; replace all membership/key
        // bytes with real native APQE fixtures before testing the issuer.
        let mut authority: AuthorityPayload = decode(include_bytes!(
            "../../../networks/testnet/posy-stability/unsigned-authority.json"
        ))
        .unwrap();
        let mut inputs = Vec::new();
        for i in 0..5 {
            let keys = prepare(&engine, AddressType::NodeClass1).unwrap();
            let (enrollment, _) = keys
                .bind_network(
                    &engine,
                    NetworkBinding {
                        chain_id_hex: network.chain_id_hex.clone(),
                        genesis_sha256: network.genesis_sha256.clone(),
                    },
                    "isolated fixture custody password",
                )
                .unwrap();
            let identity = &enrollment.payload.identity;
            let validator = &mut authority.validators[i];
            validator.record.validator_id = identity.address.clone();
            validator.record.consensus_key_id = format!("consensus-{i}");
            validator.algorithm = SignatureAlgorithm::MlDsa65;
            validator.public_key =
                decode_lower_hex("consensus", &identity.consensus_key.public_key, 1952).unwrap();
            let record = &mut authority
                .protected
                .as_mut()
                .unwrap()
                .ingress_kem_registry
                .records[i];
            record.validator_id = identity.address.clone();
            record.activation_height = authority.epoch_start_height;
            record.retirement_height = None;
            record.public_key.public_key =
                decode_lower_hex("ingress", &enrollment.payload.ingress_key.public_key, 1568)
                    .unwrap();
            let raw = serde_json::to_vec_pretty(&enrollment).unwrap();
            let path = root.join(format!("validator-{i}.json"));
            fs::write(&path, &raw).unwrap();
            inputs.push(Member {
                enrollment: Input {
                    path,
                    sha256: sha256(&raw),
                },
                dial_address: SocketAddr::from(([127, 0, 0, 1], 14000 + i as u16)),
                transport_key_id: format!("transport-{i}"),
            });
        }
        let mut inputs: [Member; 5] = inputs.try_into().ok().unwrap();
        let genesis_root = engine.generate_keypair(Algorithm::MlDsa65).unwrap();
        let cohort = Cohort {
            genesis_root: &genesis_root.public_key,
            authority: &authority,
            network: &network,
        };
        let entries = transport_entries(&engine, &cohort, &inputs).unwrap();
        assert!(entries
            .windows(2)
            .all(|pair| pair[0].node_address < pair[1].node_address));
        let a = inputs[1].dial_address;
        inputs[1].dial_address = inputs[0].dial_address;
        assert!(transport_entries(&engine, &cohort, &inputs).is_err());
        inputs[1].dial_address = a;
        inputs[1].transport_key_id = authority.validators[0].record.consensus_key_id.clone();
        assert!(transport_entries(&engine, &cohort, &inputs).is_err());
        let issuer = engine.generate_keypair(Algorithm::MlDsa87).unwrap();
        let wrong_issuer = engine.generate_keypair(Algorithm::MlDsa87).unwrap();
        let pass =
            unlock(&b"a000000000000000000000000000000000000000000000000000000000000000\n"[..])
                .unwrap();
        let custody = encrypt_with_passphrase(
            &engine,
            &Primitives,
            issuer.private_key.as_bytes(),
            std::str::from_utf8(pass.as_bytes()).unwrap(),
        )
        .unwrap();
        let payload = RegistryPayload {
            schema_version: 1,
            scope: SCOPE.into(),
            chain_id: 999998,
            network_id: "disposable-fixture".into(),
            protocol: "posy/3.0".into(),
            genesis_hash: "01".repeat(32),
            genesis_artifact_sha256: network.genesis_sha256,
            authority_binding_sha256: "02".repeat(32),
            epoch: 1,
            generation: 1,
            valid_from_unix: 1,
            expires_at_unix: 2,
            validators: entries,
        };
        assert!(sign_with_issuer(
            &engine,
            payload.clone(),
            &wrong_issuer.public_key,
            &custody,
            &pass
        )
        .is_err());
        let signed =
            sign_with_issuer(&engine, payload, &issuer.public_key, &custody, &pass).unwrap();
        let output = root.join("public");
        publish(&output, &signed, &issuer.public_key).unwrap();
        assert_eq!(
            fs::read(output.join("transport-root.pub")).unwrap(),
            issuer.public_key
        );
        assert!(publish(&output, &signed, &issuer.public_key).is_err());
        let mut signed: SignedRegistry =
            decode(&fs::read(output.join("transport-registry.json")).unwrap()).unwrap();
        signed.payload.validators[0].transport_key_id.push('x');
        assert!(!engine
            .verify(
                Algorithm::MlDsa87,
                &issuer.public_key,
                &signing_bytes(&signed.payload).unwrap(),
                &signed.signature,
                SignOptions::Pure {
                    context: REGISTRY_CONTEXT
                }
            )
            .unwrap());
    }
}
