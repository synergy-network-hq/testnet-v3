//! Real child-process acceptance for the explicitly isolated APQE profile.
use super::super::apqe_transport::{
    RegistryPayload, SignedRegistry, TransportEntry, REGISTRY_CONTEXT,
};
use super::*;
use synergy_address_engine::{
    apqe::{
        crypto_engine::CryptoEngine, fixed_digest, provider::SignOptions, FixedDigest, Primitives,
    },
    types::Algorithm,
    validator_provisioning::{NetworkBinding, PreparedValidator},
};

pub(super) fn hex_decode(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks_exact(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}
fn hash(bytes: &[u8]) -> String {
    fixed_digest(&Primitives, FixedDigest::Sha256, bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn fresh_custody_passphrase() -> synergy_address_engine::apqe::SecretBytes {
    use synergy_address_engine::apqe::SecretBytes;
    let mut entropy = vec![0; 32];
    let result = Primitives.random_bytes(&mut entropy);
    // Install the wiping owner before examining an entropy error, including
    // implementations that may have partially filled the destination.
    let entropy = SecretBytes::from_bytes(entropy);
    result.expect("authoritative APQE OS entropy required");
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let text = entropy
        .as_bytes()
        .iter()
        .flat_map(|byte| [HEX[(byte >> 4) as usize], HEX[(byte & 15) as usize]])
        .collect();
    SecretBytes::from_bytes(text)
}

#[test]
fn custody_passphrases_use_independent_apqe_entropy() {
    let first = fresh_custody_passphrase();
    let second = fresh_custody_passphrase();
    assert_eq!(first.as_bytes().len(), 64);
    assert!(first.as_bytes().iter().all(u8::is_ascii_hexdigit));
    assert!(first.as_bytes() != second.as_bytes());
}

pub(super) fn finalize_secure_fixture(
    root: &Path,
    configs: &mut [NodeConfiguration],
    staged: Vec<PreparedValidator>,
    engine: &Arc<std::sync::Mutex<CryptoEngine>>,
    endpoints: Option<&[std::net::SocketAddr; 5]>,
) -> synergy_address_engine::apqe::SecretBytes {
    let genesis_bytes = fs::read(root.join("genesis.sgen")).unwrap();
    let genesis: synergy_genesis::signing::SignedGenesis =
        serde_json::from_slice(&genesis_bytes).unwrap();
    let network = NetworkBinding {
        chain_id_hex: format!("{:064x}", configs[0].chain_id),
        genesis_sha256: hash(&genesis_bytes),
    };
    let engine = engine.lock().unwrap();
    let registry_root = engine.generate_keypair(Algorithm::MlDsa87).unwrap();
    fs::write(root.join("registry-root.pub"), &registry_root.public_key).unwrap();
    let mut entries = Vec::new();
    for (index, (config, keys)) in configs.iter_mut().zip(staged).enumerate() {
        let dir = root.join(format!("node-{index}"));
        let public = keys.public_identity();
        let pass = fresh_custody_passphrase();
        let pass_text = std::str::from_utf8(pass.as_bytes()).unwrap();
        let (request, custody) = keys
            .bind_network(
                &engine,
                NetworkBinding {
                    chain_id_hex: network.chain_id_hex.clone(),
                    genesis_sha256: network.genesis_sha256.clone(),
                },
                pass_text,
            )
            .unwrap();
        let enrollment = serde_json::to_vec(&request).unwrap();
        fs::write(dir.join("enrollment.json"), &enrollment).unwrap();
        secret(
            &dir.join("custody.json"),
            &serde_json::to_vec(&custody).unwrap(),
        );
        secret(&dir.join("unlock"), pass.as_bytes());
        entries.push(TransportEntry {
            node_address: public.address,
            dial_address: endpoints.map_or(config.network.listen_addresses[0], |v| v[index]),
            transport_key_id: format!("transport-{index}"),
            transport_key_version: 1,
            transport_public_key: hex_decode(&public.node_identity_key.public_key),
            enrollment_sha256: hash(&enrollment),
            revoked: false,
        });
        config.aegis_signing_key_path = None;
        config.aegis_key_bindings_path = None;
        config.consensus.signing_key_path = None;
        config.etdag.ingress_kem_secret_key_path = None;
        config.apqe_transport = Some(ApqeTransportConfiguration {
            profile: ApqeTransportProfile::EngineeringCanaryPqVsessionV1,
            registry_path: root.join("registry.json"),
            registry_trust_key_path: root.join("registry-root.pub"),
            registry_trust_key_sha256: hash(&registry_root.public_key),
            genesis_trust_key_sha256: hash(&fs::read(root.join("trust.pub")).unwrap()),
            enrollment_path: dir.join("enrollment.json"),
            custody_path: dir.join("custody.json"),
            custody_unlock_path: dir.join("unlock"),
        });
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let payload = RegistryPayload {
        schema_version: 1,
        scope: "isolated-development-canary".into(),
        chain_id: configs[0].chain_id,
        network_id: configs[0].network_id.clone(),
        protocol: "posy/3.0".into(),
        genesis_hash: genesis.genesis_hash,
        genesis_artifact_sha256: network.genesis_sha256,
        authority_binding_sha256: hash(&fs::read(root.join("authority.json")).unwrap()),
        epoch: 1,
        generation: 1,
        valid_from_unix: now - 1,
        expires_at_unix: now + 86400 * 2,
        validators: entries,
    };
    let signature = engine
        .sign(
            Algorithm::MlDsa87,
            registry_root.private_key.as_bytes(),
            &super::super::apqe_transport::signing_bytes(&payload).unwrap(),
            SignOptions::Pure {
                context: REGISTRY_CONTEXT,
            },
        )
        .unwrap();
    write_json(
        &root.join("registry.json"),
        &SignedRegistry {
            payload: payload.clone(),
            signature,
        },
    );
    // Signed hostile fixtures exercise the actual Core trust boundary before
    // any child starts; each mutation is restored to the exact valid registry.
    let valid_registry = fs::read(root.join("registry.json")).unwrap();
    type RegistryNegativeCase = (&'static str, fn(&mut RegistryPayload), &'static str);
    let cases: &[RegistryNegativeCase] = &[
        (
            "expired",
            |p| p.expires_at_unix = 1,
            "differs from authenticated",
        ),
        (
            "wrong chain",
            |p| p.chain_id += 1,
            "differs from authenticated",
        ),
        (
            "wrong network",
            |p| p.network_id.push('x'),
            "differs from authenticated",
        ),
        (
            "wrong Genesis",
            |p| p.genesis_artifact_sha256 = "0".repeat(64),
            "differs from authenticated",
        ),
        (
            "wrong epoch",
            |p| p.epoch += 1,
            "differs from authenticated",
        ),
        (
            "duplicate transport",
            |p| p.validators[1].transport_public_key = p.validators[0].transport_public_key.clone(),
            "cross-role or malformed",
        ),
        (
            "zero key version",
            |p| p.validators[0].transport_key_version = 0,
            "cross-role or malformed",
        ),
        (
            "revoked local",
            |p| p.validators[0].revoked = true,
            "unknown or revoked",
        ),
    ];
    for (name, mutate, boundary) in cases {
        let mut hostile = payload.clone();
        mutate(&mut hostile);
        let signature = engine
            .sign(
                Algorithm::MlDsa87,
                registry_root.private_key.as_bytes(),
                &super::super::apqe_transport::signing_bytes(&hostile).unwrap(),
                SignOptions::Pure {
                    context: REGISTRY_CONTEXT,
                },
            )
            .unwrap();
        write_json(
            &root.join("registry.json"),
            &SignedRegistry {
                payload: hostile,
                signature,
            },
        );
        let error = super::super::apqe_transport::preflight(&configs[0]).unwrap_err();
        assert!(
            error.contains(boundary),
            "{name}: wrong rejection boundary: {error}"
        );
    }
    fs::write(root.join("registry.json"), &valid_registry).unwrap();
    let mut replaced_root = configs[0].clone();
    replaced_root
        .apqe_transport
        .as_mut()
        .unwrap()
        .registry_trust_key_sha256 = "0".repeat(64);
    assert!(super::super::apqe_transport::preflight(&replaced_root)
        .unwrap_err()
        .contains("pinned trust root"));
    super::super::apqe_transport::preflight(&configs[0]).unwrap();
    eprintln!("Core signed registry negative boundaries PASS:8mutations+independentrootpin");
    for (index, config) in configs.iter().enumerate() {
        config.validate().unwrap();
        fs::write(
            root.join(format!("node-{index}/config.json")),
            serde_json::to_vec_pretty(config).unwrap(),
        )
        .unwrap();
    }
    registry_root.private_key
}

#[test]
#[ignore = "explicit native five independent processes; requires normal node binary"]
fn actual_apqe_five_process_canary() {
    let binary = PathBuf::from(
        std::env::var("SYNERGY_APQE_CANARY_BINARY").expect("normal node binary required"),
    );
    assert!(binary.is_absolute() && binary.is_file());
    let provider = ApqeProviderConfiguration {
        report_path: PathBuf::from(std::env::var("APQE_TRUSTED_NATIVE_REPORT").unwrap()),
        authenticated_report_sha256: std::env::var("APQE_AUTHENTICATED_REPORT_SHA256").unwrap(),
    };
    let network_id = format!("posy-apqe-canary-process-{}", std::process::id());
    let (transaction, world, mut account_secret) =
        funded_transaction_fixture_for_network_provider(&network_id, 10_000_000, Some(&provider));
    let mut prepared =
        prepare_socket_fixture_profile_mode(world, None, true, None, Some(&provider), true);
    struct Cleanup {
        root: PathBuf,
        children: Vec<std::process::Child>,
    }
    impl Drop for Cleanup {
        fn drop(&mut self) {
            for child in &mut self.children {
                #[cfg(target_os = "linux")]
                {
                    if let Ok(status) = fs::read_to_string(format!("/proc/{}/status", child.id())) {
                        let memory: Vec<_> = status
                            .lines()
                            .filter(|line| line.starts_with("VmRSS:") || line.starts_with("VmHWM:"))
                            .collect();
                        let stat = fs::read_to_string(format!("/proc/{}/stat", child.id()))
                            .unwrap_or_default();
                        let cpu = stat
                            .rsplit_once(')')
                            .map(|(_, v)| v.split_whitespace().collect::<Vec<_>>())
                            .and_then(|v| {
                                Some((
                                    v.get(11)?.parse::<u64>().ok()?,
                                    v.get(12)?.parse::<u64>().ok()?,
                                ))
                            });
                        eprintln!("canary process-lifetime resources pid={} memory={memory:?} cpu_user_system_ticks={cpu:?} ticks_per_second={}",child.id(),unsafe{libc::sysconf(libc::_SC_CLK_TCK)});
                    }
                }
                let _ = child.kill();
                let _ = child.wait();
            }
            let _ = fs::remove_dir_all(&self.root);
        }
    }
    let mut cleanup = Cleanup {
        root: prepared.root.clone(),
        children: Vec::new(),
    };
    // Release reservations immediately before actual listeners bind.
    prepared.listeners.clear();
    for index in 0..5 {
        let path = prepared.root.join(format!("node-{index}/config.json"));
        let preflight = std::process::Command::new(&binary)
            .args(["preflight", "--config"])
            .arg(&path)
            .output()
            .unwrap();
        assert!(
            preflight.status.success(),
            "preflight {index}: {}",
            String::from_utf8_lossy(&preflight.stderr)
        );
        let output =
            fs::File::create(prepared.root.join(format!("node-{index}/process.log"))).unwrap();
        cleanup.children.push(
            std::process::Command::new(&binary)
                .args(["start", "--config"])
                .arg(path)
                .stdout(output.try_clone().unwrap())
                .stderr(output)
                .spawn()
                .unwrap(),
        );
    }
    let deadline = Instant::now() + Duration::from_secs(180);
    loop {
        let mut ready = 0;
        for (index, child) in cleanup.children.iter_mut().enumerate() {
            assert!(
                child.try_wait().unwrap().is_none(),
                "node {index} exited: {}",
                fs::read_to_string(prepared.root.join(format!("node-{index}/process.log")))
                    .unwrap()
            );
            let response = std::process::Command::new(&binary)
                .args(["status", "--admin-socket"])
                .arg(&prepared.configurations[index].admin_socket_path)
                .output()
                .unwrap();
            if response.status.success() {
                ready += 1;
            }
        }
        if ready == 5 {
            eprintln!("APQE five independent process startup PASS; finality/ETDAG acceptance still pending");
            break;
        }
        assert!(Instant::now() < deadline, "five-process startup deadline");
        std::thread::sleep(Duration::from_millis(1000));
    }
    let session_deadline = Instant::now() + Duration::from_secs(180);
    loop {
        let sessions: Vec<_> = prepared
            .configurations
            .iter()
            .map(|c| {
                process_rpc(
                    c.rpc.listen_address.unwrap(),
                    "synergy_chainTelemetry",
                    serde_json::json!({}),
                )
            })
            .collect();
        if sessions.iter().all(|r| {
            r.as_ref().is_ok_and(|v| {
                v["transport"]["apqe_session_count"].as_u64() == Some(4)
                    && v["transport"]["authenticated_peer_count"].as_u64() == Some(4)
            })
        }) {
            eprintln!("APQE actual5process fullmesh PASS:4authenticated encrypted sessionspernode");
            break;
        }
        assert!(
            Instant::now() < session_deadline,
            "APQE fullmesh sessiondeadline"
        );
        std::thread::sleep(Duration::from_millis(1000));
    }
    let rpc_address = prepared.configurations[0].rpc.listen_address.unwrap();
    let response = process_rpc(
        rpc_address,
        "synergy_getProcessingContextV1",
        serde_json::json!({}),
    )
    .unwrap();
    let context: synergy_etdag::ProcessingContext =
        serde_json::from_value(response["context"].clone()).unwrap();
    let transaction_height = context.authority.target_height;
    let authority = authority::load(&prepared.configurations[0])
        .unwrap()
        .unwrap();
    let admission = processing_wallet_admission_fixture_provider(
        &transaction,
        &context,
        &authority,
        &account_secret,
        Some(&provider),
    );
    account_secret.fill(0);
    let receipt = process_rpc(
        rpc_address,
        "synergy_submitProcessingTransactionV1",
        serde_json::to_value(&admission).unwrap(),
    )
    .unwrap();
    eprintln!("APQE actual encrypted admission receipt={receipt}");
    let finality_deadline = Instant::now() + Duration::from_secs(180);
    let qualified_height = loop {
        let current_receipt = process_rpc(
            rpc_address,
            "synergy_getProtectedAdmissionReceipt",
            serde_json::json!({"receipt_id":receipt["receipt_id"]}),
        )
        .unwrap();
        assert!(
            !matches!(
                current_receipt["lifecycle_status"].as_str(),
                Some("rejected" | "failed")
            ),
            "immutable encrypted admission was terminally rejected: {current_receipt}"
        );
        let observed: Vec<_> = prepared
            .configurations
            .iter()
            .map(|config| {
                process_rpc(
                    config.rpc.listen_address.unwrap(),
                    "synergy_chainTelemetry",
                    serde_json::json!({}),
                )
            })
            .collect();
        if observed.iter().all(Result::is_ok) {
            let height = observed
                .iter()
                .map(|v| {
                    v.as_ref().unwrap()["finalized_height"]
                        .as_u64()
                        .unwrap_or(0)
                })
                .min()
                .unwrap();
            if height >= transaction_height.max(3) {
                let commitments: Vec<_> = prepared
                    .configurations
                    .iter()
                    .map(|config| {
                        process_rpc(
                            config.rpc.listen_address.unwrap(),
                            "synergy_chainTelemetry",
                            serde_json::json!({"at_height":height}),
                        )
                        .unwrap()["common_finalized_commitment"]
                            .clone()
                    })
                    .collect();
                assert!(!commitments[0].is_null());
                assert!(
                    commitments.iter().all(|v| v == &commitments[0]),
                    "durable state/finality disagree at same height: {commitments:?}"
                );
                let mut applied = 0;
                for config in &prepared.configurations {
                    let address = config.rpc.listen_address.unwrap();
                    let sender=process_rpc(address,"synergy_getAccount",serde_json::json!({"address":transaction.unsigned.sender,"at_height":height})).unwrap();
                    let receiver=process_rpc(address,"synergy_getAccount",serde_json::json!({"address":transaction.unsigned.receiver,"at_height":height})).unwrap();
                    if sender["nonce"].as_u64() == Some(0) {
                        continue;
                    }
                    assert_eq!(
                        sender["nonce"], 1,
                        "encrypted transaction must execute exactly once"
                    );
                    applied += 1;
                    assert_eq!(
                        receiver["balance_nwei"],
                        transaction.unsigned.amount_nwei.to_string(),
                        "actual encrypted transaction effect missing"
                    );
                }
                if applied == 5 {
                    eprintln!("APQE actual five-process encrypted transaction+matching finality/state PASS height={height} commitment={} elapsed={:?}",commitments[0],Instant::now().duration_since(finality_deadline-Duration::from_secs(180)));
                    break height;
                }
            }
        }
        let progress:Vec<_>=observed.iter().map(|value| match value {
            Ok(v)=>serde_json::json!({"finalized_height":v["finalized_height"],"consensus":v["chain"]["consensus"],"transport":v["transport"],"preparation":v["preparation"],"resource_budget":v["resource_budget"]}),
            Err(e)=>serde_json::json!({"rpc_error":e})
        }).collect();
        assert!(
            Instant::now() < finality_deadline,
            "five-process finality deadline: {progress:?}"
        );
        for (index, child) in cleanup.children.iter_mut().enumerate() {
            assert!(
                child.try_wait().unwrap().is_none(),
                "node {index} exited during finality"
            );
        }
        std::thread::sleep(Duration::from_millis(1000));
    };
    recovery::qualify_restart(
        &binary,
        &mut cleanup.children,
        &prepared.configurations,
        qualified_height,
        &transaction,
    );
}

#[path = "socket_qualification_secure_recovery.rs"]
mod recovery;

fn process_rpc(
    address: std::net::SocketAddr,
    method: &str,
    params: serde_json::Value,
) -> Result<serde_json::Value, String> {
    use std::io::{Read, Write};
    let body = serde_json::to_vec(
        &serde_json::json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}),
    )
    .unwrap();
    let mut socket = std::net::TcpStream::connect_timeout(&address, Duration::from_secs(2))
        .map_err(|e| e.to_string())?;
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    socket
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    write!(socket,"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len()).map_err(|e|e.to_string())?;
    socket.write_all(&body).map_err(|e| e.to_string())?;
    let mut response = Vec::new();
    socket
        .take(4 * 1024 * 1024)
        .read_to_end(&mut response)
        .map_err(|e| e.to_string())?;
    let split = response
        .windows(4)
        .position(|v| v == b"\r\n\r\n")
        .ok_or("missing HTTP body")?
        + 4;
    let value: serde_json::Value =
        serde_json::from_slice(&response[split..]).map_err(|e| e.to_string())?;
    if value.get("error").is_some() {
        return Err(value.to_string());
    }
    Ok(value["result"].clone())
}

/// Owns only newly created engineering output; failed exports never leave keys.
struct ExportCleanup(Option<PathBuf>);
impl Drop for ExportCleanup {
    fn drop(&mut self) {
        if let Some(path) = &self.0 {
            let _ = fs::remove_dir_all(path);
        }
    }
}
fn export_path(name: &str) -> PathBuf {
    let path = PathBuf::from(std::env::var(name).expect(name));
    assert!(
        path.is_absolute() && path.parent().is_some(),
        "absolute non-root path required"
    );
    assert!(
        path.components()
            .all(|v| !matches!(v, std::path::Component::ParentDir)),
        "parent traversal forbidden"
    );
    path
}
fn private_directory(path: &Path) {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    assert!(!path.exists(), "fresh private output required");
    for ancestor in path.ancestors().skip(1) {
        assert!(!ancestor.is_symlink(), "symlink ancestor forbidden");
    }
    fs::DirBuilder::new().mode(0o700).create(path).unwrap();
    assert_eq!(
        fs::metadata(path).unwrap().permissions().mode() & 0o777,
        0o700
    );
}
fn export_provider() -> ApqeProviderConfiguration {
    ApqeProviderConfiguration {
        report_path: export_path("APQE_TRUSTED_NATIVE_REPORT"),
        authenticated_report_sha256: std::env::var("APQE_AUTHENTICATED_REPORT_SHA256").unwrap(),
    }
}
fn vpn_endpoints(name: &str) -> [std::net::SocketAddr; 5] {
    let endpoints: [std::net::SocketAddr; 5] =
        serde_json::from_str(&std::env::var(name).expect(name)).unwrap();
    let mut distinct = std::collections::BTreeSet::new();
    for endpoint in endpoints {
        assert!(endpoint.port() != 0 && distinct.insert(endpoint));
        assert!(
            matches!(endpoint.ip(),std::net::IpAddr::V4(ip) if ip.octets()[..2] == [10,69]),
            "literal Val2-Val6 VPN endpoint required"
        );
    }
    assert_eq!(
        endpoints
            .iter()
            .map(|v| v.ip())
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        5
    );
    endpoints
}
fn relocate_configuration(
    config: &NodeConfiguration,
    source: &Path,
    target: &Path,
) -> NodeConfiguration {
    // Replace only exact path components rooted at this fixture, never substrings.
    fn visit(value: &mut serde_json::Value, source: &Path, target: &Path) {
        match value {
            serde_json::Value::String(text) => {
                if let Ok(relative) = Path::new(text).strip_prefix(source) {
                    *text = target.join(relative).to_str().unwrap().into();
                }
            }
            serde_json::Value::Array(values) => {
                values.iter_mut().for_each(|v| visit(v, source, target))
            }
            serde_json::Value::Object(values) => {
                values.values_mut().for_each(|v| visit(v, source, target))
            }
            _ => {}
        }
    }
    let mut value = serde_json::to_value(config).unwrap();
    visit(&mut value, source, target);
    serde_json::from_value(value).unwrap()
}
const EXPORT_PUBLIC: &[&str] = &[
    "manifest.json",
    "genesis.sgen",
    "authority.json",
    "trust.pub",
    "registry.json",
    "registry-root.pub",
];

#[test]
#[ignore = "explicit fresh private APQE VPN fixture export; starts no services"]
fn export_apqe_vpn_canary_fixture() {
    use synergy_address_engine::apqe::SecretBytes;
    let output = export_path("SYNERGY_APQE_EXPORT_ROOT");
    let remote = export_path("SYNERGY_APQE_REMOTE_ROOT");
    let endpoints = vpn_endpoints("SYNERGY_APQE_VPN_ENDPOINTS");
    let rpc_endpoints: [std::net::SocketAddr; 5] =
        serde_json::from_str(&std::env::var("SYNERGY_APQE_REMOTE_RPC_ENDPOINTS").unwrap()).unwrap();
    assert!(rpc_endpoints
        .iter()
        .all(|v| v.ip().is_loopback() && v.port() != 0));
    let remote_provider = ApqeProviderConfiguration {
        report_path: export_path("SYNERGY_APQE_REMOTE_NATIVE_REPORT"),
        authenticated_report_sha256: std::env::var("SYNERGY_APQE_REMOTE_REPORT_SHA256").unwrap(),
    };
    assert!(
        remote_provider.authenticated_report_sha256.len() == 64
            && remote_provider
                .authenticated_report_sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    );
    let provider = export_provider();
    let chain_id: u64 = std::env::var("SYNERGY_APQE_EXPORT_CHAIN_ID")
        .unwrap_or_else(|_| "1266".into())
        .parse()
        .expect("unsigned explicit chain ID");
    assert!(chain_id > 0);
    private_directory(&output);
    let mut cleanup = ExportCleanup(Some(output.clone()));
    let network_id = format!("posy-apqe-canary-process-{}", std::process::id());
    let (transaction, world, secret_key) = funded_transaction_fixture_for_network_provider_chain(
        &network_id,
        10_000_000,
        Some(&provider),
        chain_id,
    );
    let secret_key = SecretBytes::from_bytes(secret_key);
    let prepared = prepare_socket_fixture_profile_mode_endpoints(
        world,
        None,
        true,
        None,
        Some(&provider),
        true,
        Some(&endpoints),
        chain_id,
    );
    let _fixture_cleanup = ExportCleanup(Some(prepared.root.clone()));
    let wallet = output.join("local-wallet");
    private_directory(&wallet);
    for public in EXPORT_PUBLIC {
        fs::copy(prepared.root.join(public), wallet.join(public)).unwrap();
    }
    // The local wallet retains public authenticated context and one ML-DSA-87
    // secret only. Validator custody/unlock material never enters this directory.
    private_directory(&wallet.join("node-0"));
    fs::copy(
        prepared.root.join("node-0/identity.json"),
        wallet.join("node-0/identity.json"),
    )
    .unwrap();
    let wallet_config =
        relocate_configuration(&prepared.configurations[0], &prepared.root, &wallet);
    write_json(&wallet.join("config.json"), &wallet_config);
    write_json(&wallet.join("transaction.json"), &transaction);
    secret(&wallet.join("account.key"), secret_key.as_bytes());
    for (index, config) in prepared.configurations.iter().enumerate() {
        // Actual local provider/custody/public trust checks precede transformation.
        super::super::apqe_transport::preflight(config).unwrap();
        authority::load(config).unwrap().unwrap();
        let bundle = output.join(format!("node-{index}"));
        private_directory(&bundle);
        private_directory(&bundle.join("network"));
        private_directory(&bundle.join("keys"));
        private_directory(&bundle.join("keys/apqe"));
        private_directory(&bundle.join("config"));
        for (source, destination) in [
            ("manifest.json", "network-manifest.json"),
            ("genesis.sgen", "genesis.json"),
            ("authority.json", "authority.json"),
            ("trust.pub", "authority-root.pub"),
            ("registry.json", "transport-registry.json"),
            ("registry-root.pub", "transport-root.pub"),
        ] {
            fs::copy(
                prepared.root.join(source),
                bundle.join("network").join(destination),
            )
            .unwrap();
        }
        let own = format!("node-{index}");
        for (source, destination) in [
            ("identity.json", "validator.pub.json"),
            ("enrollment.json", "enrollment.json"),
            ("custody.json", "custody.json"),
            ("unlock", "unlock"),
        ] {
            let bytes =
                SecretBytes::from_bytes(fs::read(prepared.root.join(&own).join(source)).unwrap());
            secret(
                &bundle.join("keys/apqe").join(destination),
                bytes.as_bytes(),
            );
        }
        let mut config = config.clone();
        config.manifest_path = remote.join("network/network-manifest.json");
        config.genesis_path = Some(remote.join("network/genesis.json"));
        config.public_identity_path = remote.join("keys/apqe/validator.pub.json");
        config.consensus.authority_binding = Some(remote.join("network/authority.json"));
        config.consensus.authority_trust_key_path = Some(remote.join("network/authority-root.pub"));
        config.storage.data_directory = remote.join("data");
        config.admin_socket_path = remote.join("run/admin.sock");
        config.node_name = format!("validator-{:02}", index + 2);
        config.storage.minimum_free_bytes = 2 * 1024 * 1024 * 1024;
        let transport = config.apqe_transport.as_mut().unwrap();
        transport.registry_path = remote.join("network/transport-registry.json");
        transport.registry_trust_key_path = remote.join("network/transport-root.pub");
        transport.enrollment_path = remote.join("keys/apqe/enrollment.json");
        transport.custody_path = remote.join("keys/apqe/custody.json");
        transport.custody_unlock_path = remote.join("keys/apqe/unlock");
        config.aegis_provider = Some(remote_provider.clone());
        config.network.listen_addresses = vec![endpoints[index]];
        config.network.advertised_addresses = vec![endpoints[index]];
        config.rpc.listen_address = Some(rpc_endpoints[index]);
        config.validate().unwrap();
        assert!(
            config.aegis_signing_key_path.is_none()
                && config.consensus.signing_key_path.is_none()
                && config.etdag.ingress_kem_secret_key_path.is_none()
        );
        write_json(&bundle.join("config/node.json"), &config);
    }
    write_json(
        &output.join("export.json"),
        &serde_json::json!({
            "schema":"apqe-vpn-engineering-export-v1", "network_id":network_id, "chain_id":chain_id,
            "remote_root":remote,"vpn_endpoints":endpoints,"rpc_endpoints":rpc_endpoints,
            "remote_provider":remote_provider,"services_started":false,
            "production_approved":false,"wallet_private_directory":"local-wallet",
            "node_bundles":["node-0","node-1","node-2","node-3","node-4"]
        }),
    );
    cleanup.0 = None;
    eprintln!("APQE five VPN-node private bundles exported; no services started");
}

fn read_export_bounded(path: &Path, max: usize) -> synergy_address_engine::apqe::SecretBytes {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .unwrap();
    assert!(file.metadata().unwrap().is_file());
    let mut bytes = Vec::new();
    file.take(max as u64 + 1).read_to_end(&mut bytes).unwrap();
    let bytes = synergy_address_engine::apqe::SecretBytes::from_bytes(bytes);
    assert!(bytes.as_bytes().len() <= max, "export input exceeds bound");
    bytes
}

#[test]
#[ignore = "explicit saved fleet ProcessingContext to encrypted admission; no submission"]
fn generate_apqe_vpn_canary_request() {
    use std::os::unix::fs::PermissionsExt;
    let output = export_path("SYNERGY_APQE_EXPORT_ROOT");
    let wallet = output.join("local-wallet");
    assert_eq!(
        fs::symlink_metadata(&wallet).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert!(!wallet.is_symlink());
    let context_path = export_path("SYNERGY_APQE_PROCESSING_CONTEXT");
    let bytes = read_export_bounded(&context_path, 1024 * 1024);
    let value: serde_json::Value = serde_json::from_slice(bytes.as_bytes()).unwrap();
    let context: synergy_etdag::ProcessingContext =
        serde_json::from_value(value.get("context").unwrap_or(&value).clone()).unwrap();
    context.validate().unwrap();
    let mut config: NodeConfiguration =
        serde_json::from_slice(&fs::read(wallet.join("config.json")).unwrap()).unwrap();
    let provider = export_provider();
    config.aegis_provider = Some(provider.clone());
    let authority = authority::load(&config).unwrap().unwrap();
    let transaction: synergy_transaction::SignedTransaction =
        serde_json::from_slice(&fs::read(wallet.join("transaction.json")).unwrap()).unwrap();
    assert_eq!(context.authority.chain_id, config.chain_id);
    assert_eq!(context.authority.network_id, config.network_id);
    assert_eq!(context.authority.epoch, authority.epoch.epoch);
    assert_eq!(
        context.authority.ingress_kem_registry_root,
        authority
            .protected_ingress_registry()
            .unwrap()
            .root()
            .unwrap()
    );
    assert_eq!(
        context.authority.active_validator_set_root,
        authority.epoch.active_validator_set_root
    );
    let path = wallet.join("account.key");
    let metadata = fs::symlink_metadata(&path).unwrap();
    assert!(metadata.is_file() && !metadata.file_type().is_symlink());
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    assert!(metadata.len() <= 8192);
    let key = read_export_bounded(&path, 8192);
    let admission = processing_wallet_admission_fixture_provider(
        &transaction,
        &context,
        &authority,
        key.as_bytes(),
        Some(&provider),
    );
    admission.request.validate_context(&context).unwrap();
    let request_path = output.join("encrypted-admission.json");
    // create_new prevents accidental regeneration/overwrite of an immutable intent.
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let encoded = serde_json::to_vec(&admission).unwrap();
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&request_path)
        .unwrap();
    struct PartialRequest(Option<PathBuf>);
    impl Drop for PartialRequest {
        fn drop(&mut self) {
            if let Some(path) = &self.0 {
                let _ = fs::remove_file(path);
            }
        }
    }
    let mut cleanup = PartialRequest(Some(request_path));
    file.write_all(&encoded).unwrap();
    file.sync_all().unwrap();
    cleanup.0 = None;
    eprintln!("APQE encrypted admission generated; not submitted");
}
