//! Public-only R11 qualification assembler.
//!
//! This tool never generates, decrypts, or signs key material.  Its `genesis`
//! mode is deliberately restricted to `LOCAL_R11_QUALIFICATION`: it converts
//! the exact checked proposal named by a local decision record into a canonical
//! finalized manifest, installs Aegis-engine public consensus keys in every
//! Genesis authority location, atomically binds consensus and ETDAG governance,
//! and proves acceptance through the production Genesis loader.  `registries`
//! converts engine-issued public ML-KEM bundles into the exact durable runtime
//! artifact schema and reads every result back through the production source.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};
use sha3::Sha3_512;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use synergy_testnet::consensus::simplified_posy::{
    load_genesis_bound_simplified_activation, simplified_target_admission_assignment,
    DurableSimplifiedIngressKemRegistrySource, GenesisBoundSimplifiedActivation,
    SimplifiedIngressKemRegistryArtifact, SimplifiedIngressKemRegistrySource,
    SIMPLIFIED_INGRESS_KEM_REGISTRY_ARTIFACT_FORMAT,
};
use synergy_testnet::consensus_parameters::{
    load_finalized_consensus_parameters_from_bytes, FinalizedConsensusParameterManifest,
};
use synergy_testnet::etdag::{
    IngressKemKeyRecord, IngressKemKeyRegistry, INGRESS_KEM_REGISTRY_VERSION,
};
use synergy_testnet::etdag_governance::EtdagGovernedGenesisBinding;
use synergy_testnet::genesis::{
    bind_testnet_v3_genesis_simplified_posy_authorities, load_genesis_from_path,
};
use synergy_testnet::posy_simplified_parameters::{
    SimplifiedConsensusParameterManifest, POSY_SIMPLIFIED_PARAMETER_FINALIZED_STATUS,
    POSY_SIMPLIFIED_PARAMETER_PROPOSAL_STATUS,
};
use synergy_testnet::synergy_types::{
    ChainId, ClusterMap, Epoch, Height, NetworkId, ValidatorId,
    TESTNET_V3_MLDSA65_PUBLIC_KEY_BYTES,
};

const ENVIRONMENT: &str = "LOCAL_R11_QUALIFICATION";
const LOCAL_DECISION_SCHEMA: &str = "synergy-local-r11-qualification-consensus-decision-v1";
const LOCAL_DECISION_STATUS: &str = "FINALIZED_FOR_LOCAL_QUALIFICATION_ONLY";
const PUBLIC_KEM_BUNDLE_SCHEMA: &str = "local-r11-qualification-ingress-kem-public-bundle";
const VALIDATORS: [&str; 5] = [
    "validator-02",
    "validator-03",
    "validator-04",
    "validator-05",
    "validator-06",
];

fn usage() -> ! {
    eprintln!(
        "usage:\n  assemble-local-r11-public-artifacts genesis --source-genesis PATH --proposed-manifest PATH --local-decision PATH --activation-template PATH --validator-public-dir DIR --etdag-binding PATH --finalized-manifest-output PATH --output PATH\n  assemble-local-r11-public-artifacts registries --genesis PATH --public-kem-bundle-dir DIR --output-dir DIR"
    );
    std::process::exit(2);
}

fn fail(message: impl AsRef<str>) -> ! {
    eprintln!("assemble-local-r11-public-artifacts: {}", message.as_ref());
    std::process::exit(1);
}

fn arg_path(args: &[String], flag: &str) -> PathBuf {
    args.windows(2)
        .find(|pair| pair[0] == flag)
        .map(|pair| PathBuf::from(&pair[1]))
        .unwrap_or_else(|| usage())
}

fn require_flags(args: &[String], flags: &[&str]) {
    if args.len() != 1 + flags.len() * 2 {
        usage();
    }
    for flag in flags {
        if args.iter().filter(|value| value.as_str() == *flag).count() != 1 {
            usage();
        }
    }
}

fn read_bytes(path: &Path, label: &str) -> Result<Vec<u8>, String> {
    fs::read(path).map_err(|error| format!("read {label} {}: {error}", path.display()))
}

fn read_value(path: &Path, label: &str) -> Result<Value, String> {
    serde_json::from_slice(&read_bytes(path, label)?)
        .map_err(|error| format!("decode {label} {}: {error}", path.display()))
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("create {}: {error}", parent.display()))?;
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| format!("create new output {}: {error}", path.display()))?;
    file.write_all(bytes)
        .map_err(|error| format!("write {}: {error}", path.display()))?;
    file.sync_all()
        .map_err(|error| format!("sync {}: {error}", path.display()))
}

fn lower_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

fn sha256(bytes: &[u8]) -> String {
    lower_hex(&Sha256::digest(bytes))
}

fn sha3_512(bytes: &[u8]) -> String {
    lower_hex(&Sha3_512::digest(bytes))
}

#[derive(Debug, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct LocalDecision {
    schema: String,
    environment: String,
    status: String,
    governance_approval_id: String,
    proposed_manifest_sha256: String,
}

fn finalized_local_manifest(
    proposed_bytes: &[u8],
    decision_bytes: &[u8],
) -> Result<(Vec<u8>, String), String> {
    let decision: LocalDecision = serde_json::from_slice(decision_bytes)
        .map_err(|error| format!("decode LOCAL_R11 decision: {error}"))?;
    if serde_json::to_vec(&decision)
        .map_err(|error| format!("canonicalize LOCAL_R11 decision: {error}"))?
        != decision_bytes
    {
        return Err("LOCAL_R11 decision is not canonical JSON".to_string());
    }
    if decision.schema != LOCAL_DECISION_SCHEMA
        || decision.environment != ENVIRONMENT
        || decision.status != LOCAL_DECISION_STATUS
        || !decision
            .governance_approval_id
            .starts_with("LOCAL-R11-QUALIFICATION-")
        || decision.proposed_manifest_sha256 != sha256(proposed_bytes)
    {
        return Err("LOCAL_R11 decision does not bind the exact proposal/environment".to_string());
    }
    let mut manifest: SimplifiedConsensusParameterManifest =
        serde_json::from_slice(proposed_bytes)
            .map_err(|error| format!("decode R11 proposal manifest: {error}"))?;
    manifest.validate_proposal()?;
    if manifest.status != POSY_SIMPLIFIED_PARAMETER_PROPOSAL_STATUS
        || manifest.target_block_time_ms != 500
        || manifest.governance_approval_id.is_some()
        || manifest.activation_epoch.is_some()
        || manifest.activation_height.is_some()
    {
        return Err("LOCAL_R11 input must be the exact unactivated 500ms proposal".to_string());
    }
    manifest.status = POSY_SIMPLIFIED_PARAMETER_FINALIZED_STATUS.to_string();
    manifest.governance_approval_id = Some(decision.governance_approval_id);
    manifest.activation_epoch = Some(0);
    manifest.activation_height = Some(1);
    let bytes = manifest.canonical_bytes()?;
    let loaded = load_finalized_consensus_parameters_from_bytes(&bytes)?;
    Ok((bytes, loaded.root.to_hex()))
}

#[derive(Debug, Clone)]
struct ConsensusPublicBundle {
    validator_id: String,
    key_bytes: Vec<u8>,
}

fn public_string<'a>(value: &'a Value, field: &str, label: &str) -> Result<&'a str, String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{label} has no string {field}"))
}

fn read_consensus_public_bundles(directory: &Path) -> Result<Vec<ConsensusPublicBundle>, String> {
    let mut bundles = Vec::new();
    for expected_id in VALIDATORS {
        let path = directory.join(expected_id).join("public.json");
        let value = read_value(&path, "engine validator public bundle")?;
        let validator_id = public_string(&value, "validator_id", expected_id)?;
        let algorithm = public_string(&value, "consensus_algorithm", expected_id)?;
        let key_hex = public_string(&value, "consensus_public_key_hex", expected_id)?;
        let declared_hash = public_string(
            &value,
            "consensus_public_key_sha3_512",
            expected_id,
        )?;
        let key_bytes = hex::decode(key_hex)
            .map_err(|error| format!("decode {expected_id} consensus public key: {error}"))?;
        if validator_id != expected_id
            || !matches!(algorithm, "ML-DSA-65" | "mldsa65")
            || key_bytes.len() != TESTNET_V3_MLDSA65_PUBLIC_KEY_BYTES
            || declared_hash != sha3_512(&key_bytes)
        {
            return Err(format!("{expected_id} engine consensus public bundle is invalid"));
        }
        bundles.push(ConsensusPublicBundle {
            validator_id: validator_id.to_string(),
            key_bytes,
        });
    }
    Ok(bundles)
}

fn replace_flat_validator_keys(
    validators: &mut Value,
    bundles: &BTreeMap<String, Vec<u8>>,
    label: &str,
) -> Result<(), String> {
    let validators = validators
        .as_array_mut()
        .ok_or_else(|| format!("{label} is not an array"))?;
    let mut seen = BTreeSet::new();
    for validator in validators {
        let id = validator
            .get("validator_id")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("{label} record has no validator_id"))?
            .to_string();
        let Some(key) = bundles.get(&id) else {
            continue;
        };
        validator["consensus_key_type"] = Value::String("ML-DSA-65".to_string());
        validator["consensus_public_key"] = Value::String(BASE64.encode(key));
        seen.insert(id);
    }
    if seen != bundles.keys().cloned().collect() {
        return Err(format!("{label} does not contain the exact five LOCAL_R11 validators"));
    }
    Ok(())
}

fn install_consensus_public_keys(
    candidate: &mut Value,
    activation: &mut GenesisBoundSimplifiedActivation,
    bundles: &[ConsensusPublicBundle],
) -> Result<(), String> {
    let by_id = bundles
        .iter()
        .map(|bundle| (bundle.validator_id.clone(), bundle.key_bytes.clone()))
        .collect::<BTreeMap<_, _>>();
    if by_id.len() != VALIDATORS.len() {
        return Err("engine consensus public bundle contains duplicate validators".to_string());
    }
    replace_flat_validator_keys(&mut candidate["validators"], &by_id, "Genesis validators")?;
    replace_flat_validator_keys(
        &mut candidate["contracts"]["validator_registry"]["init_params"]["validators"],
        &by_id,
        "validator-registry init validators",
    )?;
    let mut seen = BTreeSet::new();
    for validator in &mut activation.frozen_validator_set.validators {
        let id = validator.validator_id.0.clone();
        let key = by_id
            .get(&id)
            .ok_or_else(|| format!("activation carries unexpected validator {id}"))?;
        validator.consensus_public_key.algorithm = "mldsa65".to_string();
        validator.consensus_public_key.key_bytes = key.clone();
        seen.insert(id);
    }
    if seen != by_id.keys().cloned().collect() {
        return Err("activation does not contain the exact five engine validators".to_string());
    }
    Ok(())
}

fn assemble_genesis(args: &[String]) -> Result<(), String> {
    const FLAGS: [&str; 8] = [
        "--source-genesis",
        "--proposed-manifest",
        "--local-decision",
        "--activation-template",
        "--validator-public-dir",
        "--etdag-binding",
        "--finalized-manifest-output",
        "--output",
    ];
    require_flags(args, &FLAGS);
    let source_path = arg_path(args, "--source-genesis");
    let proposal_path = arg_path(args, "--proposed-manifest");
    let decision_path = arg_path(args, "--local-decision");
    let activation_path = arg_path(args, "--activation-template");
    let public_dir = arg_path(args, "--validator-public-dir");
    let etdag_path = arg_path(args, "--etdag-binding");
    let manifest_output = arg_path(args, "--finalized-manifest-output");
    let output = arg_path(args, "--output");

    let proposal_bytes = read_bytes(&proposal_path, "R11 proposal manifest")?;
    let decision_bytes = read_bytes(&decision_path, "LOCAL_R11 decision")?;
    let (manifest_bytes, parameter_root) =
        finalized_local_manifest(&proposal_bytes, &decision_bytes)?;
    let loaded = load_finalized_consensus_parameters_from_bytes(&manifest_bytes)?;
    let manifest = match &loaded.manifest {
        FinalizedConsensusParameterManifest::SimplifiedPoSyV3(manifest) => manifest.clone(),
        _ => return Err("LOCAL_R11 manifest is not simplified PoSy v3".to_string()),
    };
    let mut activation: GenesisBoundSimplifiedActivation = serde_json::from_slice(
        &read_bytes(&activation_path, "activation template")?,
    )
    .map_err(|error| format!("decode activation template: {error}"))?;
    activation.manifest = manifest;
    activation.parameter_root_sha3_512 = parameter_root.clone();
    activation.governance_decision_id = activation
        .manifest
        .finalized_governance_approval_id()?
        .to_string();
    activation.activation_epoch = 0;
    activation.activation_height = 1;
    activation.binding_status = "FINALIZED_AND_GENESIS_BOUND".to_string();

    let bundles = read_consensus_public_bundles(&public_dir)?;
    let mut candidate = read_value(&source_path, "fresh P3 source Genesis")?;
    install_consensus_public_keys(&mut candidate, &mut activation, &bundles)?;
    activation.validate()?;
    let etdag_binding = EtdagGovernedGenesisBinding::from_canonical_bytes(&read_bytes(
        &etdag_path,
        "ETDAG Genesis binding",
    )?)?;
    let decision_sha256 = sha256(&decision_bytes);
    bind_testnet_v3_genesis_simplified_posy_authorities(
        &mut candidate,
        &loaded,
        &decision_sha256,
        &activation,
        &etdag_binding,
    )?;
    candidate["r11_qualification_candidate"] = json!({
        "environment": ENVIRONMENT,
        "status": "FINALIZED_FOR_LOCAL_QUALIFICATION_ONLY_NOT_LIVE_DEPLOYMENT_AUTHORITY",
        "target_block_time_ms": 500,
        "local_decision_sha256": decision_sha256,
    });
    let mut encoded = serde_json::to_vec_pretty(&candidate)
        .map_err(|error| format!("encode LOCAL_R11 Genesis: {error}"))?;
    encoded.push(b'\n');
    write_new(&manifest_output, &manifest_bytes)?;
    write_new(&output, &encoded)?;
    let checked = load_genesis_from_path(&output)
        .map_err(|error| format!("production loader rejected emitted Genesis: {error}"))?;
    println!("LOCAL_R11_FINALIZED_MANIFEST=YES");
    println!("LOCAL_R11_ENGINE_KEYS_BOUND=YES");
    println!("LOCAL_R11_ATOMIC_CONSENSUS_ETDAG_BINDING=YES");
    println!("LOCAL_R11_GENESIS_RUNTIME_LOAD=YES");
    println!("GENESIS_HASH={}", checked.hash());
    println!("EPOCH_CONTEXT_ROOT={}", activation.derive_fresh_genesis_epoch_context()?.root()?.to_hex());
    Ok(())
}

#[derive(Debug, Deserialize)]
struct PublicKemBundle {
    schema_version: u32,
    artifact_type: String,
    environment: String,
    chain_id: u64,
    runtime_network_id: String,
    protocol_version: String,
    target_height: u64,
    genesis_sha3_512: String,
    records: Vec<PublicKemRecord>,
    authority_signature: Value,
    validator_signatures: Vec<Value>,
}

#[derive(Debug, Deserialize)]
struct PublicKemRecord {
    validator_id: String,
    target_height: u64,
    algorithm: String,
    public_key_hex: String,
    public_key_sha3_512: String,
    custody_file: String,
}

fn ingress_key_id(height: Height, validator_id: &str, public_key_sha3_512: &str) -> String {
    format!(
        "local-r11:epoch-0:height-{}:validator-{}:{}",
        height.0,
        validator_id,
        public_key_sha3_512
    )
}

fn load_public_kem_bundle(path: &Path, height: Height) -> Result<PublicKemBundle, String> {
    let bundle: PublicKemBundle = serde_json::from_slice(&read_bytes(path, "public KEM bundle")?)
        .map_err(|error| format!("decode public KEM bundle {}: {error}", path.display()))?;
    if bundle.schema_version != 1
        || bundle.artifact_type != PUBLIC_KEM_BUNDLE_SCHEMA
        || bundle.environment != ENVIRONMENT
        || bundle.chain_id != 1266
        || bundle.runtime_network_id != "testnet"
        || bundle.protocol_version != "posy/3.0"
        || bundle.target_height != height.0
        || bundle.genesis_sha3_512.len() != 128
        || bundle.authority_signature.is_null()
        || bundle.validator_signatures.len() != VALIDATORS.len()
    {
        return Err(format!("H{} public KEM bundle envelope is invalid", height.0));
    }
    Ok(bundle)
}

fn registry_from_bundle(
    bundle: PublicKemBundle,
    height: Height,
    epoch_context: &synergy_testnet::consensus::simplified_posy::SimplifiedEpochContext,
    cluster_map: &ClusterMap,
    active_ids: &BTreeSet<String>,
) -> Result<IngressKemKeyRegistry, String> {
    let (cluster_id, _) = simplified_target_admission_assignment(epoch_context, height, cluster_map)?;
    let mut records = bundle.records;
    records.sort_by(|left, right| left.validator_id.cmp(&right.validator_id));
    let found_ids = records
        .iter()
        .map(|record| record.validator_id.clone())
        .collect::<BTreeSet<_>>();
    if records.len() != active_ids.len() || found_ids != *active_ids {
        return Err(format!("H{} public KEM bundle is not the exact active set", height.0));
    }
    let records = records
        .into_iter()
        .enumerate()
        .map(|(position, record)| {
            let key_bytes = hex::decode(&record.public_key_hex).map_err(|error| {
                format!("decode H{} {} ML-KEM key: {error}", height.0, record.validator_id)
            })?;
            if record.target_height != height.0
                || record.algorithm != "ML-KEM-1024"
                || record.custody_file.trim().is_empty()
                || record.public_key_sha3_512 != sha3_512(&key_bytes)
            {
                return Err(format!(
                    "H{} {} public KEM record is invalid",
                    height.0, record.validator_id
                ));
            }
            Ok(IngressKemKeyRecord {
                validator_id: ValidatorId(record.validator_id.clone()),
                ingress_key_id: ingress_key_id(
                    height,
                    &record.validator_id,
                    &record.public_key_sha3_512,
                ),
                share_index: u8::try_from(position + 1)
                    .map_err(|_| "LOCAL_R11 share index overflow".to_string())?,
                key_bytes,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let registry = IngressKemKeyRegistry {
        registry_version: INGRESS_KEM_REGISTRY_VERSION,
        chain_id: ChainId::synergy_testnet_v3(),
        network_id: NetworkId::fresh_posy_testnet_v3(),
        protocol_version: "posy/3.0".to_string(),
        epoch: Epoch(0),
        target_height: height,
        assigned_cluster_id: cluster_id,
        records,
    };
    registry.validate_shape()?;
    Ok(registry)
}

fn assemble_registries(args: &[String]) -> Result<(), String> {
    const FLAGS: [&str; 3] = ["--genesis", "--public-kem-bundle-dir", "--output-dir"];
    require_flags(args, &FLAGS);
    let genesis_path = arg_path(args, "--genesis");
    let bundle_dir = arg_path(args, "--public-kem-bundle-dir");
    let output_dir = arg_path(args, "--output-dir");
    let genesis = load_genesis_from_path(&genesis_path)
        .map_err(|error| format!("production loader rejected registry Genesis: {error}"))?;
    let activation = load_genesis_bound_simplified_activation(genesis.value())?
        .ok_or_else(|| "registry Genesis has no simplified activation".to_string())?;
    let context = activation.derive_fresh_genesis_epoch_context()?;
    let active = activation.frozen_validator_set.active_for_epoch(Epoch(0));
    let cluster_map = ClusterMap::derive_from_finalized_epoch_seed(
        &active,
        context.finalized_epoch_seed_root,
    )?;
    cluster_map.validate_complete_balanced_assignment(&active)?;
    let epoch_root = context.root()?;
    let active_ids = active
        .validators
        .iter()
        .map(|validator| validator.validator_id.0.clone())
        .collect::<BTreeSet<_>>();
    let context_path = output_dir.join("epoch-context.json");
    let cluster_path = output_dir.join("cluster-map.json");
    write_new(
        &context_path,
        &serde_json::to_vec(&context)
            .map_err(|error| format!("encode epoch context: {error}"))?,
    )?;
    write_new(
        &cluster_path,
        &serde_json::to_vec(&cluster_map)
            .map_err(|error| format!("encode cluster map: {error}"))?,
    )?;
    let mut source = DurableSimplifiedIngressKemRegistrySource::at_directory(
        &output_dir,
        epoch_root,
    )?;
    for raw_height in 3..=20 {
        let height = Height(raw_height);
        let bundle_path = bundle_dir.join(format!("h{raw_height:02}.ingress-kem-public-bundle.json"));
        let bundle = load_public_kem_bundle(&bundle_path, height)?;
        let registry = registry_from_bundle(bundle, height, &context, &cluster_map, &active_ids)?;
        let artifact = SimplifiedIngressKemRegistryArtifact {
            format: SIMPLIFIED_INGRESS_KEM_REGISTRY_ARTIFACT_FORMAT.to_string(),
            epoch_context_root: epoch_root,
            epoch: Epoch(0),
            target_height: height,
            assigned_cluster_id: registry.assigned_cluster_id,
            registry_root: registry.root()?,
            registry: registry.clone(),
        };
        artifact.validate(epoch_root)?;
        let output = source.artifact_path(Epoch(0), height, registry.assigned_cluster_id);
        write_new(
            &output,
            &serde_json::to_vec(&artifact)
                .map_err(|error| format!("encode H{raw_height} registry: {error}"))?,
        )?;
        let loaded = source
            .registry_for_target(Epoch(0), height, registry.assigned_cluster_id)?
            .ok_or_else(|| format!("durable source did not load H{raw_height} registry"))?;
        if loaded != registry {
            return Err(format!("durable H{raw_height} registry round-trip changed material"));
        }
        println!("H{raw_height}_REGISTRY_VALID=YES");
    }
    println!("EPOCH_CONTEXT_ROOT={}", epoch_root.to_hex());
    println!("CLUSTER_MAP_ROOT={}", cluster_map.hash()?.to_hex());
    Ok(())
}

fn run() -> Result<(), String> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    match args.first().map(String::as_str) {
        Some("genesis") => assemble_genesis(&args),
        Some("registries") => assemble_registries(&args),
        _ => usage(),
    }
}

fn main() {
    if let Err(error) = run() {
        fail(error);
    }
}
