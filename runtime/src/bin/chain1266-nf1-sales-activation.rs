use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::Path,
};

use serde_json::json;
use sha2::{Digest, Sha256};
use synergy_testnet::{
    consensus::{
        chain1266_startup_dispatch::{
            LAUNCH_AUTHORITY_ADDRESS, LAUNCH_DIRECTORY_NAMESPACE, LAUNCH_GENESIS_HASH,
            LAUNCH_RELEASE_ID,
        },
        single_authority_finality_store::SINGLE_AUTHORITY_CONSENSUS_PROTOCOL,
        single_authority_startup::{
            StartupExpectation, LAUNCH_AUTHORITY_ID, LAUNCH_CHAIN_ID, LAUNCH_CHAIN_INCARNATION,
            LAUNCH_NETWORK_ID,
        },
    },
    crypto::pqc::PQCAlgorithm,
    desired_state_v2::SignedDesiredStateV2,
    desired_state_v2_canonical::{canonical_bytes, parse_strict_canonical},
    nf1_sales_activation::{
        parse_manifest, verify_installed_activation, ActivationCheckpoint,
        Nf1SalesActivationManifest, ALLOWED_ROLE_BINARIES, AUTHORITY_BINARY,
        MAX_NF1_SALES_ACTIVATION_BYTES, NF1_SALES_ACTIVATION_SCHEMA_VERSION, NF1_SALES_PROTOCOL,
    },
};

const DESIRED: &[u8] = include_bytes!(
    "../../../launch/chain1266-incarnation-5-single-authority-rc1/activation/chain1266-desired-state-v2.json"
);
const SIGNED: &[u8] = include_bytes!(
    "../../../launch/chain1266-incarnation-5-single-authority-rc1/activation/chain1266-start-authorization-v2.json"
);
const MANIFEST_FILE: &str = "chain1266-nf1-sales-activation-v1.json";
const UNSIGNED_DESIRED_FILE: &str = "chain1266-desired-state-v2.unsigned.json";
const AUTHORITY_KEY_FINGERPRINT: &str =
    "sha256:2420c052e15721755608fdf5fc2f5aecb1741d79ef5ab24a72ed4201fd4a056c";
const USAGE: &str = concat!(
    "chain1266-nf1-sales-activation prepare <new-output-directory> <checkpoint-height> ",
    "<checkpoint-block-hash> <checkpoint-state-root> <activation-height> ",
    "synergy-validator-node=<binary> [role=<binary> ...]\n",
    "chain1266-nf1-sales-activation verify <manifest.json> <desired-state.json> ",
    "<signed-start.json> synergy-validator-node=<binary> [role=<binary> ...]",
);

fn expectation() -> StartupExpectation {
    StartupExpectation {
        genesis_chain_id: LAUNCH_CHAIN_ID,
        genesis_chain_incarnation: LAUNCH_CHAIN_INCARNATION,
        genesis_network_id: LAUNCH_NETWORK_ID.into(),
        genesis_hash: LAUNCH_GENESIS_HASH.into(),
        genesis_directory_namespace: LAUNCH_DIRECTORY_NAMESPACE.into(),
        release_id: LAUNCH_RELEASE_ID.into(),
        authority_id: LAUNCH_AUTHORITY_ID.into(),
        authority_public_key_fingerprint: AUTHORITY_KEY_FINGERPRINT.into(),
        authority_key_algorithm: PQCAlgorithm::MLDSA65,
    }
}

fn regular_file(path: &Path) -> Result<File, String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| format!("{path:?}: {error}"))?;
    if !metadata.is_file() || metadata.len() == 0 {
        return Err(format!("Expected a nonempty regular file at {path:?}"));
    }
    File::open(path).map_err(|error| format!("{path:?}: {error}"))
}

fn read_document(path: &Path, limit: usize) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    regular_file(path)?
        .take((limit + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("{path:?}: {error}"))?;
    if bytes.len() > limit {
        return Err(format!("{path:?} exceeds its document size limit"));
    }
    Ok(bytes)
}

fn role_hashes(specifications: &[String]) -> Result<BTreeMap<String, String>, String> {
    let mut hashes = BTreeMap::new();
    for specification in specifications {
        let (role, binary) = specification
            .split_once('=')
            .filter(|(_, binary)| !binary.is_empty())
            .ok_or("Supply each binary as role=path")?;
        if !ALLOWED_ROLE_BINARIES.contains(&role) {
            return Err(format!("Unexpected Chain 1266 role binary {role}"));
        }
        if hashes.contains_key(role) {
            return Err(format!("Duplicate role binary {role}"));
        }
        let path = Path::new(binary);
        let mut digest = Sha256::new();
        std::io::copy(&mut regular_file(path)?, &mut digest)
            .map_err(|error| format!("Hash candidate binary {path:?}: {error}"))?;
        hashes.insert(role.to_owned(), hex::encode(digest.finalize()));
    }
    if !hashes.contains_key(AUTHORITY_BINARY) {
        return Err(format!(
            "Supply the exact {AUTHORITY_BINARY} candidate binary"
        ));
    }
    Ok(hashes)
}

fn height(value: &str) -> Result<u64, String> {
    let parsed = value
        .parse::<u64>()
        .map_err(|_| "Heights must be canonical positive decimal integers")?;
    if parsed == 0 || parsed.to_string() != value {
        return Err("Heights must be canonical positive decimal integers".into());
    }
    Ok(parsed)
}

fn write_draft(path: &Path, bytes: &[u8]) -> Result<(), String> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .and_then(|mut file| {
            file.write_all(bytes)?;
            file.sync_all()
        })
        .map_err(|error| format!("Write {path:?}: {error}"))
}

fn prepare(
    output: &Path,
    checkpoint: ActivationCheckpoint,
    activation_height: u64,
    hashes: BTreeMap<String, String>,
) -> Result<(), String> {
    let signed: SignedDesiredStateV2 =
        serde_json::from_slice(SIGNED).map_err(|error| error.to_string())?;
    if verify_installed_activation(
        None,
        DESIRED,
        &signed,
        &expectation(),
        LAUNCH_AUTHORITY_ADDRESS,
        AUTHORITY_BINARY,
        &hashes[AUTHORITY_BINARY],
    )?
    .is_some()
    {
        return Err("Expected the incumbent signed Chain 1266 start configuration".into());
    }
    let manifest = Nf1SalesActivationManifest {
        schema_version: NF1_SALES_ACTIVATION_SCHEMA_VERSION,
        chain_id: LAUNCH_CHAIN_ID,
        chain_incarnation: LAUNCH_CHAIN_INCARNATION,
        network_id: LAUNCH_NETWORK_ID.into(),
        genesis_hash: LAUNCH_GENESIS_HASH.into(),
        consensus_release_id: LAUNCH_RELEASE_ID.into(),
        consensus_protocol: SINGLE_AUTHORITY_CONSENSUS_PROTOCOL.into(),
        protocol: NF1_SALES_PROTOCOL.into(),
        checkpoint,
        activation_height,
        role_binary_sha256: hashes,
    };
    let manifest_bytes = manifest.canonical_bytes()?;
    let fingerprint = manifest.fingerprint()?;
    let mut desired = parse_strict_canonical(DESIRED)?;
    desired.execution_configuration_fingerprint = fingerprint.clone();
    let desired_bytes = canonical_bytes(&desired)?;
    fs::create_dir(output)
        .map_err(|error| format!("Create new output directory {output:?}: {error}"))?;
    write_draft(&output.join(MANIFEST_FILE), &manifest_bytes)?;
    write_draft(&output.join(UNSIGNED_DESIRED_FILE), &desired_bytes)?;
    print_summary(json!({
        "activation_height": activation_height,
        "checkpoint": manifest.checkpoint,
        "execution_configuration_fingerprint": fingerprint,
        "manifest": output.join(MANIFEST_FILE),
        "unsigned_desired_state": output.join(UNSIGNED_DESIRED_FILE),
        "signature_required": true,
    }))
}

fn verify(
    manifest_path: &Path,
    desired_path: &Path,
    signed_path: &Path,
    hashes: &BTreeMap<String, String>,
) -> Result<(), String> {
    let bytes = read_document(manifest_path, MAX_NF1_SALES_ACTIVATION_BYTES)?;
    let manifest = parse_manifest(&bytes)?;
    let desired = read_document(desired_path, 8 * 1024)?;
    let signed: SignedDesiredStateV2 =
        serde_json::from_slice(&read_document(signed_path, 32 * 1024)?)
            .map_err(|error| format!("Parse signed Chain 1266 authorization: {error}"))?;
    let fingerprint = manifest.fingerprint()?;
    let mut expected = parse_strict_canonical(DESIRED)?;
    expected.execution_configuration_fingerprint = fingerprint.clone();
    if desired != canonical_bytes(&expected)? {
        return Err("The requested release must preserve the incumbent desired state apart from its execution configuration fingerprint".into());
    }
    let verified = verify_installed_activation(
        Some(&bytes),
        &desired,
        &signed,
        &expectation(),
        LAUNCH_AUTHORITY_ADDRESS,
        AUTHORITY_BINARY,
        &hashes[AUTHORITY_BINARY],
    )?
    .ok_or("No verified NF1 sales activation")?;
    if &verified.manifest().role_binary_sha256 != hashes {
        return Err("Supply every signed role binary with an exact SHA-256 match".into());
    }
    print_summary(json!({
        "signature_verified": true,
        "role_binaries_verified": true,
        "activation_height": verified.manifest().activation_height,
        "checkpoint": verified.manifest().checkpoint,
        "execution_configuration_fingerprint": fingerprint,
    }))
}

fn print_summary(value: serde_json::Value) -> Result<(), String> {
    println!(
        "{}",
        serde_json::to_string_pretty(&value).map_err(|error| error.to_string())?
    );
    Ok(())
}

fn run(args: &[String]) -> Result<(), String> {
    match args {
        [command, out, checkpoint_height, block_hash, state_root, activation_height, roles @ ..]
            if command == "prepare" =>
        {
            prepare(
                Path::new(out),
                ActivationCheckpoint {
                    height: height(checkpoint_height)?,
                    block_hash: block_hash.clone(),
                    state_root: state_root.clone(),
                },
                height(activation_height)?,
                role_hashes(roles)?,
            )
        }
        [command, manifest, desired, signed, roles @ ..] if command == "verify" => verify(
            Path::new(manifest),
            Path::new(desired),
            Path::new(signed),
            &role_hashes(roles)?,
        ),
        _ => Err(USAGE.into()),
    }
}

fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args == ["--help"] {
        println!("{USAGE}");
    } else if let Err(error) = run(&args) {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
