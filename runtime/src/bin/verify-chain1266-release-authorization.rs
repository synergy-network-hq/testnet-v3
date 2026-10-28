use std::env;
use std::path::PathBuf;

use synergy_testnet::consensus_activation::verify_signed_consensus_activation_file;
use synergy_testnet::consensus_start::verify_signed_start_command;
use synergy_testnet::desired_state::verify_signed_desired_state_file;
use synergy_testnet::genesis::load_genesis_from_path;
use synergy_testnet::testnet_v3_release_approval::verify_release_approval_file_public;

fn fail(message: impl AsRef<str>) -> ! {
    eprintln!(
        "verify-chain1266-release-authorization: {}",
        message.as_ref()
    );
    std::process::exit(1);
}

fn value(args: &[String], flag: &str) -> Option<PathBuf> {
    args.windows(2)
        .find(|pair| pair[0] == flag)
        .map(|pair| PathBuf::from(&pair[1]))
}

fn main() {
    let args = env::args().collect::<Vec<_>>();
    if let Some(approval) = value(&args, "--release-approval") {
        verify_fresh_p3_release(&args, &approval);
        return;
    }
    let desired =
        value(&args, "--desired-state").unwrap_or_else(|| fail("missing --desired-state <PATH>"));
    let signature = value(&args, "--desired-state-signature")
        .unwrap_or_else(|| fail("missing --desired-state-signature <PATH>"));
    let request =
        verify_signed_desired_state_file(&desired, &signature).unwrap_or_else(|error| fail(error));
    if let Some(activation) = value(&args, "--consensus-activation") {
        let genesis_path = value(&args, "--genesis")
            .unwrap_or_else(|| fail("--consensus-activation requires --genesis <PATH>"));
        let genesis = load_genesis_from_path(genesis_path)
            .unwrap_or_else(|error| fail(format!("load immutable canonical Genesis: {error}")));
        let verified =
            verify_signed_consensus_activation_file(&activation, &desired, &signature, &genesis)
                .unwrap_or_else(|error| fail(error));
        println!(
            "CHAIN1266_CONSENSUS_ACTIVATION_VERIFIED release_id={} activation_height={} activation_root={}",
            verified.manifest.release_id,
            verified.manifest.activation_height,
            verified.root.to_hex()
        );
    } else if value(&args, "--genesis").is_some() {
        fail("consensus activation verification requires --consensus-activation and --genesis");
    }
    if value(&args, "--consensus-activation-signature").is_some() {
        fail("the consensus activation is a self-contained signed manifest; do not supply a detached signature file");
    }
    if let Some(start) = value(&args, "--start-command") {
        let verified = verify_signed_start_command(&start, &desired, &request.desired_state_sha256)
            .unwrap_or_else(|error| fail(error));
        println!(
            "CHAIN1266_RELEASE_AUTHORIZATION_VERIFIED release_id={} desired_state_sha256={} start_activate_unix_ms={}",
            request.release_id, request.desired_state_sha256, verified.activate_unix_ms
        );
    } else {
        println!(
            "CHAIN1266_DESIRED_STATE_AUTHORIZATION_VERIFIED release_id={} desired_state_sha256={}",
            request.release_id, request.desired_state_sha256
        );
    }
}

/// The P3 verifier is intentionally separate from the P1 desired-state and
/// detached-start chain.  A P3 approval authorizes the exact staged release
/// candidate, Genesis, desired state, source revisions, binary, and role
/// configurations under the frozen V4 governance record.
fn verify_fresh_p3_release(args: &[String], approval: &PathBuf) {
    if value(args, "--desired-state-signature").is_some()
        || value(args, "--consensus-activation").is_some()
        || value(args, "--start-command").is_some()
        || value(args, "--consensus-activation-signature").is_some()
    {
        fail(
            "fresh P3 verification does not accept legacy desired-state, activation, or start-command signatures",
        );
    }
    let candidate = value(args, "--release-candidate")
        .unwrap_or_else(|| fail("--release-approval requires --release-candidate <PATH>"));
    let authorities = value(args, "--authority-record")
        .unwrap_or_else(|| fail("--release-approval requires --authority-record <PATH>"));
    let desired = value(args, "--desired-state")
        .unwrap_or_else(|| fail("--release-approval requires --desired-state <PATH>"));
    let genesis_path = value(args, "--genesis")
        .unwrap_or_else(|| fail("--release-approval requires --genesis <PATH>"));
    let trust_root = authorities
        .parent()
        .unwrap_or_else(|| fail("authority record has no parent trust directory"));
    let request = verify_release_approval_file_public(
        trust_root,
        &candidate,
        &authorities,
        &desired,
        approval,
    )
    .unwrap_or_else(|error| fail(format!("fresh P3 V4 release approval: {error}")));
    let genesis = load_genesis_from_path(genesis_path)
        .unwrap_or_else(|error| fail(format!("load immutable canonical Genesis: {error}")));
    if genesis.hash() != request.genesis_hash || genesis.chain_id() != request.chain_id {
        fail("immutable Genesis does not match the signed fresh P3 release approval");
    }
    println!(
        "CHAIN1266_P3_RELEASE_AUTHORIZATION_VERIFIED release_id={} genesis_hash={} desired_state_sha256={}",
        request.release_id, request.genesis_hash, request.desired_state_sha256
    );
}
