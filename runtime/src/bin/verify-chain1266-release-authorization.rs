use std::env;
use std::path::PathBuf;

use synergy_testnet::consensus_activation::verify_signed_consensus_activation_file;
use synergy_testnet::consensus_start::verify_signed_start_command;
use synergy_testnet::desired_state::verify_signed_desired_state_file;
use synergy_testnet::genesis::load_genesis_from_path;

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
