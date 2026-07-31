use std::env;
use std::path::PathBuf;

use synergy_testnet::consensus_start::verify_signed_start_command;
use synergy_testnet::desired_state::verify_signed_desired_state_file;

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
    let desired = value(&args, "--desired-state")
        .unwrap_or_else(|| fail("missing --desired-state <PATH>"));
    let signature = value(&args, "--desired-state-signature")
        .unwrap_or_else(|| fail("missing --desired-state-signature <PATH>"));
    let request =
        verify_signed_desired_state_file(&desired, &signature).unwrap_or_else(|error| fail(error));
    if let Some(start) = value(&args, "--start-command") {
        let verified =
            verify_signed_start_command(&start, &desired, &request.desired_state_sha256)
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
