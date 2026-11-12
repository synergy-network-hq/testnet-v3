mod aegis_keys;
mod authority;
mod authority_custody;
mod capsule_verify;
mod consensus_keys;
mod etdag_keys;
mod import_consensus;
mod inspect;
mod node_identity;
mod prepare_authority;
mod provider;
mod release;
mod rotation;
mod validator_custody;
#[cfg(unix)]
mod validator_formation;
mod wallet;

use std::path::Path;

use synergy_aegis::KeyId;

fn main() {
    if let Err(error) = run() {
        eprintln!("synergy-keytool: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    let (arguments, engine) = selected_arguments(&arguments)?;
    match arguments {
        #[cfg(unix)]
        [command, context, pin, directory]
            if command == "prepare-validator-formation"
                || command == "verify-validator-formation" =>
        {
            let operation = if command == "prepare-validator-formation" {
                validator_formation::prepare
            } else {
                validator_formation::verify
            };
            println!(
                "{}",
                operation(
                    Path::new(context),
                    pin,
                    Path::new(directory),
                    engine.ok_or("authenticated APQE provider required")?
                )?
            );
        }
        #[cfg(unix)]
        [command, context, pin, directory, public, bound, genesis, authority, trust]
            if command == "review-validator-genesis-binding"
                || command == "bind-validator-formation" =>
        {
            println!(
                "{}",
                validator_formation::genesis(
                    Path::new(context),
                    pin,
                    Path::new(directory),
                    [Path::new(public), Path::new(bound)],
                    [genesis, authority, trust],
                    engine.ok_or("authenticated APQE provider required")?,
                    command == "bind-validator-formation"
                )?
            );
        }
        [command, chain, genesis, directory] if command == "provision-validator-custody" => {
            let result = validator_custody::provision(
                chain,
                genesis,
                Path::new(directory),
                engine.ok_or("authenticated APQE provider required")?,
            )?;
            println!("{result}");
        }
        [command, chain, genesis, directory] if command == "verify-validator-custody" => {
            let result = validator_custody::verify(
                chain,
                genesis,
                Path::new(directory),
                engine.ok_or("authenticated APQE provider required")?,
            )?;
            println!("{result}");
        }
        [command, id, chain, network, genesis_hash, directory]
            if command == "generate-authority-custody" =>
        {
            authority_custody::generate(
                parse_key_id(id)?,
                parse_chain_id(chain)?,
                network,
                genesis_hash,
                Path::new(directory),
                engine.ok_or("authenticated APQE provider required")?,
            )?;
            println!(
                "encrypted authority custody and public root persisted; runtime trust is unchanged"
            );
        }
        [command, input, custody, output] if command == "sign-authority-custody" => {
            authority_custody::sign(
                Path::new(input),
                Path::new(custody),
                Path::new(output),
                engine.ok_or("authenticated APQE provider required")?,
            )?;
            println!("authority candidate signed and verified; runtime trust is unchanged");
        }

        [command, secret] if command == "verify-processing-capsule" => {
            capsule_verify::verify(Path::new(secret), std::io::stdin().lock(), false)?;
        }
        [command, secret] if command == "verify-historical-processing-capsule" => {
            capsule_verify::verify(Path::new(secret), std::io::stdin().lock(), true)?;
        }
        [command, key_id, network_id, directory] if command == "generate-validator-root" => {
            let address = node_identity::generate_validator_root(
                parse_key_id(key_id)?,
                network_id,
                Path::new(directory),
            )?;
            println!("generated and verified fresh validator identity address={address}");
        }
        [command, public, secret, network_id] if command == "verify-validator-root" => {
            node_identity::verify_validator_root(Path::new(public), Path::new(secret), network_id)?;
            println!("fresh validator identity-root possession verified");
        }
        [command, metadata, public, secret, address, key_id] if command == "verify-key-pair" => {
            node_identity::verify_key_pair(
                Path::new(metadata),
                Path::new(public),
                Path::new(secret),
                address,
                &parse_key_id(key_id)?,
            )?;
            println!("validator role public binding and private-key possession verified");
        }
        [command, directory, chain, network, activation, balance, name]
            if command == "generate-tps-wallet" =>
        {
            wallet::generate(
                Path::new(directory),
                parse_chain_id(chain)?,
                network,
                activation.parse().map_err(|_| "invalid activation")?,
                balance.parse().map_err(|_| "invalid balance")?,
                name,
            )?;
            println!("wallet custody and verified public Genesis allocation written");
        }
        [command, registry] if command == "prepare-wallet-admission-session-operator" => {
            wallet::session_operator(
                Path::new(registry),
                std::io::stdin().lock(),
                std::io::stdout().lock(),
            )?;
        }
        [command, input, output] if command == "reauthorize-wallet" => {
            wallet::reauthorize(Path::new(input), Path::new(output))?;
            println!("existing wallet custody verified; new selected-network public authorization written");
        }
        [command, registry] if command == "prepare-wallet-admission-session" => {
            wallet::session(
                Path::new(registry),
                std::io::stdin().lock(),
                std::io::stdout().lock(),
            )?;
        }
        [command, input, output] if command == "prepare-wallet-processing-admission" => {
            wallet::prepare_processing(Path::new(input), Path::new(output))?;
            println!("signed asynchronous protected wallet admission written");
        }
        [command, input, output] if command == "prepare-wallet-admission" => {
            wallet::prepare(Path::new(input), Path::new(output))?;
            println!("signed protected wallet admission written");
        }
        [command, chain_id, address, key_id, public_identity]
            if command == "verify-consensus-public-bound" =>
        {
            import_consensus::verify(
                parse_chain_id(chain_id)?,
                address,
                parse_key_id(key_id)?,
                Path::new(public_identity),
                std::io::stdin().lock(),
            )?;
            println!("existing consensus possession verified");
        }
        [command, chain_id, address, key_id, public_identity, output]
            if command == "import-consensus-public-bound" =>
        {
            import_consensus::import(
                parse_chain_id(chain_id)?,
                address,
                parse_key_id(key_id)?,
                Path::new(public_identity),
                Path::new(output),
                std::io::stdin().lock(),
            )?;
            println!("existing consensus possession verified and bound custody installed");
        }
        [command, input, genesis_output, authority_output]
            if command == "prepare-fresh-genesis" =>
        {
            prepare_authority::prepare_genesis(
                Path::new(input),
                Path::new(genesis_output),
                Path::new(authority_output),
            )?;
            println!("unsigned Genesis and authority prepared; signing and pinned verification are required before use");
        }
        #[cfg(unix)]
        [command, input, context, context_pin, genesis_output, authority_output]
            if command == "prepare-formation-genesis" =>
        {
            prepare_authority::prepare_formation_genesis(
                Path::new(input),
                Path::new(context),
                context_pin,
                Path::new(genesis_output),
                Path::new(authority_output),
                engine.ok_or("authenticated APQE provider required")?,
            )?;
            println!("unsigned Genesis and authority prepared from verified formation registrations; signing and independent authorization remain required");
        }
        [command, input, output] if command == "prepare-fresh-authority" => {
            prepare_authority::prepare(Path::new(input), Path::new(output))?;
            println!("unsigned fresh authority prepared; sign-authority and verify-authority are required before use");
        }
        [command, input, key_id, secret, trust, output] if command == "sign-authority" => {
            authority::sign_with_provider(
                Path::new(input),
                parse_key_id(key_id)?,
                Path::new(secret),
                Path::new(trust),
                Path::new(output),
                engine.clone(),
            )?;
            println!("fresh authority signature written and verified");
        }
        [command, input, chain_id, network_id, key_id, trust] if command == "verify-authority" => {
            authority::verify_with_provider(
                Path::new(input),
                parse_chain_id(chain_id)?,
                network_id,
                parse_key_id(key_id)?,
                Path::new(trust),
                engine.clone(),
            )?;
            println!("fresh authority signature and protected policy verified");
        }
        [command, metadata, artifact, chain_id, key_id, secret_key, public_key, output]
            if command == "sign-release" =>
        {
            release::sign_with_provider(
                Path::new(metadata),
                Path::new(artifact),
                parse_chain_id(chain_id)?,
                parse_key_id(key_id)?,
                Path::new(secret_key),
                Path::new(public_key),
                Path::new(output),
                engine.clone(),
            )?;
            println!("release signature written and verified");
        }
        [command, metadata, artifact, chain_id, key_id, public_key, installed_sequence]
            if command == "verify-release" =>
        {
            release::verify_with_provider(
                Path::new(metadata),
                Path::new(artifact),
                parse_chain_id(chain_id)?,
                parse_key_id(key_id)?,
                Path::new(public_key),
                installed_sequence
                    .parse::<u64>()
                    .map_err(|_| "invalid installed release sequence")?,
                engine.clone(),
            )?;
            println!("release signature, artifact digest, and Linux architecture verified");
        }
        [command, key_id, root_public_key, output_directory]
            if command == "generate-node" && output_directory != "--validator" =>
        {
            let result = node_identity::generate(
                parse_key_id(key_id)?,
                Path::new(root_public_key),
                Path::new(output_directory),
                false,
            )?;
            println!(
                "generated node_address={} metadata={} public_key={} secret_key={} identity={}",
                result.node_address,
                result.bundle.metadata_path.display(),
                result.bundle.public_key_path.display(),
                result.bundle.secret_key_path.display(),
                result.identity_path.display()
            );
        }
        [command, key_id, root_public_key, output_directory, flag]
            if command == "generate-node" && flag == "--validator" =>
        {
            let result = node_identity::generate(
                parse_key_id(key_id)?,
                Path::new(root_public_key),
                Path::new(output_directory),
                true,
            )?;
            println!(
                "generated validator node_address={} metadata={} public_key={} secret_key={} identity={}",
                result.node_address,
                result.bundle.metadata_path.display(),
                result.bundle.public_key_path.display(),
                result.bundle.secret_key_path.display(),
                result.identity_path.display()
            );
        }
        [command, node_address, key_id, output_directory] if command == "generate-consensus" => {
            let result = consensus_keys::generate_with_provider(
                node_address.clone(),
                parse_key_id(key_id)?,
                Path::new(output_directory),
                engine.clone().ok_or("explicit APQE provider required")?,
            )?;
            print_bundle("consensus", &result);
        }
        [command, node_address, key_id, output_directory] if command == "generate-etdag" => {
            let result = etdag_keys::generate(
                node_address.clone(),
                parse_key_id(key_id)?,
                Path::new(output_directory),
            )?;
            print_bundle("etdag ML-KEM-768", &result);
        }
        [command, node_address, key_id, output_directory] if command == "generate-etdag-1024" => {
            let result = etdag_keys::generate_1024_with_provider(
                node_address.clone(),
                parse_key_id(key_id)?,
                Path::new(output_directory),
                engine.clone().ok_or("explicit APQE provider required")?,
            )?;
            print_bundle("etdag ML-KEM-1024", &result);
        }
        [command, metadata, public_key] if command == "inspect" => {
            let inspection = inspect::inspect(Path::new(metadata), Path::new(public_key))?;
            println!(
                "{}",
                serde_json::to_string_pretty(&inspection)
                    .map_err(|error| format!("encode inspection: {error}"))?
            );
        }
        [command, current, next, epoch, output] if command == "plan-rotation" => {
            let activation_epoch = epoch
                .parse::<u64>()
                .map_err(|error| format!("invalid activation epoch: {error}"))?;
            let plan = rotation::plan(
                Path::new(current),
                Path::new(next),
                activation_epoch,
                Path::new(output),
            )?;
            println!(
                "rotation plan {} -> {} activates at epoch {}",
                plan.current_key_id, plan.next_key_id, plan.activation_epoch
            );
        }
        _ => {
            return Err(
                "usage: synergy-keytool <verify-processing-capsule SECRET_KEY|verify-historical-processing-capsule SECRET_KEY (read-only historical wrapping compatibility; no protocol authorization; bounded envelope+selected public record JSON via stdin; no share output)|generate-validator-root KEY_ID NETWORK_ID OUTPUT_DIR|verify-validator-root PUBLIC_JSON SECRET_KEY NETWORK_ID|verify-key-pair METADATA PUBLIC_KEY SECRET_KEY NODE_ADDRESS KEY_ID|generate-tps-wallet OUTPUT_DIR CHAIN_ID NETWORK_ID ACTIVATION_UNIX BALANCE_NWEI NAME|reauthorize-wallet INPUT_JSON OUTPUT_PUBLIC_JSON|prepare-wallet-admission INPUT_JSON OUTPUT_JSON|prepare-wallet-processing-admission INPUT_JSON OUTPUT_JSON|prepare-wallet-admission-session REGISTRY_JSON|verify-consensus-public-bound CHAIN_ID NODE_ADDRESS KEY_ID PUBLIC_IDENTITY_JSON (raw secret via stdin)|import-consensus-public-bound CHAIN_ID NODE_ADDRESS KEY_ID PUBLIC_IDENTITY_JSON OUTPUT_DIRECTORY (raw secret via stdin)|prepare-fresh-genesis INPUT GENESIS_OUTPUT AUTHORITY_OUTPUT (unsigned; requires signing)|prepare-fresh-authority INPUT OUTPUT (unsigned; requires signing)|generate-node KEY_ID FNDSA_ROOT_PUBLIC_KEY OUTPUT_DIR [--validator]|generate-consensus NODE_ADDRESS KEY_ID OUTPUT_DIR|generate-etdag NODE_ADDRESS KEY_ID OUTPUT_DIR (legacy ML-KEM-768)|generate-etdag-1024 NODE_ADDRESS KEY_ID OUTPUT_DIR|inspect METADATA PUBLIC_KEY|plan-rotation CURRENT_METADATA NEXT_METADATA ACTIVATION_EPOCH OUTPUT|sign-release METADATA BINARY CHAIN_ID KEY_ID SECRET_KEY TRUST_KEY OUTPUT|verify-release METADATA BINARY CHAIN_ID KEY_ID TRUST_KEY INSTALLED_SEQUENCE|sign-authority INPUT KEY_ID SECRET_KEY TRUST_KEY OUTPUT|verify-authority INPUT CHAIN_ID NETWORK_ID KEY_ID TRUST_KEY>"
                    .into(),
            );
        }
    }
    Ok(())
}

fn parse_chain_id(value: &str) -> Result<u64, String> {
    value
        .parse::<u64>()
        .ok()
        .filter(|id| *id != 0)
        .ok_or_else(|| "invalid release chain ID".into())
}

fn parse_key_id(value: &str) -> Result<KeyId, String> {
    KeyId::new(value.to_string()).map_err(|error| error.to_string())
}

fn print_bundle(label: &str, bundle: &aegis_keys::WrittenBundle) {
    println!(
        "generated {label} metadata={} public_key={} secret_key={}",
        bundle.metadata_path.display(),
        bundle.public_key_path.display(),
        bundle.secret_key_path.display()
    );
}

fn selected_arguments(
    arguments: &[String],
) -> Result<(&[String], Option<provider::Engine>), String> {
    let command = arguments
        .first()
        .map(String::as_str)
        .ok_or("command required")?;
    if arguments.len() == 2 && arguments[1] == "--help" {
        let usage = match command {
            "prepare-validator-formation" | "verify-validator-formation" =>
                Some("CONTEXT_JSON CONTEXT_SHA256 PRIVATE_DIRECTORY"),
            "prepare-formation-genesis" =>
                Some("RECIPE_JSON CONTEXT_JSON CONTEXT_SHA256 UNSIGNED_GENESIS_OUT UNSIGNED_AUTHORITY_OUT"),
            "review-validator-genesis-binding" | "bind-validator-formation" =>
                Some("CONTEXT_JSON CONTEXT_SHA256 PRIVATE_DIRECTORY SIGNED_PUBLIC_DIRECTORY BOUND_CUSTODY_DIRECTORY GENESIS_SHA256 AUTHORITY_SHA256 TRUST_ROOT_SHA256"),
            _ => None,
        };
        if let Some(usage) = usage {
            return Err(format!("usage: synergy-keytool {command} {usage} --apqe-report PATH --apqe-report-sha256 SHA256"));
        }
    }
    if matches!(
        command,
        "inspect" | "prepare-fresh-authority" | "prepare-fresh-genesis"
    ) {
        return Ok((arguments, None));
    }
    if !matches!(
        command,
        "generate-authority-custody"
            | "provision-validator-custody"
            | "verify-validator-custody"
            | "prepare-validator-formation"
            | "prepare-formation-genesis"
            | "verify-validator-formation"
            | "review-validator-genesis-binding"
            | "bind-validator-formation"
            | "sign-authority-custody"
            | "sign-authority"
            | "verify-authority"
            | "sign-release"
            | "verify-release"
            | "generate-consensus"
            | "generate-etdag-1024"
    ) {
        return Err(format!("native cryptographic command {command} is fail-closed until its role-bound explicit APQE implementation is available; embedded and historical compatibility providers are forbidden"));
    }
    if arguments.len() < 4 {
        return Err("explicit APQE report and authenticated SHA256 flags required".into());
    }
    let split = arguments.len() - 4;
    match &arguments[split..] {
        [flag, report, hashflag, digest]
            if flag == "--apqe-report" && hashflag == "--apqe-report-sha256" =>
        {
            Ok((
                &arguments[..split],
                Some(synergy_aegis::load_authenticated_native_engine(
                    Path::new(report),
                    digest,
                )?),
            ))
        }
        _ => {
            Err("trailing --apqe-report ABS --apqe-report-sha256 AUTHENTICATED_HEX required".into())
        }
    }
}

#[cfg(test)]
mod native_policy_tests {
    use super::*;
    #[test]
    #[ignore = "requires explicitly authenticated immutable APQE native artifacts"]
    fn native_apqe_generation_keeps_consensus_and_ingress_roles_distinct() {
        let engine = crate::provider::native_test_engine();
        let root = std::env::temp_dir().join(format!(
            "apqe-role-generation-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        struct Cleanup(std::path::PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let _cleanup = Cleanup(root.clone());
        let address = "synv11lrh6jcxaejkj4zv994j7qwn2rk6u3ar4emn";
        let consensus = crate::consensus_keys::generate_with_provider(
            address.into(),
            parse_key_id("consensus").unwrap(),
            &root,
            engine.clone(),
        )
        .unwrap();
        let ingress = crate::etdag_keys::generate_1024_with_provider(
            address.into(),
            parse_key_id("ingress").unwrap(),
            &root,
            engine.clone(),
        )
        .unwrap();
        for (bundle, algorithm) in [
            (consensus, synergy_address_engine::types::Algorithm::MlDsa65),
            (ingress, synergy_address_engine::types::Algorithm::MlKem1024),
        ] {
            let public = std::fs::read(&bundle.public_key_path).unwrap();
            let secret = synergy_address_engine::apqe::SecretBytes::from_bytes(
                std::fs::read(&bundle.secret_key_path).unwrap(),
            );
            assert!(engine
                .lock()
                .unwrap()
                .keypair_corresponds(algorithm, &public, secret.as_bytes())
                .unwrap());
            let wrong = if algorithm == synergy_address_engine::types::Algorithm::MlDsa65 {
                synergy_address_engine::types::Algorithm::MlKem1024
            } else {
                synergy_address_engine::types::Algorithm::MlKem768
            };
            assert!(!engine
                .lock()
                .unwrap()
                .keypair_corresponds(wrong, &public, secret.as_bytes())
                .unwrap_or(false));
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(
                    std::fs::metadata(bundle.secret_key_path)
                        .unwrap()
                        .permissions()
                        .mode()
                        & 0o077,
                    0
                );
            }
        }
    }
    #[test]
    fn unmigrated_crypto_and_legacy_commands_fail_before_reading_inputs() {
        for command in [
            "generate-validator-root",
            "generate-node",
            "generate-etdag",
            "generate-tps-wallet",
            "import-consensus-public-bound",
            "verify-historical-processing-capsule",
        ] {
            let arguments = vec![command.to_string(), "must-not-read".to_string()];
            let error = selected_arguments(&arguments)
                .err()
                .expect("unmigrated provider must fail closed");
            assert!(error.contains("fail-closed"));
        }
        for command in [
            "sign-authority",
            "verify-authority",
            "sign-release",
            "verify-release",
        ] {
            assert!(selected_arguments(&[command.into()]).is_err());
        }
    }
}
