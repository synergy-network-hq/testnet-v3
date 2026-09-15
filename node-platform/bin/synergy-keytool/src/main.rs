mod aegis_keys;
mod consensus_keys;
mod etdag_keys;
mod inspect;
mod node_identity;
mod rotation;

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
    match arguments.as_slice() {
        [command, key_id, output_directory] if command == "generate-node" => {
            let result =
                node_identity::generate(parse_key_id(key_id)?, Path::new(output_directory), false)?;
            println!(
                "generated node_address={} metadata={} public_key={} secret_key={} identity={}",
                result.node_address,
                result.bundle.metadata_path.display(),
                result.bundle.public_key_path.display(),
                result.bundle.secret_key_path.display(),
                result.identity_path.display()
            );
        }
        [command, key_id, output_directory, flag]
            if command == "generate-node" && flag == "--validator" =>
        {
            let result =
                node_identity::generate(parse_key_id(key_id)?, Path::new(output_directory), true)?;
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
            let result = consensus_keys::generate(
                node_address.clone(),
                parse_key_id(key_id)?,
                Path::new(output_directory),
            )?;
            print_bundle("consensus", &result);
        }
        [command, node_address, key_id, output_directory] if command == "generate-etdag" => {
            let result = etdag_keys::generate(
                node_address.clone(),
                parse_key_id(key_id)?,
                Path::new(output_directory),
            )?;
            print_bundle("etdag", &result);
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
                "usage: synergy-keytool <generate-node KEY_ID OUTPUT_DIR [--validator]|generate-consensus NODE_ADDRESS KEY_ID OUTPUT_DIR|generate-etdag NODE_ADDRESS KEY_ID OUTPUT_DIR|inspect METADATA PUBLIC_KEY|plan-rotation CURRENT_METADATA NEXT_METADATA ACTIVATION_EPOCH OUTPUT>"
                    .into(),
            );
        }
    }
    Ok(())
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
