use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use synergy_address_engine::{generate_identity, AddressType};

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut address_type = AddressType::NodeClass1;
    let mut label = "Synergy Identity".to_string();
    let mut output_dir: Option<PathBuf> = None;
    let mut output_json: Option<PathBuf> = None;
    let mut output_public_key: Option<PathBuf> = None;
    let mut output_private_key: Option<PathBuf> = None;
    let mut output_address: Option<PathBuf> = None;

    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--address-type" => {
                let value = args
                    .next()
                    .ok_or_else(|| "Missing value for --address-type".to_string())?;
                address_type = parse_address_type(&value)?;
            }
            "--label" => {
                label = args
                    .next()
                    .ok_or_else(|| "Missing value for --label".to_string())?;
            }
            "--output-dir" => {
                let value = args
                    .next()
                    .ok_or_else(|| "Missing value for --output-dir".to_string())?;
                output_dir = Some(PathBuf::from(value));
            }
            "--output-json" => {
                let value = args
                    .next()
                    .ok_or_else(|| "Missing value for --output-json".to_string())?;
                output_json = Some(PathBuf::from(value));
            }
            "--output-public-key" => {
                let value = args
                    .next()
                    .ok_or_else(|| "Missing value for --output-public-key".to_string())?;
                output_public_key = Some(PathBuf::from(value));
            }
            "--output-private-key" => {
                let value = args
                    .next()
                    .ok_or_else(|| "Missing value for --output-private-key".to_string())?;
                output_private_key = Some(PathBuf::from(value));
            }
            "--output-address" => {
                let value = args
                    .next()
                    .ok_or_else(|| "Missing value for --output-address".to_string())?;
                output_address = Some(PathBuf::from(value));
            }
            "--help" | "-h" => {
                print_help();
                return Ok(());
            }
            other => {
                return Err(format!("Unknown argument: {other}\n\n{}", help_text()));
            }
        }
    }

    if let Some(dir) = output_dir.as_ref() {
        output_json.get_or_insert_with(|| dir.join("identity.json"));
        output_public_key.get_or_insert_with(|| dir.join("public.key"));
        output_private_key.get_or_insert_with(|| dir.join("private.key"));
        output_address.get_or_insert_with(|| dir.join("address.txt"));
    }

    let output_json =
        output_json.ok_or_else(|| "Provide --output-dir or --output-json".to_string())?;
    let output_public_key = output_public_key
        .ok_or_else(|| "Provide --output-dir or --output-public-key".to_string())?;
    let output_private_key = output_private_key
        .ok_or_else(|| "Provide --output-dir or --output-private-key".to_string())?;
    let output_address =
        output_address.ok_or_else(|| "Provide --output-dir or --output-address".to_string())?;

    let identity = generate_identity(address_type)?;
    let identity_json = serde_json::to_string_pretty(&serde_json::json!({
        "label": label,
        "address": identity.address,
        "address_type": identity.address_type,
        "algorithm": identity.algorithm,
        "created_at": identity.created_at,
        "public_key": identity.public_key,
        "private_key": identity.private_key,
    }))
    .map_err(|error| format!("Failed to serialize identity: {error}"))?;

    write_file(&output_json, &identity_json)?;
    write_file(&output_public_key, &identity.public_key)?;
    write_file(&output_private_key, &identity.private_key)?;
    write_file(&output_address, &identity.address)?;

    println!("Generated {}", identity.address);
    println!("Identity JSON: {}", output_json.display());
    println!("Public key:    {}", output_public_key.display());
    println!("Private key:   {}", output_private_key.display());
    println!("Address file:  {}", output_address.display());

    Ok(())
}

fn write_file(path: &Path, contents: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("Failed to create {}: {error}", parent.display()))?;
    }

    fs::write(path, contents)
        .map_err(|error| format!("Failed to write {}: {error}", path.display()))
}

fn parse_address_type(value: &str) -> Result<AddressType, String> {
    match normalize(value).as_str() {
        "walletprimary" | "wallet-primary" => Ok(AddressType::WalletPrimary),
        "walletutility" | "wallet-utility" => Ok(AddressType::WalletUtility),
        "walletaccount" | "wallet-account" => Ok(AddressType::WalletAccount),
        "walletsmart" | "wallet-smart" => Ok(AddressType::WalletSmart),
        "contractsystem" | "contract-system" => Ok(AddressType::ContractSystem),
        "contractcustom" | "contract-custom" => Ok(AddressType::ContractCustom),
        "nodeclass1" | "node-class-1" | "nodeclass-1" | "validator" => Ok(AddressType::NodeClass1),
        "nodeclass2" | "node-class-2" | "nodeclass-2" | "class2" => Ok(AddressType::NodeClass2),
        "nodeclass3" | "node-class-3" | "nodeclass-3" | "class3" => Ok(AddressType::NodeClass3),
        "nodeclass4" | "node-class-4" | "nodeclass-4" | "class4" => Ok(AddressType::NodeClass4),
        "nodeclass5" | "node-class-5" | "nodeclass-5" | "class5" => Ok(AddressType::NodeClass5),
        other => Err(format!(
            "Unsupported address type: {other}\n\n{}",
            help_text()
        )),
    }
}

fn normalize(value: &str) -> String {
    value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn print_help() {
    println!("{}", help_text());
}

fn help_text() -> &'static str {
    "Usage:
  cargo run --manifest-path synergy-address-engine/Cargo.toml --bin generate-identity -- \
    --address-type validator \
    --label \"Validator Identity\" \
    --output-dir /path/to/output

Options:
  --address-type         Address class to generate. Supported: validator, node-class-1..5,
                         wallet-primary, wallet-utility, wallet-account, wallet-smart,
                         contract-system, contract-custom
  --label                Human-readable label stored in identity.json
  --output-dir           Directory to receive identity.json, public.key, private.key, address.txt
  --output-json          Explicit path for identity.json
  --output-public-key    Explicit path for public.key
  --output-private-key   Explicit path for private.key
  --output-address       Explicit path for address.txt
  --help, -h             Show this help"
}
