use base64::{engine::general_purpose, Engine as _};
use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};
use synergy_testnet::address::address_matches_public_key;
use synergy_testnet::crypto::pqc::{PQCAlgorithm, PQCManager, PQCPrivateKey, PQCPublicKey};
use synergy_testnet::sts::{
    decode_sts_payload, encode_sts_payload, estimate_sts_gas, native_snrg_definition,
    validate_sts_object_id, CreateCredentialSchemaParams, CreateFungibleParams,
    CreateMultiAssetCollectionParams, CreateMultiAssetItemParams, CreateNftCollectionParams,
    FungibleControlFlags, FungiblePolicy, IssueCredentialParams, MintNftParams, MultiAssetAmount,
    MultiAssetItemType, MultiAssetTransferPolicy, StsSignedPayload, StsState, StsTx, TokenClass,
    NATIVE_SNRG_PLACEHOLDER_ADDRESS, STS_TESTNET_CHAIN_ID, STS_TESTNET_NETWORK,
};
use synergy_testnet::synergy_types::{SYNERGY_TESTNET_V3_CHAIN_ID, SYNERGY_TESTNET_V3_NETWORK_ID};
use synergy_testnet::transaction::Transaction;

const DEFAULT_RPC_URL: &str = "https://testnet-core-rpc.synergy-network.io";
const DEFAULT_GAS_PRICE_NWEI: u64 = 40;
const DEFAULT_SUBMIT_TIMEOUT_SECONDS: u64 = 30;
const DEFAULT_STS_GAS_LIMIT_BUFFER: u64 = 25_000;
const DEFAULT_STS_CARRIER_AMOUNT_NWEI: u64 = 1;

fn main() {
    if let Err(error) = run() {
        eprintln!("synergy-sts failed closed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.is_empty() || has_flag(&args, "--help") || has_flag(&args, "-h") {
        usage();
        return Ok(());
    }

    match args.first().map(String::as_str) {
        Some("version") | Some("--version") => {
            println!("synergy-sts {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Some("native-info") => print_native_info(&args[1..]),
        Some("decode") => decode_payload_command(&args[1..]),
        Some("estimate") => estimate_payload_command(&args[1..]),
        Some("submit") | Some("send") => submit_payload_command(&args[1..]),
        Some("token") => run_token_command(&args[1..]),
        Some("nft") => run_nft_command(&args[1..]),
        Some("ma") | Some("multi-asset") => run_multi_asset_command(&args[1..]),
        Some("credential") | Some("credentials") => run_credential_command(&args[1..]),
        Some("help") => {
            usage();
            Ok(())
        }
        Some(command) => Err(format!("unknown command '{command}'")),
        None => Ok(()),
    }
}

fn usage() {
    eprintln!(
        "synergy-sts

Build and submit native Synergy Token System payloads for testnet. By default,
commands emit deterministic payload artifacts. Add --submit with a decrypted
Synergy wallet file to sign a Synergy transaction, pay gas in SNRG, and submit
through the normal transaction path.

Usage:
  synergy-sts native-info [--output json] [--out <path>]
  synergy-sts decode --payload-hex <hex> [--output json|payload-json] [--out <path>]
  synergy-sts decode --file <artifact.json-or-hex> [--output json|payload-json] [--out <path>]
  synergy-sts estimate --payload-hex <hex> [--gas-price-nwei <u64>]
  synergy-sts submit --payload-hex <hex>|--file <artifact.json-or-hex> --wallet <wallet.dec.json> [--wallet-public <wallet.pub.json>] [--rpc-url <url>] [--gas-price-nwei <u64>] [--gas-limit <u64>] [--nonce <u64>] [--carrier-amount-nwei <u64>]
  synergy-sts token create --network testnet --class b1|b2|b3 --name <name> --symbol <symbol> --decimals <0-9> --initial-supply <base_units> [--from <creator>] [--creator-nonce <u64>] [--created-at <u64>] [--max-supply <base_units>] [--metadata-uri <uri> --metadata-hash <sha3_256_hex>] [--metadata-file <path>] [--image-uri <uri> --image-hash <sha3_256_hex>] [--image-file <path>] [--no-mint-authority|--mint-authority <addr>] [--metadata-authority <addr>] [--can-freeze] [--can-pause] [--can-clawback] [--policy <template>] [--submit --wallet <wallet.dec.json>] [--output json|payload-hex|payload-json] [--out <path>]
  synergy-sts token mint --network testnet --token <synb*> --to <owner> --amount <base_units> --from <authority> [--timestamp <u64>]
  synergy-sts token transfer --network testnet --token <synb*> --from <owner> --to <owner> --amount <base_units> [--timestamp <u64>]
  synergy-sts token burn --network testnet --token <synb*> --from <owner> --amount <base_units> [--timestamp <u64>]
  synergy-sts token set-image --network testnet --token <synb*> --image-uri <uri> --image-hash <sha3_256_hex> --from <creator> [--image-file <path>] [--timestamp <u64>]
  synergy-sts token freeze --network testnet --token <synb2*> --owner <owner> --from <authority> [--timestamp <u64>]
  synergy-sts token thaw --network testnet --token <synb2*> --owner <owner> --from <authority> [--timestamp <u64>]
  synergy-sts token pause --network testnet --token <synb2*> --from <authority> [--timestamp <u64>]
  synergy-sts token unpause --network testnet --token <synb2*> --from <authority> [--timestamp <u64>]
  synergy-sts token clawback --network testnet --token <synb2*> --source <owner> --to <owner> --amount <base_units> --from <authority> [--timestamp <u64>]
  synergy-sts token snapshot --network testnet --token <synb3*> --from <authority> [--timestamp <u64>]
  synergy-sts nft create-collection --network testnet --class nf1|nf2 --name <name> --symbol <symbol> --from <creator> --creator-nonce <u64> [--metadata-uri <uri> --metadata-hash <sha3_256_hex>] [--metadata-file <path>] [--image-uri <uri> --image-hash <sha3_256_hex>] [--royalty-bps <0-10000> --royalty-recipient <addr>] [--non-transferable] [--requires-issuer-approval]
  synergy-sts nft mint --network testnet --collection <synn*> --to <owner> --from <authority> [--metadata-uri <uri> --metadata-hash <sha3_256_hex>] [--metadata-file <path>] [--expires-at <u64>] [--non-transferable] [--requires-issuer-approval]
  synergy-sts nft transfer --network testnet --nft <synn*> --from <owner-or-authority> --owner <current-owner> --to <owner> [--timestamp <u64>]
  synergy-sts nft burn --network testnet --nft <synn*> --from <owner-or-authority> --owner <current-owner> [--timestamp <u64>]
  synergy-sts nft revoke|use|freeze|thaw --network testnet --nft <synn*> --from <authority-or-owner> [--timestamp <u64>]
  synergy-sts ma create --network testnet --name <name> --symbol <symbol> --from <creator> --creator-nonce <u64> [--metadata-uri <uri> --metadata-hash <sha3_256_hex>] [--metadata-file <path>]
  synergy-sts ma create-item --network testnet --collection <synj*> --item-id <u64> --type fungible|non_fungible|semi_fungible --name <name> --symbol <symbol> --decimals <0-9> --from <authority> [--max-supply <base_units>] [--transfer-policy open|non_transferable|authority_only]
  synergy-sts ma mint|transfer|burn --network testnet --collection <synj*> --item-id <u64> --amount <base_units> --from <owner-or-authority> [--to <owner>]
  synergy-sts ma batch-transfer --network testnet --collection <synj*> --from <owner> --to <owner> --item <item_id>:<amount> [--item <item_id>:<amount> ...]
  synergy-sts credential schema create --network testnet --schema-id <id> --name <name> --schema-hash <sha3_256_hex> --from <issuer> [--description-hash <sha3_256_hex>]
  synergy-sts credential issue --network testnet --schema-id <id> --subject <addr> --subject-commitment <sha3_256_hex> --credential-hash <sha3_256_hex> --from <issuer> [--expires-at <u64>]
  synergy-sts credential revoke|suspend|restore|expire|verify-status --network testnet --credential <synk*> --from <issuer-or-caller> [--reason-hash <sha3_256_hex>]

Policy examples:
  --policy snapshot_v1
  --policy transfer_fee_v1:fee_bps=25,recipient=synw1...
  --policy vesting_v1:start_at=1700000000,cliff_at=1700000100,end_at=1700000200
  --policy max_wallet_v1:max_balance=1000000000

Submit options:
  --submit                      Sign and submit the STS payload on chain.
  --wallet <wallet.dec.json>    Decrypted Synergy wallet JSON with address/private_key.
  --wallet-public <pub.json>    Optional public-key JSON. If omitted, a sibling .pub.json is used.
  --rpc-url <url>               Defaults to https://testnet-core-rpc.synergy-network.io.
  --carrier-amount-nwei <u64>   Defaults to 1 nWei self-carrier for current public RPC compatibility.
"
    );
}

fn run_token_command(args: &[String]) -> Result<(), String> {
    let Some(subcommand) = args.first().map(String::as_str) else {
        return Err("token command requires a subcommand".to_string());
    };
    let rest = &args[1..];
    require_testnet(rest)?;

    match subcommand {
        "create" => build_create_fungible(rest),
        "mint" => build_simple_amount_tx(rest, "mint"),
        "transfer" => build_simple_amount_tx(rest, "transfer"),
        "burn" => build_simple_amount_tx(rest, "burn"),
        "set-image" => build_set_image_tx(rest),
        "freeze" => build_account_control_tx(rest, true),
        "thaw" => build_account_control_tx(rest, false),
        "pause" => build_pause_tx(rest, true),
        "unpause" => build_pause_tx(rest, false),
        "clawback" => build_clawback_tx(rest),
        "snapshot" => build_snapshot_tx(rest),
        other => Err(format!("unknown token subcommand '{other}'")),
    }
}

fn run_nft_command(args: &[String]) -> Result<(), String> {
    let Some(subcommand) = args.first().map(String::as_str) else {
        return Err("nft command requires a subcommand".to_string());
    };
    let rest = &args[1..];
    require_testnet(rest)?;
    match subcommand {
        "create-collection" => build_create_nft_collection(rest),
        "mint" => build_mint_nft(rest),
        "transfer" => build_transfer_nft(rest),
        "burn" => build_burn_nft(rest),
        "freeze" => build_nft_control(rest, "freeze"),
        "thaw" => build_nft_control(rest, "thaw"),
        "revoke" => build_nft_control(rest, "revoke"),
        "use" => build_nft_control(rest, "use"),
        "update-metadata" => build_update_nft_metadata(rest),
        "verify-collection" => build_verify_nft_collection(rest),
        other => Err(format!("unknown nft subcommand '{other}'")),
    }
}

fn run_multi_asset_command(args: &[String]) -> Result<(), String> {
    let Some(subcommand) = args.first().map(String::as_str) else {
        return Err("ma command requires a subcommand".to_string());
    };
    let rest = &args[1..];
    require_testnet(rest)?;
    match subcommand {
        "create" => build_create_multi_asset_collection(rest),
        "create-item" => build_create_multi_asset_item(rest),
        "mint" => build_multi_asset_amount_tx(rest, "mint"),
        "batch-mint" => build_batch_multi_asset_amount_tx(rest, "batch-mint"),
        "transfer" => build_multi_asset_amount_tx(rest, "transfer"),
        "burn" => build_multi_asset_amount_tx(rest, "burn"),
        "batch-burn" => build_batch_multi_asset_amount_tx(rest, "batch-burn"),
        "batch-transfer" => build_batch_multi_asset_transfer(rest),
        other => Err(format!("unknown ma subcommand '{other}'")),
    }
}

fn run_credential_command(args: &[String]) -> Result<(), String> {
    let Some(subcommand) = args.first().map(String::as_str) else {
        return Err("credential command requires a subcommand".to_string());
    };
    let rest = &args[1..];
    if subcommand == "schema" {
        let Some(schema_subcommand) = rest.first().map(String::as_str) else {
            return Err("credential schema requires a subcommand".to_string());
        };
        require_testnet(&rest[1..])?;
        return match schema_subcommand {
            "create" => build_create_credential_schema(&rest[1..]),
            other => Err(format!("unknown credential schema subcommand '{other}'")),
        };
    }
    require_testnet(rest)?;
    match subcommand {
        "issue" => build_issue_credential(rest),
        "revoke" => build_credential_status_tx(rest, "revoke"),
        "suspend" => build_credential_status_tx(rest, "suspend"),
        "restore" => build_credential_status_tx(rest, "restore"),
        "expire" => build_credential_status_tx(rest, "expire"),
        "verify-status" | "verify" => build_credential_status_tx(rest, "verify-status"),
        other => Err(format!("unknown credential subcommand '{other}'")),
    }
}

fn print_native_info(args: &[String]) -> Result<(), String> {
    let native = native_snrg_definition();
    emit_output(
        args,
        json!({
            "network": STS_TESTNET_NETWORK,
            "chain_id": STS_TESTNET_CHAIN_ID,
            "symbol": native.symbol,
            "name": native.name,
            "decimals": native.decimals,
            "native": native.native,
            "gas_asset": native.gas_asset,
            "token_address": native.token_address,
            "compatibility_placeholder_address": NATIVE_SNRG_PLACEHOLDER_ADDRESS,
        }),
    )
}

fn decode_payload_command(args: &[String]) -> Result<(), String> {
    let payload_hex = payload_hex_from_args(args)?;
    let payload = decode_payload_hex(&payload_hex)?;
    emit_output(
        args,
        payload_report(payload, payload_hex, None, None, None)?,
    )
}

fn estimate_payload_command(args: &[String]) -> Result<(), String> {
    let gas_price_nwei =
        optional_u64_arg(args, "--gas-price-nwei")?.unwrap_or(DEFAULT_GAS_PRICE_NWEI);
    let payload_hex = payload_hex_from_args(args)?;
    let payload = decode_payload_hex(&payload_hex)?;
    let gas = estimate_sts_gas(&payload.tx);
    let fee_nwei = (gas as u128)
        .checked_mul(gas_price_nwei as u128)
        .ok_or_else(|| "estimated fee overflow".to_string())?;
    emit_output(
        args,
        json!({
            "network": payload.network,
            "chain_id": payload.chain_id,
            "estimated_gas": gas,
            "gas_price_nwei": gas_price_nwei,
            "estimated_fee_nwei": fee_nwei.to_string(),
            "payload": payload,
        }),
    )
}

fn submit_payload_command(args: &[String]) -> Result<(), String> {
    let payload_hex = payload_hex_from_args(args)?;
    let payload = decode_payload_hex(&payload_hex)?;
    let sender = sender_arg(args, "--from")?;
    let mut report = payload_report(payload.clone(), payload_hex.clone(), None, None, None)?;
    let gas = estimate_sts_gas(&payload.tx);
    let submission = submit_payload(args, &sender, &payload_hex, gas)?;
    let report_object = report
        .as_object_mut()
        .ok_or_else(|| "payload report was not an object".to_string())?;
    report_object.insert("sender".to_string(), json!(sender));
    report_object.insert("submission".to_string(), submission);
    emit_output(args, report)
}

fn build_create_fungible(args: &[String]) -> Result<(), String> {
    let class = parse_token_class(&required_arg(args, "--class")?)?;
    if !class.is_fungible() {
        return Err("token create currently supports fungible classes b1, b2, and b3".to_string());
    }

    let metadata_uri = optional_arg(args, "--metadata-uri");
    let metadata_file = optional_arg(args, "--metadata-file");
    let metadata_file_hash = metadata_file
        .as_deref()
        .map(hash_file_sha3_256)
        .transpose()?;
    let metadata_hash = match (
        optional_arg(args, "--metadata-hash"),
        metadata_file_hash.as_ref(),
    ) {
        (Some(explicit), Some(file_hash)) if explicit.as_str() != file_hash.as_str() => {
            return Err(format!(
                "--metadata-hash does not match SHA3-256(metadata-file): expected {file_hash}"
            ));
        }
        (Some(explicit), _) => Some(explicit),
        (None, Some(file_hash)) => Some(file_hash.clone()),
        (None, None) => None,
    };
    if metadata_uri.is_some() && metadata_hash.is_none() {
        return Err("--metadata-hash is required when --metadata-uri is provided".to_string());
    }

    let image_uri = optional_arg(args, "--image-uri");
    let image_file = optional_arg(args, "--image-file");
    let image_file_hash = image_file.as_deref().map(hash_file_sha3_256).transpose()?;
    let image_hash = match (optional_arg(args, "--image-hash"), image_file_hash.as_ref()) {
        (Some(explicit), Some(file_hash)) if explicit.as_str() != file_hash.as_str() => {
            return Err(format!(
                "--image-hash does not match SHA3-256(image-file): expected {file_hash}"
            ));
        }
        (Some(explicit), _) => Some(explicit),
        (None, Some(file_hash)) => Some(file_hash.clone()),
        (None, None) => None,
    };
    if image_uri.is_some() && image_hash.is_none() {
        return Err("--image-hash is required when --image-uri is provided".to_string());
    }
    if image_uri.is_none() && image_hash.is_some() {
        return Err(
            "--image-uri is required when --image-hash or --image-file is provided".to_string(),
        );
    }

    let creator = sender_arg(args, "--from")?;
    let created_at = optional_u64_arg(args, "--created-at")?.unwrap_or(current_timestamp()?);
    let creator_nonce = optional_u64_arg(args, "--creator-nonce")?.unwrap_or(created_at);
    let mint_authority = if has_flag(args, "--no-mint-authority") {
        if optional_arg(args, "--mint-authority").is_some() {
            return Err("--no-mint-authority cannot be combined with --mint-authority".to_string());
        }
        None
    } else {
        optional_arg(args, "--mint-authority").or_else(|| Some(creator.clone()))
    };
    let params = CreateFungibleParams {
        class,
        creator: creator.clone(),
        creator_nonce,
        name: required_arg(args, "--name")?,
        symbol: required_arg(args, "--symbol")?,
        decimals: required_u8_arg(args, "--decimals")?,
        initial_supply: required_u128_arg(args, "--initial-supply")?,
        max_supply: optional_u128_arg(args, "--max-supply")?,
        mint_authority,
        metadata_authority: optional_arg(args, "--metadata-authority")
            .or_else(|| has_flag(args, "--metadata-mutable").then(|| creator.clone())),
        metadata_uri,
        metadata_hash: metadata_hash.clone(),
        metadata_mutable: has_flag(args, "--metadata-mutable"),
        image_uri: image_uri.clone(),
        image_hash: image_hash.clone(),
        flags: FungibleControlFlags {
            can_freeze: has_flag(args, "--can-freeze"),
            can_pause: has_flag(args, "--can-pause"),
            can_clawback: has_flag(args, "--can-clawback"),
            can_denylist: has_flag(args, "--can-denylist"),
            can_allowlist: has_flag(args, "--can-allowlist"),
            can_update_metadata: has_flag(args, "--can-update-metadata"),
            requires_transfer_approval: has_flag(args, "--requires-transfer-approval"),
        },
        policies: parse_policies(args)?,
        created_at,
    };

    let mut preview = StsState::new();
    let token_id = preview
        .create_fungible(params.clone())
        .map_err(|error| format!("create payload rejected by STS policy: {error}"))?;
    let token_address = preview
        .token_registry
        .get(&token_id)
        .map(|definition| definition.token_address.clone())
        .ok_or_else(|| "preview token registry did not contain created token".to_string())?;

    let tx = StsTx::CreateFungible(params);
    print_payload(
        args,
        &creator,
        StsSignedPayload::new(tx),
        Some(token_id),
        Some(token_address),
        Some(json!({
            "metadata_file": metadata_file,
            "metadata_file_sha3_256": metadata_file_hash,
            "image_file": image_file,
            "image_file_sha3_256": image_file_hash,
            "image_uri": image_uri,
            "image_hash": image_hash,
        })),
    )
}

fn build_set_image_tx(args: &[String]) -> Result<(), String> {
    let sender = sender_arg(args, "--from")?;
    let token_id = required_arg(args, "--token")?;
    validate_fungible_token_id(&token_id)?;
    let image_uri = required_arg(args, "--image-uri")?;
    let image_file = optional_arg(args, "--image-file");
    let image_file_hash = image_file.as_deref().map(hash_file_sha3_256).transpose()?;
    let image_hash = match (
        required_arg(args, "--image-hash")?,
        image_file_hash.as_ref(),
    ) {
        (explicit, Some(file_hash)) if explicit.as_str() != file_hash.as_str() => {
            return Err(format!(
                "--image-hash does not match SHA3-256(image-file): expected {file_hash}"
            ));
        }
        (explicit, _) => explicit,
    };
    validate_image_uri_hash(&image_uri, &image_hash)?;
    let timestamp = optional_u64_arg(args, "--timestamp")?.unwrap_or(current_timestamp()?);
    print_payload(
        args,
        &sender,
        StsSignedPayload::new(StsTx::SetFungibleImage {
            token_id,
            image_uri: image_uri.clone(),
            image_hash: image_hash.clone(),
            timestamp,
        }),
        None,
        None,
        Some(json!({
            "image_file": image_file,
            "image_file_sha3_256": image_file_hash,
            "image_uri": image_uri,
            "image_hash": image_hash,
        })),
    )
}

fn build_simple_amount_tx(args: &[String], op: &str) -> Result<(), String> {
    let token_id = required_arg(args, "--token")?;
    validate_fungible_token_id(&token_id)?;
    let amount = required_u128_arg(args, "--amount")?;
    let timestamp = optional_u64_arg(args, "--timestamp")?.unwrap_or(current_timestamp()?);

    let (sender, tx) = match op {
        "mint" => {
            let sender = sender_arg(args, "--from")?;
            let to = required_arg(args, "--to")?;
            (
                sender,
                StsTx::MintFungible {
                    token_id,
                    to,
                    amount,
                    timestamp,
                },
            )
        }
        "transfer" => {
            let from = sender_arg(args, "--from")?;
            let to = required_arg(args, "--to")?;
            (
                from.clone(),
                StsTx::TransferFungible {
                    token_id,
                    from,
                    to,
                    amount,
                    timestamp,
                },
            )
        }
        "burn" => {
            let from = sender_arg(args, "--from")?;
            (
                from.clone(),
                StsTx::BurnFungible {
                    token_id,
                    from,
                    amount,
                    timestamp,
                },
            )
        }
        _ => return Err(format!("unsupported simple amount op '{op}'")),
    };
    print_payload(args, &sender, StsSignedPayload::new(tx), None, None, None)
}

fn build_account_control_tx(args: &[String], frozen: bool) -> Result<(), String> {
    let sender = sender_arg(args, "--from")?;
    let token_id = required_arg(args, "--token")?;
    validate_sts_object_id(TokenClass::B2ManagedFungible, &token_id)
        .map_err(|_| "--token must be a synb2 managed fungible token ID".to_string())?;
    let owner = required_arg(args, "--owner")?;
    let timestamp = optional_u64_arg(args, "--timestamp")?.unwrap_or(current_timestamp()?);
    let tx = if frozen {
        StsTx::FreezeFungibleAccount {
            token_id,
            owner,
            timestamp,
        }
    } else {
        StsTx::ThawFungibleAccount {
            token_id,
            owner,
            timestamp,
        }
    };
    print_payload(args, &sender, StsSignedPayload::new(tx), None, None, None)
}

fn build_pause_tx(args: &[String], paused: bool) -> Result<(), String> {
    let sender = sender_arg(args, "--from")?;
    let token_id = required_arg(args, "--token")?;
    validate_sts_object_id(TokenClass::B2ManagedFungible, &token_id)
        .map_err(|_| "--token must be a synb2 managed fungible token ID".to_string())?;
    let timestamp = optional_u64_arg(args, "--timestamp")?.unwrap_or(current_timestamp()?);
    let tx = if paused {
        StsTx::PauseFungible {
            token_id,
            timestamp,
        }
    } else {
        StsTx::UnpauseFungible {
            token_id,
            timestamp,
        }
    };
    print_payload(args, &sender, StsSignedPayload::new(tx), None, None, None)
}

fn build_clawback_tx(args: &[String]) -> Result<(), String> {
    let sender = sender_arg(args, "--from")?;
    let token_id = required_arg(args, "--token")?;
    validate_sts_object_id(TokenClass::B2ManagedFungible, &token_id)
        .map_err(|_| "--token must be a synb2 managed fungible token ID".to_string())?;
    let from = required_arg(args, "--source")?;
    let to = required_arg(args, "--to")?;
    let amount = required_u128_arg(args, "--amount")?;
    let timestamp = optional_u64_arg(args, "--timestamp")?.unwrap_or(current_timestamp()?);
    print_payload(
        args,
        &sender,
        StsSignedPayload::new(StsTx::ClawbackFungible {
            token_id,
            from,
            to,
            amount,
            timestamp,
        }),
        None,
        None,
        None,
    )
}

fn build_snapshot_tx(args: &[String]) -> Result<(), String> {
    let sender = sender_arg(args, "--from")?;
    let token_id = required_arg(args, "--token")?;
    validate_sts_object_id(TokenClass::B3PolicyFungible, &token_id)
        .map_err(|_| "--token must be a synb3 policy fungible token ID".to_string())?;
    let timestamp = optional_u64_arg(args, "--timestamp")?.unwrap_or(current_timestamp()?);
    print_payload(
        args,
        &sender,
        StsSignedPayload::new(StsTx::CreateFungibleSnapshot {
            token_id,
            timestamp,
        }),
        None,
        None,
        None,
    )
}

fn build_create_nft_collection(args: &[String]) -> Result<(), String> {
    let class = parse_token_class(&required_arg(args, "--class")?)?;
    if !matches!(
        class,
        TokenClass::NF1StandardNft | TokenClass::NF2ControlledNft
    ) {
        return Err("--class must be nf1 or nf2".to_string());
    }
    let creator = sender_arg(args, "--from")?;
    let created_at = optional_u64_arg(args, "--created-at")?.unwrap_or(current_timestamp()?);
    let (metadata_file, metadata_file_hash, metadata_hash) = metadata_hash_args(args)?;
    let metadata_uri = optional_arg(args, "--metadata-uri");
    require_uri_hash_pair(
        "--metadata-uri",
        metadata_uri.as_ref(),
        metadata_hash.as_ref(),
    )?;
    let (image_file, image_file_hash, image_hash) = image_hash_args(args)?;
    let image_uri = optional_arg(args, "--image-uri");
    require_uri_hash_pair("--image-uri", image_uri.as_ref(), image_hash.as_ref())?;
    if let (Some(uri), Some(hash)) = (image_uri.as_ref(), image_hash.as_ref()) {
        validate_image_uri_hash(uri, hash)?;
    }
    let transferable = if class == TokenClass::NF1StandardNft {
        true
    } else {
        has_flag(args, "--transferable") || has_flag(args, "--requires-issuer-approval")
    };
    let royalty_basis_points = optional_u16_arg(args, "--royalty-bps")?;
    let royalty_recipient = optional_arg(args, "--royalty-recipient");
    if royalty_basis_points.unwrap_or(0) > 0 && royalty_recipient.is_none() {
        return Err(
            "--royalty-recipient is required when --royalty-bps is greater than 0".to_string(),
        );
    }
    let params = CreateNftCollectionParams {
        class,
        creator: creator.clone(),
        creator_nonce: required_u64_arg(args, "--creator-nonce")?,
        name: required_arg(args, "--name")?,
        symbol: required_arg(args, "--symbol")?,
        metadata_uri,
        metadata_hash: metadata_hash.clone(),
        metadata_mutable: has_flag(args, "--metadata-mutable"),
        image_uri: image_uri.clone(),
        image_hash: image_hash.clone(),
        collection_authority: optional_arg(args, "--collection-authority")
            .or_else(|| Some(creator.clone())),
        mint_authority: optional_arg(args, "--mint-authority").or_else(|| Some(creator.clone())),
        metadata_authority: optional_arg(args, "--metadata-authority")
            .or_else(|| has_flag(args, "--metadata-mutable").then(|| creator.clone())),
        royalty_basis_points,
        royalty_recipient,
        transferable,
        requires_issuer_approval: has_flag(args, "--requires-issuer-approval"),
        created_at,
    };
    let mut preview = StsState::new();
    let collection_id = preview
        .create_nft_collection(params.clone())
        .map_err(|error| {
            format!("create NFT collection payload rejected by STS policy: {error}")
        })?;
    let collection_address = preview
        .nft_collection(&collection_id)
        .map(|collection| collection.collection_address.clone());
    print_payload(
        args,
        &creator,
        StsSignedPayload::new(StsTx::CreateNftCollection(params)),
        Some(collection_id),
        collection_address,
        Some(json!({
            "metadata_file": metadata_file,
            "metadata_file_sha3_256": metadata_file_hash,
            "image_file": image_file,
            "image_file_sha3_256": image_file_hash,
            "image_uri": image_uri,
            "image_hash": image_hash,
        })),
    )
}

fn build_mint_nft(args: &[String]) -> Result<(), String> {
    let sender = sender_arg(args, "--from")?;
    let collection_id = required_arg(args, "--collection")?;
    validate_nft_object_id(&collection_id)?;
    let minted_at = optional_u64_arg(args, "--timestamp")?.unwrap_or(current_timestamp()?);
    let (metadata_file, metadata_file_hash, metadata_hash) = metadata_hash_args(args)?;
    let metadata_uri = optional_arg(args, "--metadata-uri");
    require_uri_hash_pair(
        "--metadata-uri",
        metadata_uri.as_ref(),
        metadata_hash.as_ref(),
    )?;
    let transferable = if has_flag(args, "--transferable") {
        Some(true)
    } else if has_flag(args, "--non-transferable") {
        Some(false)
    } else {
        None
    };
    let requires_issuer_approval = has_flag(args, "--requires-issuer-approval").then_some(true);
    print_payload(
        args,
        &sender,
        StsSignedPayload::new(StsTx::MintNft(MintNftParams {
            collection_id,
            to: required_arg(args, "--to")?,
            metadata_uri,
            metadata_hash: metadata_hash.clone(),
            metadata_mutable: has_flag(args, "--metadata-mutable"),
            transferable,
            requires_issuer_approval,
            expires_at: optional_u64_arg(args, "--expires-at")?,
            minted_at,
        })),
        None,
        None,
        Some(json!({
            "metadata_file": metadata_file,
            "metadata_file_sha3_256": metadata_file_hash,
        })),
    )
}

fn build_transfer_nft(args: &[String]) -> Result<(), String> {
    let sender = sender_arg(args, "--from")?;
    let nft_id = required_arg(args, "--nft")?;
    validate_nft_object_id(&nft_id)?;
    let owner = optional_arg(args, "--owner").unwrap_or_else(|| sender.clone());
    let timestamp = optional_u64_arg(args, "--timestamp")?.unwrap_or(current_timestamp()?);
    print_payload(
        args,
        &sender,
        StsSignedPayload::new(StsTx::TransferNft {
            nft_id,
            from: owner,
            to: required_arg(args, "--to")?,
            timestamp,
        }),
        None,
        None,
        None,
    )
}

fn build_burn_nft(args: &[String]) -> Result<(), String> {
    let sender = sender_arg(args, "--from")?;
    let nft_id = required_arg(args, "--nft")?;
    validate_nft_object_id(&nft_id)?;
    let owner = optional_arg(args, "--owner").unwrap_or_else(|| sender.clone());
    let timestamp = optional_u64_arg(args, "--timestamp")?.unwrap_or(current_timestamp()?);
    print_payload(
        args,
        &sender,
        StsSignedPayload::new(StsTx::BurnNft {
            nft_id,
            owner,
            timestamp,
        }),
        None,
        None,
        None,
    )
}

fn build_nft_control(args: &[String], op: &str) -> Result<(), String> {
    let sender = sender_arg(args, "--from")?;
    let nft_id = required_arg(args, "--nft")?;
    validate_nft_object_id(&nft_id)?;
    let timestamp = optional_u64_arg(args, "--timestamp")?.unwrap_or(current_timestamp()?);
    let tx = match op {
        "freeze" => StsTx::FreezeNft { nft_id, timestamp },
        "thaw" => StsTx::ThawNft { nft_id, timestamp },
        "revoke" => StsTx::RevokeNft { nft_id, timestamp },
        "use" => StsTx::UseNft { nft_id, timestamp },
        _ => return Err(format!("unsupported nft control op '{op}'")),
    };
    print_payload(args, &sender, StsSignedPayload::new(tx), None, None, None)
}

fn build_update_nft_metadata(args: &[String]) -> Result<(), String> {
    let sender = sender_arg(args, "--from")?;
    let nft_id = required_arg(args, "--nft")?;
    validate_nft_object_id(&nft_id)?;
    let metadata_uri = required_arg(args, "--metadata-uri")?;
    let (_, _, metadata_hash) = metadata_hash_args(args)?;
    let metadata_hash = metadata_hash
        .ok_or_else(|| "--metadata-hash or --metadata-file is required".to_string())?;
    validate_sha3_256_hash("--metadata-hash", &metadata_hash)?;
    let timestamp = optional_u64_arg(args, "--timestamp")?.unwrap_or(current_timestamp()?);
    print_payload(
        args,
        &sender,
        StsSignedPayload::new(StsTx::UpdateNftMetadata {
            nft_id,
            metadata_uri,
            metadata_hash,
            timestamp,
        }),
        None,
        None,
        None,
    )
}

fn build_verify_nft_collection(args: &[String]) -> Result<(), String> {
    let sender = sender_arg(args, "--from")?;
    let collection_id = required_arg(args, "--collection")?;
    validate_nft_object_id(&collection_id)?;
    let timestamp = optional_u64_arg(args, "--timestamp")?.unwrap_or(current_timestamp()?);
    print_payload(
        args,
        &sender,
        StsSignedPayload::new(StsTx::VerifyNftCollection {
            collection_id,
            timestamp,
        }),
        None,
        None,
        None,
    )
}

fn build_create_multi_asset_collection(args: &[String]) -> Result<(), String> {
    let creator = sender_arg(args, "--from")?;
    let created_at = optional_u64_arg(args, "--created-at")?.unwrap_or(current_timestamp()?);
    let (metadata_file, metadata_file_hash, metadata_hash) = metadata_hash_args(args)?;
    let metadata_uri = optional_arg(args, "--metadata-uri");
    require_uri_hash_pair(
        "--metadata-uri",
        metadata_uri.as_ref(),
        metadata_hash.as_ref(),
    )?;
    let (image_file, image_file_hash, image_hash) = image_hash_args(args)?;
    let image_uri = optional_arg(args, "--image-uri");
    require_uri_hash_pair("--image-uri", image_uri.as_ref(), image_hash.as_ref())?;
    if let (Some(uri), Some(hash)) = (image_uri.as_ref(), image_hash.as_ref()) {
        validate_image_uri_hash(uri, hash)?;
    }
    let params = CreateMultiAssetCollectionParams {
        creator: creator.clone(),
        creator_nonce: required_u64_arg(args, "--creator-nonce")?,
        name: required_arg(args, "--name")?,
        symbol: required_arg(args, "--symbol")?,
        metadata_uri,
        metadata_hash: metadata_hash.clone(),
        image_uri: image_uri.clone(),
        image_hash: image_hash.clone(),
        collection_authority: optional_arg(args, "--collection-authority")
            .or_else(|| Some(creator.clone())),
        metadata_authority: optional_arg(args, "--metadata-authority")
            .or_else(|| Some(creator.clone())),
        created_at,
    };
    let mut preview = StsState::new();
    let collection_id = preview
        .create_multi_asset_collection(params.clone())
        .map_err(|error| {
            format!("create multi-asset collection payload rejected by STS policy: {error}")
        })?;
    let collection_address = preview
        .multi_asset_collection(&collection_id)
        .map(|collection| collection.collection_address.clone());
    print_payload(
        args,
        &creator,
        StsSignedPayload::new(StsTx::CreateMultiAssetCollection(params)),
        Some(collection_id),
        collection_address,
        Some(json!({
            "metadata_file": metadata_file,
            "metadata_file_sha3_256": metadata_file_hash,
            "image_file": image_file,
            "image_file_sha3_256": image_file_hash,
            "image_uri": image_uri,
            "image_hash": image_hash,
        })),
    )
}

fn build_create_multi_asset_item(args: &[String]) -> Result<(), String> {
    let sender = sender_arg(args, "--from")?;
    let collection_id = required_arg(args, "--collection")?;
    validate_multi_asset_collection_id(&collection_id)?;
    let (metadata_file, metadata_file_hash, metadata_hash) = metadata_hash_args(args)?;
    let metadata_uri = optional_arg(args, "--metadata-uri");
    require_uri_hash_pair(
        "--metadata-uri",
        metadata_uri.as_ref(),
        metadata_hash.as_ref(),
    )?;
    let tx = StsTx::CreateMultiAssetItem(CreateMultiAssetItemParams {
        collection_id,
        item_id: required_u64_arg(args, "--item-id")?,
        item_type: parse_multi_asset_item_type(args)?,
        name: required_arg(args, "--name")?,
        symbol: required_arg(args, "--symbol")?,
        decimals: required_u8_arg(args, "--decimals")?,
        metadata_uri,
        metadata_hash: metadata_hash.clone(),
        max_supply: optional_u128_arg(args, "--max-supply")?,
        mint_authority: optional_arg(args, "--mint-authority"),
        burn_authority: optional_arg(args, "--burn-authority"),
        transfer_policy: parse_multi_asset_transfer_policy(args)?,
        created_at: optional_u64_arg(args, "--created-at")?.unwrap_or(current_timestamp()?),
    });
    print_payload(
        args,
        &sender,
        StsSignedPayload::new(tx),
        None,
        None,
        Some(json!({
            "metadata_file": metadata_file,
            "metadata_file_sha3_256": metadata_file_hash,
        })),
    )
}

fn build_multi_asset_amount_tx(args: &[String], op: &str) -> Result<(), String> {
    let sender = sender_arg(args, "--from")?;
    let collection_id = required_arg(args, "--collection")?;
    validate_multi_asset_collection_id(&collection_id)?;
    let item_id = required_u64_arg(args, "--item-id")?;
    let amount = required_u128_arg(args, "--amount")?;
    let timestamp = optional_u64_arg(args, "--timestamp")?.unwrap_or(current_timestamp()?);
    let tx = match op {
        "mint" => StsTx::MintMultiAsset {
            collection_id,
            item_id,
            to: required_arg(args, "--to")?,
            amount,
            timestamp,
        },
        "transfer" => StsTx::TransferMultiAsset {
            collection_id,
            item_id,
            from: optional_arg(args, "--owner").unwrap_or_else(|| sender.clone()),
            to: required_arg(args, "--to")?,
            amount,
            timestamp,
        },
        "burn" => StsTx::BurnMultiAsset {
            collection_id,
            item_id,
            from: optional_arg(args, "--owner").unwrap_or_else(|| sender.clone()),
            amount,
            timestamp,
        },
        _ => return Err(format!("unsupported multi-asset amount op '{op}'")),
    };
    print_payload(args, &sender, StsSignedPayload::new(tx), None, None, None)
}

fn build_batch_multi_asset_transfer(args: &[String]) -> Result<(), String> {
    build_batch_multi_asset_amount_tx(args, "batch-transfer")
}

fn build_batch_multi_asset_amount_tx(args: &[String], op: &str) -> Result<(), String> {
    let sender = sender_arg(args, "--from")?;
    let collection_id = required_arg(args, "--collection")?;
    validate_multi_asset_collection_id(&collection_id)?;
    let items = parse_multi_asset_amounts(args)?;
    let timestamp = optional_u64_arg(args, "--timestamp")?.unwrap_or(current_timestamp()?);
    let tx = match op {
        "batch-mint" => StsTx::BatchMintMultiAsset {
            collection_id,
            mints: items,
            to: required_arg(args, "--to")?,
            timestamp,
        },
        "batch-transfer" => StsTx::BatchTransferMultiAsset {
            collection_id,
            transfers: items,
            from: optional_arg(args, "--owner").unwrap_or_else(|| sender.clone()),
            to: required_arg(args, "--to")?,
            timestamp,
        },
        "batch-burn" => StsTx::BatchBurnMultiAsset {
            collection_id,
            burns: items,
            from: optional_arg(args, "--owner").unwrap_or_else(|| sender.clone()),
            timestamp,
        },
        _ => return Err(format!("unsupported multi-asset batch op '{op}'")),
    };
    print_payload(args, &sender, StsSignedPayload::new(tx), None, None, None)
}

fn build_create_credential_schema(args: &[String]) -> Result<(), String> {
    let sender = sender_arg(args, "--from")?;
    let schema_hash = required_arg(args, "--schema-hash")?;
    validate_sha3_256_hash("--schema-hash", &schema_hash)?;
    let description_hash = optional_arg(args, "--description-hash");
    if let Some(hash) = description_hash.as_ref() {
        validate_sha3_256_hash("--description-hash", hash)?;
    }
    let tx = StsTx::CreateCredentialSchema(CreateCredentialSchemaParams {
        issuer: sender.clone(),
        schema_id: required_arg(args, "--schema-id")?,
        name: required_arg(args, "--name")?,
        description_hash,
        schema_hash,
        active: !has_flag(args, "--inactive"),
        created_at: optional_u64_arg(args, "--created-at")?.unwrap_or(current_timestamp()?),
    });
    print_payload(args, &sender, StsSignedPayload::new(tx), None, None, None)
}

fn build_issue_credential(args: &[String]) -> Result<(), String> {
    let sender = sender_arg(args, "--from")?;
    let subject = optional_arg(args, "--subject");
    let subject_commitment = optional_arg(args, "--subject-commitment")
        .or_else(|| {
            subject
                .as_ref()
                .map(|subject| sha3_256_hex(subject.as_bytes()))
        })
        .ok_or_else(|| "--subject or --subject-commitment is required".to_string())?;
    validate_sha3_256_hash("--subject-commitment", &subject_commitment)?;
    let credential_hash = required_arg(args, "--credential-hash")?;
    validate_sha3_256_hash("--credential-hash", &credential_hash)?;
    let tx = StsTx::IssueCredential(IssueCredentialParams {
        issuer: sender.clone(),
        subject,
        subject_commitment,
        schema_id: required_arg(args, "--schema-id")?,
        credential_hash,
        expires_at: optional_u64_arg(args, "--expires-at")?,
        issued_at: optional_u64_arg(args, "--issued-at")?.unwrap_or(current_timestamp()?),
    });
    print_payload(args, &sender, StsSignedPayload::new(tx), None, None, None)
}

fn build_credential_status_tx(args: &[String], op: &str) -> Result<(), String> {
    let sender = sender_arg(args, "--from")?;
    let credential_id = required_arg(args, "--credential")?;
    validate_credential_id(&credential_id)?;
    let timestamp = optional_u64_arg(args, "--timestamp")?.unwrap_or(current_timestamp()?);
    let tx = match op {
        "revoke" => {
            let reason_hash = optional_arg(args, "--reason-hash");
            if let Some(hash) = reason_hash.as_ref() {
                validate_sha3_256_hash("--reason-hash", hash)?;
            }
            StsTx::RevokeCredential {
                credential_id,
                reason_hash,
                timestamp,
            }
        }
        "suspend" => StsTx::SuspendCredential {
            credential_id,
            timestamp,
        },
        "restore" => StsTx::RestoreCredential {
            credential_id,
            timestamp,
        },
        "expire" => StsTx::ExpireCredential {
            credential_id,
            timestamp,
        },
        "verify-status" => StsTx::VerifyCredentialStatus {
            credential_id,
            timestamp,
        },
        _ => return Err(format!("unsupported credential status op '{op}'")),
    };
    print_payload(args, &sender, StsSignedPayload::new(tx), None, None, None)
}

#[derive(Debug, Clone)]
struct WalletMaterial {
    address: String,
    public_key: Vec<u8>,
    private_key: Vec<u8>,
    source: String,
}

#[derive(Debug, Clone)]
struct CarrierTransactionOptions {
    nonce: u64,
    gas_price_nwei: u64,
    gas_limit: u64,
    carrier_amount_nwei: u64,
    receiver: String,
    timestamp: u64,
}

struct RpcClient {
    url: String,
    client: reqwest::blocking::Client,
}

impl RpcClient {
    fn new(url: String, timeout_seconds: u64) -> Result<Self, String> {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(timeout_seconds))
            .build()
            .map_err(|error| format!("failed to initialize RPC client: {error}"))?;
        Ok(Self { url, client })
    }

    fn call(&self, method: &str, params: serde_json::Value) -> Result<serde_json::Value, String> {
        let body = json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": 1,
        });
        let response = self
            .client
            .post(&self.url)
            .json(&body)
            .send()
            .map_err(|error| format!("RPC {method} request failed: {error}"))?;
        let status = response.status();
        let value = response
            .json::<serde_json::Value>()
            .map_err(|error| format!("RPC {method} returned invalid JSON: {error}"))?;
        if !status.is_success() {
            return Err(format!("RPC {method} returned HTTP {status}: {value}"));
        }
        if let Some(error) = value.get("error") {
            if !error.is_null() {
                return Err(format!("RPC {method} error: {error}"));
            }
        }
        Ok(value
            .get("result")
            .cloned()
            .unwrap_or(serde_json::Value::Null))
    }
}

fn submit_payload(
    args: &[String],
    sender: &str,
    payload_hex: &str,
    estimated_gas: u64,
) -> Result<serde_json::Value, String> {
    let wallet = load_wallet_material(args)?;
    if wallet.address != sender {
        return Err(format!(
            "--from ({sender}) must match wallet address ({}) for STS submission",
            wallet.address
        ));
    }

    let rpc_url = optional_arg(args, "--rpc-url")
        .or_else(|| std::env::var("SYNERGY_RPC_URL").ok())
        .unwrap_or_else(|| DEFAULT_RPC_URL.to_string());
    let timeout_seconds =
        optional_u64_arg(args, "--rpc-timeout-seconds")?.unwrap_or(DEFAULT_SUBMIT_TIMEOUT_SECONDS);
    let rpc = RpcClient::new(rpc_url, timeout_seconds)?;
    verify_rpc_native_asset(&rpc)?;

    let gas_price_nwei = match optional_u64_arg(args, "--gas-price-nwei")? {
        Some(price) => price,
        None => parse_json_u64(
            &rpc.call("synergy_gasPrice", json!([]))?,
            "synergy_gasPrice",
        )?
        .max(DEFAULT_GAS_PRICE_NWEI),
    };
    let gas_limit = optional_u64_arg(args, "--gas-limit")?
        .unwrap_or_else(|| estimated_gas.saturating_add(DEFAULT_STS_GAS_LIMIT_BUFFER));
    if gas_limit < estimated_gas {
        return Err(format!(
            "--gas-limit {gas_limit} is below estimated STS gas {estimated_gas}"
        ));
    }
    let carrier_amount_nwei =
        optional_u64_arg(args, "--carrier-amount-nwei")?.unwrap_or(DEFAULT_STS_CARRIER_AMOUNT_NWEI);
    let nonce = match optional_u64_arg(args, "--nonce")? {
        Some(nonce) => nonce,
        None => parse_json_u64(
            &rpc.call("synergy_getAccountNonce", json!([sender]))?,
            "synergy_getAccountNonce",
        )?,
    };
    let balance_nwei = parse_json_u128(
        &rpc.call("synergy_getTokenBalance", json!([sender, "SNRG"]))?,
        "synergy_getTokenBalance",
    )?;
    let fee_cap_nwei = (gas_limit as u128)
        .checked_mul(gas_price_nwei as u128)
        .and_then(|fee| fee.checked_add(carrier_amount_nwei as u128))
        .ok_or_else(|| "fee cap overflow".to_string())?;
    if balance_nwei < fee_cap_nwei {
        return Err(format!(
            "wallet SNRG balance {balance_nwei} nwei is below fee cap {fee_cap_nwei} nwei"
        ));
    }

    let tx_options = CarrierTransactionOptions {
        nonce,
        gas_price_nwei,
        gas_limit,
        carrier_amount_nwei,
        receiver: optional_arg(args, "--receiver").unwrap_or_else(|| sender.to_string()),
        timestamp: optional_u64_arg(args, "--timestamp")?.unwrap_or(current_timestamp()?),
    };
    let signed = build_signed_sts_carrier_transaction(&wallet, sender, payload_hex, tx_options)?;
    let tx_hash = signed.hash();
    let signed_value = serde_json::to_value(&signed)
        .map_err(|error| format!("failed to serialize signed transaction: {error}"))?;
    let submit_result = rpc.call("synergy_sendTransaction", json!([signed_value.clone()]))?;
    if !submit_result
        .get("success")
        .and_then(|value| value.as_bool())
        .unwrap_or(false)
    {
        return Err(format!(
            "synergy_sendTransaction did not accept transaction: {submit_result}"
        ));
    }

    let mut submission = json!({
        "submitted": true,
        "rpc_url": rpc.url,
        "wallet": {
            "address": wallet.address,
            "source": wallet.source,
        },
        "chain_id": SYNERGY_TESTNET_V3_CHAIN_ID,
        "network_id": SYNERGY_TESTNET_V3_NETWORK_ID,
        "tx_hash": submit_result
            .get("tx_hash")
            .and_then(|value| value.as_str())
            .unwrap_or(tx_hash.as_str()),
        "mempool_status": submit_result.get("mempool_status").cloned().unwrap_or(serde_json::Value::Null),
        "nonce": nonce,
        "gas_price_nwei": gas_price_nwei,
        "gas_limit": gas_limit,
        "carrier_amount_nwei": carrier_amount_nwei,
        "fee_cap_nwei": fee_cap_nwei.to_string(),
        "message": submit_result.get("message").cloned().unwrap_or(serde_json::Value::Null),
        "policy_warnings": submit_result.get("policy_warnings").cloned().unwrap_or(json!([])),
    });
    if has_flag(args, "--include-signed-transaction") || has_flag(args, "--include-signed-tx") {
        submission
            .as_object_mut()
            .ok_or_else(|| "submission report was not an object".to_string())?
            .insert("signed_transaction".to_string(), signed_value);
    }
    Ok(submission)
}

fn build_signed_sts_carrier_transaction(
    wallet: &WalletMaterial,
    sender: &str,
    payload_hex: &str,
    options: CarrierTransactionOptions,
) -> Result<Transaction, String> {
    if wallet.address != sender {
        return Err("wallet address does not match transaction sender".to_string());
    }
    let mut tx = Transaction {
        chain_id: SYNERGY_TESTNET_V3_CHAIN_ID,
        network_id: SYNERGY_TESTNET_V3_NETWORK_ID.to_string(),
        sender: sender.to_string(),
        receiver: options.receiver,
        amount: options.carrier_amount_nwei,
        nonce: options.nonce,
        signature: Vec::new(),
        signer_public_key: Vec::new(),
        timestamp: options.timestamp,
        gas_price: options.gas_price_nwei,
        gas_limit: options.gas_limit,
        data: Some(payload_hex.to_string()),
        signature_algorithm: "fndsa".to_string(),
    };
    let private_key = PQCPrivateKey {
        algorithm: PQCAlgorithm::FNDSA,
        key_data: wallet.private_key.clone(),
        public_key_id: wallet.address.clone(),
        created_at: options.timestamp,
    };
    let public_key = PQCPublicKey {
        algorithm: PQCAlgorithm::FNDSA,
        key_data: wallet.public_key.clone(),
        key_id: wallet.address.clone(),
        created_at: options.timestamp,
    };
    let mut manager = PQCManager::new();
    tx.sign_with_public_key(&public_key, &private_key, &mut manager)?;
    Ok(tx)
}

fn verify_rpc_native_asset(rpc: &RpcClient) -> Result<(), String> {
    let native = rpc.call("sts_getNativeAsset", json!([]))?;
    let chain_id = parse_json_u64(
        native
            .get("chain_id")
            .ok_or_else(|| "sts_getNativeAsset missing chain_id".to_string())?,
        "sts_getNativeAsset.chain_id",
    )?;
    if chain_id != STS_TESTNET_CHAIN_ID {
        return Err(format!(
            "RPC chain_id {chain_id} does not match required STS chain {STS_TESTNET_CHAIN_ID}"
        ));
    }
    if !native
        .get("token_address")
        .map(|value| value.is_null())
        .unwrap_or(false)
    {
        return Err("RPC native SNRG token_address must be null".to_string());
    }
    Ok(())
}

fn parse_json_u64(value: &serde_json::Value, label: &str) -> Result<u64, String> {
    if let Some(value) = value.as_u64() {
        return Ok(value);
    }
    if let Some(value) = value.as_str() {
        return value
            .parse::<u64>()
            .map_err(|_| format!("{label} must be a u64-compatible value"));
    }
    Err(format!("{label} must be a u64-compatible value"))
}

fn parse_json_u128(value: &serde_json::Value, label: &str) -> Result<u128, String> {
    if let Some(value) = value.as_u64() {
        return Ok(value as u128);
    }
    if let Some(value) = value.as_str() {
        return value
            .parse::<u128>()
            .map_err(|_| format!("{label} must be a u128-compatible value"));
    }
    Err(format!("{label} must be a u128-compatible value"))
}

fn sender_arg(args: &[String], name: &str) -> Result<String, String> {
    if let Some(sender) = optional_arg(args, name) {
        return Ok(sender);
    }
    if has_flag(args, "--submit") || has_flag(args, "--send") || wallet_path_arg(args).is_some() {
        return Ok(load_wallet_material(args)?.address);
    }
    Err(format!(
        "{name} is required unless a Synergy wallet is provided with --wallet"
    ))
}

fn load_wallet_material(args: &[String]) -> Result<WalletMaterial, String> {
    let wallet_path = wallet_path_arg(args).ok_or_else(|| {
        "--wallet <wallet.dec.json> is required for on-chain STS submission".to_string()
    })?;
    let wallet_path = PathBuf::from(wallet_path);
    let wallet_json = read_json_file(&wallet_path)?;
    let address = json_string_field(&wallet_json, "address")
        .ok_or_else(|| format!("{} missing address", wallet_path.display()))?;
    let private_key_text = json_string_field(&wallet_json, "private_key").ok_or_else(|| {
        format!(
            "{} must be decrypted and contain private_key",
            wallet_path.display()
        )
    })?;
    let public_key_text = if let Some(public_key) = json_string_field(&wallet_json, "public_key") {
        public_key
    } else if let Some(public_key) = public_key_from_optional_file(args) {
        public_key?
    } else if let Some(path) = sibling_public_key_path(&wallet_path) {
        public_key_from_file(&path)?
    } else {
        return Err(format!(
            "{} missing public_key and no sibling .pub.json or --wallet-public was found",
            wallet_path.display()
        ));
    };
    let public_key = decode_key_material_input(&public_key_text)
        .map_err(|error| format!("invalid wallet public_key: {error}"))?;
    let private_key = decode_key_material_input(&private_key_text)
        .map_err(|error| format!("invalid wallet private_key: {error}"))?;
    if !address_matches_public_key(&address, &public_key) {
        return Err("wallet address does not match wallet public_key".to_string());
    }
    Ok(WalletMaterial {
        address,
        public_key,
        private_key,
        source: wallet_path.display().to_string(),
    })
}

fn wallet_path_arg(args: &[String]) -> Option<String> {
    optional_arg(args, "--wallet")
        .or_else(|| optional_arg(args, "--wallet-file"))
        .or_else(|| std::env::var("SYNERGY_WALLET_FILE").ok())
}

fn public_key_from_optional_file(args: &[String]) -> Option<Result<String, String>> {
    optional_arg(args, "--wallet-public")
        .or_else(|| optional_arg(args, "--public-wallet"))
        .map(|path| public_key_from_file(Path::new(&path)))
}

fn public_key_from_file(path: &Path) -> Result<String, String> {
    let value = read_json_file(path)?;
    json_string_field(&value, "public_key")
        .ok_or_else(|| format!("{} missing public_key", path.display()))
}

fn sibling_public_key_path(wallet_path: &Path) -> Option<PathBuf> {
    let file_name = wallet_path.file_name()?.to_string_lossy();
    let pub_name = if file_name.ends_with(".dec.json") {
        file_name.replace(".dec.json", ".pub.json")
    } else {
        return None;
    };
    let path = wallet_path.with_file_name(pub_name);
    path.exists().then_some(path)
}

fn read_json_file(path: &Path) -> Result<serde_json::Value, String> {
    let contents = fs::read_to_string(path)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    serde_json::from_str(&contents)
        .map_err(|error| format!("failed to parse {} as JSON: {error}", path.display()))
}

fn json_string_field(value: &serde_json::Value, field: &str) -> Option<String> {
    value
        .get(field)
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn decode_key_material_input(input: &str) -> Result<Vec<u8>, String> {
    let mut normalized = input.trim().trim_matches('"').trim();
    if let Some((prefix, value)) = normalized.split_once(':') {
        let prefix = prefix.to_ascii_lowercase();
        if prefix.contains("fndsa") || prefix.contains("fn-dsa") || prefix.contains("falcon") {
            normalized = value.trim();
        }
    }
    let normalized = normalized.strip_prefix("0x").unwrap_or(normalized);
    if normalized.is_empty() {
        return Err("empty key material".to_string());
    }
    if normalized.len() % 2 == 0 && normalized.chars().all(|ch| ch.is_ascii_hexdigit()) {
        if let Ok(bytes) = hex::decode(normalized) {
            return Ok(bytes);
        }
    }
    general_purpose::STANDARD
        .decode(normalized.as_bytes())
        .map_err(|error| error.to_string())
}

fn print_payload(
    args: &[String],
    sender: &str,
    payload: StsSignedPayload,
    expected_token_id: Option<String>,
    expected_token_address: Option<String>,
    metadata_artifact: Option<serde_json::Value>,
) -> Result<(), String> {
    payload
        .require_testnet()
        .map_err(|error| format!("invalid STS payload network: {error}"))?;
    let payload_hex = hex::encode(
        encode_sts_payload(&payload)
            .map_err(|error| format!("payload encoding failed: {error}"))?,
    );
    let gas = estimate_sts_gas(&payload.tx);
    let gas_price_nwei =
        optional_u64_arg(args, "--gas-price-nwei")?.unwrap_or(DEFAULT_GAS_PRICE_NWEI);
    let estimated_fee_nwei = (gas as u128)
        .checked_mul(gas_price_nwei as u128)
        .ok_or_else(|| "estimated fee overflow".to_string())?;
    let mut value = json!({
            "network": payload.network,
            "chain_id": payload.chain_id,
            "sender": sender,
            "estimated_gas": gas,
            "gas_price_nwei": gas_price_nwei,
            "estimated_fee_nwei": estimated_fee_nwei.to_string(),
            "expected_token_id": expected_token_id,
            "expected_token_address": expected_token_address,
            "native_snrg_token_address": serde_json::Value::Null,
            "native_snrg_compatibility_placeholder_address": NATIVE_SNRG_PLACEHOLDER_ADDRESS,
            "metadata": metadata_artifact,
            "payload_hex": payload_hex,
            "payload": payload,
    });
    if has_flag(args, "--submit") || has_flag(args, "--send") {
        let submission = submit_payload(
            args,
            sender,
            value["payload_hex"].as_str().unwrap_or_default(),
            gas,
        )?;
        value
            .as_object_mut()
            .ok_or_else(|| "payload artifact was not an object".to_string())?
            .insert("submission".to_string(), submission);
    }
    emit_output(args, value)
}

fn payload_report(
    payload: StsSignedPayload,
    payload_hex: String,
    expected_token_id: Option<String>,
    expected_token_address: Option<String>,
    metadata_artifact: Option<serde_json::Value>,
) -> Result<serde_json::Value, String> {
    payload
        .require_testnet()
        .map_err(|error| format!("invalid STS payload network: {error}"))?;
    let gas = estimate_sts_gas(&payload.tx);
    Ok(json!({
        "network": payload.network,
        "chain_id": payload.chain_id,
        "estimated_gas": gas,
        "expected_token_id": expected_token_id,
        "expected_token_address": expected_token_address,
        "native_snrg_token_address": serde_json::Value::Null,
        "native_snrg_compatibility_placeholder_address": NATIVE_SNRG_PLACEHOLDER_ADDRESS,
        "metadata": metadata_artifact,
        "payload_hex": payload_hex,
        "payload": payload,
    }))
}

fn decode_payload_hex(payload_hex: &str) -> Result<StsSignedPayload, String> {
    let normalized = payload_hex.trim();
    if normalized.starts_with("0x") {
        return Err("payload hex must be lowercase hex without 0x".to_string());
    }
    if !normalized
        .chars()
        .all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase())
    {
        return Err("payload hex must be lowercase hex".to_string());
    }
    let bytes = hex::decode(normalized).map_err(|error| format!("invalid payload hex: {error}"))?;
    decode_sts_payload(&bytes)
        .map_err(|error| format!("invalid STS payload: {error}"))?
        .ok_or_else(|| "payload bytes do not contain the STS prefix".to_string())
}

fn payload_hex_from_args(args: &[String]) -> Result<String, String> {
    if let Some(payload_hex) = optional_arg(args, "--payload-hex") {
        return Ok(payload_hex);
    }
    let file = required_arg(args, "--file")?;
    let contents =
        fs::read_to_string(&file).map_err(|error| format!("failed to read {file}: {error}"))?;
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(&contents) {
        if let Some(payload_hex) = value.get("payload_hex").and_then(|value| value.as_str()) {
            return Ok(payload_hex.to_string());
        }
        return Err(format!("{file} is JSON but does not contain payload_hex"));
    }
    Ok(contents.trim().to_string())
}

fn validate_fungible_token_id(token_id: &str) -> Result<TokenClass, String> {
    let class = fungible_class_from_token_id(token_id)
        .ok_or_else(|| "--token must start with synb1, synb2, or synb3".to_string())?;
    validate_sts_object_id(class, token_id)
        .map_err(|_| format!("--token is not a valid {} object ID", class.prefix()))?;
    Ok(class)
}

fn fungible_class_from_token_id(token_id: &str) -> Option<TokenClass> {
    if token_id.starts_with(TokenClass::B1BasicFungible.prefix()) {
        Some(TokenClass::B1BasicFungible)
    } else if token_id.starts_with(TokenClass::B2ManagedFungible.prefix()) {
        Some(TokenClass::B2ManagedFungible)
    } else if token_id.starts_with(TokenClass::B3PolicyFungible.prefix()) {
        Some(TokenClass::B3PolicyFungible)
    } else {
        None
    }
}

fn validate_nft_object_id(object_id: &str) -> Result<TokenClass, String> {
    let class = if object_id.starts_with(TokenClass::NF1StandardNft.prefix()) {
        TokenClass::NF1StandardNft
    } else if object_id.starts_with(TokenClass::NF2ControlledNft.prefix()) {
        TokenClass::NF2ControlledNft
    } else {
        return Err("NFT object IDs must start with synn1 or synn2".to_string());
    };
    validate_sts_object_id(class, object_id)
        .map_err(|_| format!("object ID is not a valid {} Bech32m ID", class.prefix()))?;
    Ok(class)
}

fn validate_multi_asset_collection_id(collection_id: &str) -> Result<(), String> {
    validate_sts_object_id(TokenClass::MAMultiAsset, collection_id)
        .map_err(|_| "--collection must be a valid synj multi-asset collection ID".to_string())
}

fn validate_credential_id(credential_id: &str) -> Result<(), String> {
    validate_sts_object_id(TokenClass::IDCredential, credential_id)
        .map_err(|_| "--credential must be a valid synk credential ID".to_string())
}

fn metadata_hash_args(
    args: &[String],
) -> Result<(Option<String>, Option<String>, Option<String>), String> {
    optional_hash_with_file(args, "--metadata-hash", "--metadata-file", "metadata")
}

fn image_hash_args(
    args: &[String],
) -> Result<(Option<String>, Option<String>, Option<String>), String> {
    optional_hash_with_file(args, "--image-hash", "--image-file", "image")
}

fn optional_hash_with_file(
    args: &[String],
    hash_arg: &str,
    file_arg: &str,
    _label: &str,
) -> Result<(Option<String>, Option<String>, Option<String>), String> {
    let file = optional_arg(args, file_arg);
    let file_hash = file.as_deref().map(hash_file_sha3_256).transpose()?;
    let hash = match (optional_arg(args, hash_arg), file_hash.as_ref()) {
        (Some(explicit), Some(file_hash)) if explicit.as_str() != file_hash.as_str() => {
            return Err(format!(
                "{hash_arg} does not match SHA3-256({file_arg}): expected {file_hash}"
            ));
        }
        (Some(explicit), _) => Some(explicit),
        (None, Some(file_hash)) => Some(file_hash.clone()),
        (None, None) => None,
    };
    if let Some(hash) = hash.as_ref() {
        validate_sha3_256_hash(hash_arg, hash)?;
    }
    Ok((file, file_hash, hash))
}

fn require_uri_hash_pair(
    uri_arg: &str,
    uri: Option<&String>,
    hash: Option<&String>,
) -> Result<(), String> {
    if uri.is_some() && hash.is_none() {
        return Err(format!("{uri_arg} requires a matching hash"));
    }
    if uri.is_none() && hash.is_some() {
        return Err(format!(
            "{uri_arg} is required when a hash or file is provided"
        ));
    }
    Ok(())
}

fn hash_file_sha3_256(path: &str) -> Result<String, String> {
    let bytes = fs::read(path).map_err(|error| format!("failed to read file {path}: {error}"))?;
    Ok(sha3_256_hex(&bytes))
}

fn validate_sha3_256_hash(name: &str, hash: &str) -> Result<(), String> {
    if hash.len() != 64
        || hash.starts_with("0x")
        || !hash
            .chars()
            .all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase())
    {
        return Err(format!(
            "{name} must be 64 lowercase SHA3-256 hex characters without 0x"
        ));
    }
    Ok(())
}

fn validate_image_uri_hash(image_uri: &str, image_hash: &str) -> Result<(), String> {
    let allowed = image_uri.starts_with("ipfs://")
        || image_uri.starts_with("ar://")
        || image_uri.starts_with("https://");
    if !allowed
        || image_uri.len() > 512
        || image_uri
            .chars()
            .any(|ch| ch.is_ascii_control() || ch.is_ascii_whitespace() || ch == '\\')
        || image_uri.to_ascii_lowercase().contains(".svg")
    {
        return Err("image URI must be ipfs://, ar://, or https://, must not contain whitespace, and must not reference SVG".to_string());
    }
    if image_hash.len() != 64
        || image_hash.starts_with("0x")
        || !image_hash
            .chars()
            .all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase())
    {
        return Err(
            "image hash must be 64 lowercase SHA3-256 hex characters without 0x".to_string(),
        );
    }
    Ok(())
}

fn parse_multi_asset_item_type(args: &[String]) -> Result<MultiAssetItemType, String> {
    if has_flag(args, "--fungible") {
        return Ok(MultiAssetItemType::Fungible);
    }
    if has_flag(args, "--non-fungible") {
        return Ok(MultiAssetItemType::NonFungible);
    }
    if has_flag(args, "--semi-fungible") {
        return Ok(MultiAssetItemType::SemiFungible);
    }
    match required_arg(args, "--type")?.as_str() {
        "fungible" => Ok(MultiAssetItemType::Fungible),
        "non_fungible" | "non-fungible" => Ok(MultiAssetItemType::NonFungible),
        "semi_fungible" | "semi-fungible" => Ok(MultiAssetItemType::SemiFungible),
        other => Err(format!(
            "--type must be fungible, non_fungible, or semi_fungible; got '{other}'"
        )),
    }
}

fn parse_multi_asset_transfer_policy(args: &[String]) -> Result<MultiAssetTransferPolicy, String> {
    match optional_arg(args, "--transfer-policy")
        .unwrap_or_else(|| "open".to_string())
        .as_str()
    {
        "open" => Ok(MultiAssetTransferPolicy::Open),
        "non_transferable" | "non-transferable" => Ok(MultiAssetTransferPolicy::NonTransferable),
        "authority_only" | "authority-only" => Ok(MultiAssetTransferPolicy::AuthorityOnly),
        other => Err(format!(
            "--transfer-policy must be open, non_transferable, or authority_only; got '{other}'"
        )),
    }
}

fn parse_multi_asset_amounts(args: &[String]) -> Result<Vec<MultiAssetAmount>, String> {
    let mut items = Vec::new();
    for raw in arg_values(args, "--item") {
        let (item_id, amount) = raw
            .split_once(':')
            .ok_or_else(|| "--item must use <item_id>:<amount>".to_string())?;
        items.push(MultiAssetAmount {
            item_id: item_id
                .parse::<u64>()
                .map_err(|_| "--item item_id must be u64".to_string())?,
            amount: amount
                .parse::<u128>()
                .map_err(|_| "--item amount must be u128 base units".to_string())?,
        });
    }
    if items.is_empty() {
        return Err("at least one --item <item_id>:<amount> is required".to_string());
    }
    Ok(items)
}

fn emit_output(args: &[String], value: serde_json::Value) -> Result<(), String> {
    let output = match optional_arg(args, "--output")
        .unwrap_or_else(|| "json".to_string())
        .as_str()
    {
        "json" => serde_json::to_string_pretty(&value).map_err(|error| error.to_string())?,
        "compact-json" => serde_json::to_string(&value).map_err(|error| error.to_string())?,
        "payload-hex" => value
            .get("payload_hex")
            .and_then(|value| value.as_str())
            .ok_or_else(|| "--output payload-hex requires a payload artifact".to_string())?
            .to_string(),
        "payload-json" => serde_json::to_string_pretty(
            value
                .get("payload")
                .ok_or_else(|| "--output payload-json requires a payload artifact".to_string())?,
        )
        .map_err(|error| error.to_string())?,
        other => {
            return Err(format!(
                "unsupported --output '{other}'; use json, compact-json, payload-hex, or payload-json"
            ));
        }
    };

    if let Some(path) = optional_arg(args, "--out") {
        fs::write(&path, output.as_bytes())
            .map_err(|error| format!("failed to write {path}: {error}"))?;
    }
    println!("{output}");
    Ok(())
}

fn parse_token_class(value: &str) -> Result<TokenClass, String> {
    TokenClass::from_wire(value).map_err(|_| format!("invalid STS token class '{value}'"))
}

fn parse_policies(args: &[String]) -> Result<Vec<FungiblePolicy>, String> {
    arg_values(args, "--policy")
        .into_iter()
        .map(|value| parse_policy(&value))
        .collect()
}

fn parse_policy(value: &str) -> Result<FungiblePolicy, String> {
    let (template, raw_fields) = value.split_once(':').unwrap_or((value, ""));
    let fields = parse_policy_fields(raw_fields);
    match template {
        "snapshot_v1" => Ok(FungiblePolicy::SnapshotV1),
        "transfer_fee_v1" => Ok(FungiblePolicy::TransferFeeV1 {
            fee_bps: required_policy_field(&fields, "fee_bps")?
                .parse::<u16>()
                .map_err(|_| "transfer_fee_v1 fee_bps must be u16".to_string())?,
            recipient: required_policy_field(&fields, "recipient")?.to_string(),
        }),
        "vesting_v1" => Ok(FungiblePolicy::VestingV1 {
            start_at: required_policy_field(&fields, "start_at")?
                .parse::<u64>()
                .map_err(|_| "vesting_v1 start_at must be u64".to_string())?,
            cliff_at: required_policy_field(&fields, "cliff_at")?
                .parse::<u64>()
                .map_err(|_| "vesting_v1 cliff_at must be u64".to_string())?,
            end_at: required_policy_field(&fields, "end_at")?
                .parse::<u64>()
                .map_err(|_| "vesting_v1 end_at must be u64".to_string())?,
        }),
        "max_wallet_v1" => Ok(FungiblePolicy::MaxWalletV1 {
            max_balance: required_policy_field(&fields, "max_balance")?
                .parse::<u128>()
                .map_err(|_| "max_wallet_v1 max_balance must be u128 base units".to_string())?,
        }),
        other => Err(format!("unsupported STS policy template '{other}'")),
    }
}

fn parse_policy_fields(raw: &str) -> Vec<(&str, &str)> {
    raw.split(',')
        .filter_map(|part| part.split_once('='))
        .collect::<Vec<_>>()
}

fn required_policy_field<'a>(fields: &'a [(&str, &str)], key: &str) -> Result<&'a str, String> {
    fields
        .iter()
        .find_map(|(field_key, value)| (*field_key == key).then_some(*value))
        .ok_or_else(|| format!("policy field '{key}' is required"))
}

fn require_testnet(args: &[String]) -> Result<(), String> {
    let network =
        optional_arg(args, "--network").unwrap_or_else(|| STS_TESTNET_NETWORK.to_string());
    if network != STS_TESTNET_NETWORK {
        return Err(format!(
            "synergy-sts is testnet-only in this implementation; got network '{network}'"
        ));
    }
    Ok(())
}

fn optional_arg(args: &[String], name: &str) -> Option<String> {
    args.windows(2)
        .find_map(|window| (window[0] == name).then(|| window[1].clone()))
}

fn required_arg(args: &[String], name: &str) -> Result<String, String> {
    optional_arg(args, name).ok_or_else(|| format!("{name} is required"))
}

fn arg_values(args: &[String], name: &str) -> Vec<String> {
    let mut values = Vec::new();
    let mut index = 0usize;
    while index < args.len() {
        if args[index] == name {
            if let Some(value) = args.get(index + 1) {
                values.push(value.clone());
                index += 2;
                continue;
            }
        }
        index += 1;
    }
    values
}

fn has_flag(args: &[String], name: &str) -> bool {
    args.iter().any(|arg| arg == name)
}

fn required_u8_arg(args: &[String], name: &str) -> Result<u8, String> {
    required_arg(args, name)?
        .parse::<u8>()
        .map_err(|_| format!("{name} must be u8"))
}

fn optional_u16_arg(args: &[String], name: &str) -> Result<Option<u16>, String> {
    optional_arg(args, name)
        .map(|value| {
            value
                .parse::<u16>()
                .map_err(|_| format!("{name} must be u16"))
        })
        .transpose()
}

fn required_u64_arg(args: &[String], name: &str) -> Result<u64, String> {
    required_arg(args, name)?
        .parse::<u64>()
        .map_err(|_| format!("{name} must be u64"))
}

fn optional_u64_arg(args: &[String], name: &str) -> Result<Option<u64>, String> {
    optional_arg(args, name)
        .map(|value| {
            value
                .parse::<u64>()
                .map_err(|_| format!("{name} must be u64"))
        })
        .transpose()
}

fn required_u128_arg(args: &[String], name: &str) -> Result<u128, String> {
    required_arg(args, name)?
        .parse::<u128>()
        .map_err(|_| format!("{name} must be u128 base units"))
}

fn optional_u128_arg(args: &[String], name: &str) -> Result<Option<u128>, String> {
    optional_arg(args, name)
        .map(|value| {
            value
                .parse::<u128>()
                .map_err(|_| format!("{name} must be u128 base units"))
        })
        .transpose()
}

fn current_timestamp() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock is before Unix epoch".to_string())
        .map(|duration| duration.as_secs())
}

fn sha3_256_hex(bytes: &[u8]) -> String {
    use sha3::{Digest, Sha3_256};
    let hash: [u8; 32] = Sha3_256::digest(bytes).into();
    hex::encode(hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_supported_policy_templates() {
        assert!(matches!(
            parse_policy("snapshot_v1").unwrap(),
            FungiblePolicy::SnapshotV1
        ));
        assert!(matches!(
            parse_policy("transfer_fee_v1:fee_bps=25,recipient=synw1abc").unwrap(),
            FungiblePolicy::TransferFeeV1 { .. }
        ));
        assert!(matches!(
            parse_policy("max_wallet_v1:max_balance=1000").unwrap(),
            FungiblePolicy::MaxWalletV1 { max_balance: 1000 }
        ));
        assert!(parse_policy("unsupported_v1").is_err());
    }

    #[test]
    fn rejects_non_testnet_network() {
        let args = vec!["--network".to_string(), "mainnet".to_string()];
        assert!(require_testnet(&args).is_err());
    }

    #[test]
    fn decodes_lowercase_sts_payload_hex_and_rejects_0x() {
        let payload = StsSignedPayload::new(StsTx::TransferFungible {
            token_id: "synb11w7523v07vcc4n28knfnvyt6lq8649mey8p5ywd".to_string(),
            from: "synw1from000000000000000000000000000000".to_string(),
            to: "synw1to00000000000000000000000000000000".to_string(),
            amount: 1,
            timestamp: 1_700_000_000,
        });
        let hex_payload = hex::encode(encode_sts_payload(&payload).unwrap());
        assert_eq!(decode_payload_hex(&hex_payload).unwrap(), payload);
        assert!(decode_payload_hex(&format!("0x{hex_payload}")).is_err());
    }

    #[test]
    fn fungible_token_prefix_validation_is_class_aware() {
        assert!(validate_fungible_token_id("synb11w7523v07vcc4n28knfnvyt6lq8649mey8p5ywd").is_ok());
        assert!(validate_sts_object_id(
            TokenClass::B2ManagedFungible,
            "synb11w7523v07vcc4n28knfnvyt6lq8649mey8p5ywd"
        )
        .is_err());
    }
}
