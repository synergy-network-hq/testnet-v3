//! Invoke the canonical Rust integrity recompute over a structural Genesis
//! candidate. This binary owns no hash logic of its own: it loads JSON, calls
//! `genesis::recompute_testnet_v3_candidate_integrity`, and writes the result.
//!
//! usage: recompute-testnet-v3-genesis --input <FILE> --output <FILE>

use serde_json::Value;
use std::{env, fs, process};
use synergy_testnet::genesis::recompute_testnet_v3_candidate_integrity;

fn fail(message: impl AsRef<str>) -> ! {
    eprintln!("recompute-testnet-v3-genesis: {}", message.as_ref());
    process::exit(1);
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let mut input = None;
    let mut output = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--input" => {
                input = args.get(index + 1).cloned();
                index += 2;
            }
            "--output" => {
                output = args.get(index + 1).cloned();
                index += 2;
            }
            other => fail(format!("unknown argument {other}")),
        }
    }
    let (Some(input), Some(output)) = (input, output) else {
        fail("usage: --input <FILE> --output <FILE>");
    };

    let text = fs::read_to_string(&input)
        .unwrap_or_else(|error| fail(format!("read {input}: {error}")));
    let mut value: Value = serde_json::from_str(&text)
        .unwrap_or_else(|error| fail(format!("parse {input}: {error}")));

    let before_genesis_hash = value
        .get("integrity")
        .and_then(|entry| entry.get("genesis_hash"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();

    if let Err(error) = recompute_testnet_v3_candidate_integrity(&mut value) {
        fail(format!("recompute failed: {error}"));
    }

    let rendered = serde_json::to_string_pretty(&value)
        .unwrap_or_else(|error| fail(format!("serialize: {error}")));
    fs::write(&output, format!("{rendered}\n"))
        .unwrap_or_else(|error| fail(format!("write {output}: {error}")));

    let integrity = value.get("integrity").unwrap_or(&Value::Null);
    let show = |key: &str| {
        integrity
            .get(key)
            .and_then(Value::as_str)
            .unwrap_or("<missing>")
            .to_string()
    };
    println!("RECOMPUTE_OK");
    println!("input_genesis_hash   {before_genesis_hash}");
    println!("genesis_hash         {}", show("genesis_hash"));
    println!("state_root           {}", show("state_root"));
    println!("validator_hash       {}", show("validator_hash"));
    println!("validator_set_hash   {}", show("validator_set_hash"));
    println!("contract_hash        {}", show("contract_hash"));
    println!("allocation_hash      {}", show("allocation_hash"));
    println!(
        "header_state_root    {}",
        value
            .get("header")
            .and_then(|entry| entry.get("state_root"))
            .and_then(Value::as_str)
            .unwrap_or("<missing>")
    );
    println!(
        "network_magic        {}",
        value
            .get("network_magic_bytes")
            .and_then(|entry| entry.get("value"))
            .and_then(Value::as_str)
            .unwrap_or("<missing>")
    );
}
