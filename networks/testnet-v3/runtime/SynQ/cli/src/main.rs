use clap::{Parser, Subcommand};
use std::fs;
use std::path::{Path, PathBuf};
use synq_compiler::{PQCCompiler, PQCSecurityLevel};
use synq_vm::{QuantumVM, Value};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Compiles a SynQ source file
    Compile {
        /// The path to the SynQ source file
        #[arg(short, long)]
        path: PathBuf,
    },
    /// Runs a compiled SynQ bytecode file
    Run {
        /// The path to the SynQ bytecode file
        #[arg(short, long)]
        path: PathBuf,
        /// Call a specific contract function by name instead of running
        /// from the top of the bytecode.
        #[arg(short, long)]
        function: Option<String>,
        /// Comma-separated integer arguments for --function, e.g. "1,2,3" or "-100,50"
        #[arg(short, long, allow_hyphen_values = true)]
        args: Option<String>,
        /// List the callable functions in this bytecode file and exit.
        #[arg(long)]
        list_functions: bool,
    },
    /// Verifies the PQC signature sidecar file produced by `compile`
    Verify {
        /// The path to the compiled .synq_bytecode file
        #[arg(short, long)]
        path: PathBuf,
    },
}

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Compile { path } => {
            compile(path);
        }
        Commands::Run {
            path,
            function,
            args,
            list_functions,
        } => {
            run(path, function.as_deref(), args.as_deref(), *list_functions);
        }
        Commands::Verify { path } => {
            verify(path);
        }
    }
}

/// Signature algorithm used for compiled bytecode. Dilithium (ML-DSA-65) is
/// the default "Enhanced" security-level signer in PQCCompiler.
const SIGNING_ALGORITHM: &str = "dilithium";

fn sig_sidecar_path(bytecode_path: &Path) -> PathBuf {
    // e.g. "counter.synq_bytecode" -> "counter.synq_bytecode.sig.json"
    let mut s = bytecode_path.as_os_str().to_os_string();
    s.push(".sig.json");
    PathBuf::from(s)
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("invalid hex in signature file"))
        .collect()
}

fn compile(path: &PathBuf) {
    println!("Compiling SynQ with PQC: {}", path.display());
    // Guard: reject binary files passed by mistake (e.g. .qvm instead of .synq)
    let source = match fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {
            eprintln!(
                "❌ Error: {} does not appear to be a text file.",
                path.display()
            );
            eprintln!("   synq-cli compile expects a SynQ source file (.synq), not a bytecode file (.qvm).");
            eprintln!("   Example: synq-cli compile --path mycontract.synq");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("❌ Error: Failed to read source file: {}", e);
            std::process::exit(1);
        }
    };

    // Parse SynQ source
    let ast = synq_compiler::parser::parse(&source).expect("Failed to parse source file");

    // Generate bytecode
    let codegen = synq_compiler::codegen::CodeGenerator::new();
    let (bytecode, _state_layout) = codegen.generate(&ast).expect("Failed to generate bytecode");

    // Real PQC signing over the compiled bytecode using a fresh, EPHEMERAL
    // ML-DSA-65 (Dilithium) keypair generated for this compile only. The
    // private key is used once to sign and then dropped -- it is never
    // written to disk. This replaces the old fake
    // "PQC_SIGNATURE_<timestamp>" placeholder string with a real signature
    // that can actually be verified (see the `verify` subcommand).
    //
    // Ephemeral (vs persistent/wallet-derived) was chosen as the starting
    // point: it proves the real signing path end-to-end without requiring
    // a key-management/storage design yet. Revisit once persistent identity
    // keys are needed (e.g. tied to a wallet address).
    let pqc = PQCCompiler::new(PQCSecurityLevel::Enhanced);
    let keypair = pqc
        .generate_keypair(SIGNING_ALGORITHM)
        .expect("Failed to generate ephemeral signing keypair");
    let signature = pqc
        .sign_message(&keypair.private_key, &bytecode, SIGNING_ALGORITHM)
        .expect("Failed to sign bytecode");

    let output_path = path.with_extension("synq_bytecode");
    fs::write(&output_path, &bytecode).expect("Failed to write bytecode file");

    let sig_path = sig_sidecar_path(&output_path);
    let sig_json = serde_json::json!({
        "algorithm": signature.algorithm,
        "security_level": format!("{:?}", signature.security_level),
        "public_key": hex_encode(&keypair.public_key),
        "signature": hex_encode(&signature.signature),
    });
    fs::write(&sig_path, serde_json::to_string_pretty(&sig_json).unwrap())
        .expect("Failed to write signature sidecar file");

    println!(
        "✅ Successfully compiled SynQ with PQC to {}",
        output_path.display()
    );
    println!("🔒 PQC Security Level: Enhanced");
    println!(
        "🔏 Signed with real {} (ephemeral keypair) -- signature + public key written to {}",
        signature.algorithm,
        sig_path.display()
    );
}

fn verify(path: &PathBuf) {
    println!("Verifying PQC signature for: {}", path.display());

    let bytecode = match fs::read(path) {
        Ok(b) => b,
        Err(_) => {
            eprintln!("❌ Error: bytecode file not found: {}", path.display());
            std::process::exit(1);
        }
    };

    let sig_path = sig_sidecar_path(path);
    let sig_content = match fs::read_to_string(&sig_path) {
        Ok(s) => s,
        Err(_) => {
            eprintln!(
                "❌ Error: no signature sidecar found at {}",
                sig_path.display()
            );
            eprintln!("   Was this file compiled with synq-cli? Server-compiled .qvm files");
            eprintln!("   do not have a local sidecar -- signature is embedded in the response.");
            std::process::exit(1);
        }
    };

    let sig_json: serde_json::Value = match serde_json::from_str(&sig_content) {
        Ok(v) => v,
        Err(_) => {
            eprintln!(
                "❌ Error: malformed signature sidecar file at {}",
                sig_path.display()
            );
            std::process::exit(1);
        }
    };

    // Support both sidecar formats:
    //   flat:   { algorithm, public_key, signature }           <- synq-cli compile
    //   hybrid: { mode, evm: {...}, pqc: { algorithm, ... } }  <- server /attest endpoint
    //
    // IMPORTANT: for hybrid sidecars the server signed evm_sig_bytes ++ raw_bytecode,
    // NOT raw_bytecode alone. We must reconstruct the same message here to verify.
    let is_hybrid = sig_json["mode"].as_str() == Some("hybrid") && sig_json["pqc"].is_object();
    let sig_node = if is_hybrid {
        &sig_json["pqc"]
    } else {
        &sig_json
    };

    let algorithm = match sig_node["algorithm"].as_str() {
        Some(a) => a,
        None => {
            eprintln!("❌ Error: missing 'algorithm' field in sidecar");
            std::process::exit(1);
        }
    };
    let public_key = match sig_node["public_key"].as_str() {
        Some(h) => hex_decode(h),
        None => {
            eprintln!("❌ Error: missing 'public_key' field in sidecar");
            std::process::exit(1);
        }
    };
    let signature_bytes = match sig_node["signature"].as_str() {
        Some(h) => hex_decode(h),
        None => {
            eprintln!("❌ Error: missing 'signature' field in sidecar");
            std::process::exit(1);
        }
    };

    // Reconstruct the exact message that was signed.
    let verify_message: Vec<u8> = if is_hybrid {
        // Server signed: evm_sig_bytes (65 bytes) ++ raw_bytecode_bytes
        let raw_evm_hex = sig_json["evm"]["signature"].as_str().unwrap_or("");
        let clean_evm = raw_evm_hex.strip_prefix("0x").unwrap_or(raw_evm_hex);
        let evm_sig_bytes = hex_decode(clean_evm);
        if evm_sig_bytes.len() != 65 {
            eprintln!(
                "❌ Error: EVM signature in sidecar is {} bytes, expected 65",
                evm_sig_bytes.len()
            );
            std::process::exit(1);
        }
        let evm_addr = sig_json["evm"]["address"].as_str().unwrap_or("-");
        let evm_hash = sig_json["evm"]["message_hash"].as_str().unwrap_or("-");
        let hash_short = &evm_hash[..evm_hash.len().min(22)];
        println!("ℹ️  Hybrid sidecar detected");
        println!("   EVM address:  {}", evm_addr);
        println!("   EVM sig hash: {}...", hash_short);
        println!("   PQC covers:   evm_signature_bytes ++ raw_bytecode_bytes");
        let mut msg = Vec::with_capacity(evm_sig_bytes.len() + bytecode.len());
        msg.extend_from_slice(&evm_sig_bytes);
        msg.extend_from_slice(&bytecode);
        msg
    } else {
        bytecode.clone()
    };

    let pqc = PQCCompiler::new(PQCSecurityLevel::Enhanced);
    match pqc.verify_signature(&public_key, &signature_bytes, &verify_message, algorithm) {
        Ok(true) => println!("✅ Signature valid ({}) -- bundle is untampered", algorithm),
        Ok(false) => println!("❌ Signature INVALID -- bytecode does not match signature on file"),
        Err(e) => println!("❌ Verification error: {}", e),
    }
}

fn run(path: &PathBuf, function: Option<&str>, args: Option<&str>, list_functions: bool) {
    println!("Running SynQ with PQC: {}", path.display());
    let bytecode = match fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("❌ Error: could not read file {}: {}", path.display(), e);
            std::process::exit(1);
        }
    };

    // Reject non-bytecode files early with a helpful message
    if bytecode.starts_with(b"{")
        || bytecode.starts_with(b"//")
        || bytecode.starts_with(b"contract")
    {
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if ext == "json" || path.to_string_lossy().contains(".sig.json") {
            eprintln!(
                "❌ Error: {} is a signature sidecar file, not bytecode.",
                path.display()
            );
            eprintln!("   Pass the .qvm or .synq_bytecode file instead.");
            eprintln!(
                "   Example: synq-cli run --path contract.synq_bytecode --function mint --args 100"
            );
        } else {
            eprintln!(
                "❌ Error: {} does not look like compiled bytecode.",
                path.display()
            );
            eprintln!("   Compile your source first: synq-cli compile --path contract.synq");
        }
        std::process::exit(1);
    }

    // Initialize SynQ VM with PQC support
    let mut vm = QuantumVM::new();
    if let Err(e) = vm.load_bytecode(&bytecode) {
        let hint = if path.to_string_lossy().ends_with(".sig.json") {
            "
   Tip: pass the .qvm/.synq_bytecode file, not the .sig.json sidecar."
        } else if path.extension().and_then(|e| e.to_str()) == Some("synq") {
            "
   Tip: this looks like a source file -- compile it first with synq-cli compile."
        } else {
            ""
        };
        eprintln!("❌ Error: failed to load bytecode: {}{}", e, hint);
        std::process::exit(1);
    }

    if list_functions {
        println!("📋 Callable functions:");
        for name in vm.list_functions() {
            println!("  - {}", name);
        }
        return;
    }

    if let Some(name) = function {
        let parsed_args: Vec<Value> = match args {
            Some(s) if !s.is_empty() => s
                .split(',')
                .map(|part| {
                    Value::I32(part.trim().parse().expect("Function args must be integers"))
                })
                .collect(),
            _ => vec![],
        };

        match vm.call_function(name, &parsed_args) {
            Ok(Some(result)) => {
                println!("✅ Function '{}' returned: {:?}", name, result);
            }
            Ok(None) => {
                // Stack was empty after execution — genuinely void function.
                println!("✅ Function '{}' executed (void)", name);
            }
            Err(e) => {
                println!("❌ Function call failed: {}", e);
            }
        }
        return;
    }

    // Execute with PQC verification
    match vm.execute() {
        Ok(()) => {
            println!("✅ Execution finished successfully");
            println!("🔒 PQC Verification: Passed");
        }
        Err(e) => {
            println!("❌ VM execution failed: {}", e);
            println!("🔒 PQC Verification: Failed");
        }
    }
}
