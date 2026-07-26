use aivm_core::execution::{ContractArtifact, ContractFormat, ExecutionContext, ExecutionStatus};
use aivm_core::state::ContractState;
use aivm_core::synq_runtime::{
    call_synq_contract, deploy_synq_contract, synq_execution_request, COUNTER_GET_SELECTOR,
    COUNTER_INCREMENT_SELECTOR,
};

fn main() -> Result<(), String> {
    let mut state = ContractState::default();
    let artifact = counter_artifact()?;
    let deploy_request = synq_execution_request(
        "Counter",
        artifact.clone(),
        ExecutionContext::testnet_1266_for_contract("Counter", 10_000),
        Vec::new(),
    );
    let deploy_receipt = deploy_synq_contract(&deploy_request, &mut state);
    if deploy_receipt.status != ExecutionStatus::Succeeded {
        return Err(format!(
            "AIVM SynQ deploy failed: {:?}",
            deploy_receipt.error
        ));
    }

    let increment_request = synq_execution_request(
        "Counter",
        artifact.clone(),
        ExecutionContext::testnet_1266_for_contract("Counter", 10_000),
        COUNTER_INCREMENT_SELECTOR.to_vec(),
    );
    let increment_receipt = call_synq_contract(&increment_request, &mut state);
    if increment_receipt.status != ExecutionStatus::Succeeded {
        return Err(format!(
            "AIVM SynQ increment failed: {:?}",
            increment_receipt.error
        ));
    }

    let get_request = synq_execution_request(
        "Counter",
        artifact,
        ExecutionContext::testnet_1266_for_contract("Counter", 10_000),
        COUNTER_GET_SELECTOR.to_vec(),
    );
    let get_receipt = call_synq_contract(&get_request, &mut state);
    if get_receipt.status != ExecutionStatus::Succeeded {
        return Err(format!("AIVM SynQ get failed: {:?}", get_receipt.error));
    }

    println!("execution_mode=stateful-synq-aivm");
    println!(
        "deploy_receipt_hash={}",
        hex(&deploy_receipt.canonical_hash())
    );
    println!(
        "counter_increment_return={}",
        decode_u256(&increment_receipt.return_data)?
    );
    println!(
        "counter_get_return={}",
        decode_u256(&get_receipt.return_data)?
    );
    println!("state_root={}", hex(&state.state_root()));
    println!(
        "increment_receipt_hash={}",
        hex(&increment_receipt.canonical_hash())
    );
    println!("get_receipt_hash={}", hex(&get_receipt.canonical_hash()));
    Ok(())
}

fn counter_artifact() -> Result<ContractArtifact, String> {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../synq-language/contracts");
    let bytecode = std::fs::read(root.join("Counter.compiled.synq"))
        .map_err(|error| format!("failed to read Counter bytecode: {error}"))?;
    let abi_json = std::fs::read_to_string(root.join("Counter.abi.json"))
        .map_err(|error| format!("failed to read Counter ABI: {error}"))?;
    let manifest_json = std::fs::read_to_string(root.join("Counter.manifest.json"))
        .map_err(|error| format!("failed to read Counter manifest: {error}"))?;
    Ok(ContractArtifact {
        format: ContractFormat::SynqBytecodeV1,
        bytes: bytecode,
        abi_json: Some(abi_json),
        manifest_json: Some(manifest_json),
        metadata_json: None,
        compiler_version: None,
        source_hash: None,
    })
}

fn decode_u256(data: &[u8]) -> Result<u64, String> {
    if data.len() != 32 {
        return Err(format!("expected 32-byte u256, got {}", data.len()));
    }
    let mut tail = [0_u8; 8];
    tail.copy_from_slice(&data[24..32]);
    Ok(u64::from_be_bytes(tail))
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}
