use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

use crate::error::{AivmError, AivmErrorCode};
use crate::metering::AivmGasMeter;
use crate::vm::wasm_runner;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ContractFormat {
    SynqBytecodeV1,
    WasmModuleV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractArtifact {
    pub format: ContractFormat,
    pub bytes: Vec<u8>,
    pub abi_json: Option<String>,
    #[serde(default)]
    pub manifest_json: Option<String>,
    #[serde(default)]
    pub metadata_json: Option<String>,
    pub compiler_version: Option<String>,
    pub source_hash: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SynQManifestArtifact {
    pub abi_hash: String,
    pub artifact_format: String,
    pub bytecode_hash: String,
    pub bytecode_version: u16,
    pub compiler_version: String,
    pub contract_name: String,
    pub host_functions: Vec<String>,
    pub manifest_version: String,
    pub permissions: Vec<String>,
    pub required_aivm_version: String,
    pub required_chain_id: u64,
    pub required_network_id: String,
    pub required_signature_algorithm: String,
    pub security_policy: String,
    pub source_hash: String,
    pub storage_schema_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AivmSecurityPolicyRef {
    pub policy_id: String,
    pub required_signature_policy: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionContext {
    #[serde(default)]
    pub admission_pq_gas_used: u64,
    #[serde(default)]
    pub runtime_block_height: u64,
    pub chain_id: u64,
    pub network_id: String,
    pub block_height: u64,
    pub block_timestamp_unix: u64,
    pub tx_hash: [u8; 32],
    pub caller: Vec<u8>,
    pub contract_address: Vec<u8>,
    pub gas_limit: u64,
    pub pq_gas_limit: u64,
    pub security_policy: AivmSecurityPolicyRef,
    #[serde(default)]
    pub sts_host: Option<StsHostContext>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StsHostContext {
    pub object_classes: BTreeMap<String, u8>,
    pub fungible_tokens: BTreeMap<String, StsHostFungibleToken>,
    pub fungible_balances: BTreeMap<String, u128>,
    pub nfts: BTreeMap<String, StsHostNft>,
    pub multi_asset_balances: BTreeMap<String, u128>,
    pub credentials: BTreeMap<String, StsHostCredential>,
    pub credential_lookup: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StsHostFungibleToken {
    pub class: u8,
    pub total_supply: u128,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StsHostNft {
    pub class: u8,
    pub owner: String,
    pub burned: bool,
    pub revoked: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StsHostCredential {
    pub status: u8,
    pub issuer: String,
    pub subject: Option<String>,
    pub subject_commitment: String,
    pub schema_id: String,
    pub expires_at: Option<u64>,
}

impl StsHostContext {
    pub fn fungible_balance_key(token_id: &str, owner: &str) -> String {
        format!("{token_id}:{owner}")
    }

    pub fn multi_asset_balance_key(collection_id: &str, item_id: u64, owner: &str) -> String {
        format!("{collection_id}:{item_id}:{owner}")
    }

    pub fn credential_lookup_key(
        subject_or_commitment: &str,
        schema_id: &str,
        issuer: &str,
    ) -> String {
        format!("{subject_or_commitment}:{schema_id}:{issuer}")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionRequest {
    pub contract_id: String,
    pub artifact: ContractArtifact,
    pub calldata: Vec<u8>,
    pub context: ExecutionContext,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExecutionStatus {
    Succeeded,
    Reverted,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionReceipt {
    pub contract_id: String,
    pub context: ExecutionReceiptContext,
    pub status: ExecutionStatus,
    pub gas_used: u64,
    pub pqc_gas_used: u64,
    pub return_data: Vec<u8>,
    pub logs: Vec<String>,
    pub error_code: Option<AivmErrorCode>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionReceiptContext {
    pub chain_id: u64,
    pub network_id: String,
    pub block_height: u64,
    pub tx_hash: [u8; 32],
    pub caller: Vec<u8>,
    pub contract_address: Vec<u8>,
    pub artifact_hash: [u8; 32],
    pub policy_id: String,
    pub required_signature_policy: String,
}

impl ExecutionContext {
    pub fn testnet_1264_for_contract(contract_id: &str, gas_limit: u64) -> Self {
        Self {
            admission_pq_gas_used: 0,
            runtime_block_height: 0,
            chain_id: 1264,
            network_id: "synergy-testnet".to_string(),
            block_height: 0,
            block_timestamp_unix: 0,
            tx_hash: [0_u8; 32],
            caller: Vec::new(),
            contract_address: contract_id.as_bytes().to_vec(),
            gas_limit,
            pq_gas_limit: 300_000,
            security_policy: AivmSecurityPolicyRef {
                policy_id: "synq-testnet-1264-v1".to_string(),
                required_signature_policy: "ml-dsa-65".to_string(),
            },
            sts_host: None,
        }
    }
}

impl ExecutionReceiptContext {
    pub fn from_request(request: &ExecutionRequest) -> Self {
        let digest = Sha256::digest(&request.artifact.bytes);
        let mut artifact_hash = [0_u8; 32];
        artifact_hash.copy_from_slice(&digest);
        Self {
            chain_id: request.context.chain_id,
            network_id: canonical_network_id(&request.context.network_id),
            block_height: request.context.block_height,
            tx_hash: request.context.tx_hash,
            caller: request.context.caller.clone(),
            contract_address: request.context.contract_address.clone(),
            artifact_hash,
            policy_id: request.context.security_policy.policy_id.clone(),
            required_signature_policy: request
                .context
                .security_policy
                .required_signature_policy
                .clone(),
        }
    }
}

impl ExecutionRequest {
    pub fn synq(contract_id: impl Into<String>, bytecode: Vec<u8>, gas_limit: u64) -> Self {
        let contract_id = contract_id.into();
        Self {
            context: ExecutionContext::testnet_1264_for_contract(&contract_id, gas_limit),
            contract_id,
            artifact: ContractArtifact {
                format: ContractFormat::SynqBytecodeV1,
                bytes: bytecode,
                abi_json: None,
                manifest_json: None,
                metadata_json: None,
                compiler_version: None,
                source_hash: None,
            },
            calldata: Vec::new(),
        }
    }
}

impl ExecutionReceipt {
    pub fn canonical_hash(&self) -> [u8; 32] {
        let mut out = Vec::new();
        out.extend_from_slice(b"AIVM-RECEIPT-V1");
        push_bytes(&mut out, self.contract_id.as_bytes());
        push_receipt_context(&mut out, &self.context);
        push_u16(&mut out, execution_status_code(&self.status));
        push_u64(&mut out, self.gas_used);
        push_u64(&mut out, self.pqc_gas_used);
        push_bytes(&mut out, &self.return_data);
        push_u64(&mut out, self.logs.len() as u64);
        for log in &self.logs {
            push_bytes(&mut out, log.as_bytes());
        }
        match self.error_code {
            Some(code) => {
                push_u16(&mut out, aivm_error_code_value(code));
            }
            None => push_u16(&mut out, 0),
        }
        match &self.error {
            Some(error) => push_bytes(&mut out, error.as_bytes()),
            None => push_bytes(&mut out, &[]),
        }

        let digest = Sha256::digest(&out);
        let mut hash = [0_u8; 32];
        hash.copy_from_slice(&digest);
        hash
    }
}

pub fn execute_contract(request: &ExecutionRequest) -> ExecutionReceipt {
    match request.artifact.format {
        ContractFormat::SynqBytecodeV1 => execute_synq_contract(request),
        ContractFormat::WasmModuleV1 => execute_wasm_module(request),
    }
}

fn failed(
    request: &ExecutionRequest,
    gas_used: u64,
    pqc_gas_used: u64,
    error: AivmError,
) -> ExecutionReceipt {
    ExecutionReceipt {
        contract_id: request.contract_id.clone(),
        context: ExecutionReceiptContext::from_request(request),
        status: ExecutionStatus::Failed,
        gas_used,
        pqc_gas_used,
        return_data: Vec::new(),
        logs: Vec::new(),
        error_code: Some(error.code),
        error: Some(error.message),
    }
}

#[cfg(feature = "synq")]
fn execute_synq_contract(request: &ExecutionRequest) -> ExecutionReceipt {
    let mut meter = AivmGasMeter::new(request.context.gas_limit, request.context.pq_gas_limit);
    if let Err(error) = meter.charge_pq_gas(request.context.admission_pq_gas_used) {
        return failed(request, meter.gas_used(), meter.pq_gas_used(), error);
    }

    if let Err(error) = validate_synq_artifact(request) {
        return failed(request, meter.gas_used(), meter.pq_gas_used(), error);
    }

    let mut vm = quantumvm::QuantumVM::with_gas(meter.remaining_gas(), meter.remaining_pq_gas());

    if let Err(err) = vm.load_bytecode(&request.artifact.bytes) {
        return failed(
            request,
            meter.gas_used() + vm.consumed_gas(),
            meter.pq_gas_used() + vm.consumed_pqc_gas(),
            AivmError::bytecode(err.to_string()),
        );
    }

    match vm.execute() {
        Ok(()) => ExecutionReceipt {
            contract_id: request.contract_id.clone(),
            context: ExecutionReceiptContext::from_request(request),
            status: ExecutionStatus::Succeeded,
            gas_used: meter.gas_used() + vm.consumed_gas(),
            pqc_gas_used: meter.pq_gas_used() + vm.consumed_pqc_gas(),
            return_data: format!("{:?}", vm.stack).into_bytes(),
            logs: Vec::new(),
            error_code: None,
            error: None,
        },
        Err(err) => failed(
            request,
            meter.gas_used() + vm.consumed_gas(),
            meter.pq_gas_used() + vm.consumed_pqc_gas(),
            map_vm_execution_error(err),
        ),
    }
}

pub fn validate_synq_artifact(request: &ExecutionRequest) -> Result<(), AivmError> {
    let manifest_json = request.artifact.manifest_json.as_deref().ok_or_else(|| {
        AivmError::new(
            AivmErrorCode::Manifest,
            "SynQ bytecode execution requires a manifest artifact",
        )
    })?;
    let manifest: SynQManifestArtifact = serde_json::from_str(manifest_json).map_err(|error| {
        AivmError::new(
            AivmErrorCode::Manifest,
            format!("failed to decode SynQ manifest artifact: {error}"),
        )
    })?;

    if manifest.artifact_format != "synq-bytecode-v1" {
        return Err(AivmError::new(
            AivmErrorCode::Manifest,
            format!(
                "unsupported SynQ artifact format {}; expected synq-bytecode-v1",
                manifest.artifact_format
            ),
        ));
    }
    if manifest.bytecode_version != 1 {
        return Err(AivmError::new(
            AivmErrorCode::Bytecode,
            format!(
                "unsupported SynQ bytecode version {}",
                manifest.bytecode_version
            ),
        ));
    }
    let bytecode_hash = sha256_hex(&request.artifact.bytes);
    if manifest.bytecode_hash != bytecode_hash {
        return Err(AivmError::new(
            AivmErrorCode::Bytecode,
            format!(
                "SynQ bytecode hash mismatch: manifest {} actual {}",
                manifest.bytecode_hash, bytecode_hash
            ),
        ));
    }
    if let Some(abi_json) = request.artifact.abi_json.as_deref() {
        let abi_hash = sha256_hex(abi_json.as_bytes());
        if manifest.abi_hash != abi_hash {
            return Err(AivmError::new(
                AivmErrorCode::Abi,
                format!(
                    "SynQ ABI hash mismatch: manifest {} actual {}",
                    manifest.abi_hash, abi_hash
                ),
            ));
        }
    }
    if manifest.required_chain_id != 1264 || request.context.chain_id != manifest.required_chain_id
    {
        return Err(AivmError::new(
            AivmErrorCode::Manifest,
            format!(
                "SynQ chain mismatch: manifest {} context {}",
                manifest.required_chain_id, request.context.chain_id
            ),
        ));
    }
    if normalize_testnet_network(&manifest.required_network_id).is_none()
        || normalize_testnet_network(&request.context.network_id)
            != normalize_testnet_network(&manifest.required_network_id)
    {
        return Err(AivmError::new(
            AivmErrorCode::Manifest,
            format!(
                "SynQ network mismatch: manifest {} context {}",
                manifest.required_network_id, request.context.network_id
            ),
        ));
    }
    if manifest.required_signature_algorithm != "ML-DSA-65"
        || request.context.security_policy.required_signature_policy != "ml-dsa-65"
    {
        return Err(AivmError::new(
            AivmErrorCode::Verification,
            format!(
                "SynQ signature policy mismatch: manifest {} context {}",
                manifest.required_signature_algorithm,
                request.context.security_policy.required_signature_policy
            ),
        ));
    }
    if manifest.security_policy != request.context.security_policy.policy_id {
        return Err(AivmError::new(
            AivmErrorCode::Manifest,
            format!(
                "SynQ security policy mismatch: manifest {} context {}",
                manifest.security_policy, request.context.security_policy.policy_id
            ),
        ));
    }
    Ok(())
}

fn normalize_testnet_network(network_id: &str) -> Option<&'static str> {
    match network_id {
        "synergy-testnet" | "synergy-testnet-v3" => Some("synergy-testnet"),
        _ => None,
    }
}

fn canonical_network_id(network_id: &str) -> String {
    normalize_testnet_network(network_id)
        .unwrap_or_else(|| network_id.trim())
        .to_ascii_lowercase()
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

#[cfg(feature = "synq")]
fn map_vm_execution_error(error: quantumvm::VMError) -> AivmError {
    match &error {
        quantumvm::VMError::OutOfGas(message) if message.contains("PQC gas") => {
            AivmError::pq_gas(error.to_string())
        }
        quantumvm::VMError::OutOfGas(_) => AivmError::gas(error.to_string()),
        _ => AivmError::runtime_trap(error.to_string()),
    }
}

#[cfg(not(feature = "synq"))]
fn execute_synq_contract(request: &ExecutionRequest) -> ExecutionReceipt {
    failed(
        request,
        0,
        0,
        AivmError::runtime_trap(
            "AIVM was built without the synq feature; SynQ bytecode execution is unavailable",
        ),
    )
}

fn execute_wasm_module(request: &ExecutionRequest) -> ExecutionReceipt {
    match wasm_runner::run_wasm_bytes(&request.artifact.bytes) {
        Ok(outcome) => ExecutionReceipt {
            contract_id: request.contract_id.clone(),
            context: ExecutionReceiptContext::from_request(request),
            status: ExecutionStatus::Succeeded,
            gas_used: 0,
            pqc_gas_used: 0,
            return_data: serde_json::to_vec(&outcome).unwrap_or_default(),
            logs: Vec::new(),
            error_code: None,
            error: None,
        },
        Err(err) => failed(request, 0, 0, err),
    }
}

fn push_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn push_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn push_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    push_u64(out, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

pub(crate) fn push_receipt_context(out: &mut Vec<u8>, context: &ExecutionReceiptContext) {
    out.extend_from_slice(b"AIVM-RECEIPT-CONTEXT-V1");
    push_u64(out, context.chain_id);
    push_bytes(out, context.network_id.as_bytes());
    push_u64(out, context.block_height);
    out.extend_from_slice(&context.tx_hash);
    push_bytes(out, &context.caller);
    push_bytes(out, &context.contract_address);
    out.extend_from_slice(&context.artifact_hash);
    push_bytes(out, context.policy_id.as_bytes());
    push_bytes(out, context.required_signature_policy.as_bytes());
}

fn execution_status_code(status: &ExecutionStatus) -> u16 {
    match status {
        ExecutionStatus::Succeeded => 1,
        ExecutionStatus::Reverted => 2,
        ExecutionStatus::Failed => 3,
    }
}

fn aivm_error_code_value(code: AivmErrorCode) -> u16 {
    match code {
        AivmErrorCode::Bytecode => 1,
        AivmErrorCode::Manifest => 2,
        AivmErrorCode::Abi => 3,
        AivmErrorCode::Verification => 4,
        AivmErrorCode::Gas => 5,
        AivmErrorCode::PqGas => 6,
        AivmErrorCode::RuntimeTrap => 7,
        AivmErrorCode::State => 8,
        AivmErrorCode::HostFunction => 9,
        AivmErrorCode::Receipt => 10,
        AivmErrorCode::InternalInvariant => 11,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    #[test]
    fn accepts_wasm_artifacts() {
        let request = ExecutionRequest {
            contract_id: "minimal-wasm".to_string(),
            artifact: ContractArtifact {
                format: ContractFormat::WasmModuleV1,
                bytes: b"\0asm\x01\0\0\0".to_vec(),
                abi_json: None,
                manifest_json: None,
                metadata_json: None,
                compiler_version: None,
                source_hash: None,
            },
            calldata: Vec::new(),
            context: ExecutionContext::testnet_1264_for_contract("minimal-wasm", 10_000),
        };

        let receipt = execute_contract(&request);
        assert_eq!(receipt.status, ExecutionStatus::Succeeded);
    }

    #[test]
    fn execution_context_carries_chain_and_metering_inputs() {
        let context = ExecutionContext::testnet_1264_for_contract("counter", 50_000);

        assert_eq!(context.chain_id, 1264);
        assert_eq!(context.admission_pq_gas_used, 0);
        assert_eq!(context.network_id, "synergy-testnet");
        assert_eq!(context.gas_limit, 50_000);
        assert_eq!(context.pq_gas_limit, 300_000);
        assert_eq!(
            context.security_policy.required_signature_policy,
            "ml-dsa-65"
        );
    }

    #[test]
    fn rejects_wasm_host_imports_with_structured_error_code() {
        let wasm_with_import = [
            0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, // header
            0x01, 0x04, 0x01, 0x60, 0x00, 0x00, // type section
            0x02, 0x0d, 0x01, 0x03, b'e', b'n', b'v', 0x05, b'c', b'l', b'o', b'c', b'k', 0x00,
            0x00, // import env.clock as function type 0
        ];
        let request = ExecutionRequest {
            contract_id: "host-import".to_string(),
            artifact: ContractArtifact {
                format: ContractFormat::WasmModuleV1,
                bytes: wasm_with_import.to_vec(),
                abi_json: None,
                manifest_json: None,
                metadata_json: None,
                compiler_version: None,
                source_hash: None,
            },
            calldata: Vec::new(),
            context: ExecutionContext::testnet_1264_for_contract("host-import", 10_000),
        };

        let receipt = execute_contract(&request);

        assert_eq!(receipt.status, ExecutionStatus::Failed);
        assert_eq!(receipt.error_code, Some(AivmErrorCode::HostFunction));
    }

    #[cfg(feature = "synq")]
    #[test]
    fn invalid_synq_bytecode_returns_bytecode_error_code() {
        let request = synq_request_with_manifest("bad-bytecode", b"not-qvm".to_vec(), None, 10_000);

        let receipt = execute_contract(&request);

        assert_eq!(receipt.status, ExecutionStatus::Failed);
        assert_eq!(receipt.error_code, Some(AivmErrorCode::Bytecode));
    }

    #[test]
    fn receipt_canonical_hash_is_deterministic() {
        let request = ExecutionRequest {
            contract_id: "minimal-wasm".to_string(),
            artifact: ContractArtifact {
                format: ContractFormat::WasmModuleV1,
                bytes: b"\0asm\x01\0\0\0".to_vec(),
                abi_json: None,
                manifest_json: None,
                metadata_json: None,
                compiler_version: None,
                source_hash: None,
            },
            calldata: Vec::new(),
            context: ExecutionContext::testnet_1264_for_contract("minimal-wasm", 10_000),
        };

        let first = execute_contract(&request);
        let second = execute_contract(&request);

        assert_eq!(first, second);
        assert_eq!(first.canonical_hash(), second.canonical_hash());
    }

    #[test]
    fn receipt_canonical_hash_binds_transaction_context() {
        let artifact = ContractArtifact {
            format: ContractFormat::WasmModuleV1,
            bytes: b"\0asm\x01\0\0\0".to_vec(),
            abi_json: None,
            manifest_json: None,
            metadata_json: None,
            compiler_version: None,
            source_hash: None,
        };
        let mut first_context = ExecutionContext::testnet_1264_for_contract("minimal-wasm", 10_000);
        first_context.tx_hash = [1_u8; 32];
        first_context.caller = b"caller-a".to_vec();
        let mut second_context =
            ExecutionContext::testnet_1264_for_contract("minimal-wasm", 10_000);
        second_context.tx_hash = [2_u8; 32];
        second_context.caller = b"caller-b".to_vec();

        let first = execute_contract(&ExecutionRequest {
            contract_id: "minimal-wasm".to_string(),
            artifact: artifact.clone(),
            calldata: Vec::new(),
            context: first_context,
        });
        let second = execute_contract(&ExecutionRequest {
            contract_id: "minimal-wasm".to_string(),
            artifact,
            calldata: Vec::new(),
            context: second_context,
        });

        assert_eq!(first.status, second.status);
        assert_eq!(first.return_data, second.return_data);
        assert_ne!(first.canonical_hash(), second.canonical_hash());
    }

    #[cfg(feature = "synq")]
    #[test]
    fn executes_synq_bytecode_artifacts() {
        let mut assembler = quantumvm::Assembler::new();
        assembler.emit_op(quantumvm::OpCode::Push);
        assembler.emit_i32(42);
        assembler.emit_op(quantumvm::OpCode::Return);

        let request = synq_request_with_manifest("synq-smoke", assembler.build(), None, 10_000);
        let receipt = execute_contract(&request);

        assert_eq!(receipt.status, ExecutionStatus::Succeeded);
        assert_eq!(receipt.gas_used, 6);
        assert!(String::from_utf8(receipt.return_data)
            .expect("stack should be debug text")
            .contains("I32(42)"));
    }

    #[cfg(feature = "synq")]
    #[test]
    fn synq_receipt_reports_admission_pq_gas() {
        let mut assembler = quantumvm::Assembler::new();
        assembler.emit_op(quantumvm::OpCode::Return);

        let mut request =
            synq_request_with_manifest("synq-pq-meter", assembler.build(), None, 10_000);
        request.context.admission_pq_gas_used = 42;
        let receipt = execute_contract(&request);

        assert_eq!(receipt.status, ExecutionStatus::Succeeded);
        assert_eq!(receipt.pqc_gas_used, 42);
    }

    #[cfg(feature = "synq")]
    #[test]
    fn rejects_admission_pq_gas_exhaustion_with_structured_error() {
        let mut assembler = quantumvm::Assembler::new();
        assembler.emit_op(quantumvm::OpCode::Return);

        let mut request =
            synq_request_with_manifest("synq-pq-exhausted", assembler.build(), None, 10_000);
        request.context.pq_gas_limit = 41;
        request.context.admission_pq_gas_used = 42;
        let receipt = execute_contract(&request);

        assert_eq!(receipt.status, ExecutionStatus::Failed);
        assert_eq!(receipt.error_code, Some(AivmErrorCode::PqGas));
    }

    #[cfg(feature = "synq")]
    #[test]
    fn missing_synq_manifest_fails_closed() {
        let request = ExecutionRequest::synq("missing-manifest", minimal_synq_bytecode(), 10_000);
        let receipt = execute_contract(&request);

        assert_eq!(receipt.status, ExecutionStatus::Failed);
        assert_eq!(receipt.error_code, Some(AivmErrorCode::Manifest));
    }

    #[cfg(feature = "synq")]
    #[test]
    fn valid_synq_manifest_and_abi_validate_before_execution() {
        let request = synq_request_with_manifest(
            "manifest-valid",
            minimal_synq_bytecode(),
            Some(valid_abi_json()),
            10_000,
        );
        let receipt = execute_contract(&request);

        assert_eq!(receipt.status, ExecutionStatus::Succeeded);
    }

    #[cfg(feature = "synq")]
    #[test]
    fn checked_in_counter_artifact_envelope_validates() {
        let request = checked_in_counter_request();

        validate_synq_artifact(&request).expect("Counter artifact envelope validates");
    }

    #[cfg(feature = "synq")]
    #[test]
    fn checked_in_counter_artifact_rejects_tampered_manifest_hash() {
        let mut request = checked_in_counter_request();
        request.artifact.manifest_json = request.artifact.manifest_json.as_ref().map(|manifest| {
            manifest.replace(
                "6b8b2d0d1433c0c4941bfc41054a58a004e9cc46e475926f0f70d3d309e92533",
                "0000000000000000000000000000000000000000000000000000000000000000",
            )
        });

        let error = validate_synq_artifact(&request).expect_err("tampered manifest rejected");

        assert_eq!(error.code, AivmErrorCode::Bytecode);
    }

    #[cfg(feature = "synq")]
    #[test]
    fn wrong_bytecode_hash_fails_with_bytecode_error() {
        let bytecode = minimal_synq_bytecode();
        let mut request = synq_request_with_manifest("wrong-bytecode", bytecode, None, 10_000);
        request.artifact.manifest_json = Some(valid_manifest_json(
            "00",
            &sha256_hex(valid_abi_json().as_bytes()),
            "synergy-testnet",
            1264,
            "ML-DSA-65",
            "synq-bytecode-v1",
            1,
        ));

        let receipt = execute_contract(&request);

        assert_eq!(receipt.status, ExecutionStatus::Failed);
        assert_eq!(receipt.error_code, Some(AivmErrorCode::Bytecode));
    }

    #[cfg(feature = "synq")]
    #[test]
    fn wrong_abi_hash_fails_with_abi_error() {
        let bytecode = minimal_synq_bytecode();
        let mut request = synq_request_with_manifest(
            "wrong-abi",
            bytecode.clone(),
            Some(valid_abi_json()),
            10_000,
        );
        request.artifact.manifest_json = Some(valid_manifest_json(
            &sha256_hex(&bytecode),
            "00",
            "synergy-testnet",
            1264,
            "ML-DSA-65",
            "synq-bytecode-v1",
            1,
        ));

        let receipt = execute_contract(&request);

        assert_eq!(receipt.status, ExecutionStatus::Failed);
        assert_eq!(receipt.error_code, Some(AivmErrorCode::Abi));
    }

    #[cfg(feature = "synq")]
    #[test]
    fn wrong_chain_and_network_fail_with_manifest_error() {
        let mut wrong_chain =
            synq_request_with_manifest("wrong-chain", minimal_synq_bytecode(), None, 10_000);
        wrong_chain.context.chain_id = 999;
        let wrong_chain_receipt = execute_contract(&wrong_chain);
        assert_eq!(
            wrong_chain_receipt.error_code,
            Some(AivmErrorCode::Manifest)
        );

        let mut wrong_network =
            synq_request_with_manifest("wrong-network", minimal_synq_bytecode(), None, 10_000);
        wrong_network.context.network_id = "mainnet".to_string();
        let wrong_network_receipt = execute_contract(&wrong_network);
        assert_eq!(
            wrong_network_receipt.error_code,
            Some(AivmErrorCode::Manifest)
        );
    }

    #[cfg(feature = "synq")]
    #[test]
    fn node_testnet_v3_alias_is_accepted_for_chain_1264() {
        let mut request =
            synq_request_with_manifest("network-alias", minimal_synq_bytecode(), None, 10_000);
        request.context.network_id = "synergy-testnet-v3".to_string();

        let receipt = execute_contract(&request);

        assert_eq!(receipt.status, ExecutionStatus::Succeeded);
    }

    #[cfg(feature = "synq")]
    #[test]
    fn unsupported_artifact_format_fails_with_manifest_error() {
        let bytecode = minimal_synq_bytecode();
        let mut request = synq_request_with_manifest("bad-format", bytecode.clone(), None, 10_000);
        request.artifact.manifest_json = Some(valid_manifest_json(
            &sha256_hex(&bytecode),
            &sha256_hex(valid_abi_json().as_bytes()),
            "synergy-testnet",
            1264,
            "ML-DSA-65",
            "wasm-module-v1",
            1,
        ));

        let receipt = execute_contract(&request);

        assert_eq!(receipt.status, ExecutionStatus::Failed);
        assert_eq!(receipt.error_code, Some(AivmErrorCode::Manifest));
    }

    #[cfg(feature = "synq")]
    #[test]
    fn unsupported_signature_policy_fails_with_verification_error() {
        let bytecode = minimal_synq_bytecode();
        let mut request = synq_request_with_manifest("bad-policy", bytecode.clone(), None, 10_000);
        request.artifact.manifest_json = Some(valid_manifest_json(
            &sha256_hex(&bytecode),
            &sha256_hex(valid_abi_json().as_bytes()),
            "synergy-testnet",
            1264,
            "FN-DSA",
            "synq-bytecode-v1",
            1,
        ));

        let receipt = execute_contract(&request);

        assert_eq!(receipt.status, ExecutionStatus::Failed);
        assert_eq!(receipt.error_code, Some(AivmErrorCode::Verification));
    }

    #[cfg(feature = "synq")]
    fn synq_request_with_manifest(
        contract_id: &str,
        bytecode: Vec<u8>,
        abi_json: Option<String>,
        gas_limit: u64,
    ) -> ExecutionRequest {
        let mut request = ExecutionRequest::synq(contract_id, bytecode.clone(), gas_limit);
        let abi_hash = abi_json
            .as_deref()
            .map(|abi| sha256_hex(abi.as_bytes()))
            .unwrap_or_else(|| sha256_hex(valid_abi_json().as_bytes()));
        request.artifact.abi_json = abi_json;
        request.artifact.manifest_json = Some(valid_manifest_json(
            &sha256_hex(&bytecode),
            &abi_hash,
            "synergy-testnet",
            1264,
            "ML-DSA-65",
            "synq-bytecode-v1",
            1,
        ));
        request
    }

    #[cfg(feature = "synq")]
    fn minimal_synq_bytecode() -> Vec<u8> {
        let mut assembler = quantumvm::Assembler::new();
        assembler.emit_op(quantumvm::OpCode::Return);
        assembler.build()
    }

    #[cfg(feature = "synq")]
    fn valid_abi_json() -> String {
        r#"{"abi_version":"0.1","contract":"Counter","errors":[],"events":[],"methods":[],"security_requirements":{"call_domain":"SYNQ_CONTRACT_CALL_V1","deploy_domain":"SYNQ_CONTRACT_DEPLOY_V1","signature_algorithm":"ML-DSA-65"},"state_schema":[]}"#.to_string()
    }

    #[cfg(feature = "synq")]
    fn valid_manifest_json(
        bytecode_hash: &str,
        abi_hash: &str,
        network_id: &str,
        chain_id: u64,
        signature_algorithm: &str,
        artifact_format: &str,
        bytecode_version: u16,
    ) -> String {
        format!(
            r#"{{"abi_hash":"{abi_hash}","artifact_format":"{artifact_format}","bytecode_hash":"{bytecode_hash}","bytecode_version":{bytecode_version},"compiler_version":"0.1.0","contract_name":"Counter","host_functions":[],"manifest_version":"0.1","permissions":[],"required_aivm_version":"0.1","required_chain_id":{chain_id},"required_network_id":"{network_id}","required_signature_algorithm":"{signature_algorithm}","security_policy":"synq-testnet-1264-v1","source_hash":"00","storage_schema_hash":"00"}}"#
        )
    }

    #[cfg(feature = "synq")]
    fn checked_in_counter_request() -> ExecutionRequest {
        let root =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../synq-language/contracts");
        let bytecode = fs::read(root.join("Counter.compiled.synq")).expect("Counter bytecode");
        let abi_json = fs::read_to_string(root.join("Counter.abi.json")).expect("Counter ABI");
        let manifest_json =
            fs::read_to_string(root.join("Counter.manifest.json")).expect("Counter manifest");
        let mut request = ExecutionRequest::synq("Counter", bytecode, 10_000);
        request.artifact.abi_json = Some(abi_json);
        request.artifact.manifest_json = Some(manifest_json);
        request
    }
}
