//! Deterministic SynQ ABI and manifest artifact generation.

use crate::ast::{
    Block, ContractDefinition, ContractPart, EventDefinition, FunctionDefinition, SourceUnit,
    Statement, Type,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const SYNQ_ABI_VERSION: &str = "0.1";
pub const SYNQ_ARTIFACT_FORMAT: &str = "synq-bytecode-v1";
pub const SYNQ_BYTECODE_VERSION: u16 = 1;
pub const SYNQ_MANIFEST_VERSION: &str = "0.1";
pub const SYNQ_REQUIRED_AIVM_VERSION: &str = "0.1";
pub const SYNQ_TESTNET_CHAIN_ID: u64 = 1264;
pub const SYNQ_TESTNET_NETWORK_ID: &str = "synergy-testnet";
pub const SYNQ_TESTNET_SIGNATURE_ALGORITHM: &str = "ML-DSA-65";
pub const SYNQ_TESTNET_SECURITY_POLICY: &str = "synq-testnet-1264-v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactConfig {
    pub bytecode_version: u16,
    pub required_aivm_version: String,
    pub required_chain_id: u64,
    pub required_network_id: String,
    pub required_signature_algorithm: String,
    pub security_policy: String,
}

impl ArtifactConfig {
    pub fn testnet_1264() -> Self {
        Self {
            bytecode_version: SYNQ_BYTECODE_VERSION,
            required_aivm_version: SYNQ_REQUIRED_AIVM_VERSION.to_string(),
            required_chain_id: SYNQ_TESTNET_CHAIN_ID,
            required_network_id: SYNQ_TESTNET_NETWORK_ID.to_string(),
            required_signature_algorithm: SYNQ_TESTNET_SIGNATURE_ALGORITHM.to_string(),
            security_policy: SYNQ_TESTNET_SECURITY_POLICY.to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SynQAbiArtifact {
    pub abi_version: String,
    pub contract: String,
    pub errors: Vec<SynQAbiError>,
    pub events: Vec<SynQAbiEvent>,
    pub methods: Vec<SynQAbiMethod>,
    pub security_requirements: SynQSecurityRequirements,
    pub state_schema: Vec<SynQAbiStateField>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SynQAbiError {
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SynQAbiEvent {
    pub name: String,
    pub params: Vec<SynQAbiParameter>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SynQAbiMethod {
    pub mutability: String,
    pub name: String,
    pub params: Vec<SynQAbiParameter>,
    pub returns: Vec<String>,
    pub selector: String,
    pub visibility: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SynQAbiParameter {
    pub indexed: bool,
    pub name: String,
    pub r#type: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SynQAbiStateField {
    pub name: String,
    pub r#type: String,
    pub visibility: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SynQSecurityRequirements {
    pub call_domain: String,
    pub deploy_domain: String,
    pub signature_algorithm: String,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactHashes {
    pub abi_hash: String,
    pub bytecode_hash: String,
    pub manifest_hash: String,
    pub source_hash: String,
    pub storage_schema_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactBundle {
    pub abi: SynQAbiArtifact,
    pub bytecode: Vec<u8>,
    pub hashes: ArtifactHashes,
    pub manifest: SynQManifestArtifact,
}

impl ArtifactBundle {
    pub fn generate(source: &str, ast: &[SourceUnit], bytecode: Vec<u8>) -> Result<Self, String> {
        Self::generate_with_config(source, ast, bytecode, &ArtifactConfig::testnet_1264())
    }

    pub fn generate_with_config(
        source: &str,
        ast: &[SourceUnit],
        bytecode: Vec<u8>,
        config: &ArtifactConfig,
    ) -> Result<Self, String> {
        let contract = single_contract(ast)?;
        let abi = build_abi(contract);
        let abi_bytes = serde_json::to_vec(&abi)
            .map_err(|error| format!("failed to serialize deterministic ABI JSON: {error}"))?;
        let state_schema_bytes = serde_json::to_vec(&abi.state_schema).map_err(|error| {
            format!("failed to serialize deterministic storage schema JSON: {error}")
        })?;

        let abi_hash = sha256_hex(&abi_bytes);
        let bytecode_hash = sha256_hex(&bytecode);
        let source_hash = sha256_hex(source.as_bytes());
        let storage_schema_hash = sha256_hex(&state_schema_bytes);
        let manifest = SynQManifestArtifact {
            abi_hash: abi_hash.clone(),
            artifact_format: SYNQ_ARTIFACT_FORMAT.to_string(),
            bytecode_hash: bytecode_hash.clone(),
            bytecode_version: config.bytecode_version,
            compiler_version: env!("CARGO_PKG_VERSION").to_string(),
            contract_name: contract.name.clone(),
            host_functions: Vec::new(),
            manifest_version: SYNQ_MANIFEST_VERSION.to_string(),
            permissions: Vec::new(),
            required_aivm_version: config.required_aivm_version.clone(),
            required_chain_id: config.required_chain_id,
            required_network_id: config.required_network_id.clone(),
            required_signature_algorithm: config.required_signature_algorithm.clone(),
            security_policy: config.security_policy.clone(),
            source_hash: source_hash.clone(),
            storage_schema_hash: storage_schema_hash.clone(),
        };
        let manifest_hash = sha256_hex(&serde_json::to_vec(&manifest).map_err(|error| {
            format!("failed to serialize deterministic manifest JSON: {error}")
        })?);

        Ok(Self {
            abi,
            bytecode,
            hashes: ArtifactHashes {
                abi_hash,
                bytecode_hash,
                manifest_hash,
                source_hash,
                storage_schema_hash,
            },
            manifest,
        })
    }

    pub fn abi_json(&self) -> Result<Vec<u8>, String> {
        serde_json::to_vec(&self.abi)
            .map_err(|error| format!("failed to serialize deterministic ABI JSON: {error}"))
    }

    pub fn manifest_json(&self) -> Result<Vec<u8>, String> {
        serde_json::to_vec(&self.manifest)
            .map_err(|error| format!("failed to serialize deterministic manifest JSON: {error}"))
    }
}

fn single_contract(ast: &[SourceUnit]) -> Result<&ContractDefinition, String> {
    let mut contracts = ast.iter().filter_map(|unit| match unit {
        SourceUnit::Contract(contract) => Some(contract),
        _ => None,
    });
    let contract = contracts
        .next()
        .ok_or_else(|| "artifact generation requires one contract definition".to_string())?;
    if contracts.next().is_some() {
        return Err(
            "artifact generation currently requires exactly one contract definition".to_string(),
        );
    }
    Ok(contract)
}

fn build_abi(contract: &ContractDefinition) -> SynQAbiArtifact {
    let mut events = Vec::new();
    let mut methods = Vec::new();
    let mut state_schema = Vec::new();

    for part in &contract.parts {
        match part {
            ContractPart::Event(event) => events.push(build_event(event)),
            ContractPart::Function(function) => methods.push(build_method(function)),
            ContractPart::StateVariable(state) => state_schema.push(SynQAbiStateField {
                name: state.name.clone(),
                r#type: type_name(&state.ty),
                visibility: visibility(state.is_public),
            }),
            ContractPart::Constructor(_) => {}
        }
    }

    SynQAbiArtifact {
        abi_version: SYNQ_ABI_VERSION.to_string(),
        contract: contract.name.clone(),
        errors: Vec::new(),
        events,
        methods,
        security_requirements: SynQSecurityRequirements {
            call_domain: "SYNQ_CONTRACT_CALL_V1".to_string(),
            deploy_domain: "SYNQ_CONTRACT_DEPLOY_V1".to_string(),
            signature_algorithm: "ML-DSA-65".to_string(),
        },
        state_schema,
    }
}

fn build_event(event: &EventDefinition) -> SynQAbiEvent {
    SynQAbiEvent {
        name: event.name.clone(),
        params: event.params.iter().map(build_parameter).collect(),
    }
}

fn build_method(function: &FunctionDefinition) -> SynQAbiMethod {
    let signature = format!(
        "{}({})",
        function.name,
        function
            .params
            .iter()
            .map(|parameter| type_name(&parameter.ty))
            .collect::<Vec<_>>()
            .join(",")
    );
    let selector = Sha256::digest(signature.as_bytes());

    SynQAbiMethod {
        mutability: if block_mutates_state(&function.body) {
            "write"
        } else {
            "view"
        }
        .to_string(),
        name: function.name.clone(),
        params: function.params.iter().map(build_parameter).collect(),
        returns: function
            .returns
            .as_ref()
            .map(type_name)
            .into_iter()
            .collect(),
        selector: format!("0x{}", hex(&selector[..4])),
        visibility: visibility(function.is_public),
    }
}

fn build_parameter(parameter: &crate::ast::Parameter) -> SynQAbiParameter {
    SynQAbiParameter {
        indexed: parameter.is_indexed,
        name: parameter.name.clone(),
        r#type: type_name(&parameter.ty),
    }
}

fn block_mutates_state(block: &Block) -> bool {
    block.statements.iter().any(statement_mutates_state)
}

fn statement_mutates_state(statement: &Statement) -> bool {
    match statement {
        Statement::Assignment(_, _) | Statement::Emit(_, _) => true,
        Statement::If(_, then_block, else_block) => {
            block_mutates_state(then_block) || else_block.as_ref().is_some_and(block_mutates_state)
        }
        Statement::For(_, _, _, block) | Statement::RequirePqc(block, _) => {
            block_mutates_state(block)
        }
        _ => false,
    }
}

fn type_name(ty: &Type) -> String {
    match ty {
        Type::Address => "address".to_string(),
        Type::UInt256 => "u256".to_string(),
        Type::UInt8 => "u8".to_string(),
        Type::UInt32 => "u32".to_string(),
        Type::UInt64 => "u64".to_string(),
        Type::UInt128 => "u128".to_string(),
        Type::Int256 => "i256".to_string(),
        Type::Int8 => "i8".to_string(),
        Type::Int32 => "i32".to_string(),
        Type::Int64 => "i64".to_string(),
        Type::Int128 => "i128".to_string(),
        Type::Bool => "bool".to_string(),
        Type::Bytes => "bytes".to_string(),
        Type::String => "string".to_string(),
        Type::Array(item, Some(length)) => format!("[{};{length}]", type_name(item)),
        Type::Array(item, None) => format!("[{}]", type_name(item)),
        Type::Mapping(key, value) => format!("map<{},{}>", type_name(key), type_name(value)),
        Type::Struct(name) => format!("struct<{name}>"),
        Type::MLDSAPublicKey => "ml-dsa-public-key".to_string(),
        Type::MLDSAKeyPair => "ml-dsa-key-pair".to_string(),
        Type::MLDSASignature => "ml-dsa-signature".to_string(),
        Type::FNDSAPublicKey => "fn-dsa-public-key".to_string(),
        Type::FNDSAKeyPair => "fn-dsa-key-pair".to_string(),
        Type::FNDSASignature => "fn-dsa-signature".to_string(),
        Type::MLKEMPublicKey => "ml-kem-public-key".to_string(),
        Type::MLKEMKeyPair => "ml-kem-key-pair".to_string(),
        Type::MLKEMCiphertext => "ml-kem-ciphertext".to_string(),
        Type::SLHDSAPublicKey => "slh-dsa-public-key".to_string(),
        Type::SLHDSAKeyPair => "slh-dsa-key-pair".to_string(),
        Type::SLHDSASignature => "slh-dsa-signature".to_string(),
        Type::Generic(name, items) => format!(
            "{}<{}>",
            name,
            items.iter().map(type_name).collect::<Vec<_>>().join(",")
        ),
    }
}

fn visibility(is_public: bool) -> String {
    if is_public { "public" } else { "private" }.to_string()
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}
