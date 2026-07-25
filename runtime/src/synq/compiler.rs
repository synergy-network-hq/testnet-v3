use crate::crypto::pqc::{PQCAlgorithm, PQCManager};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SynQContract {
    pub name: String,
    pub version: String,
    pub code: String,
    pub bytecode: Vec<u8>,
    pub abi: String,
    pub pqc_algorithm: PQCAlgorithm,
    pub cross_chain_enabled: bool,
    pub created_at: u64,
    pub author: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompilationResult {
    pub success: bool,
    pub bytecode: Vec<u8>,
    pub solidity_code: String,
    pub synq_code: String,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
    pub pqc_signatures: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SynQFunction {
    pub name: String,
    pub parameters: Vec<SynQParameter>,
    pub return_type: String,
    pub visibility: FunctionVisibility,
    pub body: String,
    pub is_payable: bool,
    pub is_view: bool,
    pub is_pure: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SynQParameter {
    pub name: String,
    pub param_type: String,
    pub is_indexed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum FunctionVisibility {
    Public,
    Private,
    Internal,
    External,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SynQVariable {
    pub name: String,
    pub var_type: String,
    pub value: Option<String>,
    pub is_constant: bool,
    pub is_immutable: bool,
}

#[derive(Debug)]
pub struct SynQCompiler {
    pqc_manager: PQCManager,
    contracts: HashMap<String, SynQContract>,
    compiled_results: HashMap<String, CompilationResult>,
}

impl SynQCompiler {
    pub fn new() -> Self {
        SynQCompiler {
            pqc_manager: PQCManager::new(),
            contracts: HashMap::new(),
            compiled_results: HashMap::new(),
        }
    }

    pub fn compile_synq_code(
        &mut self,
        synq_code: &str,
        contract_name: &str,
    ) -> Result<CompilationResult, String> {
        // Parse SynQ code
        let parsed_contract = self.parse_synq_code(synq_code, contract_name)?;

        // Generate bytecode with PQC signatures
        let bytecode = self.generate_bytecode(&parsed_contract)?;

        // Compile to Solidity for cross-chain compatibility
        let solidity_code = self.compile_to_solidity(&parsed_contract)?;

        // Generate PQC signatures for the contract
        let pqc_signatures = self.generate_pqc_signatures(&parsed_contract)?;

        let result = CompilationResult {
            success: true,
            bytecode,
            solidity_code,
            synq_code: synq_code.to_string(),
            warnings: vec!["Compilation successful".to_string()],
            errors: vec![],
            pqc_signatures,
        };

        Ok(result)
    }

    fn parse_synq_code(&self, code: &str, name: &str) -> Result<SynQContract, String> {
        // Basic SynQ parser (simplified for demo)
        // In a real implementation, this would use a proper parser

        let contract = SynQContract {
            name: name.to_string(),
            version: "1.0.0".to_string(),
            code: code.to_string(),
            bytecode: vec![], // Will be generated
            abi: self.generate_abi(code)?,
            pqc_algorithm: PQCAlgorithm::FNDSA,
            cross_chain_enabled: true,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            author: "synergy_network".to_string(),
        };

        Ok(contract)
    }

    fn generate_bytecode(&self, contract: &SynQContract) -> Result<Vec<u8>, String> {
        // Generate bytecode with PQC signatures embedded
        // In a real implementation, this would compile to EVM bytecode

        let mut bytecode = Vec::new();

        // Add PQC signature header
        bytecode.extend_from_slice(&[0x53, 0x79, 0x6E, 0x51]); // "SynQ" magic bytes

        // Add PQC algorithm identifier
        match contract.pqc_algorithm {
            PQCAlgorithm::FNDSA => bytecode.push(0x03),
            _ => return Err("SynQ contracts must use FN-DSA".to_string()),
        }

        // Add contract metadata
        bytecode.extend_from_slice(&(contract.name.len() as u32).to_le_bytes());
        bytecode.extend_from_slice(contract.name.as_bytes());
        bytecode.extend_from_slice(&(contract.created_at as u64).to_le_bytes());

        // Reserve deterministic bytes for the deployment-time Aegis PQC signature.
        bytecode.extend_from_slice(&[0; 256]);

        Ok(bytecode)
    }

    fn compile_to_solidity(&self, contract: &SynQContract) -> Result<String, String> {
        // Convert SynQ to Solidity for cross-chain compatibility
        let solidity_template = format!(
            r#"// Auto-generated Solidity contract from SynQ with PQC integration
// Original SynQ contract: {}
// Generated at: {}
// PQC Algorithm: {:?}

pragma solidity ^0.8.0;

// PQC-enhanced contract with Synergy Network compatibility
contract {} {{
    // PQC algorithm support
    string public pqcAlgorithm;
    address public synergyContract;
    bytes32 public pqcPublicKeyHash;

    constructor() {{
        pqcAlgorithm = "{:?}";
        synergyContract = address(this);
        // Initialize PQC key hash (would be set during deployment)
        pqcPublicKeyHash = bytes32(0);
    }}

    // PQC signature verification (precompile call)
    function verifyPQCSignature(
        bytes memory message,
        bytes memory signature,
        bytes memory publicKey
    ) external view returns (bool) {{
        // Aegis PQC precompile verification is mandatory.
        revert("Aegis PQC verification precompile required");
    }}

    // Cross-chain compatibility functions
    function getSynQVersion() external pure returns (string memory) {{
        return "1.0.0";
    }}

    function getPQCSecurityLevel() external pure returns (string memory) {{
        return "NIST Level 5";
    }}

    function supportsCrossChain() external pure returns (bool) {{
        return true;
    }}

    // PQC key management
    function setPQCPublicKey(bytes32 keyHash) external {{
        pqcPublicKeyHash = keyHash;
    }}
}}
"#,
            contract.name,
            contract.created_at,
            contract.pqc_algorithm,
            contract.name,
            contract.pqc_algorithm
        );

        Ok(solidity_template)
    }

    fn generate_abi(&self, _code: &str) -> Result<String, String> {
        // Generate ABI from SynQ code
        // In a real implementation, this would parse the SynQ AST

        let abi = format!(
            r#"[{{ "name": "{}", "type": "contract", "version": "1.0.0", "pqc_algorithm": "{:?}" }}]"#,
            "SynQContract",
            PQCAlgorithm::FNDSA
        );

        Ok(abi)
    }

    fn generate_pqc_signatures(&mut self, contract: &SynQContract) -> Result<Vec<String>, String> {
        let mut signatures = Vec::new();

        for algorithm in [PQCAlgorithm::FNDSA] {
            let (_, private_key) = self.pqc_manager.generate_keypair(algorithm.clone())?;

            let signature = self
                .pqc_manager
                .sign_message(&private_key.public_key_id, &contract.bytecode)?;

            signatures.push(format!("{:?}_{}", algorithm, signature.public_key_id));
        }

        Ok(signatures)
    }

    pub fn verify_contract_signature(
        &self,
        contract_hash: &str,
        signature_id: &str,
    ) -> Result<bool, String> {
        let signature = self
            .pqc_manager
            .get_signature(signature_id)
            .ok_or_else(|| format!("signature {signature_id} not found"))?;
        let (public_key, _) = self
            .pqc_manager
            .get_keypair(&signature.public_key_id)
            .ok_or_else(|| format!("public key {} not found", signature.public_key_id))?;

        self.pqc_manager
            .verify(public_key, signature, contract_hash.as_bytes())
    }

    pub fn get_contract_info(&self, contract_name: &str) -> Option<&SynQContract> {
        self.contracts.get(contract_name)
    }

    pub fn register_compiled_contract(
        &mut self,
        contract: SynQContract,
        result: CompilationResult,
    ) -> String {
        let contract_id = format!("synq_{}_{}", contract.name, contract.created_at);

        self.contracts.insert(contract_id.clone(), contract);
        self.compiled_results.insert(contract_id.clone(), result);

        contract_id
    }

    pub fn get_compilation_result(&self, contract_id: &str) -> Option<&CompilationResult> {
        self.compiled_results.get(contract_id)
    }

    pub fn get_all_contracts(&self) -> Vec<&SynQContract> {
        self.contracts.values().collect()
    }

    pub fn validate_synq_syntax(&self, code: &str) -> Result<Vec<String>, Vec<String>> {
        let mut warnings = Vec::new();
        let mut errors = Vec::new();

        // Basic SynQ syntax validation
        if !code.contains("contract") {
            errors.push("Missing contract declaration".to_string());
        }

        if !code.contains("function") {
            warnings.push("No functions defined in contract".to_string());
        }

        if !code.contains("pqc") {
            warnings.push("Consider adding PQC security features".to_string());
        }

        if errors.is_empty() {
            Ok(warnings)
        } else {
            Err(errors)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contract_with_algorithm(pqc_algorithm: PQCAlgorithm) -> SynQContract {
        SynQContract {
            name: "TestContract".to_string(),
            version: "1.0.0".to_string(),
            code: "contract TestContract {}".to_string(),
            bytecode: Vec::new(),
            abi: "{}".to_string(),
            pqc_algorithm,
            cross_chain_enabled: true,
            created_at: 1,
            author: "test".to_string(),
        }
    }

    #[test]
    fn synq_bytecode_uses_fndsa_identifier() {
        let compiler = SynQCompiler::new();
        let bytecode = compiler
            .generate_bytecode(&contract_with_algorithm(PQCAlgorithm::FNDSA))
            .expect("FN-DSA bytecode should be generated");

        assert_eq!(&bytecode[..4], b"SynQ");
        assert_eq!(bytecode[4], 0x03);
    }

    #[test]
    fn synq_bytecode_rejects_unsupported_signature_algorithm() {
        let compiler = SynQCompiler::new();
        let error = compiler
            .generate_bytecode(&contract_with_algorithm(PQCAlgorithm::SLHDSA))
            .expect_err("non-FN-DSA signatures must not be emitted into SynQ bytecode");

        assert!(error.contains("FN-DSA"));
    }
}
