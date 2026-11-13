use crate::crypto::pqc::{PQCAlgorithm, PQCManager, PQCPrivateKey, PQCPublicKey};
use crate::synergy_types::{SYNERGY_TESTNET_V3_CHAIN_ID, SYNERGY_TESTNET_V3_NETWORK_ID};
use bincode::config::standard;
use bincode::{decode_from_slice, encode_to_vec};
use bincode::{Decode, Encode};
use blake3::Hasher;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct Transaction {
    #[serde(default)]
    pub chain_id: u64,
    #[serde(default)]
    pub network_id: String,
    pub sender: String,
    pub receiver: String,
    pub amount: u64,
    pub nonce: u64,
    pub signature: Vec<u8>, // Changed from String to Vec<u8> for binary signature data
    #[serde(default)]
    pub signer_public_key: Vec<u8>,
    pub timestamp: u64,
    pub gas_price: u64,
    pub gas_limit: u64,
    pub data: Option<String>,
    pub signature_algorithm: String, // Track which PQC algorithm was used
}

#[derive(Debug, Clone)]
pub struct TransactionValidationResult {
    pub is_valid: bool,
    pub error_message: Option<String>,
}

impl Transaction {
    pub fn new(
        sender: String,
        receiver: String,
        amount: u64,
        nonce: u64,
        signature: Vec<u8>,
        gas_price: u64,
        gas_limit: u64,
        data: Option<String>,
        signature_algorithm: String,
    ) -> Self {
        Transaction {
            chain_id: SYNERGY_TESTNET_V3_CHAIN_ID,
            network_id: SYNERGY_TESTNET_V3_NETWORK_ID.to_string(),
            sender,
            receiver,
            amount,
            nonce,
            signature,
            signer_public_key: Vec::new(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            gas_price,
            gas_limit,
            data,
            signature_algorithm,
        }
    }

    /// Returns the raw hash (hex string) for internal use (signing, verification)
    pub fn raw_hash(&self) -> String {
        let mut hasher = Hasher::new();
        hasher.update(&self.chain_id.to_be_bytes());
        hasher.update(&(self.network_id.len() as u64).to_be_bytes());
        hasher.update(self.network_id.as_bytes());
        hasher.update(self.sender.as_bytes());
        hasher.update(self.receiver.as_bytes());
        hasher.update(&self.amount.to_le_bytes());
        hasher.update(&self.nonce.to_le_bytes());
        hasher.update(&self.timestamp.to_le_bytes());
        hasher.update(&self.gas_price.to_le_bytes());
        hasher.update(&self.gas_limit.to_le_bytes());

        if let Some(ref data) = self.data {
            hasher.update(data.as_bytes());
        }

        hex::encode(hasher.finalize().as_bytes())
    }

    /// Returns Synergy-formatted transaction hash with appropriate prefix
    /// Regular transactions: syntxn-<hash>
    /// Cross-chain transactions: synxxn-<hash>
    pub fn hash(&self) -> String {
        let raw_hash = self.raw_hash();

        // Check if this is a cross-chain transaction
        let is_cross_chain = self
            .data
            .as_ref()
            .map(|d| d.starts_with("bridge_transfer:") || d.starts_with("cross_chain:"))
            .unwrap_or(false);

        if is_cross_chain {
            format!("synxxn-{}", raw_hash)
        } else {
            format!("syntxn-{}", raw_hash)
        }
    }

    pub fn sign(
        &mut self,
        private_key: &PQCPrivateKey,
        pqc_manager: &mut PQCManager,
    ) -> Result<(), String> {
        // Get the raw transaction hash (without prefix) for signing
        let message = self.raw_hash();
        let message_bytes =
            hex::decode(&message).map_err(|e| format!("Failed to decode hash: {}", e))?;

        // Testnet-v3 signature domains are strictly separated:
        //   user / account transactions -> ML-DSA-87   (this path)
        //   validator consensus         -> ML-DSA-65   (consensus/validator_keys.rs)
        //   P2P identity                -> Ed25519
        //   address derivation          -> SHA3-256 over FN-DSA-1024 material
        // ML-DSA-65 is deliberately NOT accepted here: accepting it would let a
        // consensus key sign a user transaction, collapsing the domain split.
        let signature =
            match private_key.algorithm {
                PQCAlgorithm::MLDSA87 => pqc_manager.sign(private_key, &message_bytes)?,
                _ => return Err(
                    "Unsupported signature algorithm; Synergy user transactions require ML-DSA-87"
                        .to_string(),
                ),
            };

        self.signature = signature.signature_data;
        self.signature_algorithm = algorithm_name(&private_key.algorithm).to_string();

        Ok(())
    }

    pub fn sign_with_public_key(
        &mut self,
        public_key: &PQCPublicKey,
        private_key: &PQCPrivateKey,
        pqc_manager: &mut PQCManager,
    ) -> Result<(), String> {
        self.sign(private_key, pqc_manager)?;
        self.signer_public_key = public_key.key_data.clone();
        Ok(())
    }

    pub fn verify_signature(&self, public_key: &PQCPublicKey, pqc_manager: &PQCManager) -> bool {
        // Get the raw transaction hash (without prefix) that was signed
        let message = self.raw_hash();
        let message_bytes = hex::decode(&message).unwrap_or_else(|_| Vec::new());

        if message_bytes.is_empty() {
            return false;
        }

        // Create a signature object for verification
        let signature = crate::crypto::pqc::PQCSignature {
            algorithm: public_key.algorithm.clone(),
            signature_data: self.signature.clone(),
            message_hash: message_bytes.clone(),
            public_key_id: public_key.key_id.clone(),
            created_at: self.timestamp,
        };

        // Verify using the appropriate PQC algorithm
        match pqc_manager.verify(public_key, &signature, &message_bytes) {
            Ok(is_valid) => is_valid,
            Err(_) => false,
        }
    }

    pub fn verify_embedded_signature(&self) -> Result<(), String> {
        if self.signer_public_key.is_empty() {
            return Err("Transaction signer public key is missing".to_string());
        }
        if self.signature.is_empty() {
            return Err("Transaction signature is missing".to_string());
        }
        if !crate::address::address_matches_public_key(&self.sender, &self.signer_public_key) {
            return Err("Transaction signer public key does not derive sender address".to_string());
        }
        let algorithm = parse_algorithm_name(&self.signature_algorithm)?;
        let public_key = PQCPublicKey {
            algorithm,
            key_data: self.signer_public_key.clone(),
            key_id: self.sender.clone(),
            created_at: self.timestamp,
        };
        let manager = PQCManager::new();
        if self.verify_signature(&public_key, &manager) {
            Ok(())
        } else {
            Err("Aegis PQC transaction signature verification failed".to_string())
        }
    }

    pub fn validate_for_admission(&self) -> TransactionValidationResult {
        let basic = self.validate();
        if !basic.is_valid {
            return basic;
        }
        if self.chain_id != SYNERGY_TESTNET_V3_CHAIN_ID {
            return TransactionValidationResult {
                is_valid: false,
                error_message: Some(format!(
                    "Transaction chain_id {} does not match Synergy Testnet chain {}",
                    self.chain_id, SYNERGY_TESTNET_V3_CHAIN_ID
                )),
            };
        }
        if self.network_id != SYNERGY_TESTNET_V3_NETWORK_ID {
            return TransactionValidationResult {
                is_valid: false,
                error_message: Some(format!(
                    "Transaction network_id {} does not match {}",
                    self.network_id, SYNERGY_TESTNET_V3_NETWORK_ID
                )),
            };
        }
        let verification = if crate::aegis_tx_tool::is_legacy_aegis_carrier_transaction(self) {
            crate::aegis_tx_tool::validate_legacy_aegis_carrier_transaction(self)
        } else {
            self.verify_embedded_signature()
        };

        match verification {
            Ok(()) => TransactionValidationResult {
                is_valid: true,
                error_message: None,
            },
            Err(error) => TransactionValidationResult {
                is_valid: false,
                error_message: Some(error),
            },
        }
    }

    pub fn validate(&self) -> TransactionValidationResult {
        // Basic validation checks
        if self.sender.is_empty() {
            return TransactionValidationResult {
                is_valid: false,
                error_message: Some("Sender address cannot be empty".to_string()),
            };
        }

        if self.receiver.is_empty() {
            return TransactionValidationResult {
                is_valid: false,
                error_message: Some("Receiver address cannot be empty".to_string()),
            };
        }

        if self.amount == 0 && !self.is_zero_value_protocol_transaction() {
            return TransactionValidationResult {
                is_valid: false,
                error_message: Some("Transaction amount must be greater than 0".to_string()),
            };
        }

        if self.gas_price == 0 {
            return TransactionValidationResult {
                is_valid: false,
                error_message: Some("Gas price must be greater than 0".to_string()),
            };
        }

        if self.gas_limit == 0 {
            return TransactionValidationResult {
                is_valid: false,
                error_message: Some("Gas limit must be greater than 0".to_string()),
            };
        }

        if self.signature.is_empty() {
            return TransactionValidationResult {
                is_valid: false,
                error_message: Some("Transaction must be signed".to_string()),
            };
        }

        // Governed Testnet-v3 profile: user/account transactions are ML-DSA-87.
        // ML-DSA-65 (consensus domain) and FN-DSA (address-derivation material)
        // are rejected here by design — cross-domain reuse must fail closed.
        match self.signature_algorithm.as_str() {
            "mldsa87" => {}
            // Internal validator Aegis carrier: ML-DSA-65 is admissible ONLY for a
            // transaction that is structurally an Aegis carrier envelope, which
            // cannot be interpreted as a user transaction. Its signature is
            // verified separately by validate_legacy_aegis_carrier_transaction.
            "mldsa65" if crate::aegis_tx_tool::is_legacy_aegis_carrier_transaction(self) => {}
            _ => {
                return TransactionValidationResult {
                    is_valid: false,
                    error_message: Some(format!(
                        "Unsupported signature algorithm: {}; Synergy user transactions require ML-DSA-87",
                        self.signature_algorithm
                    )),
                };
            }
        }

        // Check timestamp is not too old (within 1 hour)
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if current_time.saturating_sub(self.timestamp) > 3600 {
            return TransactionValidationResult {
                is_valid: false,
                error_message: Some("Transaction timestamp is too old".to_string()),
            };
        }

        TransactionValidationResult {
            is_valid: true,
            error_message: None,
        }
    }

    pub fn serialize(&self) -> Result<Vec<u8>, String> {
        encode_to_vec(self, standard())
            .map_err(|e| format!("Failed to serialize transaction: {}", e))
    }

    fn is_zero_value_protocol_transaction(&self) -> bool {
        self.data
            .as_deref()
            .map(|data| {
                data.starts_with("validator_activation:")
                    || crate::sts::transaction_data_may_contain_sts_payload(data)
            })
            .unwrap_or(false)
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, String> {
        decode_from_slice(data, standard())
            .map(|(transaction, _)| transaction)
            .map_err(|e| format!("Failed to deserialize transaction: {}", e))
    }

    pub fn to_json(&self) -> Result<String, String> {
        serde_json::to_string(self).map_err(|e| format!("Failed to serialize to JSON: {}", e))
    }

    pub fn from_json(json: &str) -> Result<Self, String> {
        serde_json::from_str(json).map_err(|e| format!("Failed to deserialize from JSON: {}", e))
    }

    /// Gas/execution fee charged for inclusion, using deterministic activity gas.
    /// This is intentionally not `gas_limit * gas_price`; unused gas is refundable.
    /// Protocol/amount fees are exposed separately by `get_network_fee_breakdown`.
    pub fn get_fee(&self) -> u64 {
        u64::try_from(self.calculate_gas_fee()).unwrap_or(u64::MAX)
    }

    pub fn get_total_value(&self) -> u64 {
        self.amount
            .saturating_add(u64::try_from(self.get_total_network_fee_nwei()).unwrap_or(u64::MAX))
    }

    pub fn is_contract_call(&self) -> bool {
        self.data.is_some()
    }

    pub fn get_contract_data(&self) -> Option<&String> {
        self.data.as_ref()
    }

    pub fn get_signature_hex(&self) -> String {
        hex::encode(&self.signature)
    }

    pub fn get_signature_algorithm(&self) -> &str {
        &self.signature_algorithm
    }

    pub fn get_sender(&self) -> &str {
        &self.sender
    }

    pub fn get_receiver(&self) -> &str {
        &self.receiver
    }

    pub fn get_amount(&self) -> u64 {
        self.amount
    }

    pub fn get_nonce(&self) -> u64 {
        self.nonce
    }

    pub fn get_timestamp(&self) -> u64 {
        self.timestamp
    }

    pub fn get_gas_price(&self) -> u64 {
        self.gas_price
    }

    pub fn get_gas_limit(&self) -> u64 {
        self.gas_limit
    }

    pub fn minimum_required_gas(&self) -> u64 {
        self.estimate_gas()
    }

    /// Calculate actual gas fee using the gas module. Returns fee in nWei.
    pub fn calculate_gas_fee(&self) -> u128 {
        crate::gas::calculate_total_fee_nwei(self.minimum_required_gas(), self.gas_price)
            .unwrap_or(u128::MAX)
    }

    /// Calculate the maximum fee reserve required before execution.
    pub fn calculate_max_fee_reserve_nwei(&self) -> u128 {
        crate::gas::calculate_total_fee_nwei(self.gas_limit, self.gas_price).unwrap_or(u128::MAX)
    }

    /// Get gas fee as NWei type
    pub fn get_gas_fee_nwei(&self) -> crate::gas::NWei {
        crate::gas::NWei::from_nwei(self.calculate_gas_fee())
    }

    /// Get gas fee in SNRG (for display)
    pub fn get_gas_fee_snrg(&self) -> String {
        self.get_gas_fee_nwei().format_snrg()
    }

    /// Get total cost (amount + total network fee) in nWei
    pub fn get_total_cost_nwei(&self) -> u128 {
        (self.amount as u128).saturating_add(self.get_total_network_fee_nwei())
    }

    /// Check if sender has sufficient balance for transaction
    /// balance should be in nWei
    pub fn has_sufficient_balance(&self, sender_balance: u128) -> bool {
        sender_balance
            >= (self.amount as u128).saturating_add(self.get_max_network_fee_reserve_nwei())
    }

    pub fn get_network_fee_breakdown(&self) -> Result<crate::gas::NetworkFeeBreakdown, String> {
        self.network_fee_breakdown_with_gas(self.minimum_required_gas(), self.gas_price)
    }

    pub fn get_total_network_fee_nwei(&self) -> u128 {
        self.get_network_fee_breakdown()
            .map(|breakdown| breakdown.total_network_fee_nwei)
            .unwrap_or_else(|_| self.calculate_gas_fee())
    }

    pub fn get_total_network_fee_u64(&self) -> Result<u64, String> {
        u64::try_from(self.get_total_network_fee_nwei())
            .map_err(|_| "total network fee exceeds u64".to_string())
    }

    pub fn get_max_network_fee_reserve_nwei(&self) -> u128 {
        self.network_fee_breakdown_with_gas(self.gas_limit, self.gas_price)
            .map(|breakdown| breakdown.total_network_fee_nwei)
            .unwrap_or_else(|_| self.calculate_max_fee_reserve_nwei())
    }

    pub fn network_fee_breakdown_with_gas(
        &self,
        gas_used: u64,
        base_fee_per_gas_nwei: u64,
    ) -> Result<crate::gas::NetworkFeeBreakdown, String> {
        use crate::gas::{
            calculate_network_fee, fee_schedule_for_runtime, NetworkFeeInput, TransactionFeeType,
        };

        let gas_fee_nwei = crate::gas::calculate_total_fee_nwei(gas_used, base_fee_per_gas_nwei)?;
        let (tx_type, asset_id, amount_raw, amount_snrgequivalent_nwei, valuation_status) =
            self.fee_value_context();
        let valuation_source = valuation_status.as_str().to_string();
        let tx_type = if tx_type == TransactionFeeType::Unknown && self.is_contract_call() {
            TransactionFeeType::ContractCall
        } else {
            tx_type
        };

        calculate_network_fee(
            NetworkFeeInput {
                tx_type,
                asset_id,
                amount_raw,
                amount_snrgequivalent_nwei,
                valuation_source,
                valuation_status,
                gas_used,
                base_fee_per_gas_nwei,
                gas_fee_nwei,
                storage_fee_nwei: 0,
                priority_fee_nwei: 0,
                pq_gas_used: 0,
                pq_gas_multiplier: 0,
                effective_pq_gas_price_nwei: 0,
                pq_execution_fee_nwei: 0,
                fee_market_active: false,
                fee_market_version: 0,
            },
            fee_schedule_for_runtime()?,
        )
    }

    fn fee_value_context(
        &self,
    ) -> (
        crate::gas::TransactionFeeType,
        String,
        u128,
        u128,
        crate::gas::ValuationStatus,
    ) {
        use crate::gas::{TransactionFeeType, ValuationStatus};

        let data = self.data.as_deref().unwrap_or_default();
        if crate::address::is_network_burn_address(&self.receiver) || data.starts_with("burn:") {
            let (asset, amount) = parse_asset_amount_payload(data.strip_prefix("burn:"));
            let amount = amount.unwrap_or(self.amount as u128);
            let asset = asset.unwrap_or_else(|| "SNRG".to_string());
            let equivalent = if asset == "SNRG" { amount } else { 0 };
            let status = if asset == "SNRG" {
                ValuationStatus::NativeSnrg
            } else {
                ValuationStatus::Unavailable
            };
            return (TransactionFeeType::Burn, asset, amount, equivalent, status);
        }

        if data.starts_with("token_transfer:") {
            let (asset, amount) = parse_asset_amount_payload(data.strip_prefix("token_transfer:"));
            let amount = amount.unwrap_or(self.amount as u128);
            let asset = asset.unwrap_or_else(|| "UNKNOWN".to_string());
            let equivalent = if asset == "SNRG" { amount } else { 0 };
            let status = if asset == "SNRG" {
                ValuationStatus::NativeSnrg
            } else {
                ValuationStatus::Unavailable
            };
            return (
                TransactionFeeType::TokenSend,
                asset,
                amount,
                equivalent,
                status,
            );
        }

        if data.starts_with("stake:") {
            return (
                TransactionFeeType::Stake,
                "SNRG".to_string(),
                self.amount as u128,
                self.amount as u128,
                ValuationStatus::NotRequired,
            );
        }

        if data.starts_with("unstake:") || data.starts_with("withdrawal_request:") {
            return (
                TransactionFeeType::Unstake,
                "SNRG".to_string(),
                self.amount as u128,
                self.amount as u128,
                ValuationStatus::NotRequired,
            );
        }

        if data.starts_with("swap:") {
            let (_, amount) = parse_asset_amount_payload(data.strip_prefix("swap:"));
            return (
                TransactionFeeType::Swap,
                "UNKNOWN".to_string(),
                amount.unwrap_or(self.amount as u128),
                0,
                ValuationStatus::Unavailable,
            );
        }

        if self.receiver.is_empty() || self.receiver == "0x0" || data.starts_with("deploy:") {
            return (
                TransactionFeeType::ContractDeploy,
                "SNRG".to_string(),
                self.amount as u128,
                self.amount as u128,
                if self.amount > 0 {
                    ValuationStatus::NativeSnrg
                } else {
                    ValuationStatus::NotRequired
                },
            );
        }

        if self.amount > 0 && data.is_empty() {
            return (
                TransactionFeeType::NativeSnrgSend,
                "SNRG".to_string(),
                self.amount as u128,
                self.amount as u128,
                ValuationStatus::NativeSnrg,
            );
        }

        (
            TransactionFeeType::ContractCall,
            "SNRG".to_string(),
            self.amount as u128,
            self.amount as u128,
            if self.amount > 0 {
                ValuationStatus::NativeSnrg
            } else {
                ValuationStatus::NotRequired
            },
        )
    }

    /// Set gas price (in nWei per gas unit)
    pub fn set_gas_price(&mut self, gas_price: u64) -> Result<(), String> {
        use crate::gas::GasPrice;
        // Validate gas price
        GasPrice::from_nwei(gas_price)?;
        self.gas_price = gas_price;
        Ok(())
    }

    /// Set gas limit
    pub fn set_gas_limit(&mut self, gas_limit: u64) -> Result<(), String> {
        use crate::gas::GasLimit;
        // Validate gas limit
        GasLimit::new(gas_limit)?;
        self.gas_limit = gas_limit;
        Ok(())
    }

    /// Estimate gas for this transaction based on its type
    pub fn estimate_gas(&self) -> u64 {
        use crate::gas::{calculate_activity_gas, GasComputationInput, GasSchedule};

        let schedule = GasSchedule::default();
        let payload_size = self
            .data
            .as_ref()
            .map(|data| data.len() as u64)
            .unwrap_or(0);
        let mut input = GasComputationInput::new(self.gas_activity_type());
        input.payload_size_bytes = payload_size;

        if let Some(ref data) = self.data {
            if data.starts_with("deploy:") {
                input.contract_bytecode_size = data.len() as u64;
            } else if data.starts_with("validator_activation:")
                || data.starts_with("validator_registration:")
            {
                input.validator_metadata_size_bytes = data.len() as u64;
            } else if data.starts_with("governance_proposal:") {
                input.proposal_size_bytes = data.len() as u64;
            } else if data.starts_with("pqc_key_registration:")
                || data.starts_with("pqc_key_rotation:")
            {
                input.key_material_size_bytes = data.len() as u64;
            } else if data.starts_with("sxcp_proof:") {
                input.proof_size_bytes = data.len() as u64;
            }
        }

        calculate_activity_gas(&schedule, &input)
            .map(|breakdown| breakdown.total_gas)
            .unwrap_or(schedule.base_tx_gas)
    }

    pub fn gas_activity_type(&self) -> crate::gas::GasActivityType {
        use crate::gas::GasActivityType;

        match self.data.as_deref() {
            None => GasActivityType::NativeSnrgTransfer,
            Some(data) if data.starts_with("token_transfer:") => {
                GasActivityType::ScetpSameChainTransfer
            }
            Some(data)
                if data.starts_with("validator_activation:")
                    || data.starts_with("validator_registration:") =>
            {
                GasActivityType::ValidatorRegistration
            }
            Some(data) if data.starts_with("validator_heartbeat:") => {
                GasActivityType::ValidatorHeartbeat
            }
            Some(data) if data.starts_with("stake:") => GasActivityType::StakingBond,
            Some(data)
                if data.starts_with("unstake:") || data.starts_with("withdrawal_request:") =>
            {
                GasActivityType::UnstakeRequest
            }
            Some(data) if data.starts_with("governance_proposal:") => {
                GasActivityType::GovernanceProposal
            }
            Some(data) if data.starts_with("governance_vote:") => GasActivityType::GovernanceVote,
            Some(data) if data.starts_with("deploy:") => GasActivityType::SynqContractDeployment,
            Some(data) if data.starts_with("pqc_key_registration:") => {
                GasActivityType::AegisPqcKeyRegistration
            }
            Some(data) if data.starts_with("pqc_key_rotation:") => {
                GasActivityType::AegisPqcKeyRotation
            }
            Some(data) if data.starts_with("sxcp_intent:") => GasActivityType::SxcpIntentCreation,
            Some(data) if data.starts_with("sxcp_proof:") => GasActivityType::SxcpProofVerification,
            Some(data) if data.starts_with("sxcp_attestation:") => {
                GasActivityType::SxcpRelayerAttestation
            }
            Some(data) if data.starts_with("uma_create:") => GasActivityType::UmaRecordCreation,
            Some(data) if data.starts_with("uma_update:") => GasActivityType::UmaRecordUpdate,
            Some(data) if data.starts_with("sns_register:") => GasActivityType::SnsNameRegistration,
            Some(data) if data.starts_with("sns_update:") => GasActivityType::SnsNameUpdate,
            Some(_) => GasActivityType::SynqContractCall,
        }
    }
}

// Helper function to get algorithm name
fn algorithm_name(algorithm: &PQCAlgorithm) -> &'static str {
    match algorithm {
        PQCAlgorithm::MLKEM1024 => "mlkem1024",
        PQCAlgorithm::MLDSA65 => "mldsa65",
        PQCAlgorithm::MLDSA87 => "mldsa87",
        PQCAlgorithm::FNDSA => "fndsa",
        PQCAlgorithm::SLHDSA => "slhdsa",
        PQCAlgorithm::HQCKEM => "hqckem",
    }
}

// Helper function to parse algorithm name
pub fn parse_algorithm_name(name: &str) -> Result<PQCAlgorithm, String> {
    match name.to_lowercase().as_str() {
        "mldsa65" | "ml-dsa-65" | "ml_dsa_65" => Ok(PQCAlgorithm::MLDSA65),
        "mldsa87" | "ml-dsa-87" | "ml_dsa_87" => Ok(PQCAlgorithm::MLDSA87),
        "fndsa" | "fn-dsa" | "fn-dsa-512" | "fn-dsa-1024" | "falcon" | "falcon-1024" => {
            Ok(PQCAlgorithm::FNDSA)
        }
        _ => Err(format!(
            "Unsupported transaction signature algorithm: {}; use mldsa65, mldsa87, or fndsa",
            name
        )),
    }
}

fn parse_asset_amount_payload(payload: Option<&str>) -> (Option<String>, Option<u128>) {
    let Some(payload) = payload else {
        return (None, None);
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(payload) else {
        return (None, None);
    };
    let asset = value
        .get("asset")
        .or_else(|| value.get("asset_id"))
        .or_else(|| value.get("token"))
        .or_else(|| value.get("token_symbol"))
        .and_then(|value| value.as_str())
        .map(|value| value.to_string());
    let amount = value
        .get("amount")
        .or_else(|| value.get("amount_raw"))
        .or_else(|| value.get("amount_nwei"))
        .or_else(|| value.get("amount_in"))
        .or_else(|| value.get("input_amount"))
        .or_else(|| value.get("payment_amount"))
        .and_then(json_u128);
    (asset, amount)
}

fn json_u128(value: &serde_json::Value) -> Option<u128> {
    if let Some(number) = value.as_u64() {
        return Some(number as u128);
    }
    value.as_str()?.trim().parse::<u128>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wallet_test_address(fill: u8) -> String {
        crate::address::generate_wallet_address(&hex::encode(vec![
            fill;
            crate::address::FN_DSA_1024_PUBLIC_KEY_BYTES
        ]))
        .expect("canonical FN-DSA test root derives a wallet address")
    }

    fn validator_test_address(fill: u8) -> String {
        crate::address::generate_class_based_address(
            &vec![fill; crate::address::FN_DSA_1024_PUBLIC_KEY_BYTES],
            1,
        )
        .expect("canonical FN-DSA test root derives a validator address")
    }

    #[test]
    fn test_transaction_creation() {
        let tx = Transaction::new(
            "sender123".to_string(),
            "receiver456".to_string(),
            1000,
            1,
            vec![0x01, 0x02, 0x03],
            100,
            21000,
            None,
            "mldsa87".to_string(),
        );

        assert_eq!(tx.sender, "sender123");
        assert_eq!(tx.receiver, "receiver456");
        assert_eq!(tx.amount, 1000);
        assert_eq!(tx.nonce, 1);
        assert_eq!(tx.signature, vec![0x01, 0x02, 0x03]);
        assert_eq!(tx.gas_price, 100);
        assert_eq!(tx.gas_limit, 21000);
        assert_eq!(tx.signature_algorithm, "mldsa87");
    }

    #[test]
    fn test_transaction_hash() {
        let tx1 = Transaction::new(
            "sender123".to_string(),
            "receiver456".to_string(),
            1000,
            1,
            vec![0x01, 0x02, 0x03],
            100,
            21000,
            None,
            "mldsa87".to_string(),
        );

        let tx2 = Transaction::new(
            "sender123".to_string(),
            "receiver456".to_string(),
            1000,
            1,
            vec![0x01, 0x02, 0x03],
            100,
            21000,
            None,
            "mldsa87".to_string(),
        );

        // Same transaction should have same hash
        assert_eq!(tx1.hash(), tx2.hash());

        let tx3 = Transaction::new(
            "sender123".to_string(),
            "receiver456".to_string(),
            2000, // Different amount
            1,
            vec![0x01, 0x02, 0x03],
            100,
            21000,
            None,
            "mldsa87".to_string(),
        );

        // Different transaction should have different hash
        assert_ne!(tx1.hash(), tx3.hash());
    }

    #[test]
    fn test_transaction_validation() {
        let valid_tx = Transaction::new(
            "sender123".to_string(),
            "receiver456".to_string(),
            1000,
            1,
            vec![0x01, 0x02, 0x03],
            100,
            21000,
            None,
            "mldsa87".to_string(),
        );

        let result = valid_tx.validate();
        assert!(result.is_valid);
        assert!(result.error_message.is_none());

        let invalid_tx = Transaction::new(
            "".to_string(), // Empty sender
            "receiver456".to_string(),
            1000,
            1,
            vec![0x01, 0x02, 0x03],
            100,
            21000,
            None,
            "mldsa87".to_string(),
        );

        let result = invalid_tx.validate();
        assert!(!result.is_valid);
        assert!(result.error_message.is_some());
    }

    #[test]
    fn admission_rejects_unbound_operational_key_even_with_real_pqc_signature() {
        let mut manager = PQCManager::new();
        let (public_key, private_key) = manager
            .generate_keypair(PQCAlgorithm::MLDSA87)
            .expect("test keypair should generate");
        let sender = wallet_test_address(1);
        let mut tx = Transaction::new(
            sender,
            "receiver456".to_string(),
            1000,
            1,
            Vec::new(),
            100,
            21000,
            None,
            "mldsa87".to_string(),
        );
        tx.sign_with_public_key(&public_key, &private_key, &mut manager)
            .expect("test transaction should sign");

        assert!(
            !tx.validate_for_admission().is_valid,
            "an ML-DSA operational key must not be accepted as an FN-DSA address root"
        );

        let mut wrong_chain = tx.clone();
        wrong_chain.chain_id = 999;
        assert!(!wrong_chain.validate_for_admission().is_valid);

        let mut wrong_network = tx.clone();
        wrong_network.network_id = "synergy-testnet".to_string();
        assert!(!wrong_network.validate_for_admission().is_valid);

        let mut tampered = tx.clone();
        tampered.amount = tampered.amount.saturating_add(1);
        assert!(!tampered.validate_for_admission().is_valid);

        let mut missing_key = tx;
        missing_key.signer_public_key.clear();
        assert!(!missing_key.validate_for_admission().is_valid);

        let mut wrong_sender = missing_key;
        wrong_sender.signer_public_key = public_key.key_data;
        wrong_sender.sender = wallet_test_address(9);
        assert!(!wrong_sender.validate_for_admission().is_valid);
    }

    #[test]
    fn admission_rejects_unbound_operational_key_validator_activation() {
        let mut manager = PQCManager::new();
        let (public_key, private_key) = manager
            .generate_keypair(PQCAlgorithm::MLDSA87)
            .expect("test keypair should generate");
        let sender = validator_test_address(2);
        let mut tx = Transaction::new(
            sender.clone(),
            sender.clone(),
            0,
            1,
            Vec::new(),
            100,
            21000,
            Some(format!(
                "validator_activation:{{\"validator\":\"{}\",\"public_key\":\"{}\",\"name\":\"Test Validator\",\"stake_amount_nwei\":50000000000000}}",
                sender,
                hex::encode(vec![2u8; crate::address::FN_DSA_1024_PUBLIC_KEY_BYTES])
            )),
            "mldsa87".to_string(),
        );
        tx.sign_with_public_key(&public_key, &private_key, &mut manager)
            .expect("test transaction should sign");

        let validation = tx.validate_for_admission();

        assert!(
            !validation.is_valid,
            "validator activation must reject an unbound operational key: {:?}",
            validation.error_message
        );
    }

    #[test]
    fn admission_rejects_unbound_operational_key_sts_payload() {
        let mut manager = PQCManager::new();
        let (public_key, private_key) = manager
            .generate_keypair(PQCAlgorithm::MLDSA87)
            .expect("test keypair should generate");
        let sender = wallet_test_address(3);
        let payload = crate::sts::StsSignedPayload::new(crate::sts::StsTx::CreateFungible(
            crate::sts::CreateFungibleParams {
                class: crate::sts::TokenClass::B1BasicFungible,
                creator: sender.clone(),
                creator_nonce: 42,
                name: "CLI Submit Test".to_string(),
                symbol: "CLISUB".to_string(),
                decimals: 9,
                initial_supply: 1_000_000_000,
                max_supply: Some(1_000_000_000),
                mint_authority: Some(sender.clone()),
                metadata_authority: None,
                metadata_uri: None,
                metadata_hash: None,
                metadata_mutable: false,
                image_uri: None,
                image_hash: None,
                flags: crate::sts::FungibleControlFlags::default(),
                policies: Vec::new(),
                created_at: 1_700_000_000,
            },
        ));
        let data = hex::encode(crate::sts::encode_sts_payload(&payload).expect("payload encodes"));
        let mut tx = Transaction::new(
            sender.clone(),
            sender,
            0,
            1,
            Vec::new(),
            100,
            150_000,
            Some(data),
            "mldsa87".to_string(),
        );
        tx.sign_with_public_key(&public_key, &private_key, &mut manager)
            .expect("test transaction should sign");

        let validation = tx.validate_for_admission();

        assert!(
            !validation.is_valid,
            "STS payload must reject an unbound operational key: {:?}",
            validation.error_message
        );
    }

    #[test]
    fn admission_still_rejects_unsigned_zero_value_transfer() {
        let tx = Transaction::new(
            "sender123".to_string(),
            "receiver456".to_string(),
            0,
            1,
            vec![0x01, 0x02, 0x03],
            100,
            21000,
            None,
            "mldsa87".to_string(),
        );

        let validation = tx.validate_for_admission();

        assert!(!validation.is_valid);
        assert_eq!(
            validation.error_message.as_deref(),
            Some("Transaction amount must be greater than 0")
        );
    }

    #[test]
    fn aegis_transaction_builder_requires_identity_authorization_carrier() {
        let error = crate::aegis_tx_tool::sign_with_new_aegis_transaction_key(
            crate::aegis_tx_tool::AegisTxBuildOptions::default(),
        )
        .expect_err("unbound Aegis operational key must be rejected");
        assert!(error.contains("identity authorization carrier"));
    }

    #[test]
    fn consensus_mldsa65_key_cannot_sign_a_user_transaction() {
        let mut manager = PQCManager::new();
        let (_public_key, private_key) = manager
            .generate_keypair(PQCAlgorithm::MLDSA65)
            .expect("consensus-domain keypair should generate");
        let mut tx = Transaction::new(
            "sender".to_string(),
            "receiver".to_string(),
            1000,
            1,
            Vec::new(),
            100,
            21000,
            None,
            "mldsa87".to_string(),
        );
        let error = tx
            .sign(&private_key, &mut manager)
            .expect_err("ML-DSA-65 consensus key must not sign a user transaction");
        assert!(error.contains("ML-DSA-87"), "{error}");
    }

    #[test]
    fn fndsa_address_material_cannot_sign_a_user_transaction() {
        let mut manager = PQCManager::new();
        let (_public_key, private_key) = manager
            .generate_keypair(PQCAlgorithm::FNDSA)
            .expect("address-domain keypair should generate");
        let mut tx = Transaction::new(
            "sender".to_string(),
            "receiver".to_string(),
            1000,
            1,
            Vec::new(),
            100,
            21000,
            None,
            "mldsa87".to_string(),
        );
        assert!(tx.sign(&private_key, &mut manager).is_err());
    }

    #[test]
    fn admission_rejects_non_mldsa87_declared_algorithms() {
        for label in ["mldsa65", "fndsa", "slhdsa", "ed25519", ""] {
            let mut tx = Transaction::new(
                "sender".to_string(),
                "receiver".to_string(),
                1000,
                1,
                vec![1, 2, 3],
                100,
                21000,
                None,
                label.to_string(),
            );
            tx.signer_public_key = vec![9u8; 32];
            let result = tx.validate();
            assert!(
                !result.is_valid,
                "declared algorithm '{label}' must be rejected for user transactions"
            );
        }
    }

    #[test]
    fn test_transaction_serialization() {
        let tx = Transaction::new(
            "sender123".to_string(),
            "receiver456".to_string(),
            1000,
            1,
            vec![0x01, 0x02, 0x03],
            100,
            21000,
            None,
            "mldsa87".to_string(),
        );

        let serialized = tx.serialize().unwrap();
        let deserialized = Transaction::deserialize(&serialized).unwrap();

        assert_eq!(tx.sender, deserialized.sender);
        assert_eq!(tx.receiver, deserialized.receiver);
        assert_eq!(tx.amount, deserialized.amount);
        assert_eq!(tx.nonce, deserialized.nonce);
        assert_eq!(tx.signature, deserialized.signature);
        assert_eq!(tx.signature_algorithm, deserialized.signature_algorithm);
    }

    #[test]
    fn test_transaction_json() {
        let tx = Transaction::new(
            "sender123".to_string(),
            "receiver456".to_string(),
            1000,
            1,
            vec![0x01, 0x02, 0x03],
            100,
            21000,
            None,
            "mldsa87".to_string(),
        );

        let json = tx.to_json().unwrap();
        let deserialized = Transaction::from_json(&json).unwrap();

        assert_eq!(tx.sender, deserialized.sender);
        assert_eq!(tx.receiver, deserialized.receiver);
        assert_eq!(tx.amount, deserialized.amount);
        assert_eq!(tx.nonce, deserialized.nonce);
        assert_eq!(tx.signature, deserialized.signature);
        assert_eq!(tx.signature_algorithm, deserialized.signature_algorithm);
    }

    #[test]
    fn test_transaction_fee_calculation() {
        let tx = Transaction::new(
            "sender123".to_string(),
            "receiver456".to_string(),
            1000,
            1,
            vec![0x01, 0x02, 0x03],
            100,
            21000,
            None,
            "mldsa87".to_string(),
        );

        assert_eq!(tx.get_fee(), 100 * 38500);
        assert_eq!(tx.get_total_value(), 1000 + (100 * 38500));
    }

    #[test]
    fn native_send_amount_changes_total_network_fee_without_changing_gas_fee() {
        let one_snrg = Transaction::new(
            "sender123".to_string(),
            "receiver456".to_string(),
            1_000_000_000,
            1,
            vec![0x01],
            100,
            50_000,
            None,
            "mldsa87".to_string(),
        );
        let hundred_snrg = Transaction::new(
            "sender123".to_string(),
            "receiver456".to_string(),
            100_000_000_000,
            2,
            vec![0x01],
            100,
            50_000,
            None,
            "mldsa87".to_string(),
        );

        assert_eq!(one_snrg.get_fee(), hundred_snrg.get_fee());
        let one_breakdown = one_snrg.get_network_fee_breakdown().unwrap();
        let hundred_breakdown = hundred_snrg.get_network_fee_breakdown().unwrap();
        assert_eq!(one_breakdown.amount_protocol_fee_nwei, 200_000);
        assert_eq!(hundred_breakdown.amount_protocol_fee_nwei, 20_000_000);
        assert_eq!(
            one_breakdown.total_network_fee_nwei,
            one_snrg.get_fee() as u128 + 200_000
        );
        assert_eq!(
            hundred_breakdown.total_network_fee_nwei,
            hundred_snrg.get_fee() as u128 + 20_000_000
        );
    }

    #[test]
    fn token_transfer_without_native_valuation_is_gas_only() {
        let tx = Transaction::new(
            "sender123".to_string(),
            "receiver456".to_string(),
            0,
            1,
            vec![0x01],
            100,
            50_000,
            Some(
                "token_transfer:{\"to\":\"receiver456\",\"token\":\"TEST\",\"amount\":500000000}"
                    .to_string(),
            ),
            "mldsa87".to_string(),
        );

        let breakdown = tx.get_network_fee_breakdown().unwrap();
        assert_eq!(breakdown.tx_type, crate::gas::TransactionFeeType::TokenSend);
        assert_eq!(breakdown.asset_id, "TEST");
        assert_eq!(breakdown.amount_protocol_fee_nwei, 0);
        assert_eq!(breakdown.total_network_fee_nwei, breakdown.gas_fee_nwei);
        assert_eq!(
            breakdown.valuation_status,
            crate::gas::ValuationStatus::Unavailable
        );
    }

    #[test]
    fn test_algorithm_parsing() {
        assert_eq!(parse_algorithm_name("fndsa").unwrap(), PQCAlgorithm::FNDSA);
        assert_eq!(parse_algorithm_name("fn-dsa").unwrap(), PQCAlgorithm::FNDSA);
        assert!(parse_algorithm_name("unsupported-signature").is_err());
        assert!(parse_algorithm_name("slhdsa").is_err());
        assert!(parse_algorithm_name("mlkem").is_err());
        assert!(parse_algorithm_name("hqckem").is_err());
        assert!(parse_algorithm_name("unknown").is_err());
    }
}
