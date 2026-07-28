use crate::address::generate_wallet_address;
use crate::crypto::pqc::{PQCAlgorithm, PQCCiphertext, PQCManager, PQCPrivateKey, PQCPublicKey};
use crate::transaction::Transaction;
use crate::{info, warn};
use base64::{engine::general_purpose, Engine as _};
use hex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Wallet {
    pub address: String,
    pub public_key: String,
    pub private_key: Option<String>, // Only stored for testing, never in production
    pub kem_public_key: Option<String>,
    pub kem_private_key: Option<String>,
    pub balance: HashMap<String, u64>, // token_symbol -> balance
    pub staked_balance: HashMap<String, u64>, // token_symbol -> staked amount
    pub nonce: u64,
    pub created_at: u64,
}

#[derive(Debug, Clone)]
pub struct WalletManager {
    wallets: HashMap<String, Wallet>,
    keypairs: HashMap<String, (String, String)>, // address -> (public_key, private_key)
    kem_keypairs: HashMap<String, (String, String)>, // address -> (kem_public, kem_private)
}

#[derive(Debug, Deserialize)]
struct TestnetProfileWalletRecord {
    address: String,
    public_key_path: String,
    private_key_path: String,
}

#[derive(Debug, Deserialize)]
struct TestnetProfileWallets {
    treasury_wallet: TestnetProfileWalletRecord,
    faucet_wallet: TestnetProfileWalletRecord,
    stake_vault_wallet: TestnetProfileWalletRecord,
}

#[derive(Debug, Clone)]
struct TestnetWalletMaterial {
    address: String,
    public_key: String,
    private_key: String,
}

impl Wallet {
    pub fn new(address: String, public_key: String) -> Self {
        Wallet {
            address,
            public_key,
            private_key: None,
            kem_public_key: None,
            kem_private_key: None,
            balance: HashMap::new(),
            staked_balance: HashMap::new(),
            nonce: 0,
            created_at: Self::current_timestamp(),
        }
    }

    pub fn with_private_key(address: String, public_key: String, private_key: String) -> Self {
        let mut wallet = Self::new(address, public_key);
        wallet.private_key = Some(private_key);
        wallet
    }

    pub fn update_balance(&mut self, token_symbol: String, amount: u64) {
        *self.balance.entry(token_symbol).or_insert(0) = amount;
    }

    pub fn get_balance(&self, token_symbol: &str) -> u64 {
        self.balance.get(token_symbol).copied().unwrap_or(0)
    }

    pub fn increment_nonce(&mut self) {
        self.nonce += 1;
    }

    fn current_timestamp() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }
}

impl WalletManager {
    pub fn new() -> Self {
        WalletManager {
            wallets: HashMap::new(),
            keypairs: HashMap::new(),
            kem_keypairs: HashMap::new(),
        }
    }

    pub fn generate_keypair() -> Result<(String, String, String, String, String), String> {
        let mut pqc_manager = PQCManager::new();
        let (sign_public, sign_private) = pqc_manager.generate_keypair(PQCAlgorithm::MLDSA87)?;
        let (kem_public, kem_private) = pqc_manager.generate_keypair(PQCAlgorithm::MLKEM1024)?;

        let address = generate_wallet_address(&hex::encode(&sign_public.key_data));

        Ok((
            address,
            hex::encode(sign_public.key_data),
            hex::encode(sign_private.key_data),
            hex::encode(kem_public.key_data),
            hex::encode(kem_private.key_data),
        ))
    }

    fn generate_mlkem_keypair() -> Result<(String, String), String> {
        let mut pqc_manager = PQCManager::new();
        let (kem_public, kem_private) = pqc_manager.generate_keypair(PQCAlgorithm::MLKEM1024)?;
        Ok((
            hex::encode(kem_public.key_data),
            hex::encode(kem_private.key_data),
        ))
    }

    pub fn generate_address(public_key: &str) -> String {
        // Delegate wallet address generation to the address module for
        // consistent formatting.
        generate_wallet_address(public_key)
    }

    pub fn create_wallet(&mut self) -> Result<String, String> {
        let (address, public_key, private_key, kem_public, kem_private) = Self::generate_keypair()?;

        let mut wallet =
            Wallet::with_private_key(address.clone(), public_key.clone(), private_key.clone());
        wallet.kem_public_key = Some(kem_public.clone());
        wallet.kem_private_key = Some(kem_private.clone());

        self.wallets.insert(address.clone(), wallet);
        self.keypairs
            .insert(address.clone(), (public_key, private_key));
        self.kem_keypairs
            .insert(address.clone(), (kem_public, kem_private));

        Ok(address)
    }

    pub fn create_wallet_from_keypair(
        &mut self,
        public_key: String,
        private_key: String,
    ) -> Result<String, String> {
        let address = Self::generate_address(&public_key);
        let (kem_public, kem_private) = Self::generate_mlkem_keypair()?;

        let mut wallet =
            Wallet::with_private_key(address.clone(), public_key.clone(), private_key.clone());
        wallet.kem_public_key = Some(kem_public.clone());
        wallet.kem_private_key = Some(kem_private.clone());

        self.wallets.insert(address.clone(), wallet);
        self.keypairs
            .insert(address.clone(), (public_key, private_key));
        self.kem_keypairs
            .insert(address.clone(), (kem_public, kem_private));

        Ok(address)
    }

    /// Import a wallet under an explicit address (used for testnet/system identities).
    pub fn import_wallet(
        &mut self,
        address: String,
        public_key: String,
        private_key: String,
    ) -> Result<String, String> {
        let wallet =
            Wallet::with_private_key(address.clone(), public_key.clone(), private_key.clone());

        self.wallets.insert(address.clone(), wallet);
        self.keypairs
            .insert(address.clone(), (public_key, private_key));

        Ok(address)
    }

    pub fn get_wallet(&self, address: &str) -> Option<&Wallet> {
        self.wallets.get(address)
    }

    pub fn get_wallet_mut(&mut self, address: &str) -> Option<&mut Wallet> {
        self.wallets.get_mut(address)
    }

    pub fn sign_transaction(&self, address: &str, tx: &mut Transaction) -> Result<String, String> {
        if let Some(keypair) = self.keypairs.get(address) {
            let (public_key, private_key) = keypair;

            let private_key_bytes = decode_key_material(private_key)
                .map_err(|e| format!("Invalid private key format: {}", e))?;
            let public_key_bytes = decode_key_material(public_key)
                .map_err(|e| format!("Invalid public key format: {}", e))?;

            let pqc_private_key = PQCPrivateKey {
                algorithm: PQCAlgorithm::MLDSA87,
                key_data: private_key_bytes,
                public_key_id: address.to_string(),
                created_at: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            };
            let pqc_public_key = crate::crypto::pqc::PQCPublicKey {
                algorithm: PQCAlgorithm::MLDSA87,
                key_data: public_key_bytes,
                key_id: address.to_string(),
                created_at: pqc_private_key.created_at,
            };

            let mut pqc_manager = PQCManager::new();
            tx.sign_with_public_key(&pqc_public_key, &pqc_private_key, &mut pqc_manager)?;
            tx.sender = address.to_string();

            Ok("Transaction signed successfully".to_string())
        } else {
            Err("Wallet not found or no private key available".to_string())
        }
    }

    pub fn verify_signature(&self, tx: &Transaction) -> bool {
        if let Some(keypair) = self.keypairs.get(&tx.sender) {
            let (public_key, _) = keypair;
            let public_key_bytes = match decode_key_material(public_key) {
                Ok(bytes) => bytes,
                Err(_) => return false,
            };
            let message_hash = match hex::decode(tx.raw_hash()) {
                Ok(bytes) => bytes,
                Err(_) => return false,
            };
            let algorithm = match parse_signature_algorithm(&tx.signature_algorithm) {
                Ok(algorithm) => algorithm,
                Err(_) => return false,
            };

            let pqc_public_key = crate::crypto::pqc::PQCPublicKey {
                algorithm: algorithm.clone(),
                key_data: public_key_bytes,
                key_id: tx.sender.clone(),
                created_at: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            };
            let signature = crate::crypto::pqc::PQCSignature {
                algorithm,
                signature_data: tx.signature.clone(),
                message_hash: message_hash.clone(),
                public_key_id: tx.sender.clone(),
                created_at: tx.timestamp,
            };

            let pqc_manager = crate::crypto::pqc::PQCManager::new();
            pqc_manager
                .verify(&pqc_public_key, &signature, &message_hash)
                .unwrap_or(false)
        } else {
            false
        }
    }

    pub fn send_tokens(
        &mut self,
        from: &str,
        to: &str,
        token_symbol: &str,
        amount: u64,
        memo: Option<&str>,
        token_manager: &crate::token::TokenManager,
    ) -> Result<Transaction, String> {
        if !crate::address::is_valid_address(from) {
            return Err("Invalid sender Synergy address".to_string());
        }
        if !crate::address::is_valid_address(to) {
            return Err("Invalid receiver Synergy address".to_string());
        }

        // Create transaction
        let mut tx = Transaction::new(
            from.to_string(),
            to.to_string(),
            amount,
            self.get_wallet(from).map_or(0, |w| w.nonce),
            vec![], // signature will be added
            1000,   // gas_price
            21000,  // gas_limit
            Some(format!(
                "token_transfer:{{\"to\":\"{}\",\"token\":\"{}\",\"amount\":{},\"memo\":{}}}",
                to,
                token_symbol,
                amount,
                serde_json::to_string(&memo.unwrap_or_default())
                    .unwrap_or_else(|_| "\"\"".to_string())
            )),
            "mldsa87".to_string(), // signature algorithm
        );
        tx.set_gas_limit(tx.estimate_gas())?;

        let balance = token_manager.get_balance(from, token_symbol) as u128;
        let fee_reserve = tx.get_max_network_fee_reserve_nwei();
        let required_balance = (amount as u128).saturating_add(fee_reserve);
        if token_symbol == crate::token::SNRG_SYMBOL && balance < required_balance {
            return Err(format!(
                "Insufficient balance for transfer amount and network fee reserve: requires {required_balance} nWei"
            ));
        }
        if token_symbol != crate::token::SNRG_SYMBOL && balance < amount as u128 {
            return Err("Insufficient token balance".to_string());
        }
        if token_symbol != crate::token::SNRG_SYMBOL
            && (token_manager.get_balance(from, crate::token::SNRG_SYMBOL) as u128) < fee_reserve
        {
            return Err(format!(
                "Insufficient SNRG balance for network fee reserve: requires {fee_reserve} nWei"
            ));
        }

        // Sign transaction
        self.sign_transaction(from, &mut tx)?;

        // Update nonce
        if let Some(wallet) = self.wallets.get_mut(from) {
            wallet.increment_nonce();
        }

        Ok(tx)
    }

    pub fn stake_tokens(
        &mut self,
        staker: &str,
        validator: &str,
        token_symbol: &str,
        amount: u64,
        token_manager: &crate::token::TokenManager,
    ) -> Result<Transaction, String> {
        if !crate::address::is_valid_address(staker) {
            return Err("Invalid staker Synergy address".to_string());
        }
        if !crate::address::is_valid_address(validator) {
            return Err("Invalid validator Synergy address".to_string());
        }

        // Create staking transaction
        let mut tx = Transaction::new(
            staker.to_string(),
            validator.to_string(),
            amount,
            self.get_wallet(staker).map_or(0, |w| w.nonce),
            vec![], // signature will be added
            1000,
            21000,
            Some(format!(
                "stake:{{\"validator\":\"{}\",\"token\":\"{}\",\"amount\":{}}}",
                validator, token_symbol, amount
            )),
            "mldsa87".to_string(), // signature algorithm
        );
        tx.set_gas_limit(tx.estimate_gas())?;

        let balance = token_manager.get_balance(staker, token_symbol) as u128;
        let fee_reserve = tx.get_max_network_fee_reserve_nwei();
        let required_balance = (amount as u128).saturating_add(fee_reserve);
        if token_symbol == crate::token::SNRG_SYMBOL && balance < required_balance {
            return Err(format!(
                "Insufficient balance for staking amount and network fee reserve: requires {required_balance} nWei"
            ));
        }
        if token_symbol != crate::token::SNRG_SYMBOL && balance < amount as u128 {
            return Err("Insufficient token balance for staking".to_string());
        }
        if token_symbol != crate::token::SNRG_SYMBOL
            && (token_manager.get_balance(staker, crate::token::SNRG_SYMBOL) as u128) < fee_reserve
        {
            return Err(format!(
                "Insufficient SNRG balance for staking fee reserve: requires {fee_reserve} nWei"
            ));
        }

        // Sign transaction
        self.sign_transaction(staker, &mut tx)?;

        // Update nonce
        if let Some(wallet) = self.wallets.get_mut(staker) {
            wallet.increment_nonce();
        }

        Ok(tx)
    }

    pub fn activate_validator(
        &mut self,
        validator: &str,
        name: &str,
        stake_amount_nwei: u64,
    ) -> Result<Transaction, String> {
        if !crate::address::is_valid_address(validator) {
            return Err("Invalid validator Synergy address".to_string());
        }

        let wallet = self
            .get_wallet(validator)
            .ok_or_else(|| "Validator wallet not found or no private key available".to_string())?;
        let public_key = wallet.public_key.clone();
        let nonce = wallet.nonce;
        let payload = serde_json::json!({
            "validator": validator,
            "public_key": public_key,
            "name": name,
            "stake_amount_nwei": stake_amount_nwei,
        });

        let mut tx = Transaction::new(
            validator.to_string(),
            validator.to_string(),
            0,
            nonce,
            vec![],
            1000,
            21000,
            Some(format!("validator_activation:{payload}")),
            "mldsa87".to_string(),
        );
        tx.set_gas_limit(tx.estimate_gas())?;

        self.sign_transaction(validator, &mut tx)?;

        if let Some(wallet) = self.wallets.get_mut(validator) {
            wallet.increment_nonce();
        }

        Ok(tx)
    }

    pub fn encrypt_payload_with_mlkem1024(
        &self,
        sender: &str,
        recipient: &str,
        payload: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), String> {
        let _sender_wallet = self
            .wallets
            .get(sender)
            .ok_or_else(|| format!("Sender wallet {} not found", sender))?;
        let recipient_wallet = self
            .wallets
            .get(recipient)
            .ok_or_else(|| format!("Recipient wallet {} not found", recipient))?;

        let kem_public = self.get_kem_public_key_bytes(recipient)?;
        let pqc_public_key = PQCPublicKey {
            algorithm: PQCAlgorithm::MLKEM1024,
            key_data: kem_public,
            key_id: format!("kem_{}", recipient),
            created_at: recipient_wallet.created_at,
        };

        let mut pqc_manager = PQCManager::new();
        let (ciphertext_record, shared_secret_record) = pqc_manager.encapsulate(&pqc_public_key)?;
        let encrypted_payload = Self::xor_with_shared_secret(payload, &shared_secret_record.secret);

        Ok((
            ciphertext_record.ciphertext.clone(),
            encrypted_payload,
            shared_secret_record.secret.clone(),
        ))
    }

    pub fn decrypt_payload_with_mlkem1024(
        &self,
        recipient: &str,
        ciphertext: &[u8],
        encrypted_payload: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), String> {
        let recipient_wallet = self
            .wallets
            .get(recipient)
            .ok_or_else(|| format!("Recipient wallet {} not found", recipient))?;
        let kem_private = self.get_kem_private_key_bytes(recipient)?;

        let pqc_private_key = PQCPrivateKey {
            algorithm: PQCAlgorithm::MLKEM1024,
            key_data: kem_private,
            public_key_id: format!("kem_{}", recipient),
            created_at: recipient_wallet.created_at,
        };

        let pqc_ciphertext = PQCCiphertext {
            algorithm: PQCAlgorithm::MLKEM1024,
            ciphertext: ciphertext.to_vec(),
            encapsulated_key: Vec::new(),
            public_key_id: pqc_private_key.public_key_id.clone(),
            created_at: Wallet::current_timestamp(),
        };

        let pqc_manager = PQCManager::new();
        let shared_secret = pqc_manager.decapsulate(&pqc_private_key, &pqc_ciphertext)?;
        let plaintext = Self::xor_with_shared_secret(encrypted_payload, &shared_secret.secret);

        Ok((plaintext, shared_secret.secret.clone()))
    }

    pub fn get_all_wallets(&self) -> Vec<&Wallet> {
        self.wallets.values().collect()
    }

    fn get_kem_public_key_bytes(&self, address: &str) -> Result<Vec<u8>, String> {
        self.kem_keypairs
            .get(address)
            .ok_or_else(|| format!("Wallet {} does not have an ML-KEM public key", address))
            .and_then(|(public_hex, _)| {
                hex::decode(public_hex)
                    .map_err(|e| format!("Invalid ML-KEM public key for {}: {}", address, e))
            })
    }

    fn get_kem_private_key_bytes(&self, address: &str) -> Result<Vec<u8>, String> {
        self.kem_keypairs
            .get(address)
            .ok_or_else(|| format!("Wallet {} does not have an ML-KEM private key", address))
            .and_then(|(_, private_hex)| {
                hex::decode(private_hex)
                    .map_err(|e| format!("Invalid ML-KEM private key for {}: {}", address, e))
            })
    }

    fn xor_with_shared_secret(data: &[u8], shared_secret: &[u8]) -> Vec<u8> {
        data.iter()
            .zip(shared_secret.iter().cycle())
            .map(|(a, b)| a ^ b)
            .collect()
    }

    // Additional wallet utility functions
    pub fn export_private_key(&self, address: &str, _password: &str) -> Result<String, String> {
        if let Some(keypair) = self.keypairs.get(address) {
            let (_, private_key) = keypair;
            // In production, this would encrypt the private key with the password
            // For now, we'll just return the hex-encoded private key
            Ok(private_key.clone())
        } else {
            Err("Wallet not found".to_string())
        }
    }

    pub fn import_private_key(
        &mut self,
        private_key: &str,
        _password: &str,
    ) -> Result<String, String> {
        // In production, this would decrypt the private key with the password
        // For now, we'll assume the private key is already decrypted

        // Generate public key from private key (simplified)
        let public_key = hex::encode(format!("pub_{}", private_key).as_bytes());
        let address = Self::generate_address(&public_key);

        // Create wallet from imported keypair
        self.create_wallet_from_keypair(public_key, private_key.to_string())?;

        Ok(address)
    }

    pub fn get_wallet_balance(
        &self,
        address: &str,
        token_manager: &crate::token::TokenManager,
    ) -> HashMap<String, u64> {
        let mut balances = HashMap::new();

        // Get balances for all tokens
        let tokens = vec!["SNRG", "USDT", "USDC", "BTC", "ETH"];
        for token in tokens {
            let balance = token_manager.get_balance(address, token);
            if balance > 0 {
                balances.insert(token.to_string(), balance);
            }
        }

        balances
    }

    pub fn get_transaction_history(&self, _address: &str) -> Vec<String> {
        // In production, this would query the blockchain for transaction history
        // For now, return empty vector
        vec![]
    }

    pub fn backup_wallet(&self, address: &str) -> Result<String, String> {
        if let Some(wallet) = self.wallets.get(address) {
            // Create wallet backup data
            let backup_data = serde_json::json!({
                "address": wallet.address,
                "public_key": wallet.public_key,
                "nonce": wallet.nonce,
                "backup_timestamp": std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
            });

            Ok(backup_data.to_string())
        } else {
            Err("Wallet not found".to_string())
        }
    }

    pub fn restore_wallet(&mut self, backup_data: &str) -> Result<String, String> {
        let backup: serde_json::Value =
            serde_json::from_str(backup_data).map_err(|e| format!("Invalid backup data: {}", e))?;

        let address = backup["address"]
            .as_str()
            .ok_or("Missing address in backup data")?;
        let public_key = backup["public_key"]
            .as_str()
            .ok_or("Missing public key in backup data")?;

        // Create wallet from backup data
        let (kem_public, kem_private) = Self::generate_mlkem_keypair()?;
        let mut wallet = Wallet::new(address.to_string(), public_key.to_string());
        wallet.kem_public_key = Some(kem_public.clone());
        wallet.kem_private_key = Some(kem_private.clone());

        self.wallets.insert(address.to_string(), wallet);
        self.kem_keypairs
            .insert(address.to_string(), (kem_public, kem_private));

        Ok(address.to_string())
    }
}

// Global wallet manager instance
lazy_static::lazy_static! {
    pub static ref WALLET_MANAGER: std::sync::Mutex<WalletManager> = std::sync::Mutex::new(WalletManager::new());
}

/// Loads testnet system identities (faucet/treasury/bootnodes) into the in-memory wallet manager.
/// This enables signing test transactions and validating known genesis identities.
pub fn init_testnet_wallets() {
    let config_path = "config/testnet_wallets.json";
    let mut imported = 0u64;

    if let Ok(cfg) = std::fs::read_to_string(config_path) {
        let json = match serde_json::from_str::<serde_json::Value>(&cfg) {
            Ok(v) => v,
            Err(e) => {
                warn!("wallet", "Failed to parse testnet_wallets.json", "error" => e.to_string());
                serde_json::Value::Null
            }
        };

        let mut identities: Vec<&serde_json::Value> = Vec::new();
        if let Some(faucet) = json.get("faucet") {
            identities.push(faucet);
        }
        if let Some(treasury) = json.get("treasury") {
            identities.push(treasury);
        }
        if let Some(bootnodes) = json.get("bootnodes").and_then(|v| v.as_array()) {
            for b in bootnodes {
                identities.push(b);
            }
        }

        for entry in identities {
            let keys_location = entry.get("keys_location").and_then(|v| v.as_str());
            if keys_location.is_none() {
                continue;
            }
            let keys_location = keys_location.unwrap();
            let identity_str = match std::fs::read_to_string(keys_location) {
                Ok(s) => s,
                Err(e) => {
                    warn!("wallet", "Failed to read identity file", "path" => keys_location.to_string(), "error" => e.to_string());
                    continue;
                }
            };

            let identity = match serde_json::from_str::<serde_json::Value>(&identity_str) {
                Ok(v) => v,
                Err(e) => {
                    warn!("wallet", "Failed to parse identity file", "path" => keys_location.to_string(), "error" => e.to_string());
                    continue;
                }
            };

            let address = identity
                .get("address")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let public_key = identity
                .get("public_key")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let private_key = identity
                .get("private_key")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            if address.is_empty() || public_key.is_empty() || private_key.is_empty() {
                continue;
            }

            import_testnet_wallet_material(
                TestnetWalletMaterial {
                    address,
                    public_key,
                    private_key,
                },
                &mut imported,
            );
        }
    }

    for wallet_material in load_testnet_local_identity_wallets() {
        import_testnet_wallet_material(wallet_material, &mut imported);
    }

    for wallet_record in load_testnet_profile_wallet_records() {
        let public_key = match std::fs::read_to_string(&wallet_record.public_key_path) {
            Ok(contents) => contents.trim().to_string(),
            Err(error) => {
                warn!(
                    "wallet",
                    "Failed to read Testnet wallet public key",
                    "path" => wallet_record.public_key_path.clone(),
                    "error" => error.to_string()
                );
                continue;
            }
        };
        let private_key = match std::fs::read_to_string(&wallet_record.private_key_path) {
            Ok(contents) => contents.trim().to_string(),
            Err(error) => {
                warn!(
                    "wallet",
                    "Failed to read Testnet wallet private key",
                    "path" => wallet_record.private_key_path.clone(),
                    "error" => error.to_string()
                );
                continue;
            }
        };

        if public_key.is_empty()
            || private_key.is_empty()
            || wallet_record.address.trim().is_empty()
        {
            continue;
        }

        import_testnet_wallet_material(
            TestnetWalletMaterial {
                address: wallet_record.address.clone(),
                public_key,
                private_key,
            },
            &mut imported,
        );
    }

    if imported > 0 {
        info!("wallet", "Imported testnet identities", "count" => imported);
    }
}

fn import_testnet_wallet_material(wallet_material: TestnetWalletMaterial, imported: &mut u64) {
    if wallet_material.address.trim().is_empty()
        || wallet_material.public_key.trim().is_empty()
        || wallet_material.private_key.trim().is_empty()
    {
        return;
    }

    if let Ok(mut wm) = WALLET_MANAGER.lock() {
        if wm
            .import_wallet(
                wallet_material.address,
                wallet_material.public_key,
                wallet_material.private_key,
            )
            .is_ok()
        {
            *imported += 1;
        }
    }
}

fn load_testnet_local_identity_wallets() -> Vec<TestnetWalletMaterial> {
    candidate_testnet_local_identity_paths()
        .into_iter()
        .filter_map(|path| read_testnet_identity_wallet_material(&path))
        .collect()
}

fn read_testnet_identity_wallet_material(identity_path: &PathBuf) -> Option<TestnetWalletMaterial> {
    let identity_str = std::fs::read_to_string(identity_path).ok()?;
    let identity = serde_json::from_str::<serde_json::Value>(&identity_str).ok()?;
    let key_directory = identity_path.parent()?;

    let address = identity
        .get("address")
        .and_then(|value| value.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    let public_key = identity
        .get("public_key")
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .or_else(|| read_trimmed_file(key_directory.join("public.key")));
    let private_key = identity
        .get("private_key")
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .or_else(|| read_trimmed_file(key_directory.join("private.key")));

    match (address.is_empty(), public_key, private_key) {
        (false, Some(public_key), Some(private_key))
            if !public_key.is_empty() && !private_key.is_empty() =>
        {
            Some(TestnetWalletMaterial {
                address,
                public_key,
                private_key,
            })
        }
        _ => None,
    }
}

fn candidate_testnet_local_identity_paths() -> Vec<PathBuf> {
    let mut candidates = Vec::new();

    if let Ok(project_root) = std::env::var("SYNERGY_PROJECT_ROOT") {
        let root = PathBuf::from(project_root.trim());
        if !root.as_os_str().is_empty() {
            candidates.push(root.join("identity").join("identity.json"));
            candidates.push(root.join("keys").join("identity.json"));
        }
    }

    if let Ok(config_path) = std::env::var("SYNERGY_CONFIG_PATH") {
        let path = PathBuf::from(config_path.trim());
        if let Some(workspace_root) = path.parent().and_then(|config_dir| config_dir.parent()) {
            candidates.push(workspace_root.join("identity").join("identity.json"));
            candidates.push(workspace_root.join("keys").join("identity.json"));
        }
    }

    if let Ok(current_dir) = std::env::current_dir() {
        candidates.push(current_dir.join("identity").join("identity.json"));
        candidates.push(current_dir.join("keys").join("identity.json"));
    }

    let mut deduped = Vec::new();
    for candidate in candidates {
        if !deduped.contains(&candidate) {
            deduped.push(candidate);
        }
    }

    deduped
}

fn read_trimmed_file(path: PathBuf) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|contents| contents.trim().to_string())
        .filter(|contents| !contents.is_empty())
}

fn load_testnet_profile_wallet_records() -> Vec<TestnetProfileWalletRecord> {
    for path in candidate_testnet_profile_paths() {
        let Ok(contents) = std::fs::read_to_string(&path) else {
            continue;
        };
        let Ok(profile) = serde_json::from_str::<TestnetProfileWallets>(&contents) else {
            continue;
        };
        return vec![
            profile.treasury_wallet,
            profile.faucet_wallet,
            profile.stake_vault_wallet,
        ];
    }

    Vec::new()
}

fn candidate_testnet_profile_paths() -> Vec<PathBuf> {
    let mut candidates = Vec::new();

    if let Ok(project_root) = std::env::var("SYNERGY_PROJECT_ROOT") {
        let root = PathBuf::from(project_root);
        candidates.push(root.join("network").join("profile.json"));
        if let Some(testnet_root) = root.parent().and_then(|parent| parent.parent()) {
            candidates.push(testnet_root.join("network").join("profile.json"));
        }
    }

    candidates.push(PathBuf::from("network/profile.json"));
    candidates.push(PathBuf::from("../../network/profile.json"));
    candidates.push(PathBuf::from("../../../network/profile.json"));

    let mut deduped = Vec::new();
    for candidate in candidates {
        if !deduped.contains(&candidate) {
            deduped.push(candidate);
        }
    }

    deduped
}

fn decode_key_material(s: &str) -> Result<Vec<u8>, String> {
    // Try hex first (preferred internal representation), then base64 (identity.json format).
    if let Ok(bytes) = hex::decode(s) {
        return Ok(bytes);
    }
    general_purpose::STANDARD
        .decode(s.as_bytes())
        .map_err(|e| e.to_string())
}

fn parse_signature_algorithm(value: &str) -> Result<PQCAlgorithm, String> {
    // Wallet-signed user transactions are ML-DSA-87 (Testnet-v3 account domain).
    match value.trim().to_ascii_lowercase().as_str() {
        "mldsa87" | "ml-dsa-87" | "ml_dsa_87" => Ok(PQCAlgorithm::MLDSA87),
        _ => Err(format!(
            "Unsupported signature algorithm: {}; use mldsa87",
            value
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::Transaction;
    use std::fs;

    fn credit_test_snrg(
        token_manager: &crate::token::TokenManager,
        address: &str,
        amount_nwei: u64,
    ) {
        let mut balances = token_manager
            .balances
            .lock()
            .expect("test token balances should lock");
        let account = balances.entry(address.to_string()).or_default();
        let current = account.get(crate::token::SNRG_SYMBOL).copied().unwrap_or(0);
        account.insert(
            crate::token::SNRG_SYMBOL.to_string(),
            current
                .checked_add(amount_nwei)
                .expect("test SNRG balance should not overflow"),
        );
    }

    #[test]
    fn wallet_signed_transaction_verifies_with_strict_pqc() {
        let mut wallet_manager = WalletManager::new();
        let sender = wallet_manager
            .create_wallet()
            .expect("wallet creation should succeed");
        let mut tx = Transaction::new(
            sender.clone(),
            "receiver_test".to_string(),
            1,
            0,
            vec![],
            1,
            21_000,
            None,
            "mldsa87".to_string(),
        );

        wallet_manager
            .sign_transaction(&sender, &mut tx)
            .expect("transaction signing should succeed");

        assert!(
            wallet_manager.verify_signature(&tx),
            "strict PQC verification should succeed for a wallet-signed transaction"
        );
    }

    #[test]
    fn wallet_rejects_unsupported_signature_algorithm() {
        let mut wallet_manager = WalletManager::new();
        let sender = wallet_manager
            .create_wallet()
            .expect("wallet creation should succeed");
        let mut tx = Transaction::new(
            sender.clone(),
            "receiver_test".to_string(),
            1,
            0,
            vec![],
            1,
            21_000,
            None,
            "mldsa87".to_string(),
        );

        wallet_manager
            .sign_transaction(&sender, &mut tx)
            .expect("transaction signing should succeed");
        tx.signature_algorithm = "unknown_algo".to_string();

        assert!(
            !wallet_manager.verify_signature(&tx),
            "unknown signature algorithm should be rejected"
        );
    }

    #[test]
    fn staking_requires_a_fee_reserve_and_uses_the_estimated_gas_limit() {
        let mut wallet_manager = WalletManager::new();
        let staker = wallet_manager
            .create_wallet()
            .expect("wallet creation should succeed");
        let validator = crate::address::generate_validator_address("wallet-stake-gas", 7);
        let token_manager = crate::token::TokenManager::new();
        let amount = 50_000_000_000_000u64;
        credit_test_snrg(&token_manager, &staker, amount);

        let error = wallet_manager
            .stake_tokens(
                &staker,
                &validator,
                crate::token::SNRG_SYMBOL,
                amount,
                &token_manager,
            )
            .expect_err("the exact bond amount cannot also pay the network fee");
        assert!(error.contains("network fee reserve"));

        credit_test_snrg(&token_manager, &staker, 1_000_000_000);
        let tx = wallet_manager
            .stake_tokens(
                &staker,
                &validator,
                crate::token::SNRG_SYMBOL,
                amount,
                &token_manager,
            )
            .expect("the buffered self-bond should be signed");

        assert_eq!(tx.get_gas_limit(), tx.minimum_required_gas());
        assert!(tx.get_gas_limit() > 21_000);
    }

    #[test]
    fn snrg_transfer_requires_the_amount_protocol_fee_and_gas_reserve() {
        let mut wallet_manager = WalletManager::new();
        let sender = wallet_manager
            .create_wallet()
            .expect("wallet creation should succeed");
        let receiver = wallet_manager
            .create_wallet()
            .expect("receiver wallet creation should succeed");
        let token_manager = crate::token::TokenManager::new();
        let amount = 50_001_000_000_000u64;
        credit_test_snrg(&token_manager, &sender, amount);

        let error = wallet_manager
            .send_tokens(
                &sender,
                &receiver,
                crate::token::SNRG_SYMBOL,
                amount,
                Some("validator self-bond funding"),
                &token_manager,
            )
            .expect_err("the transfer amount cannot also pay its network fee");
        assert!(error.contains("network fee reserve"));

        credit_test_snrg(&token_manager, &sender, 20_000_000_000);
        let tx = wallet_manager
            .send_tokens(
                &sender,
                &receiver,
                crate::token::SNRG_SYMBOL,
                amount,
                Some("validator self-bond funding"),
                &token_manager,
            )
            .expect("the buffered funding transfer should be signed");

        assert_eq!(tx.get_gas_limit(), tx.minimum_required_gas());
        assert!(tx.get_max_network_fee_reserve_nwei() < 20_000_000_000);
    }

    #[test]
    fn non_snrg_transfer_pays_native_snrg_gas_through_token_manager() {
        let mut wallet_manager = WalletManager::new();
        let sender = wallet_manager
            .create_wallet()
            .expect("wallet creation should succeed");
        let receiver = wallet_manager
            .create_wallet()
            .expect("receiver wallet creation should succeed");
        let token_manager = crate::token::TokenManager::new();
        let amount = 500_000u64;
        token_manager
            .create_token(
                "TEST".to_string(),
                "Wallet Test Token".to_string(),
                6,
                amount,
                Some(amount),
                false,
                false,
                sender.clone(),
            )
            .expect("custom token should be created for the sender");
        credit_test_snrg(&token_manager, &sender, 20_000_000_000);

        let before_snrg = token_manager.get_balance(&sender, crate::token::SNRG_SYMBOL);
        let tx = wallet_manager
            .send_tokens(
                &sender,
                &receiver,
                "TEST",
                amount,
                Some("custom-token transfer"),
                &token_manager,
            )
            .expect("custom-token transfer should be signed with native fee reserve");
        let fee = tx
            .get_total_network_fee_u64()
            .expect("network fee should fit in u64");
        let breakdown = tx
            .get_network_fee_breakdown()
            .expect("network fee breakdown should be available");
        assert_eq!(breakdown.amount_protocol_fee_nwei, 0);
        assert_eq!(breakdown.total_network_fee_nwei, breakdown.gas_fee_nwei);

        token_manager
            .process_transaction(&tx)
            .expect("TokenManager should charge native SNRG and transfer the custom token");
        assert_eq!(token_manager.get_balance(&sender, "TEST"), 0);
        assert_eq!(token_manager.get_balance(&receiver, "TEST"), amount);
        assert_eq!(
            token_manager.get_balance(&sender, crate::token::SNRG_SYMBOL),
            before_snrg - fee
        );
        assert_eq!(
            token_manager.get_balance(
                crate::token::FEE_COLLECTOR_ADDRESS,
                crate::token::SNRG_SYMBOL
            ),
            fee
        );
    }

    #[test]
    fn non_snrg_stake_pays_native_snrg_gas_through_token_manager() {
        let mut wallet_manager = WalletManager::new();
        let staker = wallet_manager
            .create_wallet()
            .expect("wallet creation should succeed");
        let validator = crate::address::generate_validator_address("wallet-custom-stake", 8);
        let token_manager = crate::token::TokenManager::new();
        let amount = 500_000u64;
        token_manager
            .create_token(
                "TEST".to_string(),
                "Wallet Stake Token".to_string(),
                6,
                amount,
                Some(amount),
                false,
                false,
                staker.clone(),
            )
            .expect("custom token should be created for the staker");
        credit_test_snrg(&token_manager, &staker, 20_000_000_000);

        let before_snrg = token_manager.get_balance(&staker, crate::token::SNRG_SYMBOL);
        let tx = wallet_manager
            .stake_tokens(&staker, &validator, "TEST", amount, &token_manager)
            .expect("custom-token stake should be signed with native fee reserve");
        let fee = tx
            .get_total_network_fee_u64()
            .expect("network fee should fit in u64");
        let breakdown = tx
            .get_network_fee_breakdown()
            .expect("network fee breakdown should be available");
        assert_eq!(breakdown.amount_protocol_fee_nwei, 0);
        assert_eq!(breakdown.total_network_fee_nwei, breakdown.gas_fee_nwei);

        token_manager
            .process_transaction(&tx)
            .expect("TokenManager should charge native SNRG and stake the custom token");
        assert_eq!(token_manager.get_balance(&staker, "TEST"), 0);
        assert_eq!(token_manager.get_staked_balance(&staker, "TEST"), amount);
        assert_eq!(
            token_manager.get_balance(&staker, crate::token::SNRG_SYMBOL),
            before_snrg - fee
        );
        assert_eq!(
            token_manager.get_balance(
                crate::token::FEE_COLLECTOR_ADDRESS,
                crate::token::SNRG_SYMBOL
            ),
            fee
        );
    }

    #[test]
    fn validator_activation_uses_the_operation_specific_gas_limit() {
        let mut wallet_manager = WalletManager::new();
        let validator = wallet_manager
            .create_wallet()
            .expect("wallet creation should succeed");

        let tx = wallet_manager
            .activate_validator(&validator, "Community Validator", 50_000_000_000_000)
            .expect("validator activation should be signed");

        assert_eq!(tx.get_gas_limit(), tx.minimum_required_gas());
        assert!(tx.get_gas_limit() > 21_000);
    }

    #[test]
    fn imported_wallet_does_not_generate_kem_material() {
        let mut wallet_manager = WalletManager::new();
        let address = "synwimportedwallet0000000000000000000000".to_string();

        wallet_manager
            .import_wallet(
                address.clone(),
                hex::encode([1u8; 32]),
                hex::encode([2u8; 32]),
            )
            .expect("imported signing wallet should not need generated KEM material");

        assert!(wallet_manager.keypairs.contains_key(&address));
        assert!(!wallet_manager.kem_keypairs.contains_key(&address));
        let wallet = wallet_manager
            .wallets
            .get(&address)
            .expect("imported wallet should be stored");
        assert!(wallet.kem_public_key.is_none());
        assert!(wallet.kem_private_key.is_none());
    }

    #[test]
    fn local_identity_loader_uses_sibling_key_files_when_metadata_omits_private_key() {
        let root = crate::utils::test_temp_root(format!(
            "synergy-wallet-identity-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system time should be valid")
                .as_nanos()
        ));
        let keys = root.join("keys");
        fs::create_dir_all(&keys).expect("keys directory should be created");
        let identity_path = keys.join("identity.json");
        fs::write(
            &identity_path,
            r#"{"address":"synv1localidentity","public_key":"public-from-json"}"#,
        )
        .expect("identity should write");
        fs::write(keys.join("private.key"), "private-from-file").expect("private key should write");

        let material = read_testnet_identity_wallet_material(&identity_path)
            .expect("local identity should load from identity.json plus private.key");

        assert_eq!(material.address, "synv1localidentity");
        assert_eq!(material.public_key, "public-from-json");
        assert_eq!(material.private_key, "private-from-file");

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn local_identity_candidates_include_validator_appliance_identity_directory() {
        let root = crate::utils::test_temp_root(format!(
            "synergy-wallet-appliance-candidate-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system time should be valid")
                .as_nanos()
        ));
        let identity = root.join("identity");
        fs::create_dir_all(&identity).expect("identity directory should be created");
        let identity_path = identity.join("identity.json");
        fs::write(
            &identity_path,
            r#"{"address":"synv1applianceidentity","public_key":"public-from-json"}"#,
        )
        .expect("identity should write");
        fs::write(identity.join("private.key"), "private-from-file")
            .expect("private key should write");

        std::env::set_var("SYNERGY_PROJECT_ROOT", &root);
        let candidates = candidate_testnet_local_identity_paths();
        std::env::remove_var("SYNERGY_PROJECT_ROOT");

        assert!(
            candidates.contains(&identity_path),
            "new validator appliance layout must be scanned before legacy keys/"
        );
        let material = read_testnet_identity_wallet_material(&identity_path)
            .expect("validator appliance identity should load from identity/ plus private.key");
        assert_eq!(material.address, "synv1applianceidentity");
        assert_eq!(material.public_key, "public-from-json");
        assert_eq!(material.private_key, "private-from-file");

        let _ = fs::remove_dir_all(root);
    }
}
