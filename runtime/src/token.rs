use crate::genesis::canonical_genesis;
use crate::transaction::Transaction;
use crate::warn;
use hex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha3::{Digest, Sha3_256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

pub const SNRG_SYMBOL: &str = "SNRG";
#[cfg(test)]
pub const FEE_COLLECTOR_ADDRESS: &str = "synf1y42p7p6jrxrg472ts6jea5y34yg7tgj6qg2j";
#[cfg(test)]
pub const DAO_TREASURY_ADDRESS: &str = "synw1pqwglyfjynrxt7ms9nvggntav6x3lx9c2l4r";
#[cfg(test)]
pub const TREASURY_RECOVERY_WALLET_ADDRESS: &str = "synw1syv3tnu6r2y5e3u9f0wqmxhavylfxena0z92";
#[cfg(test)]
pub const VALIDATOR_REWARDS_POOL_ADDRESS: &str = "synw1at607x35rkmsmvgz069nx0j3q5km93krrvge";
pub const RELIABILITY_BONUS_POOL_ADDRESS: &str = "synw1mct6a33g7hyt6jzkjdwrvxzf644lc4vytqcz";
pub const BURN_SINK_ADDRESS: &str = "synb1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqjk5cn";
pub const NETWORK_BURN_ADDRESS: &str = crate::address::NETWORK_BURN_ADDRESS;

/// Canonical protocol-controlled addresses resolved from the active Testnet-v3
/// genesis. Production must never fall back to an inherited network address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestnetV3SystemAddresses {
    pub fee_collector: String,
    pub dao_treasury: String,
    pub treasury_recovery: String,
    pub validator_rewards_pool: String,
    pub burn_sink: String,
}

fn required_genesis_account_address(value: &Value, account_id: &str) -> Result<String, String> {
    value
        .get("accounts")
        .and_then(Value::as_array)
        .and_then(|accounts| {
            accounts.iter().find_map(|account| {
                (account.get("account_id").and_then(Value::as_str) == Some(account_id))
                    .then(|| account.get("address").and_then(Value::as_str))
                    .flatten()
            })
        })
        .map(str::trim)
        .filter(|address| !address.is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| format!("canonical genesis is missing {account_id} address binding"))
}

pub(crate) fn testnet_v3_system_addresses_from_genesis(
    value: &Value,
) -> Result<TestnetV3SystemAddresses, String> {
    if value
        .get("network")
        .and_then(|network| network.get("chain_id"))
        .and_then(Value::as_u64)
        != Some(crate::synergy_types::SYNERGY_TESTNET_V3_CHAIN_ID)
    {
        return Err("system address resolution requires Testnet-v3 chain ID 1266".to_string());
    }

    let validator_rewards_pool = value
        .get("contracts")
        .and_then(|contracts| contracts.get("reward_distributor"))
        .and_then(|contract| contract.get("address"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|address| !address.is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| {
            "canonical genesis is missing RewardDistributor address binding".to_string()
        })?;

    Ok(TestnetV3SystemAddresses {
        fee_collector: required_genesis_account_address(value, "SYS-01")?,
        dao_treasury: required_genesis_account_address(value, "DAO-A01")?,
        treasury_recovery: required_genesis_account_address(value, "SYS-02")?,
        validator_rewards_pool,
        burn_sink: required_genesis_account_address(value, "SYS-04")?,
    })
}

#[cfg(not(test))]
pub fn testnet_v3_system_addresses() -> Result<TestnetV3SystemAddresses, String> {
    let genesis = canonical_genesis().map_err(|error| {
        format!("load canonical Testnet-v3 genesis for system addresses: {error}")
    })?;
    testnet_v3_system_addresses_from_genesis(genesis.value())
}

#[cfg(test)]
pub fn testnet_v3_system_addresses() -> Result<TestnetV3SystemAddresses, String> {
    // Unit fixtures intentionally use minimal legacy-shaped genesis documents.
    // Candidate-specific tests below exercise the production resolver directly.
    Ok(TestnetV3SystemAddresses {
        fee_collector: FEE_COLLECTOR_ADDRESS.to_string(),
        dao_treasury: DAO_TREASURY_ADDRESS.to_string(),
        treasury_recovery: TREASURY_RECOVERY_WALLET_ADDRESS.to_string(),
        validator_rewards_pool: VALIDATOR_REWARDS_POOL_ADDRESS.to_string(),
        burn_sink: BURN_SINK_ADDRESS.to_string(),
    })
}

pub fn fee_collector_address() -> Result<String, String> {
    Ok(testnet_v3_system_addresses()?.fee_collector)
}

pub fn token_state_path() -> PathBuf {
    crate::utils::resolve_data_path("data/token_state.json")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Token {
    pub symbol: String,
    pub name: String,
    pub decimals: u8,
    #[serde(default)]
    pub token_address: Option<String>,
    pub total_supply: String,
    pub max_supply: Option<String>,
    pub mintable: bool,
    pub burnable: bool,
    pub created_at: u64,
    pub creator: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenBalance {
    pub address: String,
    pub token_symbol: String,
    pub balance: u64,
    pub locked_balance: u64,
    pub staked_balance: u64,
    pub last_updated: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenTransfer {
    pub from: String,
    pub to: String,
    pub token_symbol: String,
    pub amount: u64,
    pub fee: u64,
    pub timestamp: u64,
    pub tx_hash: String,
    pub block_height: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BurnRecordKind {
    ExplicitBurn,
    BurnAddressTransfer,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BurnRecord {
    pub burner: String,
    pub asset_id: String,
    pub amount: u64,
    pub burn_address: String,
    pub fee_charged_nwei: u64,
    pub supply_reduced: bool,
    pub tx_hash: String,
    pub block_height: u64,
    pub kind: BurnRecordKind,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StakingInfo {
    pub validator_address: String,
    pub staker_address: String,
    pub amount: u64,
    pub stake_start: u64,
    pub stake_end: Option<u64>,
    pub rewards_earned: u64,
    pub is_active: bool,
}

#[derive(Debug, Deserialize)]
struct TestnetProfileMint {
    wallet_address: String,
    amount_nwei: String,
}

#[derive(Debug, Deserialize)]
struct TestnetTokenProfile {
    genesis_mints: Vec<TestnetProfileMint>,
}

fn profile_allocations_enabled() -> bool {
    matches!(
        std::env::var("SYNERGY_ENABLE_PROFILE_ALLOCATIONS")
            .ok()
            .as_deref(),
        Some("1" | "true" | "TRUE" | "yes" | "YES" | "on" | "ON")
    )
}

#[derive(Debug)]
pub struct TokenManager {
    tokens: Arc<Mutex<HashMap<String, Token>>>,
    pub balances: Arc<Mutex<HashMap<String, HashMap<String, u64>>>>, // address -> token_symbol -> balance
    _locked_balances: Arc<Mutex<HashMap<String, HashMap<String, u64>>>>, // address -> token_symbol -> locked
    staked_balances: Arc<Mutex<HashMap<String, HashMap<String, u64>>>>, // address -> token_symbol -> staked
    transfers: Arc<Mutex<Vec<TokenTransfer>>>,
    stakes: Arc<Mutex<HashMap<String, Vec<StakingInfo>>>>, // validator -> stakes
    total_supply: Arc<Mutex<HashMap<String, u128>>>,       // token_symbol -> total_supply
    burn_ledger: Arc<Mutex<HashMap<String, u128>>>,
    burn_records: Arc<Mutex<Vec<BurnRecord>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EpochRewardLifecycleSummary {
    pub closing_epoch: u64,
    pub next_epoch: u64,
    pub settled_unlock_epoch: u64,
    pub transition_block_height: u64,
    pub total_fees_collected_nwei: u128,
    pub fee_distribution: Option<crate::rewards::EpochFeeDistribution>,
    pub reward_allocation: Option<crate::rewards::EpochRewardAllocation>,
    pub settlements: Vec<crate::rewards::ValidatorRewardSettlement>,
    pub skipped_reasons: Vec<String>,
}

impl Token {
    pub fn new(
        symbol: String,
        name: String,
        decimals: u8,
        total_supply: u128,
        max_supply: Option<u128>,
        mintable: bool,
        burnable: bool,
        creator: String,
    ) -> Self {
        let created_at = Self::current_timestamp();
        let token_address = legacy_non_native_token_address(&symbol, &name, &creator, created_at);

        Token {
            symbol,
            name,
            decimals,
            token_address,
            total_supply: total_supply.to_string(),
            max_supply: max_supply.map(|value| value.to_string()),
            mintable,
            burnable,
            created_at,
            creator,
        }
    }

    fn normalize_identity(&mut self) {
        self.token_address = legacy_non_native_token_address(
            &self.symbol,
            &self.name,
            &self.creator,
            self.created_at,
        );
    }

    pub fn calculate_amount(&self, raw_amount: u64) -> u64 {
        raw_amount * 10u64.pow(self.decimals as u32)
    }

    pub fn format_amount(&self, amount: u64) -> String {
        let divisor = 10u64.pow(self.decimals as u32);
        let whole = amount / divisor;
        let fractional = amount % divisor;
        format!(
            "{whole}.{fractional:0width$}",
            width = self.decimals as usize
        )
    }

    fn current_timestamp() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }
}

impl TokenManager {
    pub fn new() -> Self {
        let mut manager = TokenManager {
            tokens: Arc::new(Mutex::new(HashMap::new())),
            balances: Arc::new(Mutex::new(HashMap::new())),
            _locked_balances: Arc::new(Mutex::new(HashMap::new())),
            staked_balances: Arc::new(Mutex::new(HashMap::new())),
            transfers: Arc::new(Mutex::new(Vec::new())),
            stakes: Arc::new(Mutex::new(HashMap::new())),
            total_supply: Arc::new(Mutex::new(HashMap::new())),
            burn_ledger: Arc::new(Mutex::new(HashMap::new())),
            burn_records: Arc::new(Mutex::new(Vec::new())),
        };

        // Initialize with SNRG token
        manager.initialize_snrg_token();
        manager
    }

    fn initialize_snrg_token(&mut self) {
        let genesis_token = canonical_genesis()
            .ok()
            .map(|genesis| genesis.token().clone());
        let minimum_supply_cap = required_testnet_supply_cap_floor();
        let snrg_token = Token::new(
            "SNRG".to_string(),
            genesis_token
                .as_ref()
                .map(|token| token.name.clone())
                .unwrap_or_else(|| "Synergy Token".to_string()),
            genesis_token
                .as_ref()
                .map(|token| token.decimals)
                .unwrap_or(9),
            0,
            genesis_token
                .as_ref()
                .map(|token| token.total_supply_cap_nwei)
                .map(|value| value.max(minimum_supply_cap))
                .or(Some(
                    (1_150_000u128 * 10u128.pow(9)).max(minimum_supply_cap),
                )),
            true, // mintable during bootstrap
            true, // burnable
            "genesis".to_string(),
        );

        if let Ok(mut tokens) = self.tokens.lock() {
            tokens.insert("SNRG".to_string(), snrg_token.clone());
        }

        if let Ok(mut supply) = self.total_supply.lock() {
            supply.insert("SNRG".to_string(), 0); // Start with 0 supply
        }

        // Distribute initial supply to genesis accounts
        self.distribute_genesis_supply();
        self.apply_testnet_profile_allocations();

        // Testnet SNRG supply is fixed after genesis bootstrap.
        if let Ok(mut tokens) = self.tokens.lock() {
            if let Some(token) = tokens.get_mut("SNRG") {
                token.mintable = false;
            }
        }
    }

    fn distribute_genesis_supply(&self) {
        if let Ok(genesis) = canonical_genesis() {
            for balance in genesis.balances() {
                if let Ok(_) = self.mint_tokens(&balance.address, "SNRG", balance.balance_nwei) {
                    println!(
                        "✅ Genesis allocation: {} SNRG to {}",
                        balance.balance_nwei, balance.address
                    );
                }
            }
            return;
        }

        println!(
            "⚠️ Could not load canonical genesis for token allocations, using default allocations"
        );
        // Fallback to hardcoded allocations if genesis.json is not available.
        // These MUST match the genesis.json allocations exactly.
        let genesis_allocations = [
            (
                "synu1nd0fvzfhhj4s0te3ks06csfsnpg2hed8vsmh",
                400_000_000_000_000u64,
            ),
            (
                "synw1pckkuqdeep4qz47ww9hnnm6uru2f9r6qtumv",
                150_000_000_000_000u64,
            ),
            (
                "synw1vkn2dq8mftcn7nkdhyv5t0jrv83thf0cakkj",
                200_000_000_000_000u64,
            ),
            (
                "synw1prdr55ggjhupx0d7jycftrl2hzs3k8zuw5ad",
                100_000_000_000_000u64,
            ),
            (
                "synw1f2kpjt9flxl6y4e3uez0zp3hjanamrlew5ja",
                100_000_000_000_000u64,
            ),
            (
                "synv11cv5akg5xa86y8tc5jg84t7a5xhxenaypq36",
                50_000_000_000_000u64,
            ),
            (
                "synv11vwg95ecaryv33lrq6xptrg7vd5yrafturn4",
                50_000_000_000_000u64,
            ),
            (
                "synv113jp4578crnfnwg4d9r342euxfqf8a08s22g",
                50_000_000_000_000u64,
            ),
            (
                "synv11jlm4p4utpvj5ny0g8lnpa0ry65pkfecagnz",
                50_000_000_000_000u64,
            ),
        ];

        for (address, amount) in genesis_allocations {
            if let Ok(_) = self.mint_tokens(address, "SNRG", amount) {
                println!(
                    "✅ Fallback genesis allocation: {} SNRG to {}",
                    amount, address
                );
            }
        }
    }

    fn apply_testnet_profile_allocations(&self) {
        for (address, amount) in load_testnet_profile_allocations() {
            if amount == 0 || address.trim().is_empty() {
                continue;
            }

            let current_balance = self.get_balance(&address, "SNRG");
            if current_balance >= amount {
                continue;
            }

            let missing_amount = amount.saturating_sub(current_balance);
            if let Err(error) = self.mint_tokens(&address, "SNRG", missing_amount) {
                warn!(
                    "token",
                    "Failed to apply Testnet profile allocation",
                    "address" => address,
                    "amount" => missing_amount,
                    "error" => error
                );
            }
        }
    }

    pub fn create_token(
        &self,
        symbol: String,
        name: String,
        decimals: u8,
        total_supply: u64,
        max_supply: Option<u64>,
        mintable: bool,
        burnable: bool,
        creator: String,
    ) -> Result<String, String> {
        if max_supply.is_some_and(|max| total_supply > max) {
            return Err("Maximum supply exceeded".to_string());
        }

        {
            let mut tokens = self
                .tokens
                .lock()
                .map_err(|_| "Failed to acquire lock".to_string())?;
            if tokens.contains_key(&symbol) {
                return Err(format!("Token {} already exists", symbol));
            }

            let token = Token::new(
                symbol.clone(),
                name,
                decimals,
                total_supply as u128,
                max_supply.map(u128::from),
                mintable,
                burnable,
                creator.clone(),
            );

            tokens.insert(symbol.clone(), token);
        }

        {
            let mut supply = self
                .total_supply
                .lock()
                .map_err(|_| "Failed to acquire lock".to_string())?;
            supply.insert(symbol.clone(), total_supply as u128);
        }

        if total_supply > 0 {
            let mut balances = self
                .balances
                .lock()
                .map_err(|_| "Failed to acquire lock".to_string())?;
            let address_balances = balances.entry(creator).or_insert_with(HashMap::new);
            let current_balance = address_balances.get(&symbol).copied().unwrap_or(0);
            let next_balance = current_balance
                .checked_add(total_supply)
                .ok_or_else(|| "Creator balance overflow".to_string())?;
            address_balances.insert(symbol.clone(), next_balance);
        }

        Ok(format!("Token {} created successfully", symbol))
    }

    fn update_token_supply_snapshot(&self, token_symbol: &str, total_supply: u128) {
        if let Ok(mut tokens) = self.tokens.lock() {
            if let Some(token) = tokens.get_mut(token_symbol) {
                token.total_supply = total_supply.to_string();
            }
        }
    }

    pub fn mint_tokens(&self, to: &str, token_symbol: &str, amount: u64) -> Result<String, String> {
        if let Ok(mut tokens) = self.tokens.lock() {
            if let Some(token) = tokens.get(token_symbol) {
                if !token.mintable {
                    return Err("Token is not mintable".to_string());
                }

                if let Some(max_supply) = token
                    .max_supply
                    .as_deref()
                    .and_then(|value| value.parse::<u128>().ok())
                {
                    if let Ok(supply) = self.total_supply.lock() {
                        let current_supply = supply.get(token_symbol).unwrap_or(&0);
                        if *current_supply + amount as u128 > max_supply {
                            return Err("Maximum supply exceeded".to_string());
                        }
                    }
                }
            } else {
                return Err("Token not found".to_string());
            }

            // Update total supply and snapshot while holding tokens lock (mut)
            let new_total = if let Ok(mut supply) = self.total_supply.lock() {
                let current = *supply.get(token_symbol).unwrap_or(&0);
                let new_total = current + amount as u128;
                supply.insert(token_symbol.to_string(), new_total);
                new_total
            } else {
                return Err("Failed to acquire lock".to_string());
            };

            // Update token supply snapshot inline (tokens already locked as mut — no re-lock needed)
            if let Some(token) = tokens.get_mut(token_symbol) {
                token.total_supply = new_total.to_string();
            }

            // Update balance
            if let Ok(mut balances) = self.balances.lock() {
                let address_balances = balances.entry(to.to_string()).or_insert_with(HashMap::new);
                let current_balance = address_balances.get(token_symbol).unwrap_or(&0);
                address_balances.insert(token_symbol.to_string(), current_balance + amount);
            }

            Ok(format!("Minted {} {} to {}", amount, token_symbol, to))
        } else {
            Err("Failed to acquire lock".to_string())
        }
    }

    pub fn burn_tokens(
        &self,
        from: &str,
        token_symbol: &str,
        amount: u64,
    ) -> Result<String, String> {
        self.burn_tokens_with_metadata(from, token_symbol, amount, 0, None, 0)
    }

    pub fn burn_tokens_with_metadata(
        &self,
        from: &str,
        token_symbol: &str,
        amount: u64,
        fee_charged_nwei: u64,
        tx_hash: Option<String>,
        block_height: u64,
    ) -> Result<String, String> {
        if crate::address::is_network_burn_address(from) {
            return Err("Network burn address cannot initiate burns".to_string());
        }
        if let Ok(mut tokens) = self.tokens.lock() {
            if let Some(token) = tokens.get(token_symbol) {
                if !token.burnable {
                    return Err("Token is not burnable".to_string());
                }

                // Check balance
                let current_balance = self.get_balance(from, token_symbol);
                if current_balance < amount {
                    return Err("Insufficient balance".to_string());
                }
            } else {
                return Err("Token not found".to_string());
            }

            // Update balance
            if let Ok(mut balances) = self.balances.lock() {
                if let Some(address_balances) = balances.get_mut(from) {
                    let current = address_balances.get(token_symbol).unwrap_or(&0);
                    address_balances.insert(token_symbol.to_string(), current - amount);
                }
            }

            // Update total supply and snapshot inline (tokens already locked as mut — no re-lock needed)
            let new_total = if let Ok(mut supply) = self.total_supply.lock() {
                let current = *supply.get(token_symbol).unwrap_or(&0);
                let new_total = current.saturating_sub(amount as u128);
                supply.insert(token_symbol.to_string(), new_total);
                new_total
            } else {
                return Err("Failed to acquire lock".to_string());
            };

            if let Some(token) = tokens.get_mut(token_symbol) {
                token.total_supply = new_total.to_string();
            }

            self.record_burn(BurnRecord {
                burner: from.to_string(),
                asset_id: token_symbol.to_string(),
                amount,
                burn_address: NETWORK_BURN_ADDRESS.to_string(),
                fee_charged_nwei,
                supply_reduced: true,
                tx_hash: tx_hash.unwrap_or_else(|| {
                    Self::generate_tx_hash(
                        from,
                        NETWORK_BURN_ADDRESS,
                        token_symbol,
                        amount,
                        fee_charged_nwei,
                    )
                }),
                block_height,
                kind: BurnRecordKind::ExplicitBurn,
                timestamp: Token::current_timestamp(),
            })?;

            Ok(format!("Burned {} {} from {}", amount, token_symbol, from))
        } else {
            Err("Failed to acquire lock".to_string())
        }
    }

    pub fn transfer_tokens(
        &self,
        from: &str,
        to: &str,
        token_symbol: &str,
        amount: u64,
        fee: u64,
    ) -> Result<String, String> {
        self.transfer_tokens_internal(from, to, token_symbol, amount, fee, None, 0)
    }

    /// Transfer tokens while recording the originating transaction hash and block height.
    /// This is used by consensus when a transaction is included in a block, so the explorer
    /// can attribute transfers to on-chain transactions.
    pub fn transfer_tokens_with_metadata(
        &self,
        from: &str,
        to: &str,
        token_symbol: &str,
        amount: u64,
        fee: u64,
        tx_hash: String,
        block_height: u64,
    ) -> Result<String, String> {
        self.transfer_tokens_internal(
            from,
            to,
            token_symbol,
            amount,
            fee,
            Some(tx_hash),
            block_height,
        )
    }

    fn transfer_tokens_internal(
        &self,
        from: &str,
        to: &str,
        token_symbol: &str,
        amount: u64,
        fee: u64,
        tx_hash: Option<String>,
        block_height: u64,
    ) -> Result<String, String> {
        let system_addresses = testnet_v3_system_addresses()?;
        if crate::address::is_network_burn_address(from) {
            return Err("Network burn address cannot send funds".to_string());
        }
        if let Some(existing_hash) = tx_hash.as_deref() {
            if self.transfer_hash_exists(existing_hash) {
                return Ok(format!("Transfer {} already processed", existing_hash));
            }
        }

        let current_token_balance = self.get_balance(from, token_symbol);
        let same_asset_fee = token_symbol == SNRG_SYMBOL;
        if same_asset_fee {
            let required = amount
                .checked_add(fee)
                .ok_or_else(|| "Transfer amount plus fee overflow".to_string())?;
            if current_token_balance < required {
                return Err("Insufficient balance for transfer and fee".to_string());
            }
        } else {
            if current_token_balance < amount {
                return Err("Insufficient token balance for transfer".to_string());
            }
            let current_snrg_balance = self.get_balance(from, SNRG_SYMBOL);
            if current_snrg_balance < fee {
                return Err("Insufficient SNRG balance for fee".to_string());
            }
        }

        // Update sender, receiver, and protocol FeeCollector balances atomically under one lock.
        if let Ok(mut balances) = self.balances.lock() {
            if let Some(from_balances) = balances.get_mut(from) {
                let current = from_balances.get(token_symbol).unwrap_or(&0);
                if same_asset_fee {
                    from_balances.insert(token_symbol.to_string(), current - amount - fee);
                } else {
                    from_balances.insert(token_symbol.to_string(), current - amount);
                    let current_snrg = from_balances.get(SNRG_SYMBOL).copied().unwrap_or(0);
                    from_balances.insert(SNRG_SYMBOL.to_string(), current_snrg - fee);
                }
            }

            if let Some(to_balances) = balances.get_mut(to) {
                let current = to_balances.get(token_symbol).unwrap_or(&0);
                to_balances.insert(
                    token_symbol.to_string(),
                    current
                        .checked_add(amount)
                        .ok_or_else(|| "Receiver balance overflow".to_string())?,
                );
            } else {
                let mut new_balances = HashMap::new();
                new_balances.insert(token_symbol.to_string(), amount);
                balances.insert(to.to_string(), new_balances);
            }

            if fee > 0 {
                let fee_collector_balances = balances
                    .entry(system_addresses.fee_collector.clone())
                    .or_insert_with(HashMap::new);
                let current_fee_balance = fee_collector_balances
                    .get(SNRG_SYMBOL)
                    .copied()
                    .unwrap_or(0);
                fee_collector_balances.insert(
                    SNRG_SYMBOL.to_string(),
                    current_fee_balance
                        .checked_add(fee)
                        .ok_or_else(|| "FeeCollector balance overflow".to_string())?,
                );
            }
        }

        let tx_hash =
            tx_hash.unwrap_or_else(|| Self::generate_tx_hash(from, to, token_symbol, amount, fee));

        if crate::address::is_network_burn_address(to) {
            self.record_burn(BurnRecord {
                burner: from.to_string(),
                asset_id: token_symbol.to_string(),
                amount,
                burn_address: NETWORK_BURN_ADDRESS.to_string(),
                fee_charged_nwei: fee,
                supply_reduced: false,
                tx_hash: tx_hash.clone(),
                block_height,
                kind: BurnRecordKind::BurnAddressTransfer,
                timestamp: Token::current_timestamp(),
            })?;
        }

        // Record transfer
        let transfer = TokenTransfer {
            from: from.to_string(),
            to: to.to_string(),
            token_symbol: token_symbol.to_string(),
            amount,
            fee,
            timestamp: Token::current_timestamp(),
            tx_hash,
            block_height,
        };

        if let Ok(mut transfers) = self.transfers.lock() {
            transfers.push(transfer);
        }

        Ok(format!(
            "Transferred {} {} from {} to {}",
            amount, token_symbol, from, to
        ))
    }

    pub fn distribute_epoch_fees_from_collector(
        &self,
        epoch_id: u64,
        total_fees_nwei: u64,
    ) -> Result<crate::rewards::EpochFeeDistribution, String> {
        self.distribute_epoch_fees_from_collector_at_height(epoch_id, total_fees_nwei, 0)
    }

    pub fn distribute_epoch_fees_from_collector_at_height(
        &self,
        epoch_id: u64,
        total_fees_nwei: u64,
        distribution_block_height: u64,
    ) -> Result<crate::rewards::EpochFeeDistribution, String> {
        let system_addresses = testnet_v3_system_addresses()?;
        if let Ok(ledger) = crate::rewards::REWARD_LEDGER.lock() {
            if let Some(existing) = ledger.fee_distributions.get(&epoch_id) {
                return Ok(existing.clone());
            }
        } else {
            return Err("Failed to access reward ledger".to_string());
        }

        let config = crate::rewards::RewardConfig::default();
        config.validate()?;
        let distribution = crate::rewards::split_epoch_fees(
            epoch_id,
            total_fees_nwei as u128,
            distribution_block_height,
        )?;

        let collector_balance = self.get_balance(&system_addresses.fee_collector, SNRG_SYMBOL);
        if collector_balance < total_fees_nwei {
            return Err(format!(
                "FeeCollector balance {} below epoch fees {}",
                collector_balance, total_fees_nwei
            ));
        }

        let validator_share = u64::try_from(distribution.validator_share_nwei)
            .map_err(|_| "validator fee share exceeds u64".to_string())?;
        let treasury_share = u64::try_from(distribution.treasury_share_nwei)
            .map_err(|_| "treasury fee share exceeds u64".to_string())?;
        let burn_share = u64::try_from(distribution.burn_share_nwei)
            .map_err(|_| "burn fee share exceeds u64".to_string())?;

        if validator_share > 0 {
            self.transfer_tokens_with_metadata(
                &system_addresses.fee_collector,
                &system_addresses.validator_rewards_pool,
                SNRG_SYMBOL,
                validator_share,
                0,
                format!("epoch-fees:{epoch_id}:validator-pool"),
                distribution_block_height,
            )?;
        }
        if treasury_share > 0 {
            self.transfer_tokens_with_metadata(
                &system_addresses.fee_collector,
                &system_addresses.dao_treasury,
                SNRG_SYMBOL,
                treasury_share,
                0,
                format!("epoch-fees:{epoch_id}:treasury"),
                distribution_block_height,
            )?;
        }
        if burn_share > 0 {
            self.burn_tokens(&system_addresses.fee_collector, SNRG_SYMBOL, burn_share)?;
        }

        let mut ledger = crate::rewards::REWARD_LEDGER
            .lock()
            .map_err(|_| "Failed to access reward ledger".to_string())?;
        let recorded = ledger
            .distribute_epoch_fees(epoch_id, total_fees_nwei as u128, distribution_block_height)?
            .clone();
        ledger.record_fee_collector_distribution(crate::rewards::FeeCollectorDistribution {
            epoch_id,
            from_address: system_addresses.fee_collector.clone(),
            validator_reward_pool_address: system_addresses.validator_rewards_pool.clone(),
            validator_reward_pool_amount_nwei: distribution.validator_share_nwei,
            treasury_wallet_address: system_addresses.dao_treasury.clone(),
            treasury_amount_nwei: distribution.treasury_share_nwei,
            burn_amount_nwei: distribution.burn_share_nwei,
            dust_nwei: distribution.rounding_dust_nwei,
            distribution_state_id: format!("epoch-fees:{epoch_id}"),
            distributed_block_height: distribution_block_height,
        })?;

        Ok(recorded)
    }

    pub fn escrow_epoch_validator_rewards(
        &self,
        allocation: &crate::rewards::EpochRewardAllocation,
        funded_block_height: u64,
    ) -> Result<String, String> {
        let system_addresses = testnet_v3_system_addresses()?;
        if let Ok(ledger) = crate::rewards::REWARD_LEDGER.lock() {
            if ledger
                .epoch_reward_allocations
                .contains_key(&allocation.epoch_id)
            {
                return Ok(format!(
                    "Validator rewards for epoch {} already escrowed",
                    allocation.epoch_id
                ));
            }
        } else {
            return Err("Failed to access reward ledger".to_string());
        }

        let total_cluster_rewards = Self::reward_amount_to_u64(
            "validator reward pool allocation",
            allocation.total_cluster_rewards_nwei,
        )?;
        let pool_balance = self.get_balance(&system_addresses.validator_rewards_pool, SNRG_SYMBOL);
        if pool_balance < total_cluster_rewards {
            return Err(format!(
                "Validator rewards pool balance {} below cluster allocation {}",
                pool_balance, total_cluster_rewards
            ));
        }

        for cluster in &allocation.cluster_allocations {
            if !cluster.cluster_address.starts_with("syngrp1") {
                return Err("cluster reward escrow address must use syngrp1 prefix".to_string());
            }
            if crate::address::is_network_burn_address(&cluster.cluster_address) {
                return Err("Network burn address cannot receive cluster rewards".to_string());
            }
            for pending in &cluster.validator_pending_rewards {
                if crate::address::is_network_burn_address(&pending.reward_payout_address) {
                    return Err("Network burn address cannot be a validator payout".to_string());
                }
            }
        }

        for cluster in &allocation.cluster_allocations {
            let cluster_reward =
                Self::reward_amount_to_u64("cluster reward", cluster.cluster_reward_nwei)?;
            if cluster_reward == 0 {
                continue;
            }
            self.transfer_tokens_with_metadata(
                &system_addresses.validator_rewards_pool,
                &cluster.cluster_address,
                SNRG_SYMBOL,
                cluster_reward,
                0,
                format!(
                    "epoch-reward-escrow:{}:{}",
                    allocation.epoch_id, cluster.cluster_address
                ),
                funded_block_height,
            )?;
        }

        let mut ledger = crate::rewards::REWARD_LEDGER
            .lock()
            .map_err(|_| "Failed to access reward ledger".to_string())?;
        ledger.record_epoch_reward_allocation(
            allocation.clone(),
            &system_addresses.validator_rewards_pool,
            funded_block_height,
        )?;

        Ok(format!(
            "Escrowed {} SNRG nWei of validator rewards for epoch {}",
            allocation.total_cluster_rewards_nwei, allocation.epoch_id
        ))
    }

    pub fn settle_epoch_validator_rewards_from_escrows(
        &self,
        unlock_epoch: u64,
        release_coefficients: &HashMap<String, u64>,
        settled_block_height: u64,
    ) -> Result<Vec<crate::rewards::ValidatorRewardSettlement>, String> {
        let system_addresses = testnet_v3_system_addresses()?;
        let pending_rewards = {
            let ledger = crate::rewards::REWARD_LEDGER
                .lock()
                .map_err(|_| "Failed to access reward ledger".to_string())?;
            ledger
                .pending_rewards
                .iter()
                .filter(|reward| {
                    reward.unlock_epoch == unlock_epoch
                        && reward.status == crate::rewards::PendingRewardStatus::Pending
                })
                .cloned()
                .collect::<Vec<_>>()
        };

        if pending_rewards.is_empty() {
            return Ok(Vec::new());
        }

        let mut projected_settlements = Vec::with_capacity(pending_rewards.len());
        let mut required_by_cluster: HashMap<String, u128> = HashMap::new();
        for pending in pending_rewards {
            if crate::address::is_network_burn_address(&pending.reward_payout_address) {
                return Err("Network burn address cannot be a validator payout".to_string());
            }
            let coefficient = release_coefficients
                .get(&pending.validator_id)
                .copied()
                .unwrap_or(0);
            let mut pending_clone = pending.clone();
            let settlement = crate::rewards::settle_pending_reward(
                &mut pending_clone,
                coefficient,
                settled_block_height,
            )?;
            let cluster_total = required_by_cluster
                .entry(settlement.original_cluster_address.clone())
                .or_insert(0);
            *cluster_total = cluster_total
                .checked_add(settlement.pending_reward_nwei)
                .ok_or_else(|| "cluster settlement requirement overflow".to_string())?;
            projected_settlements.push(settlement);
        }

        for (cluster_address, required) in &required_by_cluster {
            let required_u64 = Self::reward_amount_to_u64("cluster escrow settlement", *required)?;
            let balance = self.get_balance(cluster_address, SNRG_SYMBOL);
            if balance < required_u64 {
                return Err(format!(
                    "Cluster escrow balance {} below settlement requirement {} for {}",
                    balance, required_u64, cluster_address
                ));
            }
        }

        for settlement in &projected_settlements {
            let released = Self::reward_amount_to_u64(
                "released validator reward",
                settlement.final_reward_nwei,
            )?;
            if released > 0 {
                self.transfer_tokens_with_metadata(
                    &settlement.original_cluster_address,
                    &settlement.reward_payout_address,
                    SNRG_SYMBOL,
                    released,
                    0,
                    format!(
                        "validator-reward-release:{}:{}",
                        settlement.original_epoch_id, settlement.validator_id
                    ),
                    settled_block_height,
                )?;
            }
            let unreleased = Self::reward_amount_to_u64(
                "unreleased validator reward",
                settlement.unreleased_reward_nwei,
            )?;
            if unreleased > 0 {
                self.transfer_tokens_with_metadata(
                    &settlement.original_cluster_address,
                    &system_addresses.treasury_recovery,
                    SNRG_SYMBOL,
                    unreleased,
                    0,
                    format!(
                        "validator-reward-recovery:{}:{}",
                        settlement.original_epoch_id, settlement.validator_id
                    ),
                    settled_block_height,
                )?;
            }
        }

        let mut ledger = crate::rewards::REWARD_LEDGER
            .lock()
            .map_err(|_| "Failed to access reward ledger".to_string())?;
        ledger.settle_pending_rewards(unlock_epoch, release_coefficients, settled_block_height)
    }

    pub fn run_epoch_reward_lifecycle(
        &self,
        closing_epoch: u64,
        next_epoch: u64,
        transition_block_height: u64,
        closing_epoch_validators: &[crate::validator::Validator],
    ) -> Result<EpochRewardLifecycleSummary, String> {
        let total_fees_collected_nwei = Self::epoch_fee_total_from_ledger(closing_epoch)?;
        let total_fees_u64 =
            Self::reward_amount_to_u64("epoch fee total", total_fees_collected_nwei)?;
        let mut summary = EpochRewardLifecycleSummary {
            closing_epoch,
            next_epoch,
            settled_unlock_epoch: closing_epoch,
            transition_block_height,
            total_fees_collected_nwei,
            fee_distribution: None,
            reward_allocation: None,
            settlements: Vec::new(),
            skipped_reasons: Vec::new(),
        };

        let fee_distribution = self.distribute_epoch_fees_from_collector_at_height(
            closing_epoch,
            total_fees_u64,
            transition_block_height,
        )?;
        let validator_share_nwei = fee_distribution.validator_share_nwei;
        summary.fee_distribution = Some(fee_distribution);

        if validator_share_nwei == 0 {
            summary
                .skipped_reasons
                .push("epoch validator fee share is zero".to_string());
        } else if let Some(existing_allocation) =
            Self::existing_epoch_reward_allocation(closing_epoch)?
        {
            summary.reward_allocation = Some(existing_allocation);
        } else {
            let validator_inputs =
                Self::validator_phase1_inputs_for_epoch(closing_epoch_validators);
            if validator_inputs.is_empty() {
                summary.skipped_reasons.push(
                    "no active eligible validators available for epoch reward allocation"
                        .to_string(),
                );
            } else {
                let allocation = crate::rewards::allocate_epoch_validator_rewards(
                    closing_epoch,
                    validator_share_nwei,
                    &validator_inputs,
                    transition_block_height,
                    &crate::rewards::RewardConfig::default(),
                )?;
                self.escrow_epoch_validator_rewards(&allocation, transition_block_height)?;
                summary.reward_allocation = Some(allocation);
            }
        }

        let release_coefficients = Self::validator_release_coefficients(closing_epoch_validators)?;
        let settlements = self.settle_epoch_validator_rewards_from_escrows(
            closing_epoch,
            &release_coefficients,
            transition_block_height,
        )?;
        if settlements.is_empty() {
            summary.skipped_reasons.push(format!(
                "no pending validator rewards unlocked for epoch {closing_epoch}"
            ));
        }
        summary.settlements = settlements;

        Ok(summary)
    }

    fn reward_amount_to_u64(label: &str, amount_nwei: u128) -> Result<u64, String> {
        u64::try_from(amount_nwei).map_err(|_| format!("{label} exceeds u64 token balance range"))
    }

    fn epoch_fee_total_from_ledger(epoch_id: u64) -> Result<u128, String> {
        let ledger = crate::rewards::REWARD_LEDGER
            .lock()
            .map_err(|_| "Failed to access reward ledger".to_string())?;
        if let Some(distribution) = ledger.fee_distributions.get(&epoch_id) {
            return Ok(distribution.total_fees_nwei);
        }
        Ok(ledger
            .fee_accumulators
            .get(&epoch_id)
            .map(|accumulator| accumulator.total_collected_nwei)
            .unwrap_or(0))
    }

    fn existing_epoch_reward_allocation(
        epoch_id: u64,
    ) -> Result<Option<crate::rewards::EpochRewardAllocation>, String> {
        let ledger = crate::rewards::REWARD_LEDGER
            .lock()
            .map_err(|_| "Failed to access reward ledger".to_string())?;
        Ok(ledger.epoch_reward_allocations.get(&epoch_id).cloned())
    }

    fn validator_phase1_inputs_for_epoch(
        validators: &[crate::validator::Validator],
    ) -> Vec<crate::rewards::ValidatorPhase1Input> {
        validators
            .iter()
            .filter(|validator| !crate::address::is_network_burn_address(&validator.address))
            .map(|validator| crate::rewards::ValidatorPhase1Input {
                cluster_address: Self::validator_reward_escrow_address(validator),
                validator_id: validator.address.clone(),
                reward_payout_address: validator.address.clone(),
                metrics: Self::validator_phase1_metrics(validator),
            })
            .collect()
    }

    fn validator_phase1_metrics(
        validator: &crate::validator::Validator,
    ) -> crate::rewards::Phase1Metrics {
        let duty_success_bps = Self::validator_duty_success_bps(validator);
        crate::rewards::Phase1Metrics {
            consensus_participation_score_bps: duty_success_bps,
            block_proposal_score_bps: Self::validator_proposal_success_bps(validator),
            validation_accuracy_score_bps: Self::validator_accuracy_bps(validator),
            cluster_contribution_score_bps: Self::validator_cluster_stability_bps(validator),
            synergy_score_modifier_bps: duty_success_bps,
        }
    }

    fn validator_release_coefficients(
        validators: &[crate::validator::Validator],
    ) -> Result<HashMap<String, u64>, String> {
        validators
            .iter()
            .map(|validator| {
                let performance = Self::validator_release_performance(validator);
                let coefficient = crate::rewards::calculate_release_coefficient(
                    &performance,
                    &crate::rewards::RewardConfig::default(),
                )?;
                Ok((validator.address.clone(), coefficient))
            })
            .collect()
    }

    fn validator_release_performance(
        validator: &crate::validator::Validator,
    ) -> crate::rewards::ReleasePerformance {
        crate::rewards::ReleasePerformance {
            uptime_score_bps: Self::validator_duty_success_bps(validator),
            responsiveness_score_bps: Self::score_after_unit_penalty(
                validator.consecutive_missed_votes,
                1_000,
            ),
            no_jail_slash_score_bps: Self::validator_no_jail_slash_bps(validator),
            cluster_stability_score_bps: Self::validator_cluster_stability_bps(validator),
            governance_participation_score_bps: crate::rewards::BPS_DENOMINATOR,
            penalty_reason: Self::validator_penalty_reason(validator),
        }
    }

    fn validator_duty_success_bps(validator: &crate::validator::Validator) -> u64 {
        let successful_duties = validator
            .total_transactions_validated
            .saturating_add(validator.total_blocks_produced);
        let missed_duties = validator.missed_blocks;
        Self::ratio_to_bps(
            successful_duties,
            successful_duties.saturating_add(missed_duties),
        )
    }

    fn validator_proposal_success_bps(validator: &crate::validator::Validator) -> u64 {
        let assigned_or_observed = validator
            .total_blocks_produced
            .saturating_add(validator.missed_blocks);
        if assigned_or_observed == 0 {
            return Self::validator_duty_success_bps(validator);
        }
        Self::ratio_to_bps(validator.total_blocks_produced, assigned_or_observed)
    }

    fn validator_accuracy_bps(validator: &crate::validator::Validator) -> u64 {
        if validator.double_signs > 0 || validator.equivocation_evidence_count > 0 {
            return 0;
        }
        Self::score_after_unit_penalty(validator.missed_vote_window, 500)
    }

    fn validator_cluster_stability_bps(validator: &crate::validator::Validator) -> u64 {
        if validator.double_signs > 0 || validator.equivocation_evidence_count > 0 {
            return 0;
        }
        Self::score_after_unit_penalty(validator.missed_vote_window, 1_000)
    }

    fn validator_no_jail_slash_bps(validator: &crate::validator::Validator) -> u64 {
        match &validator.status {
            crate::validator::ValidatorStatus::Active => crate::rewards::BPS_DENOMINATOR,
            crate::validator::ValidatorStatus::Jailed => 5_000,
            crate::validator::ValidatorStatus::Slashed => 0,
            _ => 0,
        }
    }

    fn validator_penalty_reason(
        validator: &crate::validator::Validator,
    ) -> crate::rewards::ValidatorPenaltyReason {
        if validator.double_signs > 0 {
            crate::rewards::ValidatorPenaltyReason::DoubleSigning
        } else if validator.equivocation_evidence_count > 0 {
            crate::rewards::ValidatorPenaltyReason::Equivocation
        } else {
            match &validator.status {
                crate::validator::ValidatorStatus::Slashed => {
                    crate::rewards::ValidatorPenaltyReason::Slashed
                }
                crate::validator::ValidatorStatus::Jailed => {
                    crate::rewards::ValidatorPenaltyReason::Jailed
                }
                _ if validator.missed_vote_window
                    >= crate::validator::MISSED_VOTE_SLASH_THRESHOLD =>
                {
                    crate::rewards::ValidatorPenaltyReason::MajorDowntime
                }
                _ if validator.missed_vote_window
                    >= crate::validator::MISSED_VOTE_JAIL_THRESHOLD =>
                {
                    crate::rewards::ValidatorPenaltyReason::MinorDowntime
                }
                _ => crate::rewards::ValidatorPenaltyReason::None,
            }
        }
    }

    fn validator_reward_escrow_address(validator: &crate::validator::Validator) -> String {
        if let Some(address) = validator.cluster_address.as_deref() {
            if address.starts_with("syngrp1") {
                return address.to_string();
            }
            return crate::address::generate_validator_cluster_address(&format!(
                "reward-escrow:{address}"
            ));
        }

        if let Some(cluster_id) = validator.cluster_id {
            return crate::address::generate_validator_cluster_address(&format!(
                "reward-escrow:cluster:{cluster_id}"
            ));
        }

        crate::address::generate_validator_cluster_address(&format!(
            "reward-escrow:validator:{}",
            validator.address
        ))
    }

    fn score_after_unit_penalty(units: u64, penalty_per_unit_bps: u64) -> u64 {
        let penalty = units
            .saturating_mul(penalty_per_unit_bps)
            .min(crate::rewards::BPS_DENOMINATOR);
        crate::rewards::BPS_DENOMINATOR.saturating_sub(penalty)
    }

    fn ratio_to_bps(numerator: u64, denominator: u64) -> u64 {
        if denominator == 0 {
            return crate::rewards::BPS_DENOMINATOR;
        }
        let bps = (numerator as u128).saturating_mul(crate::rewards::BPS_DENOMINATOR as u128)
            / (denominator as u128);
        u64::try_from(bps)
            .unwrap_or(crate::rewards::BPS_DENOMINATOR)
            .min(crate::rewards::BPS_DENOMINATOR)
    }

    fn record_included_transaction_fee(
        &self,
        tx: &Transaction,
        fee_nwei: u64,
        block_height: u64,
    ) -> Result<(), String> {
        if fee_nwei == 0 {
            return Ok(());
        }
        let breakdown = tx.get_network_fee_breakdown()?;
        let epoch_id = crate::rewards::default_reward_epoch_for_block_height(block_height);
        if let Ok(mut ledger) = crate::rewards::REWARD_LEDGER.lock() {
            ledger.record_fee_charged(
                epoch_id,
                tx.hash(),
                breakdown.tx_type_name,
                fee_nwei as u128,
                block_height,
            )?;
        }
        Ok(())
    }

    fn transfer_hash_exists(&self, tx_hash: &str) -> bool {
        self.transfers
            .lock()
            .map(|transfers| transfers.iter().any(|transfer| transfer.tx_hash == tx_hash))
            .unwrap_or(false)
    }

    fn record_burn(&self, record: BurnRecord) -> Result<(), String> {
        if record.amount == 0 {
            return Err("Burn amount must be greater than zero".to_string());
        }
        if self
            .burn_records
            .lock()
            .map(|records| {
                records
                    .iter()
                    .any(|existing| existing.tx_hash == record.tx_hash)
            })
            .unwrap_or(false)
        {
            return Ok(());
        }
        if let Ok(mut ledger) = self.burn_ledger.lock() {
            let total = ledger.entry(record.asset_id.clone()).or_insert(0);
            *total = total
                .checked_add(record.amount as u128)
                .ok_or_else(|| "burn ledger overflow".to_string())?;
        } else {
            return Err("Failed to lock burn ledger".to_string());
        }
        if let Ok(mut records) = self.burn_records.lock() {
            records.push(record);
            Ok(())
        } else {
            Err("Failed to lock burn records".to_string())
        }
    }

    pub fn get_burned_total(&self, token_symbol: &str) -> u128 {
        self.burn_ledger
            .lock()
            .ok()
            .and_then(|ledger| ledger.get(token_symbol).copied())
            .unwrap_or(0)
    }

    pub fn get_burn_records(&self, token_symbol: Option<&str>) -> Vec<BurnRecord> {
        self.burn_records
            .lock()
            .map(|records| {
                records
                    .iter()
                    .filter(|record| {
                        token_symbol
                            .map(|symbol| record.asset_id == symbol)
                            .unwrap_or(true)
                    })
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn get_balance(&self, address: &str, token_symbol: &str) -> u64 {
        if let Ok(balances) = self.balances.lock() {
            if let Some(address_balances) = balances.get(address) {
                return address_balances.get(token_symbol).unwrap_or(&0).clone();
            }
        }
        0
    }

    pub fn get_all_balances(&self, address: &str) -> HashMap<String, u64> {
        if let Ok(balances) = self.balances.lock() {
            balances.get(address).cloned().unwrap_or_default()
        } else {
            HashMap::new()
        }
    }

    fn charge_snrg_fee(&self, payer: &str, fee_nwei: u64) -> Result<(), String> {
        if fee_nwei == 0 {
            return Ok(());
        }
        if crate::address::is_network_burn_address(payer) {
            return Err("Network burn address cannot pay transaction fees".to_string());
        }
        let collector_address = fee_collector_address()?;
        if let Ok(mut balances) = self.balances.lock() {
            let payer_balances = balances
                .get_mut(payer)
                .ok_or_else(|| "Fee payer balance not found".to_string())?;
            let current = payer_balances.get(SNRG_SYMBOL).copied().unwrap_or(0);
            if current < fee_nwei {
                return Err("Insufficient SNRG balance for fee".to_string());
            }
            payer_balances.insert(SNRG_SYMBOL.to_string(), current - fee_nwei);

            let collector_balances = balances
                .entry(collector_address)
                .or_insert_with(HashMap::new);
            let collector = collector_balances.get(SNRG_SYMBOL).copied().unwrap_or(0);
            collector_balances.insert(
                SNRG_SYMBOL.to_string(),
                collector
                    .checked_add(fee_nwei)
                    .ok_or_else(|| "FeeCollector balance overflow".to_string())?,
            );
            Ok(())
        } else {
            Err("Failed to acquire lock".to_string())
        }
    }

    pub fn stake_tokens(
        &self,
        staker: &str,
        validator: &str,
        token_symbol: &str,
        amount: u64,
    ) -> Result<String, String> {
        if crate::address::is_network_burn_address(staker)
            || crate::address::is_network_burn_address(validator)
        {
            return Err("Network burn address cannot stake or validate".to_string());
        }
        if !crate::address::is_valid_address(staker) {
            return Err("Invalid staker Synergy address".to_string());
        }
        if !crate::address::is_valid_address(validator) {
            return Err("Invalid validator Synergy address".to_string());
        }

        let current_balance = self.get_balance(staker, token_symbol);
        if current_balance < amount {
            return Err("Insufficient balance for staking".to_string());
        }

        // Move tokens from balance to staked balance
        if let Ok(mut balances) = self.balances.lock() {
            if let Some(staker_balances) = balances.get_mut(staker) {
                let current = staker_balances.get(token_symbol).unwrap_or(&0);
                staker_balances.insert(token_symbol.to_string(), current - amount);
            }
        }

        if let Ok(mut staked) = self.staked_balances.lock() {
            let staker_staked = staked
                .entry(staker.to_string())
                .or_insert_with(HashMap::new);
            let current = staker_staked.get(token_symbol).unwrap_or(&0);
            staker_staked.insert(token_symbol.to_string(), current + amount);
        }

        // Create staking info
        let stake_info = StakingInfo {
            validator_address: validator.to_string(),
            staker_address: staker.to_string(),
            amount,
            stake_start: Token::current_timestamp(),
            stake_end: None,
            rewards_earned: 0,
            is_active: true,
        };

        if let Ok(mut stakes) = self.stakes.lock() {
            let validator_stakes = stakes.entry(validator.to_string()).or_insert_with(Vec::new);
            validator_stakes.push(stake_info);
        }

        Ok(format!(
            "Staked {} {} to validator {}",
            amount, token_symbol, validator
        ))
    }

    pub fn unstake_tokens(
        &self,
        staker: &str,
        validator: &str,
        token_symbol: &str,
        amount: u64,
    ) -> Result<String, String> {
        // Check if staker has enough staked tokens
        let staked_balance = self.get_staked_balance(staker, token_symbol);
        if staked_balance < amount {
            return Err("Insufficient staked balance".to_string());
        }

        // Find and update the stake
        if let Ok(mut stakes) = self.stakes.lock() {
            if let Some(validator_stakes) = stakes.get_mut(validator) {
                for stake in validator_stakes.iter_mut() {
                    if stake.staker_address == staker && stake.is_active {
                        if stake.amount >= amount {
                            stake.amount -= amount;
                            if stake.amount == 0 {
                                stake.is_active = false;
                            }
                            break;
                        }
                    }
                }
            }
        }

        // Move tokens from staked back to balance
        if let Ok(mut balances) = self.balances.lock() {
            if let Some(staker_balances) = balances.get_mut(staker) {
                let current = staker_balances.get(token_symbol).unwrap_or(&0);
                staker_balances.insert(token_symbol.to_string(), current + amount);
            }
        }

        if let Ok(mut staked) = self.staked_balances.lock() {
            if let Some(staker_staked) = staked.get_mut(staker) {
                let current = staker_staked.get(token_symbol).unwrap_or(&0);
                staker_staked.insert(token_symbol.to_string(), current - amount);
            }
        }

        Ok(format!(
            "Unstaked {} {} from validator {}",
            amount, token_symbol, validator
        ))
    }

    pub fn get_staked_balance(&self, address: &str, token_symbol: &str) -> u64 {
        if address == "*" {
            let direct_total = self
                .staked_balances
                .lock()
                .ok()
                .map(|staked| {
                    staked
                        .values()
                        .filter_map(|balances| balances.get(token_symbol))
                        .copied()
                        .sum::<u64>()
                })
                .unwrap_or(0);
            if direct_total > 0 {
                return direct_total;
            }

            return self
                .stakes
                .lock()
                .ok()
                .map(|stakes| {
                    stakes
                        .values()
                        .flatten()
                        .filter(|stake| stake.is_active)
                        .map(|stake| stake.amount)
                        .sum::<u64>()
                })
                .unwrap_or(0);
        }

        if let Ok(staked) = self.staked_balances.lock() {
            if let Some(address_staked) = staked.get(address) {
                let direct = address_staked.get(token_symbol).copied().unwrap_or(0);
                if direct > 0 {
                    return direct;
                }
            }
        }

        self.stakes
            .lock()
            .ok()
            .map(|stakes| {
                stakes
                    .values()
                    .flatten()
                    .filter(|stake| stake.is_active && stake.staker_address == address)
                    .map(|stake| stake.amount)
                    .sum::<u64>()
            })
            .unwrap_or(0)
    }

    /// Distribute rewards to a cluster, then to validators in that cluster based on normalized
    /// integer basis-point Synergy scores.
    /// This implements the PoSy protocol where rewards are awarded to clusters first, then distributed
    /// among validators in the cluster based on their normalized Synergy Scores
    pub fn distribute_cluster_rewards(
        &self,
        cluster_validators: &[(String, u64)], // (validator_address, normalized_synergy_score_bps)
        reward_amount: u64,
    ) -> Result<String, String> {
        const SCORE_BPS_DENOMINATOR: u64 = 10_000;

        let pool_address = Self::get_rewards_pool_address()?;
        // Check rewards pool balance
        let pool_balance = self.get_balance(&pool_address, SNRG_SYMBOL);
        if pool_balance < reward_amount {
            return Err(format!(
                "Insufficient rewards pool balance: {} < {}",
                pool_balance, reward_amount
            ));
        }

        if cluster_validators.is_empty() {
            return Err("No validators in cluster".to_string());
        }

        let total_score: u64 = cluster_validators.iter().map(|(_, score)| *score).sum();
        if total_score != SCORE_BPS_DENOMINATOR {
            return Err(format!(
                "Invalid normalized score bps: sum = {} (expected 10000)",
                total_score
            ));
        }

        // Deduct total reward from rewards pool
        if let Ok(mut balances) = self.balances.lock() {
            if let Some(pool_balances) = balances.get_mut(&pool_address) {
                let current = pool_balances.get(SNRG_SYMBOL).unwrap_or(&0);
                if *current < reward_amount {
                    return Err(format!(
                        "Rewards pool balance check failed: {} < {}",
                        current, reward_amount
                    ));
                }
                pool_balances.insert(SNRG_SYMBOL.to_string(), current - reward_amount);
            } else {
                return Err("Rewards pool not found".to_string());
            }
        }

        // Distribute rewards to each validator based on their normalized synergy score
        let mut distributed_count = 0;
        let mut distributed_total = 0u64;
        for (index, (validator_address, normalized_score_bps)) in
            cluster_validators.iter().enumerate()
        {
            if crate::address::is_network_burn_address(validator_address) {
                return Err("Network burn address cannot receive validator rewards".to_string());
            }
            let validator_reward = if index + 1 == cluster_validators.len() {
                reward_amount.saturating_sub(distributed_total)
            } else {
                let share = ((reward_amount as u128) * (*normalized_score_bps as u128))
                    / (SCORE_BPS_DENOMINATOR as u128);
                u64::try_from(share).map_err(|_| "validator reward exceeds u64".to_string())?
            };
            distributed_total = distributed_total
                .checked_add(validator_reward)
                .ok_or_else(|| "cluster reward distribution overflow".to_string())?;

            if validator_reward == 0 {
                continue; // Skip validators with zero reward
            }

            // Add reward to validator's balance
            if let Ok(mut balances) = self.balances.lock() {
                let validator_balances = balances
                    .entry(validator_address.clone())
                    .or_insert_with(HashMap::new);
                let current = validator_balances.get(SNRG_SYMBOL).unwrap_or(&0);
                validator_balances.insert(
                    SNRG_SYMBOL.to_string(),
                    current
                        .checked_add(validator_reward)
                        .ok_or_else(|| "validator reward balance overflow".to_string())?,
                );
            }

            // Now distribute validator's reward to their stakers
            if let Err(e) =
                self.distribute_validator_rewards_to_stakers(validator_address, validator_reward)
            {
                warn!("token", "Failed to distribute validator reward to stakers", 
                      "validator" => validator_address.clone(), 
                      "error" => e);
                // Continue with other validators even if one fails
            } else {
                distributed_count += 1;
            }
        }

        Ok(format!(
            "Distributed {} rewards to cluster ({} validators)",
            reward_amount, distributed_count
        ))
    }

    /// Distribute a validator's reward to their stakers (proportional to stake)
    fn distribute_validator_rewards_to_stakers(
        &self,
        validator: &str,
        reward_amount: u64,
    ) -> Result<String, String> {
        // Collect stake data we need (read-only)
        let stake_data: Vec<(String, u64)> = {
            if let Ok(stakes) = self.stakes.lock() {
                if let Some(validator_stakes) = stakes.get(validator) {
                    let active_stakes: Vec<_> = validator_stakes
                        .iter()
                        .filter(|stake| stake.is_active)
                        .collect();

                    if active_stakes.is_empty() {
                        return Ok("No active stakes".to_string());
                    }

                    let total_staked: u64 = active_stakes.iter().map(|stake| stake.amount).sum();
                    if total_staked == 0 {
                        return Ok("No staked tokens".to_string());
                    }

                    // Collect (staker_address, reward_portion) pairs
                    active_stakes
                        .iter()
                        .map(|stake| {
                            let reward_portion = (stake.amount * reward_amount) / total_staked;
                            (stake.staker_address.clone(), reward_portion)
                        })
                        .collect()
                } else {
                    return Err("Validator not found or no active stakes".to_string());
                }
            } else {
                return Err("Failed to lock stakes".to_string());
            }
        }; // stakes lock is dropped here

        let staker_count = stake_data.len();

        // Now update balances and stakes separately, without holding multiple locks
        for (staker_address, reward_portion) in stake_data {
            // Add rewards to staker's balance
            if let Ok(mut balances) = self.balances.lock() {
                if let Some(staker_balances) = balances.get_mut(&staker_address) {
                    let current = staker_balances.get("SNRG").unwrap_or(&0);
                    staker_balances.insert("SNRG".to_string(), current + reward_portion);
                } else {
                    // Create balance entry if it doesn't exist
                    let mut new_balances = HashMap::new();
                    new_balances.insert("SNRG".to_string(), reward_portion);
                    balances.insert(staker_address.clone(), new_balances);
                }
            } // balances lock dropped

            // Update stake rewards
            if let Ok(mut stakes) = self.stakes.lock() {
                if let Some(validator_stakes) = stakes.get_mut(validator) {
                    for s in validator_stakes.iter_mut() {
                        if s.staker_address == staker_address && s.is_active {
                            s.rewards_earned += reward_portion;
                            break;
                        }
                    }
                }
            } // stakes lock dropped
        }

        Ok(format!(
            "Distributed {} rewards to {} stakers",
            reward_amount, staker_count
        ))
    }

    /// Legacy function - distributes rewards to a single validator's stakers
    /// This is kept for backward compatibility but should use distribute_cluster_rewards instead
    pub fn distribute_validator_rewards(
        &self,
        validator: &str,
        reward_amount: u64,
    ) -> Result<String, String> {
        if crate::address::is_network_burn_address(validator) {
            return Err("Network burn address cannot receive validator rewards".to_string());
        }
        let pool_address = Self::get_rewards_pool_address()?;
        // First, check the genesis-bound rewards pool has sufficient balance.
        let pool_balance = self.get_balance(&pool_address, "SNRG");
        if pool_balance < reward_amount {
            return Err(format!(
                "Insufficient rewards pool balance: {} < {}",
                pool_balance, reward_amount
            ));
        }

        // Collect stake data we need (read-only)
        let stake_data: Vec<(String, u64)> = {
            if let Ok(stakes) = self.stakes.lock() {
                if let Some(validator_stakes) = stakes.get(validator) {
                    let active_stakes: Vec<_> = validator_stakes
                        .iter()
                        .filter(|stake| stake.is_active)
                        .collect();

                    if active_stakes.is_empty() {
                        return Ok("No active stakes".to_string());
                    }

                    let total_staked: u64 = active_stakes.iter().map(|stake| stake.amount).sum();
                    if total_staked == 0 {
                        return Ok("No staked tokens".to_string());
                    }

                    // Collect (staker_address, reward_portion) pairs
                    active_stakes
                        .iter()
                        .map(|stake| {
                            let reward_portion = (stake.amount * reward_amount) / total_staked;
                            (stake.staker_address.clone(), reward_portion)
                        })
                        .collect()
                } else {
                    return Err("Validator not found or no active stakes".to_string());
                }
            } else {
                return Err("Failed to lock stakes".to_string());
            }
        }; // stakes lock is dropped here

        let staker_count = stake_data.len();

        // Deduct total reward amount from rewards pool
        if let Ok(mut balances) = self.balances.lock() {
            if let Some(pool_balances) = balances.get_mut(&pool_address) {
                let current = pool_balances.get("SNRG").unwrap_or(&0);
                if *current < reward_amount {
                    return Err(format!(
                        "Rewards pool balance check failed during deduction: {} < {}",
                        current, reward_amount
                    ));
                }
                pool_balances.insert("SNRG".to_string(), current - reward_amount);
            } else {
                return Err("Rewards pool not found".to_string());
            }
        } // balances lock dropped

        // Now update balances and stakes separately, without holding multiple locks
        for (staker_address, reward_portion) in stake_data {
            // Add rewards to staker's balance (transferred from rewards pool)
            if let Ok(mut balances) = self.balances.lock() {
                if let Some(staker_balances) = balances.get_mut(&staker_address) {
                    let current = staker_balances.get("SNRG").unwrap_or(&0);
                    staker_balances.insert("SNRG".to_string(), current + reward_portion);
                }
            } // balances lock dropped

            // Update stake rewards
            if let Ok(mut stakes) = self.stakes.lock() {
                if let Some(validator_stakes) = stakes.get_mut(validator) {
                    for s in validator_stakes.iter_mut() {
                        if s.staker_address == staker_address && s.is_active {
                            s.rewards_earned += reward_portion;
                            break;
                        }
                    }
                }
            } // stakes lock dropped
        }

        Ok(format!(
            "Distributed {} rewards from pool to {} stakers",
            reward_amount, staker_count
        ))
    }

    pub fn process_transaction(&self, tx: &Transaction) -> Result<String, String> {
        // Handle token transfers
        if tx
            .data
            .as_ref()
            .map_or(false, |data| data.starts_with("token_transfer:"))
        {
            if let Some(data_str) = &tx.data {
                if let Some(transfer_data) = data_str.strip_prefix("token_transfer:") {
                    if let Ok(transfer_info) =
                        serde_json::from_str::<serde_json::Value>(transfer_data)
                    {
                        if let (Some(to), Some(token_symbol), Some(amount)) = (
                            transfer_info.get("to").and_then(|v| v.as_str()),
                            transfer_info.get("token").and_then(|v| v.as_str()),
                            transfer_info.get("amount").and_then(|v| v.as_u64()),
                        ) {
                            return self.transfer_tokens(
                                &tx.sender,
                                to,
                                token_symbol,
                                amount,
                                tx.get_total_network_fee_u64()?,
                            );
                        }
                    }
                }
            }
        }

        // Handle staking transactions
        if tx
            .data
            .as_ref()
            .map_or(false, |data| data.starts_with("stake:"))
        {
            if let Some(data_str) = &tx.data {
                if let Some(stake_data) = data_str.strip_prefix("stake:") {
                    if let Ok(stake_info) = serde_json::from_str::<serde_json::Value>(stake_data) {
                        if let (Some(validator), Some(token_symbol), Some(amount)) = (
                            stake_info.get("validator").and_then(|v| v.as_str()),
                            stake_info.get("token").and_then(|v| v.as_str()),
                            stake_info.get("amount").and_then(|v| v.as_u64()),
                        ) {
                            self.charge_snrg_fee(&tx.sender, tx.get_total_network_fee_u64()?)?;
                            return self.stake_tokens(&tx.sender, validator, token_symbol, amount);
                        }
                    }
                }
            }
        }

        if tx
            .data
            .as_ref()
            .map_or(false, |data| data.starts_with("burn:"))
        {
            if let Some(data_str) = &tx.data {
                if let Some(burn_data) = data_str.strip_prefix("burn:") {
                    if let Ok(burn_info) = serde_json::from_str::<serde_json::Value>(burn_data) {
                        if let (Some(token_symbol), Some(amount)) = (
                            burn_info
                                .get("asset")
                                .or_else(|| burn_info.get("asset_id"))
                                .or_else(|| burn_info.get("token"))
                                .and_then(|v| v.as_str()),
                            burn_info.get("amount").and_then(|v| v.as_u64()),
                        ) {
                            let fee = tx.get_total_network_fee_u64()?;
                            self.charge_snrg_fee(&tx.sender, fee)?;
                            return self.burn_tokens_with_metadata(
                                &tx.sender,
                                token_symbol,
                                amount,
                                fee,
                                Some(tx.hash()),
                                0,
                            );
                        }
                    }
                }
            }
        }

        // Handle native SNRG transfers submitted through the public
        // synergy_sendTransaction path. These transactions carry the SNRG
        // amount in the canonical amount field and may not include the legacy
        // token_transfer data wrapper used by the local faucet helper.
        if tx.amount > 0 && !tx.receiver.trim().is_empty() {
            return self.transfer_tokens(
                &tx.sender,
                &tx.receiver,
                "SNRG",
                tx.amount,
                tx.get_total_network_fee_u64()?,
            );
        }

        if tx
            .data
            .as_deref()
            .map(|data| data.starts_with("validator_activation:"))
            .unwrap_or(false)
        {
            return Ok("Validator activation handled by validator registry".to_string());
        }

        Err("Unsupported transaction type".to_string())
    }

    /// Process a transaction that has been included in a specific block height.
    /// This records transfer metadata (tx hash + block height) for explorer queries.
    pub fn process_transaction_in_block(
        &self,
        tx: &Transaction,
        block_height: u64,
    ) -> Result<String, String> {
        self.process_transaction_in_finalized_block(tx, block_height, "")
    }

    /// Process a transaction included in a finalized block, with block hash
    /// context for protocol state snapshots that need idempotent replay guards.
    pub fn process_transaction_in_finalized_block(
        &self,
        tx: &Transaction,
        block_height: u64,
        block_hash: &str,
    ) -> Result<String, String> {
        self.process_transaction_in_finalized_block_with_fee_market(
            tx,
            block_height,
            block_hash,
            None,
        )
    }

    /// Apply a finalized transaction using the consensus-bound base fee of
    /// its containing block.  `None` is retained only for replay of
    /// pre-activation version-0 blocks.
    pub fn process_transaction_in_finalized_block_with_fee_market(
        &self,
        tx: &Transaction,
        block_height: u64,
        block_hash: &str,
        applied_base_fee_per_gas_nwei: Option<u64>,
    ) -> Result<String, String> {
        let fee = match applied_base_fee_per_gas_nwei {
            Some(base_fee_per_gas_nwei) => tx
                .network_fee_breakdown_with_gas(tx.estimate_gas(), base_fee_per_gas_nwei)?
                .total_network_fee_nwei,
            None => tx.get_total_network_fee_nwei(),
        };
        let fee = u64::try_from(fee)
            .map_err(|_| "finalized transaction fee exceeds u64".to_string())?;
        if let Some(data_str) = tx.data.as_deref() {
            if crate::sts::transaction_data_may_contain_sts_payload(data_str) {
                let tx_hash = tx.hash();
                if crate::sts::finalized_sts_transaction_processed(&tx_hash)? {
                    return Ok("STS transaction already processed".to_string());
                }

                self.charge_snrg_fee(&tx.sender, fee)?;
                let report = crate::sts::process_finalized_sts_transaction_data(
                    &tx.sender,
                    data_str,
                    &tx_hash,
                    block_height,
                    block_hash,
                )?;
                self.record_included_transaction_fee(tx, fee, block_height)?;
                if report.applied {
                    return Ok(format!("Applied STS transaction {tx_hash}"));
                }
                return Ok(format!(
                    "Rejected STS transaction {tx_hash}: {}",
                    report.error.unwrap_or_else(|| report.status.to_string())
                ));
            }
        }

        // Handle token transfers
        if tx
            .data
            .as_ref()
            .map_or(false, |data| data.starts_with("token_transfer:"))
        {
            if let Some(data_str) = &tx.data {
                if let Some(transfer_data) = data_str.strip_prefix("token_transfer:") {
                    if let Ok(transfer_info) =
                        serde_json::from_str::<serde_json::Value>(transfer_data)
                    {
                        if let (Some(to), Some(token_symbol), Some(amount)) = (
                            transfer_info.get("to").and_then(|v| v.as_str()),
                            transfer_info.get("token").and_then(|v| v.as_str()),
                            transfer_info.get("amount").and_then(|v| v.as_u64()),
                        ) {
                            let tx_hash = tx.hash();
                            let already_processed = self.transfer_hash_exists(&tx_hash);
                            let result = self.transfer_tokens_with_metadata(
                                &tx.sender,
                                to,
                                token_symbol,
                                amount,
                                fee,
                                tx_hash,
                                block_height,
                            )?;
                            if !already_processed {
                                self.record_included_transaction_fee(tx, fee, block_height)?;
                            }
                            return Ok(result);
                        }
                    }
                }
            }
        }

        // Handle staking transactions
        if tx
            .data
            .as_ref()
            .map_or(false, |data| data.starts_with("stake:"))
        {
            if let Some(data_str) = &tx.data {
                if let Some(stake_data) = data_str.strip_prefix("stake:") {
                    if let Ok(stake_info) = serde_json::from_str::<serde_json::Value>(stake_data) {
                        if let (Some(validator), Some(token_symbol), Some(amount)) = (
                            stake_info.get("validator").and_then(|v| v.as_str()),
                            stake_info.get("token").and_then(|v| v.as_str()),
                            stake_info.get("amount").and_then(|v| v.as_u64()),
                        ) {
                            self.charge_snrg_fee(&tx.sender, fee)?;
                            let result =
                                self.stake_tokens(&tx.sender, validator, token_symbol, amount)?;
                            self.record_included_transaction_fee(tx, fee, block_height)?;
                            return Ok(result);
                        }
                    }
                }
            }
        }

        if tx
            .data
            .as_ref()
            .map_or(false, |data| data.starts_with("burn:"))
        {
            if let Some(data_str) = &tx.data {
                if let Some(burn_data) = data_str.strip_prefix("burn:") {
                    if let Ok(burn_info) = serde_json::from_str::<serde_json::Value>(burn_data) {
                        if let (Some(token_symbol), Some(amount)) = (
                            burn_info
                                .get("asset")
                                .or_else(|| burn_info.get("asset_id"))
                                .or_else(|| burn_info.get("token"))
                                .and_then(|v| v.as_str()),
                            burn_info.get("amount").and_then(|v| v.as_u64()),
                        ) {
                            self.charge_snrg_fee(&tx.sender, fee)?;
                            let result = self.burn_tokens_with_metadata(
                                &tx.sender,
                                token_symbol,
                                amount,
                                fee,
                                Some(tx.hash()),
                                block_height,
                            )?;
                            self.record_included_transaction_fee(tx, fee, block_height)?;
                            return Ok(result);
                        }
                    }
                }
            }
        }

        if tx.amount > 0 && !tx.receiver.trim().is_empty() {
            let tx_hash = tx.hash();
            let already_processed = self.transfer_hash_exists(&tx_hash);
            let result = self.transfer_tokens_with_metadata(
                &tx.sender,
                &tx.receiver,
                "SNRG",
                tx.amount,
                fee,
                tx_hash,
                block_height,
            )?;
            if !already_processed {
                self.record_included_transaction_fee(tx, fee, block_height)?;
            }
            return Ok(result);
        }

        if tx
            .data
            .as_deref()
            .map(|data| data.starts_with("validator_activation:"))
            .unwrap_or(false)
        {
            return Ok("Validator activation handled by validator registry".to_string());
        }

        Err("Unsupported transaction type".to_string())
    }

    pub fn get_token_info(&self, symbol: &str) -> Option<Token> {
        if let Ok(tokens) = self.tokens.lock() {
            tokens.get(symbol).cloned().map(|mut token| {
                token.normalize_identity();
                token
            })
        } else {
            None
        }
    }

    pub fn get_all_tokens(&self) -> Vec<Token> {
        if let Ok(tokens) = self.tokens.lock() {
            tokens
                .values()
                .cloned()
                .map(|mut token| {
                    token.normalize_identity();
                    token
                })
                .collect()
        } else {
            Vec::new()
        }
    }

    pub fn get_transfer_history(&self, address: &str, limit: usize) -> Vec<TokenTransfer> {
        if let Ok(transfers) = self.transfers.lock() {
            transfers
                .iter()
                .filter(|transfer| transfer.from == address || transfer.to == address)
                .take(limit)
                .cloned()
                .collect()
        } else {
            Vec::new()
        }
    }

    pub fn replay_chain_transactions(&self, chain: &crate::block::BlockChain) -> (u64, u64) {
        let mut applied = 0u64;
        let mut failed = 0u64;

        for block in &chain.chain {
            for tx in &block.transactions {
                let is_token_transfer = tx
                    .data
                    .as_deref()
                    .map(|data| data.starts_with("token_transfer:"))
                    .unwrap_or(false);
                let is_native_transfer = tx.amount > 0
                    && !tx.receiver.trim().is_empty()
                    && !tx
                        .data
                        .as_deref()
                        .map(|data| data.starts_with("stake:"))
                        .unwrap_or(false);
                let is_stake_transaction = tx
                    .data
                    .as_deref()
                    .map(|data| data.starts_with("stake:"))
                    .unwrap_or(false);
                let is_validator_activation = tx
                    .data
                    .as_deref()
                    .map(|data| data.starts_with("validator_activation:"))
                    .unwrap_or(false);
                if !is_token_transfer
                    && !is_native_transfer
                    && !is_stake_transaction
                    && !is_validator_activation
                {
                    continue;
                }

                match self.process_transaction_in_finalized_block_with_fee_market(
                    tx,
                    block.block_index,
                    &block.hash,
                    block.applied_fee_market_base_fee(),
                ) {
                    Ok(_) => applied += 1,
                    Err(_) => failed += 1,
                }
            }
        }

        (applied, failed)
    }

    pub fn get_staking_info(&self, address: &str) -> Vec<StakingInfo> {
        if let Ok(stakes) = self.stakes.lock() {
            stakes
                .values()
                .flatten()
                .filter(|stake| stake.staker_address == address)
                .cloned()
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Ensure the rewards pool has sufficient balance for validator rewards
    /// This should be called on startup to verify the pool binding. Testnet-v3
    /// has a fixed token cap, so startup must never mint an undisclosed refill.
    pub fn ensure_rewards_pool_funded(&self) -> Result<(), String> {
        let addresses = testnet_v3_system_addresses()?;
        let pool_balance = self.get_balance(&addresses.validator_rewards_pool, SNRG_SYMBOL);
        if pool_balance == 0 {
            println!(
                "Validator reward pool is empty at startup; it remains fee/governance funded and no tokens were minted"
            );
        }
        Ok(())
    }

    /// Get the rewards pool address
    pub fn get_rewards_pool_address() -> Result<String, String> {
        Ok(testnet_v3_system_addresses()?.validator_rewards_pool)
    }

    /// Get rewards pool balance
    pub fn get_rewards_pool_balance(&self) -> Result<u64, String> {
        let address = Self::get_rewards_pool_address()?;
        Ok(self.get_balance(&address, SNRG_SYMBOL))
    }

    pub fn get_total_stake_for_validator(&self, validator: &str) -> u64 {
        if let Ok(stakes) = self.stakes.lock() {
            if let Some(validator_stakes) = stakes.get(validator) {
                return validator_stakes
                    .iter()
                    .filter(|stake| stake.is_active)
                    .map(|stake| stake.amount)
                    .sum();
            }
        }
        0
    }

    fn generate_tx_hash(from: &str, to: &str, token: &str, amount: u64, fee: u64) -> String {
        let mut hasher = Sha3_256::new();
        hasher.update(from.as_bytes());
        hasher.update(to.as_bytes());
        hasher.update(token.as_bytes());
        hasher.update(&amount.to_le_bytes());
        hasher.update(&fee.to_le_bytes());
        hasher.update(&Token::current_timestamp().to_le_bytes());
        hex::encode(hasher.finalize())
    }

    pub fn save_state<P: AsRef<Path>>(&self, path: P) -> Result<(), Box<dyn std::error::Error>> {
        let path = path.as_ref();
        let reward_ledger = crate::rewards::REWARD_LEDGER
            .lock()
            .map(|ledger| ledger.to_persisted_state())
            .unwrap_or_default();
        let state = TokenState {
            tokens: self.get_all_tokens(),
            balances: self.balances.lock().unwrap().clone(),
            transfers: self.transfers.lock().unwrap().clone(),
            stakes: self.stakes.lock().unwrap().clone(),
            burn_ledger: self.burn_ledger.lock().unwrap().clone(),
            burn_records: self.burn_records.lock().unwrap().clone(),
            reward_ledger,
        };

        let json = serde_json::to_string_pretty(&state)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    pub fn load_state<P: AsRef<Path>>(&self, path: P) -> Result<(), Box<dyn std::error::Error>> {
        let path = path.as_ref();
        if !path.is_file() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("token state file does not exist: {}", path.display()),
            )
            .into());
        }

        let content = std::fs::read_to_string(path)?;
        let state: TokenState = serde_json::from_str(&content)?;

        if let Ok(mut tokens) = self.tokens.lock() {
            for mut token in state.tokens {
                token.normalize_identity();
                tokens.insert(token.symbol.clone(), token);
            }
        }

        if let Ok(mut balances) = self.balances.lock() {
            *balances = state.balances;
        }

        if let Ok(mut transfers) = self.transfers.lock() {
            *transfers = state.transfers;
        }

        if let Ok(mut stakes) = self.stakes.lock() {
            *stakes = state.stakes;
        }
        if let Ok(mut burn_ledger) = self.burn_ledger.lock() {
            *burn_ledger = state.burn_ledger;
        }
        if let Ok(mut burn_records) = self.burn_records.lock() {
            *burn_records = state.burn_records;
        }
        if let Ok(mut reward_ledger) = crate::rewards::REWARD_LEDGER.lock() {
            *reward_ledger =
                crate::rewards::RewardLedger::from_persisted_state(state.reward_ledger);
        }

        self.reconcile_testnet_profile_allocations();

        Ok(())
    }

    fn reconcile_testnet_profile_allocations(&self) {
        let allocations = load_testnet_profile_allocations();
        if allocations.is_empty() {
            return;
        }

        let mut missing_total = 0u128;
        for (address, amount) in &allocations {
            let current_balance = self.get_balance(address, "SNRG");
            if current_balance < *amount {
                missing_total = missing_total.saturating_add((*amount - current_balance) as u128);
            }
        }

        if missing_total == 0 {
            return;
        }

        let mut updated_supply = None;
        if let Ok(mut supply) = self.total_supply.lock() {
            let total = supply.entry("SNRG".to_string()).or_insert(0);
            *total = total.saturating_add(missing_total);
            updated_supply = Some(*total);
        }

        if let Ok(mut tokens) = self.tokens.lock() {
            if let Some(token) = tokens.get_mut("SNRG") {
                let current_max = token
                    .max_supply
                    .as_deref()
                    .and_then(|value| value.parse::<u128>().ok())
                    .unwrap_or(0);
                let required_max = current_max
                    .max(updated_supply.unwrap_or(0))
                    .max(required_testnet_supply_cap_floor());
                token.max_supply = Some(required_max.to_string());
            }
        }

        if let Some(total_supply) = updated_supply {
            self.update_token_supply_snapshot("SNRG", total_supply);
        }

        if let Ok(mut balances) = self.balances.lock() {
            for (address, amount) in allocations {
                let address_balances = balances.entry(address).or_insert_with(HashMap::new);
                let current_balance = address_balances.get("SNRG").copied().unwrap_or(0);
                if current_balance < amount {
                    address_balances.insert("SNRG".to_string(), amount);
                }
            }
        }
    }
}

fn load_testnet_profile_allocations() -> Vec<(String, u64)> {
    // Per-node profile allocations are not consensus state. Applying them at
    // validator runtime causes each machine to mint a different local token
    // ledger from its own profile.json. Keep the old behavior behind an
    // explicit opt-in for non-network bootstrap tooling only.
    if !profile_allocations_enabled() {
        return Vec::new();
    }

    for path in candidate_testnet_profile_paths() {
        let Ok(contents) = std::fs::read_to_string(&path) else {
            continue;
        };
        let Ok(profile) = serde_json::from_str::<TestnetTokenProfile>(&contents) else {
            continue;
        };
        return profile
            .genesis_mints
            .into_iter()
            .filter_map(|mint| {
                mint.amount_nwei
                    .trim()
                    .parse::<u64>()
                    .ok()
                    .map(|amount| (mint.wallet_address, amount))
            })
            .collect();
    }

    Vec::new()
}

fn required_testnet_supply_cap_floor() -> u128 {
    let canonical_total = canonical_genesis()
        .ok()
        .map(|genesis| {
            genesis
                .balances()
                .iter()
                .map(|balance| balance.balance_nwei as u128)
                .sum::<u128>()
        })
        .unwrap_or(0);

    let profile_total = load_testnet_profile_allocations()
        .into_iter()
        .map(|(_, amount)| amount as u128)
        .sum::<u128>();

    canonical_total.saturating_add(profile_total)
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

fn legacy_non_native_token_address(
    symbol: &str,
    name: &str,
    creator: &str,
    created_at: u64,
) -> Option<String> {
    if symbol.eq_ignore_ascii_case(SNRG_SYMBOL) {
        return None;
    }

    let metadata_hash = legacy_token_metadata_hash(symbol, name, creator);
    Some(crate::sts::derive_fungible_token_id(
        crate::sts::STS_TESTNET_CHAIN_ID,
        crate::sts::TokenClass::B1BasicFungible,
        creator,
        legacy_token_creator_nonce(symbol, creator),
        &metadata_hash,
        created_at,
    ))
}

fn legacy_token_creator_nonce(symbol: &str, creator: &str) -> u64 {
    let mut hasher = Sha3_256::new();
    hasher.update(b"synergy-legacy-token-nonce-v1");
    hasher.update((creator.len() as u64).to_be_bytes());
    hasher.update(creator.as_bytes());
    hasher.update((symbol.len() as u64).to_be_bytes());
    hasher.update(symbol.as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&digest[..8]);
    u64::from_be_bytes(bytes)
}

fn legacy_token_metadata_hash(symbol: &str, name: &str, creator: &str) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update(b"synergy-legacy-token-metadata-v1");
    for value in [symbol, name, creator] {
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value.as_bytes());
    }
    hex::encode(hasher.finalize())
}

#[derive(Serialize, Deserialize)]
struct TokenState {
    tokens: Vec<Token>,
    balances: HashMap<String, HashMap<String, u64>>,
    transfers: Vec<TokenTransfer>,
    stakes: HashMap<String, Vec<StakingInfo>>,
    #[serde(default)]
    burn_ledger: HashMap<String, u128>,
    #[serde(default)]
    burn_records: Vec<BurnRecord>,
    #[serde(default)]
    reward_ledger: crate::rewards::PersistedRewardLedger,
}

// Global token manager instance
lazy_static::lazy_static! {
    pub static ref TOKEN_MANAGER: Arc<TokenManager> = Arc::new(TokenManager::new());
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn testnet_v3_resolver_uses_deployed_reward_distributor_address() {
        let mut candidate: Value = serde_json::from_str(include_str!(
            "../../genesis.testnet-v3.identity-assigned.json"
        ))
        .expect("Testnet-v3 candidate genesis must be valid JSON");
        let frozen: Value = serde_json::from_str(include_str!(
            "../../launch/TESTNET_V3_PRODUCTION_CONTRACT_ADDRESSES.json"
        ))
        .expect("production contract address record must be valid JSON");
        let deployed_reward_distributor = frozen["contracts"]
            .as_array()
            .and_then(|entries| {
                entries
                    .iter()
                    .find(|entry| entry["contract"] == "RewardDistributor")
            })
            .and_then(|entry| entry["contract_address"].as_str())
            .expect("production RewardDistributor address");
        candidate["contracts"]["reward_distributor"]["address"] =
            Value::String(deployed_reward_distributor.to_string());

        let addresses = testnet_v3_system_addresses_from_genesis(&candidate)
            .expect("candidate must bind all protocol-controlled addresses");

        assert_eq!(
            addresses.fee_collector,
            "synf1pnchsrnyral0u9r65xusjrexuctfh465h06l"
        );
        assert_eq!(
            addresses.validator_rewards_pool,
            deployed_reward_distributor
        );
        assert_ne!(addresses.fee_collector, FEE_COLLECTOR_ADDRESS);
        assert_ne!(
            addresses.validator_rewards_pool,
            VALIDATOR_REWARDS_POOL_ADDRESS
        );
    }

    lazy_static::lazy_static! {
        static ref ENV_GUARD: Mutex<()> = Mutex::new(());
    }

    struct EnvVarGuard {
        key: &'static str,
        previous: Option<String>,
    }

    impl EnvVarGuard {
        fn set(key: &'static str, value: &str) -> Self {
            let previous = std::env::var(key).ok();
            std::env::set_var(key, value);
            Self { key, previous }
        }

        fn remove(key: &'static str) -> Self {
            let previous = std::env::var(key).ok();
            std::env::remove_var(key);
            Self { key, previous }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            if let Some(value) = &self.previous {
                std::env::set_var(self.key, value);
            } else {
                std::env::remove_var(self.key);
            }
        }
    }

    fn write_test_profile() -> PathBuf {
        let unique = format!(
            "synergy-token-test-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let root = crate::utils::test_temp_root(unique);
        let network_dir = root.join("network");
        fs::create_dir_all(&network_dir).expect("create temp network dir");
        fs::write(
            network_dir.join("profile.json"),
            r#"{
  "genesis_mints": [
    {
      "wallet_address": "synw1testprofileallocxxxxxxxxxxxxxxxxxxxx",
      "amount_nwei": "42"
    }
  ]
}"#,
        )
        .expect("write test profile");
        root
    }

    fn seed_snrg_balance(manager: &TokenManager, address: &str, amount: u64) {
        let mut balances = manager.balances.lock().unwrap();
        let entry = balances
            .entry(address.to_string())
            .or_insert_with(HashMap::new);
        entry.insert("SNRG".to_string(), amount);
    }

    fn reset_reward_ledger() {
        crate::rewards::reset_reward_ledger_for_test();
    }

    fn perfect_phase1_metrics() -> crate::rewards::Phase1Metrics {
        crate::rewards::Phase1Metrics {
            consensus_participation_score_bps: 10_000,
            block_proposal_score_bps: 10_000,
            validation_accuracy_score_bps: 10_000,
            cluster_contribution_score_bps: 10_000,
            synergy_score_modifier_bps: 10_000,
        }
    }

    fn reward_scenario_validator(
        address_seed: &str,
        cluster_address: &str,
        missed_blocks: u64,
        status: crate::validator::ValidatorStatus,
    ) -> crate::validator::Validator {
        let mut validator = crate::validator::Validator::new(
            crate::address::generate_validator_address(address_seed, 1),
            format!("{address_seed}-public-key"),
            address_seed.to_string(),
            50_000 * 1_000_000_000,
        );
        validator.status = status;
        validator.cluster_address = Some(cluster_address.to_string());
        validator.total_blocks_produced = 100;
        validator.total_transactions_validated = 1_000;
        validator.missed_blocks = missed_blocks;
        validator.missed_vote_window = missed_blocks;
        validator
    }

    #[test]
    fn native_snrg_has_no_token_address_but_custom_tokens_do() {
        let manager = TokenManager::new();
        let snrg = manager
            .get_token_info(SNRG_SYMBOL)
            .expect("SNRG token should be initialized");
        assert_eq!(snrg.token_address, None);
        assert_eq!(crate::sts::native_snrg_token_address(), None);
        assert_eq!(crate::sts::NATIVE_SNRG_PLACEHOLDER_ADDRESS.len(), 41);

        manager
            .create_token(
                "GLD".to_string(),
                "Gold Token".to_string(),
                9,
                1_000,
                Some(2_000),
                true,
                true,
                crate::address::generate_wallet_address("legacy-custom-token-creator"),
            )
            .expect("custom token should be created");

        let custom = manager
            .get_token_info("GLD")
            .expect("custom token should be readable");
        let token_address = custom
            .token_address
            .as_deref()
            .expect("non-native token must expose a token address");
        assert!(token_address.starts_with("synb1"));
        assert_ne!(token_address, crate::sts::NATIVE_SNRG_PLACEHOLDER_ADDRESS);
    }

    #[test]
    fn profile_allocations_are_disabled_by_default() {
        let _guard = ENV_GUARD.lock().unwrap();
        let temp_root = write_test_profile();
        let _project_root = EnvVarGuard::set(
            "SYNERGY_PROJECT_ROOT",
            temp_root.to_str().expect("temp path utf8"),
        );
        let _allocations_flag = EnvVarGuard::remove("SYNERGY_ENABLE_PROFILE_ALLOCATIONS");

        assert!(
            load_testnet_profile_allocations().is_empty(),
            "runtime must ignore per-node profile allocations unless explicitly enabled"
        );

        let _ = fs::remove_dir_all(temp_root);
    }

    #[test]
    fn profile_allocations_can_be_enabled_explicitly() {
        let _guard = ENV_GUARD.lock().unwrap();
        let temp_root = write_test_profile();
        let _project_root = EnvVarGuard::set(
            "SYNERGY_PROJECT_ROOT",
            temp_root.to_str().expect("temp path utf8"),
        );
        let _allocations_flag = EnvVarGuard::set("SYNERGY_ENABLE_PROFILE_ALLOCATIONS", "1");

        assert_eq!(
            load_testnet_profile_allocations(),
            vec![("synw1testprofileallocxxxxxxxxxxxxxxxxxxxx".to_string(), 42)]
        );

        let _ = fs::remove_dir_all(temp_root);
    }

    #[test]
    fn native_snrg_transaction_updates_balances_and_transfer_history() {
        let _env_guard = ENV_GUARD.lock().unwrap();
        let _ledger_guard = crate::rewards::reward_ledger_test_guard();
        reset_reward_ledger();
        let manager = TokenManager::new();
        let sender = "synw1sendernative000000000000000000000000";
        let receiver = "synw1receivernative00000000000000000000";
        seed_snrg_balance(&manager, sender, 100_000);

        let tx = Transaction::new(
            sender.to_string(),
            receiver.to_string(),
            1_500,
            0,
            vec![1, 2, 3],
            2,
            10,
            None,
            "mldsa87".to_string(),
        );

        manager
            .process_transaction_in_block(&tx, 77)
            .expect("native SNRG transaction should apply");

        assert_eq!(manager.get_balance(sender, "SNRG"), 21_500);
        assert_eq!(manager.get_balance(receiver, "SNRG"), 1_500);
        assert_eq!(manager.get_balance(FEE_COLLECTOR_ADDRESS, "SNRG"), 77_000);

        let history = manager.get_transfer_history(sender, 10);
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].tx_hash, tx.hash());
        assert_eq!(history[0].block_height, 77);

        manager
            .process_transaction_in_block(&tx, 77)
            .expect("replaying same transaction should be idempotent");

        assert_eq!(manager.get_balance(sender, "SNRG"), 21_500);
        assert_eq!(manager.get_balance(receiver, "SNRG"), 1_500);
        assert_eq!(manager.get_balance(FEE_COLLECTOR_ADDRESS, "SNRG"), 77_000);
        assert_eq!(manager.get_transfer_history(sender, 10).len(), 1);
    }

    #[test]
    fn explicit_burn_records_supply_reducing_burn() {
        let manager = TokenManager::new();
        let burner = crate::address::generate_wallet_address("explicit-burn-sender");
        seed_snrg_balance(&manager, &burner, 1_000_000);

        manager
            .burn_tokens_with_metadata(
                &burner,
                SNRG_SYMBOL,
                125_000,
                3_000,
                Some("burn-tx-1".to_string()),
                44,
            )
            .expect("burn should apply");

        assert_eq!(manager.get_balance(&burner, SNRG_SYMBOL), 875_000);
        let records = manager.get_burn_records(Some(SNRG_SYMBOL));
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].kind, BurnRecordKind::ExplicitBurn);
        assert!(records[0].supply_reduced);
        assert_eq!(records[0].burn_address, NETWORK_BURN_ADDRESS);
        assert_eq!(records[0].fee_charged_nwei, 3_000);
        assert_eq!(records[0].block_height, 44);
    }

    #[test]
    fn direct_transfer_to_burn_address_is_locked_not_supply_reduced() {
        let manager = TokenManager::new();
        let sender = crate::address::generate_wallet_address("burn-transfer-sender");
        seed_snrg_balance(&manager, &sender, 1_000_000);

        manager
            .transfer_tokens_with_metadata(
                &sender,
                NETWORK_BURN_ADDRESS,
                SNRG_SYMBOL,
                50_000,
                1_000,
                "burn-transfer-tx-1".to_string(),
                45,
            )
            .expect("transfer to burn address should apply");

        assert_eq!(manager.get_balance(&sender, SNRG_SYMBOL), 949_000);
        assert_eq!(
            manager.get_balance(NETWORK_BURN_ADDRESS, SNRG_SYMBOL),
            50_000
        );
        assert_eq!(
            manager.get_balance(FEE_COLLECTOR_ADDRESS, SNRG_SYMBOL),
            1_000
        );
        let records = manager.get_burn_records(Some(SNRG_SYMBOL));
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].kind, BurnRecordKind::BurnAddressTransfer);
        assert!(!records[0].supply_reduced);
    }

    #[test]
    fn network_burn_address_cannot_initiate_transfers() {
        let manager = TokenManager::new();
        seed_snrg_balance(&manager, NETWORK_BURN_ADDRESS, 100_000);
        let receiver = crate::address::generate_wallet_address("burn-transfer-receiver");

        let err = manager
            .transfer_tokens(NETWORK_BURN_ADDRESS, &receiver, SNRG_SYMBOL, 1, 0)
            .unwrap_err();
        assert_eq!(err, "Network burn address cannot send funds");
    }

    #[test]
    fn epoch_fee_distribution_moves_collector_balance_once() {
        let _env_guard = ENV_GUARD.lock().unwrap();
        let _ledger_guard = crate::rewards::reward_ledger_test_guard();
        reset_reward_ledger();
        let manager = TokenManager::new();
        seed_snrg_balance(&manager, FEE_COLLECTOR_ADDRESS, 101);
        seed_snrg_balance(&manager, VALIDATOR_REWARDS_POOL_ADDRESS, 0);
        seed_snrg_balance(&manager, DAO_TREASURY_ADDRESS, 0);

        let distribution = manager
            .distribute_epoch_fees_from_collector(12, 101)
            .expect("epoch fees should distribute");

        assert_eq!(distribution.validator_share_nwei, 70);
        assert_eq!(distribution.treasury_share_nwei, 31);
        assert_eq!(manager.get_balance(FEE_COLLECTOR_ADDRESS, SNRG_SYMBOL), 0);
        assert_eq!(
            manager.get_balance(VALIDATOR_REWARDS_POOL_ADDRESS, SNRG_SYMBOL),
            70
        );
        assert_eq!(manager.get_balance(DAO_TREASURY_ADDRESS, SNRG_SYMBOL), 31);

        let duplicate = manager
            .distribute_epoch_fees_from_collector(12, 101)
            .expect("duplicate epoch close should be idempotent");
        assert_eq!(duplicate, distribution);
        assert_eq!(manager.get_balance(FEE_COLLECTOR_ADDRESS, SNRG_SYMBOL), 0);
        assert_eq!(
            manager.get_balance(VALIDATOR_REWARDS_POOL_ADDRESS, SNRG_SYMBOL),
            70
        );
        assert_eq!(manager.get_balance(DAO_TREASURY_ADDRESS, SNRG_SYMBOL), 31);

        let ledger = crate::rewards::REWARD_LEDGER.lock().unwrap();
        assert_eq!(ledger.fee_distributions.len(), 1);
        assert_eq!(ledger.fee_collector_distributions.len(), 1);
    }

    #[test]
    fn included_transaction_records_fee_accumulator_once() {
        let _env_guard = ENV_GUARD.lock().unwrap();
        let _ledger_guard = crate::rewards::reward_ledger_test_guard();
        reset_reward_ledger();
        let manager = TokenManager::new();
        let sender = crate::address::generate_wallet_address("fee-accumulator-sender");
        let receiver = crate::address::generate_wallet_address("fee-accumulator-receiver");
        let tx = Transaction::new(
            sender.clone(),
            receiver,
            1_000,
            0,
            vec![1, 2, 3],
            2,
            10,
            None,
            "mldsa87".to_string(),
        );
        let fee = tx.get_total_network_fee_u64().unwrap();
        seed_snrg_balance(&manager, &sender, 1_000 + fee);

        manager
            .process_transaction_in_block(&tx, 77)
            .expect("included transfer should apply");
        manager
            .process_transaction_in_block(&tx, 77)
            .expect("included transfer replay should be idempotent");

        let ledger = crate::rewards::REWARD_LEDGER.lock().unwrap();
        let accumulator = ledger
            .fee_accumulators
            .get(&0)
            .expect("epoch 0 accumulator should exist");
        assert_eq!(accumulator.total_collected_nwei, fee as u128);
        assert_eq!(
            accumulator.by_tx_type.get("native_snrg_send").copied(),
            Some(fee as u128)
        );
    }

    #[test]
    fn validator_rewards_escrow_and_phase2_settlement_reconcile_balances() {
        let _env_guard = ENV_GUARD.lock().unwrap();
        let _ledger_guard = crate::rewards::reward_ledger_test_guard();
        reset_reward_ledger();
        let manager = TokenManager::new();
        let cluster = crate::address::generate_validator_cluster_address("reward-cluster-a");
        let payout_a = crate::address::generate_wallet_address("reward-payout-a");
        let payout_b = crate::address::generate_wallet_address("reward-payout-b");
        let validators = vec![
            crate::rewards::ValidatorPhase1Input {
                cluster_address: cluster.clone(),
                validator_id: "validator-a".to_string(),
                reward_payout_address: payout_a.clone(),
                metrics: perfect_phase1_metrics(),
            },
            crate::rewards::ValidatorPhase1Input {
                cluster_address: cluster.clone(),
                validator_id: "validator-b".to_string(),
                reward_payout_address: payout_b.clone(),
                metrics: perfect_phase1_metrics(),
            },
        ];
        let allocation = crate::rewards::allocate_epoch_validator_rewards(
            42,
            10_000,
            &validators,
            420,
            &crate::rewards::RewardConfig::default(),
        )
        .expect("allocation should succeed");
        seed_snrg_balance(&manager, VALIDATOR_REWARDS_POOL_ADDRESS, 10_000);
        seed_snrg_balance(&manager, &cluster, 0);
        seed_snrg_balance(&manager, &payout_a, 0);
        seed_snrg_balance(&manager, &payout_b, 0);
        seed_snrg_balance(&manager, TREASURY_RECOVERY_WALLET_ADDRESS, 0);

        manager
            .escrow_epoch_validator_rewards(&allocation, 421)
            .expect("cluster rewards should escrow");
        assert_eq!(
            manager.get_balance(VALIDATOR_REWARDS_POOL_ADDRESS, SNRG_SYMBOL),
            0
        );
        assert_eq!(manager.get_balance(&cluster, SNRG_SYMBOL), 10_000);
        {
            let ledger = crate::rewards::REWARD_LEDGER.lock().unwrap();
            assert_eq!(ledger.cluster_reward_escrows.len(), 1);
            assert_eq!(ledger.get_validator_pending_rewards("validator-a").len(), 1);
            assert_eq!(ledger.get_validator_pending_rewards("validator-b").len(), 1);
        }

        manager
            .escrow_epoch_validator_rewards(&allocation, 421)
            .expect("escrow replay should not move funds twice");
        assert_eq!(manager.get_balance(&cluster, SNRG_SYMBOL), 10_000);

        let settlements = manager
            .settle_epoch_validator_rewards_from_escrows(
                43,
                &HashMap::from([
                    ("validator-a".to_string(), 10_000),
                    ("validator-b".to_string(), 8_500),
                ]),
                500,
            )
            .expect("phase2 settlement should apply");

        assert_eq!(settlements.len(), 2);
        assert_eq!(manager.get_balance(&cluster, SNRG_SYMBOL), 0);
        assert_eq!(manager.get_balance(&payout_a, SNRG_SYMBOL), 5_000);
        assert_eq!(manager.get_balance(&payout_b, SNRG_SYMBOL), 4_250);
        assert_eq!(
            manager.get_balance(TREASURY_RECOVERY_WALLET_ADDRESS, SNRG_SYMBOL),
            750
        );

        let replay = manager
            .settle_epoch_validator_rewards_from_escrows(
                43,
                &HashMap::from([
                    ("validator-a".to_string(), 10_000),
                    ("validator-b".to_string(), 8_500),
                ]),
                501,
            )
            .expect("settlement replay should be idempotent");
        assert!(replay.is_empty());
        assert_eq!(manager.get_balance(&payout_a, SNRG_SYMBOL), 5_000);
        assert_eq!(manager.get_balance(&payout_b, SNRG_SYMBOL), 4_250);
        assert_eq!(
            manager.get_balance(TREASURY_RECOVERY_WALLET_ADDRESS, SNRG_SYMBOL),
            750
        );

        let ledger = crate::rewards::REWARD_LEDGER.lock().unwrap();
        assert_eq!(ledger.reward_settlements.len(), 2);
        assert_eq!(
            ledger
                .treasury_recovery_ledger
                .get(&43)
                .expect("recovery ledger should exist")
                .total_recovered_nwei,
            750
        );
    }

    #[test]
    fn three_validator_fee_burn_and_reward_lifecycle_reconciles_invariants() {
        let _env_guard = ENV_GUARD.lock().unwrap();
        let _ledger_guard = crate::rewards::reward_ledger_test_guard();
        reset_reward_ledger();
        let manager = TokenManager::new();
        seed_snrg_balance(&manager, FEE_COLLECTOR_ADDRESS, 0);
        seed_snrg_balance(&manager, VALIDATOR_REWARDS_POOL_ADDRESS, 0);
        seed_snrg_balance(&manager, DAO_TREASURY_ADDRESS, 0);
        seed_snrg_balance(&manager, TREASURY_RECOVERY_WALLET_ADDRESS, 0);

        let sender = crate::address::generate_wallet_address("reward-scenario-sender");
        let receiver_a = crate::address::generate_wallet_address("reward-scenario-receiver-a");
        let receiver_b = crate::address::generate_wallet_address("reward-scenario-receiver-b");
        seed_snrg_balance(&manager, &sender, 250_000_000_000);

        let one_snrg = Transaction::new(
            sender.clone(),
            receiver_a.clone(),
            1_000_000_000,
            0,
            vec![1, 2, 3],
            1,
            21_000,
            None,
            "mldsa87".to_string(),
        );
        let hundred_snrg = Transaction::new(
            sender.clone(),
            receiver_b.clone(),
            100_000_000_000,
            1,
            vec![1, 2, 3],
            1,
            21_000,
            None,
            "mldsa87".to_string(),
        );
        let burn_snrg = Transaction::new(
            sender.clone(),
            String::new(),
            0,
            2,
            vec![1, 2, 3],
            1,
            21_000,
            Some(r#"burn:{"asset":"SNRG","amount":10000000000}"#.to_string()),
            "mldsa87".to_string(),
        );

        let one_fee = one_snrg.get_total_network_fee_u64().unwrap();
        let hundred_fee = hundred_snrg.get_total_network_fee_u64().unwrap();
        let burn_fee = burn_snrg.get_total_network_fee_u64().unwrap();
        assert!(hundred_fee > one_fee);

        manager
            .process_transaction_in_block(&one_snrg, 100)
            .expect("one SNRG transfer should apply");
        manager
            .process_transaction_in_block(&hundred_snrg, 101)
            .expect("hundred SNRG transfer should apply");
        manager
            .process_transaction_in_block(&burn_snrg, 102)
            .expect("explicit SNRG burn should apply");

        let failed_tx = Transaction::new(
            sender.clone(),
            receiver_a.clone(),
            u64::MAX / 2,
            3,
            vec![1, 2, 3],
            1,
            21_000,
            None,
            "mldsa87".to_string(),
        );
        let failed = manager.process_transaction_in_block(&failed_tx, 103);
        assert_eq!(
            failed.unwrap_err(),
            "Insufficient balance for transfer and fee"
        );

        let expected_fees = one_fee as u128 + hundred_fee as u128 + burn_fee as u128;
        assert_eq!(
            manager.get_balance(FEE_COLLECTOR_ADDRESS, SNRG_SYMBOL) as u128,
            expected_fees
        );
        assert_eq!(manager.get_burned_total(SNRG_SYMBOL), 10_000_000_000);
        {
            let ledger = crate::rewards::REWARD_LEDGER.lock().unwrap();
            let accumulator = ledger
                .fee_accumulators
                .get(&0)
                .expect("epoch 0 accumulator should exist");
            assert_eq!(accumulator.total_collected_nwei, expected_fees);
        }

        let cluster =
            crate::address::generate_validator_cluster_address("three-validator-reward-scenario");
        seed_snrg_balance(&manager, &cluster, 0);
        let validators = vec![
            reward_scenario_validator(
                "reward-scenario-validator-a",
                &cluster,
                0,
                crate::validator::ValidatorStatus::Active,
            ),
            reward_scenario_validator(
                "reward-scenario-validator-b",
                &cluster,
                1,
                crate::validator::ValidatorStatus::Active,
            ),
            reward_scenario_validator(
                "reward-scenario-validator-c",
                &cluster,
                2,
                crate::validator::ValidatorStatus::Jailed,
            ),
        ];
        for validator in &validators {
            seed_snrg_balance(&manager, &validator.address, 0);
        }

        let epoch0 = manager
            .run_epoch_reward_lifecycle(0, 1, 1_000, &validators)
            .expect("epoch 0 lifecycle should close fees and escrow rewards");
        let fee_distribution = epoch0
            .fee_distribution
            .as_ref()
            .expect("epoch 0 fees should distribute");
        assert_eq!(fee_distribution.total_fees_nwei, expected_fees);
        assert_eq!(manager.get_balance(FEE_COLLECTOR_ADDRESS, SNRG_SYMBOL), 0);
        assert_eq!(
            manager.get_balance(DAO_TREASURY_ADDRESS, SNRG_SYMBOL) as u128,
            fee_distribution.treasury_share_nwei
        );
        assert_eq!(
            manager.get_balance(&cluster, SNRG_SYMBOL) as u128,
            fee_distribution.validator_share_nwei
        );
        {
            let ledger = crate::rewards::REWARD_LEDGER.lock().unwrap();
            assert_eq!(ledger.pending_rewards.len(), 3);
            assert!(ledger.reward_settlements.is_empty());
        }

        let epoch1 = manager
            .run_epoch_reward_lifecycle(1, 2, 2_000, &validators)
            .expect("epoch 1 lifecycle should settle epoch 0 pending rewards");
        assert_eq!(epoch1.settlements.len(), 3);
        assert_eq!(manager.get_balance(&cluster, SNRG_SYMBOL), 0);
        assert!(manager.get_balance(TREASURY_RECOVERY_WALLET_ADDRESS, SNRG_SYMBOL) > 0);

        let ledger = crate::rewards::REWARD_LEDGER.lock().unwrap();
        let report = ledger.check_invariants(None);
        assert!(report.passed, "reward invariant violations: {:?}", report);
    }

    #[test]
    fn reward_ledger_survives_token_state_roundtrip() {
        let _env_guard = ENV_GUARD.lock().unwrap();
        let _ledger_guard = crate::rewards::reward_ledger_test_guard();
        reset_reward_ledger();
        let manager = TokenManager::new();
        seed_snrg_balance(&manager, FEE_COLLECTOR_ADDRESS, 101);
        seed_snrg_balance(&manager, VALIDATOR_REWARDS_POOL_ADDRESS, 0);
        seed_snrg_balance(&manager, DAO_TREASURY_ADDRESS, 0);
        manager
            .distribute_epoch_fees_from_collector(90, 101)
            .expect("epoch distribution should apply");

        let cluster = crate::address::generate_validator_cluster_address("roundtrip-cluster");
        let payout = crate::address::generate_wallet_address("roundtrip-payout");
        let validators = vec![crate::rewards::ValidatorPhase1Input {
            cluster_address: cluster.clone(),
            validator_id: "roundtrip-validator".to_string(),
            reward_payout_address: payout.clone(),
            metrics: perfect_phase1_metrics(),
        }];
        let allocation = crate::rewards::allocate_epoch_validator_rewards(
            91,
            10_000,
            &validators,
            910,
            &crate::rewards::RewardConfig::default(),
        )
        .expect("allocation should succeed");
        seed_snrg_balance(&manager, VALIDATOR_REWARDS_POOL_ADDRESS, 10_000);
        seed_snrg_balance(&manager, &cluster, 0);
        seed_snrg_balance(&manager, &payout, 0);
        seed_snrg_balance(&manager, TREASURY_RECOVERY_WALLET_ADDRESS, 0);
        manager
            .escrow_epoch_validator_rewards(&allocation, 911)
            .expect("escrow should apply");
        manager
            .settle_epoch_validator_rewards_from_escrows(
                92,
                &HashMap::from([("roundtrip-validator".to_string(), 8_500)]),
                920,
            )
            .expect("settlement should apply");

        let unique = format!(
            "synergy-token-state-roundtrip-{}.json",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let path = crate::utils::test_temp_root(unique);
        manager
            .save_state(path.to_str().expect("temp path utf8"))
            .expect("state should save");

        reset_reward_ledger();
        let restored = TokenManager::new();
        restored
            .load_state(path.to_str().expect("temp path utf8"))
            .expect("state should load");

        assert_eq!(restored.get_balance(&payout, SNRG_SYMBOL), 8_500);
        assert_eq!(
            restored.get_balance(TREASURY_RECOVERY_WALLET_ADDRESS, SNRG_SYMBOL),
            1_500
        );
        let ledger = crate::rewards::REWARD_LEDGER.lock().unwrap();
        assert_eq!(
            ledger
                .fee_distributions
                .get(&90)
                .expect("fee distribution should restore")
                .total_fees_nwei,
            101
        );
        assert!(ledger
            .cluster_reward_escrows
            .contains_key(&(91, cluster.clone())));
        assert_eq!(ledger.reward_settlements.len(), 1);
        assert_eq!(
            ledger
                .treasury_recovery_ledger
                .get(&92)
                .expect("recovery ledger should restore")
                .total_recovered_nwei,
            1_500
        );
        drop(ledger);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn staking_transaction_is_not_intercepted_as_native_transfer() {
        let manager = TokenManager::new();
        let staker = crate::address::generate_wallet_address("staking-transaction-staker");
        let validator =
            crate::address::generate_validator_address("staking-transaction-validator", 1);

        let tx = Transaction::new(
            staker.clone(),
            validator.clone(),
            3_000,
            0,
            vec![1, 2, 3],
            2,
            10,
            Some(format!(
                "stake:{{\"validator\":\"{}\",\"token\":\"SNRG\",\"amount\":3000}}",
                validator
            )),
            "mldsa87".to_string(),
        );
        let fee = tx.get_total_network_fee_u64().unwrap();
        seed_snrg_balance(&manager, &staker, 10_000 + fee);

        manager
            .process_transaction(&tx)
            .expect("staking transaction should apply as stake");

        assert_eq!(manager.get_balance(&staker, "SNRG"), 7_000);
        assert_eq!(manager.get_balance(&validator, "SNRG"), 0);
        assert_eq!(manager.get_staked_balance(&staker, "SNRG"), 3_000);
    }

    #[test]
    fn replay_chain_transactions_restores_staking_state() {
        let manager = TokenManager::new();
        let staker = crate::address::generate_wallet_address("staking-replay-staker");
        let validator = crate::address::generate_validator_address("staking-replay-validator", 1);
        let tx = Transaction::new(
            staker.clone(),
            validator.clone(),
            50_000,
            0,
            vec![1, 2, 3],
            2,
            10,
            Some(format!(
                "stake:{{\"validator\":\"{}\",\"token\":\"SNRG\",\"amount\":50000}}",
                validator
            )),
            "mldsa87".to_string(),
        );
        let fee = tx
            .get_total_network_fee_u64()
            .expect("staking replay transaction fee should be valid");
        seed_snrg_balance(&manager, &staker, 50_000 + fee);

        let mut chain = crate::block::BlockChain::new();
        chain.add_block(crate::block::Block::new(
            1,
            vec![tx],
            "replay-parent".to_string(),
            "replay-validator".to_string(),
            0,
        ));

        assert_eq!(manager.replay_chain_transactions(&chain), (1, 0));
        assert_eq!(manager.get_staked_balance(&staker, "SNRG"), 50_000);
        assert_eq!(manager.get_balance(&validator, "SNRG"), 0);
    }

    #[test]
    fn staked_balance_falls_back_to_active_stake_entries() {
        let manager = TokenManager::new();
        let staker = "synw1stakerfallback00000000000000000000";
        let validator = "synv1validatorfallback0000000000000000";

        manager.stakes.lock().unwrap().insert(
            validator.to_string(),
            vec![StakingInfo {
                validator_address: validator.to_string(),
                staker_address: staker.to_string(),
                amount: 50_000,
                stake_start: 1,
                stake_end: None,
                rewards_earned: 0,
                is_active: true,
            }],
        );

        assert_eq!(manager.get_staked_balance(staker, "SNRG"), 50_000);
        assert_eq!(manager.get_staked_balance("*", "SNRG"), 50_000);
    }

    #[test]
    fn token_state_path_uses_configured_data_root() {
        let _lock = ENV_GUARD.lock().unwrap();
        let root = crate::utils::test_temp_root(format!(
            "synergy-token-state-root-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _data_path = EnvVarGuard::set("SYNERGY_DATA_PATH", &root.to_string_lossy());

        assert_eq!(token_state_path(), root.join("token_state.json"));
    }

    #[test]
    fn missing_token_state_is_not_reported_as_loaded() {
        let path = crate::utils::test_temp_root(format!(
            "synergy-missing-token-state-{}.json",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let manager = TokenManager::new();

        let error = manager
            .load_state(&path)
            .expect_err("a missing token state must trigger replay or fail closed");

        assert!(error.to_string().contains("does not exist"));
    }
}
