use cosmwasm_std::{entry_point, to_binary, Addr, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdError, StdResult, Uint128};
use cw2::set_contract_version;
use cw_storage_plus::{Map};

// Version info for migration
const CONTRACT_NAME: &str = "sxcp_vault_wasm";
const CONTRACT_VERSION: &str = "0.1.0";

// A deposit record keyed by a unique id
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct DepositRecord {
    pub amount: Uint128,
    pub depositor: Addr,
    pub hash_lock: String,
    pub timeout: u64,
    pub claimed: bool,
}

// Storage: deposit_id -> DepositRecord
pub const DEPOSITS: Map<&str, DepositRecord> = Map::new("deposits");

// Instantiate message. No parameters for now.
#[entry_point]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    _msg: ()
) -> StdResult<Response> {
    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;
    Ok(Response::default())
}

// Execute messages
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExecuteMsg {
    Deposit { deposit_id: String, hash_lock: String, timeout: u64 },
    Claim { deposit_id: String, preimage: String },
    Refund { deposit_id: String },
}

// Queries
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    GetDeposit { deposit_id: String },
}

#[entry_point]
pub fn execute(deps: DepsMut, env: Env, info: MessageInfo, msg: ExecuteMsg) -> Result<Response, StdError> {
    match msg {
        ExecuteMsg::Deposit { deposit_id, hash_lock, timeout } => execute_deposit(deps, env, info, deposit_id, hash_lock, timeout),
        ExecuteMsg::Claim { deposit_id, preimage } => execute_claim(deps, env, info, deposit_id, preimage),
        ExecuteMsg::Refund { deposit_id } => execute_refund(deps, env, info, deposit_id),
    }
}

fn execute_deposit(deps: DepsMut, env: Env, info: MessageInfo, deposit_id: String, hash_lock: String, timeout: u64) -> Result<Response, StdError> {
    // require funds
    let coins = info.funds;
    if coins.is_empty() || coins[0].amount.is_zero() {
        return Err(StdError::generic_err("No funds sent"));
    }
    if timeout <= env.block.time.seconds() {
        return Err(StdError::generic_err("Timeout must be in the future"));
    }
    let record = DepositRecord {
        amount: coins[0].amount,
        depositor: info.sender.clone(),
        hash_lock: hash_lock.clone(),
        timeout,
        claimed: false,
    };
    DEPOSITS.save(deps.storage, &deposit_id, &record)?;
    Ok(Response::new().add_attribute("action", "deposit").add_attribute("deposit_id", deposit_id))
}

fn execute_claim(deps: DepsMut, _env: Env, info: MessageInfo, deposit_id: String, preimage: String) -> Result<Response, StdError> {
    let mut record = DEPOSITS.load(deps.storage, &deposit_id)?;
    if record.claimed {
        return Err(StdError::generic_err("Already claimed"));
    }
    if record.hash_lock != sha256_hex(&preimage) {
        return Err(StdError::generic_err("Invalid preimage"));
    }
    record.claimed = true;
    DEPOSITS.save(deps.storage, &deposit_id, &record)?;
    // In a full implementation we would send funds to the claimer via BankMsg
    Ok(Response::new().add_attribute("action", "claim").add_attribute("deposit_id", deposit_id))
}

fn execute_refund(deps: DepsMut, env: Env, info: MessageInfo, deposit_id: String) -> Result<Response, StdError> {
    let mut record = DEPOSITS.load(deps.storage, &deposit_id)?;
    if env.block.time.seconds() < record.timeout {
        return Err(StdError::generic_err("Not expired"));
    }
    if info.sender != record.depositor {
        return Err(StdError::generic_err("Not depositor"));
    }
    if record.claimed {
        return Err(StdError::generic_err("Already claimed"));
    }
    record.claimed = true;
    DEPOSITS.save(deps.storage, &deposit_id, &record)?;
    // send funds back to depositor via BankMsg
    Ok(Response::new().add_attribute("action", "refund").add_attribute("deposit_id", deposit_id))
}

#[entry_point]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::GetDeposit { deposit_id } => to_binary(&DEPOSITS.may_load(deps.storage, &deposit_id)?),
    }
}

// Compute SHA256 hash and return lowercase hex string
fn sha256_hex(data: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    let result = hasher.finalize();
    hex::encode(result)
}