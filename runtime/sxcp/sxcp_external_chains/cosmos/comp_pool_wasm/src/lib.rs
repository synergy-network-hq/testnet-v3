use cosmwasm_std::{entry_point, to_binary, Addr, Binary, Coin, Deps, DepsMut, Env, MessageInfo, Response, StdError, StdResult, Uint128, BankMsg, CosmosMsg};
use cw2::set_contract_version;
use cw_storage_plus::{Item, Map};

const CONTRACT_NAME: &str = "comp_pool_wasm";
const CONTRACT_VERSION: &str = "0.1.0";

// Stake mapping: relayer address -> stake amount
pub const STAKES: Map<&Addr, Uint128> = Map::new("stakes");
pub const PENDING_REWARDS: Map<&Addr, Uint128> = Map::new("pending_rewards");
pub const TOTAL_STAKE: Item<Uint128> = Item::new("total_stake");
pub const ADMIN: Item<Addr> = Item::new("admin");

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExecuteMsg {
    Initialize {},
    DepositFee {},
    AddStake { relayer: String },
    Distribute {},
    ClaimRewards {},
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {}

#[entry_point]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    _msg: ()
) -> StdResult<Response> {
    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;
    ADMIN.save(deps.storage, &info.sender)?;
    TOTAL_STAKE.save(deps.storage, &Uint128::zero())?;
    Ok(Response::default())
}

#[entry_point]
pub fn execute(deps: DepsMut, env: Env, info: MessageInfo, msg: ExecuteMsg) -> Result<Response, StdError> {
    match msg {
        ExecuteMsg::Initialize {} => Ok(Response::default()),
        ExecuteMsg::DepositFee {} => execute_deposit_fee(deps, info),
        ExecuteMsg::AddStake { relayer } => execute_add_stake(deps, info, relayer),
        ExecuteMsg::Distribute {} => execute_distribute(deps, env),
        ExecuteMsg::ClaimRewards {} => execute_claim_rewards(deps, info),
    }
}

fn execute_deposit_fee(deps: DepsMut, info: MessageInfo) -> Result<Response, StdError> {
    // Fees are whatever funds are sent along with the message.
    if info.funds.is_empty() || info.funds[0].amount.is_zero() {
        return Err(StdError::generic_err("No fee sent"));
    }
    // Fees accumulate in contract balance implicitly.
    Ok(Response::new().add_attribute("action", "deposit_fee").add_attribute("amount", info.funds[0].amount.to_string()))
}

fn execute_add_stake(deps: DepsMut, info: MessageInfo, relayer: String) -> Result<Response, StdError> {
    let addr = deps.api.addr_validate(&relayer)?;
    if info.funds.is_empty() || info.funds[0].amount.is_zero() {
        return Err(StdError::generic_err("No stake sent"));
    }
    STAKES.update(deps.storage, &addr, |opt| -> StdResult<_> {
        let mut current = opt.unwrap_or_default();
        current += info.funds[0].amount;
        Ok(current)
    })?;
    TOTAL_STAKE.update(deps.storage, |mut total| -> StdResult<_> {
        total += info.funds[0].amount;
        Ok(total)
    })?;
    Ok(Response::new().add_attribute("action", "add_stake").add_attribute("relayer", relayer).add_attribute("amount", info.funds[0].amount.to_string()))
}

fn execute_distribute(deps: DepsMut, env: Env) -> Result<Response, StdError> {
    let total_stake = TOTAL_STAKE.load(deps.storage)?;
    let balance = deps.querier.query_balance(&env.contract.address, "ucosm")?;
    let available = balance.amount;
    if total_stake.is_zero() || available.is_zero() {
        return Err(StdError::generic_err("Nothing to distribute"));
    }
    // In this simplified example we transfer all fees to the admin.
    let admin = ADMIN.load(deps.storage)?;
    let msg = CosmosMsg::Bank(BankMsg::Send { to_address: admin.to_string(), amount: vec![Coin { denom: balance.denom, amount: available }] });
    Ok(Response::new().add_message(msg).add_attribute("action", "distribute").add_attribute("amount", available.to_string()))
}

fn execute_claim_rewards(deps: DepsMut, info: MessageInfo) -> Result<Response, StdError> {
    let addr = info.sender;
    let reward = PENDING_REWARDS.may_load(deps.storage, &addr)?.unwrap_or_default();
    if reward.is_zero() {
        return Err(StdError::generic_err("No rewards"));
    }
    PENDING_REWARDS.save(deps.storage, &addr, &Uint128::zero())?;
    let msg = CosmosMsg::Bank(BankMsg::Send { to_address: addr.to_string(), amount: vec![Coin { denom: "ucosm".to_string(), amount: reward }] });
    Ok(Response::new().add_message(msg).add_attribute("action", "claim_rewards").add_attribute("amount", reward.to_string()))
}