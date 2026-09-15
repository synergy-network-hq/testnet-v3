use cosmwasm_std::{entry_point, to_binary, Addr, Binary, Coin, Deps, DepsMut, Env, MessageInfo, Response, StdError, StdResult, Uint128, BankMsg, CosmosMsg};
use cw2::set_contract_version;
use cw_storage_plus::{Item, Map};

const CONTRACT_NAME: &str = "relayer_registry_wasm";
const CONTRACT_VERSION: &str = "0.1.0";

pub const STAKES: Map<&Addr, Uint128> = Map::new("stakes");
pub const ADMIN: Item<Addr> = Item::new("admin");

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExecuteMsg {
    Initialize {},
    DepositStake {},
    WithdrawStake { amount: Uint128 },
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    GetStake { relayer: String },
}

#[entry_point]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    _msg: ()
) -> StdResult<Response> {
    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;
    ADMIN.save(deps.storage, &info.sender)?;
    Ok(Response::default())
}

#[entry_point]
pub fn execute(deps: DepsMut, _env: Env, info: MessageInfo, msg: ExecuteMsg) -> Result<Response, StdError> {
    match msg {
        ExecuteMsg::Initialize {} => Ok(Response::default()),
        ExecuteMsg::DepositStake {} => execute_deposit_stake(deps, info),
        ExecuteMsg::WithdrawStake { amount } => execute_withdraw_stake(deps, info, amount),
    }
}

fn execute_deposit_stake(deps: DepsMut, info: MessageInfo) -> Result<Response, StdError> {
    if info.funds.is_empty() || info.funds[0].amount.is_zero() {
        return Err(StdError::generic_err("No stake"));
    }
    STAKES.update(deps.storage, &info.sender, |opt| -> StdResult<_> {
        let mut current = opt.unwrap_or_default();
        current += info.funds[0].amount;
        Ok(current)
    })?;
    Ok(Response::new().add_attribute("action", "deposit_stake").add_attribute("amount", info.funds[0].amount.to_string()))
}

fn execute_withdraw_stake(deps: DepsMut, info: MessageInfo, amount: Uint128) -> Result<Response, StdError> {
    STAKES.update(deps.storage, &info.sender, |opt| -> StdResult<_> {
        let mut current = opt.unwrap_or_default();
        if current < amount {
            return Err(StdError::generic_err("Insufficient stake"));
        }
        current -= amount;
        Ok(current)
    })?;
    let msg = CosmosMsg::Bank(BankMsg::Send { to_address: info.sender.to_string(), amount: vec![Coin { denom: "ucosm".to_string(), amount }] });
    Ok(Response::new().add_message(msg).add_attribute("action", "withdraw_stake").add_attribute("amount", amount.to_string()))
}

#[entry_point]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::GetStake { relayer } => {
            let addr = deps.api.addr_validate(&relayer)?;
            let stake = STAKES.may_load(deps.storage, &addr)?.unwrap_or_default();
            to_binary(&stake)
        }
    }
}