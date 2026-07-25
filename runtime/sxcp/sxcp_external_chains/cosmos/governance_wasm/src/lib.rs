use cosmwasm_std::{entry_point, to_binary, Addr, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdError, StdResult};
use cw2::set_contract_version;
use cw_storage_plus::Item;

const CONTRACT_NAME: &str = "governance_wasm";
const CONTRACT_VERSION: &str = "0.1.0";

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Config {
    pub admin: Addr,
    pub paused: bool,
    pub deposit_limit: u128,
}

pub const CONFIG: Item<Config> = Item::new("config");

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExecuteMsg {
    Initialize { deposit_limit: u128 },
    SetDepositLimit { new_limit: u128 },
    Pause {},
    Unpause {},
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    GetConfig {},
}

#[entry_point]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    _msg: ()
) -> StdResult<Response> {
    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;
    // config will be initialised by calling Initialize execute message
    CONFIG.save(deps.storage, &Config { admin: info.sender.clone(), paused: false, deposit_limit: 0 })?;
    Ok(Response::default())
}

#[entry_point]
pub fn execute(deps: DepsMut, _env: Env, info: MessageInfo, msg: ExecuteMsg) -> Result<Response, StdError> {
    match msg {
        ExecuteMsg::Initialize { deposit_limit } => {
            CONFIG.update(deps.storage, |mut cfg| -> StdResult<_> {
                cfg.admin = info.sender.clone();
                cfg.deposit_limit = deposit_limit;
                Ok(cfg)
            })?;
            Ok(Response::new().add_attribute("action", "initialize"))
        }
        ExecuteMsg::SetDepositLimit { new_limit } => {
            CONFIG.update(deps.storage, |mut cfg| -> StdResult<_> {
                if info.sender != cfg.admin {
                    return Err(StdError::generic_err("Only admin"));
                }
                cfg.deposit_limit = new_limit;
                Ok(cfg)
            })?;
            Ok(Response::new().add_attribute("action", "set_deposit_limit"))
        }
        ExecuteMsg::Pause {} => {
            CONFIG.update(deps.storage, |mut cfg| -> StdResult<_> {
                if info.sender != cfg.admin { return Err(StdError::generic_err("Only admin")); }
                cfg.paused = true;
                Ok(cfg)
            })?;
            Ok(Response::new().add_attribute("action", "pause"))
        }
        ExecuteMsg::Unpause {} => {
            CONFIG.update(deps.storage, |mut cfg| -> StdResult<_> {
                if info.sender != cfg.admin { return Err(StdError::generic_err("Only admin")); }
                cfg.paused = false;
                Ok(cfg)
            })?;
            Ok(Response::new().add_attribute("action", "unpause"))
        }
    }
}

#[entry_point]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::GetConfig {} => to_binary(&CONFIG.load(deps.storage)?),
    }
}