use cosmwasm_std::{entry_point, to_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdError, StdResult};
use cw2::set_contract_version;
use cw_storage_plus::Item;

const CONTRACT_NAME: &str = "finality_checker_wasm";
const CONTRACT_VERSION: &str = "0.1.0";

// Config with admin and confirmation threshold
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Config {
    pub admin: String,
    pub confirmations: u64,
}

pub const CONFIG: Item<Config> = Item::new("config");

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExecuteMsg {
    Initialize { confirmations: u64 },
    SetConfirmations { confirmations: u64 },
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    IsFinal { block_height: u64 },
}

#[entry_point]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    _msg: ()
) -> StdResult<Response> {
    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;
    CONFIG.save(deps.storage, &Config { admin: info.sender.to_string(), confirmations: 1 })?;
    Ok(Response::default())
}

#[entry_point]
pub fn execute(deps: DepsMut, _env: Env, info: MessageInfo, msg: ExecuteMsg) -> Result<Response, StdError> {
    match msg {
        ExecuteMsg::Initialize { confirmations } => {
            CONFIG.update(deps.storage, |mut cfg| -> StdResult<_> {
                cfg.admin = info.sender.to_string();
                cfg.confirmations = confirmations;
                Ok(cfg)
            })?;
            Ok(Response::new().add_attribute("action", "initialize"))
        }
        ExecuteMsg::SetConfirmations { confirmations } => {
            CONFIG.update(deps.storage, |mut cfg| -> StdResult<_> {
                if info.sender.to_string() != cfg.admin {
                    return Err(StdError::generic_err("Only admin"));
                }
                cfg.confirmations = confirmations;
                Ok(cfg)
            })?;
            Ok(Response::new().add_attribute("action", "set_confirmations"))
        }
    }
}

#[entry_point]
pub fn query(deps: Deps, env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::IsFinal { block_height } => {
            let cfg = CONFIG.load(deps.storage)?;
            let current_height = env.block.height;
            let diff = current_height.saturating_sub(block_height);
            let finality = diff >= cfg.confirmations;
            to_binary(&finality)
        }
    }
}