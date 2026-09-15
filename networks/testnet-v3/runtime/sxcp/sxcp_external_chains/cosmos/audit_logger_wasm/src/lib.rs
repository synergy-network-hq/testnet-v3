use cosmwasm_std::{entry_point, to_binary, Addr, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdError, StdResult};
use cw2::set_contract_version;
use cw_storage_plus::Item;

const CONTRACT_NAME: &str = "audit_logger_wasm";
const CONTRACT_VERSION: &str = "0.1.0";

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct LogEntry {
    pub actor: Addr,
    pub event_hash: String,
    pub action: String,
    pub timestamp: u64,
}

pub const HISTORY: Item<Vec<LogEntry>> = Item::new("history");

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExecuteMsg {
    Record { event_hash: String, action: String },
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    GetHistory {},
}

#[entry_point]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    _msg: ()
) -> StdResult<Response> {
    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;
    HISTORY.save(deps.storage, &Vec::new())?;
    Ok(Response::default())
}

#[entry_point]
pub fn execute(deps: DepsMut, env: Env, info: MessageInfo, msg: ExecuteMsg) -> Result<Response, StdError> {
    match msg {
        ExecuteMsg::Record { event_hash, action } => {
            let timestamp = env.block.time.seconds();
            HISTORY.update(deps.storage, |mut history| -> StdResult<_> {
                history.push(LogEntry { actor: info.sender.clone(), event_hash: event_hash.clone(), action: action.clone(), timestamp });
                Ok(history)
            })?;
            Ok(Response::new().add_attribute("action", "record").add_attribute("event_hash", event_hash).add_attribute("actor", info.sender))
        }
    }
}

#[entry_point]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::GetHistory {} => to_binary(&HISTORY.load(deps.storage)?),
    }
}