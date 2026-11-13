use cosmwasm_std::{entry_point, to_binary, Addr, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdError, StdResult};
use cw2::set_contract_version;
use cw_storage_plus::{Item, Map};

const CONTRACT_NAME: &str = "witness_registry_wasm";
const CONTRACT_VERSION: &str = "0.1.0";

// Relayer information
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct RelayerInfo {
    pub active: bool,
    pub reputation: u64,
}

// admin address
pub const ADMIN: Item<Addr> = Item::new("admin");
pub const RELAYERS: Map<&Addr, RelayerInfo> = Map::new("relayers");

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExecuteMsg {
    AddRelayer { relayer: String },
    RemoveRelayer { relayer: String },
    UpdateReputation { relayer: String, delta: i64 },
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    GetRelayer { relayer: String },
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
    let admin = ADMIN.load(deps.storage)?;
    if info.sender != admin {
        return Err(StdError::generic_err("Only admin"));
    }
    match msg {
        ExecuteMsg::AddRelayer { relayer } => {
            let addr = deps.api.addr_validate(&relayer)?;
            RELAYERS.save(deps.storage, &addr, &RelayerInfo { active: true, reputation: 0 })?;
            Ok(Response::new().add_attribute("action", "add_relayer").add_attribute("relayer", relayer))
        }
        ExecuteMsg::RemoveRelayer { relayer } => {
            let addr = deps.api.addr_validate(&relayer)?;
            RELAYERS.remove(deps.storage, &addr);
            Ok(Response::new().add_attribute("action", "remove_relayer").add_attribute("relayer", relayer))
        }
        ExecuteMsg::UpdateReputation { relayer, delta } => {
            let addr = deps.api.addr_validate(&relayer)?;
            RELAYERS.update(deps.storage, &addr, |old| {
                let mut info = old.unwrap_or(RelayerInfo { active: true, reputation: 0 });
                if delta >= 0 {
                    info.reputation = info.reputation.saturating_add(delta as u64);
                } else {
                    let d = (-delta) as u64;
                    if info.reputation > d { info.reputation -= d; } else { info.reputation = 0; }
                }
                Ok(info)
            })?;
            Ok(Response::new().add_attribute("action", "update_reputation").add_attribute("relayer", relayer))
        }
    }
}

#[entry_point]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::GetRelayer { relayer } => {
            let addr = deps.api.addr_validate(&relayer)?;
            let info = RELAYERS.may_load(deps.storage, &addr)?;
            to_binary(&info)
        }
    }
}