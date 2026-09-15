use cosmwasm_std::{entry_point, to_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdError, StdResult};
use cw2::set_contract_version;
use cw_storage_plus::Item;

const CONTRACT_NAME: &str = "state_proof_validator_wasm";
const CONTRACT_VERSION: &str = "0.1.0";

// Storage for the current Merkle root
pub const ROOT: Item<String> = Item::new("root");

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExecuteMsg {
    SetRoot { root: String },
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    Verify { leaf: String, proof: Vec<String> },
}

#[entry_point]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    _msg: ()
) -> StdResult<Response> {
    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;
    ROOT.save(deps.storage, &"".to_string())?;
    Ok(Response::default())
}

#[entry_point]
pub fn execute(deps: DepsMut, _env: Env, info: MessageInfo, msg: ExecuteMsg) -> Result<Response, StdError> {
    // In this simple example anyone can set the root
    match msg {
        ExecuteMsg::SetRoot { root } => {
            ROOT.save(deps.storage, &root)?;
            Ok(Response::new().add_attribute("action", "set_root"))
        }
    }
}

#[entry_point]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::Verify { leaf, proof } => {
            let root = ROOT.load(deps.storage)?;
            let mut computed = leaf.clone();
            for sibling in proof.iter() {
                let pair = if computed <= *sibling {
                    format!("{}{}", computed, sibling)
                } else {
                    format!("{}{}", sibling, computed)
                };
                computed = sha256_hex(&pair);
            }
            let valid = computed == root;
            to_binary(&valid)
        }
    }
}

fn sha256_hex(data: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    let result = hasher.finalize();
    hex::encode(result)
}