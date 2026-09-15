mod account;
mod block;
mod chain;
mod etdag;
mod node;
mod peers;
mod posy;
mod sync;
mod system;
mod transaction;
mod validator;

pub use account::{AccountQuery, ACCOUNT_GET};
pub use block::{BlockQuery, BLOCK_GET};
pub use chain::{ChainQuery, CHAIN_STATUS};
pub use etdag::{EtdagQuery, ETDAG_STATUS};
pub use node::NODE_STATUS;
pub use peers::{PeerQuery, PEERS_LIST};
pub use posy::{PosyQuery, POSY_STATUS};
pub use sync::SYNC_STATUS;
pub use system::SYSTEM_VERSION;
pub use transaction::{TransactionQuery, TRANSACTION_GET};
pub use validator::{ValidatorQuery, VALIDATOR_GET};

pub fn method_access(method: &str) -> crate::auth::RpcAccess {
    match method {
        SYSTEM_VERSION | NODE_STATUS | CHAIN_STATUS | BLOCK_GET | TRANSACTION_GET | ACCOUNT_GET
        | SYNC_STATUS | POSY_STATUS | ETDAG_STATUS => crate::auth::RpcAccess::Public,
        PEERS_LIST | VALIDATOR_GET => crate::auth::RpcAccess::Restricted,
        _ => crate::auth::RpcAccess::Restricted,
    }
}
