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

pub const SYNID_RESOLVE: &str = "synergy_resolveSynID";
pub const SYNID_REVERSE: &str = "synergy_reverseResolveSynID";

pub const PROCESSING_CONTEXT_V1: &str = "synergy_getProcessingContextV1";
pub const PROCESSING_TRANSACTION_SUBMIT_V1: &str = "synergy_submitProcessingTransactionV1";

pub const PROTECTED_ADMISSION_CONTEXT_V2: &str = "synergy_getProtectedAdmissionContextV2";
pub const CHAIN_TELEMETRY: &str = "synergy_chainTelemetry";

pub const PROTECTED_ADMISSION_CONTEXT: &str = "synergy_getProtectedAdmissionContext";
pub const PROTECTED_TRANSACTION_SUBMIT: &str = "synergy_submitProtectedTransaction";
pub const PROTECTED_ADMISSION_STATS: &str = "synergy_getProtectedAdmissionStats";
pub const PROTECTED_ADMISSION_RECEIPT: &str = "synergy_getProtectedAdmissionReceipt";

pub fn method_access(method: &str) -> crate::auth::RpcAccess {
    match method {
        SYSTEM_VERSION
        | NODE_STATUS
        | CHAIN_STATUS
        | BLOCK_GET
        | TRANSACTION_GET
        | SYNID_RESOLVE
        | SYNID_REVERSE
        | ACCOUNT_GET
        | SYNC_STATUS
        | POSY_STATUS
        | ETDAG_STATUS
        | PROTECTED_ADMISSION_CONTEXT
        | PROTECTED_ADMISSION_CONTEXT_V2
        | PROCESSING_CONTEXT_V1
        | PROCESSING_TRANSACTION_SUBMIT_V1
        | CHAIN_TELEMETRY
        | PROTECTED_TRANSACTION_SUBMIT
        | PROTECTED_ADMISSION_RECEIPT
        | PROTECTED_ADMISSION_STATS => crate::auth::RpcAccess::Public,
        PEERS_LIST | VALIDATOR_GET => crate::auth::RpcAccess::Restricted,
        _ => crate::auth::RpcAccess::Restricted,
    }
}
