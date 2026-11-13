pub mod abi;
pub mod cosmwasm;
pub mod evm;
#[path = "move/mod.rs"]
pub mod move_vm;
pub mod solana;
pub mod substrate;

#[derive(Debug, thiserror::Error)]
pub enum IntegrationError {
    #[error("unsupported operation: {0}")]
    Unsupported(&'static str),
    #[error("invalid payload: {0}")]
    InvalidPayload(&'static str),
}
