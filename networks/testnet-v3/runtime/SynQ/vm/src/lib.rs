pub mod assembler;
pub mod opcode;
pub mod vm;

// Re-export for convenience
pub use assembler::Assembler;
pub use opcode::{OpCode, VMError};
pub use vm::{QuantumVM, Value};
