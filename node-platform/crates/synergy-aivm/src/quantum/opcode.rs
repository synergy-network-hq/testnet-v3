use std::fmt;

// Error types
#[derive(Debug, Clone)]
pub enum VMError {
    InvalidBytecode(String),
    StackUnderflow(String),
    StackOverflow(String),
    InvalidInstruction(u8),
    InvalidAddress(String),
    CryptoError(String),
    RuntimeError(String),
    OutOfGas(String),
}

impl fmt::Display for VMError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            VMError::InvalidBytecode(msg) => write!(f, "Invalid bytecode: {}", msg),
            VMError::StackUnderflow(msg) => write!(f, "Stack underflow: {}", msg),
            VMError::StackOverflow(msg) => write!(f, "Stack overflow: {}", msg),
            VMError::InvalidInstruction(op) => write!(
                f,
                "Invalid instruction: 0x{:02x} (unknown opcode at this location)",
                op
            ),
            VMError::InvalidAddress(msg) => write!(f, "Invalid address: {}", msg),
            VMError::CryptoError(msg) => write!(f, "Cryptographic operation failed: {}", msg),
            VMError::RuntimeError(msg) => write!(f, "Runtime error: {}", msg),
            VMError::OutOfGas(msg) => write!(f, "Out of gas: {}", msg),
        }
    }
}

impl std::error::Error for VMError {}

// Instruction opcodes
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum OpCode {
    // Stack operations
    Push = 0x01,
    Pop = 0x02,
    Dup = 0x03,
    Swap = 0x04,

    // Arithmetic operations
    Add = 0x10,
    Sub = 0x11,
    Mul = 0x12,
    Div = 0x13,

    // Comparison operations
    Eq = 0x20,
    Ne = 0x21,
    Lt = 0x22,
    Le = 0x23,
    Gt = 0x24,
    Ge = 0x25,

    // Control flow
    Jump = 0x30,
    JumpIf = 0x31,
    Call = 0x32,
    Return = 0x33,

    // Memory operations
    Load = 0x40,
    Store = 0x41,
    LoadImm = 0x42,

    // PQC operations
    MLDSAVerify = 0x80,
    MLKEMKeyExchange = 0x81,
    FNDSAVerify = 0x82,
    SLHDSAVerify = 0x83,
    HQCKEM128KeyExchange = 0x84,
    HQCKEM192KeyExchange = 0x85,
    HQCKEM256KeyExchange = 0x86,

    // Utility
    Print = 0xF0,
    Halt = 0xFF,
}

impl TryFrom<u8> for OpCode {
    type Error = VMError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(OpCode::Push),
            0x02 => Ok(OpCode::Pop),
            0x03 => Ok(OpCode::Dup),
            0x04 => Ok(OpCode::Swap),
            0x10 => Ok(OpCode::Add),
            0x11 => Ok(OpCode::Sub),
            0x12 => Ok(OpCode::Mul),
            0x13 => Ok(OpCode::Div),
            0x20 => Ok(OpCode::Eq),
            0x21 => Ok(OpCode::Ne),
            0x22 => Ok(OpCode::Lt),
            0x23 => Ok(OpCode::Le),
            0x24 => Ok(OpCode::Gt),
            0x25 => Ok(OpCode::Ge),
            0x30 => Ok(OpCode::Jump),
            0x31 => Ok(OpCode::JumpIf),
            0x32 => Ok(OpCode::Call),
            0x33 => Ok(OpCode::Return),
            0x40 => Ok(OpCode::Load),
            0x41 => Ok(OpCode::Store),
            0x42 => Ok(OpCode::LoadImm),
            0x80 => Ok(OpCode::MLDSAVerify),
            0x81 => Ok(OpCode::MLKEMKeyExchange),
            0x82 => Ok(OpCode::FNDSAVerify),
            0x83 => Ok(OpCode::SLHDSAVerify),
            0x84 => Ok(OpCode::HQCKEM128KeyExchange),
            0x85 => Ok(OpCode::HQCKEM192KeyExchange),
            0x86 => Ok(OpCode::HQCKEM256KeyExchange),
            0xF0 => Ok(OpCode::Print),
            0xFF => Ok(OpCode::Halt),
            _ => Err(VMError::InvalidInstruction(value)),
        }
    }
}
