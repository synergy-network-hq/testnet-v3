use std::fmt;

// Error types
#[derive(Debug, Clone)]
pub enum VMError {
    InvalidBytecode(String),
    StackUnderflow,
    StackOverflow,
    InvalidInstruction(u8),
    InvalidAddress(usize),
    CryptoError(String),
    RuntimeError(String),
    Reverted(String), // require() failure — carries the require message
}

impl fmt::Display for VMError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            VMError::InvalidBytecode(msg) => write!(f, "Invalid bytecode: {}", msg),
            VMError::StackUnderflow => write!(f, "Stack underflow"),
            VMError::StackOverflow => write!(f, "Stack overflow"),
            VMError::InvalidInstruction(op) => write!(f, "Invalid instruction: 0x{:02x}", op),
            VMError::InvalidAddress(addr) => write!(f, "Invalid address: {}", addr),
            VMError::CryptoError(msg) => write!(f, "Crypto error: {}", msg),
            VMError::RuntimeError(msg) => write!(f, "Runtime error: {}", msg),
            VMError::Reverted(msg) => write!(f, "require failed: {}", msg),
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
    Revert = 0x34, // require() failure — followed by 4-byte LE len + message bytes

    // Memory operations
    Load = 0x40,
    Store = 0x41,
    LoadImm = 0x42,    // push raw bytes (strings / PQC keys)
    LoadImm128 = 0x43, // push a 16-byte big-endian u128 (UInt256 values)
    LoadImm256 = 0x44, // push a 32-byte big-endian U256 (full Ethereum address / real UInt256)

    // PQC operations
    DilithiumVerify = 0x80,
    KyberKeyExchange = 0x81,
    FalconVerify = 0x82,
    SphincsVerify = 0x83,

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
            0x34 => Ok(OpCode::Revert),
            0x40 => Ok(OpCode::Load),
            0x41 => Ok(OpCode::Store),
            0x42 => Ok(OpCode::LoadImm),
            0x43 => Ok(OpCode::LoadImm128),
            0x44 => Ok(OpCode::LoadImm256),
            0x80 => Ok(OpCode::DilithiumVerify),
            0x81 => Ok(OpCode::KyberKeyExchange),
            0x82 => Ok(OpCode::FalconVerify),
            0x83 => Ok(OpCode::SphincsVerify),
            0xF0 => Ok(OpCode::Print),
            0xFF => Ok(OpCode::Halt),
            _ => Err(VMError::InvalidInstruction(value)),
        }
    }
}
