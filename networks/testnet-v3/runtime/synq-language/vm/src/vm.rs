use super::opcode::{OpCode, VMError};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy)]
enum KemOperation {
    MlKem768,
    HqcKem128,
    HqcKem192,
    HqcKem256,
}

// Value types that can be stored on the stack
#[derive(Debug, Clone)]
pub enum Value {
    I32(i32),
    I64(i64),
    Bytes(Vec<u8>),
    Bool(bool),
}

impl Value {
    pub fn as_i32(&self) -> Result<i32, VMError> {
        match self {
            Value::I32(v) => Ok(*v),
            _ => Err(VMError::RuntimeError("Expected i32".to_string())),
        }
    }

    pub fn as_i64(&self) -> Result<i64, VMError> {
        match self {
            Value::I64(v) => Ok(*v),
            Value::I32(v) => Ok(*v as i64),
            _ => Err(VMError::RuntimeError("Expected i64".to_string())),
        }
    }

    pub fn as_bytes(&self) -> Result<&[u8], VMError> {
        match self {
            Value::Bytes(v) => Ok(v),
            _ => Err(VMError::RuntimeError("Expected bytes".to_string())),
        }
    }

    pub fn as_bool(&self) -> Result<bool, VMError> {
        match self {
            Value::Bool(v) => Ok(*v),
            Value::I32(v) => Ok(*v != 0),
            _ => Err(VMError::RuntimeError("Expected bool".to_string())),
        }
    }
}

// Bytecode header
#[derive(Debug)]
pub struct Header {
    pub magic: u32,
    pub version: u8,
    pub header_length: u16,
    pub code_length: u32,
    pub data_length: u32,
}

impl Header {
    pub const MAGIC: u32 = 0x51564D00; // QVM\0

    pub fn parse(bytes: &[u8]) -> Result<Self, VMError> {
        if bytes.len() < 15 {
            return Err(VMError::InvalidBytecode("Header too short".to_string()));
        }

        let magic = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if magic != Self::MAGIC {
            return Err(VMError::InvalidBytecode("Invalid magic number".to_string()));
        }

        let version = bytes[4];
        let header_length = u16::from_le_bytes([bytes[5], bytes[6]]);
        let code_length = u32::from_le_bytes([bytes[7], bytes[8], bytes[9], bytes[10]]);
        let data_length = u32::from_le_bytes([bytes[11], bytes[12], bytes[13], bytes[14]]);

        Ok(Header {
            magic,
            version,
            header_length,
            code_length,
            data_length,
        })
    }
}

// Gas meter for tracking gas consumption
pub struct GasMeter {
    pub remaining: u64,
    pub consumed: u64,
    pub pqc_consumed: u64,
    pub max_pqc_per_tx: u64,
}

impl GasMeter {
    pub fn new(initial: u64, max_pqc_per_tx: u64) -> Self {
        GasMeter {
            remaining: initial,
            consumed: 0,
            pqc_consumed: 0,
            max_pqc_per_tx,
        }
    }

    pub fn consume(&mut self, amount: u64) -> Result<(), VMError> {
        if self.remaining < amount {
            return Err(VMError::OutOfGas(format!(
                "Insufficient gas: required {}, remaining {}",
                amount, self.remaining
            )));
        }
        self.remaining -= amount;
        self.consumed += amount;
        Ok(())
    }

    pub fn consume_pqc(&mut self, amount: u64) -> Result<(), VMError> {
        if self.pqc_consumed + amount > self.max_pqc_per_tx {
            return Err(VMError::OutOfGas(format!(
                "PQC gas limit exceeded: consumed {}, limit {}, attempting to consume {}",
                self.pqc_consumed, self.max_pqc_per_tx, amount
            )));
        }
        self.consume(amount)?;
        self.pqc_consumed += amount;
        Ok(())
    }
}

// The main VM struct
pub struct QuantumVM {
    pub stack: Vec<Value>,
    memory: HashMap<usize, Value>,
    code: Vec<u8>,
    data: Vec<u8>,
    pc: usize,
    call_stack: Vec<usize>,
    halted: bool,
    gas_meter: GasMeter,
}

impl Default for QuantumVM {
    fn default() -> Self {
        Self::new()
    }
}

impl QuantumVM {
    pub fn new() -> Self {
        QuantumVM::with_gas(10_000_000, 300_000) // Default: 10M gas, 300K PQC gas limit
    }

    pub fn with_gas(initial_gas: u64, max_pqc_gas: u64) -> Self {
        QuantumVM {
            stack: Vec::new(),
            memory: HashMap::new(),
            code: Vec::new(),
            data: Vec::new(),
            pc: 0,
            call_stack: Vec::new(),
            halted: false,
            gas_meter: GasMeter::new(initial_gas, max_pqc_gas),
        }
    }

    pub fn remaining_gas(&self) -> u64 {
        self.gas_meter.remaining
    }

    pub fn consumed_gas(&self) -> u64 {
        self.gas_meter.consumed
    }

    pub fn consumed_pqc_gas(&self) -> u64 {
        self.gas_meter.pqc_consumed
    }

    pub fn load_bytecode(&mut self, bytecode: &[u8]) -> Result<(), VMError> {
        let header = Header::parse(bytecode)?;

        let header_end = header.header_length as usize;
        let code_end = header_end + header.code_length as usize;
        let data_end = code_end + header.data_length as usize;

        if bytecode.len() < data_end {
            return Err(VMError::InvalidBytecode("Bytecode too short".to_string()));
        }

        self.code = bytecode[header_end..code_end].to_vec();
        self.data = bytecode[code_end..data_end].to_vec();
        self.pc = 0;
        self.halted = false;

        Ok(())
    }

    pub fn execute(&mut self) -> Result<(), VMError> {
        while !self.halted && self.pc < self.code.len() {
            self.execute_instruction()?;
        }
        Ok(())
    }

    fn execute_instruction(&mut self) -> Result<(), VMError> {
        if self.pc >= self.code.len() {
            return Err(VMError::InvalidAddress(format!(
                "Program counter {} exceeds code length {}",
                self.pc,
                self.code.len()
            )));
        }

        let opcode = OpCode::try_from(self.code[self.pc])?;
        self.pc += 1;

        // Consume base gas for instruction execution
        self.gas_meter.consume(1)?;

        match opcode {
            OpCode::Push => {
                let value = self.read_i32()?;
                self.push(Value::I32(value))?;
            }
            OpCode::Pop => {
                self.pop()?;
            }
            OpCode::Dup => {
                let value = self.peek()?.clone();
                self.push(value)?;
            }
            OpCode::Swap => {
                let a = self.pop()?;
                let b = self.pop()?;
                self.push(a)?;
                self.push(b)?;
            }
            OpCode::Add => {
                let b = self.pop()?.as_i32()?;
                let a = self.pop()?.as_i32()?;
                self.push(Value::I32(a + b))?;
            }
            OpCode::Sub => {
                let b = self.pop()?.as_i32()?;
                let a = self.pop()?.as_i32()?;
                self.push(Value::I32(a - b))?;
            }
            OpCode::Mul => {
                let b = self.pop()?.as_i32()?;
                let a = self.pop()?.as_i32()?;
                self.push(Value::I32(a * b))?;
            }
            OpCode::Div => {
                let b = self.pop()?.as_i32()?;
                let a = self.pop()?.as_i32()?;
                if b == 0 {
                    return Err(VMError::RuntimeError(format!(
                        "Division by zero: attempted to divide {} by 0 at PC {}",
                        a,
                        self.pc - 1
                    )));
                }
                self.gas_meter.consume(5)?; // Division is more expensive
                self.push(Value::I32(a / b))?;
            }
            OpCode::Eq => {
                let b = self.pop()?.as_i32()?;
                let a = self.pop()?.as_i32()?;
                self.push(Value::Bool(a == b))?;
            }
            OpCode::Ne => {
                let b = self.pop()?.as_i32()?;
                let a = self.pop()?.as_i32()?;
                self.push(Value::Bool(a != b))?;
            }
            OpCode::Lt => {
                let b = self.pop()?.as_i32()?;
                let a = self.pop()?.as_i32()?;
                self.push(Value::Bool(a < b))?;
            }
            OpCode::Le => {
                let b = self.pop()?.as_i32()?;
                let a = self.pop()?.as_i32()?;
                self.push(Value::Bool(a <= b))?;
            }
            OpCode::Gt => {
                let b = self.pop()?.as_i32()?;
                let a = self.pop()?.as_i32()?;
                self.push(Value::Bool(a > b))?;
            }
            OpCode::Ge => {
                let b = self.pop()?.as_i32()?;
                let a = self.pop()?.as_i32()?;
                self.push(Value::Bool(a >= b))?;
            }
            OpCode::Jump => {
                let addr = self.read_u32()? as usize;
                self.gas_meter.consume(2)?; // Jump cost
                if addr >= self.code.len() {
                    return Err(VMError::InvalidAddress(format!(
                        "Jump target {} exceeds code length {} at PC {}",
                        addr,
                        self.code.len(),
                        self.pc - 5
                    )));
                }
                self.pc = addr;
            }
            OpCode::JumpIf => {
                let addr = self.read_u32()? as usize;
                let condition = self.pop()?.as_bool()?;
                self.gas_meter.consume(2)?; // Conditional jump cost
                if condition {
                    if addr >= self.code.len() {
                        return Err(VMError::InvalidAddress(format!(
                            "JumpIf target {} exceeds code length {} at PC {}",
                            addr,
                            self.code.len(),
                            self.pc - 5
                        )));
                    }
                    self.pc = addr;
                }
            }
            OpCode::Call => {
                let addr = self.read_u32()? as usize;
                self.gas_meter.consume(10)?; // Function call overhead
                if addr >= self.code.len() {
                    return Err(VMError::InvalidAddress(format!(
                        "Call target {} exceeds code length {} at PC {}",
                        addr,
                        self.code.len(),
                        self.pc - 5
                    )));
                }
                self.call_stack.push(self.pc);
                self.pc = addr;
            }
            OpCode::Return => {
                self.gas_meter.consume(3)?; // Return cost
                if let Some(return_addr) = self.call_stack.pop() {
                    self.pc = return_addr;
                } else {
                    // Top-level return is treated as program completion.
                    self.halted = true;
                }
            }
            OpCode::Load => {
                let addr = self.pop()?.as_i32()? as usize;
                self.gas_meter.consume(3)?; // Memory load cost
                if let Some(value) = self.memory.get(&addr) {
                    self.push(value.clone())?;
                } else {
                    return Err(VMError::InvalidAddress(format!(
                        "Memory address {} not found. Valid addresses: {:?}",
                        addr,
                        self.memory.keys().take(10).collect::<Vec<_>>()
                    )));
                }
            }
            OpCode::Store => {
                let addr = self.pop()?.as_i32()? as usize;
                let value = self.pop()?;
                self.gas_meter.consume(5)?; // Memory store cost (higher than load)
                self.memory.insert(addr, value);
            }
            OpCode::LoadImm => {
                let len = self.read_u32()? as usize;
                let bytes = self.read_bytes(len)?;
                self.push(Value::Bytes(bytes))?;
            }
            OpCode::MLDSAVerify => {
                let public_key = self.pop()?.as_bytes()?.to_vec();
                let message = self.pop()?.as_bytes()?.to_vec();
                let signature = self.pop()?.as_bytes()?.to_vec();

                // Calculate gas cost: base + data cost + compute cost
                // Base: 6000, Data: ~9 per byte, Compute: 20000
                let data_cost = (public_key.len() + message.len() + signature.len()) as u64 * 9;
                let gas_cost = 6000 + data_cost + 20000;
                self.gas_meter.consume_pqc(gas_cost)?;

                let result = verify_mldsa65(&message, &signature, &public_key)?;
                self.push(Value::Bool(result))?;
            }
            OpCode::MLKEMKeyExchange => {
                self.execute_kem_key_exchange(
                    KemOperation::MlKem768,
                    "ML-KEM-768",
                    5000,
                    6,
                    14000,
                )?;
            }
            OpCode::FNDSAVerify => {
                let public_key = self.pop()?.as_bytes()?.to_vec();
                let message = self.pop()?.as_bytes()?.to_vec();
                let signature = self.pop()?.as_bytes()?.to_vec();

                // Calculate gas cost: base + data cost + compute cost
                // Base: 4000, Data: ~6 per byte, Compute: 10000
                let data_cost = (public_key.len() + message.len() + signature.len()) as u64 * 6;
                let gas_cost = 4000 + data_cost + 10000;
                self.gas_meter.consume_pqc(gas_cost)?;

                let result = verify_fndsa512(&message, &signature, &public_key)?;
                self.push(Value::Bool(result))?;
            }
            OpCode::SLHDSAVerify => {
                return Err(VMError::CryptoError(
                    "SLH-DSA is not enabled in this SynQ build".to_string(),
                ));
            }
            OpCode::HQCKEM128KeyExchange => {
                self.execute_kem_key_exchange(
                    KemOperation::HqcKem128,
                    "HQC-KEM-128",
                    6500,
                    7,
                    22000,
                )?;
            }
            OpCode::HQCKEM192KeyExchange => {
                self.execute_kem_key_exchange(
                    KemOperation::HqcKem192,
                    "HQC-KEM-192",
                    7000,
                    7,
                    26000,
                )?;
            }
            OpCode::HQCKEM256KeyExchange => {
                self.execute_kem_key_exchange(
                    KemOperation::HqcKem256,
                    "HQC-KEM-256",
                    7500,
                    7,
                    32000,
                )?;
            }
            OpCode::Print => {
                let value = self.pop()?;
                println!("{:?}", value);
            }
            OpCode::Halt => {
                self.halted = true;
            }
        }

        Ok(())
    }

    fn execute_kem_key_exchange(
        &mut self,
        operation: KemOperation,
        algorithm_name: &str,
        base_cost: u64,
        data_multiplier: u64,
        compute_cost: u64,
    ) -> Result<(), VMError> {
        // This opcode performs decapsulation as per the VM contract interface.
        let private_key = self.pop()?.as_bytes()?.to_vec();
        let ciphertext = self.pop()?.as_bytes()?.to_vec();

        // Dynamic gas model: base + byte-scaled cost + algorithm compute weight.
        let data_cost = (private_key.len() + ciphertext.len()) as u64 * data_multiplier;
        let gas_cost = base_cost + data_cost + compute_cost;
        self.gas_meter.consume_pqc(gas_cost)?;

        let shared_secret = decapsulate(operation, &ciphertext, &private_key).map_err(|e| {
            VMError::CryptoError(format!("{algorithm_name} decapsulation failed: {e}"))
        })?;
        self.push(Value::Bytes(shared_secret))?;
        Ok(())
    }

    fn push(&mut self, value: Value) -> Result<(), VMError> {
        if self.stack.len() >= 1000 {
            return Err(VMError::StackOverflow(format!(
                "Stack overflow: maximum stack size (1000) exceeded. Current size: {}",
                self.stack.len()
            )));
        }
        self.gas_meter.consume(1)?; // Stack push cost
        self.stack.push(value);
        Ok(())
    }

    fn pop(&mut self) -> Result<Value, VMError> {
        self.gas_meter.consume(1)?; // Stack pop cost
        self.stack.pop().ok_or_else(|| {
            VMError::StackUnderflow(format!(
                "Stack underflow: attempted to pop from empty stack at PC {}",
                self.pc
            ))
        })
    }

    fn peek(&self) -> Result<&Value, VMError> {
        self.stack.last().ok_or_else(|| {
            VMError::StackUnderflow(format!(
                "Stack underflow: attempted to peek empty stack at PC {}",
                self.pc
            ))
        })
    }

    fn read_i32(&mut self) -> Result<i32, VMError> {
        if self.pc + 4 > self.code.len() {
            return Err(VMError::InvalidAddress(format!(
                "Cannot read i32: need 4 bytes but only {} bytes remaining at PC {}",
                self.code.len() - self.pc,
                self.pc
            )));
        }
        let bytes = [
            self.code[self.pc],
            self.code[self.pc + 1],
            self.code[self.pc + 2],
            self.code[self.pc + 3],
        ];
        self.pc += 4;
        Ok(i32::from_le_bytes(bytes))
    }

    fn read_u32(&mut self) -> Result<u32, VMError> {
        if self.pc + 4 > self.code.len() {
            return Err(VMError::InvalidAddress(format!(
                "Cannot read u32: need 4 bytes but only {} bytes remaining at PC {}",
                self.code.len() - self.pc,
                self.pc
            )));
        }
        let bytes = [
            self.code[self.pc],
            self.code[self.pc + 1],
            self.code[self.pc + 2],
            self.code[self.pc + 3],
        ];
        self.pc += 4;
        Ok(u32::from_le_bytes(bytes))
    }

    fn read_bytes(&mut self, len: usize) -> Result<Vec<u8>, VMError> {
        if self.pc + len > self.code.len() {
            return Err(VMError::InvalidAddress(format!(
                "Cannot read {} bytes: only {} bytes remaining at PC {}",
                len,
                self.code.len() - self.pc,
                self.pc
            )));
        }
        let bytes = self.code[self.pc..self.pc + len].to_vec();
        self.pc += len;
        Ok(bytes)
    }
}

#[cfg(not(feature = "pqc-aegis"))]
fn missing_pqc_backend_error() -> VMError {
    VMError::CryptoError(
        "aegis-pqsynq backend is unavailable; restore aegis-pqsynq/pqsynq and rebuild with feature `pqc-aegis`".to_string(),
    )
}

#[cfg(not(feature = "pqc-aegis"))]
fn verify_mldsa65(_message: &[u8], _signature: &[u8], _public_key: &[u8]) -> Result<bool, VMError> {
    Err(missing_pqc_backend_error())
}

#[cfg(feature = "pqc-aegis")]
fn verify_mldsa65(message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool, VMError> {
    use pqsynq::{DigitalSignature, Sign};

    let signer = Sign::mldsa65();
    Ok(signer
        .verify(message, signature, public_key)
        .unwrap_or(false))
}

#[cfg(not(feature = "pqc-aegis"))]
fn verify_fndsa512(
    _message: &[u8],
    _signature: &[u8],
    _public_key: &[u8],
) -> Result<bool, VMError> {
    Err(missing_pqc_backend_error())
}

#[cfg(feature = "pqc-aegis")]
fn verify_fndsa512(message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool, VMError> {
    use pqsynq::{DigitalSignature, Sign};

    let signer = Sign::fndsa512();
    Ok(signer
        .verify(message, signature, public_key)
        .unwrap_or(false))
}

#[cfg(not(feature = "pqc-aegis"))]
fn decapsulate(
    _operation: KemOperation,
    _ciphertext: &[u8],
    _private_key: &[u8],
) -> Result<Vec<u8>, String> {
    Err("aegis-pqsynq backend is unavailable; restore aegis-pqsynq/pqsynq and rebuild with feature `pqc-aegis`".to_string())
}

#[cfg(feature = "pqc-aegis")]
fn decapsulate(
    operation: KemOperation,
    ciphertext: &[u8],
    private_key: &[u8],
) -> Result<Vec<u8>, String> {
    use pqsynq::{Kem, KeyEncapsulation};

    let kem = match operation {
        KemOperation::MlKem768 => Kem::mlkem768(),
        KemOperation::HqcKem128 => Kem::hqckem128(),
        KemOperation::HqcKem192 => Kem::hqckem192(),
        KemOperation::HqcKem256 => Kem::hqckem256(),
    };

    kem.decapsulate(ciphertext, private_key)
        .map_err(|e| format!("{e:?}"))
}
