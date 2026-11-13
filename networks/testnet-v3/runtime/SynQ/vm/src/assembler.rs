use crate::opcode::OpCode;
use crate::vm::Header;

// Assembler for creating bytecode
pub struct Assembler {
    code: Vec<u8>,
    data: Vec<u8>,
    function_count: u32,
}

impl Assembler {
    pub fn new() -> Self {
        Assembler {
            code: Vec::new(),
            data: Vec::new(),
            function_count: 0,
        }
    }

    pub fn emit_op(&mut self, op: OpCode) {
        self.code.push(op as u8);
    }

    pub fn emit_i32(&mut self, value: i32) {
        self.code.extend_from_slice(&value.to_le_bytes());
    }

    pub fn emit_u32(&mut self, value: u32) {
        self.code.extend_from_slice(&value.to_le_bytes());
    }

    /// Emit a 16-byte big-endian u128 literal (for LoadImm128 / UInt256 values).
    pub fn emit_u128(&mut self, v: u128) {
        self.code.extend_from_slice(&v.to_be_bytes());
    }

    /// Emit a 32-byte big-endian U256 literal (for LoadImm256 / full UInt256).
    pub fn emit_u256_bytes(&mut self, bytes: &[u8; 32]) {
        self.code.extend_from_slice(bytes);
    }

    pub fn emit_bytes(&mut self, bytes: &[u8]) {
        self.emit_u32(bytes.len() as u32);
        self.code.extend_from_slice(bytes);
    }

    /// Returns the current write position (byte offset) in the code buffer.
    /// Used to record jump targets (e.g. a function's entry address, or the
    /// address right after a conditional block) for later backpatching.
    pub fn current_pos(&self) -> usize {
        self.code.len()
    }

    /// Emits a 4-byte placeholder (zeros) at the current position and
    /// returns its offset so it can later be overwritten via `patch_u32`
    /// once the real target address is known (forward-jump backpatching,
    /// e.g. for `require()` aborts and forward-referenced function calls).
    pub fn emit_placeholder_u32(&mut self) -> usize {
        let pos = self.code.len();
        self.code.extend_from_slice(&0u32.to_le_bytes());
        pos
    }

    /// Overwrites a previously emitted placeholder (or any 4-byte code
    /// location) with the given value.
    pub fn patch_u32(&mut self, pos: usize, value: u32) {
        let bytes = value.to_le_bytes();
        self.code[pos..pos + 4].copy_from_slice(&bytes);
    }

    /// Registers a function in the dispatch table (stored in the data
    /// section) so the VM can resolve calls by name at runtime.
    pub fn add_function_entry(
        &mut self,
        name: &str,
        address: u32,
        param_addresses: &[u32],
        has_return: bool,
    ) {
        let name_bytes = name.as_bytes();
        self.data
            .extend_from_slice(&(name_bytes.len() as u32).to_le_bytes());
        self.data.extend_from_slice(name_bytes);
        self.data.extend_from_slice(&address.to_le_bytes());
        self.data
            .extend_from_slice(&(param_addresses.len() as u32).to_le_bytes());
        for addr in param_addresses {
            self.data.extend_from_slice(&addr.to_le_bytes());
        }
        self.data.push(if has_return { 1 } else { 0 });
        self.function_count += 1;
    }

    pub fn build(self) -> Vec<u8> {
        let mut bytecode = Vec::new();

        // Header
        bytecode.extend_from_slice(&Header::MAGIC.to_le_bytes());
        bytecode.push(1); // version
        bytecode.extend_from_slice(&15u16.to_le_bytes()); // header length
        bytecode.extend_from_slice(&(self.code.len() as u32).to_le_bytes());

        // Data section: function count prefix, then each encoded FunctionEntry.
        let mut data = Vec::new();
        data.extend_from_slice(&self.function_count.to_le_bytes());
        data.extend_from_slice(&self.data);

        bytecode.extend_from_slice(&(data.len() as u32).to_le_bytes());

        // Code and data
        bytecode.extend_from_slice(&self.code);
        bytecode.extend_from_slice(&data);

        bytecode
    }
}
