//! SynQ bytecode generator
//! Generates .synq bytecode files for the QuantumVM

use crate::ast::*;
use quantumvm::{Assembler, OpCode};

pub struct CodeGenerator {
    assembler: Assembler,
    function_labels: std::collections::HashMap<String, usize>,
    current_function: Option<String>,
    jump_patches: Vec<(usize, String)>, // (address_position, label)
    label_positions: std::collections::HashMap<String, usize>,
}

impl CodeGenerator {
    pub fn new() -> Self {
        CodeGenerator {
            assembler: Assembler::new(),
            function_labels: std::collections::HashMap::new(),
            current_function: None,
            jump_patches: Vec::new(),
            label_positions: std::collections::HashMap::new(),
        }
    }

    pub fn generate(mut self, ast: &[SourceUnit]) -> Result<Vec<u8>, String> {
        // First pass: collect function labels and their positions
        for item in ast {
            self.collect_functions(item)?;
        }

        // Second pass: generate code with proper label resolution
        for item in ast {
            self.gen_source_unit(item)?;
        }

        // Third pass: patch jump addresses
        self.patch_jumps()?;

        Ok(self.assembler.build())
    }

    fn patch_jumps(&mut self) -> Result<(), String> {
        for (patch_pos, label) in &self.jump_patches {
            if let Some(&target_pos) = self.label_positions.get(label) {
                let addr = target_pos as u32;
                self.assembler.patch_u32(*patch_pos, addr)?;
            } else {
                return Err(format!("Undefined label: {}", label));
            }
        }
        Ok(())
    }

    fn collect_functions(&mut self, unit: &SourceUnit) -> Result<(), String> {
        if let SourceUnit::Contract(c) = unit {
            for part in &c.parts {
                if let ContractPart::Function(f) = part {
                    let label = format!("{}_{}", c.name, f.name);
                    // Store current code position as function label
                    let pos = self.assembler.code_len();
                    self.function_labels.insert(label.clone(), pos);
                    self.label_positions.insert(label, pos);
                }
            }
        }
        Ok(())
    }

    fn gen_source_unit(&mut self, unit: &SourceUnit) -> Result<(), String> {
        match unit {
            SourceUnit::Struct(_) => {
                // Structs are metadata only, no bytecode
                Ok(())
            }
            SourceUnit::Contract(c) => self.gen_contract(c),
            SourceUnit::Event(_) => {
                // Events are metadata only
                Ok(())
            }
        }
    }

    fn gen_contract(&mut self, c: &ContractDefinition) -> Result<(), String> {
        // Generate constructor if present
        for part in &c.parts {
            if let ContractPart::Constructor(ctor) = part {
                self.gen_constructor(ctor)?;
            }
        }

        // Generate functions
        for part in &c.parts {
            match part {
                ContractPart::Function(f) => {
                    self.current_function = Some(format!("{}_{}", c.name, f.name));
                    self.gen_function(f)?;
                    self.current_function = None;
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn gen_constructor(&mut self, ctor: &ConstructorDefinition) -> Result<(), String> {
        // Generate constructor bytecode
        self.gen_block(&ctor.body)?;
        self.assembler.emit_op(OpCode::Return);
        Ok(())
    }

    fn gen_function(&mut self, f: &FunctionDefinition) -> Result<(), String> {
        // Generate function prologue
        // Push function parameters onto stack (simplified)

        // Generate function body
        self.gen_block(&f.body)?;

        // Generate return if needed
        if f.returns.is_some() {
            // Return value should be on stack
            self.assembler.emit_op(OpCode::Return);
        } else {
            self.assembler.emit_op(OpCode::Return);
        }

        Ok(())
    }

    fn gen_block(&mut self, block: &Block) -> Result<(), String> {
        for stmt in &block.statements {
            self.gen_statement(stmt)?;
        }
        Ok(())
    }

    fn gen_statement(&mut self, stmt: &Statement) -> Result<(), String> {
        match stmt {
            Statement::VariableDeclaration(name, _ty, expr) => {
                if let Some(ref expr) = expr {
                    self.gen_expression(expr)?;
                } else {
                    // Keep declared variables addressable even when parser could not recover an initializer.
                    self.assembler.emit_op(OpCode::Push);
                    self.assembler.emit_u32(0);
                }
                self.emit_variable_store(name);
            }
            Statement::Assignment(name, expr) => {
                self.gen_expression(expr)?;
                self.emit_variable_store(name);
            }
            Statement::Return(expr) => {
                if let Some(ref expr) = expr {
                    self.gen_expression(expr)?;
                }
                self.assembler.emit_op(OpCode::Return);
            }
            Statement::Require(expr, _msg) => {
                self.gen_expression(expr)?;
                // Jump to error handler if condition is false
                let error_label = format!(
                    "{}_require_error",
                    self.current_function
                        .as_ref()
                        .unwrap_or(&"global".to_string())
                );
                self.assembler.emit_op(OpCode::JumpIf);
                let patch_pos = self.assembler.code_len();
                self.assembler.emit_u32(0);
                self.jump_patches.push((patch_pos, error_label.clone()));
                // Error handler would emit revert - for now, halt
                self.label_positions
                    .insert(error_label, self.assembler.code_len());
                self.assembler.emit_op(OpCode::Halt);
            }
            Statement::Revert(_msg) => {
                // Revert operation - halt execution
                self.assembler.emit_op(OpCode::Halt);
            }
            Statement::If(cond, then_block, else_block) => {
                self.gen_expression(cond)?;

                // Emit JumpIf to skip then block if condition is false
                let else_label = format!(
                    "{}_if_else_{}",
                    self.current_function
                        .as_ref()
                        .unwrap_or(&"global".to_string()),
                    self.assembler.code_len()
                );
                let end_label = format!(
                    "{}_if_end_{}",
                    self.current_function
                        .as_ref()
                        .unwrap_or(&"global".to_string()),
                    self.assembler.code_len()
                );

                self.assembler.emit_op(OpCode::JumpIf);
                let patch_pos = self.assembler.code_len();
                self.assembler.emit_u32(0);
                self.jump_patches.push((patch_pos, else_label.clone()));

                // Generate then block
                self.gen_block(then_block)?;

                if else_block.is_some() {
                    // Emit Jump to skip else block
                    self.assembler.emit_op(OpCode::Jump);
                    let patch_pos = self.assembler.code_len();
                    self.assembler.emit_u32(0);
                    self.jump_patches.push((patch_pos, end_label.clone()));

                    // Mark else block start
                    self.label_positions
                        .insert(else_label, self.assembler.code_len());

                    // Generate else block
                    if let Some(ref else_block) = else_block {
                        self.gen_block(else_block)?;
                    }

                    // Mark end of if statement
                    self.label_positions
                        .insert(end_label, self.assembler.code_len());
                } else {
                    // No else block, mark else label as end
                    self.label_positions
                        .insert(else_label, self.assembler.code_len());
                }
            }
            Statement::Emit(event_name, args) => {
                // Event emission - push event name and args
                // Push event name hash as identifier
                use std::collections::hash_map::DefaultHasher;
                use std::hash::{Hash, Hasher};
                let mut hasher = DefaultHasher::new();
                event_name.hash(&mut hasher);
                let event_id = hasher.finish() as u32;
                self.assembler.emit_op(OpCode::Push);
                self.assembler.emit_u32(event_id);

                // Push arguments
                for arg in args {
                    self.gen_expression(arg)?;
                }
                // Event logging would be handled by VM runtime
            }
            Statement::RequirePqc(pqc_block, fallback) => {
                // require_pqc block: execute block, if any PQC verification fails, execute fallback
                // The block should contain PQC verification calls
                // If all verifications pass, continue; otherwise execute fallback (revert/return)

                let success_label = format!(
                    "{}_require_pqc_success_{}",
                    self.current_function
                        .as_ref()
                        .unwrap_or(&"global".to_string()),
                    self.assembler.code_len()
                );
                let failure_label = format!(
                    "{}_require_pqc_failure_{}",
                    self.current_function
                        .as_ref()
                        .unwrap_or(&"global".to_string()),
                    self.assembler.code_len()
                );
                let end_label = format!(
                    "{}_require_pqc_end_{}",
                    self.current_function
                        .as_ref()
                        .unwrap_or(&"global".to_string()),
                    self.assembler.code_len()
                );

                // Execute the PQC block
                // Each PQC verification in the block should push a bool result
                self.gen_block(pqc_block)?;

                // After the block, check if all verifications passed
                // For simplicity, we assume the last value on stack is the verification result
                // In a full implementation, we'd track all verification results
                self.assembler.emit_op(OpCode::JumpIf);
                let patch_pos = self.assembler.code_len();
                self.assembler.emit_u32(0);
                self.jump_patches.push((patch_pos, failure_label.clone()));

                // Success path - jump to end
                self.label_positions
                    .insert(success_label.clone(), self.assembler.code_len());
                self.assembler.emit_op(OpCode::Jump);
                let patch_pos = self.assembler.code_len();
                self.assembler.emit_u32(0);
                self.jump_patches.push((patch_pos, end_label.clone()));

                // Failure path - execute fallback
                self.label_positions
                    .insert(failure_label, self.assembler.code_len());
                if let Some(fallback_stmt) = fallback.as_deref() {
                    match fallback_stmt {
                        Statement::Revert(_msg) => {
                            self.assembler.emit_op(OpCode::Halt); // Revert = halt
                        }
                        Statement::Return(expr) => {
                            if let Some(ref expr) = expr {
                                self.gen_expression(expr)?;
                            }
                            self.assembler.emit_op(OpCode::Return);
                        }
                        _ => {
                            // Default: halt on failure
                            self.assembler.emit_op(OpCode::Halt);
                        }
                    }
                } else {
                    // No fallback specified - default to halt
                    self.assembler.emit_op(OpCode::Halt);
                }

                // End label
                self.label_positions
                    .insert(end_label, self.assembler.code_len());
            }
            Statement::Expression(expr) => {
                self.gen_expression(expr)?;
                // Pop result if not used
                self.assembler.emit_op(OpCode::Pop);
            }
            Statement::For(iterator, start_expr, end_expr, body) => {
                // Canonical lowering for parsed range loops:
                // for (i in start..end) { body }  => i=start; while i<end { body; i=i+1; }
                self.gen_expression(start_expr)?;
                self.emit_variable_store(iterator);

                let loop_id = self.assembler.code_len();
                let loop_check_label = format!(
                    "{}_for_check_{}",
                    self.current_function.as_deref().unwrap_or("global"),
                    loop_id
                );
                let loop_body_label = format!(
                    "{}_for_body_{}",
                    self.current_function.as_deref().unwrap_or("global"),
                    loop_id
                );
                let loop_end_label = format!(
                    "{}_for_end_{}",
                    self.current_function.as_deref().unwrap_or("global"),
                    loop_id
                );

                self.label_positions
                    .insert(loop_check_label.clone(), self.assembler.code_len());

                self.emit_variable_load(iterator);
                self.gen_expression(end_expr)?;
                self.assembler.emit_op(OpCode::Lt);
                self.assembler.emit_op(OpCode::JumpIf);
                let patch_pos = self.assembler.code_len();
                self.assembler.emit_u32(0);
                self.jump_patches.push((patch_pos, loop_body_label.clone()));

                // Condition failed; jump to loop end.
                self.assembler.emit_op(OpCode::Jump);
                let patch_pos = self.assembler.code_len();
                self.assembler.emit_u32(0);
                self.jump_patches.push((patch_pos, loop_end_label.clone()));

                self.label_positions
                    .insert(loop_body_label, self.assembler.code_len());
                self.gen_block(body)?;

                // i = i + 1
                self.emit_variable_load(iterator);
                self.assembler.emit_op(OpCode::Push);
                self.assembler.emit_u32(1);
                self.assembler.emit_op(OpCode::Add);
                self.emit_variable_store(iterator);

                self.assembler.emit_op(OpCode::Jump);
                let patch_pos = self.assembler.code_len();
                self.assembler.emit_u32(0);
                self.jump_patches.push((patch_pos, loop_check_label));

                self.label_positions
                    .insert(loop_end_label, self.assembler.code_len());
            }
        }
        Ok(())
    }

    fn gen_expression(&mut self, expr: &Expression) -> Result<(), String> {
        match expr {
            Expression::Literal(lit) => {
                self.gen_literal(lit)?;
            }
            Expression::Identifier(name) => {
                self.emit_variable_load(name);
            }
            Expression::Call(name, args) => {
                // Generate arguments
                for arg in args {
                    self.gen_expression(arg)?;
                }

                // Handle PQC function calls using integration
                use crate::pqc_integration::{KemAlgorithm, PqcIntegration};
                if PqcIntegration::is_pqc_function(name) {
                    if PqcIntegration::is_mldsa_verify_function(name) {
                        self.assembler.emit_op(OpCode::MLDSAVerify);
                    } else if PqcIntegration::is_fndsa_verify_function(name) {
                        self.assembler.emit_op(OpCode::FNDSAVerify);
                    } else if PqcIntegration::is_slhdsa_verify_function(name) {
                        self.assembler.emit_op(OpCode::SLHDSAVerify);
                    } else if PqcIntegration::is_mlkem_family_function(name)
                        || PqcIntegration::is_hqckem_family_function(name)
                    {
                        match PqcIntegration::get_kem_algorithm(name) {
                            Some(KemAlgorithm::Hqckem128) => {
                                self.assembler.emit_op(OpCode::HQCKEM128KeyExchange);
                            }
                            Some(KemAlgorithm::Hqckem192) => {
                                self.assembler.emit_op(OpCode::HQCKEM192KeyExchange);
                            }
                            Some(KemAlgorithm::Hqckem256) => {
                                self.assembler.emit_op(OpCode::HQCKEM256KeyExchange);
                            }
                            _ => {
                                // ML-KEM family currently maps to the ML-KEM decapsulation opcode.
                                self.assembler.emit_op(OpCode::MLKEMKeyExchange);
                            }
                        }
                    }
                } else {
                    // Regular function call
                    self.assembler.emit_op(OpCode::Call);
                    // Would need function address
                }
            }
            Expression::MemberAccess(obj, _member) => {
                self.gen_expression(obj)?;
                // Member access - in full implementation, would load member from struct/object
                // For now, member name is available in 'member' parameter for future implementation
            }
            Expression::Binary(op, left, right) => {
                self.gen_expression(left)?;
                self.gen_expression(right)?;
                self.gen_binary_op(op)?;
            }
            Expression::Unary(op, expr) => {
                self.gen_expression(expr)?;
                self.gen_unary_op(op)?;
            }
            Expression::IndexAccess(obj, idx) => {
                self.gen_expression(obj)?;
                self.gen_expression(idx)?;
                // Index access: calculate offset and load
                // Stack: [array, index] -> [value]
                // For now, assume array is in memory and index is offset
                // In full implementation, would calculate byte offset based on element size
            }
            Expression::Ternary(cond, then_expr, else_expr) => {
                // Ternary: condition ? then_expr : else_expr
                let else_label = format!(
                    "{}_ternary_else_{}",
                    self.current_function
                        .as_ref()
                        .unwrap_or(&"global".to_string()),
                    self.assembler.code_len()
                );
                let end_label = format!(
                    "{}_ternary_end_{}",
                    self.current_function
                        .as_ref()
                        .unwrap_or(&"global".to_string()),
                    self.assembler.code_len()
                );

                self.gen_expression(cond)?;
                self.assembler.emit_op(OpCode::JumpIf);
                let patch_pos = self.assembler.code_len();
                self.assembler.emit_u32(0);
                self.jump_patches.push((patch_pos, else_label.clone()));

                // Generate then expression
                self.gen_expression(then_expr)?;

                // Jump to end
                self.assembler.emit_op(OpCode::Jump);
                let patch_pos = self.assembler.code_len();
                self.assembler.emit_u32(0);
                self.jump_patches.push((patch_pos, end_label.clone()));

                // Mark else label
                self.label_positions
                    .insert(else_label, self.assembler.code_len());

                // Generate else expression
                self.gen_expression(else_expr)?;

                // Mark end label
                self.label_positions
                    .insert(end_label, self.assembler.code_len());
            }
        }
        Ok(())
    }

    fn gen_literal(&mut self, lit: &Literal) -> Result<(), String> {
        match lit {
            Literal::Number(n) => {
                self.assembler.emit_op(OpCode::Push);
                self.assembler.emit_u32(*n as u32);
            }
            Literal::Bool(b) => {
                self.assembler.emit_op(OpCode::Push);
                self.assembler.emit_u32(if *b { 1 } else { 0 });
            }
            Literal::String(s) => {
                self.assembler.emit_op(OpCode::LoadImm);
                self.assembler.emit_bytes(s.as_bytes());
            }
            Literal::Address(addr) => {
                self.assembler.emit_op(OpCode::LoadImm);
                // Parse hex address payload (without 0x prefix) into bytes.
                let hex = addr.strip_prefix("0x").unwrap_or(addr);
                if hex.len() % 2 == 0 && hex.chars().all(|c| c.is_ascii_hexdigit()) {
                    let mut out = Vec::with_capacity(hex.len() / 2);
                    let bytes = hex.as_bytes();
                    let mut i = 0usize;
                    while i < bytes.len() {
                        let byte_text = std::str::from_utf8(&bytes[i..i + 2])
                            .map_err(|e| format!("Invalid address encoding: {e}"))?;
                        let byte = u8::from_str_radix(byte_text, 16)
                            .map_err(|e| format!("Invalid address hex: {e}"))?;
                        out.push(byte);
                        i += 2;
                    }
                    self.assembler.emit_bytes(&out);
                } else {
                    return Err("Address literal must be hex encoded".to_string());
                }
            }
            Literal::Bytes(bytes) => {
                self.assembler.emit_op(OpCode::LoadImm);
                self.assembler.emit_bytes(bytes);
            }
        }
        Ok(())
    }

    fn gen_binary_op(&mut self, op: &BinaryOp) -> Result<(), String> {
        match op {
            BinaryOp::Add => self.assembler.emit_op(OpCode::Add),
            BinaryOp::Sub => self.assembler.emit_op(OpCode::Sub),
            BinaryOp::Mul => self.assembler.emit_op(OpCode::Mul),
            BinaryOp::Div => self.assembler.emit_op(OpCode::Div),
            BinaryOp::Eq => self.assembler.emit_op(OpCode::Eq),
            BinaryOp::Ne => self.assembler.emit_op(OpCode::Ne),
            BinaryOp::Lt => self.assembler.emit_op(OpCode::Lt),
            BinaryOp::Le => self.assembler.emit_op(OpCode::Le),
            BinaryOp::Gt => self.assembler.emit_op(OpCode::Gt),
            BinaryOp::Ge => self.assembler.emit_op(OpCode::Ge),
            _ => {
                // Logical ops and shifts would need additional opcodes
                return Err("Unsupported binary operation".to_string());
            }
        }
        Ok(())
    }

    fn gen_unary_op(&mut self, op: &UnaryOp) -> Result<(), String> {
        match op {
            UnaryOp::Neg => {
                // Negation: push 0, swap, sub
                self.assembler.emit_op(OpCode::Push);
                self.assembler.emit_u32(0);
                self.assembler.emit_op(OpCode::Swap);
                self.assembler.emit_op(OpCode::Sub);
            }
            UnaryOp::Not => {
                // Logical not: push 1, swap, eq
                self.assembler.emit_op(OpCode::Push);
                self.assembler.emit_u32(1);
                self.assembler.emit_op(OpCode::Swap);
                self.assembler.emit_op(OpCode::Eq);
            }
            _ => {
                return Err("Unsupported unary operation".to_string());
            }
        }
        Ok(())
    }

    fn variable_address(&self, name: &str) -> u32 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        self.current_function
            .as_deref()
            .unwrap_or("global")
            .hash(&mut hasher);
        name.hash(&mut hasher);
        hasher.finish() as u32
    }

    fn emit_variable_store(&mut self, name: &str) {
        let addr = self.variable_address(name);
        self.assembler.emit_op(OpCode::Push);
        self.assembler.emit_u32(addr);
        self.assembler.emit_op(OpCode::Store);
    }

    fn emit_variable_load(&mut self, name: &str) {
        let addr = self.variable_address(name);
        self.assembler.emit_op(OpCode::Push);
        self.assembler.emit_u32(addr);
        self.assembler.emit_op(OpCode::Load);
    }
}
