use crate::ast::*;
use quantumvm::{Assembler, OpCode};
use ruint::aliases::U256;
use std::collections::HashMap;

// Memory layout: state variables get fixed contract-wide addresses (0..N).
// Each function gets its own disjoint address block so that parameters
// with the same name across different functions never alias the same
// memory slot.
const FUNCTION_LOCAL_BASE: u32 = 1_000_000;
const FUNCTION_LOCAL_STRIDE: u32 = 1_000;

/// One PQC/KEM builtin call compiles directly to its matching VM opcode.
/// The tuple is (arg count, opcode, pushes a Bool/Bytes result).
fn pqc_builtin_opcode(name: &str) -> Option<OpCode> {
    match name {
        "dilithium_verify" => Some(OpCode::DilithiumVerify),
        "falcon_verify" => Some(OpCode::FalconVerify),
        "sphincs_verify" => Some(OpCode::SphincsVerify),
        "kyber_decaps" => Some(OpCode::KyberKeyExchange),
        _ => None,
    }
}

struct FunctionScope {
    /// name -> memory address, local to this function (params + any
    /// future locals). Looked up before falling back to state variables.
    locals: HashMap<String, u32>,
    /// Reserved for future local-variable declarations (not yet supported
    /// by the grammar -- only params are locals today).
    #[allow(dead_code)]
    next_local_addr: u32,
}

pub struct CodeGenerator {
    assembler: Assembler,
    /// Contract-wide state variable addresses, shared across all functions.
    state_vars: HashMap<String, u32>,
    next_state_addr: u32,
    /// Forward-referenceable function addresses, registered in a
    /// pre-pass before any function body is generated so a caller can
    /// marshal args into a callee defined later in the source.
    function_addresses: HashMap<String, u32>,
    function_param_addrs: HashMap<String, Vec<u32>>,
    function_has_return: HashMap<String, bool>,
    /// (placeholder position, callee name) pairs for calls made before
    /// the callee's address was known (forward references). Backpatched
    /// once all functions have been code-generated.
    pending_call_patches: Vec<(usize, String)>,
}

impl CodeGenerator {
    pub fn new() -> Self {
        CodeGenerator {
            assembler: Assembler::new(),
            state_vars: HashMap::new(),
            next_state_addr: 0,
            function_addresses: HashMap::new(),
            function_param_addrs: HashMap::new(),
            function_has_return: HashMap::new(),
            pending_call_patches: Vec::new(),
        }
    }

    pub fn generate(mut self, ast: &[SourceUnit]) -> Result<(Vec<u8>, Vec<(String, u32)>), String> {
        // Pre-registration pass: assign every state variable and every
        // function's parameter memory addresses before generating any
        // code, so forward references (function A calling function B
        // defined later) and state variable reads work everywhere.
        for item in ast {
            if let SourceUnit::Contract(c) = item {
                self.register_contract_symbols(c)?;
            }
        }

        for item in ast {
            self.gen_source_unit(item)?;
        }

        // Backpatch any inter-function calls made before their callee's
        // address was known (a caller calling a function defined later in
        // source order).
        for (pos, name) in self.pending_call_patches.drain(..).collect::<Vec<_>>() {
            let addr = *self
                .function_addresses
                .get(&name)
                .ok_or_else(|| format!("Undefined function: {}", name))?;
            self.assembler.patch_u32(pos, addr);
        }

        // Emit the function dispatch table (in the data section) now that
        // every function's real code address is known.
        let functions: Vec<String> = self.function_addresses.keys().cloned().collect();
        for name in functions {
            let address = self.function_addresses[&name];
            let params = self
                .function_param_addrs
                .get(&name)
                .cloned()
                .unwrap_or_default();
            let has_return = *self.function_has_return.get(&name).unwrap_or(&false);
            self.assembler
                .add_function_entry(&name, address, &params, has_return);
        }

        let bytecode = self.assembler.build();
        // Return state var layout so callers can expose live state
        let mut sv_layout: Vec<(String, u32)> = self.state_vars.into_iter().collect();
        sv_layout.sort_by_key(|e| e.1); // order by address
        Ok((bytecode, sv_layout))
    }

    fn register_contract_symbols(&mut self, c: &ContractDefinition) -> Result<(), String> {
        for part in &c.parts {
            if let ContractPart::StateVariable(sv) = part {
                let addr = self.next_state_addr;
                self.next_state_addr += 1;
                self.state_vars.insert(sv.name.clone(), addr);
            }
        }

        for (i, part) in c.parts.iter().enumerate() {
            if let ContractPart::Function(f) = part {
                let base = FUNCTION_LOCAL_BASE + (i as u32) * FUNCTION_LOCAL_STRIDE;
                let mut addr = base;
                let mut param_addrs = Vec::with_capacity(f.params.len());
                for _param in &f.params {
                    param_addrs.push(addr);
                    addr += 1;
                }
                self.function_param_addrs
                    .insert(f.name.clone(), param_addrs);
                // The grammar has no explicit return-type declaration in a
                // function signature, so infer "has a return value" from
                // whether the body actually contains a `return <expr>;`.
                let has_return = f
                    .body
                    .statements
                    .iter()
                    .any(|s| matches!(s, Statement::Return(Some(_))));
                self.function_has_return.insert(f.name.clone(), has_return);
            }
        }

        Ok(())
    }

    fn gen_source_unit(&mut self, unit: &SourceUnit) -> Result<(), String> {
        match unit {
            SourceUnit::Struct(s) => self.gen_struct(s),
            SourceUnit::Contract(c) => self.gen_contract(c),
            _ => Err("Not implemented".to_string()),
        }
    }

    fn gen_struct(&mut self, _s: &StructDefinition) -> Result<(), String> {
        // Structs don't generate executable code (metadata only, for now).
        Ok(())
    }

    fn gen_contract(&mut self, c: &ContractDefinition) -> Result<(), String> {
        for part in &c.parts {
            match part {
                ContractPart::Function(f) => self.gen_function(f)?,
                _ => {} // State variables were handled in the pre-pass.
            }
        }
        Ok(())
    }

    fn gen_function(&mut self, f: &FunctionDefinition) -> Result<(), String> {
        let address = self.assembler.current_pos() as u32;
        self.function_addresses.insert(f.name.clone(), address);

        // Build this function's local scope: its parameters, at the
        // addresses already assigned in the pre-pass.
        let param_addrs = self
            .function_param_addrs
            .get(&f.name)
            .cloned()
            .unwrap_or_default();
        let mut locals = HashMap::new();
        for (param, addr) in f.params.iter().zip(param_addrs.iter()) {
            locals.insert(param.name.clone(), *addr);
        }
        let next_local_addr = param_addrs.last().map(|a| a + 1).unwrap_or_else(|| {
            // No params: still needs a base for any future local vars.
            let idx = self.function_addresses.len() as u32 - 1;
            FUNCTION_LOCAL_BASE + idx * FUNCTION_LOCAL_STRIDE
        });
        let mut scope = FunctionScope {
            locals,
            next_local_addr,
        };

        for stmt in &f.body.statements {
            self.gen_statement(stmt, &mut scope)?;
        }

        // Every function must end in Return (not Halt) so multi-function
        // dispatch/call chains resume correctly; a top-level call (the old
        // plain `execute()` convention with pc=0 and an empty call stack)
        // gracefully halts on Return instead of erroring.
        self.assembler.emit_op(OpCode::Return);

        Ok(())
    }

    fn resolve_address(&self, scope: &FunctionScope, name: &str) -> Result<u32, String> {
        if let Some(addr) = scope.locals.get(name) {
            return Ok(*addr);
        }
        if let Some(addr) = self.state_vars.get(name) {
            return Ok(*addr);
        }
        Err(format!("Undefined variable: {}", name))
    }

    fn gen_statement(&mut self, stmt: &Statement, scope: &mut FunctionScope) -> Result<(), String> {
        match stmt {
            Statement::Expression(expr) => {
                self.gen_expression(expr, scope)?;
                // Expression statements discard their result.
                self.assembler.emit_op(OpCode::Pop);
                Ok(())
            }
            Statement::Require(cond, msg) => {
                // require(cond, msg): compiles to a JumpIf-based
                // conditional abort. If the condition is TRUE we jump
                // PAST the Halt (execution continues normally); if FALSE
                // we fall straight through into Halt, aborting the
                // contract. The jump target is backpatched once we know
                // where the Halt instruction ends.
                self.gen_expression(cond, scope)?;
                self.assembler.emit_op(OpCode::JumpIf);
                let jump_target_pos = self.assembler.emit_placeholder_u32();
                // Emit Revert opcode + length-prefixed message.
                // emit_bytes() already prepends the 4-byte LE length.
                self.assembler.emit_op(OpCode::Revert);
                let msg_bytes = msg.as_bytes();
                self.assembler.emit_bytes(msg_bytes);
                let after_revert = self.assembler.current_pos() as u32;
                self.assembler.patch_u32(jump_target_pos, after_revert);
                Ok(())
            }
            Statement::Assignment(name, expr) => {
                let addr = self.resolve_address(scope, name)?;
                self.gen_expression(expr, scope)?;
                self.assembler.emit_op(OpCode::Push);
                self.assembler.emit_i32(addr as i32);
                self.assembler.emit_op(OpCode::Store);
                Ok(())
            }
            Statement::Return(expr) => {
                if let Some(e) = expr {
                    self.gen_expression(e, scope)?;
                }
                // Note: the actual Return opcode is emitted by the
                // caller context (gen_function emits a trailing Return
                // for the implicit end-of-body case). An explicit early
                // `return;` mid-function also just emits Return here.
                self.assembler.emit_op(OpCode::Return);
                Ok(())
            }
        }
    }

    fn gen_expression(
        &mut self,
        expr: &Expression,
        scope: &mut FunctionScope,
    ) -> Result<(), String> {
        match expr {
            Expression::Literal(Literal::Number(n)) => {
                if *n > i32::MAX as u128 {
                    self.assembler.emit_op(OpCode::LoadImm128);
                    self.assembler.emit_u128(*n as u128);
                } else {
                    self.assembler.emit_op(OpCode::Push);
                    self.assembler.emit_i32(*n as i32);
                }
                Ok(())
            }
            Expression::Literal(Literal::BigNumber(s)) => {
                // Full UInt256 literal (> u128::MAX) — 32 big-endian bytes via LoadImm256.
                let v: U256 = s
                    .parse()
                    .map_err(|_| format!("Invalid UInt256 literal: {}", s))?;
                self.assembler.emit_op(OpCode::LoadImm256);
                self.assembler.emit_u256_bytes(&v.to_be_bytes::<32>());
                Ok(())
            }
            Expression::Literal(Literal::Bool(b)) => {
                self.assembler.emit_op(OpCode::Push);
                self.assembler.emit_i32(if *b { 1 } else { 0 });
                Ok(())
            }
            Expression::Literal(Literal::String(s)) => {
                self.assembler.emit_op(OpCode::LoadImm);
                self.assembler.emit_bytes(s.as_bytes());
                Ok(())
            }
            Expression::Identifier(name) => {
                let addr = self.resolve_address(scope, name)?;
                self.assembler.emit_op(OpCode::Push);
                self.assembler.emit_i32(addr as i32);
                self.assembler.emit_op(OpCode::Load);
                Ok(())
            }
            Expression::BinaryOp(lhs, op, rhs) => {
                self.gen_expression(lhs, scope)?;
                self.gen_expression(rhs, scope)?;
                let opcode = match op {
                    BinaryOperator::Add => OpCode::Add,
                    BinaryOperator::Sub => OpCode::Sub,
                    BinaryOperator::Mul => OpCode::Mul,
                    BinaryOperator::Div => OpCode::Div,
                    BinaryOperator::Eq => OpCode::Eq,
                    BinaryOperator::Ne => OpCode::Ne,
                    BinaryOperator::Lt => OpCode::Lt,
                    BinaryOperator::Le => OpCode::Le,
                    BinaryOperator::Gt => OpCode::Gt,
                    BinaryOperator::Ge => OpCode::Ge,
                };
                self.assembler.emit_op(opcode);
                Ok(())
            }
            Expression::Call(name, args) => self.gen_call(name, args, scope),
        }
    }

    fn gen_call(
        &mut self,
        name: &str,
        args: &[Expression],
        scope: &mut FunctionScope,
    ) -> Result<(), String> {
        if let Some(opcode) = pqc_builtin_opcode(name) {
            // PQC/KEM builtins: argument push order matches the VM
            // opcode handler's pop order exactly (see vm.rs), which is
            // the reverse of natural source-code argument order for
            // these specific ops.
            match name {
                "dilithium_verify" | "falcon_verify" | "sphincs_verify" => {
                    // Source order: (message, signature, public_key).
                    // VM pops: public_key, then message, then signature.
                    // So push order must be: signature, message, public_key.
                    if args.len() != 3 {
                        return Err(format!("{} expects 3 arguments", name));
                    }
                    self.gen_expression(&args[1], scope)?; // signature
                    self.gen_expression(&args[0], scope)?; // message
                    self.gen_expression(&args[2], scope)?; // public_key
                }
                "kyber_decaps" => {
                    // Source order: (ciphertext, private_key).
                    // VM pops: private_key, then ciphertext.
                    // So push order must be: ciphertext, private_key.
                    if args.len() != 2 {
                        return Err(format!("{} expects 2 arguments", name));
                    }
                    self.gen_expression(&args[0], scope)?; // ciphertext
                    self.gen_expression(&args[1], scope)?; // private_key
                }
                _ => unreachable!(),
            }
            self.assembler.emit_op(opcode);
            return Ok(());
        }

        // Inter-function call: push args in source order into the
        // callee's known parameter slots isn't how the VM's Call opcode
        // works (Call is a plain code jump with a call-stack return
        // address) — argument marshaling for a same-VM `Call` happens by
        // storing directly into the callee's fixed local addresses
        // before jumping, since the VM has no register-passing ABI.
        let param_addrs = self
            .function_param_addrs
            .get(name)
            .cloned()
            .ok_or_else(|| format!("Undefined function: {}", name))?;

        if args.len() != param_addrs.len() {
            return Err(format!(
                "Function '{}' expects {} argument(s), got {}",
                name,
                param_addrs.len(),
                args.len()
            ));
        }

        for (arg, addr) in args.iter().zip(param_addrs.iter()) {
            self.gen_expression(arg, scope)?;
            self.assembler.emit_op(OpCode::Push);
            self.assembler.emit_i32(*addr as i32);
            self.assembler.emit_op(OpCode::Store);
        }

        // Forward-reference safe: address is patched even if the target
        // function hasn't been code-generated yet, because we backpatch
        // using the function_addresses map filled in during codegen. If
        // the callee comes AFTER this call site in source order, we defer
        // patching via a placeholder resolved once the whole contract has
        // been generated (see generate()'s final backpatch pass)...
        self.assembler.emit_op(OpCode::Call);
        if let Some(&addr) = self.function_addresses.get(name) {
            self.assembler.emit_u32(addr);
        } else {
            // Callee not yet generated (forward reference): emit a
            // placeholder and record it for a final backpatch pass.
            let pos = self.assembler.emit_placeholder_u32();
            self.pending_call_patches.push((pos, name.to_string()));
        }

        // The callee leaves its return value (if any) on the stack; if it
        // has no return value the caller treats the call as a statement
        // and the surrounding gen_statement's Pop handles cleanup. To keep
        // the stack balanced for void calls used as expressions, push a
        // dummy 0 when the function has no return value.
        let has_return = *self.function_has_return.get(name).unwrap_or(&false);
        if !has_return {
            self.assembler.emit_op(OpCode::Push);
            self.assembler.emit_i32(0);
        }

        Ok(())
    }
}
