//! Solidity code generator for SynQ contracts
//! Generates Solidity-compatible output from SynQ AST

use crate::ast::*;

pub const SOLIDITY_COMPATIBILITY_WARNING: &str =
    "WARNING: Solidity compatibility preview only; not production deployable.";

pub struct SolidityGenerator {
    output: String,
    indent_level: usize,
}

impl SolidityGenerator {
    pub fn new() -> Self {
        SolidityGenerator {
            output: String::new(),
            indent_level: 0,
        }
    }

    pub fn generate(mut self, ast: &[SourceUnit]) -> Result<String, String> {
        // Add SPDX license identifier
        self.writeln("// SPDX-License-Identifier: MIT");
        self.writeln("pragma solidity ^0.8.0;");
        self.writeln("");
        self.writeln("// Generated from SynQ source");
        self.writeln(&format!("// {SOLIDITY_COMPATIBILITY_WARNING}"));
        self.writeln("// This file is auto-generated - do not edit manually");
        self.writeln("");

        // Generate imports for PQC libraries
        self.writeln("// PQC library imports (to be implemented)");
        self.writeln("// import \"@synq/pqc/MLDSA.sol\";");
        self.writeln("// import \"@synq/pqc/FNDSA.sol\";");
        self.writeln("// import \"@synq/pqc/MLKEM.sol\";");
        self.writeln("// import \"@synq/pqc/SLH-DSA.sol\";");
        self.writeln("");

        // Generate structs first
        for item in ast {
            if let SourceUnit::Struct(s) = item {
                self.gen_struct(s)?;
                self.writeln("");
            }
        }

        // Generate contracts
        for item in ast {
            if let SourceUnit::Contract(c) = item {
                self.gen_contract(c)?;
                self.writeln("");
            }
        }

        Ok(self.output)
    }

    fn gen_struct(&mut self, s: &StructDefinition) -> Result<(), String> {
        self.writeln(&format!("struct {} {{", s.name));
        self.indent();
        for field in &s.fields {
            self.writeln(&format!(
                "{} {};",
                self.type_to_solidity(&field.ty),
                field.name
            ));
        }
        self.dedent();
        self.writeln("}");
        Ok(())
    }

    fn gen_contract(&mut self, c: &ContractDefinition) -> Result<(), String> {
        // Generate annotations as comments
        for ann in &c.annotations {
            self.writeln(&format!("// @{}", ann.name));
        }

        self.writeln(&format!("contract {} {{", c.name));
        self.indent();

        // Generate state variables
        for part in &c.parts {
            if let ContractPart::StateVariable(v) = part {
                self.gen_state_variable(v)?;
            }
        }

        self.writeln("");

        // Generate constructor
        for part in &c.parts {
            if let ContractPart::Constructor(ctor) = part {
                self.gen_constructor(ctor)?;
                self.writeln("");
            }
        }

        // Generate events
        for part in &c.parts {
            if let ContractPart::Event(e) = part {
                self.gen_event(e)?;
            }
        }

        if c.parts.iter().any(|p| matches!(p, ContractPart::Event(_))) {
            self.writeln("");
        }

        // Generate functions
        for part in &c.parts {
            if let ContractPart::Function(f) = part {
                self.gen_function(f)?;
                self.writeln("");
            }
        }

        self.dedent();
        self.writeln("}");
        Ok(())
    }

    fn gen_state_variable(&mut self, v: &StateVariableDeclaration) -> Result<(), String> {
        for ann in &v.annotations {
            self.writeln(&format!("// @{}", ann.name));
        }

        let visibility = if v.is_public { "public" } else { "internal" };
        self.writeln(&format!(
            "{} {} {};",
            self.type_to_solidity(&v.ty),
            visibility,
            v.name
        ));
        Ok(())
    }

    fn gen_constructor(&mut self, ctor: &ConstructorDefinition) -> Result<(), String> {
        for ann in &ctor.annotations {
            self.writeln(&format!("// @{}", ann.name));
        }

        self.write("constructor(");
        self.gen_params(&ctor.params)?;
        self.write(") ");
        self.gen_gas_annotation(&ctor.annotations);
        self.writeln("{");
        self.indent();
        self.gen_block(&ctor.body)?;
        self.dedent();
        self.writeln("}");
        Ok(())
    }

    fn gen_function(&mut self, f: &FunctionDefinition) -> Result<(), String> {
        for ann in &f.annotations {
            self.writeln(&format!("// @{}", ann.name));
        }

        let visibility = if f.is_public { "public" } else { "internal" };
        self.write(&format!("function {}(", f.name));
        self.gen_params(&f.params)?;
        self.write(") ");

        if let Some(ref ret_ty) = f.returns {
            self.write(&format!(
                "external returns ({}) ",
                self.type_to_solidity(ret_ty)
            ));
        }

        self.write(&format!("{} ", visibility));
        self.gen_gas_annotation(&f.annotations);
        self.writeln("{");
        self.indent();
        self.gen_block(&f.body)?;
        self.dedent();
        self.writeln("}");
        Ok(())
    }

    fn gen_event(&mut self, e: &EventDefinition) -> Result<(), String> {
        for ann in &e.annotations {
            self.writeln(&format!("// @{}", ann.name));
        }

        self.write(&format!("event {}((", e.name));
        self.gen_params(&e.params)?;
        self.writeln("));");
        Ok(())
    }

    fn gen_params(&mut self, params: &[Parameter]) -> Result<(), String> {
        for (i, param) in params.iter().enumerate() {
            if i > 0 {
                self.write(", ");
            }
            self.write(&format!(
                "{} {}",
                self.type_to_solidity(&param.ty),
                param.name
            ));
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
            Statement::VariableDeclaration(name, ty, expr) => {
                self.write(&format!("{} ", self.type_to_solidity(ty)));
                self.write(name);
                if let Some(ref expr) = expr {
                    self.write(" = ");
                    self.gen_expression(expr)?;
                }
                self.writeln(";");
            }
            Statement::Assignment(target, expr) => {
                self.gen_expression(target)?;
                self.write(" = ");
                self.gen_expression(expr)?;
                self.writeln(";");
            }
            Statement::Return(expr) => {
                self.write("return");
                if let Some(ref expr) = expr {
                    self.write(" ");
                    self.gen_expression(expr)?;
                }
                self.writeln(";");
            }
            Statement::Require(expr, msg) => {
                self.write("require(");
                self.gen_expression(expr)?;
                if !msg.is_empty() {
                    self.write(&format!(r#", "{}""#, msg));
                }
                self.writeln(");");
            }
            Statement::Revert(msg) => {
                self.write(&format!(r#"revert("{}");"#, msg));
                self.writeln("");
            }
            Statement::If(cond, then_block, else_block) => {
                self.write("if (");
                self.gen_expression(cond)?;
                self.writeln(") {");
                self.indent();
                self.gen_block(then_block)?;
                self.dedent();
                if let Some(ref else_block) = else_block {
                    self.writeln("} else {");
                    self.indent();
                    self.gen_block(else_block)?;
                    self.dedent();
                }
                self.writeln("}");
            }
            Statement::Emit(event_name, args) => {
                self.write(&format!("emit {}((", event_name));
                for (i, arg) in args.iter().enumerate() {
                    if i > 0 {
                        self.write(", ");
                    }
                    self.gen_expression(arg)?;
                }
                self.writeln("));");
            }
            Statement::Expression(expr) => {
                self.gen_expression(expr)?;
                self.writeln(";");
            }
            Statement::For(iterator, start, end, body) => {
                self.write("for (uint256 ");
                self.write(iterator);
                self.write(" = ");
                self.gen_expression(start)?;
                self.write("; ");
                self.write(iterator);
                self.write(" < ");
                self.gen_expression(end)?;
                self.write("; ");
                self.write(iterator);
                self.writeln("++) {");
                self.indent();
                self.gen_block(body)?;
                self.dedent();
                self.writeln("}");
            }
            Statement::RequirePqc(pqc_block, fallback) => {
                self.writeln("{");
                self.indent();
                self.writeln("// SynQ require_pqc compatibility block");
                self.writeln("bool __synq_pqc_ok = true;");
                self.gen_block(pqc_block)?;
                self.writeln("if (!__synq_pqc_ok) {");
                self.indent();
                if let Some(fallback_stmt) = fallback {
                    self.gen_statement(fallback_stmt)?;
                } else {
                    self.writeln("revert(\"PQC verification failed\");");
                }
                self.dedent();
                self.writeln("}");
                self.dedent();
                self.writeln("}");
            }
        }
        Ok(())
    }

    fn gen_expression(&mut self, expr: &Expression) -> Result<(), String> {
        match expr {
            Expression::Literal(lit) => {
                self.write(&self.literal_to_solidity(lit));
            }
            Expression::Identifier(name) => {
                self.write(name);
            }
            Expression::Call(name, args) => {
                self.write(name);
                self.write("(");
                for (i, arg) in args.iter().enumerate() {
                    if i > 0 {
                        self.write(", ");
                    }
                    self.gen_expression(arg)?;
                }
                self.write(")");
            }
            Expression::MemberAccess(obj, member) => {
                self.gen_expression(obj)?;
                self.write(&format!(".{}", member));
            }
            Expression::Binary(op, left, right) => {
                self.gen_expression(left)?;
                self.write(&format!(" {} ", self.binary_op_to_solidity(op)));
                self.gen_expression(right)?;
            }
            Expression::Unary(op, expr) => {
                let op_str = self.unary_op_to_solidity(op);
                self.write(&op_str);
                self.gen_expression(expr)?;
            }
            Expression::IndexAccess(obj, idx) => {
                self.gen_expression(obj)?;
                self.write("[");
                self.gen_expression(idx)?;
                self.write("]");
            }
            Expression::Ternary(cond, then_expr, else_expr) => {
                self.gen_expression(cond)?;
                self.write(" ? ");
                self.gen_expression(then_expr)?;
                self.write(" : ");
                self.gen_expression(else_expr)?;
            }
        }
        Ok(())
    }

    fn type_to_solidity(&self, ty: &Type) -> String {
        match ty {
            Type::Address => "address".to_string(),
            Type::UInt256 => "uint256".to_string(),
            Type::UInt128 => "uint128".to_string(),
            Type::UInt64 => "uint64".to_string(),
            Type::UInt32 => "uint32".to_string(),
            Type::UInt8 => "uint8".to_string(),
            Type::Int256 => "int256".to_string(),
            Type::Int128 => "int128".to_string(),
            Type::Int64 => "int64".to_string(),
            Type::Int32 => "int32".to_string(),
            Type::Int8 => "int8".to_string(),
            Type::Bool => "bool".to_string(),
            Type::Bytes => "bytes".to_string(),
            Type::String => "string".to_string(),
            Type::MLDSAPublicKey => "bytes memory".to_string(), // PQC types as bytes
            Type::MLDSAKeyPair => "bytes memory".to_string(),
            Type::MLDSASignature => "bytes memory".to_string(),
            Type::FNDSAPublicKey => "bytes memory".to_string(),
            Type::FNDSAKeyPair => "bytes memory".to_string(),
            Type::FNDSASignature => "bytes memory".to_string(),
            Type::MLKEMPublicKey => "bytes memory".to_string(),
            Type::MLKEMKeyPair => "bytes memory".to_string(),
            Type::MLKEMCiphertext => "bytes memory".to_string(),
            Type::SLHDSAPublicKey => "bytes memory".to_string(),
            Type::SLHDSAKeyPair => "bytes memory".to_string(),
            Type::SLHDSASignature => "bytes memory".to_string(),
            Type::Generic(name, _) => name.clone(),
            Type::Array(ty, size) => {
                if let Some(size) = size {
                    format!("{}[{}]", self.type_to_solidity(ty), size)
                } else {
                    format!("{}[]", self.type_to_solidity(ty))
                }
            }
            Type::Mapping(key, value) => {
                format!(
                    "mapping({} => {})",
                    self.type_to_solidity(key),
                    self.type_to_solidity(value)
                )
            }
            Type::Struct(name) => name.clone(),
        }
    }

    fn literal_to_solidity(&self, lit: &Literal) -> String {
        match lit {
            Literal::Number(n) => n.to_string(),
            Literal::String(s) => format!("\"{}\"", s),
            Literal::Bool(b) => b.to_string(),
            Literal::Address(addr) => addr.clone(),
            Literal::Bytes(bytes) => {
                let hex_str: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
                format!("hex\"{}\"", hex_str)
            }
        }
    }

    fn binary_op_to_solidity(&self, op: &BinaryOp) -> &str {
        match op {
            BinaryOp::Add => "+",
            BinaryOp::Sub => "-",
            BinaryOp::Mul => "*",
            BinaryOp::Div => "/",
            BinaryOp::Mod => "%",
            BinaryOp::Eq => "==",
            BinaryOp::Ne => "!=",
            BinaryOp::Lt => "<",
            BinaryOp::Le => "<=",
            BinaryOp::Gt => ">",
            BinaryOp::Ge => ">=",
            BinaryOp::And => "&&",
            BinaryOp::Or => "||",
            BinaryOp::Shl => "<<",
            BinaryOp::Shr => ">>",
        }
    }

    fn unary_op_to_solidity(&self, op: &UnaryOp) -> String {
        match op {
            UnaryOp::Not => "!".to_string(),
            UnaryOp::Neg => "-".to_string(),
            UnaryOp::Inc => "++".to_string(),
            UnaryOp::Dec => "--".to_string(),
        }
    }

    fn gen_gas_annotation(&mut self, annotations: &[Annotation]) {
        for ann in annotations {
            if ann.name == "gas_cost" {
                self.write("// @gas_cost");
                if !ann.args.is_empty() {
                    self.write("(");
                    // Format gas cost args
                    self.write(")");
                }
                self.write(" ");
            }
        }
    }

    fn writeln(&mut self, s: &str) {
        self.write(s);
        self.write("\n");
    }

    fn write(&mut self, s: &str) {
        if s.contains('\n') {
            let lines: Vec<&str> = s.split('\n').collect();
            for (i, line) in lines.iter().enumerate() {
                if i > 0 {
                    self.output.push('\n');
                }
                if !line.is_empty() {
                    self.output.push_str(&"    ".repeat(self.indent_level));
                }
                self.output.push_str(line);
            }
        } else {
            self.output.push_str(s);
        }
    }

    fn indent(&mut self) {
        self.indent_level += 1;
    }

    fn dedent(&mut self) {
        if self.indent_level > 0 {
            self.indent_level -= 1;
        }
    }
}
