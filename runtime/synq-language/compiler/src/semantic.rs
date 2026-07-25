use crate::ast::{
    BinaryOp, Block, ContractDefinition, ContractPart, Expression, FunctionDefinition, Literal,
    SemanticError, SourceUnit, Statement, Type, UnaryOp,
};
use std::collections::HashMap;

#[derive(Debug, Default)]
pub struct SemanticAnalyzer {
    errors: Vec<SemanticError>,
}

#[derive(Debug, Clone)]
struct FunctionSignature {
    params: Vec<Type>,
    returns: Option<Type>,
}

#[derive(Debug)]
struct ContractContext {
    name: String,
    state_variables: HashMap<String, Type>,
    functions: HashMap<String, FunctionSignature>,
}

#[derive(Debug)]
struct FunctionContext<'a> {
    contract: &'a ContractContext,
    function_name: String,
    returns: Option<&'a Type>,
    scopes: Vec<HashMap<String, Type>>,
}

#[derive(Debug, Clone)]
enum InferredType {
    Known(Type),
    Unknown,
}

#[derive(Debug)]
enum BuiltinResolution {
    Supported(FunctionSignature),
    Unsupported(String),
    NotBuiltin,
}

impl InferredType {
    fn known(ty: Type) -> Self {
        Self::Known(ty)
    }

    fn as_type(&self) -> Option<&Type> {
        match self {
            Self::Known(ty) => Some(ty),
            Self::Unknown => None,
        }
    }
}

impl SemanticAnalyzer {
    pub fn analyze(ast: &[SourceUnit]) -> Result<(), Vec<SemanticError>> {
        let mut analyzer = Self::default();
        analyzer.analyze_units(ast);
        if analyzer.errors.is_empty() {
            Ok(())
        } else {
            Err(analyzer.errors)
        }
    }

    fn analyze_units(&mut self, units: &[SourceUnit]) {
        for unit in units {
            if let SourceUnit::Contract(contract) = unit {
                self.analyze_contract(contract);
            }
        }
    }

    fn analyze_contract(&mut self, contract: &ContractDefinition) {
        let mut state_variables = HashMap::new();
        let mut constructor_count = 0usize;

        for part in &contract.parts {
            match part {
                ContractPart::StateVariable(state) => {
                    if state_variables
                        .insert(state.name.clone(), state.ty.clone())
                        .is_some()
                    {
                        self.push_error(format!(
                            "Contract `{}` has duplicate state variable `{}`",
                            contract.name, state.name
                        ));
                    }
                }
                ContractPart::Constructor(_) => {
                    constructor_count += 1;
                }
                _ => {}
            }
        }

        if constructor_count > 1 {
            self.push_error(format!(
                "Contract `{}` defines {} constructors; only one constructor is allowed",
                contract.name, constructor_count
            ));
        }

        let mut functions = HashMap::new();
        for part in &contract.parts {
            if let ContractPart::Function(function) = part {
                let signature = FunctionSignature {
                    params: function.params.iter().map(|p| p.ty.clone()).collect(),
                    returns: function.returns.clone(),
                };
                functions.entry(function.name.clone()).or_insert(signature);
            }
        }

        let ctx = ContractContext {
            name: contract.name.clone(),
            state_variables,
            functions,
        };

        for part in &contract.parts {
            match part {
                ContractPart::Function(function) => self.analyze_function(function, &ctx),
                ContractPart::Constructor(constructor) => {
                    let mut root_scope = HashMap::new();
                    for param in &constructor.params {
                        if root_scope
                            .insert(param.name.clone(), param.ty.clone())
                            .is_some()
                        {
                            self.push_error(format!(
                                "Constructor in contract `{}` has duplicate parameter `{}`",
                                ctx.name, param.name
                            ));
                        }
                    }

                    let mut fn_ctx = FunctionContext {
                        contract: &ctx,
                        function_name: "constructor".to_string(),
                        returns: None,
                        scopes: vec![root_scope],
                    };
                    self.analyze_block(&constructor.body, &mut fn_ctx);
                }
                _ => {}
            }
        }
    }

    fn analyze_function(&mut self, function: &FunctionDefinition, contract: &ContractContext) {
        let mut root_scope = HashMap::new();

        for param in &function.params {
            if root_scope
                .insert(param.name.clone(), param.ty.clone())
                .is_some()
            {
                self.push_error(format!(
                    "Function `{}` in contract `{}` has duplicate parameter `{}`",
                    function.name, contract.name, param.name
                ));
            }
        }

        let mut ctx = FunctionContext {
            contract,
            function_name: function.name.clone(),
            returns: function.returns.as_ref(),
            scopes: vec![root_scope],
        };

        let function_terminates = self.analyze_block(&function.body, &mut ctx);
        if function.returns.is_some() && !function_terminates {
            self.push_error(format!(
                "Function `{}` in contract `{}` may exit without returning a value on all paths",
                function.name, contract.name
            ));
        }
    }

    fn analyze_block(&mut self, block: &Block, ctx: &mut FunctionContext<'_>) -> bool {
        let mut terminated = false;
        for statement in &block.statements {
            if terminated {
                self.push_error(format!(
                    "Function `{}` in contract `{}` contains unreachable statement after terminal control flow",
                    ctx.function_name, ctx.contract.name
                ));
                continue;
            }

            if self.analyze_statement(statement, ctx) {
                terminated = true;
            }
        }

        terminated
    }

    fn analyze_statement(&mut self, statement: &Statement, ctx: &mut FunctionContext<'_>) -> bool {
        match statement {
            Statement::VariableDeclaration(name, ty, value) => {
                let value_ty = value
                    .as_ref()
                    .map(|expr| self.infer_expression_type(expr, ctx));
                let effective_ty = effective_variable_type(ty, value_ty.as_ref());

                if let Some(scope) = ctx.scopes.last_mut() {
                    if scope.contains_key(name) {
                        self.push_error(format!(
                            "Function `{}` in contract `{}` redeclares local variable `{}` in the same scope",
                            ctx.function_name, ctx.contract.name, name
                        ));
                    } else {
                        scope.insert(name.clone(), effective_ty);
                    }
                }

                if let Some(inferred) = value_ty {
                    if let Some(actual_ty) = inferred.as_type() {
                        if should_enforce_variable_decl_check(ty, actual_ty)
                            && !types_compatible(ty, actual_ty)
                        {
                            self.push_error(format!(
                                "Function `{}` in contract `{}` initializes `{}` with incompatible type (expected `{:?}`, found `{:?}`)",
                                ctx.function_name, ctx.contract.name, name, ty, actual_ty
                            ));
                        }
                    }
                }
                false
            }
            Statement::Assignment(name, expr) => {
                let target_ty = self.lookup_symbol_type(name, ctx);
                if target_ty.is_none() {
                    self.push_error(format!(
                        "Function `{}` in contract `{}` assigns to undefined symbol `{}`",
                        ctx.function_name, ctx.contract.name, name
                    ));
                }

                let value_ty = self.infer_expression_type(expr, ctx);
                if let (Some(expected), Some(actual)) = (target_ty.as_ref(), value_ty.as_type()) {
                    // Parser currently stores assignment lvalues as root symbols.
                    // Skip strict type checks for container-like lvalues until full lvalue AST support lands.
                    if is_precise_assignment_target(expected) && !types_compatible(expected, actual)
                    {
                        self.push_error(format!(
                            "Function `{}` in contract `{}` assigns incompatible type to `{}` (expected `{:?}`, found `{:?}`)",
                            ctx.function_name, ctx.contract.name, name, expected, actual
                        ));
                    }
                }
                false
            }
            Statement::Return(expr) => {
                match (ctx.returns.is_some(), expr.is_some()) {
                    (true, false) => self.push_error(format!(
                        "Function `{}` in contract `{}` must return a value",
                        ctx.function_name, ctx.contract.name
                    )),
                    (false, true) => self.push_error(format!(
                        "Function `{}` in contract `{}` cannot return a value (no return type declared)",
                        ctx.function_name, ctx.contract.name
                    )),
                    _ => {}
                }

                if let (Some(expected), Some(return_expr)) = (ctx.returns, expr.as_ref()) {
                    let actual = self.infer_expression_type(return_expr, ctx);
                    if let Some(actual_ty) = actual.as_type() {
                        if !types_compatible(expected, actual_ty) {
                            self.push_error(format!(
                                "Function `{}` in contract `{}` returns incompatible type (expected `{:?}`, found `{:?}`)",
                                ctx.function_name, ctx.contract.name, expected, actual_ty
                            ));
                        }
                    }
                } else if let Some(return_expr) = expr.as_ref() {
                    self.infer_expression_type(return_expr, ctx);
                }
                true
            }
            Statement::Require(condition, _) => {
                let ty = self.infer_expression_type(condition, ctx);
                if let Some(ty) = ty.as_type() {
                    if !is_bool_type(ty) {
                        self.push_error(format!(
                            "Function `{}` in contract `{}` uses non-boolean require condition of type `{:?}`",
                            ctx.function_name, ctx.contract.name, ty
                        ));
                    }
                }
                false
            }
            Statement::If(condition, then_block, else_block) => {
                let condition_ty = self.infer_expression_type(condition, ctx);
                if let Some(ty) = condition_ty.as_type() {
                    if !is_bool_type(ty) {
                        self.push_error(format!(
                            "Function `{}` in contract `{}` uses non-boolean if condition of type `{:?}`",
                            ctx.function_name, ctx.contract.name, ty
                        ));
                    }
                }

                ctx.scopes.push(HashMap::new());
                let then_terminates = self.analyze_block(then_block, ctx);
                ctx.scopes.pop();

                let mut else_terminates = false;
                if let Some(else_block) = else_block {
                    ctx.scopes.push(HashMap::new());
                    else_terminates = self.analyze_block(else_block, ctx);
                    ctx.scopes.pop();
                }

                then_terminates && else_terminates
            }
            Statement::For(iterator, start, end, body) => {
                let start_ty = self.infer_expression_type(start, ctx);
                let end_ty = self.infer_expression_type(end, ctx);

                if let Some(ty) = start_ty.as_type() {
                    if !is_numeric_type(ty) {
                        self.push_error(format!(
                            "Function `{}` in contract `{}` for-loop start bound has non-numeric type `{:?}`",
                            ctx.function_name, ctx.contract.name, ty
                        ));
                    }
                }
                if let Some(ty) = end_ty.as_type() {
                    if !is_numeric_type(ty) {
                        self.push_error(format!(
                            "Function `{}` in contract `{}` for-loop end bound has non-numeric type `{:?}`",
                            ctx.function_name, ctx.contract.name, ty
                        ));
                    }
                }

                let mut for_scope = HashMap::new();
                for_scope.insert(iterator.clone(), Type::UInt256);
                ctx.scopes.push(for_scope);
                self.analyze_block(body, ctx);
                ctx.scopes.pop();
                false
            }
            Statement::Emit(_, args) => {
                for arg in args {
                    self.infer_expression_type(arg, ctx);
                }
                false
            }
            Statement::RequirePqc(block, fallback) => {
                ctx.scopes.push(HashMap::new());
                let block_terminates = self.analyze_block(block, ctx);
                ctx.scopes.pop();

                if let Some(fallback_stmt) = fallback {
                    self.analyze_statement(fallback_stmt, ctx);
                }

                block_terminates
            }
            Statement::Expression(expr) => {
                self.infer_expression_type(expr, ctx);
                false
            }
            Statement::Revert(_) => true,
        }
    }

    fn infer_expression_type(
        &mut self,
        expression: &Expression,
        ctx: &FunctionContext<'_>,
    ) -> InferredType {
        match expression {
            Expression::Literal(literal) => match literal {
                Literal::String(_) => InferredType::known(Type::String),
                Literal::Number(_) => InferredType::known(Type::UInt256),
                Literal::Bool(_) => InferredType::known(Type::Bool),
                Literal::Address(_) => InferredType::known(Type::Address),
                Literal::Bytes(_) => InferredType::known(Type::Bytes),
            },
            Expression::Identifier(raw) => self.infer_identifier_type(raw, ctx),
            Expression::Call(name, args) => self.infer_call_type(name, args, ctx),
            Expression::MemberAccess(object, member) => {
                let object_ty = self.infer_expression_type(object, ctx);
                match object_ty {
                    InferredType::Known(Type::Array(_, _))
                    | InferredType::Known(Type::Bytes)
                    | InferredType::Known(Type::String)
                        if member == "length" =>
                    {
                        InferredType::known(Type::UInt256)
                    }
                    _ => InferredType::Unknown,
                }
            }
            Expression::IndexAccess(object, index) => {
                let object_ty = self.infer_expression_type(object, ctx);
                self.infer_expression_type(index, ctx);
                match object_ty {
                    InferredType::Known(Type::Array(element, _)) => InferredType::known(*element),
                    InferredType::Known(Type::Mapping(_, value)) => InferredType::known(*value),
                    _ => InferredType::Unknown,
                }
            }
            Expression::Binary(op, lhs, rhs) => {
                let lhs_ty = self.infer_expression_type(lhs, ctx);
                let rhs_ty = self.infer_expression_type(rhs, ctx);

                match op {
                    BinaryOp::Eq | BinaryOp::Ne => {
                        if let (Some(left), Some(right)) = (lhs_ty.as_type(), rhs_ty.as_type()) {
                            if !types_compatible(left, right) {
                                self.push_error(format!(
                                    "Function `{}` in contract `{}` compares incompatible types `{:?}` and `{:?}`",
                                    ctx.function_name, ctx.contract.name, left, right
                                ));
                            }
                        }
                        InferredType::known(Type::Bool)
                    }
                    BinaryOp::Lt | BinaryOp::Le | BinaryOp::Gt | BinaryOp::Ge => {
                        if let (Some(left), Some(right)) = (lhs_ty.as_type(), rhs_ty.as_type()) {
                            if !(is_numeric_type(left) && is_numeric_type(right)) {
                                self.push_error(format!(
                                    "Function `{}` in contract `{}` uses relational comparison on non-numeric types `{:?}` and `{:?}`",
                                    ctx.function_name, ctx.contract.name, left, right
                                ));
                            }
                        }
                        InferredType::known(Type::Bool)
                    }
                    BinaryOp::And | BinaryOp::Or => {
                        if let Some(left) = lhs_ty.as_type() {
                            if !is_bool_type(left) {
                                self.push_error(format!(
                                    "Function `{}` in contract `{}` uses logical operation with non-boolean left operand `{:?}`",
                                    ctx.function_name, ctx.contract.name, left
                                ));
                            }
                        }
                        if let Some(right) = rhs_ty.as_type() {
                            if !is_bool_type(right) {
                                self.push_error(format!(
                                    "Function `{}` in contract `{}` uses logical operation with non-boolean right operand `{:?}`",
                                    ctx.function_name, ctx.contract.name, right
                                ));
                            }
                        }
                        InferredType::known(Type::Bool)
                    }
                    BinaryOp::Add
                    | BinaryOp::Sub
                    | BinaryOp::Mul
                    | BinaryOp::Div
                    | BinaryOp::Mod
                    | BinaryOp::Shl
                    | BinaryOp::Shr => {
                        if let (Some(left), Some(right)) = (lhs_ty.as_type(), rhs_ty.as_type()) {
                            if is_numeric_type(left) && is_numeric_type(right) {
                                if is_signed_integer(left) || is_signed_integer(right) {
                                    InferredType::known(Type::Int256)
                                } else {
                                    InferredType::known(Type::UInt256)
                                }
                            } else {
                                self.push_error(format!(
                                    "Function `{}` in contract `{}` applies arithmetic operation to non-numeric types `{:?}` and `{:?}`",
                                    ctx.function_name, ctx.contract.name, left, right
                                ));
                                InferredType::Unknown
                            }
                        } else {
                            InferredType::Unknown
                        }
                    }
                }
            }
            Expression::Unary(op, expr) => {
                let expr_ty = self.infer_expression_type(expr, ctx);
                match op {
                    UnaryOp::Not => {
                        if let Some(ty) = expr_ty.as_type() {
                            if !is_bool_type(ty) {
                                self.push_error(format!(
                                    "Function `{}` in contract `{}` applies `!` to non-boolean type `{:?}`",
                                    ctx.function_name, ctx.contract.name, ty
                                ));
                            }
                        }
                        InferredType::known(Type::Bool)
                    }
                    UnaryOp::Neg | UnaryOp::Inc | UnaryOp::Dec => {
                        if let Some(ty) = expr_ty.as_type() {
                            if !is_numeric_type(ty) {
                                self.push_error(format!(
                                    "Function `{}` in contract `{}` applies numeric unary operator to non-numeric type `{:?}`",
                                    ctx.function_name, ctx.contract.name, ty
                                ));
                            }
                        }
                        expr_ty
                    }
                }
            }
            Expression::Ternary(condition, then_expr, else_expr) => {
                let condition_ty = self.infer_expression_type(condition, ctx);
                if let Some(ty) = condition_ty.as_type() {
                    if !is_bool_type(ty) {
                        self.push_error(format!(
                            "Function `{}` in contract `{}` uses non-boolean ternary condition type `{:?}`",
                            ctx.function_name, ctx.contract.name, ty
                        ));
                    }
                }

                let then_ty = self.infer_expression_type(then_expr, ctx);
                let else_ty = self.infer_expression_type(else_expr, ctx);

                match (then_ty, else_ty) {
                    (InferredType::Known(a), InferredType::Known(b)) => {
                        if types_compatible(&a, &b) {
                            InferredType::known(a)
                        } else if types_compatible(&b, &a) {
                            InferredType::known(b)
                        } else {
                            self.push_error(format!(
                                "Function `{}` in contract `{}` uses ternary branches with incompatible types `{:?}` and `{:?}`",
                                ctx.function_name, ctx.contract.name, a, b
                            ));
                            InferredType::Unknown
                        }
                    }
                    (InferredType::Known(a), InferredType::Unknown) => InferredType::known(a),
                    (InferredType::Unknown, InferredType::Known(b)) => InferredType::known(b),
                    _ => InferredType::Unknown,
                }
            }
        }
    }

    fn infer_identifier_type(&mut self, raw: &str, ctx: &FunctionContext<'_>) -> InferredType {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return InferredType::Unknown;
        }

        match trimmed {
            "msg.sender" => return InferredType::known(Type::Address),
            "msg.value" => return InferredType::known(Type::UInt256),
            "block.number" | "block.timestamp" => return InferredType::known(Type::UInt256),
            "true" | "false" => return InferredType::known(Type::Bool),
            "break" | "continue" => return InferredType::Unknown,
            _ => {}
        }

        if trimmed.starts_with('[') || trimmed.starts_with('{') {
            // Parser still may collapse complex literals into identifier nodes.
            return InferredType::Unknown;
        }

        let Some(root_symbol) = extract_root_symbol(trimmed) else {
            return InferredType::Unknown;
        };

        if let Some(base_ty) = self.lookup_symbol_type(root_symbol, ctx) {
            let suffix = &trimmed[root_symbol.len()..];
            if suffix.is_empty() {
                return InferredType::known(base_ty);
            }
            return infer_type_with_accessors(base_ty, suffix);
        }

        if trimmed.contains('.')
            && root_symbol
                .chars()
                .next()
                .map(|ch| ch.is_ascii_uppercase())
                .unwrap_or(false)
        {
            // Treat `TypeName.Member` references (e.g. enum variants) as parse-only valid for now.
            return InferredType::Unknown;
        }

        if matches!(root_symbol, "msg" | "block") {
            return InferredType::Unknown;
        }

        self.push_error(format!(
            "Function `{}` in contract `{}` references undefined symbol `{}`",
            ctx.function_name, ctx.contract.name, root_symbol
        ));
        InferredType::Unknown
    }

    fn infer_call_type(
        &mut self,
        name: &str,
        args: &[Expression],
        ctx: &FunctionContext<'_>,
    ) -> InferredType {
        let arg_types: Vec<InferredType> = args
            .iter()
            .map(|arg| self.infer_expression_type(arg, ctx))
            .collect();

        if let Some(cast_ty) = parse_constructor_type(name) {
            if arg_types.len() != 1 {
                self.push_error(format!(
                    "Function `{}` in contract `{}` calls type constructor `{}` with {} arguments; expected 1",
                    ctx.function_name,
                    ctx.contract.name,
                    name,
                    arg_types.len()
                ));
            }
            return InferredType::known(cast_ty);
        }

        if let Some(signature) = ctx.contract.functions.get(name) {
            self.validate_call_signature(name, signature, &arg_types, ctx);
            return signature
                .returns
                .clone()
                .map(InferredType::known)
                .unwrap_or(InferredType::Unknown);
        }

        match resolve_builtin_signature(name) {
            BuiltinResolution::Supported(signature) => {
                self.validate_call_signature(name, &signature, &arg_types, ctx);
                signature
                    .returns
                    .clone()
                    .map(InferredType::known)
                    .unwrap_or(InferredType::Unknown)
            }
            BuiltinResolution::Unsupported(reason) => {
                self.push_error(format!(
                    "Function `{}` in contract `{}` uses unsupported builtin `{}`: {}",
                    ctx.function_name, ctx.contract.name, name, reason
                ));
                InferredType::Unknown
            }
            BuiltinResolution::NotBuiltin => {
                // Unknown call target is tolerated for now because parser/codegen still treat
                // several high-level constructs (e.g., struct constructor-like forms) as plain calls.
                InferredType::Unknown
            }
        }
    }

    fn validate_call_signature(
        &mut self,
        name: &str,
        signature: &FunctionSignature,
        args: &[InferredType],
        ctx: &FunctionContext<'_>,
    ) {
        if signature.params.len() != args.len() {
            self.push_error(format!(
                "Function `{}` in contract `{}` calls `{}` with {} arguments; expected {}",
                ctx.function_name,
                ctx.contract.name,
                name,
                args.len(),
                signature.params.len()
            ));
            return;
        }

        for (idx, (expected, actual)) in signature.params.iter().zip(args.iter()).enumerate() {
            if let Some(actual_ty) = actual.as_type() {
                if !types_compatible(expected, actual_ty) {
                    self.push_error(format!(
                        "Function `{}` in contract `{}` passes incompatible argument {} to `{}` (expected `{:?}`, found `{:?}`)",
                        ctx.function_name,
                        ctx.contract.name,
                        idx + 1,
                        name,
                        expected,
                        actual_ty
                    ));
                }
            }
        }
    }

    fn lookup_symbol_type(&self, symbol: &str, ctx: &FunctionContext<'_>) -> Option<Type> {
        for scope in ctx.scopes.iter().rev() {
            if let Some(ty) = scope.get(symbol) {
                return Some(ty.clone());
            }
        }

        if let Some(ty) = ctx.contract.state_variables.get(symbol) {
            return Some(ty.clone());
        }

        None
    }

    fn push_error(&mut self, message: String) {
        self.errors.push(SemanticError {
            message,
            line: None,
            column: None,
        });
    }
}

pub fn analyze(ast: &[SourceUnit]) -> Result<(), Vec<SemanticError>> {
    SemanticAnalyzer::analyze(ast)
}

fn resolve_builtin_signature(name: &str) -> BuiltinResolution {
    let normalized = normalize_name(name);

    if normalized.starts_with("verifyslhdsa") || normalized.starts_with("slhdsa") {
        return BuiltinResolution::Unsupported(
            "SLH-DSA is de-scoped in the current SynQ runtime profile".to_string(),
        );
    }

    if normalized.starts_with("verifymldsa") {
        return BuiltinResolution::Supported(FunctionSignature {
            params: vec![Type::MLDSAPublicKey, Type::Bytes, Type::MLDSASignature],
            returns: Some(Type::Bool),
        });
    }

    if normalized.starts_with("verifyfndsa") {
        return BuiltinResolution::Supported(FunctionSignature {
            params: vec![Type::FNDSAPublicKey, Type::Bytes, Type::FNDSASignature],
            returns: Some(Type::Bool),
        });
    }

    if normalized.starts_with("mlkem") && normalized.contains("decapsulate") {
        return BuiltinResolution::Supported(FunctionSignature {
            params: vec![Type::MLKEMCiphertext, Type::Bytes],
            returns: Some(Type::Bytes),
        });
    }

    if normalized.starts_with("hqckem") && normalized.contains("decapsulate") {
        return BuiltinResolution::Supported(FunctionSignature {
            params: vec![Type::Bytes, Type::Bytes],
            returns: Some(Type::Bytes),
        });
    }

    // Treat other PQC-like names as parse-time tolerated but semantically unknown until modeled.
    if normalized.starts_with("mldsa")
        || normalized.starts_with("fndsa")
        || normalized.starts_with("mlkem")
        || normalized.starts_with("hqckem")
    {
        return BuiltinResolution::NotBuiltin;
    }

    BuiltinResolution::NotBuiltin
}

fn parse_constructor_type(name: &str) -> Option<Type> {
    match name {
        "Address" => Some(Type::Address),
        "UInt256" => Some(Type::UInt256),
        "UInt128" => Some(Type::UInt128),
        "UInt64" => Some(Type::UInt64),
        "UInt32" => Some(Type::UInt32),
        "UInt8" => Some(Type::UInt8),
        "Int256" => Some(Type::Int256),
        "Int128" => Some(Type::Int128),
        "Int64" => Some(Type::Int64),
        "Int32" => Some(Type::Int32),
        "Int8" => Some(Type::Int8),
        "Bool" => Some(Type::Bool),
        "Bytes" => Some(Type::Bytes),
        "String" => Some(Type::String),
        "MLDSAPublicKey" => Some(Type::MLDSAPublicKey),
        "MLDSAKeyPair" => Some(Type::MLDSAKeyPair),
        "MLDSASignature" => Some(Type::MLDSASignature),
        "FNDSAPublicKey" => Some(Type::FNDSAPublicKey),
        "FNDSAKeyPair" => Some(Type::FNDSAKeyPair),
        "FNDSASignature" => Some(Type::FNDSASignature),
        "MLKEMPublicKey" => Some(Type::MLKEMPublicKey),
        "MLKEMKeyPair" => Some(Type::MLKEMKeyPair),
        "MLKEMCiphertext" => Some(Type::MLKEMCiphertext),
        "SLHDSAPublicKey" => Some(Type::SLHDSAPublicKey),
        "SLHDSAKeyPair" => Some(Type::SLHDSAKeyPair),
        "SLHDSASignature" => Some(Type::SLHDSASignature),
        _ => None,
    }
}

fn infer_type_with_accessors(base: Type, suffix: &str) -> InferredType {
    let mut current = base;
    let mut rest = suffix.trim();

    while !rest.is_empty() {
        if rest.starts_with('[') {
            let Some(close_idx) = find_closing_bracket(rest) else {
                return InferredType::Unknown;
            };

            current = match current {
                Type::Array(element, _) => *element,
                Type::Mapping(_, value) => *value,
                _ => return InferredType::Unknown,
            };
            rest = rest[close_idx + 1..].trim_start();
            continue;
        }

        if let Some(next) = rest.strip_prefix(".length") {
            return if next.is_empty() {
                InferredType::known(Type::UInt256)
            } else {
                InferredType::Unknown
            };
        }

        if rest.starts_with('.') {
            // Member access beyond `.length` is not fully modeled yet.
            return InferredType::Unknown;
        }

        return InferredType::Unknown;
    }

    InferredType::known(current)
}

fn find_closing_bracket(text: &str) -> Option<usize> {
    let mut depth = 0usize;
    for (idx, ch) in text.char_indices() {
        match ch {
            '[' => depth += 1,
            ']' => {
                if depth == 0 {
                    return None;
                }
                depth -= 1;
                if depth == 0 {
                    return Some(idx);
                }
            }
            _ => {}
        }
    }
    None
}

fn types_compatible(expected: &Type, actual: &Type) -> bool {
    if expected == actual {
        return true;
    }

    if is_numeric_type(expected) && is_numeric_type(actual) {
        return true;
    }

    match (expected, actual) {
        (Type::MLKEMCiphertext, Type::Bytes) | (Type::Bytes, Type::MLKEMCiphertext) => true,
        (Type::Array(exp_elem, exp_len), Type::Array(act_elem, act_len)) => {
            (exp_len == act_len || exp_len.is_none() || act_len.is_none())
                && types_compatible(exp_elem, act_elem)
        }
        (Type::Mapping(exp_key, exp_value), Type::Mapping(act_key, act_value)) => {
            types_compatible(exp_key, act_key) && types_compatible(exp_value, act_value)
        }
        (Type::Generic(exp_name, exp_types), Type::Generic(act_name, act_types)) => {
            exp_name == act_name
                && exp_types.len() == act_types.len()
                && exp_types
                    .iter()
                    .zip(act_types.iter())
                    .all(|(exp, act)| types_compatible(exp, act))
        }
        _ => false,
    }
}

fn is_precise_assignment_target(ty: &Type) -> bool {
    !matches!(
        ty,
        Type::Array(_, _) | Type::Mapping(_, _) | Type::Struct(_) | Type::Generic(_, _)
    )
}

fn should_enforce_variable_decl_check(expected: &Type, actual: &Type) -> bool {
    // `let name = expr` declarations are currently normalized to `UInt256`
    // when no explicit type is supplied. Until parser AST preserves explicit type presence,
    // skip incompatible checks for non-numeric initializers under this fallback.
    if matches!(expected, Type::UInt256) && !is_numeric_type(actual) {
        return false;
    }
    true
}

fn effective_variable_type(declared: &Type, initializer: Option<&InferredType>) -> Type {
    // Heuristic for parser fallback: untyped `let` declarations are represented as `UInt256`.
    // If initializer is clearly non-numeric, use initializer type for later local checks.
    if matches!(declared, Type::UInt256) {
        if let Some(InferredType::Known(actual)) = initializer {
            if !is_numeric_type(actual) {
                return actual.clone();
            }
        }
    }

    declared.clone()
}

fn is_bool_type(ty: &Type) -> bool {
    matches!(ty, Type::Bool)
}

fn is_numeric_type(ty: &Type) -> bool {
    matches!(
        ty,
        Type::UInt8
            | Type::UInt32
            | Type::UInt64
            | Type::UInt128
            | Type::UInt256
            | Type::Int8
            | Type::Int32
            | Type::Int64
            | Type::Int128
            | Type::Int256
    )
}

fn is_signed_integer(ty: &Type) -> bool {
    matches!(
        ty,
        Type::Int8 | Type::Int32 | Type::Int64 | Type::Int128 | Type::Int256
    )
}

fn normalize_name(name: &str) -> String {
    let mut normalized = String::with_capacity(name.len());
    for ch in name.chars() {
        if ch != '_' {
            normalized.push(ch.to_ascii_lowercase());
        }
    }
    normalized
}

fn extract_root_symbol(raw: &str) -> Option<&str> {
    let mut chars = raw.char_indices();
    let (_, first) = chars.next()?;
    if !(first.is_ascii_alphabetic() || first == '_') {
        return None;
    }

    let mut end = first.len_utf8();
    for (idx, ch) in chars {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            end = idx + ch.len_utf8();
        } else {
            break;
        }
    }

    Some(&raw[..end])
}
