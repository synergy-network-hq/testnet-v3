use crate::ast::*;
use pest::iterators::Pair;
use pest::Parser;

#[derive(Parser)]
#[grammar = "synq.pest"]
pub struct SynQParser;

// VersionRequirement is now in version.rs, keeping a simple one here for parser compatibility
#[derive(Debug, Clone, PartialEq)]
pub struct VersionRequirement {
    pub comparator: String,
    pub version: String,
}

pub fn parse(
    source: &str,
) -> Result<(Option<VersionRequirement>, Vec<SourceUnit>), pest::error::Error<Rule>> {
    let pairs = SynQParser::parse(Rule::source_file, source)?;
    let mut ast = vec![];
    let mut version_req: Option<VersionRequirement> = None;

    let source_file = pairs.into_iter().next().unwrap();
    for pair in source_file.into_inner() {
        match pair.as_rule() {
            Rule::pragma_version => {
                version_req = Some(parse_version_requirement(pair));
            }
            Rule::item => {
                let item = pair.into_inner().next().unwrap();
                match item.as_rule() {
                    Rule::struct_definition => {
                        ast.push(SourceUnit::Struct(parse_struct(item)));
                    }
                    Rule::contract_definition => {
                        ast.push(SourceUnit::Contract(parse_contract(item)));
                    }
                    _ => unreachable!(),
                }
            }
            Rule::EOI => (),
            _ => {} // Ignore whitespace and comments
        }
    }

    Ok((version_req, ast))
}

fn parse_version_requirement(pair: Pair<Rule>) -> VersionRequirement {
    let mut inner = pair.into_inner();

    // Find version_requirement rule
    if let Some(version_req) = inner.find(|p| p.as_rule() == Rule::version_requirement) {
        // Parse first comparator and version (simplified)
        // Full implementation would handle multiple constraints like ">=1.0.0 <2.0.0"
        let mut parts = version_req.into_inner();

        let comparator = if let Some(comp_pair) = parts.next() {
            comp_pair.as_str().to_string()
        } else {
            "^".to_string() // Default to caret
        };

        let version = if let Some(ver_pair) = parts.next() {
            ver_pair.as_str().to_string()
        } else {
            "1.0.0".to_string()
        };

        VersionRequirement {
            comparator,
            version,
        }
    } else {
        // Fallback
        VersionRequirement {
            comparator: "^".to_string(),
            version: "1.0.0".to_string(),
        }
    }
}

fn parse_struct(pair: Pair<Rule>) -> StructDefinition {
    let mut name = String::new();
    let mut fields = Vec::new();

    for item in pair.into_inner() {
        match item.as_rule() {
            Rule::IDENT if name.is_empty() => {
                name = item.as_str().to_string();
            }
            Rule::struct_field => {
                fields.push(parse_struct_field(item));
            }
            _ => {}
        }
    }

    StructDefinition { name, fields }
}

fn parse_struct_field(pair: Pair<Rule>) -> Parameter {
    let mut name = String::new();
    let mut ty = Type::UInt256;

    extract_name_and_type(pair, &mut name, &mut ty);

    Parameter {
        ty,
        name,
        is_indexed: false,
    }
}

fn parse_contract(pair: Pair<Rule>) -> ContractDefinition {
    let mut name = String::new();
    let mut parts = Vec::new();
    let mut annotations = Vec::new();

    for item in pair.into_inner() {
        match item.as_rule() {
            Rule::annotation => {
                let annotation = parse_annotation(item);
                if annotation.name != "public" {
                    annotations.push(annotation);
                }
            }
            Rule::IDENT if name.is_empty() => {
                name = item.as_str().to_string();
            }
            Rule::contract_part => {
                if let Some(part) = item.into_inner().next() {
                    match part.as_rule() {
                        Rule::struct_definition | Rule::enum_definition => {
                            // Contract-local type declarations are parse-only metadata for now.
                        }
                        _ => parts.push(parse_contract_part(part)),
                    }
                }
            }
            Rule::state_variable_declaration
            | Rule::function_definition
            | Rule::constructor_definition
            | Rule::event_definition => {
                parts.push(parse_contract_part(item));
            }
            _ => {}
        }
    }

    ContractDefinition {
        name,
        parts,
        annotations,
    }
}

fn parse_contract_part(pair: Pair<Rule>) -> ContractPart {
    match pair.as_rule() {
        Rule::state_variable_declaration => ContractPart::StateVariable(parse_state_variable(pair)),
        Rule::function_definition => ContractPart::Function(parse_function(pair)),
        Rule::constructor_definition => ContractPart::Constructor(parse_constructor(pair)),
        Rule::event_definition => ContractPart::Event(parse_event(pair)),
        _ => {
            // Fallback - try to parse as function
            ContractPart::Function(parse_function(pair))
        }
    }
}

fn parse_constructor(pair: Pair<Rule>) -> ConstructorDefinition {
    let mut params = Vec::new();
    let mut body = Block { statements: vec![] };
    let mut annotations = Vec::new();

    for item in pair.into_inner() {
        match item.as_rule() {
            Rule::annotation => annotations.push(parse_annotation(item)),
            Rule::param => params.push(parse_param(item)),
            Rule::block => body = parse_block(item),
            _ => {}
        }
    }

    ConstructorDefinition {
        params,
        body,
        annotations,
    }
}

fn parse_event(pair: Pair<Rule>) -> EventDefinition {
    let mut name = String::new();
    let mut params = Vec::new();
    let mut annotations = Vec::new();

    for item in pair.into_inner() {
        match item.as_rule() {
            Rule::annotation => annotations.push(parse_annotation(item)),
            Rule::IDENT if name.is_empty() => {
                name = item.as_str().to_string();
            }
            Rule::event_param | Rule::param => {
                params.push(parse_event_param(item));
            }
            _ => {}
        }
    }

    EventDefinition {
        name,
        params,
        annotations,
    }
}

fn parse_state_variable(pair: Pair<Rule>) -> StateVariableDeclaration {
    let mut name = String::new();
    let mut ty = Type::UInt256;
    let mut is_public = false;
    let mut annotations = Vec::new();

    for item in pair.into_inner() {
        match item.as_rule() {
            Rule::annotation => {
                let annotation = parse_annotation(item);
                if annotation.name != "public" {
                    annotations.push(annotation);
                }
            }
            Rule::synq_state_variable_declaration | Rule::solidity_state_variable_declaration => {
                let state_text = item.as_str().to_string();
                for state_item in item.into_inner() {
                    match state_item.as_rule() {
                        Rule::type_decl => ty = parse_type(state_item),
                        Rule::IDENT if name.is_empty() => {
                            name = state_item.as_str().to_string();
                        }
                        _ => {}
                    }
                }

                if state_text.contains("public") {
                    is_public = true;
                }
            }
            _ => {}
        }
    }

    StateVariableDeclaration {
        ty,
        name,
        is_public,
        annotations,
    }
}

fn parse_function(pair: Pair<Rule>) -> FunctionDefinition {
    let mut is_public = pair.as_str().contains("@public");
    let mut name = String::new();
    let mut params = Vec::new();
    let mut returns: Option<Type> = None;
    let mut body = Block { statements: vec![] };
    let mut annotations = Vec::new();

    for item in pair.into_inner() {
        match item.as_rule() {
            Rule::annotation => {
                let annotation = parse_annotation(item);
                if annotation.name != "public" {
                    annotations.push(annotation);
                }
            }
            Rule::IDENT if name.is_empty() => {
                name = item.as_str().to_string();
            }
            Rule::param => {
                params.push(parse_param(item));
            }
            Rule::visibility_kw => {
                if item.as_str() == "public" {
                    is_public = true;
                }
            }
            Rule::return_type | Rule::tuple_type | Rule::type_decl => {
                // Top-level return type in a function definition.
                returns = Some(parse_return_type(item));
            }
            Rule::block => {
                body = parse_block(item);
            }
            _ => {}
        }
    }

    FunctionDefinition {
        name,
        params,
        returns,
        body,
        is_public,
        annotations,
    }
}

fn parse_param(pair: Pair<Rule>) -> Parameter {
    let mut name = String::new();
    let mut ty = Type::UInt256;

    extract_name_and_type(pair, &mut name, &mut ty);

    Parameter {
        ty,
        name,
        is_indexed: false,
    }
}

fn parse_block(pair: Pair<Rule>) -> Block {
    let statements = pair.into_inner().filter_map(parse_statement).collect();
    Block { statements }
}

fn parse_statement(pair: Pair<Rule>) -> Option<Statement> {
    let statement = if pair.as_rule() == Rule::statement {
        pair.into_inner().next()?
    } else {
        pair
    };

    match statement.as_rule() {
        Rule::expression_statement => {
            let mut inner = statement.into_inner();
            let expr = inner.next().map(parse_expression)?;
            Some(Statement::Expression(expr))
        }
        Rule::revert_statement => {
            let message = statement
                .into_inner()
                .find(|p| p.as_rule() == Rule::STRING_LITERAL)
                .map(parse_string_literal)
                .unwrap_or_else(|| "Execution reverted".to_string());
            Some(Statement::Revert(message))
        }
        Rule::return_statement => {
            let expr = statement
                .into_inner()
                .find(|p| p.as_rule() == Rule::expression)
                .map(parse_expression);
            Some(Statement::Return(expr))
        }
        Rule::variable_declaration => {
            let mut name = String::new();
            let mut ty = Type::UInt256;
            let mut expr: Option<Expression> = None;

            for item in statement.into_inner() {
                match item.as_rule() {
                    Rule::IDENT if name.is_empty() => {
                        name = item.as_str().to_string();
                    }
                    Rule::type_decl => {
                        ty = parse_type(item);
                    }
                    Rule::expression => {
                        expr = Some(parse_expression(item));
                    }
                    _ => {}
                }
            }

            if name.is_empty() {
                return None;
            }

            Some(Statement::VariableDeclaration(name, ty, expr))
        }
        Rule::typed_variable_declaration => {
            let mut name = String::new();
            let mut ty = Type::UInt256;
            let mut expr: Option<Expression> = None;

            for item in statement.into_inner() {
                match item.as_rule() {
                    Rule::type_decl => {
                        ty = parse_type(item);
                    }
                    Rule::IDENT if name.is_empty() => {
                        name = item.as_str().to_string();
                    }
                    Rule::expression => {
                        expr = Some(parse_expression(item));
                    }
                    _ => {}
                }
            }

            if name.is_empty() {
                return None;
            }

            Some(Statement::VariableDeclaration(name, ty, expr))
        }
        Rule::assignment => {
            let mut name = String::new();
            let mut rhs_expr: Option<Expression> = None;

            for item in statement.into_inner() {
                match item.as_rule() {
                    Rule::lvalue => {
                        for lvalue_item in item.into_inner() {
                            if lvalue_item.as_rule() == Rule::IDENT && name.is_empty() {
                                name = lvalue_item.as_str().to_string();
                                break;
                            }
                        }
                    }
                    Rule::IDENT if name.is_empty() => {
                        name = item.as_str().to_string();
                    }
                    Rule::expression => {
                        rhs_expr = Some(parse_expression(item));
                    }
                    _ => {}
                }
            }

            if name.is_empty() {
                return None;
            }

            rhs_expr.map(|expr| Statement::Assignment(name, expr))
        }
        Rule::require_statement => {
            let mut condition: Option<Expression> = None;
            let mut message = "require failed".to_string();

            for item in statement.into_inner() {
                match item.as_rule() {
                    Rule::expression => condition = Some(parse_expression(item)),
                    Rule::STRING_LITERAL => message = parse_string_literal(item),
                    _ => {}
                }
            }

            condition.map(|expr| Statement::Require(expr, message))
        }
        Rule::if_statement => {
            let mut condition: Option<Expression> = None;
            let mut then_block: Option<Block> = None;
            let mut else_block: Option<Block> = None;

            for item in statement.into_inner() {
                match item.as_rule() {
                    Rule::expression if condition.is_none() => {
                        condition = Some(parse_expression(item));
                    }
                    Rule::block if then_block.is_none() => {
                        then_block = Some(parse_block(item));
                    }
                    Rule::block => {
                        else_block = Some(parse_block(item));
                    }
                    Rule::if_statement => {
                        if let Some(nested_else_if) = parse_statement(item) {
                            else_block = Some(Block {
                                statements: vec![nested_else_if],
                            });
                        }
                    }
                    _ => {}
                }
            }

            match (condition, then_block) {
                (Some(cond), Some(then_b)) => Some(Statement::If(cond, then_b, else_block)),
                _ => None,
            }
        }
        Rule::emit_statement => {
            let mut event_name = String::new();
            let mut args = Vec::new();

            for item in statement.into_inner() {
                match item.as_rule() {
                    Rule::IDENT if event_name.is_empty() => {
                        event_name = item.as_str().to_string();
                    }
                    Rule::expression_list => {
                        args.extend(
                            item.into_inner()
                                .filter(|p| p.as_rule() == Rule::expression)
                                .map(parse_expression),
                        );
                    }
                    _ => {}
                }
            }

            if event_name.is_empty() {
                return None;
            }

            Some(Statement::Emit(event_name, args))
        }
        Rule::require_pqc_block => {
            let mut pqc_block = Block { statements: vec![] };
            let mut fallback: Option<Box<Statement>> = None;

            for item in statement.into_inner() {
                match item.as_rule() {
                    Rule::block => {
                        pqc_block = parse_block(item);
                    }
                    Rule::revert_statement | Rule::return_statement | Rule::statement => {
                        if let Some(parsed) = parse_statement(item) {
                            fallback = Some(Box::new(parsed));
                        }
                    }
                    _ => {}
                }
            }

            Some(Statement::RequirePqc(pqc_block, fallback))
        }
        Rule::for_statement => parse_for_statement(statement),
        _ => None,
    }
}

fn parse_annotation(pair: Pair<Rule>) -> Annotation {
    let mut name = String::new();
    let mut args = Vec::new();

    for item in pair.into_inner() {
        match item.as_rule() {
            Rule::IDENT if name.is_empty() => {
                name = item.as_str().to_string();
            }
            Rule::annotation_args => {
                for arg in item.into_inner() {
                    if arg.as_rule() != Rule::annotation_arg {
                        continue;
                    }
                    for arg_item in arg.into_inner() {
                        if arg_item.as_rule() == Rule::expression {
                            args.push(parse_expression(arg_item));
                        }
                    }
                }
            }
            _ => {}
        }
    }

    Annotation { name, args }
}

fn parse_event_param(pair: Pair<Rule>) -> Parameter {
    let is_indexed = pair.as_str().contains("indexed");
    let mut name = String::new();
    let mut ty = Type::UInt256;

    extract_name_and_type(pair, &mut name, &mut ty);

    Parameter {
        ty,
        name,
        is_indexed,
    }
}

fn parse_for_statement(pair: Pair<Rule>) -> Option<Statement> {
    let mut iterator = String::new();
    let mut start: Option<Expression> = None;
    let mut end: Option<Expression> = None;
    let mut body: Option<Block> = None;

    for item in pair.into_inner() {
        match item.as_rule() {
            Rule::for_init => {
                let mut identifiers = Vec::new();
                let mut expressions = Vec::new();

                for init_part in item.into_inner() {
                    match init_part.as_rule() {
                        Rule::IDENT => identifiers.push(init_part.as_str().to_string()),
                        Rule::expression => expressions.push(parse_expression(init_part)),
                        _ => {}
                    }
                }

                if let Some(first_ident) = identifiers.first() {
                    iterator = first_ident.clone();
                }

                if expressions.len() >= 2 {
                    start = Some(expressions[0].clone());
                    if expressions.len() == 2 {
                        end = Some(expressions[1].clone());
                    } else {
                        end = Some(
                            extract_for_loop_end_bound(&iterator, &expressions[1])
                                .unwrap_or_else(|| expressions[1].clone()),
                        );
                    }
                }
            }
            Rule::block => {
                body = Some(parse_block(item));
            }
            _ => {}
        }
    }

    match (start, end, body) {
        (Some(start_expr), Some(end_expr), Some(loop_body)) if !iterator.is_empty() => {
            Some(Statement::For(iterator, start_expr, end_expr, loop_body))
        }
        _ => None,
    }
}

fn extract_for_loop_end_bound(iterator: &str, condition: &Expression) -> Option<Expression> {
    match condition {
        Expression::Binary(op, lhs, rhs) => match op {
            BinaryOp::Lt | BinaryOp::Le | BinaryOp::Gt | BinaryOp::Ge => match (&**lhs, &**rhs) {
                (Expression::Identifier(name), expr) if name == iterator => Some(expr.clone()),
                (expr, Expression::Identifier(name)) if name == iterator => Some(expr.clone()),
                _ => None,
            },
            _ => None,
        },
        _ => None,
    }
}

fn parse_expression(pair: Pair<Rule>) -> Expression {
    parse_expression_text(pair.as_str())
        .unwrap_or_else(|| Expression::Identifier(pair.as_str().trim().to_string()))
}

fn parse_expression_text(raw: &str) -> Option<Expression> {
    let text = trim_wrapping_parens(raw.trim());
    if text.is_empty() {
        return None;
    }

    if let Some((q_pos, c_pos)) = find_top_level_ternary_positions(text) {
        let cond = parse_expression_text(&text[..q_pos])?;
        let then_expr = parse_expression_text(&text[q_pos + 1..c_pos])?;
        let else_expr = parse_expression_text(&text[c_pos + 1..])?;
        return Some(Expression::Ternary(
            Box::new(cond),
            Box::new(then_expr),
            Box::new(else_expr),
        ));
    }

    const BINARY_PRECEDENCE: &[(&[&str], BinaryOp)] = &[
        (&["||"], BinaryOp::Or),
        (&["&&"], BinaryOp::And),
        (&["=="], BinaryOp::Eq),
        (&["!="], BinaryOp::Ne),
        (&["<=", ">=", "<", ">"], BinaryOp::Lt),
        (&["+", "-"], BinaryOp::Add),
        (&["*", "/", "%"], BinaryOp::Mul),
    ];

    for (ops, default_op) in BINARY_PRECEDENCE {
        if let Some((idx, op)) = find_top_level_operator(text, ops) {
            let lhs = parse_expression_text(&text[..idx])?;
            let rhs = parse_expression_text(&text[idx + op.len()..])?;
            let binary_op = match op {
                "||" => BinaryOp::Or,
                "&&" => BinaryOp::And,
                "==" => BinaryOp::Eq,
                "!=" => BinaryOp::Ne,
                "<" => BinaryOp::Lt,
                "<=" => BinaryOp::Le,
                ">" => BinaryOp::Gt,
                ">=" => BinaryOp::Ge,
                "+" => BinaryOp::Add,
                "-" => BinaryOp::Sub,
                "*" => BinaryOp::Mul,
                "/" => BinaryOp::Div,
                "%" => BinaryOp::Mod,
                _ => default_op.clone(),
            };
            return Some(Expression::Binary(binary_op, Box::new(lhs), Box::new(rhs)));
        }
    }

    if let Some(rest) = text.strip_prefix('!') {
        let expr = parse_expression_text(rest)?;
        return Some(Expression::Unary(UnaryOp::Not, Box::new(expr)));
    }

    if let Some(rest) = text.strip_prefix('-') {
        if rest.chars().all(|c| c.is_ascii_digit()) {
            return None;
        }
        let expr = parse_expression_text(rest)?;
        return Some(Expression::Unary(UnaryOp::Neg, Box::new(expr)));
    }

    if let Some(literal) = parse_literal(text) {
        return Some(Expression::Literal(literal));
    }

    if let Some((callee, args)) = parse_call_expression(text) {
        return Some(Expression::Call(callee.to_string(), args));
    }

    if is_identifier(text) {
        return Some(Expression::Identifier(text.to_string()));
    }

    None
}

fn parse_call_expression(text: &str) -> Option<(&str, Vec<Expression>)> {
    if !text.ends_with(')') {
        return None;
    }

    let open = find_top_level_open_paren(text)?;
    let callee = text[..open].trim();
    if !is_identifier(callee) {
        return None;
    }

    let args_src = &text[open + 1..text.len() - 1];
    let args = if args_src.trim().is_empty() {
        Vec::new()
    } else {
        split_top_level(args_src, ',')
            .into_iter()
            .filter_map(|item| {
                let trimmed = item.trim();
                if trimmed.is_empty() {
                    return None;
                }
                Some(
                    parse_expression_text(trimmed)
                        .unwrap_or_else(|| Expression::Identifier(trimmed.to_string())),
                )
            })
            .collect()
    };

    Some((callee, args))
}

fn parse_literal(text: &str) -> Option<Literal> {
    if text == "true" {
        return Some(Literal::Bool(true));
    }
    if text == "false" {
        return Some(Literal::Bool(false));
    }
    if text == "null" {
        return None;
    }

    if text.starts_with('"') && text.ends_with('"') && text.len() >= 2 {
        return Some(Literal::String(text[1..text.len() - 1].to_string()));
    }

    if text.starts_with("Bytes(\"") && text.ends_with("\")") {
        let hex = &text[7..text.len() - 2];
        let bytes = decode_hex(hex)?;
        return Some(Literal::Bytes(bytes));
    }

    if text.starts_with("0x")
        && text.len() == 42
        && text[2..].chars().all(|c| c.is_ascii_hexdigit())
    {
        return Some(Literal::Address(text.to_string()));
    }

    if text.chars().all(|c| c.is_ascii_digit()) {
        let value = text.parse::<u64>().ok()?;
        return Some(Literal::Number(value));
    }

    None
}

fn parse_string_literal(pair: Pair<Rule>) -> String {
    let value = pair.as_str().trim();
    if value.starts_with('"') && value.ends_with('"') && value.len() >= 2 {
        value[1..value.len() - 1].to_string()
    } else {
        value.to_string()
    }
}

fn trim_wrapping_parens(input: &str) -> &str {
    let mut text = input.trim();
    loop {
        if !(text.starts_with('(') && text.ends_with(')')) {
            return text;
        }

        let mut depth = 0usize;
        let mut wraps = true;
        for (idx, ch) in text.char_indices() {
            match ch {
                '(' => depth += 1,
                ')' => {
                    if depth == 0 {
                        wraps = false;
                        break;
                    }
                    depth -= 1;
                    if depth == 0 && idx + ch.len_utf8() < text.len() {
                        wraps = false;
                        break;
                    }
                }
                _ => {}
            }
        }

        if wraps {
            text = text[1..text.len() - 1].trim();
        } else {
            return text;
        }
    }
}

fn find_top_level_open_paren(text: &str) -> Option<usize> {
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;

    for (idx, ch) in text.char_indices() {
        if in_string {
            if escaped {
                escaped = false;
                continue;
            }
            match ch {
                '\\' => escaped = true,
                '"' => in_string = false,
                _ => {}
            }
            continue;
        }

        match ch {
            '"' => in_string = true,
            '(' => {
                if depth == 0 {
                    return Some(idx);
                }
                depth += 1;
            }
            ')' => {
                depth = depth.saturating_sub(1);
            }
            _ => {}
        }
    }

    None
}

fn find_top_level_ternary_positions(text: &str) -> Option<(usize, usize)> {
    let mut depth_paren = 0usize;
    let mut depth_bracket = 0usize;
    let mut depth_brace = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    let mut question_pos: Option<usize> = None;

    for (idx, ch) in text.char_indices() {
        if in_string {
            if escaped {
                escaped = false;
                continue;
            }
            match ch {
                '\\' => escaped = true,
                '"' => in_string = false,
                _ => {}
            }
            continue;
        }

        match ch {
            '"' => in_string = true,
            '(' => depth_paren += 1,
            ')' => depth_paren = depth_paren.saturating_sub(1),
            '[' => depth_bracket += 1,
            ']' => depth_bracket = depth_bracket.saturating_sub(1),
            '{' => depth_brace += 1,
            '}' => depth_brace = depth_brace.saturating_sub(1),
            '?' if depth_paren == 0 && depth_bracket == 0 && depth_brace == 0 => {
                question_pos = Some(idx)
            }
            ':' if depth_paren == 0 && depth_bracket == 0 && depth_brace == 0 => {
                if let Some(q_idx) = question_pos {
                    return Some((q_idx, idx));
                }
            }
            _ => {}
        }
    }

    None
}

fn find_top_level_operator<'a>(text: &'a str, ops: &[&'a str]) -> Option<(usize, &'a str)> {
    let mut depth_paren = 0usize;
    let mut depth_bracket = 0usize;
    let mut depth_brace = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    let mut candidate: Option<(usize, &str)> = None;

    for (idx, ch) in text.char_indices() {
        if in_string {
            if escaped {
                escaped = false;
                continue;
            }
            match ch {
                '\\' => escaped = true,
                '"' => in_string = false,
                _ => {}
            }
            continue;
        }

        match ch {
            '"' => {
                in_string = true;
                continue;
            }
            '(' => {
                depth_paren += 1;
                continue;
            }
            ')' => {
                depth_paren = depth_paren.saturating_sub(1);
                continue;
            }
            '[' => {
                depth_bracket += 1;
                continue;
            }
            ']' => {
                depth_bracket = depth_bracket.saturating_sub(1);
                continue;
            }
            '{' => {
                depth_brace += 1;
                continue;
            }
            '}' => {
                depth_brace = depth_brace.saturating_sub(1);
                continue;
            }
            _ => {}
        }

        if depth_paren != 0 || depth_bracket != 0 || depth_brace != 0 {
            continue;
        }

        for op in ops {
            if text[idx..].starts_with(op) {
                if (*op == "-" || *op == "+") && is_unary_operator(text, idx) {
                    continue;
                }
                candidate = Some((idx, *op));
                break;
            }
        }
    }

    candidate
}

fn is_unary_operator(text: &str, op_idx: usize) -> bool {
    let prefix = &text[..op_idx];
    let Some(prev) = prefix.chars().rev().find(|c| !c.is_whitespace()) else {
        return true;
    };

    matches!(
        prev,
        '(' | '['
            | '{'
            | ','
            | ':'
            | '?'
            | '+'
            | '-'
            | '*'
            | '/'
            | '%'
            | '!'
            | '<'
            | '>'
            | '='
            | '&'
            | '|'
    )
}

fn split_top_level(text: &str, delimiter: char) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0usize;
    let mut depth_paren = 0usize;
    let mut depth_bracket = 0usize;
    let mut depth_brace = 0usize;
    let mut in_string = false;
    let mut escaped = false;

    for (idx, ch) in text.char_indices() {
        if in_string {
            if escaped {
                escaped = false;
                continue;
            }
            match ch {
                '\\' => escaped = true,
                '"' => in_string = false,
                _ => {}
            }
            continue;
        }

        match ch {
            '"' => in_string = true,
            '(' => depth_paren += 1,
            ')' => depth_paren = depth_paren.saturating_sub(1),
            '[' => depth_bracket += 1,
            ']' => depth_bracket = depth_bracket.saturating_sub(1),
            '{' => depth_brace += 1,
            '}' => depth_brace = depth_brace.saturating_sub(1),
            _ => {}
        }

        if ch == delimiter && depth_paren == 0 && depth_bracket == 0 && depth_brace == 0 {
            parts.push(text[start..idx].trim());
            start = idx + ch.len_utf8();
        }
    }

    if start <= text.len() {
        let tail = text[start..].trim();
        if !tail.is_empty() {
            parts.push(tail);
        }
    }

    parts
}

fn decode_hex(hex: &str) -> Option<Vec<u8>> {
    if hex.len() % 2 != 0 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }

    let mut out = Vec::with_capacity(hex.len() / 2);
    let bytes = hex.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        let part = std::str::from_utf8(&bytes[i..i + 2]).ok()?;
        let value = u8::from_str_radix(part, 16).ok()?;
        out.push(value);
        i += 2;
    }
    Some(out)
}

fn is_identifier(text: &str) -> bool {
    let mut chars = text.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn parse_type(pair: Pair<Rule>) -> Type {
    match pair.as_rule() {
        Rule::mapping_type => {
            let mut inner = pair.into_inner();
            let key = inner
                .next()
                .map(parse_type)
                .unwrap_or(Type::Struct("Unknown".to_string()));
            let value = inner
                .next()
                .map(parse_type)
                .unwrap_or(Type::Struct("Unknown".to_string()));
            Type::Mapping(Box::new(key), Box::new(value))
        }
        Rule::type_decl => {
            let mut base: Option<Type> = None;
            let mut array_suffix: Option<String> = None;

            for item in pair.into_inner() {
                match item.as_rule() {
                    Rule::mapping_type => {
                        base = Some(parse_type(item));
                    }
                    Rule::base_type => {
                        base = Some(parse_base_type_name(item.as_str()));
                    }
                    Rule::array_suffix => {
                        array_suffix = Some(item.as_str().to_string());
                    }
                    _ => {}
                }
            }

            let mut ty = base.unwrap_or(Type::Struct("Unknown".to_string()));

            if let Some(suffix) = array_suffix {
                let size = parse_array_suffix_size(&suffix);
                ty = Type::Array(Box::new(ty), size);
            }

            ty
        }
        Rule::base_type => parse_base_type_name(pair.as_str()),
        _ => Type::Struct(pair.as_str().to_string()),
    }
}

fn parse_base_type_name(name: &str) -> Type {
    match name {
        "Address" => Type::Address,
        "UInt256" => Type::UInt256,
        "UInt128" => Type::UInt128,
        "UInt64" => Type::UInt64,
        "UInt32" => Type::UInt32,
        "UInt8" => Type::UInt8,
        "Int256" => Type::Int256,
        "Int128" => Type::Int128,
        "Int64" => Type::Int64,
        "Int32" => Type::Int32,
        "Int8" => Type::Int8,
        "Bool" => Type::Bool,
        "Bytes" => Type::Bytes,
        "String" => Type::String,
        "MLDSAPublicKey" => Type::MLDSAPublicKey,
        "MLDSAKeyPair" => Type::MLDSAKeyPair,
        "MLDSASignature" => Type::MLDSASignature,
        "FNDSAPublicKey" => Type::FNDSAPublicKey,
        "FNDSAKeyPair" => Type::FNDSAKeyPair,
        "FNDSASignature" => Type::FNDSASignature,
        "MLKEMPublicKey" => Type::MLKEMPublicKey,
        "MLKEMKeyPair" => Type::MLKEMKeyPair,
        "MLKEMCiphertext" => Type::MLKEMCiphertext,
        "SLHDSAPublicKey" => Type::SLHDSAPublicKey,
        "SLHDSAKeyPair" => Type::SLHDSAKeyPair,
        "SLHDSASignature" => Type::SLHDSASignature,
        _ => {
            // Unknown type - try to parse as generic or struct
            Type::Struct(name.to_string())
        }
    }
}

fn parse_array_suffix_size(suffix: &str) -> Option<u32> {
    if suffix == "[]" {
        return None;
    }

    let trimmed = suffix.trim();
    if !(trimmed.starts_with('[') && trimmed.ends_with(']')) {
        return None;
    }

    let inner = &trimmed[1..trimmed.len() - 1];
    if inner.is_empty() {
        return None;
    }

    inner.parse::<u32>().ok()
}

fn parse_return_type(pair: Pair<Rule>) -> Type {
    match pair.as_rule() {
        Rule::return_type => {
            let mut inner = pair.into_inner();
            inner
                .next()
                .map(parse_return_type)
                .unwrap_or(Type::Struct("Unknown".to_string()))
        }
        Rule::tuple_type => {
            let mut items = Vec::new();
            for item in pair.into_inner() {
                if item.as_rule() == Rule::type_decl {
                    items.push(parse_type(item));
                }
            }
            Type::Generic("Tuple".to_string(), items)
        }
        Rule::type_decl => parse_type(pair),
        _ => Type::Struct("Unknown".to_string()),
    }
}

fn extract_name_and_type(pair: Pair<Rule>, name: &mut String, ty: &mut Type) {
    match pair.as_rule() {
        Rule::IDENT if name.is_empty() => {
            *name = pair.as_str().to_string();
        }
        Rule::type_decl => {
            *ty = parse_type(pair);
        }
        _ => {
            for item in pair.into_inner() {
                extract_name_and_type(item, name, ty);
            }
        }
    }
}
