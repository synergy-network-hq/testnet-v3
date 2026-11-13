use compiler::ast::{BinaryOp, ContractPart, Expression, SourceUnit, Statement};
use compiler::parse;

fn function_statements(source: &str, function_name: &str) -> Vec<Statement> {
    let (_, units) = parse(source).expect("source parses");
    let contract = units
        .iter()
        .find_map(|unit| match unit {
            SourceUnit::Contract(contract) => Some(contract),
            _ => None,
        })
        .expect("contract");
    contract
        .parts
        .iter()
        .find_map(|part| match part {
            ContractPart::Function(function) if function.name == function_name => {
                Some(function.body.statements.clone())
            }
            _ => None,
        })
        .expect("function")
}

#[test]
fn parser_preserves_nested_mapping_assignment_target() {
    let statements = function_statements(
        r#"
contract MappingWrites {
    approvals: mapping(UInt256 => mapping(Address => Bool)) public;
    function approve(id: UInt256) {
        approvals[id][msg.sender] = true;
    }
}
"#,
        "approve",
    );

    let Statement::Assignment(target, Expression::Literal(_)) = &statements[0] else {
        panic!("expected assignment");
    };
    let Expression::IndexAccess(outer, account) = target else {
        panic!("expected outer index");
    };
    assert!(matches!(
        &**account,
        Expression::MemberAccess(object, member)
            if matches!(&**object, Expression::Identifier(name) if name == "msg")
                && member == "sender"
    ));
    assert!(matches!(
        &**outer,
        Expression::IndexAccess(root, index)
            if matches!(&**root, Expression::Identifier(name) if name == "approvals")
                && matches!(&**index, Expression::Identifier(name) if name == "id")
    ));
}

#[test]
fn parser_preserves_index_reads_and_qualified_calls() {
    let statements = function_statements(
        r#"
contract ReadsAndCalls {
    values: mapping(Address => UInt256) public;
    signers: Address[] public;
    function update(account: Address) {
        values[account] = values[account] + msg.value;
        signers.push(account);
    }
}
"#,
        "update",
    );

    let Statement::Assignment(_, Expression::Binary(BinaryOp::Add, lhs, rhs)) = &statements[0]
    else {
        panic!("expected additive mapping assignment");
    };
    assert!(matches!(&**lhs, Expression::IndexAccess(_, _)));
    assert!(matches!(
        &**rhs,
        Expression::MemberAccess(object, member)
            if matches!(&**object, Expression::Identifier(name) if name == "msg")
                && member == "value"
    ));
    assert!(matches!(
        &statements[1],
        Statement::Expression(Expression::Call(name, args))
            if name == "signers.push" && args.len() == 1
    ));
}
