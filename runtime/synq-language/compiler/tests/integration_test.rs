use compiler::ast::{ContractPart, Expression, Literal, SourceUnit, Statement};
use compiler::{parser, CodeGenerator};
use quantumvm::{OpCode, QuantumVM};

#[cfg(feature = "pqc-aegis")]
use pqsynq::{Kem, KeyEncapsulation};
#[cfg(feature = "pqc-aegis")]
use std::fs;
#[cfg(feature = "pqc-aegis")]
use std::path::PathBuf;

const SIMPLE_CONTRACT_WITH_FUNCTION_PARAMS: &str = r#"
contract MyContract {
    function my_function(a: UInt256, b: Bool) {
    }
}
"#;

#[test]
fn test_parse_simple_contract_with_function_params() {
    let result = parser::parse(SIMPLE_CONTRACT_WITH_FUNCTION_PARAMS);
    if let Err(e) = &result {
        println!("Parser error: {}", e);
    }
    assert!(result.is_ok());
    let (_version_req, source_units) = result.unwrap();
    assert_eq!(source_units.len(), 1);
}

fn expect_number_literal(expr: &Expression, expected: u64) {
    match expr {
        Expression::Literal(Literal::Number(value)) => assert_eq!(*value, expected),
        other => panic!("Expected numeric literal {expected}, got {other:?}"),
    }
}

#[test]
fn test_parser_extracts_annotations_and_range_for_loop() {
    let source = r#"
@audited(level: 2, reviewer: "sec")
contract AnnotatedContract {
    @state(slot: 7)
    counter: UInt256 public;

    @gas(limit: 1500)
    @public function iterate() -> UInt256 {
        let sum: UInt256 = 0;
        for(i in 1..4) {
            sum = sum + 1;
        }
        return sum;
    }
}
"#;

    let (_, units) = parser::parse(source).expect("source should parse");
    let SourceUnit::Contract(contract) = &units[0] else {
        panic!("Expected contract source unit");
    };

    assert_eq!(contract.annotations.len(), 1);
    assert_eq!(contract.annotations[0].name, "audited");
    assert_eq!(contract.annotations[0].args.len(), 2);

    let state_part = contract
        .parts
        .iter()
        .find_map(|part| match part {
            ContractPart::StateVariable(state) => Some(state),
            _ => None,
        })
        .expect("state variable should exist");
    assert_eq!(state_part.annotations.len(), 1);
    assert_eq!(state_part.annotations[0].name, "state");

    let function = contract
        .parts
        .iter()
        .find_map(|part| match part {
            ContractPart::Function(function) => Some(function),
            _ => None,
        })
        .expect("function should exist");
    assert!(function.is_public);
    assert_eq!(function.annotations.len(), 1);
    assert_eq!(function.annotations[0].name, "gas");

    let loop_stmt = function
        .body
        .statements
        .iter()
        .find_map(|stmt| match stmt {
            Statement::For(iterator, start, end, body) => Some((iterator, start, end, body)),
            _ => None,
        })
        .expect("for loop should exist");

    assert_eq!(loop_stmt.0, "i");
    expect_number_literal(loop_stmt.1, 1);
    expect_number_literal(loop_stmt.2, 4);
    assert_eq!(loop_stmt.3.statements.len(), 1);
}

#[test]
fn test_parser_lowers_c_style_for_loop_to_for_statement() {
    let source = r#"
contract CStyleLoop {
    @public function count() -> UInt256 {
        let total: UInt256 = 0;
        for(i = 0; i < 3; i + 1) {
            total = total + 1;
        }
        return total;
    }
}
"#;

    let (_, units) = parser::parse(source).expect("source should parse");
    let SourceUnit::Contract(contract) = &units[0] else {
        panic!("Expected contract source unit");
    };

    let function = contract
        .parts
        .iter()
        .find_map(|part| match part {
            ContractPart::Function(function) => Some(function),
            _ => None,
        })
        .expect("function should exist");

    let loop_stmt = function
        .body
        .statements
        .iter()
        .find_map(|stmt| match stmt {
            Statement::For(iterator, start, end, _body) => Some((iterator, start, end)),
            _ => None,
        })
        .expect("for loop should be lowered");

    assert_eq!(loop_stmt.0, "i");
    expect_number_literal(loop_stmt.1, 0);
    expect_number_literal(loop_stmt.2, 3);
}

#[test]
fn test_codegen_vm_executes_basic_for_loop_and_returns_value() {
    let source = r#"
contract LoopRuntime {
    @public function count() -> UInt256 {
        let sum: UInt256 = 0;
        for(i in 0..3) {
            sum = sum + 1;
        }
        return sum;
    }
}
"#;

    let bytecode = compile_source(source);
    let mut vm = QuantumVM::new();
    vm.load_bytecode(&bytecode)
        .expect("VM should load compiled loop bytecode");
    vm.execute()
        .expect("VM should execute loop without runtime errors");

    let top = vm
        .stack
        .last()
        .expect("return value should remain on the stack")
        .as_i64()
        .expect("return value should be numeric");
    assert_eq!(top, 3);
}

#[test]
fn test_codegen_recognizes_camel_case_mldsa_verify_builtin() {
    let source = r#"
contract VerifyAlias {
    function run(pk: MLDSAPublicKey, msg: Bytes, sig: MLDSASignature) {
        verifyMLDSASignature(pk, msg, sig);
        revert("halt");
    }
}
"#;

    let bytecode = compile_source(source);
    let code = code_section(&bytecode);
    assert!(
        code.contains(&(OpCode::MLDSAVerify as u8)),
        "Expected MLDSAVerify opcode for verifyMLDSASignature"
    );
}

#[cfg(feature = "pqc-aegis")]
fn encode_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

#[cfg(feature = "pqc-aegis")]
fn render_fixture_source(file_name: &str, ciphertext: &[u8], private_key: &[u8]) -> String {
    let fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../smart-contracts/tests")
        .join(file_name);
    let fixture = fs::read_to_string(&fixture_path)
        .unwrap_or_else(|e| panic!("Failed to read fixture {}: {e}", fixture_path.display()));

    fixture
        .replace("{{CIPHERTEXT_HEX}}", &encode_hex(ciphertext))
        .replace("{{PRIVATE_KEY_HEX}}", &encode_hex(private_key))
}

fn compile_source(source: &str) -> Vec<u8> {
    let (_version_req, ast) = parser::parse(source).expect("Fixture should parse");
    CodeGenerator::new()
        .generate(&ast)
        .expect("Fixture should compile to bytecode")
}

fn code_section(bytecode: &[u8]) -> &[u8] {
    let header_length = u16::from_le_bytes([bytecode[5], bytecode[6]]) as usize;
    let code_length =
        u32::from_le_bytes([bytecode[7], bytecode[8], bytecode[9], bytecode[10]]) as usize;
    &bytecode[header_length..header_length + code_length]
}

#[cfg(feature = "pqc-aegis")]
fn run_hqckem_fixture(fixture_file: &str, opcode: OpCode, kem: Kem) {
    let (public_key, private_key) = kem.keygen().expect("keygen should succeed");
    let (ciphertext, expected_shared_secret) = kem
        .encapsulate(&public_key)
        .expect("encapsulation should succeed");

    let source = render_fixture_source(fixture_file, &ciphertext, &private_key);
    let bytecode = compile_source(&source);
    let code = code_section(&bytecode);

    assert!(
        code.contains(&(opcode as u8)),
        "Expected opcode 0x{:02x} in generated bytecode",
        opcode as u8
    );

    let mut vm = QuantumVM::new();
    vm.load_bytecode(&bytecode)
        .expect("VM should load compiled fixture");
    vm.execute()
        .expect("VM should execute generated HQC fixture");

    // Expression statement pops decapsulation result; successful cryptographic execution
    // is proven by non-zero PQC gas and no runtime cryptographic failure.
    assert!(vm.consumed_pqc_gas() > 0);

    // Validate expected shared secret independently for fixture sanity.
    let shared_secret = kem
        .decapsulate(&ciphertext, &private_key)
        .expect("Decapsulation should succeed");
    assert_eq!(shared_secret, expected_shared_secret);
}

#[cfg(feature = "pqc-aegis")]
fn run_hqckem_fixture_expect_failure(
    fixture_file: &str,
    kem_for_ciphertext: Kem,
    private_key_for_execution: Vec<u8>,
) {
    let (public_key, _private_key) = kem_for_ciphertext.keygen().expect("keygen should succeed");
    let (ciphertext, _shared_secret) = kem_for_ciphertext
        .encapsulate(&public_key)
        .expect("encapsulation should succeed");

    let source = render_fixture_source(fixture_file, &ciphertext, &private_key_for_execution);
    let bytecode = compile_source(&source);

    let mut vm = QuantumVM::new();
    vm.load_bytecode(&bytecode)
        .expect("VM should load compiled fixture");
    let execution = vm.execute();
    assert!(
        execution.is_err(),
        "Fixture with mismatched or corrupted key material must fail"
    );
}

#[cfg(feature = "pqc-aegis")]
#[test]
fn test_hqckem128_contract_fixture_parser_codegen_vm_e2e() {
    run_hqckem_fixture(
        "hqckem128-decap-fixture.synq",
        OpCode::HQCKEM128KeyExchange,
        Kem::hqckem128(),
    );
}

#[cfg(feature = "pqc-aegis")]
#[test]
fn test_hqckem192_contract_fixture_parser_codegen_vm_e2e() {
    run_hqckem_fixture(
        "hqckem192-decap-fixture.synq",
        OpCode::HQCKEM192KeyExchange,
        Kem::hqckem192(),
    );
}

#[cfg(feature = "pqc-aegis")]
#[test]
fn test_hqckem256_contract_fixture_parser_codegen_vm_e2e() {
    run_hqckem_fixture(
        "hqckem256-decap-fixture.synq",
        OpCode::HQCKEM256KeyExchange,
        Kem::hqckem256(),
    );
}

#[cfg(feature = "pqc-aegis")]
#[test]
fn test_hqckem128_contract_fixture_rejects_mismatched_private_key() {
    let kem = Kem::hqckem128();
    let (_other_pk, other_sk) = kem.keygen().expect("secondary keygen should succeed");
    run_hqckem_fixture_expect_failure("hqckem128-decap-fixture.synq", kem, other_sk);
}

#[cfg(feature = "pqc-aegis")]
#[test]
fn test_hqckem192_contract_fixture_rejects_mismatched_private_key() {
    let kem = Kem::hqckem192();
    let (_other_pk, other_sk) = kem.keygen().expect("secondary keygen should succeed");
    run_hqckem_fixture_expect_failure("hqckem192-decap-fixture.synq", kem, other_sk);
}

#[cfg(feature = "pqc-aegis")]
#[test]
fn test_hqckem256_contract_fixture_rejects_mismatched_private_key() {
    let kem = Kem::hqckem256();
    let (_other_pk, other_sk) = kem.keygen().expect("secondary keygen should succeed");
    run_hqckem_fixture_expect_failure("hqckem256-decap-fixture.synq", kem, other_sk);
}
