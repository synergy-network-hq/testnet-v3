use compiler::{analyze, parse};

fn analyze_source(source: &str) -> Result<(), Vec<compiler::ast::SemanticError>> {
    let (_version_req, ast) = parse(source).expect("source should parse for semantic test");
    analyze(&ast)
}

#[test]
fn semantic_accepts_declared_symbols() {
    let source = r#"
contract SafeContract {
    counter: UInt256 public;

    function bump() -> UInt256 {
        let local: UInt256 = counter + 1;
        counter = local;
        return local;
    }
}
"#;

    assert!(analyze_source(source).is_ok());
}

#[test]
fn semantic_rejects_duplicate_state_variables() {
    let source = r#"
contract DuplicateState {
    counter: UInt256 public;
    counter: UInt256 public;
}
"#;

    let errors = analyze_source(source).expect_err("duplicate state vars must fail");
    assert!(errors
        .iter()
        .any(|e| e.message.contains("duplicate state variable `counter`")));
}

#[test]
fn semantic_rejects_assignment_to_undefined_symbol() {
    let source = r#"
contract MissingSymbol {
    function write() {
        ghost = 1;
    }
}
"#;

    let errors = analyze_source(source).expect_err("undefined assignment must fail");
    assert!(errors
        .iter()
        .any(|e| e.message.contains("assigns to undefined symbol `ghost`")));
}

#[test]
fn semantic_rejects_missing_return_value() {
    let source = r#"
contract MissingReturnValue {
    function compute() -> UInt256 {
        return;
    }
}
"#;

    let errors = analyze_source(source).expect_err("missing return value must fail");
    assert!(errors
        .iter()
        .any(|e| e.message.contains("must return a value")));
}

#[test]
fn semantic_rejects_return_value_for_void_function() {
    let source = r#"
contract VoidReturnValue {
    function noop() {
        return 1;
    }
}
"#;

    let errors = analyze_source(source).expect_err("void return value must fail");
    assert!(errors
        .iter()
        .any(|e| e.message.contains("cannot return a value")));
}

#[test]
fn semantic_rejects_duplicate_parameters() {
    let source = r#"
contract DuplicateParams {
    function set(a: UInt256, a: UInt256) {
    }
}
"#;

    let errors = analyze_source(source).expect_err("duplicate params must fail");
    assert!(errors
        .iter()
        .any(|e| e.message.contains("duplicate parameter `a`")));
}

#[test]
fn semantic_rejects_variable_initializer_type_mismatch() {
    let source = r#"
contract TypeMismatchInit {
    function bad_init() {
        let flag: Bool = 1;
    }
}
"#;

    let errors = analyze_source(source).expect_err("initializer type mismatch must fail");
    assert!(errors.iter().any(|e| e
        .message
        .contains("initializes `flag` with incompatible type")));
}

#[test]
fn semantic_rejects_require_condition_type_mismatch() {
    let source = r#"
contract RequireTypeMismatch {
    function bad_require() {
        require(1, "not bool");
    }
}
"#;

    let errors = analyze_source(source).expect_err("require type mismatch must fail");
    assert!(errors
        .iter()
        .any(|e| e.message.contains("non-boolean require condition")));
}

#[test]
fn semantic_accepts_mldsa_builtin_with_expected_types() {
    let source = r#"
contract PqcBuiltins {
    function verify(pk: MLDSAPublicKey, msg: Bytes, sig: MLDSASignature) -> Bool {
        let ok: Bool = verifyMLDSASignature(pk, msg, sig);
        return ok;
    }
}
"#;

    assert!(analyze_source(source).is_ok());
}

#[test]
fn semantic_rejects_mldsa_builtin_argument_type_order_mismatch() {
    let source = r#"
contract PqcBuiltins {
    function verify(pk: MLDSAPublicKey, msg: Bytes, sig: MLDSASignature) -> Bool {
        let ok: Bool = verifyMLDSASignature(msg, pk, sig);
        return ok;
    }
}
"#;

    let errors = analyze_source(source).expect_err("builtin argument mismatch must fail");
    assert!(errors
        .iter()
        .any(|e| e.message.contains("passes incompatible argument")));
}

#[test]
fn semantic_rejects_de_scoped_slhdsa_builtin() {
    let source = r#"
contract SlhDisabled {
    function verify(pk: SLHDSAPublicKey, msg: Bytes, sig: SLHDSASignature) -> Bool {
        return verifySLHDSASignature(pk, msg, sig);
    }
}
"#;

    let errors = analyze_source(source).expect_err("SLH-DSA builtin usage must fail");
    assert!(errors.iter().any(|e| e
        .message
        .contains("unsupported builtin `verifySLHDSASignature`")));
}

#[test]
fn semantic_accepts_hqckem_decapsulation_signature() {
    let source = r#"
contract HqcBuiltins {
    function run(ciphertext: Bytes, privateKey: Bytes) {
        let sharedSecret: Bytes = hqckem_hqckem128_decapsulate(ciphertext, privateKey);
    }
}
"#;

    assert!(analyze_source(source).is_ok());
}

#[test]
fn semantic_rejects_non_void_function_with_partial_return_paths() {
    let source = r#"
contract ControlFlow {
    function maybe(flag: Bool) -> UInt256 {
        if (flag) {
            return 1;
        }
    }
}
"#;

    let errors = analyze_source(source).expect_err("partial return paths must fail");
    assert!(errors.iter().any(|e| e
        .message
        .contains("may exit without returning a value on all paths")));
}

#[test]
fn semantic_accepts_non_void_function_when_if_else_both_return() {
    let source = r#"
contract ControlFlow {
    function always(flag: Bool) -> UInt256 {
        if (flag) {
            return 1;
        } else {
            return 2;
        }
    }
}
"#;

    assert!(analyze_source(source).is_ok());
}

#[test]
fn semantic_rejects_unreachable_statement_after_return() {
    let source = r#"
contract DeadCode {
    function run() -> UInt256 {
        return 1;
        let dead: UInt256 = 2;
    }
}
"#;

    let errors = analyze_source(source).expect_err("unreachable statements must fail");
    assert!(errors
        .iter()
        .any(|e| e.message.contains("contains unreachable statement")));
}
