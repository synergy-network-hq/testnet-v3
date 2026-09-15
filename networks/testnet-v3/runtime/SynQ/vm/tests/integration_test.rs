use ruint::aliases::U256;
use synq_vm::{Assembler, OpCode, QuantumVM};

#[test]
fn test_basic_arithmetic() {
    let mut assembler = Assembler::new();
    assembler.emit_op(OpCode::Push);
    assembler.emit_i32(10);
    assembler.emit_op(OpCode::Push);
    assembler.emit_i32(20);
    assembler.emit_op(OpCode::Add);
    assembler.emit_op(OpCode::Halt);

    let bytecode = assembler.build();
    let mut vm = QuantumVM::new();
    vm.load_bytecode(&bytecode).unwrap();
    vm.execute().unwrap();

    let result = vm.stack.pop().unwrap().as_i32().unwrap();
    assert_eq!(result, 30);
}

#[test]
fn test_dilithium_verify_shim() {
    // Uses a REAL ML-DSA-65 keypair + real signature (not the old zeroed
    // placeholder bytes) so this test actually exercises the fixed
    // real-crypto verify path end to end through the VM opcode.
    let (pk, sk) = pqc_shims::dilithium::keygen();
    let message = b"Hello, quantum world!";
    let signature = pqc_shims::dilithium::sign(message, &sk);

    let mut assembler = Assembler::new();

    // The arguments are popped in reverse order of how they are pushed.
    // Push order: signature, message, public_key (public_key ends up on
    // top of the stack, popped first by the VM's DilithiumVerify handler).
    assembler.emit_op(OpCode::LoadImm);
    assembler.emit_bytes(&signature);

    assembler.emit_op(OpCode::LoadImm);
    assembler.emit_bytes(message);

    assembler.emit_op(OpCode::LoadImm);
    assembler.emit_bytes(&pk);

    assembler.emit_op(OpCode::DilithiumVerify);
    assembler.emit_op(OpCode::Halt);

    let bytecode = assembler.build();
    let mut vm = QuantumVM::new();
    vm.load_bytecode(&bytecode).unwrap();
    vm.execute().unwrap();

    let result = vm.stack.pop().unwrap().as_bool().unwrap();
    assert_eq!(result, true);
}

#[test]
fn test_dilithium_verify_shim_rejects_forged_signature() {
    // A signature made with a DIFFERENT keypair must not verify against
    // the original public key — proves the VM path enforces real security
    // properties rather than the old always-true stub.
    let (pk, _sk) = pqc_shims::dilithium::keygen();
    let (_other_pk, other_sk) = pqc_shims::dilithium::keygen();
    let message = b"Hello, quantum world!";
    let forged_signature = pqc_shims::dilithium::sign(message, &other_sk);

    let mut assembler = Assembler::new();
    assembler.emit_op(OpCode::LoadImm);
    assembler.emit_bytes(&forged_signature);
    assembler.emit_op(OpCode::LoadImm);
    assembler.emit_bytes(message);
    assembler.emit_op(OpCode::LoadImm);
    assembler.emit_bytes(&pk);
    assembler.emit_op(OpCode::DilithiumVerify);
    assembler.emit_op(OpCode::Halt);

    let bytecode = assembler.build();
    let mut vm = QuantumVM::new();
    vm.load_bytecode(&bytecode).unwrap();
    vm.execute().unwrap();

    let result = vm.stack.pop().unwrap().as_bool().unwrap();
    assert_eq!(result, false);
}

#[test]
fn test_kyber_decaps_shim() {
    // Uses a REAL Kyber-768 keypair + real encapsulation (not the old
    // fake fixed-size byte arrays) so decapsulation inside the VM must
    // recover the exact same shared secret that encaps produced.
    let (pk, sk) = pqc_shims::kyber::keygen().unwrap();
    let (ciphertext, expected_shared_secret) = pqc_shims::kyber::encaps(&pk).unwrap();

    let mut assembler = Assembler::new();

    // The decaps function expects (ciphertext, private_key), and the VM
    // pops private_key first, so push order is: ciphertext, private_key.
    assembler.emit_op(OpCode::LoadImm);
    assembler.emit_bytes(&ciphertext);

    assembler.emit_op(OpCode::LoadImm);
    assembler.emit_bytes(&sk);

    assembler.emit_op(OpCode::KyberKeyExchange); // This opcode maps to decaps
    assembler.emit_op(OpCode::Halt);

    let bytecode = assembler.build();
    let mut vm = QuantumVM::new();
    vm.load_bytecode(&bytecode).unwrap();
    vm.execute().unwrap();

    let shared_secret = vm.stack.pop().unwrap().as_bytes().unwrap().to_vec();
    assert_eq!(shared_secret, expected_shared_secret);
}

// --- VM Value::U128 & LoadImm128 Tests ---

#[test]
fn test_u128_push_and_return() {
    // Verify LoadImm128 pushes the correct Value::U128 onto the stack.
    let expected: u128 = 1_000_000_000_000_000_000_000u128; // 10^21 — well above i32::MAX
    let mut assembler = Assembler::new();
    assembler.emit_op(OpCode::LoadImm128);
    assembler.emit_u128(expected);
    assembler.emit_op(OpCode::Halt);
    let bytecode = assembler.build();
    let mut vm = QuantumVM::new();
    vm.load_bytecode(&bytecode).unwrap();
    vm.execute().unwrap();
    let result = vm.stack.pop().unwrap();
    assert_eq!(result.as_u128().unwrap(), expected);
}

#[test]
fn test_u128_add() {
    // 1T + 2T = 3T — values that would silently truncate under i32.
    let a: u128 = 1_000_000_000_000u128;
    let b: u128 = 2_000_000_000_000u128;
    let mut assembler = Assembler::new();
    assembler.emit_op(OpCode::LoadImm128);
    assembler.emit_u128(a);
    assembler.emit_op(OpCode::LoadImm128);
    assembler.emit_u128(b);
    assembler.emit_op(OpCode::Add);
    assembler.emit_op(OpCode::Halt);
    let bytecode = assembler.build();
    let mut vm = QuantumVM::new();
    vm.load_bytecode(&bytecode).unwrap();
    vm.execute().unwrap();
    let result = vm.stack.pop().unwrap();
    assert_eq!(result.as_u128().unwrap(), 3_000_000_000_000u128);
}

#[test]
fn test_u128_add_promotes_to_u256() {
    // U128::MAX + 1 remains valid in the real UInt256 domain and must not wrap.
    let mut assembler = Assembler::new();
    assembler.emit_op(OpCode::LoadImm128);
    assembler.emit_u128(u128::MAX);
    assembler.emit_op(OpCode::LoadImm128);
    assembler.emit_u128(1u128);
    assembler.emit_op(OpCode::Add);
    assembler.emit_op(OpCode::Halt);
    let bytecode = assembler.build();
    let mut vm = QuantumVM::new();
    vm.load_bytecode(&bytecode).unwrap();
    vm.execute().unwrap();
    let result = vm.stack.pop().unwrap();
    assert_eq!(
        result.as_u256().unwrap(),
        U256::from(u128::MAX) + U256::from(1u8)
    );
}

#[test]
fn test_u128_i32_mixed_add() {
    // Push an i32(5) then a U128(10) — Add should promote and return U128(15).
    let mut assembler = Assembler::new();
    assembler.emit_op(OpCode::Push);
    assembler.emit_i32(5);
    assembler.emit_op(OpCode::LoadImm128);
    assembler.emit_u128(10u128);
    assembler.emit_op(OpCode::Add);
    assembler.emit_op(OpCode::Halt);
    let bytecode = assembler.build();
    let mut vm = QuantumVM::new();
    vm.load_bytecode(&bytecode).unwrap();
    vm.execute().unwrap();
    let result = vm.stack.pop().unwrap();
    assert_eq!(result.as_u128().unwrap(), 15u128);
}
