//! PQVM integration ABI
//!
//! This module defines a small, self-contained byte ABI used by the "integration shims"
//! (EVM/Substrate/CosmWasm/Solana/Move).
//!
//! Important:
//! - Deterministic dispatchers (for on-chain) intentionally exclude operations that require RNG
//!   (e.g., key generation, encapsulation, signing).
//! - Off-chain dispatchers may include RNG-based operations.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use crate::integrations::IntegrationError;

const MAGIC: [u8; 4] = *b"AEG1";

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    /// ML-KEM decapsulation: (ct, sk) -> ss
    MlkemDecapsulate = 1,
    /// FN-DSA verify (detached): (pk, msg, sig) -> [0|1]
    FndsaVerifyDetached = 3,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Alg {
    Mlkem512 = 1,
    Mlkem768 = 2,
    Mlkem1024 = 3,
    Fndsa512 = 20,
    Fndsa1024 = 21,
}

#[derive(Clone, Debug)]
pub struct Call {
    pub op: Op,
    pub alg: Alg,
    pub args: Vec<Vec<u8>>,
}

fn be_u32(n: u32) -> [u8; 4] {
    n.to_be_bytes()
}

fn read_u32_be(input: &[u8], offset: &mut usize) -> Result<u32, IntegrationError> {
    if *offset + 4 > input.len() {
        return Err(IntegrationError::InvalidPayload("truncated u32"));
    }
    let mut b = [0u8; 4];
    b.copy_from_slice(&input[*offset..*offset + 4]);
    *offset += 4;
    Ok(u32::from_be_bytes(b))
}

fn read_bytes(input: &[u8], offset: &mut usize) -> Result<Vec<u8>, IntegrationError> {
    let len = read_u32_be(input, offset)? as usize;
    if *offset + len > input.len() {
        return Err(IntegrationError::InvalidPayload("truncated bytes"));
    }
    let out = input[*offset..*offset + len].to_vec();
    *offset += len;
    Ok(out)
}

pub fn encode_call(call: &Call) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&MAGIC);
    out.push(call.op as u8);
    out.push(call.alg as u8);
    out.push(call.args.len().min(255) as u8);
    for a in call.args.iter() {
        out.extend_from_slice(&be_u32(a.len() as u32));
        out.extend_from_slice(a);
    }
    out
}

pub fn decode_call(payload: &[u8]) -> Result<Call, IntegrationError> {
    if payload.len() < 7 {
        return Err(IntegrationError::InvalidPayload("payload too small"));
    }
    if payload[0..4] != MAGIC {
        return Err(IntegrationError::InvalidPayload("bad magic"));
    }
    let op = match payload[4] {
        1 => Op::MlkemDecapsulate,
        3 => Op::FndsaVerifyDetached,
        _ => return Err(IntegrationError::InvalidPayload("unknown op")),
    };
    let alg = match payload[5] {
        1 => Alg::Mlkem512,
        2 => Alg::Mlkem768,
        3 => Alg::Mlkem1024,
        20 => Alg::Fndsa512,
        21 => Alg::Fndsa1024,
        _ => return Err(IntegrationError::InvalidPayload("unknown alg")),
    };
    let argc = payload[6] as usize;
    let mut offset = 7usize;
    let mut args = Vec::with_capacity(argc);
    for _ in 0..argc {
        args.push(read_bytes(payload, &mut offset)?);
    }
    if offset != payload.len() {
        return Err(IntegrationError::InvalidPayload("trailing bytes"));
    }
    Ok(Call { op, alg, args })
}

pub fn encode_ok(result: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&MAGIC);
    out.push(0); // status OK
    out.extend_from_slice(&be_u32(result.len() as u32));
    out.extend_from_slice(result);
    out
}

pub fn encode_err(code: u8, message: &str) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&MAGIC);
    out.push(1); // status ERR
    out.push(code);
    let msg = message.as_bytes();
    out.extend_from_slice(&be_u32(msg.len() as u32));
    out.extend_from_slice(msg);
    out
}

pub fn decode_response(payload: &[u8]) -> Result<Result<Vec<u8>, (u8, String)>, IntegrationError> {
    if payload.len() < 5 {
        return Err(IntegrationError::InvalidPayload("response too small"));
    }
    if payload[0..4] != MAGIC {
        return Err(IntegrationError::InvalidPayload("bad magic"));
    }
    match payload[4] {
        0 => {
            let mut offset = 5usize;
            let b = read_bytes(payload, &mut offset)?;
            if offset != payload.len() {
                return Err(IntegrationError::InvalidPayload("trailing bytes"));
            }
            Ok(Ok(b))
        }
        1 => {
            if payload.len() < 6 {
                return Err(IntegrationError::InvalidPayload("error response too small"));
            }
            let code = payload[5];
            let mut offset = 6usize;
            let b = read_bytes(payload, &mut offset)?;
            if offset != payload.len() {
                return Err(IntegrationError::InvalidPayload("trailing bytes"));
            }
            let msg = String::from_utf8(b).unwrap_or_else(|_| "non-utf8 error".to_string());
            Ok(Err((code, msg)))
        }
        _ => Err(IntegrationError::InvalidPayload("unknown response status")),
    }
}

/// Deterministic dispatcher intended for on-chain style integrations.
pub fn dispatch_deterministic(payload: &[u8]) -> Result<Vec<u8>, IntegrationError> {
    use crate::fndsa;
    use crate::mlkem;

    use pqcrypto_traits::kem::{Ciphertext as _, SecretKey as _, SharedSecret as _};
    use pqcrypto_traits::sign::PublicKey as _;

    let call = decode_call(payload)?;
    let out: Vec<u8> = match (call.op, call.alg) {
        (Op::MlkemDecapsulate, Alg::Mlkem512) => {
            if call.args.len() != 2 {
                return Err(IntegrationError::InvalidPayload(
                    "mlkem512 decap expects 2 args",
                ));
            }
            let ct = mlkem::mlkem512::Ciphertext::from_bytes(&call.args[0]).map_err(|_| {
                IntegrationError::InvalidPayload("invalid mlkem512 ciphertext bytes")
            })?;
            let sk = mlkem::mlkem512::SecretKey::from_bytes(&call.args[1]).map_err(|_| {
                IntegrationError::InvalidPayload("invalid mlkem512 secret key bytes")
            })?;
            let ss = mlkem::mlkem512::decapsulate(&ct, &sk);
            ss.as_bytes().to_vec()
        }
        (Op::MlkemDecapsulate, Alg::Mlkem768) => {
            if call.args.len() != 2 {
                return Err(IntegrationError::InvalidPayload(
                    "mlkem768 decap expects 2 args",
                ));
            }
            let ct = mlkem::mlkem768::Ciphertext::from_bytes(&call.args[0]).map_err(|_| {
                IntegrationError::InvalidPayload("invalid mlkem768 ciphertext bytes")
            })?;
            let sk = mlkem::mlkem768::SecretKey::from_bytes(&call.args[1]).map_err(|_| {
                IntegrationError::InvalidPayload("invalid mlkem768 secret key bytes")
            })?;
            let ss = mlkem::mlkem768::decapsulate(&ct, &sk);
            ss.as_bytes().to_vec()
        }
        (Op::MlkemDecapsulate, Alg::Mlkem1024) => {
            if call.args.len() != 2 {
                return Err(IntegrationError::InvalidPayload(
                    "mlkem1024 decap expects 2 args",
                ));
            }
            let ct = mlkem::mlkem1024::Ciphertext::from_bytes(&call.args[0]).map_err(|_| {
                IntegrationError::InvalidPayload("invalid mlkem1024 ciphertext bytes")
            })?;
            let sk = mlkem::mlkem1024::SecretKey::from_bytes(&call.args[1]).map_err(|_| {
                IntegrationError::InvalidPayload("invalid mlkem1024 secret key bytes")
            })?;
            let ss = mlkem::mlkem1024::decapsulate(&ct, &sk);
            ss.as_bytes().to_vec()
        }

        (Op::FndsaVerifyDetached, Alg::Fndsa512) => {
            if call.args.len() != 3 {
                return Err(IntegrationError::InvalidPayload(
                    "fndsa512 verify expects 3 args",
                ));
            }
            let pk = fndsa::fndsa512::PublicKey::from_bytes(&call.args[0])
                .map_err(|_| IntegrationError::InvalidPayload("invalid fndsa512 public key"))?;
            let sig = <fndsa::fndsa512::DetachedSignature as pqcrypto_traits::sign::DetachedSignature>::from_bytes(&call.args[2])
                .map_err(|_| IntegrationError::InvalidPayload("invalid fndsa512 signature"))?;
            let ok = fndsa::fndsa512::verify_detached_signature(&sig, &call.args[1], &pk).is_ok();
            vec![ok as u8]
        }
        (Op::FndsaVerifyDetached, Alg::Fndsa1024) => {
            if call.args.len() != 3 {
                return Err(IntegrationError::InvalidPayload(
                    "fndsa1024 verify expects 3 args",
                ));
            }
            let pk = fndsa::fndsa1024::PublicKey::from_bytes(&call.args[0])
                .map_err(|_| IntegrationError::InvalidPayload("invalid fndsa1024 public key"))?;
            let sig = <fndsa::fndsa1024::DetachedSignature as pqcrypto_traits::sign::DetachedSignature>::from_bytes(&call.args[2])
                .map_err(|_| IntegrationError::InvalidPayload("invalid fndsa1024 signature"))?;
            let ok = fndsa::fndsa1024::verify_detached_signature(&sig, &call.args[1], &pk).is_ok();
            vec![ok as u8]
        }

        // Deterministic dispatcher: exclude RNG-based ops by design.
        _ => {
            return Err(IntegrationError::Unsupported(
                "operation not supported by deterministic dispatcher",
            ))
        }
    };

    Ok(encode_ok(&out))
}

/// Basic, conservative gas cost estimate for EVM-like integrations.
pub fn gas_cost_deterministic(payload: &[u8]) -> Result<u64, IntegrationError> {
    let call = decode_call(payload)?;
    let cost = match (call.op, call.alg) {
        (Op::MlkemDecapsulate, Alg::Mlkem512) => 150_000,
        (Op::MlkemDecapsulate, Alg::Mlkem768) => 200_000,
        (Op::MlkemDecapsulate, Alg::Mlkem1024) => 250_000,
        (Op::FndsaVerifyDetached, Alg::Fndsa512) => 90_000,
        (Op::FndsaVerifyDetached, Alg::Fndsa1024) => 140_000,
        _ => return Err(IntegrationError::Unsupported("no gas cost for this op/alg")),
    };
    Ok(cost)
}
