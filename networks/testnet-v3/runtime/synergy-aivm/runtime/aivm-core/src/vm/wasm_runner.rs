use crate::error::AivmError;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::{fs, path::Path};
use wasmtime::{Engine, ExternType, Instance, Module, Store};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WasmRunOutcome {
    pub exported_functions: Vec<String>,
    pub exported_memories: usize,
}

pub fn run_wasm(file: impl AsRef<Path>) -> Result<WasmRunOutcome> {
    let bytes = fs::read(file)?;
    Ok(run_wasm_bytes(&bytes)?)
}

pub fn run_wasm_bytes(bytes: &[u8]) -> Result<WasmRunOutcome, AivmError> {
    let engine = Engine::default();
    let module =
        Module::from_binary(&engine, bytes).map_err(|err| AivmError::bytecode(err.to_string()))?;
    reject_host_imports(&module)?;
    let mut store = Store::new(&engine, ());
    let instance = Instance::new(&mut store, &module, &[])
        .map_err(|err| AivmError::runtime_trap(err.to_string()))?;

    let exported_functions = module
        .exports()
        .filter_map(|export| match export.ty() {
            ExternType::Func(_) => Some(export.name().to_string()),
            _ => None,
        })
        .collect();
    let exported_memories = instance
        .exports(&mut store)
        .filter_map(|export| match export.into_extern() {
            wasmtime::Extern::Memory(_) => Some(()),
            _ => None,
        })
        .count();

    Ok(WasmRunOutcome {
        exported_functions,
        exported_memories,
    })
}

fn reject_host_imports(module: &Module) -> Result<(), AivmError> {
    if let Some(import) = module.imports().next() {
        return Err(AivmError::host_function(format!(
            "AIVM deterministic execution prohibits host import {}.{}",
            import.module(),
            import.name()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_minimal_wasm_module() {
        let wasm = b"\0asm\x01\0\0\0";
        let outcome = run_wasm_bytes(wasm).expect("minimal wasm should load");
        assert!(outcome.exported_functions.is_empty());
        assert_eq!(outcome.exported_memories, 0);
    }

    #[test]
    fn rejects_wasm_host_imports() {
        let wasm_with_import = [
            0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, // header
            0x01, 0x04, 0x01, 0x60, 0x00, 0x00, // type section
            0x02, 0x0d, 0x01, 0x03, b'e', b'n', b'v', 0x05, b'c', b'l', b'o', b'c', b'k', 0x00,
            0x00, // import env.clock as function type 0
        ];

        let error = run_wasm_bytes(&wasm_with_import).expect_err("host import must be rejected");
        assert_eq!(error.code, crate::error::AivmErrorCode::HostFunction);
    }
}
