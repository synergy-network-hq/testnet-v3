use aivm_core::vm::wasm_runner;

fn main() -> anyhow::Result<()> {
    println!("Synergy-AIVM Core starting...");

    if let Some(wasm_file) = std::env::args().nth(1) {
        let outcome = wasm_runner::run_wasm(wasm_file)?;
        println!(
            "WASM module loaded: {} exported functions, {} exported memories",
            outcome.exported_functions.len(),
            outcome.exported_memories
        );
    } else {
        println!("No WASM module path provided; AIVM core initialized.");
    }

    Ok(())
}
