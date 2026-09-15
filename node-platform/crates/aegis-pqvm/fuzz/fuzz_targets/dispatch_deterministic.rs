#![no_main]

use aegis_pqvm::integrations::abi;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = abi::dispatch_deterministic(data);
    if let Ok(call) = abi::decode_call(data) {
        let _ = abi::try_encode_call(&call);
    }
});
