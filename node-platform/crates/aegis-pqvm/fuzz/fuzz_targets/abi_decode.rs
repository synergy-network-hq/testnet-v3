#![no_main]

use aegis_pqvm::integrations::abi;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = abi::decode_call(data);
    let _ = abi::decode_response(data);
});
