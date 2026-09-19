#![no_main]

use aegis_crypto_core::mlkem::{mlkem768_decapsulate, mlkem768_encapsulate, mlkem768_keygen};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let keypair = mlkem768_keygen();
    let public_key = keypair.public_key();
    let secret_key = keypair.secret_key();
    let encapsulated =
        mlkem768_encapsulate(&public_key).expect("ML-KEM-768 encapsulation should succeed");
    let valid_ciphertext = encapsulated.ciphertext();

    let _ = mlkem768_decapsulate(&secret_key, &valid_ciphertext);

    if data.len() >= valid_ciphertext.len() {
        let candidate = &data[..valid_ciphertext.len()];
        let _ = mlkem768_decapsulate(&secret_key, candidate);
    } else {
        let _ = mlkem768_decapsulate(&secret_key, data);
    }
});
