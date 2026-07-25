use pqsynq::{DigitalSignature, Kem, KeyEncapsulation, PqcError, Sign};
use serde::Serialize;

#[derive(Serialize)]
struct FixtureSet {
    schema_version: u32,
    profile: &'static str,
    generated_by: &'static str,
    generated_at_utc: &'static str,
    kem_vectors: Vec<KemVector>,
    sign_vectors: Vec<SignVector>,
}

#[derive(Serialize)]
struct KemVector {
    algorithm: &'static str,
    public_key_hex: String,
    secret_key_hex: String,
    ciphertext_hex: String,
    shared_secret_hex: String,
}

#[derive(Serialize)]
struct SignVector {
    algorithm: &'static str,
    message_hex: String,
    public_key_hex: String,
    secret_key_hex: String,
    signature_hex: String,
    context_hex: Option<String>,
}

fn hex(data: &[u8]) -> String {
    hex::encode(data)
}

fn make_kem_vector(algorithm: &'static str, kem: Kem) -> Result<KemVector, PqcError> {
    let (pk, sk) = kem.keygen()?;
    let (ct, ss) = kem.encapsulate(&pk)?;

    Ok(KemVector {
        algorithm,
        public_key_hex: hex(&pk),
        secret_key_hex: hex(&sk),
        ciphertext_hex: hex(&ct),
        shared_secret_hex: hex(&ss),
    })
}

fn make_sign_vector(
    algorithm: &'static str,
    signer: Sign,
    message: &[u8],
    context: Option<&[u8]>,
) -> Result<SignVector, PqcError> {
    let (pk, sk) = signer.keygen()?;

    let signature = if let Some(ctx) = context {
        signer.sign_ctx(message, &sk, ctx)?
    } else {
        signer.sign(message, &sk)?
    };

    Ok(SignVector {
        algorithm,
        message_hex: hex(message),
        public_key_hex: hex(&pk),
        secret_key_hex: hex(&sk),
        signature_hex: hex(&signature),
        context_hex: context.map(hex),
    })
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = FixtureSet {
        schema_version: 1,
        profile: "synq-pq-full",
        generated_by: "cargo run -p aegis-pqsynq --example generate_pinned_vectors --features full",
        generated_at_utc: "2026-02-09T00:00:00Z",
        kem_vectors: vec![
            make_kem_vector("mlkem512", Kem::mlkem512())?,
            make_kem_vector("mlkem768", Kem::mlkem768())?,
            make_kem_vector("mlkem1024", Kem::mlkem1024())?,
            make_kem_vector("hqckem128", Kem::hqckem128())?,
            make_kem_vector("hqckem192", Kem::hqckem192())?,
            make_kem_vector("hqckem256", Kem::hqckem256())?,
        ],
        sign_vectors: vec![
            make_sign_vector(
                "mldsa44",
                Sign::mldsa44(),
                b"SynQ-MLDSA44-pinned-message",
                Some(b"synq-v1-contract"),
            )?,
            make_sign_vector(
                "mldsa65",
                Sign::mldsa65(),
                b"SynQ-MLDSA65-pinned-message",
                Some(b"synq-v1-contract"),
            )?,
            make_sign_vector(
                "mldsa87",
                Sign::mldsa87(),
                b"SynQ-MLDSA87-pinned-message",
                Some(b"synq-v1-contract"),
            )?,
            make_sign_vector(
                "fndsa512",
                Sign::fndsa512(),
                b"SynQ-FNDSA512-pinned-message",
                None,
            )?,
            make_sign_vector(
                "fndsa1024",
                Sign::fndsa1024(),
                b"SynQ-FNDSA1024-pinned-message",
                None,
            )?,
        ],
    };

    println!("{}", serde_json::to_string_pretty(&fixture)?);
    Ok(())
}
