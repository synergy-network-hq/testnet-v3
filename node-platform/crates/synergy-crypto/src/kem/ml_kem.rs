use synergy_aegis::{AegisKem, KemEncapsulation};

pub type MlKem768Ciphertext = KemEncapsulation;

pub fn encapsulate_ml_kem_768(
    provider: &impl AegisKem,
    public_key: &[u8],
) -> Result<MlKem768Ciphertext, String> {
    if provider.algorithm() != "ML-KEM-768" {
        return Err("Aegis provider is not ML-KEM-768".into());
    }
    provider
        .encapsulate(public_key)
        .map_err(|error| format!("Aegis KEM provider failed: {error:?}"))
}

pub fn decapsulate_ml_kem_768(
    provider: &impl AegisKem,
    ciphertext: &[u8],
    secret_key: &[u8],
) -> Result<Vec<u8>, String> {
    if provider.algorithm() != "ML-KEM-768" {
        return Err("Aegis provider is not ML-KEM-768".into());
    }
    provider
        .decapsulate(ciphertext, secret_key)
        .map_err(|error| format!("Aegis KEM provider failed: {error:?}"))
}
