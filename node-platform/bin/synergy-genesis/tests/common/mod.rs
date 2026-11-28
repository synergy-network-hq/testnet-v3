use synergy_address_engine::apqe::{
    crypto_engine::CryptoEngine,
    provider::{
        variants::{Mldsa65, Mldsa87},
        PqProvider, Profile,
    },
};
use synergy_genesis::r1::profiles::{ProfileCatalog, ProfileDefinition, ProfileKind};
pub fn bytes(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2));
    s.as_bytes()
        .chunks_exact(2)
        .map(|x| u8::from_str_radix(std::str::from_utf8(x).unwrap(), 16).unwrap())
        .collect()
}
pub const PIN65: &str = "6dbd9741d717ee5c40fd22bfa11c1e734b90af6727df61042d21f621105d8fa6";
pub const PIN87: &str = "06dbd772bd335da463d6befbaef8aa4bf9e0e342af0fc281eed143e347fdad9d";
pub const PINKEM: &str = "11522b9e7063fce234bdf4d755092feb8ae8896779aacc38ddb7f3e189d45cd0";
pub fn catalog() -> ProfileCatalog {
    ProfileCatalog::new(
        ProfileKind::ALL
            .into_iter()
            .map(|kind| {
                ProfileDefinition::from_target_matrix(kind,synergy_genesis::r1::artifact_matrix::PlatformArtifactMatrix::darwin_public_validation_only(synergy_genesis::r1::artifact_matrix::ArtifactPins{mldsa65:bytes(PIN65).try_into().unwrap(),mldsa87:bytes(PIN87).try_into().unwrap(),mlkem1024:bytes(PINKEM).try_into().unwrap()}))
            })
            .collect::<Result<Vec<_>, _>>()
            .unwrap(),
    )
    .unwrap()
}
pub fn engine() -> CryptoEngine {
    let base=std::path::PathBuf::from("/Volumes/PortableSSD/02-Synergy-Network/24-Technical-Documentation/testnet-9969-preparation/revisions/r2/provider-validation");
    // Only canonical locally built validation artifacts; no signing or key generation.
    unsafe {
        CryptoEngine::new()
            .with_mldsa65(
                PqProvider::<Mldsa65>::open_verified(
                    base.join("libaegismldsa65.dylib"),
                    bytes(PIN65).try_into().unwrap(),
                    Profile::Validation,
                )
                .unwrap(),
            )
            .with_mldsa87(
                PqProvider::<Mldsa87>::open_verified(
                    base.join("libaegismldsa87.dylib"),
                    bytes(PIN87).try_into().unwrap(),
                    Profile::Validation,
                )
                .unwrap(),
            )
    }
}
