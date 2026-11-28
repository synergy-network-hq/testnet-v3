//! Public synthetic proof qualification using real pinned native verification.
use synergy_address_engine::apqe::{
    crypto_engine::CryptoEngine,
    provider::{
        variants::{Mldsa65, Mldsa87},
        PqProvider, Profile,
    },
    r1_framing::NetworkRef,
};
use synergy_genesis::r1::policy::{verify_node, NodeRecord};
use synergy_protocol_types::c14n02::{Decoder, Encoder};
fn decode(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2));
    s.as_bytes()
        .chunks_exact(2)
        .map(|x| u8::from_str_radix(std::str::from_utf8(x).unwrap(), 16).unwrap())
        .collect()
}
fn public_fixture() -> (NodeRecord, NetworkRef) {
    let data:serde_json::Value=serde_json::from_str(include_str!("../../../../../21-Aegis-Engine/synergy-address-engine/tests/fixtures/r1_node_public_signed_record.json")).unwrap();
    assert_eq!(data["production_import_permitted"], false);
    let n = NetworkRef {
        chain_id: u64::MAX - 1,
        nic: decode(data["nic_hex"].as_str().unwrap())
            .try_into()
            .unwrap(),
    };
    let bytes = decode(data["node_record_c14n02_hex"].as_str().unwrap());
    let mut d = Decoder::new(&bytes, 1024 * 1024).unwrap();
    let node = NodeRecord::decode_from(&mut d, n).unwrap();
    d.finish().unwrap();
    (node, n)
}
fn engine() -> CryptoEngine {
    let base=std::path::PathBuf::from("/Volumes/PortableSSD/02-Synergy-Network/24-Technical-Documentation/testnet-9969-preparation/revisions/r2/provider-validation");
    let d65 = decode("6dbd9741d717ee5c40fd22bfa11c1e734b90af6727df61042d21f621105d8fa6")
        .try_into()
        .unwrap();
    let d87 = decode("06dbd772bd335da463d6befbaef8aa4bf9e0e342af0fc281eed143e347fdad9d")
        .try_into()
        .unwrap();
    // Exact locally built canonical artifacts; validation verification only.
    unsafe {
        CryptoEngine::new()
            .with_mldsa65(
                PqProvider::<Mldsa65>::open_verified(
                    base.join("libaegismldsa65.dylib"),
                    d65,
                    Profile::Validation,
                )
                .unwrap(),
            )
            .with_mldsa87(
                PqProvider::<Mldsa87>::open_verified(
                    base.join("libaegismldsa87.dylib"),
                    d87,
                    Profile::Validation,
                )
                .unwrap(),
            )
    }
}
#[test]
fn genuine_public_node_possession_and_controller_authority_verify() {
    let (node, n) = public_fixture();
    let mut e = Encoder::new(1024 * 1024);
    node.encode_into(&mut e, n).unwrap();
    let bytes = e.finish().unwrap();
    let mut d = Decoder::new(&bytes, 1024 * 1024).unwrap();
    let round = NodeRecord::decode_from(&mut d, n).unwrap();
    d.finish().unwrap();
    assert_eq!(node, round);
    let engine = engine();
    assert_eq!(
        verify_node(node.clone(), n, &engine).unwrap().record(),
        &node
    );
    let mut changed = node.clone();
    changed.enrollment_nonce[0] ^= 1;
    assert!(verify_node(changed, n, &engine).is_err());
    let mut changed = node.clone();
    changed.birth_nonce[0] ^= 1;
    assert!(verify_node(changed, n, &engine).is_err());
    let mut changed = node.clone();
    changed.role_keys[0].key.public_key[0] ^= 1;
    assert!(verify_node(changed, n, &engine).is_err());
    let mut changed = node.clone();
    changed.current_policy.ordinary.threshold = 2;
    assert!(verify_node(changed, n, &engine).is_err());
    let mut changed = node.clone();
    changed.possession_proofs[0].signature[0] ^= 1;
    assert!(verify_node(changed, n, &engine).is_err());
    let mut changed = node.clone();
    changed.ordinary_controller_approvals.clear();
    assert!(verify_node(changed, n, &engine).is_err());
    let mut changed = node.clone();
    changed.possession_proofs[0].index = 1;
    assert!(verify_node(changed, n, &engine).is_err());
    let mut changed = n;
    changed.nic[0] ^= 1;
    assert!(verify_node(node.clone(), changed, &engine).is_err());
    let mut changed = n;
    changed.chain_id = 9969;
    // Received verification checks the supplied complete birth under the actual
    // N; it must reject the synthetic identity, without an issuance gate or
    // returning a newly derived presentation.
    assert!(matches!(
        node.validate_birth(changed),
        Err(synergy_genesis::r1::policy::PolicyError::Identity)
    ));
    assert!(verify_node(node, changed, &CryptoEngine::new()).is_err());
}
#[test]
fn missing_provider_never_mints_verified_record() {
    let (node, n) = public_fixture();
    assert!(verify_node(node, n, &CryptoEngine::new()).is_err());
}
