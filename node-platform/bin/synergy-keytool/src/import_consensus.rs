//! Imports existing consensus custody after proving possession against the
//! canonical public identity. Private bytes enter only through bounded stdin.
use std::{io::Read, path::Path};

use aegis_pqvm::pqc::signatures::mldsa::mldsa65;
use serde::Deserialize;
use synergy_aegis::{
    AegisPolicy, AegisSigner, AegisVerifier, KeyId, KeyPurpose, KeyRecord, KeyState,
    SignatureAlgorithm, SigningContext,
};
use synergy_identity::{NodeAddress, NodeClass};

use crate::aegis_keys::{read_bounded, write_bundle, KeyMetadata};

struct Secret(Vec<u8>);
impl Drop for Secret {
    fn drop(&mut self) {
        for byte in &mut self.0 {
            unsafe { std::ptr::write_volatile(byte, 0) };
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

#[derive(Deserialize)]
struct PublicIdentity {
    address: String,
    consensus_key: PublicKey,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicKey {
    algorithm: String,
    public_key: String,
}

fn public_consensus(address: &str, path: &Path) -> Result<Vec<u8>, String> {
    // The shared loader verifies exact canonical JSON schema, FN-DSA root,
    // claimed address, encoding and validator class before selecting a role.
    crate::node_identity::load_identity_root_public_key(
        path,
        NodeClass::ConsensusAndChainIntegrity,
    )?;
    let public: PublicIdentity =
        serde_json::from_slice(&read_bounded(path, 64 * 1024, "canonical public identity")?)
            .map_err(|_| "invalid public consensus identity")?;
    if public.address != address
        || public.consensus_key.algorithm != "ML-DSA-65"
        || public.consensus_key.public_key.len() != mldsa65::public_key_bytes() * 2
        || !public
            .consensus_key
            .public_key
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(
            "public consensus key differs from explicit canonical validator binding".into(),
        );
    }
    public
        .consensus_key
        .public_key
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).map_err(|_| "invalid public hex")?;
            u8::from_str_radix(text, 16).map_err(|_| "invalid public hex".into())
        })
        .collect()
}

fn verify_possession(
    chain_id: u64,
    address: &str,
    key_id: &KeyId,
    public: &[u8],
    secret: &[u8],
    engine: Option<crate::provider::Engine>,
) -> Result<(), String> {
    let policy = AegisPolicy {
        allowed_algorithms: vec![SignatureAlgorithm::MlDsa65],
        maximum_message_bytes: 16 * 1024,
        maximum_signature_bytes: 16 * 1024,
    };
    let context = SigningContext {
        domain: "SYNERGY_EXISTING_CONSENSUS_CUSTODY_IMPORT_V1".into(),
        chain_id,
        epoch: None,
        height: None,
    };
    let message = serde_json::to_vec(&(context.domain.as_str(), address, key_id.as_str(), public))
        .map_err(|_| "encode possession transcript")?;
    let signer = crate::provider::signer(
        policy.clone(),
        key_id.clone(),
        public,
        secret.to_vec(),
        engine.clone(),
    )
    .map_err(|_| "invalid consensus secret custody")?;
    let signature = signer
        .sign(key_id, &context, &message)
        .map_err(|_| "consensus possession signing failed")?;
    crate::provider::verifier(policy, engine)
        .map_err(|_| "invalid possession verification policy")?
        .verify(&context, &message, &signature, public)
        .map_err(|_| "consensus secret does not possess canonical public key".into())
}

fn validated_secret(
    chain_id: u64,
    address: &str,
    key_id: &KeyId,
    public_identity: &Path,
    reader: impl Read,
    engine: Option<crate::provider::Engine>,
) -> Result<(Vec<u8>, Secret), String> {
    let public = public_consensus(address, public_identity)?;
    let mut secret = Secret(Vec::new());
    reader
        .take(mldsa65::secret_key_bytes() as u64 + 1)
        .read_to_end(&mut secret.0)
        .map_err(|_| "read bounded consensus custody stdin")?;
    if secret.0.len() != mldsa65::secret_key_bytes() {
        return Err("consensus stdin must contain exactly 4032 raw secret bytes".into());
    }
    verify_possession(chain_id, address, key_id, &public, &secret.0, engine)?;
    Ok((public, secret))
}

pub fn verify(
    chain_id: u64,
    address: &str,
    key_id: KeyId,
    public_identity: &Path,
    reader: impl Read,
) -> Result<(), String> {
    validated_secret(chain_id, address, &key_id, public_identity, reader, None)?;
    Ok(())
}

pub fn import(
    chain_id: u64,
    address: &str,
    key_id: KeyId,
    public_identity: &Path,
    output: &Path,
    reader: impl Read,
) -> Result<(), String> {
    import_with_provider(
        chain_id,
        address,
        key_id,
        public_identity,
        output,
        reader,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
fn import_with_provider(
    chain_id: u64,
    address: &str,
    key_id: KeyId,
    public_identity: &Path,
    output: &Path,
    reader: impl Read,
    engine: Option<crate::provider::Engine>,
) -> Result<(), String> {
    let (public, mut secret) =
        validated_secret(chain_id, address, &key_id, public_identity, reader, engine)?;
    let metadata = KeyMetadata::new(
        NodeAddress::parse(address.to_string()).map_err(|_| "invalid node address")?,
        KeyRecord {
            id: key_id,
            purpose: KeyPurpose::PosyConsensus,
            state: KeyState::Generated,
            public_key: public.clone(),
        },
        "ML-DSA-65",
    )?;
    write_bundle(output, &metadata, &public, &mut secret.0)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use synergy_address_engine::types::Algorithm;
    #[test]
    fn possession_rejects_different_secret_and_binds_public_key() {
        let engine = crate::provider::native_test_engine();
        let pair = engine
            .lock()
            .unwrap()
            .generate_keypair(Algorithm::MlDsa65)
            .unwrap();
        let public = pair.public_key;
        let secret = pair.private_key;
        let wrong = engine
            .lock()
            .unwrap()
            .generate_keypair(Algorithm::MlDsa65)
            .unwrap()
            .private_key;
        let id = KeyId::new("validator-existing-consensus").unwrap();
        assert!(
            verify_possession(1266, "validator", &id, &public, secret.as_bytes(), None).is_err()
        );
        assert!(verify_possession(
            1266,
            "validator",
            &id,
            public.as_slice(),
            secret.as_bytes(),
            Some(engine.clone())
        )
        .is_ok());
        assert!(verify_possession(
            1266,
            "validator",
            &id,
            public.as_slice(),
            wrong.as_bytes(),
            Some(engine.clone())
        )
        .is_err());
        assert!(verify_possession(
            1266,
            "validator",
            &id,
            public.as_slice(),
            &[1; 4031],
            Some(engine.clone())
        )
        .is_err());
    }
    #[test]
    fn import_preserves_existing_public_key_and_refuses_overwrite_or_wrong_stdin() {
        let engine = crate::provider::native_test_engine();
        let pair = engine
            .lock()
            .unwrap()
            .generate_keypair(Algorithm::MlDsa65)
            .unwrap();
        let public = pair.public_key;
        let secret = pair.private_key;
        let root = vec![42; synergy_address::FN_DSA_1024_PUBLIC_KEY_BYTES];
        let address = synergy_address::derive_key_controlled_address("synv1", &root).unwrap();
        let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
        let doc = serde_json::json!({
            "schema_version":"synergy-validator-public-identity-v3","binary_encoding":"lowercase-hex",
            "address":address,"public_key":hex(&root),"algorithm":"FN-DSA-1024","address_type":"NodeClass1","created_at":"test",
            "consensus_key":{"algorithm":"ML-DSA-65","public_key":hex(public.as_slice())},
            "node_identity_key":{"algorithm":"ML-DSA-65","public_key":hex(&public),"peer_id":"test"},
            "account_key":{"algorithm":"ML-DSA-87","public_key":"00"},
            "entropy_contribution_key":{"algorithm":"ML-KEM-768","public_key":"00"}
        });
        let dir =
            std::env::temp_dir().join(format!("synergy-import-consensus-{}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        struct Cleanup(std::path::PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let _cleanup = Cleanup(dir.clone());
        let path = dir.join("identity.pub.json");
        std::fs::write(&path, serde_json::to_vec(&doc).unwrap()).unwrap();
        let id = KeyId::new("existing-consensus").unwrap();
        assert!(verify(1266, &address, id.clone(), &path, &[1; 4031][..]).is_err());
        assert!(verify(1266, &address, id.clone(), &path, &[1; 4033][..]).is_err());
        import_with_provider(
            1266,
            &address,
            id.clone(),
            &path,
            &dir,
            secret.as_bytes(),
            Some(engine.clone()),
        )
        .unwrap();
        let stored = dir.join("existing-consensus.public.key");
        assert_eq!(std::fs::read(&stored).unwrap(), public.as_slice());
        assert!(import_with_provider(
            1266,
            &address,
            id,
            &path,
            &dir,
            secret.as_bytes(),
            Some(engine.clone())
        )
        .is_err());
        assert_eq!(std::fs::read(&stored).unwrap(), public.as_slice());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
