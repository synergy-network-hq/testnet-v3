//! Permissionless owner registration or optional sponsored registration. This
//! prepares protocol state only; the caller owns signature, fee, nonce and finality.
use crate::authorization::{
    canonical_binding_commitment, IdentityAuthorizationBindingCommitment,
    IdentityAuthorizationCarrier, AEGIS_TRANSACTION_AUTHORIZATION_DOMAIN,
    IDENTITY_AUTHORIZATION_BINDINGS_STATE_KEY,
};
use std::collections::BTreeMap;

pub const MAX_AUTHORIZATION_TABLE_BYTES: usize = 1024 * 1024;
pub const AUTHORIZATION_UPDATED_HEIGHT_STATE_KEY: &str = "identity_authorization_updated_height";

/// Existing networks without an update marker still use their authenticated
/// Genesis table. This is canonical execution metadata, never a local clock.
pub fn authorization_update_height(protocol: &BTreeMap<String, Vec<u8>>) -> Result<u64, String> {
    protocol
        .get(AUTHORIZATION_UPDATED_HEIGHT_STATE_KEY)
        .map_or(Ok(0), |bytes| {
            if bytes.len() > 20 {
                return Err("identity authorization update height exceeds bound".into());
            }
            let height = serde_json::from_slice::<u64>(bytes)
                .map_err(|e| format!("identity authorization update height: {e}"))?;
            if height == 0 {
                return Err("identity authorization update height must be positive".into());
            }
            Ok(height)
        })
}

/// Verify root and delegated-key possession for this selected network, then add
/// an immutable first binding. Exact repetition is idempotent; rotation requires
/// its own authorized transition and cannot be performed by this entry point.
pub fn register_authorization(
    protocol: &BTreeMap<String, Vec<u8>>,
    sponsor: &str,
    carrier: &IdentityAuthorizationCarrier,
    chain_id: u64,
    network_id: &str,
    consensus_timestamp_unix: u64,
) -> Result<Vec<u8>, String> {
    register_authorization_with_verifier(
        protocol,
        sponsor,
        carrier,
        chain_id,
        network_id,
        consensus_timestamp_unix,
        None,
    )
}
#[allow(clippy::too_many_arguments)]
pub fn register_authorization_with_verifier(
    protocol: &BTreeMap<String, Vec<u8>>,
    sponsor: &str,
    carrier: &IdentityAuthorizationCarrier,
    chain_id: u64,
    network_id: &str,
    consensus_timestamp_unix: u64,
    verifier: Option<&dyn crate::authorization::AuthorizationSignatureVerifier>,
) -> Result<Vec<u8>, String> {
    let bytes = protocol
        .get(IDENTITY_AUTHORIZATION_BINDINGS_STATE_KEY)
        .ok_or("finalized identity authorization table is absent")?;
    if bytes.len() > MAX_AUTHORIZATION_TABLE_BYTES {
        return Err("identity authorization table exceeds the byte limit".into());
    }
    let mut bindings: BTreeMap<String, IdentityAuthorizationBindingCommitment> =
        serde_json::from_slice(bytes)
            .map_err(|e| format!("decode identity authorization table: {e}"))?;
    let principal = carrier
        .binding
        .authorization_policy
        .principals
        .iter()
        .find(|p| {
            p.status == crate::authorization::BindingStatus::Active
                && p.principal_type == crate::authorization::PrincipalType::PublicKey
                && p.algorithm.as_deref() == Some("ML-DSA-87")
                && p.purposes
                    .iter()
                    .any(|purpose| purpose == "transaction-signing")
        })
        .ok_or("registration has no active transaction-signing key")?;
    let public_key = hex::decode(
        principal
            .public_key
            .as_deref()
            .ok_or("registration key is absent")?,
    )
    .map_err(|_| "registration key is not canonical hex")?;
    let address = carrier.identity_address_for_key_for_admission_at_with_verifier(
        AEGIS_TRANSACTION_AUTHORIZATION_DOMAIN,
        chain_id,
        network_id,
        "ML-DSA-87",
        &public_key,
        "transaction-signing",
        consensus_timestamp_unix,
        &carrier.binding.binding_payload_sha3_256,
        verifier,
    )?;
    // A root/key-possession-proven owner may enroll itself. Sponsoring a
    // different identity continues to require an already committed sponsor.
    if sponsor != address {
        canonical_binding_commitment(protocol, sponsor)?;
    }
    let commitment = IdentityAuthorizationBindingCommitment::from_verified_binding_with_verifier(
        &carrier.binding,
        consensus_timestamp_unix,
        verifier,
    )?;
    if let Some(existing) = bindings.get(&address) {
        if existing != &commitment {
            return Err(
                "registration cannot replace an existing identity authorization binding".into(),
            );
        }
        return Ok(bytes.clone());
    }
    bindings.insert(address, commitment);
    let updated = serde_json::to_vec(&bindings)
        .map_err(|e| format!("encode identity authorization table: {e}"))?;
    if updated.len() > MAX_AUTHORIZATION_TABLE_BYTES {
        return Err("identity authorization table exceeds the byte limit".into());
    }
    Ok(updated)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authorization::*;
    use aegis_pqvm::pqc::signatures::{fndsa::fndsa1024, mldsa::mldsa87};
    use pqrust_traits::sign::{DetachedSignature as _, PublicKey as _};
    use sha3::{Digest, Sha3_256};
    use synergy_address::derive_key_controlled_address;
    #[test]
    fn update_height_is_canonical_metadata_with_genesis_default_and_bounded_decode() {
        let mut protocol = BTreeMap::new();
        assert_eq!(authorization_update_height(&protocol).unwrap(), 0);
        protocol.insert(
            AUTHORIZATION_UPDATED_HEIGHT_STATE_KEY.into(),
            b"17".to_vec(),
        );
        assert_eq!(authorization_update_height(&protocol).unwrap(), 17);
        for invalid in [
            b"0".to_vec(),
            b"-1".to_vec(),
            b"\"17\"".to_vec(),
            vec![b'9'; 21],
        ] {
            protocol.insert(AUTHORIZATION_UPDATED_HEIGHT_STATE_KEY.into(), invalid);
            assert!(authorization_update_height(&protocol).is_err());
        }
    }
    fn sha3_256_hex(bytes: &[u8]) -> String {
        hex::encode(Sha3_256::digest(bytes))
    }
    fn binding_signature_message(payload: &[u8]) -> Vec<u8> {
        let mut message = AUTH_BINDING_SIGNATURE_DOMAIN.to_vec();
        message.extend_from_slice(payload);
        message
    }
    fn signed_carrier() -> (IdentityAuthorizationCarrier, Vec<u8>) {
        let (identity_public, identity_secret) = fndsa1024::keypair();
        let (account_public, account_secret) = mldsa87::keypair();
        let identity_address =
            derive_key_controlled_address("syna", identity_public.as_bytes()).unwrap();
        let account_hash = sha3_256_hex(account_public.as_bytes());
        let mut binding: IdentityAuthorizationBinding = serde_json::from_value(serde_json::json!({
            "schema_version": AUTH_BINDING_SCHEMA_VERSION,
            "binary_encoding": AUTH_BINDING_BINARY_ENCODING,
            "identity_id": "test-account",
            "identity_address": identity_address,
            "identity_root": {
                "algorithm": "FN-DSA-1024",
                "public_key": hex::encode(identity_public.as_bytes()),
                "public_key_sha3_256": sha3_256_hex(identity_public.as_bytes())
            },
            "authorization_policy": {"policy_type":"single-key", "threshold":1,
                "principals":[{"principal_id":"account", "principal_type":"public-key",
                    "algorithm":"ML-DSA-87", "public_key":hex::encode(account_public.as_bytes()),
                    "public_key_sha3_256":account_hash, "status":"active", "purposes":["transaction-signing"]}]},
            "authorization_scopes":[{"signature_domain":AEGIS_TRANSACTION_AUTHORIZATION_DOMAIN,
                "chain_id":1266,"network_id":"testnet", "purpose":"transaction-signing"}],
            "current_auth_key_hash":account_hash,
            "auth_key_history":[], "supersession_history":[],
            "effective_at":"1970-01-01T00:00:10Z",
            "binding_payload_sha3_256":"",
            "proofs":{"identity_root":{"algorithm":"FN-DSA-1024","signature":""}}
        })).unwrap();
        let payload = canonical_binding_payload(&binding).unwrap();
        binding.binding_payload_sha3_256 = sha3_256_hex(&payload);
        let message = binding_signature_message(&payload);
        binding.proofs.identity_root.signature =
            hex::encode(fndsa1024::detached_sign(&message, &identity_secret).as_bytes());
        binding.proofs.authorization_key_possession = vec![AuthorizationKeyPossessionProof {
            principal_id: "account".into(),
            algorithm: "ML-DSA-87".into(),
            signature: hex::encode(mldsa87::detached_sign(&message, &account_secret).as_bytes()),
        }];
        (
            IdentityAuthorizationCarrier {
                schema_version: AUTHORIZATION_CARRIER_SCHEMA_VERSION,
                signature_domain: AEGIS_TRANSACTION_AUTHORIZATION_DOMAIN.into(),
                binding,
            },
            account_public.as_bytes().to_vec(),
        )
    }

    #[test]
    fn owner_can_self_register_without_a_sponsor_but_cannot_replace_binding() {
        let (carrier, _) = signed_carrier();
        let address = &carrier.binding.identity_address;
        let mut protocol = BTreeMap::from([(
            IDENTITY_AUTHORIZATION_BINDINGS_STATE_KEY.into(),
            b"{}".to_vec(),
        )]);
        let updated =
            register_authorization(&protocol, address, &carrier, 1266, "testnet", 10).unwrap();
        protocol.insert(
            IDENTITY_AUTHORIZATION_BINDINGS_STATE_KEY.into(),
            updated.clone(),
        );
        assert_eq!(
            register_authorization(&protocol, address, &carrier, 1266, "testnet", 10).unwrap(),
            updated
        );
        let mut old = canonical_binding_commitment(&protocol, address).unwrap();
        old.binding_payload_sha3_256 = "0".repeat(64);
        protocol.insert(
            IDENTITY_AUTHORIZATION_BINDINGS_STATE_KEY.into(),
            serde_json::to_vec(&BTreeMap::from([(address, old)])).unwrap(),
        );
        assert!(register_authorization(&protocol, address, &carrier, 1266, "testnet", 10).is_err());
    }

    #[test]
    fn registration_preserves_authority_and_rejects_wrong_network_time_proofs_and_replacement() {
        let (sponsor, _) = signed_carrier();
        let (carrier, _) = signed_carrier();
        let sponsor_id = sponsor.binding.identity_address.clone();
        let old =
            IdentityAuthorizationBindingCommitment::from_verified_binding(&sponsor.binding, 10)
                .unwrap();
        let mut protocol = BTreeMap::from([(
            IDENTITY_AUTHORIZATION_BINDINGS_STATE_KEY.into(),
            serde_json::to_vec(&BTreeMap::from([(sponsor_id.clone(), old.clone())])).unwrap(),
        )]);
        let before = protocol.clone();
        for (chain, network, time) in [
            (1267, "testnet", 10),
            (1266, "wrong", 10),
            (1266, "testnet", 9),
        ] {
            assert!(
                register_authorization(&protocol, &sponsor_id, &carrier, chain, network, time)
                    .is_err()
            );
        }
        assert!(
            register_authorization(&protocol, "unregistered", &carrier, 1266, "testnet", 10)
                .is_err()
        );
        let mut corrupt = carrier.clone();
        let replacement = if corrupt
            .binding
            .proofs
            .identity_root
            .signature
            .starts_with('0')
        {
            "1"
        } else {
            "0"
        };
        corrupt
            .binding
            .proofs
            .identity_root
            .signature
            .replace_range(0..1, replacement);
        assert!(
            register_authorization(&protocol, &sponsor_id, &corrupt, 1266, "testnet", 10).is_err()
        );
        let mut no_possession = carrier.clone();
        no_possession
            .binding
            .proofs
            .authorization_key_possession
            .clear();
        assert!(register_authorization(
            &protocol,
            &sponsor_id,
            &no_possession,
            1266,
            "testnet",
            10
        )
        .is_err());
        let mut wrong_root = carrier.clone();
        wrong_root.binding.identity_address = sponsor_id.clone();
        assert!(
            register_authorization(&protocol, &sponsor_id, &wrong_root, 1266, "testnet", 10)
                .is_err()
        );
        let updated =
            register_authorization(&protocol, &sponsor_id, &carrier, 1266, "testnet", 10).unwrap();
        assert_eq!(protocol, before);
        protocol.insert(
            IDENTITY_AUTHORIZATION_BINDINGS_STATE_KEY.into(),
            updated.clone(),
        );
        assert_eq!(
            canonical_binding_commitment(&protocol, &sponsor_id).unwrap(),
            old
        );
        assert_eq!(
            register_authorization(&protocol, &sponsor_id, &carrier, 1266, "testnet", 10).unwrap(),
            updated
        );
        let mut entries: BTreeMap<String, IdentityAuthorizationBindingCommitment> =
            serde_json::from_slice(&updated).unwrap();
        entries
            .get_mut(&carrier.binding.identity_address)
            .unwrap()
            .binding_payload_sha3_256 = "f".repeat(64);
        protocol.insert(
            IDENTITY_AUTHORIZATION_BINDINGS_STATE_KEY.into(),
            serde_json::to_vec(&entries).unwrap(),
        );
        assert!(
            register_authorization(&protocol, &sponsor_id, &carrier, 1266, "testnet", 10).is_err()
        );
        protocol.insert(
            IDENTITY_AUTHORIZATION_BINDINGS_STATE_KEY.into(),
            vec![b' '; MAX_AUTHORIZATION_TABLE_BYTES + 1],
        );
        assert!(
            register_authorization(&protocol, &sponsor_id, &carrier, 1266, "testnet", 10).is_err()
        );
    }
}
