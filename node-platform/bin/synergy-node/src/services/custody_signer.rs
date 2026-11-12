//! Opt-in encrypted consensus custody boundary. No CLI activation or key export.
use super::authority::VerifiedAuthority;
use std::sync::{Arc, Mutex};
use synergy_address_engine::{
    apqe::crypto_engine::CryptoEngine,
    encrypt::EncryptedEnvelope,
    validator_provisioning::{self, CustodyRole, EnrollmentRequest, NetworkBinding},
};
use synergy_posy::{
    persistence::{ConsensusSigner, DurableSigningAuthority},
    SignOnceJournal,
};

/// Constructible only by authenticating the exact selected signed-Genesis bytes.
pub(crate) struct AuthenticatedCustodyNetwork {
    binding: NetworkBinding,
    authority_digest: [u8; 32],
    network_id: String,
}
impl AuthenticatedCustodyNetwork {
    #[allow(dead_code)]
    pub(crate) fn from_configuration(
        configuration: &synergy_config::NodeConfiguration,
        authority: &VerifiedAuthority,
    ) -> Result<Self, String> {
        if configuration.chain_id != authority.epoch.chain_id
            || configuration.network_id != authority.epoch.network_id
        {
            return Err("custody configuration differs from authenticated authority".into());
        }
        let (_, binding) =
            crate::commands::selected_network::verify_with_custody_binding(configuration)?;
        Ok(Self {
            binding,
            authority_digest: authority_digest(authority),
            network_id: authority.epoch.network_id.clone(),
        })
    }
}

fn authority_digest(authority: &VerifiedAuthority) -> [u8; 32] {
    synergy_address_engine::apqe::fixed_digest(
        &synergy_address_engine::apqe::Primitives,
        synergy_address_engine::apqe::FixedDigest::Sha256,
        authority.binding_bytes(),
    )
}
struct CustodySigner {
    validator: String,
    key_id: String,
    engine: Arc<Mutex<CryptoEngine>>,
    custody: validator_provisioning::ConsensusCustodyHandle,
}
impl ConsensusSigner for CustodySigner {
    fn validator_id(&self) -> &str {
        &self.validator
    }
    fn key_id(&self) -> &str {
        &self.key_id
    }
    fn sign(&self, _: &str, _: u64, transcript: &[u8]) -> Result<Vec<u8>, String> {
        let engine = self
            .engine
            .try_lock()
            .map_err(|_| "custody provider busy or poisoned")?;
        self.custody
            .sign_canonical(&engine, transcript)
            .map_err(|e| e.to_string())
    }
}
/// The caller supplies its already recovered canonical journal and independently
/// authenticated network binding. Enrollment alone never grants signing authority.
/// Current v1 custody can supply consensus only; transport/ingress roles fail closed.
#[allow(dead_code, clippy::too_many_arguments)]
pub(crate) fn consensus_custody_authority(
    authority: &VerifiedAuthority,
    journal: SignOnceJournal,
    engine: Arc<Mutex<CryptoEngine>>,
    request: &EnrollmentRequest,
    network: &AuthenticatedCustodyNetwork,
    envelope: &EncryptedEnvelope,
    passphrase: &str,
) -> Result<DurableSigningAuthority<impl ConsensusSigner>, String> {
    if network.authority_digest != authority_digest(authority)
        || network.network_id != authority.epoch.network_id
    {
        return Err("custody token differs from exact authenticated authority incarnation".into());
    }
    if network.binding.chain_id_hex != format!("{:064x}", authority.epoch.chain_id) {
        return Err("custody differs from authenticated authority chain".into());
    }
    let validator = &request.payload.identity.address;
    let (key_id, public) = authority.consensus_binding(validator)?;
    let custody = {
        let engine = engine
            .try_lock()
            .map_err(|_| "custody provider busy or poisoned")?;
        validator_provisioning::unlock_consensus_custody(
            &engine,
            request,
            &network.binding,
            envelope,
            passphrase,
            CustodyRole::ConsensusMlDsa65,
            public,
        )
        .map_err(|e| e.to_string())?
    };
    Ok(DurableSigningAuthority::new(
        journal,
        CustodySigner {
            validator: validator.clone(),
            key_id: key_id.into(),
            engine,
            custody,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use synergy_address_engine::types::AddressType;
    use synergy_posy::{SigningSlot, ValidatorRecord, ValidatorStatus};
    #[test]
    #[ignore = "requires explicitly authenticated immutable APQE native artifacts"]
    fn native_encrypted_consensus_custody_keeps_existing_sign_once_journal() {
        let selected = synergy_config::ApqeProviderConfiguration {
            report_path: std::env::var("APQE_TRUSTED_NATIVE_REPORT").unwrap().into(),
            authenticated_report_sha256: std::env::var("APQE_AUTHENTICATED_REPORT_SHA256").unwrap(),
        };
        let engine = super::super::apqe_provider::load_selected(&selected).unwrap();
        let network = NetworkBinding {
            chain_id_hex: format!("{:064x}", 1266),
            genesis_sha256: "ab".repeat(32),
        };
        let passphrase = "test-only-custody-passphrase";
        let (request, envelope) = validator_provisioning::provision(
            &engine.lock().unwrap(),
            AddressType::NodeClass1,
            NetworkBinding {
                chain_id_hex: network.chain_id_hex.clone(),
                genesis_sha256: network.genesis_sha256.clone(),
            },
            passphrase,
        )
        .unwrap();
        let public = synergy_address_engine::snts07::decode_lower_hex(
            "consensus public",
            &request.payload.identity.consensus_key.public_key,
            1952,
        )
        .unwrap();
        let entries = (0..5)
            .map(|i| {
                (
                    ValidatorRecord {
                        validator_id: if i == 0 {
                            request.payload.identity.address.clone()
                        } else {
                            format!("other-{i}")
                        },
                        consensus_key_id: format!("key-{i}"),
                        frozen_voting_weight: 1,
                        status: ValidatorStatus::Active,
                    },
                    public.clone(),
                )
            })
            .collect();
        let authority = super::super::authority::qualification_authority_with_provider(
            entries,
            Some(engine.clone()),
        );
        let network = AuthenticatedCustodyNetwork {
            binding: network,
            authority_digest: authority_digest(&authority),
            network_id: authority.epoch.network_id.clone(),
        };
        let root = std::env::temp_dir().join(format!(
            "custody-journal-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        struct Cleanup(std::path::PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let _cleanup = Cleanup(root.clone());
        let journal = root.join("sign-once.json");
        let open = || {
            consensus_custody_authority(
                &authority,
                SignOnceJournal::load(&journal).unwrap(),
                engine.clone(),
                &request,
                &network,
                &envelope,
                passphrase,
            )
            .unwrap()
        };
        let slot = SigningSlot {
            height: 1,
            round: 0,
            domain: "block-vote".into(),
        };
        let changed_network = AuthenticatedCustodyNetwork {
            binding: NetworkBinding {
                chain_id_hex: network.binding.chain_id_hex.clone(),
                genesis_sha256: network.binding.genesis_sha256.clone(),
            },
            authority_digest: [0; 32],
            network_id: network.network_id.clone(),
        };
        assert!(consensus_custody_authority(
            &authority,
            SignOnceJournal::load(&journal).unwrap(),
            engine.clone(),
            &request,
            &changed_network,
            &envelope,
            passphrase
        )
        .is_err());
        let mut signer = open();
        let signature = signer
            .sign_once(
                slot.clone(),
                synergy_posy::POSY_SIMPLIFIED_BLOCK_VOTE_DOMAIN,
                "subject-A",
                b"original-canonical-transcript",
            )
            .unwrap();
        let before = std::fs::read(&journal).unwrap();
        drop(signer);
        let mut recovered = open();
        assert_eq!(
            signature,
            recovered
                .sign_once(
                    slot.clone(),
                    synergy_posy::POSY_SIMPLIFIED_BLOCK_VOTE_DOMAIN,
                    "subject-A",
                    b"original-canonical-transcript"
                )
                .unwrap()
        );
        assert!(recovered
            .sign_once(
                slot.clone(),
                synergy_posy::POSY_SIMPLIFIED_BLOCK_VOTE_DOMAIN,
                "subject-B",
                b"different-transcript"
            )
            .is_err());
        assert_eq!(before, std::fs::read(&journal).unwrap());
        assert!(validator_provisioning::unlock_consensus_custody(
            &engine.lock().unwrap(),
            &request,
            &network.binding,
            &envelope,
            passphrase,
            CustodyRole::TransportMlDsa65,
            &public
        )
        .is_err());
        assert!(consensus_custody_authority(
            &authority,
            SignOnceJournal::load(&journal).unwrap(),
            engine.clone(),
            &request,
            &network,
            &envelope,
            "wrong-passphrase"
        )
        .is_err());
    }
}
