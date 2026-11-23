//! The managed native configuration independently pins release inputs. Neither
//! signed peer messages nor RPC can originate a Wallet release capability.
use super::*;
use crate::services::{apqe_transport, protected_accounts::inspection::candidate_wire_profile};
use synergy_address_engine::apqe::{
    enrollment::UnactivatedWireProfile,
    enrollment_commit::UnactivatedCommitmentProfile,
    enrollment_registry::{EnrollmentRegistryRelease, EnrollmentRegistryReleaseIssuer},
    provider::{
        Operation, PqProvider, SignOptions, VerifiedNativeVerificationQualification,
        variants::Mldsa87,
    },
};
use synergy_address_engine::types::Algorithm;
use synergy_config::ManagedWalletDispatchReleaseConfiguration;
use synergy_execution::FeeSchedule;
use synergy_genesis::authority::{VerifiedWalletDispatchRelease, WalletDispatchReleaseTrust};

pub(super) const WALLET_RELEASE_ISSUER_DOMAIN: &str = "SYNERGY-POSY-WALLET-RELEASE-ISSUER-V1";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ReleaseIssuerAuthorization {
    pub(super) version: u32,
    pub(super) genesis_hash: String,
    pub(super) attachment_sha256: String,
    pub(super) issuer_sha256: String,
    pub(super) issuer_key_id: String,
    pub(super) signature: Vec<u8>,
}

impl ReleaseIssuerAuthorization {
    pub(super) fn signing_bytes(&self) -> Result<Vec<u8>, String> {
        let mut bytes = WALLET_RELEASE_ISSUER_DOMAIN.as_bytes().to_vec();
        bytes.push(0);
        serde_json::to_writer(
            &mut bytes,
            &(
                self.version,
                &self.genesis_hash,
                &self.attachment_sha256,
                &self.issuer_sha256,
                &self.issuer_key_id,
            ),
        )
        .map_err(|error| error.to_string())?;
        Ok(bytes)
    }
}

pub(in crate::services) struct ManagedWalletRelease {
    pub(in crate::services) verified: VerifiedWalletDispatchRelease,
    pub(in crate::services) proof_provider: Mutex<PqProvider<Mldsa87>>,
    pub(in crate::services) wire: UnactivatedWireProfile,
    pub(in crate::services) fees: FeeSchedule,
}

impl std::fmt::Debug for ManagedWalletRelease {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ManagedWalletRelease")
            .field("policy", self.verified.policy())
            .finish_non_exhaustive()
    }
}

impl ManagedWalletRelease {
    pub(super) fn load(
        config: &NodeConfiguration,
        origin: &VerifiedAuthority,
        expected: &ManagedWalletDispatchReleaseConfiguration,
    ) -> Result<Self, String> {
        let SimplifiedFinalityParent::Genesis { genesis_hash, .. } = &origin.anchor_parent else {
            return Err("managed Wallet release lacks signed Genesis origin".into());
        };
        let genesis_path = config
            .genesis_path
            .as_ref()
            .ok_or("managed Wallet release lacks a Genesis path")?;
        let root = genesis_path
            .parent()
            .ok_or("managed Wallet release lacks its network directory")?;
        if !root.is_absolute() || root.canonicalize().map_err(|error| error.to_string())? != root {
            return Err(
                "managed Wallet release requires its direct canonical network directory".into(),
            );
        }
        let read = |name, maximum, pin: &str| {
            let bytes = apqe_transport::read(&root.join(name), maximum, false)?;
            if apqe_transport::sha256(&bytes) != pin {
                return Err(format!(
                    "managed Wallet release input {name} differs from the approved pin"
                ));
            }
            Ok(bytes)
        };
        let attachment = read(
            "wallet-dispatch-release.json",
            32 * 1024,
            &expected.attachment_sha256,
        )?;
        let issuer_key = read(
            "wallet-dispatch-release-issuer.pub",
            1952,
            &expected.issuer_sha256,
        )?;
        let endorsement_original = apqe_transport::read(
            &root.join("wallet-dispatch-release-issuer-authorization.json"),
            24 * 1024,
            false,
        )?;
        let endorsement: ReleaseIssuerAuthorization = serde_json::from_slice(&endorsement_original)
            .map_err(|_| "invalid signed Wallet release issuer authorization")?;
        if endorsement.version != 1
            || endorsement.genesis_hash != *genesis_hash
            || endorsement.attachment_sha256 != expected.attachment_sha256
            || endorsement.issuer_sha256 != expected.issuer_sha256
            || endorsement.issuer_key_id != expected.issuer_key_id
            || endorsement.signature.len() != 3309
            || serde_json::to_vec(&endorsement).map_err(|error| error.to_string())?
                != endorsement_original
        {
            return Err("Wallet release issuer is outside the signed origin delegation".into());
        }
        let original_root = apqe_transport::read(
            config
                .consensus
                .authority_trust_key_path
                .as_ref()
                .ok_or("managed Wallet release requires the original Genesis root")?,
            1952,
            false,
        )?;
        let signer = KeyId::new(&expected.issuer_key_id).map_err(|error| error.to_string())?;
        let signer_artifact =
            synergy_posy::parse_hash_bytes(&expected.release_verifier_artifact_sha256)
                .map_err(|error| error.to_string())?;
        let trust = WalletDispatchReleaseTrust {
            genesis_hash,
            release_signer_key_id: &signer,
            release_signer_public_key: &issuer_key,
            release_verifier_artifact_sha256: signer_artifact,
            managed_release_manifest_sha256: &expected.managed_release_manifest_sha256,
            off_chain_approval_sha256: &expected.off_chain_approval_sha256,
            release_attestation_sha256: &expected.release_attestation_sha256,
        };
        let providers = config
            .aegis_provider
            .as_ref()
            .ok_or("managed Wallet release requires native APQE")?;
        let engine = crate::services::apqe_provider::load_selected(providers)?;
        let (verified, qualification) = {
            let engine = engine
                .lock()
                .map_err(|_| "managed Wallet release provider poisoned")?;
            let selected = crate::commands::selected_network::verified_genesis(config)?;
            if selected.genesis_hash != *genesis_hash {
                return Err("Wallet release delegation selected a different Genesis".into());
            }
            synergy_genesis::signing::verify(&selected, &origin.verifier, &original_root)?;
            if !engine
                .verify(
                    Algorithm::MlDsa65,
                    &original_root,
                    &endorsement.signing_bytes()?,
                    &endorsement.signature,
                    SignOptions::default(),
                )
                .map_err(|error| error.to_string())?
            {
                return Err("Wallet release issuer delegation signature is invalid".into());
            }
            let verified =
                VerifiedWalletDispatchRelease::verify_signed(&attachment, &trust, &engine)?;
            let qualification_bytes = apqe_transport::read(
                &root.join("wallet-dispatch-ml-dsa-87-qualification.json"),
                24 * 1024,
                false,
            )
            .map_err(|error| {
                format!("managed Wallet production ML-DSA-87 qualification: {error}")
            })?;
            let qualification = VerifiedNativeVerificationQualification::verify(
                &qualification_bytes,
                verified.enrollment(),
                &EnrollmentRegistryReleaseIssuer {
                    public_key: &issuer_key,
                    verifier_artifact_sha256: signer_artifact,
                },
                &engine,
                synergy_posy::parse_hash_bytes(&providers.authenticated_report_sha256)
                    .map_err(|error| error.to_string())?,
                synergy_posy::parse_hash_bytes(&expected.release_attestation_sha256)
                    .map_err(|error| error.to_string())?,
            )
            .map_err(|error| {
                format!("managed Wallet production ML-DSA-87 qualification: {error}")
            })?;
            (verified, qualification)
        };
        let policy = verified.policy();
        super::super::protected_accounts::processing_execution::native::require_compiled_wallet_contract(policy)?;
        if policy.chain_id != origin.epoch.chain_id || policy.network_id != origin.epoch.network_id
        {
            return Err("managed Wallet release changes the authenticated network scope".into());
        }
        let wire = candidate_wire_profile()?;
        let statement = verified.enrollment().statement();
        let original = wire
            .profile_fingerprint()
            .map_err(|error| error.to_string())?;
        let dual = wire
            .dual_enrollment_profile_fingerprint()
            .map_err(|error| error.to_string())?;
        if (statement.wire_profile_fingerprint != original
            && statement.wire_profile_fingerprint != dual)
            || statement.commitment_profile_fingerprint
                != EnrollmentRegistryRelease::commitment_fingerprint(
                    UnactivatedCommitmentProfile::candidate_concat_v1(),
                )
        {
            return Err(
                "managed Wallet release differs from the compiled APQE profile and provider".into(),
            );
        }
        let report_root = providers
            .report_path
            .parent()
            .ok_or("managed Wallet provider directory absent")?;
        let library = report_root.join(format!(
            "libaegismldsa87.{}",
            std::env::consts::DLL_EXTENSION
        ));
        // The installed native report has already independently pinned this
        // file and its trusted directory. The signed Wallet release must
        // independently select the same bytes and genuine production profile.
        let proof_provider =
            unsafe { PqProvider::<Mldsa87>::open_qualified_verifier(&library, &qualification) }
                .map_err(|error| {
                    format!("managed Wallet production ML-DSA-87 qualification: {error}")
                })?;
        let capability = proof_provider
            .capability(Operation::Verify)
            .map_err(|error| error.to_string())?;
        if !capability.artifact_verified
            || !capability.production_available
            || capability.eligibility.is_err()
        {
            return Err(
                "managed Wallet release lacks production-eligible ML-DSA-87 verification".into(),
            );
        }
        let fees = FeeSchedule {
            collector: policy.fee_collector.clone(),
            base_fee_per_gas_nwei: policy.base_fee_per_gas_nwei,
        };
        Ok(Self {
            verified,
            proof_provider: Mutex::new(proof_provider),
            wire,
            fees,
        })
    }
}

impl VerifiedAuthority {
    pub(in crate::services) fn native_wallet_release(
        &self,
    ) -> Result<&Arc<ManagedWalletRelease>, String> {
        let release = self
            .managed_wallet_release
            .as_ref()
            .ok_or("managed Wallet release is absent")?;
        if self.wallet_dispatch_policy() != Some(release.verified.policy()) {
            return Err("selected authority has no activated Wallet release".into());
        }
        self.matches_wallet_dispatch_release(&release.verified)?;
        Ok(release)
    }

    pub(super) fn pending_wallet_release(
        &self,
        previous: &SimplifiedEpochContext,
    ) -> Option<&VerifiedWalletDispatchRelease> {
        self.managed_wallet_release
            .as_ref()
            .map(|release| &release.verified)
            .filter(|release| {
                previous.epoch_end_height.checked_add(1)
                    == Some(release.policy().activation_finalized_height)
            })
    }
}
