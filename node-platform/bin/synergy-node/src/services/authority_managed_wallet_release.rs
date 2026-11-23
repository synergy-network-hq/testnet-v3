//! The managed native configuration independently pins release inputs. Neither
//! signed peer messages nor RPC can originate a Wallet release capability.
use super::wallet_release_artifacts::{ManagedArtifacts, Platform, PlatformArtifact};
use super::*;
use crate::services::{apqe_transport, protected_accounts::inspection::candidate_wire_profile};
use synergy_address_engine::apqe::{
    enrollment::UnactivatedWireProfile,
    enrollment_commit::UnactivatedCommitmentProfile,
    enrollment_registry::{EnrollmentRegistryRelease, EnrollmentRegistryReleaseIssuer},
    provider::{variants::Mldsa87, Operation, PqProvider, VerifiedNativeVerificationQualification},
};
use synergy_config::ManagedWalletDispatchReleaseConfiguration;
use synergy_execution::FeeSchedule;
use synergy_genesis::authority::{
    VerifiedWalletDispatchRelease, WalletDispatchReleaseIssuerAuthorization,
    WalletDispatchReleaseIssuerTrust, WalletDispatchReleaseTrust,
};

pub(in crate::services) struct ManagedWalletRelease {
    pub(in crate::services) verified: VerifiedWalletDispatchRelease,
    pub(in crate::services) proof_provider: Mutex<PqProvider<Mldsa87>>,
    pub(in crate::services) wire: UnactivatedWireProfile,
    pub(in crate::services) fees: FeeSchedule,
    artifacts: PlatformArtifact,
    quick_setup_enrollment: bool,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum WalletReleaseState {
    VerifiedPending,
    Active,
    MissedActivation,
}

#[derive(Serialize)]
pub(crate) struct WalletReleasePreflight<'a> {
    state: WalletReleaseState,
    initial_adoption_before_close: bool,
    quick_setup_enrollment: bool,
    activation_finalized_height: u64,
    target: Platform,
    managed_release_manifest_sha256: &'a str,
    base_package_manifest_sha256: &'a str,
    executable_sha256: &'a str,
    apqe_report_sha256: &'a str,
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
        let providers = config
            .aegis_provider
            .as_ref()
            .ok_or("managed Wallet release requires native APQE")?;
        let root = if expected.from_sealed_package {
            providers
                .report_path
                .ancestors()
                .nth(3)
                .filter(|root| providers.report_path == root.join("lib/apqe/build-report.json"))
                .ok_or("managed Wallet release requires the canonical package APQE report path")?
                .join("assets/wallet-dispatch")
        } else {
            config
                .genesis_path
                .as_ref()
                .and_then(|path| path.parent())
                .ok_or("managed Wallet release lacks its Genesis network directory")?
                .to_path_buf()
        };
        if !root.is_absolute() || root.canonicalize().map_err(|error| error.to_string())? != root {
            return Err(
                "managed Wallet release requires its direct canonical artifact directory".into(),
            );
        }
        let read = |name, maximum| {
            apqe_transport::read(&root.join(name), maximum, false)
                .map_err(|error| format!("managed Wallet release input {name}: {error}"))
        };
        let attachment = read("wallet-dispatch-release.json", 32 * 1024)?;
        let issuer_key = read("wallet-dispatch-release-issuer.pub", 1952)?;
        let endorsement = read(
            "wallet-dispatch-release-issuer-authorization.json",
            24 * 1024,
        )?;
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
        let selected = crate::commands::selected_network::verified_genesis(config)?;
        WalletDispatchReleaseIssuerAuthorization::verify(
            &endorsement,
            &attachment,
            &trust,
            &WalletDispatchReleaseIssuerTrust {
                origin: &selected,
                authority_public_key: &original_root,
                attachment_sha256: &expected.attachment_sha256,
                issuer_sha256: &expected.issuer_sha256,
            },
            &origin.verifier,
        )?;
        let engine = crate::services::apqe_provider::load_selected(providers)?;
        let (verified, qualification) = {
            let engine = engine
                .lock()
                .map_err(|_| "managed Wallet release provider poisoned")?;
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
        let artifacts = ManagedArtifacts::verify_current(
            &root,
            policy,
            &providers.authenticated_report_sha256,
        )?;
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
        let quick_setup_enrollment = statement.wire_profile_fingerprint == dual;
        Ok(Self {
            verified,
            proof_provider: Mutex::new(proof_provider),
            wire,
            fees,
            artifacts,
            quick_setup_enrollment,
        })
    }
}

impl VerifiedAuthority {
    pub(crate) fn wallet_release_preflight(
        &self,
        configuration: &NodeConfiguration,
    ) -> Result<Option<WalletReleasePreflight<'_>>, String> {
        let Some(release) = self.managed_wallet_release.as_ref() else {
            return Ok(None);
        };
        let policy = release.verified.policy();
        let state = if self.wallet_dispatch_policy().is_some() {
            self.native_wallet_release()?;
            WalletReleaseState::Active
        } else if self.epoch.epoch_start_height < policy.activation_finalized_height {
            if self.epoch.epoch_end_height.checked_add(1)
                == Some(policy.activation_finalized_height)
            {
                let protected = self
                    .protected
                    .as_ref()
                    .ok_or("Wallet release lacks its predecessor parameters")?;
                release
                    .verified
                    .prepare_successor(&self.epoch, protected, &self.registry)?;
            }
            WalletReleaseState::VerifiedPending
        } else {
            WalletReleaseState::MissedActivation
        };
        Ok(Some(WalletReleasePreflight {
            initial_adoption_before_close: match state {
                WalletReleaseState::VerifiedPending => unused_closing_slot(configuration, policy.activation_finalized_height)?,
                _ => false,
            },
            state,
            quick_setup_enrollment: release.quick_setup_enrollment,
            activation_finalized_height: policy.activation_finalized_height,
            target: release.artifacts.target,
            managed_release_manifest_sha256: &policy.managed_release_manifest_sha256,
            base_package_manifest_sha256: &release.artifacts.base_package_manifest_sha256,
            executable_sha256: &release.artifacts.executable_sha256,
            apqe_report_sha256: &release.artifacts.apqe_report_sha256,
        }))
    }

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

fn unused_closing_slot(config: &NodeConfiguration, activation: u64) -> Result<bool, String> {
    // The new governed subject appears in predecessor E-2, three heights
    // below the first height in the selected successor. An already reserved
    // vote or a finalized execution at that height cannot be rewritten.
    let closing_height = activation.checked_sub(3).ok_or("invalid Wallet activation close")?;
    let root = &config.storage.data_directory;
    let optional = |relative: &str, maximum| {
        let path = root.join(relative);
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.to_string()),
            Ok(_) => apqe_transport::read(&path, maximum, false).map(Some),
        }
    };
    if let Some(bytes) = optional("consensus/posy/sign-once.json", 4 * 1024 * 1024)? {
        let height = synergy_posy::persistence::SignOnceJournal::highest_reserved_or_finalized_height(&bytes)
            .map_err(|_| "invalid existing PoSy signing reservation")?;
        if height >= closing_height { return Ok(false); }
    }
    if let Some(bytes) = optional("state/execution/finalized-state.json", 4096)? {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct CommittedPointer {
            format: String,
            state: synergy_state::FinalizedState,
        }
        let pointer: CommittedPointer = serde_json::from_slice(&bytes).map_err(|_| "invalid existing finalized pointer")?;
        if pointer.format != "synergy-finalized-state-v1" {
            return Err("unsupported existing finalized pointer".into());
        }
        if pointer.state.finalized_height >= closing_height { return Ok(false); }
    }
    Ok(true)
}
