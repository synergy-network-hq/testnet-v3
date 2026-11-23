//! Signed selection of the protected Wallet action profile. The approval and
//! release attestation can be governed off-chain. These pins record that
//! approval boundary independently of ETDAG's transport cryptography root.

use serde::{Deserialize, Serialize};
use synergy_aegis::{
    ChainId, CryptoEngine, EnrollmentRegistryRelease, EnrollmentRegistryReleaseIssuer, KeyId,
    NativeGenesisHash, SignatureAlgorithm, SigningContext, VerifiedEnrollmentRegistryRelease,
};
use synergy_etdag::EtdagParameters;
use synergy_posy::{
    EpochTransitionAuthorization, FinalizedBlockRecord, FrozenValidatorRegistry,
    SimplifiedEpochContext,
};

use super::{ProtectedCutoffRelationship, ProtectedEpochPolicy};

pub use synergy_aegis::ENROLLMENT_REGISTRY_RELEASE_DOMAIN as WALLET_DISPATCH_RELEASE_DOMAIN;
const MAX_RELEASE_BYTES: usize = 32 * 1024;
const ML_DSA_65_PUBLIC_KEY_BYTES: usize = 1952;
const ML_DSA_65_SIGNATURE_BYTES: usize = 3309;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedWalletDispatchPolicy {
    pub version: u32,
    pub chain_id: u64,
    pub network_id: String,
    pub genesis_hash: String,
    /// Earliest certified predecessor under which admission can open.
    pub activation_finalized_height: u64,
    pub managed_release_manifest_sha256: String,
    pub off_chain_approval_sha256: String,
    pub release_attestation_sha256: String,
    pub action_registry_sha256: String,
    pub wire_schema_sha256: String,
    pub action_vectors_sha256: String,
    pub ownership_chain_id: String,
    pub enrollment_wire_profile_fingerprint: String,
    pub enrollment_commitment_profile_fingerprint: String,
    pub enrollment_provider_manifests: Vec<String>,
    pub enrollment_proof_provider_artifacts: Vec<String>,
    pub fee_collector: String,
    pub fee_class: u32,
    pub base_fee_per_gas_nwei: u64,
    pub enroll_commit_gas: u64,
    pub enroll_reveal_gas: u64,
    pub transfer_gas: u64,
}

fn digest(value: &str) -> bool {
    synergy_posy::is_hash(value) && value.bytes().any(|byte| byte != b'0')
}

impl ProtectedWalletDispatchPolicy {
    pub fn validate(
        &self,
        epoch: &SimplifiedEpochContext,
        parameters: &EtdagParameters,
    ) -> Result<(), String> {
        self.validate_epoch_scope(
            epoch.chain_id,
            &epoch.network_id,
            epoch.epoch_end_height,
            parameters,
        )
    }

    fn validate_epoch_scope(
        &self,
        chain_id: u64,
        network_id: &str,
        epoch_end_height: u64,
        parameters: &EtdagParameters,
    ) -> Result<(), String> {
        let fingerprints = [
            &self.genesis_hash,
            &self.managed_release_manifest_sha256,
            &self.off_chain_approval_sha256,
            &self.release_attestation_sha256,
            &self.action_registry_sha256,
            &self.wire_schema_sha256,
            &self.action_vectors_sha256,
            &self.ownership_chain_id,
            &self.enrollment_wire_profile_fingerprint,
            &self.enrollment_commitment_profile_fingerprint,
        ];
        if self.version != 1
            || self.chain_id != chain_id
            || self.network_id != network_id
            || self.activation_finalized_height == 0
            || self.activation_finalized_height >= epoch_end_height
            || fingerprints.iter().any(|value| !digest(value))
            || self.off_chain_approval_sha256 == self.release_attestation_sha256
            || !(1..=4).contains(&self.enrollment_provider_manifests.len())
            || self
                .enrollment_provider_manifests
                .iter()
                .any(|value| !digest(value))
            || self
                .enrollment_provider_manifests
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            || !(1..=8).contains(&self.enrollment_proof_provider_artifacts.len())
            || self
                .enrollment_proof_provider_artifacts
                .iter()
                .any(|value| !digest(value))
            || self
                .enrollment_proof_provider_artifacts
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            || !self.fee_collector.starts_with("synf1")
            || self.fee_collector.len() > 256
            || self.fee_collector.chars().any(char::is_whitespace)
            || self.fee_collector.chars().any(char::is_control)
            || self.base_fee_per_gas_nwei == 0
            || [
                self.enroll_commit_gas,
                self.enroll_reveal_gas,
                self.transfer_gas,
            ]
            .iter()
            .any(|gas| !(1..=parameters.max_protected_gas).contains(gas))
        {
            return Err("signed protected Wallet action policy has invalid scope, evidence, or resource limits".into());
        }
        Ok(())
    }

    pub fn commitment(&self) -> Result<String, String> {
        synergy_posy::canonical_hash("SYNERGY_POSY_PROTECTED_WALLET_DISPATCH_V1", self)
            .map_err(|error| error.to_string())
    }

    /// Called only with the native separately certified source. The source
    /// must already be verified against the canonical three-QC history.
    pub fn check_finalized_source(
        &self,
        genesis: &str,
        source: &FinalizedBlockRecord,
    ) -> Result<(), String> {
        if self.genesis_hash != genesis
            || source.height < self.activation_finalized_height
            || !digest(&source.block_id)
            || !digest(&source.finality_certificate_id)
        {
            return Err("protected Wallet dispatch is outside the authorized Genesis or finalized activation boundary".into());
        }
        Ok(())
    }
}

/// The release role signs the exact already reviewed inputs and the existing
/// epoch which may introduce them. The signed release is independent of PoSy
/// votes and cannot grant authority without the normal certified epoch close.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WalletDispatchReleasePayload {
    pub version: u32,
    pub predecessor_context_root: String,
    pub signer_key_id: String,
    pub policy: ProtectedWalletDispatchPolicy,
}

impl WalletDispatchReleasePayload {
    pub fn signing_context(
        &self,
        previous: &SimplifiedEpochContext,
    ) -> Result<SigningContext, String> {
        let height = previous
            .epoch_end_height
            .checked_sub(2)
            .filter(|height| previous.contains_height(*height))
            .ok_or("Wallet release predecessor has no certified close")?;
        Ok(SigningContext {
            domain: WALLET_DISPATCH_RELEASE_DOMAIN.into(),
            chain_id: previous.chain_id,
            epoch: Some(previous.epoch),
            height: Some(height),
        })
    }

    pub fn signing_bytes(&self) -> Result<Vec<u8>, String> {
        self.enrollment_statement()?
            .signing_bytes()
            .map_err(|error| error.to_string())
    }

    fn enrollment_statement(&self) -> Result<EnrollmentRegistryRelease, String> {
        let hash =
            |value: &str| synergy_posy::parse_hash_bytes(value).map_err(|error| error.to_string());
        let pins = |values: &[String]| -> Result<Vec<[u8; 32]>, String> {
            values.iter().map(|value| hash(value)).collect()
        };
        if self.version != 1
            || !digest(&self.predecessor_context_root)
            || self.signer_key_id.len() > 128
            || KeyId::new(self.signer_key_id.as_str()).is_err()
        {
            return Err(
                "Wallet dispatch release transcript has invalid version, predecessor or signer"
                    .into(),
            );
        }
        let release_context =
            synergy_posy::canonical_hash("SYNERGY_POSY_WALLET_DISPATCH_RELEASE_CONTEXT_V1", self)
                .map_err(|error| error.to_string())?;
        let policy = &self.policy;
        Ok(EnrollmentRegistryRelease {
            native_chain: ChainId::from_u64(policy.chain_id),
            network_id: policy.network_id.clone(),
            genesis: NativeGenesisHash::from_bytes(hash(&policy.genesis_hash)?),
            ownership_chain: ChainId::from_be_bytes(hash(&policy.ownership_chain_id)?),
            activation_finalized_height: policy.activation_finalized_height,
            wire_profile_fingerprint: hash(&policy.enrollment_wire_profile_fingerprint)?,
            commitment_profile_fingerprint: hash(
                &policy.enrollment_commitment_profile_fingerprint,
            )?,
            enrollment_provider_manifests: pins(&policy.enrollment_provider_manifests)?,
            proof_provider_artifacts: pins(&policy.enrollment_proof_provider_artifacts)?,
            release_context: hash(&release_context)?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedWalletDispatchRelease {
    pub payload: WalletDispatchReleasePayload,
    pub signature_algorithm: SignatureAlgorithm,
    pub signature: Vec<u8>,
}

/// The native caller supplies these values from verified signed origin,
/// release manifest and approved evidence. None can come from the attachment.
pub struct WalletDispatchReleaseTrust<'a> {
    pub genesis_hash: &'a str,
    pub release_signer_key_id: &'a KeyId,
    pub release_signer_public_key: &'a [u8],
    pub release_verifier_artifact_sha256: [u8; 32],
    pub managed_release_manifest_sha256: &'a str,
    pub off_chain_approval_sha256: &'a str,
    pub release_attestation_sha256: &'a str,
}

/// This in-memory capability cannot be decoded directly or supply an active
/// APQE verifier. It prepares only the acyclic PoSy close subject.
pub struct VerifiedWalletDispatchRelease {
    payload: WalletDispatchReleasePayload,
    enrollment: VerifiedEnrollmentRegistryRelease,
}

impl VerifiedWalletDispatchRelease {
    pub fn verify(
        original: &[u8],
        trust: &WalletDispatchReleaseTrust<'_>,
        previous: &SimplifiedEpochContext,
        parameters: &EtdagParameters,
        engine: &CryptoEngine,
    ) -> Result<Self, String> {
        let verified = Self::verify_signed(original, trust, engine)?;
        verified.check_predecessor(previous, parameters)?;
        Ok(verified)
    }

    /// Signature and independent release pins can be authenticated when a
    /// package is installed, before its exact future predecessor is finalized.
    pub fn verify_signed(
        original: &[u8],
        trust: &WalletDispatchReleaseTrust<'_>,
        engine: &CryptoEngine,
    ) -> Result<Self, String> {
        if original.is_empty() || original.len() > MAX_RELEASE_BYTES {
            return Err("Wallet dispatch release attachment exceeds its bound".into());
        }
        let release: SignedWalletDispatchRelease = serde_json::from_slice(original)
            .map_err(|error| format!("decode Wallet dispatch release: {error}"))?;
        if serde_json::to_vec(&release).map_err(|error| error.to_string())? != original {
            return Err("Wallet dispatch release requires exact canonical bytes".into());
        }
        let policy = &release.payload.policy;
        if release.payload.version != 1
            || policy.genesis_hash != trust.genesis_hash
            || policy.managed_release_manifest_sha256 != trust.managed_release_manifest_sha256
            || policy.off_chain_approval_sha256 != trust.off_chain_approval_sha256
            || policy.release_attestation_sha256 != trust.release_attestation_sha256
            || release.payload.signer_key_id != trust.release_signer_key_id.as_str()
            || trust.release_signer_public_key.len() != ML_DSA_65_PUBLIC_KEY_BYTES
            || release.signature_algorithm != SignatureAlgorithm::MlDsa65
            || release.signature.len() != ML_DSA_65_SIGNATURE_BYTES
        {
            return Err(
                "Wallet dispatch release differs from the independently approved scope".into(),
            );
        }
        let enrollment = VerifiedEnrollmentRegistryRelease::verify(
            release.payload.enrollment_statement()?,
            &release.signature,
            &EnrollmentRegistryReleaseIssuer {
                public_key: trust.release_signer_public_key,
                verifier_artifact_sha256: trust.release_verifier_artifact_sha256,
            },
            engine,
        )
        .map_err(|error| format!("verify Wallet dispatch release: {error}"))?;
        Ok(Self {
            payload: release.payload,
            enrollment,
        })
    }

    fn check_predecessor(
        &self,
        previous: &SimplifiedEpochContext,
        parameters: &EtdagParameters,
    ) -> Result<(), String> {
        let next_first = previous
            .epoch_end_height
            .checked_add(1)
            .ok_or("Wallet release successor height overflow")?;
        let next_last = next_first
            .checked_add(999)
            .ok_or("Wallet release successor height overflow")?;
        if self.predecessor_context_root() != previous.root().map_err(|error| error.to_string())?
            || self.policy().activation_finalized_height != next_first
        {
            return Err("Wallet release differs from the exact authenticated predecessor".into());
        }
        self.policy().validate_epoch_scope(
            previous.chain_id,
            &previous.network_id,
            next_last,
            parameters,
        )
    }

    pub fn enrollment(&self) -> &VerifiedEnrollmentRegistryRelease {
        &self.enrollment
    }

    pub fn policy(&self) -> &ProtectedWalletDispatchPolicy {
        &self.payload.policy
    }

    pub fn predecessor_context_root(&self) -> &str {
        &self.payload.predecessor_context_root
    }

    pub fn prepare_successor(
        &self,
        previous: &SimplifiedEpochContext,
        current: &ProtectedEpochPolicy,
        current_registry: &FrozenValidatorRegistry,
    ) -> Result<(EpochTransitionAuthorization, ProtectedEpochPolicy), String> {
        self.check_predecessor(previous, &current.parameters)?;
        if current.commitment()? != previous.consensus_parameter_root
            || current.cutoff_relationship != ProtectedCutoffRelationship::ProcessingGroupsV1
            || current.wallet_dispatch.is_some()
        {
            return Err("Wallet release does not extend the exact authenticated policy".into());
        }
        previous
            .validate_against(current_registry)
            .map_err(|error| error.to_string())?;
        current.validate(current_registry, previous)?;
        let next_epoch = previous
            .epoch
            .checked_add(1)
            .ok_or("Wallet release successor epoch overflow")?;
        let next_registry =
            FrozenValidatorRegistry::new(next_epoch, current_registry.active().cloned().collect())
                .map_err(|error| error.to_string())?;
        let mut next =
            current.successor_clock(previous.epoch_start_height, previous.epoch_end_height)?;
        next.wallet_dispatch = Some(self.payload.policy.clone());
        let authorization = EpochTransitionAuthorization::for_governed_successor(
            previous,
            &next_registry,
            next.commitment()?,
        )
        .map_err(|error| error.to_string())?;
        self.payload.policy.validate_epoch_scope(
            previous.chain_id,
            &previous.network_id,
            authorization.next_epoch_end_height,
            &next.parameters,
        )?;
        Ok((authorization, next))
    }
}
