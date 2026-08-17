//! Verified and durable v3-to-v3 epoch transition evidence.
//!
//! A boundary QC is only a certified parent.  It is never promoted to
//! finality by changing epochs.  The transition proof retains the last three
//! consecutive QCs of the previous epoch, so the first QC is the exact latest
//! finalized seed and the third QC is the exact certified parent of the next
//! epoch.  Dynamic membership is accepted only through an application-owned
//! proof that the transition subject was committed by that finalized block.

use super::{
    ConsensusSignatureVerifier, QuorumCertificateReference, SimplifiedEpochContext,
    SimplifiedQuorumCertificate, SimplifiedV3EpochTransitionAnchor,
};
use crate::consensus_parameters::ConsensusParameterRoot;
use crate::synergy_types::{CanonicalSerialize, Epoch, Hash, Height, ValidatorSet};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub const POSY_SIMPLIFIED_EPOCH_TRANSITION_FORMAT: &str =
    "synergy-posy-simplified-epoch-transition-v2";
pub const POSY_SIMPLIFIED_EPOCH_TRANSITION_SCHEMA_VERSION: u32 = 2;
pub const MAX_SIMPLIFIED_EPOCH_TRANSITION_PROOF_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_SIMPLIFIED_EPOCH_TRANSITION_AUTHORITY_BYTES: usize = 1024 * 1024;

/// Signer-independent next-epoch decision that must be proven part of the
/// finalized execution at `finalized_height`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SimplifiedEpochTransitionAuthorization {
    pub schema_version: u32,
    pub previous_epoch: Epoch,
    pub previous_epoch_context_root: Hash,
    /// The previous-epoch block height that must commit this subject. The
    /// block and QC identifiers are deliberately excluded: both depend on the
    /// protected-execution commitment that contains this subject, so hashing
    /// either identifier here would create an impossible fixed point.
    pub finalized_height: Height,
    pub next_epoch: Epoch,
    pub next_epoch_start_height: Height,
    pub next_epoch_end_height: Height,
    pub next_consensus_parameter_root: String,
    pub next_active_validator_set_root: Hash,
    pub next_validator_consensus_key_root: Hash,
    pub next_frozen_voting_weight_root: Hash,
}

impl SimplifiedEpochTransitionAuthorization {
    pub fn root(&self) -> Result<Hash, String> {
        if self.schema_version != POSY_SIMPLIFIED_EPOCH_TRANSITION_SCHEMA_VERSION
            || self.previous_epoch.0.checked_add(1) != Some(self.next_epoch.0)
            || self.finalized_height.0 == 0
            || self.next_epoch_start_height.0 == 0
            || self.next_epoch_end_height.0 < self.next_epoch_start_height.0
            || self.previous_epoch_context_root.is_zero()
            || self.next_active_validator_set_root.is_zero()
            || self.next_validator_consensus_key_root.is_zero()
            || self.next_frozen_voting_weight_root.is_zero()
        {
            return Err("invalid simplified epoch-transition authorization".to_string());
        }
        let parameter_root = ConsensusParameterRoot::from_hex(&self.next_consensus_parameter_root)?;
        if parameter_root.is_zero() {
            return Err("epoch-transition authorization has a zero parameter root".to_string());
        }
        Ok(Hash::from_domain_bytes(
            "SYNERGY_POSY_SIMPLIFIED_EPOCH_TRANSITION_SUBJECT_V2",
            &self.canonical_bytes()?,
        ))
    }
}

/// Application/finality adapter required to prove that a transition subject
/// was actually committed by the finalized block's protected execution.
///
/// Consensus deliberately supplies no permissive implementation.  Production
/// wiring must verify an inclusion/receipt proof against `finalized_qc`; a
/// process flag or an unsigned validator list cannot satisfy this boundary.
pub trait SimplifiedTransitionAuthorityVerifier {
    fn verify_finalized_transition_authority(
        &self,
        finalized_qc: &SimplifiedQuorumCertificate,
        transition_subject_root: Hash,
        authority_evidence: &[u8],
    ) -> Result<(), String>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct FailClosedSimplifiedTransitionAuthorityVerifier;

impl SimplifiedTransitionAuthorityVerifier for FailClosedSimplifiedTransitionAuthorityVerifier {
    fn verify_finalized_transition_authority(
        &self,
        _finalized_qc: &SimplifiedQuorumCertificate,
        _transition_subject_root: Hash,
        _authority_evidence: &[u8],
    ) -> Result<(), String> {
        Err(
            "v3 epoch transition is disabled until finalized execution supplies a transition-commitment proof"
                .to_string(),
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SimplifiedEpochTransitionProof {
    pub format: String,
    pub previous_epoch_context: SimplifiedEpochContext,
    pub previous_validator_set: ValidatorSet,
    pub next_validator_set: ValidatorSet,
    pub authorization: SimplifiedEpochTransitionAuthorization,
    /// Exactly three consecutive, fully signed previous-epoch QCs ending at
    /// the previous epoch's last height.
    pub finality_witness: Vec<SimplifiedQuorumCertificate>,
    /// Bounded application-owned proof consumed by the authority verifier.
    pub authority_evidence: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct VerifiedSimplifiedEpochTransition {
    proof: SimplifiedEpochTransitionProof,
    next_epoch_context: SimplifiedEpochContext,
    certified_parent: QuorumCertificateReference,
    finalized_seed: QuorumCertificateReference,
    transition_subject_root: Hash,
}

impl VerifiedSimplifiedEpochTransition {
    pub fn proof(&self) -> &SimplifiedEpochTransitionProof {
        &self.proof
    }

    pub fn next_epoch_context(&self) -> &SimplifiedEpochContext {
        &self.next_epoch_context
    }

    pub fn previous_epoch_context(&self) -> &SimplifiedEpochContext {
        &self.proof.previous_epoch_context
    }

    pub fn previous_validator_set(&self) -> &ValidatorSet {
        &self.proof.previous_validator_set
    }

    pub fn next_validator_set(&self) -> &ValidatorSet {
        &self.proof.next_validator_set
    }

    pub fn certified_parent(&self) -> &QuorumCertificateReference {
        &self.certified_parent
    }

    pub fn finalized_seed(&self) -> &QuorumCertificateReference {
        &self.finalized_seed
    }

    pub fn transition_tail(&self) -> &[SimplifiedQuorumCertificate] {
        &self.proof.finality_witness
    }

    pub fn transition_subject_root(&self) -> Hash {
        self.transition_subject_root
    }
}

impl SimplifiedEpochTransitionProof {
    pub fn verify<V, A>(
        &self,
        consensus_verifier: &V,
        authority_verifier: &A,
    ) -> Result<VerifiedSimplifiedEpochTransition, String>
    where
        V: ConsensusSignatureVerifier,
        A: SimplifiedTransitionAuthorityVerifier,
    {
        if self.format != POSY_SIMPLIFIED_EPOCH_TRANSITION_FORMAT {
            return Err("unsupported simplified epoch-transition proof format".to_string());
        }
        if self.authority_evidence.len() > MAX_SIMPLIFIED_EPOCH_TRANSITION_AUTHORITY_BYTES {
            return Err("simplified epoch-transition authority evidence is oversized".to_string());
        }
        if self.previous_validator_set != self.previous_validator_set.canonicalized()
            || self.next_validator_set != self.next_validator_set.canonicalized()
        {
            return Err("epoch-transition validator sets are not canonical".to_string());
        }
        self.previous_epoch_context
            .validate_against(&self.previous_validator_set)?;
        if self.finality_witness.len() != 3 {
            return Err(
                "v3 epoch transition requires exactly three previous-epoch QCs".to_string(),
            );
        }
        let expected_first_height = self
            .previous_epoch_context
            .epoch_end_height
            .0
            .checked_sub(2)
            .ok_or_else(|| "previous v3 epoch is too short for three-QC finality".to_string())?;
        for (offset, certificate) in self.finality_witness.iter().enumerate() {
            let expected_height = expected_first_height
                .checked_add(offset as u64)
                .ok_or_else(|| "transition witness height overflow".to_string())?;
            if certificate.context.height != Height(expected_height) {
                return Err(
                    "transition finality witness is not the exact previous-epoch tail".to_string(),
                );
            }
            certificate.verify(
                &self.previous_epoch_context,
                &self.previous_validator_set,
                consensus_verifier,
            )?;
            if offset > 0
                && certificate.parent_qc != self.finality_witness[offset - 1].reference()?
            {
                return Err(
                    "transition finality witness does not form one consecutive QC chain"
                        .to_string(),
                );
            }
        }

        let finalized = &self.finality_witness[0];
        let certified_parent = &self.finality_witness[2];
        let next_epoch = self
            .previous_epoch_context
            .epoch
            .0
            .checked_add(1)
            .map(Epoch)
            .ok_or_else(|| "next simplified epoch overflows".to_string())?;
        let next_start = self
            .previous_epoch_context
            .epoch_end_height
            .0
            .checked_add(1)
            .map(Height)
            .ok_or_else(|| "next simplified epoch start overflows".to_string())?;
        if self.next_validator_set.epoch != next_epoch {
            return Err("next validator set is not frozen for the adjacent epoch".to_string());
        }
        let next_active = self.next_validator_set.active_for_epoch(next_epoch);
        let expected_authorization = SimplifiedEpochTransitionAuthorization {
            schema_version: POSY_SIMPLIFIED_EPOCH_TRANSITION_SCHEMA_VERSION,
            previous_epoch: self.previous_epoch_context.epoch,
            previous_epoch_context_root: self.previous_epoch_context.root()?,
            finalized_height: finalized.context.height,
            next_epoch,
            next_epoch_start_height: next_start,
            next_epoch_end_height: self.authorization.next_epoch_end_height,
            next_consensus_parameter_root: self.authorization.next_consensus_parameter_root.clone(),
            next_active_validator_set_root: next_active.hash()?,
            next_validator_consensus_key_root: next_active.consensus_key_root()?,
            next_frozen_voting_weight_root: next_active.frozen_bonded_weight_root()?,
        };
        if self.authorization != expected_authorization {
            return Err(
                "epoch-transition authorization does not bind the exact dynamic next set"
                    .to_string(),
            );
        }
        let transition_subject_root = self.authorization.root()?;
        authority_verifier.verify_finalized_transition_authority(
            finalized,
            transition_subject_root,
            &self.authority_evidence,
        )?;

        let finalized_seed = finalized.reference()?;
        let certified_parent = certified_parent.reference()?;
        if finalized_seed == certified_parent {
            return Err(
                "epoch transition attempted to treat one boundary QC as finalized".to_string(),
            );
        }
        let anchor = SimplifiedV3EpochTransitionAnchor {
            previous_epoch: self.previous_epoch_context.epoch,
            previous_epoch_context_root: self.previous_epoch_context.root()?,
            certified_parent_height: certified_parent.height,
            certified_parent_block_id: certified_parent.block_id.clone(),
            certified_parent_qc_id: certified_parent.qc_id,
            finalized_seed_height: finalized_seed.height,
            finalized_seed_block_id: finalized_seed.block_id.clone(),
            finalized_seed_qc_id: finalized_seed.qc_id,
            transition_subject_root,
        };
        let parameter_root =
            ConsensusParameterRoot::from_hex(&self.authorization.next_consensus_parameter_root)?;
        let next_epoch_context = SimplifiedEpochContext::derive_from_verified_v3_transition_anchor(
            next_epoch,
            next_start,
            self.authorization.next_epoch_end_height,
            anchor,
            parameter_root,
            &self.next_validator_set,
        )?;
        Ok(VerifiedSimplifiedEpochTransition {
            proof: self.clone(),
            next_epoch_context,
            certified_parent,
            finalized_seed,
            transition_subject_root,
        })
    }

    pub fn canonical_record_bytes(&self) -> Result<Vec<u8>, String> {
        let bytes = self.canonical_bytes()?;
        if bytes.len() > MAX_SIMPLIFIED_EPOCH_TRANSITION_PROOF_BYTES {
            return Err("simplified epoch-transition proof is oversized".to_string());
        }
        Ok(bytes)
    }
}

/// Immutable one-record transition-proof store.  Startup always canonical
/// decodes and re-verifies every QC plus the finalized execution authority.
#[derive(Debug, Clone)]
pub struct DurableSimplifiedEpochTransitionStore {
    path: PathBuf,
}

impl DurableSimplifiedEpochTransitionStore {
    pub fn at_path(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn install_or_load<V, A>(
        &self,
        proposed: &SimplifiedEpochTransitionProof,
        consensus_verifier: &V,
        authority_verifier: &A,
    ) -> Result<VerifiedSimplifiedEpochTransition, String>
    where
        V: ConsensusSignatureVerifier,
        A: SimplifiedTransitionAuthorityVerifier,
    {
        let proposed_verified = proposed.verify(consensus_verifier, authority_verifier)?;
        if self.path.exists() {
            let existing = self.load(consensus_verifier, authority_verifier)?;
            if existing.transition_subject_root() != proposed_verified.transition_subject_root()
                || existing.certified_parent() != proposed_verified.certified_parent()
                || existing.finalized_seed() != proposed_verified.finalized_seed()
            {
                return Err(
                    "durable epoch-transition proof conflicts with the proposed transition"
                        .to_string(),
                );
            }
            return Ok(existing);
        }
        let bytes = proposed.canonical_record_bytes()?;
        persist_immutable(&self.path, &bytes)?;
        self.load(consensus_verifier, authority_verifier)
    }

    pub fn load<V, A>(
        &self,
        consensus_verifier: &V,
        authority_verifier: &A,
    ) -> Result<VerifiedSimplifiedEpochTransition, String>
    where
        V: ConsensusSignatureVerifier,
        A: SimplifiedTransitionAuthorityVerifier,
    {
        let bytes = fs::read(&self.path).map_err(|error| {
            format!(
                "read durable epoch-transition proof {}: {error}",
                self.path.display()
            )
        })?;
        if bytes.len() > MAX_SIMPLIFIED_EPOCH_TRANSITION_PROOF_BYTES {
            return Err("durable epoch-transition proof is oversized".to_string());
        }
        let proof = SimplifiedEpochTransitionProof::assert_canonical_bytes(&bytes)?;
        proof.verify(consensus_verifier, authority_verifier)
    }

    /// Loads a canonical proof while allowing the caller to construct the
    /// previous epoch's signature verifier from the proof's root-bound frozen
    /// inputs. The factory must independently pin the expected previous
    /// context root before trusting those keys; only a fully verified
    /// capability is returned.
    pub fn load_with_consensus_verifier_factory<V, A, F>(
        &self,
        authority_verifier: &A,
        verifier_factory: F,
    ) -> Result<VerifiedSimplifiedEpochTransition, String>
    where
        V: ConsensusSignatureVerifier,
        A: SimplifiedTransitionAuthorityVerifier,
        F: FnOnce(&SimplifiedEpochContext, &ValidatorSet) -> Result<V, String>,
    {
        let bytes = fs::read(&self.path).map_err(|error| {
            format!(
                "read durable epoch-transition proof {}: {error}",
                self.path.display()
            )
        })?;
        if bytes.len() > MAX_SIMPLIFIED_EPOCH_TRANSITION_PROOF_BYTES {
            return Err("durable epoch-transition proof is oversized".to_string());
        }
        let proof = SimplifiedEpochTransitionProof::assert_canonical_bytes(&bytes)?;
        let consensus_verifier =
            verifier_factory(&proof.previous_epoch_context, &proof.previous_validator_set)?;
        proof.verify(&consensus_verifier, authority_verifier)
    }
}

fn persist_immutable(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "epoch-transition proof path has no parent".to_string())?;
    fs::create_dir_all(parent).map_err(|error| {
        format!(
            "create epoch-transition proof directory {}: {error}",
            parent.display()
        )
    })?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "epoch-transition proof path has no valid file name".to_string())?;
    let temp = parent.join(format!(
        ".{file_name}.tmp-{}-{}",
        std::process::id(),
        current_unix_nanos()
    ));
    let result = (|| -> Result<(), String> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&temp)
            .map_err(|error| format!("create transition temp {}: {error}", temp.display()))?;
        file.write_all(bytes)
            .map_err(|error| format!("write transition temp {}: {error}", temp.display()))?;
        file.sync_all()
            .map_err(|error| format!("fsync transition temp {}: {error}", temp.display()))?;
        fs::hard_link(&temp, path).map_err(|error| {
            format!(
                "install immutable transition proof {}: {error}",
                path.display()
            )
        })?;
        OpenOptions::new()
            .read(true)
            .open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| format!("fsync transition directory {}: {error}", parent.display()))
    })();
    let _ = fs::remove_file(&temp);
    result
}

fn current_unix_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::consensus::signing_authority::DurableConsensusSigningAuthority;
    use crate::consensus::simplified_posy::{
        build_state_sync_chunks, select_consensus_profile_from_verified_v3_transition, BlockVote,
        ConsensusObjectContext, ConsensusProfileAtHeight, FinalizedBlockRecord,
        ParticipantSignature, SimplifiedConsensusStateMachine, SimplifiedSafetyState,
        SimplifiedStateSyncBundle, SimplifiedStateSyncStager, POSY_SIMPLIFIED_BLOCK_VOTE_DOMAIN,
        POSY_SIMPLIFIED_STATE_SYNC_FORMAT,
    };
    use crate::synergy_types::{
        AegisPqKeyId, AegisPqPublicKey, AegisPqSignature, BlockId, ClusterId, Round, UmaId,
        ValidatorId, ValidatorRecord, ValidatorStatus, TESTNET_V3_CONSENSUS_SIGNATURE_ALGORITHM,
        TESTNET_V3_MLDSA65_PUBLIC_KEY_BYTES,
    };
    use std::collections::BTreeMap;
    use std::time::Instant;

    #[derive(Debug, Clone, Copy)]
    pub(crate) struct DeterministicVerifier;

    impl ConsensusSignatureVerifier for DeterministicVerifier {
        fn verify_consensus_signature(
            &self,
            domain: &str,
            payload: &[u8],
            validator: &ValidatorRecord,
            key_id: &AegisPqKeyId,
            _epoch: Epoch,
            signature: &AegisPqSignature,
        ) -> Result<(), String> {
            if *signature == fake_signature(domain, payload, &validator.validator_id, key_id) {
                Ok(())
            } else {
                Err("deterministic transition signature failed".to_string())
            }
        }
    }

    #[derive(Debug, Clone, Copy)]
    pub(crate) struct DeterministicAuthorityVerifier;

    impl SimplifiedTransitionAuthorityVerifier for DeterministicAuthorityVerifier {
        fn verify_finalized_transition_authority(
            &self,
            finalized_qc: &SimplifiedQuorumCertificate,
            transition_subject_root: Hash,
            authority_evidence: &[u8],
        ) -> Result<(), String> {
            let expected = (
                transition_subject_root,
                finalized_qc.protected_execution_root,
            )
                .canonical_bytes()?;
            if authority_evidence == expected {
                Ok(())
            } else {
                Err("transition subject is not committed by finalized execution".to_string())
            }
        }
    }

    fn fake_signature(
        domain: &str,
        payload: &[u8],
        validator_id: &ValidatorId,
        key_id: &AegisPqKeyId,
    ) -> AegisPqSignature {
        let mut transcript = payload.to_vec();
        transcript.extend_from_slice(validator_id.0.as_bytes());
        transcript.extend_from_slice(key_id.0.as_bytes());
        AegisPqSignature {
            algorithm: TESTNET_V3_CONSENSUS_SIGNATURE_ALGORITHM.to_string(),
            signature_bytes: Hash::from_domain_bytes(domain, &transcript).0.to_vec(),
        }
    }

    fn validator_set(epoch: Epoch, count: usize) -> ValidatorSet {
        ValidatorSet {
            epoch,
            validators: (0..count)
                .map(|index| {
                    let key_id = AegisPqKeyId(format!("transition-key-{index}"));
                    let key = AegisPqPublicKey {
                        key_id,
                        algorithm: TESTNET_V3_CONSENSUS_SIGNATURE_ALGORITHM.to_string(),
                        key_bytes: vec![index as u8 + 1; TESTNET_V3_MLDSA65_PUBLIC_KEY_BYTES],
                    };
                    ValidatorRecord {
                        validator_id: ValidatorId(format!("transition-validator-{index}")),
                        validator_uma_id: UmaId(format!("uma:transition-validator-{index}")),
                        consensus_public_key: key.clone(),
                        peer_public_key: key.clone(),
                        operator_public_key: key,
                        voting_weight: 1,
                        status: ValidatorStatus::Active,
                        cluster_id: ClusterId(0),
                        activation_epoch: if index < 5 { Epoch(7) } else { epoch },
                    }
                })
                .collect(),
        }
        .canonicalized()
    }

    fn signed_qc(
        context: &SimplifiedEpochContext,
        validators: &ValidatorSet,
        height: Height,
        parent_qc: QuorumCertificateReference,
    ) -> SimplifiedQuorumCertificate {
        let object_context = ConsensusObjectContext::for_height(context, height, Round(0)).unwrap();
        let block_id = BlockId(format!("transition-block-{}", height.0));
        let protected_execution_root = Hash::from_domain_bytes(
            "transition-test-protected-execution",
            &height.0.to_le_bytes(),
        );
        let participants = validators
            .validators
            .iter()
            .map(|validator| {
                let mut vote = BlockVote {
                    context: object_context.clone(),
                    block_id: block_id.clone(),
                    parent_block_id: parent_qc.block_id.clone(),
                    parent_qc: parent_qc.clone(),
                    takeover_tc_id: None,
                    protected_execution_root,
                    validator_id: validator.validator_id.clone(),
                    key_id: validator.consensus_public_key.key_id.clone(),
                    signature: AegisPqSignature {
                        algorithm: TESTNET_V3_CONSENSUS_SIGNATURE_ALGORITHM.to_string(),
                        signature_bytes: vec![1],
                    },
                };
                vote.signature = fake_signature(
                    POSY_SIMPLIFIED_BLOCK_VOTE_DOMAIN,
                    &vote.signing_bytes().unwrap(),
                    &vote.validator_id,
                    &vote.key_id,
                );
                ParticipantSignature {
                    validator_id: vote.validator_id,
                    key_id: vote.key_id,
                    signature: vote.signature,
                }
            })
            .collect();
        SimplifiedQuorumCertificate {
            context: object_context,
            block_id,
            parent_block_id: parent_qc.block_id.clone(),
            parent_qc,
            takeover_tc_id: None,
            protected_execution_root,
            participants,
        }
    }

    pub(crate) fn proof() -> SimplifiedEpochTransitionProof {
        let previous_validator_set = validator_set(Epoch(7), 5);
        let previous_epoch_context = SimplifiedEpochContext::derive(
            Epoch(7),
            Height(1_000),
            Height(1_010),
            Hash::from_domain_bytes("transition-test-seed", b"epoch-7"),
            ConsensusParameterRoot::from_canonical_manifest_bytes(b"epoch-7-parameters"),
            &previous_validator_set,
        )
        .unwrap();
        let qc_1008 = signed_qc(
            &previous_epoch_context,
            &previous_validator_set,
            Height(1_008),
            QuorumCertificateReference {
                height: Height(1_007),
                block_id: BlockId("transition-block-1007".to_string()),
                qc_id: Hash::from_domain_bytes("transition-test-qc", b"1007"),
            },
        );
        let qc_1009 = signed_qc(
            &previous_epoch_context,
            &previous_validator_set,
            Height(1_009),
            qc_1008.reference().unwrap(),
        );
        let qc_1010 = signed_qc(
            &previous_epoch_context,
            &previous_validator_set,
            Height(1_010),
            qc_1009.reference().unwrap(),
        );
        let next_validator_set = validator_set(Epoch(8), 7);
        let next_active = next_validator_set.active_for_epoch(Epoch(8));
        let authorization = SimplifiedEpochTransitionAuthorization {
            schema_version: POSY_SIMPLIFIED_EPOCH_TRANSITION_SCHEMA_VERSION,
            previous_epoch: Epoch(7),
            previous_epoch_context_root: previous_epoch_context.root().unwrap(),
            finalized_height: Height(1_008),
            next_epoch: Epoch(8),
            next_epoch_start_height: Height(1_011),
            next_epoch_end_height: Height(2_010),
            next_consensus_parameter_root: ConsensusParameterRoot::from_canonical_manifest_bytes(
                b"epoch-8-parameters",
            )
            .to_hex(),
            next_active_validator_set_root: next_active.hash().unwrap(),
            next_validator_consensus_key_root: next_active.consensus_key_root().unwrap(),
            next_frozen_voting_weight_root: next_active.frozen_bonded_weight_root().unwrap(),
        };
        let authority_evidence = (
            authorization.root().unwrap(),
            qc_1008.protected_execution_root,
        )
            .canonical_bytes()
            .unwrap();
        SimplifiedEpochTransitionProof {
            format: POSY_SIMPLIFIED_EPOCH_TRANSITION_FORMAT.to_string(),
            previous_epoch_context,
            previous_validator_set,
            next_validator_set,
            authorization,
            finality_witness: vec![qc_1008, qc_1009, qc_1010],
            authority_evidence,
        }
    }

    fn temp_path(label: &str) -> PathBuf {
        crate::utils::test_temp_root(format!(
            "posy-transition-{label}-{}-{}/proof.json",
            std::process::id(),
            current_unix_nanos()
        ))
    }

    #[test]
    fn verified_transition_onboards_dynamic_set_without_resetting_finality() {
        let verified = proof()
            .verify(&DeterministicVerifier, &DeterministicAuthorityVerifier)
            .unwrap();
        assert_eq!(verified.next_validator_set().validators.len(), 7);
        assert_eq!(verified.certified_parent().height, Height(1_010));
        assert_eq!(verified.finalized_seed().height, Height(1_008));
        assert_ne!(verified.certified_parent(), verified.finalized_seed());
        assert_eq!(
            verified.next_epoch_context().finalized_epoch_seed_root,
            verified.finalized_seed().qc_id
        );
        let selected =
            select_consensus_profile_from_verified_v3_transition(Height(1_011), &verified).unwrap();
        assert!(matches!(
            selected,
            ConsensusProfileAtHeight::PosySimplifiedV3 { validator_set, .. }
                if validator_set.validators.len() == 7
        ));
        assert!(
            select_consensus_profile_from_verified_v3_transition(Height(2_011), &verified,)
                .is_err()
        );

        assert!(SimplifiedSafetyState::new(
            verified.next_epoch_context(),
            verified.certified_parent().clone(),
        )
        .is_err());
        let state = SimplifiedSafetyState::new_from_verified_v3_transition(
            verified.next_epoch_context(),
            &verified,
        )
        .unwrap();
        assert_eq!(state.finalized.height, Height(1_008));
        assert_eq!(state.highest_qc.height, Height(1_010));

        let state_path = temp_path("state-continuity").with_file_name("state.json");
        let store = super::super::DurableSimplifiedPosyStore::at_path(state_path);
        let machine =
            SimplifiedConsensusStateMachine::open_from_verified_v3_transition(&verified, store)
                .unwrap();
        let first_new_qc = signed_qc(
            verified.next_epoch_context(),
            verified.next_validator_set(),
            Height(1_011),
            verified.certified_parent().clone(),
        );
        let preview = machine
            .preview_finalized_with_qc(&first_new_qc)
            .unwrap()
            .expect("first new-epoch QC continues the prior three-chain");
        assert_eq!(preview.height, Height(1_009));
    }

    #[test]
    fn transition_fails_closed_without_finalized_execution_authority() {
        let error = proof()
            .verify(
                &DeterministicVerifier,
                &FailClosedSimplifiedTransitionAuthorityVerifier,
            )
            .unwrap_err();
        assert!(error.contains("disabled until finalized execution"));

        let mut single_qc = proof();
        single_qc.finality_witness = vec![single_qc.finality_witness[2].clone()];
        let error = single_qc
            .verify(&DeterministicVerifier, &DeterministicAuthorityVerifier)
            .unwrap_err();
        assert!(error.contains("exactly three"));
    }

    #[test]
    fn durable_transition_restart_reverifies_and_rejects_membership_substitution() {
        let proof = proof();
        let path = temp_path("durable-restart");
        let store = DurableSimplifiedEpochTransitionStore::at_path(&path);
        let installed = store
            .install_or_load(
                &proof,
                &DeterministicVerifier,
                &DeterministicAuthorityVerifier,
            )
            .unwrap();
        let restarted = store
            .load(&DeterministicVerifier, &DeterministicAuthorityVerifier)
            .unwrap();
        assert_eq!(
            installed.transition_subject_root(),
            restarted.transition_subject_root()
        );

        let mut substituted = proof;
        substituted.next_validator_set.validators.pop();
        let error = store
            .install_or_load(
                &substituted,
                &DeterministicVerifier,
                &DeterministicAuthorityVerifier,
            )
            .unwrap_err();
        assert!(error.contains("exact dynamic next set"));
    }

    #[test]
    fn proof_aware_state_sync_reconstructs_and_installs_across_v3_epochs() {
        let verified = proof()
            .verify(&DeterministicVerifier, &DeterministicAuthorityVerifier)
            .unwrap();
        let first_new_qc = signed_qc(
            verified.next_epoch_context(),
            verified.next_validator_set(),
            Height(1_011),
            verified.certified_parent().clone(),
        );
        let newly_finalized = verified.transition_tail()[1].reference().unwrap();
        let bundle = SimplifiedStateSyncBundle {
            format: POSY_SIMPLIFIED_STATE_SYNC_FORMAT.to_string(),
            epoch_context: verified.next_epoch_context().clone(),
            anchor_qc: verified.certified_parent().clone(),
            certified_qcs: vec![first_new_qc],
            certified_tcs: BTreeMap::new(),
            claimed_finalized: FinalizedBlockRecord {
                height: newly_finalized.height,
                block_id: newly_finalized.block_id,
                qc_id: newly_finalized.qc_id,
            },
        };

        let plain_error = bundle
            .verify_and_reconstruct(
                verified.next_epoch_context(),
                verified.next_validator_set(),
                verified.certified_parent(),
                &DeterministicVerifier,
                None,
                None,
            )
            .unwrap_err();
        assert!(plain_error.contains("independently verified durable transition proof"));

        let reconstructed = bundle
            .verify_and_reconstruct_from_verified_v3_transition(
                &verified,
                &DeterministicVerifier,
                None,
                None,
            )
            .unwrap();
        assert_eq!(reconstructed.highest_qc.height, Height(1_011));
        assert_eq!(reconstructed.finalized.height, Height(1_009));
        assert_eq!(reconstructed.epoch_transition_tail_qcs.len(), 3);

        let request_id = Hash::from_domain_bytes("transition-state-sync", b"request-1");
        let chunks = build_state_sync_chunks(&bundle, request_id).unwrap();
        let mut stager = SimplifiedStateSyncStager::new_from_verified_v3_transition(&verified)
            .expect("proof-aware stager");
        let now = Instant::now();
        stager.register_request(request_id, now).unwrap();
        let peer = verified.next_validator_set().validators[0]
            .validator_id
            .clone();
        let mut completed = None;
        for chunk in chunks {
            completed = stager.accept(&peer, chunk, now).unwrap().or(completed);
        }
        let completed = completed.expect("complete proof-aware state sync");

        let state_path = temp_path("state-sync-target").with_file_name("state.json");
        let mut target = SimplifiedConsensusStateMachine::open_from_verified_v3_transition(
            &verified,
            super::super::DurableSimplifiedPosyStore::at_path(&state_path),
        )
        .unwrap();
        let signing_authority = DurableConsensusSigningAuthority::at_path(
            temp_path("state-sync-signer").with_file_name("signer.json"),
        );
        target
            .install_state_sync_bundle(
                &completed.bundle,
                &DeterministicVerifier,
                &signing_authority,
            )
            .unwrap();
        assert_eq!(target.state().highest_qc.height, Height(1_011));
        assert_eq!(target.state().finalized.height, Height(1_009));
        drop(target);
        let restarted = SimplifiedConsensusStateMachine::open_from_verified_v3_transition(
            &verified,
            super::super::DurableSimplifiedPosyStore::at_path(&state_path),
        )
        .unwrap();
        assert_eq!(restarted.state().highest_qc.height, Height(1_011));
        assert_eq!(restarted.state().finalized.height, Height(1_009));

        let mut substituted = bundle;
        substituted.claimed_finalized.qc_id =
            Hash::from_domain_bytes("transition-state-sync", b"substituted-finality");
        let request_id = Hash::from_domain_bytes("transition-state-sync", b"request-2");
        let chunks = build_state_sync_chunks(&substituted, request_id).unwrap();
        let mut stager = SimplifiedStateSyncStager::new_from_verified_v3_transition(&verified)
            .expect("proof-aware stager");
        stager.register_request(request_id, now).unwrap();
        let error = chunks
            .into_iter()
            .find_map(|chunk| stager.accept(&peer, chunk, now).err())
            .expect("substituted transition-tail claim must fail");
        assert!(error.contains("receiver's verified transition tail"));
    }
}
