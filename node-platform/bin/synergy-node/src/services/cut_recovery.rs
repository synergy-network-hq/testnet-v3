//! R3 proof verification. No timers, votes or consensus transitions live here.
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use super::authority::VerifiedAuthority;
use serde::{Deserialize, Serialize};
use synergy_etdag::persistence::{CutRecoveryGeneration, ProtectedRecoveryVerifier};
use synergy_etdag::{EtdagDigest, EtdagError, TargetAdmissionContextV3};
use synergy_posy::{
    AcceptedTimeoutSummary, ProposalDelivery, ProposalValidationCertificate,
    SimplifiedFinalityParent, SimplifiedTimeoutCertificate, VerifiedTimeoutCertificateStore,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveryProof {
    version: u32,
    original_validation_id: String,
    terminal_height: u64,
    terminal_round: u64,
    timeout_path_root: EtdagDigest,
    certified_parent: SimplifiedFinalityParent,
}

pub(super) fn generation(
    target: u64,
    original: &ProposalValidationCertificate,
    previous: EtdagDigest,
    path: &[&AcceptedTimeoutSummary],
) -> Result<CutRecoveryGeneration, String> {
    let terminal = path.last().ok_or("R3 timeout path is empty")?;
    generation_from_parts(
        target,
        original,
        previous,
        terminal.context(),
        terminal.id(),
        terminal.highest_parent().clone(),
        &path.iter().map(|tc| tc.id().to_owned()).collect::<Vec<_>>(),
    )
}

// Negative native fixtures deliberately construct rejected ancestry. Never
// expose an unsealed wire-proof constructor on the production fast path.
#[cfg(test)]
pub(super) fn generation_from_certificates(
    target: u64,
    original: &ProposalValidationCertificate,
    previous: EtdagDigest,
    path: &[SimplifiedTimeoutCertificate],
) -> Result<CutRecoveryGeneration, String> {
    let terminal = path.last().ok_or("R3 timeout path is empty")?;
    generation_from_parts(
        target,
        original,
        previous,
        &terminal.context,
        &terminal.id().map_err(|e| e.to_string())?,
        terminal.highest_parent().map_err(|e| e.to_string())?,
        &path
            .iter()
            .map(|tc| tc.id().map_err(|e| e.to_string()))
            .collect::<Result<Vec<_>, _>>()?,
    )
}

fn generation_from_parts(
    target: u64,
    original: &ProposalValidationCertificate,
    previous: EtdagDigest,
    terminal: &synergy_posy::ConsensusObjectContext,
    timeout_id: &str,
    certified_parent: SimplifiedFinalityParent,
    ids: &[String],
) -> Result<CutRecoveryGeneration, String> {
    let original_id = original.id().map_err(|e| e.to_string())?;
    if original.context.height.checked_add(2) != Some(target)
        || terminal.height.checked_add(1) != Some(target)
    {
        return Err("R3 target differs from cutoff/timeout authority".into());
    }
    let original_root =
        EtdagDigest::from_domain_bytes("SYNERGY_ETDAG_CUTOFF_VC_V1", original_id.as_bytes());
    let proof = RecoveryProof {
        version: 1,
        original_validation_id: original_id,
        terminal_height: terminal.height,
        terminal_round: terminal.round,
        timeout_path_root: path_root_from_ids(ids)
            .map_err(|e| format!("R3 timeout path root: {e:?}"))?,
        certified_parent,
    };
    let cutoff = recovery_root(&original_root, target, &proof)
        .map_err(|e| format!("R3 cutoff root: {e:?}"))?;
    Ok(CutRecoveryGeneration {
        original_cutoff_context_root: original_root,
        previous_cutoff_context_root: previous,
        cutoff_context_root: cutoff,
        timeout_id: timeout_id.to_owned(),
        timeout_round: terminal.round,
        authorization: serde_json::to_vec(&proof).map_err(|e| e.to_string())?,
    })
}

fn path_root_from_ids(ids: &[String]) -> Result<EtdagDigest, EtdagError> {
    EtdagDigest::from_canonical("SYNERGY_POSY_R3_TIMEOUT_PATH_V1", &ids)
}

fn recovery_root(
    original: &EtdagDigest,
    target: u64,
    proof: &RecoveryProof,
) -> Result<EtdagDigest, EtdagError> {
    EtdagDigest::from_canonical(
        "SYNERGY_ETDAG_CUT_RECOVERY_R3_V1",
        &(
            original,
            target,
            &proof.timeout_path_root,
            &proof.certified_parent,
        ),
    )
}

const MAX_TIMEOUT_CACHE_RECORDS: usize = 4096;
// Existing native lease-proof bound, independent of cache eviction capacity.
const MAX_TIMEOUT_PATH_RECORDS: u64 = 4096;
const MAX_VALIDATION_CACHE_RECORDS: usize = 64;
const MAX_VERIFIED_CACHE_BYTES: usize = 64 * 1024 * 1024;

#[derive(Serialize)]
struct VerifiedTimeout {
    height: u64,
    round: u64,
    lease: u64,
    previous_tc_id: Option<String>,
    id: String,
    native_proof_root: EtdagDigest,
    parent: SimplifiedFinalityParent,
    has_carry: bool,
    parent_execution_roots: BTreeMap<String, String>,
    #[serde(skip)]
    bytes: usize,
}

impl VerifiedTimeout {
    // Only native-store-verified immutable originals may reach this constructor.
    fn from_verified(certificate: SimplifiedTimeoutCertificate) -> Result<Self, String> {
        let native_proof_root = EtdagDigest::from_domain_bytes(
            "SYNERGY_POSY_R3_VERIFIED_NATIVE_TC_V1",
            &serde_json::to_vec(&certificate).map_err(|e| e.to_string())?,
        );
        let id = certificate.id().map_err(|e| e.to_string())?;
        let parent = certificate.highest_parent().map_err(|e| e.to_string())?;
        let has_carry = certificate
            .mandatory_carry_candidate()
            .map_err(|e| e.to_string())?
            .is_some();
        let parent_execution_roots = certificate
            .highest_qc_proofs
            .iter()
            .map(|qc| {
                Ok((
                    qc.id().map_err(|e| e.to_string())?,
                    qc.protected_execution_root.clone(),
                ))
            })
            .collect::<Result<BTreeMap<_, _>, String>>()?;
        let mut summary = Self {
            height: certificate.context.height,
            round: certificate.context.round,
            lease: certificate.lease_index,
            previous_tc_id: certificate.previous_tc_id,
            id,
            native_proof_root,
            parent,
            has_carry,
            parent_execution_roots,
            bytes: 0,
        };
        summary.charge_bytes()?;
        Ok(summary)
    }

    fn charge_bytes(&mut self) -> Result<(), String> {
        // Original signatures remain in the immutable store. Charge the retained
        // authenticated summary, not a discarded 100 KiB signature bundle.
        self.bytes = serde_json::to_vec(self).map_err(|e| e.to_string())?.len()
            + std::mem::size_of::<Self>();
        Ok(())
    }
}

#[derive(Default)]
struct TimeoutCache {
    lease: Option<u64>,
    bytes: usize,
    certificates: BTreeMap<(u64, u64), Arc<VerifiedTimeout>>,
    identities: BTreeMap<String, (u64, u64)>,
}

impl TimeoutCache {
    fn select_lease(&mut self, lease: u64) {
        if self.lease != Some(lease) {
            self.certificates.clear();
            self.identities.clear();
            self.bytes = 0;
            self.lease = Some(lease);
        }
    }

    fn insert(&mut self, certificate: Arc<VerifiedTimeout>) {
        self.insert_with_budget(certificate, MAX_VERIFIED_CACHE_BYTES);
    }

    fn get(&self, height: u64, round: u64, identity: Option<&str>) -> Option<Arc<VerifiedTimeout>> {
        let slot = if let Some(id) = identity {
            self.identities.get(id).copied()
        } else {
            Some((height, round))
        }?;
        self.certificates.get(&slot).cloned()
    }

    fn insert_with_budget(&mut self, certificate: Arc<VerifiedTimeout>, byte_budget: usize) {
        let slot = (certificate.height, certificate.round);
        self.select_lease(certificate.lease);
        if self.certificates.contains_key(&slot) || certificate.bytes > byte_budget {
            return;
        }
        while self.certificates.len() >= MAX_TIMEOUT_CACHE_RECORDS
            || self.bytes > byte_budget - certificate.bytes
        {
            let Some((_, oldest)) = self.certificates.pop_first() else {
                break;
            };
            self.bytes -= oldest.bytes;
            self.identities.remove(&oldest.id);
        }
        self.bytes += certificate.bytes;
        self.identities.insert(certificate.id.clone(), slot);
        self.certificates.insert(slot, certificate);
    }
}

/// One verified round-zero ancestry, shared across successive recovery prefixes.
/// IDs are small; signatures stay in the immutable native store. The V1 path
/// root still hashes the exact original canonical ID array, including its length.
#[derive(Default)]
struct VerifiedPath {
    lease: Option<u64>,
    entries: Vec<PathEntry>,
}
struct PathEntry {
    id: String,
    height: u64,
    maximum_carry_height: Option<u64>,
}
impl VerifiedPath {
    fn select_lease(&mut self, lease: u64) {
        if self.lease != Some(lease) {
            self.entries.clear();
            self.lease = Some(lease);
        }
    }
    fn prefix(&self, round: u64, id: &str, height: u64) -> Option<&PathEntry> {
        self.entries
            .get(round as usize)
            .filter(|entry| entry.id == id && entry.height <= height)
    }
}

struct VerifiedValidation {
    certificate: ProposalValidationCertificate,
    id: String,
    cutoff: EtdagDigest,
    bytes: usize,
}

#[derive(Default)]
struct ValidationCache {
    bytes: usize,
    certificates: BTreeMap<u64, Arc<VerifiedValidation>>,
}

/// Disk bytes are references to immutable PoSy evidence, never authority by
/// themselves. Cache only certificates already verified by the native store.
pub(super) struct CutRecoveryVerifier {
    pub authority: Arc<VerifiedAuthority>,
    consensus_root: PathBuf,
    timeouts: Mutex<TimeoutCache>,
    validations: Mutex<ValidationCache>,
    path: Mutex<VerifiedPath>,
}
impl CutRecoveryVerifier {
    pub fn new(authority: Arc<VerifiedAuthority>, consensus_root: PathBuf) -> Self {
        Self {
            authority,
            consensus_root,
            timeouts: Mutex::new(TimeoutCache::default()),
            validations: Mutex::new(ValidationCache::default()),
            path: Mutex::new(VerifiedPath::default()),
        }
    }

    fn original_validation(&self, height: u64) -> Result<Arc<VerifiedValidation>, String> {
        if let Some(original) = self
            .validations
            .lock()
            .map_err(|_| "R3 validation cache poisoned")?
            .certificates
            .get(&height)
            .cloned()
        {
            return Ok(original);
        }
        let authority = self.authority.as_ref();
        let delivery = ProposalDelivery::open(
            &self.consensus_root,
            &authority.epoch,
            &authority.registry,
            authority,
        )
        .map_err(|e| e.to_string())?;
        let certificate = delivery
            .stored_validation(height, &authority.epoch, &authority.registry, authority)
            .map_err(|e| e.to_string())?
            .ok_or("R3 original VC is missing")?;
        let bytes = serde_json::to_vec(&certificate)
            .map_err(|e| e.to_string())?
            .len();
        let id = certificate.id().map_err(|e| e.to_string())?;
        let cutoff = EtdagDigest::from_domain_bytes("SYNERGY_ETDAG_CUTOFF_VC_V1", id.as_bytes());
        let original = Arc::new(VerifiedValidation {
            certificate,
            id,
            cutoff,
            bytes,
        });
        let mut cache = self
            .validations
            .lock()
            .map_err(|_| "R3 validation cache poisoned")?;
        if !cache.certificates.contains_key(&height) && bytes <= MAX_VERIFIED_CACHE_BYTES {
            while cache.certificates.len() >= MAX_VALIDATION_CACHE_RECORDS
                || cache.bytes > MAX_VERIFIED_CACHE_BYTES - bytes
            {
                let Some((_, oldest)) = cache.certificates.pop_first() else {
                    break;
                };
                cache.bytes -= oldest.bytes;
            }
            cache.bytes += bytes;
            cache.certificates.insert(height, Arc::clone(&original));
        }
        Ok(original)
    }

    fn verified_timeout(
        &self,
        store: &VerifiedTimeoutCertificateStore,
        height: u64,
        round: u64,
        identity: Option<&str>,
        lease: u64,
    ) -> Result<Arc<VerifiedTimeout>, String> {
        {
            let mut cache = self
                .timeouts
                .lock()
                .map_err(|_| "R3 verification cache poisoned")?;
            cache.select_lease(lease);
            // Identity only indexes an authenticated summary of one immutable
            // native-store object, including its exact proof digest and slot.
            // Incoming TC variants never populate this cache by their shared ID.
            if let Some(cached) = cache.get(height, round, identity) {
                return Ok(cached);
            }
        }
        let authority = self.authority.as_ref();
        let certificate = if let Some(id) = identity {
            store.get_verified_predecessor(
                height,
                round,
                id,
                &authority.epoch,
                &authority.registry,
                authority,
            )
        } else {
            store.get_verified(
                height,
                round,
                &authority.epoch,
                &authority.registry,
                authority,
            )
        }
        .map_err(|e| e.to_string())?
        .ok_or("R3 predecessor TC missing")?;
        let certificate = Arc::new(VerifiedTimeout::from_verified(certificate)?);
        self.timeouts
            .lock()
            .map_err(|_| "R3 verification cache poisoned")?
            .insert(Arc::clone(&certificate));
        Ok(certificate)
    }
    fn verify_generation(
        &self,
        context: &TargetAdmissionContextV3,
        generation: &CutRecoveryGeneration,
    ) -> Result<(), String> {
        if generation.authorization.len() > 1024 * 1024 {
            return Err("R3 proof exceeds bound".into());
        }
        let proof: RecoveryProof =
            serde_json::from_slice(&generation.authorization).map_err(|e| e.to_string())?;
        if proof.version != 1
            || proof.terminal_height.checked_add(1) != Some(context.target_height)
            || proof.terminal_round != generation.timeout_round
            || recovery_root(
                &generation.original_cutoff_context_root,
                context.target_height,
                &proof,
            )
            .map_err(|e| format!("R3 root: {e:?}"))?
                != generation.cutoff_context_root
        {
            return Err("R3 proof context/root mismatch".into());
        }
        let authority = self.authority.as_ref();
        context
            .validate()
            .map_err(|e| format!("R3 admission context: {e:?}"))?;
        if context.chain_id != authority.epoch.chain_id
            || context.network_id != authority.epoch.network_id
            || context.protocol_version != authority.epoch.protocol_version
            || context.epoch != authority.epoch.epoch
            || context.active_validator_set_root != authority.epoch.active_validator_set_root
            || context.validator_consensus_key_root != authority.epoch.validator_consensus_key_root
            || context.frozen_voting_weight_root != authority.epoch.frozen_voting_weight_root
        {
            return Err("R3 admission context differs from verified authority".into());
        }
        let original_height = context
            .target_height
            .checked_sub(2)
            .ok_or("R3 cutoff height underflow")?;
        let original = self.original_validation(original_height)?;
        if original.id != proof.original_validation_id
            || original.cutoff != generation.original_cutoff_context_root
        {
            return Err("R3 original cutoff does not match verified VC".into());
        }
        let store = VerifiedTimeoutCertificateStore::new(&self.consensus_root)
            .map_err(|e| e.to_string())?;
        let lease = authority
            .epoch
            .lease_index(proof.terminal_height)
            .map_err(|e| e.to_string())?;
        if proof.terminal_round >= MAX_TIMEOUT_PATH_RECORDS {
            return Err("R3 timeout path exceeds native bound".into());
        }
        let terminal = self.verified_timeout(
            &store,
            proof.terminal_height,
            proof.terminal_round,
            None,
            lease,
        )?;
        if terminal.id != generation.timeout_id
            || terminal.parent != proof.certified_parent
            || terminal.has_carry
        {
            return Err("R3 terminal identity/parent/carry mismatch".into());
        }
        match &proof.certified_parent {
            SimplifiedFinalityParent::QuorumCertificate {
                height,
                block_id,
                qc_id,
            } if *height == original_height
                && *block_id == original.certificate.candidate.block_id =>
            {
                let parent_root = terminal
                    .parent_execution_roots
                    .get(qc_id)
                    .ok_or("R3 cutoff parent QC proof missing")?;
                if parent_root != &original.certificate.candidate.protected_execution_root {
                    return Err("R3 cutoff parent protected execution mismatch".into());
                }
            }
            _ => return Err("R3 timeout parent differs from original cutoff candidate".into()),
        }
        let mut verified_path = self.path.lock().map_err(|_| "R3 path cache poisoned")?;
        verified_path.select_lease(lease);
        let mut expected = Some(generation.timeout_id.clone());
        let mut height = proof.terminal_height;
        let mut suffix = Vec::new();
        let mut prefix_length = 0;
        for round in (0..=proof.terminal_round).rev() {
            let id = expected.as_deref().ok_or("R3 predecessor path truncated")?;
            if let Some(prefix) = verified_path.prefix(round, id, height) {
                if prefix.maximum_carry_height == Some(proof.terminal_height) {
                    return Err("R3 predecessor cached prefix has mandatory carry".into());
                }
                prefix_length = round as usize + 1;
                expected = None;
                break;
            }
            let verified = self.verified_timeout(&store, height, round, Some(id), lease)?;
            if verified.id != id
                || verified.round != round
                || verified.height > height
                || verified.lease != lease
                || (verified.height == proof.terminal_height && verified.has_carry)
            {
                return Err("R3 predecessor slot/lease/carry mismatch".into());
            }
            height = verified.height;
            expected = verified.previous_tc_id.clone();
            suffix.push((verified.id.clone(), verified.height, verified.has_carry));
        }
        if expected.is_some() {
            return Err("R3 predecessor path does not begin at round zero".into());
        }
        let mut ids: Vec<&str> = verified_path.entries[..prefix_length]
            .iter()
            .map(|e| e.id.as_str())
            .collect();
        ids.extend(suffix.iter().rev().map(|e| e.0.as_str()));
        if EtdagDigest::from_canonical("SYNERGY_POSY_R3_TIMEOUT_PATH_V1", &ids)
            .map_err(|e| format!("R3 path root: {e:?}"))?
            != proof.timeout_path_root
        {
            return Err("R3 timeout path root mismatch".into());
        }
        drop(ids);
        // Publish only after the exact signed root has matched. A rejected
        // generation cannot install a partial ancestry or replace the good one.
        verified_path.entries.truncate(prefix_length);
        let mut maximum_carry_height = verified_path
            .entries
            .last()
            .and_then(|e| e.maximum_carry_height);
        for (id, height, has_carry) in suffix.into_iter().rev() {
            if has_carry {
                maximum_carry_height = maximum_carry_height.max(Some(height));
            }
            verified_path.entries.push(PathEntry {
                id,
                height,
                maximum_carry_height,
            });
        }
        Ok(())
    }
}
impl synergy_etdag::crypto::SignatureVerifier for CutRecoveryVerifier {
    fn verify(
        &self,
        validator: &str,
        key: &str,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), EtdagError> {
        synergy_etdag::crypto::SignatureVerifier::verify(
            self.authority.as_ref(),
            validator,
            key,
            message,
            signature,
        )
    }
}
impl synergy_etdag::reveal::RevealAuthorizationVerifier for CutRecoveryVerifier {
    fn verify_parent_commitment(
        &self,
        authorization: &synergy_etdag::ProtectedRevealAuthorization,
        evidence: &synergy_etdag::execution::ParentProposalRevealEvidence,
    ) -> Result<(), EtdagError> {
        synergy_etdag::reveal::RevealAuthorizationVerifier::verify_parent_commitment(
            self.authority.as_ref(),
            authorization,
            evidence,
        )
    }
}
impl ProtectedRecoveryVerifier for CutRecoveryVerifier {
    fn verify_cut_recovery_generation(
        &self,
        context: &TargetAdmissionContextV3,
        generation: &CutRecoveryGeneration,
    ) -> Result<(), EtdagError> {
        self.verify_generation(context, generation)
            .map_err(EtdagError::Governance)
    }
    fn verify_cut_recovery_batch_binding(
        &self,
        context: &TargetAdmissionContextV3,
        generation: &CutRecoveryGeneration,
        batch: Option<&synergy_etdag::DeterministicProtectedBatch>,
    ) -> Result<(), EtdagError> {
        let check = || -> Result<(), String> {
            let authority = self.authority.as_ref();
            let height = context
                .target_height
                .checked_sub(1)
                .ok_or("R3 proposer height underflow")?;
            let delivery = ProposalDelivery::open(
                &self.consensus_root,
                &authority.epoch,
                &authority.registry,
                authority,
            )
            .map_err(|e| e.to_string())?;
            let vc = delivery
                .stored_validation(height, &authority.epoch, &authority.registry, authority)
                .map_err(|e| e.to_string())?;
            let ready = delivery
                .stored_ready_envelope(height, &authority.epoch, &authority.registry, authority)
                .map_err(|e| e.to_string())?;
            let qcs = synergy_posy::VerifiedQuorumCertificateStore::new(&self.consensus_root)
                .map_err(|e| e.to_string())?;
            let qc = qcs
                .get_verified(height, &authority.epoch, &authority.registry, authority)
                .map_err(|e| e.to_string())?;
            let data_root = self
                .consensus_root
                .parent()
                .and_then(|p| p.parent())
                .ok_or("R3 consensus layout mismatch")?;
            let candidates = synergy_execution::CandidateStore::new(
                data_root.join("blocks/execution-candidates"),
            )?;
            let candidate = candidates.get_bounded(height, 8 * 1024 * 1024)?;
            let bound = vc.is_some() || ready.is_some() || qc.is_some() || candidate.is_some();
            if !bound {
                return Ok(());
            }
            let selected = batch
                .ok_or("R3 uncommitted generation conflicts with retained proposal/certificate")?;
            let candidate =
                candidate.ok_or("R3 certified replacement lacks retained candidate material")?;
            if candidate.height != height
                || candidate
                    .protected_material
                    .as_legacy()
                    .ok_or("processing material cannot authorize legacy cut recovery")?
                    .next_batch_root
                    != selected.protected_batch_root
            {
                return Err("R3 retained proposal binds another protected batch".into());
            }
            if let Some(vc) = &vc {
                if vc.context.round <= generation.timeout_round
                    || vc.candidate.block_id != candidate.block_id
                    || vc.candidate.protected_execution_root != candidate.protected_execution_root
                {
                    return Err("R3 replacement differs from retained validation authority".into());
                }
            }
            if let Some(ready) = &ready {
                if ready.statement.context.round <= generation.timeout_round
                    || ready.statement.candidate.block_id != candidate.block_id
                    || ready.statement.candidate.protected_execution_root
                        != candidate.protected_execution_root
                {
                    return Err("R3 replacement differs from retained READY authority".into());
                }
            }
            if let Some(qc) = &qc {
                if qc.context.round <= generation.timeout_round
                    || qc.block_id != candidate.block_id
                    || qc.protected_execution_root != candidate.protected_execution_root
                {
                    return Err("R3 replacement differs from retained QC authority".into());
                }
            }
            Ok(())
        };
        check().map_err(EtdagError::Governance)
    }

    fn verify_nonempty_prepared(
        &self,
        context: &TargetAdmissionContextV3,
        prepared: &synergy_etdag::execution::PreparedProtectedBatch,
        transcripts: &BTreeMap<EtdagDigest, synergy_etdag::reveal::RevealTranscript>,
        envelopes: &BTreeMap<EtdagDigest, synergy_etdag::EncryptedTransactionEnvelope>,
    ) -> Result<(), EtdagError> {
        self.authority
            .verify_nonempty_prepared(context, prepared, transcripts, envelopes)
    }
}

#[cfg(test)]
mod cache_tests {
    use super::*;

    // Cache-budget fixtures only. Production construction remains exclusively
    // after native-store signature/quorum verification; genuine R3 tests cover it.
    fn summary(round: u64) -> Arc<VerifiedTimeout> {
        let qc_id = "a".repeat(64);
        let mut summary = VerifiedTimeout {
            height: 27_242,
            round,
            lease: 3_405,
            previous_tc_id: round.checked_sub(1).map(|r| format!("{r:064x}")),
            id: format!("{round:064x}"),
            native_proof_root: EtdagDigest::from_domain_bytes(
                "qualified-native-original",
                &round.to_le_bytes(),
            ),
            parent: SimplifiedFinalityParent::QuorumCertificate {
                height: 27_241,
                block_id: "b".repeat(64),
                qc_id: qc_id.clone(),
            },
            has_carry: false,
            parent_execution_roots: BTreeMap::from([(qc_id, "c".repeat(64))]),
            bytes: 0,
        };
        summary.charge_bytes().unwrap();
        Arc::new(summary)
    }

    #[test]
    fn replay_full_4096_recovery_prefixes_loads_each_original_once_under_eight_mib() {
        const BYTE_BUDGET: usize = 8 * 1024 * 1024;
        const ORIGINAL_BYTES: usize = 100 * 1024;
        const GENERATIONS: u64 = MAX_TIMEOUT_PATH_RECORDS;
        let mut cache = TimeoutCache::default();
        let mut store_loads = 0;
        for terminal_round in 0..GENERATIONS {
            let mut expected = Some(format!("{terminal_round:064x}"));
            for round in (0..=terminal_round).rev() {
                let id = expected.as_deref().unwrap();
                let entry = cache.get(27_242, round, Some(id)).unwrap_or_else(|| {
                    // Simulate the sole cache-miss native-store load boundary.
                    store_loads += 1;
                    let loaded = summary(round);
                    cache.insert_with_budget(Arc::clone(&loaded), BYTE_BUDGET);
                    loaded
                });
                assert_eq!(entry.round, round);
                assert_eq!(entry.id, id);
                assert!(!entry.has_carry);
                expected = entry.previous_tc_id.clone();
            }
            assert!(expected.is_none());
            assert!(cache.bytes <= BYTE_BUDGET);
        }
        assert_eq!(store_loads, GENERATIONS);
        assert_eq!(cache.certificates.len(), GENERATIONS as usize);
        assert!(GENERATIONS as usize * ORIGINAL_BYTES > MAX_VERIFIED_CACHE_BYTES);
    }

    #[test]
    fn verified_path_prefix_requires_exact_identity_height_and_lease() {
        let mut path = VerifiedPath::default();
        path.select_lease(3405);
        path.entries.push(PathEntry {
            id: "first".into(),
            height: 27_240,
            maximum_carry_height: Some(27_240),
        });
        assert!(path.prefix(0, "first", 27_241).is_some());
        assert!(path.prefix(0, "variant", 27_241).is_none());
        assert!(path.prefix(0, "first", 27_239).is_none());
        assert!(path.prefix(1, "first", 27_241).is_none());
        path.select_lease(3406);
        assert!(path.entries.is_empty());
    }

    #[test]
    fn summary_eviction_and_lease_replacement_keep_slot_index_and_bytes_bounded() {
        let first = summary(0);
        let budget = first.bytes * 2;
        let mut cache = TimeoutCache::default();
        for round in 0..4 {
            cache.insert_with_budget(summary(round), budget);
            assert!(cache.bytes <= budget);
            assert_eq!(cache.certificates.len(), cache.identities.len());
        }
        assert!(cache.get(27_242, 0, Some(&first.id)).is_none());
        assert!(cache.get(27_242, 3, None).is_some());
        cache.select_lease(3_406);
        assert!(cache.certificates.is_empty());
        assert!(cache.identities.is_empty());
        assert_eq!(cache.bytes, 0);
    }
}
