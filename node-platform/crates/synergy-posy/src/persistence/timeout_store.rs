use std::{fs, path::PathBuf};

const MAX_LEASE_CERTIFICATES: usize = 4_096;
const MAX_LEASE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_CERTIFICATE_RECORD_BYTES: u64 = 16 * 1024 * 1024;

use crate::{
    ConsensusSignatureVerifier, FrozenValidatorRegistry, PosyError, PosyResult,
    SimplifiedEpochContext, SimplifiedTimeoutCertificate,
};

use super::CanonicalObjectStore;

/// Durable, independently reverified timeout certificates for exact
/// height/round recovery. A certificate never grants membership or finality.
#[derive(Debug)]
pub struct VerifiedTimeoutCertificateStore {
    objects: CanonicalObjectStore<SimplifiedTimeoutCertificate>,
    root: PathBuf,
    legacy_generation: std::sync::Mutex<Option<std::time::SystemTime>>,
}

/// A bounded transport index cursor. Filenames are untrusted locators only;
/// each selected original still requires `get_verified` before use as evidence.
#[derive(Debug)]
pub struct TimeoutSlotCursor {
    entries: Option<fs::ReadDir>,
    archive: super::evidence_store::EvidenceStore,
    after: String,
    archive_complete: bool,
}
impl TimeoutSlotCursor {
    pub fn is_complete(&self) -> bool {
        self.entries.is_none() && self.archive_complete
    }

    /// Inspect at most 64 directory entries per call, including ignored files.
    /// Directory order is not proof order; callers sort a bounded working set.
    pub fn next_slots(&mut self, maximum_entries: usize) -> PosyResult<Vec<(u64, u64)>> {
        if maximum_entries == 0 || maximum_entries > 64 {
            return Err(PosyError::invalid(
                "timeout cursor batch must be between 1 and 64",
            ));
        }
        let mut slots = Vec::new();
        let mut inspected = 0;
        for _ in 0..maximum_entries {
            let Some(entries) = self.entries.as_mut() else {
                break;
            };
            let Some(entry) = entries.next() else {
                self.entries = None;
                break;
            };
            inspected += 1;
            let entry = entry.map_err(read_error)?;
            let kind = entry.file_type().map_err(read_error)?;
            if kind.is_symlink() || !kind.is_file() {
                return Err(PosyError::invalid(
                    "timeout cursor encountered a non-regular record",
                ));
            }
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if name.starts_with("._") {
                continue;
            }
            // Noncanonical names can never address a canonical object and are
            // ignored by transport indexing, never admitted as signed evidence.
            if let Ok(slot) = parse_record_name(name) {
                slots.push(slot);
            }
        }
        // Spend at most the remaining per-call budget on indexed archive rows.
        if inspected < maximum_entries && self.entries.is_none() && !self.archive_complete {
            let remaining = maximum_entries - inspected;
            let keys = self
                .archive
                .keys_after("verified-timeouts/", &self.after, remaining)?;
            self.archive_complete = keys.len() < remaining;
            for (key, _) in keys {
                self.after = key.clone();
                let name = key
                    .strip_prefix("verified-timeouts/")
                    .ok_or_else(|| PosyError::invalid("invalid timeout index key"))?;
                let slot = parse_record_name(name)?;
                // Legacy originals already traversed above need no second send.
                // No unbounded seen-set is retained by the transport cursor.
                if !slots.contains(&slot) {
                    slots.push(slot);
                }
            }
        }
        Ok(slots)
    }
}

impl VerifiedTimeoutCertificateStore {
    pub fn new(root: impl Into<PathBuf>) -> PosyResult<Self> {
        let root = root.into();
        let objects = CanonicalObjectStore::new(&root, "verified-timeouts")?;
        let directory = root.join("verified-timeouts");
        if !directory.exists() {
            fs::create_dir(&directory).map_err(read_error)?;
        }
        Ok(Self {
            objects,
            root,
            legacy_generation: std::sync::Mutex::new(None),
        })
    }

    pub fn slot_cursor(&self) -> PosyResult<TimeoutSlotCursor> {
        let metadata = fs::symlink_metadata(&self.root).map_err(read_error)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(PosyError::invalid(
                "timeout store root is not a real directory",
            ));
        }
        let directory = self.root.join("verified-timeouts");
        let metadata = match fs::symlink_metadata(&directory) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return self.archive_cursor(None);
            }
            Err(error) => return Err(read_error(error)),
        };
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(PosyError::invalid(
                "timeout namespace is not a real directory",
            ));
        }
        let entries = if fs::read_dir(&directory)
            .map_err(read_error)?
            .next()
            .is_none()
        {
            None
        } else {
            Some(fs::read_dir(directory).map_err(read_error)?)
        };
        self.archive_cursor(entries)
    }

    fn archive_cursor(&self, entries: Option<fs::ReadDir>) -> PosyResult<TimeoutSlotCursor> {
        let archive = self.objects.evidence();
        let archive_complete = archive.keys_after("verified-timeouts/", "", 1)?.is_empty();
        Ok(TimeoutSlotCursor {
            entries,
            archive,
            after: String::new(),
            archive_complete,
        })
    }

    /// Select bounded slot metadata without retaining any native signatures.
    /// The record byte limit applies individually: total disk bytes do not
    /// consume RAM when the caller authenticates one original at a time.
    pub fn get_slots_for_lease_before(
        &self,
        height: u64,
        before_height: u64,
        epoch: &SimplifiedEpochContext,
        validators: &FrozenValidatorRegistry,
    ) -> PosyResult<Vec<(u64, u64)>> {
        self.slots_for_lease_selected(height, Some(before_height), epoch, validators, false)
    }

    pub fn put_verified(
        &self,
        certificate: &SimplifiedTimeoutCertificate,
        epoch: &SimplifiedEpochContext,
        validators: &FrozenValidatorRegistry,
        verifier: &impl ConsensusSignatureVerifier,
    ) -> PosyResult<bool> {
        certificate.verify(epoch, validators, verifier)?;
        let key = key(certificate.context.height, certificate.context.round);
        if let Some(existing) = self.get_verified(
            certificate.context.height,
            certificate.context.round,
            epoch,
            validators,
            verifier,
        )? {
            return if existing.id()? == certificate.id()? {
                Ok(false)
            } else {
                Err(PosyError::Conflict(
                    "different timeout closure already stored at one height/round".into(),
                ))
            };
        }
        self.objects.put_once(&key, certificate)
    }

    /// Reloads the immutable original records needed to reconstruct one lease.
    /// Names are only an index: canonical integrity, slot binding, frozen authority,
    /// signatures and quorum are independently checked before returning any proof.
    /// This does not itself admit a TC or establish its predecessor closure.
    pub fn get_verified_for_lease(
        &self,
        height: u64,
        epoch: &SimplifiedEpochContext,
        validators: &FrozenValidatorRegistry,
        verifier: &impl ConsensusSignatureVerifier,
    ) -> PosyResult<Vec<SimplifiedTimeoutCertificate>> {
        self.get_verified_for_lease_selected(height, None, epoch, validators, verifier)
    }

    /// Select relevant historical slots before charging the bounded load budget.
    /// Active-height records are replayed separately through exact-slot reads.
    pub fn get_verified_for_lease_before(
        &self,
        height: u64,
        before_height: u64,
        epoch: &SimplifiedEpochContext,
        validators: &FrozenValidatorRegistry,
        verifier: &impl ConsensusSignatureVerifier,
    ) -> PosyResult<Vec<SimplifiedTimeoutCertificate>> {
        self.get_verified_for_lease_selected(
            height,
            Some(before_height),
            epoch,
            validators,
            verifier,
        )
    }

    fn get_verified_for_lease_selected(
        &self,
        height: u64,
        before_height: Option<u64>,
        epoch: &SimplifiedEpochContext,
        validators: &FrozenValidatorRegistry,
        verifier: &impl ConsensusSignatureVerifier,
    ) -> PosyResult<Vec<SimplifiedTimeoutCertificate>> {
        let slots =
            self.slots_for_lease_selected(height, before_height, epoch, validators, true)?;
        let mut certificates = Vec::with_capacity(slots.len());
        let mut decoded_bytes = 0u64;
        for (record_height, round) in slots {
            let certificate = self
                .get_verified(record_height, round, epoch, validators, verifier)?
                .ok_or_else(|| {
                    PosyError::NotReady("enumerated timeout record disappeared".into())
                })?;
            // Also bound the values actually loaded if a concurrent writer changes
            // record sizes after enumeration. CanonicalObjectStore bounds each read.
            let actual_bytes = serde_json::to_vec(&certificate)
                .map_err(|error| {
                    PosyError::invalid(format!("encode timeout certificate: {error}"))
                })?
                .len() as u64;
            charge_record_budget(certificates.len(), &mut decoded_bytes, actual_bytes)?;
            certificates.push(certificate);
        }
        Ok(certificates)
    }

    fn slots_for_lease_selected(
        &self,
        height: u64,
        before_height: Option<u64>,
        epoch: &SimplifiedEpochContext,
        validators: &FrozenValidatorRegistry,
        charge_payload_budget: bool,
    ) -> PosyResult<Vec<(u64, u64)>> {
        epoch.validate_against(validators)?;
        let lease = epoch.lease_index(height)?;
        let root_metadata = fs::symlink_metadata(&self.root).map_err(read_error)?;
        if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
            return Err(PosyError::invalid(
                "timeout store root is not a real directory",
            ));
        }
        let directory = self.root.join("verified-timeouts");
        let metadata = match fs::symlink_metadata(&directory) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(read_error(error)),
        };
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(PosyError::invalid(
                "timeout namespace is not a real directory",
            ));
        }
        let modified = metadata.modified().map_err(read_error)?;
        let mut generation = self
            .legacy_generation
            .lock()
            .map_err(|_| PosyError::NotReady("poisoned legacy timeout index".into()))?;
        let archive = self.objects.evidence();
        if generation.as_ref() != Some(&modified) {
            archive.index_legacy_timeouts(&directory)?;
            *generation = Some(modified);
        }
        drop(generation);
        let first = epoch
            .epoch_start_height
            .checked_add(
                lease
                    .checked_mul(epoch.leader_lease_blocks)
                    .ok_or_else(|| PosyError::invalid("timeout lease overflow"))?,
            )
            .ok_or_else(|| PosyError::invalid("timeout lease overflow"))?;
        let mut last = first.saturating_add(epoch.leader_lease_blocks.saturating_sub(1));
        if let Some(before) = before_height {
            last = last.min(before.saturating_sub(1));
        }
        if last < first {
            return Ok(Vec::new());
        }
        let mut slots = Vec::new();
        let mut total_bytes = 0;
        for (key, bytes) in archive.timeout_keys(first, last, MAX_LEASE_CERTIFICATES + 1)? {
            let name = key
                .strip_prefix("verified-timeouts/")
                .ok_or_else(|| PosyError::invalid("invalid indexed timeout key"))?;
            let (record_height, round) = parse_record_name(name)?;
            if !epoch.contains_height(record_height) {
                continue;
            }
            if charge_payload_budget {
                charge_record_budget(slots.len(), &mut total_bytes, bytes)?;
            } else if slots.len() >= MAX_LEASE_CERTIFICATES || bytes > MAX_CERTIFICATE_RECORD_BYTES
            {
                return Err(PosyError::ResourcePressure(
                    "timeout lease slot index resource limit exceeded".into(),
                ));
            }
            slots.push((record_height, round));
        }
        slots.sort_unstable_by_key(|&(record_height, round)| (round, record_height));
        Ok(slots)
    }

    /// Resolve one ancestry ID through bounded original slots, never bulk history.
    pub fn get_verified_predecessor(
        &self,
        height: u64,
        round: u64,
        expected_id: &str,
        epoch: &SimplifiedEpochContext,
        validators: &FrozenValidatorRegistry,
        verifier: &impl ConsensusSignatureVerifier,
    ) -> PosyResult<Option<SimplifiedTimeoutCertificate>> {
        let lease = epoch.lease_index(height)?;
        let first = epoch
            .epoch_start_height
            .checked_add(
                lease
                    .checked_mul(epoch.leader_lease_blocks)
                    .ok_or_else(|| PosyError::invalid("timeout lease overflow"))?,
            )
            .ok_or_else(|| PosyError::invalid("timeout lease overflow"))?;
        for candidate in (first..=height).rev() {
            if let Some(tc) = self.get_verified(candidate, round, epoch, validators, verifier)? {
                if tc.id()? == expected_id {
                    return Ok(Some(tc));
                }
            }
        }
        Ok(None)
    }

    pub fn get_verified(
        &self,
        height: u64,
        round: u64,
        epoch: &SimplifiedEpochContext,
        validators: &FrozenValidatorRegistry,
        verifier: &impl ConsensusSignatureVerifier,
    ) -> PosyResult<Option<SimplifiedTimeoutCertificate>> {
        let Some(certificate) = self.objects.get(&key(height, round))? else {
            return Ok(None);
        };
        if certificate.context.height != height || certificate.context.round != round {
            return Err(PosyError::Conflict(
                "stored timeout certificate differs from its recovery slot".into(),
            ));
        }
        certificate.verify(epoch, validators, verifier)?;
        Ok(Some(certificate))
    }
}

fn key(height: u64, round: u64) -> String {
    format!("h{height}r{round}")
}

fn parse_record_name(name: &str) -> PosyResult<(u64, u64)> {
    let (height, round) = name
        .strip_prefix('h')
        .and_then(|name| name.strip_suffix(".json"))
        .and_then(|name| name.split_once('r'))
        .ok_or_else(|| PosyError::invalid("invalid timeout record filename"))?;
    let height = height
        .parse::<u64>()
        .map_err(|_| PosyError::invalid("invalid timeout record height"))?;
    let round = round
        .parse::<u64>()
        .map_err(|_| PosyError::invalid("invalid timeout record round"))?;
    if name != format!("{}.json", key(height, round)) {
        return Err(PosyError::invalid("noncanonical timeout record filename"));
    }
    Ok((height, round))
}

fn charge_record_budget(count: usize, bytes: &mut u64, record_bytes: u64) -> PosyResult<()> {
    let total = bytes
        .checked_add(record_bytes)
        .ok_or_else(|| PosyError::NotReady("timeout lease byte count overflow".into()))?;
    if count >= MAX_LEASE_CERTIFICATES
        || record_bytes > MAX_CERTIFICATE_RECORD_BYTES
        || total > MAX_LEASE_BYTES
    {
        return Err(PosyError::NotReady(
            "timeout lease recovery evidence limit exceeded".into(),
        ));
    }
    *bytes = total;
    Ok(())
}

fn read_error(error: std::io::Error) -> PosyError {
    PosyError::NotReady(format!("enumerate timeout certificates: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ConsensusObjectContext, SimplifiedFinalityParent, TimeoutVote, ValidatorRecord,
        ValidatorStatus,
    };

    struct AcceptSignatures;
    impl ConsensusSignatureVerifier for AcceptSignatures {
        fn verify_consensus_signature(
            &self,
            _: &str,
            _: &[u8],
            _: &ValidatorRecord,
            _: &str,
            _: u64,
            _: &[u8],
        ) -> PosyResult<()> {
            Ok(())
        }
    }

    struct RejectSignatures;
    impl ConsensusSignatureVerifier for RejectSignatures {
        fn verify_consensus_signature(
            &self,
            _: &str,
            _: &[u8],
            _: &ValidatorRecord,
            _: &str,
            _: u64,
            _: &[u8],
        ) -> PosyResult<()> {
            Err(PosyError::invalid("signature rejected by test verifier"))
        }
    }

    fn fixture() -> (
        PathBuf,
        VerifiedTimeoutCertificateStore,
        SimplifiedEpochContext,
        FrozenValidatorRegistry,
        SimplifiedTimeoutCertificate,
    ) {
        static NEXT_FIXTURE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let unique = NEXT_FIXTURE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "posy-timeout-enumeration-{}-{}-{}",
            unique,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let validators = FrozenValidatorRegistry::new(
            7,
            (0..5)
                .map(|i| ValidatorRecord {
                    validator_id: format!("validator-{i}"),
                    consensus_key_id: format!("key-{i}"),
                    frozen_voting_weight: 1,
                    status: ValidatorStatus::Active,
                })
                .collect(),
        )
        .unwrap();
        let epoch = SimplifiedEpochContext::from_frozen_registry(
            1266,
            "testnet-v3".into(),
            7,
            1,
            20,
            "a".repeat(64),
            "b".repeat(64),
            &validators,
        )
        .unwrap();
        let tc = SimplifiedTimeoutCertificate::from_votes(
            (0..4)
                .map(|i| TimeoutVote {
                    context: ConsensusObjectContext::for_height(&epoch, 1, 0).unwrap(),
                    lease_index: 0,
                    timed_out_proposer: epoch.authorized_proposer(1, 0).unwrap().into(),
                    highest_parent: SimplifiedFinalityParent::Genesis {
                        genesis_hash: "c".repeat(64),
                        block_id: "genesis".into(),
                        reference_id: "d".repeat(64),
                    },
                    previous_tc_id: None,
                    last_voted_candidate: None,
                    validator_id: format!("validator-{i}"),
                    key_id: format!("key-{i}"),
                    signature: vec![1],
                })
                .collect(),
        )
        .unwrap();
        let store = VerifiedTimeoutCertificateStore::new(&root).unwrap();
        (root, store, epoch, validators, tc)
    }

    #[test]
    fn timeout_slot_cursor_bounds_each_scan_and_never_authenticates_names() {
        let (root, store, epoch, validators, tc) = fixture();
        assert!(store.slot_cursor().unwrap().is_complete());
        store
            .put_verified(&tc, &epoch, &validators, &AcceptSignatures)
            .unwrap();
        let directory = root.join("verified-timeouts");
        for index in 0..130 {
            fs::write(directory.join(format!("._ignored-{index}")), b"sidecar").unwrap();
        }
        fs::write(directory.join("h01r0.json"), b"noncanonical").unwrap();
        fs::write(directory.join("h1r1.json"), b"not authenticated").unwrap();
        let mut cursor = store.slot_cursor().unwrap();
        assert!(cursor.next_slots(0).is_err());
        assert!(cursor.next_slots(65).is_err());
        let mut slots = Vec::new();
        let mut polls = 0;
        while !cursor.is_complete() {
            let next = cursor.next_slots(64).unwrap();
            assert!(next.len() <= 64);
            slots.extend(next);
            polls += 1;
            assert!(polls <= 4);
        }
        assert!(polls >= 3); // Ignored entries consume the per-poll work bound.
        slots.sort_unstable();
        assert_eq!(slots, vec![(1, 0), (1, 1)]);
        assert!(store
            .get_verified(1, 1, &epoch, &validators, &AcceptSignatures)
            .is_err());
        assert!(cursor.next_slots(64).unwrap().is_empty());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn lease_slot_metadata_does_not_charge_unloaded_original_payloads_to_ram() {
        let (root, store, epoch, validators, tc) = fixture();
        store
            .put_verified(&tc, &epoch, &validators, &AcceptSignatures)
            .unwrap();
        for round in 1..=5 {
            let file =
                fs::File::create(root.join(format!("verified-timeouts/h1r{round}.json"))).unwrap();
            file.set_len(15 * 1024 * 1024).unwrap();
        }
        assert_eq!(
            store
                .get_slots_for_lease_before(2, 2, &epoch, &validators)
                .unwrap(),
            vec![(1, 0), (1, 1), (1, 2), (1, 3), (1, 4), (1, 5)]
        );
        // The old aggregate payload API still fails closed at its own byte cap.
        assert!(store
            .get_verified_for_lease_before(2, 2, &epoch, &validators, &AcceptSignatures)
            .is_err());
        // Metadata never grants authority to the intentionally corrupt files.
        assert!(store
            .get_verified(1, 1, &epoch, &validators, &AcceptSignatures)
            .is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn timeout_transport_cursor_rejects_symlinks_and_namespace_escape() {
        use std::os::unix::fs::symlink;
        let (root, store, epoch, validators, tc) = fixture();
        store
            .put_verified(&tc, &epoch, &validators, &AcceptSignatures)
            .unwrap();
        symlink("h1r0.json", root.join("verified-timeouts/h1r1.json")).unwrap();
        let mut cursor = store.slot_cursor().unwrap();
        assert!(cursor.next_slots(64).is_err());
        fs::remove_file(root.join("verified-timeouts/h1r1.json")).unwrap();
        fs::rename(root.join("verified-timeouts"), root.join("originals")).unwrap();
        symlink("originals", root.join("verified-timeouts")).unwrap();
        assert!(store.slot_cursor().is_err());
        fs::remove_file(root.join("verified-timeouts")).unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn timeout_lease_enumeration_reverifies_and_orders_original_records() {
        let (root, store, epoch, validators, tc) = fixture();
        assert!(store
            .get_verified_for_lease(1, &epoch, &validators, &AcceptSignatures)
            .unwrap()
            .is_empty());
        let mut later = tc.clone();
        later.context.round = 1;
        later.previous_tc_id = Some(tc.id().unwrap());
        later.timed_out_proposer = epoch.authorized_proposer(1, 1).unwrap().into();
        for report in &mut later.reports {
            report.context = later.context.clone();
            report.previous_tc_id = later.previous_tc_id.clone();
            report.timed_out_proposer = later.timed_out_proposer.clone();
        }
        store
            .put_verified(&later, &epoch, &validators, &AcceptSignatures)
            .unwrap();
        store
            .put_verified(&tc, &epoch, &validators, &AcceptSignatures)
            .unwrap();
        assert!(store
            .get_verified_for_lease(4, &epoch, &validators, &RejectSignatures)
            .is_err());
        let mut wrong_epoch = epoch.clone();
        wrong_epoch.chain_id += 1;
        assert!(store
            .get_verified_for_lease(4, &wrong_epoch, &validators, &AcceptSignatures)
            .is_err());
        assert_eq!(
            store
                .get_verified_for_lease(4, &epoch, &validators, &AcceptSignatures)
                .unwrap(),
            vec![tc, later]
        );
        assert!(store
            .get_verified_for_lease(11, &epoch, &validators, &AcceptSignatures)
            .unwrap()
            .is_empty());
        // Renaming an intact canonical record must not change its verified slot.
        // Copy the exact archived original into a legacy fixture, then rename
        // its locator. The signed height remains one and must be rejected at two.
        let original = store
            .objects
            .evidence()
            .get("verified-timeouts/h1r0.json")
            .unwrap()
            .unwrap();
        fs::write(root.join("verified-timeouts/h1r0.json"), original).unwrap();
        fs::rename(
            root.join("verified-timeouts/h1r0.json"),
            root.join("verified-timeouts/h2r0.json"),
        )
        .unwrap();
        assert!(store
            .get_verified_for_lease(4, &epoch, &validators, &AcceptSignatures)
            .is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn exact_timeout_predecessor_ignores_unrelated_tail_and_rejects_needed_invalid_proof() {
        let (root, store, epoch, validators, tc) = fixture();
        store
            .put_verified(&tc, &epoch, &validators, &AcceptSignatures)
            .unwrap();
        let id = tc.id().unwrap();
        let tail = fs::File::create(root.join("verified-timeouts/h1r99.json")).unwrap();
        tail.set_len(MAX_LEASE_BYTES + 1).unwrap();
        assert_eq!(
            store
                .get_verified_predecessor(2, 0, &id, &epoch, &validators, &AcceptSignatures)
                .unwrap(),
            Some(tc)
        );
        assert!(store
            .get_verified_predecessor(2, 0, &id, &epoch, &validators, &RejectSignatures)
            .is_err());
        assert!(store
            .get_verified_predecessor(2, 1, &id, &epoch, &validators, &AcceptSignatures)
            .unwrap()
            .is_none());
        fs::write(root.join("verified-timeouts/h1r0.json"), b"{}").unwrap();
        assert!(store
            .get_verified_predecessor(2, 0, &id, &epoch, &validators, &AcceptSignatures)
            .is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn historical_timeout_selection_ignores_oversized_active_tail_but_verifies_needed_records() {
        let (root, store, epoch, validators, tc) = fixture();
        store
            .put_verified(&tc, &epoch, &validators, &AcceptSignatures)
            .unwrap();
        let tail = fs::File::create(root.join("verified-timeouts/h2r0.json")).unwrap();
        tail.set_len(MAX_LEASE_BYTES + 1).unwrap();
        assert!(store
            .get_verified_for_lease(2, &epoch, &validators, &AcceptSignatures)
            .is_err());
        assert_eq!(
            store
                .get_verified_for_lease_before(2, 2, &epoch, &validators, &AcceptSignatures)
                .unwrap(),
            vec![tc]
        );
        assert!(store
            .get_verified_for_lease_before(2, 2, &epoch, &validators, &RejectSignatures)
            .is_err());
        fs::write(root.join("verified-timeouts/h1r0.json"), b"{}").unwrap();
        assert!(store
            .get_verified_for_lease_before(2, 2, &epoch, &validators, &AcceptSignatures)
            .is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn timeout_lease_enumeration_rejects_noncanonical_names_and_excess_budgets() {
        for invalid in [
            "h01r0.json",
            "h1r+0.json",
            "h1r0.json.tmp",
            "h1r0r1.json",
            "../h1r0.json",
        ] {
            assert!(parse_record_name(invalid).is_err());
        }
        assert_eq!(parse_record_name("h9r42.json").unwrap(), (9, 42));
        let mut bytes = MAX_LEASE_BYTES;
        assert!(charge_record_budget(0, &mut bytes, 1).is_err());
        assert_eq!(bytes, MAX_LEASE_BYTES);
        assert!(charge_record_budget(MAX_LEASE_CERTIFICATES, &mut 0, 1).is_err());
        assert!(charge_record_budget(0, &mut 0, MAX_CERTIFICATE_RECORD_BYTES + 1).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn timeout_lease_enumeration_rejects_symlinks_and_corrupt_records() {
        let (root, store, epoch, validators, tc) = fixture();
        store
            .put_verified(&tc, &epoch, &validators, &AcceptSignatures)
            .unwrap();
        let record = root.join("verified-timeouts/h1r0.json");
        let link = root.join("verified-timeouts/h2r0.json");
        std::os::unix::fs::symlink(&record, &link).unwrap();
        assert!(store
            .get_verified_for_lease(1, &epoch, &validators, &AcceptSignatures)
            .is_err());
        fs::remove_file(link).unwrap();
        fs::write(record, b"{}").unwrap();
        assert!(store
            .get_verified_for_lease(1, &epoch, &validators, &AcceptSignatures)
            .is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
