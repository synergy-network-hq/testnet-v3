//! Durable exact-purpose BootstrapRoot approval. Custody remains pre-NIC NoneN;
//! prospective N is bound by immutable incarnation/choice latches, not by
//! relabeling the original key/envelope. No native authority is issued here.
use super::*;
use synergy_address_engine::apqe::managed_creation::root_approval_use::{
    ManagedRootApprovalReceipt, VerifiedManagedRootApprovalAuthorization as Auth,
};
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RootApprovalReservation {
    native_request_digest: Vec<u8>,
    operation_nonce: Vec<u8>,
    approval_plan_commitment: Vec<u8>,
    pub(super) expected_envelope_commitment: Vec<u8>,
    pub(super) source_journal_generation: u64,
    root_index: u32,
}
impl RootApprovalReservation {
    pub(super) fn validate(&self) -> Result<(), CustodyJournalError> {
        if self.source_journal_generation == 0
            || self.source_journal_generation.checked_add(2).is_none()
            || self.root_index >= 32
            || self.native_request_digest.len() != 32
            || self.operation_nonce.len() != 32
            || self.approval_plan_commitment.len() != 64
            || self.expected_envelope_commitment.len() != 64
            || [
                &self.native_request_digest,
                &self.operation_nonce,
                &self.approval_plan_commitment,
                &self.expected_envelope_commitment,
            ]
            .iter()
            .any(|b| b.iter().all(|v| *v == 0))
        {
            return Err(CustodyJournalError::InvalidIntent);
        }
        Ok(())
    }
    fn from_auth(a: &Auth) -> Self {
        Self {
            native_request_digest: a.native_request_digest().to_vec(),
            operation_nonce: a.operation_nonce().to_vec(),
            approval_plan_commitment: a.approval_plan_commitment().to_vec(),
            expected_envelope_commitment: a.expected_envelope_commitment().to_vec(),
            source_journal_generation: a.expected_journal_generation(),
            root_index: a.root_index(),
        }
    }
}
pub struct CustodyRootApprovalLease {
    record: Record,
    bytes: Vec<u8>,
    marker: Vec<u8>,
    incarnation_key: PathBuf,
    incarnation: Vec<u8>,
    choice_key: PathBuf,
    choice: Vec<u8>,
}
pub struct CompletedRootApproval {
    bytes: Vec<u8>,
}
impl CompletedRootApproval {
    pub fn canonical_public_bytes(&self) -> &[u8] {
        &self.bytes
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CompleteMarker {
    schema: u16,
    reservation: RootApprovalReservation,
    completion_record_commitment: Vec<u8>,
}
fn hash(b: &[u8]) -> Result<[u8; 64], CustodyJournalError> {
    use crate::r1_public::{HashAlgorithm, Primitives};
    Primitives
        .hash(HashAlgorithm::Sha3512, b)
        .map_err(|_| CustodyJournalError::Corrupt)?
        .try_into()
        .map_err(|_| CustodyJournalError::Corrupt)
}
fn safe_latch(p: &Path) -> Result<(), CustodyJournalError> {
    if p.is_absolute()
        || p.components()
            .any(|c| !matches!(c, std::path::Component::Normal(_)))
    {
        return Err(CustodyJournalError::InvalidIntent);
    }
    Ok(())
}
fn marker_path(n: &[u8]) -> String {
    format!("root-approval-operations/{}.json", hex(n))
}
fn result_path(n: &[u8]) -> String {
    format!("root-approval-results/{}.bin", hex(n))
}
impl NativeCustodyJournal {
    pub fn from_managed_root_approval(a: &Auth) -> Result<Self, CustodyJournalError> {
        a.ensure_current()
            .map_err(|_| CustodyJournalError::InvalidIntent)?;
        #[cfg(not(unix))]
        {
            let _ = a;
            Err(CustodyJournalError::PlatformUnqualified)
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            let root = a.journal_root();
            let platform = a.platform_root();
            if !platform.is_absolute()
                || !root.starts_with(platform)
                || root.canonicalize().ok().as_deref() != Some(root.as_path())
            {
                return Err(CustodyJournalError::Storage);
            }
            for p in root.ancestors().take_while(|p| p.starts_with(platform)) {
                let m = fs::symlink_metadata(p).map_err(|_| CustodyJournalError::Storage)?;
                if m.file_type().is_symlink()
                    || !m.is_dir()
                    || m.uid() != 0
                    || m.permissions().mode() & 0o022 != 0
                {
                    return Err(CustodyJournalError::Storage);
                }
            }
            let expected = encode(&(
                1u16,
                "NATIVE-MANAGED-CUSTODY-JOURNAL",
                Option::<(u64, Vec<u8>)>::None,
            ))?;
            AtomicStore::inspect_existing_read_only(&root, MAX_RECORD, |r| {
                if r.with_maximum_bytes(4096)
                    .read_optional_bounded("context.json")
                    .map_err(|_| CustodyJournalError::Storage)?
                    .as_deref()
                    != Some(expected.as_slice())
                {
                    return Err(CustodyJournalError::Conflict);
                }
                Ok(())
            })
            .map_err(|_| CustodyJournalError::Storage)?
            .ok_or(CustodyJournalError::Storage)??;
            // Existing initialized source only; original context/key namespace stays None.
            Self::open_private(root, None, Admission::NativeManaged)
        }
    }
    pub fn reserve_managed_root_approval(
        &mut self,
        a: &Auth,
    ) -> Result<CustodyRootApprovalLease, CustodyJournalError> {
        a.ensure_current()
            .map_err(|_| CustodyJournalError::InvalidIntent)?;
        if !matches!(self.admission, Admission::NativeManaged)
            || self.network.is_some()
            || self.root != a.journal_root()
        {
            return Err(CustodyJournalError::Conflict);
        }
        let (r, _) = self
            .current(a.slot_ref())?
            .ok_or(CustodyJournalError::Conflict)?;
        let k = r.public_key.as_ref().ok_or(CustodyJournalError::Corrupt)?;
        let p = a.public_key_record();
        if r.key_generation != a.key_generation()
            || r.native_request_digest.as_slice() != a.original_creation_request_digest()
            || r.creation_scope_commitment.as_slice() != a.creation_scope_commitment()
            || r.full_binding_aad.as_deref() != Some(a.full_binding_aad())
            || k.role != p.role
            || k.algorithm != p.algorithm
            || k.key_generation != p.key_generation
            || k.full_public_key != p.full_public_key
        {
            return Err(CustodyJournalError::Conflict);
        }
        let n = a.network();
        let incarnation = encode(&(
            1u16,
            "BOOTSTRAP-ROOT-INCARNATION",
            a.slot_ref(),
            a.key_generation(),
            a.creation_scope_commitment().to_vec(),
            p.full_public_key,
            (n.chain_id, n.nic.to_vec()),
        ))?;
        self.reserve_root_checked(
            a.slot_ref(),
            RootApprovalReservation::from_auth(a),
            a.incarnation_choice_key(),
            incarnation,
            a.approval_choice_key(),
            a.approval_plan_commitment().to_vec(),
        )
    }
    fn reserve_root_checked(
        &mut self,
        slot: &str,
        reservation: RootApprovalReservation,
        incarnation_key: PathBuf,
        incarnation: Vec<u8>,
        choice_key: PathBuf,
        choice: Vec<u8>,
    ) -> Result<CustodyRootApprovalLease, CustodyJournalError> {
        reservation.validate()?;
        safe_latch(&incarnation_key)?;
        safe_latch(&choice_key)?;
        if self.network.is_some()
            || incarnation_key == choice_key
            || incarnation.is_empty()
            || incarnation.len() > 16384
            || choice.len() != 64
        {
            return Err(CustodyJournalError::InvalidIntent);
        }
        let (mut r, old) = self.current(slot)?.ok_or(CustodyJournalError::Conflict)?;
        if r.stage == CustodyStage::RootApproving {
            return Err(CustodyJournalError::AmbiguousRootApproval);
        }
        if r.stage != CustodyStage::SealedPending
            || r.algorithm != "ML-DSA-87"
            || r.journal_generation != reservation.source_journal_generation
            || r.envelope_commitment.as_ref() != Some(&reservation.expected_envelope_commitment)
        {
            return Err(CustodyJournalError::Conflict);
        }
        let mut guards = vec![
            StoragePrecondition {
                relative_path: slot_path(slot).into(),
                required: RequiredRecord::Exact(old),
            },
            StoragePrecondition {
                relative_path: marker_path(&reservation.operation_nonce).into(),
                required: RequiredRecord::Missing,
            },
            StoragePrecondition {
                relative_path: result_path(&reservation.operation_nonce).into(),
                required: RequiredRecord::Missing,
            },
        ];
        for (path, value) in [(&incarnation_key, &incarnation), (&choice_key, &choice)] {
            let previous = self
                .store
                .read_optional_bounded(path)
                .map_err(|_| CustodyJournalError::Storage)?;
            if previous.as_ref().is_some_and(|b| b != value) {
                return Err(CustodyJournalError::Conflict);
            }
            guards.push(StoragePrecondition {
                relative_path: path.clone(),
                required: previous
                    .map(RequiredRecord::Exact)
                    .unwrap_or(RequiredRecord::Missing),
            });
        }
        let marker = encode(&reservation)?;
        r.stage = CustodyStage::RootApproving;
        r.journal_generation = r
            .journal_generation
            .checked_add(1)
            .ok_or(CustodyJournalError::Conflict)?;
        r.root_approval_reservation = Some(reservation.clone());
        r.validate(None)?;
        let bytes = encode(&r)?;
        let mut tx =
            StorageTransaction::new(4 * MAX_RECORD).map_err(|_| CustodyJournalError::Storage)?;
        for (p, b) in [
            (PathBuf::from(slot_path(slot)), bytes.clone()),
            (
                marker_path(&reservation.operation_nonce).into(),
                marker.clone(),
            ),
            (incarnation_key.clone(), incarnation.clone()),
            (choice_key.clone(), choice.clone()),
        ] {
            tx.put(p, b).map_err(|_| CustodyJournalError::Storage)?;
        }
        tx.commit_guarded(&mut self.store, &guards)
            .map_err(|_| CustodyJournalError::Conflict)?;
        Ok(CustodyRootApprovalLease {
            record: r,
            bytes,
            marker,
            incarnation_key,
            incarnation,
            choice_key,
            choice,
        })
    }
    pub fn managed_root_approval_record(
        &self,
        l: &CustodyRootApprovalLease,
    ) -> Result<(PathBuf, fs::File), CustodyJournalError> {
        if !matches!(self.admission, Admission::NativeManaged)
            || self.network.is_some()
            || l.record.stage != CustodyStage::RootApproving
            || self
                .current(&l.record.slot_ref)?
                .is_none_or(|(_, b)| b != l.bytes)
        {
            return Err(CustodyJournalError::Conflict);
        }
        let p = self.root.join(slot_path(&l.record.slot_ref));
        #[cfg(not(unix))]
        {
            let _ = p;
            Err(CustodyJournalError::PlatformUnqualified)
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let f = fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
                .open(&p)
                .map_err(|_| CustodyJournalError::Storage)?;
            Ok((p, f))
        }
    }
    pub fn complete_managed_root_approval(
        &mut self,
        l: &CustodyRootApprovalLease,
        receipt: ManagedRootApprovalReceipt,
    ) -> Result<CompletedRootApproval, CustodyJournalError> {
        let a = receipt.authorization();
        a.ensure_current()
            .map_err(|_| CustodyJournalError::InvalidIntent)?;
        if !matches!(self.admission, Admission::NativeManaged)
            || self.network.is_some()
            || self.root != a.journal_root()
            || a.slot_ref() != l.record.slot_ref
            || a.key_generation() != l.record.key_generation
            || a.creation_scope_commitment().as_slice() != l.record.creation_scope_commitment
            || a.original_creation_request_digest().as_slice() != l.record.native_request_digest
            || encode(&RootApprovalReservation::from_auth(a))?
                != encode(
                    l.record
                        .root_approval_reservation
                        .as_ref()
                        .ok_or(CustodyJournalError::InvalidStage)?,
                )?
            || a.incarnation_choice_key() != l.incarnation_key
            || a.approval_choice_key() != l.choice_key
        {
            return Err(CustodyJournalError::Conflict);
        }
        let key = l
            .record
            .public_key
            .as_ref()
            .ok_or(CustodyJournalError::Corrupt)?;
        let p = a.public_key_record();
        if key.role != p.role
            || key.algorithm != p.algorithm
            || key.key_generation != p.key_generation
            || key.full_public_key != p.full_public_key
        {
            return Err(CustodyJournalError::Conflict);
        }
        let result = self.complete_root_checked(
            l,
            receipt.canonical_public_bytes(),
            receipt.completion_record_commitment(),
        )?;
        a.ensure_current()
            .map_err(|_| CustodyJournalError::InvalidIntent)?;
        Ok(result)
    }
    fn complete_root_checked(
        &mut self,
        l: &CustodyRootApprovalLease,
        public: &[u8],
        commitment: [u8; 64],
    ) -> Result<CompletedRootApproval, CustodyJournalError> {
        if public.is_empty() || public.len() > 1024 * 1024 || hash(public)? != commitment {
            return Err(CustodyJournalError::Corrupt);
        }
        let reservation = l
            .record
            .root_approval_reservation
            .as_ref()
            .ok_or(CustodyJournalError::InvalidStage)?;
        let mut r = l.record.clone();
        r.stage = CustodyStage::SealedPending;
        r.root_approval_reservation = None;
        r.journal_generation = r
            .journal_generation
            .checked_add(1)
            .ok_or(CustodyJournalError::Conflict)?;
        r.validate(None)?;
        let mut tx =
            StorageTransaction::new(3 * MAX_RECORD).map_err(|_| CustodyJournalError::Storage)?;
        tx.put(slot_path(&r.slot_ref), encode(&r)?)
            .map_err(|_| CustodyJournalError::Storage)?;
        tx.put(
            marker_path(&reservation.operation_nonce),
            encode(&CompleteMarker {
                schema: 1,
                reservation: reservation.clone(),
                completion_record_commitment: commitment.to_vec(),
            })?,
        )
        .map_err(|_| CustodyJournalError::Storage)?;
        tx.put(result_path(&reservation.operation_nonce), public.to_vec())
            .map_err(|_| CustodyJournalError::Storage)?;
        tx.commit_guarded(
            &mut self.store,
            &[
                StoragePrecondition {
                    relative_path: slot_path(&r.slot_ref).into(),
                    required: RequiredRecord::Exact(l.bytes.clone()),
                },
                StoragePrecondition {
                    relative_path: marker_path(&reservation.operation_nonce).into(),
                    required: RequiredRecord::Exact(l.marker.clone()),
                },
                StoragePrecondition {
                    relative_path: result_path(&reservation.operation_nonce).into(),
                    required: RequiredRecord::Missing,
                },
                StoragePrecondition {
                    relative_path: l.incarnation_key.clone(),
                    required: RequiredRecord::Exact(l.incarnation.clone()),
                },
                StoragePrecondition {
                    relative_path: l.choice_key.clone(),
                    required: RequiredRecord::Exact(l.choice.clone()),
                },
            ],
        )
        .map_err(|_| CustodyJournalError::Conflict)?;
        Ok(CompletedRootApproval {
            bytes: public.to_vec(),
        })
    }
    pub fn completed_root_approval(
        &self,
        nonce: &[u8; 32],
        request: &[u8; 32],
    ) -> Result<Option<CompletedRootApproval>, CustodyJournalError> {
        if self.network.is_some() {
            return Err(CustodyJournalError::Conflict);
        }
        self.store
            .inspect_consistent(|reader| {
                let Some(marker) = reader
                    .read_optional_bounded(marker_path(nonce))
                    .map_err(|_| CustodyJournalError::Storage)?
                else {
                    return Ok(None);
                };
                let m: CompleteMarker = serde_json::from_slice(&marker)
                    .map_err(|_| CustodyJournalError::AmbiguousRootApproval)?;
                m.reservation.validate()?;
                if m.schema != 1
                    || m.reservation.operation_nonce.as_slice() != nonce
                    || m.reservation.native_request_digest.as_slice() != request
                {
                    return Err(CustodyJournalError::Conflict);
                }
                let bytes = reader
                    .with_maximum_bytes(1024 * 1024)
                    .read_optional_bounded(result_path(nonce))
                    .map_err(|_| CustodyJournalError::Storage)?
                    .ok_or(CustodyJournalError::Corrupt)?;
                if bytes.is_empty() || hash(&bytes)?.as_slice() != m.completion_record_commitment {
                    return Err(CustodyJournalError::Corrupt);
                }
                Ok(Some(CompletedRootApproval { bytes }))
            })
            .map_err(|_| CustodyJournalError::Storage)?
    }
}

/// Storage-only adversarial checks using the existing sealed public fixture.
/// These bytes are not approval signatures and never enter a managed provider.
#[cfg(test)]
pub(super) fn test_public_storage_transition(j: &mut NativeCustodyJournal, slot: &str) {
    let original = j.current(slot).unwrap().unwrap().0;
    let reservation = |generation, nonce, plan| RootApprovalReservation {
        native_request_digest: vec![81; 32],
        operation_nonce: vec![nonce; 32],
        approval_plan_commitment: vec![plan; 64],
        expected_envelope_commitment: original.envelope_commitment.clone().unwrap(),
        source_journal_generation: generation,
        root_index: 0,
    };
    let incarnation_key = PathBuf::from("root-approval-incarnations/public-fixture.bin");
    let choice_key = PathBuf::from("root-approval-choices/public-nic.bin");
    let incarnation = b"PUBLIC-SYNTHETIC-PROSPECTIVE-N-ONLY".to_vec();
    let plan = vec![83; 64];
    assert!(j
        .reserve_root_checked(
            slot,
            reservation(original.journal_generation - 1, 82, 83),
            incarnation_key.clone(),
            incarnation.clone(),
            choice_key.clone(),
            plan.clone()
        )
        .is_err());
    let lease = j
        .reserve_root_checked(
            slot,
            reservation(original.journal_generation, 82, 83),
            incarnation_key.clone(),
            incarnation.clone(),
            choice_key.clone(),
            plan.clone(),
        )
        .unwrap();
    assert_eq!(
        lease.record.journal_generation,
        original.journal_generation + 1
    );
    assert_eq!(lease.record.full_binding_aad, original.full_binding_aad);
    assert_eq!(lease.record.key_generation, original.key_generation);
    assert!(matches!(
        j.completed_root_approval(&[82; 32], &[81; 32]),
        Err(CustodyJournalError::AmbiguousRootApproval)
    ));
    let public = b"PUBLIC-SYNTHETIC-ROOT-APPROVAL-STORAGE-ONLY";
    let digest = hash(public).unwrap();
    let mut bad = digest;
    bad[0] ^= 1;
    assert!(j.complete_root_checked(&lease, public, bad).is_err());
    let mut restarted = NativeCustodyJournal::for_public_bootstrap_fixture(&j.root).unwrap();
    assert!(matches!(
        restarted.reserve_root_checked(
            slot,
            reservation(original.journal_generation, 82, 83),
            incarnation_key.clone(),
            incarnation.clone(),
            choice_key.clone(),
            plan.clone()
        ),
        Err(CustodyJournalError::AmbiguousRootApproval)
    ));
    let result = restarted
        .complete_root_checked(&lease, public, digest)
        .unwrap();
    assert_eq!(result.canonical_public_bytes(), public);
    assert!(restarted
        .complete_root_checked(&lease, public, digest)
        .is_err());
    assert_eq!(
        restarted
            .completed_root_approval(&[82; 32], &[81; 32])
            .unwrap()
            .unwrap()
            .canonical_public_bytes(),
        public
    );
    assert!(restarted
        .completed_root_approval(&[82; 32], &[80; 32])
        .is_err());
    let current = restarted.current(slot).unwrap().unwrap().0;
    assert_eq!(current.stage, CustodyStage::SealedPending);
    assert_eq!(current.journal_generation, original.journal_generation + 2);
    assert_eq!(current.full_binding_aad, original.full_binding_aad);
    assert_eq!(
        current.creation_scope_commitment,
        original.creation_scope_commitment
    );
    assert_eq!(current.key_generation, original.key_generation);
    assert!(restarted.network.is_none());
    // A different plan for this purpose, or a second incarnation, is refused
    // even with a fresh native nonce and the exact latest journal generation.
    assert!(restarted
        .reserve_root_checked(
            slot,
            reservation(current.journal_generation, 84, 85),
            incarnation_key.clone(),
            incarnation.clone(),
            choice_key.clone(),
            vec![85; 64]
        )
        .is_err());
    assert!(restarted
        .reserve_root_checked(
            slot,
            reservation(current.journal_generation, 84, 83),
            incarnation_key.clone(),
            b"A-DIFFERENT-PUBLIC-INCARNATION".to_vec(),
            PathBuf::from("root-approval-choices/another-nic.bin"),
            plan.clone()
        )
        .is_err());
    assert!(restarted
        .reserve_root_checked(
            slot,
            reservation(current.journal_generation, 82, 83),
            incarnation_key.clone(),
            incarnation.clone(),
            choice_key.clone(),
            plan
        )
        .is_err());
    // Another purpose in the same incarnation is permitted. Its latch must
    // remain exact through completion, including across a process restart.
    let next_choice = PathBuf::from("root-approval-choices/public-formation.bin");
    let next = restarted
        .reserve_root_checked(
            slot,
            reservation(current.journal_generation, 86, 87),
            incarnation_key,
            incarnation,
            next_choice.clone(),
            vec![87; 64],
        )
        .unwrap();
    let mut tx = StorageTransaction::new(MAX_RECORD).unwrap();
    tx.put(&next_choice, vec![88; 64]).unwrap();
    tx.commit(&mut restarted.store).unwrap();
    assert!(restarted
        .complete_root_checked(&next, public, digest)
        .is_err());
    assert_eq!(
        restarted.current(slot).unwrap().unwrap().0.stage,
        CustodyStage::RootApproving
    );
    assert!(restarted
        .store
        .read_optional_bounded(result_path(&[86; 32]))
        .unwrap()
        .is_none());
}
