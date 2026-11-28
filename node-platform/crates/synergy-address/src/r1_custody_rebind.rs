//! Same-key envelope transitions in the existing custody journal. The engine
//! owns authentication/decrypt/reseal; this child owns only durable CAS.
use super::*;
use synergy_address_engine::apqe::managed_creation::identity_proof::{
    ManagedIdentityRebindReceipt, VerifiedManagedRebindAuthorization, MAX_PROOF_RECEIPT_BYTES,
};
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RebindReservation {
    native_request_digest: Vec<u8>,
    operation_nonce: Vec<u8>,
    pub(super) birth_plan_commitment: Vec<u8>,
    pub(super) expected_envelope_commitment: Vec<u8>,
    pub(super) source_journal_generation: u64,
    target_binding_aad: Vec<u8>,
}
impl RebindReservation {
    pub(super) fn validate(&self) -> Result<(), CustodyJournalError> {
        if self.native_request_digest.len() != 32
            || self.operation_nonce.len() != 32
            || self.birth_plan_commitment.len() != 64
            || self.expected_envelope_commitment.len() != 64
            || self.source_journal_generation == 0
            || self.source_journal_generation.checked_add(2).is_none()
            || self.target_binding_aad.is_empty()
            || self.target_binding_aad.len() > 1024 * 1024
            || [
                &self.native_request_digest,
                &self.operation_nonce,
                &self.birth_plan_commitment,
                &self.expected_envelope_commitment,
            ]
            .iter()
            .any(|v| v.iter().all(|b| *b == 0))
        {
            return Err(CustodyJournalError::InvalidIntent);
        }
        Ok(())
    }
    fn from_auth(auth: &VerifiedManagedRebindAuthorization) -> Self {
        Self {
            native_request_digest: auth.native_request_digest().to_vec(),
            operation_nonce: auth.operation_nonce().to_vec(),
            birth_plan_commitment: auth.birth_plan_commitment().to_vec(),
            expected_envelope_commitment: auth.expected_envelope_commitment().to_vec(),
            source_journal_generation: auth.expected_journal_generation(),
            target_binding_aad: auth.target_binding_aad().to_vec(),
        }
    }
}
pub struct CustodyRebindLease {
    record: Record,
    bytes: Vec<u8>,
    marker: Vec<u8>,
}
/// Only the public completion receipt/commitment, never the encrypted secret.
pub struct CompletedIdentityRebind {
    bytes: Vec<u8>,
    envelope_commitment: [u8; 64],
}
impl CompletedIdentityRebind {
    pub fn canonical_public_bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn envelope_commitment(&self) -> [u8; 64] {
        self.envelope_commitment
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CompletionMarker {
    schema: u16,
    reservation: RebindReservation,
    completion_record_commitment: Vec<u8>,
    envelope_commitment: Vec<u8>,
}
fn hash(bytes: &[u8]) -> Result<[u8; 64], CustodyJournalError> {
    use crate::r1_public::{HashAlgorithm, Primitives};
    Primitives
        .hash(HashAlgorithm::Sha3512, bytes)
        .map_err(|_| CustodyJournalError::Corrupt)?
        .try_into()
        .map_err(|_| CustodyJournalError::Corrupt)
}
impl NativeCustodyJournal {
    pub fn from_managed_rebind(
        auth: &VerifiedManagedRebindAuthorization,
    ) -> Result<Self, CustodyJournalError> {
        #[cfg(not(unix))]
        {
            let _ = auth;
            return Err(CustodyJournalError::PlatformUnqualified);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            let root = auth.journal_root();
            if !root.starts_with(auth.platform_root())
                || root.canonicalize().ok().as_deref() != Some(root.as_path())
            {
                return Err(CustodyJournalError::Storage);
            }
            for path in root
                .ancestors()
                .take_while(|p| p.starts_with(auth.platform_root()))
            {
                let m = fs::symlink_metadata(path).map_err(|_| CustodyJournalError::Storage)?;
                if m.file_type().is_symlink()
                    || !m.is_dir()
                    || m.uid() != 0
                    || m.permissions().mode() & 0o022 != 0
                {
                    return Err(CustodyJournalError::Storage);
                }
            }
            if !root.join("context.json").is_file() {
                return Err(CustodyJournalError::Storage);
            }
            Self::open_private(root, Some(auth.network()), Admission::NativeManaged)
        }
    }
    pub fn reserve_managed_rebind(
        &mut self,
        auth: &VerifiedManagedRebindAuthorization,
    ) -> Result<CustodyRebindLease, CustodyJournalError> {
        if !matches!(self.admission, Admission::NativeManaged)
            || self.network != Some(auth.network())
            || self.root != auth.journal_root()
        {
            return Err(CustodyJournalError::Conflict);
        }
        let Some((r, _)) = self.current(auth.slot_ref())? else {
            return Err(CustodyJournalError::Conflict);
        };
        let key = r.public_key.as_ref().ok_or(CustodyJournalError::Corrupt)?;
        let public = auth.public_key_record();
        if key.role != public.role
            || key.algorithm != public.algorithm
            || key.full_public_key != public.full_public_key
            || key.key_generation != public.key_generation
            || r.creation_scope_commitment.as_slice() != auth.creation_scope_commitment()
            || r.native_request_digest.as_slice() != auth.original_creation_request_digest()
        {
            return Err(CustodyJournalError::Conflict);
        }
        self.reserve_rebind_checked(
            auth.slot_ref(),
            auth.key_generation(),
            RebindReservation::from_auth(auth),
        )
    }
    fn reserve_rebind_checked(
        &mut self,
        slot: &str,
        key_generation: u64,
        reservation: RebindReservation,
    ) -> Result<CustodyRebindLease, CustodyJournalError> {
        reservation.validate()?;
        let Some((mut r, old)) = self.current(slot)? else {
            return Err(CustodyJournalError::Conflict);
        };
        if r.stage == CustodyStage::Rebinding {
            return Err(CustodyJournalError::AmbiguousRebind);
        }
        if r.stage != CustodyStage::SealedPending
            || r.key_generation != key_generation
            || r.journal_generation != reservation.source_journal_generation
            || r.envelope_commitment.as_ref() != Some(&reservation.expected_envelope_commitment)
            || r.birth_plan_commitment.as_ref() != Some(&reservation.birth_plan_commitment)
            || r.full_binding_aad.as_ref() == Some(&reservation.target_binding_aad)
        {
            return Err(CustodyJournalError::Conflict);
        }
        let marker = encode(&(
            1u16,
            "PENDING-IDENTITY-REBIND",
            slot,
            key_generation,
            &reservation,
        ))?;
        let op = format!(
            "rebind-operations/{}.json",
            hex(&reservation.operation_nonce)
        );
        r.stage = CustodyStage::Rebinding;
        r.rebind_reservation = Some(reservation);
        r.journal_generation = r
            .journal_generation
            .checked_add(1)
            .ok_or(CustodyJournalError::Conflict)?;
        r.validate(self.network)?;
        let bytes = encode(&r)?;
        let mut tx =
            StorageTransaction::new(2 * MAX_RECORD).map_err(|_| CustodyJournalError::Storage)?;
        tx.put(slot_path(slot), bytes.clone())
            .map_err(|_| CustodyJournalError::Storage)?;
        tx.put(&op, marker.clone())
            .map_err(|_| CustodyJournalError::Storage)?;
        tx.commit_guarded(
            &mut self.store,
            &[
                StoragePrecondition {
                    relative_path: slot_path(slot).into(),
                    required: RequiredRecord::Exact(old),
                },
                StoragePrecondition {
                    relative_path: op.into(),
                    required: RequiredRecord::Missing,
                },
            ],
        )
        .map_err(|_| CustodyJournalError::Conflict)?;
        Ok(CustodyRebindLease {
            record: r,
            bytes,
            marker,
        })
    }
    pub fn managed_rebind_record(
        &self,
        lease: &CustodyRebindLease,
    ) -> Result<(PathBuf, fs::File), CustodyJournalError> {
        if !matches!(self.admission, Admission::NativeManaged)
            || lease.record.stage != CustodyStage::Rebinding
            || self
                .current(&lease.record.slot_ref)?
                .is_none_or(|(_, b)| b != lease.bytes)
        {
            return Err(CustodyJournalError::Conflict);
        }
        let path = self.root.join(slot_path(&lease.record.slot_ref));
        #[cfg(not(unix))]
        {
            let _ = path;
            return Err(CustodyJournalError::PlatformUnqualified);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let file = fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
                .open(&path)
                .map_err(|_| CustodyJournalError::Storage)?;
            Ok((path, file))
        }
    }
    pub fn complete_managed_rebind(
        &mut self,
        lease: &CustodyRebindLease,
        receipt: ManagedIdentityRebindReceipt,
    ) -> Result<CompletedIdentityRebind, CustodyJournalError> {
        let r = &lease.record;
        let reservation = r
            .rebind_reservation
            .as_ref()
            .ok_or(CustodyJournalError::InvalidStage)?;
        let key = r.public_key.as_ref().ok_or(CustodyJournalError::Corrupt)?;
        let public = receipt.public_key_record();
        if !matches!(self.admission, Admission::NativeManaged)
            || self.root != receipt.journal_root()
            || self.network != Some(receipt.network())
            || r.slot_ref != receipt.slot_ref()
            || r.key_generation != receipt.key_generation()
            || r.creation_scope_commitment.as_slice() != receipt.creation_scope_commitment()
            || r.native_request_digest.as_slice() != receipt.original_creation_request_digest()
            || key.role != public.role
            || key.algorithm != public.algorithm
            || key.key_generation != public.key_generation
            || key.full_public_key != public.full_public_key
            || reservation.native_request_digest.as_slice() != receipt.native_request_digest()
            || reservation.operation_nonce.as_slice() != receipt.operation_nonce()
            || reservation.source_journal_generation != receipt.expected_journal_generation()
            || reservation.expected_envelope_commitment.as_slice()
                != receipt.expected_envelope_commitment()
            || reservation.birth_plan_commitment.as_slice() != receipt.birth_plan_commitment()
            || reservation.target_binding_aad != receipt.full_binding_aad()
        {
            return Err(CustodyJournalError::Conflict);
        }
        self.complete_rebind_checked(
            lease,
            receipt.encrypted_envelope(),
            receipt.envelope_commitment(),
            receipt.canonical_receipt_bytes(),
            receipt.completion_record_commitment(),
        )
    }
    fn complete_rebind_checked(
        &mut self,
        lease: &CustodyRebindLease,
        envelope: &EncryptedEnvelope,
        new_commit: [u8; 64],
        public: &[u8],
        receipt_commit: [u8; 64],
    ) -> Result<CompletedIdentityRebind, CustodyJournalError> {
        if public.is_empty()
            || public.len() > MAX_PROOF_RECEIPT_BYTES
            || hash(public)? != receipt_commit
            || envelope.version != 5
            || new_commit == [0; 64]
        {
            return Err(CustodyJournalError::InvalidSeal);
        }
        let reservation = lease
            .record
            .rebind_reservation
            .as_ref()
            .ok_or(CustodyJournalError::InvalidStage)?;
        if reservation.expected_envelope_commitment.as_slice() == new_commit {
            return Err(CustodyJournalError::InvalidSeal);
        }
        let mut r = lease.record.clone();
        r.stage = CustodyStage::SealedPending;
        r.rebind_reservation = None;
        r.full_binding_aad = Some(reservation.target_binding_aad.clone());
        r.envelope = Some(envelope.clone());
        r.envelope_commitment = Some(new_commit.to_vec());
        r.journal_generation = r
            .journal_generation
            .checked_add(1)
            .ok_or(CustodyJournalError::Conflict)?;
        r.validate(self.network)?;
        let marker = encode(&CompletionMarker {
            schema: 1,
            reservation: reservation.clone(),
            completion_record_commitment: receipt_commit.to_vec(),
            envelope_commitment: new_commit.to_vec(),
        })?;
        let op = format!(
            "rebind-operations/{}.json",
            hex(&reservation.operation_nonce)
        );
        let output = format!("rebind-results/{}.bin", hex(&reservation.operation_nonce));
        let mut tx =
            StorageTransaction::new(3 * MAX_RECORD).map_err(|_| CustodyJournalError::Storage)?;
        tx.put(slot_path(&r.slot_ref), encode(&r)?)
            .map_err(|_| CustodyJournalError::Storage)?;
        tx.put(&op, marker)
            .map_err(|_| CustodyJournalError::Storage)?;
        tx.put(&output, public.to_vec())
            .map_err(|_| CustodyJournalError::Storage)?;
        tx.commit_guarded(
            &mut self.store,
            &[
                StoragePrecondition {
                    relative_path: slot_path(&r.slot_ref).into(),
                    required: RequiredRecord::Exact(lease.bytes.clone()),
                },
                StoragePrecondition {
                    relative_path: op.into(),
                    required: RequiredRecord::Exact(lease.marker.clone()),
                },
                StoragePrecondition {
                    relative_path: output.into(),
                    required: RequiredRecord::Missing,
                },
            ],
        )
        .map_err(|_| CustodyJournalError::Conflict)?;
        Ok(CompletedIdentityRebind {
            bytes: public.to_vec(),
            envelope_commitment: new_commit,
        })
    }
    pub fn completed_rebind(
        &self,
        nonce: &[u8; 32],
        request: &[u8; 32],
    ) -> Result<Option<CompletedIdentityRebind>, CustodyJournalError> {
        self.store
            .inspect_consistent(|reader| {
                let Some(marker) = reader
                    .read_optional_bounded(format!("rebind-operations/{}.json", hex(nonce)))
                    .map_err(|_| CustodyJournalError::Storage)?
                else {
                    return Ok(None);
                };
                let marker: CompletionMarker = serde_json::from_slice(&marker)
                    .map_err(|_| CustodyJournalError::AmbiguousRebind)?;
                marker.reservation.validate()?;
                if marker.schema != 1
                    || marker.reservation.operation_nonce.as_slice() != nonce
                    || marker.reservation.native_request_digest.as_slice() != request
                {
                    return Err(CustodyJournalError::Conflict);
                }
                let bytes = reader
                    .with_maximum_bytes(MAX_PROOF_RECEIPT_BYTES)
                    .read_optional_bounded(format!("rebind-results/{}.bin", hex(nonce)))
                    .map_err(|_| CustodyJournalError::Storage)?
                    .ok_or(CustodyJournalError::Corrupt)?;
                if bytes.is_empty()
                    || hash(&bytes)?.as_slice() != marker.completion_record_commitment
                {
                    return Err(CustodyJournalError::Corrupt);
                }
                let envelope_commitment = marker
                    .envelope_commitment
                    .try_into()
                    .map_err(|_| CustodyJournalError::Corrupt)?;
                Ok(Some(CompletedIdentityRebind {
                    bytes,
                    envelope_commitment,
                }))
            })
            .map_err(|_| CustodyJournalError::Storage)?
    }
}

#[cfg(test)]
pub(super) fn test_public_storage_transition(journal: &mut NativeCustodyJournal, slot: &str) {
    // Storage-only fixture: the test calls private helpers. These bytes are NOT
    // authenticated engine rebind results and cannot enter managed wrappers.
    let (before, original) = journal.current(slot).unwrap().unwrap();
    let birth = before.birth_plan_commitment.clone().unwrap();
    let reservation = RebindReservation {
        native_request_digest: vec![61; 32],
        operation_nonce: vec![62; 32],
        birth_plan_commitment: birth.clone(),
        expected_envelope_commitment: before.envelope_commitment.clone().unwrap(),
        source_journal_generation: before.journal_generation,
        target_binding_aad: b"PUBLIC-SYNTHETIC-STORAGE-TARGET-ONLY".to_vec(),
    };
    let mut wrong = reservation.clone();
    wrong.birth_plan_commitment = vec![63; 64];
    assert!(journal
        .reserve_rebind_checked(slot, before.key_generation, wrong)
        .is_err());
    assert_eq!(journal.current(slot).unwrap().unwrap().1, original);
    assert!(journal
        .reserve_rebind_checked(slot, before.key_generation + 1, reservation.clone())
        .is_err());
    let lease = journal
        .reserve_rebind_checked(slot, before.key_generation, reservation.clone())
        .unwrap();
    assert_eq!(
        lease.record.journal_generation,
        before.journal_generation + 1
    );
    assert_eq!(lease.record.stage, CustodyStage::Rebinding);
    assert!(matches!(
        journal.reserve_rebind_checked(slot, before.key_generation, reservation),
        Err(CustodyJournalError::AmbiguousRebind)
    ));
    assert!(matches!(
        journal.completed_rebind(&[62; 32], &[61; 32]),
        Err(CustodyJournalError::AmbiguousRebind)
    ));
    let root = journal.root.clone();
    let n = journal.network;
    // Reopen independently to demonstrate the durable unresolved-attempt fence.
    let mut reopened =
        NativeCustodyJournal::open_private(&root, n, Admission::PublicFixture).unwrap();
    assert_eq!(
        reopened.current(slot).unwrap().unwrap().0.stage,
        CustodyStage::Rebinding
    );
    let public = b"PUBLIC-SYNTHETIC-REBIND-STORAGE-ONLY";
    let receipt_commit = hash(public).unwrap();
    let mut bad = receipt_commit;
    bad[63] ^= 1;
    let envelope = before.envelope.as_ref().unwrap();
    let new_commit = [64; 64];
    assert!(reopened
        .complete_rebind_checked(&lease, envelope, new_commit, public, bad)
        .is_err());
    assert_eq!(
        reopened.current(slot).unwrap().unwrap().0.stage,
        CustodyStage::Rebinding
    );
    let result = reopened
        .complete_rebind_checked(&lease, envelope, new_commit, public, receipt_commit)
        .unwrap();
    assert_eq!(result.canonical_public_bytes(), public);
    assert_eq!(result.envelope_commitment(), new_commit);
    assert!(reopened
        .complete_rebind_checked(&lease, envelope, new_commit, public, receipt_commit)
        .is_err());
    let current = reopened.current(slot).unwrap().unwrap().0;
    assert_eq!(current.stage, CustodyStage::SealedPending);
    assert_eq!(current.key_generation, before.key_generation);
    assert_eq!(current.journal_generation, before.journal_generation + 2);
    assert_eq!(current.operation_nonce, before.operation_nonce);
    assert_eq!(current.native_request_digest, before.native_request_digest);
    assert_eq!(
        current.creation_scope_commitment,
        before.creation_scope_commitment
    );
    assert_eq!(current.birth_plan_commitment, Some(birth));
    assert_eq!(
        current.full_binding_aad,
        Some(b"PUBLIC-SYNTHETIC-STORAGE-TARGET-ONLY".to_vec())
    );
    assert_eq!(current.envelope_commitment, Some(new_commit.to_vec()));
    assert_eq!(
        reopened
            .completed_rebind(&[62; 32], &[61; 32])
            .unwrap()
            .unwrap()
            .canonical_public_bytes(),
        public
    );
    assert!(reopened.completed_rebind(&[62; 32], &[60; 32]).is_err());
}
