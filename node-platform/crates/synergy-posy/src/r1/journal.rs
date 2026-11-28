//! R1 ordinary-approval durability, not custody or consensus authority.
//!
//! The native custody owner must hold its genuine policy/key/provider fence
//! through computation and completion. This journal never opens a secret.
//! Its finality cursor stores verified evidence; it is not the AIVM state commit.
use super::{
    codec::Reader, Digest48, R1AuthorityMember, R1ConsensusVerifier, R1Header, R1ProofError,
    R1QuorumCertificate, VerifiedR1FinalizedAnchor,
};
use serde::Serialize;
use std::path::{Path, PathBuf};
use synergy_protocol_types::R1NetworkCoordinate;
use synergy_storage::{
    AtomicStore, AtomicStoreWriter, GuardedTransactionBackend, RequiredRecord, StorageError,
    StoragePrecondition, StorageTransaction,
};

const MAX_RECORD: usize = 20 * 1024 * 1024;
const SAFETY: &str = "r1-safety.json";
const CONTEXT: &str = "r1-context.bin";
const CURSOR: &str = "r1-finalized.json";

#[derive(Debug)]
pub enum R1JournalError {
    Storage(StorageError),
    Proof(R1ProofError),
    Conflict,
    Corrupt,
    Fenced,
    PlatformUnqualified,
}
impl std::fmt::Display for R1JournalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "R1 signing journal: {self:?}")
    }
}
impl std::error::Error for R1JournalError {}
impl From<StorageError> for R1JournalError {
    fn from(e: StorageError) -> Self {
        Self::Storage(e)
    }
}
impl From<R1ProofError> for R1JournalError {
    fn from(e: R1ProofError) -> Self {
        Self::Proof(e)
    }
}
type Result<T> = std::result::Result<T, R1JournalError>;

#[derive(Clone, Debug)]
pub struct R1JournalBinding {
    pub coordinate: R1NetworkCoordinate,
    pub protocol: Digest48,
    pub authority: Digest48,
    pub epoch: u64,
    pub identity: Digest48,
    pub key_id: Digest48,
    pub key_version: u64,
}
impl R1JournalBinding {
    fn bytes(&self) -> Result<Vec<u8>> {
        if self.key_version == 0 {
            return Err(R1JournalError::Conflict);
        }
        self.coordinate
            .validate()
            .map_err(|_| R1JournalError::Conflict)?;
        let c = &self.coordinate;
        synergy_posy_approval::JournalContext {
            coordinate: synergy_posy_approval::Coordinate {
                chain_id: c.network.chain_id,
                nic: c.network.nic,
                genesis_profile: synergy_posy_approval::ProfileRef {
                    name: c.genesis.profile.name.clone(),
                    revision: c.genesis.profile.revision,
                },
                genesis: c.genesis.digest,
                profiles_profile: synergy_posy_approval::ProfileRef {
                    name: c.activated_profiles.profile.name.clone(),
                    revision: c.activated_profiles.profile.revision,
                },
                profiles: c.activated_profiles.commitment,
            },
            protocol_profile: self.protocol,
            authority: self.authority,
            epoch: self.epoch,
            identity: self.identity,
            key_id: self.key_id,
            key_generation: self.key_version,
        }
        .encode()
        .map_err(|_| R1JournalError::Conflict)
    }
}
use synergy_posy_approval::journal::{Finalized, Safety, Slot};

/// A durable reservation, not permission to use a key. No public constructor.
#[derive(Debug)]
pub struct R1ApprovalReservation {
    context: Vec<u8>,
    path: PathBuf,
    slot: Slot,
    original: Vec<u8>,
}
impl R1ApprovalReservation {
    pub fn approval_message(&self) -> &[u8] {
        &self.slot.message
    }
    pub fn relative_path(&self) -> &Path {
        &self.path
    }
}
/// Only bytes durably release-authorized by this journal. Not a QC.
#[derive(Debug, Clone)]
pub struct R1ReleasedApproval {
    message: Vec<u8>,
    signature: Vec<u8>,
}
impl R1ReleasedApproval {
    pub fn approval_message(&self) -> &[u8] {
        &self.message
    }
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }
}
#[derive(Debug)]
pub enum R1ReservationOutcome {
    Pending(R1ApprovalReservation),
    Released(R1ReleasedApproval),
}
/// Persisted evidence cursor. Reading this does not authenticate stored proofs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct R1JournalCursor {
    height: u64,
    block: Digest48,
}
impl R1JournalCursor {
    pub fn height(&self) -> u64 {
        self.height
    }
    pub fn block_digest(&self) -> &Digest48 {
        &self.block
    }
}

pub struct R1SigningJournal {
    store: AtomicStore,
    binding: R1JournalBinding,
    context: Vec<u8>,
}
impl R1SigningJournal {
    /// Only the native managed owner may choose the already protected journal
    /// root. AtomicStore supplies durability, not protected-custody admission.
    pub fn open(root: impl Into<PathBuf>, binding: R1JournalBinding) -> Result<Self> {
        if !cfg!(unix) {
            return Err(R1JournalError::PlatformUnqualified);
        }
        let context = binding.bytes()?;
        let root = root.into();
        let store = AtomicStore::new(&root, MAX_RECORD)?;
        if store.read_optional_bounded(CONTEXT)?.is_none() {
            // Initialization is one durable transaction. An existing journal
            // with a missing safety/context record is never silently reset.
            for entry in std::fs::read_dir(&root)
                .map_err(|e| R1JournalError::Storage(StorageError::Io(e.to_string())))?
            {
                let entry =
                    entry.map_err(|e| R1JournalError::Storage(StorageError::Io(e.to_string())))?;
                let name = entry.file_name();
                if name != ".synergy-writer.lock" && name != ".transactions" {
                    return Err(R1JournalError::Corrupt);
                }
            }
            let mut tx = StorageTransaction::new(4096)?;
            tx.put(CONTEXT, context.clone())?;
            tx.put(
                SAFETY,
                encode(&Safety {
                    generation: 0,
                    last_approval_round: None,
                    pass_fence: None,
                    lock: None,
                })?,
            )?;
            match tx.commit_guarded(
                &mut store.clone(),
                &[guard(CONTEXT, None), guard(SAFETY, None)],
            ) {
                Ok(()) => (),
                Err(StorageError::ConflictingWrite) => (),
                Err(e) => return Err(e.into()),
            }
        }
        let j = Self {
            store,
            binding,
            context,
        };
        j.safety_generation()?;
        j.cursor()?;
        Ok(j)
    }
    fn access(&mut self) -> JournalAccess<'_, AtomicStore> {
        JournalAccess {
            store: &mut self.store,
            binding: &self.binding,
            context: &self.context,
        }
    }
    pub fn safety_generation(&self) -> Result<u64> {
        let mut store = self.store.clone();
        JournalAccess {
            store: &mut store,
            binding: &self.binding,
            context: &self.context,
        }
        .safety_generation()
    }
    pub fn cursor(&self) -> Result<R1JournalCursor> {
        let mut store = self.store.clone();
        JournalAccess {
            store: &mut store,
            binding: &self.binding,
            context: &self.context,
        }
        .cursor()
    }
    pub fn fence(&mut self, generation: u64) -> Result<u64> {
        self.access().fence(generation)
    }
    pub fn fence_through_round(&mut self, generation: u64, round: u64) -> Result<u64> {
        self.access().fence_through_round(generation, round)
    }
    pub fn reserve_ordinary(
        &mut self,
        h: &R1Header,
        m: &R1AuthorityMember,
        g: u64,
        parent: Option<&super::VerifiedR1QuorumCertificate>,
        lock: Option<&super::R1CertifiedLock>,
    ) -> Result<R1ReservationOutcome> {
        self.access().reserve_ordinary(h, m, g, parent, lock)
    }
    /// Low-level durability mechanism. Native SDK integration must privately
    /// complete its original signature before exposing release bytes.
    pub fn complete_and_release(
        &mut self,
        r: &R1ApprovalReservation,
        s: &[u8],
        v: &impl R1ConsensusVerifier,
    ) -> Result<R1ReleasedApproval> {
        self.access().complete_and_release(r, s, v)
    }
    pub fn suppress(&mut self, r: &R1ApprovalReservation) -> Result<()> {
        self.access().suppress(r)
    }
    pub fn commit_finalized(
        &mut self,
        a: &VerifiedR1FinalizedAnchor,
        c: &R1JournalCursor,
    ) -> Result<R1JournalCursor> {
        self.access().commit_finalized(a, c)
    }
    /// Storage orchestration only, never a caller-supplied signing authority.
    /// Native SDK must consume this SAME writer, privately finish its signature
    /// and the same durable outbox before returning any released signature bytes.
    pub fn with_held_writer<T>(
        &mut self,
        effect: impl FnOnce(&mut R1HeldJournal<'_, '_>) -> Result<T>,
    ) -> Result<T> {
        let binding = &self.binding;
        let context = &self.context;
        self.store.with_exclusive_writer(|writer| {
            effect(&mut R1HeldJournal {
                access: JournalAccess {
                    store: writer,
                    binding,
                    context,
                },
            })
        })?
    }
}

/// A scoped view of the SAME journal under its existing retained writer lock.
/// No public constructor, Clone or ability to detach the writer from its scope.
pub struct R1HeldJournal<'a, 'store> {
    access: JournalAccess<'a, AtomicStoreWriter<'store>>,
}
impl<'store> R1HeldJournal<'_, 'store> {
    pub fn writer(&mut self) -> &mut AtomicStoreWriter<'store> {
        self.access.store
    }
    pub fn safety_generation(&self) -> Result<u64> {
        self.access.safety_generation()
    }
    pub fn cursor(&self) -> Result<R1JournalCursor> {
        self.access.cursor()
    }
    /// Independently verify native authority, parent ancestry and execution
    /// before the durable reservation and before any SDK computation.
    pub fn reserve_verified_ordinary(
        &mut self,
        h: &R1Header,
        m: &R1AuthorityMember,
        g: u64,
        parent: Option<&super::VerifiedR1QuorumCertificate>,
        lock: Option<&super::R1CertifiedLock>,
        verifier: &impl R1ConsensusVerifier,
    ) -> Result<R1ReservationOutcome> {
        let cursor = self.access.cursor()?;
        verifier.verify_finalized_extension(
            &self.access.binding.coordinate,
            cursor.height,
            &cursor.block,
            h,
        )?;
        let members = verifier.authenticate_authority(h)?;
        if members.iter().filter(|v| v.identity == m.identity).count() != 1 || !members.contains(m)
        {
            return Err(R1JournalError::Conflict);
        }
        verifier.verify_proposal_and_execution(h)?;
        self.access.reserve_ordinary(h, m, g, parent, lock)
    }
    pub fn suppress(&mut self, r: &R1ApprovalReservation) -> Result<()> {
        self.access.suppress(r)
    }
    pub fn fence(&mut self, g: u64) -> Result<u64> {
        self.access.fence(g)
    }
    /// Read SAME previously release-authorized output after private SDK completion.
    /// A pending reservation is never upgraded to a release by this method.
    pub fn released_ordinary(
        &mut self,
        h: &R1Header,
        m: &R1AuthorityMember,
    ) -> Result<R1ReleasedApproval> {
        self.access.check_context()?;
        let expected = self.access.slot(h, m, 0)?;
        let bytes = self
            .access
            .store
            .read_optional_bounded(slot_path(h.round))?
            .ok_or(R1JournalError::Conflict)?;
        let slot: Slot = decode(&bytes)?;
        self.access.validate_slot(&slot)?;
        if slot.suppressed
            || slot.header != expected.header
            || slot.message != expected.message
            || slot.subject != expected.subject
        {
            return Err(R1JournalError::Conflict);
        }
        let signature = slot.signature.ok_or(R1JournalError::Conflict)?;
        Ok(R1ReleasedApproval {
            message: slot.message,
            signature,
        })
    }
}
trait JournalBackend: GuardedTransactionBackend {
    fn read_optional_bounded(
        &self,
        path: impl AsRef<Path>,
    ) -> std::result::Result<Option<Vec<u8>>, StorageError>;
}
impl JournalBackend for AtomicStore {
    fn read_optional_bounded(
        &self,
        p: impl AsRef<Path>,
    ) -> std::result::Result<Option<Vec<u8>>, StorageError> {
        AtomicStore::read_optional_bounded(self, p)
    }
}
impl JournalBackend for AtomicStoreWriter<'_> {
    fn read_optional_bounded(
        &self,
        p: impl AsRef<Path>,
    ) -> std::result::Result<Option<Vec<u8>>, StorageError> {
        AtomicStoreWriter::read_optional_bounded(self, p)
    }
}
struct JournalAccess<'a, B: JournalBackend> {
    store: &'a mut B,
    binding: &'a R1JournalBinding,
    context: &'a Vec<u8>,
}
impl<B: JournalBackend> JournalAccess<'_, B> {
    pub fn safety_generation(&self) -> Result<u64> {
        Ok(self.safety()?.0)
    }
    fn safety(&self) -> Result<(u64, Vec<u8>)> {
        self.check_context()?;
        let bytes = self
            .store
            .read_optional_bounded(SAFETY)?
            .ok_or(R1JournalError::Corrupt)?;
        let s: Safety = decode(&bytes)?;
        Ok((s.generation, bytes))
    }
    fn check_context(&self) -> Result<()> {
        if self.store.read_optional_bounded(CONTEXT)?.as_deref() != Some(self.context.as_slice()) {
            return Err(R1JournalError::Conflict);
        }
        Ok(())
    }
    /// Increment before any native lock/authority/pass transition. A pending
    /// computation from the old generation cannot subsequently be released.
    pub fn fence(&mut self, expected_generation: u64) -> Result<u64> {
        let (generation, bytes) = self.safety()?;
        if generation != expected_generation {
            return Err(R1JournalError::Fenced);
        }
        let next = generation.checked_add(1).ok_or(R1JournalError::Corrupt)?;
        let mut tx = StorageTransaction::new(4096)?;
        let mut updated: Safety = decode(&bytes)?;
        updated.generation = next;
        tx.put(SAFETY, encode(&updated)?)?;
        tx.commit_guarded(
            self.store,
            &[
                guard(CONTEXT, Some(self.context.to_vec())),
                guard(SAFETY, Some(bytes)),
            ],
        )?;
        Ok(next)
    }
    pub fn reserve_ordinary(
        &mut self,
        header: &R1Header,
        member: &R1AuthorityMember,
        expected_safety_generation: u64,
        parent: Option<&super::VerifiedR1QuorumCertificate>,
        lock: Option<&super::R1CertifiedLock>,
    ) -> Result<R1ReservationOutcome> {
        let mut slot = self.slot(header, member, expected_safety_generation)?;
        let path = slot_path(header.round);
        let (generation, safety) = self.safety()?;
        let finalized = self.store.read_optional_bounded(CURSOR)?;
        let finalized_height = self.cursor()?.height;
        let existing = self.store.read_optional_bounded(&path)?;
        if let Some(bytes) = existing {
            let old: Slot = decode(&bytes)?;
            self.validate_slot(&old)?;
            if old.header != slot.header
                || old.message != slot.message
                || old.subject != slot.subject
            {
                return Err(R1JournalError::Conflict);
            }
            // Previously authorized output survives a later fence; it is replay,
            // never permission for another cryptographic computation.
            if let Some(signature) = old.signature {
                return Ok(R1ReservationOutcome::Released(R1ReleasedApproval {
                    message: old.message,
                    signature,
                }));
            }
            if header.height <= finalized_height
                || old.suppressed
                || old.safety_generation != generation
                || generation != expected_safety_generation
            {
                return Err(R1JournalError::Fenced);
            }
            return Ok(R1ReservationOutcome::Pending(R1ApprovalReservation {
                context: self.context.to_vec(),
                path,
                slot: old,
                original: bytes,
            }));
        }
        if generation != expected_safety_generation || header.height <= finalized_height {
            return Err(R1JournalError::Fenced);
        }
        let mut next: Safety = decode(&safety)?;
        if next.last_approval_round.is_some_and(|r| header.round <= r)
            || next.pass_fence.is_some_and(|r| header.round <= r)
        {
            return Err(R1JournalError::Fenced);
        }
        if next.lock.is_some() && lock.is_none() {
            return Err(R1JournalError::Conflict);
        }
        self.safe_parent_and_lock(header, parent, lock, &mut next)?;
        slot.parent_qc = parent.map(|q| q.canonical_qc_bytes().to_vec());
        next.generation = generation.checked_add(1).ok_or(R1JournalError::Corrupt)?;
        next.last_approval_round = Some(header.round);
        slot.safety_generation = next.generation;
        let original = encode(&slot)?;
        let mut tx = StorageTransaction::new(MAX_RECORD)?;
        tx.put(path.clone(), original.clone())?;
        tx.put(SAFETY, encode(&next)?)?;
        tx.commit_guarded(
            self.store,
            &[
                guard(CONTEXT, Some(self.context.to_vec())),
                guard(SAFETY, Some(safety)),
                guard(path.clone(), None),
                guard(CURSOR, finalized),
            ],
        )?;
        Ok(R1ReservationOutcome::Pending(R1ApprovalReservation {
            context: self.context.to_vec(),
            path,
            slot,
            original,
        }))
    }
    /// A local monotonic release fence, not a pass vote/certificate or authority transition.
    pub fn fence_through_round(
        &mut self,
        expected_generation: u64,
        through_round: u64,
    ) -> Result<u64> {
        let (generation, bytes) = self.safety()?;
        if generation != expected_generation {
            return Err(R1JournalError::Fenced);
        }
        let mut next: Safety = decode(&bytes)?;
        if next.pass_fence.is_some_and(|r| through_round < r) {
            return Err(R1JournalError::Fenced);
        }
        next.pass_fence = Some(through_round);
        next.generation = generation.checked_add(1).ok_or(R1JournalError::Corrupt)?;
        let mut tx = StorageTransaction::new(MAX_RECORD)?;
        tx.put(SAFETY, encode(&next)?)?;
        tx.commit_guarded(
            self.store,
            &[
                guard(CONTEXT, Some(self.context.to_vec())),
                guard(SAFETY, Some(bytes)),
            ],
        )?;
        Ok(next.generation)
    }
    fn safe_parent_and_lock(
        &self,
        h: &R1Header,
        parent: Option<&super::VerifiedR1QuorumCertificate>,
        lock: Option<&super::R1CertifiedLock>,
        next: &mut Safety,
    ) -> Result<()> {
        let parent_header = if let Some(q) = parent {
            let p = &q.certificate().header;
            self.same_authority(p)?;
            if h.consensus_parent != p.parent_subject()?
                || h.ledger_parent != p.block_digest()?
                || h.execution.pre_state != p.execution.post_state
            {
                return Err(R1JournalError::Conflict);
            }
            Some(p)
        } else {
            if h.height != 1 || next.lock.is_some() {
                return Err(R1JournalError::Conflict);
            }
            None
        };
        let previous_lock = next
            .lock
            .as_ref()
            .map(|q| super::R1QuorumCertificate::decode_canonical(&q[0]))
            .transpose()?;
        if let Some(l) = lock {
            self.same_authority(l.header())?;
            if let Some(old) = &previous_lock {
                if l.header().round < old.header.round
                    || (l.header().round == old.header.round
                        && l.header().block_digest()? != old.header.block_digest()?)
                {
                    return Err(R1JournalError::Conflict);
                }
            }
            next.lock = Some([
                l.certificates()[0].canonical_qc_bytes().to_vec(),
                l.certificates()[1].canonical_qc_bytes().to_vec(),
            ]);
        }
        if let Some(bytes) = &next.lock {
            let locked = super::R1QuorumCertificate::decode_canonical(&bytes[0])?;
            self.same_authority(&locked.header)?;
            let p = parent_header.ok_or(R1JournalError::Conflict)?;
            // Direct extension is proven by equality; a higher *verified* parent
            // QC satisfies the distinct higher-parent rule. Height alone never does.
            if p.round < locked.header.round
                || (p.round == locked.header.round
                    && p.block_digest()? != locked.header.block_digest()?)
            {
                return Err(R1JournalError::Conflict);
            }
        }
        Ok(())
    }
    fn same_authority(&self, h: &R1Header) -> Result<()> {
        h.coordinate
            .ensure_matches(&self.binding.coordinate)
            .map_err(|_| R1JournalError::Conflict)?;
        if h.authority != self.binding.authority
            || h.protocol_profile != self.binding.protocol
            || h.epoch != self.binding.epoch
        {
            return Err(R1JournalError::Conflict);
        }
        Ok(())
    }
    fn slot(&self, h: &R1Header, m: &R1AuthorityMember, generation: u64) -> Result<Slot> {
        h.coordinate
            .ensure_matches(&self.binding.coordinate)
            .map_err(|_| R1JournalError::Conflict)?;
        if h.protocol_profile != self.binding.protocol
            || h.authority != self.binding.authority
            || h.epoch != self.binding.epoch
            || m.identity != self.binding.identity
            || m.key_id != self.binding.key_id
            || m.key_version != self.binding.key_version
            || m.weight == 0
            || m.signature_bytes != 3309
        {
            return Err(R1JournalError::Conflict);
        }
        let message = R1QuorumCertificate {
            header: h.clone(),
            approvals: vec![],
        }
        .approval_message(m)?;
        Ok(Slot {
            header: h.canonical_bytes()?,
            message,
            subject: h.block_digest()?.to_vec(),
            safety_generation: generation,
            parent_qc: None,
            suppressed: false,
            signature: None,
        })
    }
    fn validate_slot(&self, s: &Slot) -> Result<R1Header> {
        let mut r = Reader::new(&s.header, 4096)?;
        let h = R1Header::decode(&mut r)?;
        r.finish()?;
        if h.canonical_bytes() != Ok(s.header.clone())
            || h.block_digest()?.as_slice() != s.subject
            || s.signature.as_ref().is_some_and(|b| b.len() != 3309)
            || (s.suppressed && s.signature.is_some())
        {
            return Err(R1JournalError::Corrupt);
        }
        Ok(h)
    }
    /// Holds no signer callback. The SAME complete native verifier must check
    /// the exact reserved statement and original APQE signature before CAS.
    pub fn complete_and_release(
        &mut self,
        reservation: &R1ApprovalReservation,
        signature: &[u8],
        verifier: &impl R1ConsensusVerifier,
    ) -> Result<R1ReleasedApproval> {
        if reservation.context != *self.context || signature.len() != 3309 {
            return Err(R1JournalError::Conflict);
        }
        let h = self.validate_slot(&reservation.slot)?;
        // Bind the entire independent verification to the ORIGINAL snapshot.
        // A finality/fence transition during verification must fail the CAS.
        let (generation, safety) = self.safety()?;
        let finalized = self.store.read_optional_bounded(CURSOR)?;
        let cursor = self.cursor_from_bytes(finalized.as_deref())?;
        if generation != reservation.slot.safety_generation || h.height <= cursor.height {
            return Err(R1JournalError::Fenced);
        }
        verifier.verify_finalized_extension(
            &self.binding.coordinate,
            cursor.height,
            &cursor.block,
            &h,
        )?;
        let members = verifier.authenticate_authority(&h)?;
        let mut matching = members
            .iter()
            .filter(|m| m.identity == self.binding.identity);
        let member = matching.next().ok_or(R1JournalError::Conflict)?;
        if matching.next().is_some() {
            return Err(R1JournalError::Conflict);
        }
        let expected = self.slot(&h, member, reservation.slot.safety_generation)?;
        if expected.header != reservation.slot.header
            || expected.message != reservation.slot.message
            || expected.subject != reservation.slot.subject
            || reservation.slot.suppressed
            || reservation.slot.signature.is_some()
        {
            return Err(R1JournalError::Conflict);
        }
        verifier.verify_proposal_and_execution(&h)?;
        verifier.verify_approval(member, &reservation.slot.message, signature)?;
        // Reconstruct authenticated native evidence after recovery; persisted
        // bytes and numeric lock rounds themselves never become authority.
        let mut state: Safety = decode(&safety)?;
        let parent = reservation
            .slot
            .parent_qc
            .as_ref()
            .map(|b| super::R1QuorumCertificate::decode_canonical(b)?.into_verified(verifier))
            .transpose()?;
        let lock = state
            .lock
            .as_ref()
            .map(|q| {
                super::R1CertifiedLock::from_verified_pair(
                    super::R1QuorumCertificate::decode_canonical(&q[0])?.into_verified(verifier)?,
                    super::R1QuorumCertificate::decode_canonical(&q[1])?.into_verified(verifier)?,
                )
            })
            .transpose()?;
        self.safe_parent_and_lock(&h, parent.as_ref(), lock.as_ref(), &mut state)?;
        if state.last_approval_round != Some(h.round)
            || state.pass_fence.is_some_and(|r| h.round <= r)
        {
            return Err(R1JournalError::Fenced);
        }
        let mut completed = reservation.slot.clone();
        completed.signature = Some(signature.to_vec());
        let mut tx = StorageTransaction::new(MAX_RECORD)?;
        tx.put(reservation.path.clone(), encode(&completed)?)?;
        tx.commit_guarded(
            self.store,
            &[
                guard(CONTEXT, Some(self.context.to_vec())),
                guard(SAFETY, Some(safety)),
                guard(reservation.path.clone(), Some(reservation.original.clone())),
                guard(CURSOR, finalized),
            ],
        )?;
        Ok(R1ReleasedApproval {
            message: completed.message,
            signature: signature.to_vec(),
        })
    }
    pub fn suppress(&mut self, reservation: &R1ApprovalReservation) -> Result<()> {
        if reservation.context != *self.context {
            return Err(R1JournalError::Conflict);
        }
        let mut next = reservation.slot.clone();
        next.suppressed = true;
        let mut tx = StorageTransaction::new(MAX_RECORD)?;
        tx.put(reservation.path.clone(), encode(&next)?)?;
        tx.commit_guarded(
            self.store,
            &[
                guard(CONTEXT, Some(self.context.to_vec())),
                guard(reservation.path.clone(), Some(reservation.original.clone())),
            ],
        )?;
        Ok(())
    }
    pub fn cursor(&self) -> Result<R1JournalCursor> {
        self.check_context()?;
        let bytes = self.store.read_optional_bounded(CURSOR)?;
        self.cursor_from_bytes(bytes.as_deref())
    }
    fn cursor_from_bytes(&self, bytes: Option<&[u8]>) -> Result<R1JournalCursor> {
        match bytes {
            None => Ok(R1JournalCursor {
                height: 0,
                block: self.binding.coordinate.genesis.digest,
            }),
            Some(bytes) => {
                let r: Finalized = decode(bytes)?;
                if r.height == 0
                    || r.block.len() != 48
                    || r.state.len() != 48
                    || r.receipts.len() != 48
                    || r.original_proof.is_empty()
                {
                    return Err(R1JournalError::Corrupt);
                }
                Ok(R1JournalCursor {
                    height: r.height,
                    block: r.block.try_into().map_err(|_| R1JournalError::Corrupt)?,
                })
            }
        }
    }
    /// Evidence-only cursor; the native AIVM owner must independently commit
    /// canonical state/receipts atomically before its publication hooks.
    pub fn commit_finalized(
        &mut self,
        anchor: &VerifiedR1FinalizedAnchor,
        expected: &R1JournalCursor,
    ) -> Result<R1JournalCursor> {
        anchor
            .coordinate()
            .ensure_matches(&self.binding.coordinate)
            .map_err(|_| R1JournalError::Conflict)?;
        let prior = self.store.read_optional_bounded(CURSOR)?;
        if &self.cursor()? != expected {
            return Err(R1JournalError::Conflict);
        }
        let next = R1JournalCursor {
            height: anchor.height(),
            block: *anchor.block_digest(),
        };
        let proof = super::R1ThreeQcProof::decode(anchor.original_proof())?;
        let target = &proof.certificates[0].header;
        if anchor.height() == expected.height && anchor.block_digest() == &expected.block {
            let old: Finalized = decode(prior.as_deref().ok_or(R1JournalError::Corrupt)?)?;
            if old.state != anchor.state_root().as_slice()
                || old.receipts != anchor.receipts_root().as_slice()
            {
                return Err(R1JournalError::Conflict);
            }
            return Ok(next);
        }
        if expected.height.checked_add(1) != Some(anchor.height())
            || target.ledger_parent != expected.block
            || target.authority != self.binding.authority
            || target.protocol_profile != self.binding.protocol
            || target.epoch != self.binding.epoch
        {
            return Err(R1JournalError::Conflict);
        }
        let record = Finalized {
            height: anchor.height(),
            block: anchor.block_digest().to_vec(),
            state: anchor.state_root().to_vec(),
            receipts: anchor.receipts_root().to_vec(),
            original_proof: anchor.original_proof().to_vec(),
        };
        let mut tx = StorageTransaction::new(MAX_RECORD * 2)?;
        tx.put(CURSOR, encode(&record)?)?;
        // Immutable history and the cursor share the exact same durable transaction.
        let history = PathBuf::from(format!("r1-finality/{:020}.json", anchor.height()));
        tx.put(history.clone(), encode(&record)?)?;
        tx.commit_guarded(
            self.store,
            &[
                guard(CONTEXT, Some(self.context.to_vec())),
                guard(CURSOR, prior),
                guard(history, None),
            ],
        )?;
        Ok(next)
    }
}
fn slot_path(round: u64) -> PathBuf {
    PathBuf::from(format!("r1-ordinary/{round:020}.json"))
}
fn guard(path: impl Into<PathBuf>, bytes: Option<Vec<u8>>) -> StoragePrecondition {
    StoragePrecondition {
        relative_path: path.into(),
        required: bytes.map_or(RequiredRecord::Missing, RequiredRecord::Exact),
    }
}
fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|_| R1JournalError::Corrupt)
}
fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    serde_json::from_slice(bytes).map_err(|_| R1JournalError::Corrupt)
}
#[cfg(test)]
#[path = "journal_tests.rs"]
mod tests;
