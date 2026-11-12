//! Fixed per-pending-item sideband. Only native verification can authorize an
//! update; the original wallet JSON is never rewritten as reveal work advances.
use super::*;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProgressIndex {
    pub(super) root: EtdagDigest,
    pub(super) bytes: usize,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredProgress {
    version: u32,
    namespace_root: EtdagDigest,
    identity: PendingProcessingIdentity,
    admission_record_root: EtdagDigest,
    evidence: ProcessingProgressEvidence,
}
pub(super) fn path(slot: usize) -> String {
    format!("progress/{slot:04}.json")
}
#[allow(clippy::too_many_arguments)]
fn verify(
    bytes: &[u8],
    namespace: &EtdagDigest,
    original: &EtdagDigest,
    context: &ProcessingContext,
    admission: &WalletProcessingAdmission,
    verifier: &impl ProcessingAdmissionAuthenticator,
    budget: &Arc<WorldResourceBudget>,
    retained: bool,
) -> Result<StoredProgress, ProcessingStoreError> {
    let record: StoredProgress =
        serde_json::from_slice(bytes).map_err(|e| invalid(format!("processing progress: {e}")))?;
    if record.version != 1
        || &record.namespace_root != namespace
        || record.identity != identity(admission)
        || &record.admission_record_root != original
    {
        return Err(invalid(
            "processing progress differs from immutable original admission",
        ));
    }
    if retained {
        verifier.verify_retained_progress(context, admission, &record.evidence, budget)
    } else {
        verifier.verify_progress(context, admission, &record.evidence, budget)
    }
    .map_err(ProcessingStoreError::Verification)?;
    Ok(record)
}
#[allow(clippy::too_many_arguments)]
pub(super) fn recover(
    reader: &synergy_storage::AtomicStoreReader<'_>,
    slot: usize,
    namespace: &EtdagDigest,
    original: &EtdagDigest,
    context: &ProcessingContext,
    admission: &WalletProcessingAdmission,
    verifier: &impl ProcessingAdmissionAuthenticator,
    budget: &Arc<WorldResourceBudget>,
) -> Result<Option<ProgressIndex>, ProcessingStoreError> {
    let Some(size) = reader.optional_record_bytes(path(slot))? else {
        return Ok(None);
    };
    if size == 0 || size > MAX_SLOT_BYTES {
        return Err(invalid("processing progress exceeds bound"));
    }
    let _permit = budget.reserve(completion_reservation(size)?)?;
    let bytes = reader
        .with_maximum_bytes(size)
        .read_optional_bounded(path(slot))?
        .ok_or_else(|| invalid("missing processing progress"))?;
    if bytes == b"null" {
        return Ok(None);
    }
    verify(
        &bytes, namespace, original, context, admission, verifier, budget, false,
    )?;
    Ok(Some(ProgressIndex {
        root: encoded_root(&bytes),
        bytes: size,
    }))
}
impl PendingProcessingStore {
    /// Read already authenticated public reveal evidence without reopening a
    /// finalized worker. Reserve temporary decoding capacity from the shared
    /// pool; the quiescent item's released workspace is never grown again.
    pub(crate) fn with_finalized_progress<T>(
        &self,
        envelope: &EtdagDigest,
        action: impl FnOnce(
            &ProcessingProgressEvidence,
            &Arc<WorldResourceBudget>,
        ) -> Result<T, ProcessingStoreError>,
    ) -> Result<Option<T>, ProcessingStoreError> {
        let slot = self.progress_slot(envelope)?;
        let entry = self.slots[slot].as_ref().expect("located finalized slot");
        if entry.finalized.is_none() {
            return Err(invalid("retained reveal replay requires finalized work"));
        }
        let Some(index) = &entry.progress else {
            return Ok(None);
        };
        let decode = completion_reservation(index.bytes)?;
        let capacity = decode
            .checked_add(32 * synergy_network::protocol::DEFAULT_MAX_FRAME_BYTES)
            .and_then(|n| n.checked_add(128 * 1024))
            .ok_or(WorldResourceError::ArithmeticOverflow)?;
        let budget = self.budget.reserve(capacity)?.into_budget();
        let _decode = budget.reserve(decode)?;
        self.verify_finalized_record(slot, entry)?;
        // Index hashes were populated only by native verification or recovery.
        // Check the exact hash before decoding, then bind every stored identity.
        let bytes = self.read_progress(slot, index)?;
        let record: StoredProgress = serde_json::from_slice(&bytes)
            .map_err(|e| invalid(format!("retained reveal progress: {e}")))?;
        if record.version != 1
            || record.namespace_root != self.header.namespace_root
            || record.identity != entry.identity
            || record.admission_record_root != entry.encoded_root
        {
            return Err(invalid("retained reveal progress identity differs"));
        }
        action(&record.evidence, &budget).map(Some)
    }

    fn progress_slot(&self, envelope: &EtdagDigest) -> Result<usize, ProcessingStoreError> {
        self.slots
            .iter()
            .position(|entry| {
                entry
                    .as_ref()
                    .is_some_and(|entry| &entry.identity.envelope_id == envelope)
            })
            .ok_or_else(|| invalid("unknown processing progress envelope"))
    }
    pub(super) fn read_progress(
        &self,
        slot: usize,
        index: &ProgressIndex,
    ) -> Result<Vec<u8>, ProcessingStoreError> {
        self.store
            .inspect_consistent(|reader| -> Result<_, ProcessingStoreError> {
                if reader.optional_record_bytes(path(slot))? != Some(index.bytes) {
                    return Err(invalid("processing progress length changed"));
                }
                let bytes = reader
                    .with_maximum_bytes(index.bytes)
                    .read_optional_bounded(path(slot))?
                    .ok_or_else(|| invalid("missing processing progress"))?;
                if encoded_root(&bytes) != index.root {
                    return Err(invalid("processing progress bytes changed"));
                }
                Ok(bytes)
            })?
    }
    pub(crate) fn has_completion(&self, envelope: &EtdagDigest) -> bool {
        self.slots
            .iter()
            .flatten()
            .any(|entry| &entry.identity.envelope_id == envelope && entry.completion.is_some())
    }
    pub(crate) fn with_progress<T>(
        &mut self,
        envelope: &EtdagDigest,
        verifier: &impl ProcessingAdmissionAuthenticator,
        action: impl FnOnce(
            &WalletProcessingAdmission,
            Option<&ProcessingProgressEvidence>,
            &Arc<WorldResourceBudget>,
        ) -> Result<T, ProcessingStoreError>,
    ) -> Result<T, ProcessingStoreError> {
        let slot = self.progress_slot(envelope)?;
        let entry = self.slots[slot].as_ref().expect("located progress slot");
        if entry.finalized.is_some() {
            return Err(invalid("finalized processing work is quiescent"));
        }
        let _read = entry
            .workspace
            .reserve(read_reservation(entry.encoded_bytes)?)?;
        let bytes = self.read_entry(slot, entry)?;
        let pending: StoredPending =
            serde_json::from_slice(&bytes).map_err(|e| invalid(e.to_string()))?;
        let admission = verify_retained_stored(&pending, &self.header.namespace_root, verifier)?;
        let mut _decode = None;
        let record = match &entry.progress {
            None => None,
            Some(index) => {
                _decode = Some(
                    entry
                        .workspace
                        .reserve(completion_reservation(index.bytes)?)?,
                );
                Some(verify(
                    &self.read_progress(slot, index)?,
                    &self.header.namespace_root,
                    &entry.encoded_root,
                    &pending.context,
                    &admission,
                    verifier,
                    &entry.workspace,
                    true,
                )?)
            }
        };
        action(
            &admission,
            record.as_ref().map(|record| &record.evidence),
            &entry.workspace,
        )
    }
    pub(crate) fn update_progress(
        &mut self,
        envelope: &EtdagDigest,
        evidence: &ProcessingProgressEvidence,
        verifier: &impl ProcessingAdmissionAuthenticator,
    ) -> Result<(), ProcessingStoreError> {
        let slot = self.progress_slot(envelope)?;
        let entry = self.slots[slot].as_ref().expect("located progress slot");
        if entry.finalized.is_some() {
            return Err(invalid("finalized processing work is quiescent"));
        }
        let _read = entry
            .workspace
            .reserve(read_reservation(entry.encoded_bytes)?)?;
        let bytes = self.read_entry(slot, entry)?;
        let pending: StoredPending =
            serde_json::from_slice(&bytes).map_err(|e| invalid(e.to_string()))?;
        let admission = verify_retained_stored(&pending, &self.header.namespace_root, verifier)?;
        struct Counter(usize);
        impl std::io::Write for Counter {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                self.0 = self
                    .0
                    .checked_add(b.len())
                    .filter(|n| *n < MAX_SLOT_BYTES - 4096)
                    .ok_or_else(|| std::io::Error::other("processing progress exceeds bound"))?;
                Ok(b.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let _measure = entry.workspace.reserve(16 * 1024)?;
        let mut counter = Counter(0);
        serde_json::to_writer(&mut counter, evidence).map_err(|e| invalid(e.to_string()))?;
        let _encode = entry
            .workspace
            .reserve(completion_reservation(counter.0 + 4096)?)?;
        verifier
            .verify_progress(&pending.context, &admission, evidence, &entry.workspace)
            .map_err(ProcessingStoreError::Verification)?;
        if let Some(index) = &entry.progress {
            let _old = entry
                .workspace
                .reserve(completion_reservation(index.bytes)?)?;
            let record = verify(
                &self.read_progress(slot, index)?,
                &self.header.namespace_root,
                &entry.encoded_root,
                &pending.context,
                &admission,
                verifier,
                &entry.workspace,
                true,
            )?;
            if evidence == &record.evidence {
                return Ok(());
            }
            if !evidence.preserves(&record.evidence) {
                return Err(invalid(
                    "processing progress update rewrites accepted evidence",
                ));
            }
        }
        let bytes = encode(&StoredProgress {
            version: 1,
            namespace_root: self.header.namespace_root.clone(),
            identity: entry.identity.clone(),
            admission_record_root: entry.encoded_root.clone(),
            evidence: evidence.clone(),
        })?;
        if bytes.len() > counter.0 + 4096 {
            return Err(invalid("processing progress framing exceeded bound"));
        }
        let index = ProgressIndex {
            root: encoded_root(&bytes),
            bytes: bytes.len(),
        };
        self.replace_records(vec![(path(slot), bytes)])?;
        self.slots[slot]
            .as_mut()
            .expect("located progress slot")
            .progress = Some(index);
        Ok(())
    }
}
