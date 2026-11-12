//! Sparse proof dependencies of the approved processing profile. These pins
//! preserve native replay/retirement evidence; they confer no consensus power.
use super::*;

// Reclaim only positively unreferenced, finalized dependencies before any new
// source pin or retry can return resource backpressure. Otherwise a full index
// containing obsolete pins can indefinitely starve its own bounded cleanup.
fn release_obsolete_processing_pins(
    candidate_store: &mut CandidateStore,
    state_store: &mut FinalizedStateStore,
    cursor: &mut usize,
    references: &std::collections::BTreeSet<u64>,
    finalized_height: u64,
) -> Result<bool, String> {
    const MAX_EXAMINED: usize = 64;
    const MAX_RELEASED: usize = 4;
    let pins = candidate_store.pinned_descriptors();
    // Only four compact identities are cloned, under the registered owner's
    // existing bounded metadata scratch. No World or historical range loads.
    let mut release = Vec::with_capacity(MAX_RELEASED);
    if !pins.is_empty() {
        let mut next_cursor = *cursor % pins.len();
        for _ in 0..pins.len().min(MAX_EXAMINED) {
            let pin = &pins[next_cursor];
            next_cursor = (next_cursor + 1) % pins.len();
            // A pin can be the parent of a consumption at height+1.
            // Keep it until that child can itself have finalized and ETDAG
            // has reconciled the matching durable execution fence.
            if pin
                .height
                .checked_add(1)
                .is_some_and(|height| height <= finalized_height)
                && !references.contains(&pin.height)
            {
                release.push((pin.height, pin.block_id.clone()));
                if release.len() == MAX_RELEASED {
                    break;
                }
            }
        }
        *cursor = next_cursor;
    } else {
        *cursor = 0;
    }
    for (height, block_id) in release {
        // Remove the state commitment first: if interrupted, the remaining
        // candidate descriptor still names this exact cleanup on restart.
        match state_store.unpin_processing_history(height) {
            Ok(()) => {}
            Err(synergy_state::StateError::ResourcePressure { .. }) => return Ok(false),
            Err(error) => return Err(format!("release processing state proof: {error:?}")),
        }
        match candidate_store.unpin(height, &block_id) {
            Ok(()) => {}
            Err(synergy_execution::CandidateResourceError::Resource(
                synergy_state::world_resources::WorldResourceError::Capacity { .. },
            )) => return Ok(false),
            Err(error) => return Err(error.to_string()),
        }
    }
    Ok(true)
}

impl ExecutionService {
    pub(super) fn pin_processing_candidate(
        &mut self,
        candidate: &ExecutionCandidate,
    ) -> Result<bool, String> {
        let synergy_etdag::execution::CandidateProtectedMaterial::Processing(material) =
            &candidate.protected_material
        else {
            return Ok(true);
        };
        let mut required = Vec::new();
        if material.ordered_group.is_some() {
            let (next, _, open) =
                synergy_execution::processing_order_tip(&self.state, &material.namespace_root)
                    .map_err(|error| error.to_string())?;
            if open && next > 1 {
                let previous = synergy_execution::processing_group_state(
                    &self.state,
                    &material.namespace_root,
                    next - 1,
                )
                .map_err(|error| error.to_string())?;
                if previous.remaining > 0 {
                    required.push(candidate.height);
                }
            }
        }
        if !material.selection.item_indices.is_empty() {
            required.push(candidate.height);
            required.push(
                candidate
                    .height
                    .checked_sub(1)
                    .ok_or("processing consumption at Genesis")?,
            );
        }
        required.sort_unstable();
        required.dedup();
        required.retain(|height| {
            !self
                .candidate_store
                .pinned_descriptors()
                .iter()
                .any(|pin| pin.height == *height)
        });
        if required.len() > self.candidate_store.remaining_pin_capacity() {
            return Ok(false);
        }
        for height in required {
            let stored;
            let value = if height == candidate.height {
                candidate
            } else {
                stored = match self.candidate_store.get_budgeted(height) {
                    Ok(Some(stored)) => stored,
                    Ok(None) => return Err("processing retirement parent is absent".into()),
                    Err(error) if candidate_resource_pressure(&error) => return Ok(false),
                    Err(error) => return Err(error.to_string()),
                };
                &stored
            };
            match self.candidate_store.pin_budgeted(value) {
                Ok(()) => {}
                Err(synergy_execution::CandidateResourceError::Resource(
                    synergy_state::world_resources::WorldResourceError::Capacity { .. },
                )) => return Ok(false),
                Err(error) => return Err(error.to_string()),
            }
        }
        Ok(true)
    }
    /// Positive ETDAG reconciliation is required before releasing sparse proof
    /// dependencies. A cold/unfinished owner publishes None, never an empty set.
    /// The execution owner is the sole creator/remover of these candidate pins.
    pub(super) fn cleanup_processing_proofs(&mut self) -> Result<(), String> {
        const MAX_RELEASED: usize = 4;
        let Some((references, _references_permit)) = self.ingress.processing_proof_references()?
        else {
            return Ok(());
        };
        let Some(owner) = self.processing.as_mut() else {
            return Ok(());
        };
        if !release_obsolete_processing_pins(
            &mut self.candidate_store,
            self.state_store
                .as_mut()
                .ok_or("processing cleanup lacks finalized state store")?,
            &mut owner.proof_cleanup_cursor,
            &references,
            self.finalized_height,
        )? {
            return Ok(());
        }
        if let Some(height) = self
            .processing
            .as_ref()
            .and_then(|owner| owner.source_pin_retry)
        {
            if references.contains(&height) {
                match self
                    .state_store
                    .as_mut()
                    .ok_or("processing source pin lacks finalized store")?
                    .pin_processing_history(height)
                {
                    Ok(()) => {}
                    Err(synergy_state::StateError::ResourcePressure { .. }) => return Ok(()),
                    Err(error) => {
                        return Err(format!(
                            "retry processing authorization state pin: {error:?}"
                        ))
                    }
                }
            }
            self.processing
                .as_mut()
                .expect("processing owner checked")
                .source_pin_retry = None;
        }
        // ETDAG also references immutable finalized authorization sources. Pin
        // those through this existing sole writer before canonical pruning can
        // remove their World; a reference itself grants no source authority.
        let mut created = 0;
        for height in references
            .iter()
            .copied()
            .filter(|height| *height > 0 && *height <= self.finalized_height)
        {
            if self
                .candidate_store
                .pinned_descriptors()
                .iter()
                .any(|pin| pin.height == height)
            {
                continue;
            }
            if created == MAX_RELEASED {
                break;
            }
            let Some((record, _)) = self.ingress.finalized_record_with_witness(height)? else {
                return Err("processing source pin lacks authenticated finality".into());
            };
            let candidate = match self.candidate_store.get_budgeted(height) {
                Ok(Some(candidate)) => candidate,
                Ok(None) => return Err("processing source pin candidate is absent".into()),
                Err(error) if candidate_resource_pressure(&error) => return Ok(()),
                Err(error) => return Err(error.to_string()),
            };
            if candidate.block_id != record.block_id
                || candidate.protected_execution_root != record.protected_execution_root
            {
                return Err("processing source pin differs from finalized candidate".into());
            }
            match self.candidate_store.pin_budgeted(&candidate) {
                Ok(()) => {
                    created += 1;
                }
                Err(synergy_execution::CandidateResourceError::Resource(
                    synergy_state::world_resources::WorldResourceError::Capacity { .. },
                )) => return Ok(()),
                Err(error) => return Err(error.to_string()),
            }
            match self
                .state_store
                .as_mut()
                .ok_or("processing source pin lacks finalized store")?
                .pin_processing_history(height)
            {
                Ok(()) => {}
                Err(synergy_state::StateError::ResourcePressure { .. }) => {
                    self.processing
                        .as_mut()
                        .ok_or("processing source pin owner is absent")?
                        .source_pin_retry = Some(height);
                    return Ok(());
                }
                Err(error) => return Err(format!("pin processing authorization state: {error:?}")),
            }
        }
        if let Some(retain) = self.retention_blocks {
            // Archive GC runs after ordinary canonical pruning and exact unpin.
            // The caller's current positive references plus all unreleased
            // descriptors protect every still-readable recovery dependency.
            let metadata_bytes = references
                .len()
                .checked_add(self.candidate_store.pinned_descriptors().len())
                .and_then(|count| count.checked_mul(256))
                .and_then(|bytes| bytes.checked_add(16 * 1024))
                .ok_or("processing archive protection accounting overflow")?;
            let _metadata = match self.ingress.world_budget().reserve(metadata_bytes) {
                Ok(permit) => permit,
                Err(synergy_state::world_resources::WorldResourceError::Capacity { .. }) => {
                    return Ok(())
                }
                Err(error) => return Err(error.to_string()),
            };
            let mut protected = references.as_ref().clone();
            protected.extend(
                self.candidate_store
                    .pinned_descriptors()
                    .iter()
                    .map(|pin| pin.height),
            );
            self.processing
                .as_ref()
                .expect("processing owner checked")
                .store
                .lock()
                .map_err(|_| "processing proposal journal lock poisoned")?
                .prune_archive(self.finalized_height, retain, &protected)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn processing_source_pin_capacity_reclaims_obsolete_before_admission() {
        let root = std::env::temp_dir().join(format!(
            "synergy-source-pin-capacity-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let candidates_root = root.join("candidates");
        std::fs::create_dir_all(candidates_root.join("candidate-pins")).unwrap();
        // Exercise the actual persisted maximum-size descriptor index. Payload
        // contents are not consulted for dependencies that remain protected.
        let maximum = 3 * 4096 + 16;
        let pins = (0..maximum)
            .map(|slot| {
                serde_json::json!({
                    "height": slot as u64 + 1, "block_id":"a".repeat(64),
                    "slot":slot, "bytes":1024, "root":"b".repeat(64)
                })
            })
            .collect::<Vec<_>>();
        std::fs::write(
            candidates_root.join("candidate-pins/index-v1.json"),
            serde_json::to_vec(&serde_json::json!({"version":1,"generation":1,"pins":pins}))
                .unwrap(),
        )
        .unwrap();
        let budget = synergy_state::world_resources::WorldResourceBudget::new(1024 * 1024 * 1024);
        let mut candidates =
            CandidateStore::new_budgeted(&candidates_root, budget.clone()).unwrap();
        let mut states =
            FinalizedStateStore::load_budgeted(root.join("states"), budget.clone()).unwrap();
        assert_eq!(candidates.remaining_pin_capacity(), 0);
        let height = maximum as u64 + 1;
        let material = synergy_etdag::execution::ProtectedProposalMaterial {
            material_version: 2,
            height,
            execution_root: synergy_etdag::EtdagDigest::from_domain_bytes("test", b"execution"),
            next_batch_root: synergy_etdag::EtdagDigest::from_domain_bytes("test", b"batch"),
            cutoff_boundary_root: synergy_etdag::EtdagDigest::from_domain_bytes("test", b"cutoff"),
        };
        let world = WorldState::default();
        let mut candidate = synergy_execution::ExecutionCandidate {
            resource_permit: None,
            height,
            block_id: String::new(),
            parent_block_id: "parent".into(),
            protected_execution_root: synergy_block::hash_block_bytes(
                &material.commitment_bytes().unwrap(),
            ),
            protected_material: material.into(),
            state_root: synergy_state::state_root(&world).unwrap(),
            transactions: vec![],
            receipts: vec![],
            state: Arc::new(world),
        };
        candidate.block_id = candidate.commitment_id().unwrap();
        let candidate = synergy_execution::decode_budgeted_candidate(
            &serde_json::to_vec(&candidate).unwrap(),
            &budget,
        )
        .unwrap();
        assert!(matches!(
            candidates.pin_budgeted(&candidate),
            Err(synergy_execution::CandidateResourceError::Resource(
                synergy_state::world_resources::WorldResourceError::Capacity { .. }
            ))
        ));
        let mut cursor = 0;
        // All live dependencies are protected even when pressure cannot progress.
        let live = (1..=height).collect::<BTreeSet<_>>();
        assert!(release_obsolete_processing_pins(
            &mut candidates,
            &mut states,
            &mut cursor,
            &live,
            height + 1
        )
        .unwrap());
        assert_eq!(candidates.remaining_pin_capacity(), 0);
        // A positive snapshot retains current, pending, requested and the newly
        // requested source. Four obsolete entries free admission on this poll.
        let references = BTreeSet::from([1, 2, 3, height]);
        cursor = 0;
        assert!(release_obsolete_processing_pins(
            &mut candidates,
            &mut states,
            &mut cursor,
            &references,
            height + 1
        )
        .unwrap());
        assert_eq!(candidates.remaining_pin_capacity(), 4);
        for protected in [1, 2, 3] {
            assert!(candidates
                .pinned_descriptors()
                .iter()
                .any(|p| p.height == protected));
        }
        candidates.pin_budgeted(&candidate).unwrap();
        assert!(candidates
            .pinned_descriptors()
            .iter()
            .any(|p| p.height == height));
        drop(candidates);
        let candidates = CandidateStore::new_budgeted(&candidates_root, budget).unwrap();
        for protected in references {
            assert!(candidates
                .pinned_descriptors()
                .iter()
                .any(|p| p.height == protected));
        }
        drop(candidates);
        drop(states);
        std::fs::remove_dir_all(root).unwrap();
    }
}
