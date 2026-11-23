//! Phase-one recovery of an original encrypted member. Donor completion,
//! reveal shares and finalized flags never grant local lifecycle authority.
use super::*;
use crate::services::processing_proposals::ProcessingProposalInputs;
use crate::services::processing_store::PendingProcessingIdentity;
use serde::Deserialize;
use synergy_etdag::execution::CandidateProtectedMaterial;
use synergy_posy::SimplifiedQuorumCertificate;

const MAX_INPUT: u64 = 8 * 1024 * 1024;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CertifiedOrder {
    version: u32,
    namespace: EtdagDigest,
    inputs: ProcessingProposalInputs,
    validation: ProposalValidationCertificate,
    qc: SimplifiedQuorumCertificate,
}
#[derive(Deserialize)]
struct OriginalContext {
    context: ProcessingContext,
}
fn original_context(bytes: &[u8]) -> Result<ProcessingContext, String> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_INPUT {
        return Err("historical original exceeds bound".into());
    }
    serde_json::from_slice::<OriginalContext>(bytes)
        .map(|v| v.context)
        .map_err(|e| e.to_string())
}

/// The expected QC MUST come from the recipient's verified durable finality.
/// The protected material binds the complete member group, rather than merely
/// accepting an uncommitted group attached to otherwise valid donor QCs.
#[allow(clippy::too_many_arguments)] // Explicit independently authenticated inputs.
fn recover_with<A: ProcessingAdmissionRecord + ProcessingVertexAdmission + Clone>(
    pending: &mut PendingProcessingStore<A>,
    source: &NativeProcessingContext<'_>,
    authority: &VerifiedAuthority,
    original: &[u8],
    progress: &[u8],
    order: &[u8],
    material: &CandidateProtectedMaterial,
    expected: &SimplifiedQuorumCertificate,
    verifier: &impl ProcessingAdmissionAuthenticator<A>,
) -> Result<PendingProcessingIdentity, String> {
    if order.is_empty() || order.len() as u64 > MAX_INPUT {
        return Err("historical order exceeds bound".into());
    }
    let certified: CertifiedOrder = serde_json::from_slice(order).map_err(|e| e.to_string())?;
    let inputs = &certified.inputs;
    expected
        .verify(&authority.epoch, &authority.registry, authority)
        .map_err(|e| e.to_string())?;
    certified
        .validation
        .verify(&authority.epoch, &authority.registry, authority)
        .map_err(|e| e.to_string())?;
    let CandidateProtectedMaterial::Processing(material) = material else {
        return Err("historical order requires native processing material".into());
    };
    let group = inputs
        .ordered_group
        .as_ref()
        .ok_or("historical order has no group")?;
    if certified.version != 1
        || certified.qc != *expected
        || inputs.context != expected.context
        || inputs.block_id != expected.block_id
        || inputs.parent != expected.parent
        || inputs.protected_execution_root != expected.protected_execution_root
        || certified.validation.candidate != expected.subject().map_err(|e| e.to_string())?
        || !inputs.certified_ancestors.is_empty()
        || material.height != expected.context.height
        || material.namespace_root != certified.namespace
        || group.namespace_root != certified.namespace
        || material.ordered_group.as_ref()
            != Some(&group.commitment().map_err(|e| format!("{e:?}"))?)
        || synergy_block::hash_block_bytes(
            &material.commitment_bytes().map_err(|e| format!("{e:?}"))?,
        ) != expected.protected_execution_root
    {
        return Err("historical order differs from exact local certified material".into());
    }
    pending
        .recover_ordered_member(
            original,
            progress,
            verifier,
            |context, admission, evidence, budget| {
                verifier.verify_progress(context, admission, evidence, budget)?;
                let v = vertex(admission, evidence);
                // Parentless records are handled here; dependent DAG records require
                // actual native retained parents, never donor-provided replacements.
                let verified = NativeProcessingVertex::verify_authenticated(
                    source,
                    &v,
                    Some(evidence
                        .availability
                        .as_ref()
                        .ok_or("historical member lacks availability")?),
                    &[],
                    budget,
                    |original| verifier.verify(context, source.persisted_authorization_timestamp()?, original),
                )?;
                if group
                    .members
                    .iter()
                    .filter(|m| *m == verified.member())
                    .count()
                    != 1
                {
                    return Err(
                        "historical member is absent or duplicated in certified group".into(),
                    );
                }
                Ok(())
            },
        )
        .map_err(|e| e.to_string())
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
fn recover(
    pending: &mut PendingProcessingStore,
    source: &NativeProcessingContext<'_>,
    authority: &VerifiedAuthority,
    original: &[u8],
    progress: &[u8],
    order: &[u8],
    material: &CandidateProtectedMaterial,
    expected: &SimplifiedQuorumCertificate,
) -> Result<PendingProcessingIdentity, String> {
    let verifier = NativeProcessingProgressRecovery { source, reveal_parent: None, dag_parents: &[] };
    recover_with(pending, source, authority, original, progress, order, material, expected, &verifier)
}

impl EtdagService {
    /// One fixed bounded inbox under the selected data owner. A privileged
    /// canonical operator stages public inputs; paths never come from RPC/env.
    pub(super) fn recover_historical_member(
        &self,
        work: &mut ProcessingWork,
    ) -> Result<(), String> {
        let inbox = self.pipeline_root.join("historical-recovery");
        if !inbox.try_exists().map_err(|e| e.to_string())? {
            return Ok(());
        }
        if inbox.canonicalize().map_err(|e| e.to_string())? != inbox
            || !std::fs::symlink_metadata(&inbox)
                .map_err(|e| e.to_string())?
                .is_dir()
        {
            return Err("historical recovery inbox must be a direct contained directory".into());
        }
        let order_path = inbox.join("order.json");
        let stamp = crate::services::apqe_transport::Stamp::capture(&order_path)?;
        if work.recovered_order.as_ref() == Some(&stamp) {
            return Ok(());
        }
        let _permit = self
            .ingress
            .world_budget()
            .reserve(4 * MAX_INPUT as usize * 4)
            .map_err(|e| e.to_string())?;
        let read =
            |name: &str| crate::services::apqe_transport::read(&inbox.join(name), MAX_INPUT, false);
        let original = read("original.json")?;
        let progress = read("progress.json")?;
        let order = read("order.json")?;
        let material = read("material.json")?;
        let certified: CertifiedOrder =
            serde_json::from_slice(&order).map_err(|e| e.to_string())?;
        let Some((_, witness)) = self
            .ingress
            .finalized_record_with_witness(certified.qc.context.height)?
        else {
            return Ok(());
        };
        let context = original_context(&original)?;
        let source = work
            .verifier
            .source(&context, self.ingress.world_budget())?;
        let material = serde_json::from_slice(&material).map_err(|e| e.to_string())?;
        recover_with(
            &mut work.pending,
            &source,
            &self.authority,
            &original,
            &progress,
            &order,
            &material,
            &witness[0],
            &work.verifier,
        )?;
        // If a concurrent operator replaces a file, recovery still admitted
        // only fully authenticated facts. Do not mark a changed inbox complete.
        if stamp.unchanged() {
            work.recovered_order = Some(stamp);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};
    struct Scratch(PathBuf);
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn scratch() -> Scratch {
        let p = std::env::temp_dir().join(format!(
            "native-historical-member-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&p).unwrap();
        Scratch(p)
    }
    fn copy_source(from: &Path, to: &Path) {
        for name in ["candidate", "candidate-world"] {
            std::fs::create_dir_all(to.join(name)).unwrap();
            for p in std::fs::read_dir(from.join(name)).unwrap() {
                let p = p.unwrap().path();
                assert!(p.is_file() && !p.is_symlink());
                std::fs::copy(&p, to.join(name).join(p.file_name().unwrap())).unwrap();
            }
        }
    }
    #[test]
    #[ignore = "requires exact retained signed public Canary artifacts and native APQE provider"]
    fn native_historical_order_member_recovers_atomically_without_donor_reveal() {
        let artifacts = PathBuf::from(
            std::env::var("SYNERGY_HISTORICAL_RECOVERY_FIXTURE")
                .expect("explicit public artifact directory"),
        );
        let base = artifacts.parent().unwrap();
        let config =
            synergy_config::load(base.join("canary-tail.spFFvzKO/local/config/node.json")).unwrap();
        let authority = crate::services::authority::load(&config).unwrap().unwrap();
        assert_eq!(authority.epoch.epoch, 2);
        let transition = crate::services::authority::load_transition_context(&config, &authority)
            .unwrap()
            .unwrap();
        let original = std::fs::read(artifacts.join("etdag-donor-val2/slots/0001.json")).unwrap();
        let progress =
            std::fs::read(artifacts.join("etdag-donor-val2/progress/0001.json")).unwrap();
        let order =
            std::fs::read(artifacts.join("etdag-certified/00000000000000017641.json")).unwrap();
        let certified: CertifiedOrder = serde_json::from_slice(&order).unwrap();
        assert_eq!(certified.qc.context.height, 17641);
        assert_eq!(
            certified
                .inputs
                .ordered_group
                .as_ref()
                .unwrap()
                .members
                .len(),
            1
        );
        let raw =
            std::fs::read(artifacts.join("etdag-candidate/candidate/00000000000000017641.json"))
                .unwrap();
        let candidate: serde_json::Value = serde_json::from_slice(&raw[8..]).unwrap();
        let material: CandidateProtectedMaterial =
            serde_json::from_value(candidate["protected_material"].clone()).unwrap();
        let context = original_context(&original).unwrap();
        let scratch = scratch();
        let source_root = scratch.0.join("source");
        copy_source(&artifacts.join("etdag-source-9998"), &source_root);
        let budget = WorldResourceBudget::new(512 * 1024 * 1024);
        let candidate = BudgetedCandidateStore::new_budgeted(&source_root, budget.clone())
            .unwrap()
            .get_budgeted(9998)
            .unwrap()
            .unwrap();
        #[derive(Deserialize)]
        struct SourceWitness {
            certificates: [SimplifiedQuorumCertificate; 3],
        }
        let witness: SourceWitness = serde_json::from_slice(
            &std::fs::read(artifacts.join("etdag-source-9998/witness.json")).unwrap(),
        )
        .unwrap();
        let source = NativeProcessingContext::verify_owned_finalized_with_transition(
            &authority,
            &context,
            candidate,
            &witness.certificates,
            &budget,
            Some(&transition),
        )
        .unwrap();
        let verifier = NativeProcessingProgressRecovery {
            source: &source,
            reveal_parent: None,
            dag_parents: &[],
        };
        let namespace = processing_namespace(&authority, &budget).unwrap();
        let limits = ProcessingStoreLimits {
            slots: 4,
            completion_bytes_per_item: 64 * 1024 * 1024,
        };
        let pending_root = scratch.0.join("pending");
        let mut pending = PendingProcessingStore::open(
            &pending_root,
            namespace.clone(),
            limits,
            &budget,
            &verifier,
        )
        .unwrap();
        let later: CertifiedOrder = serde_json::from_slice(
            &std::fs::read(artifacts.join("etdag-certified/00000000000000017642.json")).unwrap(),
        )
        .unwrap();
        assert!(recover(
            &mut pending,
            &source,
            &authority,
            &original,
            &progress,
            &order,
            &material,
            &later.qc
        )
        .is_err());
        let mut wrong_order: serde_json::Value = serde_json::from_slice(&order).unwrap();
        wrong_order["inputs"]["ordered_group"]["group_number"] = serde_json::json!(999);
        assert!(recover(
            &mut pending,
            &source,
            &authority,
            &original,
            &progress,
            &serde_json::to_vec(&wrong_order).unwrap(),
            &material,
            &certified.qc
        )
        .is_err());
        let mut tampered: serde_json::Value = serde_json::from_slice(&progress).unwrap();
        tampered["evidence"]["author_signature"][0] = serde_json::json!(0);
        assert!(recover(
            &mut pending,
            &source,
            &authority,
            &original,
            &serde_json::to_vec(&tampered).unwrap(),
            &order,
            &material,
            &certified.qc
        )
        .is_err());
        assert_eq!(pending.pending_identities().count(), 0);
        let id = recover(
            &mut pending,
            &source,
            &authority,
            &original,
            &progress,
            &order,
            &material,
            &certified.qc,
        )
        .unwrap();
        assert_eq!(pending.pending_identities().count(), 1);
        assert_eq!(
            recover(
                &mut pending,
                &source,
                &authority,
                &original,
                &progress,
                &order,
                &material,
                &certified.qc
            )
            .unwrap(),
            id
        );
        pending
            .with_progress(&id.envelope_id, &verifier, |_, p, _| {
                let p = p.unwrap();
                assert!(p.availability.is_some());
                assert!(p.reveal_validation.is_none());
                assert!(p.shares.is_empty());
                Ok(())
            })
            .unwrap();
        drop(pending);
        let mut pending =
            PendingProcessingStore::open(&pending_root, namespace, limits, &budget, &verifier)
                .unwrap();
        assert_eq!(pending.pending_identities().count(), 1);
        assert_eq!(
            recover(
                &mut pending,
                &source,
                &authority,
                &original,
                &progress,
                &order,
                &material,
                &certified.qc
            )
            .unwrap(),
            id
        );
        // Corruption after acceptance must not become idempotent success.
        let slot = pending_root.join("slots/0000.json");
        let mut bytes = std::fs::read(&slot).unwrap();
        bytes[0] ^= 1;
        std::fs::write(&slot, bytes).unwrap();
        assert!(recover(
            &mut pending,
            &source,
            &authority,
            &original,
            &progress,
            &order,
            &material,
            &certified.qc
        )
        .is_err());
    }
}
