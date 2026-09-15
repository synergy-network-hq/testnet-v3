use std::collections::BTreeSet;

use crate::{GenerationDecision, GenerationGate, RevocationSet, SnapshotError, VerifiedSnapshot};

#[derive(Debug, Default)]
pub struct TransportRegistryState {
    generation: GenerationGate,
    current: Option<VerifiedSnapshot>,
    revocations: RevocationSet,
}

impl TransportRegistryState {
    pub fn install(
        &mut self,
        snapshot: VerifiedSnapshot,
        active_identities: &[String],
    ) -> Result<GenerationDecision, SnapshotError> {
        snapshot
            .registry()
            .require_coverage(active_identities)
            .map_err(SnapshotError::Coverage)?;
        let decision = self.generation.check(snapshot.generation())?;
        if decision == GenerationDecision::Idempotent {
            let same = self
                .current
                .as_ref()
                .is_some_and(|current| current.registry().same_routes(snapshot.registry()));
            return same.then_some(decision).ok_or(SnapshotError::Equivocation {
                generation: snapshot.generation(),
            });
        }
        self.generation.commit(snapshot.generation())?;
        self.current = Some(snapshot);
        Ok(decision)
    }

    pub fn route_for(&self, identity: &str) -> Option<&crate::TransportRoute> {
        let snapshot = self.current.as_ref()?;
        if self.revocations.is_revoked(identity, snapshot.generation()) {
            return None;
        }
        snapshot.registry().route_for(identity)
    }

    pub fn revoke(
        &mut self,
        revocation: crate::Revocation,
        active_identities: &BTreeSet<String>,
    ) -> Result<(), crate::RegistryError> {
        if active_identities.contains(&revocation.identity) {
            return Err(crate::RegistryError::MissingActiveIdentities(vec![
                revocation.identity,
            ]));
        }
        self.revocations.insert(revocation)
    }
}
