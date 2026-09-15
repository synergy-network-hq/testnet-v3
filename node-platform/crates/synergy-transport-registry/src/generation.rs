#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GenerationDecision {
    Install,
    Idempotent,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GenerationGate {
    current: Option<u64>,
}

impl GenerationGate {
    pub fn current(self) -> Option<u64> {
        self.current
    }

    pub fn check(&self, generation: u64) -> Result<GenerationDecision, crate::SnapshotError> {
        if generation == 0 {
            return Err(crate::SnapshotError::InvalidDocument(
                "transport generation must be nonzero".into(),
            ));
        }
        match self.current {
            Some(current) if generation < current => Err(crate::SnapshotError::Rollback {
                received: generation,
                current,
            }),
            Some(current) if generation == current => Ok(GenerationDecision::Idempotent),
            _ => Ok(GenerationDecision::Install),
        }
    }

    pub fn commit(&mut self, generation: u64) -> Result<GenerationDecision, crate::SnapshotError> {
        let decision = self.check(generation)?;
        if decision == GenerationDecision::Install {
            self.current = Some(generation);
        }
        Ok(decision)
    }
}
