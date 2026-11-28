use crate::{
    records::BootseedRecord,
    verification::{verify_record, BootseedVerifier},
};
use std::collections::BTreeMap;
#[derive(Default)]
pub struct BootseedRegistry {
    records: BTreeMap<String, BootseedRecord>,
}
impl BootseedRegistry {
    pub fn publish(
        &mut self,
        record: BootseedRecord,
        now: u64,
        verifier: &dyn BootseedVerifier,
    ) -> Result<(), String> {
        verify_record(&record, now, verifier)?;
        if let Some(old) = self.records.get(&record.node_address) {
            if old.generation > record.generation {
                return Err("stale bootseed generation".into());
            }
            if old.generation == record.generation {
                // A verified retry preserves the accepted publication; equal
                // generations never permit conflicting content replacement.
                return if old == &record {
                    Ok(())
                } else {
                    Err("conflicting bootseed generation".into())
                };
            }
        }
        self.records.insert(record.node_address.clone(), record);
        Ok(())
    }
    pub fn live(&self, now: u64, limit: usize) -> Vec<BootseedRecord> {
        self.records
            .values()
            .filter(|r| r.expires_at > now)
            .take(limit.min(256))
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FixtureVerifier(bool);

    impl BootseedVerifier for FixtureVerifier {
        fn verify(&self, _: &BootseedRecord) -> Result<(), String> {
            if self.0 {
                Ok(())
            } else {
                Err("fixture verification rejected".into())
            }
        }
    }

    fn record(generation: u64) -> BootseedRecord {
        BootseedRecord {
            node_address: "isolated-test-only".into(),
            endpoints: vec!["https://seed.example.test".into()],
            expires_at: 100,
            generation,
            signature: vec![1],
        }
    }

    #[test]
    fn identical_verified_publication_is_idempotent() {
        let mut registry = BootseedRegistry::default();
        let value = record(12);
        registry
            .publish(value.clone(), 1, &FixtureVerifier(true))
            .unwrap();
        assert_eq!(
            registry.publish(value.clone(), 2, &FixtureVerifier(true)),
            Ok(())
        );
        assert_eq!(registry.live(2, 10), vec![value]);
    }

    #[test]
    fn conflicting_equal_generation_preserves_accepted_record() {
        let mut registry = BootseedRegistry::default();
        let accepted = record(12);
        registry
            .publish(accepted.clone(), 1, &FixtureVerifier(true))
            .unwrap();
        let mut conflict = accepted.clone();
        conflict.endpoints = vec!["https://different.example.test".into()];
        assert_eq!(
            registry.publish(conflict, 2, &FixtureVerifier(true)),
            Err("conflicting bootseed generation".into())
        );
        assert_eq!(registry.live(2, 10), vec![accepted]);
    }

    #[test]
    fn lower_generation_cannot_replace_accepted_record() {
        let mut registry = BootseedRegistry::default();
        let accepted = record(12);
        registry
            .publish(accepted.clone(), 1, &FixtureVerifier(true))
            .unwrap();
        assert_eq!(
            registry.publish(record(11), 2, &FixtureVerifier(true)),
            Err("stale bootseed generation".into())
        );
        assert_eq!(registry.live(2, 10), vec![accepted]);
    }

    #[test]
    fn identical_replay_still_requires_current_verification() {
        let mut registry = BootseedRegistry::default();
        let accepted = record(12);
        registry
            .publish(accepted.clone(), 1, &FixtureVerifier(true))
            .unwrap();
        assert_eq!(
            registry.publish(accepted, 2, &FixtureVerifier(false)),
            Err("fixture verification rejected".into())
        );
    }

    #[test]
    fn identical_replay_cannot_extend_expiry() {
        let mut registry = BootseedRegistry::default();
        let accepted = record(12);
        registry
            .publish(accepted.clone(), 1, &FixtureVerifier(true))
            .unwrap();
        assert_eq!(
            registry.publish(accepted, 100, &FixtureVerifier(true)),
            Err("bootseed record expired".into())
        );
        assert!(registry.live(100, 10).is_empty());
    }

    #[test]
    fn verified_new_generation_replaces_previous_record() {
        let mut registry = BootseedRegistry::default();
        registry
            .publish(record(12), 1, &FixtureVerifier(true))
            .unwrap();
        let next = record(13);
        registry
            .publish(next.clone(), 2, &FixtureVerifier(true))
            .unwrap();
        assert_eq!(registry.live(2, 10), vec![next]);
    }
}
