use crate::validator::SimValidator;
#[derive(Debug, Clone)]
pub struct SimCluster {
    pub validators: Vec<SimValidator>,
    pub finalized_height: u64,
}
impl SimCluster {
    pub fn new(validators: Vec<SimValidator>) -> Result<Self, String> {
        if validators.len() < 3 || validators.iter().any(|v| v.weight == 0) {
            return Err("invalid validator set".into());
        }
        Ok(Self {
            validators,
            finalized_height: 0,
        })
    }
    pub fn quorum(&self, voters: &[String]) -> bool {
        let active = self
            .validators
            .iter()
            .filter(|v| v.can_sign())
            .collect::<Vec<_>>();
        let total: u64 = active.iter().map(|v| v.weight).sum();
        let voted = active
            .iter()
            .filter(|v| voters.contains(&v.id))
            .collect::<Vec<_>>();
        let count_ok = voted.len() * 3 > active.len() * 2;
        let weight: u64 = voted.iter().map(|v| v.weight).sum();
        count_ok && weight * 3 > total * 2
    }
    pub fn finalize(&mut self, height: u64, voters: &[String]) -> Result<(), String> {
        if height != self.finalized_height + 1 {
            return Err("non-contiguous finality".into());
        }
        if !self.quorum(voters) {
            return Err("count and weight quorum not met".into());
        }
        self.finalized_height = height;
        Ok(())
    }
}
