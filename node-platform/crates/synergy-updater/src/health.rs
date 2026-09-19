#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HealthObservation {
    pub process_running: bool,
    pub ready: bool,
    pub storage_healthy: bool,
    pub protocol_compatible: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HealthGate;

impl HealthGate {
    pub fn check(&self, observation: HealthObservation) -> Result<(), &'static str> {
        if observation.process_running
            && observation.ready
            && observation.storage_healthy
            && observation.protocol_compatible
        {
            Ok(())
        } else {
            Err("post-install health gate failed")
        }
    }
}
