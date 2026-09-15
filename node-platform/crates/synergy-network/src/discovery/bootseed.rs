#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootseedCandidate {
    pub peer_id: String,
    pub dial_address: String,
    pub priority: u16,
}

#[derive(Debug, Clone, Default)]
pub struct BootseedSet {
    candidates: Vec<BootseedCandidate>,
}

impl BootseedSet {
    pub fn new(mut candidates: Vec<BootseedCandidate>) -> Result<Self, String> {
        let mut identities = std::collections::BTreeSet::new();
        for candidate in &mut candidates {
            if candidate.peer_id.trim().is_empty() || !identities.insert(candidate.peer_id.clone())
            {
                return Err("invalid or duplicate bootseed identity".into());
            }
            candidate.dial_address = crate::transport::parse_dial_address(&candidate.dial_address)
                .ok_or_else(|| "invalid bootseed dial address".to_string())?;
        }
        candidates.sort_by(|left, right| {
            left.priority
                .cmp(&right.priority)
                .then_with(|| left.peer_id.cmp(&right.peer_id))
        });
        Ok(Self { candidates })
    }

    pub fn candidates(&self) -> &[BootseedCandidate] {
        &self.candidates
    }

    pub const fn is_liveness_dependency(&self) -> bool {
        false
    }
}
