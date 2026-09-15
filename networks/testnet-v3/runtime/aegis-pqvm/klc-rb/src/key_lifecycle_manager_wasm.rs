//! WASM bindings for Key Lifecycle Manager

#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;
use crate::key_lifecycle_manager::*;

#[cfg(feature = "wasm")]
#[wasm_bindgen]
impl KeyLifecycleManager {
    /// Create a new lifecycle manager (JS-friendly constructor)
    #[wasm_bindgen(constructor)]
    pub fn new_js() -> KeyLifecycleManager {
        Self::new()
    }

    /// Register rotation policy (JS-friendly)
    #[wasm_bindgen]
    pub fn register_policy_js(&mut self, policy: RotationPolicy) {
        self.register_policy(policy);
    }

    /// Generate new key with policy (JS-friendly)
    #[wasm_bindgen]
    pub fn generate_key_js(&mut self, policy_id: &str) -> Result<u64, String> {
        self.generate_key(policy_id).map(|id| id.0)
    }

    /// Record key usage (JS-friendly)
    #[wasm_bindgen]
    pub fn record_usage_js(&mut self, key_id: u64, operation_type: &str) -> Result<(), String> {
        self.record_usage(KeyId(key_id), operation_type)
    }

    /// Check if key needs rotation (JS-friendly)
    #[wasm_bindgen]
    pub fn check_rotation_needed_js(&self, key_id: u64) -> Result<bool, String> {
        self.check_rotation_needed(KeyId(key_id))
    }

    /// Schedule key rotation (JS-friendly)
    #[wasm_bindgen]
    pub fn schedule_rotation_js(&mut self, key_id: u64, reason: &str) -> Result<u64, String> {
        self.schedule_rotation(KeyId(key_id), reason).map(|id| id.0)
    }

    /// Execute key rotation (JS-friendly)
    #[wasm_bindgen]
    pub fn execute_rotation_js(&mut self, old_key_id: u64) -> Result<ProofOfDestruction, String> {
        self.execute_rotation(KeyId(old_key_id))
    }

    /// Retire key (JS-friendly)
    #[wasm_bindgen]
    pub fn retire_key_js(&mut self, key_id: u64, reason: &str) -> Result<(), String> {
        self.retire_key(KeyId(key_id), reason)
    }

    /// Destroy key (JS-friendly)
    #[wasm_bindgen]
    pub fn destroy_key_js(&mut self, key_id: u64) -> Result<ProofOfDestruction, String> {
        self.destroy_key(KeyId(key_id))
    }

    /// Get key metadata (JS-friendly)
    #[wasm_bindgen]
    pub fn get_key_metadata_js(&self, key_id: u64) -> Option<KeyMetadata> {
        self.get_key_metadata(KeyId(key_id)).cloned()
    }

    /// Get audit trail for key (JS-friendly)
    #[wasm_bindgen]
    pub fn get_audit_trail_js(&self, key_id: u64) -> Vec<AuditEvent> {
        self.get_audit_trail(KeyId(key_id))
            .into_iter()
            .cloned()
            .collect()
    }

    /// Get Merkle root of audit log (JS-friendly)
    #[wasm_bindgen]
    pub fn get_audit_root_js(&self) -> Vec<u8> {
        self.get_audit_root().to_vec()
    }

    /// Verify proof of destruction (JS-friendly)
    #[wasm_bindgen]
    pub fn verify_destruction_proof_js(&self, proof: &ProofOfDestruction) -> bool {
        self.verify_destruction_proof(proof)
    }

    /// Get statistics (JS-friendly)
    #[wasm_bindgen]
    pub fn get_statistics_js(&self) -> LifecycleStatistics {
        self.get_statistics()
    }
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
impl RotationPolicy {
    /// Create a new rotation policy (JS-friendly constructor)
    #[wasm_bindgen(constructor)]
    pub fn new_js(
        id: String,
        algorithm: String,
        max_operations: u64,
        max_lifetime_seconds: u64,
        auto_rotate: bool,
        require_approval: bool,
        notification_threshold: f64,
    ) -> RotationPolicy {
        let algorithm_family = match algorithm.as_str() {
            "MLKEM512" => AlgorithmFamily::MLKEM512,
            "MLKEM768" => AlgorithmFamily::MLKEM768,
            "MLKEM1024" => AlgorithmFamily::MLKEM1024,
            "MLDSA44" => AlgorithmFamily::MLDSA44,
            "MLDSA65" => AlgorithmFamily::MLDSA65,
            "MLDSA87" => AlgorithmFamily::MLDSA87,
            _ => AlgorithmFamily::MLDSA87, // Default
        };

        RotationPolicy {
            id,
            algorithm: algorithm_family,
            max_operations,
            max_lifetime_seconds,
            auto_rotate,
            require_approval,
            notification_threshold,
        }
    }

    #[wasm_bindgen(getter)]
    pub fn id_js(&self) -> String {
        self.id.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn algorithm_js(&self) -> String {
        self.algorithm.as_str().to_string()
    }

    #[wasm_bindgen(getter)]
    pub fn max_operations_js(&self) -> u64 {
        self.max_operations
    }

    #[wasm_bindgen(getter)]
    pub fn max_lifetime_seconds_js(&self) -> u64 {
        self.max_lifetime_seconds
    }

    #[wasm_bindgen(getter)]
    pub fn auto_rotate_js(&self) -> bool {
        self.auto_rotate
    }

    #[wasm_bindgen(getter)]
    pub fn require_approval_js(&self) -> bool {
        self.require_approval
    }

    #[wasm_bindgen(getter)]
    pub fn notification_threshold_js(&self) -> f64 {
        self.notification_threshold
    }
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
impl LifecycleStatistics {
    #[wasm_bindgen(getter)]
    pub fn total_keys_js(&self) -> usize {
        self.total_keys
    }

    #[wasm_bindgen(getter)]
    pub fn active_keys_js(&self) -> usize {
        self.active_keys
    }

    #[wasm_bindgen(getter)]
    pub fn retired_keys_js(&self) -> usize {
        self.retired_keys
    }

    #[wasm_bindgen(getter)]
    pub fn destroyed_keys_js(&self) -> usize {
        self.destroyed_keys
    }

    #[wasm_bindgen(getter)]
    pub fn total_operations_js(&self) -> u64 {
        self.total_operations
    }

    #[wasm_bindgen(getter)]
    pub fn audit_log_size_js(&self) -> usize {
        self.audit_log_size
    }

    #[wasm_bindgen(getter)]
    pub fn audit_root_js(&self) -> Vec<u8> {
        self.audit_root.to_vec()
    }
}
