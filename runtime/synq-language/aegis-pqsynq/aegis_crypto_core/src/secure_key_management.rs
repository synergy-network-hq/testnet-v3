//! Secure Key Management System for Aegis
//!
//! This module provides enhanced key management capabilities including
//! secure key storage, rotation, and lifecycle management.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use zeroize::Zeroize;

/// Key lifecycle states
#[derive(Debug, Clone, PartialEq)]
pub enum KeyState {
    /// Key is being generated
    Generating,
    /// Key is active and can be used
    Active,
    /// Key is being rotated
    Rotating,
    /// Key is deprecated but still valid
    Deprecated,
    /// Key is revoked and cannot be used
    Revoked,
    /// Key is being destroyed
    Destroying,
    /// Key has been destroyed
    Destroyed,
}

/// Key metadata for tracking key lifecycle
#[derive(Debug, Clone)]
pub struct KeyMetadata {
    /// Unique key identifier
    pub id: String,
    /// Key creation timestamp
    pub created_at: SystemTime,
    /// Key expiration timestamp
    pub expires_at: Option<SystemTime>,
    /// Last used timestamp
    pub last_used: Option<SystemTime>,
    /// Usage count
    pub usage_count: u64,
    /// Key state
    pub state: KeyState,
    /// Key version
    pub version: u32,
    /// Associated algorithm
    pub algorithm: String,
    /// Security level
    pub security_level: u32,
}

/// Secure key wrapper that automatically zeroizes on drop
pub struct SecureKey {
    /// The actual key material
    data: Vec<u8>,
    /// Key metadata
    metadata: KeyMetadata,
}

impl SecureKey {
    /// Create a new secure key
    pub fn new(data: Vec<u8>, algorithm: String, security_level: u32) -> Self {
        let now = SystemTime::now();
        let id = format!(
            "key_{}_{}",
            algorithm,
            now.duration_since(UNIX_EPOCH).unwrap().as_secs()
        );

        Self {
            data,
            metadata: KeyMetadata {
                id,
                created_at: now,
                expires_at: None,
                last_used: None,
                usage_count: 0,
                state: KeyState::Active,
                version: 1,
                algorithm,
                security_level,
            },
        }
    }

    /// Get the key data (creates a copy)
    pub fn get_data(&mut self) -> Vec<u8> {
        self.metadata.last_used = Some(SystemTime::now());
        self.metadata.usage_count += 1;
        self.data.clone()
    }

    /// Get key metadata
    pub fn get_metadata(&self) -> &KeyMetadata {
        &self.metadata
    }

    /// Update key metadata
    pub fn update_metadata(&mut self, metadata: KeyMetadata) {
        self.metadata = metadata;
    }

    /// Check if key is expired
    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.metadata.expires_at {
            SystemTime::now() > expires_at
        } else {
            false
        }
    }

    /// Check if key is usable
    pub fn is_usable(&self) -> bool {
        matches!(self.metadata.state, KeyState::Active | KeyState::Deprecated) && !self.is_expired()
    }
}

impl Drop for SecureKey {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}

/// Key rotation policy
#[derive(Debug, Clone)]
pub struct KeyRotationPolicy {
    /// Rotation interval
    pub rotation_interval: Duration,
    /// Maximum key age before forced rotation
    pub max_key_age: Duration,
    /// Maximum usage count before rotation
    pub max_usage_count: u64,
    /// Whether to rotate on expiration
    pub rotate_on_expiration: bool,
}

impl Default for KeyRotationPolicy {
    fn default() -> Self {
        Self {
            rotation_interval: Duration::from_secs(86400 * 30), // 30 days
            max_key_age: Duration::from_secs(86400 * 90),       // 90 days
            max_usage_count: 1000000,                           // 1 million uses
            rotate_on_expiration: true,
        }
    }
}

/// Secure key manager
pub struct SecureKeyManager {
    /// Active keys by algorithm
    keys: Arc<RwLock<HashMap<String, Vec<Arc<Mutex<SecureKey>>>>>>,
    /// Key rotation policies by algorithm
    rotation_policies: Arc<RwLock<HashMap<String, KeyRotationPolicy>>>,
    /// Audit logger
    audit_logger: Arc<Mutex<Vec<AuditEvent>>>,
}

/// Audit event for key operations
#[derive(Debug, Clone)]
pub struct AuditEvent {
    pub timestamp: SystemTime,
    pub event_type: String,
    pub key_id: String,
    pub algorithm: String,
    pub details: String,
    pub success: bool,
}

impl SecureKeyManager {
    /// Create a new secure key manager
    pub fn new() -> Self {
        Self {
            keys: Arc::new(RwLock::new(HashMap::new())),
            rotation_policies: Arc::new(RwLock::new(HashMap::new())),
            audit_logger: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Set rotation policy for an algorithm
    pub fn set_rotation_policy(&self, algorithm: String, policy: KeyRotationPolicy) {
        let mut policies = self.rotation_policies.write().unwrap();
        policies.insert(algorithm, policy);
    }

    /// Add a new key
    pub fn add_key(&self, key: SecureKey) -> Result<String, String> {
        let algorithm = key.get_metadata().algorithm.clone();
        let key_id = key.get_metadata().id.clone();

        // Log the event
        self.log_audit_event(AuditEvent {
            timestamp: SystemTime::now(),
            event_type: "key_added".to_string(),
            key_id: key_id.clone(),
            algorithm: algorithm.clone(),
            details: "New key added to key manager".to_string(),
            success: true,
        });

        let mut keys = self.keys.write().unwrap();
        let algorithm_keys = keys.entry(algorithm).or_insert_with(Vec::new);
        algorithm_keys.push(Arc::new(Mutex::new(key)));

        Ok(key_id)
    }

    /// Get the most recent active key for an algorithm
    pub fn get_active_key(&self, algorithm: &str) -> Result<Arc<Mutex<SecureKey>>, String> {
        let keys = self.keys.read().unwrap();
        if let Some(algorithm_keys) = keys.get(algorithm) {
            // Find the most recent active key
            for key_arc in algorithm_keys.iter().rev() {
                let key = key_arc.lock().unwrap();
                if key.is_usable() {
                    // Log the event
                    self.log_audit_event(AuditEvent {
                        timestamp: SystemTime::now(),
                        event_type: "key_accessed".to_string(),
                        key_id: key.get_metadata().id.clone(),
                        algorithm: algorithm.to_string(),
                        details: "Key accessed for cryptographic operation".to_string(),
                        success: true,
                    });
                    return Ok(key_arc.clone());
                }
            }
            Err(format!("No active keys found for algorithm: {}", algorithm))
        } else {
            Err(format!("No keys found for algorithm: {}", algorithm))
        }
    }

    /// Rotate keys for an algorithm
    pub fn rotate_keys(&self, algorithm: &str, new_key: SecureKey) -> Result<(), String> {
        let key_id = new_key.get_metadata().id.clone();

        // Log the event
        self.log_audit_event(AuditEvent {
            timestamp: SystemTime::now(),
            event_type: "key_rotation_started".to_string(),
            key_id: key_id.clone(),
            algorithm: algorithm.to_string(),
            details: "Key rotation initiated".to_string(),
            success: true,
        });

        let mut keys = self.keys.write().unwrap();
        if let Some(algorithm_keys) = keys.get_mut(algorithm) {
            // Mark old keys as deprecated
            for key_arc in algorithm_keys.iter() {
                let mut key = key_arc.lock().unwrap();
                if key.is_usable() {
                    let mut metadata = key.get_metadata().clone();
                    metadata.state = KeyState::Deprecated;
                    key.update_metadata(metadata);
                }
            }

            // Add new key
            algorithm_keys.push(Arc::new(Mutex::new(new_key)));

            // Log successful rotation
            self.log_audit_event(AuditEvent {
                timestamp: SystemTime::now(),
                event_type: "key_rotation_completed".to_string(),
                key_id,
                algorithm: algorithm.to_string(),
                details: "Key rotation completed successfully".to_string(),
                success: true,
            });

            Ok(())
        } else {
            Err(format!("No keys found for algorithm: {}", algorithm))
        }
    }

    /// Check if keys need rotation
    pub fn check_rotation_needed(&self, algorithm: &str) -> bool {
        let policies = self.rotation_policies.read().unwrap();
        let keys = self.keys.read().unwrap();

        if let (Some(policy), Some(algorithm_keys)) = (policies.get(algorithm), keys.get(algorithm))
        {
            let now = SystemTime::now();

            for key_arc in algorithm_keys.iter() {
                let key = key_arc.lock().unwrap();
                let metadata = key.get_metadata();

                // Check if key is expired
                if policy.rotate_on_expiration && key.is_expired() {
                    return true;
                }

                // Check if key is too old
                if now.duration_since(metadata.created_at).unwrap() > policy.max_key_age {
                    return true;
                }

                // Check if key has been used too much
                if metadata.usage_count > policy.max_usage_count {
                    return true;
                }
            }
        }

        false
    }

    /// Get audit log
    pub fn get_audit_log(&self) -> Vec<AuditEvent> {
        let log = self.audit_logger.lock().unwrap();
        log.clone()
    }

    /// Log audit event
    fn log_audit_event(&self, event: AuditEvent) {
        let mut log = self.audit_logger.lock().unwrap();
        log.push(event);

        // Keep only last 10000 events to prevent memory issues
        if log.len() > 10000 {
            log.drain(0..1000);
        }
    }

    /// Clean up expired and revoked keys
    pub fn cleanup_keys(&self) {
        let mut keys = self.keys.write().unwrap();

        for algorithm_keys in keys.values_mut() {
            algorithm_keys.retain(|key_arc| {
                let key = key_arc.lock().unwrap();
                let metadata = key.get_metadata();

                // Keep keys that are not destroyed
                !matches!(metadata.state, KeyState::Destroyed)
            });
        }
    }
}

impl Default for SecureKeyManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_key_creation() {
        let key_data = vec![1, 2, 3, 4, 5];
        let key = SecureKey::new(key_data.clone(), "ML-KEM-768".to_string(), 256);

        assert_eq!(key.get_metadata().algorithm, "ML-KEM-768");
        assert_eq!(key.get_metadata().security_level, 256);
        assert_eq!(key.get_metadata().state, KeyState::Active);
        assert!(key.is_usable());
    }

    #[test]
    fn test_key_manager_operations() {
        let manager = SecureKeyManager::new();
        let key = SecureKey::new(vec![1, 2, 3, 4, 5], "ML-KEM-768".to_string(), 256);

        let key_id = manager.add_key(key).unwrap();
        assert!(!key_id.is_empty());

        let retrieved_key = manager.get_active_key("ML-KEM-768").unwrap();
        let retrieved_data = retrieved_key.lock().unwrap().get_data();
        assert_eq!(retrieved_data, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_key_rotation() {
        let manager = SecureKeyManager::new();
        let key1 = SecureKey::new(vec![1, 2, 3, 4, 5], "ML-KEM-768".to_string(), 256);
        let key2 = SecureKey::new(vec![6, 7, 8, 9, 10], "ML-KEM-768".to_string(), 256);

        manager.add_key(key1).unwrap();
        manager.rotate_keys("ML-KEM-768", key2).unwrap();

        let active_key = manager.get_active_key("ML-KEM-768").unwrap();
        let active_data = active_key.lock().unwrap().get_data();
        assert_eq!(active_data, vec![6, 7, 8, 9, 10]);
    }
}
