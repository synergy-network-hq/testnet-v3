//! Key lifecycle management for `aegis-pqvm`.
//!
//! This module provides deterministic metadata tracking and auditable state
//! transitions for PQC key identifiers managed by a host application.

use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Algorithm family for key identification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AlgorithmFamily {
    MLKEM512,
    MLKEM768,
    MLKEM1024,
    MLDSA44,
    MLDSA65,
    MLDSA87,
    FNDSA512,
    FNDSA1024,
}

impl AlgorithmFamily {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::MLKEM512 => "ML-KEM-512",
            Self::MLKEM768 => "ML-KEM-768",
            Self::MLKEM1024 => "ML-KEM-1024",
            Self::MLDSA44 => "ML-DSA-44",
            Self::MLDSA65 => "ML-DSA-65",
            Self::MLDSA87 => "ML-DSA-87",
            Self::FNDSA512 => "FN-DSA-512",
            Self::FNDSA1024 => "FN-DSA-1024",
        }
    }
}

/// Key state in lifecycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyState {
    Active,
    RotationScheduled { at_timestamp: u64 },
    Retired { reason: String },
    Destroyed,
}

impl KeyState {
    fn as_label(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::RotationScheduled { .. } => "rotation_scheduled",
            Self::Retired { .. } => "retired",
            Self::Destroyed => "destroyed",
        }
    }
}

/// Key metadata for lifecycle tracking.
#[derive(Debug, Clone)]
pub struct KeyMetadata {
    pub id: u64,
    pub algorithm: AlgorithmFamily,
    pub created_at: u64,
    pub last_used: u64,
    pub state: KeyState,
}

/// Lifecycle audit event type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyLifecycleEventType {
    Registered,
    Accessed,
    RotationScheduled,
    Retired,
    Destroyed,
}

impl KeyLifecycleEventType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Registered => "registered",
            Self::Accessed => "accessed",
            Self::RotationScheduled => "rotation_scheduled",
            Self::Retired => "retired",
            Self::Destroyed => "destroyed",
        }
    }
}

/// Append-only audit record for lifecycle operations.
#[derive(Debug, Clone)]
pub struct KeyLifecycleEvent {
    pub timestamp: u64,
    pub key_id: u64,
    pub event_type: KeyLifecycleEventType,
    pub details: String,
}

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum KeyLifecycleError {
    #[error("key id {0} not found")]
    KeyNotFound(u64),
    #[error("key id space exhausted")]
    IdExhausted,
    #[error("key store capacity exceeded ({max_keys})")]
    CapacityExceeded { max_keys: usize },
    #[error("invalid state transition for key {id}: {state}")]
    InvalidStateTransition { id: u64, state: &'static str },
    #[error("rotation timestamp must be in the future")]
    InvalidRotationTimestamp,
    #[error("retire reason must not be empty")]
    EmptyRetireReason,
}

/// Deterministic key lifecycle store with append-only audit events.
#[derive(Debug)]
pub struct KeyLifecycleManager {
    keys: BTreeMap<u64, KeyMetadata>,
    audit_log: Vec<KeyLifecycleEvent>,
    next_id: u64,
    max_keys: usize,
}

impl Default for KeyLifecycleManager {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyLifecycleManager {
    /// Creates a manager with a conservative default capacity.
    pub fn new() -> Self {
        Self::with_capacity(100_000)
    }

    /// Creates a manager with an explicit key-capacity limit.
    pub fn with_capacity(max_keys: usize) -> Self {
        Self {
            keys: BTreeMap::new(),
            audit_log: Vec::new(),
            next_id: 1,
            max_keys,
        }
    }

    fn current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_secs()
    }

    fn reserve_id(&mut self) -> Result<u64, KeyLifecycleError> {
        if self.keys.len() >= self.max_keys {
            return Err(KeyLifecycleError::CapacityExceeded {
                max_keys: self.max_keys,
            });
        }
        let id = self.next_id;
        self.next_id = self
            .next_id
            .checked_add(1)
            .ok_or(KeyLifecycleError::IdExhausted)?;
        Ok(id)
    }

    fn record_event(
        &mut self,
        key_id: u64,
        event_type: KeyLifecycleEventType,
        details: impl Into<String>,
    ) {
        self.audit_log.push(KeyLifecycleEvent {
            timestamp: Self::current_timestamp(),
            key_id,
            event_type,
            details: details.into(),
        });
    }

    /// Registers a newly generated key identifier.
    pub fn register_key(&mut self, algorithm: AlgorithmFamily) -> Result<u64, KeyLifecycleError> {
        let id = self.reserve_id()?;
        let now = Self::current_timestamp();
        self.keys.insert(
            id,
            KeyMetadata {
                id,
                algorithm,
                created_at: now,
                last_used: now,
                state: KeyState::Active,
            },
        );
        self.record_event(
            id,
            KeyLifecycleEventType::Registered,
            format!("algorithm={}", algorithm.as_str()),
        );
        Ok(id)
    }

    /// Updates the `last_used` timestamp for an active key.
    pub fn touch_key(&mut self, id: u64) -> Result<(), KeyLifecycleError> {
        let now = Self::current_timestamp();
        let mut invalid_state: Option<&'static str> = None;

        {
            let meta = self
                .keys
                .get_mut(&id)
                .ok_or(KeyLifecycleError::KeyNotFound(id))?;

            match meta.state {
                KeyState::Active | KeyState::RotationScheduled { .. } => {
                    meta.last_used = now;
                }
                _ => {
                    invalid_state = Some(meta.state.as_label());
                }
            }
        }

        if let Some(state) = invalid_state {
            return Err(KeyLifecycleError::InvalidStateTransition { id, state });
        }

        self.record_event(id, KeyLifecycleEventType::Accessed, "touch");
        Ok(())
    }

    /// Schedules key rotation at a future epoch timestamp.
    pub fn schedule_rotation(
        &mut self,
        id: u64,
        at_timestamp: u64,
    ) -> Result<(), KeyLifecycleError> {
        let now = Self::current_timestamp();
        if at_timestamp <= now {
            return Err(KeyLifecycleError::InvalidRotationTimestamp);
        }

        {
            let meta = self
                .keys
                .get_mut(&id)
                .ok_or(KeyLifecycleError::KeyNotFound(id))?;

            if meta.state != KeyState::Active {
                return Err(KeyLifecycleError::InvalidStateTransition {
                    id,
                    state: meta.state.as_label(),
                });
            }

            meta.state = KeyState::RotationScheduled { at_timestamp };
        }

        self.record_event(
            id,
            KeyLifecycleEventType::RotationScheduled,
            format!("rotate_at={at_timestamp}"),
        );
        Ok(())
    }

    /// Retires a key and stores the retirement reason.
    pub fn retire_key(
        &mut self,
        id: u64,
        reason: impl Into<String>,
    ) -> Result<(), KeyLifecycleError> {
        let reason = reason.into();
        if reason.trim().is_empty() {
            return Err(KeyLifecycleError::EmptyRetireReason);
        }

        {
            let meta = self
                .keys
                .get_mut(&id)
                .ok_or(KeyLifecycleError::KeyNotFound(id))?;

            match meta.state {
                KeyState::Active | KeyState::RotationScheduled { .. } => {
                    meta.state = KeyState::Retired {
                        reason: reason.clone(),
                    };
                }
                _ => {
                    return Err(KeyLifecycleError::InvalidStateTransition {
                        id,
                        state: meta.state.as_label(),
                    });
                }
            }
        }

        self.record_event(id, KeyLifecycleEventType::Retired, reason);
        Ok(())
    }

    /// Marks a key as destroyed (terminal state).
    pub fn destroy_key(&mut self, id: u64) -> Result<(), KeyLifecycleError> {
        {
            let meta = self
                .keys
                .get_mut(&id)
                .ok_or(KeyLifecycleError::KeyNotFound(id))?;

            if meta.state == KeyState::Destroyed {
                return Err(KeyLifecycleError::InvalidStateTransition {
                    id,
                    state: meta.state.as_label(),
                });
            }

            meta.state = KeyState::Destroyed;
            meta.last_used = Self::current_timestamp();
        }

        self.record_event(id, KeyLifecycleEventType::Destroyed, "explicit-destroy");
        Ok(())
    }

    /// Returns metadata for a key id.
    pub fn get_metadata(&self, id: u64) -> Option<&KeyMetadata> {
        self.keys.get(&id)
    }

    /// Returns all keys in deterministic id order.
    pub fn list_keys(&self) -> Vec<&KeyMetadata> {
        self.keys.values().collect()
    }

    /// Returns immutable access to audit events.
    pub fn audit_events(&self) -> &[KeyLifecycleEvent] {
        &self.audit_log
    }

    /// Writes the full audit log as JSON lines (`.jsonl`).
    pub fn write_audit_log_jsonl<P: AsRef<Path>>(&self, path: P) -> io::Result<()> {
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(path)?;

        for event in &self.audit_log {
            let details = json_escape(&event.details);
            writeln!(
                file,
                "{{\"timestamp\":{},\"key_id\":{},\"event\":\"{}\",\"details\":\"{}\"}}",
                event.timestamp,
                event.key_id,
                event.event_type.as_str(),
                details
            )?;
        }

        file.flush()
    }
}

fn json_escape(input: &str) -> String {
    let mut escaped = String::with_capacity(input.len());
    for c in input.chars() {
        match c {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            other => escaped.push(other),
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::{AlgorithmFamily, KeyLifecycleError, KeyLifecycleManager, KeyState};

    #[test]
    fn lifecycle_enforces_state_transitions() {
        let mut manager = KeyLifecycleManager::new();
        let key_id = manager.register_key(AlgorithmFamily::MLKEM768).unwrap();

        manager.touch_key(key_id).unwrap();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let invalid = manager.schedule_rotation(key_id, now);
        assert!(matches!(
            invalid,
            Err(KeyLifecycleError::InvalidRotationTimestamp)
        ));

        manager.schedule_rotation(key_id, now + 60).unwrap();
        manager.retire_key(key_id, "rotation complete").unwrap();

        let state = &manager.get_metadata(key_id).unwrap().state;
        assert!(matches!(state, KeyState::Retired { .. }));

        manager.destroy_key(key_id).unwrap();

        let second_destroy = manager.destroy_key(key_id);
        assert!(matches!(
            second_destroy,
            Err(KeyLifecycleError::InvalidStateTransition { .. })
        ));
    }

    #[test]
    fn lifecycle_writes_jsonl_audit_log() {
        let mut manager = KeyLifecycleManager::new();
        let key_id = manager.register_key(AlgorithmFamily::MLDSA44).unwrap();
        manager.touch_key(key_id).unwrap();

        let out = tempfile::NamedTempFile::new().unwrap();
        manager
            .write_audit_log_jsonl(out.path())
            .expect("write audit log");

        let contents = std::fs::read_to_string(out.path()).unwrap();
        assert!(contents.contains("\"event\":\"registered\""));
        assert!(contents.contains("\"event\":\"accessed\""));
    }
}
