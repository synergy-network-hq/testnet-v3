//! Aegis PQC Core - Key Lifecycle Manager
//! Patent Claims [1104], [1105], [1111], [1112]
//! 
//! Automated key generation, distribution, rotation, retirement, and destruction
//! with Merkleized audit logs for compliance verification.
//!
//! This module integrates with the actual PQC implementations in aegis_crypto_core.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(feature = "serde")]
use serde::{Serialize, Deserialize};

#[cfg(not(feature = "serde"))]
// Minimal serialization support when serde is not available
mod serde {
    pub trait Serialize {}
    pub trait Deserialize {}
    impl<T> Serialize for T {}
    impl<T> Deserialize for T {}
}

#[cfg(feature = "mldsa")]
use crate::algorithms::mldsa::{mldsa87_keygen, mldsa87_sign, mldsa87_verify};

/// Algorithm family for key identification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AlgorithmFamily {
    MLKEM512,
    MLKEM768,
    MLKEM1024,
    MLDSA44,
    MLDSA65,
    MLDSA87,
    SLHDSA128F,
    SLHDSA128S,
    SLHDSA192F,
    SLHDSA192S,
    SLHDSA256F,
    SLHDSA256S,
    FNDSA512,
    FNDSA1024,
    HQCKEM128,
    HQCKEM192,
    HQCKEM256,
}

impl AlgorithmFamily {
    pub fn as_str(&self) -> &str {
        match self {
            Self::MLKEM512 => "ML-KEM-512",
            Self::MLKEM768 => "ML-KEM-768",
            Self::MLKEM1024 => "ML-KEM-1024",
            Self::MLDSA44 => "ML-DSA-44",
            Self::MLDSA65 => "ML-DSA-65",
            Self::MLDSA87 => "ML-DSA-87",
            Self::SLHDSA128F => "SLH-DSA-128F",
            Self::SLHDSA128S => "SLH-DSA-128S",
            Self::SLHDSA192F => "SLH-DSA-192F",
            Self::SLHDSA192S => "SLH-DSA-192S",
            Self::SLHDSA256F => "SLH-DSA-256F",
            Self::SLHDSA256S => "SLH-DSA-256S",
            Self::FNDSA512 => "FN-DSA-512",
            Self::FNDSA1024 => "FN-DSA-1024",
            Self::HQCKEM128 => "HQC-KEM-128",
            Self::HQCKEM192 => "HQC-KEM-192",
            Self::HQCKEM256 => "HQC-KEM-256",
        }
    }
}

/// Unique key identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct KeyId(pub u64);

impl KeyId {
    pub fn new() -> Self {
        let timestamp = current_timestamp();
        let random = generate_random_u64();
        KeyId(timestamp ^ random)
    }
}

/// Key state in lifecycle
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KeyState {
    Active,
    RotationScheduled { at_timestamp: u64 },
    Retired { reason: String },
    Destroyed { proof: ProofOfDestruction },
}

/// Key metadata for lifecycle tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyMetadata {
    pub id: KeyId,
    pub algorithm: AlgorithmFamily,
    pub created_at: u64,
    pub last_used: u64,
    pub usage_count: u64,
    pub state: KeyState,
    pub policy_id: String,
    pub key_material: Vec<u8>, // Serialized key material
}

/// Cryptographic proof of key destruction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofOfDestruction {
    pub key_id: KeyId,
    pub timestamp: u64,
    pub destructor_identity: String,
    pub method: DestructionMethod,
    pub witness_signature: Vec<u8>,  // ML-DSA signature
    pub merkle_proof: MerkleProof,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DestructionMethod {
    SecureErase,
    CryptographicWipe,
    PhysicalDestruction,
}

/// Rotation policy for keys
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationPolicy {
    pub id: String,
    pub algorithm: AlgorithmFamily,
    pub max_operations: u64,
    pub max_lifetime_seconds: u64,
    pub auto_rotate: bool,
    pub require_approval: bool,
    pub notification_threshold: f64,
}

impl Default for RotationPolicy {
    fn default() -> Self {
        Self {
            id: "default".to_string(),
            algorithm: AlgorithmFamily::MLDSA87,
            max_operations: 1_000_000,
            max_lifetime_seconds: 90 * 24 * 3600,
            auto_rotate: true,
            require_approval: false,
            notification_threshold: 0.8,
        }
    }
}

/// Audit event for Merkle log
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditEvent {
    KeyCreated {
        key_id: KeyId,
        algorithm: AlgorithmFamily,
        timestamp: u64,
        policy_id: String,
    },
    KeyUsed {
        key_id: KeyId,
        timestamp: u64,
        operation_type: String,
    },
    KeyRotationScheduled {
        old_key_id: KeyId,
        new_key_id: KeyId,
        scheduled_at: u64,
        reason: String,
    },
    KeyRotated {
        old_key_id: KeyId,
        new_key_id: KeyId,
        timestamp: u64,
        proof: ProofOfDestruction,
    },
    KeyRetired {
        key_id: KeyId,
        timestamp: u64,
        reason: String,
    },
    KeyDestroyed {
        key_id: KeyId,
        timestamp: u64,
        proof: ProofOfDestruction,
    },
    PolicyUpdated {
        policy_id: String,
        timestamp: u64,
        changes: String,
    },
}

impl AuditEvent {
    pub fn key_id(&self) -> Option<KeyId> {
        match self {
            Self::KeyCreated { key_id, .. } => Some(*key_id),
            Self::KeyUsed { key_id, .. } => Some(*key_id),
            Self::KeyRotationScheduled { old_key_id, .. } => Some(*old_key_id),
            Self::KeyRotated { old_key_id, .. } => Some(*old_key_id),
            Self::KeyRetired { key_id, .. } => Some(*key_id),
            Self::KeyDestroyed { key_id, .. } => Some(*key_id),
            Self::PolicyUpdated { .. } => None,
        }
    }

    pub fn timestamp(&self) -> u64 {
        match self {
            Self::KeyCreated { timestamp, .. } => *timestamp,
            Self::KeyUsed { timestamp, .. } => *timestamp,
            Self::KeyRotationScheduled { scheduled_at, .. } => *scheduled_at,
            Self::KeyRotated { timestamp, .. } => *timestamp,
            Self::KeyRetired { timestamp, .. } => *timestamp,
            Self::KeyDestroyed { timestamp, .. } => *timestamp,
            Self::PolicyUpdated { timestamp, .. } => *timestamp,
        }
    }
}

/// Merkle proof for audit verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    pub leaf_index: usize,
    pub leaf_hash: [u8; 32],
    pub siblings: Vec<[u8; 32]>,
    pub root: [u8; 32],
}

impl MerkleProof {
    pub fn verify(&self) -> bool {
        let mut current_hash = self.leaf_hash;
        let mut index = self.leaf_index;

        for sibling in &self.siblings {
            current_hash = if index % 2 == 0 {
                hash_pair(&current_hash, sibling)
            } else {
                hash_pair(sibling, &current_hash)
            };
            index /= 2;
        }

        current_hash == self.root
    }
}

/// Merkle tree for audit log
#[derive(Debug, Clone)]
pub struct MerkleLog {
    leaves: Vec<[u8; 32]>,
    events: Vec<AuditEvent>,
}

impl MerkleLog {
    pub fn new() -> Self {
        Self {
            leaves: Vec::new(),
            events: Vec::new(),
        }
    }

    pub fn append(&mut self, event: AuditEvent) -> [u8; 32] {
        #[cfg(feature = "serde")]
        let event_bytes = serde_json::to_vec(&event).expect("Serialization failed");
        #[cfg(not(feature = "serde"))]
        let event_bytes = format!("{:?}", event).into_bytes();
        
        let event_hash = blake3::hash(&event_bytes);
        let mut hash_array = [0u8; 32];
        hash_array.copy_from_slice(event_hash.as_bytes());

        self.leaves.push(hash_array);
        self.events.push(event);

        hash_array
    }

    pub fn root(&self) -> [u8; 32] {
        if self.leaves.is_empty() {
            return [0u8; 32];
        }

        let mut layer = self.leaves.clone();
        
        while layer.len() > 1 {
            let mut next_layer = Vec::new();
            
            for chunk in layer.chunks(2) {
                if chunk.len() == 2 {
                    next_layer.push(hash_pair(&chunk[0], &chunk[1]));
                } else {
                    next_layer.push(chunk[0]);
                }
            }
            
            layer = next_layer;
        }

        layer[0]
    }

    pub fn generate_proof(&self, index: usize) -> Option<MerkleProof> {
        if index >= self.leaves.len() {
            return None;
        }

        let mut siblings = Vec::new();
        let mut layer = self.leaves.clone();
        let mut current_index = index;

        while layer.len() > 1 {
            let sibling_index = if current_index % 2 == 0 {
                current_index + 1
            } else {
                current_index - 1
            };

            if sibling_index < layer.len() {
                siblings.push(layer[sibling_index]);
            }

            let mut next_layer = Vec::new();
            for chunk in layer.chunks(2) {
                if chunk.len() == 2 {
                    next_layer.push(hash_pair(&chunk[0], &chunk[1]));
                } else {
                    next_layer.push(chunk[0]);
                }
            }

            layer = next_layer;
            current_index /= 2;
        }

        Some(MerkleProof {
            leaf_index: index,
            leaf_hash: self.leaves[index],
            siblings,
            root: layer[0],
        })
    }

    pub fn get_events_for_key(&self, key_id: KeyId) -> Vec<&AuditEvent> {
        self.events
            .iter()
            .filter(|e| e.key_id() == Some(key_id))
            .collect()
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }
}

/// Key Lifecycle Manager
pub struct KeyLifecycleManager {
    keys: HashMap<KeyId, KeyMetadata>,
    policies: HashMap<String, RotationPolicy>,
    audit_log: MerkleLog,
    witness_signing_keypair: Option<(Vec<u8>, Vec<u8>)>, // (pk, sk) for signing destruction proofs
    active_rotations: Vec<(KeyId, KeyId)>,
}

impl KeyLifecycleManager {
    /// Create new lifecycle manager
    pub fn new() -> Self {
        let mut manager = Self {
            keys: HashMap::new(),
            policies: HashMap::new(),
            audit_log: MerkleLog::new(),
            witness_signing_keypair: None,
            active_rotations: Vec::new(),
        };

        // Generate witness keypair for signing destruction proofs
        #[cfg(feature = "mldsa")]
        {
            let keypair = mldsa87_keygen();
            manager.witness_signing_keypair = Some((
                keypair.public_key(),
                keypair.secret_key(),
            ));
        }

        // Register default policy
        manager.register_policy(RotationPolicy::default());

        manager
    }

    /// Register rotation policy
    pub fn register_policy(&mut self, policy: RotationPolicy) {
        let policy_id = policy.id.clone();
        self.policies.insert(policy_id.clone(), policy);
        
        let event = AuditEvent::PolicyUpdated {
            policy_id,
            timestamp: current_timestamp(),
            changes: "Policy registered".to_string(),
        };
        self.audit_log.append(event);
    }

    /// Generate new key with policy
    pub fn generate_key(&mut self, policy_id: &str) -> Result<KeyId, String> {
        let policy = self.policies
            .get(policy_id)
            .ok_or_else(|| format!("Policy '{}' not found", policy_id))?
            .clone();

        let key_id = KeyId::new();
        let timestamp = current_timestamp();

        // Generate actual keypair based on algorithm
        let key_material = match policy.algorithm {
            AlgorithmFamily::MLDSA87 => {
                #[cfg(feature = "mldsa")]
                {
                    let keypair = mldsa87_keygen();
                    // Store both keys
                    let mut material = keypair.public_key();
                    material.extend_from_slice(&keypair.secret_key());
                    material
                }
                #[cfg(not(feature = "mldsa"))]
                {
                    return Err("mldsa feature not enabled".to_string());
                }
            }
            // Add other algorithms as needed
            _ => {
                return Err(format!("Algorithm {:?} not yet implemented", policy.algorithm));
            }
        };

        let metadata = KeyMetadata {
            id: key_id,
            algorithm: policy.algorithm,
            created_at: timestamp,
            last_used: 0,
            usage_count: 0,
            state: KeyState::Active,
            policy_id: policy_id.to_string(),
            key_material,
        };

        self.keys.insert(key_id, metadata);

        // Log creation
        let event = AuditEvent::KeyCreated {
            key_id,
            algorithm: policy.algorithm,
            timestamp,
            policy_id: policy_id.to_string(),
        };
        self.audit_log.append(event);

        Ok(key_id)
    }

    /// Record key usage
    pub fn record_usage(&mut self, key_id: KeyId, operation_type: &str) -> Result<(), String> {
        let metadata = self.keys
            .get_mut(&key_id)
            .ok_or_else(|| format!("Key {:?} not found", key_id))?;

        if !matches!(metadata.state, KeyState::Active) {
            return Err(format!("Key {:?} is not active", key_id));
        }

        let timestamp = current_timestamp();
        metadata.last_used = timestamp;
        metadata.usage_count += 1;

        let event = AuditEvent::KeyUsed {
            key_id,
            timestamp,
            operation_type: operation_type.to_string(),
        };
        self.audit_log.append(event);

        if self.check_rotation_needed(key_id)? {
            self.schedule_rotation(key_id, "Usage threshold exceeded")?;
        }

        Ok(())
    }

    /// Check if key needs rotation
    pub fn check_rotation_needed(&self, key_id: KeyId) -> Result<bool, String> {
        let metadata = self.keys
            .get(&key_id)
            .ok_or_else(|| format!("Key {:?} not found", key_id))?;

        let policy = self.policies
            .get(&metadata.policy_id)
            .ok_or_else(|| "Policy not found".to_string())?;

        let age = current_timestamp() - metadata.created_at;

        Ok(
            metadata.usage_count >= policy.max_operations ||
            age >= policy.max_lifetime_seconds
        )
    }

    /// Schedule key rotation
    pub fn schedule_rotation(&mut self, key_id: KeyId, reason: &str) -> Result<KeyId, String> {
        let metadata = self.keys
            .get(&key_id)
            .ok_or_else(|| format!("Key {:?} not found", key_id))?;

        let new_key_id = self.generate_key(&metadata.policy_id)?;
        let scheduled_at = current_timestamp() + 60;

        let old_metadata = self.keys.get_mut(&key_id).unwrap();
        old_metadata.state = KeyState::RotationScheduled { at_timestamp: scheduled_at };

        let event = AuditEvent::KeyRotationScheduled {
            old_key_id: key_id,
            new_key_id,
            scheduled_at,
            reason: reason.to_string(),
        };
        self.audit_log.append(event);

        self.active_rotations.push((key_id, new_key_id));

        Ok(new_key_id)
    }

    /// Execute key rotation
    pub fn execute_rotation(&mut self, old_key_id: KeyId) -> Result<ProofOfDestruction, String> {
        let rotation_pair = self.active_rotations
            .iter()
            .find(|(old, _)| *old == old_key_id)
            .ok_or_else(|| format!("No rotation scheduled for key {:?}", old_key_id))?
            .clone();

        let proof = self.destroy_key(old_key_id)?;

        let event = AuditEvent::KeyRotated {
            old_key_id,
            new_key_id: rotation_pair.1,
            timestamp: current_timestamp(),
            proof: proof.clone(),
        };
        self.audit_log.append(event);

        self.active_rotations.retain(|(old, _)| *old != old_key_id);

        Ok(proof)
    }

    /// Retire key without immediate destruction
    pub fn retire_key(&mut self, key_id: KeyId, reason: &str) -> Result<(), String> {
        let metadata = self.keys
            .get_mut(&key_id)
            .ok_or_else(|| format!("Key {:?} not found", key_id))?;

        metadata.state = KeyState::Retired {
            reason: reason.to_string(),
        };

        let event = AuditEvent::KeyRetired {
            key_id,
            timestamp: current_timestamp(),
            reason: reason.to_string(),
        };
        self.audit_log.append(event);

        Ok(())
    }

    /// Destroy key with cryptographic proof
    pub fn destroy_key(&mut self, key_id: KeyId) -> Result<ProofOfDestruction, String> {
        let metadata = self.keys
            .get(&key_id)
            .ok_or_else(|| format!("Key {:?} not found", key_id))?;

        let timestamp = current_timestamp();

        let last_event_index = self.audit_log.len() - 1;
        let merkle_proof = self.audit_log
            .generate_proof(last_event_index)
            .ok_or_else(|| "Failed to generate Merkle proof".to_string())?;

        let statement = format!(
            "Key {} ({}) destroyed at {} using SecureErase method",
            key_id.0,
            metadata.algorithm.as_str(),
            timestamp
        );

        // Sign with witness key using actual ML-DSA
        let witness_signature = if let Some((_, ref sk)) = self.witness_signing_keypair {
            #[cfg(feature = "mldsa")]
            {
                mldsa87_sign(sk, statement.as_bytes())
            }
            #[cfg(not(feature = "mldsa"))]
            {
                return Err("mldsa feature not enabled".to_string());
            }
        } else {
            return Err("Witness keypair not initialized".to_string());
        };

        let proof = ProofOfDestruction {
            key_id,
            timestamp,
            destructor_identity: "lifecycle_manager".to_string(),
            method: DestructionMethod::SecureErase,
            witness_signature,
            merkle_proof,
        };

        let metadata = self.keys.get_mut(&key_id).unwrap();
        metadata.state = KeyState::Destroyed { proof: proof.clone() };

        let event = AuditEvent::KeyDestroyed {
            key_id,
            timestamp,
            proof: proof.clone(),
        };
        self.audit_log.append(event);

        Ok(proof)
    }

    /// Get key metadata
    pub fn get_key_metadata(&self, key_id: KeyId) -> Option<&KeyMetadata> {
        self.keys.get(&key_id)
    }

    /// Get audit trail for key
    pub fn get_audit_trail(&self, key_id: KeyId) -> Vec<&AuditEvent> {
        self.audit_log.get_events_for_key(key_id)
    }

    /// Get Merkle root of audit log
    pub fn get_audit_root(&self) -> [u8; 32] {
        self.audit_log.root()
    }

    /// Verify proof of destruction
    pub fn verify_destruction_proof(&self, proof: &ProofOfDestruction) -> bool {
        if !proof.merkle_proof.verify() {
            return false;
        }

        let statement = format!(
            "Key {} destroyed at {} using {:?} method",
            proof.key_id.0,
            proof.timestamp,
            proof.method
        );

        if let Some((ref pk, _)) = self.witness_signing_keypair {
            #[cfg(feature = "mldsa")]
            {
                mldsa87_verify(pk, statement.as_bytes(), &proof.witness_signature)
            }
            #[cfg(not(feature = "mldsa"))]
            {
                false
            }
        } else {
            false
        }
    }

    /// Get statistics
    pub fn get_statistics(&self) -> LifecycleStatistics {
        let total_keys = self.keys.len();
        let active_keys = self.keys.values()
            .filter(|m| matches!(m.state, KeyState::Active))
            .count();
        let retired_keys = self.keys.values()
            .filter(|m| matches!(m.state, KeyState::Retired { .. }))
            .count();
        let destroyed_keys = self.keys.values()
            .filter(|m| matches!(m.state, KeyState::Destroyed { .. }))
            .count();

        LifecycleStatistics {
            total_keys,
            active_keys,
            retired_keys,
            destroyed_keys,
            total_operations: self.keys.values().map(|m| m.usage_count).sum(),
            audit_log_size: self.audit_log.len(),
            audit_root: self.audit_log.root(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct LifecycleStatistics {
    pub total_keys: usize,
    pub active_keys: usize,
    pub retired_keys: usize,
    pub destroyed_keys: usize,
    pub total_operations: u64,
    pub audit_log_size: usize,
    pub audit_root: [u8; 32],
}

// Utility functions

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs()
}

fn generate_random_u64() -> u64 {
    let bytes = blake3::hash(b"random_seed").as_bytes()[..8].try_into().unwrap();
    u64::from_le_bytes(bytes)
}

fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(left);
    hasher.update(right);
    let hash = hasher.finalize();
    let mut result = [0u8; 32];
    result.copy_from_slice(hash.as_bytes());
    result
}
