//! Public self-service admission contracts. No administrator approves a user.
use serde::{Deserialize, Serialize};
pub const VALIDATOR_ADMISSION_PREFIX: &str = "posy-validator-admission/v1/";
pub const VALIDATOR_BOND_PREFIX: &str = "posy-validator-bond/v1/";
pub const VALIDATOR_ADMISSION_SIGNING_DOMAIN: &str = "SYNERGY-VALIDATOR-ADMISSION-POSSESSION-V1";
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutomaticValidatorAdmissionPolicy {
    pub schema_version: u32,
    pub minimum_bond_nwei: String,
    pub initial_frozen_voting_weight: u128,
    pub maximum_admissions_per_epoch: u16,
    pub minimum_shadow_finalized_blocks: u64,
}
impl AutomaticValidatorAdmissionPolicy {
    pub fn validate(&self) -> Result<(), String> {
        let amount = self
            .minimum_bond_nwei
            .parse::<u128>()
            .map_err(|_| "invalid validator bond")?;
        if self.schema_version != 1
            || amount.to_string() != self.minimum_bond_nwei
            || amount < synergy_protocol_types::VALIDATOR_MINIMUM_BOND_NWEI
            || self.initial_frozen_voting_weight == 0
            || !(1..=4).contains(&self.maximum_admissions_per_epoch)
            || self.minimum_shadow_finalized_blocks < 3
            || self.minimum_shadow_finalized_blocks > 1000
        {
            return Err("invalid bounded automatic validator admission policy".into());
        }
        Ok(())
    }
    pub fn bond_nwei(&self) -> Result<u128, String> {
        self.validate()?;
        self.minimum_bond_nwei
            .parse()
            .map_err(|_| "invalid validator bond".into())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidatorAdmissionSpec {
    pub schema_version: u32,
    pub chain_id: u64,
    pub network_id: String,
    pub genesis_hash: String,
    pub frozen_epoch: u64,
    pub frozen_epoch_context_root: String,
    pub effective_epoch: u64,
    pub owner_wallet: String,
    pub validator_id: String,
    #[serde(with = "synergy_protocol_types::canonical_bytes")]
    pub identity_root_public_key: Vec<u8>,
    pub consensus_key_id: String,
    #[serde(with = "synergy_protocol_types::canonical_bytes")]
    pub consensus_public_key: Vec<u8>,
    pub transport_key_id: String,
    #[serde(with = "synergy_protocol_types::canonical_bytes")]
    pub transport_public_key: Vec<u8>,
    pub ingress_kem_key_id: String,
    #[serde(with = "synergy_protocol_types::canonical_bytes")]
    pub ingress_kem_public_key: Vec<u8>,
    pub sync_finalized_height: u64,
    pub sync_finalized_block_id: String,
    pub dial_address: String,
    pub enrollment_sha256: String,
}
impl ValidatorAdmissionSpec {
    pub fn validate_shape(&self) -> Result<(), String> {
        if self.schema_version != 1
            || self.chain_id == 0
            || !crate::bounded(&self.network_id, 256)
            || self.genesis_hash.len() != 64
            || self.frozen_epoch_context_root.len() != 64
            || self.sync_finalized_height == 0
            || self.sync_finalized_block_id.len() != 64
            || self.frozen_epoch.checked_add(1) != Some(self.effective_epoch)
            || !crate::bounded(&self.owner_wallet, 128)
            || !crate::bounded(&self.validator_id, 128)
            || !crate::bounded(&self.consensus_key_id, 128)
            || !crate::bounded(&self.transport_key_id, 128)
            || !crate::bounded(&self.ingress_kem_key_id, 128)
            || self.identity_root_public_key.len() != 1793
            || self.consensus_public_key.len() != 1952
            || self.transport_public_key.len() != 1952
            || self.ingress_kem_public_key.len() != 1568
            || self.consensus_key_id == self.transport_key_id
            || self.enrollment_sha256.len() != 64
            || self.dial_address.len() > 128
            || self.consensus_public_key == self.transport_public_key
        {
            return Err("invalid native validator admission shape".into());
        }
        Ok(())
    }
    pub fn signing_bytes(&self) -> Result<Vec<u8>, String> {
        self.validate_shape()?;
        let mut bytes = b"SYNERGY/VALIDATOR-ADMISSION-POSSESSION/v1\0".to_vec();
        bytes.extend_from_slice(&serde_json::to_vec(self).map_err(|e| e.to_string())?);
        Ok(bytes)
    }
    pub fn record_key(&self) -> String {
        format!(
            "{VALIDATOR_ADMISSION_PREFIX}epoch-{:020}/{}",
            self.effective_epoch, self.validator_id
        )
    }
    pub fn bond_key(&self) -> String {
        format!("{VALIDATOR_BOND_PREFIX}{}", self.validator_id)
    }
    pub fn escrow_account(&self) -> String {
        format!("validator-bond:{}", self.validator_id)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidatorAdmissionRequest {
    pub spec: ValidatorAdmissionSpec,
    #[serde(with = "synergy_protocol_types::canonical_bytes")]
    pub identity_root_signature: Vec<u8>,
    #[serde(with = "synergy_protocol_types::canonical_bytes")]
    pub consensus_possession_signature: Vec<u8>,
    #[serde(with = "synergy_protocol_types::canonical_bytes")]
    pub transport_possession_signature: Vec<u8>,
    /// Exact public three-QC source document, authenticated by the native owner.
    #[serde(with = "synergy_protocol_types::bounded_document")]
    pub sync_finality_document: Vec<u8>,
}
/// The native executor creates this only after identity/key possession, bond
/// debit and sync evidence pass. Consumers authenticate its complete World.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalizedValidatorAdmissionRecord {
    pub schema_version: u32,
    pub chain_id: u64,
    pub network_id: String,
    pub genesis_hash: String,
    pub frozen_epoch: u64,
    pub frozen_epoch_context_root: String,
    pub effective_epoch: u64,
    pub owner_wallet: String,
    pub validator_id: String,
    pub identity_root_sha3_256: String,
    pub consensus_key_id: String,
    pub consensus_public_key: Vec<u8>,
    pub transport_key_id: String,
    pub transport_public_key: Vec<u8>,
    pub ingress_kem_key_id: String,
    pub ingress_kem_public_key: Vec<u8>,
    pub installed_height: u64,
    pub eligible_finalized_height: u64,
    pub sync_finalized_height: u64,
    pub sync_finalized_block_id: String,
    pub bond_nwei: String,
    pub escrow_account: String,
    pub request_sha256: String,
    pub dial_address: String,
    pub enrollment_sha256: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidatorBondRecord {
    pub schema_version: u32,
    pub chain_id: u64,
    pub genesis_hash: String,
    pub validator_id: String,
    pub owner_wallet: String,
    pub bond_nwei: String,
    pub escrow_account: String,
    pub installed_height: u64,
    pub effective_epoch: u64,
    pub request_sha256: String,
}
impl FinalizedValidatorAdmissionRecord {
    pub fn bond_record(&self) -> ValidatorBondRecord {
        ValidatorBondRecord {
            schema_version: 1,
            chain_id: self.chain_id,
            genesis_hash: self.genesis_hash.clone(),
            validator_id: self.validator_id.clone(),
            owner_wallet: self.owner_wallet.clone(),
            bond_nwei: self.bond_nwei.clone(),
            escrow_account: self.escrow_account.clone(),
            installed_height: self.installed_height,
            effective_epoch: self.effective_epoch,
            request_sha256: self.request_sha256.clone(),
        }
    }
}
impl FinalizedValidatorAdmissionRecord {
    pub fn record_key(&self) -> String {
        format!(
            "{VALIDATOR_ADMISSION_PREFIX}epoch-{:020}/{}",
            self.effective_epoch, self.validator_id
        )
    }
    pub fn bond_key(&self) -> String {
        format!("{VALIDATOR_BOND_PREFIX}{}", self.validator_id)
    }
}

pub const PROTECTED_VALIDATOR_BOND_ACTION: u16 = 0x700b;
pub const VALIDATOR_BOND_SETTLEMENT_PREFIX: &str =
    "apqe-protected-account-candidate/v1/validator-bond/";
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidatorBondOutcome {
    Registered,
    Rejected,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidatorBondSettlement {
    pub version: u8,
    pub genesis: [u8; 32],
    pub account: [u8; 20],
    pub intent_id: [u8; 32],
    pub validator_id: String,
    pub request_sha256: String,
    pub native_intent_digest: Vec<u8>,
    pub envelope_id: String,
    pub policy_epoch: u64,
    pub nonce_before: u64,
    pub nonce_after: u64,
    pub source_finalized_height: u64,
    pub included_height: u64,
    pub bond_nwei: String,
    pub gas_used: u64,
    pub fee_nwei: String,
    pub outcome: ValidatorBondOutcome,
}
impl ValidatorBondSettlement {
    pub fn record_key(&self) -> String {
        format!("{VALIDATOR_BOND_SETTLEMENT_PREFIX}{}", self.envelope_id)
    }
}
