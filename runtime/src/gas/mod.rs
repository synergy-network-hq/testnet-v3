// Synergy Network gas and fee accounting.
//
// Consensus-facing gas math is integer-only. Monetary values are nWei and
// percentage-like parameters are basis points.

use serde::{Deserialize, Serialize};
use std::fmt;

pub mod constants {
    pub const SNRG_DECIMALS: u32 = 9;
    pub const NWEI_PER_SNRG: u128 = 1_000_000_000;
    pub const MIN_GAS_PRICE: u64 = 1;
    pub const DEFAULT_GAS_PRICE: u64 = 40;
    pub const MAX_GAS_PRICE: u64 = 1_000_000_000;
    pub const MAX_GAS_LIMIT: u64 = 10_000_000;
    pub const GAS_LIMIT_TRANSFER: u64 = 38_500;
    pub const BLOCK_GAS_LIMIT: u64 = 30_000_000;
    pub const BPS_DENOMINATOR: u64 = 10_000;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct NWei(pub u128);

impl NWei {
    pub fn from_nwei(nwei: u128) -> Self {
        Self(nwei)
    }

    pub fn from_snrg_units(whole_snrg: u128, fractional_nwei: u128) -> Option<Self> {
        if fractional_nwei >= constants::NWEI_PER_SNRG {
            return None;
        }
        whole_snrg
            .checked_mul(constants::NWEI_PER_SNRG)
            .and_then(|whole| whole.checked_add(fractional_nwei))
            .map(Self)
    }

    pub fn as_nwei(self) -> u128 {
        self.0
    }

    pub fn format_snrg(self) -> String {
        let whole = self.0 / constants::NWEI_PER_SNRG;
        let frac = self.0 % constants::NWEI_PER_SNRG;
        format!("{whole}.{frac:09}")
    }

    pub fn checked_add(self, other: NWei) -> Option<NWei> {
        self.0.checked_add(other.0).map(NWei)
    }

    pub fn checked_sub(self, other: NWei) -> Option<NWei> {
        self.0.checked_sub(other.0).map(NWei)
    }

    pub fn checked_mul(self, scalar: u128) -> Option<NWei> {
        self.0.checked_mul(scalar).map(NWei)
    }

    pub fn checked_div(self, scalar: u128) -> Option<NWei> {
        if scalar == 0 {
            return None;
        }
        Some(NWei(self.0 / scalar))
    }

    pub fn to_evm_wei(self) -> Option<u128> {
        self.0.checked_mul(1_000_000_000)
    }

    pub fn from_evm_wei(evm_wei: u128) -> Self {
        NWei(evm_wei / 1_000_000_000)
    }

    pub fn to_bitcoin_sats(self) -> Option<u64> {
        u64::try_from(self.0 / 10).ok()
    }

    pub fn from_bitcoin_sats(sats: u64) -> Self {
        NWei((sats as u128) * 10)
    }
}

impl fmt::Display for NWei {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} nWei ({} SNRG)", self.0, self.format_snrg())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct GasPrice(pub u64);

impl GasPrice {
    pub fn from_nwei(nwei: u64) -> Result<Self, &'static str> {
        if nwei < constants::MIN_GAS_PRICE {
            return Err("Gas price below minimum");
        }
        if nwei > constants::MAX_GAS_PRICE {
            return Err("Gas price above maximum");
        }
        Ok(GasPrice(nwei))
    }

    pub fn as_nwei(self) -> u64 {
        self.0
    }
}

impl Default for GasPrice {
    fn default() -> Self {
        GasPrice(40)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct GasLimit(pub u64);

impl GasLimit {
    pub fn new(limit: u64) -> Result<Self, &'static str> {
        if limit == 0 {
            return Err("Gas limit cannot be zero");
        }
        if limit > constants::MAX_GAS_LIMIT {
            return Err("Gas limit exceeds maximum");
        }
        Ok(GasLimit(limit))
    }

    pub fn transfer() -> Self {
        GasLimit(GasSchedule::default().base_tx_gas + GasSchedule::default().native_transfer_gas)
    }

    pub fn contract_deploy() -> Self {
        GasLimit(GasSchedule::default().synq_contract_deploy_base_gas)
    }

    pub fn contract_call() -> Self {
        GasLimit(GasSchedule::default().synq_contract_call_base_gas)
    }

    pub fn as_u64(self) -> u64 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct GasFee {
    pub gas_limit: u64,
    pub gas_price_nwei: u64,
    pub fee_nwei: u128,
}

impl GasFee {
    pub fn calculate(gas_limit: GasLimit, gas_price: GasPrice) -> Self {
        let fee_nwei = (gas_limit.0 as u128) * (gas_price.0 as u128);
        GasFee {
            gas_limit: gas_limit.0,
            gas_price_nwei: gas_price.0,
            fee_nwei,
        }
    }

    pub fn as_nwei(self) -> NWei {
        NWei(self.fee_nwei)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct GasSchedule {
    pub base_tx_gas: u64,
    pub native_transfer_gas: u64,
    pub scetp_transfer_gas: u64,
    pub payload_byte_gas: u64,
    pub signature_base_gas: u64,
    pub pqc_signature_verify_gas: u64,
    pub pqc_kem_operation_gas: u64,
    pub pqc_key_registration_gas: u64,
    pub pqc_key_rotation_gas: u64,
    pub compute_unit_gas: u64,
    pub storage_read_gas: u64,
    pub storage_write_gas: u64,
    pub storage_byte_gas: u64,
    pub state_creation_gas: u64,
    pub state_deletion_refund_gas: u64,
    pub validator_registration_gas: u64,
    pub validator_heartbeat_gas: u64,
    pub staking_bond_gas: u64,
    pub unstake_request_gas: u64,
    pub governance_proposal_gas: u64,
    pub governance_vote_gas: u64,
    pub synq_contract_deploy_base_gas: u64,
    pub synq_contract_byte_gas: u64,
    pub synq_contract_call_base_gas: u64,
    pub synq_contract_execution_unit_gas: u64,
    pub sxcp_intent_creation_gas: u64,
    pub sxcp_proof_verification_base_gas: u64,
    pub sxcp_proof_byte_gas: u64,
    pub sxcp_attestation_submission_gas: u64,
    pub uma_record_create_gas: u64,
    pub uma_record_update_gas: u64,
    pub sns_name_register_gas: u64,
    pub sns_name_update_gas: u64,
}

impl Default for GasSchedule {
    fn default() -> Self {
        Self {
            base_tx_gas: 21_000,
            native_transfer_gas: 5_000,
            scetp_transfer_gas: 12_000,
            payload_byte_gas: 16,
            signature_base_gas: 500,
            pqc_signature_verify_gas: 12_000,
            pqc_kem_operation_gas: 18_000,
            pqc_key_registration_gas: 40_000,
            pqc_key_rotation_gas: 30_000,
            compute_unit_gas: 1,
            storage_read_gas: 100,
            storage_write_gas: 2_000,
            storage_byte_gas: 25,
            state_creation_gas: 20_000,
            state_deletion_refund_gas: 5_000,
            validator_registration_gas: 75_000,
            validator_heartbeat_gas: 3_000,
            staking_bond_gas: 25_000,
            unstake_request_gas: 20_000,
            governance_proposal_gas: 100_000,
            governance_vote_gas: 10_000,
            synq_contract_deploy_base_gas: 150_000,
            synq_contract_byte_gas: 200,
            synq_contract_call_base_gas: 30_000,
            synq_contract_execution_unit_gas: 1,
            sxcp_intent_creation_gas: 45_000,
            sxcp_proof_verification_base_gas: 125_000,
            sxcp_proof_byte_gas: 50,
            sxcp_attestation_submission_gas: 60_000,
            uma_record_create_gas: 50_000,
            uma_record_update_gas: 25_000,
            sns_name_register_gas: 60_000,
            sns_name_update_gas: 30_000,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum GasActivityType {
    NativeSnrgTransfer,
    ScetpSameChainTransfer,
    ValidatorRegistration,
    ValidatorHeartbeat,
    StakingBond,
    UnstakeRequest,
    GovernanceProposal,
    GovernanceVote,
    SynqContractDeployment,
    SynqContractCall,
    AegisPqcKeyRegistration,
    AegisPqcKeyRotation,
    SxcpIntentCreation,
    SxcpProofVerification,
    SxcpRelayerAttestation,
    UmaRecordCreation,
    UmaRecordUpdate,
    SnsNameRegistration,
    SnsNameUpdate,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct GasComputationInput {
    pub activity_type: GasActivityType,
    pub payload_size_bytes: u64,
    pub validator_metadata_size_bytes: u64,
    pub proposal_size_bytes: u64,
    pub contract_bytecode_size: u64,
    pub initial_contract_state_size_bytes: u64,
    pub execution_units: u64,
    pub storage_reads: u64,
    pub storage_writes: u64,
    pub storage_bytes_written: u64,
    pub key_material_size_bytes: u64,
    pub proof_size_bytes: u64,
    pub signature_count: u64,
    pub uma_record_size_bytes: u64,
    pub sns_record_size_bytes: u64,
}

impl GasComputationInput {
    pub fn new(activity_type: GasActivityType) -> Self {
        Self {
            activity_type,
            payload_size_bytes: 0,
            validator_metadata_size_bytes: 0,
            proposal_size_bytes: 0,
            contract_bytecode_size: 0,
            initial_contract_state_size_bytes: 0,
            execution_units: 0,
            storage_reads: 0,
            storage_writes: 0,
            storage_bytes_written: 0,
            key_material_size_bytes: 0,
            proof_size_bytes: 0,
            signature_count: 1,
            uma_record_size_bytes: 0,
            sns_record_size_bytes: 0,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct GasBreakdown {
    pub base_tx_gas: u64,
    pub payload_byte_gas: u64,
    pub signature_gas: u64,
    pub compute_gas: u64,
    pub storage_read_gas: u64,
    pub storage_write_gas: u64,
    pub state_creation_gas: u64,
    pub bandwidth_gas: u64,
    pub pqc_gas: u64,
    pub sxcp_gas: u64,
    pub contract_deployment_gas: u64,
    pub contract_execution_gas: u64,
    pub operation_gas: u64,
    pub total_gas: u64,
}

impl GasBreakdown {
    fn empty(schedule: &GasSchedule) -> Self {
        Self {
            base_tx_gas: schedule.base_tx_gas,
            payload_byte_gas: 0,
            signature_gas: 0,
            compute_gas: 0,
            storage_read_gas: 0,
            storage_write_gas: 0,
            state_creation_gas: 0,
            bandwidth_gas: 0,
            pqc_gas: 0,
            sxcp_gas: 0,
            contract_deployment_gas: 0,
            contract_execution_gas: 0,
            operation_gas: 0,
            total_gas: schedule.base_tx_gas,
        }
    }

    fn add(&mut self, field: GasComponent, amount: u64) -> Result<(), String> {
        match field {
            GasComponent::Payload => {
                self.payload_byte_gas = checked_add(self.payload_byte_gas, amount)?
            }
            GasComponent::Signature => {
                self.signature_gas = checked_add(self.signature_gas, amount)?
            }
            GasComponent::Compute => self.compute_gas = checked_add(self.compute_gas, amount)?,
            GasComponent::StorageRead => {
                self.storage_read_gas = checked_add(self.storage_read_gas, amount)?
            }
            GasComponent::StorageWrite => {
                self.storage_write_gas = checked_add(self.storage_write_gas, amount)?
            }
            GasComponent::StateCreation => {
                self.state_creation_gas = checked_add(self.state_creation_gas, amount)?
            }
            GasComponent::Bandwidth => {
                self.bandwidth_gas = checked_add(self.bandwidth_gas, amount)?
            }
            GasComponent::Pqc => self.pqc_gas = checked_add(self.pqc_gas, amount)?,
            GasComponent::Sxcp => self.sxcp_gas = checked_add(self.sxcp_gas, amount)?,
            GasComponent::ContractDeployment => {
                self.contract_deployment_gas = checked_add(self.contract_deployment_gas, amount)?
            }
            GasComponent::ContractExecution => {
                self.contract_execution_gas = checked_add(self.contract_execution_gas, amount)?
            }
            GasComponent::Operation => {
                self.operation_gas = checked_add(self.operation_gas, amount)?
            }
        }
        self.total_gas = checked_add(self.total_gas, amount)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
enum GasComponent {
    Payload,
    Signature,
    Compute,
    StorageRead,
    StorageWrite,
    StateCreation,
    Bandwidth,
    Pqc,
    Sxcp,
    ContractDeployment,
    ContractExecution,
    Operation,
}

pub fn calculate_activity_gas(
    schedule: &GasSchedule,
    input: &GasComputationInput,
) -> Result<GasBreakdown, String> {
    let mut gas = GasBreakdown::empty(schedule);
    let payload_gas = checked_mul(schedule.payload_byte_gas, input.payload_size_bytes)?;
    gas.add(GasComponent::Payload, payload_gas)?;

    match input.activity_type {
        GasActivityType::NativeSnrgTransfer => {
            gas.add(GasComponent::Operation, schedule.native_transfer_gas)?;
            gas.add(GasComponent::Signature, schedule.signature_base_gas)?;
            gas.add(GasComponent::Pqc, schedule.pqc_signature_verify_gas)?;
        }
        GasActivityType::ScetpSameChainTransfer => {
            gas.add(GasComponent::Operation, schedule.scetp_transfer_gas)?;
            gas.add(GasComponent::Signature, schedule.signature_base_gas)?;
            gas.add(GasComponent::Pqc, schedule.pqc_signature_verify_gas)?;
            gas.add(GasComponent::StorageRead, schedule.storage_read_gas)?;
            gas.add(GasComponent::StorageWrite, schedule.storage_write_gas)?;
        }
        GasActivityType::ValidatorRegistration => {
            gas.add(GasComponent::Operation, schedule.validator_registration_gas)?;
            gas.add(GasComponent::Pqc, schedule.pqc_key_registration_gas)?;
            gas.add(GasComponent::Pqc, schedule.pqc_signature_verify_gas)?;
            gas.add(GasComponent::StateCreation, schedule.state_creation_gas)?;
            gas.add(
                GasComponent::StorageWrite,
                checked_mul(
                    schedule.storage_byte_gas,
                    input.validator_metadata_size_bytes,
                )?,
            )?;
        }
        GasActivityType::ValidatorHeartbeat => {
            gas.add(GasComponent::Operation, schedule.validator_heartbeat_gas)?;
            gas.add(GasComponent::Pqc, schedule.pqc_signature_verify_gas)?;
        }
        GasActivityType::StakingBond => {
            gas.add(GasComponent::Operation, schedule.staking_bond_gas)?;
            gas.add(GasComponent::Pqc, schedule.pqc_signature_verify_gas)?;
            gas.add(GasComponent::StorageRead, schedule.storage_read_gas)?;
            gas.add(GasComponent::StorageWrite, schedule.storage_write_gas)?;
        }
        GasActivityType::UnstakeRequest => {
            gas.add(GasComponent::Operation, schedule.unstake_request_gas)?;
            gas.add(GasComponent::Pqc, schedule.pqc_signature_verify_gas)?;
            gas.add(GasComponent::StorageRead, schedule.storage_read_gas)?;
            gas.add(GasComponent::StorageWrite, schedule.storage_write_gas)?;
        }
        GasActivityType::GovernanceProposal => {
            gas.add(GasComponent::Operation, schedule.governance_proposal_gas)?;
            gas.add(GasComponent::Pqc, schedule.pqc_signature_verify_gas)?;
            gas.add(GasComponent::StateCreation, schedule.state_creation_gas)?;
            gas.add(
                GasComponent::StorageWrite,
                checked_mul(schedule.storage_byte_gas, input.proposal_size_bytes)?,
            )?;
        }
        GasActivityType::GovernanceVote => {
            gas.add(GasComponent::Operation, schedule.governance_vote_gas)?;
            gas.add(GasComponent::Pqc, schedule.pqc_signature_verify_gas)?;
            gas.add(GasComponent::StorageRead, schedule.storage_read_gas)?;
            gas.add(GasComponent::StorageWrite, schedule.storage_write_gas)?;
        }
        GasActivityType::SynqContractDeployment => {
            gas.add(
                GasComponent::ContractDeployment,
                schedule.synq_contract_deploy_base_gas,
            )?;
            gas.add(
                GasComponent::ContractDeployment,
                checked_mul(
                    schedule.synq_contract_byte_gas,
                    input.contract_bytecode_size,
                )?,
            )?;
            gas.add(GasComponent::Pqc, schedule.pqc_signature_verify_gas)?;
            gas.add(GasComponent::StateCreation, schedule.state_creation_gas)?;
            gas.add(
                GasComponent::StorageWrite,
                checked_mul(
                    schedule.storage_byte_gas,
                    input.initial_contract_state_size_bytes,
                )?,
            )?;
        }
        GasActivityType::SynqContractCall => {
            gas.add(
                GasComponent::ContractExecution,
                schedule.synq_contract_call_base_gas,
            )?;
            gas.add(GasComponent::Pqc, schedule.pqc_signature_verify_gas)?;
            gas.add(
                GasComponent::ContractExecution,
                checked_mul(
                    schedule.synq_contract_execution_unit_gas,
                    input.execution_units,
                )?,
            )?;
            gas.add(
                GasComponent::StorageRead,
                checked_mul(schedule.storage_read_gas, input.storage_reads)?,
            )?;
            gas.add(
                GasComponent::StorageWrite,
                checked_mul(schedule.storage_write_gas, input.storage_writes)?,
            )?;
            gas.add(
                GasComponent::StorageWrite,
                checked_mul(schedule.storage_byte_gas, input.storage_bytes_written)?,
            )?;
        }
        GasActivityType::AegisPqcKeyRegistration => {
            gas.add(GasComponent::Pqc, schedule.pqc_key_registration_gas)?;
            gas.add(GasComponent::Pqc, schedule.pqc_signature_verify_gas)?;
            gas.add(GasComponent::StateCreation, schedule.state_creation_gas)?;
            gas.add(
                GasComponent::StorageWrite,
                checked_mul(schedule.storage_byte_gas, input.key_material_size_bytes)?,
            )?;
        }
        GasActivityType::AegisPqcKeyRotation => {
            gas.add(GasComponent::Pqc, schedule.pqc_key_rotation_gas)?;
            gas.add(GasComponent::Pqc, schedule.pqc_signature_verify_gas)?;
            gas.add(GasComponent::StorageRead, schedule.storage_read_gas)?;
            gas.add(GasComponent::StorageWrite, schedule.storage_write_gas)?;
            gas.add(
                GasComponent::StorageWrite,
                checked_mul(schedule.storage_byte_gas, input.key_material_size_bytes)?,
            )?;
        }
        GasActivityType::SxcpIntentCreation => {
            gas.add(GasComponent::Sxcp, schedule.sxcp_intent_creation_gas)?;
            gas.add(GasComponent::Pqc, schedule.pqc_signature_verify_gas)?;
            gas.add(GasComponent::StorageWrite, schedule.storage_write_gas)?;
        }
        GasActivityType::SxcpProofVerification => {
            gas.add(
                GasComponent::Sxcp,
                schedule.sxcp_proof_verification_base_gas,
            )?;
            gas.add(
                GasComponent::Sxcp,
                checked_mul(schedule.sxcp_proof_byte_gas, input.proof_size_bytes)?,
            )?;
            gas.add(
                GasComponent::Pqc,
                checked_mul(schedule.pqc_signature_verify_gas, input.signature_count)?,
            )?;
            gas.add(
                GasComponent::StorageRead,
                checked_mul(schedule.storage_read_gas, input.storage_reads)?,
            )?;
            gas.add(
                GasComponent::StorageWrite,
                checked_mul(schedule.storage_write_gas, input.storage_writes)?,
            )?;
        }
        GasActivityType::SxcpRelayerAttestation => {
            gas.add(GasComponent::Sxcp, schedule.sxcp_attestation_submission_gas)?;
            gas.add(GasComponent::Pqc, schedule.pqc_signature_verify_gas)?;
            gas.add(GasComponent::StorageRead, schedule.storage_read_gas)?;
            gas.add(GasComponent::StorageWrite, schedule.storage_write_gas)?;
        }
        GasActivityType::UmaRecordCreation => {
            gas.add(GasComponent::Operation, schedule.uma_record_create_gas)?;
            gas.add(GasComponent::Pqc, schedule.pqc_signature_verify_gas)?;
            gas.add(GasComponent::StateCreation, schedule.state_creation_gas)?;
            gas.add(
                GasComponent::StorageWrite,
                checked_mul(schedule.storage_byte_gas, input.uma_record_size_bytes)?,
            )?;
        }
        GasActivityType::UmaRecordUpdate => {
            gas.add(GasComponent::Operation, schedule.uma_record_update_gas)?;
            gas.add(GasComponent::Pqc, schedule.pqc_signature_verify_gas)?;
            gas.add(GasComponent::StorageRead, schedule.storage_read_gas)?;
            gas.add(GasComponent::StorageWrite, schedule.storage_write_gas)?;
            gas.add(
                GasComponent::StorageWrite,
                checked_mul(schedule.storage_byte_gas, input.uma_record_size_bytes)?,
            )?;
        }
        GasActivityType::SnsNameRegistration => {
            gas.add(GasComponent::Operation, schedule.sns_name_register_gas)?;
            gas.add(GasComponent::Pqc, schedule.pqc_signature_verify_gas)?;
            gas.add(GasComponent::StateCreation, schedule.state_creation_gas)?;
            gas.add(
                GasComponent::StorageWrite,
                checked_mul(schedule.storage_byte_gas, input.sns_record_size_bytes)?,
            )?;
        }
        GasActivityType::SnsNameUpdate => {
            gas.add(GasComponent::Operation, schedule.sns_name_update_gas)?;
            gas.add(GasComponent::Pqc, schedule.pqc_signature_verify_gas)?;
            gas.add(GasComponent::StorageRead, schedule.storage_read_gas)?;
            gas.add(GasComponent::StorageWrite, schedule.storage_write_gas)?;
            gas.add(
                GasComponent::StorageWrite,
                checked_mul(schedule.storage_byte_gas, input.sns_record_size_bytes)?,
            )?;
        }
    }

    Ok(gas)
}

pub fn calculate_total_fee_nwei(
    gas_used: u64,
    effective_gas_price_nwei: u64,
) -> Result<u128, String> {
    (gas_used as u128)
        .checked_mul(effective_gas_price_nwei as u128)
        .ok_or_else(|| "total fee overflow".to_string())
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum TransactionFeeType {
    NativeSnrgSend,
    TokenSend,
    Swap,
    Burn,
    Mint,
    Stake,
    Unstake,
    ContractCall,
    ContractDeploy,
    AiJobPayment,
    SxcpCrossChainValueAction,
    Unknown,
}

impl TransactionFeeType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NativeSnrgSend => "native_snrg_send",
            Self::TokenSend => "token_send",
            Self::Swap => "swap",
            Self::Burn => "burn",
            Self::Mint => "mint",
            Self::Stake => "stake",
            Self::Unstake => "unstake",
            Self::ContractCall => "contract_call",
            Self::ContractDeploy => "contract_deploy",
            Self::AiJobPayment => "ai_job_payment",
            Self::SxcpCrossChainValueAction => "sxcp_cross_chain_value_action",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ValuationStatus {
    NativeSnrg,
    FixedConfig,
    Unavailable,
    NotRequired,
}

impl ValuationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NativeSnrg => "native_snrg",
            Self::FixedConfig => "fixed_config",
            Self::Unavailable => "unavailable",
            Self::NotRequired => "not_required",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FeeScheduleEntry {
    pub tx_type: TransactionFeeType,
    pub amount_fee_bps: u64,
    pub min_amount_fee_nwei: u128,
    pub max_amount_fee_nwei: u128,
    pub valuation_required: bool,
    pub storage_fee_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FeeSchedule {
    pub entries: Vec<FeeScheduleEntry>,
}

impl FeeSchedule {
    pub fn entry(&self, tx_type: TransactionFeeType) -> Option<&FeeScheduleEntry> {
        self.entries.iter().find(|entry| entry.tx_type == tx_type)
    }
}

impl Default for FeeSchedule {
    fn default() -> Self {
        Self {
            entries: vec![
                FeeScheduleEntry {
                    tx_type: TransactionFeeType::NativeSnrgSend,
                    amount_fee_bps: 2,
                    min_amount_fee_nwei: 0,
                    max_amount_fee_nwei: u128::MAX,
                    valuation_required: false,
                    storage_fee_enabled: false,
                },
                FeeScheduleEntry {
                    tx_type: TransactionFeeType::TokenSend,
                    amount_fee_bps: 3,
                    min_amount_fee_nwei: 0,
                    max_amount_fee_nwei: u128::MAX,
                    valuation_required: true,
                    storage_fee_enabled: false,
                },
                FeeScheduleEntry {
                    tx_type: TransactionFeeType::Swap,
                    amount_fee_bps: 10,
                    min_amount_fee_nwei: 0,
                    max_amount_fee_nwei: u128::MAX,
                    valuation_required: true,
                    storage_fee_enabled: false,
                },
                FeeScheduleEntry {
                    tx_type: TransactionFeeType::Burn,
                    amount_fee_bps: 1,
                    min_amount_fee_nwei: 0,
                    max_amount_fee_nwei: u128::MAX,
                    valuation_required: false,
                    storage_fee_enabled: false,
                },
                FeeScheduleEntry {
                    tx_type: TransactionFeeType::Mint,
                    amount_fee_bps: 5,
                    min_amount_fee_nwei: 0,
                    max_amount_fee_nwei: u128::MAX,
                    valuation_required: true,
                    storage_fee_enabled: false,
                },
                FeeScheduleEntry {
                    tx_type: TransactionFeeType::Stake,
                    amount_fee_bps: 0,
                    min_amount_fee_nwei: 0,
                    max_amount_fee_nwei: 0,
                    valuation_required: false,
                    storage_fee_enabled: false,
                },
                FeeScheduleEntry {
                    tx_type: TransactionFeeType::Unstake,
                    amount_fee_bps: 0,
                    min_amount_fee_nwei: 0,
                    max_amount_fee_nwei: 0,
                    valuation_required: false,
                    storage_fee_enabled: false,
                },
                FeeScheduleEntry {
                    tx_type: TransactionFeeType::ContractCall,
                    amount_fee_bps: 2,
                    min_amount_fee_nwei: 0,
                    max_amount_fee_nwei: u128::MAX,
                    valuation_required: false,
                    storage_fee_enabled: false,
                },
                FeeScheduleEntry {
                    tx_type: TransactionFeeType::ContractDeploy,
                    amount_fee_bps: 0,
                    min_amount_fee_nwei: 0,
                    max_amount_fee_nwei: 0,
                    valuation_required: false,
                    storage_fee_enabled: true,
                },
                FeeScheduleEntry {
                    tx_type: TransactionFeeType::AiJobPayment,
                    amount_fee_bps: 5,
                    min_amount_fee_nwei: 0,
                    max_amount_fee_nwei: u128::MAX,
                    valuation_required: true,
                    storage_fee_enabled: false,
                },
                FeeScheduleEntry {
                    tx_type: TransactionFeeType::SxcpCrossChainValueAction,
                    amount_fee_bps: 5,
                    min_amount_fee_nwei: 0,
                    max_amount_fee_nwei: u128::MAX,
                    valuation_required: true,
                    storage_fee_enabled: false,
                },
                FeeScheduleEntry {
                    tx_type: TransactionFeeType::Unknown,
                    amount_fee_bps: 0,
                    min_amount_fee_nwei: 0,
                    max_amount_fee_nwei: 0,
                    valuation_required: false,
                    storage_fee_enabled: false,
                },
            ],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkFeeInput {
    pub tx_type: TransactionFeeType,
    pub asset_id: String,
    pub amount_raw: u128,
    pub amount_snrgequivalent_nwei: u128,
    pub valuation_source: String,
    pub valuation_status: ValuationStatus,
    pub gas_used: u64,
    pub base_fee_per_gas_nwei: u64,
    pub gas_fee_nwei: u128,
    pub storage_fee_nwei: u128,
    pub priority_fee_nwei: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkFeeBreakdown {
    pub tx_type: TransactionFeeType,
    pub tx_type_name: String,
    pub asset_id: String,
    pub amount_raw: u128,
    pub amount_snrgequivalent_nwei: u128,
    pub valuation_source: String,
    pub valuation_status: ValuationStatus,
    pub valuation_status_name: String,
    pub amount_fee_bps: u64,
    pub gas_used: u64,
    pub base_fee_per_gas_nwei: u64,
    pub gas_fee_nwei: u128,
    pub amount_protocol_fee_nwei: u128,
    pub storage_fee_nwei: u128,
    pub priority_fee_nwei: u128,
    pub total_network_fee_nwei: u128,
    pub fee_collector_address: String,
}

pub fn calculate_network_fee(
    input: NetworkFeeInput,
    schedule: &FeeSchedule,
) -> Result<NetworkFeeBreakdown, String> {
    let entry = schedule
        .entry(input.tx_type)
        .or_else(|| schedule.entry(TransactionFeeType::Unknown))
        .ok_or_else(|| "fee schedule is missing unknown fallback entry".to_string())?;

    let amount_protocol_fee =
        if entry.valuation_required && input.valuation_status == ValuationStatus::Unavailable {
            0
        } else {
            let raw = input
                .amount_snrgequivalent_nwei
                .checked_mul(entry.amount_fee_bps as u128)
                .ok_or_else(|| "amount protocol fee overflow".to_string())?
                / (constants::BPS_DENOMINATOR as u128);
            raw.max(entry.min_amount_fee_nwei)
                .min(entry.max_amount_fee_nwei)
        };

    let total_network_fee = input
        .gas_fee_nwei
        .checked_add(amount_protocol_fee)
        .and_then(|value| value.checked_add(input.storage_fee_nwei))
        .and_then(|value| value.checked_add(input.priority_fee_nwei))
        .ok_or_else(|| "network fee total overflow".to_string())?;

    Ok(NetworkFeeBreakdown {
        tx_type: input.tx_type,
        tx_type_name: input.tx_type.as_str().to_string(),
        asset_id: input.asset_id,
        amount_raw: input.amount_raw,
        amount_snrgequivalent_nwei: input.amount_snrgequivalent_nwei,
        valuation_source: input.valuation_source,
        valuation_status: input.valuation_status,
        valuation_status_name: input.valuation_status.as_str().to_string(),
        amount_fee_bps: entry.amount_fee_bps,
        gas_used: input.gas_used,
        base_fee_per_gas_nwei: input.base_fee_per_gas_nwei,
        gas_fee_nwei: input.gas_fee_nwei,
        amount_protocol_fee_nwei: amount_protocol_fee,
        storage_fee_nwei: input.storage_fee_nwei,
        priority_fee_nwei: input.priority_fee_nwei,
        total_network_fee_nwei: total_network_fee,
        fee_collector_address: crate::token::fee_collector_address()?,
    })
}

pub fn calculate_effective_gas_price_nwei(
    base_fee_nwei: u64,
    priority_fee_nwei: u64,
    congestion_premium_nwei: u64,
) -> Result<u64, String> {
    base_fee_nwei
        .checked_add(priority_fee_nwei)
        .and_then(|value| value.checked_add(congestion_premium_nwei))
        .ok_or_else(|| "effective gas price overflow".to_string())
}

pub fn calculate_congestion_premium_nwei(
    base_fee_nwei: u64,
    utilization_bps: u64,
    target_epoch_utilization_bps: u64,
    congestion_multiplier_bps: u64,
    max_congestion_premium_bps: u64,
) -> Result<u64, String> {
    if target_epoch_utilization_bps == 0 {
        return Err("target utilization cannot be zero".to_string());
    }
    if utilization_bps <= target_epoch_utilization_bps {
        return Ok(0);
    }

    let excess_bps = utilization_bps - target_epoch_utilization_bps;
    let raw = (base_fee_nwei as u128)
        .checked_mul(congestion_multiplier_bps as u128)
        .and_then(|value| value.checked_mul(excess_bps as u128))
        .ok_or_else(|| "congestion premium overflow".to_string())?
        / (target_epoch_utilization_bps as u128)
        / (constants::BPS_DENOMINATOR as u128);
    let cap = (base_fee_nwei as u128)
        .checked_mul(max_congestion_premium_bps as u128)
        .ok_or_else(|| "congestion cap overflow".to_string())?
        / (constants::BPS_DENOMINATOR as u128);
    u64::try_from(raw.min(cap)).map_err(|_| "congestion premium exceeds u64".to_string())
}

pub fn calculate_next_base_fee_nwei(
    base_fee_current_nwei: u64,
    gas_used_epoch: u64,
    target_gas_epoch: u64,
    adjustment_rate_bps: u64,
    max_base_fee_change_per_epoch_bps: u64,
    min_base_fee_nwei: u64,
) -> Result<u64, String> {
    if target_gas_epoch == 0 {
        return Err("target gas epoch cannot be zero".to_string());
    }
    if min_base_fee_nwei == 0 {
        return Err("min base fee must be at least 1".to_string());
    }
    if gas_used_epoch == target_gas_epoch || adjustment_rate_bps == 0 {
        return Ok(base_fee_current_nwei.max(min_base_fee_nwei));
    }

    let delta_gas = gas_used_epoch.abs_diff(target_gas_epoch) as u128;
    let base = base_fee_current_nwei.max(min_base_fee_nwei) as u128;
    let raw_delta = base
        .checked_mul(adjustment_rate_bps as u128)
        .and_then(|value| value.checked_mul(delta_gas))
        .ok_or_else(|| "base fee delta overflow".to_string())?
        / (target_gas_epoch as u128)
        / (constants::BPS_DENOMINATOR as u128);
    let max_delta = base
        .checked_mul(max_base_fee_change_per_epoch_bps as u128)
        .ok_or_else(|| "base fee max delta overflow".to_string())?
        / (constants::BPS_DENOMINATOR as u128);
    let delta = raw_delta.min(max_delta).max(1);

    let next = if gas_used_epoch > target_gas_epoch {
        base.checked_add(delta)
            .ok_or_else(|| "base fee increase overflow".to_string())?
    } else {
        base.saturating_sub(delta).max(min_base_fee_nwei as u128)
    };
    u64::try_from(next).map_err(|_| "base fee exceeds u64".to_string())
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct GasSettlement {
    pub gas_limit: u64,
    pub minimum_required_gas: u64,
    pub gas_used: u64,
    pub max_effective_gas_price_nwei: u64,
    pub effective_gas_price_nwei: u64,
    pub max_fee_reserved_nwei: u128,
    pub actual_fee_nwei: u128,
    pub refund_nwei: u128,
}

pub fn settle_gas_limit(
    gas_limit: u64,
    minimum_required_gas: u64,
    gas_used: u64,
    max_effective_gas_price_nwei: u64,
    effective_gas_price_nwei: u64,
) -> Result<GasSettlement, String> {
    if gas_limit < minimum_required_gas {
        return Err("gas limit below minimum required gas".to_string());
    }
    if gas_used > gas_limit {
        return Err("gas used exceeds gas limit".to_string());
    }
    if effective_gas_price_nwei > max_effective_gas_price_nwei {
        return Err("effective gas price exceeds max effective gas price".to_string());
    }

    let max_fee_reserved_nwei = calculate_total_fee_nwei(gas_limit, max_effective_gas_price_nwei)?;
    let actual_fee_nwei = calculate_total_fee_nwei(gas_used, effective_gas_price_nwei)?;
    let refund_nwei = max_fee_reserved_nwei
        .checked_sub(actual_fee_nwei)
        .ok_or_else(|| "refund underflow".to_string())?;

    Ok(GasSettlement {
        gas_limit,
        minimum_required_gas,
        gas_used,
        max_effective_gas_price_nwei,
        effective_gas_price_nwei,
        max_fee_reserved_nwei,
        actual_fee_nwei,
        refund_nwei,
    })
}

pub struct GasEstimator;

impl GasEstimator {
    pub fn estimate_transfer() -> GasLimit {
        let schedule = GasSchedule::default();
        let input = GasComputationInput::new(GasActivityType::NativeSnrgTransfer);
        let gas = calculate_activity_gas(&schedule, &input)
            .map(|breakdown| breakdown.total_gas)
            .unwrap_or(schedule.base_tx_gas + schedule.native_transfer_gas);
        GasLimit(gas.min(constants::MAX_GAS_LIMIT))
    }

    pub fn estimate_contract_deploy(bytecode_size: usize) -> GasLimit {
        let schedule = GasSchedule::default();
        let mut input = GasComputationInput::new(GasActivityType::SynqContractDeployment);
        input.contract_bytecode_size = bytecode_size as u64;
        let gas = calculate_activity_gas(&schedule, &input)
            .map(|breakdown| breakdown.total_gas)
            .unwrap_or(constants::MAX_GAS_LIMIT);
        GasLimit(gas.min(constants::MAX_GAS_LIMIT))
    }

    pub fn estimate_contract_call(calldata_size: usize) -> GasLimit {
        let schedule = GasSchedule::default();
        let mut input = GasComputationInput::new(GasActivityType::SynqContractCall);
        input.payload_size_bytes = calldata_size as u64;
        let gas = calculate_activity_gas(&schedule, &input)
            .map(|breakdown| breakdown.total_gas)
            .unwrap_or(constants::MAX_GAS_LIMIT);
        GasLimit(gas.min(constants::MAX_GAS_LIMIT))
    }
}

fn checked_add(left: u64, right: u64) -> Result<u64, String> {
    left.checked_add(right)
        .ok_or_else(|| "gas addition overflow".to_string())
}

fn checked_mul(left: u64, right: u64) -> Result<u64, String> {
    left.checked_mul(right)
        .ok_or_else(|| "gas multiplication overflow".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nwei_formats_without_floating_point() {
        let amount = NWei::from_snrg_units(2, 500_000_000).expect("valid fractional nWei");
        assert_eq!(amount.as_nwei(), 2_500_000_000);
        assert_eq!(amount.format_snrg(), "2.500000000");
    }

    #[test]
    fn native_transfer_gas_is_calculated_correctly() {
        let schedule = GasSchedule::default();
        let mut input = GasComputationInput::new(GasActivityType::NativeSnrgTransfer);
        input.payload_size_bytes = 10;
        let gas = calculate_activity_gas(&schedule, &input).expect("gas should calculate");
        assert_eq!(gas.total_gas, 21_000 + 5_000 + (16 * 10) + 500 + 12_000);
    }

    #[test]
    fn validator_registration_gas_increases_with_metadata_size() {
        let schedule = GasSchedule::default();
        let mut small = GasComputationInput::new(GasActivityType::ValidatorRegistration);
        small.validator_metadata_size_bytes = 10;
        let mut large = small;
        large.validator_metadata_size_bytes = 100;

        let small_gas = calculate_activity_gas(&schedule, &small).unwrap().total_gas;
        let large_gas = calculate_activity_gas(&schedule, &large).unwrap().total_gas;

        assert_eq!(large_gas - small_gas, 90 * schedule.storage_byte_gas);
    }

    #[test]
    fn synq_call_gas_increases_with_execution_and_storage() {
        let schedule = GasSchedule::default();
        let mut input = GasComputationInput::new(GasActivityType::SynqContractCall);
        input.execution_units = 10;
        input.storage_reads = 2;
        input.storage_writes = 3;
        input.storage_bytes_written = 20;
        let gas = calculate_activity_gas(&schedule, &input).unwrap();

        assert_eq!(
            gas.total_gas,
            21_000 + 30_000 + 12_000 + 10 + (2 * 100) + (3 * 2_000) + (20 * 25)
        );
    }

    #[test]
    fn sxcp_proof_gas_increases_with_proof_size_and_signature_count() {
        let schedule = GasSchedule::default();
        let mut input = GasComputationInput::new(GasActivityType::SxcpProofVerification);
        input.proof_size_bytes = 100;
        input.signature_count = 3;
        let gas = calculate_activity_gas(&schedule, &input).unwrap();

        assert_eq!(gas.total_gas, 21_000 + 125_000 + (100 * 50) + (3 * 12_000));
    }

    #[test]
    fn congestion_premium_is_zero_below_target() {
        assert_eq!(
            calculate_congestion_premium_nwei(100, 5_000, 6_000, 1_000, 5_000).unwrap(),
            0
        );
    }

    #[test]
    fn congestion_premium_activates_above_target() {
        let premium = calculate_congestion_premium_nwei(100, 9_000, 6_000, 1_000, 5_000).unwrap();
        assert_eq!(premium, 5);
    }

    #[test]
    fn congestion_premium_cap_is_enforced() {
        let premium = calculate_congestion_premium_nwei(100, 60_000, 6_000, 10_000, 5_000).unwrap();
        assert_eq!(premium, 50);
    }

    #[test]
    fn base_fee_increases_decreases_and_respects_caps() {
        assert_eq!(
            calculate_next_base_fee_nwei(100, 120, 100, 1_000, 1_250, 1).unwrap(),
            102
        );
        assert_eq!(
            calculate_next_base_fee_nwei(100, 80, 100, 1_000, 1_250, 1).unwrap(),
            98
        );
        assert_eq!(
            calculate_next_base_fee_nwei(100, 100, 100, 1_000, 1_250, 1).unwrap(),
            100
        );
        assert_eq!(
            calculate_next_base_fee_nwei(100, 10_000, 100, 10_000, 1_250, 1).unwrap(),
            112
        );
    }

    #[test]
    fn min_base_fee_is_enforced() {
        assert_eq!(
            calculate_next_base_fee_nwei(1, 0, 100, 10_000, 10_000, 1).unwrap(),
            1
        );
    }

    #[test]
    fn gas_limit_below_required_gas_fails() {
        let err = settle_gas_limit(10, 11, 10, 2, 2).unwrap_err();
        assert_eq!(err, "gas limit below minimum required gas");
    }

    #[test]
    fn unused_gas_is_refunded_and_actual_fee_is_collected() {
        let settlement = settle_gas_limit(100, 50, 60, 3, 2).unwrap();
        assert_eq!(settlement.max_fee_reserved_nwei, 300);
        assert_eq!(settlement.actual_fee_nwei, 120);
        assert_eq!(settlement.refund_nwei, 180);
    }

    #[test]
    fn network_fee_adds_gas_amount_storage_and_priority_components() {
        let breakdown = calculate_network_fee(
            NetworkFeeInput {
                tx_type: TransactionFeeType::NativeSnrgSend,
                asset_id: "SNRG".to_string(),
                amount_raw: 1_000_000_000,
                amount_snrgequivalent_nwei: 1_000_000_000,
                valuation_source: "native_snrg".to_string(),
                valuation_status: ValuationStatus::NativeSnrg,
                gas_used: 38_500,
                base_fee_per_gas_nwei: 2,
                gas_fee_nwei: 77_000,
                storage_fee_nwei: 11,
                priority_fee_nwei: 7,
            },
            &FeeSchedule::default(),
        )
        .unwrap();

        assert_eq!(breakdown.amount_fee_bps, 2);
        assert_eq!(breakdown.amount_protocol_fee_nwei, 200_000);
        assert_eq!(breakdown.total_network_fee_nwei, 77_000 + 200_000 + 11 + 7);
    }

    #[test]
    fn valuation_required_asset_without_valuation_charges_gas_only() {
        let breakdown = calculate_network_fee(
            NetworkFeeInput {
                tx_type: TransactionFeeType::TokenSend,
                asset_id: "TEST".to_string(),
                amount_raw: 500_000,
                amount_snrgequivalent_nwei: 0,
                valuation_source: "unavailable".to_string(),
                valuation_status: ValuationStatus::Unavailable,
                gas_used: 40_000,
                base_fee_per_gas_nwei: 1,
                gas_fee_nwei: 40_000,
                storage_fee_nwei: 0,
                priority_fee_nwei: 0,
            },
            &FeeSchedule::default(),
        )
        .unwrap();

        assert_eq!(breakdown.amount_fee_bps, 3);
        assert_eq!(breakdown.amount_protocol_fee_nwei, 0);
        assert_eq!(breakdown.total_network_fee_nwei, 40_000);
    }
}
