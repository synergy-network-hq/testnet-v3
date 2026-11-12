//! Synergy TESTNET RPC contract for Aegis PQVM integration.
//!
//! This module intentionally describes method names and exposure rules only. It
//! does not perform network I/O; node runtimes and smoke scripts use these
//! constants to keep JSON-RPC wiring aligned with the crate ABI.

use super::SynergyNetwork;
use crate::integrations::IntegrationError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RpcExposure {
    /// Safe for public RPC gateways. Never accepts secret-key payloads.
    Public,
    /// Trusted/private RPC only. May accept secret-key payloads.
    TrustedOnly,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SynergyRpcMethod {
    /// Dispatch deterministic AEG1 payloads through `SynergyIntegration::dispatch_call`.
    AegisDispatch,
    /// Estimate deterministic AEG1 fee/gas through `SynergyIntegration::synergy_gas_cost`.
    AegisEstimateGas,
    /// Dispatch trusted off-chain AEG1 payloads through `dispatch_offchain_call`.
    AegisDispatchOffchain,
    /// Return `licensing::license_summary()` for authenticated operators.
    AegisLicenseSummary,
    /// Verify a randomness beacon output without exposing raw entropy.
    AegisBeaconVerify,
    /// EVM precompile invocation via `eth_call`.
    EthCall,
    /// EVM precompile gas estimation via `eth_estimateGas`.
    EthEstimateGas,
    /// EVM chain identity check.
    EthChainId,
}

impl SynergyRpcMethod {
    pub const fn name(self) -> &'static str {
        match self {
            SynergyRpcMethod::AegisDispatch => "aegis_dispatch",
            SynergyRpcMethod::AegisEstimateGas => "aegis_estimateGas",
            SynergyRpcMethod::AegisDispatchOffchain => "aegis_dispatchOffchain",
            SynergyRpcMethod::AegisLicenseSummary => "aegis_licenseSummary",
            SynergyRpcMethod::AegisBeaconVerify => "aegis_verifyBeacon",
            SynergyRpcMethod::EthCall => "eth_call",
            SynergyRpcMethod::EthEstimateGas => "eth_estimateGas",
            SynergyRpcMethod::EthChainId => "eth_chainId",
        }
    }

    pub const fn exposure(self) -> RpcExposure {
        match self {
            SynergyRpcMethod::AegisDispatchOffchain | SynergyRpcMethod::AegisLicenseSummary => {
                RpcExposure::TrustedOnly
            }
            SynergyRpcMethod::AegisDispatch
            | SynergyRpcMethod::AegisEstimateGas
            | SynergyRpcMethod::AegisBeaconVerify
            | SynergyRpcMethod::EthCall
            | SynergyRpcMethod::EthEstimateGas
            | SynergyRpcMethod::EthChainId => RpcExposure::Public,
        }
    }

    pub const fn requires_trusted_transport(self) -> bool {
        matches!(self.exposure(), RpcExposure::TrustedOnly)
    }
}

pub const PUBLIC_METHODS: &[SynergyRpcMethod] = &[
    SynergyRpcMethod::AegisDispatch,
    SynergyRpcMethod::AegisEstimateGas,
    SynergyRpcMethod::AegisBeaconVerify,
    SynergyRpcMethod::EthCall,
    SynergyRpcMethod::EthEstimateGas,
    SynergyRpcMethod::EthChainId,
];

pub const TRUSTED_ONLY_METHODS: &[SynergyRpcMethod] = &[
    SynergyRpcMethod::AegisDispatchOffchain,
    SynergyRpcMethod::AegisLicenseSummary,
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvmPrecompileRoute {
    pub chain_id_hex: String,
    pub network_id: String,
    pub address: String,
    pub call_method: &'static str,
    pub estimate_method: &'static str,
}

impl EvmPrecompileRoute {
    pub fn for_network(network: &SynergyNetwork) -> Result<Self, IntegrationError> {
        network.validate()?;
        Ok(Self {
            chain_id_hex: format!("0x{:x}", network.chain_id),
            network_id: network.network_id.clone(),
            address: network.evm_precompile_address.clone(),
            call_method: "eth_call",
            estimate_method: "eth_estimateGas",
        })
    }
}
