use crate::integrations::abi::{self, Alg, Op};
use crate::integrations::IntegrationError;
use crate::licensing::{check_platform, VmPlatform};

pub mod rpc;

/// Synergy TESTNET chain id. Decimal `1264`, hex `0x4f0`.
pub const TESTNET_CHAIN_ID: u64 = 1264;

/// Synergy TESTNET chain id as returned by EVM JSON-RPC `eth_chainId`.
pub const TESTNET_CHAIN_ID_HEX: &str = "0x4f0";

/// Canonical Synergy TESTNET network id used by signed transaction/RPC envelopes.
pub const TESTNET_NETWORK_ID: &str = "synergy-testnet-v2";

/// Reserved Aegis PQVM EVM precompile address for Synergy TESTNET.
///
/// The address is deliberately outside the low EVM precompile range and embeds
/// the Synergy TESTNET chain id (`0x04f0`) in the low two bytes.
pub const EVM_PRECOMPILE_ADDRESS: [u8; 20] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x04, 0xf0,
];

/// Reserved Aegis PQVM EVM precompile address as a checksummed-insensitive hex string.
pub const EVM_PRECOMPILE_ADDRESS_HEX: &str = "0x00000000000000000000000000000000000004f0";

/// Synergy testnet / mainnet host integration for AEG1 PQVM calls.
///
/// Supports raw AEG1 byte dispatch (Substrate-style) and optional module/function
/// route binding (Move-style) when the Synergy runtime exposes named host functions.
pub struct SynergyIntegration;

impl SynergyIntegration {
    fn expected_route(module: &str, function: &str) -> Result<(Op, Alg), IntegrationError> {
        match (module, function) {
            ("aegis", "mldsa44_verify_detached") => Ok((Op::MldsaVerifyDetached, Alg::Mldsa44)),
            ("aegis", "mldsa65_verify_detached") => Ok((Op::MldsaVerifyDetached, Alg::Mldsa65)),
            ("aegis", "mldsa87_verify_detached") => Ok((Op::MldsaVerifyDetached, Alg::Mldsa87)),
            ("aegis", "fndsa512_verify_detached") => Ok((Op::FndsaVerifyDetached, Alg::Fndsa512)),
            ("aegis", "fndsa1024_verify_detached") => Ok((Op::FndsaVerifyDetached, Alg::Fndsa1024)),
            _ => Err(IntegrationError::Unsupported(
                "unsupported Synergy module/function route",
            )),
        }
    }

    fn check_synergy_platform() -> Result<(), IntegrationError> {
        check_platform(VmPlatform::Synergy)
            .map_err(|msg| IntegrationError::Unsupported(Box::leak(msg.into_boxed_str())))
    }

    /// Deterministic on-chain dispatch (verify-only operations; no secret-key payloads).
    pub fn dispatch_call(call_data: &[u8]) -> Result<Vec<u8>, IntegrationError> {
        if call_data.is_empty() {
            return Err(IntegrationError::InvalidPayload(
                "call data must not be empty",
            ));
        }
        Self::check_synergy_platform()?;
        abi::dispatch_deterministic(call_data)
    }

    /// Trusted off-chain dispatch (allows ML-KEM decapsulation with secret key in payload).
    pub fn dispatch_offchain_call(call_data: &[u8]) -> Result<Vec<u8>, IntegrationError> {
        if call_data.is_empty() {
            return Err(IntegrationError::InvalidPayload(
                "call data must not be empty",
            ));
        }
        Self::check_synergy_platform()?;
        abi::dispatch_offchain(call_data)
    }

    /// Fee / weight estimate for a deterministic AEG1 payload on Synergy.
    pub fn synergy_gas_cost(call_data: &[u8]) -> Result<u64, IntegrationError> {
        if call_data.is_empty() {
            return Err(IntegrationError::InvalidPayload(
                "call data must not be empty",
            ));
        }
        Self::check_synergy_platform()?;
        abi::gas_cost_deterministic(call_data)
    }

    /// Route-bound host function entry (module + function must match AEG1 op/alg).
    pub fn invoke_host_function(
        module: &str,
        function: &str,
        call_data: &[u8],
    ) -> Result<Vec<u8>, IntegrationError> {
        if module.is_empty() {
            return Err(IntegrationError::InvalidPayload(
                "module name must not be empty",
            ));
        }
        if function.is_empty() {
            return Err(IntegrationError::InvalidPayload(
                "function name must not be empty",
            ));
        }
        if call_data.is_empty() {
            return Err(IntegrationError::InvalidPayload(
                "call data must not be empty",
            ));
        }

        Self::check_synergy_platform()?;

        let decoded = abi::decode_call(call_data)?;
        let (expected_op, expected_alg) = Self::expected_route(module, function)?;
        if decoded.op != expected_op || decoded.alg != expected_alg {
            return Err(IntegrationError::InvalidPayload(
                "AEG1 payload op/alg does not match Synergy module/function route",
            ));
        }

        abi::dispatch_deterministic(call_data)
    }
}
