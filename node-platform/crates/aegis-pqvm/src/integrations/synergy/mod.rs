use crate::integrations::abi::{self, Alg, Op};
use crate::integrations::IntegrationError;
use crate::licensing::{check_platform, VmPlatform};

pub mod rpc;

/// Selected network settings supplied by authenticated host configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SynergyNetwork {
    pub chain_id: u64,
    pub network_id: String,
    pub evm_precompile_address: String,
}
impl SynergyNetwork {
    pub fn validate(&self) -> Result<(), IntegrationError> {
        if self.chain_id == 0
            || self.network_id.trim().is_empty()
            || self.network_id.len() > 128
            || self.network_id.contains(char::is_control)
            || self.evm_precompile_address.len() != 42
            || !self.evm_precompile_address.starts_with("0x")
            || !self.evm_precompile_address[2..]
                .bytes()
                .all(|b| b.is_ascii_hexdigit())
        {
            return Err(IntegrationError::InvalidPayload(
                "invalid selected Synergy network",
            ));
        }
        Ok(())
    }
}

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
