use crate::integrations::abi::{self, Alg, Op};
use crate::integrations::IntegrationError;

pub struct MoveIntegration;

impl MoveIntegration {
    fn expected_route(module: &str, function: &str) -> Result<(Op, Alg), IntegrationError> {
        match (module, function) {
            ("aegis", "mldsa44_verify_detached") => Ok((Op::MldsaVerifyDetached, Alg::Mldsa44)),
            ("aegis", "mldsa65_verify_detached") => Ok((Op::MldsaVerifyDetached, Alg::Mldsa65)),
            ("aegis", "mldsa87_verify_detached") => Ok((Op::MldsaVerifyDetached, Alg::Mldsa87)),
            ("aegis", "fndsa512_verify_detached") => Ok((Op::FndsaVerifyDetached, Alg::Fndsa512)),
            ("aegis", "fndsa1024_verify_detached") => Ok((Op::FndsaVerifyDetached, Alg::Fndsa1024)),
            _ => Err(IntegrationError::Unsupported(
                "unsupported Move module/function route",
            )),
        }
    }

    pub fn invoke_entry_function(
        module: &str,
        function: &str,
        args: &[Vec<u8>],
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
        if args.len() != 1 {
            return Err(IntegrationError::InvalidPayload(
                "Move adapter expects exactly one AEG1 payload argument",
            ));
        }

        let payload = &args[0];
        let decoded = abi::decode_call(payload)?;
        let (expected_op, expected_alg) = Self::expected_route(module, function)?;
        if decoded.op != expected_op || decoded.alg != expected_alg {
            return Err(IntegrationError::InvalidPayload(
                "AEG1 payload op/alg does not match Move module/function route",
            ));
        }

        abi::dispatch_deterministic(payload)
    }
}
