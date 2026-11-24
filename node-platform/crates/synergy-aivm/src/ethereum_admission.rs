//! AIVM's external Ethereum authorization boundary. This is deliberately not a
//! native protected-wallet authorization and does not manufacture an ETDAG
//! carrier, execution receipt or PoSy finality record.
use crate::ethereum::{decode_eip155, DecodedLegacyTransaction, EthereumDecodeError};
use synergy_aegis::ethereum::{
    verify_eip155_signature, EthereumAuthorizationError, VerifiedEthereumSigner,
};
use synergy_state::WorldState;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EthereumAdmissionError {
    Decode(EthereumDecodeError),
    Signature(EthereumAuthorizationError),
    ProtectedAccountRequiresQualifiedThresholdAuthorization,
}
impl std::fmt::Display for EthereumAdmissionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for EthereumAdmissionError {}

/// An authenticated conventional signer over the exact decoded raw bytes.
/// Consumers must recheck account policy on the actual execution overlay: an
/// earlier admission snapshot cannot authorize spending after class changes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedLegacyTransaction {
    transaction: DecodedLegacyTransaction,
    signer: VerifiedEthereumSigner,
}
impl AuthenticatedLegacyTransaction {
    pub fn transaction(&self) -> &DecodedLegacyTransaction {
        &self.transaction
    }
    pub fn signer(&self) -> &VerifiedEthereumSigner {
        &self.signer
    }
    pub fn validate_account_policy(
        &self,
        execution_state: &WorldState,
    ) -> Result<(), EthereumAdmissionError> {
        // This is the canonical protected_accounts.rs ACCOUNT_PREFIX record,
        // keyed by bytes20 rendered as lowercase hex, independent of whether a
        // user presents the address as synw or 0x. Presence denies conventional
        // ECDSA even if the stored policy cannot be decoded.
        let mut key = String::from("apqe-protected-account-candidate/v1/policy/");
        use std::fmt::Write;
        for byte in self.signer.account_id() {
            write!(&mut key, "{byte:02x}").unwrap();
        }
        if execution_state.protocol.contains_key(&key) {
            return Err(
                EthereumAdmissionError::ProtectedAccountRequiresQualifiedThresholdAuthorization,
            );
        }
        Ok(())
    }
}

pub fn authenticate_conventional_eip155(
    raw: &[u8],
    selected_chain_id: u64,
    state: &WorldState,
) -> Result<AuthenticatedLegacyTransaction, EthereumAdmissionError> {
    let transaction =
        decode_eip155(raw, selected_chain_id).map_err(EthereumAdmissionError::Decode)?;
    let signer = verify_eip155_signature(
        selected_chain_id,
        &transaction.signing_hash,
        transaction.v,
        &transaction.r,
        &transaction.s,
    )
    .map_err(EthereumAdmissionError::Signature)?;
    let authenticated = AuthenticatedLegacyTransaction {
        transaction,
        signer,
    };
    authenticated.validate_account_policy(state)?;
    Ok(authenticated)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn raw() -> Vec<u8> {
        let text = "f86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83";
        text.as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }
    #[test]
    fn published_external_transaction_authenticates_and_policy_transition_revokes_admission() {
        let mut world = WorldState::default();
        let tx = authenticate_conventional_eip155(&raw(), 1, &world).unwrap();
        assert_eq!(
            tx.signer().account_id(),
            &[
                0x9d, 0x8a, 0x62, 0xf6, 0x56, 0xa8, 0xd1, 0x61, 0x5c, 0x12, 0x94, 0xfd, 0x71, 0xe9,
                0xcf, 0xb3, 0xe4, 0x85, 0x5a, 0x4f
            ]
        );
        assert!(tx
            .transaction()
            .validate_execution_limits(9, 21_000, 30_000_000, 1)
            .is_ok());
        world.protocol.insert(
            "apqe-protected-account-candidate/v1/policy/9d8a62f656a8d1615c1294fd71e9cfb3e4855a4f"
                .into(),
            vec![0xff],
        );
        assert_eq!(
            tx.validate_account_policy(&world),
            Err(EthereumAdmissionError::ProtectedAccountRequiresQualifiedThresholdAuthorization)
        );
        assert_eq!(
            authenticate_conventional_eip155(&raw(), 1, &world),
            Err(EthereumAdmissionError::ProtectedAccountRequiresQualifiedThresholdAuthorization)
        );
    }
}
