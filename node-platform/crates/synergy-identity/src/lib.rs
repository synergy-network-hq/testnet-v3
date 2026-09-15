//! Public node identity validation and transport binding.
//! This crate never stores or generates private credentials.

mod duplicate_guard;
mod key_binding;
mod node_address;
mod proof_of_possession;
mod public_identity;
mod rotation;
mod store;

pub use duplicate_guard::DuplicateIdentityGuard;
pub use node_address::{NodeAddress, NodeAddressError, NodeClass};
pub use proof_of_possession::ProofOfPossession;
pub use public_identity::{IdentityError, PublicNodeIdentity};
pub use rotation::IdentityRotation;
pub use store::IdentityStore;

use key_binding::valid_fingerprint;

impl PublicNodeIdentity {
    /// Validates the public-key binding without granting role or PoSy authority.
    ///
    /// # Errors
    /// Returns [`IdentityError`] for an invalid fingerprint or a contradictory
    /// legacy validator-address field.
    pub fn validate(self) -> Result<Self, IdentityError> {
        if !valid_fingerprint(&self.public_key_fingerprint) {
            return Err(IdentityError::InvalidFingerprint);
        }
        if self
            .legacy_validator_address()
            .is_some_and(|legacy| legacy != self.node_address.as_str())
        {
            return Err(IdentityError::InvalidValidatorAddress);
        }
        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> PublicNodeIdentity {
        PublicNodeIdentity::new(
            NodeAddress::parse("synv11lrh6jcxaejkj4zv994j7qwn2rk6u3ar4emn").unwrap(),
            "a".repeat(64),
        )
    }

    #[test]
    fn public_identity_requires_valid_non_secret_bindings() {
        assert!(identity().validate().is_ok());
        let mut bad = identity();
        bad.public_key_fingerprint = "bad".into();
        assert_eq!(bad.validate(), Err(IdentityError::InvalidFingerprint));
    }

    #[test]
    fn legacy_node_id_deserializes_as_the_canonical_node_address() {
        let encoded = format!(
            r#"{{"node_id":"synv11lrh6jcxaejkj4zv994j7qwn2rk6u3ar4emn","public_key_fingerprint":"{}","validator_address":"synv11lrh6jcxaejkj4zv994j7qwn2rk6u3ar4emn"}}"#,
            "a".repeat(64)
        );
        let value: PublicNodeIdentity = serde_json::from_str(&encoded).unwrap();
        assert_eq!(
            value.validate().unwrap().node_address.as_str(),
            "synv11lrh6jcxaejkj4zv994j7qwn2rk6u3ar4emn"
        );
    }

    #[test]
    fn legacy_parallel_validator_identity_must_match_the_node_address() {
        let encoded = format!(
            r#"{{"node_id":"synv11lrh6jcxaejkj4zv994j7qwn2rk6u3ar4emn","public_key_fingerprint":"{}","validator_address":"synv21lrh6jcxaejkj4zv994j7qwn2rk6u3zat22n"}}"#,
            "a".repeat(64)
        );
        let value: PublicNodeIdentity = serde_json::from_str(&encoded).unwrap();
        assert_eq!(
            value.validate(),
            Err(IdentityError::InvalidValidatorAddress)
        );
    }
}
