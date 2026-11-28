//! R1 logical network coordinates shared by Genesis and runtime consumers.
//!
//! Identity R1 p267 and PoSy/QACE R1 M03/M06 distinguish NIC, final Genesis
//! and the activated profile set. These are typed data, not authentication.
//! A caller obtains its trusted expected coordinate from the Genesis/authority
//! verifier. This module neither chooses a wire codec nor issues authority.

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct R1ProfileRef {
    pub name: String,
    pub revision: u32,
}
impl R1ProfileRef {
    pub fn validate(&self) -> Result<(), R1ContextError> {
        if self.name.is_empty()
            || self.name.len() > 128
            || self.revision == 0
            || !self.name.bytes().all(|b| b.is_ascii_graphic())
        {
            return Err(R1ContextError::Profile);
        }
        Ok(())
    }
}

/// SHA3-512 NetworkBirth incarnation bytes; never a final Genesis digest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct R1NetworkRef {
    pub chain_id: u64,
    pub nic: [u8; 64],
}
/// The profile fixes the exact canonical Genesis schema/domain and SHA3-384.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct R1GenesisReference {
    pub profile: R1ProfileRef,
    pub digest: [u8; 48],
}
/// The selected profile defines the full committed activated-profile register.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct R1ProfileSetReference {
    pub profile: R1ProfileRef,
    pub commitment: [u8; 64],
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct R1NetworkCoordinate {
    pub network: R1NetworkRef,
    pub genesis: R1GenesisReference,
    pub activated_profiles: R1ProfileSetReference,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum R1ContextError {
    Chain,
    Incarnation,
    Genesis,
    Profile,
    ActivatedProfiles,
}
impl R1NetworkCoordinate {
    pub fn validate(&self) -> Result<(), R1ContextError> {
        if self.network.chain_id == 0 {
            return Err(R1ContextError::Chain);
        }
        self.genesis.profile.validate()?;
        self.activated_profiles.profile.validate()?;
        Ok(())
    }
    /// Exact agreement with an independently authenticated expectation. A match
    /// never supplies that authentication and never treats zero as a wildcard.
    pub fn ensure_matches(&self, expected: &Self) -> Result<(), R1ContextError> {
        self.validate()?;
        expected.validate()?;
        if self.network.chain_id != expected.network.chain_id {
            return Err(R1ContextError::Chain);
        }
        if self.network.nic != expected.network.nic {
            return Err(R1ContextError::Incarnation);
        }
        if self.genesis != expected.genesis {
            return Err(R1ContextError::Genesis);
        }
        if self.activated_profiles != expected.activated_profiles {
            return Err(R1ContextError::ActivatedProfiles);
        }
        Ok(())
    }
}
impl std::fmt::Display for R1ContextError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "R1 network context mismatch: {self:?}")
    }
}
impl std::error::Error for R1ContextError {}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> R1NetworkCoordinate {
        R1NetworkCoordinate {
            network: R1NetworkRef {
                chain_id: u64::MAX - 1,
                nic: [0x11; 64],
            },
            genesis: R1GenesisReference {
                profile: R1ProfileRef {
                    name: "SYNTHETIC-GENESIS".into(),
                    revision: 1,
                },
                digest: [0x22; 48],
            },
            activated_profiles: R1ProfileSetReference {
                profile: R1ProfileRef {
                    name: "SYNTHETIC-PROFILES".into(),
                    revision: 1,
                },
                commitment: [0x33; 64],
            },
        }
    }
    #[test]
    fn runtime_context_binds_each_exact_component_and_profile() {
        let expected = fixture();
        assert!(expected.ensure_matches(&expected).is_ok());
        let mut c = expected.clone();
        c.network.chain_id = u64::MAX;
        assert_eq!(c.ensure_matches(&expected), Err(R1ContextError::Chain));
        let mut c = expected.clone();
        c.network.nic[63] ^= 1;
        assert_eq!(
            c.ensure_matches(&expected),
            Err(R1ContextError::Incarnation)
        );
        let mut c = expected.clone();
        c.genesis.digest[47] ^= 1;
        assert_eq!(c.ensure_matches(&expected), Err(R1ContextError::Genesis));
        let mut c = expected.clone();
        c.genesis.profile.revision = 2;
        assert_eq!(c.ensure_matches(&expected), Err(R1ContextError::Genesis));
        let mut c = expected.clone();
        c.activated_profiles.commitment[63] ^= 1;
        assert_eq!(
            c.ensure_matches(&expected),
            Err(R1ContextError::ActivatedProfiles)
        );
        let mut c = expected.clone();
        c.activated_profiles.profile.name.push('2');
        assert_eq!(
            c.ensure_matches(&expected),
            Err(R1ContextError::ActivatedProfiles)
        );
    }
    #[test]
    fn zero_is_not_a_genesis_or_incarnation_wildcard() {
        let expected = fixture();
        let mut c = expected.clone();
        c.genesis.digest = [0; 48];
        c.network.nic = [0; 64];
        assert!(c.ensure_matches(&expected).is_err());
        let mut c = expected.clone();
        c.genesis.profile.name = "untrusted\0alias".into();
        assert_eq!(c.validate(), Err(R1ContextError::Profile));
        let mut c = expected.clone();
        c.network.chain_id = 0;
        assert_eq!(c.validate(), Err(R1ContextError::Chain));
    }
}
