//! Exact catalog-derived protocol context. A digest never grants authority.
use crate::{R1NetworkRef, R1ProfileSetReference};
use synergy_address::r1_public::{canonical_framing as c, HashAlgorithm, Primitives, ProfileRef};
pub const PROFILE_NAME: &str = "SYNERGY-PROTOCOL-PROFILE-R1";
pub const PROFILE_REVISION: u32 = 1;
pub const PROFILE_SCHEMA: &[u8] = b"SYNERGY-PROTOCOL-PROFILE-R1/1;Protocol48=SHA3-384(F(PROTOCOL.PROFILE,[SYNERGY-PROTOCOL-PROFILE-R1,1],N,[[APQE-PROFILE-SET,1],ASCII-SHA3-512,ActivatedProfileSetCommit64]));F=centralAPQErestrictedcanonicalCBOR;N=[chainU64,NIC64];noGenesis;profile-set-must-be-exact-independent-closed-catalog-of-complete-definitions-and-schema-digests;nonzero-chain/NIC/commitment;data-only-not-activation-or-seed-authority";
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProtocolProfileError {
    Context,
    Encoding,
    Primitive,
}
impl std::fmt::Display for ProtocolProfileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "R1 protocol profile rejected: {self:?}")
    }
}
impl std::error::Error for ProtocolProfileError {}
pub fn commitment(
    network: &R1NetworkRef,
    profiles: &R1ProfileSetReference,
) -> Result<[u8; 48], ProtocolProfileError> {
    if network.chain_id == 0
        || network.nic == [0; 64]
        || profiles.profile.name != "APQE-PROFILE-SET"
        || profiles.profile.revision != 1
        || profiles.commitment == [0; 64]
    {
        return Err(ProtocolProfileError::Context);
    }
    let bytes = c::frame(
        "PROTOCOL.PROFILE",
        ProfileRef {
            name: PROFILE_NAME,
            revision: PROFILE_REVISION,
        },
        Some(c::NetworkRef {
            chain_id: network.chain_id,
            nic: network.nic,
        }),
        c::Value::Array(vec![
            c::profile(ProfileRef {
                name: "APQE-PROFILE-SET",
                revision: 1,
            }),
            c::text("SHA3-512"),
            c::bytes(&profiles.commitment),
        ]),
        1024,
    )
    .map_err(|_| ProtocolProfileError::Encoding)?;
    Primitives
        .hash(HashAlgorithm::Sha3384, &bytes)
        .map_err(|_| ProtocolProfileError::Primitive)?
        .try_into()
        .map_err(|_| ProtocolProfileError::Primitive)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_catalog_and_full_network_are_committed_without_genesis() {
        let n = R1NetworkRef {
            chain_id: u64::MAX - 1,
            nic: [7; 64],
        };
        let p = R1ProfileSetReference {
            profile: crate::R1ProfileRef {
                name: "APQE-PROFILE-SET".into(),
                revision: 1,
            },
            commitment: [8; 64],
        };
        let original = commitment(&n, &p).unwrap();
        // Independent Python hashlib + minimal RFC8949 primitive encoder oracle.
        assert_eq!(
            original,
            [
                0xce, 0x25, 0x79, 0xf3, 0x74, 0x0e, 0xa2, 0x8c, 0xf9, 0xb1, 0xec, 0x0c, 0xd6, 0xce,
                0x13, 0x02, 0x01, 0xf8, 0x6e, 0x78, 0x62, 0x1d, 0xed, 0x38, 0xfa, 0x45, 0x88, 0x4d,
                0xe1, 0x99, 0x67, 0xbd, 0x6b, 0x31, 0x9b, 0x9e, 0x59, 0x95, 0xee, 0x84, 0xdf, 0x8e,
                0xf8, 0x23, 0x19, 0x9d, 0x95, 0x4c
            ]
        );
        let mut other = n;
        other.nic[63] ^= 1;
        assert_ne!(original, commitment(&other, &p).unwrap());
        other = n;
        other.chain_id -= 1;
        assert_ne!(original, commitment(&other, &p).unwrap());
        let mut q = p.clone();
        q.commitment[63] ^= 1;
        assert_ne!(original, commitment(&n, &q).unwrap());
        q = p.clone();
        q.profile.revision = 2;
        assert_eq!(commitment(&n, &q), Err(ProtocolProfileError::Context));
        q = p;
        q.commitment = [0; 64];
        assert_eq!(commitment(&n, &q), Err(ProtocolProfileError::Context));
    }
}
