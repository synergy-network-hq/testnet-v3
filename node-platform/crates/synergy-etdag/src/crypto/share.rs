use crate::{EtdagDigest, EtdagError};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShamirShare {
    pub index: u8,
    pub value: Vec<u8>,
}

impl ShamirShare {
    pub fn validate(&self) -> Result<(), EtdagError> {
        if self.index == 0 || self.value.len() != 32 {
            return Err(EtdagError::UnauthorizedReveal);
        }
        Ok(())
    }

    pub fn commitment(
        &self,
        validator_id: &str,
        context_root: &EtdagDigest,
        target_height: u64,
    ) -> Result<EtdagDigest, EtdagError> {
        self.validate()?;
        context_root.validate()?;
        EtdagDigest::from_canonical(
            "PoSy/ETDAG/ShareCommitment/v3",
            &(validator_id, self, context_root, target_height),
        )
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, EtdagError> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|e| EtdagError::Corrupt(format!("encode share: {e}")))
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, EtdagError> {
        if bytes.len() > 1024 {
            return Err(EtdagError::UnauthorizedReveal);
        }
        let share: Self =
            serde_json::from_slice(bytes).map_err(|_| EtdagError::UnauthorizedReveal)?;
        if share.canonical_bytes()? != bytes {
            return Err(EtdagError::UnauthorizedReveal);
        }
        Ok(share)
    }
}

/// The reveal threshold is derived from the SAME governed count quorum as PoSy.
pub fn governed_reveal_threshold(
    member_count: usize,
    count_quorum: usize,
) -> Result<usize, EtdagError> {
    if member_count == 0 || member_count > 255 || count_quorum == 0 || count_quorum > member_count {
        return Err(EtdagError::InvalidCapacity);
    }
    Ok(member_count - count_quorum + 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_shares_bind_validator_height_context_and_index() {
        let share = ShamirShare {
            index: 1,
            value: vec![7; 32],
        };
        let context = EtdagDigest::from_domain_bytes("test", b"context");
        let commitment = share.commitment("val2", &context, 3).unwrap();
        assert_eq!(
            ShamirShare::from_canonical_bytes(&share.canonical_bytes().unwrap()).unwrap(),
            share
        );
        assert_ne!(commitment, share.commitment("val3", &context, 3).unwrap());
        assert_ne!(commitment, share.commitment("val2", &context, 4).unwrap());
        let mut changed = share.clone();
        changed.index = 2;
        assert_ne!(commitment, changed.commitment("val2", &context, 3).unwrap());
        changed.value[0] ^= 1;
        assert_ne!(commitment, changed.commitment("val2", &context, 3).unwrap());
        let mut noncanonical = share.canonical_bytes().unwrap();
        noncanonical.push(b' ');
        assert!(ShamirShare::from_canonical_bytes(&noncanonical).is_err());
        assert!(ShamirShare {
            index: 0,
            value: vec![7; 32]
        }
        .canonical_bytes()
        .is_err());
    }

    #[test]
    fn threshold_uses_the_governed_count_quorum() {
        for (n, q, t) in [(5, 4, 2), (6, 5, 2), (7, 5, 3), (10, 7, 4)] {
            assert_eq!(governed_reveal_threshold(n, q).unwrap(), t);
        }
        assert!(governed_reveal_threshold(5, 6).is_err());
        assert!(governed_reveal_threshold(256, 200).is_err());
        assert!(governed_reveal_threshold(5, 0).is_err());
    }
}
