//! POSY-CODEC-1 little-endian framing, distinct from QACE-C14N-02.
use super::{R1ProofError, Result};
use synergy_protocol_types::{
    R1GenesisReference, R1NetworkCoordinate, R1NetworkRef, R1ProfileRef, R1ProfileSetReference,
};

pub(super) struct Writer {
    pub bytes: Vec<u8>,
    max: usize,
}
impl Writer {
    pub fn new(max: usize) -> Self {
        Self {
            bytes: Vec::new(),
            max,
        }
    }
    pub fn fixed(&mut self, bytes: &[u8]) -> Result<()> {
        if self
            .bytes
            .len()
            .checked_add(bytes.len())
            .is_none_or(|n| n > self.max)
        {
            return Err(R1ProofError::Bounds);
        }
        self.bytes
            .try_reserve(bytes.len())
            .map_err(|_| R1ProofError::Bounds)?;
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }
    pub fn u16(&mut self, n: u16) -> Result<()> {
        self.fixed(&n.to_le_bytes())
    }
    pub fn u32(&mut self, n: u32) -> Result<()> {
        self.fixed(&n.to_le_bytes())
    }
    pub fn u64(&mut self, n: u64) -> Result<()> {
        self.fixed(&n.to_le_bytes())
    }
    pub fn u128(&mut self, n: u128) -> Result<()> {
        self.fixed(&n.to_le_bytes())
    }
    pub fn variable(&mut self, bytes: &[u8], max: usize) -> Result<()> {
        if bytes.len() > max {
            return Err(R1ProofError::Bounds);
        }
        self.u32(u32::try_from(bytes.len()).map_err(|_| R1ProofError::Bounds)?)?;
        self.fixed(bytes)
    }
    pub fn profile(&mut self, p: &R1ProfileRef) -> Result<()> {
        p.validate().map_err(|_| R1ProofError::Profile)?;
        self.variable(p.name.as_bytes(), 128)?;
        self.u32(p.revision)
    }
    pub fn coordinate(&mut self, c: &R1NetworkCoordinate) -> Result<()> {
        c.validate().map_err(|_| R1ProofError::Context)?;
        self.u64(c.network.chain_id)?;
        self.fixed(&c.network.nic)?;
        self.profile(&c.genesis.profile)?;
        self.fixed(&c.genesis.digest)?;
        self.profile(&c.activated_profiles.profile)?;
        self.fixed(&c.activated_profiles.commitment)
    }
}
pub(super) struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl<'a> Reader<'a> {
    pub fn new(bytes: &'a [u8], max: usize) -> Result<Self> {
        if bytes.len() > max {
            return Err(R1ProofError::Bounds);
        }
        Ok(Self { bytes, at: 0 })
    }
    pub fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self.at.checked_add(len).ok_or(R1ProofError::Bounds)?;
        let out = self.bytes.get(self.at..end).ok_or(R1ProofError::Encoding)?;
        self.at = end;
        Ok(out)
    }
    pub fn fixed<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.take(N)?.try_into().map_err(|_| R1ProofError::Encoding)
    }
    pub fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.fixed()?))
    }
    pub fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.fixed()?))
    }
    pub fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.fixed()?))
    }
    pub fn variable(&mut self, max: usize) -> Result<&'a [u8]> {
        let len = usize::try_from(self.u32()?).map_err(|_| R1ProofError::Bounds)?;
        if len > max {
            return Err(R1ProofError::Bounds);
        }
        self.take(len)
    }
    pub fn profile(&mut self) -> Result<R1ProfileRef> {
        let name = std::str::from_utf8(self.variable(128)?)
            .map_err(|_| R1ProofError::Encoding)?
            .to_owned();
        let p = R1ProfileRef {
            name,
            revision: self.u32()?,
        };
        p.validate().map_err(|_| R1ProofError::Profile)?;
        Ok(p)
    }
    pub fn coordinate(&mut self) -> Result<R1NetworkCoordinate> {
        let c = R1NetworkCoordinate {
            network: R1NetworkRef {
                chain_id: self.u64()?,
                nic: self.fixed()?,
            },
            genesis: R1GenesisReference {
                profile: self.profile()?,
                digest: self.fixed()?,
            },
            activated_profiles: R1ProfileSetReference {
                profile: self.profile()?,
                commitment: self.fixed()?,
            },
        };
        c.validate().map_err(|_| R1ProofError::Context)?;
        Ok(c)
    }
    pub fn finish(self) -> Result<()> {
        if self.at == self.bytes.len() {
            Ok(())
        } else {
            Err(R1ProofError::Encoding)
        }
    }
}
