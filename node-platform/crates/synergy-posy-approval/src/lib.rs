//! Sole dependency-free codec for the existing POSY-CODEC-1 ordinary approval.
//! These are public transcript data, never membership, execution or signing
//! authority. PoSy computes/authenticates the header; native custody independently
//! enforces its exact current permission and durable signing reservation.

pub const CONTEXT: &[u8] = b"POSY/APPROVAL/V1";
pub const MAX_MESSAGE_BYTES: usize = 8192;
pub type Digest48 = [u8; 48];

/// Existing POSY/BLOCK/R1 hash input, not a parsed or verified block. The owning
/// PoSy header decoder authenticates grammar; both consumers hash these bytes.
pub fn block_commitment_frame(header: &[u8]) -> Result<Vec<u8>, Error> {
    if header.is_empty() || header.len() > 4096 {
        return Err(Error::Bounds);
    }
    let mut w = Writer(Vec::new());
    w.variable(b"POSY/BLOCK/R1")?;
    w.u16(1)?;
    w.bytes(header)?;
    Ok(w.0)
}

#[cfg(feature = "journal-serde")]
pub mod journal;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Bounds,
    Encoding,
    Profile,
    Context,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProfileRef {
    pub name: String,
    pub revision: u32,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Coordinate {
    pub chain_id: u64,
    pub nic: [u8; 64],
    pub genesis_profile: ProfileRef,
    pub genesis: Digest48,
    pub profiles_profile: ProfileRef,
    pub profiles: [u8; 64],
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Parent {
    Genesis {
        commitment: Digest48,
    },
    Ordinary {
        epoch: u64,
        height: u64,
        round: u64,
        block: Digest48,
        authority: Digest48,
    },
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovalMessage {
    pub coordinate: Coordinate,
    pub protocol_profile: Digest48,
    pub authority: Digest48,
    pub epoch: u64,
    pub round: u64,
    pub height: u64,
    pub block: Digest48,
    pub parent: Parent,
    pub opportunity: Digest48,
    pub execution_profile: Digest48,
    pub payload: Digest48,
    pub post_state: Digest48,
    pub receipts: Digest48,
    pub identity: Digest48,
    pub key_id: Digest48,
    pub key_generation: u64,
}
/// Exact EXISTING R1-LOCAL-SIGNING-JOURNAL context bytes. These bind durable
/// storage to one native authority/key; computing them grants no reservation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JournalContext {
    pub coordinate: Coordinate,
    pub protocol_profile: Digest48,
    pub authority: Digest48,
    pub epoch: u64,
    pub identity: Digest48,
    pub key_id: Digest48,
    pub key_generation: u64,
}
impl JournalContext {
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        if self.coordinate.chain_id == 0 || self.key_generation == 0 {
            return Err(Error::Context);
        }
        let mut w = Writer(Vec::new());
        w.variable(b"R1-LOCAL-SIGNING-JOURNAL")?;
        w.u16(1)?;
        let n = &self.coordinate;
        w.u64(n.chain_id)?;
        w.bytes(&n.nic)?;
        w.profile(&n.genesis_profile)?;
        w.bytes(&n.genesis)?;
        w.profile(&n.profiles_profile)?;
        w.bytes(&n.profiles)?;
        w.bytes(&self.protocol_profile)?;
        w.bytes(&self.authority)?;
        w.u64(self.epoch)?;
        w.bytes(&self.identity)?;
        w.bytes(&self.key_id)?;
        w.u64(self.key_generation)?;
        Ok(w.0)
    }
}
impl ApprovalMessage {
    /// Cross-bind the existing Header to this approval. Public data checks
    /// cannot verify execution/opportunity, ancestry or authority.
    pub fn ensure_header_bindings(&self, header: &[u8], schedule: &Digest48) -> Result<(), Error> {
        if header.is_empty() || header.len() > 4096 {
            return Err(Error::Bounds);
        }
        let mut r = Reader {
            bytes: header,
            at: 0,
        };
        if r.u16()? != 1
            || r.coordinate()? != self.coordinate
            || r.fixed::<48>()? != self.protocol_profile
            || r.u64()? != self.epoch
            || r.u64()? != self.height
            || r.u64()? != self.round
        {
            return Err(Error::Context);
        }
        let _proposer = r.fixed::<48>()?;
        if r.fixed::<48>()? != self.authority
            || r.fixed::<48>()? != *schedule
            || r.fixed::<48>()? != self.opportunity
        {
            return Err(Error::Context);
        }
        let _ledger_parent = r.fixed::<48>()?;
        if r.parent()? != self.parent || r.fixed::<48>()? != self.execution_profile {
            return Err(Error::Context);
        }
        let _pre_state = r.fixed::<48>()?;
        if r.fixed::<48>()? != self.post_state
            || r.fixed::<48>()? != self.receipts
            || r.fixed::<48>()? != self.payload
        {
            return Err(Error::Context);
        }
        let _dependencies = r.fixed::<48>()?;
        let _resources = r.fixed::<48>()?;
        let _effects = r.fixed::<48>()?;
        let _payload_bytes = r.u64()?;
        let _tx_count = u32::from_le_bytes(r.fixed()?);
        let _gas_used = r.u64()?;
        if r.at != header.len() {
            return Err(Error::Encoding);
        }
        Ok(())
    }
    /// Exact existing ordinary-block approval bytes; no hash or prehash here.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        if self.coordinate.chain_id == 0 {
            return Err(Error::Context);
        }
        let mut w = Writer(Vec::new());
        w.variable(CONTEXT)?;
        w.u16(1)?;
        let n = &self.coordinate;
        w.u64(n.chain_id)?;
        w.bytes(&n.nic)?;
        w.profile(&n.genesis_profile)?;
        w.bytes(&n.genesis)?;
        w.profile(&n.profiles_profile)?;
        w.bytes(&n.profiles)?;
        w.bytes(&self.protocol_profile)?;
        w.bytes(&self.authority)?;
        w.u64(self.epoch)?;
        w.u16(0)?; // Existing ordinary ledger family, not timeout/boundary.
        w.u64(self.round)?;
        w.u64(self.height)?;
        w.bytes(&self.block)?;
        match &self.parent {
            Parent::Genesis { commitment } => {
                w.u16(0)?;
                w.bytes(commitment)?;
            }
            Parent::Ordinary {
                epoch,
                height,
                round,
                block,
                authority,
            } => {
                w.u16(1)?;
                w.u64(*epoch)?;
                w.u64(*height)?;
                w.u64(*round)?;
                w.bytes(block)?;
                w.bytes(authority)?;
            }
        }
        for value in [
            &self.opportunity,
            &self.execution_profile,
            &self.payload,
            &self.post_state,
            &self.receipts,
            &self.identity,
            &self.key_id,
        ] {
            w.bytes(value)?;
        }
        w.u64(self.key_generation)?;
        Ok(w.0)
    }
    /// Strict bounded public decoding. A returned value is not an authorization
    /// or a claim that its block, parent, authority or execution was verified.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_MESSAGE_BYTES {
            return Err(Error::Bounds);
        }
        let mut r = Reader { bytes, at: 0 };
        if r.variable(128)? != CONTEXT || r.u16()? != 1 {
            return Err(Error::Encoding);
        }
        let coordinate = r.coordinate()?;
        let protocol_profile = r.fixed()?;
        let authority = r.fixed()?;
        let epoch = r.u64()?;
        if r.u16()? != 0 {
            return Err(Error::Encoding);
        }
        let round = r.u64()?;
        let height = r.u64()?;
        let block = r.fixed()?;
        let parent = r.parent()?;
        let message = Self {
            coordinate,
            protocol_profile,
            authority,
            epoch,
            round,
            height,
            block,
            parent,
            opportunity: r.fixed()?,
            execution_profile: r.fixed()?,
            payload: r.fixed()?,
            post_state: r.fixed()?,
            receipts: r.fixed()?,
            identity: r.fixed()?,
            key_id: r.fixed()?,
            key_generation: r.u64()?,
        };
        if r.at != bytes.len() || message.encode()?.as_slice() != bytes {
            return Err(Error::Encoding);
        }
        Ok(message)
    }
}
struct Writer(Vec<u8>);
impl Writer {
    fn bytes(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if self
            .0
            .len()
            .checked_add(bytes.len())
            .is_none_or(|n| n > MAX_MESSAGE_BYTES)
        {
            return Err(Error::Bounds);
        }
        self.0.try_reserve(bytes.len()).map_err(|_| Error::Bounds)?;
        self.0.extend_from_slice(bytes);
        Ok(())
    }
    fn u16(&mut self, n: u16) -> Result<(), Error> {
        self.bytes(&n.to_le_bytes())
    }
    fn u64(&mut self, n: u64) -> Result<(), Error> {
        self.bytes(&n.to_le_bytes())
    }
    fn variable(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.bytes(
            &u32::try_from(bytes.len())
                .map_err(|_| Error::Bounds)?
                .to_le_bytes(),
        )?;
        self.bytes(bytes)
    }
    fn profile(&mut self, p: &ProfileRef) -> Result<(), Error> {
        profile(p)?;
        self.variable(p.name.as_bytes())?;
        self.bytes(&p.revision.to_le_bytes())
    }
}
fn profile(p: &ProfileRef) -> Result<(), Error> {
    if p.name.is_empty()
        || p.name.len() > 128
        || p.revision == 0
        || !p.name.bytes().all(|b| b.is_ascii_graphic())
    {
        return Err(Error::Profile);
    }
    Ok(())
}
struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl<'a> Reader<'a> {
    fn coordinate(&mut self) -> Result<Coordinate, Error> {
        Ok(Coordinate {
            chain_id: self.u64()?,
            nic: self.fixed()?,
            genesis_profile: self.profile()?,
            genesis: self.fixed()?,
            profiles_profile: self.profile()?,
            profiles: self.fixed()?,
        })
    }
    fn parent(&mut self) -> Result<Parent, Error> {
        match self.u16()? {
            0 => Ok(Parent::Genesis {
                commitment: self.fixed()?,
            }),
            1 => Ok(Parent::Ordinary {
                epoch: self.u64()?,
                height: self.u64()?,
                round: self.u64()?,
                block: self.fixed()?,
                authority: self.fixed()?,
            }),
            _ => Err(Error::Encoding),
        }
    }
    fn take(&mut self, size: usize) -> Result<&'a [u8], Error> {
        let end = self.at.checked_add(size).ok_or(Error::Bounds)?;
        let out = self.bytes.get(self.at..end).ok_or(Error::Encoding)?;
        self.at = end;
        Ok(out)
    }
    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        self.take(N)?.try_into().map_err(|_| Error::Encoding)
    }
    fn u16(&mut self) -> Result<u16, Error> {
        Ok(u16::from_le_bytes(self.fixed()?))
    }
    fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_le_bytes(self.fixed()?))
    }
    fn variable(&mut self, max: usize) -> Result<&'a [u8], Error> {
        let count = u32::from_le_bytes(self.fixed()?) as usize;
        if count > max {
            return Err(Error::Bounds);
        }
        self.take(count)
    }
    fn profile(&mut self) -> Result<ProfileRef, Error> {
        let name = std::str::from_utf8(self.variable(128)?)
            .map_err(|_| Error::Encoding)?
            .to_owned();
        let p = ProfileRef {
            name,
            revision: u32::from_le_bytes(self.fixed()?),
        };
        profile(&p)?;
        Ok(p)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> ApprovalMessage {
        ApprovalMessage {
            coordinate: Coordinate {
                chain_id: u64::MAX - 1,
                nic: [1; 64],
                genesis_profile: ProfileRef {
                    name: "SYNERGY-GENESIS-R1".into(),
                    revision: 1,
                },
                genesis: [2; 48],
                profiles_profile: ProfileRef {
                    name: "APQE-PROFILE-SET".into(),
                    revision: 1,
                },
                profiles: [3; 64],
            },
            protocol_profile: [4; 48],
            authority: [5; 48],
            epoch: 1,
            round: 7,
            height: 1,
            block: [6; 48],
            parent: Parent::Genesis {
                commitment: [2; 48],
            },
            opportunity: [7; 48],
            execution_profile: [8; 48],
            payload: [9; 48],
            post_state: [10; 48],
            receipts: [11; 48],
            identity: [12; 48],
            key_id: [13; 48],
            key_generation: 9,
        }
    }
    #[test]
    fn exact_independent_python_struct_vector_preserves_existing_wire() {
        // Independently generated with Python struct LE primitive packing, not
        // this encoder or the former PoSy Writer. Fixed public synthetic data.
        let expected = "10000000504f53592f415050524f56414c2f56310100feffffffffffffff010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101011200000053594e455247592d47454e455349532d52310100000002020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020210000000415051452d50524f46494c452d5345540100000003030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505010000000000000000000700000000000000010000000000000006060606060606060606060606060606060606060606060606060606060606060606060606060606060606060606060600000202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0900000000000000";
        let expected: Vec<u8> = expected
            .as_bytes()
            .chunks_exact(2)
            .map(|x| u8::from_str_radix(std::str::from_utf8(x).unwrap(), 16).unwrap())
            .collect();
        let message = fixture();
        assert_eq!(message.encode().unwrap(), expected);
        assert_eq!(ApprovalMessage::decode(&expected).unwrap(), message);
    }
    #[test]
    fn strict_parser_rejects_truncation_unknown_family_profile_and_trailing() {
        let message = fixture();
        let bytes = message.encode().unwrap();
        for end in 0..bytes.len() {
            assert!(ApprovalMessage::decode(&bytes[..end]).is_err());
        }
        let mut bad = bytes.clone();
        bad.push(0);
        assert!(ApprovalMessage::decode(&bad).is_err());
        let mut bad = bytes.clone();
        bad[4] ^= 1;
        assert!(ApprovalMessage::decode(&bad).is_err());
        let mut bad = bytes.clone();
        bad[0..4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(ApprovalMessage::decode(&bad).is_err());
        let mut bad = message.clone();
        bad.coordinate.genesis_profile.name = "foreign\0profile".into();
        assert_eq!(bad.encode(), Err(Error::Profile));
        let mut bad = message.clone();
        bad.coordinate.chain_id = 0;
        assert_eq!(bad.encode(), Err(Error::Context));
        let mut ordinary = message.clone();
        ordinary.parent = Parent::Ordinary {
            epoch: 1,
            height: 8,
            round: 12,
            block: [14; 48],
            authority: [5; 48],
        };
        let encoded = ordinary.encode().unwrap();
        assert_eq!(ApprovalMessage::decode(&encoded).unwrap(), ordinary);
        assert!(ApprovalMessage::decode(&vec![0; MAX_MESSAGE_BYTES + 1]).is_err());
    }
}
