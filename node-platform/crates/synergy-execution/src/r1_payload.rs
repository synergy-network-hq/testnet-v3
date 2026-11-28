//! QACE PayloadCore schema3 for the current full-width incarnation.
//! This is canonical public data, not proof of availability, computation,
//! parent authority or PoSy finality. AIVM/ETDAG must independently verify it.
use std::collections::BTreeSet;
use synergy_address::r1_public::{HashAlgorithm, Primitives, TransactionIdentifierPresentation};
use synergy_protocol_types::{
    c14n02::{Decoder, Encoder},
    R1GenesisReference, R1NetworkCoordinate, R1NetworkRef, R1ProfileRef, R1ProfileSetReference,
};

pub const PROFILE_NAME: &str = "QACE-PAYLOAD-R1";
pub const PROFILE_REVISION: u32 = 1;
pub const MAX_OPERATIONS: usize = 4096;
pub const MAX_OBJECTS: usize = 16384;
pub const MAX_CORE_BYTES: usize = 4 * 1024 * 1024;
pub const PROFILE_SCHEMA: &str = concat!(
 "QACE-PAYLOAD-R1/1;core-schema=3;codec=QACE-C14N-02;domain=QACE/EXECUTION/03;hash=APQE-SHA3-384;",
 "core=(U16(3),Coordinate,epoch:U64,height:U64,execution_profile48,state_profile48,context48,parent_block48,parent_execution48,pre_state48,user_operations:Vector4096(TransactionRef),system:Vector4096(SystemRef),protected:Vector4096(ProtectedRef),transactions_root48,results_root48,receipts_root48,Resources,Fees,manifest_root48,post_state48);",
 "Coordinate=(chain_id:U64,NIC64,genesis_profile:ProfileRef,genesis48,activated_profiles:ProfileRef,profile_set64);ProfileRef=(ASCII128(name),U32(revision));",
 "TransactionRef=(U8(syntxn0,synxxn1),digest48);SystemRef=(phase:U8(before0,after1),ordinal:U32,operation_profile48,kind:U16,operation48,result48);",
 "transactions_root=power2-indexed-QACE/TXN-{LEAF,PAD,NODE,ROOT,EMPTY}/02;leaf=U32(index),TransactionRef;pad=U32(index);node=U32(level>=1),left48,right48;root=U32(count),top48;empty=U32(0);",
 "ProtectedRef=(TransactionRef,PEC_profile48,PEC48,input48,policy_statement48,evidence:Vector16(Digest48));",
 "Resources=(fuel_sum:U64,input_bytes_sum:U64,output_bytes_sum:U64,state_read_bytes_sum:U64,state_written_bytes_sum:U64,memory_peak_max:U64);",
 "Fees=(debited:U128,charged:U128,refunded:U128,validator_class:U128,treasury_class:U128,escrow_before:U128,escrow_after:U128);",
 "fees:debited=charged+refunded;debited+escrow_before=refunded+validator_class+treasury_class+escrow_after;checked-U128-aggregate-turnover-not-stock-capped;escrow0or1;",
 "unique_complete_transaction_refs;system_phase_ordinal_strictly_ordered;protected_input_in_included_users;uniquePECperinput;",
 "NO_current_execution_digest_block_header_QC_or_finality_in_core;manifest_object_classes_exclude_current_wrappers;all_availability_and_semantic_authority_external"
);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PayloadError {
    Codec,
    Context,
    Bounds,
    Duplicate,
    Ordering,
    Evidence,
    Fees,
}
impl From<synergy_protocol_types::c14n02::Error> for PayloadError {
    fn from(_: synergy_protocol_types::c14n02::Error) -> Self {
        Self::Codec
    }
}
impl std::fmt::Display for PayloadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "R1 payload {:?}", self)
    }
}
impl std::error::Error for PayloadError {}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct R1ResourceTotals {
    pub fuel_sum: u64,
    pub input_bytes_sum: u64,
    pub output_bytes_sum: u64,
    pub state_read_bytes_sum: u64,
    pub state_written_bytes_sum: u64,
    pub memory_peak_max: u64,
}
impl R1ResourceTotals {
    /// Serial-equivalent cumulative usage; memory is a maximum, never a sum of
    /// local worker allocations or wall-clock time.
    pub fn checked_add(&self, other: &Self) -> Result<Self, PayloadError> {
        let add = |a: u64, b: u64| a.checked_add(b).ok_or(PayloadError::Bounds);
        Ok(Self {
            fuel_sum: add(self.fuel_sum, other.fuel_sum)?,
            input_bytes_sum: add(self.input_bytes_sum, other.input_bytes_sum)?,
            output_bytes_sum: add(self.output_bytes_sum, other.output_bytes_sum)?,
            state_read_bytes_sum: add(self.state_read_bytes_sum, other.state_read_bytes_sum)?,
            state_written_bytes_sum: add(
                self.state_written_bytes_sum,
                other.state_written_bytes_sum,
            )?,
            memory_peak_max: self.memory_peak_max.max(other.memory_peak_max),
        })
    }
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct R1FeeTotals {
    pub debited: u128,
    pub charged: u128,
    pub refunded: u128,
    pub validator_class: u128,
    pub treasury_class: u128,
    pub escrow_before: u128,
    pub escrow_after: u128,
}
impl R1FeeTotals {
    pub fn validate(&self) -> Result<(), PayloadError> {
        let gross = self
            .charged
            .checked_add(self.refunded)
            .ok_or(PayloadError::Fees)?;
        let available = self
            .debited
            .checked_add(self.escrow_before)
            .ok_or(PayloadError::Fees)?;
        let posted = self
            .refunded
            .checked_add(self.validator_class)
            .and_then(|n| n.checked_add(self.treasury_class))
            .and_then(|n| n.checked_add(self.escrow_after))
            .ok_or(PayloadError::Fees)?;
        if self.escrow_before > 1
            || self.escrow_after > 1
            || gross != self.debited
            || available != posted
        {
            return Err(PayloadError::Fees);
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct R1SystemTransitionRef {
    pub phase: u8,
    pub ordinal: u32,
    pub operation_profile: [u8; 48],
    pub kind: u16,
    pub operation: [u8; 48],
    pub result: [u8; 48],
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct R1ProtectedEvidenceRef {
    pub transaction: TransactionIdentifierPresentation,
    pub pec_profile: [u8; 48],
    pub pec: [u8; 48],
    pub input: [u8; 48],
    pub policy_statement: [u8; 48],
    pub evidence: Vec<[u8; 48]>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct R1PayloadCore {
    pub coordinate: R1NetworkCoordinate,
    pub epoch: u64,
    pub height: u64,
    pub execution_profile: [u8; 48],
    pub state_profile: [u8; 48],
    pub context: [u8; 48],
    pub parent_block: [u8; 48],
    pub parent_execution: [u8; 48],
    pub pre_state: [u8; 48],
    pub user_operations: Vec<TransactionIdentifierPresentation>,
    pub system_transitions: Vec<R1SystemTransitionRef>,
    pub protected_evidence: Vec<R1ProtectedEvidenceRef>,
    pub transactions_root: [u8; 48],
    pub results_root: [u8; 48],
    pub receipts_root: [u8; 48],
    pub resources: R1ResourceTotals,
    pub fees: R1FeeTotals,
    pub manifest_root: [u8; 48],
    pub post_state: [u8; 48],
}
fn tx_key(t: &TransactionIdentifierPresentation) -> (u8, [u8; 48]) {
    (u8::from(t.to_text().starts_with("synxxn")), *t.digest48())
}
fn write_tx(e: &mut Encoder, t: &TransactionIdentifierPresentation) -> Result<(), PayloadError> {
    let (kind, digest) = tx_key(t);
    e.u8(kind)?;
    e.fixed(&digest)?;
    Ok(())
}
fn read_tx(d: &mut Decoder<'_>) -> Result<TransactionIdentifierPresentation, PayloadError> {
    let prefix = match d.u8()? {
        0 => "syntxn",
        1 => "synxxn",
        _ => return Err(PayloadError::Codec),
    };
    TransactionIdentifierPresentation::from_digest(prefix, d.fixed()?)
        .map_err(|_| PayloadError::Codec)
}
fn write_profile(e: &mut Encoder, p: &R1ProfileRef) -> Result<(), PayloadError> {
    p.validate().map_err(|_| PayloadError::Context)?;
    e.ascii(&p.name, 128)?;
    e.u32(p.revision)?;
    Ok(())
}
fn read_profile(d: &mut Decoder<'_>) -> Result<R1ProfileRef, PayloadError> {
    let p = R1ProfileRef {
        name: d.ascii(128)?.into(),
        revision: d.u32()?,
    };
    p.validate().map_err(|_| PayloadError::Context)?;
    Ok(p)
}
fn hash_record(
    tag: &str,
    encode: impl FnOnce(&mut Encoder) -> Result<(), PayloadError>,
) -> Result<[u8; 48], PayloadError> {
    let mut e = Encoder::with_domain(tag, 512)?;
    encode(&mut e)?;
    Primitives
        .hash(HashAlgorithm::Sha3384, &e.finish()?)
        .map_err(|_| PayloadError::Codec)?
        .try_into()
        .map_err(|_| PayloadError::Codec)
}
/// Complete ordered native identifiers, including their exact family. Inclusion
/// commits order and membership, not authorization or transaction availability.
pub fn transactions_root(
    operations: &[TransactionIdentifierPresentation],
) -> Result<[u8; 48], PayloadError> {
    if operations.len() > MAX_OPERATIONS {
        return Err(PayloadError::Bounds);
    }
    if operations.iter().map(tx_key).collect::<BTreeSet<_>>().len() != operations.len() {
        return Err(PayloadError::Duplicate);
    }
    if operations.is_empty() {
        return hash_record("QACE/TXN-EMPTY/02", |e| {
            e.u32(0)?;
            Ok(())
        });
    }
    let mut layer = Vec::new();
    let m = operations
        .len()
        .checked_next_power_of_two()
        .ok_or(PayloadError::Bounds)?;
    for i in 0..m {
        layer.push(if let Some(tx) = operations.get(i) {
            hash_record("QACE/TXN-LEAF/02", |e| {
                e.u32(i as u32)?;
                write_tx(e, tx)
            })?
        } else {
            hash_record("QACE/TXN-PAD/02", |e| {
                e.u32(i as u32)?;
                Ok(())
            })?
        });
    }
    let mut level = 1;
    while layer.len() > 1 {
        layer = layer
            .chunks_exact(2)
            .map(|p| {
                hash_record("QACE/TXN-NODE/02", |e| {
                    e.u32(level)?;
                    e.fixed(&p[0])?;
                    e.fixed(&p[1])?;
                    Ok(())
                })
            })
            .collect::<Result<_, _>>()?;
        level += 1;
    }
    hash_record("QACE/TXN-ROOT/02", |e| {
        e.u32(operations.len() as u32)?;
        e.fixed(&layer[0])?;
        Ok(())
    })
}
impl R1PayloadCore {
    pub fn validate_shape(&self) -> Result<(), PayloadError> {
        self.coordinate
            .validate()
            .map_err(|_| PayloadError::Context)?;
        if self.epoch == 0 || self.height == 0 {
            return Err(PayloadError::Context);
        }
        if self.user_operations.len() > MAX_OPERATIONS
            || self.system_transitions.len() > MAX_OPERATIONS
            || self.protected_evidence.len() > MAX_OPERATIONS
        {
            return Err(PayloadError::Bounds);
        }
        let users = self
            .user_operations
            .iter()
            .map(tx_key)
            .collect::<BTreeSet<_>>();
        if users.len() != self.user_operations.len() {
            return Err(PayloadError::Duplicate);
        }
        if transactions_root(&self.user_operations)? != self.transactions_root {
            return Err(PayloadError::Evidence);
        }
        let mut system = BTreeSet::new();
        let mut prior = None;
        for s in &self.system_transitions {
            if s.phase > 1 || s.kind == 0 || prior.is_some_and(|p| p >= (s.phase, s.ordinal)) {
                return Err(PayloadError::Ordering);
            }
            if !system.insert(s.operation) {
                return Err(PayloadError::Duplicate);
            }
            prior = Some((s.phase, s.ordinal));
        }
        let mut protected = BTreeSet::new();
        for p in &self.protected_evidence {
            if !users.contains(&tx_key(&p.transaction))
                || p.evidence.is_empty()
                || p.evidence.len() > 16
            {
                return Err(PayloadError::Evidence);
            }
            if !protected.insert(tx_key(&p.transaction))
                || p.evidence.iter().collect::<BTreeSet<_>>().len() != p.evidence.len()
            {
                return Err(PayloadError::Duplicate);
            }
        }
        self.fees.validate()
    }
    fn encode_into(&self, e: &mut Encoder) -> Result<(), PayloadError> {
        self.validate_shape()?;
        e.u16(3)?;
        let c = &self.coordinate;
        e.u64(c.network.chain_id)?;
        e.fixed(&c.network.nic)?;
        write_profile(e, &c.genesis.profile)?;
        e.fixed(&c.genesis.digest)?;
        write_profile(e, &c.activated_profiles.profile)?;
        e.fixed(&c.activated_profiles.commitment)?;
        e.u64(self.epoch)?;
        e.u64(self.height)?;
        for digest in [
            &self.execution_profile,
            &self.state_profile,
            &self.context,
            &self.parent_block,
            &self.parent_execution,
            &self.pre_state,
        ] {
            e.fixed(digest)?;
        }
        e.vector(&self.user_operations, MAX_OPERATIONS, |e, t| {
            write_tx(e, t).map_err(|_| synergy_protocol_types::c14n02::Error::CountLimit)
        })?;
        e.vector(&self.system_transitions, MAX_OPERATIONS, |e, s| {
            e.u8(s.phase)?;
            e.u32(s.ordinal)?;
            e.fixed(&s.operation_profile)?;
            e.u16(s.kind)?;
            e.fixed(&s.operation)?;
            e.fixed(&s.result)
        })?;
        e.vector(&self.protected_evidence, MAX_OPERATIONS, |e, p| {
            write_tx(e, &p.transaction)
                .map_err(|_| synergy_protocol_types::c14n02::Error::CountLimit)?;
            for d in [&p.pec_profile, &p.pec, &p.input, &p.policy_statement] {
                e.fixed(d)?;
            }
            e.vector(&p.evidence, 16, |e, d| e.fixed(d))
        })?;
        for digest in [
            &self.transactions_root,
            &self.results_root,
            &self.receipts_root,
        ] {
            e.fixed(digest)?;
        }
        let r = self.resources;
        for n in [
            r.fuel_sum,
            r.input_bytes_sum,
            r.output_bytes_sum,
            r.state_read_bytes_sum,
            r.state_written_bytes_sum,
            r.memory_peak_max,
        ] {
            e.u64(n)?;
        }
        let f = self.fees;
        for n in [
            f.debited,
            f.charged,
            f.refunded,
            f.validator_class,
            f.treasury_class,
            f.escrow_before,
            f.escrow_after,
        ] {
            e.u128(n)?;
        }
        e.fixed(&self.manifest_root)?;
        e.fixed(&self.post_state)?;
        Ok(())
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, PayloadError> {
        let mut e = Encoder::new(MAX_CORE_BYTES);
        self.encode_into(&mut e)?;
        Ok(e.finish()?)
    }
    pub fn execution_digest(&self) -> Result<[u8; 48], PayloadError> {
        let mut e = Encoder::with_domain("QACE/EXECUTION/03", MAX_CORE_BYTES + 256)?;
        self.encode_into(&mut e)?;
        Primitives
            .hash(HashAlgorithm::Sha3384, &e.finish()?)
            .map_err(|_| PayloadError::Codec)?
            .try_into()
            .map_err(|_| PayloadError::Codec)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, PayloadError> {
        let mut d = Decoder::new(bytes, MAX_CORE_BYTES)?;
        if d.u16()? != 3 {
            return Err(PayloadError::Codec);
        }
        let coordinate = R1NetworkCoordinate {
            network: R1NetworkRef {
                chain_id: d.u64()?,
                nic: d.fixed()?,
            },
            genesis: R1GenesisReference {
                profile: read_profile(&mut d)?,
                digest: d.fixed()?,
            },
            activated_profiles: R1ProfileSetReference {
                profile: read_profile(&mut d)?,
                commitment: d.fixed()?,
            },
        };
        let epoch = d.u64()?;
        let height = d.u64()?;
        let execution_profile = d.fixed()?;
        let state_profile = d.fixed()?;
        let context = d.fixed()?;
        let parent_block = d.fixed()?;
        let parent_execution = d.fixed()?;
        let pre_state = d.fixed()?;
        let user_operations = d.vector(MAX_OPERATIONS, 49, |d| {
            read_tx(d).map_err(|_| synergy_protocol_types::c14n02::Error::Truncated)
        })?;
        let system_transitions = d.vector(MAX_OPERATIONS, 151, |d| {
            Ok(R1SystemTransitionRef {
                phase: d.u8()?,
                ordinal: d.u32()?,
                operation_profile: d.fixed()?,
                kind: d.u16()?,
                operation: d.fixed()?,
                result: d.fixed()?,
            })
        })?;
        let protected_evidence = d.vector(MAX_OPERATIONS, 293, |d| {
            Ok(R1ProtectedEvidenceRef {
                transaction: read_tx(d)
                    .map_err(|_| synergy_protocol_types::c14n02::Error::Truncated)?,
                pec_profile: d.fixed()?,
                pec: d.fixed()?,
                input: d.fixed()?,
                policy_statement: d.fixed()?,
                evidence: d.vector(16, 48, |d| d.fixed())?,
            })
        })?;
        let transactions_root = d.fixed()?;
        let results_root = d.fixed()?;
        let receipts_root = d.fixed()?;
        let resources = R1ResourceTotals {
            fuel_sum: d.u64()?,
            input_bytes_sum: d.u64()?,
            output_bytes_sum: d.u64()?,
            state_read_bytes_sum: d.u64()?,
            state_written_bytes_sum: d.u64()?,
            memory_peak_max: d.u64()?,
        };
        let fees = R1FeeTotals {
            debited: d.u128()?,
            charged: d.u128()?,
            refunded: d.u128()?,
            validator_class: d.u128()?,
            treasury_class: d.u128()?,
            escrow_before: d.u128()?,
            escrow_after: d.u128()?,
        };
        let out = Self {
            coordinate,
            epoch,
            height,
            execution_profile,
            state_profile,
            context,
            parent_block,
            parent_execution,
            pre_state,
            user_operations,
            system_transitions,
            protected_evidence,
            transactions_root,
            results_root,
            receipts_root,
            resources,
            fees,
            manifest_root: d.fixed()?,
            post_state: d.fixed()?,
        };
        d.finish()?;
        if out.canonical_bytes()?.as_slice() != bytes {
            return Err(PayloadError::Codec);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn p(n: &str) -> R1ProfileRef {
        R1ProfileRef {
            name: n.into(),
            revision: 1,
        }
    }
    fn fixture() -> R1PayloadCore {
        R1PayloadCore {
            coordinate: R1NetworkCoordinate {
                network: R1NetworkRef {
                    chain_id: u64::MAX - 1,
                    nic: [1; 64],
                },
                genesis: R1GenesisReference {
                    profile: p("SYNERGY-GENESIS-R1"),
                    digest: [2; 48],
                },
                activated_profiles: R1ProfileSetReference {
                    profile: p("APQE-PROFILE-SET"),
                    commitment: [3; 64],
                },
            },
            epoch: 1,
            height: 1,
            execution_profile: [4; 48],
            state_profile: [5; 48],
            context: [6; 48],
            parent_block: [7; 48],
            parent_execution: [8; 48],
            pre_state: [9; 48],
            user_operations: vec![TransactionIdentifierPresentation::from_digest(
                "syntxn", [10; 48],
            )
            .unwrap()],
            system_transitions: vec![R1SystemTransitionRef {
                phase: 1,
                ordinal: 0,
                operation_profile: [11; 48],
                kind: 1,
                operation: [12; 48],
                result: [13; 48],
            }],
            protected_evidence: vec![],
            transactions_root: transactions_root(&[
                TransactionIdentifierPresentation::from_digest("syntxn", [10; 48]).unwrap(),
            ])
            .unwrap(),
            results_root: [15; 48],
            receipts_root: [16; 48],
            resources: R1ResourceTotals {
                fuel_sum: 7,
                input_bytes_sum: 11,
                output_bytes_sum: 13,
                state_read_bytes_sum: 17,
                state_written_bytes_sum: 19,
                memory_peak_max: 23,
            },
            fees: R1FeeTotals {
                debited: 7,
                charged: 5,
                refunded: 2,
                validator_class: 4,
                treasury_class: 1,
                escrow_before: 0,
                escrow_after: 0,
            },
            manifest_root: [17; 48],
            post_state: [18; 48],
        }
    }
    #[test]
    fn independent_transaction_trees_bind_count_padding_order_and_full_family() {
        let v: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/r1_payload_public.json")).unwrap();
        for case in v["transaction_cases"].as_array().unwrap() {
            let n = case["count"].as_u64().unwrap() as usize;
            let mut tx = (0..n)
                .map(|i| {
                    TransactionIdentifierPresentation::from_digest(
                        if i % 2 == 0 { "syntxn" } else { "synxxn" },
                        [i as u8 + 1; 48],
                    )
                    .unwrap()
                })
                .collect::<Vec<_>>();
            let root = transactions_root(&tx).unwrap();
            assert_eq!(hex::encode(root), case["root_hex"].as_str().unwrap());
            if n > 1 {
                tx.swap(0, 1);
                assert_ne!(transactions_root(&tx).unwrap(), root);
            }
        }
        let native = TransactionIdentifierPresentation::from_digest("syntxn", [1; 48]).unwrap();
        let cross = TransactionIdentifierPresentation::from_digest("synxxn", [1; 48]).unwrap();
        assert_ne!(
            transactions_root(&[native.clone()]).unwrap(),
            transactions_root(&[cross]).unwrap()
        );
        assert_eq!(
            transactions_root(&[native.clone(), native]),
            Err(PayloadError::Duplicate)
        );
    }
    #[test]
    fn independent_python_payload_digest_and_exact_full_width_codec() {
        let oracle: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/r1_payload_public.json")).unwrap();
        let c = fixture();
        let bytes = c.canonical_bytes().unwrap();
        assert_eq!(hex::encode(&bytes), oracle["core_hex"].as_str().unwrap());
        assert_eq!(
            hex::encode(c.execution_digest().unwrap()),
            oracle["execution_digest_hex"].as_str().unwrap()
        );
        assert_eq!(R1PayloadCore::decode(&bytes).unwrap(), c);
        for n in [0, 1, 2, bytes.len() - 1] {
            assert!(R1PayloadCore::decode(&bytes[..n]).is_err());
        }
        let mut bad = bytes.clone();
        bad.push(0);
        assert!(R1PayloadCore::decode(&bad).is_err());
        let mut old = bytes;
        old[1] = 2;
        assert!(R1PayloadCore::decode(&old).is_err());
    }
    #[test]
    fn parent_network_evidence_and_required_system_changes_bind_execution() {
        let c = fixture();
        let digest = c.execution_digest().unwrap();
        let mut next = c.clone();
        next.coordinate.network.nic[63] ^= 1;
        assert_ne!(next.execution_digest().unwrap(), digest);
        let mut next = c.clone();
        next.parent_execution[47] ^= 1;
        assert_ne!(next.execution_digest().unwrap(), digest);
        let mut next = c.clone();
        next.system_transitions.clear();
        assert_ne!(next.execution_digest().unwrap(), digest);
        let mut next = c.clone();
        next.user_operations.push(next.user_operations[0].clone());
        assert_eq!(next.validate_shape(), Err(PayloadError::Duplicate));
        let mut next = c.clone();
        next.protected_evidence.push(R1ProtectedEvidenceRef {
            transaction: TransactionIdentifierPresentation::from_digest("syntxn", [99; 48])
                .unwrap(),
            pec_profile: [20; 48],
            pec: [21; 48],
            input: [22; 48],
            policy_statement: [23; 48],
            evidence: vec![[24; 48]],
        });
        assert_eq!(next.validate_shape(), Err(PayloadError::Evidence));
        let mut next = c.clone();
        next.system_transitions
            .push(next.system_transitions[0].clone());
        assert_eq!(next.validate_shape(), Err(PayloadError::Ordering));
    }
    #[test]
    fn resource_aggregation_uses_maximum_and_fees_conserve_without_turnover_stock_cap() {
        let a = R1ResourceTotals {
            fuel_sum: 7,
            memory_peak_max: 11,
            ..Default::default()
        };
        let b = R1ResourceTotals {
            fuel_sum: 5,
            memory_peak_max: 9,
            ..Default::default()
        };
        let c = a.checked_add(&b).unwrap();
        assert_eq!(c.fuel_sum, 12);
        assert_eq!(c.memory_peak_max, 11);
        assert!(a
            .checked_add(&R1ResourceTotals {
                fuel_sum: u64::MAX,
                ..Default::default()
            })
            .is_err());
        let mut fees = fixture().fees;
        fees.refunded += 1;
        assert_eq!(fees.validate(), Err(PayloadError::Fees));
        let large = 12_000_000_000_000_000_001;
        R1FeeTotals {
            debited: large,
            charged: large,
            validator_class: large,
            ..Default::default()
        }
        .validate()
        .unwrap();
        assert!(R1FeeTotals {
            debited: u128::MAX,
            charged: u128::MAX,
            validator_class: u128::MAX,
            escrow_before: 1,
            escrow_after: 1,
            ..Default::default()
        }
        .validate()
        .is_err());
    }
}
