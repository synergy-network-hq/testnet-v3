//! QACE chapter91 indexed receipt commitment. A valid receipt proof proves
//! inclusion only; independent execution and PoSy finality remain mandatory.
use crate::r1::{hash_encoded, R1StateError};
use crate::r1_finalized::R1TransactionStatus;
use std::collections::BTreeSet;
use synergy_address::r1_public::TransactionIdentifierPresentation;
use synergy_protocol_types::c14n02::{Decoder, Encoder};
pub const MAX_RECEIPTS: usize = 4096;
pub const MAX_OUTCOME_BYTES: usize = 4096;
pub const RECEIPT_PROFILE_SCHEMA:&str=concat!(
 "QACE-RECEIPT-R1/1;codec=QACE-C14N-02;H=SHA3-384(U16BE(2),ASCII128(domain),typed-fields);",
 "ReceiptCore=(schema:U16BE(1),transaction_kind:U8(syntxn=0,synxxn=1),transaction_digest48,sequence_index:U32BE,result:U8(applied=0,reverted=1,resource_exhausted=2),gas_used:U64BE,paid_nwei:U128BE,refunded_nwei:U128BE,events_commitment48,permitted_return_commitment48,error_code:Option(ASCII128),operation_outcome:Bytes4096);",
 "error_code=nonempty-ASCII-graphic-if-present;applied-has-no-error;no-current-block-digest-or-wallclock;",
 "n<=4096;unique-transaction-kind-and-digest;index-equals-position;",
 "n=0:H(QACE/RCT-EMPTY/02,U32BE(0));n>0:m=least-power-of-two>=n;",
 "leaf(i)=H(QACE/RCT-LEAF/02,U32BE(i),ReceiptCore(i));pad(i)=H(QACE/RCT-PAD/02,U32BE(i));",
 "node(l,left,right)=H(QACE/RCT-NODE/02,U32BE(l),left48,right48),level-starts1;root=H(QACE/RCT-ROOT/02,U32BE(n),top48);",
 "proof=receipt_count:U32BE,sequence_index:U32BE,siblings48-bottom-up;index<n;exact-log2(m)-siblings;",
 "inclusion-proves-neither-computation-nor-finality"
);

/// Selected receipt schema1. Deterministic gas usage is the current native
/// resource meter. This schema never substitutes elapsed time or worker metrics.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct R1ReceiptCore {
    pub transaction: TransactionIdentifierPresentation,
    pub sequence_index: u32,
    pub result: R1TransactionStatus,
    pub gas_used: u64,
    pub paid_nwei: u128,
    pub refunded_nwei: u128,
    pub events_commitment: [u8; 48],
    pub permitted_return_commitment: [u8; 48],
    pub error_code: Option<String>,
    pub operation_outcome: Vec<u8>,
}
impl R1ReceiptCore {
    /// Original canonical core, never reconstructed from a compact RPC result.
    pub fn decode_canonical(encoded: &[u8]) -> Result<Self, R1StateError> {
        let mut d = Decoder::new(encoded, MAX_OUTCOME_BYTES + 512)?;
        if d.u16()? != 1 {
            return Err(R1StateError::InvalidValue);
        }
        let namespace = match d.u8()? {
            0 => "syntxn",
            1 => "synxxn",
            _ => return Err(R1StateError::InvalidValue),
        };
        let transaction = TransactionIdentifierPresentation::from_digest(namespace, d.fixed()?)
            .map_err(|_| R1StateError::InvalidValue)?;
        let sequence_index = d.u32()?;
        let result = match d.u8()? {
            0 => R1TransactionStatus::Applied,
            1 => R1TransactionStatus::Reverted,
            2 => R1TransactionStatus::ResourceExhausted,
            _ => return Err(R1StateError::InvalidValue),
        };
        let core = Self {
            transaction,
            sequence_index,
            result,
            gas_used: d.u64()?,
            paid_nwei: d.u128()?,
            refunded_nwei: d.u128()?,
            events_commitment: d.fixed()?,
            permitted_return_commitment: d.fixed()?,
            error_code: d.option(|d| Ok(d.ascii(128)?.to_owned()))?,
            operation_outcome: d.bytes(MAX_OUTCOME_BYTES)?.to_vec(),
        };
        d.finish()?;
        if core.canonical_bytes()? != encoded {
            return Err(R1StateError::InvalidValue);
        }
        Ok(core)
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, R1StateError> {
        if self.operation_outcome.len() > MAX_OUTCOME_BYTES
            || self.error_code.as_ref().is_some_and(|s| {
                s.is_empty() || s.len() > 128 || !s.bytes().all(|b| b.is_ascii_graphic())
            })
            || (self.result == R1TransactionStatus::Applied && self.error_code.is_some())
        {
            return Err(R1StateError::InvalidValue);
        }
        let mut e = Encoder::new(MAX_OUTCOME_BYTES + 512);
        e.u16(1)?;
        // Prefix is a typed transaction kind, never an arbitrary identifier namespace.
        e.u8(match &self.transaction.to_text()[..6] {
            "syntxn" => 0,
            "synxxn" => 1,
            _ => return Err(R1StateError::InvalidValue),
        })?;
        e.fixed(self.transaction.digest48())?;
        e.u32(self.sequence_index)?;
        e.u8(match self.result {
            R1TransactionStatus::Applied => 0,
            R1TransactionStatus::Reverted => 1,
            R1TransactionStatus::ResourceExhausted => 2,
        })?;
        e.u64(self.gas_used)?;
        e.u128(self.paid_nwei)?;
        e.u128(self.refunded_nwei)?;
        e.fixed(&self.events_commitment)?;
        e.fixed(&self.permitted_return_commitment)?;
        e.option(&self.error_code, |e, s| e.ascii(s, 128))?;
        e.bytes(&self.operation_outcome, MAX_OUTCOME_BYTES)?;
        Ok(e.finish()?)
    }
}
fn encode_index(i: u32) -> Result<Vec<u8>, R1StateError> {
    let mut e = Encoder::new(4);
    e.u32(i)?;
    Ok(e.finish()?)
}
fn leaf(i: u32, core: &R1ReceiptCore) -> Result<[u8; 48], R1StateError> {
    if core.sequence_index != i {
        return Err(R1StateError::InvalidValue);
    }
    hash_encoded(
        "QACE/RCT-LEAF/02",
        &[&encode_index(i)?, &core.canonical_bytes()?],
    )
}
fn padding(i: u32) -> Result<[u8; 48], R1StateError> {
    hash_encoded("QACE/RCT-PAD/02", &[&encode_index(i)?])
}
fn node(level: u32, l: &[u8; 48], r: &[u8; 48]) -> Result<[u8; 48], R1StateError> {
    hash_encoded("QACE/RCT-NODE/02", &[&encode_index(level)?, l, r])
}
fn list_root(n: u32, top: &[u8; 48]) -> Result<[u8; 48], R1StateError> {
    hash_encoded("QACE/RCT-ROOT/02", &[&encode_index(n)?, top])
}
fn leaves(receipts: &[R1ReceiptCore]) -> Result<Vec<[u8; 48]>, R1StateError> {
    if receipts.len() > MAX_RECEIPTS {
        return Err(R1StateError::ResourceLimit);
    }
    let n = receipts.len();
    if n == 0 {
        return Ok(Vec::new());
    }
    let m = n
        .checked_next_power_of_two()
        .ok_or(R1StateError::Overflow)?;
    let mut result = Vec::new();
    result
        .try_reserve_exact(m)
        .map_err(|_| R1StateError::ResourceLimit)?;
    let mut ids = BTreeSet::new();
    for (i, r) in receipts.iter().enumerate() {
        if !ids.insert(r.transaction.to_text()) {
            return Err(R1StateError::Duplicate);
        }
        result.push(leaf(i as u32, r)?)
    }
    for i in n..m {
        result.push(padding(i as u32)?)
    }
    Ok(result)
}
pub fn receipts_root(receipts: &[R1ReceiptCore]) -> Result<[u8; 48], R1StateError> {
    let mut layer = leaves(receipts)?;
    if layer.is_empty() {
        return crate::r1::empty_receipts_root();
    }
    let mut level = 1;
    while layer.len() > 1 {
        layer = layer
            .chunks_exact(2)
            .map(|p| node(level, &p[0], &p[1]))
            .collect::<Result<_, _>>()?;
        level += 1
    }
    list_root(receipts.len() as u32, &layer[0])
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct R1ReceiptProof {
    pub receipt_count: u32,
    pub sequence_index: u32,
    pub siblings: Vec<[u8; 48]>,
}
pub fn prove_receipt(
    receipts: &[R1ReceiptCore],
    index: u32,
) -> Result<R1ReceiptProof, R1StateError> {
    if index as usize >= receipts.len() {
        return Err(R1StateError::Proof);
    }
    let mut layer = leaves(receipts)?;
    let mut position = index as usize;
    let mut siblings = Vec::new();
    let mut level = 1;
    while layer.len() > 1 {
        siblings.push(layer[position ^ 1]);
        layer = layer
            .chunks_exact(2)
            .map(|p| node(level, &p[0], &p[1]))
            .collect::<Result<_, _>>()?;
        position /= 2;
        level += 1
    }
    Ok(R1ReceiptProof {
        receipt_count: receipts.len() as u32,
        sequence_index: index,
        siblings,
    })
}
pub fn verify_receipt(
    root: &[u8; 48],
    core: &R1ReceiptCore,
    proof: &R1ReceiptProof,
) -> Result<(), R1StateError> {
    let n = proof.receipt_count as usize;
    if n == 0
        || n > MAX_RECEIPTS
        || proof.sequence_index >= proof.receipt_count
        || core.sequence_index != proof.sequence_index
    {
        return Err(R1StateError::Proof);
    }
    let m = n
        .checked_next_power_of_two()
        .ok_or(R1StateError::Overflow)?;
    if proof.siblings.len() != m.trailing_zeros() as usize {
        return Err(R1StateError::Proof);
    }
    let mut hash = leaf(proof.sequence_index, core)?;
    let mut pos = proof.sequence_index;
    for (i, sibling) in proof.siblings.iter().enumerate() {
        hash = if pos & 1 == 0 {
            node(i as u32 + 1, &hash, sibling)?
        } else {
            node(i as u32 + 1, sibling, &hash)?
        };
        pos >>= 1
    }
    if list_root(proof.receipt_count, &hash)? != *root {
        return Err(R1StateError::Proof);
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn received_cores_preserve_every_original_field_and_reject_noncanonical_data() {
        let mut c = core(0);
        c.transaction = TransactionIdentifierPresentation::from_digest("synxxn", [7; 48]).unwrap();
        c.result = R1TransactionStatus::Reverted;
        c.error_code = Some("REVERT".into());
        c.refunded_nwei = 123;
        c.operation_outcome = vec![5, 6, 7];
        let bytes = c.canonical_bytes().unwrap();
        assert_eq!(R1ReceiptCore::decode_canonical(&bytes).unwrap(), c);
        for end in [0, 1, 2, 3, bytes.len() - 1] {
            assert!(R1ReceiptCore::decode_canonical(&bytes[..end]).is_err());
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(R1ReceiptCore::decode_canonical(&trailing).is_err());
        let mut bad = bytes;
        bad[2] = 2;
        assert!(R1ReceiptCore::decode_canonical(&bad).is_err());
    }
    #[test]
    fn independent_python_vectors_bind_empty_single_and_padded_trees() {
        let vectors: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/qace_receipts_public.json"))
                .unwrap();
        for case in vectors["cases"].as_array().unwrap() {
            let n = case["count"].as_u64().unwrap() as u32;
            let receipts = (0..n).map(core).collect::<Vec<_>>();
            let root = receipts_root(&receipts).unwrap();
            let actual = root.iter().map(|b| format!("{b:02x}")).collect::<String>();
            assert_eq!(actual, case["root_hex"].as_str().unwrap());
        }
    }
    fn core(i: u32) -> R1ReceiptCore {
        R1ReceiptCore {
            transaction: TransactionIdentifierPresentation::from_digest(
                "syntxn",
                [i as u8 + 1; 48],
            )
            .unwrap(),
            sequence_index: i,
            result: R1TransactionStatus::Applied,
            gas_used: 7,
            paid_nwei: u128::MAX,
            refunded_nwei: 0,
            events_commitment: [2; 48],
            permitted_return_commitment: [3; 48],
            error_code: None,
            operation_outcome: vec![],
        }
    }
    #[test]
    fn indexed_tree_binds_index_count_outcome_and_exact_path() {
        for n in [1, 2, 3, 7, 8, 9] {
            let r = (0..n).map(core).collect::<Vec<_>>();
            let root = receipts_root(&r).unwrap();
            for i in 0..n {
                let p = prove_receipt(&r, i).unwrap();
                verify_receipt(&root, &r[i as usize], &p).unwrap();
                let mut bad = p.clone();
                bad.receipt_count += 1;
                assert!(verify_receipt(&root, &r[i as usize], &bad).is_err());
                let mut bad = p.clone();
                bad.siblings.push([0; 48]);
                assert!(verify_receipt(&root, &r[i as usize], &bad).is_err());
                let mut bad = r[i as usize].clone();
                bad.refunded_nwei = 1;
                assert!(verify_receipt(&root, &bad, &p).is_err());
            }
        }
    }
    #[test]
    fn duplicate_execution_and_reordered_receipts_reject() {
        let a = core(0);
        let mut b = core(1);
        b.transaction = a.transaction.clone();
        assert_eq!(receipts_root(&[a.clone(), b]), Err(R1StateError::Duplicate));
        let r = vec![core(1), core(0)];
        assert_eq!(receipts_root(&r), Err(R1StateError::InvalidValue));
        assert!(prove_receipt(&[], 0).is_err());
    }
}
