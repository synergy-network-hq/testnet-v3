//! Deterministic transfer-only payload assembly over the actual state.
//! This is NOT a complete block executor or signing capability: mandatory
//! system context, protected opening and mutable contract dispatch remain
//! separately required. Empty users never prove absence of system effects.
use crate::{
    r1_native::{self, NativeError, R1NativeContext},
    r1_payload::{
        self, PayloadError, R1FeeTotals, R1PayloadCore, R1ResourceTotals, MAX_CORE_BYTES,
        MAX_OBJECTS, MAX_OPERATIONS,
    },
};
use std::{collections::BTreeSet, sync::Arc, time::Instant};
use synergy_address::r1_public::{HashAlgorithm, Primitives};
use synergy_address_engine::apqe::{
    crypto_engine::CryptoEngine, policy_transition_r1::IndexedOrdinaryProof,
};
use synergy_protocol_types::{c14n02::Encoder, R1NetworkCoordinate};
use synergy_state::{
    r1::{R1StateError, R1StateMap},
    r1_fees,
    r1_receipts::{receipts_root, R1ReceiptCore},
    world_resources::{WorldResourceBudget, WorldResourcePermit},
};
use synergy_transaction::r1::R1TransactionIntent;
pub const PROFILE_SCHEMA:&str="QACE-NATIVE-BATCH-R1/1;engineering-only-no-complete-block-authority;C14N02-BE;RESULT=(U16(1),TransactionRef,U32position,U8status,Bytes4096outcome);ManifestRef=(U16class,object48,U64bytes);class=1intent2indexedProofs3receipt4feeOrigin;hashes=H(QACE/TRANSACTION-OBJECT/03,rawIntent),H(QACE/AUTHORIZATION-OBJECT/03,proofVector),H(QACE/RECEIPT/02,receiptCore),H(QACE/FEE-ORIGIN/03,origin);resultTree=QACE/RESULT-{LEAF,PAD,NODE,ROOT,EMPTY}/02;manifestTree=QACE/MAN-{LEAF,PAD,NODE,ROOT,EMPTY}/02;tree=QACE-ch91-indexed-power2-wrapper-once;no-current-wrapper-in-manifest;deterministic-meter=inputCanonicalIntentAndProofBytes,outputCanonicalReceiptAndOriginBytes,stateReads=initialParentCanonicalSnapshotPlusFullCanonicalSnapshotOncePerOperation,stateWrites=actualChangedCanonicalKeyPlusNewValueBytes,memory=logicalCanonicalInputPlusOldAndNewStatePlusOutputPeak;not-local-RSS-or-allocator-headroom;fuel=actualReceiptGas;sumAllExceptMemoryMax;no-system-absence-authority";
#[derive(Debug)]
pub enum BlockError {
    Bounds,
    Context,
    LocalResource,
    Encoding,
    Native(NativeError),
    State(R1StateError),
}
impl From<PayloadError> for BlockError {
    fn from(_: PayloadError) -> Self {
        Self::Encoding
    }
}
impl From<synergy_protocol_types::c14n02::Error> for BlockError {
    fn from(_: synergy_protocol_types::c14n02::Error) -> Self {
        Self::Encoding
    }
}
impl From<R1StateError> for BlockError {
    fn from(e: R1StateError) -> Self {
        Self::State(e)
    }
}
pub struct SignedNativeOperation<'a> {
    pub intent: &'a R1TransactionIntent,
    pub proofs: &'a [IndexedOrdinaryProof<'a>],
}
pub struct NativeBatchContext {
    pub coordinate: R1NetworkCoordinate,
    pub epoch: u64,
    pub height: u64,
    pub execution_profile: [u8; 48],
    pub state_profile: [u8; 48],
    pub semantic_context: [u8; 48],
    pub parent_block: [u8; 48],
    pub parent_execution: [u8; 48],
    pub pre_state: [u8; 48],
    pub deadline: Instant,
    pub maximum_state_hashes: u64,
}
pub struct PublicManifestObject {
    pub class: u16,
    pub digest: [u8; 48],
    pub canonical_bytes: Vec<u8>,
}
pub struct PreparedNativePayload {
    state: R1StateMap,
    core: R1PayloadCore,
    receipts: Vec<R1ReceiptCore>,
    objects: Vec<PublicManifestObject>,
    _permit: WorldResourcePermit,
}
impl PreparedNativePayload {
    pub fn state(&self) -> &R1StateMap {
        &self.state
    }
    pub fn partial_core(&self) -> &R1PayloadCore {
        &self.core
    }
    pub fn receipts(&self) -> &[R1ReceiptCore] {
        &self.receipts
    }
    pub fn objects(&self) -> &[PublicManifestObject] {
        &self.objects
    }
}
fn hash(tag: &str, value: &[u8]) -> Result<[u8; 48], BlockError> {
    let mut e = Encoder::with_domain(tag, MAX_CORE_BYTES + 256)?;
    for b in value {
        e.u8(*b)?;
    }
    Primitives
        .hash(HashAlgorithm::Sha3384, &e.finish()?)
        .map_err(|_| BlockError::Encoding)?
        .try_into()
        .map_err(|_| BlockError::Encoding)
}
fn tree(rows: &[Vec<u8>], family: &str) -> Result<[u8; 48], BlockError> {
    if rows.len() > MAX_OBJECTS {
        return Err(BlockError::Bounds);
    }
    let n = u32::try_from(rows.len()).map_err(|_| BlockError::Bounds)?;
    if n == 0 {
        return hash(&format!("QACE/{family}-EMPTY/02"), &n.to_be_bytes());
    }
    let m = rows
        .len()
        .checked_next_power_of_two()
        .ok_or(BlockError::Bounds)?;
    let mut layer = Vec::with_capacity(m);
    for i in 0..m {
        let mut b = Encoder::new(MAX_CORE_BYTES);
        b.u32(i as u32)?;
        let tag = if let Some(row) = rows.get(i) {
            for byte in row {
                b.u8(*byte)?;
            }
            "LEAF"
        } else {
            "PAD"
        };
        layer.push(hash(&format!("QACE/{family}-{tag}/02"), &b.finish()?)?);
    }
    let mut level = 1u32;
    while layer.len() > 1 {
        let mut next = Vec::with_capacity(layer.len() / 2);
        for pair in layer.as_chunks::<2>().0 {
            let mut b = Encoder::new(100);
            b.u32(level)?;
            b.fixed(&pair[0])?;
            b.fixed(&pair[1])?;
            next.push(hash(&format!("QACE/{family}-NODE/02"), &b.finish()?)?);
        }
        layer = next;
        level += 1;
    }
    let mut b = Encoder::new(52);
    b.u32(n)?;
    b.fixed(&layer[0])?;
    hash(&format!("QACE/{family}-ROOT/02"), &b.finish()?)
}
fn proofs_bytes(proofs: &[IndexedOrdinaryProof<'_>]) -> Result<Vec<u8>, BlockError> {
    let mut e = Encoder::new(MAX_CORE_BYTES);
    e.vector(proofs, 32, |e, p| {
        e.u32(p.controller_index)?;
        e.u64(p.key_generation)?;
        e.bytes(p.signature, 4627)
    })?;
    Ok(e.finish()?)
}
fn u64n(n: usize) -> Result<u64, BlockError> {
    u64::try_from(n).map_err(|_| BlockError::Bounds)
}
fn add(a: u128, b: u128) -> Result<u128, BlockError> {
    a.checked_add(b).ok_or(BlockError::Bounds)
}
/// Execute ordered ordinary native transfers and derive every returned field.
/// Inputs are public data; this function cannot authenticate PoSy ancestry or
/// supply missing mandatory system/PEC/VM authority to a complete verifier.
pub fn assemble_transfers(
    parent: &R1StateMap,
    c: &NativeBatchContext,
    ops: &[SignedNativeOperation<'_>],
    engine: &CryptoEngine,
    budget: &Arc<WorldResourceBudget>,
) -> Result<PreparedNativePayload, BlockError> {
    if ops.len() > MAX_OPERATIONS || c.epoch == 0 || c.height == 0 || Instant::now() >= c.deadline {
        return Err(BlockError::Bounds);
    }
    c.coordinate.validate().map_err(|_| BlockError::Context)?;
    if ops.iter().any(|op| {
        !matches!(
            op.intent.action,
            synergy_transaction::r1::R1Action::Transfer { .. }
        ) || op.proofs.len() > 32
            || op.proofs.iter().any(|p| p.signature.len() > 4627)
    }) {
        return Err(BlockError::Bounds);
    }
    // Reserve the bounded transient encoder before allocating a signing frame.
    let preflight = budget
        .reserve(synergy_transaction::r1::MAX_FRAME_BYTES + 256 * 1024)
        .map_err(|_| BlockError::LocalResource)?;
    let input_bound = ops.iter().try_fold(0usize, |sum, op| {
        let n = op
            .intent
            .signing_frame()
            .map_err(|_| BlockError::Encoding)?
            .len();
        let signatures = op.proofs.iter().try_fold(0usize, |a, p| {
            a.checked_add(p.signature.len() + 12)
                .ok_or(BlockError::Bounds)
        })?;
        sum.checked_add(n)
            .and_then(|x| x.checked_add(signatures + 4))
            .filter(|x| *x <= MAX_CORE_BYTES)
            .ok_or(BlockError::Bounds)
    })?;
    let reserve = parent
        .canonical_storage_bytes()
        .checked_mul(8)
        .and_then(|n| n.checked_add(input_bound.checked_mul(8)?))
        .and_then(|n| n.checked_add(2 * MAX_CORE_BYTES))
        .ok_or(BlockError::Bounds)?;
    let permit = budget
        .reserve(reserve)
        .map_err(|_| BlockError::LocalResource)?;
    drop(preflight);
    let mut hashes = c.maximum_state_hashes;
    if synergy_state::r1_smt::root_with_limits(parent, c.deadline, &mut hashes)? != c.pre_state {
        return Err(BlockError::Context);
    }
    let before = r1_fees::read_fee_state(parent, c.coordinate.network)?;
    let mut state = parent.clone();
    let mut receipts = Vec::new();
    let mut objects = Vec::new();
    let mut results = Vec::new();
    let mut txs = Vec::new();
    let mut seen = BTreeSet::new();
    let mut totals = R1ResourceTotals {
        state_read_bytes_sum: u64n(parent.canonical_storage_bytes())?,
        memory_peak_max: u64n(
            parent
                .canonical_storage_bytes()
                .checked_mul(2)
                .ok_or(BlockError::Bounds)?,
        )?,
        ..Default::default()
    };
    let mut fees = R1FeeTotals {
        escrow_before: before.escrow_nwei,
        ..Default::default()
    };
    for (index, op) in ops.iter().enumerate() {
        let id = op.intent.identifier().map_err(|_| BlockError::Encoding)?;
        if !seen.insert(id.to_text()) {
            return Err(BlockError::Bounds);
        }
        let frame = op
            .intent
            .signing_frame()
            .map_err(|_| BlockError::Encoding)?;
        let proof = proofs_bytes(op.proofs)?;
        let old = state.canonical_storage_bytes();
        let pre = synergy_state::r1_smt::root_with_limits(&state, c.deadline, &mut hashes)?;
        let native_hash_bound = u64n(state.len())?
            .checked_mul(386)
            .and_then(|n| n.checked_add(385))
            .ok_or(BlockError::Bounds)?;
        let native_hashes = hashes;
        hashes = hashes
            .checked_sub(native_hash_bound)
            .ok_or(BlockError::LocalResource)?;
        let native = R1NativeContext {
            coordinate: c.coordinate.clone(),
            epoch: c.epoch,
            height: c.height,
            pre_state_root: pre,
            operation_position: index as u32,
            receipt_index: index as u32,
            deadline: c.deadline,
            maximum_state_hashes: native_hashes,
        };
        let result =
            r1_native::compute_transfer(&state, &native, op.intent, op.proofs, engine, budget)
                .map_err(BlockError::Native)?;
        let receipt = result.receipt().clone();
        let receipt_bytes = receipt.canonical_bytes()?;
        let origin = result
            .fee_origin()
            .canonical_bytes(c.coordinate.network)
            .map_err(|_| BlockError::Encoding)?;
        let mut written = 0usize;
        for (k, v) in result.state().entries() {
            if state.get(k) != Some(v) {
                written = written
                    .checked_add(k.canonical_bytes()?.len())
                    .and_then(|n| n.checked_add(v.canonical_bytes().ok()?.len()))
                    .ok_or(BlockError::Bounds)?;
            }
        }
        for (k, _) in state.entries() {
            if result.state().get(k).is_none() {
                written = written
                    .checked_add(k.canonical_bytes()?.len())
                    .ok_or(BlockError::Bounds)?;
            }
        }
        let input = frame
            .len()
            .checked_add(proof.len())
            .ok_or(BlockError::Bounds)?;
        let output = receipt_bytes
            .len()
            .checked_add(origin.len())
            .ok_or(BlockError::Bounds)?;
        let logical_peak = old
            .checked_add(result.state().canonical_storage_bytes())
            .and_then(|n| n.checked_add(input))
            .and_then(|n| n.checked_add(output))
            .ok_or(BlockError::Bounds)?;
        totals = totals.checked_add(&R1ResourceTotals {
            fuel_sum: receipt.gas_used,
            input_bytes_sum: u64n(input)?,
            output_bytes_sum: u64n(output)?,
            state_read_bytes_sum: u64n(old)?,
            state_written_bytes_sum: u64n(written)?,
            memory_peak_max: u64n(logical_peak)?,
        })?;
        fees.debited = add(fees.debited, add(receipt.paid_nwei, receipt.refunded_nwei)?)?;
        fees.charged = add(fees.charged, receipt.paid_nwei)?;
        fees.refunded = add(fees.refunded, receipt.refunded_nwei)?;
        fees.validator_class = add(fees.validator_class, result.fee_origin().validator_nwei)?;
        fees.treasury_class = add(fees.treasury_class, result.fee_origin().treasury_nwei)?;
        let mut r = Encoder::new(8192);
        r.u16(1)?;
        r.u8(u8::from(id.to_text().starts_with("synxxn")))?;
        r.fixed(id.digest48())?;
        r.u32(index as u32)?;
        r.u8(match receipt.result {
            synergy_state::r1_finalized::R1TransactionStatus::Applied => 0,
            synergy_state::r1_finalized::R1TransactionStatus::Reverted => 1,
            synergy_state::r1_finalized::R1TransactionStatus::ResourceExhausted => 2,
        })?;
        r.bytes(&receipt.operation_outcome, 4096)?;
        results.push(r.finish()?);
        for (class, tag, bytes) in [
            (1, "QACE/TRANSACTION-OBJECT/03", frame),
            (2, "QACE/AUTHORIZATION-OBJECT/03", proof),
            (3, "QACE/RECEIPT/02", receipt_bytes),
            (4, "QACE/FEE-ORIGIN/03", origin),
        ] {
            objects.push(PublicManifestObject {
                class,
                digest: hash(tag, &bytes)?,
                canonical_bytes: bytes,
            });
        }
        state = result.state().clone();
        receipts.push(receipt);
        txs.push(id);
    }
    let after = r1_fees::read_fee_state(&state, c.coordinate.network)?;
    fees.escrow_after = after.escrow_nwei;
    fees.validate()?;
    let refs = objects
        .iter()
        .map(|o| {
            let mut e = Encoder::new(58);
            e.u16(o.class)?;
            e.fixed(&o.digest)?;
            e.u64(u64n(o.canonical_bytes.len())?)?;
            Ok(e.finish()?)
        })
        .collect::<Result<Vec<_>, BlockError>>()?;
    let core = R1PayloadCore {
        coordinate: c.coordinate.clone(),
        epoch: c.epoch,
        height: c.height,
        execution_profile: c.execution_profile,
        state_profile: c.state_profile,
        context: c.semantic_context,
        parent_block: c.parent_block,
        parent_execution: c.parent_execution,
        pre_state: c.pre_state,
        user_operations: txs.clone(),
        system_transitions: Vec::new(),
        protected_evidence: Vec::new(),
        transactions_root: r1_payload::transactions_root(&txs)?,
        results_root: tree(&results, "RESULT")?,
        receipts_root: receipts_root(&receipts)?,
        resources: totals,
        fees,
        manifest_root: tree(&refs, "MAN")?,
        post_state: synergy_state::r1_smt::root_with_limits(&state, c.deadline, &mut hashes)?,
    };
    core.validate_shape()?;
    Ok(PreparedNativePayload {
        state,
        core,
        receipts,
        objects,
        _permit: permit,
    })
}

/// H1 parent execution is a distinct explicit typed anchor derived OUTSIDE
/// Genesis, only after the caller has authenticated that complete Genesis.
/// The output itself grants no Genesis or state authority.
pub fn genesis_execution_anchor(
    coordinate: &R1NetworkCoordinate,
    execution_profile: &[u8; 48],
    state_profile: &[u8; 48],
    initial_state: &[u8; 48],
    initial_receipts: &[u8; 48],
) -> Result<[u8; 48], BlockError> {
    coordinate.validate().map_err(|_| BlockError::Context)?;
    let mut e = Encoder::new(1024);
    e.u16(1)?;
    e.u64(coordinate.network.chain_id)?;
    e.fixed(&coordinate.network.nic)?;
    for (profile, digest) in [
        (
            &coordinate.genesis.profile,
            coordinate.genesis.digest.as_slice(),
        ),
        (
            &coordinate.activated_profiles.profile,
            coordinate.activated_profiles.commitment.as_slice(),
        ),
    ] {
        e.ascii(&profile.name, 128)?;
        e.u32(profile.revision)?;
        for b in digest {
            e.u8(*b)?;
        }
    }
    for d in [
        execution_profile,
        state_profile,
        initial_state,
        initial_receipts,
    ] {
        e.fixed(d)?;
    }
    hash("QACE/GENESIS-EXECUTION-ANCHOR/01", &e.finish()?)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> R1PayloadCore {
        let v: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/r1_payload_public.json")).unwrap();
        R1PayloadCore::decode(&hex::decode(v["core_hex"].as_str().unwrap()).unwrap()).unwrap()
    }
    #[test]
    fn native_batch_independent_empty_roots_and_h1_anchor() {
        assert_eq!(hex::encode(tree(&[],"RESULT").unwrap()),"79cfee24e108138dcb957611ede58b54c86688155419b899fc99b49745397ba95812e1e7ed7c4b4f50fc49eb8a3eca30");
        assert_eq!(hex::encode(tree(&[],"MAN").unwrap()),"0a4f17465b6e0cdd3087b28aa14fa521e538321495be074253229025aa61f6c2e659e5340a0dc945e94b700984519305");
        let c = fixture();
        let a = genesis_execution_anchor(
            &c.coordinate,
            &c.execution_profile,
            &c.state_profile,
            &c.pre_state,
            &c.receipts_root,
        )
        .unwrap();
        assert_eq!(hex::encode(a),"bf5416875434d85e1ebdefa3c5ce9f3e6fa07ee9d55a5cb3eb096cc41e4df65acedc86a7729e01d5bdf8059cdd95f47c");
        assert_ne!(a, c.coordinate.genesis.digest);
        assert_ne!(a, c.pre_state);
        let mut c = c;
        c.coordinate.network.nic[63] ^= 1;
        assert_ne!(
            a,
            genesis_execution_anchor(
                &c.coordinate,
                &c.execution_profile,
                &c.state_profile,
                &c.pre_state,
                &c.receipts_root
            )
            .unwrap()
        );
        let rows = vec![vec![1], vec![2], vec![3]];
        assert_ne!(
            tree(&rows, "MAN").unwrap(),
            tree(&rows[..2], "MAN").unwrap()
        );
        let mut r = rows.clone();
        r.swap(0, 1);
        assert_ne!(tree(&rows, "MAN").unwrap(), tree(&r, "MAN").unwrap());
    }
    #[test]
    fn native_batch_empty_uses_real_backed_carry_and_does_not_claim_system_absence() {
        let c = fixture();
        let mut s = R1StateMap::new();
        r1_fees::initialize_genesis(&mut s, c.coordinate.network).unwrap();
        for k in [
            synergy_state::r1::RestrictedRecordKind::Treasury,
            synergy_state::r1::RestrictedRecordKind::FeeRoundingEscrow,
        ] {
            s.insert(
                r1_fees::restricted_key(k),
                synergy_state::r1::R1StateValue::RestrictedBalance {
                    amount_nwei: 0,
                    policy_commitment: vec![31; 64],
                },
            )
            .unwrap();
        }
        let cx = NativeBatchContext {
            coordinate: c.coordinate,
            epoch: 1,
            height: 1,
            execution_profile: c.execution_profile,
            state_profile: c.state_profile,
            semantic_context: c.context,
            parent_block: c.parent_block,
            parent_execution: c.parent_execution,
            pre_state: s.root().unwrap(),
            deadline: Instant::now() + std::time::Duration::from_secs(10),
            maximum_state_hashes: 100000,
        };
        let b = WorldResourceBudget::new(32 * 1024 * 1024);
        let original = s.clone();
        let prepared = assemble_transfers(&s, &cx, &[], &CryptoEngine::new(), &b).unwrap();
        assert_eq!(prepared.state(), &original);
        assert_eq!(prepared.partial_core().post_state, cx.pre_state);
        assert!(prepared.objects().is_empty());
        assert!(prepared.receipts().is_empty());
        assert_eq!(prepared.partial_core().fees, R1FeeTotals::default());
        assert_eq!(prepared.partial_core().resources.state_read_bytes_sum, s.canonical_storage_bytes() as u64);
        assert_eq!(prepared.partial_core().resources.memory_peak_max, (2 * s.canonical_storage_bytes()) as u64);
        let mut wrong = cx;
        wrong.pre_state[47] ^= 1;
        assert!(assemble_transfers(&s, &wrong, &[], &CryptoEngine::new(), &b).is_err());
        assert_eq!(s, original);
    }
}
