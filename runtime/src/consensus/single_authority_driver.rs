//! `single_authority_v1` block production driver (vertical slice).
//!
//! Produces and finalizes one block per height using the canonical `Block`
//! type and the canonical ML-DSA-65 block-signature convention (signature over
//! `block.hash` bytes, verified by `Block::verify_proposer_signature`).
//!
//! No coordinator, producer, vote, QC, quorum, round, cluster, view change,
//! catch-up, peer, or relayer participation exists in this path.

use super::single_authority_execution::{
    append_receipt_frame, authorize_for_execution, genesis_anchor_block, load_execution_state,
    persist_execution_state, recover_receipt_tip,
    recover_single_authority_committed_body_tail, record_committed_block_nonces,
    require_state_root_agreement, typed_transactions_for_block_with_nonce_index,
    SingleAuthorityReceiptFrame, SINGLE_AUTHORITY_RUNTIME_TAIL_CAPACITY,
};
use super::single_authority_finality_store::*;
use super::single_authority_signing_journal::*;
use super::single_authority_writable_store::WritableSingleAuthorityStore;
use crate::block::{Block, BlockChain};
use crate::crypto::pqc::{PQCAlgorithm, PQCManager, PQCPrivateKey, PQCPublicKey};
use crate::execution::{
    compute_state_root_after, execute_block_contents, ExecutionBlockContext, ExecutionResult,
    ExecutionState,
};
use crate::synergy_types::{Hash, Height};
use crate::transaction::Transaction;
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Everything the driver needs. Deliberately carries no coordinated fields.
pub struct SingleAuthorityRuntimeInputs {
    pub chain_id: u64,
    pub chain_incarnation: u64,
    pub network_id: String,
    pub release_id: String,
    pub authority_id: String,
    pub authority_key_id: String,
    pub authority_public_key: PQCPublicKey,
    pub authority_private_key: PQCPrivateKey,
    pub authority_public_key_fingerprint: String,
    pub target_block_time_ms: u64,
    pub genesis_hash: String,
    pub directory_namespace: String,
    pub finality_log_path: PathBuf,
    pub finality_head_path: PathBuf,
    pub signing_journal_path: PathBuf,
    pub committed_block_log_path: PathBuf,
    pub execution_state_path: PathBuf,
    pub receipt_log_path: PathBuf,
    /// Canonical Genesis-derived execution state. This is the height-0 state
    /// the first authority block extends, and it is produced by the Genesis
    /// path, never synthesised by the driver.
    pub genesis_execution_state: ExecutionState,
}

impl SingleAuthorityRuntimeInputs {
    pub fn chain_binding(&self) -> SingleAuthorityChainBinding {
        SingleAuthorityChainBinding {
            first_authority_height: 1,
            chain_id: self.chain_id,
            chain_incarnation: self.chain_incarnation,
            authority_id: self.authority_id.clone(),
            authority_public_key_fingerprint: self.authority_public_key_fingerprint.clone(),
        }
    }

    pub fn halt_namespace(&self) -> SingleAuthorityHaltNamespace {
        SingleAuthorityHaltNamespace {
            chain_id: self.chain_id,
            chain_incarnation: self.chain_incarnation,
            consensus_protocol: SINGLE_AUTHORITY_CONSENSUS_PROTOCOL.to_string(),
            authority_id: self.authority_id.clone(),
            release_id: self.release_id.clone(),
        }
    }
}

/// The finalized parent the next block must extend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalizedParent {
    pub height: u64,
    pub block_hash: String,
    pub state_root: Hash,
}

pub struct SingleAuthorityDriver {
    inputs: SingleAuthorityRuntimeInputs,
    journal: SingleAuthoritySigningJournal,
    store: WritableSingleAuthorityStore,
    parent: FinalizedParent,
    execution_state: ExecutionState,
    /// The highest committed nonce per sender, rebuilt by streaming the
    /// durable body archive at startup. This preserves canonical admission
    /// without retaining every historical block body in memory.
    committed_nonce_index: BTreeMap<String, u64>,
    chain: BlockChain,
}

impl SingleAuthorityDriver {
    /// Startup: open durable components, reconcile, resolve the next height.
    pub fn start(inputs: SingleAuthorityRuntimeInputs) -> Result<Self, String> {
        if inputs.authority_public_key.algorithm != PQCAlgorithm::MLDSA65 {
            return Err(format!(
                "single-authority block signing requires ML-DSA-65, found {:?}",
                inputs.authority_public_key.algorithm
            ));
        }
        let store = SingleAuthorityFinalityStore::at_paths(
            inputs.finality_log_path.clone(),
            inputs.finality_head_path.clone(),
            inputs.chain_binding(),
        )?;
        let writable = WritableSingleAuthorityStore::open(store)?;

        // Genesis is finalized height 0 and is NOT in the authority finality
        // log: it is bound by the ML-DSA-87 start authorization. Its state root
        // is the canonical Genesis execution state root, not a zero placeholder.
        let genesis_state_root = compute_state_root_after(&inputs.genesis_execution_state)?;
        let parent = match writable.cached_tail() {
            None => FinalizedParent {
                height: 0,
                block_hash: inputs.genesis_hash.clone(),
                state_root: genesis_state_root,
            },
            Some(tail) => FinalizedParent {
                height: tail.height,
                block_hash: tail.block_hash.to_hex(),
                state_root: tail.state_root,
            },
        };
        let finalized_hash = writable.cached_tail().map(|tail| tail.block_hash);
        let journal = SingleAuthoritySigningJournal::at_path(inputs.signing_journal_path.clone());
        // Reconcile the journal only after the finality log/head have been
        // recovered.  This one-time migration compacts completed signature
        // entries without ever allowing a second signature for a height.
        journal.reconcile_finalized_head(
            &inputs.halt_namespace(),
            parent.height,
            finalized_hash.as_ref(),
        )?;
        journal.require_signing_allowed(&inputs.halt_namespace())?;

        // Stream the committed-body archive to validate its entire linkage and
        // rebuild the compact nonce index, retaining only the hot suffix that
        // RPC and the next block need. Any disagreement is a hard startup
        // failure.
        let mut chain = BlockChain::new();
        chain.add_block(genesis_anchor_block(&inputs.genesis_hash));
        let committed_nonce_index = recover_single_authority_committed_body_tail(
            &mut chain,
            &inputs.committed_block_log_path,
            SINGLE_AUTHORITY_RUNTIME_TAIL_CAPACITY,
        )?;
        let execution_state = Self::reconcile_recovered_state(&inputs, &parent, &chain)?;

        // The explorer's hot range is the recent finalized tail.  Publish it
        // only after all body/finality/execution reconciliation succeeds, so
        // RPC never sees an entry that startup has not accepted as canonical.
        let rpc_tail = writable
            .recent_records()
            .iter()
            .map(|record| {
                let body = chain
                    .chain
                    .iter()
                    .find(|body| body.block_index == record.height)
                    .cloned()
                    .ok_or_else(|| {
                        format!(
                            "single-authority RPC cache has no recovered body for finalized height {}",
                            record.height
                        )
                    })?;
                Ok((record.clone(), body))
            })
            .collect::<Result<Vec<_>, String>>()?;
        crate::rpc::single_authority_finality_rpc::replace_single_authority_rpc_cache(rpc_tail)?;

        Ok(Self {
            inputs,
            journal,
            store: writable,
            parent,
            execution_state,
            committed_nonce_index,
            chain,
        })
    }

    /// Fails closed unless committed bodies, execution state, receipts, the
    /// finality record, and the durable head all describe the same chain tip.
    fn reconcile_recovered_state(
        inputs: &SingleAuthorityRuntimeInputs,
        parent: &FinalizedParent,
        chain: &BlockChain,
    ) -> Result<ExecutionState, String> {
        let (receipt_tip, saw_receipts) =
            recover_receipt_tip(&inputs.receipt_log_path, parent.height)?;
        let durable_state = load_execution_state(&inputs.execution_state_path)?;

        if parent.height == 0 {
            if chain.last().map(|tip| tip.block_index) != Some(0) {
                return Err(
                    "committed block bodies exist but no authority height is finalized".to_string(),
                );
            }
            if saw_receipts {
                return Err(
                    "durable receipts exist but no authority height is finalized".to_string(),
                );
            }
            let state = durable_state.unwrap_or_else(|| inputs.genesis_execution_state.clone());
            require_state_root_agreement(&state, parent.state_root, "genesis recovery")?;
            return Ok(state);
        }

        let tip = chain.last().ok_or_else(|| {
            format!(
                "finalized height {} has no recovered committed block body",
                parent.height
            )
        })?;
        if tip.block_index != parent.height || tip.hash != parent.block_hash {
            return Err(format!(
                "recovered committed block tip {}:{} does not match finalized head {}:{}",
                tip.block_index, tip.hash, parent.height, parent.block_hash
            ));
        }
        let frame = receipt_tip
            .as_ref()
            .ok_or_else(|| format!("finalized height {} has no durable receipts", parent.height))?;
        if frame.block_hash != parent.block_hash || frame.state_root_after != parent.state_root {
            return Err(format!(
                "durable receipt frame at height {} disagrees with the finalized record",
                parent.height
            ));
        }
        let state = durable_state.ok_or_else(|| {
            format!(
                "finalized height {} has no durable execution state",
                parent.height
            )
        })?;
        require_state_root_agreement(
            &state,
            parent.state_root,
            &format!("height {} recovery", parent.height),
        )?;
        Ok(state)
    }

    pub fn next_height(&self) -> u64 {
        self.parent.height + 1
    }

    pub fn finalized_parent(&self) -> &FinalizedParent {
        &self.parent
    }

    /// The finalized execution state the next block extends.
    pub fn execution_state(&self) -> &ExecutionState {
        &self.execution_state
    }

    /// The recovered committed block bodies.
    pub fn chain(&self) -> &BlockChain {
        &self.chain
    }
}

impl SingleAuthorityDriver {
    /// Produce and finalize exactly one block at the next height.
    pub fn produce_next_block(&mut self, transactions: Vec<Transaction>) -> Result<Block, String> {
        let height = self.next_height();

        // 1. Canonical block construction on the DURABLE finalized parent.
        let mut block = Block::new(
            height,
            transactions,
            self.parent.block_hash.clone(),
            self.inputs.authority_id.clone(),
            0,
        );
        // `Block::hash` is blake3 hex, so this round-trips exactly via to_hex()
        // and a recovered parent reproduces the identical canonical block id.
        let block_hash = Hash::from_hex(&block.hash)?;

        // 1b. Canonical execution. The roots below are produced by the one
        // shared state transition, not by the driver. Height and the
        // consensus-bounded block timestamp are the only block-derived inputs.
        let execution = self.execute_block_body(&block)?;
        let state_root = execution.state_root_after;
        let receipt_root = execution.receipt_root;
        // `transactions_root` is the canonical blake3 merkle root already
        // committed in the block preimage; it round-trips exactly.
        let transaction_root = Hash::from_hex(&block.transactions_root)?;

        // 2. Signing subject bound to the exact canonical block.
        let subject = SingleAuthoritySigningSubject {
            schema_version: SINGLE_AUTHORITY_JOURNAL_SCHEMA_VERSION,
            chain_id: self.inputs.chain_id,
            chain_incarnation: self.inputs.chain_incarnation,
            consensus_protocol: SINGLE_AUTHORITY_CONSENSUS_PROTOCOL.to_string(),
            authority_id: self.inputs.authority_id.clone(),
            authority_key_id: self.inputs.authority_key_id.clone(),
            release_id: self.inputs.release_id.clone(),
            height,
            parent_hash: Hash::from_hex(&self.parent.block_hash)?,
            canonical_block_hash: block_hash,
            canonical_signing_payload_digest: Hash::from_domain_bytes(
                "SYNERGY_CHAIN1266_SINGLE_AUTHORITY_PAYLOAD",
                block.hash.as_bytes(),
            ),
        };

        // 3. Authorize BEFORE signing; replay an existing signature, never re-sign.
        let signature_bytes = match self.journal.authorize_before_signature(&subject)? {
            SingleAuthoritySigningDecision::ReplayExisting(existing) => {
                use base64::{engine::general_purpose, Engine as _};
                general_purpose::STANDARD
                    .decode(&existing.signature_base64)
                    .map_err(|error| format!("decode replayed signature: {error}"))?
            }
            SingleAuthoritySigningDecision::SafetyHalt(reason) => {
                self.journal
                    .enter_safety_halt(&self.inputs.halt_namespace(), height, &reason)?;
                return Err(format!("SINGLE_AUTHORITY_SAFETY_HALT: {reason}"));
            }
            SingleAuthoritySigningDecision::SignFresh => {
                let mut manager = PQCManager::new();
                manager
                    .sign(&self.inputs.authority_private_key, block.hash.as_bytes())
                    .map_err(|error| format!("ML-DSA-65 block signing failed: {error}"))?
                    .signature_data
            }
        };
        self.finalize_signed_block(
            block_hash,
            state_root,
            transaction_root,
            receipt_root,
            subject,
            signature_bytes,
            &mut block,
            execution,
        )?;
        Ok(block)
    }

    /// Runs the canonical, protocol-neutral state transition over a block body.
    ///
    /// Every carrier is re-admitted here; a body the admission path would
    /// reject can never be executed or finalized.
    pub fn execute_block_body(&self, block: &Block) -> Result<ExecutionResult, String> {
        let consensus_timestamp_unix = block.timestamp;
        let typed = typed_transactions_for_block_with_nonce_index(
            &block.transactions,
            &self.committed_nonce_index,
            consensus_timestamp_unix,
        )?;
        let authorized =
            authorize_for_execution(&self.execution_state, &typed, consensus_timestamp_unix)?;
        execute_block_contents(
            &ExecutionBlockContext {
                height: Height(block.block_index),
                timestamp_ms: consensus_timestamp_unix.saturating_mul(1_000),
            },
            &typed,
            &authorized,
        )
    }
}

impl SingleAuthorityDriver {
    #[allow(clippy::too_many_arguments)]
    fn finalize_signed_block(
        &mut self,
        block_hash: Hash,
        state_root: Hash,
        transaction_root: Hash,
        receipt_root: Hash,
        subject: SingleAuthoritySigningSubject,
        signature_bytes: Vec<u8>,
        block: &mut Block,
        execution: ExecutionResult,
    ) -> Result<(), String> {
        use base64::{engine::general_purpose, Engine as _};

        // 4. Attach the signature and VERIFY it before anything is persisted.
        block.proposer_public_key = self.inputs.authority_public_key.key_data.clone();
        block.block_signature = signature_bytes.clone();
        block.block_signature_algorithm = "mldsa65".to_string();
        block.verify_proposer_signature()?;

        // 5. Durably journal the exact signature.
        self.journal.record_signature(
            &subject,
            &SingleAuthoritySignatureRecord {
                signature_algorithm: SINGLE_AUTHORITY_SIGNATURE_ALGORITHM.to_string(),
                signature_base64: general_purpose::STANDARD.encode(&signature_bytes),
                authority_public_key_fingerprint: self
                    .inputs
                    .authority_public_key_fingerprint
                    .clone(),
            },
        )?;

        // 6. Persist the canonical committed block body.
        crate::consensus::chain_durability::append_committed_block_body_at(
            block,
            &self.inputs.committed_block_log_path,
        )?;

        // 6b. Persist the executed state and the canonical receipts BEFORE
        // finality is appended, so a crash can never leave a finalized height
        // without its reproducible execution products.
        persist_execution_state(&self.inputs.execution_state_path, &execution.state)?;
        append_receipt_frame(
            &self.inputs.receipt_log_path,
            &SingleAuthorityReceiptFrame {
                height: subject.height,
                block_hash: block.hash.clone(),
                receipt_root,
                state_root_after: state_root,
                receipts: execution.receipts.clone(),
            },
        )?;

        // 7. Append + fsync the finality record.
        let record = SingleAuthorityFinalityRecord {
            schema_version: SINGLE_AUTHORITY_FINALITY_SCHEMA_VERSION,
            chain_id: self.inputs.chain_id,
            chain_incarnation: self.inputs.chain_incarnation,
            consensus_protocol: SINGLE_AUTHORITY_CONSENSUS_PROTOCOL.to_string(),
            release_id: self.inputs.release_id.clone(),
            height: subject.height,
            block_hash,
            parent_hash: subject.parent_hash,
            state_root,
            transaction_root,
            receipt_root,
            authority_id: self.inputs.authority_id.clone(),
            authority_public_key_fingerprint: self.inputs.authority_public_key_fingerprint.clone(),
            authority_signature_base64: general_purpose::STANDARD.encode(&signature_bytes),
            finalized_timestamp_ms: block.timestamp.saturating_mul(1_000),
        };
        self.store.append_finalized(&record)?;

        // 8. Atomically commit the durable head, THEN mark finalized.
        self.store.commit_head(&record)?;
        self.journal.mark_finalized(&subject)?;

        // 9. Only now may the parent, the bounded in-memory body tail, nonce
        // index, and execution state advance (publication would happen here).
        self.chain.add_block_extending_tip(block.clone())?;
        while self.chain.chain.len() > SINGLE_AUTHORITY_RUNTIME_TAIL_CAPACITY + 1 {
            self.chain.chain.remove(1);
        }
        record_committed_block_nonces(&mut self.committed_nonce_index, block);
        crate::rpc::single_authority_finality_rpc::push_single_authority_rpc_cache_entry(
            record,
            block.clone(),
        );
        self.execution_state = execution.state;
        self.parent = FinalizedParent {
            height: subject.height,
            block_hash: block.hash.clone(),
            state_root,
        };
        Ok(())
    }
}
