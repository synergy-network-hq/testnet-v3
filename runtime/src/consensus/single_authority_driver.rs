//! `single_authority_v1` block production driver (vertical slice).
//!
//! Produces and finalizes one block per height using the canonical `Block`
//! type and the canonical ML-DSA-65 block-signature convention (signature over
//! `block.hash` bytes, verified by `Block::verify_proposer_signature`).
//!
//! No coordinator, producer, vote, QC, quorum, round, cluster, view change,
//! catch-up, peer, or relayer participation exists in this path.

use super::single_authority_finality_store::*;
use super::single_authority_signing_journal::*;
use super::single_authority_writable_store::WritableSingleAuthorityStore;
use crate::block::Block;
use crate::crypto::pqc::{PQCAlgorithm, PQCManager, PQCPrivateKey, PQCPublicKey};
use crate::synergy_types::Hash;
use crate::transaction::Transaction;
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
        let journal = SingleAuthoritySigningJournal::at_path(inputs.signing_journal_path.clone());
        journal.require_signing_allowed(&inputs.halt_namespace())?;

        let store = SingleAuthorityFinalityStore::at_paths(
            inputs.finality_log_path.clone(),
            inputs.finality_head_path.clone(),
            inputs.chain_binding(),
        )?;
        let writable = WritableSingleAuthorityStore::open(store)?;

        // Genesis is finalized height 0 and is NOT in the authority finality
        // log: it is bound by the ML-DSA-87 start authorization.
        let parent = match writable.cached_tail() {
            None => FinalizedParent {
                height: 0,
                block_hash: inputs.genesis_hash.clone(),
                state_root: Hash::zero(),
            },
            Some(tail) => FinalizedParent {
                height: tail.height,
                block_hash: tail.block_hash.to_hex(),
                state_root: tail.state_root,
            },
        };
        Ok(Self {
            inputs,
            journal,
            store: writable,
            parent,
        })
    }

    pub fn next_height(&self) -> u64 {
        self.parent.height + 1
    }

    pub fn finalized_parent(&self) -> &FinalizedParent {
        &self.parent
    }
}

impl SingleAuthorityDriver {
    /// Produce and finalize exactly one block at the next height.
    pub fn produce_next_block(
        &mut self,
        transactions: Vec<Transaction>,
    ) -> Result<Block, String> {
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
        let state_root = Hash::from_domain_bytes(
            "SYNERGY_CHAIN1266_SINGLE_AUTHORITY_STATE_ROOT",
            block.hash.as_bytes(),
        );
        let transaction_root = Hash::from_domain_bytes(
            "SYNERGY_CHAIN1266_SINGLE_AUTHORITY_TX_ROOT",
            block.transactions_root.as_bytes(),
        );
        let receipt_root = Hash::from_domain_bytes(
            "SYNERGY_CHAIN1266_SINGLE_AUTHORITY_RECEIPT_ROOT",
            block.transactions_root.as_bytes(),
        );

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
        )?;
        Ok(block)
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
            authority_public_key_fingerprint: self
                .inputs
                .authority_public_key_fingerprint
                .clone(),
            authority_signature_base64: general_purpose::STANDARD.encode(&signature_bytes),
            finalized_timestamp_ms: block.timestamp.saturating_mul(1_000),
        };
        self.store.append_finalized(&record)?;

        // 8. Atomically commit the durable head, THEN mark finalized.
        self.store.commit_head(&record)?;
        self.journal.mark_finalized(&subject)?;

        // 9. Only now may the parent advance (publication would happen here).
        self.parent = FinalizedParent {
            height: subject.height,
            block_hash: block.hash.clone(),
            state_root,
        };
        Ok(())
    }
}
