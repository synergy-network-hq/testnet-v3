use crate::crypto::aegis_pqvm::{AegisPqvmSigner, AegisPqvmVerifier, SYNERGY_BLOCK_V1};
use crate::dag_mempool::{compute_tx_order_root, DagMempool};
use crate::execution::{execute_block, ExecutionState};
use crate::synergy_types::{
    AegisPqKeyRole, AegisPqSignature, Block, BlockHeader, BlockId, CanonicalSerialize, ChainId,
    ClusterId, ClusterMap, Epoch, Hash, Height, NetworkId, ProtocolConfig, QuorumCertificate,
    Round, Transaction, ValidatorRecord, ValidatorSet, ValidatorStatus, Vote, VotePhase,
};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ConsensusPhase {
    Idle,
    WaitingForProposal,
    ProposingBlock,
    ReceivedProposal,
    ValidatingProposal,
    Voting,
    CollectingVotes,
    FormingQc,
    FinalizingBlock,
    Finalized,
    ViewChange,
    TimeoutWaitingForProposer,
}

#[derive(Debug, Clone)]
pub struct LocalConsensusContext {
    pub chain_id: ChainId,
    pub network_id: NetworkId,
    pub latest_finalized_height: Height,
    pub latest_finalized_block_hash: Hash,
    pub latest_finalized_state_root: Hash,
    pub last_finalized_qc_hash: Hash,
    pub epoch: Epoch,
    pub round: Round,
    pub cluster_id: ClusterId,
    pub active_validator_set_hash: Hash,
    pub eligible_validator_set_hash: Hash,
    pub cluster_map_hash: Hash,
    pub proposer_schedule_hash: Hash,
    pub protocol_config_hash: Hash,
    pub evidence_root: Hash,
    pub app_version: u32,
    pub execution_version: u32,
    pub dag_version: u32,
    pub aegis_pqvm_version: String,
}

pub struct ProofOfSynergyBft<'a> {
    pub verifier: &'a AegisPqvmVerifier,
    pub validator_set: ValidatorSet,
    pub cluster_map: ClusterMap,
    pub protocol_config: ProtocolConfig,
    pub phase: ConsensusPhase,
    observed_qcs: BTreeMap<(Height, Round, Epoch, ClusterId), BlockId>,
}

impl<'a> ProofOfSynergyBft<'a> {
    pub fn new(
        verifier: &'a AegisPqvmVerifier,
        validator_set: ValidatorSet,
        cluster_map: ClusterMap,
        protocol_config: ProtocolConfig,
    ) -> Self {
        Self {
            verifier,
            validator_set,
            cluster_map,
            protocol_config,
            phase: ConsensusPhase::Idle,
            observed_qcs: BTreeMap::new(),
        }
    }

    pub fn proposer_for(
        &self,
        height: Height,
        round: Round,
        cluster_id: ClusterId,
    ) -> Result<ValidatorRecord, String> {
        let active = self.validator_set.active_for_cluster(cluster_id);
        if active.is_empty() {
            return Err("no active validators in cluster".to_string());
        }
        let index = ((height.0 + round.0) as usize) % active.len();
        Ok(active[index].clone())
    }

    pub fn propose_block(
        &mut self,
        signer: &mut AegisPqvmSigner,
        proposer: &ValidatorRecord,
        transactions: Vec<Transaction>,
        context: &LocalConsensusContext,
        state: &ExecutionState,
        dag_frontier_root: Hash,
    ) -> Result<Block, String> {
        self.phase = ConsensusPhase::ProposingBlock;
        self.ensure_testnet_context(context)?;
        let scheduled = self.proposer_for(
            Height(context.latest_finalized_height.0 + 1),
            context.round,
            context.cluster_id,
        )?;
        if scheduled.validator_id != proposer.validator_id {
            return Err("wrong proposer for height/round/cluster".to_string());
        }
        if proposer.status != ValidatorStatus::Active {
            return Err("proposer is not ACTIVE".to_string());
        }
        if !signer.registry.key_is_active_for_epoch(
            &proposer.validator_uma_id.0,
            &proposer.consensus_public_key.key_id,
            context.epoch,
            AegisPqKeyRole::ConsensusProposer,
        ) {
            return Err("proposer key is not active for consensus proposer role".to_string());
        }
        let ordered_tx_ids = transactions
            .iter()
            .map(|tx| {
                Ok(crate::synergy_types::TxId::from_hash(
                    Hash::from_domain_bytes("SYNERGY_EXECUTION_TX_ID_V1", &tx.canonical_bytes()?),
                ))
            })
            .collect::<Result<Vec<_>, String>>()?;
        let tx_order_root = compute_tx_order_root(&ordered_tx_ids)?;
        let mut block = Block {
            header: BlockHeader {
                version: 1,
                chain_id: context.chain_id,
                network_id: context.network_id.clone(),
                height: Height(context.latest_finalized_height.0 + 1),
                round: context.round,
                epoch: context.epoch,
                cluster_id: context.cluster_id,
                parent_block_hash: context.latest_finalized_block_hash,
                parent_state_root: context.latest_finalized_state_root,
                last_finalized_qc_hash: context.last_finalized_qc_hash,
                proposer_validator_id: proposer.validator_id.clone(),
                proposer_uma_id: proposer.validator_uma_id.clone(),
                proposer_key_id: proposer.consensus_public_key.key_id.clone(),
                active_validator_set_hash: context.active_validator_set_hash,
                eligible_validator_set_hash: context.eligible_validator_set_hash,
                cluster_map_hash: context.cluster_map_hash,
                proposer_schedule_hash: context.proposer_schedule_hash,
                protocol_config_hash: context.protocol_config_hash,
                dag_frontier_root,
                tx_order_root,
                tx_count: transactions.len() as u64,
                evidence_root: context.evidence_root,
                state_root_before: context.latest_finalized_state_root,
                state_root_after: Hash::zero(),
                receipt_root: Hash::zero(),
                app_version: context.app_version,
                execution_version: context.execution_version,
                dag_version: context.dag_version,
                aegis_pqvm_version: context.aegis_pqvm_version.clone(),
                timestamp_ms_consensus_bounded: 0,
            },
            transactions,
            proposer_signature: AegisPqSignature {
                algorithm: String::new(),
                signature_bytes: Vec::new(),
            },
        };
        let execution = execute_block(&block, state)?;
        block.header.state_root_after = execution.state_root_after;
        block.header.receipt_root = execution.receipt_root;
        let header_bytes = block.header.canonical_bytes()?;
        block.proposer_signature = signer
            .sign_domain(
                SYNERGY_BLOCK_V1,
                &header_bytes,
                &proposer.consensus_public_key.key_id,
            )
            .map_err(|error| error.to_string())?;
        Ok(block)
    }

    pub fn validate_proposal(
        &mut self,
        block: &Block,
        context: &LocalConsensusContext,
        state: &ExecutionState,
        dag: &DagMempool<'_>,
    ) -> Result<(), String> {
        self.phase = ConsensusPhase::ValidatingProposal;
        self.ensure_testnet_context(context)?;
        block.header.chain_id.require_testnet_v3()?;
        block.header.network_id.require_testnet_v3()?;
        if block.header.height.0 != context.latest_finalized_height.0 + 1 {
            return Err("proposal height is not the expected next height".to_string());
        }
        if block.header.parent_block_hash != context.latest_finalized_block_hash {
            return Err("proposal parent hash does not match latest finalized block".to_string());
        }
        if block.header.state_root_before != context.latest_finalized_state_root {
            return Err(
                "proposal state_root_before does not match latest finalized state".to_string(),
            );
        }
        if block.header.active_validator_set_hash != context.active_validator_set_hash
            || block.header.cluster_map_hash != context.cluster_map_hash
            || block.header.protocol_config_hash != context.protocol_config_hash
        {
            return Err("proposal consensus context hash mismatch".to_string());
        }
        let proposer = self
            .validator_set
            .validators
            .iter()
            .find(|record| record.validator_id == block.header.proposer_validator_id)
            .ok_or_else(|| "proposal proposer not in validator set".to_string())?;
        let scheduled = self.proposer_for(
            block.header.height,
            block.header.round,
            block.header.cluster_id,
        )?;
        if scheduled.validator_id != proposer.validator_id {
            return Err("proposal was not made by scheduled proposer".to_string());
        }
        if proposer.status != ValidatorStatus::Active
            || !proposer.is_active_for_epoch(block.header.epoch)
        {
            return Err("proposal proposer is not active for epoch".to_string());
        }
        self.verifier
            .verify_domain_signature(
                SYNERGY_BLOCK_V1,
                &block.header.canonical_bytes()?,
                &proposer.validator_uma_id.0,
                &block.header.proposer_key_id,
                block.header.epoch,
                AegisPqKeyRole::ConsensusProposer,
                &block.proposer_signature,
            )
            .map_err(|error| error.to_string())?;
        for tx in &block.transactions {
            self.verifier
                .verify_transaction_signature_checked(tx)
                .map_err(|error| error.to_string())?;
        }
        let tx_ids = block
            .transactions
            .iter()
            .map(|tx| {
                Ok(crate::synergy_types::TxId::from_hash(
                    Hash::from_domain_bytes("SYNERGY_EXECUTION_TX_ID_V1", &tx.canonical_bytes()?),
                ))
            })
            .collect::<Result<Vec<_>, String>>()?;
        if block.header.tx_order_root != compute_tx_order_root(&tx_ids)? {
            return Err("proposal tx_order_root mismatch".to_string());
        }
        let sorted = dag.deterministic_topological_sort(&tx_ids)?;
        if sorted != tx_ids {
            return Err(
                "proposal transaction order is not deterministic topological order".to_string(),
            );
        }
        let execution = execute_block(block, state)?;
        if execution.state_root_after != block.header.state_root_after {
            return Err("proposal state_root_after mismatch".to_string());
        }
        if execution.receipt_root != block.header.receipt_root {
            return Err("proposal receipt_root mismatch".to_string());
        }
        Ok(())
    }

    pub fn vote(
        &mut self,
        signer: &mut AegisPqvmSigner,
        validator: &ValidatorRecord,
        block: &Block,
    ) -> Result<Vote, String> {
        self.phase = ConsensusPhase::Voting;
        if validator.status != ValidatorStatus::Active
            || !validator.is_active_for_epoch(block.header.epoch)
        {
            return Err("validator cannot vote before ACTIVE epoch".to_string());
        }
        if !self
            .cluster_map
            .contains(block.header.cluster_id, &validator.validator_id)
        {
            return Err("validator is not assigned to proposal cluster".to_string());
        }
        let mut vote = Vote {
            chain_id: block.header.chain_id,
            network_id: block.header.network_id.clone(),
            height: block.header.height,
            round: block.header.round,
            epoch: block.header.epoch,
            cluster_id: block.header.cluster_id,
            phase: VotePhase::Commit,
            block_id: block.block_id()?,
            validator_id: validator.validator_id.clone(),
            validator_uma_id: validator.validator_uma_id.clone(),
            key_id: validator.consensus_public_key.key_id.clone(),
            active_validator_set_hash: block.header.active_validator_set_hash,
            cluster_map_hash: block.header.cluster_map_hash,
            aegis_pq_signature: AegisPqSignature {
                algorithm: String::new(),
                signature_bytes: Vec::new(),
            },
        };
        vote.aegis_pq_signature = signer
            .sign_vote(
                &vote.signing_bytes()?,
                &validator.consensus_public_key.key_id,
            )
            .map_err(|error| error.to_string())?;
        Ok(vote)
    }

    pub fn collect_votes(&self, votes: &[Vote]) -> Result<Vec<Vote>, String> {
        let mut verified = Vec::new();
        let mut seen = BTreeSet::new();
        for vote in votes {
            if !seen.insert(vote.validator_id.clone()) {
                return Err("duplicate vote signer".to_string());
            }
            let validator = self
                .validator_set
                .validators
                .iter()
                .find(|record| record.validator_id == vote.validator_id)
                .ok_or_else(|| "vote signer not in validator set".to_string())?;
            self.verifier
                .verify_vote_signature_checked(vote, validator)
                .map_err(|error| error.to_string())?;
            verified.push(vote.clone());
        }
        Ok(verified)
    }

    pub fn form_qc(&mut self, votes: &[Vote]) -> Result<QuorumCertificate, String> {
        self.phase = ConsensusPhase::FormingQc;
        let verified = self.collect_votes(votes)?;
        if verified.is_empty() {
            return Err("cannot form QC without votes".to_string());
        }
        let first = &verified[0];
        let validators = self.validator_set.canonicalized().validators;
        let mut signer_bitmap = vec![0u8; (validators.len() + 7) / 8];
        let mut signatures = Vec::new();
        let mut key_ids = Vec::new();
        let mut signed_weight = 0u64;
        for vote in &verified {
            if vote.block_id != first.block_id
                || vote.height != first.height
                || vote.round != first.round
                || vote.epoch != first.epoch
                || vote.cluster_id != first.cluster_id
            {
                return Err(
                    "votes do not target the exact same block/height/round/epoch/cluster"
                        .to_string(),
                );
            }
            let index = validators
                .iter()
                .position(|validator| validator.validator_id == vote.validator_id)
                .ok_or_else(|| "vote signer missing from canonical validator set".to_string())?;
            signer_bitmap[index / 8] |= 1u8 << (index % 8);
            let validator = &validators[index];
            signed_weight = signed_weight.saturating_add(validator.voting_weight);
            signatures.push(vote.aegis_pq_signature.clone());
            key_ids.push(vote.key_id.clone());
        }
        let qc = QuorumCertificate {
            qc_version: 1,
            chain_id: first.chain_id,
            network_id: first.network_id.clone(),
            height: first.height,
            round: first.round,
            epoch: first.epoch,
            cluster_id: first.cluster_id,
            phase: first.phase.clone(),
            block_id: first.block_id.clone(),
            active_validator_set_hash: first.active_validator_set_hash,
            cluster_map_hash: first.cluster_map_hash,
            threshold_weight_required: self.validator_set.threshold_weight(),
            signed_weight,
            signer_bitmap,
            aegis_pq_signatures: signatures,
            aegis_pq_key_ids: key_ids,
        };
        self.verify_qc(&qc)?;
        Ok(qc)
    }

    pub fn verify_qc(&self, qc: &QuorumCertificate) -> Result<(), String> {
        self.verifier
            .verify_qc_checked(qc, &self.validator_set, &self.cluster_map)
            .map_err(|error| error.to_string())
    }

    pub fn commit_block(&mut self, block: &Block, qc: &QuorumCertificate) -> Result<(), String> {
        self.phase = ConsensusPhase::FinalizingBlock;
        if qc.block_id != block.block_id()? {
            return Err("QC does not certify exact block_id".to_string());
        }
        self.verify_qc(qc)?;
        let key = (qc.height, qc.round, qc.epoch, qc.cluster_id);
        if let Some(existing) = self.observed_qcs.get(&key) {
            if existing != &qc.block_id {
                return Err("SAFETY_INCIDENT_CONFLICTING_VALID_QC".to_string());
            }
        }
        self.observed_qcs.insert(key, qc.block_id.clone());
        self.phase = ConsensusPhase::Finalized;
        Ok(())
    }

    pub fn enter_view_change(&mut self) {
        self.phase = ConsensusPhase::ViewChange;
    }

    pub fn handle_timeout(&mut self) {
        self.phase = ConsensusPhase::TimeoutWaitingForProposer;
    }

    pub fn detect_equivocation(&self, proposals: &[Block]) -> bool {
        let mut seen = BTreeMap::<(Height, Round, Epoch, ClusterId), BlockId>::new();
        for block in proposals {
            let key = (
                block.header.height,
                block.header.round,
                block.header.epoch,
                block.header.cluster_id,
            );
            let Ok(block_id) = block.block_id() else {
                return true;
            };
            if let Some(existing) = seen.insert(key, block_id.clone()) {
                if existing != block_id {
                    return true;
                }
            }
        }
        false
    }

    fn ensure_testnet_context(&self, context: &LocalConsensusContext) -> Result<(), String> {
        context.chain_id.require_testnet_v3()?;
        context.network_id.require_testnet_v3()?;
        if context.active_validator_set_hash != self.validator_set.hash()? {
            return Err("local active validator set hash mismatch".to_string());
        }
        if context.cluster_map_hash != self.cluster_map.hash()? {
            return Err("local cluster map hash mismatch".to_string());
        }
        if context.protocol_config_hash != self.protocol_config.hash()? {
            return Err("local protocol config hash mismatch".to_string());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::aegis_pqvm::AegisPqvmSigner;
    use crate::synergy_types::{AegisPqKeyId, ClusterAssignment, TxId, UmaId, ValidatorId};

    fn setup_validators() -> (AegisPqvmSigner, ValidatorSet, ClusterMap, ProtocolConfig) {
        let mut signer = AegisPqvmSigner::initialize_required().expect("aegis");
        let mut validators = Vec::new();
        for index in 0..5 {
            let uma = format!("uma-{index}");
            let key_id = signer
                .generate_and_register_key(
                    &uma,
                    vec![
                        AegisPqKeyRole::ConsensusVote,
                        AegisPqKeyRole::ConsensusProposer,
                    ],
                    Epoch(0),
                )
                .expect("key");
            let public = signer.public_key_record(&key_id).unwrap();
            validators.push(ValidatorRecord {
                validator_id: ValidatorId(format!("validator-{index}")),
                validator_uma_id: UmaId(uma),
                consensus_public_key: public.clone(),
                peer_public_key: public.clone(),
                operator_public_key: public,
                voting_weight: 1,
                status: ValidatorStatus::Active,
                cluster_id: ClusterId(0),
                activation_epoch: Epoch(0),
            });
        }
        let set = ValidatorSet {
            epoch: Epoch(0),
            validators,
        };
        let cluster = ClusterMap {
            epoch: Epoch(0),
            assignments: set
                .validators
                .iter()
                .map(|record| ClusterAssignment {
                    cluster_id: ClusterId(0),
                    validator_id: record.validator_id.clone(),
                })
                .collect(),
        };
        (signer, set, cluster, ProtocolConfig::testnet_v3())
    }

    fn context(
        set: &ValidatorSet,
        cluster: &ClusterMap,
        protocol: &ProtocolConfig,
    ) -> LocalConsensusContext {
        LocalConsensusContext {
            chain_id: ChainId::synergy_testnet_v3(),
            network_id: NetworkId::synergy_testnet_v3(),
            latest_finalized_height: Height(0),
            latest_finalized_block_hash: Hash::zero(),
            latest_finalized_state_root: Hash::zero(),
            last_finalized_qc_hash: Hash::zero(),
            epoch: Epoch(0),
            round: Round(0),
            cluster_id: ClusterId(0),
            active_validator_set_hash: set.hash().unwrap(),
            eligible_validator_set_hash: set.hash().unwrap(),
            cluster_map_hash: cluster.hash().unwrap(),
            proposer_schedule_hash: Hash::zero(),
            protocol_config_hash: protocol.hash().unwrap(),
            evidence_root: Hash::zero(),
            app_version: 1,
            execution_version: 1,
            dag_version: 1,
            aegis_pqvm_version: "aegis-pqvm".to_string(),
        }
    }

    fn empty_state() -> ExecutionState {
        ExecutionState::new()
    }

    #[test]
    fn validators_require_dynamic_pqc_quorum_to_commit() {
        let (mut signer, set, cluster, protocol) = setup_validators();
        let verifier = signer.verifier();
        let mut consensus =
            ProofOfSynergyBft::new(&verifier, set.clone(), cluster.clone(), protocol.clone());
        let ctx = context(&set, &cluster, &protocol);
        let proposer = consensus
            .proposer_for(Height(1), Round(0), ClusterId(0))
            .unwrap();
        let block = consensus
            .propose_block(
                &mut signer,
                &proposer,
                Vec::new(),
                &ctx,
                &empty_state(),
                Hash::zero(),
            )
            .unwrap();
        let required_votes = set.threshold_weight() as usize;
        let votes = set
            .validators
            .iter()
            .take(required_votes)
            .map(|validator| consensus.vote(&mut signer, validator, &block).unwrap())
            .collect::<Vec<_>>();
        let qc = consensus.form_qc(&votes).unwrap();
        assert!(consensus.commit_block(&block, &qc).is_ok());

        let few_votes = set.validators[0..3]
            .iter()
            .map(|validator| consensus.vote(&mut signer, validator, &block).unwrap())
            .collect::<Vec<_>>();
        assert!(consensus.form_qc(&few_votes).is_err());
    }

    #[test]
    fn wrong_chain_network_proposer_and_roots_are_rejected() {
        let (mut signer, set, cluster, protocol) = setup_validators();
        let verifier = signer.verifier();
        let mut consensus =
            ProofOfSynergyBft::new(&verifier, set.clone(), cluster.clone(), protocol.clone());
        let ctx = context(&set, &cluster, &protocol);
        let wrong_proposer = set.validators[0].clone();
        assert!(consensus
            .propose_block(
                &mut signer,
                &wrong_proposer,
                Vec::new(),
                &ctx,
                &empty_state(),
                Hash::zero()
            )
            .is_err());

        let proposer = consensus
            .proposer_for(Height(1), Round(0), ClusterId(0))
            .unwrap();
        let mut block = consensus
            .propose_block(
                &mut signer,
                &proposer,
                Vec::new(),
                &ctx,
                &empty_state(),
                Hash::zero(),
            )
            .unwrap();
        block.header.tx_order_root = Hash::from_domain_bytes("bad", b"root");
        let dag = DagMempool::new(&verifier, Epoch(0), Height(0));
        assert!(consensus
            .validate_proposal(&block, &ctx, &empty_state(), &dag)
            .is_err());

        let mut bad_ctx = ctx.clone();
        bad_ctx.chain_id = ChainId(999);
        assert!(consensus
            .propose_block(
                &mut signer,
                &proposer,
                Vec::new(),
                &bad_ctx,
                &empty_state(),
                Hash::zero()
            )
            .is_err());
    }

    #[test]
    fn shadow_validator_signature_cannot_form_qc() {
        let (mut signer, mut set, cluster, protocol) = setup_validators();
        set.validators[0].status = ValidatorStatus::Shadow;
        let verifier = signer.verifier();
        let mut consensus =
            ProofOfSynergyBft::new(&verifier, set.clone(), cluster.clone(), protocol);
        let block = Block {
            header: BlockHeader {
                version: 1,
                chain_id: ChainId::synergy_testnet_v3(),
                network_id: NetworkId::synergy_testnet_v3(),
                height: Height(1),
                round: Round(0),
                epoch: Epoch(0),
                cluster_id: ClusterId(0),
                parent_block_hash: Hash::zero(),
                parent_state_root: Hash::zero(),
                last_finalized_qc_hash: Hash::zero(),
                proposer_validator_id: ValidatorId("validator-1".to_string()),
                proposer_uma_id: UmaId("uma-1".to_string()),
                proposer_key_id: AegisPqKeyId("key".to_string()),
                active_validator_set_hash: set.hash().unwrap(),
                eligible_validator_set_hash: set.hash().unwrap(),
                cluster_map_hash: cluster.hash().unwrap(),
                proposer_schedule_hash: Hash::zero(),
                protocol_config_hash: ProtocolConfig::testnet_v3().hash().unwrap(),
                dag_frontier_root: Hash::zero(),
                tx_order_root: compute_tx_order_root(&Vec::<TxId>::new()).unwrap(),
                tx_count: 0,
                evidence_root: Hash::zero(),
                state_root_before: Hash::zero(),
                state_root_after: compute_tx_order_root(&Vec::<TxId>::new()).unwrap(),
                receipt_root: Hash::zero(),
                app_version: 1,
                execution_version: 1,
                dag_version: 1,
                aegis_pqvm_version: "aegis-pqvm".to_string(),
                timestamp_ms_consensus_bounded: 0,
            },
            transactions: Vec::new(),
            proposer_signature: AegisPqSignature {
                algorithm: "fndsa".to_string(),
                signature_bytes: vec![1],
            },
        };
        assert!(consensus
            .vote(&mut signer, &set.validators[0], &block)
            .is_err());
    }
}
