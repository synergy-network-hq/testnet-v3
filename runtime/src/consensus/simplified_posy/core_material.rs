//! Canonical core-side proposal material shared by protected execution.
//!
//! The adapter remains available for historical typed-PoSy fixtures. Fresh P3
//! startup is governed-ETDAG-only and never selects this adapter as a fallback.

use super::{
    compute_simplified_protected_execution_root, simplified_fee_market_header_fields,
    validate_simplified_fee_market_header_against_parent, CertifiedCandidateSubject,
    FinalizedBlockRecord, SimplifiedEpochContext, SimplifiedMaterialAdapter,
    SimplifiedParentFeeMarketState, SimplifiedProposal, SimplifiedProposalDirective,
    SimplifiedQuorumCertificate, VerifiedSimplifiedProposalMaterial,
    POSY_SIMPLIFIED_PROTOCOL_VERSION,
};
use crate::consensus_parameters::ConsensusParameterRoot;
use crate::dag_mempool::compute_tx_order_root;
use crate::execution::{compute_receipt_root, compute_state_root_after, ExecutionState};
use crate::synergy_types::{
    AegisPqSignature, Block, BlockHeader, CanonicalSerialize, ClusterId, ClusterMap, Hash,
    ValidatorRecord, ValidatorSet,
};

pub const POSY_SIMPLIFIED_CORE_CLUSTER_SCHEDULE_VERSION: &str =
    "posy-v3-single-consensus-cluster-v1";

/// Frozen consensus-side block-construction inputs for one epoch.
#[derive(Debug, Clone)]
pub struct SimplifiedCoreMaterialConfiguration {
    pub validator_set: ValidatorSet,
    pub cluster_map: ClusterMap,
    pub execution_state: ExecutionState,
    /// Explicit certified-parent fee authority for this historical adapter.
    /// Fresh block one uses `None`; every later height fails closed without
    /// the exact parent values. Production P3 uses the protected adapter,
    /// which derives this state from QC-keyed durable material.
    pub parent_fee_market: Option<SimplifiedParentFeeMarketState>,
    pub cryptographic_profile_root: Hash,
    pub epoch_start_timestamp_ms: u64,
    pub target_block_time_ms: u64,
    pub app_version: u32,
    pub execution_version: u32,
    pub dag_version: u32,
    pub aegis_pqvm_version: String,
}

impl SimplifiedCoreMaterialConfiguration {
    fn validate(&self, epoch_context: &SimplifiedEpochContext) -> Result<(), String> {
        epoch_context
            .validate_against(&self.validator_set.active_for_epoch(epoch_context.epoch))?;
        if self.cluster_map.epoch != epoch_context.epoch
            || self.cluster_map != self.cluster_map.canonicalized()
            || self.cryptographic_profile_root.is_zero()
            || self.epoch_start_timestamp_ms == 0
            || self.target_block_time_ms == 0
            || self.app_version == 0
            || self.execution_version == 0
            || self.dag_version == 0
            || self.aegis_pqvm_version.trim().is_empty()
        {
            return Err("invalid simplified core-material configuration".to_string());
        }
        simplified_fee_market_header_fields(
            epoch_context.epoch_start_height,
            self.parent_fee_market,
        )?;
        let active = self.validator_set.active_for_epoch(epoch_context.epoch);
        let expected_ids = active
            .validators
            .iter()
            .map(|validator| validator.validator_id.clone())
            .collect::<std::collections::BTreeSet<_>>();
        let assigned_ids = self
            .cluster_map
            .assignments
            .iter()
            .map(|assignment| assignment.validator_id.clone())
            .collect::<std::collections::BTreeSet<_>>();
        let cluster_ids = self
            .cluster_map
            .assignments
            .iter()
            .map(|assignment| assignment.cluster_id)
            .collect::<std::collections::BTreeSet<_>>();
        if assigned_ids != expected_ids
            || assigned_ids.len() != self.cluster_map.assignments.len()
            || cluster_ids.len() != 1
            || active.validators.iter().any(|validator| {
                !self
                    .cluster_map
                    .contains(validator.cluster_id, &validator.validator_id)
            })
        {
            return Err(
                "simplified core material requires one exhaustive frozen cluster map".to_string(),
            );
        }
        Ok(())
    }
}

/// Historical empty-block adapter retained for typed-PoSy compatibility tests.
/// Fresh P3 role-runtime startup fails before adapter selection if its governed
/// ETDAG permit is absent.
pub struct SimplifiedCoreMaterialAdapter {
    epoch_context: SimplifiedEpochContext,
    configuration: SimplifiedCoreMaterialConfiguration,
    certified_parent_fee_markets: std::collections::BTreeMap<Hash, SimplifiedParentFeeMarketState>,
}

impl SimplifiedCoreMaterialAdapter {
    pub fn new(
        epoch_context: SimplifiedEpochContext,
        configuration: SimplifiedCoreMaterialConfiguration,
    ) -> Result<Self, String> {
        configuration.validate(&epoch_context)?;
        Ok(Self {
            epoch_context,
            configuration,
            certified_parent_fee_markets: std::collections::BTreeMap::new(),
        })
    }

    /// Restores the fee authority for already verified, durable certified
    /// material after a process restart. The historical core adapter keeps
    /// this cache only to derive the next header; it must never treat an
    /// unbound file as authority.
    pub fn restore_certified_parent_fee_authority(
        &mut self,
        certificate: &SimplifiedQuorumCertificate,
        material: &VerifiedSimplifiedProposalMaterial,
    ) -> Result<(), String> {
        material.validate(self.epoch_context.root()?)?;
        let candidate = CertifiedCandidateSubject::new(
            certificate.context.clone(),
            certificate.block_id.clone(),
            certificate.parent_block_id.clone(),
            certificate.parent.clone(),
            certificate.protected_execution_root,
        )?;
        let candidate_id = candidate.id()?;
        if certificate.id()? != candidate_id
            || material.stable_candidate_id != candidate_id
            || material.candidate_subject != candidate
            || material.canonical_block.candidate_id()? != certificate.block_id
        {
            return Err(
                "durable core material does not bind its certified parent fee authority"
                    .to_string(),
            );
        }
        self.certified_parent_fee_markets.insert(
            candidate_id,
            SimplifiedParentFeeMarketState::from_verified_header(&material.canonical_block.header)?,
        );
        Ok(())
    }

    fn parent_fee_market(
        &self,
        parent: &super::SimplifiedFinalityParent,
        child_height: crate::synergy_types::Height,
    ) -> Result<Option<SimplifiedParentFeeMarketState>, String> {
        if parent.quorum_certificate_reference().is_none() {
            return Ok(None);
        }
        if child_height == self.epoch_context.epoch_start_height {
            return self
                .configuration
                .parent_fee_market
                .map(Some)
                .ok_or_else(|| {
                    "core adapter epoch boundary has no explicit certified parent fee authority"
                        .to_string()
                });
        }
        let reference = parent.quorum_certificate_reference().ok_or_else(|| {
            "core adapter child above block one has no quorum-certified parent".to_string()
        })?;
        self.certified_parent_fee_markets
            .get(&reference.qc_id)
            .copied()
            .map(Some)
            .ok_or_else(|| {
                "core adapter has no verified material for the certified parent fee authority"
                    .to_string()
            })
    }

    fn cluster_members(&self) -> Result<(ClusterId, Vec<ValidatorRecord>, u64, Hash), String> {
        let active = self
            .configuration
            .validator_set
            .active_for_epoch(self.epoch_context.epoch);
        let cluster_id = active
            .validators
            .first()
            .map(|validator| validator.cluster_id)
            .ok_or_else(|| "simplified core cluster is empty".to_string())?;
        let mut members = active.active_for_cluster(cluster_id);
        members.sort_by(|left, right| left.validator_id.cmp(&right.validator_id));
        let total_weight = members.iter().try_fold(0u64, |total, validator| {
            total
                .checked_add(validator.voting_weight)
                .ok_or_else(|| "simplified cluster weight overflowed".to_string())
        })?;
        let member_ids = members
            .iter()
            .map(|validator| validator.validator_id.clone())
            .collect::<Vec<_>>();
        let membership_root = Hash::from_domain_bytes(
            "SYNERGY_ASSIGNED_CLUSTER_MEMBERSHIP_V1",
            &(self.epoch_context.epoch, cluster_id, member_ids).canonical_bytes()?,
        );
        Ok((cluster_id, members, total_weight, membership_root))
    }

    fn timestamp_for_height(&self, height: crate::synergy_types::Height) -> Result<u64, String> {
        let offset = height
            .0
            .checked_sub(self.epoch_context.epoch_start_height.0)
            .ok_or_else(|| "simplified core height precedes the epoch".to_string())?;
        self.configuration
            .target_block_time_ms
            .checked_mul(offset)
            .and_then(|delta| {
                self.configuration
                    .epoch_start_timestamp_ms
                    .checked_add(delta)
            })
            .ok_or_else(|| "simplified core timestamp overflowed".to_string())
    }

    fn expected_dag_frontier(
        &self,
        directive: &SimplifiedProposalDirective,
    ) -> Result<Hash, String> {
        Ok(Hash::from_domain_bytes(
            "SYNERGY_POSY_SIMPLIFIED_CORE_DAG_FRONTIER_V1",
            &serde_json::to_vec(&(
                directive.context.epoch_context_root,
                directive.context.height,
                &directive.parent,
            ))
            .map_err(|error| format!("serialize simplified core DAG frontier: {error}"))?,
        ))
    }

    fn expected_evidence_root(
        &self,
        directive: &SimplifiedProposalDirective,
    ) -> Result<Hash, String> {
        Ok(Hash::from_domain_bytes(
            "SYNERGY_POSY_SIMPLIFIED_CORE_EVIDENCE_V1",
            &serde_json::to_vec(&(&directive.parent, &directive.finalized))
                .map_err(|error| format!("serialize simplified core evidence: {error}"))?,
        ))
    }

    fn verify_static_header(
        &self,
        proposal: &SimplifiedProposal,
        expected_finalized: &FinalizedBlockRecord,
        material: &VerifiedSimplifiedProposalMaterial,
    ) -> Result<(), String> {
        let (cluster_id, members, total_weight, membership_root) = self.cluster_members()?;
        let header = &material.canonical_block.header;
        let directive = SimplifiedProposalDirective {
            context: proposal.context.clone(),
            parent: proposal.parent.clone(),
            finalized: expected_finalized.clone(),
            proposer_id: proposal.proposer_id.clone(),
            proposer_key_id: proposal.proposer_key_id.clone(),
            takeover_tc_id: proposal.takeover_tc_id,
            mandatory_carry_candidate: None,
        };
        if header.cluster_id != cluster_id
            || header.cluster_schedule_version != POSY_SIMPLIFIED_CORE_CLUSTER_SCHEDULE_VERSION
            || header.cluster_map_hash != self.configuration.cluster_map.hash()?
            || header.assigned_cluster_membership_root != membership_root
            || header.assigned_cluster_validator_count
                != u64::try_from(members.len())
                    .map_err(|_| "simplified cluster count exceeds u64".to_string())?
            || header.assigned_cluster_total_voting_weight != total_weight
            || header.proposer_schedule_hash != self.epoch_context.leader_ring_root
            || header.cryptographic_profile_root != self.configuration.cryptographic_profile_root
            || header.dag_frontier_root != self.expected_dag_frontier(&directive)?
            || header.tx_order_root != compute_tx_order_root(&[])?
            || header.evidence_root != self.expected_evidence_root(&directive)?
            || header.last_finalized_qc_hash != expected_finalized.finality_reference_id()
            || header.timestamp_ms_consensus_bounded
                != self.timestamp_for_height(proposal.context.height)?
            || header.app_version != self.configuration.app_version
            || header.execution_version != self.configuration.execution_version
            || header.dag_version != self.configuration.dag_version
            || header.aegis_pqvm_version != self.configuration.aegis_pqvm_version
        {
            return Err("simplified core block has noncanonical static commitments".to_string());
        }
        Ok(())
    }
}

impl SimplifiedMaterialAdapter for SimplifiedCoreMaterialAdapter {
    fn build_local(
        &mut self,
        epoch_context: &SimplifiedEpochContext,
        directive: &SimplifiedProposalDirective,
    ) -> Result<Option<(SimplifiedProposal, VerifiedSimplifiedProposalMaterial)>, String> {
        if epoch_context.root()? != self.epoch_context.root()?
            || directive.context.epoch_context_root != self.epoch_context.root()?
        {
            return Err("simplified core proposal request names another epoch".to_string());
        }
        let proposer = self
            .configuration
            .validator_set
            .active_for_epoch(self.epoch_context.epoch)
            .validators
            .into_iter()
            .find(|validator| validator.validator_id == directive.proposer_id)
            .ok_or_else(|| "simplified core proposer is absent from the frozen set".to_string())?;
        if proposer.consensus_public_key.key_id != directive.proposer_key_id {
            return Err("simplified core proposer key differs from the frozen key".to_string());
        }
        let (cluster_id, members, total_weight, membership_root) = self.cluster_members()?;
        let state_root = compute_state_root_after(&self.configuration.execution_state)?;
        let parent_fee_market =
            self.parent_fee_market(&directive.parent, directive.context.height)?;
        let fee_market =
            simplified_fee_market_header_fields(directive.context.height, parent_fee_market)?;
        let block = Block {
            header: BlockHeader {
                version: 3,
                chain_id: directive.context.chain_id,
                network_id: directive.context.network_id.clone(),
                protocol_version: POSY_SIMPLIFIED_PROTOCOL_VERSION.to_string(),
                height: directive.context.height,
                round: directive.context.round,
                epoch: directive.context.epoch,
                cluster_id,
                height_context_root: directive.context.epoch_context_root,
                parent_block_hash: Hash::from_hex(&directive.parent.block_id().0)?,
                parent_state_root: state_root,
                last_finalized_qc_hash: directive.finalized.finality_reference_id(),
                proposer_validator_id: proposer.validator_id.clone(),
                proposer_uma_id: proposer.validator_uma_id.clone(),
                proposer_key_id: proposer.consensus_public_key.key_id.clone(),
                active_validator_set_hash: directive.context.active_validator_set_root,
                eligible_validator_set_hash: directive.context.active_validator_set_root,
                validator_consensus_key_root: directive.context.validator_consensus_key_root,
                frozen_bonded_weight_root: directive.context.frozen_voting_weight_root,
                cluster_schedule_version: POSY_SIMPLIFIED_CORE_CLUSTER_SCHEDULE_VERSION.to_string(),
                cluster_map_hash: self.configuration.cluster_map.hash()?,
                assigned_cluster_membership_root: membership_root,
                assigned_cluster_validator_count: u64::try_from(members.len())
                    .map_err(|_| "simplified cluster count exceeds u64".to_string())?,
                assigned_cluster_total_voting_weight: total_weight,
                proposer_schedule_hash: self.epoch_context.leader_ring_root,
                protocol_config_hash: ConsensusParameterRoot::from_hex(
                    &self.epoch_context.consensus_parameter_root,
                )?,
                cryptographic_profile_root: self.configuration.cryptographic_profile_root,
                dag_frontier_root: self.expected_dag_frontier(directive)?,
                tx_order_root: compute_tx_order_root(&[])?,
                tx_count: 0,
                protected_batch: None,
                evidence_root: self.expected_evidence_root(directive)?,
                state_root_before: state_root,
                state_root_after: state_root,
                receipt_root: compute_receipt_root(&[])?,
                app_version: self.configuration.app_version,
                execution_version: self.configuration.execution_version,
                dag_version: self.configuration.dag_version,
                aegis_pqvm_version: self.configuration.aegis_pqvm_version.clone(),
                timestamp_ms_consensus_bounded: self
                    .timestamp_for_height(directive.context.height)?,
                base_fee_per_gas_nwei: fee_market.base_fee_per_gas_nwei,
                gas_used: 0,
                gas_limit: fee_market.gas_limit,
                pq_gas_used: 0,
                pq_gas_limit: fee_market.pq_gas_limit,
                pq_gas_multiplier: fee_market.pq_gas_multiplier,
                fee_market_version: fee_market.fee_market_version,
            },
            transactions: Vec::new(),
            proposer_signature: AegisPqSignature {
                algorithm: String::new(),
                signature_bytes: Vec::new(),
            },
        };
        let block_id = block.candidate_id()?;
        let protected_execution_root = compute_simplified_protected_execution_root(
            &directive.context,
            &block,
            directive.parent.block_id(),
            &directive.parent,
            None,
            None,
        )?;
        let proposal = SimplifiedProposal {
            context: directive.context.clone(),
            block_id,
            parent_block_id: directive.parent.block_id().clone(),
            parent: directive.parent.clone(),
            takeover_tc_id: directive.takeover_tc_id,
            protected_execution_root,
            proposer_id: proposer.validator_id,
            proposer_key_id: proposer.consensus_public_key.key_id,
            proposer_signature: AegisPqSignature {
                algorithm: String::new(),
                signature_bytes: Vec::new(),
            },
        };
        let (material, next_state) = VerifiedSimplifiedProposalMaterial::verify_core(
            epoch_context,
            &proposal,
            block,
            &self.configuration.execution_state,
            parent_fee_market,
        )?;
        if next_state != self.configuration.execution_state {
            return Err("core-only simplified block changed execution state".to_string());
        }
        self.verify_static_header(&proposal, &directive.finalized, &material)?;
        self.certified_parent_fee_markets.insert(
            material.stable_candidate_id,
            SimplifiedParentFeeMarketState::from_verified_header(&material.canonical_block.header)?,
        );
        Ok(Some((proposal, material)))
    }

    fn verify_received(
        &mut self,
        epoch_context: &SimplifiedEpochContext,
        proposal: &SimplifiedProposal,
        expected_finalized: &FinalizedBlockRecord,
        material: &VerifiedSimplifiedProposalMaterial,
    ) -> Result<Hash, String> {
        if epoch_context.root()? != self.epoch_context.root()? {
            return Err("received core material names another epoch".to_string());
        }
        let parent_fee_market =
            self.parent_fee_market(&proposal.parent, proposal.context.height)?;
        self.verify_static_header(proposal, expected_finalized, material)?;
        let next_state = material.replay_core(
            epoch_context,
            &self.configuration.execution_state,
            parent_fee_market,
        )?;
        validate_simplified_fee_market_header_against_parent(
            &material.canonical_block.header,
            parent_fee_market,
        )?;
        if next_state != self.configuration.execution_state {
            return Err("received core-only block changed execution state".to_string());
        }
        self.certified_parent_fee_markets.insert(
            material.stable_candidate_id,
            SimplifiedParentFeeMarketState::from_verified_header(&material.canonical_block.header)?,
        );
        Ok(material.candidate_subject.protected_execution_root)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::simplified_posy::QuorumCertificateReference;
    use crate::synergy_types::{
        AegisPqKeyId, AegisPqPublicKey, BlockId, ClusterAssignment, Epoch, Height, Round, UmaId,
        ValidatorId, ValidatorStatus, TESTNET_V3_CONSENSUS_SIGNATURE_ALGORITHM,
        TESTNET_V3_MLDSA65_PUBLIC_KEY_BYTES,
    };

    fn validators() -> ValidatorSet {
        ValidatorSet {
            epoch: Epoch(7),
            validators: (0..7)
                .map(|index| {
                    let key = AegisPqPublicKey {
                        key_id: AegisPqKeyId(format!("core-material-key-{index}")),
                        algorithm: TESTNET_V3_CONSENSUS_SIGNATURE_ALGORITHM.to_string(),
                        key_bytes: vec![index as u8 + 1; TESTNET_V3_MLDSA65_PUBLIC_KEY_BYTES],
                    };
                    ValidatorRecord {
                        validator_id: ValidatorId(format!("core-material-validator-{index}")),
                        validator_uma_id: UmaId(format!("uma:core-material-validator-{index}")),
                        consensus_public_key: key.clone(),
                        peer_public_key: key.clone(),
                        operator_public_key: key,
                        voting_weight: 1,
                        status: ValidatorStatus::Active,
                        cluster_id: ClusterId(0),
                        activation_epoch: Epoch(7),
                    }
                })
                .collect(),
        }
    }

    fn parent_fee_market() -> SimplifiedParentFeeMarketState {
        let parameters = crate::gas::fee_market_params_for_runtime().unwrap();
        SimplifiedParentFeeMarketState {
            base_fee_per_gas_nwei: parameters.initial_base_fee_nwei,
            gas_used: 0,
            fee_market_version: parameters.fee_market_version,
        }
    }

    #[test]
    fn core_adapter_builds_and_replays_a_dynamic_epoch_empty_block() {
        let validators = validators();
        let seed = Hash::from_domain_bytes("core-material-test", b"seed");
        let epoch_context = SimplifiedEpochContext::derive(
            Epoch(7),
            Height(1_000),
            Height(1_999),
            seed,
            ConsensusParameterRoot::from_canonical_manifest_bytes(b"core-material-parameters"),
            &validators,
        )
        .unwrap();
        let cluster_map = ClusterMap {
            epoch: Epoch(7),
            assignments: validators
                .validators
                .iter()
                .map(|validator| ClusterAssignment {
                    cluster_id: ClusterId(0),
                    validator_id: validator.validator_id.clone(),
                })
                .collect(),
        }
        .canonicalized();
        let parent_qc = QuorumCertificateReference {
            height: Height(999),
            block_id: BlockId::from_hash(Hash::from_domain_bytes(
                "core-material-test",
                b"anchor-block",
            )),
            qc_id: Hash::from_domain_bytes("core-material-test", b"anchor-qc"),
        };
        let anchor = FinalizedBlockRecord::from_quorum_certificate(parent_qc.clone()).unwrap();
        let proposer_id = epoch_context
            .authorized_proposer(Height(1_000), 0)
            .unwrap()
            .clone();
        let proposer_key_id = validators
            .validators
            .iter()
            .find(|validator| validator.validator_id == proposer_id)
            .unwrap()
            .consensus_public_key
            .key_id
            .clone();
        let directive = SimplifiedProposalDirective {
            context: super::super::ConsensusObjectContext::for_height(
                &epoch_context,
                Height(1_000),
                Round(0),
            )
            .unwrap(),
            parent: anchor.finality_parent.clone(),
            finalized: anchor.clone(),
            proposer_id,
            proposer_key_id,
            takeover_tc_id: None,
            mandatory_carry_candidate: None,
        };
        let configuration = SimplifiedCoreMaterialConfiguration {
            validator_set: validators,
            cluster_map,
            execution_state: ExecutionState::new(),
            parent_fee_market: Some(parent_fee_market()),
            cryptographic_profile_root: Hash::from_domain_bytes(
                "core-material-test",
                b"crypto-profile",
            ),
            epoch_start_timestamp_ms: 1_000_000,
            target_block_time_ms: 1_000,
            app_version: 1,
            execution_version: 1,
            dag_version: 2,
            aegis_pqvm_version: "aegis-pqvm-core-v1".to_string(),
        };
        let mut adapter =
            SimplifiedCoreMaterialAdapter::new(epoch_context.clone(), configuration).unwrap();
        let (proposal, material) = adapter
            .build_local(&epoch_context, &directive)
            .unwrap()
            .unwrap();
        assert!(material.canonical_block.transactions.is_empty());
        assert_eq!(
            adapter
                .verify_received(&epoch_context, &proposal, &anchor, &material)
                .unwrap(),
            proposal.protected_execution_root
        );

        // A timeout changes only the proposal envelope. The carried block,
        // execution root, and stable certified-candidate identity must remain
        // byte-for-byte reusable under the replacement proposer/round.
        let carry_context = super::super::ConsensusObjectContext::for_height(
            &epoch_context,
            Height(1_000),
            Round(1),
        )
        .unwrap();
        let carry_proposer_id = epoch_context
            .authorized_proposer(Height(1_000), 1)
            .unwrap()
            .clone();
        let carry_proposer_key_id = adapter
            .configuration
            .validator_set
            .validators
            .iter()
            .find(|validator| validator.validator_id == carry_proposer_id)
            .unwrap()
            .consensus_public_key
            .key_id
            .clone();
        let carry_proposal = SimplifiedProposal {
            context: carry_context,
            block_id: proposal.block_id.clone(),
            parent_block_id: proposal.parent_block_id.clone(),
            parent: proposal.parent.clone(),
            takeover_tc_id: Some(Hash::from_domain_bytes(
                "core-material-test",
                b"takeover-tc",
            )),
            protected_execution_root: proposal.protected_execution_root,
            proposer_id: carry_proposer_id,
            proposer_key_id: carry_proposer_key_id,
            proposer_signature: AegisPqSignature {
                algorithm: String::new(),
                signature_bytes: Vec::new(),
            },
        };
        assert_eq!(
            super::super::CertifiedCandidateSubject::new(
                carry_proposal.context.clone(),
                carry_proposal.block_id.clone(),
                carry_proposal.parent_block_id.clone(),
                carry_proposal.parent.clone(),
                carry_proposal.protected_execution_root,
            )
            .unwrap(),
            material.candidate_subject
        );
        assert_eq!(
            adapter
                .verify_received(&epoch_context, &carry_proposal, &anchor, &material)
                .unwrap(),
            proposal.protected_execution_root
        );

        let substituted_finality =
            FinalizedBlockRecord::from_quorum_certificate(QuorumCertificateReference {
                height: anchor.height,
                block_id: anchor.block_id.clone(),
                qc_id: Hash::from_domain_bytes("core-material-test", b"wrong-finality"),
            })
            .unwrap();
        assert!(adapter
            .verify_received(&epoch_context, &proposal, &substituted_finality, &material,)
            .is_err());
    }
}
