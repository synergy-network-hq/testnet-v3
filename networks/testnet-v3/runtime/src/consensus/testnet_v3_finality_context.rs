//! Canonical finalized-chain sources for the typed Testnet-v3 PoSy driver.
//!
//! No peer message, timer, mempool state, or legacy chain record can enter
//! this derivation.  Genesis and the durable typed-QC store are the only
//! sources of authority.

use crate::consensus::posy::LocalConsensusContext;
use crate::consensus::testnet_v3_bootstrap::TestnetV3GenesisBootstrap;
use crate::consensus::typed_coordinator::{
    TypedFinalityContextDigestSource, TypedNextHeightAuthority, TypedNextHeightContextSource,
};
use crate::consensus::typed_finality_store::{TypedFinalityRecord, TypedFinalityStore};
use crate::etdag::{canonical_finality_context_digest, EtdagDigest};
use crate::synergy_types::{
    BlockId, Epoch, Hash, Height, HeightConsensusContext, HeightConsensusContextSpec,
    ProtocolConfig, Round,
};
use serde::{Deserialize, Serialize};

const FINALITY_CONTEXT_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum FinalityContextSource {
    Genesis,
    TypedFinalityQc,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct CanonicalTypedFinalityContext {
    context_version: u32,
    source: FinalityContextSource,
    genesis_anchor: Hash,
    genesis_deployed_state_root: Hash,
    genesis_transition_root: Hash,
    genesis_epoch_seed_root: Hash,
    genesis_cryptographic_profile_root: Hash,
    source_finalized_height: Height,
    source_finalized_block_id: BlockId,
    source_finalized_block_hash: Hash,
    source_finalized_state_root: Hash,
    source_finality_qc_root: Hash,
    source_height_context_root: Hash,
    source_epoch: Epoch,
    source_active_validator_set_root: Hash,
    source_cluster_map_root: Hash,
    consumer_height: Height,
    consumer_epoch: Epoch,
    consumer_height_context_root: Hash,
}

/// Production implementation of the typed driver's finalized-context traits.
///
/// It supports the finalized Genesis topology and same-topology typed-QC
/// advancement.  A persisted epoch transition is fail-closed until the
/// coordinator receives the exact verified topology-installation payload.
#[derive(Debug, Clone)]
pub struct FinalizedTypedContextProvider {
    bootstrap: TestnetV3GenesisBootstrap,
    protocol_config: ProtocolConfig,
    finality_store: TypedFinalityStore,
    deployed_genesis_state_root: Hash,
}

impl FinalizedTypedContextProvider {
    pub fn new(
        bootstrap: TestnetV3GenesisBootstrap,
        protocol_config: ProtocolConfig,
        finality_store: TypedFinalityStore,
        deployed_genesis_state_root: Hash,
    ) -> Result<Self, String> {
        if deployed_genesis_state_root.is_zero() {
            return Err(
                "finalized context requires the committed Genesis execution root".to_string(),
            );
        }
        bootstrap
            .validator_set
            .validate_unique_validator_and_key_ids()?;
        bootstrap
            .cluster_map
            .validate_complete_balanced_assignment(
                &bootstrap.validator_set.active_for_epoch(Epoch(0)),
            )?;
        protocol_config.hash()?;
        bootstrap.initial_local_consensus_context(
            &protocol_config,
            finality_store.genesis_anchor(),
            deployed_genesis_state_root,
        )?;
        Ok(Self {
            bootstrap,
            protocol_config,
            finality_store,
            deployed_genesis_state_root,
        })
    }

    pub fn finality_store(&self) -> &TypedFinalityStore {
        &self.finality_store
    }

    /// Rebuilds the sole allowable local authority for the height after the
    /// durable typed finality tip.  This is also the restart/recovery API.
    pub fn recover_next_context(&self) -> Result<LocalConsensusContext, String> {
        let latest = self.finality_store.latest()?;
        self.context_after_latest(latest.as_ref())
    }

    pub fn canonical_finality_context_digest(
        &self,
        local: &LocalConsensusContext,
    ) -> Result<EtdagDigest, String> {
        self.require_expected_context(local)?;
        let material = match self.finality_store.latest()? {
            None => CanonicalTypedFinalityContext {
                context_version: FINALITY_CONTEXT_VERSION,
                source: FinalityContextSource::Genesis,
                genesis_anchor: self.finality_store.genesis_anchor(),
                genesis_deployed_state_root: self.deployed_genesis_state_root,
                genesis_transition_root: self.bootstrap.genesis_transition_root,
                genesis_epoch_seed_root: self.bootstrap.finalized_epoch_seed_root,
                genesis_cryptographic_profile_root: self.bootstrap.cryptographic_profile_root,
                source_finalized_height: Height(0),
                source_finalized_block_id: BlockId::from_hash(self.finality_store.genesis_anchor()),
                source_finalized_block_hash: self.finality_store.genesis_anchor(),
                source_finalized_state_root: self.deployed_genesis_state_root,
                source_finality_qc_root: self.bootstrap.genesis_transition_root,
                source_height_context_root: self.bootstrap.genesis_transition_root,
                source_epoch: Epoch(0),
                source_active_validator_set_root: local.height_context.active_validator_set_root,
                source_cluster_map_root: local.height_context.cluster_map_root,
                consumer_height: local.height_context.height,
                consumer_epoch: local.height_context.epoch,
                consumer_height_context_root: local.height_context.root()?,
            },
            Some(record) => CanonicalTypedFinalityContext {
                context_version: FINALITY_CONTEXT_VERSION,
                source: FinalityContextSource::TypedFinalityQc,
                genesis_anchor: self.finality_store.genesis_anchor(),
                genesis_deployed_state_root: self.deployed_genesis_state_root,
                genesis_transition_root: self.bootstrap.genesis_transition_root,
                genesis_epoch_seed_root: self.bootstrap.finalized_epoch_seed_root,
                genesis_cryptographic_profile_root: self.bootstrap.cryptographic_profile_root,
                source_finalized_height: record.height,
                source_finalized_block_id: record.block_id.clone(),
                source_finalized_block_hash: Hash::from_hex(&record.block_id.0).map_err(
                    |error| format!("persisted typed finality block ID is not a hash: {error}"),
                )?,
                source_finalized_state_root: record.block.header.state_root_after,
                source_finality_qc_root: record.quorum_certificate.finality_context_root()?,
                source_height_context_root: record.block.header.height_context_root,
                source_epoch: record.block.header.epoch,
                source_active_validator_set_root: record.block.header.active_validator_set_hash,
                source_cluster_map_root: record.block.header.cluster_map_hash,
                consumer_height: local.height_context.height,
                consumer_epoch: local.height_context.epoch,
                consumer_height_context_root: local.height_context.root()?,
            },
        };
        canonical_finality_context_digest(&material)
    }

    fn require_expected_context(&self, local: &LocalConsensusContext) -> Result<(), String> {
        let expected = self.recover_next_context()?;
        if !same_local_context(local, &expected) {
            return Err(
                "typed local context does not match finalized Genesis/QC authority".to_string(),
            );
        }
        Ok(())
    }

    fn context_before_finality(
        &self,
        finalized: &TypedFinalityRecord,
    ) -> Result<LocalConsensusContext, String> {
        if finalized.height.0 == 1 {
            return self.bootstrap.initial_local_consensus_context(
                &self.protocol_config,
                self.finality_store.genesis_anchor(),
                self.deployed_genesis_state_root,
            );
        }
        let predecessor_height = finalized
            .height
            .0
            .checked_sub(1)
            .ok_or_else(|| "typed finalized height underflows".to_string())?;
        let predecessor = self
            .finality_store
            .recover()?
            .into_iter()
            .find(|record| record.height.0 == predecessor_height)
            .ok_or_else(|| {
                "typed finality store lacks the direct predecessor record".to_string()
            })?;
        self.context_after_latest(Some(&predecessor))
    }

    fn context_after_latest(
        &self,
        latest: Option<&TypedFinalityRecord>,
    ) -> Result<LocalConsensusContext, String> {
        let Some(record) = latest else {
            return self.bootstrap.initial_local_consensus_context(
                &self.protocol_config,
                self.finality_store.genesis_anchor(),
                self.deployed_genesis_state_root,
            );
        };
        if let Some(transition) = self.finality_store.epoch_transition_for_finality(record)? {
            return Err(format!(
                "FINALIZED_TYPED_CONTEXT_PROVIDER_NOT_READY: persisted verified epoch transition {} at height {} requires an exact topology installation payload",
                transition.transition_root.to_hex(),
                record.height.0
            ));
        }
        if record.block.header.epoch != Epoch(0)
            || record.block.header.cluster_id.0 != 0
            || record.block.header.active_validator_set_hash
                != self
                    .bootstrap
                    .validator_set
                    .active_for_epoch(Epoch(0))
                    .hash()?
            || record.block.header.cluster_map_hash != self.bootstrap.cluster_map.hash()?
        {
            return Err(
                "FINALIZED_TYPED_CONTEXT_PROVIDER_NOT_READY: non-Genesis topology requires a verified epoch-transition authority"
                    .to_string(),
            );
        }
        let next_height = Height(
            record
                .height
                .0
                .checked_add(1)
                .ok_or_else(|| "typed next height overflows".to_string())?,
        );
        let height_context = HeightConsensusContext::derive(
            HeightConsensusContextSpec {
                protocol_version: record.block.header.protocol_version.clone(),
                height: next_height,
                epoch: Epoch(0),
                assigned_cluster_id: record.block.header.cluster_id,
                cluster_schedule_version: record.block.header.cluster_schedule_version.clone(),
                finalized_epoch_seed_root: self.bootstrap.finalized_epoch_seed_root,
                assigned_height_schedule_root: self
                    .bootstrap
                    .assigned_height_schedule_root(next_height.0),
                cryptographic_profile_root: self.bootstrap.cryptographic_profile_root,
                prior_finalized_qc_or_transition_root: record
                    .quorum_certificate
                    .finality_context_root()?,
            },
            &self.bootstrap.validator_set,
            &self.bootstrap.cluster_map,
            &self.protocol_config,
        )?;
        let block_hash = Hash::from_hex(&record.block_id.0)
            .map_err(|error| format!("persisted typed finality block ID is not a hash: {error}"))?;
        Ok(LocalConsensusContext {
            height_context,
            latest_finalized_height: record.height,
            latest_finalized_block_hash: block_hash,
            latest_finalized_state_root: record.block.header.state_root_after,
            latest_finalized_timestamp_ms: record.block.header.timestamp_ms_consensus_bounded,
            round: Round(0),
            evidence_root: record.quorum_certificate.finality_context_root()?,
            app_version: 1,
            execution_version: 1,
            dag_version: 1,
            aegis_pqvm_version: "aegis-pqvm".to_string(),
        })
    }
}

impl TypedFinalityContextDigestSource for FinalizedTypedContextProvider {
    fn expected_digest(&self, local: &LocalConsensusContext) -> Result<EtdagDigest, String> {
        self.canonical_finality_context_digest(local)
    }
}

impl TypedNextHeightContextSource for FinalizedTypedContextProvider {
    fn next_authority(
        &mut self,
        finalized: &TypedFinalityRecord,
        current: &LocalConsensusContext,
    ) -> Result<TypedNextHeightAuthority, String> {
        let latest = self.finality_store.latest()?.ok_or_else(|| {
            "typed next-height authority requires persisted typed finality".to_string()
        })?;
        if latest != *finalized {
            return Err(
                "typed next-height authority is not the durable typed finality tip".to_string(),
            );
        }
        let expected_current = self.context_before_finality(&latest)?;
        if !same_post_finality_context(current, &expected_current, &latest)? {
            return Err(
                "typed next-height authority current context does not match the durable finalized tip"
                    .to_string(),
            );
        }
        let context = self.context_after_latest(Some(&latest))?;
        Ok(TypedNextHeightAuthority::UnchangedTopology { context })
    }
}

fn same_local_context(left: &LocalConsensusContext, right: &LocalConsensusContext) -> bool {
    left.height_context == right.height_context
        && left.latest_finalized_height == right.latest_finalized_height
        && left.latest_finalized_block_hash == right.latest_finalized_block_hash
        && left.latest_finalized_state_root == right.latest_finalized_state_root
        && left.round == right.round
        && left.evidence_root == right.evidence_root
        && left.app_version == right.app_version
        && left.execution_version == right.execution_version
        && left.dag_version == right.dag_version
        && left.aegis_pqvm_version == right.aegis_pqvm_version
}

/// The coordinator calls `next_authority` only after it has committed and
/// durably appended the QC.  Its immutable height authority and prior
/// evidence must therefore still match the predecessor context, while its
/// finalized-chain fields and round must match the just-persisted block.
fn same_post_finality_context(
    current: &LocalConsensusContext,
    predecessor: &LocalConsensusContext,
    finalized: &TypedFinalityRecord,
) -> Result<bool, String> {
    let finalized_block_hash = Hash::from_hex(&finalized.block_id.0)
        .map_err(|error| format!("persisted typed finality block ID is not a hash: {error}"))?;
    Ok(current.height_context == predecessor.height_context
        && current.latest_finalized_height == finalized.height
        && current.latest_finalized_block_hash == finalized_block_hash
        && current.latest_finalized_state_root == finalized.block.header.state_root_after
        // A valid QC can arrive after this replica has advanced through one
        // or more timeout rounds at the same height. The certified block
        // round is therefore a lower bound on the local round, not an exact
        // equality requirement. QC verification already binds the height,
        // candidate, membership, incarnation, and parameter context.
        && current.round.0 >= finalized.block.header.round.0
        && current.evidence_root == predecessor.evidence_root
        && current.app_version == predecessor.app_version
        && current.execution_version == predecessor.execution_version
        && current.dag_version == predecessor.dag_version
        && current.aegis_pqvm_version == predecessor.aegis_pqvm_version)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::testnet_v3_bootstrap::load_testnet_v3_genesis_bootstrap;
    use crate::genesis::load_genesis_from_path_for_test;
    use crate::synergy_types::{
        AegisPqKeyId, AegisPqSignature, Block, BlockHeader, ChainId, NetworkId, QuorumCertificate,
        UmaId, VotePhase,
    };
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn fixture() -> (
        TestnetV3GenesisBootstrap,
        ProtocolConfig,
        TypedFinalityStore,
        LocalConsensusContext,
        Hash,
        PathBuf,
    ) {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("genesis.testnet-v3.identity-assigned.json");
        let genesis = load_genesis_from_path_for_test(path).expect("load Genesis fixture");
        let bootstrap = load_testnet_v3_genesis_bootstrap(&genesis).expect("bootstrap fixture");
        let protocol = ProtocolConfig::testnet_v3();
        let anchor = Hash::from_domain_bytes("typed-finality-context-test", b"genesis-anchor");
        let deployed_root =
            Hash::from_domain_bytes("typed-finality-context-test", b"deployed-genesis-root");
        let store_path = crate::utils::test_temp_root(format!(
            "typed-finality-context-{}-{}.json",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("test clock")
                .as_nanos()
        ));
        let store = TypedFinalityStore::at_path(store_path.clone(), anchor).expect("store fixture");
        let initial = bootstrap
            .initial_local_consensus_context(&protocol, anchor, deployed_root)
            .expect("height one fixture");
        (
            bootstrap,
            protocol,
            store,
            initial,
            deployed_root,
            store_path,
        )
    }

    fn provider(
        bootstrap: &TestnetV3GenesisBootstrap,
        protocol: &ProtocolConfig,
        store: &TypedFinalityStore,
        deployed_root: Hash,
    ) -> FinalizedTypedContextProvider {
        FinalizedTypedContextProvider::new(
            bootstrap.clone(),
            protocol.clone(),
            store.clone(),
            deployed_root,
        )
        .expect("provider fixture")
    }

    fn finalized_block(context: &LocalConsensusContext, parent: Hash, state_after: Hash) -> Block {
        let authority = &context.height_context;
        Block {
            header: BlockHeader {
                version: 2,
                chain_id: ChainId::synergy_testnet_v3(),
                network_id: NetworkId::synergy_testnet_v3(),
                protocol_version: authority.protocol_version.clone(),
                height: authority.height,
                round: context.round,
                epoch: authority.epoch,
                cluster_id: authority.assigned_cluster_id,
                height_context_root: authority.root().expect("context root"),
                parent_block_hash: parent,
                parent_state_root: context.latest_finalized_state_root,
                last_finalized_qc_hash: authority.prior_finalized_qc_or_transition_root,
                proposer_validator_id: authority.leader_schedule[0].clone(),
                proposer_uma_id: UmaId("typed-finality-context-test-proposer".to_string()),
                proposer_key_id: AegisPqKeyId("typed-finality-context-test-key".to_string()),
                active_validator_set_hash: authority.active_validator_set_root,
                eligible_validator_set_hash: authority.active_validator_set_root,
                validator_consensus_key_root: authority.validator_consensus_key_root,
                frozen_bonded_weight_root: authority.frozen_bonded_weight_root,
                cluster_schedule_version: authority.cluster_schedule_version.clone(),
                cluster_map_hash: authority.cluster_map_root,
                assigned_cluster_membership_root: authority.assigned_cluster_membership_root,
                assigned_cluster_validator_count: authority.assigned_cluster_validator_count,
                assigned_cluster_total_voting_weight: authority
                    .assigned_cluster_total_voting_weight,
                proposer_schedule_hash: authority.leader_schedule_root,
                protocol_config_hash: authority.consensus_parameter_root,
                cryptographic_profile_root: authority.cryptographic_profile_root,
                dag_frontier_root: Hash::from_domain_bytes("typed-finality-context-test", b"dag"),
                tx_order_root: Hash::from_domain_bytes("typed-finality-context-test", b"tx-order"),
                tx_count: 0,
                protected_batch: None,
                evidence_root: Hash::from_domain_bytes("typed-finality-context-test", b"evidence"),
                state_root_before: context.latest_finalized_state_root,
                state_root_after: state_after,
                receipt_root: Hash::from_domain_bytes("typed-finality-context-test", b"receipts"),
                app_version: 1,
                execution_version: 1,
                dag_version: 1,
                aegis_pqvm_version: "aegis-pqvm".to_string(),
                timestamp_ms_consensus_bounded: 1,
                base_fee_per_gas_nwei: 0,
                gas_used: 0,
                gas_limit: 0,
                pq_gas_used: 0,
                pq_gas_limit: 0,
                pq_gas_multiplier: 0,
                fee_market_version: 0,
            },
            transactions: Vec::new(),
            proposer_signature: AegisPqSignature {
                algorithm: "mldsa65".to_string(),
                signature_bytes: vec![1],
            },
        }
    }

    fn finality_qc(block: &Block) -> QuorumCertificate {
        QuorumCertificate {
            qc_version: 1,
            chain_id: block.header.chain_id,
            network_id: block.header.network_id.clone(),
            protocol_version: block.header.protocol_version.clone(),
            height: block.header.height,
            round: block.header.round,
            epoch: block.header.epoch,
            cluster_id: block.header.cluster_id,
            height_context_root: block.header.height_context_root,
            phase: VotePhase::Finality,
            block_id: block.candidate_id().expect("candidate"),
            highest_prepared_vc_root: None,
            active_validator_set_hash: block.header.active_validator_set_hash,
            cluster_map_hash: block.header.cluster_map_hash,
            threshold_weight_required: 1,
            signed_weight: 1,
            signer_bitmap: vec![1],
            aegis_pq_signatures: vec![AegisPqSignature {
                algorithm: "mldsa65".to_string(),
                signature_bytes: vec![1],
            }],
            aegis_pq_key_ids: vec![AegisPqKeyId("typed-finality-context-test-key".to_string())],
        }
    }

    fn append_height_one(
        store: &TypedFinalityStore,
        initial: &LocalConsensusContext,
    ) -> TypedFinalityRecord {
        let block = finalized_block(
            initial,
            store.genesis_anchor(),
            Hash::from_domain_bytes("typed-finality-context-test", b"state-one"),
        );
        store
            .append_verified_finality(&block, &finality_qc(&block))
            .expect("persist height one")
    }

    #[test]
    fn genesis_height_one_digest_is_deterministic_and_nonzero() {
        let (bootstrap, protocol, store, initial, deployed_root, store_path) = fixture();
        let provider = provider(&bootstrap, &protocol, &store, deployed_root);
        let first = provider
            .canonical_finality_context_digest(&initial)
            .expect("Genesis digest");
        let second = provider
            .canonical_finality_context_digest(&initial)
            .expect("same Genesis digest");
        assert_eq!(first, second);
        assert!(!first.is_zero());
        let _ = std::fs::remove_file(store_path);
    }

    #[test]
    fn normal_finality_derives_the_only_next_height_context() {
        let (bootstrap, protocol, store, initial, deployed_root, store_path) = fixture();
        let mut provider = provider(&bootstrap, &protocol, &store, deployed_root);
        let record = append_height_one(&store, &initial);
        let mut post_finality = initial.clone();
        post_finality.latest_finalized_height = record.height;
        post_finality.latest_finalized_block_hash =
            Hash::from_hex(&record.block_id.0).expect("finalized fixture block ID is a hash");
        post_finality.latest_finalized_state_root = record.block.header.state_root_after;
        post_finality.round = record.block.header.round;
        let authority = provider
            .next_authority(&record, &post_finality)
            .expect("same-topology post-finality next authority");
        let TypedNextHeightAuthority::UnchangedTopology { context } = authority else {
            panic!("Genesis topology must retain unchanged authority");
        };
        assert_eq!(context.height_context.height, Height(2));
        assert_eq!(context.latest_finalized_height, Height(1));
        assert_eq!(
            context.height_context.prior_finalized_qc_or_transition_root,
            record.quorum_certificate.finality_context_root().unwrap()
        );
        let _ = std::fs::remove_file(store_path);
    }

    #[test]
    fn restart_recovery_rebuilds_the_same_context_and_digest() {
        let (bootstrap, protocol, store, initial, deployed_root, store_path) = fixture();
        let record = append_height_one(&store, &initial);
        let first = provider(&bootstrap, &protocol, &store, deployed_root)
            .recover_next_context()
            .expect("initial recovery");
        let restarted = provider(&bootstrap, &protocol, &store, deployed_root);
        let second = restarted.recover_next_context().expect("restart recovery");
        assert!(same_local_context(&first, &second));
        assert_eq!(first.latest_finalized_height, record.height);
        assert_eq!(
            restarted
                .canonical_finality_context_digest(&second)
                .expect("restart digest"),
            provider(&bootstrap, &protocol, &store, deployed_root)
                .canonical_finality_context_digest(&first)
                .expect("same digest")
        );
        let _ = std::fs::remove_file(store_path);
    }

    #[test]
    fn mismatched_local_context_is_rejected_before_digest_derivation() {
        let (bootstrap, protocol, store, initial, deployed_root, store_path) = fixture();
        let provider = provider(&bootstrap, &protocol, &store, deployed_root);
        let mut mismatch = initial;
        mismatch.latest_finalized_state_root =
            Hash::from_domain_bytes("typed-finality-context-test", b"wrong-state");
        let error = provider
            .canonical_finality_context_digest(&mismatch)
            .expect_err("mismatch must fail closed");
        assert!(error.contains("does not match"));
        let _ = std::fs::remove_file(store_path);
    }

    #[test]
    fn persisted_epoch_transition_refuses_unchanged_topology_derivation() {
        let (bootstrap, protocol, store, initial, deployed_root, store_path) = fixture();
        let record = append_height_one(&store, &initial);
        let transition = crate::synergy_types::EpochTransition {
            chain_id: ChainId::synergy_testnet_v3(),
            network_id: NetworkId::synergy_testnet_v3(),
            from_epoch: Epoch(0),
            to_epoch: Epoch(1),
            finalized_height: record.height,
            finalized_block_id: record.block_id.clone(),
            active_validator_set_hash: record.block.header.active_validator_set_hash,
            next_validator_set_hash: Hash::from_domain_bytes(
                "typed-finality-context-test",
                b"next-set",
            ),
            cluster_map_hash: Hash::from_domain_bytes("typed-finality-context-test", b"next-map"),
            height_context_root: record.block.header.height_context_root,
            signer_key_ids: vec![AegisPqKeyId(
                "typed-finality-context-transition-key".to_string(),
            )],
            signatures: vec![AegisPqSignature {
                algorithm: "mldsa65".to_string(),
                signature_bytes: vec![1],
            }],
        };
        store
            .append_verified_epoch_transition(&transition)
            .expect("persisted transition record");
        let error = provider(&bootstrap, &protocol, &store, deployed_root)
            .recover_next_context()
            .expect_err("ordinary next-height derivation must reject a transition");
        assert!(error.contains("topology installation payload"));
        let _ = std::fs::remove_file(store_path);
    }
}
