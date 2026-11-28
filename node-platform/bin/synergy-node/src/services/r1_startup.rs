//! Current startup inputs. Cryptographic Genesis admission is deliberately
//! separate from private native use permissions and concrete service owners.
use std::{sync::Arc, time::Duration};
use synergy_config::{ConsensusMode, NodeConfiguration};
use synergy_genesis::r1::{profiles::ProfileKind, VerifiedR1Genesis};
use synergy_node_core::RuntimeView;
use synergy_rpc::provider::CanonicalReadProvider;
use synergy_state::world_resources::WorldResourceBudget;

pub(crate) fn selected(c: &NodeConfiguration) -> bool {
    c.r1_genesis.is_some() || matches!(c.chain_id, 9969 | 469)
}
/// Owns genuine complete initial inputs; no public fields/serde/boolean permit.
/// This is NOT a commissioning token or a constructed running service graph.
pub(crate) struct VerifiedR1StartupInputs {
    genesis: Arc<VerifiedR1Genesis>,
    local_node_index: usize,
}
impl VerifiedR1StartupInputs {
    pub(crate) fn authenticate(c: &NodeConfiguration) -> Result<Self, String> {
        c.validate().map_err(|e| e.to_string())?;
        let genesis = crate::commands::selected_network::verify_configured_current_r1(c)?;
        Self::from_verified(c, genesis)
    }
    pub(crate) fn from_verified(
        c: &NodeConfiguration,
        genesis: Arc<VerifiedR1Genesis>,
    ) -> Result<Self, String> {
        c.validate().map_err(|e| e.to_string())?;
        let selection = c
            .r1_genesis
            .as_ref()
            .ok_or("explicit current Genesis selection required")?;
        let runtime = c
            .r1_runtime
            .as_ref()
            .ok_or("explicit native runtime policy required")?;
        let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
        if genesis.coordinate().network.chain_id != c.chain_id
            || hex(&genesis.coordinate().network.nic) != selection.expected_nic_hex
            || hex(&genesis.coordinate().genesis.digest) != selection.expected_genesis_hex
        {
            return Err("current startup selection differs from authenticated Genesis".into());
        }
        // Even a real NIC+Genesis root quorum cannot replace qualified seed,
        // deterministic assignment and the complete native initial authority.
        let formation=genesis.compiled().complete_formation().ok_or("current startup requires complete schema2 formation and qualified HashRand; bootstrap crypto quorum alone is insufficient")?;
        for kind in [
            ProfileKind::CompleteFormation,
            ProfileKind::InitialBootstrapScore,
            ProfileKind::ProtocolProfile,
            ProfileKind::FormationAssignment,
            ProfileKind::PoSySchedule,
            ProfileKind::Custody,
            ProfileKind::NativeRuntimeUse,
        ] {
            if !genesis
                .compiled()
                .catalog()
                .definitions()
                .iter()
                .any(|d| d.kind == kind)
            {
                return Err(format!(
                    "current startup profile is not selected: {}",
                    kind.name()
                ));
            }
        }
        let local_node_index = genesis
            .compiled()
            .nodes()
            .iter()
            .position(|n| n.identity == runtime.local_node_identity)
            .ok_or("local identity absent from complete Genesis roster")?;
        let local = &genesis.compiled().nodes()[local_node_index];
        if local.primary_role != c.role {
            return Err(
                "local runtime role differs from authenticated complete node record".into(),
            );
        }
        if c.consensus.mode == ConsensusMode::ValidateAndVote
            && !genesis
                .compiled()
                .initial_voters()
                .iter()
                .any(|v| v.identity == local.identity)
        {
            return Err("candidate/nonvoter cannot become an initial voting producer".into());
        }
        let authority = formation.initial_authority();
        if authority.epoch != 1
            || authority.first_height != 1
            || authority.last_height != 1000
            || authority.commitment == [0; 48]
            || formation.computed_schedule().commitment() != &formation.candidate().schedule
        {
            return Err("complete initial native authority/schedule binding unavailable".into());
        }
        let keys = super::posy_r1::InitialR1ConsensusKeys::from_verified_genesis(&genesis)
            .map_err(|e| format!("native initial consensus keys: {e}"))?;
        if keys.members().len() != authority.members.len() {
            return Err("native initial authority/member key mismatch".into());
        }
        for (key, member) in keys.members().iter().zip(&authority.members) {
            let node = genesis
                .compiled()
                .nodes()
                .get(member.node_index as usize)
                .ok_or("native authority node index out of bounds")?;
            let identity =
                synergy_address::r1_public::NativeIdentityPresentation::parse(&node.identity)
                    .map_err(|_| "invalid native authority identity")?;
            if key.identity != *identity.raw48()
                || key.key_id != member.key_id
                || key.key_version != member.key_generation
                || key.weight != member.weight
            {
                return Err(
                    "native initial authority differs from authenticated consensus key snapshot"
                        .into(),
                );
            }
        }
        drop(keys);
        Ok(Self {
            genesis,
            local_node_index,
        })
    }
    pub(crate) fn genesis(&self) -> &Arc<VerifiedR1Genesis> {
        &self.genesis
    }
    pub(crate) fn local_node(&self) -> &synergy_genesis::r1::policy::NodeRecord {
        &self.genesis.compiled().nodes()[self.local_node_index]
    }
    /// Uses the EXISTING process pool and actual full-width store/provider.
    /// Construction creates/recover no database and confers no finality status.
    pub(crate) fn read_provider(
        &self,
        c: &NodeConfiguration,
        runtime: RuntimeView,
        pool: Arc<WorldResourceBudget>,
    ) -> Result<Arc<dyn CanonicalReadProvider>, String> {
        let policy = c
            .r1_runtime
            .as_ref()
            .ok_or("missing native runtime policy")?;
        if pool.limit() != policy.process_world_budget_bytes {
            return Err(
                "native public read provider must share the exact configured process budget".into(),
            );
        }
        let p = policy
            .rpc_read_policy
            .as_ref()
            .ok_or("explicit native public read quota/headroom required")?;
        let provider = super::rpc::r1::CanonicalR1QueryStore::open(
            c.storage.data_directory.clone(),
            Arc::clone(&self.genesis),
            runtime,
            pool,
            super::rpc::r1::R1ReadCapacity {
                request_timeout: Duration::from_millis(p.request_timeout_ms),
                maximum_hashes: p.maximum_hashes,
                maximum_response_bytes: p.maximum_response_bytes,
                public_quota_bytes: p.public_quota_bytes,
                protected_world_headroom_bytes: p.protected_world_headroom_bytes,
            },
        )
        .map_err(|e| format!("construct current read provider: {e:?}"))?;
        Ok(Arc::new(provider))
    }
    /// Remains explicit while the actual native transport/private-use and
    /// consensus/execution owners are being joined. No legacy registration,
    /// caller-supplied service or successful parse can satisfy this boundary.
    pub(crate) fn unavailable_owner_reason(&self) -> String {
        format!("current native service graph unavailable for authenticated {}: private managed runtime-use admission/current PeerRelay factory, native consensus/execution and current finalized sync owners are required before any listener or lifecycle start",self.local_node().identity)
    }
}

/// Nonexecuting current preflight. The provider owns only a lease in this
/// process's explicit pool; its read-only constructor opens no database.
pub(crate) fn preflight(c: &NodeConfiguration) -> Result<serde_json::Value, String> {
    let current = VerifiedR1StartupInputs::authenticate(c)?;
    let policy = c
        .r1_runtime
        .as_ref()
        .ok_or("missing current runtime policy")?;
    let pool = WorldResourceBudget::new(policy.process_world_budget_bytes);
    let view = Arc::new(std::sync::RwLock::new(synergy_node_core::RuntimeSnapshot {
        node_name: c.node_name.clone(),
        role: format!("{:?}", c.role),
        chain_id: c.chain_id,
        lifecycle: synergy_node_core::NodeLifecycleState::Configured,
        services: Vec::new(),
    }));
    let read_adapter = if c.rpc.enabled {
        Some(current.read_provider(c, view, Arc::clone(&pool))?)
    } else {
        None
    };
    let coordinate = current.genesis().coordinate();
    let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let result = serde_json::json!({"profile":"current_r1","chain_id":coordinate.network.chain_id,"nic_hex":hex(&coordinate.network.nic),"genesis_digest_hex":hex(&coordinate.genesis.digest),"profile_set_commitment_hex":hex(&coordinate.activated_profiles.commitment),"local_node_identity":current.local_node().identity,"complete_formation_verified":true,"native_runtime_permissions_verified":false,"startup_ready":false,"typed_read_adapter_constructed":read_adapter.is_some(),"database_opened":false,"listeners_started":false,"unavailable":current.unavailable_owner_reason()});
    drop(read_adapter);
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn configured(genesis: &VerifiedR1Genesis) -> NodeConfiguration {
        let root = std::env::temp_dir().join(format!("r1-startup-noio-{}", std::process::id()));
        let hex = |b: &[u8]| b.iter().map(|b| format!("{b:02x}")).collect::<String>();
        serde_json::from_value(serde_json::json!({
            "schema_version":1,"node_name":"public-synthetic-startup","role":"validator","chain_id":genesis.coordinate().network.chain_id,"network_id":"public-synthetic-startup",
            "r1_genesis":{"managed_root":root,"core_path":"public/core.bin","approvals_path":"public/approvals.json","pinned_bootstrap_input_path":"public/birth.json","pinned_bootstrap_input_sha256":"11".repeat(32),"profile_catalog_path":"public/catalog.bin","profile_catalog_sha256":"12".repeat(32),"expected_nic_hex":hex(&genesis.coordinate().network.nic),"expected_genesis_hex":hex(&genesis.coordinate().genesis.digest)},
            "r1_runtime":{"local_node_identity":genesis.compiled().nodes()[0].identity,"process_world_budget_bytes":67108864,"transport_use_receipts":["native/transport-use.json"],"consensus_use_receipt":null,"rpc_read_policy":null},
            "aegis_provider":{"report_path":root.join("provider/report.json"),"authenticated_report_sha256":"13".repeat(32)},"admin_socket_path":root.join("run/admin.sock"),
            "storage":{"data_directory":root.join("state"),"wal_sync":"every_commit","max_open_files":64,"world_memory_budget_bytes":67108864,"minimum_free_bytes":1,"prune_finalized_history_after_blocks":null}
        })).unwrap()
    }
    #[test]
    fn genuine_crypto_quorums_cannot_start_incomplete_native_runtime_or_open_state() {
        let genesis = super::super::rpc::r1::tests::verified_genesis();
        let config = configured(&genesis);
        assert!(config.validate().is_ok());
        let root = &config.r1_genesis.as_ref().unwrap().managed_root;
        assert!(!root.exists());
        let result = VerifiedR1StartupInputs::from_verified(&config, Arc::clone(&genesis));
        assert!(matches!(result,Err(reason) if reason.contains("complete schema2 formation")));
        assert!(!root.exists());
        let mut wrong = config.clone();
        wrong.r1_genesis.as_mut().unwrap().expected_genesis_hex = "14".repeat(48);
        assert!(
            matches!(VerifiedR1StartupInputs::from_verified(&wrong,genesis),Err(reason) if reason.contains("differs from authenticated Genesis"))
        );
        assert!(!root.exists());
    }
}
