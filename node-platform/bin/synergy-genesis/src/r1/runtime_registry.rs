//! Pure initial runtime admission data from the authenticated complete Genesis.
//! This neither writes a registry nor grants native use or starts a service.
use super::{policy::RoleKeyKind, profiles::ProfileKind, GenesisError, VerifiedR1Genesis};
use synergy_address_engine::apqe::{
    managed_runtime_transport::{
        RegistryNode, RegistrySource, RegistryTransportKey, RuntimeAdmissionRegistry,
    },
    r1_framing::NetworkRef,
};
use synergy_protocol_types::NodeRole;
impl VerifiedR1Genesis {
    /// Native controller input only: schema1 fixture/root approvals alone can
    /// never produce an admission registry. Current profile admission, protected
    /// publication, custody and phase permissions remain separate boundaries.
    pub fn initial_runtime_admission_registry(
        &self,
    ) -> Result<RuntimeAdmissionRegistry, GenesisError> {
        let compiled = self.compiled();
        let formation = compiled
            .complete_formation()
            .ok_or(GenesisError::FormationUnavailable)?;
        for kind in [
            ProfileKind::RuntimeTransport,
            ProfileKind::NativeRuntimeUse,
            ProfileKind::RuntimeAdmissionRegistry,
        ] {
            if !compiled
                .catalog()
                .definitions()
                .iter()
                .any(|d| d.kind == kind)
            {
                return Err(GenesisError::Profile);
            }
        }
        let coordinate = self.coordinate();
        coordinate.validate().map_err(|_| GenesisError::Profile)?;
        let network = NetworkRef {
            chain_id: coordinate.network.chain_id,
            nic: coordinate.network.nic,
        };
        if formation.initial_authority().epoch != 1 {
            return Err(GenesisError::Registry);
        }
        let mut nodes = Vec::with_capacity(compiled.nodes().len());
        for node in compiled.nodes() {
            let mut keys = Vec::new();
            for role in &node.role_keys {
                if role.kind == RoleKeyKind::Consensus {
                    continue;
                }
                let key = &role.key;
                if key.algorithm != synergy_address_engine::types::Algorithm::MlDsa65 {
                    return Err(GenesisError::Policy);
                }
                let label = role.kind.label();
                keys.push(RegistryTransportKey {
                    role: label.into(),
                    generation: key.generation,
                    public_key: key.public_key.clone(),
                    key_reference: RegistryTransportKey::reference(
                        network,
                        &node.identity,
                        label,
                        key.generation,
                        &key.public_key,
                    )
                    .map_err(|_| GenesisError::Registry)?,
                });
            }
            keys.sort_by(|a, b| a.role.cmp(&b.role));
            let selected_voter = compiled
                .initial_voters()
                .iter()
                .any(|v| v.identity == node.identity);
            // A retained sixth validator candidate has no implicit overlay grant.
            // Internal nonvoting roles retain only their exact role transport.
            let status = if node.primary_role == NodeRole::Validator && !selected_voter {
                0
            } else {
                1
            };
            nodes.push(RegistryNode {
                identity: node.identity.clone(),
                class: node.class.digit().into(),
                primary_role: super::policy::role_number(node.primary_role).into(),
                policy_epoch: node.policy_epoch,
                policy_commitment: node
                    .current_policy
                    .commitment(network)
                    .map_err(|_| GenesisError::Policy)?,
                role_key_set_commitment: node
                    .role_key_set_commitment(network)
                    .map_err(|_| GenesisError::Policy)?,
                status,
                keys,
            });
        }
        nodes.sort_by(|a, b| a.identity.cmp(&b.identity));
        let registry = RuntimeAdmissionRegistry {
            network,
            profiles: coordinate.activated_profiles.commitment,
            epoch: 1,
            source: RegistrySource::InitialGenesis {
                genesis: coordinate.genesis.digest,
            },
            nodes,
        };
        registry
            .canonical_frame()
            .map_err(|_| GenesisError::Registry)?;
        Ok(registry)
    }
}
