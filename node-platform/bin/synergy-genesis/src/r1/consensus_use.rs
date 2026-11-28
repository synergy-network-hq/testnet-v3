//! Native-helper handoff from genuinely complete Genesis. Public admission data
//! never grants custody, execution, activation, or voting by itself.
use super::{
    policy::{KeyRecord, RoleKeyKind},
    GenesisError, VerifiedR1Genesis,
};
use std::{fs::File, path::Path};
use synergy_address_engine::{
    apqe::{
        crypto_engine::CryptoEngine,
        managed_creation::consensus_use::{
            ManagedConsensusKey, VerifiedManagedConsensusUseAuthorization,
        },
        r1_framing::NetworkRef,
        SecretBytes,
    },
    types::Algorithm,
};
use synergy_config::ConsensusMode;
use synergy_protocol_types::{NodeRole, R1NetworkCoordinate};

/// Exact received data for the native issuer's independent admission review.
/// No public constructor: only the actual complete Genesis can populate it.
pub struct InitialConsensusAdmission {
    coordinate: R1NetworkCoordinate,
    owner_id: String,
    journal: synergy_posy::r1::R1JournalBinding,
    schedule: [u8; 48],
    first_height: u64,
    last_height: u64,
    key: KeyRecord,
    policy_epoch: u64,
    full_policy_frame: Vec<u8>,
    policy_commitment: [u8; 64],
    role_key_set_commitment: [u8; 64],
}
impl InitialConsensusAdmission {
    pub fn coordinate(&self) -> &R1NetworkCoordinate {
        &self.coordinate
    }
    pub fn owner_id(&self) -> &str {
        &self.owner_id
    }
    pub fn journal_binding(&self) -> &synergy_posy::r1::R1JournalBinding {
        &self.journal
    }
    pub fn schedule(&self) -> &[u8; 48] {
        &self.schedule
    }
    pub fn first_height(&self) -> u64 {
        self.first_height
    }
    pub fn last_height(&self) -> u64 {
        self.last_height
    }
    pub fn public_key(&self) -> &KeyRecord {
        &self.key
    }
    pub fn policy_epoch(&self) -> u64 {
        self.policy_epoch
    }
    pub fn full_policy_frame(&self) -> &[u8] {
        &self.full_policy_frame
    }
    pub fn policy_commitment(&self) -> &[u8; 64] {
        &self.policy_commitment
    }
    pub fn role_key_set_commitment(&self) -> &[u8; 64] {
        &self.role_key_set_commitment
    }
}
impl VerifiedR1Genesis {
    pub fn initial_consensus_admission(
        &self,
        owner_id: &str,
    ) -> Result<InitialConsensusAdmission, GenesisError> {
        let compiled = self.compiled();
        let formation = compiled
            .complete_formation()
            .ok_or(GenesisError::FormationUnavailable)?;
        let authority = formation.initial_authority();
        if authority.epoch != 1
            || authority.first_height != 1
            || authority.last_height != 1000
            || authority.commitment == [0; 48]
            || formation.computed_schedule().commitment() != &formation.candidate().schedule
        {
            return Err(GenesisError::Registry);
        }
        let index = compiled
            .nodes()
            .iter()
            .position(|n| n.identity == owner_id)
            .ok_or(GenesisError::Identity)?;
        let node = &compiled.nodes()[index];
        if node.primary_role != NodeRole::Validator
            || node.class.digit() != 1
            || !compiled
                .initial_voters()
                .iter()
                .any(|v| v.identity == node.identity)
        {
            return Err(GenesisError::Voter);
        }
        let member = authority
            .members
            .iter()
            .find(|m| m.node_index as usize == index)
            .ok_or(GenesisError::Voter)?;
        let key = &node
            .role_keys
            .iter()
            .find(|k| k.kind == RoleKeyKind::Consensus)
            .ok_or(GenesisError::Policy)?
            .key;
        if key.role != "consensus"
            || key.algorithm != Algorithm::MlDsa65
            || key.public_key.len() != 1952
            || key.generation == 0
            || key.generation != member.key_generation
            || synergy_posy::r1::consensus_key_id(&key.public_key, key.generation)
                .map_err(|_| GenesisError::Policy)?
                != member.key_id
        {
            return Err(GenesisError::Policy);
        }
        let identity=synergy_address_engine::apqe::native_identity_presentation_r1::NativeIdentityPresentation::parse(&node.identity).map_err(|_|GenesisError::Identity)?;
        if identity.namespace() != "synv1" {
            return Err(GenesisError::Identity);
        }
        let coordinate = self.coordinate().clone();
        let network = NetworkRef {
            chain_id: coordinate.network.chain_id,
            nic: coordinate.network.nic,
        };
        Ok(InitialConsensusAdmission {
            coordinate: coordinate.clone(),
            owner_id: node.identity.clone(),
            journal: synergy_posy::r1::R1JournalBinding {
                coordinate,
                protocol: authority.protocol_profile,
                authority: authority.commitment,
                epoch: authority.epoch,
                identity: *identity.raw48(),
                key_id: member.key_id,
                key_version: member.key_generation,
            },
            schedule: formation.candidate().schedule,
            first_height: authority.first_height,
            last_height: authority.last_height,
            key: key.clone(),
            policy_epoch: node.policy_epoch,
            full_policy_frame: node.current_policy.frame(network)?,
            policy_commitment: node.current_policy.commitment(network)?,
            role_key_set_commitment: node.role_key_set_commitment(network)?,
        })
    }
}
/// Explicit native-helper inputs. The ordinary node never receives plaintext
/// custody; this function must run in its existing privileged native helper.
pub struct InitialConsensusOpen<'a> {
    pub genesis: &'a VerifiedR1Genesis,
    pub configuration: &'a synergy_config::NodeConfiguration,
    pub authorization: VerifiedManagedConsensusUseAuthorization,
    pub engine: CryptoEngine,
    pub record_path: &'a Path,
    pub record: File,
    pub passphrase: &'a SecretBytes,
}
pub struct OpenedInitialConsensus {
    admission: InitialConsensusAdmission,
    key: ManagedConsensusKey,
}
impl OpenedInitialConsensus {
    pub fn admission(&self) -> &InitialConsensusAdmission {
        &self.admission
    }
    pub fn key(&mut self) -> &mut ManagedConsensusKey {
        &mut self.key
    }
}
pub fn open_initial_consensus_key(
    input: InitialConsensusOpen<'_>,
) -> Result<OpenedInitialConsensus, String> {
    let c = input.configuration;
    c.validate().map_err(|e| e.to_string())?;
    let runtime = c
        .r1_runtime
        .as_ref()
        .ok_or("explicit current runtime policy required")?;
    let selected = c
        .r1_genesis
        .as_ref()
        .ok_or("explicit authenticated Genesis selection required")?;
    if c.role != NodeRole::Validator
        || c.consensus.mode != ConsensusMode::ValidateAndVote
        || runtime.consensus_use_receipt.is_none()
    {
        return Err("native consensus use is only selected for an admitted voting validator".into());
    }
    let admission = input
        .genesis
        .initial_consensus_admission(&runtime.local_node_identity)
        .map_err(|e| e.to_string())?;
    let a = &input.authorization;
    let n = &admission.coordinate.network;
    let key = a.public_key_record();
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    if c.chain_id != n.chain_id
        || selected.managed_root != a.platform_root()
        || selected.expected_nic_hex != hex(&n.nic)
        || selected.expected_genesis_hex != hex(&admission.coordinate.genesis.digest)
        || a.network()
            != (NetworkRef {
                chain_id: n.chain_id,
                nic: n.nic,
            })
        || a.genesis() != admission.coordinate.genesis.digest
        || a.activated_profiles() != admission.coordinate.activated_profiles.commitment
        || a.owner_id() != admission.owner_id
        || a.identity_raw48() != &admission.journal.identity
        || a.protocol_profile() != &admission.journal.protocol
        || a.authority_commitment() != &admission.journal.authority
        || a.schedule_commitment() != &admission.schedule
        || a.epoch() != admission.journal.epoch
        || a.first_height() != admission.first_height
        || a.last_height() != admission.last_height
        || a.key_id() != &admission.journal.key_id
        || key.role != "consensus"
        || key.algorithm != "ML-DSA-65"
        || key.key_generation != admission.key.generation
        || key.full_public_key != admission.key.public_key
        || a.current_policy_epoch() != admission.policy_epoch
        || a.policy_commitment() != &admission.policy_commitment
        || a.role_key_set_commitment() != &admission.role_key_set_commitment
        || !a
            .consensus_store_root()
            .starts_with(&c.storage.data_directory)
        || input.record_path != a.record_path()
    {
        return Err(
            "native consensus grant differs from genuine complete initial authority/configuration"
                .into(),
        );
    }
    a.ensure_current()
        .map_err(|e| format!("native consensus currentness: {e:?}"))?;
    let password = std::str::from_utf8(input.passphrase.as_bytes())
        .map_err(|_| "native passphrase encoding")?;
    let key = ManagedConsensusKey::open(
        input.authorization,
        input.engine,
        input.record_path,
        input.record,
        password,
    )
    .map_err(|e| format!("native consensus key open: {e:?}"))?;
    Ok(OpenedInitialConsensus { admission, key })
}
