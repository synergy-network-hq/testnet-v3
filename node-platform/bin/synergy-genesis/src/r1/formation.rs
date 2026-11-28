//! Current NIC-only formation registration and bounded seed-evidence admission.
//! This adapts the canonical formation order, not a new randomness protocol.
//! Cryptographic registration never proves host/operator independence or PoSy
//! admission. HashRand's missing construction is never replaced by local entropy.
use super::{
    policy::{self, IndexedProof, KeyRecord, NodeRecord},
    VerifiedR1Genesis,
};
use std::{collections::BTreeSet, path::PathBuf};
use synergy_address_engine::{
    apqe::{
        bootstrap_approvals_r1::{
            ApprovalPurpose, IndexedRootApproval, PinnedBootstrapAuthority,
            VerifiedApprovalPurpose, VerifiedBootstrapApprovals,
        },
        crypto_engine::CryptoEngine,
        network_birth_r1::{NetworkBirth, ProfileRef, ReceivedNetworkBirth},
        preparation::require_nonproduction_fixture,
        provider::SignOptions,
        r1_framing::{self as c, NetworkRef, Value},
        HashAlgorithm, Primitives,
    },
    types::Algorithm,
};
use synergy_protocol_types::NodeRole;
use synergy_storage::{AtomicStore, RequiredRecord, StoragePrecondition, StorageTransaction};
pub const REGISTRATION_PROFILE: &str = "APQE-FORMATION-REGISTRATION";
pub const REGISTRY_PROFILE: &str = "APQE-FORMATION-REGISTRY";
pub const INPUT_PROFILE: &str = "APQE-FORMATION-INPUT";
pub const REGISTRATION_SCHEMA:&[u8]=b"APQE-FORMATION-REGISTRATION/1;NIC-only;F domains=FORMATION.REGISTER.KEY-POSSESSION|FORMATION.REGISTER.CONTROLLER-AUTHORIZATION;body=[synv1,raw48,currentPolicyCommit64,currentRoleKeySetCommit64,policyEpochU64,completeDedicatedFormationKeyRecord,registrationNonce32];formationkey=ML-DSA-87,roleformation_authentication,generation>0,fullpublic2592;key-not-node-root-controller-role-or-bootstrap-key;purecontexts=SYNERGY.FORMATION.POP.R1|SYNERGY.FORMATION.AUTH.R1;keyPoP+currentordinarycontrollerquorum;noGenesis-runtime-usertraffic-permission";
pub const REGISTRY_SCHEMA:&[u8]=b"APQE-FORMATION-REGISTRY/1;SHA3-512(F(FORMATION.REGISTRY,[APQE-FORMATION-REGISTRY,1],N,[activatedProfiles64,populationCode,registrations]));registration=[raw48,currentPolicyCommit64,currentRoleKeySetCommit64,completeFormationKeyRecord,registrationNonce32];participants-strict-raw48-order-unique-key;populationConditionalFive1-count5|ReferenceSeven2-count7;one-logical-coordinate-per-node;no-host-operator-qualification-inferred";
pub const INPUT_SCHEMA:&[u8]=b"APQE-FORMATION-INPUT/1;SHA3-512(F(FORMATION.PRE-SEED.INPUT,[APQE-FORMATION-INPUT,1],N,[registry64,targetProductionEpoch1,[APQE-RAND-HASHRAND-FULL-P1,1],n,f=floor((n-1)/3),orderedParticipantRaw48]));preseed-is-not-seed;full-frozen-network-electorate;no-weight-duplication;HashRand-weakVSS-RBC-Gather-BAA-verifier-unimplemented;no-fallback;no-candidate-output-authority";
const MAX: usize = 4 * 1024 * 1024;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FormationError {
    Ceremony,
    Context,
    Profile,
    Key,
    Policy,
    Proof,
    Bounds,
    Population,
    Order,
    Closed,
    Conflict,
    Storage,
    ConstructionUnavailable,
}
impl std::fmt::Display for FormationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "R1 formation rejected: {self:?}")
    }
}
impl std::error::Error for FormationError {}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Population {
    ConditionalFive,
    ReferenceSeven,
}
impl Population {
    fn count(self) -> usize {
        match self {
            Self::ConditionalFive => 5,
            Self::ReferenceSeven => 7,
        }
    }
    fn code(self) -> u64 {
        match self {
            Self::ConditionalFive => 1,
            Self::ReferenceSeven => 2,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FormationRegistration {
    pub node: NodeRecord,
    pub formation_key: KeyRecord,
    pub registration_nonce: [u8; 32],
    pub key_possession: Vec<u8>,
    pub controller_approvals: Vec<IndexedProof>,
}
fn key_value(k: &KeyRecord) -> Result<Value, FormationError> {
    let k = k.as_apqe().map_err(|_| FormationError::Key)?;
    Ok(Value::Array(vec![
        c::text(k.role),
        c::text(k.algorithm),
        Value::Unsigned(k.key_generation),
        c::bytes(k.full_public_key),
    ]))
}
fn frame(
    domain: &str,
    profile: &str,
    n: NetworkRef,
    body: Value,
) -> Result<Vec<u8>, FormationError> {
    c::frame(
        domain,
        ProfileRef {
            name: profile,
            revision: 1,
        },
        Some(n),
        body,
        MAX,
    )
    .map_err(|_| FormationError::Bounds)
}
fn digest(bytes: &[u8]) -> Result<[u8; 64], FormationError> {
    Primitives
        .hash(HashAlgorithm::Sha3512, bytes)
        .map_err(|_| FormationError::Profile)?
        .try_into()
        .map_err(|_| FormationError::Bounds)
}
impl FormationRegistration {
    pub fn message(
        &self,
        n: NetworkRef,
        controller_authorization: bool,
    ) -> Result<Vec<u8>, FormationError> {
        // Pure public received-frame recomputation; no key, identity or nonce
        // is issued and no signature or ceremony permission is constructed.
        let id = self
            .node
            .validate_birth(n)
            .map_err(|_| FormationError::Policy)?;
        if self.node.primary_role != NodeRole::Validator
            || self.formation_key.algorithm != Algorithm::MlDsa87
            || self.formation_key.role != "formation_authentication"
            || self.registration_nonce == [0; 32]
            || self
                .node
                .possession_keys()
                .map_err(|_| FormationError::Key)?
                .iter()
                .any(|k| k.public_key == self.formation_key.public_key)
        {
            return Err(FormationError::Key);
        }
        frame(
            if controller_authorization {
                "FORMATION.REGISTER.CONTROLLER-AUTHORIZATION"
            } else {
                "FORMATION.REGISTER.KEY-POSSESSION"
            },
            REGISTRATION_PROFILE,
            n,
            Value::Array(vec![
                c::text("synv1"),
                c::bytes(id.raw48()),
                c::bytes(
                    &self
                        .node
                        .current_policy
                        .commitment(n)
                        .map_err(|_| FormationError::Policy)?,
                ),
                c::bytes(
                    &self
                        .node
                        .role_key_set_commitment(n)
                        .map_err(|_| FormationError::Policy)?,
                ),
                Value::Unsigned(self.node.policy_epoch),
                key_value(&self.formation_key)?,
                c::bytes(&self.registration_nonce),
            ]),
        )
    }
    fn verify(&self, n: NetworkRef, engine: &CryptoEngine) -> Result<(), FormationError> {
        policy::verify_node(self.node.clone(), n, engine).map_err(|_| FormationError::Policy)?;
        if self.key_possession.len() != 4627
            || !engine
                .verify(
                    Algorithm::MlDsa87,
                    &self.formation_key.public_key,
                    &self.message(n, false)?,
                    &self.key_possession,
                    SignOptions::Pure {
                        context: b"SYNERGY.FORMATION.POP.R1",
                    },
                )
                .map_err(|_| FormationError::Proof)?
        {
            return Err(FormationError::Proof);
        }
        let rule = &self.node.current_policy.ordinary;
        if self.controller_approvals.len() < rule.threshold as usize
            || self.controller_approvals.len() > 32
            || self
                .controller_approvals
                .windows(2)
                .any(|w| w[0].index >= w[1].index)
        {
            return Err(FormationError::Proof);
        }
        let message = self.message(n, true)?;
        for p in &self.controller_approvals {
            if !rule.controller_indices.contains(&p.index) {
                return Err(FormationError::Proof);
            };
            let key = &self
                .node
                .current_policy
                .controllers
                .get(p.index as usize)
                .ok_or(FormationError::Policy)?
                .key;
            if key.algorithm != Algorithm::MlDsa87
                || p.signature.len() != 4627
                || !engine
                    .verify(
                        key.algorithm,
                        &key.public_key,
                        &message,
                        &p.signature,
                        SignOptions::Pure {
                            context: b"SYNERGY.FORMATION.AUTH.R1",
                        },
                    )
                    .map_err(|_| FormationError::Proof)?
            {
                return Err(FormationError::Proof);
            }
        }
        Ok(())
    }
}
/// Immutable, crypto-checked registration snapshot. Not an independently
/// qualified host/operator population, seed or admitted consensus authority.
pub struct FormationRegistrySnapshot {
    network: NetworkRef,
    profiles: [u8; 64],
    population: Population,
    registrations: Vec<FormationRegistration>,
    canonical: Vec<u8>,
    commitment: [u8; 64],
}
impl FormationRegistrySnapshot {
    pub fn build(
        nic: &VerifiedBootstrapApprovals,
        birth: &NetworkBirth<'_>,
        catalog: &super::profiles::ProfileCatalog,
        population: Population,
        registrations: Vec<FormationRegistration>,
        engine: &CryptoEngine,
    ) -> Result<Self, FormationError> {
        require_nonproduction_fixture(nic.network().chain_id)
            .map_err(|_| FormationError::Ceremony)?;
        Self::recompute_received(nic, birth, catalog, population, registrations, engine)
    }
    /// Private full-data received verifier used by complete Genesis. A parsed
    /// snapshot still requires a real indexed Formation-purpose root quorum.
    pub(super) fn recompute_received(
        nic: &VerifiedBootstrapApprovals,
        birth: &NetworkBirth<'_>,
        catalog: &super::profiles::ProfileCatalog,
        population: Population,
        registrations: Vec<FormationRegistration>,
        engine: &CryptoEngine,
    ) -> Result<Self, FormationError> {
        let n = nic.network();
        if nic.purpose() != VerifiedApprovalPurpose::Nic
            || birth.chain_id != n.chain_id
            || ReceivedNetworkBirth::validate(birth, &n.nic, MAX)
                .map_err(|_| FormationError::Context)?
                .frame()
                != nic.complete_network_birth_frame()
        {
            return Err(FormationError::Context);
        }
        if catalog.commitment().map_err(|_| FormationError::Profile)?
            != *birth.initial_profile_set_commitment
        {
            return Err(FormationError::Profile);
        }
        catalog
            .validate_provider(engine)
            .map_err(|_| FormationError::Profile)?;
        if registrations.len() != population.count() {
            return Err(FormationError::Population);
        }
        // A formation-only key must be disjoint from every participant's
        // birth/controller/runtime keys, including participants later in order.
        // Checking only its own node permits cross-participant authority reuse.
        let mut all_node_keys = BTreeSet::new();
        for registration in &registrations {
            for key in registration
                .node
                .possession_keys()
                .map_err(|_| FormationError::Key)?
            {
                all_node_keys.insert(key.public_key.clone());
            }
        }
        if registrations
            .iter()
            .any(|r| all_node_keys.contains(&r.formation_key.public_key))
        {
            return Err(FormationError::Key);
        }
        let mut members = BTreeSet::new();
        let mut keys = BTreeSet::new();
        let mut node_roots = BTreeSet::new();
        let mut runtime_keys = BTreeSet::new();
        let mut values = Vec::new();
        let mut previous = None;
        for r in &registrations {
            r.verify(n, engine)?;
            let id = r
                .node
                .validate_birth(n)
                .map_err(|_| FormationError::Policy)?;
            let raw = *id.raw48();
            if previous.is_some_and(|p| p >= raw)
                || !members.insert(raw)
                || !node_roots.insert(r.node.birth_root.public_key.clone())
                || r.node
                    .role_keys
                    .iter()
                    .any(|k| !runtime_keys.insert(k.key.public_key.clone()))
                || !keys.insert(r.formation_key.public_key.clone())
                || birth
                    .bootstrap_roots
                    .iter()
                    .any(|root| root.full_public_key == r.formation_key.public_key)
            {
                return Err(FormationError::Order);
            }
            previous = Some(raw);
            values.push(Value::Array(vec![
                c::bytes(&raw),
                c::bytes(
                    &r.node
                        .current_policy
                        .commitment(n)
                        .map_err(|_| FormationError::Policy)?,
                ),
                c::bytes(
                    &r.node
                        .role_key_set_commitment(n)
                        .map_err(|_| FormationError::Policy)?,
                ),
                key_value(&r.formation_key)?,
                c::bytes(&r.registration_nonce),
            ]));
        }
        let all_node_keys = registrations
            .iter()
            .map(|r| r.node.possession_keys())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| FormationError::Key)?;
        if registrations.iter().any(|r| {
            all_node_keys
                .iter()
                .flatten()
                .any(|k| k.public_key == r.formation_key.public_key)
        }) {
            return Err(FormationError::Key);
        }
        let canonical = frame(
            "FORMATION.REGISTRY",
            REGISTRY_PROFILE,
            n,
            Value::Array(vec![
                c::bytes(birth.initial_profile_set_commitment),
                Value::Unsigned(population.code()),
                Value::Array(values),
            ]),
        )?;
        let commitment = digest(&canonical)?;
        Ok(Self {
            network: n,
            profiles: *birth.initial_profile_set_commitment,
            population,
            registrations,
            canonical,
            commitment,
        })
    }
    pub fn registrations(&self) -> &[FormationRegistration] {
        &self.registrations
    }
    pub fn network(&self) -> NetworkRef {
        self.network
    }
    pub fn commitment(&self) -> &[u8; 64] {
        &self.commitment
    }
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical
    }
    pub fn population(&self) -> Population {
        self.population
    }
    pub fn activated_profiles(&self) -> &[u8; 64] {
        &self.profiles
    }
    pub fn preseed_frame(&self) -> Result<Vec<u8>, FormationError> {
        let n = self.registrations.len() as u64;
        if self.registrations.len() != self.population.count() {
            return Err(FormationError::Population);
        }
        let ids = self
            .registrations
            .iter()
            .map(|r| {
                r.node
                    .validate_birth(self.network)
                    .map(|i| c::bytes(i.raw48()))
                    .map_err(|_| FormationError::Policy)
            })
            .collect::<Result<Vec<_>, _>>()?;
        frame(
            "FORMATION.PRE-SEED.INPUT",
            INPUT_PROFILE,
            self.network,
            Value::Array(vec![
                c::bytes(&self.commitment),
                Value::Unsigned(1),
                Value::Array(vec![
                    c::text("APQE-RAND-HASHRAND-FULL-P1"),
                    Value::Unsigned(1),
                ]),
                Value::Unsigned(n),
                Value::Unsigned((n - 1) / 3),
                Value::Array(ids),
            ]),
        )
    }
    pub fn preseed_commitment(&self) -> Result<[u8; 64], FormationError> {
        digest(&self.preseed_frame()?)
    }
    fn base(&self) -> PathBuf {
        PathBuf::from(format!(
            "formation-r1/{}-{}",
            self.network.chain_id,
            hex(&self.network.nic)
        ))
    }
    /// Exact existing AtomicStore key, for the native closure adapter. This
    /// relative path is data and grants neither storage access nor authority.
    pub fn storage_relative_root(&self) -> PathBuf {
        self.base()
    }
    /// Consistent local observation only, not release authorization. The caller
    /// must enforce its durable post-computation release/retirement fence.
    pub fn ensure_open_preparation(&self, store: &AtomicStore) -> Result<(), FormationError> {
        require_nonproduction_fixture(self.network.chain_id)
            .map_err(|_| FormationError::Ceremony)?;
        store
            .inspect_consistent(|reader| {
                if reader
                    .read_optional_bounded(self.base().join("retired.bin"))
                    .map_err(storage_error)?
                    .is_some()
                {
                    return Err(FormationError::Closed);
                }
                match reader
                    .read_optional_bounded(self.base().join("registry.cbor"))
                    .map_err(storage_error)?
                {
                    Some(bytes) if bytes == self.canonical => Ok(()),
                    _ => Err(FormationError::Context),
                }
            })
            .map_err(storage_error)?
    }
    pub fn persist_preparation(&self, store: &mut AtomicStore) -> Result<(), FormationError> {
        require_nonproduction_fixture(self.network.chain_id)
            .map_err(|_| FormationError::Ceremony)?;
        let base = self.base();
        let registry = base.join("registry.cbor");
        let closed = base.join("retired.bin");
        let mut tx = StorageTransaction::new(MAX).map_err(|_| FormationError::Storage)?;
        tx.put(&registry, self.canonical.clone())
            .map_err(|_| FormationError::Storage)?;
        tx.commit_guarded(
            store,
            &[
                StoragePrecondition {
                    relative_path: closed,
                    required: RequiredRecord::Missing,
                },
                StoragePrecondition {
                    relative_path: registry,
                    required: RequiredRecord::MissingOrSameWrite,
                },
            ],
        )
        .map_err(storage_error)
    }
}
/// Root-authenticated frozen formation population, still distinct from host/
/// operator qualification, valid randomness, assignments or runtime admission.
pub struct VerifiedFormationAuthority {
    approvals: VerifiedBootstrapApprovals,
    registry: FormationRegistrySnapshot,
}
/// Complete untrusted received registry material plus independently pinned
/// bootstrap authority. This describes no generation, signing or execution.
pub struct ReceivedFormationRegistryInput<'a> {
    pub nic: &'a VerifiedBootstrapApprovals,
    pub birth: &'a NetworkBirth<'a>,
    pub catalog: &'a super::profiles::ProfileCatalog,
    pub population: Population,
    pub registrations: Vec<FormationRegistration>,
    pub expected_registry: [u8; 64],
    pub expected_preseed: [u8; 64],
    pub authority: &'a PinnedBootstrapAuthority,
    pub approvals: &'a [IndexedRootApproval<'a>],
}
impl VerifiedFormationAuthority {
    /// Pure received verifier before final Genesis: every Node/key/controller
    /// proof, complete NIC birth and exact indexed Formation root quorum are
    /// verified. Actual private key/session use still requires the existing
    /// native lifecycle's separate NIC-only permission; no seed is constructed.
    pub fn verify_received(
        input: ReceivedFormationRegistryInput<'_>,
        engine: &CryptoEngine,
    ) -> Result<Self, FormationError> {
        if input.expected_registry == [0; 64]
            || input.expected_preseed == [0; 64]
            || input.authority.network() != input.nic.network()
        {
            return Err(FormationError::Context);
        }
        let snapshot = FormationRegistrySnapshot::recompute_received(
            input.nic,
            input.birth,
            input.catalog,
            input.population,
            input.registrations,
            engine,
        )?;
        if snapshot.commitment() != &input.expected_registry
            || snapshot.preseed_commitment()? != input.expected_preseed
        {
            return Err(FormationError::Context);
        }
        snapshot.authenticate(input.authority, input.approvals, engine)
    }
    pub fn approvals(&self) -> &VerifiedBootstrapApprovals {
        &self.approvals
    }
    pub fn registry(&self) -> &FormationRegistrySnapshot {
        &self.registry
    }
    pub fn verify_seed(
        &self,
        e: &CandidateSeedEvidence<'_>,
    ) -> Result<VerifiedFormationSeed, FormationError> {
        verify_seed_evidence(&self.registry, e)
    }
}
impl FormationRegistrySnapshot {
    pub fn authenticate(
        self,
        authority: &PinnedBootstrapAuthority,
        approvals: &[IndexedRootApproval<'_>],
        engine: &CryptoEngine,
    ) -> Result<VerifiedFormationAuthority, FormationError> {
        if authority.network() != self.network {
            return Err(FormationError::Context);
        }
        let input = self.preseed_commitment()?;
        let token = authority
            .verify_approvals(
                engine,
                ApprovalPurpose::Formation {
                    registry_profile: ProfileRef {
                        name: REGISTRY_PROFILE,
                        revision: 1,
                    },
                    registry_commitment: &self.commitment,
                    input_profile: ProfileRef {
                        name: INPUT_PROFILE,
                        revision: 1,
                    },
                    input_commitment: &input,
                },
                approvals,
            )
            .map_err(|_| FormationError::Proof)?;
        match token.purpose() {
            VerifiedApprovalPurpose::Formation {
                registry_commitment,
                input_commitment,
            } if registry_commitment == self.commitment && input_commitment == input => {
                Ok(VerifiedFormationAuthority {
                    registry: self,
                    approvals: token,
                })
            }
            _ => Err(FormationError::Context),
        }
    }
}
/// Candidate bytes cannot produce a verified seed. Exact implementation/proofs
/// of weak-VSS/RBC/Gather/BAA and release qualification are missing. This bounded
/// adapter rejects foreign context before reporting that concrete dependency.
pub struct CandidateSeedEvidence<'a> {
    pub network: NetworkRef,
    pub registry_commitment: [u8; 64],
    pub preseed_commitment: [u8; 64],
    pub target_epoch: u64,
    pub construction: &'a str,
    pub transcript: &'a [u8],
    pub candidate_output: &'a [u8],
}
/// Only an actual selected HashRand verification implementation may construct
/// this token. No public constructor, serde or caller-supplied success flag.
pub struct VerifiedFormationSeed {
    network: NetworkRef,
    registry: [u8; 64],
    input: [u8; 64],
    /// Qualified result-reference commitment; its normalization/construction is
    /// not selected yet. Only the eventual real verifier may populate it.
    reference: [u8; 64],
    output: Vec<u8>,
}
impl VerifiedFormationSeed {
    pub fn network(&self) -> NetworkRef {
        self.network
    }
    pub fn registry_commitment(&self) -> &[u8; 64] {
        &self.registry
    }
    pub fn preseed_commitment(&self) -> &[u8; 64] {
        &self.input
    }
    pub fn output(&self) -> &[u8] {
        &self.output
    }
    pub fn qualified_reference(&self) -> &[u8; 64] {
        &self.reference
    }
}
fn verify_seed_evidence(
    registry: &FormationRegistrySnapshot,
    e: &CandidateSeedEvidence<'_>,
) -> Result<VerifiedFormationSeed, FormationError> {
    if e.network != registry.network
        || e.registry_commitment != registry.commitment
        || e.preseed_commitment != registry.preseed_commitment()?
        || e.target_epoch != 1
        || e.construction != "APQE-RAND-HASHRAND-FULL-P1"
    {
        return Err(FormationError::Context);
    }
    if e.transcript.is_empty()
        || e.transcript.len() > MAX
        || e.candidate_output.is_empty()
        || e.candidate_output.len() > 65536
    {
        return Err(FormationError::Bounds);
    }
    Err(FormationError::ConstructionUnavailable)
}
fn storage_error(e: synergy_storage::StorageError) -> FormationError {
    if e == synergy_storage::StorageError::ConflictingWrite {
        FormationError::Conflict
    } else {
        FormationError::Storage
    }
}
fn hex(v: &[u8]) -> String {
    v.iter().map(|b| format!("{b:02x}")).collect()
}
/// Retire only after a verified matching Genesis AND genuine first finality.
/// This local durable tombstone does not replace external antirollback/current
/// runtime fences. Actual production mutation remains unavailable in this phase.
pub fn retire_preparation(
    store: &mut AtomicStore,
    registry: &FormationRegistrySnapshot,
    genesis: &VerifiedR1Genesis,
    first_finality: &synergy_posy::r1::VerifiedR1FinalizedAnchor,
) -> Result<(), FormationError> {
    require_nonproduction_fixture(registry.network.chain_id)
        .map_err(|_| FormationError::Ceremony)?;
    if genesis.formation_registry_commitment() != Some(&registry.commitment) {
        return Err(FormationError::Context);
    }
    let n = &genesis.coordinate().network;
    if n.chain_id != registry.network.chain_id
        || n.nic != registry.network.nic
        || genesis.coordinate().activated_profiles.commitment != registry.profiles
        || first_finality.coordinate() != genesis.coordinate()
        || first_finality.height() == 0
    {
        return Err(FormationError::Context);
    }
    let mut bytes = Vec::from(genesis.coordinate().genesis.digest);
    bytes.extend_from_slice(&first_finality.height().to_be_bytes());
    bytes.extend_from_slice(first_finality.block_digest());
    retire_marker(store, registry.base(), &registry.canonical, bytes)
}
fn retire_marker(
    store: &mut AtomicStore,
    base: PathBuf,
    registry_bytes: &[u8],
    marker: Vec<u8>,
) -> Result<(), FormationError> {
    let path = base.join("retired.bin");
    let mut tx = StorageTransaction::new(4096).map_err(|_| FormationError::Storage)?;
    tx.put(&path, marker).map_err(|_| FormationError::Storage)?;
    tx.commit_guarded(
        store,
        &[
            StoragePrecondition {
                relative_path: base.join("registry.cbor"),
                required: RequiredRecord::Exact(registry_bytes.to_vec()),
            },
            StoragePrecondition {
                relative_path: path,
                required: RequiredRecord::MissingOrSameWrite,
            },
        ],
    )
    .map_err(storage_error)
}
#[cfg(test)]
mod tests {
    use super::*;
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    struct Temp(std::path::PathBuf);
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn temp() -> Temp {
        Temp(std::env::temp_dir().join(format!(
            "synergy-r1-formation-public-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
        )))
    }
    fn storage_fixture() -> FormationRegistrySnapshot {
        FormationRegistrySnapshot {
            network: NetworkRef {
                chain_id: u64::MAX - 1,
                nic: [3; 64],
            },
            profiles: [4; 64],
            population: Population::ConditionalFive,
            registrations: vec![],
            canonical: b"PUBLIC-NONCRYPTOGRAPHIC-STORAGE-FIXTURE-ONLY".to_vec(),
            commitment: [5; 64],
        }
    }
    #[test]
    fn local_tombstone_cas_is_one_way_and_retry_exact_noncrypto_storage_fixture() {
        let t = temp();
        let mut store = AtomicStore::new(&t.0, 1024 * 1024).unwrap();
        let registry = storage_fixture();
        registry.persist_preparation(&mut store).unwrap();
        registry.persist_preparation(&mut store).unwrap();
        registry.ensure_open_preparation(&store).unwrap();
        retire_marker(
            &mut store,
            registry.base(),
            &registry.canonical,
            vec![9; 104],
        )
        .unwrap();
        retire_marker(
            &mut store,
            registry.base(),
            &registry.canonical,
            vec![9; 104],
        )
        .unwrap();
        assert_eq!(
            registry.ensure_open_preparation(&store),
            Err(FormationError::Closed)
        );
        assert_eq!(
            registry.persist_preparation(&mut store),
            Err(FormationError::Conflict)
        );
        assert_eq!(
            retire_marker(
                &mut store,
                registry.base(),
                &registry.canonical,
                vec![8; 104]
            ),
            Err(FormationError::Conflict)
        );
    }
    #[test]
    fn production_coordinate_rejects_before_store_mutation() {
        let t = temp();
        let mut store = AtomicStore::new(&t.0, 1024).unwrap();
        let mut registry = storage_fixture();
        registry.network.chain_id = 9969;
        assert_eq!(
            registry.persist_preparation(&mut store),
            Err(FormationError::Ceremony)
        );
        assert!(!store.exists(registry.base().join("registry.cbor")).unwrap());
    }
    #[test]
    fn source_populations_and_count_fault_bound_stay_separate_from_weights() {
        assert_eq!(Population::ConditionalFive.count(), 5);
        assert_eq!(Population::ReferenceSeven.count(), 7);
        for n in [5usize, 7] {
            assert_eq!((n - 1) / 3, if n == 5 { 1 } else { 2 });
            let quorum = 2 * n / 3 + 1;
            assert_eq!(quorum, if n == 5 { 4 } else { 5 });
        }
    }
}
