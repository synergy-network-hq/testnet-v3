//! Current Genesis compiler and authenticated synthetic runtime handoff.
//! Historical JSON/SHA3-256 verification is separate. Production ceremony
//! admission remains closed; this module does not authorize activation.
pub mod account;
pub mod artifact_matrix;
pub mod compiler;
mod decode;
pub mod formation;
pub mod formation_fence;
pub mod policy;
pub mod profiles;
pub mod received_bundle;
use synergy_address_engine::apqe::{
    bootstrap_approvals_r1::{
        ApprovalPurpose, IndexedRootApproval, PinnedBootstrapAuthority, VerifiedBootstrapApprovals,
    },
    crypto_engine::CryptoEngine,
    network_birth_r1::ProfileRef,
};
use synergy_protocol_types::R1NetworkCoordinate;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GenesisError {
    Ceremony,
    Bound,
    Profile,
    Primitive,
    Encoding,
    Identity,
    Duplicate,
    Order,
    Voter,
    Registry,
    State,
    Policy,
    Approval,
    FormationUnavailable,
}
impl std::fmt::Display for GenesisError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "R1 Genesis rejected: {self:?}")
    }
}
impl std::error::Error for GenesisError {}
impl From<synergy_protocol_types::c14n02::Error> for GenesisError {
    fn from(_: synergy_protocol_types::c14n02::Error) -> Self {
        Self::Encoding
    }
}
impl From<policy::PolicyError> for GenesisError {
    fn from(_: policy::PolicyError) -> Self {
        Self::Policy
    }
}
/// Authenticated current Genesis bytes/state, constructed exclusively by actual
/// indexed NIC and Genesis signature verification over a recomputed core.
/// This is not a native PoSy finality proof or production activation permit.
/// Exact authenticated Genesis voter/key data. No independent key-id or
/// authority digest is invented from a convenient width.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InitialValidatorKey {
    pub identity: [u8; 48],
    pub weight: u128,
    pub consensus_key: policy::KeyRecord,
}
pub struct VerifiedR1Genesis {
    nic_approvals: VerifiedBootstrapApprovals,
    genesis_approvals: VerifiedBootstrapApprovals,
    compiled: compiler::CompiledR1Genesis,
    state_profile: synergy_protocol_types::R1ProfileRef,
    receipt_profile: synergy_protocol_types::R1ProfileRef,
    block_profile: synergy_protocol_types::R1ProfileRef,
}
impl VerifiedR1Genesis {
    pub fn nic_approvals(&self) -> &VerifiedBootstrapApprovals {
        &self.nic_approvals
    }
    pub fn genesis_approvals(&self) -> &VerifiedBootstrapApprovals {
        &self.genesis_approvals
    }
    pub fn initial_validator_keys(&self) -> Vec<InitialValidatorKey> {
        self.compiled.initial_voters().iter().map(|v| {
            let node = self.compiled.nodes().iter().find(|n| n.identity == v.identity)
                .expect("compiler validated frozen voter membership");
            let identity = synergy_address_engine::apqe::native_identity_presentation_r1::NativeIdentityPresentation::parse(&node.identity)
                .expect("compiler recomputed complete birth");
            let key = node.role_keys.iter().find(|k| k.kind == policy::RoleKeyKind::Consensus)
                .expect("compiler verified validator role keys");
            InitialValidatorKey { identity: *identity.raw48(), weight: v.weight, consensus_key: key.key.clone() }
        }).collect()
    }
    /// Complete frozen formation/seed binding remains a separate missing input;
    /// registration snapshots alone may not mint it or trigger retirement.
    pub fn formation_registry_commitment(&self) -> Option<&[u8; 64]> {
        None
    }
    pub fn coordinate(&self) -> &R1NetworkCoordinate {
        self.compiled.coordinate()
    }
    pub fn initial_state_root(&self) -> &[u8; 48] {
        &self.compiled.state().root
    }
    pub fn initial_receipts_root(&self) -> &[u8; 48] {
        &self.compiled.state().receipts_root
    }
    pub fn state_profile(&self) -> &synergy_protocol_types::R1ProfileRef {
        &self.state_profile
    }
    pub fn receipt_profile(&self) -> &synergy_protocol_types::R1ProfileRef {
        &self.receipt_profile
    }
    pub fn block_profile(&self) -> &synergy_protocol_types::R1ProfileRef {
        &self.block_profile
    }
    pub fn compiled(&self) -> &compiler::CompiledR1Genesis {
        &self.compiled
    }
}
/// Independently pinned authority is never selected from the candidate. Its
/// APQE received constructor matches complete independently pinned birth inputs.
/// Both NIC-purpose and Genesis-purpose approval quorums are mandatory.
pub fn verify(
    input: compiler::GenesisCoreInput,
    expected_catalog: &profiles::ProfileCatalog,
    authority: &PinnedBootstrapAuthority,
    nic_approvals: &[IndexedRootApproval<'_>],
    genesis_approvals: &[IndexedRootApproval<'_>],
    engine: &CryptoEngine,
) -> Result<VerifiedR1Genesis, GenesisError> {
    let compiled = compiler::compile(input, expected_catalog, engine)?;
    authenticate(
        compiled,
        authority,
        nic_approvals,
        genesis_approvals,
        engine,
    )
}
/// Strict byte loader recomputes state and exact canonical core before approvals.
pub fn verify_bytes(
    bytes: &[u8],
    expected_catalog: &profiles::ProfileCatalog,
    authority: &PinnedBootstrapAuthority,
    nic_approvals: &[IndexedRootApproval<'_>],
    genesis_approvals: &[IndexedRootApproval<'_>],
    engine: &CryptoEngine,
) -> Result<VerifiedR1Genesis, GenesisError> {
    let input = decode::decode(bytes, expected_catalog)?;
    let compiled = compiler::recompute_received_core(input, expected_catalog, engine)?;
    if compiled.canonical_bytes() != bytes {
        return Err(GenesisError::Encoding);
    }
    authenticate(
        compiled,
        authority,
        nic_approvals,
        genesis_approvals,
        engine,
    )
}
fn authenticate(
    compiled: compiler::CompiledR1Genesis,
    authority: &PinnedBootstrapAuthority,
    nic_approvals: &[IndexedRootApproval<'_>],
    genesis_approvals: &[IndexedRootApproval<'_>],
    engine: &CryptoEngine,
) -> Result<VerifiedR1Genesis, GenesisError> {
    let c = compiled.coordinate();
    if authority.network().chain_id != c.network.chain_id
        || authority.network().nic != c.network.nic
    {
        return Err(GenesisError::Approval);
    }
    let nic = authority
        .verify_approvals(engine, ApprovalPurpose::Nic, nic_approvals)
        .map_err(|_| GenesisError::Approval)?;
    if nic.purpose()
        != synergy_address_engine::apqe::bootstrap_approvals_r1::VerifiedApprovalPurpose::Nic
    {
        return Err(GenesisError::Approval);
    }
    let genesis = authority
        .verify_approvals(
            engine,
            ApprovalPurpose::Genesis {
                profile: ProfileRef {
                    name: &c.genesis.profile.name,
                    revision: c.genesis.profile.revision,
                },
                digest: &c.genesis.digest,
                activated_profile_set_commitment: &c.activated_profiles.commitment,
            },
            genesis_approvals,
        )
        .map_err(|_| GenesisError::Approval)?;
    if genesis.genesis_digest() != Some(&c.genesis.digest) {
        return Err(GenesisError::Approval);
    }
    // Root signatures authenticate bytes; they cannot replace the mandatory
    // frozen registry/preseed, qualified randomness, assignments and initial
    // authority interval. That complete R1 formation binding is not yet in the
    // executable core schema. Never promote a real incarnation to runtime trust
    // merely because its bootstrap roots signed an incomplete core.
    if synergy_address_engine::apqe::preparation::require_nonproduction_fixture(c.network.chain_id)
        .is_err()
    {
        return Err(GenesisError::FormationUnavailable);
    }
    Ok(VerifiedR1Genesis {
        nic_approvals: nic,
        genesis_approvals: genesis,
        block_profile: synergy_protocol_types::R1ProfileRef {
            name: synergy_posy::r1::BLOCK_PROFILE_NAME.into(),
            revision: synergy_posy::r1::PROFILE_REVISION,
        },
        state_profile: compiled.state().profile.clone(),
        receipt_profile: synergy_protocol_types::R1ProfileRef {
            name: synergy_state::r1::RECEIPT_PROFILE_NAME.into(),
            revision: synergy_state::r1::RECEIPT_PROFILE_REVISION,
        },
        compiled,
    })
}
