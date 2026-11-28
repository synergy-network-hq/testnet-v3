//! Pure review of the actual input being approved. Neither result is a root
//! approval, finality/activation capability, native grant or permission to issue
//! material. The existing native issuer additionally qualifies its release and
//! ceremony scope before binding these exact canonical references in policy.
use super::{
    compiler, complete_formation, decode,
    formation::{FormationError, FormationRegistration, FormationRegistrySnapshot, Population},
    profiles::ProfileCatalog,
    GenesisError,
};
use synergy_address_engine::apqe::{
    bootstrap_approvals_r1::{
        PinnedBootstrapAuthority, VerifiedApprovalPurpose, VerifiedBootstrapApprovals,
    },
    crypto_engine::CryptoEngine,
    network_birth_r1::with_received_network_birth,
    r1_framing::NetworkRef,
};
/// Full Node/registration/controller verification under genuine NIC. Deliberately
/// does NOT require the Formation-purpose quorum that is about to be requested.
pub struct ReviewedFormationCandidate {
    registry: FormationRegistrySnapshot,
    input: [u8; 64],
}
impl ReviewedFormationCandidate {
    pub fn network(&self) -> NetworkRef {
        self.registry.network()
    }
    pub fn activated_profiles(&self) -> &[u8; 64] {
        self.registry.activated_profiles()
    }
    pub fn registry_commitment(&self) -> &[u8; 64] {
        self.registry.commitment()
    }
    pub fn preseed_commitment(&self) -> &[u8; 64] {
        &self.input
    }
    pub fn canonical_registry(&self) -> &[u8] {
        self.registry.canonical_bytes()
    }
    pub fn canonical_preseed(&self) -> Result<Vec<u8>, FormationError> {
        self.registry.preseed_frame()
    }
}
pub fn review_formation(
    nic: &VerifiedBootstrapApprovals,
    catalog: &ProfileCatalog,
    population: Population,
    registrations: Vec<FormationRegistration>,
    engine: &CryptoEngine,
) -> Result<ReviewedFormationCandidate, FormationError> {
    if nic.purpose() != VerifiedApprovalPurpose::Nic {
        return Err(FormationError::Context);
    }
    let registry = with_received_network_birth(
        nic.complete_network_birth_frame(),
        &nic.network().nic,
        1024 * 1024,
        |birth| {
            FormationRegistrySnapshot::recompute_received(
                nic,
                birth,
                catalog,
                population,
                registrations,
                engine,
            )
        },
    )
    .map_err(|_| FormationError::Context)??;
    let input = registry.preseed_commitment()?;
    Ok(ReviewedFormationCandidate { registry, input })
}
/// Complete schema2 recomputation under genuine NIC and qualified full formation.
/// Deliberately does NOT require its own future Genesis-purpose quorum. This
/// is calculation over received bytes, not authenticated Genesis or execution.
pub struct ReviewedGenesisCandidate {
    compiled: compiler::CompiledR1Genesis,
}
impl ReviewedGenesisCandidate {
    pub fn coordinate(&self) -> &synergy_protocol_types::R1NetworkCoordinate {
        self.compiled.coordinate()
    }
    pub fn canonical_bytes(&self) -> &[u8] {
        self.compiled.canonical_bytes()
    }
    pub fn state_root(&self) -> &[u8; 48] {
        &self.compiled.state().root
    }
    pub fn receipts_root(&self) -> &[u8; 48] {
        &self.compiled.state().receipts_root
    }
    pub fn formation(&self) -> &complete_formation::VerifiedCompleteFormation {
        self.compiled
            .complete_formation()
            .expect("review constructor requires complete schema2")
    }
}
pub fn review_complete_genesis(
    bytes: &[u8],
    catalog: &ProfileCatalog,
    authority: &PinnedBootstrapAuthority,
    nic: &VerifiedBootstrapApprovals,
    engine: &CryptoEngine,
) -> Result<ReviewedGenesisCandidate, GenesisError> {
    if nic.purpose() != VerifiedApprovalPurpose::Nic
        || nic.network() != authority.network()
        || nic.complete_network_birth_frame() != authority.canonical_birth_frame()
    {
        return Err(GenesisError::Approval);
    }
    let (input, formation) = decode::decode_any(bytes, catalog)?;
    if input.network.chain_id != nic.network().chain_id || input.network.nic != nic.network().nic {
        return Err(GenesisError::Approval);
    }
    let candidate = formation.ok_or(GenesisError::FormationUnavailable)?;
    let complete = with_received_network_birth(
        nic.complete_network_birth_frame(),
        &input.network.nic,
        1024 * 1024,
        |birth| candidate.verify_received(&input, nic, birth, authority, engine),
    )
    .map_err(|_| GenesisError::Approval)??;
    let compiled = compiler::recompute_received_complete_core(input, catalog, engine, complete)?;
    if compiled.canonical_bytes() != bytes {
        return Err(GenesisError::Encoding);
    }
    Ok(ReviewedGenesisCandidate { compiled })
}
