//! Pure received NIC quorum verification using the same native protected reader
//! and independently pinned birth/catalog parser as complete Genesis.
use super::*;
use synergy_address_engine::apqe::bootstrap_approvals_r1::{
    ApprovalPurpose, VerifiedBootstrapApprovals,
};
use synergy_config::R1NicSelection;

pub struct VerifiedR1NicBundle {
    catalog: ProfileCatalog,
    approvals: VerifiedBootstrapApprovals,
}
impl VerifiedR1NicBundle {
    pub fn catalog(&self) -> &ProfileCatalog {
        &self.catalog
    }
    pub fn approvals(&self) -> &VerifiedBootstrapApprovals {
        &self.approvals
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NicApprovals {
    schema_version: u16,
    nic: Vec<PublicApproval>,
}
/// Read-only authentication, not an initial-creation permission, ceremony,
/// formation authority, validator enrollment or runtime activation.
pub fn load_received_nic_bundle(
    selection: &R1NicSelection,
    expected_chain: u64,
    engine: &CryptoEngine,
) -> Result<Arc<VerifiedR1NicBundle>, BundleError> {
    let expected_nic = hex::<64>(&selection.expected_nic_hex)?;
    if expected_chain == 0 || expected_nic == [0; 64] {
        return Err(BundleError::Context);
    }
    for path in [
        &selection.approvals_path,
        &selection.pinned_bootstrap_input_path,
        &selection.profile_catalog_path,
    ] {
        normal_components(path)?;
    }
    let root = ProtectedRoot::open(&selection.managed_root)?;
    let (authority, catalog) = load_pinned_inputs(&root, selection, expected_chain, &expected_nic)?;
    catalog.validate_provider(engine).map_err(|_| BundleError::Catalog)?;
    let approvals: NicApprovals =
        serde_json::from_slice(&root.read(&selection.approvals_path, 1024 * 1024)?)
            .map_err(|_| BundleError::Encoding)?;
    if approvals.schema_version != 1 || approvals.nic.is_empty() || approvals.nic.len() > 32 {
        return Err(BundleError::Bounds);
    }
    let signatures = approvals
        .nic
        .iter()
        .map(|a| hex::<4627>(&a.signature_hex).map(|s| s.to_vec()))
        .collect::<Result<Vec<_>, _>>()?;
    let indexed = approvals
        .nic
        .iter()
        .zip(&signatures)
        .map(|(a, s)| IndexedRootApproval {
            root_index: a.root_index,
            signature: s.as_slice(),
        })
        .collect::<Vec<_>>();
    let approved = authority
        .verify_approvals(engine, ApprovalPurpose::Nic, &indexed)
        .map_err(|_| BundleError::Approval)?;
    Ok(Arc::new(VerifiedR1NicBundle {
        catalog,
        approvals: approved,
    }))
}
