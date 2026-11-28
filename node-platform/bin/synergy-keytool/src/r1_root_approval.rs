//! Existing native receipt → APQE opaque authorization → durable original result.
//! Prospective network pins are protected native policy, never CLI arguments.
use std::path::Path;
use synergy_address::r1_custody::CompletedRootApproval;

pub(crate) const COMMAND: &str = "use-managed-r1-root-approval";
pub(crate) const READ_COMMAND: &str = "read-managed-r1-root-approval-result";

pub(crate) enum DurableRootApprovalResult {
    Absent,
    Completed(CompletedRootApproval),
}
impl DurableRootApprovalResult {
    pub(crate) fn canonical_public_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Absent => None,
            Self::Completed(result) => Some(result.canonical_public_bytes()),
        }
    }
}

pub(crate) fn dispatch(arguments: &[String]) -> Result<Option<DurableRootApprovalResult>, String> {
    if arguments.first().map(String::as_str) == Some(READ_COMMAND) {
        let [_, root, nonce, request] = arguments else {
            return Err(
                "Exact original root result ROOT NONCE ORIGINAL_REQUEST_SHA256 required".into(),
            );
        };
        let nonce = crate::r1_identity_custody::original_request_digest(nonce)?;
        let request = crate::r1_identity_custody::original_request_digest(request)?;
        if nonce == [0; 32] || request == [0; 32] {
            return Err("Nonzero original root result coordinates required".into());
        }
        // Root's existing-store-only reader verifies the original NoneN journal
        // and exact nonce/request. This observes history, not current authority;
        // no future mutation permission, provider, replay or receipt is needed.
        return synergy_address::r1_custody::NativeCustodyJournal::inspect_managed_completed_root_approval(
            Path::new(root), &nonce, &request)
            .map(|r| Some(r.map(DurableRootApprovalResult::Completed)
                .unwrap_or(DurableRootApprovalResult::Absent)))
            .map_err(|_| "Original root result unavailable; reconcile durable operation".into());
    }
    if arguments.first().map(String::as_str) != Some(COMMAND) {
        return Ok(None);
    }
    let [_, root, receipt, request] = arguments else {
        return Err("Exact root approval ROOT RECEIPT ORIGINAL_REQUEST_SHA256 required".into());
    };
    use_approval(Path::new(root), Path::new(receipt), request)
        .map(DurableRootApprovalResult::Completed)
        .map(Some)
}

#[cfg(not(unix))]
fn use_approval(_: &Path, _: &Path, _: &str) -> Result<CompletedRootApproval, String> {
    Err("Native root approval protection is not qualified for this platform".into())
}

#[cfg(unix)]
fn use_approval(
    root: &Path,
    receipt: &Path,
    request: &str,
) -> Result<CompletedRootApproval, String> {
    use std::{fs::OpenOptions, io::Seek, os::unix::fs::OpenOptionsExt};
    use synergy_address::r1_custody::NativeCustodyJournal;
    use synergy_address_engine::apqe::managed_creation::root_approval_use::{
        self as approval, RootApprovalStage,
    };
    use synergy_genesis::r1::received_bundle;

    let expected = crate::r1_identity_custody::original_request_digest(request)?;
    if expected == [0; 32] {
        return Err("Nonzero original root approval request required".into());
    }
    let mut held = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(receipt)
        .map_err(|_| "Protected root approval receipt unavailable")?;
    // Receipt/root/release/expiry/request checks precede prospective context,
    // provider loading, durable reservation and all secret operations.
    let inspected = approval::preflight_controller_root_approval_receipt(
        root,
        receipt,
        held.try_clone()
            .map_err(|_| "Protected root receipt unavailable")?,
        expected,
    )
    .map_err(|_| "Native root approval preflight refused")?;
    held.rewind()
        .map_err(|_| "Protected root receipt offset unavailable")?;
    let selected = selection(root)?;
    let (authority, catalog) =
        received_bundle::load_received_pinned_authority(&selected.nic_selection, selected.chain()?)
            .map_err(|_| "Protected prospective network pins unavailable")?;
    let report_pin =
        crate::r1_identity_custody::original_request_digest(&inspected.provider_report_sha256)?;
    let report = root.join("lib/apqe/build-report.json");
    // SAFETY: preflight authenticated the exact installed native package/report
    // pin. No caller-selected provider path or command-line report is accepted.
    let engine = unsafe {
        synergy_address_engine::apqe::native_manifest::managed_creation_engine(&report, report_pin)
    }
    .map_err(|_| "Qualified native root provider unavailable")?;
    catalog
        .validate_provider(&engine)
        .map_err(|_| "Root approval provider/catalog mismatch")?;
    let nic = match selected.stage {
        RootApprovalStage::Nic {} => None,
        RootApprovalStage::Formation { .. } | RootApprovalStage::Genesis { .. } => Some(
            received_bundle::load_received_nic_bundle(
                &selected.nic_selection,
                selected.chain()?,
                &engine,
            )
            .map_err(|_| "Genuine received NIC approval unavailable")?,
        ),
    };
    let auth = approval::VerifiedManagedRootApprovalAuthorization::from_controller_receipt(
        root,
        receipt,
        held,
        &authority,
        nic.as_ref().map(|n| n.approvals()),
    )
    .map_err(|_| "Native root approval authorization refused")?;
    if auth.native_request_digest() != expected || auth.stage() != &selected.stage {
        return Err("Original native root approval request/context differs".into());
    }
    let mut journal = NativeCustodyJournal::from_managed_root_approval(&auth)
        .map_err(|_| "Existing BootstrapRoot custody journal unavailable")?;
    let lease = journal
        .reserve_managed_root_approval(&auth)
        .map_err(|_| "Root approval conflict; reconcile the original operation")?;
    let (path, record) = journal
        .managed_root_approval_record(&lease)
        .map_err(|_| "Durable root approval reservation unavailable")?;
    let factor = crate::r1_identity_custody::proof_rebind::unlock_factor(
        root,
        &auth.creation_scope_commitment(),
        auth.key_generation(),
    )?;
    let signed = auth
        .consume_sign_approval(&engine, &path, record, factor.passphrase()?)
        .map_err(|_| "Root approval failed; original durable operation remains fenced")?;
    let result = journal
        .complete_managed_root_approval(&lease, signed)
        .map_err(|_| "Root completion CAS failed; reconcile original durable operation")?;
    drop(factor);
    Ok(result)
}

#[cfg(unix)]
#[derive(serde::Deserialize)]
struct Selection {
    chain_id: String,
    nic_selection: synergy_config::R1NicSelection,
    stage: synergy_address_engine::apqe::managed_creation::root_approval_use::RootApprovalStage,
}
#[cfg(unix)]
impl Selection {
    fn chain(&self) -> Result<u64, String> {
        let value = self
            .chain_id
            .parse::<u64>()
            .map_err(|_| "Canonical root approval chain required")?;
        if value == 0 || value.to_string() != self.chain_id {
            return Err("Canonical root approval chain required".into());
        }
        Ok(value)
    }
}
#[cfg(unix)]
fn selection(root: &Path) -> Result<Selection, String> {
    #[derive(serde::Deserialize)]
    struct Policy {
        format: String,
        root: String,
        community_enrollment: bool,
        qualified_operations: Vec<String>,
        r1_root_approval_use_context: Selection,
    }
    let bytes = synergy_genesis::r1::received_bundle::read_protected_managed_file(
        root,
        Path::new("tmp/controller/policy.json"),
        2 * 1024 * 1024,
    )
    .map_err(|_| "Protected root approval policy unavailable")?;
    let p: Policy =
        serde_json::from_slice(&bytes).map_err(|_| "Protected root approval policy differs")?;
    if p.format != "synergy-nodenetwork-host-policy-v1"
        || p.root != root.to_string_lossy()
        || p.community_enrollment
        || !p
            .qualified_operations
            .iter()
            .any(|s| s == "r1_root_approval_use")
        || p.r1_root_approval_use_context.nic_selection.managed_root != root
    {
        return Err("Native root approval policy scope differs".into());
    }
    p.r1_root_approval_use_context.chain()?;
    Ok(p.r1_root_approval_use_context)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_dispatch_refuses_before_context_provider_or_durable_output() {
        assert!(dispatch(&["another-command".into()]).unwrap().is_none());
        for fields in [
            vec![COMMAND.into()],
            vec![
                COMMAND.into(),
                "/missing-root".into(),
                "/missing-receipt".into(),
                "00".repeat(32),
                "extra".into(),
            ],
        ] {
            assert!(dispatch(&fields).is_err());
        }
        for digest in [
            String::new(),
            "00".repeat(32),
            "AB".repeat(32),
            "01".repeat(31),
            format!("{}\n", "01".repeat(32)),
            "01".repeat(32),
        ] {
            let fields = [
                COMMAND.into(),
                "/missing-root".into(),
                "/missing-receipt".into(),
                digest,
            ];
            assert!(dispatch(&fields).is_err());
        }
        assert!(!Path::new("/missing-root").exists());
        assert!(!Path::new("/missing-receipt").exists());
    }

    #[cfg(unix)]
    #[test]
    fn an_open_existing_file_cannot_replace_the_protected_native_receipt() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let path = root.join("Cargo.toml");
        let before = std::fs::read(&path).unwrap();
        let result = use_approval(root, &path, &"01".repeat(32));
        assert_eq!(
            result.err().as_deref(),
            Some("Native root approval preflight refused")
        );
        assert_eq!(std::fs::read(path).unwrap(), before);
    }

    #[test]
    fn missing_absolute_platform_root_is_not_verified_original_absence() {
        let root = "/PUBLIC-SYNTHETIC-NONEXISTENT-ROOT";
        assert!(!Path::new(root).exists());
        let args = [READ_COMMAND.into(), root.into(), "02".repeat(32), "01".repeat(32)];
        assert!(dispatch(&args).is_err());
        assert!(!Path::new(root).exists());
    }
}
