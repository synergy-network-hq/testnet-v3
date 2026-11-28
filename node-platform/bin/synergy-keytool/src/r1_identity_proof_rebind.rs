//! Existing protected native operations joined to the sole APQE capability and
//! durable custody owners. No public plan, CLI flag or JSON result supplies
//! authority. Return only Root's committed original-public-result token.
use std::path::Path;
use synergy_address::r1_custody::{CompletedIdentityProof, CompletedIdentityRebind};

#[cfg(unix)]
use std::{
    fs::{File, OpenOptions},
    io::{Read, Seek},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
};
#[cfg(unix)]
use synergy_address_engine::apqe::{managed_creation::identity_proof as proof, SecretBytes};

pub(crate) const PROVE_COMMAND: &str = "prove-managed-r1-identity";
pub(crate) const READ_PROOF_COMMAND: &str = "read-managed-r1-identity-proof-result";
pub(crate) const READ_REBIND_COMMAND: &str = "read-managed-r1-identity-rebind-result";
pub(crate) const REBIND_COMMAND: &str = "rebind-managed-r1-identity";
/// Contains only the existing durable owner's private completion tokens.
pub(crate) enum DurableIdentityResult {
    Absent,
    Proof(CompletedIdentityProof),
    Rebind(CompletedIdentityRebind),
}
impl DurableIdentityResult {
    pub(crate) fn canonical_public_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Absent => None,
            Self::Proof(r) => Some(r.canonical_public_bytes()),
            Self::Rebind(r) => Some(r.canonical_public_bytes()),
        }
    }
}
pub(crate) fn dispatch(arguments: &[String]) -> Result<Option<DurableIdentityResult>, String> {
    match arguments.first().map(String::as_str) {
        Some(READ_PROOF_COMMAND | READ_REBIND_COMMAND) => {
            let [command, root, nonce, request] = arguments else {
                return Err(
                    "Exact original result ROOT NONCE ORIGINAL_REQUEST_SHA256 required".into(),
                );
            };
            read_original(
                Path::new(root),
                nonce,
                request,
                command == READ_REBIND_COMMAND,
            )
            .map(Some)
        }
        Some(PROVE_COMMAND | REBIND_COMMAND) => {
            let [command, root, receipt, request] = arguments else {
                return Err(
                    "Exact native identity command ROOT RECEIPT ORIGINAL_REQUEST_SHA256 required"
                        .into(),
                );
            };
            let root = Path::new(root);
            let receipt = Path::new(receipt);
            if command == PROVE_COMMAND {
                prove(root, receipt, request)
                    .map(DurableIdentityResult::Proof)
                    .map(Some)
            } else {
                rebind(root, receipt, request)
                    .map(DurableIdentityResult::Rebind)
                    .map(Some)
            }
        }
        _ => Ok(None),
    }
}

fn read_original(
    root: &Path,
    nonce: &str,
    request: &str,
    rebind: bool,
) -> Result<DurableIdentityResult, String> {
    use synergy_address::r1_custody::NativeCustodyJournal;
    let nonce = super::original_request_digest(nonce)?;
    let request = super::original_request_digest(request)?;
    let context = crate::r1_identity_context::load_for_observation(root)?;
    let network = context
        .network()
        .ok_or("Original identity result requires authenticated network context")?;
    if rebind {
        NativeCustodyJournal::inspect_managed_completed_rebind_in_network(
            root, network, &nonce, &request,
        )
        .map(|r| {
            r.map(DurableIdentityResult::Rebind)
                .unwrap_or(DurableIdentityResult::Absent)
        })
        .map_err(|_| {
            "Original rebind result unavailable; reconcile existing durable operation".into()
        })
    } else {
        NativeCustodyJournal::inspect_managed_completed_proof_in_network(
            root, network, &nonce, &request,
        )
        .map(|r| {
            r.map(DurableIdentityResult::Proof)
                .unwrap_or(DurableIdentityResult::Absent)
        })
        .map_err(|_| {
            "Original proof result unavailable; reconcile existing durable operation".into()
        })
    }
}

#[cfg(unix)]
fn receipt(
    root: &Path,
    path: &Path,
    request: &str,
    rebind: bool,
) -> Result<(File, [u8; 32]), String> {
    let expected = super::original_request_digest(request)?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| "Protected native operation receipt unavailable")?;
    let duplicate = file
        .try_clone()
        .map_err(|_| "Protected native receipt unavailable")?;
    if rebind {
        proof::preflight_controller_rebind_receipt(root, path, duplicate, expected)
    } else {
        proof::preflight_controller_proof_receipt(root, path, duplicate, expected)
    }
    .map_err(|_| "Native identity operation preflight refused")?;
    // Cloned descriptors share offset; APQE rechecks the same held descriptor.
    file.rewind()
        .map_err(|_| "Protected native receipt offset unavailable")?;
    Ok((file, expected))
}

/// No raw engine receipt is returned. A failed durable completion remains
/// fenced for the existing native reconciliation workflow, never retried here.
#[cfg(unix)]
pub(crate) fn prove(
    root: &Path,
    receipt_path: &Path,
    request: &str,
) -> Result<CompletedIdentityProof, String> {
    use crate::r1_identity_context::{self, NativeContext};
    use synergy_address::r1_custody::NativeCustodyJournal;
    let (file, expected) = receipt(root, receipt_path, request, false)?;
    let context = r1_identity_context::load_for_operation(
        root,
        r1_identity_context::NativeIdentityOperation::Prove,
    )?;
    let auth = match &context {
        NativeContext::Initial(nic) => {
            proof::VerifiedManagedProofAuthorization::from_controller_receipt_for_initial(
                root,
                receipt_path,
                file,
                nic.approvals(),
            )
        }
        NativeContext::Runtime(genesis) => {
            proof::VerifiedManagedProofAuthorization::from_controller_receipt_for_runtime(
                root,
                receipt_path,
                file,
                genesis.nic_approvals(),
                genesis.genesis_approvals(),
            )
        }
        NativeContext::Bootstrap | NativeContext::Formation(_) => {
            return Err(
                "Identity proof requires the exact initial or runtime identity purpose".into(),
            )
        }
    }
    .map_err(|_| "Native identity proof authorization refused")?;
    if auth.native_request_digest() != expected {
        return Err("Original native proof request differs".into());
    }
    let mut journal = NativeCustodyJournal::from_managed_proof(&auth)
        .map_err(|_| "Existing native custody journal unavailable")?;
    let lease = journal
        .reserve_managed_proof(&auth)
        .map_err(|_| "Proof generation conflict; reconcile original operation")?;
    let (path, record) = journal
        .managed_proof_record(&lease)
        .map_err(|_| "Durable proof reservation unavailable")?;
    let factor = unlock_factor(
        root,
        &auth.creation_scope_commitment(),
        auth.key_generation(),
    )?;
    let report = root.join("lib/apqe/build-report.json");
    // SAFETY: the private APQE authorization independently checked the installed
    // immutable package/report pin. Root has durably reserved the exact plan.
    let engine = unsafe {
        synergy_address_engine::apqe::native_manifest::managed_creation_engine(
            &report,
            auth.provider_report_sha256(),
        )
    }
    .map_err(|_| "Qualified native identity provider unavailable")?;
    let signed = auth
        .consume_sign_exact_plan(&engine, &path, record, factor.passphrase()?)
        .map_err(|_| "Native identity proof failed; durable operation remains fenced")?;
    let completed = journal
        .complete_managed_proof(&lease, signed)
        .map_err(|_| "Proof completion CAS failed; reconcile original durable operation")?;
    drop(factor);
    Ok(completed)
}

/// Same existing key/generation, with authenticated final Genesis in target AAD.
/// Retains the existing protected unlock factor; generates no replacement key or
/// factor, exports no envelope, and confers no runtime signing/activation right.
#[cfg(unix)]
pub(crate) fn rebind(
    root: &Path,
    receipt_path: &Path,
    request: &str,
) -> Result<CompletedIdentityRebind, String> {
    use crate::r1_identity_context::{self, NativeContext};
    use synergy_address::r1_custody::NativeCustodyJournal;
    let (file, expected) = receipt(root, receipt_path, request, true)?;
    let context = r1_identity_context::load_for_operation(
        root,
        r1_identity_context::NativeIdentityOperation::Rebind,
    )?;
    let NativeContext::Runtime(genesis) = &context else {
        return Err("Identity rebind requires independently verified final Genesis".into());
    };
    let auth = proof::VerifiedManagedRebindAuthorization::from_controller_receipt(
        root,
        receipt_path,
        file,
        genesis.nic_approvals(),
        genesis.genesis_approvals(),
    )
    .map_err(|_| "Native identity rebind authorization refused")?;
    if auth.native_request_digest() != expected {
        return Err("Original native rebind request differs".into());
    }
    let mut journal = NativeCustodyJournal::from_managed_rebind(&auth)
        .map_err(|_| "Existing native custody journal unavailable")?;
    let lease = journal
        .reserve_managed_rebind(&auth)
        .map_err(|_| "Rebind generation conflict; reconcile original operation")?;
    let (path, record) = journal
        .managed_rebind_record(&lease)
        .map_err(|_| "Durable rebind reservation unavailable")?;
    let factor = unlock_factor(
        root,
        &auth.creation_scope_commitment(),
        auth.key_generation(),
    )?;
    let report = root.join("lib/apqe/build-report.json");
    // SAFETY: same private authenticated immutable-package contract as prove.
    let engine = unsafe {
        synergy_address_engine::apqe::native_manifest::managed_creation_engine(
            &report,
            auth.provider_report_sha256(),
        )
    }
    .map_err(|_| "Qualified native identity provider unavailable")?;
    let passphrase = factor.passphrase()?;
    let sealed = auth
        .consume_rebind_same_key(&engine, &path, record, passphrase, passphrase)
        .map_err(|_| "Native identity rebind failed; durable operation remains fenced")?;
    let completed = journal
        .complete_managed_rebind(&lease, sealed)
        .map_err(|_| "Rebind completion CAS failed; reconcile original durable operation")?;
    drop(factor);
    Ok(completed)
}

#[cfg(not(unix))]
pub(crate) fn prove(_: &Path, _: &Path, _: &str) -> Result<CompletedIdentityProof, String> {
    Err("Native identity proof protection is unqualified on this platform".into())
}
#[cfg(not(unix))]
pub(crate) fn rebind(_: &Path, _: &Path, _: &str) -> Result<CompletedIdentityRebind, String> {
    Err("Native identity rebind protection is unqualified on this platform".into())
}

#[cfg(unix)]
pub(crate) struct HeldUnlockFactor {
    _file: File,
    bytes: SecretBytes,
}
#[cfg(unix)]
impl HeldUnlockFactor {
    pub(crate) fn passphrase(&self) -> Result<&str, String> {
        std::str::from_utf8(self.bytes.as_bytes())
            .map_err(|_| "Native unlock factor encoding differs".into())
    }
}
#[cfg(unix)]
fn read_factor_bytes(reader: &mut impl Read) -> Result<SecretBytes, String> {
    let mut bytes = Vec::with_capacity(65);
    let read = reader.take(65).read_to_end(&mut bytes);
    // Own even partial failed reads before inspecting the result. Drop wipes it.
    let bytes = SecretBytes::from_bytes(bytes);
    read.map_err(|_| "Native unlock factor unavailable")?;
    if bytes.as_bytes().len() != 64
        || !bytes
            .as_bytes()
            .iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
    {
        return Err("Native unlock factor encoding differs".into());
    }
    Ok(bytes)
}
#[cfg(unix)]
pub(crate) fn unlock_factor(
    root: &Path,
    scope: &[u8; 64],
    generation: u64,
) -> Result<HeldUnlockFactor, String> {
    if generation == 0 || scope == &[0; 64] || root.canonicalize().ok().as_deref() != Some(root) {
        return Err("Protected native unlock scope differs".into());
    }
    let mut directory = root.to_owned();
    for component in ["keys", "apqe", "r1", "unlock"] {
        directory.push(component);
        let m = std::fs::symlink_metadata(&directory)
            .map_err(|_| "Protected native unlock directory unavailable")?;
        if !m.is_dir() || m.file_type().is_symlink() || m.uid() != 0 || m.mode() & 0o022 != 0 {
            return Err("Protected native unlock directory differs".into());
        }
    }
    let scope: String = scope.iter().map(|b| format!("{b:02x}")).collect();
    let path = directory.join(format!("{scope}-{generation}.factor"));
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(&path)
        .map_err(|_| "Protected native unlock factor unavailable")?;
    let valid = |m: &std::fs::Metadata| {
        m.is_file() && m.uid() == 0 && m.nlink() == 1 && m.mode() & 0o777 == 0o600 && m.len() == 64
    };
    let before = file
        .metadata()
        .map_err(|_| "Protected native unlock factor unavailable")?;
    if !valid(&before) {
        return Err("Protected native unlock factor differs".into());
    }
    let bytes = read_factor_bytes(&mut file)?;
    let after = std::fs::symlink_metadata(&path)
        .map_err(|_| "Protected native unlock factor unavailable")?;
    if !valid(&after) || before.dev() != after.dev() || before.ino() != after.ino() {
        return Err("Protected native unlock factor changed".into());
    }
    Ok(HeldUnlockFactor { _file: file, bytes })
}

#[cfg(test)]
#[path = "r1_identity_proof_rebind_tests.rs"]
mod tests;
