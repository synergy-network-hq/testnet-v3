//! Read-only bridge for an already admitted native NIC-only formation-use capability.
//! This never initializes custody, changes a stage, unlocks or returns secrets.
use super::*;
use synergy_address_engine::apqe::managed_creation::formation_use::VerifiedManagedFormationUseAuthorization;
impl NativeCustodyJournal {
    pub fn managed_formation_transport_record(
        auth: &VerifiedManagedFormationUseAuthorization,
    ) -> Result<(PathBuf, fs::File), CustodyJournalError> {
        auth.ensure_open_ceremony()
            .map_err(|_| CustodyJournalError::InvalidIntent)?;
        #[cfg(not(unix))]
        {
            let _ = auth;
            return Err(CustodyJournalError::PlatformUnqualified);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
            let root = auth.journal_root();
            let platform = auth.platform_root();
            if !platform.is_absolute()
                || !root.starts_with(platform)
                || root.canonicalize().ok().as_deref() != Some(root.as_path())
            {
                return Err(CustodyJournalError::Storage);
            }
            for p in root.ancestors().take_while(|p| p.starts_with(platform)) {
                let m = fs::symlink_metadata(p).map_err(|_| CustodyJournalError::Storage)?;
                if m.file_type().is_symlink()
                    || !m.is_dir()
                    || m.uid() != 0
                    || m.permissions().mode() & 0o022 != 0
                {
                    return Err(CustodyJournalError::Storage);
                }
            }
            let expected = encode(&(
                1u16,
                "NATIVE-MANAGED-CUSTODY-JOURNAL",
                Some((auth.network().chain_id, auth.network().nic.to_vec())),
            ))?;
            AtomicStore::inspect_existing_read_only(
                &root,
                MAX_RECORD,
                |reader| -> Result<(), CustodyJournalError> {
                    if reader
                        .with_maximum_bytes(4096)
                        .read_optional_bounded("context.json")
                        .map_err(|_| CustodyJournalError::Storage)?
                        .as_deref()
                        != Some(expected.as_slice())
                    {
                        return Err(CustodyJournalError::Conflict);
                    }
                    let b = reader
                        .read_optional_bounded(slot_path(auth.slot_ref()))
                        .map_err(|_| CustodyJournalError::Storage)?
                        .ok_or(CustodyJournalError::Conflict)?;
                    let r = decode(&b)?;
                    r.validate(Some(auth.network()))?;
                    let key = r.public_key.as_ref().ok_or(CustodyJournalError::Corrupt)?;
                    let p = auth.public_key_record();
                    if r.stage != CustodyStage::SealedPending
                        || r.slot_ref != auth.slot_ref()
                        || r.journal_generation != auth.expected_journal_generation()
                        || r.key_generation != auth.key_generation()
                        || r.role != auth.role()
                        || r.algorithm != auth.algorithm()
                        || r.native_request_digest.as_slice()
                            != auth.original_creation_request_digest()
                        || r.creation_scope_commitment.as_slice()
                            != auth.creation_scope_commitment()
                        || r.envelope_commitment.as_deref()
                            != Some(auth.expected_envelope_commitment().as_slice())
                        || r.full_binding_aad.as_deref() != Some(auth.full_binding_aad())
                        || key.role != p.role
                        || key.algorithm != p.algorithm
                        || key.key_generation != p.key_generation
                        || key.full_public_key != p.full_public_key
                    {
                        return Err(CustodyJournalError::Conflict);
                    }
                    Ok(())
                },
            )
            .map_err(|_| CustodyJournalError::Storage)?
            .ok_or(CustodyJournalError::Storage)??;
            auth.ensure_open_ceremony()
                .map_err(|_| CustodyJournalError::InvalidIntent)?;
            let path = root.join(slot_path(auth.slot_ref()));
            let file = fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
                .open(&path)
                .map_err(|_| CustodyJournalError::Storage)?;
            // The engine revalidates exact FD/path/inode, every pin and lifetime
            // again before secret opening; a concurrent replacement cannot unlock.
            Ok((path, file))
        }
    }
}
