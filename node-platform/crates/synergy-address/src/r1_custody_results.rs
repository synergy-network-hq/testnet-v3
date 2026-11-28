//! Read-only reconciliation of original public proof/rebind results. Never
//! consumes a new grant, initializes/recovers a store, opens a key or re-signs.
use super::*;
impl NativeCustodyJournal {
    pub fn inspect_managed_completed_proof_in_network(
        platform_root: &Path,
        network: NetworkRef,
        nonce: &[u8; 32],
        request: &[u8; 32],
    ) -> Result<Option<CompletedIdentityProof>, CustodyJournalError> {
        inspect(platform_root, Some(network), |reader| {
            super::read_completed_proof(reader, nonce, request)
        })
    }
    pub fn inspect_managed_completed_rebind_in_network(
        platform_root: &Path,
        network: NetworkRef,
        nonce: &[u8; 32],
        request: &[u8; 32],
    ) -> Result<Option<CompletedIdentityRebind>, CustodyJournalError> {
        inspect(platform_root, Some(network), |reader| {
            super::rebind::read_completed_rebind(reader, nonce, request)
        })
    }
}
pub(super) fn inspect<T>(
    platform_root: &Path,
    network: Option<NetworkRef>,
    read: impl FnOnce(&synergy_storage::AtomicStoreReader<'_>) -> Result<Option<T>, CustodyJournalError>,
) -> Result<Option<T>, CustodyJournalError> {
    if !platform_root.is_absolute() || network.is_some_and(|n| n.chain_id == 0) {
        return Err(CustodyJournalError::InvalidIntent);
    }
    let root = platform_root.join(
        synergy_address_engine::apqe::managed_creation::managed_journal_relative_root(network),
    );
    match fs::symlink_metadata(&root) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(CustodyJournalError::Storage),
        Ok(_) => {}
    }
    #[cfg(not(unix))]
    {
        let _ = read;
        Err(CustodyJournalError::PlatformUnqualified)
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if root.canonicalize().ok().as_deref() != Some(root.as_path()) {
            return Err(CustodyJournalError::Storage);
        }
        for path in root
            .ancestors()
            .take_while(|p| p.starts_with(platform_root))
        {
            let m = fs::symlink_metadata(path).map_err(|_| CustodyJournalError::Storage)?;
            if m.file_type().is_symlink()
                || !m.is_dir()
                || m.uid() != 0
                || m.permissions().mode() & 0o022 != 0
            {
                return Err(CustodyJournalError::Storage);
            }
        }
        inspect_existing(&root, network, read)
    }
}
fn inspect_existing<T>(
    root: &Path,
    network: Option<NetworkRef>,
    read: impl FnOnce(&synergy_storage::AtomicStoreReader<'_>) -> Result<Option<T>, CustodyJournalError>,
) -> Result<Option<T>, CustodyJournalError> {
    AtomicStore::inspect_existing_read_only(root, MAX_RECORD, |reader| {
        let expected = encode(&(
            1u16,
            "NATIVE-MANAGED-CUSTODY-JOURNAL",
            network.map(|n| (n.chain_id, n.nic.to_vec())),
        ))?;
        if reader
            .with_maximum_bytes(4096)
            .read_optional_bounded("context.json")
            .map_err(|_| CustodyJournalError::Storage)?
            .as_deref()
            != Some(expected.as_slice())
        {
            return Err(CustodyJournalError::Conflict);
        }
        read(reader)
    })
    .map_err(|_| CustodyJournalError::Storage)?
    .transpose()
    .map(Option::flatten)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn public_original_lookup_does_not_create_missing_journal() {
        let root = std::env::temp_dir().join(format!(
            "no-native-proof-result-root-{}",
            std::process::id()
        ));
        assert!(NativeCustodyJournal::inspect_managed_completed_root_approval(&root, &[1;32], &[2;32]).unwrap().is_none());
        assert!(!root.exists());
        let n = NetworkRef {
            chain_id: u64::MAX - 1,
            nic: [17; 64],
        };
        assert!(
            NativeCustodyJournal::inspect_managed_completed_proof_in_network(
                &root, n, &[1; 32], &[2; 32]
            )
            .unwrap()
            .is_none()
        );
        assert!(
            NativeCustodyJournal::inspect_managed_completed_rebind_in_network(
                &root, n, &[1; 32], &[2; 32]
            )
            .unwrap()
            .is_none()
        );
        assert!(!root.exists());
        assert!(
            NativeCustodyJournal::inspect_managed_completed_proof_in_network(
                Path::new("relative-root"),
                n,
                &[1; 32],
                &[2; 32]
            )
            .is_err()
        );
    }
    #[test]
    fn storage_only_context_and_ambiguous_marker_do_not_become_absence() {
        struct Temp(PathBuf);
        impl Drop for Temp {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        let root = std::env::temp_dir().join(format!(
            "public-original-result-context-{}",
            std::process::id()
        ));
        fs::create_dir(&root).unwrap();
        let temp = Temp(root);
        let n = NetworkRef {
            chain_id: u64::MAX - 1,
            nic: [31; 64],
        };
        let mut store = AtomicStore::new(&temp.0, MAX_RECORD).unwrap();
        let marker = encode(&(
            1u16,
            "NATIVE-MANAGED-CUSTODY-JOURNAL",
            Some((n.chain_id, n.nic.to_vec())),
        ))
        .unwrap();
        let mut tx = StorageTransaction::new(MAX_RECORD).unwrap();
        tx.put("context.json", marker).unwrap();
        tx.commit(&mut store).unwrap();
        assert!(
            inspect_existing(&temp.0, Some(n), |r| super::super::read_completed_proof(
                r, &[1; 32], &[2; 32]
            ))
            .unwrap()
            .is_none()
        );
        let mut wrong = n;
        wrong.nic[63] ^= 1;
        assert!(matches!(
            inspect_existing(
                &temp.0,
                Some(wrong),
                |r| super::super::read_completed_proof(r, &[1; 32], &[2; 32])
            ),
            Err(CustodyJournalError::Conflict)
        ));
        assert!(matches!(inspect_existing(&temp.0, None,
            |r| super::super::root_approval::read_completed_root_approval(r, &[1;32], &[2;32])),
            Err(CustodyJournalError::Conflict)));
        let mut tx = StorageTransaction::new(MAX_RECORD).unwrap();
        tx.put(
            format!("proof-operations/{}.json", hex(&[1; 32])),
            b"{}".to_vec(),
        )
        .unwrap();
        tx.commit(&mut store).unwrap();
        assert!(matches!(
            inspect_existing(&temp.0, Some(n), |r| super::super::read_completed_proof(
                r, &[1; 32], &[2; 32]
            )),
            Err(CustodyJournalError::AmbiguousProof)
        ));
        let mut tx = StorageTransaction::new(MAX_RECORD).unwrap();
        tx.put(
            format!("rebind-operations/{}.json", hex(&[1; 32])),
            b"{}".to_vec(),
        )
        .unwrap();
        tx.commit(&mut store).unwrap();
        assert!(matches!(
            inspect_existing(&temp.0, Some(n), |r| {
                super::super::rebind::read_completed_rebind(r, &[1; 32], &[2; 32])
            }),
            Err(CustodyJournalError::AmbiguousRebind)
        ));
    }
}
