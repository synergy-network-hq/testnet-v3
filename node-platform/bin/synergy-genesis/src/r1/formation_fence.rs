//! Consuming native preparation fence for the EXISTING formation AtomicStore.
//! No store initialization/recovery, new lock, phase permission or live authority.
//! A delivery callback MUST NOT acquire/write this same store: the canonical
//! cross-process writer lock is deliberately retained until the effect returns.
use super::{formation::VerifiedFormationAuthority, received_bundle::read_protected_managed_file};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};
use synergy_address_engine::apqe::{
    formation_channel::{
        FormationAuthority, FormationChannelError as Error, FormationContext, FormationFence,
    },
    preparation::require_nonproduction_fixture,
    HashAlgorithm, Primitives,
};
use synergy_storage::AtomicStore;
const MAX_REGISTRY: usize = 4 * 1024 * 1024;
/// Owns the genuine full Node/registration/root-approval factory result, not a
/// standalone root quorum, caller boolean or downloaded candidate digest.
pub struct PreparationFormationFence {
    owner: Arc<VerifiedFormationAuthority>,
    store_root: PathBuf,
    input_commitment: [u8; 64],
}
impl PreparationFormationFence {
    /// Native callers select their existing protected store root. This only
    /// permits isolated preparation coordinates, never an actual ceremony.
    pub fn new(store_root: PathBuf, owner: Arc<VerifiedFormationAuthority>) -> Result<Self, Error> {
        let registry = owner.registry();
        require_nonproduction_fixture(registry.network().chain_id).map_err(|_| Error::Closed)?;
        let input = registry.preseed_frame().map_err(|_| Error::Authority)?;
        // Independently consume the exact private root-purpose token + originals.
        let channel = FormationAuthority::from_approved_registry(
            owner.approvals(),
            registry.canonical_bytes(),
            &input,
        )?;
        let input_commitment = *channel.input_commitment();
        let protected = read_protected_managed_file(
            &store_root,
            &registry.storage_relative_root().join("registry.cbor"),
            MAX_REGISTRY as u64,
        )
        .map_err(|_| Error::Closed)?;
        if protected != registry.canonical_bytes() {
            return Err(Error::Context);
        }
        Ok(Self {
            owner,
            store_root,
            input_commitment,
        })
    }
}
impl FormationFence for PreparationFormationFence {
    fn with_open(
        &self,
        channel: &FormationAuthority<'_>,
        context: &FormationContext,
        effect: &mut dyn FnMut() -> Result<(), Error>,
    ) -> Result<(), Error> {
        let registry = self.owner.registry();
        require_nonproduction_fixture(registry.network().chain_id).map_err(|_| Error::Closed)?;
        with_open_storage(
            &self.store_root,
            &registry.storage_relative_root(),
            registry.canonical_bytes(),
            &mut || {
                if channel.network() != registry.network()
                    || channel.profiles() != registry.activated_profiles()
                    || channel.registry_commitment() != registry.commitment()
                    || channel.input_commitment() != &self.input_commitment
                    || channel.target_epoch() != 1
                {
                    return Err(Error::Context);
                }
                FormationContext::new(channel, *context.initiator(), *context.responder())?;
                // The original input remains frozen by the owned verified authority;
                // this check cannot be replaced by a caller's asserted scope digest.
                let input = registry.preseed_frame().map_err(|_| Error::Authority)?;
                let hash = Primitives
                    .hash(HashAlgorithm::Sha3512, &input)
                    .map_err(|_| Error::Provider)?;
                if hash.as_slice() != self.input_commitment {
                    return Err(Error::Context);
                }
                effect()
            },
        )
    }
}
fn with_open_storage(
    root: &Path,
    base: &Path,
    canonical: &[u8],
    effect: &mut dyn FnMut() -> Result<(), Error>,
) -> Result<(), Error> {
    // Existing API holds the SAME canonical writer flock used by retirement
    // CAS through the entire closure, and refuses pending WAL rather than replay.
    AtomicStore::inspect_existing_read_only(root, MAX_REGISTRY, |reader| {
        let stored = reader
            .read_optional_bounded(base.join("registry.cbor"))
            .map_err(|_| Error::Closed)?;
        if stored.as_deref() != Some(canonical) {
            return Err(Error::Context);
        }
        if reader
            .read_optional_bounded(base.join("retired.bin"))
            .map_err(|_| Error::Closed)?
            .is_some()
        {
            return Err(Error::Closed);
        }
        // Reuse the existing protected descriptor reader rather than introducing
        // weaker file/path ownership checks in this adapter.
        let protected =
            read_protected_managed_file(root, &base.join("registry.cbor"), MAX_REGISTRY as u64)
                .map_err(|_| Error::Closed)?;
        if protected != canonical {
            return Err(Error::Context);
        }
        effect()
    })
    .map_err(|_| Error::Closed)?
    .ok_or(Error::Closed)?
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::{
        fs,
        os::unix::fs::PermissionsExt,
        sync::{
            atomic::{AtomicU64, Ordering},
            mpsc,
        },
        time::Duration,
    };
    use synergy_storage::StorageTransaction;
    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            static N: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "synergy-formation-fence-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            // macOS temp_dir may start with the /var or /tmp symlink.
            // Tests supply the real created root to the strict no-follow reader;
            // production protected-path validation is deliberately unchanged.
            Self(fs::canonicalize(path).unwrap())
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn put(store: &mut AtomicStore, path: PathBuf, bytes: &[u8]) {
        let mut tx = StorageTransaction::new(4096).unwrap();
        tx.put(path, bytes.to_vec()).unwrap();
        tx.commit(store).unwrap();
    }
    #[test]
    fn no_init_registry_drift_or_retirement_can_deliver() {
        let tmp = Temp::new();
        let absent = tmp.0.join("not-initialized");
        let base = Path::new("formation-r1/synthetic-only");
        let mut calls = 0;
        assert!(with_open_storage(&absent, base, b"registry", &mut || {
            calls += 1;
            Ok(())
        })
        .is_err());
        assert!(!absent.exists());
        let mut store = AtomicStore::new(&tmp.0, 4096).unwrap();
        put(&mut store, base.join("registry.cbor"), b"registry");
        assert!(with_open_storage(&tmp.0, base, b"different", &mut || {
            calls += 1;
            Ok(())
        })
        .is_err());
        with_open_storage(&tmp.0, base, b"registry", &mut || {
            calls += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(calls, 1);
        put(&mut store, base.join("retired.bin"), b"test-only closure");
        assert!(with_open_storage(&tmp.0, base, b"registry", &mut || {
            calls += 1;
            Ok(())
        })
        .is_err());
        assert_eq!(calls, 1);
    }
    #[test]
    fn actual_writer_cannot_retire_between_check_and_effect() {
        let tmp = Temp::new();
        let base = PathBuf::from("formation-r1/synthetic-only");
        let mut writer = AtomicStore::new(&tmp.0, 4096).unwrap();
        put(&mut writer, base.join("registry.cbor"), b"registry");
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let (retired_tx, retired_rx) = mpsc::channel();
        let (writer_started_tx, writer_started_rx) = mpsc::channel();
        let root = tmp.0.clone();
        let read_base = base.clone();
        let delivery = std::thread::spawn(move || {
            with_open_storage(&root, &read_base, b"registry", &mut || {
                entered_tx.send(()).unwrap();
                release_rx.recv_timeout(Duration::from_secs(3)).unwrap();
                Ok(())
            })
        });
        entered_rx.recv_timeout(Duration::from_secs(3)).unwrap();
        let retirement = std::thread::spawn(move || {
            writer_started_tx.send(()).unwrap();
            put(&mut writer, base.join("retired.bin"), b"test-only closure");
            retired_tx.send(()).unwrap();
        });
        writer_started_rx
            .recv_timeout(Duration::from_secs(3))
            .unwrap();
        assert!(matches!(
            retired_rx.recv_timeout(Duration::from_millis(50)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
        release_tx.send(()).unwrap();
        delivery.join().unwrap().unwrap();
        retired_rx.recv_timeout(Duration::from_secs(3)).unwrap();
        retirement.join().unwrap();
        assert!(with_open_storage(
            &tmp.0,
            Path::new("formation-r1/synthetic-only"),
            b"registry",
            &mut || panic!("retired delivery")
        )
        .is_err());
    }
}
