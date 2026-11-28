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
/// Actual NIC-only native use bridge. The lease can only originate in the
/// existing protected native issuer; the independent Core owner additionally
/// proves every Node/registration/controller/Root approval in the full registry.
/// Retaining this read-only lease cannot unlock a key or issue a ceremony.
pub struct ManagedFormationFence {
    owner: Arc<VerifiedFormationAuthority>,
    lease: synergy_address_engine::apqe::managed_creation::formation_use::ManagedFormationUseFence,
}
impl ManagedFormationFence {
    pub fn new(
        auth: &synergy_address_engine::apqe::managed_creation::formation_use::VerifiedManagedFormationUseAuthorization,
        owner: Arc<VerifiedFormationAuthority>,
    ) -> Result<Self, Error> {
        let lease = auth.fence_lease();
        let out = Self { owner, lease };
        out.check_owner()?;
        // No initialize/recover, new lock, substitute store or phase transition.
        let r = out.owner.registry();
        with_open_storage(
            &out.lease.formation_store_root(),
            &r.storage_relative_root(),
            r.canonical_bytes(),
            &mut || out.lease.ensure_current().map_err(|_| Error::Closed),
        )?;
        Ok(out)
    }
    fn check_owner(&self) -> Result<(), Error> {
        self.lease.ensure_current().map_err(|_| Error::Closed)?;
        let r = self.owner.registry();
        if self.lease.network() != r.network()
            || &self.lease.activated_profiles() != r.activated_profiles()
            || &self.lease.registry_commitment() != r.commitment()
            || self.lease.input_commitment()
                != r.preseed_commitment().map_err(|_| Error::Authority)?
            || self.lease.target_epoch() != 1
        {
            return Err(Error::Context);
        }
        let entry = r
            .registrations()
            .iter()
            .find(|entry| entry.node.identity == self.lease.participant_id())
            .ok_or(Error::Participant)?;
        let id = entry
            .node
            .validate_birth(r.network())
            .map_err(|_| Error::Authority)?;
        let actual = &entry.formation_key;
        let expected = self.lease.public_key_record();
        if id.raw48() != self.lease.participant_raw48()
            || actual.role != expected.role
            || actual.algorithm != synergy_address_engine::types::Algorithm::MlDsa87
            || actual.generation != expected.key_generation
            || actual.public_key != expected.full_public_key
        {
            return Err(Error::Context);
        }
        Ok(())
    }
}
impl FormationFence for ManagedFormationFence {
    fn with_open(
        &self,
        channel: &FormationAuthority<'_>,
        context: &FormationContext,
        effect: &mut dyn FnMut() -> Result<(), Error>,
    ) -> Result<(), Error> {
        self.check_owner()?;
        let r = self.owner.registry();
        with_open_storage(
            &self.lease.formation_store_root(),
            &r.storage_relative_root(),
            r.canonical_bytes(),
            &mut || {
                // Retirement takes the SAME writer lock and cannot cross this
                // closure. The native policy/expiry check is shared with APQE,
                // including its original monotonic deadline (no renewed grant).
                self.lease.ensure_current().map_err(|_| Error::Closed)?;
                if channel.network() != r.network()
                    || channel.profiles() != r.activated_profiles()
                    || channel.registry_commitment() != r.commitment()
                    || channel.input_commitment() != &self.lease.input_commitment()
                    || channel.target_epoch() != 1
                    || (context.initiator() != self.lease.participant_raw48()
                        && context.responder() != self.lease.participant_raw48())
                {
                    return Err(Error::Context);
                }
                FormationContext::new(channel, *context.initiator(), *context.responder())?;
                let peer = channel.participant(self.lease.participant_raw48())?;
                let expected = self.lease.public_key_record();
                if peer.key_generation() != expected.key_generation
                    || peer.public_key() != expected.full_public_key
                {
                    return Err(Error::Context);
                }
                effect()?;
                self.lease.ensure_current().map_err(|_| Error::Closed)
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
