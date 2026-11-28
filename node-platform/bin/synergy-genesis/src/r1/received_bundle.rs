//! One read-only installed-artifact parser for node/keytool managed consumers.
//! The existing native release/controller owns authentication of configuration
//! pins. A successful parse/quorum is never commissioning or creation authority.
mod nic;
use super::{profiles::ProfileCatalog, VerifiedR1Genesis};
pub use nic::{load_received_nic_bundle, VerifiedR1NicBundle};
use serde::Deserialize;
use std::{
    path::{Component, Path},
    sync::Arc,
};
use synergy_address_engine::apqe::{
    bootstrap_approvals_r1::{IndexedRootApproval, PinnedBootstrapAuthority, PinnedBootstrapInput},
    crypto_engine::CryptoEngine,
    network_birth_r1::{BootstrapKeyRecord, NetworkBirth, ProfileRef},
    HashAlgorithm, Primitives,
};
use synergy_config::R1GenesisSelection;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BundleError {
    Selection,
    Path,
    Protection,
    UnsupportedPlatform,
    Bounds,
    Read,
    Encoding,
    Integrity,
    Context,
    Catalog,
    Approval,
}
impl std::fmt::Display for BundleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "received R1 bundle rejected: {self:?}")
    }
}
impl std::error::Error for BundleError {}
fn hex<const N: usize>(s: &str) -> Result<[u8; N], BundleError> {
    if s.len() != N * 2
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(BundleError::Encoding);
    }
    let mut out = [0; N];
    for (i, v) in out.iter_mut().enumerate() {
        *v = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).map_err(|_| BundleError::Encoding)?;
    }
    Ok(out)
}
fn normal_components(path: &Path) -> Result<Vec<&std::ffi::OsStr>, BundleError> {
    if path.as_os_str().is_empty() || path.is_absolute() {
        return Err(BundleError::Path);
    }
    let parts = path
        .components()
        .map(|p| match p {
            Component::Normal(s) => Ok(s),
            _ => Err(BundleError::Path),
        })
        .collect::<Result<Vec<_>, _>>()?;
    if parts.len() > 16
        || parts.iter().any(|p| {
            p.to_str().is_none_or(|s| {
                s.is_empty()
                    || s.starts_with("._")
                    || s.contains(['\\', ':'])
                    || s.chars().any(char::is_control)
            })
        })
    {
        return Err(BundleError::Path);
    }
    // Components normalizes an embedded `.`; reject that original spelling too.
    if path
        .to_str()
        .is_none_or(|s| s.split('/').any(|p| p.is_empty() || p == "." || p == ".."))
    {
        return Err(BundleError::Path);
    }
    Ok(parts)
}

/// Hold an exact root descriptor for all reads. No path resolution followed by
/// a second pathname open, no database creation/recovery or secret/provider use.
#[cfg(unix)]
struct ProtectedRoot(std::fs::File);
#[cfg(unix)]
impl ProtectedRoot {
    fn open(root: &Path) -> Result<Self, BundleError> {
        use std::os::{
            fd::{AsRawFd, FromRawFd},
            unix::ffi::OsStrExt,
        };
        if !root.is_absolute() {
            return Err(BundleError::Path);
        }
        let mut current = std::fs::File::open("/").map_err(|_| BundleError::Read)?;
        let mut count = 0;
        for component in root.components() {
            let Component::Normal(name) = component else {
                if component == Component::RootDir {
                    continue;
                } else {
                    return Err(BundleError::Path);
                }
            };
            count += 1;
            if count > 64 {
                return Err(BundleError::Bounds);
            }
            let name = std::ffi::CString::new(name.as_bytes()).map_err(|_| BundleError::Path)?;
            // SAFETY: borrowed descriptor and NUL-terminated single component;
            // returned descriptor is uniquely owned and immediately RAII-closed.
            let fd = unsafe {
                libc::openat(
                    current.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                return Err(BundleError::Path);
            }
            current = unsafe { std::fs::File::from_raw_fd(fd) };
        }
        if count == 0 {
            return Err(BundleError::Path);
        }
        protected(&current, true)?;
        Ok(Self(current))
    }
    fn open_file(&self, path: &Path, max: u64) -> Result<std::fs::File, BundleError> {
        use std::os::{
            fd::{AsRawFd, FromRawFd},
            unix::ffi::OsStrExt,
        };
        let parts = normal_components(path)?;
        let mut current = self.0.try_clone().map_err(|_| BundleError::Read)?;
        for (i, part) in parts.iter().enumerate() {
            let directory = i + 1 < parts.len();
            let name = std::ffi::CString::new(part.as_bytes()).map_err(|_| BundleError::Path)?;
            let flags = libc::O_RDONLY
                | libc::O_NOFOLLOW
                | libc::O_CLOEXEC
                | if directory {
                    libc::O_DIRECTORY
                } else {
                    libc::O_NONBLOCK
                };
            let fd = unsafe { libc::openat(current.as_raw_fd(), name.as_ptr(), flags) };
            if fd < 0 {
                return Err(BundleError::Path);
            }
            current = unsafe { std::fs::File::from_raw_fd(fd) };
            protected(&current, directory)?;
        }
        let metadata = current.metadata().map_err(|_| BundleError::Read)?;
        if metadata.len() == 0 || metadata.len() > max {
            return Err(BundleError::Bounds);
        }
        Ok(current)
    }
    fn read(&self, path: &Path, max: u64) -> Result<Vec<u8>, BundleError> {
        use std::io::Read;
        let current = self.open_file(path, max)?;
        let metadata = current.metadata().map_err(|_| BundleError::Read)?;
        let mut bytes = Vec::new();
        current
            .take(max + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| BundleError::Read)?;
        if bytes.len() as u64 != metadata.len() {
            return Err(BundleError::Read);
        }
        Ok(bytes)
    }
}
#[cfg(unix)]
fn protected(file: &std::fs::File, directory: bool) -> Result<(), BundleError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let m = file.metadata().map_err(|_| BundleError::Read)?;
    if (directory && !m.is_dir())
        || (!directory && !m.is_file())
        || m.permissions().mode() & 0o022 != 0
        || (m.uid() != 0 && m.uid() != unsafe { libc::geteuid() })
    {
        return Err(BundleError::Protection);
    }
    Ok(())
}
#[cfg(windows)]
mod windows;
#[cfg(windows)]
use windows::ProtectedRoot;
#[cfg(not(any(unix, windows)))]
struct ProtectedRoot;
#[cfg(not(any(unix, windows)))]
impl ProtectedRoot {
    fn open(_: &Path) -> Result<Self, BundleError> {
        Err(BundleError::UnsupportedPlatform)
    }
    fn read(&self, _: &Path, _: u64) -> Result<Vec<u8>, BundleError> {
        Err(BundleError::UnsupportedPlatform)
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicProfile {
    name: String,
    revision: u32,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicRoot {
    role: String,
    algorithm: String,
    key_generation: u64,
    public_key_hex: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicBirth {
    schema_version: u16,
    chain_id: u64,
    incarnation_nonce_hex: String,
    genesis_schema: PublicProfile,
    initial_profile_set_commitment_hex: String,
    bootstrap_roots: Vec<PublicRoot>,
    network_label: String,
    threshold: u32,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicApproval {
    root_index: u32,
    signature_hex: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicApprovals {
    schema_version: u16,
    nic: Vec<PublicApproval>,
    genesis: Vec<PublicApproval>,
}
fn digest_matches(bytes: &[u8], expected: &str) -> Result<(), BundleError> {
    let expected = hex::<32>(expected)?;
    let actual = Primitives
        .hash(HashAlgorithm::Sha256, bytes)
        .map_err(|_| BundleError::Integrity)?;
    if actual.as_slice() != expected {
        return Err(BundleError::Integrity);
    }
    Ok(())
}

/// Read bounded public managed metadata through the same protected descriptor
/// boundary as Genesis. This primitive establishes no release, network,
/// current-context or operation authority; the native owner authenticates pins.
pub fn read_protected_managed_file(
    root: &Path,
    relative: &Path,
    maximum: u64,
) -> Result<Vec<u8>, BundleError> {
    if maximum == 0 || maximum > 64 * 1024 * 1024 {
        return Err(BundleError::Bounds);
    }
    ProtectedRoot::open(root)?.read(relative, maximum)
}

/// Return the SAME protected descriptor for an exact selected native receipt.
/// This authenticates neither its contents nor any operation permission. Native
/// APQE revalidates descriptor/path/inode and its independent Root-issued grant.
/// No symlink or blocking special-file open, file creation, or path reopen.
pub fn open_protected_managed_file(
    root: &Path,
    relative: &Path,
    maximum: u64,
) -> Result<std::fs::File, BundleError> {
    if maximum == 0 || maximum > 64 * 1024 * 1024 {
        return Err(BundleError::Bounds);
    }
    #[cfg(unix)]
    {
        ProtectedRoot::open(root)?.open_file(relative, maximum)
    }
    #[cfg(not(unix))]
    {
        let _ = (root, relative);
        Err(BundleError::UnsupportedPlatform)
    }
}

fn load_pinned_inputs(
    root: &ProtectedRoot,
    selection: &synergy_config::R1NicSelection,
    expected_chain: u64,
    expected_nic: &[u8; 64],
) -> Result<(PinnedBootstrapAuthority, ProfileCatalog), BundleError> {
    let pinned_bytes = root.read(&selection.pinned_bootstrap_input_path, 1024 * 1024)?;
    digest_matches(&pinned_bytes, &selection.pinned_bootstrap_input_sha256)?;
    let catalog_bytes = root.read(&selection.profile_catalog_path, 1024 * 1024)?;
    digest_matches(&catalog_bytes, &selection.profile_catalog_sha256)?;
    let catalog =
        ProfileCatalog::from_received_frame(&catalog_bytes).map_err(|_| BundleError::Catalog)?;
    let pins: PublicBirth =
        serde_json::from_slice(&pinned_bytes).map_err(|_| BundleError::Encoding)?;
    if pins.schema_version != 1
        || pins.chain_id != expected_chain
        || pins.genesis_schema.name != super::compiler::GENESIS_PROFILE
        || pins.genesis_schema.revision != 1
        || pins.bootstrap_roots.is_empty()
        || pins.bootstrap_roots.len() > 32
    {
        return Err(BundleError::Context);
    }
    let nonce = hex::<32>(&pins.incarnation_nonce_hex)?;
    if nonce == [0; 32] {
        return Err(BundleError::Context);
    }
    let profile_set = hex::<64>(&pins.initial_profile_set_commitment_hex)?;
    if catalog.commitment().map_err(|_| BundleError::Catalog)? != profile_set {
        return Err(BundleError::Catalog);
    }
    let keys = pins
        .bootstrap_roots
        .iter()
        .map(|r| hex::<2592>(&r.public_key_hex).map(|k| k.to_vec()))
        .collect::<Result<Vec<_>, _>>()?;
    let records = pins
        .bootstrap_roots
        .iter()
        .zip(&keys)
        .map(|(r, key)| BootstrapKeyRecord {
            role: &r.role,
            algorithm: &r.algorithm,
            key_generation: r.key_generation,
            full_public_key: key,
        })
        .collect::<Vec<_>>();
    let birth = NetworkBirth {
        chain_id: pins.chain_id,
        incarnation_nonce: &nonce,
        genesis_schema: ProfileRef {
            name: &pins.genesis_schema.name,
            revision: pins.genesis_schema.revision,
        },
        initial_profile_set_commitment: &profile_set,
        bootstrap_roots: &records,
        network_label: &pins.network_label,
    };
    let authority = PinnedBootstrapAuthority::from_received_pins(
        &PinnedBootstrapInput {
            birth,
            threshold: pins.threshold,
        },
        &birth,
        expected_nic,
    )
    .map_err(|_| BundleError::Approval)?;
    Ok((authority, catalog))
}

/// Load independently selected complete bootstrap pins before the NIC approval
/// ceremony. This recomputes the supplied birth against the expected NIC and
/// checks its exact catalog; it grants no signing or runtime authority. In
/// particular, the future NIC approvals path is neither opened nor required.
pub fn load_received_pinned_authority(
    selection: &synergy_config::R1NicSelection,
    expected_chain: u64,
) -> Result<(PinnedBootstrapAuthority, ProfileCatalog), BundleError> {
    let expected_nic = hex::<64>(&selection.expected_nic_hex)?;
    if expected_chain == 0 || expected_nic == [0; 64] {
        return Err(BundleError::Context);
    }
    for path in [
        &selection.pinned_bootstrap_input_path,
        &selection.profile_catalog_path,
    ] {
        normal_components(path)?;
    }
    let root = ProtectedRoot::open(&selection.managed_root)?;
    load_pinned_inputs(&root, selection, expected_chain, &expected_nic)
}

/// Authenticate existing public artifacts selected by a protected managed
/// configuration. The caller must supply that authenticated configuration, not
/// copy this selection from the candidate download or an RPC response.
pub fn load_received_bundle(
    selection: &R1GenesisSelection,
    expected_chain: u64,
    engine: &CryptoEngine,
) -> Result<Arc<VerifiedR1Genesis>, BundleError> {
    if expected_chain == 0 {
        return Err(BundleError::Context);
    }
    let expected_nic = hex::<64>(&selection.expected_nic_hex)?;
    let expected_genesis = hex::<48>(&selection.expected_genesis_hex)?;
    if expected_nic == [0; 64] || expected_genesis == [0; 48] {
        return Err(BundleError::Context);
    }
    for path in [
        &selection.core_path,
        &selection.approvals_path,
        &selection.pinned_bootstrap_input_path,
        &selection.profile_catalog_path,
    ] {
        normal_components(path)?;
    }
    let root = ProtectedRoot::open(&selection.managed_root)?;
    let nic_selection = synergy_config::R1NicSelection {
        managed_root: selection.managed_root.clone(),
        approvals_path: selection.approvals_path.clone(),
        pinned_bootstrap_input_path: selection.pinned_bootstrap_input_path.clone(),
        pinned_bootstrap_input_sha256: selection.pinned_bootstrap_input_sha256.clone(),
        profile_catalog_path: selection.profile_catalog_path.clone(),
        profile_catalog_sha256: selection.profile_catalog_sha256.clone(),
        expected_nic_hex: selection.expected_nic_hex.clone(),
    };
    let (authority, catalog) =
        load_pinned_inputs(&root, &nic_selection, expected_chain, &expected_nic)?;
    let approvals: PublicApprovals =
        serde_json::from_slice(&root.read(&selection.approvals_path, 1024 * 1024)?)
            .map_err(|_| BundleError::Encoding)?;
    if approvals.schema_version != 1 || approvals.nic.len() > 32 || approvals.genesis.len() > 32 {
        return Err(BundleError::Bounds);
    }
    let nic_signatures = approvals
        .nic
        .iter()
        .map(|a| hex::<4627>(&a.signature_hex).map(|s| s.to_vec()))
        .collect::<Result<Vec<_>, _>>()?;
    let genesis_signatures = approvals
        .genesis
        .iter()
        .map(|a| hex::<4627>(&a.signature_hex).map(|s| s.to_vec()))
        .collect::<Result<Vec<_>, _>>()?;
    fn indexed<'a>(
        approvals: &[PublicApproval],
        signatures: &'a [Vec<u8>],
    ) -> Vec<IndexedRootApproval<'a>> {
        approvals
            .iter()
            .zip(signatures)
            .map(|(a, s)| IndexedRootApproval {
                root_index: a.root_index,
                signature: s.as_slice(),
            })
            .collect::<Vec<_>>()
    }
    let nic = indexed(&approvals.nic, &nic_signatures);
    let genesis = indexed(&approvals.genesis, &genesis_signatures);
    let core = root.read(&selection.core_path, super::compiler::MAX_CORE_BYTES as u64)?;
    let verified = super::verify_bytes(&core, &catalog, &authority, &nic, &genesis, engine)
        .map_err(|_| BundleError::Approval)?;
    if verified.coordinate().network.chain_id != expected_chain
        || verified.coordinate().network.nic != expected_nic
        || verified.coordinate().genesis.digest != expected_genesis
    {
        return Err(BundleError::Context);
    }
    Ok(Arc::new(verified))
}

#[cfg(all(test, unix))]
mod descriptor_tests {
    use super::*;
    use std::{
        fs,
        io::Read,
        os::unix::{
            ffi::OsStrExt,
            fs::{symlink, PermissionsExt},
        },
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };
    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let p = std::env::temp_dir().join(format!(
                "r1-public-descriptor-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&p).unwrap();
            fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
            Self(p.canonicalize().unwrap())
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    #[test]
    fn same_descriptor_survives_path_replacement_without_reopen() {
        let t = Temp::new();
        fs::write(t.0.join("receipt.json"), b"original public receipt").unwrap();
        let mut fd = open_protected_managed_file(&t.0, Path::new("receipt.json"), 64).unwrap();
        fs::rename(t.0.join("receipt.json"), t.0.join("retired-public.json")).unwrap();
        fs::write(t.0.join("receipt.json"), b"replaced public receipt").unwrap();
        let mut bytes = Vec::new();
        fd.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"original public receipt");
        assert_eq!(
            read_protected_managed_file(&t.0, Path::new("receipt.json"), 64).unwrap(),
            b"replaced public receipt"
        );
    }
    #[test]
    fn bounds_confinement_symlinks_and_fifo_reject_without_creation_or_blocking() {
        let t = Temp::new();
        fs::write(t.0.join("public.json"), b"public fixture").unwrap();
        assert!(open_protected_managed_file(&t.0, Path::new("public.json"), 2).is_err());
        for path in [
            "../public.json",
            "./public.json",
            "nested/../public.json",
            "/public.json",
            "._public.json",
        ] {
            assert!(open_protected_managed_file(&t.0, Path::new(path), 64).is_err());
        }
        symlink(t.0.join("public.json"), t.0.join("alias.json")).unwrap();
        assert!(open_protected_managed_file(&t.0, Path::new("alias.json"), 64).is_err());
        let fifo = t.0.join("fifo");
        let name = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // Public test FIFO, no writer. O_NONBLOCK + regular-file verification
        // must reject immediately rather than wait for an attacker-owned peer.
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        assert!(open_protected_managed_file(&t.0, Path::new("fifo"), 64).is_err());
        let absent = t.0.join("absent");
        assert!(open_protected_managed_file(&absent, Path::new("public.json"), 64).is_err());
        assert!(!absent.exists());
    }
}
