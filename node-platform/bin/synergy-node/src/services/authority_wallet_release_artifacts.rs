use super::super::apqe_transport;
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File},
    io::Read,
    path::Path,
};
use synergy_address_engine::apqe::{provider::Target, HashAlgorithm, Primitives};
use synergy_genesis::authority::ProtectedWalletDispatchPolicy;

pub(super) const FILE_NAME: &str = "wallet-dispatch-managed-artifacts.json";
const MAX_MANIFEST_BYTES: u64 = 8 * 1024;
const MAX_EXECUTABLE_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub(super) enum Platform {
    #[serde(rename = "aarch64-apple-darwin")]
    DarwinArm64,
    #[serde(rename = "aarch64-unknown-linux-gnu")]
    LinuxArm64,
    #[serde(rename = "x86_64-unknown-linux-gnu")]
    LinuxX86_64,
}

impl Platform {
    pub(super) fn current() -> Result<Self, String> {
        match Target::current() {
            Target::DarwinArm64 => Ok(Self::DarwinArm64),
            Target::LinuxArm64Gnu => Ok(Self::LinuxArm64),
            Target::LinuxX86_64Gnu => Ok(Self::LinuxX86_64),
            _ => Err("managed Wallet release has no qualified verifier for this target".into()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PlatformArtifact {
    pub(super) target: Platform,
    /// Canonical platform package manifest before adding the detached release inputs.
    pub(super) base_package_manifest_sha256: String,
    pub(super) executable_size: u64,
    pub(super) executable_sha256: String,
    pub(super) apqe_report_sha256: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ManagedArtifacts {
    pub(super) version: u8,
    pub(super) chain_id: u64,
    pub(super) network_id: String,
    pub(super) genesis_hash: String,
    pub(super) platforms: Vec<PlatformArtifact>,
}

impl ManagedArtifacts {
    pub(super) fn verify_current(
        root: &Path,
        signed_policy: &ProtectedWalletDispatchPolicy,
        authenticated_report_sha256: &str,
    ) -> Result<PlatformArtifact, String> {
        let bytes = apqe_transport::read(&root.join(FILE_NAME), MAX_MANIFEST_BYTES, false)
            .map_err(|error| format!("managed Wallet release artifact manifest: {error}"))?;
        if apqe_transport::sha256(&bytes) != signed_policy.managed_release_manifest_sha256 {
            return Err("managed Wallet release artifact manifest differs from signed pin".into());
        }
        let manifest: Self = serde_json::from_slice(&bytes)
            .map_err(|_| "invalid managed Wallet release artifact manifest")?;
        if manifest.version != 1
            || manifest.chain_id != signed_policy.chain_id
            || manifest.network_id != signed_policy.network_id
            || manifest.genesis_hash != signed_policy.genesis_hash
            || manifest.platforms.is_empty()
            || !manifest
                .platforms
                .windows(2)
                .all(|p| p[0].target < p[1].target)
            || !manifest.platforms.iter().all(PlatformArtifact::valid)
            || serde_json::to_vec(&manifest).map_err(|error| error.to_string())? != bytes
        {
            return Err(
                "managed Wallet release artifact manifest is outside the signed scope".into(),
            );
        }
        let current = Platform::current()?;
        let selected = manifest
            .platforms
            .into_iter()
            .find(|p| p.target == current)
            .ok_or("managed Wallet release omits the running target")?;
        if selected.apqe_report_sha256 != authenticated_report_sha256 {
            return Err(
                "managed Wallet release does not select the authenticated APQE report".into(),
            );
        }
        let (size, sha256) = measure_executable(selected.executable_size)?;
        if size != selected.executable_size || sha256 != selected.executable_sha256 {
            return Err("managed Wallet release does not select the running executable".into());
        }
        Ok(selected)
    }
}

impl PlatformArtifact {
    fn valid(&self) -> bool {
        fn nonzero_sha256(value: &str) -> bool {
            value.len() == 64
                && value
                    .bytes()
                    .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
                && value.bytes().any(|b| b != b'0')
        }
        (1..=MAX_EXECUTABLE_BYTES).contains(&self.executable_size)
            && nonzero_sha256(&self.executable_sha256)
            && nonzero_sha256(&self.base_package_manifest_sha256)
            && nonzero_sha256(&self.apqe_report_sha256)
    }
}

/// Linux reads the kernel's executing file descriptor, so renaming the pathname
/// cannot switch the measured bytes. Managed Darwin runs use an immutable,
/// attributed executable path and refuse symlinks, substitution and read drift.
pub(super) fn measure_executable(maximum: u64) -> Result<(u64, String), String> {
    let path = std::env::current_exe()
        .map_err(|e| format!("locate running Wallet release executable: {e}"))?;
    if path
        .canonicalize()
        .map_err(|e| format!("resolve running Wallet release executable: {e}"))?
        != path
    {
        return Err("managed Wallet release requires the canonical executable path".into());
    }
    let stamp = apqe_transport::Stamp::capture(&path)?;
    let original = fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
    let file = open_executable(&path)
        .map_err(|e| format!("open running Wallet release executable: {e}"))?;
    let opened = file.metadata().map_err(|e| e.to_string())?;
    if !opened.is_file()
        || opened.len() != original.len()
        || opened.len() == 0
        || opened.len() > maximum.min(MAX_EXECUTABLE_BYTES)
    {
        return Err("managed Wallet release executable has an invalid size/type".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if (
            original.dev(),
            original.ino(),
            original.ctime(),
            original.ctime_nsec(),
        ) != (
            opened.dev(),
            opened.ino(),
            opened.ctime(),
            opened.ctime_nsec(),
        ) || opened.mode() & 0o022 != 0
        {
            return Err(
                "managed Wallet release executable changed or is writable by other users".into(),
            );
        }
    }
    let mut file = file.take(opened.len() + 1);
    let mut hash = Primitives
        .hash_stream(HashAlgorithm::Sha256)
        .map_err(|e| e.to_string())?;
    let mut buffer = [0; 16 * 1024];
    let mut size = 0;
    loop {
        let count = file.read(&mut buffer).map_err(|e| e.to_string())?;
        if count == 0 {
            break;
        }
        size += count as u64;
        hash.update(&buffer[..count]);
    }
    if size != opened.len() || !stamp.unchanged() {
        return Err("managed Wallet release executable changed during measurement".into());
    }
    let sha256 = hash.finalize().iter().map(|b| format!("{b:02x}")).collect();
    Ok((size, sha256))
}

#[cfg(target_os = "linux")]
fn open_executable(_path: &Path) -> std::io::Result<File> {
    File::open("/proc/self/exe")
}

#[cfg(not(target_os = "linux"))]
fn open_executable(path: &Path) -> std::io::Result<File> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    }
    options.open(path)
}
