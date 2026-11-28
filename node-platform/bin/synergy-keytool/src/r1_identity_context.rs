//! Existing protected native permission → independently authenticated R1 bundle.
//! No renderer context, new issuer, future identity, persistence or key operation.
use serde::Deserialize;
use std::{path::Path, sync::Arc};
use synergy_address_engine::apqe::{HashAlgorithm, Primitives};
use synergy_config::{R1GenesisSelection, R1NicSelection};
use synergy_genesis::r1::{received_bundle, VerifiedR1Genesis};

#[derive(Deserialize)]
struct Policy {
    #[serde(default)]
    r1_creation_context: Option<Context>,
    #[serde(default)]
    r1_initial_creation_context: Option<NicContext>,
    #[serde(default)]
    r1_formation_creation_context: Option<NicContext>,
    format: String,
    root: String,
    community_enrollment: bool,
    qualified_operations: Vec<String>,
    releases: serde_json::Value,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Context {
    chain_id: String,
    genesis_selection: R1GenesisSelection,
    target_namespace: String,
    purpose: String,
    allowed_roles: Vec<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NicContext {
    chain_id: String,
    nic_selection: R1NicSelection,
    profile_catalog_commitment_hex: String,
    #[serde(default)]
    target_namespace: Option<String>,
    purpose: String,
    allowed_roles: Vec<String>,
    selected_slots: Vec<String>,
    custody_object_refs: Vec<String>,
}
#[derive(Deserialize)]
#[serde(
    tag = "scope",
    content = "context",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum ReviewSelection {
    Runtime(Context),
    Initial(NicContext),
    Formation(NicContext),
}
/// Purpose selection only, never an authorization token. The operation must
/// independently pass APQE's protected receipt verification before secret use.
#[derive(Clone, Copy)]
pub(super) enum NativeIdentityOperation {
    Generate,
    Prove,
    Rebind,
    Observation,
}
impl NativeIdentityOperation {
    fn name(self) -> &'static str {
        match self {
            Self::Generate => "r1_identity_generate",
            Self::Prove => "r1_identity_prove",
            Self::Rebind => "r1_identity_rebind",
            Self::Observation => "read_original_public_identity_result",
        }
    }
    fn permitted(self, operations: &[String]) -> bool {
        matches!(self, Self::Observation) || operations.iter().any(|s| s == self.name())
    }
}
pub(super) enum NativeContext {
    Bootstrap,
    Runtime(Arc<VerifiedR1Genesis>),
    Initial(Arc<received_bundle::VerifiedR1NicBundle>),
    Formation(Arc<received_bundle::VerifiedR1NicBundle>),
}
impl NativeContext {
    pub(super) fn network(&self) -> Option<synergy_address_engine::apqe::r1_framing::NetworkRef> {
        match self {
            Self::Bootstrap => None,
            Self::Runtime(g) => Some(g.nic_approvals().network()),
            Self::Initial(n) | Self::Formation(n) => Some(n.approvals().network()),
        }
    }
}
fn chain(value: &str) -> Result<u64, String> {
    let n = value
        .parse::<u64>()
        .map_err(|_| "Canonical native chain required")?;
    if n == 0 || n.to_string() != value {
        return Err("Canonical native chain required".into());
    }
    Ok(n)
}
fn bounded_names(values: &[String]) -> bool {
    !values.is_empty()
        && values.len() <= 64
        && values
            .iter()
            .all(|s| !s.is_empty() && s.len() <= 120 && s.bytes().all(|b| b.is_ascii_graphic()))
        && values
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            == values.len()
}
fn digest(bytes: &[u8]) -> Result<String, String> {
    Primitives
        .hash(HashAlgorithm::Sha256, bytes)
        .map(|v| v.iter().map(|b| format!("{b:02x}")).collect())
        .map_err(|_| "Native inventory digest unavailable".into())
}
fn read(root: &Path, relative: &str, max: u64) -> Result<Vec<u8>, String> {
    received_bundle::read_protected_managed_file(root, Path::new(relative), max)
        .map_err(|_| "Protected native creation context unavailable".into())
}
#[cfg(not(unix))]
pub(super) fn load(_: &Path) -> Result<NativeContext, String> {
    Err("Native creation context protection is not qualified for this platform".into())
}
/// The target controller holds its existing lifecycle lock throughout this
/// operation. Its protected policy, not request JSON, chooses the current scope.
#[cfg(unix)]
pub(super) fn load(root: &Path) -> Result<NativeContext, String> {
    load_for_operation(root, NativeIdentityOperation::Generate)
}

#[cfg(unix)]
pub(super) fn load_for_operation(
    root: &Path,
    operation: NativeIdentityOperation,
) -> Result<NativeContext, String> {
    load_impl(root, None, operation)
}
#[cfg(not(unix))]
pub(super) fn load_for_operation(
    _: &Path,
    _: NativeIdentityOperation,
) -> Result<NativeContext, String> {
    Err("Native identity context protection is not qualified for this platform".into())
}

/// Public original-result observation only. Genuine installed context is still
/// verified; no mutation permission, private key or creation cap is returned.
pub(super) fn load_for_observation(root: &Path) -> Result<NativeContext, String> {
    load_for_operation(root, NativeIdentityOperation::Observation)
}

/// Public proof review for the SAME native atomic authorization writer before
/// it installs a selected context. Supplied pins require independent native
/// approval; successful cryptographic verification is never a creation grant.
#[cfg(unix)]
pub(super) fn review(root: &Path, parameters: &str) -> Result<serde_json::Value, String> {
    if parameters.is_empty() || parameters.len() > 64 * 1024 {
        return Err("Bounded native context review required".into());
    }
    let selected: ReviewSelection =
        serde_json::from_str(parameters).map_err(|_| "Closed native context review required")?;
    let context = load_impl(root, Some(selected), NativeIdentityOperation::Generate)?;
    let (scope, profiles, genesis) = match &context {
        NativeContext::Runtime(g) => (
            "runtime",
            g.coordinate().activated_profiles.commitment,
            Some(g.coordinate().genesis.digest),
        ),
        NativeContext::Initial(n) => (
            "initial",
            n.catalog()
                .commitment()
                .map_err(|_| "Native profile catalog differs")?,
            None,
        ),
        NativeContext::Formation(n) => (
            "formation",
            n.catalog()
                .commitment()
                .map_err(|_| "Native profile catalog differs")?,
            None,
        ),
        NativeContext::Bootstrap => {
            return Err("Bootstrap roots are outside public context review".into())
        }
    };
    let n = context
        .network()
        .ok_or("Verified native network unavailable")?;
    let hex = |b: &[u8]| b.iter().map(|b| format!("{b:02x}")).collect::<String>();
    Ok(
        serde_json::json!({"schema":"synergy-r1-creation-context-review-v1","scope":scope,
        "chain_id":n.chain_id.to_string(),"nic_hex":hex(&n.nic),"profile_catalog_commitment_hex":hex(&profiles),
        "genesis_digest_hex":genesis.map(|g|hex(&g)),"creation_authority_granted":false}),
    )
}
#[cfg(not(unix))]
pub(super) fn review(_: &Path, _: &str) -> Result<serde_json::Value, String> {
    Err("Native creation context protection is not qualified for this platform".into())
}

#[cfg(unix)]
fn load_impl(
    root: &Path,
    selection: Option<ReviewSelection>,
    operation: NativeIdentityOperation,
) -> Result<NativeContext, String> {
    use std::os::unix::fs::MetadataExt;
    if unsafe { libc::geteuid() } != 0
        || !root.is_absolute()
        || root.canonicalize().ok().as_deref() != Some(root)
    {
        return Err("Native creation requires the protected canonical platform root".into());
    }
    // Establish the immutable-code trust boundary BEFORE any native library load.
    for path in root.ancestors() {
        let m = std::fs::symlink_metadata(path).map_err(|_| "Native root unavailable")?;
        if !m.is_dir() || m.uid() != 0 || m.mode() & 0o022 != 0 {
            return Err("Native creation root protection differs".into());
        }
    }
    let mut policy: Policy =
        serde_json::from_slice(&read(root, "tmp/controller/policy.json", 2 * 1024 * 1024)?)
            .map_err(|_| "Native creation policy differs")?;
    let public_review = selection.is_some();
    if let Some(selected) = selection {
        // In-memory review only: never install candidate pins as trusted policy.
        policy.r1_creation_context = None;
        policy.r1_initial_creation_context = None;
        policy.r1_formation_creation_context = None;
        match selected {
            ReviewSelection::Runtime(c) => policy.r1_creation_context = Some(c),
            ReviewSelection::Initial(c) => policy.r1_initial_creation_context = Some(c),
            ReviewSelection::Formation(c) => policy.r1_formation_creation_context = Some(c),
        }
    }
    let count = usize::from(policy.r1_creation_context.is_some())
        + usize::from(policy.r1_initial_creation_context.is_some())
        + usize::from(policy.r1_formation_creation_context.is_some());
    if count == 0 {
        return Ok(NativeContext::Bootstrap);
    }
    if count != 1 {
        return Err("Ambiguous native creation phase refused".into());
    }
    if policy.format != "synergy-nodenetwork-host-policy-v1"
        || policy.root != root.to_string_lossy()
        || policy.community_enrollment
        || (!public_review && !operation.permitted(&policy.qualified_operations))
    {
        return Err("Current native creation permission unavailable".into());
    }
    if let Some(context) = policy.r1_creation_context.as_ref() {
        chain(&context.chain_id)?;
        if context.genesis_selection.managed_root != root
            || context.purpose != "NODE_ENROLLMENT"
            || context.target_namespace.is_empty()
            || context.target_namespace.len() > 6
            || context.allowed_roles.is_empty()
            || context.allowed_roles.len() > 5
            || context.allowed_roles.iter().any(|r| {
                !matches!(
                    r.as_str(),
                    "node_birth_root"
                        | "consensus"
                        | "transport/public"
                        | "transport/private"
                        | "transport/service"
                )
            })
            || context
                .allowed_roles
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != context.allowed_roles.len()
        {
            return Err("Exact current native node-creation scope required".into());
        }
    }
    for (context, formation) in [
        (policy.r1_initial_creation_context.as_ref(), false),
        (policy.r1_formation_creation_context.as_ref(), true),
    ] {
        if let Some(context) = context {
            chain(&context.chain_id)?;
            if context.nic_selection.managed_root != root
                || !bounded_names(&context.allowed_roles)
                || !bounded_names(&context.selected_slots)
                || !bounded_names(&context.custody_object_refs)
                || context.profile_catalog_commitment_hex.len() != 128
                || !context
                    .profile_catalog_commitment_hex
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                || (formation
                    && (context.purpose != "FORMATION_AUTHENTICATION"
                        || context.target_namespace.is_some()
                        || context.allowed_roles != ["formation_authentication"]))
                || (!formation
                    && (!matches!(context.purpose.as_str(), "GENESIS_NODE" | "GENESIS_ACCOUNT")
                        || !context
                            .target_namespace
                            .as_ref()
                            .is_some_and(|n| !n.is_empty() && n.len() <= 6)))
            {
                return Err("Exact NIC-only initial creation scope required".into());
            }
        }
    }
    let package_bytes = read(root, "package.json", 2 * 1024 * 1024)?;
    let package: serde_json::Value =
        serde_json::from_slice(&package_bytes).map_err(|_| "Native package differs")?;
    let installation: serde_json::Value =
        serde_json::from_slice(&read(root, "installation.json", 2 * 1024 * 1024)?)
            .map_err(|_| "Native installation differs")?;
    let package_hash = digest(&package_bytes)?;
    let release = package["release_id"]
        .as_str()
        .ok_or("Native release absent")?;
    if installation["root"] != policy.root
        || installation["package_sha256"] != package_hash
        || installation["package_files"] != package["files"]
        || policy.releases[release]["manifest_sha256"] != package_hash
        || policy.releases[release]["inventory_authenticated"] != true
    {
        return Err("Authenticated native release unavailable".into());
    }
    let report_path = "lib/apqe/build-report.json";
    let report_bytes = read(root, report_path, 1024 * 1024)?;
    let report_hash = digest(&report_bytes)?;
    let report: serde_json::Value =
        serde_json::from_slice(&report_bytes).map_err(|_| "Native report differs")?;
    if package["files"][report_path] != report_hash || report["validation"] != false {
        return Err("Current installed native provider qualification differs".into());
    }
    for variant in ["mldsa65", "mldsa87", "mlkem1024"] {
        let path = format!(
            "lib/apqe/libaegis{variant}.{}",
            std::env::consts::DLL_EXTENSION
        );
        if package["files"][&path] != digest(&read(root, &path, 64 * 1024 * 1024)?)? {
            return Err("Installed native provider inventory differs".into());
        }
    }
    let engine = synergy_aegis::load_authenticated_r1_verification_engine(
        &root.join(report_path),
        &report_hash,
    )?;
    let engine = engine
        .lock()
        .map_err(|_| "Native verification engine unavailable")?;
    if let Some(context) = policy.r1_creation_context.as_ref() {
        return received_bundle::load_received_bundle(
            &context.genesis_selection,
            chain(&context.chain_id)?,
            &engine,
        )
        .map(NativeContext::Runtime)
        .map_err(|_| "Complete authenticated R1 Genesis unavailable".into());
    }
    let (context, formation) = match (
        policy.r1_initial_creation_context.as_ref(),
        policy.r1_formation_creation_context.as_ref(),
    ) {
        (Some(c), None) => (c, false),
        (None, Some(c)) => (c, true),
        _ => return Err("Native phase unavailable".into()),
    };
    let nic = received_bundle::load_received_nic_bundle(
        &context.nic_selection,
        chain(&context.chain_id)?,
        &engine,
    )
    .map_err(|_| "Complete authenticated NIC unavailable")?;
    let commitment = nic
        .catalog()
        .commitment()
        .map_err(|_| "Approved native catalog unavailable")?;
    let actual: String = commitment.iter().map(|b| format!("{b:02x}")).collect();
    if actual != context.profile_catalog_commitment_hex {
        return Err("Approved NIC catalog differs".into());
    }
    Ok(if formation {
        NativeContext::Formation(nic)
    } else {
        NativeContext::Initial(nic)
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn exact_native_operation_is_required_without_implicit_generation_permission() {
        use super::NativeIdentityOperation as Operation;
        assert!(Operation::Prove.permitted(&["r1_identity_prove".into()]));
        assert!(Operation::Rebind.permitted(&["r1_identity_rebind".into()]));
        assert!(!Operation::Prove.permitted(&["r1_identity_generate".into()]));
        assert!(!Operation::Rebind.permitted(&["r1_identity_generate".into()]));
        assert!(!Operation::Generate.permitted(&["r1_identity_prove".into()]));
        assert!(!Operation::Prove.permitted(&["r1_identity_prove\n".into()]));
    }
    #[test]
    fn missing_native_context_cannot_load_provider_or_create_platform_root() {
        let root = std::env::temp_dir().join(format!(
            "synergy-no-current-r1-context-{}",
            std::process::id()
        ));
        assert!(!root.exists());
        assert!(super::load(&root).is_err());
        assert!(!root.exists());
    }
}
