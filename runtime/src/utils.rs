use std::env;
use std::path::{Component, Path, PathBuf};

/// Gets the project root directory by looking for Cargo.toml
/// or by using the binary's location to infer the project root
pub fn get_project_root() -> Option<PathBuf> {
    // First, try to find Cargo.toml in current directory or parents
    let mut current = env::current_dir().ok()?;

    loop {
        let cargo_toml = current.join("Cargo.toml");
        if cargo_toml.exists() {
            return Some(current);
        }

        if let Some(parent) = current.parent() {
            current = parent.to_path_buf();
        } else {
            break;
        }
    }

    // Fallback: try to infer from binary location
    if let Ok(exe_path) = env::current_exe() {
        // If binary is in target/release/ or target/debug/, go up 2 levels
        if let Some(parent) = exe_path.parent() {
            if parent.ends_with("release") || parent.ends_with("debug") {
                if let Some(grandparent) = parent.parent() {
                    if grandparent.ends_with("target") {
                        if let Some(project_root) = grandparent.parent() {
                            let cargo_toml = project_root.join("Cargo.toml");
                            if cargo_toml.exists() {
                                return Some(project_root.to_path_buf());
                            }
                        }
                    }
                }
            }
        }
    }

    None
}

fn has_runtime_config_dir(path: &Path) -> bool {
    let config_dir = path.join("config");
    if !config_dir.is_dir() {
        return false;
    }
    if config_dir.join("mod.rs").is_file()
        && !config_dir.join("genesis.json").is_file()
        && !config_dir.join("genesis.testnet.json").is_file()
        && !config_dir.join("node_config.toml").is_file()
        && !config_dir.join("network-config.toml").is_file()
    {
        return false;
    }
    true
}

fn search_runtime_root_from(start: &Path) -> Option<PathBuf> {
    let mut current = if start.is_dir() {
        start.to_path_buf()
    } else {
        start.parent()?.to_path_buf()
    };

    loop {
        if has_runtime_config_dir(&current) {
            return Some(current);
        }

        if let Some(parent) = current.parent() {
            current = parent.to_path_buf();
        } else {
            return None;
        }
    }
}

/// Gets the active runtime root for a launched node workspace.
///
/// Unlike `get_project_root`, this prefers deployed node workspaces discovered
/// via `SYNERGY_PROJECT_ROOT` / `SYNERGY_CONFIG_PATH` before falling back to the
/// source checkout root.
pub fn get_runtime_root() -> Option<PathBuf> {
    if let Ok(configured_root) = env::var("SYNERGY_PROJECT_ROOT") {
        let trimmed = configured_root.trim();
        if !trimmed.is_empty() {
            let root = PathBuf::from(trimmed);
            if has_runtime_config_dir(&root) {
                return Some(root);
            }
        }
    }

    if let Ok(config_path) = env::var("SYNERGY_CONFIG_PATH") {
        let trimmed = config_path.trim();
        if !trimmed.is_empty() {
            if let Some(root) = search_runtime_root_from(Path::new(trimmed)) {
                return Some(root);
            }
        }
    }

    if let Ok(current_dir) = env::current_dir() {
        if let Some(root) = search_runtime_root_from(&current_dir) {
            return Some(root);
        }
    }

    get_project_root().filter(|root| has_runtime_config_dir(root))
}

/// Resolves a path relative to the project root, or returns absolute path as-is
pub fn resolve_data_path(relative_path: &str) -> PathBuf {
    // If it's already absolute, use it as-is
    if Path::new(relative_path).is_absolute() {
        return PathBuf::from(relative_path);
    }

    if let Some(data_path) = resolve_synergy_data_path(relative_path) {
        return data_path;
    }

    // Prefer the explicit runtime root for launched nodes so state/log paths stay
    // anchored to the node workspace even when the process starts from another cwd.
    if let Some(runtime_root) = get_runtime_root() {
        return runtime_root.join(relative_path);
    }

    if let Ok(current_dir) = env::current_dir() {
        return current_dir.join(relative_path);
    }

    // Try to get project root
    if let Some(project_root) = get_project_root() {
        project_root.join(relative_path)
    } else {
        // Fallback to current directory (original behavior)
        PathBuf::from(relative_path)
    }
}

fn resolve_synergy_data_path(relative_path: &str) -> Option<PathBuf> {
    let data_root = env::var("SYNERGY_DATA_PATH").ok()?;
    let data_root = data_root.trim();
    if data_root.is_empty() {
        return None;
    }

    let path = Path::new(relative_path);
    if path.is_absolute() {
        return None;
    }

    let mut components = path.components();
    match components.next() {
        Some(Component::Normal(first)) if first == "data" => {
            let mut resolved = PathBuf::from(data_root);
            for component in components {
                match component {
                    Component::Normal(segment) => resolved.push(segment),
                    Component::CurDir => {}
                    _ => return None,
                }
            }
            Some(resolved)
        }
        _ => None,
    }
}

/// Validates that we're running from the correct project root
pub fn validate_project_root() -> Result<PathBuf, String> {
    if let Some(project_root) = get_runtime_root() {
        return Ok(project_root);
    }

    Err(
        "Could not determine a writable runtime root. Set SYNERGY_PROJECT_ROOT or SYNERGY_CONFIG_PATH, or run from the node workspace."
            .to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::{get_runtime_root, resolve_data_path};
    use std::env;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::{Mutex, OnceLock};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    struct EnvVarGuard {
        key: &'static str,
        previous: Option<String>,
    }

    impl EnvVarGuard {
        fn clear(key: &'static str) -> Self {
            let previous = env::var(key).ok();
            env::remove_var(key);
            Self { key, previous }
        }

        fn set(key: &'static str, value: &str) -> Self {
            let previous = env::var(key).ok();
            env::set_var(key, value);
            Self { key, previous }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            if let Some(previous) = &self.previous {
                env::set_var(self.key, previous);
            } else {
                env::remove_var(self.key);
            }
        }
    }

    struct TempWorkspace {
        root: PathBuf,
    }

    impl TempWorkspace {
        fn new() -> Self {
            let unique = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system time should be after unix epoch")
                .as_nanos();
            let root = env::temp_dir().join(format!(
                "synergy-runtime-root-test-{}-{}",
                std::process::id(),
                unique
            ));
            fs::create_dir_all(root.join("config"))
                .expect("temp workspace config dir should exist");
            Self { root }
        }
    }

    impl Drop for TempWorkspace {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn runtime_root_prefers_synergy_project_root() {
        let _lock = env_lock().lock().expect("env lock should be available");
        let workspace = TempWorkspace::new();
        let _project_root = EnvVarGuard::set(
            "SYNERGY_PROJECT_ROOT",
            workspace
                .root
                .to_str()
                .expect("workspace path should be utf-8"),
        );
        let _config_path = EnvVarGuard::clear("SYNERGY_CONFIG_PATH");

        assert_eq!(get_runtime_root(), Some(workspace.root.clone()));
    }

    #[test]
    fn runtime_root_falls_back_to_synergy_config_path() {
        let _lock = env_lock().lock().expect("env lock should be available");
        let workspace = TempWorkspace::new();
        let config_path = workspace.root.join("config").join("node.toml");
        fs::write(&config_path, b"").expect("temp config file should be writable");
        let _project_root = EnvVarGuard::clear("SYNERGY_PROJECT_ROOT");
        let _config_path = EnvVarGuard::set(
            "SYNERGY_CONFIG_PATH",
            config_path.to_str().expect("config path should be utf-8"),
        );

        assert_eq!(get_runtime_root(), Some(workspace.root.clone()));
    }

    #[test]
    fn resolve_data_path_uses_synergy_data_path_for_legacy_data_files() {
        let _lock = env_lock().lock().expect("env lock should be available");
        let workspace = TempWorkspace::new();
        let data_path = workspace.root.join("state").join("store");
        let _project_root = EnvVarGuard::clear("SYNERGY_PROJECT_ROOT");
        let _config_path = EnvVarGuard::clear("SYNERGY_CONFIG_PATH");
        let _data_path = EnvVarGuard::set(
            "SYNERGY_DATA_PATH",
            data_path.to_str().expect("data path should be utf-8"),
        );

        assert_eq!(resolve_data_path("data"), data_path);
        assert_eq!(
            resolve_data_path("data/chain.json"),
            data_path.join("chain.json")
        );
    }

    #[test]
    fn resolve_data_path_does_not_redirect_non_data_paths() {
        let _lock = env_lock().lock().expect("env lock should be available");
        let workspace = TempWorkspace::new();
        let _project_root = EnvVarGuard::set(
            "SYNERGY_PROJECT_ROOT",
            workspace
                .root
                .to_str()
                .expect("workspace path should be utf-8"),
        );
        let _data_path = EnvVarGuard::set("SYNERGY_DATA_PATH", "/tmp/synergy-data");

        assert_eq!(
            resolve_data_path("logs/synergy-testnet.log"),
            workspace.root.join("logs").join("synergy-testnet.log")
        );
    }
}
