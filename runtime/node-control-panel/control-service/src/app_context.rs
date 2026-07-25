use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Default)]
pub struct AppContext {
    resource_roots: Vec<PathBuf>,
    app_data_dir: Option<PathBuf>,
}

impl AppContext {
    pub fn from_env() -> Self {
        load_env_overrides();

        let mut resource_roots = Vec::new();

        if let Some(root) = std::env::var_os("SYNERGY_RESOURCE_ROOT") {
            resource_roots.push(PathBuf::from(root));
        }

        if let Ok(current_dir) = std::env::current_dir() {
            resource_roots.push(current_dir.clone());
            for ancestor in current_dir.ancestors().take(8) {
                resource_roots.push(ancestor.to_path_buf());
            }
        }

        Self {
            resource_roots: dedupe_paths(resource_roots),
            app_data_dir: std::env::var_os("SYNERGY_APP_DATA_DIR").map(PathBuf::from),
        }
    }

    pub fn resource_roots(&self) -> &[PathBuf] {
        &self.resource_roots
    }

    pub fn app_data_dir(&self) -> Option<&PathBuf> {
        self.app_data_dir.as_ref()
    }
}

fn load_env_overrides() {
    for path in env_override_candidates() {
        load_env_file_if_present(path);
    }
}

fn env_override_candidates() -> Vec<PathBuf> {
    let mut candidates = Vec::new();

    if let Some(path) = std::env::var_os("SYNERGY_CONTROL_PANEL_ENV_FILE") {
        candidates.push(PathBuf::from(path));
    }

    if let Some(root) = std::env::var_os("SYNERGY_RESOURCE_ROOT").map(PathBuf::from) {
        push_env_override_root(&mut candidates, &root);
    }

    if let Ok(current_dir) = std::env::current_dir() {
        for root in current_dir.ancestors().take(8) {
            push_env_override_root(&mut candidates, root);
        }
    }

    if let Some(app_data_dir) = std::env::var_os("SYNERGY_APP_DATA_DIR").map(PathBuf::from) {
        push_env_override_root(&mut candidates, &app_data_dir);
    }

    if let Some(home_dir) = dirs::home_dir() {
        for root in [
            home_dir.join(".synergy-node-control-panel"),
            home_dir.join(".synergy-testnet-control-panel"),
        ] {
            push_env_override_root(&mut candidates, &root);
        }
    }

    if let Some(data_dir) = dirs::data_dir() {
        let root = data_dir.join("Synergy Node Control Panel");
        push_env_override_root(&mut candidates, &root);
    }

    dedupe_paths(candidates)
}

fn push_env_override_root(candidates: &mut Vec<PathBuf>, root: &Path) {
    candidates.push(root.join(".env"));
    candidates.push(root.join("control-service.env"));
    candidates.push(root.join("validator-vpn-coordinator.env"));
    candidates.push(root.join("config").join("control-service.env"));
    candidates.push(root.join("config").join("validator-vpn-coordinator.env"));
    candidates.push(
        root.join("testnet")
            .join("runtime")
            .join("control-service.env"),
    );
    candidates.push(
        root.join("testnet")
            .join("runtime")
            .join("validator-vpn")
            .join("validator-vpn-coordinator.env"),
    );
}

fn load_env_file_if_present(path: PathBuf) {
    if !path.is_file() {
        return;
    }

    match dotenvy::from_path_iter(&path) {
        Ok(iter) => {
            for item in iter {
                match item {
                    Ok((key, value)) => {
                        if std::env::var_os(&key).is_none() {
                            std::env::set_var(key, value);
                        }
                    }
                    Err(error) => {
                        eprintln!(
                            "failed to parse control-service env override {}: {error}",
                            path.display()
                        );
                    }
                }
            }
        }
        Err(error) => {
            eprintln!(
                "failed to load control-service env override {}: {error}",
                path.display()
            );
        }
    }
}

fn dedupe_paths(paths: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut output = Vec::new();
    for path in paths {
        if output.iter().any(|existing| existing == &path) {
            continue;
        }
        output.push(path);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::fs;
    use std::sync::Mutex;
    use tempfile::TempDir;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    struct EnvVarGuard {
        key: &'static str,
        previous: Option<OsString>,
    }

    impl EnvVarGuard {
        fn set_path(key: &'static str, value: &Path) -> Self {
            let previous = std::env::var_os(key);
            std::env::set_var(key, value);
            Self { key, previous }
        }

        fn remove(key: &'static str) -> Self {
            let previous = std::env::var_os(key);
            std::env::remove_var(key);
            Self { key, previous }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            if let Some(previous) = &self.previous {
                std::env::set_var(self.key, previous);
            } else {
                std::env::remove_var(self.key);
            }
        }
    }

    #[test]
    fn from_env_loads_installer_validator_vpn_coordinator_config_from_resource_root() {
        let _lock = ENV_LOCK.lock().unwrap();
        let temp = TempDir::new().expect("temp resource root");
        let config_dir = temp
            .path()
            .join("testnet")
            .join("runtime")
            .join("validator-vpn");
        fs::create_dir_all(&config_dir).expect("config dir");
        fs::write(
            config_dir.join("validator-vpn-coordinator.env"),
            "SYNERGY_VALIDATOR_VPN_COORDINATOR_URL=https://installer-vpn.example\n",
        )
        .expect("coordinator env should write");

        let _resource_root = EnvVarGuard::set_path("SYNERGY_RESOURCE_ROOT", temp.path());
        let _coordinator_url = EnvVarGuard::remove("SYNERGY_VALIDATOR_VPN_COORDINATOR_URL");
        let _agent_url = EnvVarGuard::remove("VALIDATOR_VPN_COORDINATOR_URL");
        let _explicit_env = EnvVarGuard::remove("SYNERGY_CONTROL_PANEL_ENV_FILE");

        let context = AppContext::from_env();

        assert!(context
            .resource_roots()
            .contains(&temp.path().to_path_buf()));
        assert_eq!(
            std::env::var("SYNERGY_VALIDATOR_VPN_COORDINATOR_URL").as_deref(),
            Ok("https://installer-vpn.example")
        );
    }
}
