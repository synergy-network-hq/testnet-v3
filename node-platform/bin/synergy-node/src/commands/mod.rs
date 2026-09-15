pub mod ai;
pub mod config;
pub mod cross_chain;
pub mod database;
pub mod doctor;
pub mod etdag;
pub mod health;
pub mod identity;
pub mod init;
pub mod join;
pub mod keys;
pub mod leave;
pub mod manifest;
pub mod node_state;
pub mod peers;
pub mod posy;
pub mod readiness;
pub mod restart;
pub mod role;
pub mod sentry;
pub mod snapshot;
pub mod start;
pub mod status;
pub mod stop;
pub mod sync;
pub mod telemetry;
pub mod upgrade;
pub mod validator;
pub mod version;
pub mod vpn;

use std::path::{Path, PathBuf};

pub(crate) fn nonempty(value: &str, label: &str, maximum: usize) -> Result<String, String> {
    if value.trim().is_empty() || value.len() > maximum || value.contains(char::is_control) {
        return Err(format!(
            "{label} must contain 1..={maximum} safe characters"
        ));
    }
    Ok(value.to_string())
}

pub(crate) fn parse_u64(value: &str, label: &str, allow_zero: bool) -> Result<u64, String> {
    let parsed = value
        .parse::<u64>()
        .map_err(|error| format!("invalid {label}: {error}"))?;
    if !allow_zero && parsed == 0 {
        return Err(format!("{label} must be nonzero"));
    }
    Ok(parsed)
}

pub(crate) fn absolute_path(value: &str, label: &str) -> Result<PathBuf, String> {
    let path = Path::new(value);
    if !path.is_absolute() {
        return Err(format!("{label} must be an absolute path"));
    }
    Ok(path.to_path_buf())
}
