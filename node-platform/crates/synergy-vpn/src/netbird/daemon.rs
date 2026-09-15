use std::{path::PathBuf, process::Command};

use super::{NetbirdProfile, NetbirdStatus};

pub trait NetbirdDaemon {
    fn status(&self) -> Result<NetbirdStatus, String>;
    fn connect(&mut self, profile: &NetbirdProfile, setup_key: &str) -> Result<(), String>;
    fn disconnect(&mut self) -> Result<(), String>;
}

#[derive(Debug, Clone)]
pub struct CommandNetbirdDaemon {
    binary: PathBuf,
}

impl CommandNetbirdDaemon {
    pub fn new(binary: impl Into<PathBuf>) -> Result<Self, String> {
        let binary = binary.into();
        if !binary.is_absolute() {
            return Err("NetBird binary path must be absolute".into());
        }
        Ok(Self { binary })
    }

    fn run(&self, arguments: &[&str]) -> Result<String, String> {
        let output = Command::new(&self.binary)
            .args(arguments)
            .output()
            .map_err(|error| format!("run NetBird: {error}"))?;
        if !output.status.success() {
            let error = String::from_utf8_lossy(&output.stderr);
            return Err(format!("NetBird command failed: {}", error.trim()));
        }
        String::from_utf8(output.stdout).map_err(|_| "NetBird output is not UTF-8".into())
    }
}

impl NetbirdDaemon for CommandNetbirdDaemon {
    fn status(&self) -> Result<NetbirdStatus, String> {
        self.run(&["status"])
            .map(|output| NetbirdStatus::from_command_output(&output))
    }

    fn connect(&mut self, profile: &NetbirdProfile, setup_key: &str) -> Result<(), String> {
        profile.validate()?;
        if setup_key.is_empty() || setup_key.len() > 4096 {
            return Err("invalid NetBird setup credential".into());
        }
        self.run(&[
            "up",
            "--management-url",
            &profile.management_url,
            "--setup-key",
            setup_key,
        ])
        .map(|_| ())
    }

    fn disconnect(&mut self) -> Result<(), String> {
        self.run(&["down"]).map(|_| ())
    }
}
