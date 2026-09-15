use crate::{NetbirdDaemon, NetbirdProfile, NetbirdStatus, VpnState};

#[derive(Debug)]
pub struct VpnClient<D> {
    daemon: D,
    profile: NetbirdProfile,
    state: VpnState,
}

impl<D: NetbirdDaemon> VpnClient<D> {
    pub fn new(daemon: D, profile: NetbirdProfile) -> Result<Self, String> {
        profile.validate()?;
        Ok(Self {
            daemon,
            profile,
            state: VpnState::Disconnected,
        })
    }

    pub fn connect(&mut self, setup_key: &str) -> Result<(), String> {
        self.state = VpnState::Connecting;
        match self.daemon.connect(&self.profile, setup_key) {
            Ok(()) => {
                self.state = VpnState::Connected;
                Ok(())
            }
            Err(error) => {
                self.state = VpnState::Failed;
                Err(error)
            }
        }
    }

    pub fn refresh(&mut self) -> Result<NetbirdStatus, String> {
        let status = self.daemon.status()?;
        self.state = if status.connected {
            VpnState::Connected
        } else if status.management_connected || status.signal_connected {
            VpnState::Degraded
        } else {
            VpnState::Disconnected
        };
        Ok(status)
    }

    pub fn disconnect(&mut self) -> Result<(), String> {
        self.daemon.disconnect()?;
        self.state = VpnState::Disconnected;
        Ok(())
    }

    pub fn state(&self) -> VpnState {
        self.state
    }
}
