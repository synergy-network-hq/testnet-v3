#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetbirdStatus {
    pub connected: bool,
    pub management_connected: bool,
    pub signal_connected: bool,
    pub overlay_ip: Option<String>,
    pub connected_peers: usize,
    pub raw_summary: String,
}

impl NetbirdStatus {
    pub fn from_command_output(output: &str) -> Self {
        let lower = output.to_ascii_lowercase();
        let connected = lower.contains("management: connected")
            || lower.contains("management connection: connected");
        let signal_connected =
            lower.contains("signal: connected") || lower.contains("signal connection: connected");
        Self {
            connected: connected && signal_connected,
            management_connected: connected,
            signal_connected,
            overlay_ip: output
                .lines()
                .find_map(|line| line.trim().strip_prefix("NetBird IP: ").map(str::to_owned)),
            connected_peers: output
                .lines()
                .filter(|line| line.to_ascii_lowercase().contains("connected"))
                .count()
                .saturating_sub(usize::from(connected) + usize::from(signal_connected)),
            raw_summary: output.chars().take(4096).collect(),
        }
    }
}
