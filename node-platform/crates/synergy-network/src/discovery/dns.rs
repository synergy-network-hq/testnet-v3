/// Parses the TCP subset of a dnsaddr multiaddr into an untrusted dial
/// candidate. UDP and malformed records are rejected because the initial
/// platform transport boundary is TCP-only.
pub fn parse_dnsaddr_multiaddr_to_dial_address(value: &str) -> Option<String> {
    let segments = value
        .split('/')
        .filter(|segment| !segment.trim().is_empty())
        .collect::<Vec<_>>();
    let (mut host, mut port, mut transport) = (None, None, None);
    let mut index = 0;
    while index + 1 < segments.len() {
        let key = segments[index];
        let value = segments[index + 1];
        match key {
            "dns" | "dns4" | "dns6" | "ip4" | "ip6" if host.is_none() => {
                host = Some(value.to_string())
            }
            "tcp" => {
                if let Ok(parsed) = value.parse::<u16>() {
                    if parsed > 0 {
                        port = Some(parsed);
                        transport = Some("tcp")
                    }
                }
            }
            "udp" => transport = Some("udp"),
            _ => {}
        }
        index += 2
    }
    match (host, port, transport) {
        (Some(host), Some(port), Some("tcp")) => Some(format!("{host}:{port}")),
        _ => None,
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn accepts_only_tcp_dnsaddr_multiaddrs() {
        assert_eq!(
            parse_dnsaddr_multiaddr_to_dial_address("/dns4/boot.synergy-network.io/tcp/5622"),
            Some("boot.synergy-network.io:5622".to_string())
        );
        assert_eq!(
            parse_dnsaddr_multiaddr_to_dial_address("/ip4/10.69.10.2/tcp/5622"),
            Some("10.69.10.2:5622".to_string())
        );
        assert_eq!(
            parse_dnsaddr_multiaddr_to_dial_address("/dns4/boot.synergy-network.io/udp/5622"),
            None
        );
        assert_eq!(
            parse_dnsaddr_multiaddr_to_dial_address("/dns4/boot.synergy-network.io/tcp/not-a-port"),
            None
        )
    }
}
